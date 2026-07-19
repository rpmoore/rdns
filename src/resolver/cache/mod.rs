// Copyright 2026 Ryan Moore
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Sharded answer-cache implementation. See `docs/plans/cache_rework/` for
//! the design this module is built from.

mod assemble;
mod entry;
mod lru;
mod namespace;
mod shard;
mod singleflight;

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::OnceLock;
use std::time::SystemTime;

use crate::config::RefreshConfig;
use shard::Shard;

pub use assemble::ChainLookup;
#[cfg(test)]
pub(crate) use assemble::STALE_WIRE_TTL_SECS;
pub(crate) use assemble::{
    RefreshHint, ResolvedAnswer, ResolvedNegative, assemble_negative_response, assemble_response,
};
pub use entry::{DnssecState, NegativeEntry, NegativeKey, RRsetEntry, StoredRecord};
pub(crate) use singleflight::{
    InFlightMiss, MissKey, ShardedSingleFlight, SingleFlightLeader, SingleFlightTicket,
};

/// The top-level sharded cache: one `Shard` (its own lock, its own slice
/// of `max_entries`) per configured shard, routed to by `shard_index`.
pub struct ShardedDnsCache {
    shards: Vec<Shard>,
}

impl ShardedDnsCache {
    /// Builds one `Shard` per `config.resolved_shard_count()`, splitting
    /// `config.max_entries` across them via `config.shard_capacity` (the
    /// exact remainder-distributed formula from section-01 — not
    /// recomputed here). Each shard also carries the RFC 8767 serve-stale
    /// window (`None` when `serve_stale_enabled` is off), fixed for the
    /// process lifetime like the shard count itself.
    pub fn new(config: &crate::config::CacheConfig) -> Self {
        let stale_window = config.serve_stale_enabled.then_some(config.max_stale);
        let shard_count = config.resolved_shard_count();
        let shards = (0..shard_count)
            .map(|index| {
                Shard::with_stale_window(config.shard_capacity(index, shard_count), stale_window)
            })
            .collect();
        Self { shards }
    }

    /// The number of shards this cache was built with — exposed so
    /// callers (`ResolveQuery`'s construction, section-07) can build a
    /// `ShardedSingleFlight` with a matching shard count, keeping "shard
    /// N" meaning the same domain-routing bucket in both structures.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Routes to the one shard responsible for `domain`, via `shard_index`.
    /// Kept private/crate-visible: external callers (the `DomainDnsCache`
    /// impl below, tests) go through `assemble::resolve_from_cache` or the
    /// trait methods, except where a section-06 test needs to reach into a
    /// specific shard to set up fixture state directly.
    fn shard_for(&self, domain: &str) -> &Shard {
        &self.shards[shard_index(domain, self.shards.len())]
    }
}

/// One backend response, decomposed into what the sharded cache actually
/// stores: an `RRsetEntry` per `(name, qtype, qclass)` that was actually
/// present in the answer (every CNAME hop's own RRset included), plus, if
/// the terminal result was negative, a single `NegativeEntry` for that
/// terminal name.
///
/// `negative`'s `NegativeKey` is not part of the plan's literal listing
/// (which only lists `(String, NegativeEntry)`) — added because the key's
/// `qtype: Option<u16>` (whole-name NXDOMAIN vs. NODATA-for-a-specific-type)
/// can't be derived from `NegativeEntry` alone; the caller building this
/// struct (`resolver::mod`'s store-decomposition logic, which already
/// knows the original query's qtype) supplies it directly instead.
#[derive(Debug, Clone)]
pub struct DecomposedResponse {
    pub positive: Vec<(String, u16, u16, RRsetEntry)>,
    pub negative: Option<(String, NegativeKey, NegativeEntry)>,
}

/// Trait boundary between `resolver::mod`'s call sites and the concrete
/// cache implementation — replaces the old flat `DnsCache` trait
/// (`lookup`/`store` keyed on a flat `CacheKey`). Implemented by
/// `ShardedDnsCache` (below) and `NoopDnsCache` (`resolver::mod`, unchanged
/// name, new trait).
pub trait DomainDnsCache: Send + Sync {
    /// Chain-aware lookup — replaces the old flat `lookup`. Internally
    /// calls `resolve_from_cache` (section-06).
    ///
    /// `max_chain_depth` is not in the plan's literal listed trait
    /// signature — added for the same reason `resolve_from_cache` itself
    /// needs it (section-06's documented deviation): the depth bound
    /// (`RecursiveResolverConfig.max_cname_restarts`) isn't reachable from
    /// this trait's other inputs, so callers thread it through explicitly.
    ///
    /// `dnssec_ok` is likewise not in the plan's literal listing — added
    /// so a DO=true lookup can reject a hit against an entry whose DNSSEC
    /// material isn't confirmed complete (see `RRsetEntry::dnssec_complete`
    /// and `Shard::lookup_hop`), the fix for the stale-DO-false-entry bug:
    /// without this, a DO=false request's cache miss could populate an
    /// entry with no RRSIGs, and a later DO=true request would be served
    /// that same entry as a hit for its full remaining TTL, never
    /// re-fetching with DNSSEC material actually requested.
    #[allow(clippy::too_many_arguments)]
    fn lookup_chain(
        &self,
        qname: &str,
        qtype: u16,
        qclass: u16,
        dnssec_ok: bool,
        epoch: u64,
        max_chain_depth: u8,
        now: SystemTime,
        refresh_config: &RefreshConfig,
    ) -> ChainLookup;

    /// Replaces the old flat `store` — called once per backend response,
    /// storing the already-decomposed `RRsetEntry`/`NegativeEntry` values.
    fn store_response(&self, decomposed: DecomposedResponse, epoch: u64);

    /// Reclaims entries whose stored `cache_epoch` no longer equals
    /// `current_epoch` — pure memory reclamation, not a correctness
    /// dependency, since `lookup_chain` already treats an epoch mismatch as
    /// a miss regardless of whether this has run. Called from the reload
    /// path (`ResolveQuery::publish_reload`). The name is retained from
    /// the pre-epoch string-namespace design; it no longer compares
    /// namespaces.
    fn sweep_stale_namespace(&self, current_epoch: u64);

    /// Approximate (sum-across-shards, no single lock) domain count, for
    /// the `OpenTelemetryMetrics` gauges.
    fn domain_count(&self) -> usize;

    fn capacity(&self) -> usize;
}

impl DomainDnsCache for ShardedDnsCache {
    fn lookup_chain(
        &self,
        qname: &str,
        qtype: u16,
        qclass: u16,
        dnssec_ok: bool,
        epoch: u64,
        max_chain_depth: u8,
        now: SystemTime,
        refresh_config: &RefreshConfig,
    ) -> ChainLookup {
        assemble::resolve_from_cache(
            self,
            qname,
            qtype,
            qclass,
            dnssec_ok,
            epoch,
            max_chain_depth,
            now,
            refresh_config,
        )
    }

    fn store_response(&self, decomposed: DecomposedResponse, epoch: u64) {
        // Stamps the current epoch onto every entry at store time (rather
        // than trusting the caller's `DecomposedResponse` to have already
        // set it correctly) so there is exactly one place that decides what
        // epoch a freshly-stored entry belongs to.
        for (name, qtype, qclass, mut entry) in decomposed.positive {
            entry.cache_epoch = epoch;
            self.shard_for(&name)
                .store_positive(&name, (qtype, qclass), entry);
        }
        if let Some((name, key, mut entry)) = decomposed.negative {
            entry.cache_epoch = epoch;
            self.shard_for(&name).store_negative(&name, key, entry);
        }
    }

    fn sweep_stale_namespace(&self, current_epoch: u64) {
        namespace::sweep_stale_namespace(&self.shards, current_epoch);
    }

    fn domain_count(&self) -> usize {
        self.shards.iter().map(Shard::domain_count).sum()
    }

    fn capacity(&self) -> usize {
        self.shards.iter().map(Shard::capacity).sum()
    }
}

/// Routes a domain name to a shard index in `[0, shard_count)`. Shared by
/// the cache shards (`cache::shard`, section-03) and the single-flight
/// shards (`cache::singleflight`, section-04) — both structures shard
/// purely by domain name, so a single hashing implementation keeps their
/// routing behavior identical and avoids duplicated hashing logic.
///
/// `domain` is expected to already be normalized (lowercased, trailing dot
/// stripped — the same normalization `normalize_question_name` applies in
/// `resolver::mod`) by the caller; this function does not normalize
/// internally, so two differently-cased spellings of the same domain will
/// only route to the same shard if the caller normalizes first. Every call
/// site added in later sections normalizes before calling this.
///
/// `shard_count` is expected to be at least 1 in real use (see
/// `CacheConfig::resolved_shard_count`); `shard_count == 0` is handled
/// defensively (returns 0) rather than panicking, since this is a cheap
/// routing function, not a place to enforce config invariants.
///
/// Hashes with a per-process-random `RandomState` (the same builder
/// `std::collections::HashMap`'s own default uses), generated once and
/// reused for every call via `PROCESS_SHARD_HASH_SEED` — not
/// `DefaultHasher::new()`'s fixed, well-known seed, which would make shard
/// routing predictable across restarts. Reusing one seed per process (
/// rather than randomizing per call) is what keeps routing deterministic
/// *within* one running resolver's lifetime: the same domain must always
/// land in the same shard for as long as this process is up, or every
/// lookup would miss its own just-stored entry.
#[allow(dead_code)]
pub(crate) fn shard_index(domain: &str, shard_count: usize) -> usize {
    if shard_count == 0 {
        return 0;
    }
    static PROCESS_SHARD_HASH_SEED: OnceLock<RandomState> = OnceLock::new();
    let build_hasher = PROCESS_SHARD_HASH_SEED.get_or_init(RandomState::new);
    (build_hasher.hash_one(domain) % shard_count as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn shard_index_is_deterministic_for_same_input() {
        let first = shard_index("example.com", 16);
        let second = shard_index("example.com", 16);
        assert_eq!(first, second);
    }

    #[test]
    fn shard_index_stays_within_bounds() {
        let domains = [
            "example.com",
            "a.example.com",
            "www.example.org",
            "sub.domain.example.net",
            "localhost",
        ];
        for shard_count in [1usize, 2, 8, 17] {
            for domain in domains {
                let index = shard_index(domain, shard_count);
                assert!(
                    index < shard_count,
                    "index {index} out of bounds for shard_count {shard_count} (domain {domain})"
                );
            }
        }
    }

    #[test]
    fn shard_index_distributes_distinct_domains_across_shards() {
        let shard_count = 16;
        let mut seen = HashSet::new();
        for i in 0..200 {
            let domain = format!("host-{i}.example.com");
            seen.insert(shard_index(&domain, shard_count));
        }
        assert!(
            seen.len() > 1,
            "expected distinct domains to spread across more than one shard"
        );
    }

    #[test]
    fn shard_index_returns_zero_for_zero_shard_count() {
        assert_eq!(shard_index("example.com", 0), 0);
    }

    #[test]
    fn sharded_dns_cache_never_creates_zero_capacity_shards_when_max_entries_positive() {
        // Regression test: a `CacheConfig` with `shard_count` greater than
        // `max_entries` used to silently create shards with capacity 0
        // (`max_entries / shard_count` floors to 0 for every shard past
        // index `max_entries`). `Shard::store_positive`/`store_negative`
        // are no-ops at capacity 0, so any domain hashing into one of
        // those shards could never be cached — a permanent, silent miss
        // storm under a configuration that looks valid.
        // `CacheConfig::resolved_shard_count` now caps the effective shard
        // count at `max_entries` to prevent this.
        let config = crate::config::CacheConfig {
            max_entries: 5,
            shard_count: Some(64),
            ..crate::config::CacheConfig::default()
        };
        let cache = ShardedDnsCache::new(&config);
        assert_eq!(
            cache.shard_count(),
            5,
            "shard count should be capped at max_entries"
        );
        for shard in &cache.shards {
            assert!(
                shard.capacity() > 0,
                "every shard must retain at least one domain's worth of capacity"
            );
        }
    }
}
