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

//! `Shard`/`ShardState` combine one shard's positive cache, negative
//! cache, and LRU behind a single lock, plus the eviction loop that keeps
//! all three in sync when the shard reaches capacity. All data for a
//! given domain — its positive record sets, its negative-cache entries,
//! and its LRU recency token — lives in exactly one shard and is mutated
//! together, atomically, under that shard's single lock.
//!
//! `ShardedDnsCache` (`mod.rs`) routes production lookups/stores through
//! `Shard`, so most of this module is exercised outside tests now.
//! `#[allow(dead_code)]` below only covers the handful of methods (e.g.
//! `Shard::touch`) that remain test-only conveniences.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::entry::{
    DnssecState, DomainNegativeEntries, DomainRecordSets, NegativeEntry, NegativeKey, RRsetEntry,
};
use super::lru::ShardLru;
use crate::config::{LeakRate, RefreshConfig};
use crate::protocol::RecordData;

const CNAME_RECORD_TYPE: u16 = 5;

/// Per-domain leaky-bucket popularity tracker. Created the first time a
/// domain is stored (mirroring `ShardLru`'s own on-first-store creation),
/// drained-then-incremented on every subsequent lookup hit, and removed
/// alongside the LRU token's own two removal points
/// (`ShardState::evict_domain`, `ShardState::drop_lru_if_domain_now_empty`)
/// — this keeps popularity state from drifting out of sync with which
/// domains still have cached data via those two paths. Note
/// `sweep_stale_namespace` clears a domain's LRU token directly without
/// going through either of those two functions, so a bucket can currently
/// outlive its domain's data when cleared via a namespace sweep instead —
/// an accepted gap matching the plan's explicit scope (only the two named
/// removal points are in scope for popularity cleanup).
///
/// Granularity is per-domain (qname only), not per-`(qname, qtype, qclass)`
/// — matching `ShardLru`'s own granularity. A query for any record type
/// under a domain raises that domain's popularity.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PopularityBucket {
    level: u32,
    last_drained: SystemTime,
}

impl PopularityBucket {
    /// A fresh bucket for a domain seen for the first time: zero level,
    /// drained as of `now`.
    fn new(now: SystemTime) -> Self {
        Self {
            level: 0,
            last_drained: now,
        }
    }

    /// Drains the bucket by elapsed time since `last_drained`, then adds
    /// `hit_increment`, saturating at `capacity`. Uses integer arithmetic
    /// throughout (no floats) to avoid long-uptime rounding drift.
    ///
    /// `now` must be >= `last_drained` under normal operation; a `now` that
    /// appears to go backward (clock adjustment) is treated as zero elapsed
    /// time rather than panicking or underflowing — `last_drained` is never
    /// moved backward.
    ///
    /// Truncation-bias avoidance: converting elapsed time to leaked units
    /// naively (`elapsed * leak_rate.units / leak_rate.per`, discarding the
    /// remainder, then setting `last_drained = now`) would silently bias the
    /// drain low whenever elapsed time is repeatedly smaller than one full
    /// drain unit. Avoided here by only ever advancing `last_drained` by the
    /// exact amount of time actually "spent" on the whole leaked units
    /// applied this call, leaving any leftover sub-unit elapsed time still
    /// pending against `last_drained` for the next call to pick up — never
    /// simply resetting `last_drained = now`.
    fn drain_and_increment(
        &mut self,
        now: SystemTime,
        leak_rate: LeakRate,
        hit_increment: u32,
        capacity: u32,
    ) {
        let elapsed = now.duration_since(self.last_drained).unwrap_or_default();
        if leak_rate.units > 0 && !leak_rate.per.is_zero() {
            let leaked_units_wide =
                elapsed.as_nanos() * u128::from(leak_rate.units) / leak_rate.per.as_nanos().max(1);
            let leaked_units = u32::try_from(leaked_units_wide).unwrap_or(u32::MAX);
            if leaked_units > 0 {
                self.level = self.level.saturating_sub(leaked_units);
                let time_spent = leak_rate.per * leaked_units / leak_rate.units;
                self.last_drained += time_spent;
            }
        }
        self.level = self.level.saturating_add(hit_increment).min(capacity);
    }

    /// True if `level >= hot_threshold` (an absolute count derived elsewhere
    /// from `RefreshConfig::hot_threshold_fraction * bucket_capacity` — this
    /// method just takes the precomputed absolute threshold).
    fn is_hot(&self, hot_threshold: u32) -> bool {
        self.level >= hot_threshold
    }

    #[cfg(test)]
    fn level(&self) -> u32 {
        self.level
    }
}

/// Result of one hop's lookup within `resolve_from_cache`'s CNAME-chain
/// walk (`cache::assemble`, section-06) — whatever this shard found (or
/// didn't) for one name in the chain, already cloned out from under this
/// shard's lock.
#[derive(Debug, Clone)]
pub(crate) enum HopResult {
    /// A record set matching the queried `(qtype, qclass)` directly, plus
    /// whether this hop currently wants a proactive refresh
    /// (`wants_refresh`, computed inside `lookup_hop` while the lock —
    /// and this domain's popularity bucket — is already held). Entries are
    /// handed out as `Arc` clones of the shard's stored value (a refcount
    /// bump under the lock, not a deep copy).
    Answer(Arc<RRsetEntry>, bool),
    /// The queried type wasn't found, but a CNAME record set was — carries
    /// the CNAME's own entry (for the response's answer section), the
    /// extracted target name to continue the walk, and whether this hop
    /// wants a proactive refresh.
    CnameHop(Arc<RRsetEntry>, String, bool),
    /// NODATA for the queried type at this (existing) name. Negative
    /// entries never carry a refresh signal (v1 scope is positive-entries
    /// only), so there is no bool here.
    NoData(Arc<NegativeEntry>),
    /// Whole-name NXDOMAIN at this name. Same scope note as `NoData`.
    NxDomain(Arc<NegativeEntry>),
    /// Nothing usable here: absent, expired, or stored under a stale
    /// namespace.
    Miss,
}

#[derive(Debug, Default)]
struct PositiveShardState {
    domains: HashMap<String, DomainRecordSets>,
}

#[derive(Debug, Default)]
struct NegativeShardState {
    domains: HashMap<String, DomainNegativeEntries>,
}

#[derive(Debug, Default)]
struct ShardState {
    positive: PositiveShardState,
    negative: NegativeShardState,
    lru: ShardLru,
    popularity: HashMap<String, PopularityBucket>,
}

impl ShardState {
    /// Removes `domain` from both the positive and negative maps
    /// (unconditionally — capacity counts a domain once regardless of
    /// whether it holds positive data, negative data, or both) and clears
    /// its LRU position.
    fn evict_domain(&mut self, domain: &str) {
        self.positive.domains.remove(domain);
        self.negative.domains.remove(domain);
        self.lru.remove(domain);
        self.popularity.remove(domain);
    }

    /// Drains-then-increments `domain`'s popularity bucket, allocating it on
    /// first hit. A complete no-op — the bucket is never allocated at all,
    /// not merely "left untouched" — when `enabled` is false.
    fn record_popularity_hit(
        &mut self,
        domain: &str,
        now: SystemTime,
        enabled: bool,
        leak_rate: LeakRate,
        hit_increment: u32,
        bucket_capacity: u32,
    ) {
        if !enabled {
            return;
        }
        // `get_mut` before falling back to insertion: the bucket already
        // exists on every hit but the first, and the `entry` API would
        // allocate an owned key for each of those hits just to discard it.
        if let Some(bucket) = self.popularity.get_mut(domain) {
            bucket.drain_and_increment(now, leak_rate, hit_increment, bucket_capacity);
            return;
        }
        let mut bucket = PopularityBucket::new(now);
        bucket.drain_and_increment(now, leak_rate, hit_increment, bucket_capacity);
        self.popularity.insert(domain.to_string(), bucket);
    }

    /// Shared by `lookup_hop`'s `Answer`/`CnameHop` branches: records this
    /// hit against `domain`'s popularity bucket, then evaluates
    /// `wants_refresh` against the just-updated bucket (so this same hit's
    /// own increment counts toward its own hot-threshold determination —
    /// deterministic read-after-write within one lock scope, not a race).
    fn record_hit_and_check_refresh(
        &mut self,
        domain: &str,
        entry_minimum_ttl: Duration,
        entry_expires_at: SystemTime,
        now: SystemTime,
        refresh_config: &RefreshConfig,
    ) -> bool {
        self.record_popularity_hit(
            domain,
            now,
            refresh_config.enabled,
            refresh_config.leak_rate,
            refresh_config.hit_increment,
            refresh_config.bucket_capacity,
        );
        let remaining_ttl = entry_expires_at.duration_since(now).unwrap_or_default();
        wants_refresh(
            entry_minimum_ttl,
            remaining_ttl,
            self.popularity.get(domain),
            refresh_config,
        )
    }

    /// `record_hit_and_check_refresh`, generalized over staleness: a live
    /// hit runs the normal three-gate `wants_refresh` formula; a stale hit
    /// still records the popularity hit (a stale serve is real client
    /// demand) but wants a refresh *unconditionally* — stale data was just
    /// served, so refetching is mandatory, not a popularity-gated
    /// optimization (RFC 8767 §4: attempt to refresh whenever stale data
    /// is served). Gated on `refresh_config.enabled` because the refresh
    /// worker pool is the only machinery that can execute the refetch;
    /// `RuntimeConfig::validate` rejects serve-stale without it, so this
    /// gate is unreachable in a validated config and exists only to keep
    /// directly-constructed (test) configs from signaling refreshes nobody
    /// can service.
    fn record_hit_and_check_refresh_maybe_stale(
        &mut self,
        domain: &str,
        entry: &RRsetEntry,
        stale: bool,
        now: SystemTime,
        refresh_config: &RefreshConfig,
    ) -> bool {
        if stale {
            self.record_popularity_hit(
                domain,
                now,
                refresh_config.enabled,
                refresh_config.leak_rate,
                refresh_config.hit_increment,
                refresh_config.bucket_capacity,
            );
            return refresh_config.enabled;
        }
        self.record_hit_and_check_refresh(
            domain,
            entry.minimum_ttl,
            entry.expires_at,
            now,
            refresh_config,
        )
    }

    /// Evicts the least-recently-touched domain, if any is tracked.
    fn evict_oldest(&mut self) {
        if let Some(oldest) = self.lru.peek_oldest() {
            let oldest = oldest.to_string();
            self.evict_domain(&oldest);
        }
    }

    /// Ensures there is room for a new domain (i.e. one not already
    /// tracked by this shard) by evicting the least-recently-touched
    /// domain if the shard is already at `capacity`. A no-op if `domain`
    /// is already tracked, since inserting more data under an existing
    /// domain does not increase the domain count.
    fn make_room_for(&mut self, domain: &str, capacity: usize) {
        if self.domain_is_tracked(domain) {
            return;
        }
        if self.lru.len() >= capacity {
            self.evict_oldest();
        }
    }

    fn domain_is_tracked(&self, domain: &str) -> bool {
        self.lru.contains(domain)
    }

    /// Removes exactly one positive record set (`domain`, `key`) — e.g. an
    /// expired entry encountered during a lookup — and drops `domain`'s LRU
    /// token too if that leaves it with no positive or negative data left
    /// in this shard. Mirrors `evict_domain`/`sweep_stale_namespace`'s
    /// empty-domain cleanup, just scoped to a single record set instead of
    /// every entry for a domain or every stale-namespace entry shard-wide.
    fn remove_positive_entry(&mut self, domain: &str, key: (u16, u16)) {
        if let Some(record_sets) = self.positive.domains.get_mut(domain) {
            record_sets.record_sets.remove(&key);
            if record_sets.record_sets.is_empty() {
                self.positive.domains.remove(domain);
            }
        }
        self.drop_lru_if_domain_now_empty(domain);
    }

    /// Removes exactly one negative-cache entry (`domain`, `key`) — same
    /// contract as `remove_positive_entry`, for the negative-cache side.
    fn remove_negative_entry(&mut self, domain: &str, key: &NegativeKey) {
        if let Some(entries) = self.negative.domains.get_mut(domain) {
            entries.entries.remove(key);
            if entries.entries.is_empty() {
                self.negative.domains.remove(domain);
            }
        }
        self.drop_lru_if_domain_now_empty(domain);
    }

    fn drop_lru_if_domain_now_empty(&mut self, domain: &str) {
        if !self.positive.domains.contains_key(domain)
            && !self.negative.domains.contains_key(domain)
        {
            self.lru.remove(domain);
            self.popularity.remove(domain);
        }
    }

    /// Single-probe positive-answer lookup for `Shard::lookup_hop`: probes
    /// `domain`/`key` in the positive map exactly once and, from that one
    /// borrow, decides in-place whether the candidate is expired (removing
    /// it via `remove_positive_entry` and returning `None`), live and
    /// usable (cloning it out and returning `Some((entry, false))`),
    /// expired-but-stale-servable (cloning it out and returning
    /// `Some((entry, true))` — see `stale_servability` for exactly when),
    /// or neither (a namespace mismatch or DO-incompleteness, left in
    /// place for other requesters/namespaces — returning `None` without
    /// removing anything).
    /// Replaces the previous two-probe shape (an `is_some_and` expiry
    /// precheck followed by a second, independent `.filter(..).cloned()`
    /// lookup) that double-locked-and-hashed the common cache-hit path just
    /// to support the uncommon expired-entry-eviction case.
    fn take_live_positive(
        &mut self,
        domain: &str,
        key: (u16, u16),
        dnssec_ok: bool,
        current_epoch: u64,
        now: SystemTime,
        stale_window: Option<Duration>,
    ) -> Option<(Arc<RRsetEntry>, bool)> {
        let expired = match self
            .positive
            .domains
            .get(domain)
            .and_then(|record_sets| record_sets.record_sets.get(&key))
        {
            None => return None,
            Some(entry) if entry.expires_at <= now => {
                match stale_servability(entry, dnssec_ok, current_epoch, now, stale_window) {
                    StaleServability::Servable => return Some((entry.clone(), true)),
                    StaleServability::KeepButMiss => return None,
                    StaleServability::Evict => true,
                }
            }
            Some(entry) => {
                if entry.cache_epoch == current_epoch && (!dnssec_ok || entry.dnssec_complete) {
                    return Some((entry.clone(), false));
                }
                false
            }
        };
        if expired {
            self.remove_positive_entry(domain, key);
        }
        None
    }

    /// `take_live_positive`'s sibling for the CNAME-hop candidate: same
    /// single-probe expired/live/stale/absent decision, plus extracting the
    /// CNAME's target name from the entry's records. A *live* entry
    /// whose records don't actually contain a CNAME (unexpected/corrupt
    /// data) is treated as absent for this call — same as before — without
    /// being removed, since only genuine TTL expiry warrants removal here.
    /// An *expired* (stale-servable) entry with no extractable CNAME is
    /// evicted instead: it already satisfies the one removal criterion (TTL
    /// expiry), and serving it stale — the only thing that justified keeping
    /// an expired entry — is impossible without a target, so leaving it
    /// would park unusable expired data in the shard until the stale window
    /// ran out, where the pre-serve-stale code cleaned it up on first read
    /// (PR #142 review finding).
    fn take_live_cname_hop(
        &mut self,
        domain: &str,
        key: (u16, u16),
        dnssec_ok: bool,
        current_epoch: u64,
        now: SystemTime,
        stale_window: Option<Duration>,
    ) -> Option<(Arc<RRsetEntry>, String, bool)> {
        let cname_target = |entry: &RRsetEntry| {
            entry.records.iter().find_map(|record| match &record.rdata {
                RecordData::CNAME(target) => Some(target.clone()),
                _ => None,
            })
        };
        let expired = match self
            .positive
            .domains
            .get(domain)
            .and_then(|record_sets| record_sets.record_sets.get(&key))
        {
            None => return None,
            Some(entry) if entry.expires_at <= now => {
                match stale_servability(entry, dnssec_ok, current_epoch, now, stale_window) {
                    StaleServability::Servable => match cname_target(entry) {
                        Some(target) => return Some((entry.clone(), target, true)),
                        // Admitted as stale-servable but nothing to serve:
                        // expired + unusable ⇒ evict (see doc comment).
                        None => true,
                    },
                    StaleServability::KeepButMiss => return None,
                    StaleServability::Evict => true,
                }
            }
            Some(entry) => {
                if entry.cache_epoch == current_epoch
                    && (!dnssec_ok || entry.dnssec_complete)
                    && let Some(target) = cname_target(entry)
                {
                    return Some((entry.clone(), target, false));
                }
                false
            }
        };
        if expired {
            self.remove_positive_entry(domain, key);
        }
        None
    }

    /// `take_live_positive`'s sibling for negative-cache candidates
    /// (NODATA and NXDOMAIN share this — callers pass the appropriate
    /// `NegativeKey`): same single-probe expired/live/absent decision, with
    /// the negative-entry-specific DNSSEC-proof-freshness check folded into
    /// the "live" condition.
    fn take_live_negative(
        &mut self,
        domain: &str,
        key: &NegativeKey,
        dnssec_ok: bool,
        current_epoch: u64,
        now: SystemTime,
    ) -> Option<Arc<NegativeEntry>> {
        let expired = match self
            .negative
            .domains
            .get(domain)
            .and_then(|entries| entries.entries.get(key))
        {
            None => return None,
            Some(entry) if entry.expires_at <= now => true,
            Some(entry) => {
                if entry.cache_epoch == current_epoch
                    && (!dnssec_ok
                        || (entry.dnssec_complete && entry.dnssec_proof_material_fresh(now)))
                {
                    return Some(entry.clone());
                }
                false
            }
        };
        if expired {
            self.remove_negative_entry(domain, key);
        }
        None
    }
}

/// What to do with a positive entry found *expired* (`expires_at <= now`)
/// during a lookup, under RFC 8767 serve-stale. Only TTL expiry routes
/// through this — live entries never reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleServability {
    /// Within the stale window and admissible for *this* reader: serve it
    /// (with the stale wire TTL, `cache::assemble::STALE_WIRE_TTL_SECS`)
    /// and signal an unconditional background refresh.
    Servable,
    /// Within the stale window but not admissible for this reader (a
    /// DO=true reader vs. `dnssec_complete == false`): a miss for this
    /// caller, but the entry stays — a DO=false reader can still be
    /// stale-served from it.
    KeepButMiss,
    /// Not stale-servable by anyone — serve-stale disabled, beyond the
    /// window, stamped with a stale epoch, or carrying any record whose
    /// *origin* TTL (`StoredRecord::ttl_at_store`) was 0 (RFC 1035: TTL 0
    /// means "this transaction only", so it must never outlive its expiry,
    /// let alone be served stale — checked per record, since a
    /// `min_positive_ttl` floor makes the entry-level `minimum_ttl` nonzero
    /// even for such records). Evict at read time, exactly as every
    /// expired entry was before serve-stale existed.
    Evict,
}

/// Decides `StaleServability` for one expired positive entry. Epoch
/// equality is required even for stale service: an epoch mismatch means
/// resolution-affecting config changed since this was stored, and RFC 8767
/// staleness is about *time*, never about serving answers a config change
/// already invalidated. `checked_add` guards the window arithmetic — an
/// overflowing `expires_at + window` (corrupt clock territory) fails
/// closed to `Evict` rather than panicking.
fn stale_servability(
    entry: &RRsetEntry,
    dnssec_ok: bool,
    current_epoch: u64,
    now: SystemTime,
    stale_window: Option<Duration>,
) -> StaleServability {
    let Some(window) = stale_window else {
        return StaleServability::Evict;
    };
    if entry.cache_epoch != current_epoch {
        return StaleServability::Evict;
    }
    // A `Bogus` entry must never be served via serve-stale, regardless of
    // window or TTL state -- serving a known-tampered response past its
    // expiration defeats the point of validating it in the first place.
    // Checked early, ahead of the window/zero-TTL checks below, since no
    // other condition can make a `Bogus` entry servable.
    if matches!(entry.dnssec_state, DnssecState::Bogus(_)) {
        return StaleServability::Evict;
    }
    // The TTL-0 exclusion checks each stored record's own origin TTL
    // (`ttl_at_store`), not `entry.minimum_ttl`: with a configured
    // `min_positive_ttl` floor, `minimum_ttl` is the policy-bounded cache
    // lifetime, which the floor makes nonzero even for a record the origin
    // published with TTL 0 — exactly the record RFC 1035 says must not
    // outlive its transaction. RRSIGs are included since a DO=true stale
    // serve would put them on the wire too.
    let has_zero_origin_ttl = entry
        .records
        .iter()
        .chain(entry.rrsigs.iter())
        .any(|record| record.ttl_at_store == 0);
    if has_zero_origin_ttl {
        return StaleServability::Evict;
    }
    let within_window = entry
        .expires_at
        .checked_add(window)
        .is_some_and(|stale_until| now < stale_until);
    if !within_window {
        return StaleServability::Evict;
    }
    if dnssec_ok && !entry.dnssec_complete {
        return StaleServability::KeepButMiss;
    }
    StaleServability::Servable
}

/// Pure trigger-formula check — see
/// `docs/knowledge/resolver/caching/auto-refresh.md` for the full formula.
/// Given a live entry's own TTL data, the domain's current popularity bucket
/// (if any — a domain that has never been hit, or whose bucket was evicted
/// alongside its LRU entry, has no bucket and is therefore never hot), and
/// refresh-config thresholds, decides whether the entry currently "wants" a
/// proactive background refresh.
///
/// This does not mutate anything, perform any I/O, or take any lock beyond
/// what the caller already holds — it is a pure function of data the
/// live-entry probes (`take_live_positive`/`take_live_cname_hop`) already
/// have in hand. It also does not change what those probes return as the
/// *served* answer; it only decides whether to *additionally* signal "this
/// entry wants a refresh" (consumed by section-04's `ChainLookup`/
/// `RefreshHint` plumbing).
///
/// All three independent gates must hold for this to return `true`:
/// 1. **Eligibility floor**: `original_ttl >= config.eligibility_floor`.
///    Entries below this floor are never refresh-eligible regardless of
///    remaining TTL or popularity — this exists to avoid refresh thrash on
///    very-short-TTL records.
/// 2. **Lead window**: `remaining_ttl <= max(original_ttl * config.lead_ratio,
///    config.min_lead)`.
/// 3. **Popularity**: the domain's bucket, if present, is hot at the
///    threshold derived from `config.hot_threshold_fraction *
///    config.bucket_capacity` (rounded to the nearest `u32`); a missing
///    bucket (`None`) is never hot.
///
/// Callers in `lookup_hop` pass the bucket *after* recording the current
/// hit (`record_hit_and_check_refresh`), so this same hit's own increment
/// counts toward its own hot-threshold determination — a domain becomes
/// "hot" and can produce a refresh hint on the very hit that pushes its
/// bucket over the threshold, not only on a subsequent one. Deterministic
/// (both happen under the same lock, back-to-back), not a race.
pub(crate) fn wants_refresh(
    original_ttl: Duration,
    remaining_ttl: Duration,
    bucket: Option<&PopularityBucket>,
    config: &RefreshConfig,
) -> bool {
    if original_ttl < config.eligibility_floor {
        return false;
    }
    let lead = original_ttl.mul_f32(config.lead_ratio).max(config.min_lead);
    if remaining_ttl > lead {
        return false;
    }
    let hot_threshold =
        (config.hot_threshold_fraction * config.bucket_capacity as f32).round() as u32;
    bucket.is_some_and(|b| b.is_hot(hot_threshold))
}

/// One shard of the sharded DNS cache: its own lock, its own share of the
/// total configured capacity (the exact remainder-distributed per-shard
/// capacity from `CacheConfig`, section-01 — not a naive
/// `ceil(max_entries / shard_count)`).
#[derive(Debug)]
pub(crate) struct Shard {
    state: Mutex<ShardState>,
    capacity: usize,
    /// RFC 8767 serve-stale window: how long past `expires_at` a positive
    /// entry remains servable (with a background refresh) instead of being
    /// evicted at read time. `None` disables serve-stale entirely,
    /// restoring the original expired-means-evict lookup behavior. Fixed at
    /// construction from `CacheConfig` (`serve_stale_enabled`/`max_stale`)
    /// — startup-only, like shard count and capacity.
    stale_window: Option<Duration>,
}

impl Shard {
    pub(crate) fn new(capacity: usize) -> Self {
        Self::with_stale_window(capacity, None)
    }

    pub(crate) fn with_stale_window(capacity: usize, stale_window: Option<Duration>) -> Self {
        Self {
            state: Mutex::new(ShardState::default()),
            capacity,
            stale_window,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Stores one positive RRset for `domain` under `(qtype, qclass)`,
    /// evicting the least-recently-touched domain first if this is a new
    /// domain and the shard is already at capacity. A no-op if
    /// `capacity == 0`.
    pub(crate) fn store_positive(&self, domain: &str, key: (u16, u16), entry: RRsetEntry) {
        if self.capacity == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        state.make_room_for(domain, self.capacity);
        state
            .positive
            .domains
            .entry(domain.to_string())
            .or_default()
            .record_sets
            .insert(key, Arc::new(entry));
        state.lru.touch(domain);
    }

    /// Stores one negative-cache entry for `domain` under `key`, evicting
    /// the least-recently-touched domain first if this is a new domain
    /// and the shard is already at capacity. A no-op if `capacity == 0`.
    pub(crate) fn store_negative(&self, domain: &str, key: NegativeKey, entry: NegativeEntry) {
        if self.capacity == 0 {
            return;
        }
        let mut state = self.state.lock().unwrap();
        state.make_room_for(domain, self.capacity);
        state
            .negative
            .domains
            .entry(domain.to_string())
            .or_default()
            .entries
            .insert(key, Arc::new(entry));
        state.lru.touch(domain);
    }

    /// Records a lookup/hit against `domain` without changing its stored
    /// data — bumps its LRU recency the same way a real cache hit would.
    /// A no-op if `domain` has no live data in this shard.
    pub(crate) fn touch(&self, domain: &str) {
        let mut state = self.state.lock().unwrap();
        if state.domain_is_tracked(domain) {
            state.lru.touch(domain);
        }
    }

    /// Number of distinct domains currently occupying a capacity slot in
    /// this shard (positive data, negative data, or both — counted once).
    pub(crate) fn domain_count(&self) -> usize {
        self.state.lock().unwrap().lru.len()
    }

    /// One hop of `resolve_from_cache`'s CNAME-chain walk (`cache::assemble`,
    /// section-06): looks up `domain` for `(qtype, qclass)` directly,
    /// falls back to a CNAME record set at the same name if `qtype` itself
    /// isn't CNAME, then falls back to a negative entry (NODATA for
    /// `qtype`, then whole-name NXDOMAIN). Rejects expired or
    /// stale-namespace matches inline — independent of, and in addition
    /// to, section-05's bulk namespace sweep. Touches this domain's LRU
    /// position on any live match found, including CNAME hops. Takes and
    /// releases this shard's lock for the duration of this one hop only —
    /// callers must not hold it across hops.
    ///
    /// Any candidate entry found *expired* (`expires_at <= now`) — whether
    /// it would otherwise have been the answer, a CNAME hop, a NODATA, or
    /// an NXDOMAIN — is removed from this shard's map immediately, right
    /// here at lookup time, rather than merely being filtered out of this
    /// one call's result. Left alone, an expired entry would otherwise sit
    /// in the map (and hold its domain's LRU token) until an unrelated
    /// capacity eviction or the next namespace sweep happened to catch it.
    /// Removal drops the domain's LRU token too, but only once that domain
    /// has no other live positive or negative entry left in this shard
    /// (`ShardState::remove_positive_entry`/`remove_negative_entry`,
    /// mirroring `evict_domain`/`sweep_stale_namespace`'s own empty-domain
    /// cleanup). By contrast, a namespace mismatch or (for a DO=true
    /// lookup) a `dnssec_complete`/proof-freshness miss is *not* grounds
    /// for removal here — that entry may still be perfectly valid for a
    /// different namespace or a DO=false requester, so only genuine TTL
    /// expiry triggers eviction at this call site.
    ///
    /// `dnssec_ok` is the *reading* requester's own DO flag — not to be
    /// confused with any entry's own `dnssec_complete` (whether the entry
    /// was itself populated by a DO=true fetch). When `dnssec_ok` is true,
    /// every candidate entry (positive answer, CNAME hop, NODATA,
    /// NXDOMAIN) is additionally filtered on `entry.dnssec_complete`: an
    /// entry populated by a DO=false fetch cannot be trusted to reflect
    /// the true DNSSEC state (its empty `rrsigs`/`proof_records` might
    /// just mean "never asked"), so it must be treated the same as if it
    /// weren't present at all, falling through the same
    /// answer/CNAME/NODATA/NXDOMAIN/Miss chain a genuinely absent entry
    /// would. A DO=false reader is unaffected by `dnssec_complete` either
    /// way, since it never needs/emits RRSIGs.
    ///
    /// For NODATA/NXDOMAIN candidates specifically, a DO=true lookup is
    /// *also* filtered on `NegativeEntry::dnssec_proof_material_fresh`:
    /// `dnssec_complete` alone only proves this entry's DNSSEC material
    /// was confirmed at store time, not that the individually-TTLed SOA
    /// RRSIG/NSEC/NSEC3 proof records it carries are still within their
    /// own TTL as of `now` — those can expire well before the entry's
    /// overall SOA-derived `expires_at` does. The positive-answer path
    /// needs no equivalent extra check: `RRsetEntry::expires_at` is
    /// already derived from the minimum TTL across the whole backend
    /// answer section, which includes any RRSIGs stored alongside it (see
    /// `decompose_response_for_store`/`ttl_for_response`), so a positive
    /// entry's RRSIGs can never individually outlive `expires_at`. Negative
    /// entries have no equivalent guarantee: the SOA RRSIG/proof records
    /// live in the *authority* section and their TTLs play no part in the
    /// SOA-minimum-derived negative TTL computation, hence this dedicated
    /// read-time check.
    // lookup_hop threads cache-lookup and refresh-eligibility inputs
    // through one call; splitting adds indirection without benefit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn lookup_hop(
        &self,
        domain: &str,
        qtype: u16,
        qclass: u16,
        dnssec_ok: bool,
        current_epoch: u64,
        now: SystemTime,
        refresh_config: &RefreshConfig,
    ) -> HopResult {
        let mut state = self.state.lock().unwrap();
        let answer_key = (qtype, qclass);

        // Each candidate below probes its map exactly once, via
        // `take_live_positive`/`take_live_cname_hop`/`take_live_negative`:
        // one borrow decides expired-vs-live-vs-absent in a single pass
        // (expired candidates are removed from `state` from inside that
        // same call), rather than a separate expiry precheck followed by a
        // second, independent lookup for the live/filtered case.
        if let Some((entry, stale)) = state.take_live_positive(
            domain,
            answer_key,
            dnssec_ok,
            current_epoch,
            now,
            self.stale_window,
        ) {
            state.lru.touch(domain);
            let refresh_wanted = state.record_hit_and_check_refresh_maybe_stale(
                domain,
                &entry,
                stale,
                now,
                refresh_config,
            );
            return HopResult::Answer(entry, refresh_wanted);
        }

        if qtype != CNAME_RECORD_TYPE {
            let cname_key = (CNAME_RECORD_TYPE, qclass);
            if let Some((entry, target, stale)) = state.take_live_cname_hop(
                domain,
                cname_key,
                dnssec_ok,
                current_epoch,
                now,
                self.stale_window,
            ) {
                state.lru.touch(domain);
                let refresh_wanted = state.record_hit_and_check_refresh_maybe_stale(
                    domain,
                    &entry,
                    stale,
                    now,
                    refresh_config,
                );
                return HopResult::CnameHop(entry, target, refresh_wanted);
            }
        }

        let nodata_key = NegativeKey {
            qtype: Some(qtype),
            qclass,
        };
        if let Some(entry) =
            state.take_live_negative(domain, &nodata_key, dnssec_ok, current_epoch, now)
        {
            state.lru.touch(domain);
            state.record_popularity_hit(
                domain,
                now,
                refresh_config.enabled,
                refresh_config.leak_rate,
                refresh_config.hit_increment,
                refresh_config.bucket_capacity,
            );
            return HopResult::NoData(entry);
        }

        let nxdomain_key = NegativeKey {
            qtype: None,
            qclass,
        };
        if let Some(entry) =
            state.take_live_negative(domain, &nxdomain_key, dnssec_ok, current_epoch, now)
        {
            state.lru.touch(domain);
            state.record_popularity_hit(
                domain,
                now,
                refresh_config.enabled,
                refresh_config.leak_rate,
                refresh_config.hit_increment,
                refresh_config.bucket_capacity,
            );
            return HopResult::NxDomain(entry);
        }

        HopResult::Miss
    }

    /// Removes every positive/negative entry in this shard whose stored
    /// `cache_epoch` no longer matches `current_epoch`, and drops
    /// any domain (and its LRU token) left with no entries in either map
    /// afterward. Takes this shard's lock for the duration of the scan
    /// only — sweeping one shard never waits on any other shard's lock.
    /// Returns the total number of entries removed.
    pub(crate) fn sweep_stale_namespace(&self, current_epoch: u64) -> usize {
        let mut state = self.state.lock().unwrap();
        let mut removed = 0usize;
        let mut emptied_domains: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        state.positive.domains.retain(|domain, record_sets| {
            let before = record_sets.record_sets.len();
            record_sets
                .record_sets
                .retain(|_, entry| entry.cache_epoch == current_epoch);
            removed += before - record_sets.record_sets.len();
            let keep = !record_sets.record_sets.is_empty();
            if !keep {
                emptied_domains.insert(domain.clone());
            }
            keep
        });

        state.negative.domains.retain(|domain, entries| {
            let before = entries.entries.len();
            entries
                .entries
                .retain(|_, entry| entry.cache_epoch == current_epoch);
            removed += before - entries.entries.len();
            let keep = !entries.entries.is_empty();
            if !keep {
                emptied_domains.insert(domain.clone());
            }
            keep
        });

        for domain in emptied_domains {
            if !state.positive.domains.contains_key(&domain)
                && !state.negative.domains.contains_key(&domain)
            {
                state.lru.remove(&domain);
            }
        }

        removed
    }

    #[cfg(test)]
    pub(crate) fn contains_positive(&self, domain: &str, key: (u16, u16)) -> bool {
        self.state
            .lock()
            .unwrap()
            .positive
            .domains
            .get(domain)
            .is_some_and(|record_sets| record_sets.record_sets.contains_key(&key))
    }

    #[cfg(test)]
    pub(crate) fn contains_negative(&self, domain: &str, key: &NegativeKey) -> bool {
        self.state
            .lock()
            .unwrap()
            .negative
            .domains
            .get(domain)
            .is_some_and(|entries| entries.entries.contains_key(key))
    }

    #[cfg(test)]
    pub(crate) fn has_any_data(&self, domain: &str) -> bool {
        self.state.lock().unwrap().domain_is_tracked(domain)
    }

    #[cfg(test)]
    pub(crate) fn popularity_level(&self, domain: &str) -> Option<u32> {
        self.state
            .lock()
            .unwrap()
            .popularity
            .get(domain)
            .map(PopularityBucket::level)
    }

    /// Test-only: locks this shard's state and sleeps, to let a
    /// concurrency test prove some other shard's operations don't block on
    /// this one's lock.
    #[cfg(test)]
    pub(crate) fn hold_lock_for_test(&self, duration: std::time::Duration) {
        let _guard = self.state.lock().unwrap();
        std::thread::sleep(duration);
    }

    /// Test-only: domains in this shard's LRU, oldest-touched first. Lets a
    /// test assert relative recency ordering was left untouched by an
    /// operation (e.g. the namespace sweep) rather than just checking
    /// presence/absence.
    #[cfg(test)]
    pub(crate) fn lru_order_for_test(&self) -> Vec<String> {
        self.state.lock().unwrap().lru.order_for_test()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{RecordData, ResponseCode};
    use crate::resolver::NegativeCacheKind;
    use crate::resolver::cache::entry::StoredRecord;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    const IN_QCLASS: u16 = 1;
    const A_QTYPE: u16 = 1;

    fn stored_record() -> StoredRecord {
        StoredRecord {
            rtype: A_QTYPE,
            rclass: IN_QCLASS,
            ttl_at_store: 300,
            rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    fn rrset_entry() -> RRsetEntry {
        let now = SystemTime::now();
        RRsetEntry {
            records: vec![stored_record()],
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(300),
            stored_at: now,
            expires_at: now + Duration::from_secs(300),
            dnssec_state: Default::default(),
            cache_epoch: 1,
            dnssec_complete: true,
            authoritative: false,
        }
    }

    fn negative_entry() -> NegativeEntry {
        let now = SystemTime::now();
        NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: stored_record(),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_epoch: 1,
            dnssec_complete: true,
            dnssec_state: Default::default(),
            authoritative: false,
        }
    }

    #[test]
    fn domain_with_only_negative_entry_still_counts_toward_shard_capacity() {
        let shard = Shard::new(4);
        let key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative("nxdomain.example.com", key, negative_entry());

        assert_eq!(shard.domain_count(), 1);
    }

    #[test]
    fn evicting_a_domain_removes_both_positive_and_negative_data() {
        let shard = Shard::new(1);
        let domain = "both.example.com";
        let neg_key = NegativeKey {
            qtype: Some(28),
            qclass: IN_QCLASS,
        };
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
        shard.store_negative(domain, neg_key.clone(), negative_entry());
        assert_eq!(shard.domain_count(), 1);

        // Force eviction by storing a second, different domain into a
        // shard with capacity 1.
        shard.store_positive("other.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());

        assert!(!shard.has_any_data(domain));
        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
        assert!(!shard.contains_negative(domain, &neg_key));
        assert_eq!(shard.domain_count(), 1);
    }

    #[test]
    fn zero_capacity_shard_stores_nothing() {
        let shard = Shard::new(0);
        shard.store_positive("example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
        let neg_key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative("other.example.com", neg_key, negative_entry());

        assert_eq!(shard.domain_count(), 0);
        assert!(!shard.has_any_data("example.com"));
        assert!(!shard.has_any_data("other.example.com"));
    }

    #[test]
    fn eviction_removes_least_recently_used_domain_while_touched_ones_survive() {
        let shard = Shard::new(3);
        shard.store_positive("a.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
        shard.store_positive("b.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
        shard.store_positive("c.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());

        // Touch b and c (simulating cache hits) so a is the
        // least-recently-touched domain.
        shard.touch("b.example.com");
        shard.touch("c.example.com");

        // Storing a fourth, new domain in a full shard must evict "a".
        shard.store_positive("d.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());

        assert!(!shard.has_any_data("a.example.com"));
        assert!(shard.has_any_data("b.example.com"));
        assert!(shard.has_any_data("c.example.com"));
        assert!(shard.has_any_data("d.example.com"));
        assert_eq!(shard.domain_count(), 3);
    }

    #[test]
    fn adding_a_second_qtype_to_an_existing_domain_never_evicts_at_full_capacity() {
        let shard = Shard::new(2);
        shard.store_positive("a.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
        shard.store_positive("b.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
        assert_eq!(shard.domain_count(), 2);

        // Shard is now at capacity. Adding a second qtype under the
        // *same* domain "a.example.com" must not trigger eviction, since
        // the domain is already tracked and the domain count does not
        // increase.
        const AAAA_QTYPE: u16 = 28;
        shard.store_positive("a.example.com", (AAAA_QTYPE, IN_QCLASS), rrset_entry());

        assert_eq!(shard.domain_count(), 2);
        assert!(shard.contains_positive("a.example.com", (A_QTYPE, IN_QCLASS)));
        assert!(shard.contains_positive("a.example.com", (AAAA_QTYPE, IN_QCLASS)));
        assert!(shard.has_any_data("b.example.com"));
    }

    #[test]
    fn touching_only_the_negative_side_of_a_dual_entry_domain_keeps_it_recently_used() {
        let shard = Shard::new(2);
        let domain = "dual.example.com";
        let neg_key = NegativeKey {
            qtype: Some(28),
            qclass: IN_QCLASS,
        };
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
        shard.store_negative(domain, neg_key, negative_entry());
        shard.store_positive("other.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
        assert_eq!(shard.domain_count(), 2);

        // Touch only via the negative side of `domain`, then force an
        // eviction by storing a third, new domain. `domain` must survive
        // because it was the most recently touched, even though only its
        // negative entry was touched.
        shard.touch(domain);
        shard.store_positive("newcomer.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());

        assert!(shard.has_any_data(domain));
        assert!(!shard.has_any_data("other.example.com"));
        assert!(shard.has_any_data("newcomer.example.com"));
    }

    #[test]
    fn touch_on_untracked_domain_is_a_no_op() {
        let shard = Shard::new(4);
        shard.store_positive("a.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
        assert_eq!(shard.domain_count(), 1);

        shard.touch("never-stored.example.com");

        assert_eq!(shard.domain_count(), 1);
        assert!(!shard.has_any_data("never-stored.example.com"));
    }

    // Regression tests for the stale-DO-false-entry bug: `lookup_hop` must
    // treat a DO=true (`dnssec_ok = true`) lookup against an entry whose
    // `dnssec_complete` is `false` as though the entry weren't there at
    // all, falling through to `HopResult::Miss` rather than serving
    // possibly-incomplete DNSSEC material for the entry's full TTL.

    #[test]
    fn lookup_hop_treats_do_true_read_of_dnssec_incomplete_answer_as_miss() {
        let shard = Shard::new(4);
        let domain = "incomplete.example.com";
        let mut entry = rrset_entry();
        entry.dnssec_complete = false;
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);
        let now = SystemTime::now();

        let do_false_result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_false_result, HopResult::Answer(_, _)),
            "a DO=false reader may still be served from a dnssec-incomplete entry"
        );

        let do_true_result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_true_result, HopResult::Miss),
            "a DO=true reader must not be served from a dnssec-incomplete entry, got {do_true_result:?}"
        );
    }

    #[test]
    fn lookup_hop_serves_do_true_read_of_dnssec_complete_answer() {
        let shard = Shard::new(4);
        let domain = "complete.example.com";
        let mut entry = rrset_entry();
        entry.dnssec_complete = true;
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);
        let now = SystemTime::now();

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(matches!(result, HopResult::Answer(_, _)));
    }

    #[test]
    fn lookup_hop_treats_do_true_read_of_dnssec_incomplete_cname_hop_as_miss() {
        let shard = Shard::new(4);
        let domain = "alias-incomplete.example.com";
        let mut entry = rrset_entry();
        entry.dnssec_complete = false;
        entry.records = vec![StoredRecord {
            rtype: CNAME_RECORD_TYPE,
            rclass: IN_QCLASS,
            ttl_at_store: 300,
            rdata: RecordData::CNAME("target.example.com".to_string()),
        }];
        shard.store_positive(domain, (CNAME_RECORD_TYPE, IN_QCLASS), entry);
        let now = SystemTime::now();

        let do_true_result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_true_result, HopResult::Miss),
            "a DO=true reader must not follow a dnssec-incomplete CNAME hop, got {do_true_result:?}"
        );
    }

    #[test]
    fn lookup_hop_treats_do_true_read_of_dnssec_incomplete_negative_entries_as_miss() {
        let shard = Shard::new(4);
        let domain = "nxincomplete.example.com";
        let mut entry = negative_entry();
        entry.dnssec_complete = false;
        let nxdomain_key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative(domain, nxdomain_key, entry.clone());
        let now = SystemTime::now();

        let do_false_result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(matches!(do_false_result, HopResult::NxDomain(_)));

        let do_true_result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_true_result, HopResult::Miss),
            "a DO=true reader must not be served from a dnssec-incomplete NXDOMAIN entry, got {do_true_result:?}"
        );

        let domain2 = "nodataincomplete.example.com";
        let nodata_key = NegativeKey {
            qtype: Some(A_QTYPE),
            qclass: IN_QCLASS,
        };
        shard.store_negative(domain2, nodata_key, entry);
        let do_true_nodata = shard.lookup_hop(
            domain2,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_true_nodata, HopResult::Miss),
            "a DO=true reader must not be served from a dnssec-incomplete NODATA entry, got {do_true_nodata:?}"
        );
    }

    // Regression tests for the negative-entry DNSSEC-proof-TTL bug:
    // `lookup_hop` must treat a DO=true lookup as a miss once any
    // individual DNSSEC-relevant record stored in a `dnssec_complete`
    // negative entry (the SOA RRSIG or an NSEC/NSEC3 proof record) has
    // outlived its own TTL, even while the entry's overall SOA-derived
    // `expires_at` is still in the future. A DO=false reader must remain
    // unaffected, since it neither needs nor emits this material.

    fn negative_entry_with_short_lived_proof(stored_at: SystemTime) -> NegativeEntry {
        NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: stored_record(),
            soa_rrsig: None,
            // The overall negative TTL (driven by `expires_at` below) is a
            // full hour, but this NSEC proof record's own TTL is only
            // 300s — a DO=true lookup arriving after 300s (but well before
            // the hour is up) must not be served this record at a stale/
            // wire-TTL-0 state.
            proof_records: vec![(
                "adjacent.example.com".to_string(),
                StoredRecord {
                    rtype: 47, // NSEC
                    rclass: IN_QCLASS,
                    ttl_at_store: 300,
                    rdata: RecordData::NSEC {
                        next_domain: "zzz.example.com".to_string(),
                        type_bit_maps: vec![0, 1],
                    },
                },
            )],
            stored_at,
            expires_at: stored_at + Duration::from_secs(3600),
            cache_epoch: 1,
            dnssec_complete: true,
            dnssec_state: Default::default(),
            authoritative: false,
        }
    }

    #[test]
    fn lookup_hop_treats_do_true_read_of_negative_entry_with_expired_proof_record_ttl_as_miss() {
        let shard = Shard::new(4);
        let now = SystemTime::now();
        // Stored 301s ago: the proof record's own 300s TTL has elapsed,
        // but the entry's overall hour-long negative TTL has not.
        let stored_at = now - Duration::from_secs(301);

        let nxdomain_domain = "nx-stale-proof.example.com";
        let nxdomain_key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative(
            nxdomain_domain,
            nxdomain_key,
            negative_entry_with_short_lived_proof(stored_at),
        );

        let do_false_result = shard.lookup_hop(
            nxdomain_domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_false_result, HopResult::NxDomain(_)),
            "a DO=false reader may still be served despite the stale proof record, got {do_false_result:?}"
        );

        let do_true_result = shard.lookup_hop(
            nxdomain_domain,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_true_result, HopResult::Miss),
            "a DO=true reader must not be served an NXDOMAIN entry whose proof record TTL has elapsed, got {do_true_result:?}"
        );

        let nodata_domain = "nodata-stale-proof.example.com";
        let nodata_key = NegativeKey {
            qtype: Some(A_QTYPE),
            qclass: IN_QCLASS,
        };
        shard.store_negative(
            nodata_domain,
            nodata_key,
            negative_entry_with_short_lived_proof(stored_at),
        );
        let do_true_nodata_result = shard.lookup_hop(
            nodata_domain,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_true_nodata_result, HopResult::Miss),
            "a DO=true reader must not be served a NODATA entry whose proof record TTL has elapsed, got {do_true_nodata_result:?}"
        );
    }

    #[test]
    fn lookup_hop_serves_do_true_read_of_negative_entry_while_proof_record_still_fresh() {
        let shard = Shard::new(4);
        let now = SystemTime::now();
        // Stored only 10s ago: the proof record's 300s TTL has not
        // elapsed, so a DO=true reader must still be served.
        let stored_at = now - Duration::from_secs(10);
        let domain = "nx-fresh-proof.example.com";
        let nxdomain_key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative(
            domain,
            nxdomain_key,
            negative_entry_with_short_lived_proof(stored_at),
        );

        let do_true_result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_true_result, HopResult::NxDomain(_)),
            "a DO=true reader must still be served while every stored record remains within its own TTL, got {do_true_result:?}"
        );
    }

    // Regression tests for the expired-entry-not-evicted bug: `lookup_hop`
    // must actually remove an expired candidate entry from this shard's
    // internal state the moment it's encountered, not merely filter it out
    // of that one call's `HopResult`.

    fn expired_rrset_entry(now: SystemTime) -> RRsetEntry {
        let mut entry = rrset_entry();
        entry.stored_at = now - Duration::from_secs(600);
        entry.expires_at = now - Duration::from_secs(300); // expired 300s ago
        entry
    }

    fn expired_negative_entry(now: SystemTime) -> NegativeEntry {
        let mut entry = negative_entry();
        entry.stored_at = now - Duration::from_secs(7200);
        entry.expires_at = now - Duration::from_secs(3600); // expired an hour ago
        entry
    }

    #[test]
    fn lookup_hop_evicts_expired_positive_answer_from_shard_state() {
        let shard = Shard::new(4);
        let domain = "expired-answer.example.com";
        let now = SystemTime::now();
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired_rrset_entry(now));
        assert_eq!(shard.domain_count(), 1);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(
            !shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)),
            "an expired positive entry must be removed from the shard's map, not just filtered out"
        );
        assert!(!shard.has_any_data(domain));
        assert_eq!(
            shard.domain_count(),
            0,
            "the domain's LRU token must be dropped once its only entry expires"
        );
    }

    #[test]
    fn lookup_hop_evicts_expired_cname_hop_from_shard_state() {
        let shard = Shard::new(4);
        let domain = "expired-cname.example.com";
        let now = SystemTime::now();
        let mut entry = expired_rrset_entry(now);
        entry.records = vec![StoredRecord {
            rtype: CNAME_RECORD_TYPE,
            rclass: IN_QCLASS,
            ttl_at_store: 300,
            rdata: RecordData::CNAME("target.example.com".to_string()),
        }];
        shard.store_positive(domain, (CNAME_RECORD_TYPE, IN_QCLASS), entry);
        assert_eq!(shard.domain_count(), 1);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(!shard.contains_positive(domain, (CNAME_RECORD_TYPE, IN_QCLASS)));
        assert!(!shard.has_any_data(domain));
        assert_eq!(shard.domain_count(), 0);
    }

    #[test]
    fn lookup_hop_evicts_expired_nodata_entry_from_shard_state() {
        let shard = Shard::new(4);
        let domain = "expired-nodata.example.com";
        let now = SystemTime::now();
        let nodata_key = NegativeKey {
            qtype: Some(A_QTYPE),
            qclass: IN_QCLASS,
        };
        shard.store_negative(domain, nodata_key.clone(), expired_negative_entry(now));
        assert_eq!(shard.domain_count(), 1);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(
            !shard.contains_negative(domain, &nodata_key),
            "an expired NODATA entry must be removed from the shard's map, not just filtered out"
        );
        assert!(!shard.has_any_data(domain));
        assert_eq!(shard.domain_count(), 0);
    }

    #[test]
    fn lookup_hop_evicts_expired_nxdomain_entry_from_shard_state() {
        let shard = Shard::new(4);
        let domain = "expired-nxdomain.example.com";
        let now = SystemTime::now();
        let nxdomain_key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative(domain, nxdomain_key.clone(), expired_negative_entry(now));
        assert_eq!(shard.domain_count(), 1);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(!shard.contains_negative(domain, &nxdomain_key));
        assert!(!shard.has_any_data(domain));
        assert_eq!(shard.domain_count(), 0);
    }

    #[test]
    fn lookup_hop_expired_entry_eviction_leaves_domain_tracked_when_other_live_data_remains() {
        // A domain with both an expired A entry and a still-live AAAA
        // entry: encountering the expired A entry during an A lookup must
        // remove only that record set, not the domain's LRU token (since
        // the AAAA entry is still live).
        let shard = Shard::new(4);
        let domain = "partially-expired.example.com";
        let now = SystemTime::now();
        const AAAA_QTYPE: u16 = 28;
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired_rrset_entry(now));
        shard.store_positive(domain, (AAAA_QTYPE, IN_QCLASS), rrset_entry());
        assert_eq!(shard.domain_count(), 1);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
        assert!(
            shard.contains_positive(domain, (AAAA_QTYPE, IN_QCLASS)),
            "the still-live AAAA entry must survive the A entry's expiry-triggered eviction"
        );
        assert!(
            shard.has_any_data(domain),
            "the domain must remain tracked since it still has live data"
        );
        assert_eq!(shard.domain_count(), 1);
    }

    // Popularity bucket (leaky bucket) tests: section-01-popularity-bucket.

    fn leak_rate_1_per_60s() -> LeakRate {
        LeakRate {
            units: 1,
            per: Duration::from_secs(60),
        }
    }

    #[test]
    fn popularity_bucket_drains_by_elapsed_time() {
        let now = SystemTime::now();
        let mut bucket = PopularityBucket::new(now);
        // Get the level up to 5 first, with no elapsed time so nothing drains.
        for _ in 0..5 {
            bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
        }
        assert_eq!(bucket.level(), 5);

        // 180s elapsed at 1 unit/60s should drain 3 units, then +1 hit.
        let later = now + Duration::from_secs(180);
        bucket.drain_and_increment(later, leak_rate_1_per_60s(), 1, 10);
        assert_eq!(bucket.level(), 5 - 3 + 1);
    }

    #[test]
    fn popularity_bucket_increments_on_hit() {
        let now = SystemTime::now();
        let mut bucket = PopularityBucket::new(now);
        bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
        assert_eq!(bucket.level(), 1);
        bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
        assert_eq!(bucket.level(), 2);
    }

    #[test]
    fn popularity_bucket_saturates_at_capacity() {
        let now = SystemTime::now();
        let mut bucket = PopularityBucket::new(now);
        for _ in 0..50 {
            bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
        }
        assert_eq!(bucket.level(), 10);
    }

    #[test]
    fn popularity_bucket_drain_no_truncation_bias() {
        let now = SystemTime::now();
        let leak_rate = leak_rate_1_per_60s();

        // One big step: fill to capacity, then let 600s elapse in one call.
        let mut big_step = PopularityBucket::new(now);
        for _ in 0..10 {
            big_step.drain_and_increment(now, leak_rate, 1, 10);
        }
        let big_step_result_time = now + Duration::from_secs(600);
        big_step.drain_and_increment(big_step_result_time, leak_rate, 0, 10);

        // Many small steps covering the same total elapsed time (600s),
        // advanced 60 times in 10s increments.
        let mut small_steps = PopularityBucket::new(now);
        for _ in 0..10 {
            small_steps.drain_and_increment(now, leak_rate, 1, 10);
        }
        let mut t = now;
        for _ in 0..60 {
            t += Duration::from_secs(10);
            small_steps.drain_and_increment(t, leak_rate, 0, 10);
        }

        assert_eq!(
            big_step.level(),
            small_steps.level(),
            "draining in many small sub-unit steps must not bias the cumulative drain \
             relative to one large step covering the same total elapsed time"
        );
    }

    #[test]
    fn popularity_bucket_treats_backward_clock_as_zero_elapsed() {
        let now = SystemTime::now();
        let mut bucket = PopularityBucket::new(now);
        bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
        assert_eq!(bucket.level(), 1);

        let earlier = now - Duration::from_secs(120);
        // Should not panic/underflow, and should not drain (treated as zero
        // elapsed time), so the hit_increment is simply added.
        bucket.drain_and_increment(earlier, leak_rate_1_per_60s(), 1, 10);
        assert_eq!(bucket.level(), 2);
    }

    #[test]
    fn popularity_cleared_on_evict_domain() {
        let shard = Shard::new(1);
        let domain = "popular.example.com";
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
        let now = SystemTime::now();
        shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert_eq!(shard.popularity_level(domain), Some(1));

        // Force eviction via capacity pressure.
        shard.store_positive("other.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());

        assert_eq!(shard.popularity_level(domain), None);
    }

    #[test]
    fn popularity_cleared_on_drop_lru_if_domain_now_empty() {
        let shard = Shard::new(4);
        let domain = "solo-positive.example.com";
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
        let now = SystemTime::now();
        shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert_eq!(shard.popularity_level(domain), Some(1));

        // Expire the only entry and look it up again, triggering removal
        // via remove_positive_entry -> drop_lru_if_domain_now_empty.
        let mut expired = rrset_entry();
        expired.expires_at = now - Duration::from_secs(1);
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired);
        shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert_eq!(shard.popularity_level(domain), None);
    }

    #[test]
    fn popularity_not_allocated_when_disabled() {
        let shard = Shard::new(4);
        let domain = "disabled.example.com";
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
        let now = SystemTime::now();

        // Exercise record_popularity_hit directly with enabled = false via
        // the shard's internal state, since lookup_hop always passes
        // enabled = true today (placeholder until section-03 threads real
        // config through). Access via hold_lock_for_test's lock pattern
        // would deadlock, so this test targets ShardState directly.
        let mut state = ShardState::default();
        state.record_popularity_hit(domain, now, false, leak_rate_1_per_60s(), 1, 10);
        assert!(!state.popularity.contains_key(domain));
    }

    #[test]
    fn is_hot_reflects_configured_threshold() {
        let now = SystemTime::now();
        let mut bucket = PopularityBucket::new(now);
        for _ in 0..5 {
            bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
        }
        assert_eq!(bucket.level(), 5);
        assert!(bucket.is_hot(5));
        assert!(!bucket.is_hot(6));
    }

    #[test]
    fn lookup_hop_hit_increments_popularity_level() {
        let shard = Shard::new(4);
        let domain = "hit-tracked.example.com";
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
        let now = SystemTime::now();

        assert_eq!(shard.popularity_level(domain), None);
        shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert_eq!(shard.popularity_level(domain), Some(1));
        shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert_eq!(shard.popularity_level(domain), Some(2));
    }

    #[test]
    fn lookup_hop_cname_hop_hit_increments_popularity_level() {
        let shard = Shard::new(4);
        let domain = "cname-tracked.example.com";
        let mut cname_entry = rrset_entry();
        cname_entry.records = vec![StoredRecord {
            rtype: CNAME_RECORD_TYPE,
            rclass: IN_QCLASS,
            ttl_at_store: 300,
            rdata: RecordData::CNAME("target.example.com".to_string()),
        }];
        shard.store_positive(domain, (CNAME_RECORD_TYPE, IN_QCLASS), cname_entry);
        let now = SystemTime::now();

        assert_eq!(shard.popularity_level(domain), None);
        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(matches!(result, HopResult::CnameHop(_, _, _)));
        assert_eq!(shard.popularity_level(domain), Some(1));
    }

    #[test]
    fn lookup_hop_nodata_hit_increments_popularity_level() {
        let shard = Shard::new(4);
        let domain = "nodata-tracked.example.com";
        let key = NegativeKey {
            qtype: Some(A_QTYPE),
            qclass: IN_QCLASS,
        };
        let mut nodata_entry = negative_entry();
        nodata_entry.kind = NegativeCacheKind::NoData;
        shard.store_negative(domain, key, nodata_entry);
        let now = SystemTime::now();

        assert_eq!(shard.popularity_level(domain), None);
        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(matches!(result, HopResult::NoData(_)));
        assert_eq!(shard.popularity_level(domain), Some(1));
    }

    #[test]
    fn lookup_hop_nxdomain_hit_increments_popularity_level() {
        let shard = Shard::new(4);
        let domain = "nxdomain-tracked.example.com";
        let key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative(domain, key, negative_entry());
        let now = SystemTime::now();

        assert_eq!(shard.popularity_level(domain), None);
        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(matches!(result, HopResult::NxDomain(_)));
        assert_eq!(shard.popularity_level(domain), Some(1));
    }

    #[test]
    fn popularity_bucket_drain_with_non_unit_leak_rate() {
        // Exercises the `leak_rate.per * leaked_units / leak_rate.units`
        // reconstruction with a divisor other than 1, to confirm the
        // truncation-avoidance formula still holds when units != 1.
        let now = SystemTime::now();
        let leak_rate = LeakRate {
            units: 3,
            per: Duration::from_secs(60),
        };

        let mut bucket = PopularityBucket::new(now);
        for _ in 0..10 {
            bucket.drain_and_increment(now, leak_rate, 1, 10);
        }
        assert_eq!(bucket.level(), 10);

        // 60s elapsed at 3 units/60s should drain 3 units, then +1 hit.
        let later = now + Duration::from_secs(60);
        bucket.drain_and_increment(later, leak_rate, 1, 10);
        assert_eq!(bucket.level(), 10 - 3 + 1);
    }

    // RFC 8767 serve-stale tests: expired-but-in-window positive entries
    // are served (with an unconditional refresh signal) instead of being
    // evicted at read time; everything outside `stale_servability`'s
    // Servable arm behaves exactly as before serve-stale existed.

    const STALE_TEST_WINDOW: Duration = Duration::from_secs(3600);

    fn stale_shard() -> Shard {
        Shard::with_stale_window(4, Some(STALE_TEST_WINDOW))
    }

    #[test]
    fn lookup_hop_serves_stale_positive_within_window_with_unconditional_refresh() {
        let shard = stale_shard();
        let domain = "stale.example.com";
        let now = SystemTime::now();
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired_rrset_entry(now));

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        // The domain has no popularity history at all — a stale serve must
        // still want a refresh, since the popularity gate only applies to
        // pre-expiry prefetch, never to just-served stale data.
        assert!(
            matches!(result, HopResult::Answer(_, true)),
            "expected stale Answer with unconditional refresh, got {result:?}"
        );
        assert!(
            shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)),
            "a stale-served entry must stay cached for the next reader"
        );
    }

    #[test]
    fn lookup_hop_evicts_expired_bogus_entry_instead_of_serving_stale() {
        // section-04 (A6): a `Bogus` entry must never be served via
        // serve-stale, even within the window that would otherwise make it
        // servable -- serving a known-tampered response past its expiration
        // defeats the point of validating it.
        let shard = stale_shard();
        let domain = "bogus-stale.example.com";
        let now = SystemTime::now();
        let mut entry = expired_rrset_entry(now);
        entry.dnssec_state = DnssecState::Bogus("signature verification failed".to_string());
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(
            matches!(result, HopResult::Miss),
            "expected a Bogus expired entry to be evicted rather than stale-served, got {result:?}"
        );
        assert!(
            !shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)),
            "a Bogus entry excluded from serve-stale must not remain cached"
        );
    }

    #[test]
    fn lookup_hop_serves_stale_secure_entry_unaffected_by_bogus_exclusion() {
        // No-regression check: `Secure`/`Insecure` entries keep today's
        // serve-stale behavior unchanged by the new Bogus exclusion above.
        let shard = stale_shard();
        let domain = "secure-stale.example.com";
        let now = SystemTime::now();
        let mut entry = expired_rrset_entry(now);
        entry.dnssec_state = DnssecState::Secure;
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(
            matches!(result, HopResult::Answer(_, true)),
            "expected a Secure expired entry to still be stale-served, got {result:?}"
        );
    }

    #[test]
    fn lookup_hop_evicts_expired_positive_beyond_stale_window() {
        let shard = stale_shard();
        let domain = "beyond.example.com";
        let now = SystemTime::now();
        let mut entry = rrset_entry();
        entry.stored_at = now - STALE_TEST_WINDOW - Duration::from_secs(600);
        entry.expires_at = now - STALE_TEST_WINDOW - Duration::from_secs(300);
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
    }

    #[test]
    fn lookup_hop_evicts_stale_entry_with_mismatched_epoch() {
        // Staleness is about time, not config identity: an entry stamped
        // with an old epoch is invalid for every reader regardless of the
        // window, and eviction at read time matches the pre-serve-stale
        // expired path.
        let shard = stale_shard();
        let domain = "old-epoch.example.com";
        let now = SystemTime::now();
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired_rrset_entry(now));

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            2, // entries above were stored with cache_epoch 1
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
    }

    #[test]
    fn lookup_hop_stale_do_true_reader_misses_but_entry_survives_for_do_false() {
        let shard = stale_shard();
        let domain = "stale-do.example.com";
        let now = SystemTime::now();
        let mut entry = expired_rrset_entry(now);
        entry.dnssec_complete = false;
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);

        let do_true = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            true,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(
            matches!(do_true, HopResult::Miss),
            "a DO=true reader must not be stale-served dnssec-incomplete data"
        );
        assert!(
            shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)),
            "the DO filter is not grounds for eviction — a DO=false reader can still use this"
        );

        let do_false = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );
        assert!(matches!(do_false, HopResult::Answer(_, true)));
    }

    #[test]
    fn lookup_hop_never_stale_serves_zero_origin_ttl_entry() {
        // RFC 1035: TTL 0 means "use for this transaction only" — such a
        // record must never outlive its expiry, stale window or not. The
        // entry deliberately models a configured `min_positive_ttl` floor:
        // `minimum_ttl` is the *policy-bounded* cache lifetime and is
        // nonzero here, so only the per-record origin TTL
        // (`ttl_at_store == 0`) can catch this — a guard on
        // `minimum_ttl.is_zero()` would wrongly stale-serve it (PR #142
        // review finding).
        let shard = stale_shard();
        let domain = "ttl-zero.example.com";
        let now = SystemTime::now();
        let mut entry = expired_rrset_entry(now);
        entry.minimum_ttl = Duration::from_secs(60); // floored lifetime
        for record in &mut entry.records {
            record.ttl_at_store = 0; // origin published TTL 0
        }
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
    }

    #[test]
    fn lookup_hop_serves_stale_cname_hop_within_window() {
        let shard = stale_shard();
        let domain = "stale-alias.example.com";
        let now = SystemTime::now();
        let mut entry = expired_rrset_entry(now);
        entry.records = vec![StoredRecord {
            rtype: CNAME_RECORD_TYPE,
            rclass: IN_QCLASS,
            ttl_at_store: 300,
            rdata: RecordData::CNAME("target.example.com".to_string()),
        }];
        shard.store_positive(domain, (CNAME_RECORD_TYPE, IN_QCLASS), entry);

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        match result {
            HopResult::CnameHop(_, target, refresh_wanted) => {
                assert_eq!(target, "target.example.com");
                assert!(refresh_wanted, "stale CNAME hop must want a refresh");
            }
            other => panic!("expected stale CnameHop, got {other:?}"),
        }
    }

    /// An expired CNAME-slot entry admitted as stale-servable but carrying
    /// no extractable CNAME (corrupt/unexpected rdata) must be evicted at
    /// read time, not left parked until the stale window ends — it is
    /// expired (the one removal criterion) and cannot serve any stale
    /// reader on this path (PR #142 review finding).
    #[test]
    fn lookup_hop_evicts_stale_cname_slot_entry_with_no_extractable_target() {
        let shard = stale_shard();
        let domain = "corrupt-alias.example.com";
        let now = SystemTime::now();
        let cname_key = (CNAME_RECORD_TYPE, IN_QCLASS);
        // Stored under the CNAME key, but the records hold an A rdata —
        // no target to extract.
        shard.store_positive(domain, cname_key, expired_rrset_entry(now));

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(
            !shard.contains_positive(domain, cname_key),
            "an expired, unservable CNAME-slot entry must be evicted, not parked for the window"
        );
    }

    #[test]
    fn lookup_hop_negative_entries_are_never_stale_served() {
        // v1 scope: RFC 8767 §5 flags stale negative answers (especially
        // NXDOMAIN) as the risky case, so expired negative entries keep the
        // original evict-at-read behavior even inside the stale window.
        let shard = stale_shard();
        let domain = "stale-nx.example.com";
        let now = SystemTime::now();
        let key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        shard.store_negative(domain, key.clone(), expired_negative_entry(now));

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(!shard.contains_negative(domain, &key));
    }

    #[test]
    fn lookup_hop_with_stale_disabled_keeps_original_expired_eviction() {
        // `Shard::new` (no window) must behave byte-for-byte like the
        // pre-serve-stale code: expired ⇒ evict ⇒ miss.
        let shard = Shard::new(4);
        let domain = "no-stale.example.com";
        let now = SystemTime::now();
        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired_rrset_entry(now));

        let result = shard.lookup_hop(
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            now,
            &test_refresh_config(),
        );

        assert!(matches!(result, HopResult::Miss));
        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
    }

    // Trigger-formula (`wants_refresh`) tests: section-03-trigger-formula.

    fn test_refresh_config() -> RefreshConfig {
        RefreshConfig {
            enabled: true,
            bucket_capacity: 10,
            leak_rate: LeakRate {
                units: 1,
                per: Duration::from_secs(60),
            },
            hit_increment: 1,
            hot_threshold_fraction: 0.5,
            lead_ratio: 0.10,
            min_lead: Duration::from_secs(5),
            eligibility_floor: Duration::from_secs(15),
            worker_count: 4,
            channel_capacity: 256,
        }
    }

    fn bucket_at_level(level: u32) -> PopularityBucket {
        PopularityBucket {
            level,
            last_drained: SystemTime::now(),
        }
    }

    #[test]
    fn trigger_requires_eligibility_floor() {
        let config = test_refresh_config();
        let hot_bucket = bucket_at_level(10);

        // Original TTL below eligibility_floor (15s): never eligible, even
        // deep inside what would otherwise be the lead window and hot.
        let original_ttl = Duration::from_secs(10);
        let remaining_ttl = Duration::from_secs(1);
        assert!(!wants_refresh(
            original_ttl,
            remaining_ttl,
            Some(&hot_bucket),
            &config
        ));
    }

    #[test]
    fn trigger_fires_within_lead_window() {
        let config = test_refresh_config();
        let hot_bucket = bucket_at_level(10);
        let original_ttl = Duration::from_secs(300);
        // lead = max(300 * 0.10, 5s) = 30s.

        // Just inside the window.
        assert!(wants_refresh(
            original_ttl,
            Duration::from_secs(29),
            Some(&hot_bucket),
            &config
        ));
        // Just outside the window.
        assert!(!wants_refresh(
            original_ttl,
            Duration::from_secs(31),
            Some(&hot_bucket),
            &config
        ));
    }

    #[test]
    fn trigger_requires_hot_popularity() {
        let config = test_refresh_config();
        let original_ttl = Duration::from_secs(300);
        let remaining_ttl = Duration::from_secs(10);

        let cold_bucket = bucket_at_level(0);
        assert!(!wants_refresh(
            original_ttl,
            remaining_ttl,
            Some(&cold_bucket),
            &config
        ));

        let hot_bucket = bucket_at_level(5);
        assert!(wants_refresh(
            original_ttl,
            remaining_ttl,
            Some(&hot_bucket),
            &config
        ));
    }

    /// Pins the *shipped* `RefreshConfig::default()` gate (not the local
    /// `test_refresh_config` fixture) to a realistic small-network access
    /// pattern: a domain queried once every two minutes must become hot.
    /// The original defaults (threshold 5 against a 1-per-minute leak)
    /// required a sustained >1 query/min, which client-side stub caches
    /// make nearly unreachable in practice — live counters showed exactly
    /// one refresh ever triggered. This test fails if the defaults ever
    /// regress to a gate that steady 1-per-2-min demand can't pass.
    #[test]
    fn shipped_defaults_let_a_two_minute_interval_domain_reach_hot() {
        let config = RefreshConfig::default();
        let hot_threshold =
            (config.hot_threshold_fraction * config.bucket_capacity as f32).round() as u32;

        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut bucket = PopularityBucket::new(start);
        let mut hot_after = None;
        for hit in 0..10u64 {
            let now = start + Duration::from_secs(120 * hit);
            bucket.drain_and_increment(
                now,
                config.leak_rate,
                config.hit_increment,
                config.bucket_capacity,
            );
            if bucket.is_hot(hot_threshold) {
                hot_after = Some(hit + 1);
                break;
            }
        }
        let hot_after = hot_after.expect(
            "a domain queried every 2 minutes should reach the hot threshold \
             under the shipped defaults",
        );
        assert!(
            hot_after <= 2,
            "expected hot within 2 hits at a 2-minute interval, took {hot_after}"
        );
    }

    #[test]
    fn trigger_boundary_at_exact_lead_window_edge() {
        // lead_ratio = 0.25 is exactly representable in f32 (a power-of-two
        // fraction), and 400s * 0.25 = 100s is itself an exact integer, so
        // `original_ttl.mul_f32(lead_ratio)` computes to *exactly* 100s with
        // no floating-point rounding error — unlike the default config's
        // 0.10 ratio (not exactly representable in f32), which would make a
        // remaining_ttl set to the nominal boundary actually land strictly
        // inside the true (slightly-larger) computed lead, passing this test
        // under both `<=` and `<` semantics and failing to actually pin the
        // operator. With an exact boundary, this test can properly assert
        // `<=` fires and `<` alone would not.
        let mut config = test_refresh_config();
        config.lead_ratio = 0.25;
        config.min_lead = Duration::from_secs(1); // small enough that the ratio term dominates
        let hot_bucket = bucket_at_level(10);
        let original_ttl = Duration::from_secs(400);
        // lead = max(400 * 0.25, 1s) = 100s, computed exactly.

        assert!(
            wants_refresh(
                original_ttl,
                Duration::from_secs(100),
                Some(&hot_bucket),
                &config
            ),
            "remaining_ttl exactly equal to the lead window must fire (formula is <=, not <)"
        );
        assert!(
            !wants_refresh(
                original_ttl,
                Duration::from_millis(100_001),
                Some(&hot_bucket),
                &config
            ),
            "remaining_ttl just past the lead window must not fire"
        );
    }

    #[test]
    fn trigger_boundary_at_exact_eligibility_floor() {
        let config = test_refresh_config();
        let hot_bucket = bucket_at_level(10);
        // original_ttl exactly equal to eligibility_floor (15s) must still
        // count as eligible.
        let original_ttl = config.eligibility_floor;
        // lead = max(15s * 0.10, 5s) = 5s.
        let remaining_ttl = Duration::from_secs(5);

        assert!(wants_refresh(
            original_ttl,
            remaining_ttl,
            Some(&hot_bucket),
            &config
        ));
    }

    #[test]
    fn trigger_no_bucket_is_never_hot() {
        let config = test_refresh_config();
        let original_ttl = Duration::from_secs(300);
        let remaining_ttl = Duration::from_secs(10);

        assert!(!wants_refresh(original_ttl, remaining_ttl, None, &config));
    }

    #[test]
    fn trigger_min_lead_dominates_over_small_ratio_lead() {
        let config = test_refresh_config();
        let hot_bucket = bucket_at_level(10);
        // A short-but-still-eligible TTL: 20s * 0.10 = 2s, but min_lead is 5s,
        // so the effective lead window must be 5s (min_lead dominates).
        let original_ttl = Duration::from_secs(20);

        assert!(wants_refresh(
            original_ttl,
            Duration::from_secs(5),
            Some(&hot_bucket),
            &config
        ));
        assert!(!wants_refresh(
            original_ttl,
            Duration::from_secs(6),
            Some(&hot_bucket),
            &config
        ));
    }

    #[test]
    fn trigger_hot_threshold_fraction_zero_makes_any_existing_bucket_hot() {
        // hot_threshold_fraction = 0.0 is a valid, reachable operator
        // configuration (RefreshConfig::validate allows the inclusive
        // 0.0..=1.0 range) that effectively disables the popularity gate:
        // hot_threshold rounds to 0, so is_hot(0) is trivially true for any
        // bucket, even one at level 0.
        let mut config = test_refresh_config();
        config.hot_threshold_fraction = 0.0;
        let original_ttl = Duration::from_secs(300);
        let remaining_ttl = Duration::from_secs(10);
        let cold_bucket = bucket_at_level(0);

        assert!(wants_refresh(
            original_ttl,
            remaining_ttl,
            Some(&cold_bucket),
            &config
        ));
    }

    #[test]
    fn trigger_hot_threshold_fraction_one_requires_bucket_at_full_capacity() {
        // hot_threshold_fraction = 1.0 (the other valid extreme) requires
        // the bucket to be at exactly bucket_capacity to be considered hot.
        let mut config = test_refresh_config();
        config.hot_threshold_fraction = 1.0;
        let original_ttl = Duration::from_secs(300);
        let remaining_ttl = Duration::from_secs(10);

        let almost_full_bucket = bucket_at_level(config.bucket_capacity - 1);
        assert!(!wants_refresh(
            original_ttl,
            remaining_ttl,
            Some(&almost_full_bucket),
            &config
        ));

        let full_bucket = bucket_at_level(config.bucket_capacity);
        assert!(wants_refresh(
            original_ttl,
            remaining_ttl,
            Some(&full_bucket),
            &config
        ));
    }

    #[test]
    fn trigger_ratio_lead_dominates_over_small_min_lead() {
        let config = test_refresh_config();
        let hot_bucket = bucket_at_level(10);
        // A long TTL: 1000s * 0.10 = 100s, which is larger than min_lead
        // (5s), so the effective lead window must be 100s (ratio dominates).
        let original_ttl = Duration::from_secs(1000);

        assert!(wants_refresh(
            original_ttl,
            Duration::from_secs(100),
            Some(&hot_bucket),
            &config
        ));
        assert!(!wants_refresh(
            original_ttl,
            Duration::from_secs(101),
            Some(&hot_bucket),
            &config
        ));
    }
}
