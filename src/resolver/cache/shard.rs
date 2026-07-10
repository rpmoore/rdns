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
//! No non-test callers yet (section-06/section-07 wire this into the
//! top-level cache type); `#[allow(dead_code)]` below is transient, same
//! pattern as `shard_index` in section-01.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use super::entry::{
    DomainNegativeEntries, DomainRecordSets, NegativeEntry, NegativeKey, RRsetEntry,
};
use super::lru::ShardLru;
use crate::protocol::RecordData;

const CNAME_RECORD_TYPE: u16 = 5;

/// Result of one hop's lookup within `resolve_from_cache`'s CNAME-chain
/// walk (`cache::assemble`, section-06) — whatever this shard found (or
/// didn't) for one name in the chain, already cloned out from under this
/// shard's lock.
#[derive(Debug, Clone)]
pub(crate) enum HopResult {
    /// A record set matching the queried `(qtype, qclass)` directly.
    Answer(RRsetEntry),
    /// The queried type wasn't found, but a CNAME record set was — carries
    /// the CNAME's own entry (for the response's answer section) plus the
    /// extracted target name to continue the walk.
    CnameHop(RRsetEntry, String),
    /// NODATA for the queried type at this (existing) name.
    NoData(NegativeEntry),
    /// Whole-name NXDOMAIN at this name.
    NxDomain(NegativeEntry),
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
}

/// One shard of the sharded DNS cache: its own lock, its own share of the
/// total configured capacity (the exact remainder-distributed per-shard
/// capacity from `CacheConfig`, section-01 — not a naive
/// `ceil(max_entries / shard_count)`).
#[derive(Debug)]
pub(crate) struct Shard {
    state: Mutex<ShardState>,
    capacity: usize,
}

impl Shard {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(ShardState::default()),
            capacity,
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
            .insert(key, entry);
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
            .insert(key, entry);
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
    pub(crate) fn lookup_hop(
        &self,
        domain: &str,
        qtype: u16,
        qclass: u16,
        current_namespace: &str,
        now: SystemTime,
    ) -> HopResult {
        let mut state = self.state.lock().unwrap();

        let answer = state
            .positive
            .domains
            .get(domain)
            .and_then(|record_sets| record_sets.record_sets.get(&(qtype, qclass)))
            .filter(|entry| entry.expires_at > now && entry.cache_namespace == current_namespace)
            .cloned();
        if let Some(entry) = answer {
            state.lru.touch(domain);
            return HopResult::Answer(entry);
        }

        if qtype != CNAME_RECORD_TYPE {
            let cname_hop = state
                .positive
                .domains
                .get(domain)
                .and_then(|record_sets| record_sets.record_sets.get(&(CNAME_RECORD_TYPE, qclass)))
                .filter(|entry| {
                    entry.expires_at > now && entry.cache_namespace == current_namespace
                })
                .and_then(|entry| {
                    entry
                        .records
                        .iter()
                        .find_map(|record| match &record.rdata {
                            RecordData::CNAME(target) => Some(target.clone()),
                            _ => None,
                        })
                        .map(|target| (entry.clone(), target))
                });
            if let Some((entry, target)) = cname_hop {
                state.lru.touch(domain);
                return HopResult::CnameHop(entry, target);
            }
        }

        let nodata_key = NegativeKey {
            qtype: Some(qtype),
            qclass,
        };
        let nodata = state
            .negative
            .domains
            .get(domain)
            .and_then(|entries| entries.entries.get(&nodata_key))
            .filter(|entry| entry.expires_at > now && entry.cache_namespace == current_namespace)
            .cloned();
        if let Some(entry) = nodata {
            state.lru.touch(domain);
            return HopResult::NoData(entry);
        }

        let nxdomain_key = NegativeKey {
            qtype: None,
            qclass,
        };
        let nxdomain = state
            .negative
            .domains
            .get(domain)
            .and_then(|entries| entries.entries.get(&nxdomain_key))
            .filter(|entry| entry.expires_at > now && entry.cache_namespace == current_namespace)
            .cloned();
        if let Some(entry) = nxdomain {
            state.lru.touch(domain);
            return HopResult::NxDomain(entry);
        }

        HopResult::Miss
    }

    /// Removes every positive/negative entry in this shard whose stored
    /// `cache_namespace` no longer matches `current_namespace`, and drops
    /// any domain (and its LRU token) left with no entries in either map
    /// afterward. Takes this shard's lock for the duration of the scan
    /// only — sweeping one shard never waits on any other shard's lock.
    /// Returns the total number of entries removed (`cache::namespace`,
    /// section-05).
    pub(crate) fn sweep_stale_namespace(&self, current_namespace: &str) -> usize {
        let mut state = self.state.lock().unwrap();
        let mut removed = 0usize;
        let mut emptied_domains: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        state.positive.domains.retain(|domain, record_sets| {
            let before = record_sets.record_sets.len();
            record_sets
                .record_sets
                .retain(|_, entry| entry.cache_namespace == current_namespace);
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
                .retain(|_, entry| entry.cache_namespace == current_namespace);
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
            cache_namespace: "ns-1".to_string(),
        }
    }

    fn negative_entry() -> NegativeEntry {
        let now = SystemTime::now();
        NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_record: stored_record(),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
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
}
