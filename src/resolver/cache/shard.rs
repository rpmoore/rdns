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
        }
    }

    /// Single-probe positive-answer lookup for `Shard::lookup_hop`: probes
    /// `domain`/`key` in the positive map exactly once and, from that one
    /// borrow, decides in-place whether the candidate is expired (removing
    /// it via `remove_positive_entry` and returning `None`), live and
    /// usable (cloning it out and returning `Some`), or neither (a
    /// namespace mismatch or DO-incompleteness, left in place for other
    /// requesters/namespaces — returning `None` without removing anything).
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
    ) -> Option<RRsetEntry> {
        let expired = match self
            .positive
            .domains
            .get(domain)
            .and_then(|record_sets| record_sets.record_sets.get(&key))
        {
            None => return None,
            Some(entry) if entry.expires_at <= now => true,
            Some(entry) => {
                if entry.cache_epoch == current_epoch
                    && (!dnssec_ok || entry.dnssec_complete)
                {
                    return Some(entry.clone());
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
    /// single-probe expired/live/absent decision, plus extracting the
    /// CNAME's target name from the live entry's records. A live entry
    /// whose records don't actually contain a CNAME (unexpected/corrupt
    /// data) is treated as absent for this call — same as before — without
    /// being removed, since only genuine TTL expiry warrants removal here.
    fn take_live_cname_hop(
        &mut self,
        domain: &str,
        key: (u16, u16),
        dnssec_ok: bool,
        current_epoch: u64,
        now: SystemTime,
    ) -> Option<(RRsetEntry, String)> {
        let expired = match self
            .positive
            .domains
            .get(domain)
            .and_then(|record_sets| record_sets.record_sets.get(&key))
        {
            None => return None,
            Some(entry) if entry.expires_at <= now => true,
            Some(entry) => {
                if entry.cache_epoch == current_epoch
                    && (!dnssec_ok || entry.dnssec_complete)
                {
                    let target = entry.records.iter().find_map(|record| match &record.rdata {
                        RecordData::CNAME(target) => Some(target.clone()),
                        _ => None,
                    });
                    if let Some(target) = target {
                        return Some((entry.clone(), target));
                    }
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
    ) -> Option<NegativeEntry> {
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
    pub(crate) fn lookup_hop(
        &self,
        domain: &str,
        qtype: u16,
        qclass: u16,
        dnssec_ok: bool,
        current_epoch: u64,
        now: SystemTime,
    ) -> HopResult {
        let mut state = self.state.lock().unwrap();
        let answer_key = (qtype, qclass);

        // Each candidate below probes its map exactly once, via
        // `take_live_positive`/`take_live_cname_hop`/`take_live_negative`:
        // one borrow decides expired-vs-live-vs-absent in a single pass
        // (expired candidates are removed from `state` from inside that
        // same call), rather than a separate expiry precheck followed by a
        // second, independent lookup for the live/filtered case.
        if let Some(entry) =
            state.take_live_positive(domain, answer_key, dnssec_ok, current_epoch, now)
        {
            state.lru.touch(domain);
            return HopResult::Answer(entry);
        }

        if qtype != CNAME_RECORD_TYPE {
            let cname_key = (CNAME_RECORD_TYPE, qclass);
            if let Some((entry, target)) =
                state.take_live_cname_hop(domain, cname_key, dnssec_ok, current_epoch, now)
            {
                state.lru.touch(domain);
                return HopResult::CnameHop(entry, target);
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
            return HopResult::NxDomain(entry);
        }

        HopResult::Miss
    }

    /// Removes every positive/negative entry in this shard whose stored
    /// `cache_epoch` no longer matches `current_epoch`, and drops
    /// any domain (and its LRU token) left with no entries in either map
    /// afterward. Takes this shard's lock for the duration of the scan
    /// only — sweeping one shard never waits on any other shard's lock.
    /// Returns the total number of entries removed (`cache::namespace`,
    /// section-05).
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

        let do_false_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
        assert!(
            matches!(do_false_result, HopResult::Answer(_)),
            "a DO=false reader may still be served from a dnssec-incomplete entry"
        );

        let do_true_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
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

        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
        assert!(matches!(result, HopResult::Answer(_)));
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

        let do_true_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
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

        let do_false_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
        assert!(matches!(do_false_result, HopResult::NxDomain(_)));

        let do_true_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
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
        let do_true_nodata = shard.lookup_hop(domain2, A_QTYPE, IN_QCLASS, true, 1, now);
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

        let do_false_result =
            shard.lookup_hop(nxdomain_domain, A_QTYPE, IN_QCLASS, false, 1, now);
        assert!(
            matches!(do_false_result, HopResult::NxDomain(_)),
            "a DO=false reader may still be served despite the stale proof record, got {do_false_result:?}"
        );

        let do_true_result =
            shard.lookup_hop(nxdomain_domain, A_QTYPE, IN_QCLASS, true, 1, now);
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
        let do_true_nodata_result =
            shard.lookup_hop(nodata_domain, A_QTYPE, IN_QCLASS, true, 1, now);
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

        let do_true_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
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

        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);

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

        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);

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

        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);

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

        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);

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

        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);

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
}
