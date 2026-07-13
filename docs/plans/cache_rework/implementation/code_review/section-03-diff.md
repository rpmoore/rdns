diff --git a/src/resolver/cache/entry.rs b/src/resolver/cache/entry.rs
index 4d6b8b5..30967e2 100644
--- a/src/resolver/cache/entry.rs
+++ b/src/resolver/cache/entry.rs
@@ -17,13 +17,6 @@
 //! and the negative-cache shape (`NegativeEntry`, `NegativeKey`,
 //! `DomainNegativeEntries`). No locking, shard combination, or LRU wiring
 //! lives here — that's section-03 (`cache::shard`, `cache::lru`).
-//!
-//! These types have no non-test callers yet (section-03 wraps them in
-//! shard state); `#[allow(dead_code)]` below is transient and should be
-//! removed once section-03 adds real callers, mirroring the same pattern
-//! used for `shard_index` in section-01.
-
-#![allow(dead_code)]
 
 use std::collections::HashMap;
 use std::time::{Duration, SystemTime};
@@ -82,8 +75,14 @@ pub(crate) struct StoredRecord {
 pub(crate) enum DnssecState {
     #[default]
     Unvalidated,
+    // Not constructed anywhere yet — real DNSSEC validation is out of
+    // scope for this whole rework; these variants exist so the data
+    // model doesn't need reshaping again when that work happens later.
+    #[allow(dead_code)]
     Insecure,
+    #[allow(dead_code)]
     Secure,
+    #[allow(dead_code)]
     Bogus(String), // reason, for diagnostics; short negative-style TTL applies
 }
 
diff --git a/src/resolver/cache/lru.rs b/src/resolver/cache/lru.rs
index 162ec6c..097dcb7 100644
--- a/src/resolver/cache/lru.rs
+++ b/src/resolver/cache/lru.rs
@@ -12,5 +12,148 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! `ShardLru` (`BTreeSet` + `HashMap` side-index) — exact O(log n)
-//! touch/evict LRU, filled in by section-03.
+//! Exact per-shard LRU (`ShardLru`), replacing the current ghost-token
+//! `VecDeque` design used by `InMemoryDnsCache`. Gives O(log n)
+//! average-case touch/evict with no periodic full-scan compaction, and
+//! exact (not approximate) recency ordering within a shard.
+//!
+//! No non-test callers yet (section-06/section-07 wire this into the
+//! top-level cache type); `#[allow(dead_code)]` below is transient, same
+//! pattern as `shard_index` in section-01.
+
+#![allow(dead_code)]
+
+use std::collections::{BTreeSet, HashMap};
+
+/// Ordered by `(sequence, domain)` so the numerically smallest entry is
+/// always the least-recently-touched domain in this shard.
+#[derive(Debug, Default)]
+pub(crate) struct ShardLru {
+    order: BTreeSet<(u64, String)>,
+    /// Reverse index: domain -> its current sequence number, so a touch
+    /// can find and remove its old position in `order` in O(log n)
+    /// instead of scanning.
+    positions: HashMap<String, u64>,
+    next_sequence: u64,
+}
+
+impl ShardLru {
+    pub(crate) fn new() -> Self {
+        Self::default()
+    }
+
+    /// Records that `domain` was just accessed (hit or store). Removes
+    /// its old `(sequence, domain)` pair from `order` (O(log n)) if
+    /// present, assigns a fresh sequence, and reinserts (O(log n)).
+    /// Unlike the ghost-token design it replaces, there is never more
+    /// than one entry per domain in `order` — no compaction pass is ever
+    /// needed.
+    pub(crate) fn touch(&mut self, domain: &str) {
+        if let Some(old_sequence) = self.positions.get(domain).copied() {
+            self.order.remove(&(old_sequence, domain.to_string()));
+        }
+        let sequence = self.next_sequence;
+        self.next_sequence += 1;
+        self.order.insert((sequence, domain.to_string()));
+        self.positions.insert(domain.to_string(), sequence);
+    }
+
+    /// Removes `domain` from LRU tracking entirely (used when a domain's
+    /// last record set/negative entry is deleted, whether by eviction,
+    /// expiry, or the namespace sweep in section-05).
+    pub(crate) fn remove(&mut self, domain: &str) {
+        if let Some(sequence) = self.positions.remove(domain) {
+            self.order.remove(&(sequence, domain.to_string()));
+        }
+    }
+
+    /// Returns the least-recently-touched domain without removing it, for
+    /// the eviction loop to consult.
+    pub(crate) fn peek_oldest(&self) -> Option<&str> {
+        self.order.iter().next().map(|(_, domain)| domain.as_str())
+    }
+
+    /// Number of domains currently tracked by this LRU — used by the
+    /// shard's capacity check, since a domain "counts" iff it has a live
+    /// LRU position.
+    pub(crate) fn len(&self) -> usize {
+        self.positions.len()
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn lru_touch_moves_domain_to_most_recent_without_leaving_stale_positions() {
+        let mut lru = ShardLru::new();
+        lru.touch("a.example.com");
+        lru.touch("b.example.com");
+        lru.touch("a.example.com");
+        lru.touch("a.example.com");
+        lru.touch("b.example.com");
+
+        assert_eq!(lru.order.len(), 2, "at most one live position per domain");
+        assert_eq!(lru.positions.len(), 2);
+        assert_eq!(lru.peek_oldest(), Some("a.example.com"));
+    }
+
+    #[test]
+    fn lru_peek_oldest_returns_least_recently_touched_domain() {
+        let mut lru = ShardLru::new();
+        lru.touch("first.example.com");
+        lru.touch("second.example.com");
+        lru.touch("third.example.com");
+
+        assert_eq!(lru.peek_oldest(), Some("first.example.com"));
+
+        lru.touch("first.example.com");
+        assert_eq!(lru.peek_oldest(), Some("second.example.com"));
+    }
+
+    #[test]
+    fn lru_remove_clears_domain_from_both_order_and_positions() {
+        let mut lru = ShardLru::new();
+        lru.touch("a.example.com");
+        lru.touch("b.example.com");
+
+        lru.remove("a.example.com");
+
+        assert_eq!(lru.positions.get("a.example.com"), None);
+        assert!(
+            !lru.order
+                .iter()
+                .any(|(_, domain)| domain == "a.example.com"),
+            "removed domain must not remain in order"
+        );
+        assert_eq!(lru.len(), 1);
+        assert_eq!(lru.peek_oldest(), Some("b.example.com"));
+    }
+
+    #[test]
+    fn lru_touch_and_evict_cost_is_independent_of_shard_size() {
+        // Each touch performs exactly one BTreeSet removal (if the domain
+        // was already tracked) and one BTreeSet insertion, plus one
+        // HashMap lookup/insert — none of which scale with the number of
+        // other tracked domains. Assert this indirectly: touching a large
+        // number of distinct domains, then repeatedly re-touching one
+        // domain, never grows `order`/`positions` beyond the distinct
+        // domain count, regardless of how many other domains are present.
+        let mut lru = ShardLru::new();
+        for i in 0..500 {
+            lru.touch(&format!("host-{i}.example.com"));
+        }
+        assert_eq!(lru.len(), 500);
+
+        for _ in 0..50 {
+            lru.touch("host-0.example.com");
+        }
+        assert_eq!(
+            lru.len(),
+            500,
+            "repeated touches of one domain must not grow tracked count"
+        );
+        assert_eq!(lru.order.len(), 500);
+    }
+}
diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index d0535a4..89b1100 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -12,5 +12,299 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! `Shard`/`ShardState` (`PositiveShardState`/`NegativeShardState`) and the
-//! per-shard eviction loop — filled in by section-03.
+//! `Shard`/`ShardState` combine one shard's positive cache, negative
+//! cache, and LRU behind a single lock, plus the eviction loop that keeps
+//! all three in sync when the shard reaches capacity. All data for a
+//! given domain — its positive record sets, its negative-cache entries,
+//! and its LRU recency token — lives in exactly one shard and is mutated
+//! together, atomically, under that shard's single lock.
+//!
+//! No non-test callers yet (section-06/section-07 wire this into the
+//! top-level cache type); `#[allow(dead_code)]` below is transient, same
+//! pattern as `shard_index` in section-01.
+
+#![allow(dead_code)]
+
+use std::collections::HashMap;
+use std::sync::Mutex;
+
+use super::entry::{
+    DomainNegativeEntries, DomainRecordSets, NegativeEntry, NegativeKey, RRsetEntry,
+};
+use super::lru::ShardLru;
+
+#[derive(Debug, Default)]
+struct PositiveShardState {
+    domains: HashMap<String, DomainRecordSets>,
+}
+
+#[derive(Debug, Default)]
+struct NegativeShardState {
+    domains: HashMap<String, DomainNegativeEntries>,
+}
+
+#[derive(Debug, Default)]
+struct ShardState {
+    positive: PositiveShardState,
+    negative: NegativeShardState,
+    lru: ShardLru,
+}
+
+impl ShardState {
+    /// Removes `domain` from both the positive and negative maps
+    /// (unconditionally — capacity counts a domain once regardless of
+    /// whether it holds positive data, negative data, or both) and clears
+    /// its LRU position.
+    fn evict_domain(&mut self, domain: &str) {
+        self.positive.domains.remove(domain);
+        self.negative.domains.remove(domain);
+        self.lru.remove(domain);
+    }
+
+    /// Evicts the least-recently-touched domain, if any is tracked.
+    fn evict_oldest(&mut self) {
+        if let Some(oldest) = self.lru.peek_oldest() {
+            let oldest = oldest.to_string();
+            self.evict_domain(&oldest);
+        }
+    }
+
+    /// Ensures there is room for a new domain (i.e. one not already
+    /// tracked by this shard) by evicting the least-recently-touched
+    /// domain if the shard is already at `capacity`. A no-op if `domain`
+    /// is already tracked, since inserting more data under an existing
+    /// domain does not increase the domain count.
+    fn make_room_for(&mut self, domain: &str, capacity: usize) {
+        if self.domain_is_tracked(domain) {
+            return;
+        }
+        if self.lru.len() >= capacity {
+            self.evict_oldest();
+        }
+    }
+
+    fn domain_is_tracked(&self, domain: &str) -> bool {
+        self.positive.domains.contains_key(domain) || self.negative.domains.contains_key(domain)
+    }
+}
+
+/// One shard of the sharded DNS cache: its own lock, its own share of the
+/// total configured capacity (the exact remainder-distributed per-shard
+/// capacity from `CacheConfig`, section-01 — not a naive
+/// `ceil(max_entries / shard_count)`).
+#[derive(Debug)]
+pub(crate) struct Shard {
+    state: Mutex<ShardState>,
+    capacity: usize,
+}
+
+impl Shard {
+    pub(crate) fn new(capacity: usize) -> Self {
+        Self {
+            state: Mutex::new(ShardState::default()),
+            capacity,
+        }
+    }
+
+    /// Stores one positive RRset for `domain` under `(qtype, qclass)`,
+    /// evicting the least-recently-touched domain first if this is a new
+    /// domain and the shard is already at capacity. A no-op if
+    /// `capacity == 0`.
+    pub(crate) fn store_positive(&self, domain: &str, key: (u16, u16), entry: RRsetEntry) {
+        if self.capacity == 0 {
+            return;
+        }
+        let mut state = self.state.lock().unwrap();
+        state.make_room_for(domain, self.capacity);
+        state
+            .positive
+            .domains
+            .entry(domain.to_string())
+            .or_default()
+            .record_sets
+            .insert(key, entry);
+        state.lru.touch(domain);
+    }
+
+    /// Stores one negative-cache entry for `domain` under `key`, evicting
+    /// the least-recently-touched domain first if this is a new domain
+    /// and the shard is already at capacity. A no-op if `capacity == 0`.
+    pub(crate) fn store_negative(&self, domain: &str, key: NegativeKey, entry: NegativeEntry) {
+        if self.capacity == 0 {
+            return;
+        }
+        let mut state = self.state.lock().unwrap();
+        state.make_room_for(domain, self.capacity);
+        state
+            .negative
+            .domains
+            .entry(domain.to_string())
+            .or_default()
+            .entries
+            .insert(key, entry);
+        state.lru.touch(domain);
+    }
+
+    /// Records a lookup/hit against `domain` without changing its stored
+    /// data — bumps its LRU recency the same way a real cache hit would.
+    /// A no-op if `domain` has no live data in this shard.
+    pub(crate) fn touch(&self, domain: &str) {
+        let mut state = self.state.lock().unwrap();
+        if state.domain_is_tracked(domain) {
+            state.lru.touch(domain);
+        }
+    }
+
+    /// Number of distinct domains currently occupying a capacity slot in
+    /// this shard (positive data, negative data, or both — counted once).
+    pub(crate) fn domain_count(&self) -> usize {
+        self.state.lock().unwrap().lru.len()
+    }
+
+    #[cfg(test)]
+    fn contains_positive(&self, domain: &str, key: (u16, u16)) -> bool {
+        self.state
+            .lock()
+            .unwrap()
+            .positive
+            .domains
+            .get(domain)
+            .is_some_and(|record_sets| record_sets.record_sets.contains_key(&key))
+    }
+
+    #[cfg(test)]
+    fn contains_negative(&self, domain: &str, key: &NegativeKey) -> bool {
+        self.state
+            .lock()
+            .unwrap()
+            .negative
+            .domains
+            .get(domain)
+            .is_some_and(|entries| entries.entries.contains_key(key))
+    }
+
+    #[cfg(test)]
+    fn has_any_data(&self, domain: &str) -> bool {
+        self.state.lock().unwrap().domain_is_tracked(domain)
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::protocol::{RecordData, ResponseCode};
+    use crate::resolver::NegativeCacheKind;
+    use crate::resolver::cache::entry::StoredRecord;
+    use std::net::Ipv4Addr;
+    use std::time::{Duration, SystemTime};
+
+    const IN_QCLASS: u16 = 1;
+    const A_QTYPE: u16 = 1;
+
+    fn stored_record() -> StoredRecord {
+        StoredRecord {
+            rtype: A_QTYPE,
+            rclass: IN_QCLASS,
+            ttl_at_store: 300,
+            rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
+        }
+    }
+
+    fn rrset_entry() -> RRsetEntry {
+        let now = SystemTime::now();
+        RRsetEntry {
+            records: vec![stored_record()],
+            rrsigs: Vec::new(),
+            response_code: ResponseCode::NoError,
+            minimum_ttl: Duration::from_secs(300),
+            stored_at: now,
+            expires_at: now + Duration::from_secs(300),
+            dnssec_state: Default::default(),
+            cache_namespace: "ns-1".to_string(),
+        }
+    }
+
+    fn negative_entry() -> NegativeEntry {
+        let now = SystemTime::now();
+        NegativeEntry {
+            kind: NegativeCacheKind::NxDomain,
+            soa_record: stored_record(),
+            soa_rrsig: None,
+            proof_records: Vec::new(),
+            stored_at: now,
+            expires_at: now + Duration::from_secs(3600),
+            cache_namespace: "ns-1".to_string(),
+        }
+    }
+
+    #[test]
+    fn domain_with_only_negative_entry_still_counts_toward_shard_capacity() {
+        let shard = Shard::new(4);
+        let key = NegativeKey {
+            qtype: None,
+            qclass: IN_QCLASS,
+        };
+        shard.store_negative("nxdomain.example.com", key, negative_entry());
+
+        assert_eq!(shard.domain_count(), 1);
+    }
+
+    #[test]
+    fn evicting_a_domain_removes_both_positive_and_negative_data() {
+        let shard = Shard::new(1);
+        let domain = "both.example.com";
+        let neg_key = NegativeKey {
+            qtype: Some(28),
+            qclass: IN_QCLASS,
+        };
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
+        shard.store_negative(domain, neg_key.clone(), negative_entry());
+        assert_eq!(shard.domain_count(), 1);
+
+        // Force eviction by storing a second, different domain into a
+        // shard with capacity 1.
+        shard.store_positive("other.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
+
+        assert!(!shard.has_any_data(domain));
+        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
+        assert!(!shard.contains_negative(domain, &neg_key));
+        assert_eq!(shard.domain_count(), 1);
+    }
+
+    #[test]
+    fn zero_capacity_shard_stores_nothing() {
+        let shard = Shard::new(0);
+        shard.store_positive("example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
+        let neg_key = NegativeKey {
+            qtype: None,
+            qclass: IN_QCLASS,
+        };
+        shard.store_negative("other.example.com", neg_key, negative_entry());
+
+        assert_eq!(shard.domain_count(), 0);
+        assert!(!shard.has_any_data("example.com"));
+        assert!(!shard.has_any_data("other.example.com"));
+    }
+
+    #[test]
+    fn eviction_removes_least_recently_used_domain_while_touched_ones_survive() {
+        let shard = Shard::new(3);
+        shard.store_positive("a.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
+        shard.store_positive("b.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
+        shard.store_positive("c.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
+
+        // Touch b and c (simulating cache hits) so a is the
+        // least-recently-touched domain.
+        shard.touch("b.example.com");
+        shard.touch("c.example.com");
+
+        // Storing a fourth, new domain in a full shard must evict "a".
+        shard.store_positive("d.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
+
+        assert!(!shard.has_any_data("a.example.com"));
+        assert!(shard.has_any_data("b.example.com"));
+        assert!(shard.has_any_data("c.example.com"));
+        assert!(shard.has_any_data("d.example.com"));
+        assert_eq!(shard.domain_count(), 3);
+    }
+}
