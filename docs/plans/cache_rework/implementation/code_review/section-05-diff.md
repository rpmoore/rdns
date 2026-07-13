diff --git a/src/resolver/cache/namespace.rs b/src/resolver/cache/namespace.rs
index 8c5f12b..d42d9af 100644
--- a/src/resolver/cache/namespace.rs
+++ b/src/resolver/cache/namespace.rs
@@ -12,4 +12,200 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! `sweep_stale_namespace` — filled in by section-05.
+//! Namespace sweep: the one deliberate O(n) operation in the cache design
+//! (n = total cached entries, not domains), run once after a reload
+//! publishes a new `cache_namespace`. Every other cache operation is
+//! O(log n) or better per shard. Wiring this into the reload path
+//! (`main.rs`'s `publish_reload`, `DomainDnsCache::sweep_stale_namespace`)
+//! is section-07's job — here it is a free function, fully testable
+//! against hand-constructed shard state.
+
+#![allow(dead_code)]
+
+use super::shard::Shard;
+
+/// Walks every shard and removes any entry whose stored `cache_namespace`
+/// no longer matches `current_namespace`, dropping any domain left with no
+/// remaining entries in either map (and its LRU token along with it). Each
+/// shard's lock is held only for the duration of that shard's own scan —
+/// never a lock shared across shards, so concurrent lookups against
+/// already-swept or not-yet-swept shards proceed normally throughout.
+///
+/// Takes `shards` directly rather than the `ShardedDnsCache` container.
+/// `ShardedDnsCache` is section-06's deliverable, built in parallel with
+/// this section from the same section-03 dependency, so it does not exist
+/// at this section's implementation time — see this section's
+/// implementation notes. Section-07 will call this as
+/// `sweep_stale_namespace(&cache.shards, ...)` once `ShardedDnsCache`
+/// exists.
+///
+/// Returns the total number of entries removed across all shards — a
+/// reasonable deviation from the plan's bare `fn(...)` signature, useful
+/// for both direct assertions in tests below and logging/metrics in
+/// section-07's wiring.
+pub(crate) fn sweep_stale_namespace(shards: &[Shard], current_namespace: &str) -> usize {
+    shards
+        .iter()
+        .map(|shard| shard.sweep_stale_namespace(current_namespace))
+        .sum()
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::protocol::{RecordData, ResponseCode};
+    use crate::resolver::NegativeCacheKind;
+    use crate::resolver::cache::entry::{NegativeEntry, NegativeKey, RRsetEntry, StoredRecord};
+    use std::net::Ipv4Addr;
+    use std::time::{Duration, Instant, SystemTime};
+
+    const IN_QCLASS: u16 = 1;
+    const A_QTYPE: u16 = 1;
+    const AAAA_QTYPE: u16 = 28;
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
+    fn rrset_entry(namespace: &str) -> RRsetEntry {
+        let now = SystemTime::now();
+        RRsetEntry {
+            records: vec![stored_record()],
+            rrsigs: Vec::new(),
+            response_code: ResponseCode::NoError,
+            minimum_ttl: Duration::from_secs(300),
+            stored_at: now,
+            expires_at: now + Duration::from_secs(300),
+            dnssec_state: Default::default(),
+            cache_namespace: namespace.to_string(),
+        }
+    }
+
+    fn negative_entry(namespace: &str) -> NegativeEntry {
+        let now = SystemTime::now();
+        NegativeEntry {
+            kind: NegativeCacheKind::NxDomain,
+            soa_record: stored_record(),
+            soa_rrsig: None,
+            proof_records: Vec::new(),
+            stored_at: now,
+            expires_at: now + Duration::from_secs(3600),
+            cache_namespace: namespace.to_string(),
+        }
+    }
+
+    #[test]
+    fn sweep_removes_only_entries_from_stale_namespace() {
+        let shard = Shard::new(4);
+        shard.store_positive(
+            "stale.example.com",
+            (A_QTYPE, IN_QCLASS),
+            rrset_entry("old"),
+        );
+        shard.store_positive(
+            "current.example.com",
+            (A_QTYPE, IN_QCLASS),
+            rrset_entry("current"),
+        );
+
+        let removed = sweep_stale_namespace(std::slice::from_ref(&shard), "current");
+
+        assert_eq!(removed, 1);
+        assert!(!shard.has_any_data("stale.example.com"));
+        assert!(shard.has_any_data("current.example.com"));
+        assert!(shard.contains_positive("current.example.com", (A_QTYPE, IN_QCLASS)));
+    }
+
+    #[test]
+    fn sweep_removes_domain_entirely_when_all_its_record_sets_are_stale() {
+        let shard = Shard::new(4);
+        let domain = "fully-stale.example.com";
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry("old"));
+        shard.store_positive(domain, (AAAA_QTYPE, IN_QCLASS), rrset_entry("old"));
+        let neg_key = NegativeKey {
+            qtype: Some(15),
+            qclass: IN_QCLASS,
+        };
+        shard.store_negative(domain, neg_key.clone(), negative_entry("old"));
+
+        let removed = sweep_stale_namespace(std::slice::from_ref(&shard), "current");
+
+        assert_eq!(removed, 3);
+        assert!(!shard.has_any_data(domain));
+        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
+        assert!(!shard.contains_positive(domain, (AAAA_QTYPE, IN_QCLASS)));
+        assert!(!shard.contains_negative(domain, &neg_key));
+        assert_eq!(shard.domain_count(), 0);
+    }
+
+    #[test]
+    fn sweep_keeps_domain_partially_when_some_record_sets_are_current() {
+        let shard = Shard::new(4);
+        let domain = "mixed.example.com";
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry("old"));
+        shard.store_positive(domain, (AAAA_QTYPE, IN_QCLASS), rrset_entry("current"));
+
+        let removed = sweep_stale_namespace(std::slice::from_ref(&shard), "current");
+
+        assert_eq!(removed, 1);
+        assert!(shard.has_any_data(domain));
+        assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
+        assert!(shard.contains_positive(domain, (AAAA_QTYPE, IN_QCLASS)));
+        assert_eq!(shard.domain_count(), 1);
+    }
+
+    #[test]
+    fn sweep_removes_domain_with_only_stale_negative_entry() {
+        let shard = Shard::new(4);
+        let domain = "nxdomain-only.example.com";
+        let neg_key = NegativeKey {
+            qtype: None,
+            qclass: IN_QCLASS,
+        };
+        shard.store_negative(domain, neg_key.clone(), negative_entry("old"));
+
+        let removed = sweep_stale_namespace(std::slice::from_ref(&shard), "current");
+
+        assert_eq!(removed, 1);
+        assert!(!shard.has_any_data(domain));
+        assert!(!shard.contains_negative(domain, &neg_key));
+        assert_eq!(shard.domain_count(), 0);
+    }
+
+    #[test]
+    fn sweep_across_shards_does_not_require_a_shared_lock() {
+        let shard_a = Shard::new(4);
+        let shard_b = Shard::new(4);
+        shard_a.store_positive("a.example.com", (A_QTYPE, IN_QCLASS), rrset_entry("old"));
+        shard_b.store_positive(
+            "b.example.com",
+            (A_QTYPE, IN_QCLASS),
+            rrset_entry("current"),
+        );
+
+        // Hold shard A's lock in a background thread for well longer than
+        // sweeping shard B alone should ever take, then assert sweeping
+        // shard B was not blocked by it.
+        let handle = std::thread::spawn(move || {
+            shard_a.hold_lock_for_test(Duration::from_millis(200));
+        });
+        std::thread::sleep(Duration::from_millis(50));
+
+        let start = Instant::now();
+        let removed = sweep_stale_namespace(std::slice::from_ref(&shard_b), "current");
+        let elapsed = start.elapsed();
+
+        handle.join().unwrap();
+
+        assert_eq!(removed, 0);
+        assert!(
+            elapsed < Duration::from_millis(150),
+            "sweeping shard B should not wait on shard A's held lock, took {elapsed:?}"
+        );
+    }
+}
diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index 2ea1907..114fe75 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -161,8 +161,57 @@ impl Shard {
         self.state.lock().unwrap().lru.len()
     }
 
+    /// Removes every positive/negative entry in this shard whose stored
+    /// `cache_namespace` no longer matches `current_namespace`, and drops
+    /// any domain (and its LRU token) left with no entries in either map
+    /// afterward. Takes this shard's lock for the duration of the scan
+    /// only — sweeping one shard never waits on any other shard's lock.
+    /// Returns the total number of entries removed (`cache::namespace`,
+    /// section-05).
+    pub(crate) fn sweep_stale_namespace(&self, current_namespace: &str) -> usize {
+        let mut state = self.state.lock().unwrap();
+        let mut removed = 0usize;
+        let mut emptied_domains: Vec<String> = Vec::new();
+
+        state.positive.domains.retain(|domain, record_sets| {
+            let before = record_sets.record_sets.len();
+            record_sets
+                .record_sets
+                .retain(|_, entry| entry.cache_namespace == current_namespace);
+            removed += before - record_sets.record_sets.len();
+            let keep = !record_sets.record_sets.is_empty();
+            if !keep {
+                emptied_domains.push(domain.clone());
+            }
+            keep
+        });
+
+        state.negative.domains.retain(|domain, entries| {
+            let before = entries.entries.len();
+            entries
+                .entries
+                .retain(|_, entry| entry.cache_namespace == current_namespace);
+            removed += before - entries.entries.len();
+            let keep = !entries.entries.is_empty();
+            if !keep {
+                emptied_domains.push(domain.clone());
+            }
+            keep
+        });
+
+        for domain in emptied_domains {
+            if !state.positive.domains.contains_key(&domain)
+                && !state.negative.domains.contains_key(&domain)
+            {
+                state.lru.remove(&domain);
+            }
+        }
+
+        removed
+    }
+
     #[cfg(test)]
-    fn contains_positive(&self, domain: &str, key: (u16, u16)) -> bool {
+    pub(crate) fn contains_positive(&self, domain: &str, key: (u16, u16)) -> bool {
         self.state
             .lock()
             .unwrap()
@@ -173,7 +222,7 @@ impl Shard {
     }
 
     #[cfg(test)]
-    fn contains_negative(&self, domain: &str, key: &NegativeKey) -> bool {
+    pub(crate) fn contains_negative(&self, domain: &str, key: &NegativeKey) -> bool {
         self.state
             .lock()
             .unwrap()
@@ -184,9 +233,18 @@ impl Shard {
     }
 
     #[cfg(test)]
-    fn has_any_data(&self, domain: &str) -> bool {
+    pub(crate) fn has_any_data(&self, domain: &str) -> bool {
         self.state.lock().unwrap().domain_is_tracked(domain)
     }
+
+    /// Test-only: locks this shard's state and sleeps, to let a
+    /// concurrency test prove some other shard's operations don't block on
+    /// this one's lock.
+    #[cfg(test)]
+    pub(crate) fn hold_lock_for_test(&self, duration: std::time::Duration) {
+        let _guard = self.state.lock().unwrap();
+        std::thread::sleep(duration);
+    }
 }
 
 #[cfg(test)]
