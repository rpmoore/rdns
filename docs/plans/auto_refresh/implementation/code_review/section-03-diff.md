diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index 573fe95..939fe05 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -34,7 +34,7 @@ use super::entry::{
     DomainNegativeEntries, DomainRecordSets, NegativeEntry, NegativeKey, RRsetEntry,
 };
 use super::lru::ShardLru;
-use crate::config::LeakRate;
+use crate::config::{LeakRate, RefreshConfig};
 use crate::protocol::RecordData;
 
 const CNAME_RECORD_TYPE: u16 = 5;
@@ -384,6 +384,50 @@ impl ShardState {
     }
 }
 
+/// Pure trigger-formula check (`docs/plans/auto_refresh/claude-plan.md` §3.1).
+/// Given a live entry's own TTL data, the domain's current popularity bucket
+/// (if any — a domain that has never been hit, or whose bucket was evicted
+/// alongside its LRU entry, has no bucket and is therefore never hot), and
+/// refresh-config thresholds, decides whether the entry currently "wants" a
+/// proactive background refresh.
+///
+/// This does not mutate anything, perform any I/O, or take any lock beyond
+/// what the caller already holds — it is a pure function of data the
+/// live-entry probes (`take_live_positive`/`take_live_cname_hop`) already
+/// have in hand. It also does not change what those probes return as the
+/// *served* answer; it only decides whether to *additionally* signal "this
+/// entry wants a refresh" (consumed by section-04's `ChainLookup`/
+/// `RefreshHint` plumbing).
+///
+/// All three independent gates must hold for this to return `true`:
+/// 1. **Eligibility floor**: `original_ttl >= config.eligibility_floor`.
+///    Entries below this floor are never refresh-eligible regardless of
+///    remaining TTL or popularity — this exists to avoid refresh thrash on
+///    very-short-TTL records.
+/// 2. **Lead window**: `remaining_ttl <= max(original_ttl * config.lead_ratio,
+///    config.min_lead)`.
+/// 3. **Popularity**: the domain's bucket, if present, is hot at the
+///    threshold derived from `config.hot_threshold_fraction *
+///    config.bucket_capacity` (rounded to the nearest `u32`); a missing
+///    bucket (`None`) is never hot.
+pub(crate) fn wants_refresh(
+    original_ttl: Duration,
+    remaining_ttl: Duration,
+    bucket: Option<&PopularityBucket>,
+    config: &RefreshConfig,
+) -> bool {
+    if original_ttl < config.eligibility_floor {
+        return false;
+    }
+    let lead = original_ttl.mul_f32(config.lead_ratio).max(config.min_lead);
+    if remaining_ttl > lead {
+        return false;
+    }
+    let hot_threshold =
+        (config.hot_threshold_fraction * config.bucket_capacity as f32).round() as u32;
+    bucket.is_some_and(|b| b.is_hot(hot_threshold))
+}
+
 /// One shard of the sharded DNS cache: its own lock, its own share of the
 /// total configured capacity (the exact remainder-distributed per-shard
 /// capacity from `CacheConfig`, section-01 — not a naive
@@ -1493,4 +1537,181 @@ mod tests {
         bucket.drain_and_increment(later, leak_rate, 1, 10);
         assert_eq!(bucket.level(), 10 - 3 + 1);
     }
+
+    // Trigger-formula (`wants_refresh`) tests: section-03-trigger-formula.
+
+    fn test_refresh_config() -> RefreshConfig {
+        RefreshConfig {
+            enabled: true,
+            bucket_capacity: 10,
+            leak_rate: LeakRate {
+                units: 1,
+                per: Duration::from_secs(60),
+            },
+            hit_increment: 1,
+            hot_threshold_fraction: 0.5,
+            lead_ratio: 0.10,
+            min_lead: Duration::from_secs(5),
+            eligibility_floor: Duration::from_secs(15),
+            worker_count: 4,
+            channel_capacity: 256,
+        }
+    }
+
+    fn bucket_at_level(level: u32) -> PopularityBucket {
+        PopularityBucket {
+            level,
+            last_drained: SystemTime::now(),
+        }
+    }
+
+    #[test]
+    fn trigger_requires_eligibility_floor() {
+        let config = test_refresh_config();
+        let hot_bucket = bucket_at_level(10);
+
+        // Original TTL below eligibility_floor (15s): never eligible, even
+        // deep inside what would otherwise be the lead window and hot.
+        let original_ttl = Duration::from_secs(10);
+        let remaining_ttl = Duration::from_secs(1);
+        assert!(!wants_refresh(
+            original_ttl,
+            remaining_ttl,
+            Some(&hot_bucket),
+            &config
+        ));
+    }
+
+    #[test]
+    fn trigger_fires_within_lead_window() {
+        let config = test_refresh_config();
+        let hot_bucket = bucket_at_level(10);
+        let original_ttl = Duration::from_secs(300);
+        // lead = max(300 * 0.10, 5s) = 30s.
+
+        // Just inside the window.
+        assert!(wants_refresh(
+            original_ttl,
+            Duration::from_secs(29),
+            Some(&hot_bucket),
+            &config
+        ));
+        // Just outside the window.
+        assert!(!wants_refresh(
+            original_ttl,
+            Duration::from_secs(31),
+            Some(&hot_bucket),
+            &config
+        ));
+    }
+
+    #[test]
+    fn trigger_requires_hot_popularity() {
+        let config = test_refresh_config();
+        let original_ttl = Duration::from_secs(300);
+        let remaining_ttl = Duration::from_secs(10);
+
+        let cold_bucket = bucket_at_level(0);
+        assert!(!wants_refresh(
+            original_ttl,
+            remaining_ttl,
+            Some(&cold_bucket),
+            &config
+        ));
+
+        let hot_bucket = bucket_at_level(5);
+        assert!(wants_refresh(
+            original_ttl,
+            remaining_ttl,
+            Some(&hot_bucket),
+            &config
+        ));
+    }
+
+    #[test]
+    fn trigger_boundary_at_exact_lead_window_edge() {
+        let config = test_refresh_config();
+        let hot_bucket = bucket_at_level(10);
+        let original_ttl = Duration::from_secs(300);
+        // lead = max(300 * 0.10, 5s) = 30s exactly.
+        let remaining_ttl = Duration::from_secs(30);
+
+        assert!(wants_refresh(
+            original_ttl,
+            remaining_ttl,
+            Some(&hot_bucket),
+            &config
+        ));
+    }
+
+    #[test]
+    fn trigger_boundary_at_exact_eligibility_floor() {
+        let config = test_refresh_config();
+        let hot_bucket = bucket_at_level(10);
+        // original_ttl exactly equal to eligibility_floor (15s) must still
+        // count as eligible.
+        let original_ttl = config.eligibility_floor;
+        // lead = max(15s * 0.10, 5s) = 5s.
+        let remaining_ttl = Duration::from_secs(5);
+
+        assert!(wants_refresh(
+            original_ttl,
+            remaining_ttl,
+            Some(&hot_bucket),
+            &config
+        ));
+    }
+
+    #[test]
+    fn trigger_no_bucket_is_never_hot() {
+        let config = test_refresh_config();
+        let original_ttl = Duration::from_secs(300);
+        let remaining_ttl = Duration::from_secs(10);
+
+        assert!(!wants_refresh(original_ttl, remaining_ttl, None, &config));
+    }
+
+    #[test]
+    fn trigger_min_lead_dominates_over_small_ratio_lead() {
+        let config = test_refresh_config();
+        let hot_bucket = bucket_at_level(10);
+        // A short-but-still-eligible TTL: 20s * 0.10 = 2s, but min_lead is 5s,
+        // so the effective lead window must be 5s (min_lead dominates).
+        let original_ttl = Duration::from_secs(20);
+
+        assert!(wants_refresh(
+            original_ttl,
+            Duration::from_secs(5),
+            Some(&hot_bucket),
+            &config
+        ));
+        assert!(!wants_refresh(
+            original_ttl,
+            Duration::from_secs(6),
+            Some(&hot_bucket),
+            &config
+        ));
+    }
+
+    #[test]
+    fn trigger_ratio_lead_dominates_over_small_min_lead() {
+        let config = test_refresh_config();
+        let hot_bucket = bucket_at_level(10);
+        // A long TTL: 1000s * 0.10 = 100s, which is larger than min_lead
+        // (5s), so the effective lead window must be 100s (ratio dominates).
+        let original_ttl = Duration::from_secs(1000);
+
+        assert!(wants_refresh(
+            original_ttl,
+            Duration::from_secs(100),
+            Some(&hot_bucket),
+            &config
+        ));
+        assert!(!wants_refresh(
+            original_ttl,
+            Duration::from_secs(101),
+            Some(&hot_bucket),
+            &config
+        ));
+    }
 }
