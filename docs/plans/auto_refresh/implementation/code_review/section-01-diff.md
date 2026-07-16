diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index 7fabf22..c59fc0d 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -38,6 +38,103 @@ use crate::protocol::RecordData;
 
 const CNAME_RECORD_TYPE: u16 = 5;
 
+const DEFAULT_POPULARITY_LEAK_RATE: LeakRate = LeakRate {
+    units: 1,
+    per: std::time::Duration::from_secs(60),
+};
+const DEFAULT_POPULARITY_HIT_INCREMENT: u32 = 1;
+const DEFAULT_POPULARITY_BUCKET_CAPACITY: u32 = 10;
+
+/// Leak rate for a `PopularityBucket`: drains `units` worth of level per
+/// `per` elapsed real time. Defined here (cache layer), not in `config`,
+/// because the leaky-bucket concept itself belongs to the cache; a later
+/// section's `RefreshConfig` (`src/config/mod.rs`) references this same
+/// type by name for its `leak_rate` field.
+#[derive(Debug, Clone, Copy, PartialEq, Eq)]
+pub(crate) struct LeakRate {
+    pub(crate) units: u32,
+    pub(crate) per: std::time::Duration,
+}
+
+/// Per-domain leaky-bucket popularity tracker. Created the first time a
+/// domain is stored (mirroring `ShardLru`'s own on-first-store creation),
+/// drained-then-incremented on every subsequent lookup hit, and removed at
+/// exactly the two points a domain's `ShardLru` token is removed today
+/// (`ShardState::evict_domain`, `ShardState::drop_lru_if_domain_now_empty`)
+/// — this keeps popularity state from ever drifting out of sync with which
+/// domains still have cached data: when a domain's data is gone, its
+/// popularity state is gone in the same operation.
+///
+/// Granularity is per-domain (qname only), not per-`(qname, qtype, qclass)`
+/// — matching `ShardLru`'s own granularity. A query for any record type
+/// under a domain raises that domain's popularity.
+#[derive(Debug, Clone, Copy)]
+pub(crate) struct PopularityBucket {
+    level: u32,
+    last_drained: SystemTime,
+}
+
+impl PopularityBucket {
+    /// A fresh bucket for a domain seen for the first time: zero level,
+    /// drained as of `now`.
+    fn new(now: SystemTime) -> Self {
+        Self {
+            level: 0,
+            last_drained: now,
+        }
+    }
+
+    /// Drains the bucket by elapsed time since `last_drained`, then adds
+    /// `hit_increment`, saturating at `capacity`. Uses integer arithmetic
+    /// throughout (no floats) to avoid long-uptime rounding drift.
+    ///
+    /// `now` must be >= `last_drained` under normal operation; a `now` that
+    /// appears to go backward (clock adjustment) is treated as zero elapsed
+    /// time rather than panicking or underflowing — `last_drained` is never
+    /// moved backward.
+    ///
+    /// Truncation-bias avoidance: converting elapsed time to leaked units
+    /// naively (`elapsed * leak_rate.units / leak_rate.per`, discarding the
+    /// remainder, then setting `last_drained = now`) would silently bias the
+    /// drain low whenever elapsed time is repeatedly smaller than one full
+    /// drain unit. Avoided here by only ever advancing `last_drained` by the
+    /// exact amount of time actually "spent" on the whole leaked units
+    /// applied this call, leaving any leftover sub-unit elapsed time still
+    /// pending against `last_drained` for the next call to pick up — never
+    /// simply resetting `last_drained = now`.
+    fn drain_and_increment(
+        &mut self,
+        now: SystemTime,
+        leak_rate: LeakRate,
+        hit_increment: u32,
+        capacity: u32,
+    ) {
+        let elapsed = now.duration_since(self.last_drained).unwrap_or_default();
+        if leak_rate.units > 0 && !leak_rate.per.is_zero() {
+            let leaked_units = (elapsed.as_nanos() * u128::from(leak_rate.units)
+                / leak_rate.per.as_nanos().max(1)) as u32;
+            if leaked_units > 0 {
+                self.level = self.level.saturating_sub(leaked_units);
+                let time_spent = leak_rate.per * leaked_units / leak_rate.units;
+                self.last_drained += time_spent;
+            }
+        }
+        self.level = self.level.saturating_add(hit_increment).min(capacity);
+    }
+
+    /// True if `level >= hot_threshold` (an absolute count derived elsewhere
+    /// from `RefreshConfig::hot_threshold_fraction * bucket_capacity` — this
+    /// method just takes the precomputed absolute threshold).
+    fn is_hot(&self, hot_threshold: u32) -> bool {
+        self.level >= hot_threshold
+    }
+
+    #[cfg(test)]
+    fn level(&self) -> u32 {
+        self.level
+    }
+}
+
 /// Result of one hop's lookup within `resolve_from_cache`'s CNAME-chain
 /// walk (`cache::assemble`, section-06) — whatever this shard found (or
 /// didn't) for one name in the chain, already cloned out from under this
@@ -74,6 +171,7 @@ struct ShardState {
     positive: PositiveShardState,
     negative: NegativeShardState,
     lru: ShardLru,
+    popularity: HashMap<String, PopularityBucket>,
 }
 
 impl ShardState {
@@ -85,6 +183,28 @@ impl ShardState {
         self.positive.domains.remove(domain);
         self.negative.domains.remove(domain);
         self.lru.remove(domain);
+        self.popularity.remove(domain);
+    }
+
+    /// Drains-then-increments `domain`'s popularity bucket, allocating it on
+    /// first hit. A complete no-op — the bucket is never allocated at all,
+    /// not merely "left untouched" — when `enabled` is false.
+    fn record_popularity_hit(
+        &mut self,
+        domain: &str,
+        now: SystemTime,
+        enabled: bool,
+        leak_rate: LeakRate,
+        hit_increment: u32,
+        bucket_capacity: u32,
+    ) {
+        if !enabled {
+            return;
+        }
+        self.popularity
+            .entry(domain.to_string())
+            .or_insert_with(|| PopularityBucket::new(now))
+            .drain_and_increment(now, leak_rate, hit_increment, bucket_capacity);
     }
 
     /// Evicts the least-recently-touched domain, if any is tracked.
@@ -146,6 +266,7 @@ impl ShardState {
             && !self.negative.domains.contains_key(domain)
         {
             self.lru.remove(domain);
+            self.popularity.remove(domain);
         }
     }
 
@@ -424,6 +545,14 @@ impl Shard {
             state.take_live_positive(domain, answer_key, dnssec_ok, current_epoch, now)
         {
             state.lru.touch(domain);
+            state.record_popularity_hit(
+                domain,
+                now,
+                true,
+                DEFAULT_POPULARITY_LEAK_RATE,
+                DEFAULT_POPULARITY_HIT_INCREMENT,
+                DEFAULT_POPULARITY_BUCKET_CAPACITY,
+            );
             return HopResult::Answer(entry);
         }
 
@@ -433,6 +562,14 @@ impl Shard {
                 state.take_live_cname_hop(domain, cname_key, dnssec_ok, current_epoch, now)
             {
                 state.lru.touch(domain);
+                state.record_popularity_hit(
+                    domain,
+                    now,
+                    true,
+                    DEFAULT_POPULARITY_LEAK_RATE,
+                    DEFAULT_POPULARITY_HIT_INCREMENT,
+                    DEFAULT_POPULARITY_BUCKET_CAPACITY,
+                );
                 return HopResult::CnameHop(entry, target);
             }
         }
@@ -445,6 +582,14 @@ impl Shard {
             state.take_live_negative(domain, &nodata_key, dnssec_ok, current_epoch, now)
         {
             state.lru.touch(domain);
+            state.record_popularity_hit(
+                domain,
+                now,
+                true,
+                DEFAULT_POPULARITY_LEAK_RATE,
+                DEFAULT_POPULARITY_HIT_INCREMENT,
+                DEFAULT_POPULARITY_BUCKET_CAPACITY,
+            );
             return HopResult::NoData(entry);
         }
 
@@ -456,6 +601,14 @@ impl Shard {
             state.take_live_negative(domain, &nxdomain_key, dnssec_ok, current_epoch, now)
         {
             state.lru.touch(domain);
+            state.record_popularity_hit(
+                domain,
+                now,
+                true,
+                DEFAULT_POPULARITY_LEAK_RATE,
+                DEFAULT_POPULARITY_HIT_INCREMENT,
+                DEFAULT_POPULARITY_BUCKET_CAPACITY,
+            );
             return HopResult::NxDomain(entry);
         }
 
@@ -538,6 +691,16 @@ impl Shard {
         self.state.lock().unwrap().domain_is_tracked(domain)
     }
 
+    #[cfg(test)]
+    pub(crate) fn popularity_level(&self, domain: &str) -> Option<u32> {
+        self.state
+            .lock()
+            .unwrap()
+            .popularity
+            .get(domain)
+            .map(PopularityBucket::level)
+    }
+
     /// Test-only: locks this shard's state and sleeps, to let a
     /// concurrency test prove some other shard's operations don't block on
     /// this one's lock.
@@ -1087,4 +1250,173 @@ mod tests {
         );
         assert_eq!(shard.domain_count(), 1);
     }
+
+    // Popularity bucket (leaky bucket) tests: section-01-popularity-bucket.
+
+    fn leak_rate_1_per_60s() -> LeakRate {
+        LeakRate {
+            units: 1,
+            per: Duration::from_secs(60),
+        }
+    }
+
+    #[test]
+    fn popularity_bucket_drains_by_elapsed_time() {
+        let now = SystemTime::now();
+        let mut bucket = PopularityBucket::new(now);
+        // Get the level up to 5 first, with no elapsed time so nothing drains.
+        for _ in 0..5 {
+            bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
+        }
+        assert_eq!(bucket.level(), 5);
+
+        // 180s elapsed at 1 unit/60s should drain 3 units, then +1 hit.
+        let later = now + Duration::from_secs(180);
+        bucket.drain_and_increment(later, leak_rate_1_per_60s(), 1, 10);
+        assert_eq!(bucket.level(), 5 - 3 + 1);
+    }
+
+    #[test]
+    fn popularity_bucket_increments_on_hit() {
+        let now = SystemTime::now();
+        let mut bucket = PopularityBucket::new(now);
+        bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
+        assert_eq!(bucket.level(), 1);
+        bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
+        assert_eq!(bucket.level(), 2);
+    }
+
+    #[test]
+    fn popularity_bucket_saturates_at_capacity() {
+        let now = SystemTime::now();
+        let mut bucket = PopularityBucket::new(now);
+        for _ in 0..50 {
+            bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
+        }
+        assert_eq!(bucket.level(), 10);
+    }
+
+    #[test]
+    fn popularity_bucket_drain_no_truncation_bias() {
+        let now = SystemTime::now();
+        let leak_rate = leak_rate_1_per_60s();
+
+        // One big step: fill to capacity, then let 600s elapse in one call.
+        let mut big_step = PopularityBucket::new(now);
+        for _ in 0..10 {
+            big_step.drain_and_increment(now, leak_rate, 1, 10);
+        }
+        let big_step_result_time = now + Duration::from_secs(600);
+        big_step.drain_and_increment(big_step_result_time, leak_rate, 0, 10);
+
+        // Many small steps covering the same total elapsed time (600s),
+        // advanced 60 times in 10s increments.
+        let mut small_steps = PopularityBucket::new(now);
+        for _ in 0..10 {
+            small_steps.drain_and_increment(now, leak_rate, 1, 10);
+        }
+        let mut t = now;
+        for _ in 0..60 {
+            t += Duration::from_secs(10);
+            small_steps.drain_and_increment(t, leak_rate, 0, 10);
+        }
+
+        assert_eq!(
+            big_step.level(),
+            small_steps.level(),
+            "draining in many small sub-unit steps must not bias the cumulative drain \
+             relative to one large step covering the same total elapsed time"
+        );
+    }
+
+    #[test]
+    fn popularity_bucket_treats_backward_clock_as_zero_elapsed() {
+        let now = SystemTime::now();
+        let mut bucket = PopularityBucket::new(now);
+        bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
+        assert_eq!(bucket.level(), 1);
+
+        let earlier = now - Duration::from_secs(120);
+        // Should not panic/underflow, and should not drain (treated as zero
+        // elapsed time), so the hit_increment is simply added.
+        bucket.drain_and_increment(earlier, leak_rate_1_per_60s(), 1, 10);
+        assert_eq!(bucket.level(), 2);
+    }
+
+    #[test]
+    fn popularity_cleared_on_evict_domain() {
+        let shard = Shard::new(1);
+        let domain = "popular.example.com";
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
+        let now = SystemTime::now();
+        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        assert_eq!(shard.popularity_level(domain), Some(1));
+
+        // Force eviction via capacity pressure.
+        shard.store_positive("other.example.com", (A_QTYPE, IN_QCLASS), rrset_entry());
+
+        assert_eq!(shard.popularity_level(domain), None);
+    }
+
+    #[test]
+    fn popularity_cleared_on_drop_lru_if_domain_now_empty() {
+        let shard = Shard::new(4);
+        let domain = "solo-positive.example.com";
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
+        let now = SystemTime::now();
+        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        assert_eq!(shard.popularity_level(domain), Some(1));
+
+        // Expire the only entry and look it up again, triggering removal
+        // via remove_positive_entry -> drop_lru_if_domain_now_empty.
+        let mut expired = rrset_entry();
+        expired.expires_at = now - Duration::from_secs(1);
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired);
+        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+
+        assert_eq!(shard.popularity_level(domain), None);
+    }
+
+    #[test]
+    fn popularity_not_allocated_when_disabled() {
+        let shard = Shard::new(4);
+        let domain = "disabled.example.com";
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
+        let now = SystemTime::now();
+
+        // Exercise record_popularity_hit directly with enabled = false via
+        // the shard's internal state, since lookup_hop always passes
+        // enabled = true today (placeholder until section-03 threads real
+        // config through). Access via hold_lock_for_test's lock pattern
+        // would deadlock, so this test targets ShardState directly.
+        let mut state = ShardState::default();
+        state.record_popularity_hit(domain, now, false, leak_rate_1_per_60s(), 1, 10);
+        assert!(!state.popularity.contains_key(domain));
+    }
+
+    #[test]
+    fn is_hot_reflects_configured_threshold() {
+        let now = SystemTime::now();
+        let mut bucket = PopularityBucket::new(now);
+        for _ in 0..5 {
+            bucket.drain_and_increment(now, leak_rate_1_per_60s(), 1, 10);
+        }
+        assert_eq!(bucket.level(), 5);
+        assert!(bucket.is_hot(5));
+        assert!(!bucket.is_hot(6));
+    }
+
+    #[test]
+    fn lookup_hop_hit_increments_popularity_level() {
+        let shard = Shard::new(4);
+        let domain = "hit-tracked.example.com";
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
+        let now = SystemTime::now();
+
+        assert_eq!(shard.popularity_level(domain), None);
+        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        assert_eq!(shard.popularity_level(domain), Some(1));
+        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        assert_eq!(shard.popularity_level(domain), Some(2));
+    }
 }
