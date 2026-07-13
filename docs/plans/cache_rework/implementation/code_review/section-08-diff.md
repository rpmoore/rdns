diff --git a/justfile b/justfile
index ea9bccd..9fdcb4b 100644
--- a/justfile
+++ b/justfile
@@ -2,7 +2,7 @@ fmt:
     cargo fmt
 
 bench:
-    cargo test --locked --release --test recursive_perf -- --ignored --nocapture --test-threads=1
+    cargo test --locked --release --test recursive_perf --test cache_concurrency_bench -- --ignored --nocapture --test-threads=1
 
 coverage:
     cargo llvm-cov --locked --summary-only
diff --git a/src/resolver/cache/entry.rs b/src/resolver/cache/entry.rs
index 95b37d7..cec68f9 100644
--- a/src/resolver/cache/entry.rs
+++ b/src/resolver/cache/entry.rs
@@ -41,17 +41,17 @@ pub(crate) struct DomainRecordSets {
 /// assembly design, implemented in section-06, not this section).
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct RRsetEntry {
-    pub(crate) records: Vec<StoredRecord>,
-    pub(crate) rrsigs: Vec<StoredRecord>, // empty if none were fetched/cached
+    pub records: Vec<StoredRecord>,
+    pub rrsigs: Vec<StoredRecord>, // empty if none were fetched/cached
     // Almost always NoError; kept for parity with today's CachedResponse shape.
-    pub(crate) response_code: ResponseCode,
-    pub(crate) minimum_ttl: Duration,
-    pub(crate) stored_at: SystemTime,
-    pub(crate) expires_at: SystemTime,
-    pub(crate) dnssec_state: DnssecState,
+    pub response_code: ResponseCode,
+    pub minimum_ttl: Duration,
+    pub stored_at: SystemTime,
+    pub expires_at: SystemTime,
+    pub dnssec_state: DnssecState,
     // Namespace is no longer part of the lookup key, so it must be stored
     // per entry instead.
-    pub(crate) cache_namespace: String,
+    pub cache_namespace: String,
 }
 
 /// A single stored resource record, minus anything request-specific
@@ -60,10 +60,10 @@ pub struct RRsetEntry {
 /// existing `RecordData` type from `src/protocol`.
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct StoredRecord {
-    pub(crate) rtype: u16,
-    pub(crate) rclass: u16,
-    pub(crate) ttl_at_store: u32,
-    pub(crate) rdata: RecordData,
+    pub rtype: u16,
+    pub rclass: u16,
+    pub ttl_at_store: u32,
+    pub rdata: RecordData,
 }
 
 /// Mirrors RFC 6840 §3.1's "BAD cache" concept and Unbound/BIND-style
@@ -72,7 +72,7 @@ pub struct StoredRecord {
 /// for this whole rework) — this enum exists purely so the data model
 /// doesn't need reshaping again when that work happens later.
 #[derive(Debug, Clone, PartialEq, Eq, Default)]
-pub(crate) enum DnssecState {
+pub enum DnssecState {
     #[default]
     Unvalidated,
     // Not constructed anywhere yet — real DNSSEC validation is out of
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 8f393ab..8bc8e15 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -38,11 +38,17 @@ use crate::protocol::{
 
 mod cache;
 use cache::{
-    ChainLookup, DecomposedResponse, InFlightMiss, NegativeEntry, NegativeKey, RRsetEntry,
-    ShardedSingleFlight, SingleFlightLeader, SingleFlightTicket, StoredRecord,
+    ChainLookup, InFlightMiss, ShardedSingleFlight, SingleFlightLeader, SingleFlightTicket,
     assemble_negative_response, assemble_response,
 };
-pub use cache::{DomainDnsCache, ShardedDnsCache};
+// `DecomposedResponse`/`RRsetEntry`/`StoredRecord`/`NegativeKey`/`NegativeEntry`
+// are re-exported (not just used privately) so external test crates — see
+// `tests/cache_concurrency_bench.rs` (section-08) — can drive
+// `DomainDnsCache::store_response` with real data, not just the read path.
+pub use cache::{
+    DecomposedResponse, DomainDnsCache, NegativeEntry, NegativeKey, RRsetEntry, ShardedDnsCache,
+    StoredRecord,
+};
 
 pub mod policy;
 pub use policy::{
@@ -14030,6 +14036,62 @@ mod tests {
         assert_eq!(second_backend.requests.lock().unwrap().len(), 1);
     }
 
+    /// `backend_generation_separates_cache_entries` (above) only proves two
+    /// generations' entries land under different namespaces and so never
+    /// collide as *lookups* — it never proves `publish_reload`'s
+    /// namespace-sweep call (wired in section-07) actually runs and
+    /// removes the stale entry, versus just leaving it as orphaned, never
+    /// pruned capacity. This test seeds a real `ShardedDnsCache` under
+    /// generation 1's namespace, reloads to generation 2, and asserts the
+    /// domain is actually gone afterward, not merely unreachable.
+    #[tokio::test]
+    async fn backend_reload_sweep_invalidates_stale_generation_entries() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x1111, "example.com", 60),
+        ))));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = ResolveQuery::with_cache_and_backend_generation(
+            Arc::new(StandardProtocolCodec::new(1232)),
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            CacheTtlPolicy::default(),
+            upstream.clone(),
+            1,
+            Arc::new(BasicResponseFactory),
+            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
+            events,
+            metrics,
+        );
+
+        let _ = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                SystemTime::UNIX_EPOCH,
+                a_query(0x1111, "example.com"),
+            ))
+            .await;
+        assert_eq!(
+            cache.domain_count(),
+            1,
+            "warming resolve should have stored one domain under generation 1's namespace"
+        );
+
+        let new_backend = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let new_snapshot = BackendSnapshot::forwarding(new_backend, 2);
+        service.publish_reload(new_snapshot, Arc::new(NoopLocalDnsEntries));
+
+        assert_eq!(
+            cache.domain_count(),
+            0,
+            "publish_reload's namespace sweep should have removed the generation-1 entry, \
+             not just left it unreachable"
+        );
+    }
+
     #[tokio::test]
     async fn resolve_rejects_invalid_backend_response_bytes() {
         for response in [
diff --git a/tests/cache_concurrency_bench.rs b/tests/cache_concurrency_bench.rs
new file mode 100644
index 0000000..c949280
--- /dev/null
+++ b/tests/cache_concurrency_bench.rs
@@ -0,0 +1,144 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Concurrency benchmark for the sharded answer cache (`docs/plans/cache_rework/`,
+//! goal 1: reduce lock scope so concurrent requests for different domains
+//! don't serialize behind one global mutex). `#[ignore]`d like
+//! `recursive_perf.rs`, run via `just bench` — this measures raw
+//! `lookup_chain`/`store_response` throughput under concurrent load
+//! directly, not end-to-end DNS resolution through a scripted backend, so
+//! it doesn't fit `recursive_perf.rs`'s harness.
+//!
+//! No before/after comparison against the old, now-deleted
+//! single-global-mutex `InMemoryDnsCache` is included here: per the
+//! section-08 plan, that comparison is a one-time manual step (run this
+//! workload's shape against a temporarily-reinstated old implementation
+//! from a pre-section-07 commit, on request) rather than a permanently
+//! dual-implemented benchmark kept in the tree — `InMemoryDnsCache` no
+//! longer exists in this codebase at all as of section-07.
+
+use std::net::Ipv4Addr;
+use std::sync::Arc;
+use std::thread;
+use std::time::{Duration, Instant, SystemTime};
+
+use rdns::config::CacheConfig;
+use rdns::protocol::{RecordData, ResponseCode};
+use rdns::resolver::{
+    DecomposedResponse, DomainDnsCache, RRsetEntry, ShardedDnsCache, StoredRecord,
+};
+
+const A_QTYPE: u16 = 1;
+const IN_QCLASS: u16 = 1;
+const NAMESPACE: &str = "bench";
+const MAX_CHAIN_DEPTH: u8 = 8;
+
+fn seed_entry(now: SystemTime) -> RRsetEntry {
+    RRsetEntry {
+        records: vec![StoredRecord {
+            rtype: A_QTYPE,
+            rclass: IN_QCLASS,
+            ttl_at_store: 300,
+            rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
+        }],
+        rrsigs: Vec::new(),
+        response_code: ResponseCode::NoError,
+        minimum_ttl: Duration::from_secs(300),
+        stored_at: now,
+        expires_at: now + Duration::from_secs(300),
+        dnssec_state: Default::default(),
+        cache_namespace: NAMESPACE.to_string(),
+    }
+}
+
+/// One thread's share of the workload: a mix of stores (25%) and lookups
+/// (75%, roughly matching a cache that's mostly serving hits/misses rather
+/// than constantly re-populating), cycling through `domains` so many
+/// threads repeatedly contend for the same small set of shards rather than
+/// each staying comfortably within its own.
+fn run_workload(cache: &ShardedDnsCache, domains: &[String], operation_count: usize) {
+    for i in 0..operation_count {
+        let domain = &domains[i % domains.len()];
+        if i % 4 == 0 {
+            cache.store_response(
+                DecomposedResponse {
+                    positive: vec![(
+                        domain.clone(),
+                        A_QTYPE,
+                        IN_QCLASS,
+                        seed_entry(SystemTime::now()),
+                    )],
+                    negative: None,
+                },
+                NAMESPACE,
+            );
+        } else {
+            let _ = cache.lookup_chain(
+                domain,
+                A_QTYPE,
+                IN_QCLASS,
+                NAMESPACE,
+                MAX_CHAIN_DEPTH,
+                SystemTime::now(),
+            );
+        }
+    }
+}
+
+/// Not a pass/fail assertion (absolute throughput is environment-dependent
+/// — matches `recursive_perf.rs`'s own convention of printing a table for
+/// manual inspection via `--nocapture` rather than asserting a specific
+/// number). The property worth eyeballing: `ops_per_sec` at higher thread
+/// counts should stay in the same ballpark as at 1 thread, not collapse
+/// toward it (which is what a single-global-mutex design would do, since
+/// every thread would serialize behind the one lock regardless of which
+/// domains it touches).
+#[test]
+#[ignore = "run via `just bench`; prints a throughput table, no CI assertion"]
+fn concurrent_cache_access_across_shards_scales_with_thread_count() {
+    // 256 distinct domain names, hashed across whatever shard count
+    // `CacheConfig::default()`'s `shard_count: None` resolves to
+    // (`available_parallelism() * 4`, rounded to a power of two) — plenty
+    // to spread across many shards without needing `shard_index` itself
+    // (crate-private, not part of this benchmark's public surface) to
+    // engineer the mix by hand.
+    let domains: Vec<String> = (0..256).map(|i| format!("host-{i}.example.com")).collect();
+    let total_operations = 200_000usize;
+
+    println!("threads,total_ops,wall_ms,ops_per_sec");
+    for &thread_count in &[1usize, 2, 4, 8] {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 100_000,
+            shard_count: None,
+        }));
+        let operations_per_thread = total_operations / thread_count;
+
+        let start = Instant::now();
+        thread::scope(|scope| {
+            for _ in 0..thread_count {
+                let cache = Arc::clone(&cache);
+                let domains = &domains;
+                scope.spawn(move || run_workload(&cache, domains, operations_per_thread));
+            }
+        });
+        let elapsed = start.elapsed();
+
+        let completed_operations = operations_per_thread * thread_count;
+        let ops_per_sec = completed_operations as f64 / elapsed.as_secs_f64();
+        println!(
+            "{thread_count},{completed_operations},{},{ops_per_sec:.0}",
+            elapsed.as_millis()
+        );
+    }
+}
