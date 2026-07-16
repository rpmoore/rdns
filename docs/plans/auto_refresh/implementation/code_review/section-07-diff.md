diff --git a/docs/knowledge/resolver/caching/answer-cache.md b/docs/knowledge/resolver/caching/answer-cache.md
index dd21b54..e7a2a23 100644
--- a/docs/knowledge/resolver/caching/answer-cache.md
+++ b/docs/knowledge/resolver/caching/answer-cache.md
@@ -220,36 +220,13 @@ Capacity is domain-count-based, configured via `CacheConfig.max_entries`,
 split across shards by `CacheConfig::shard_capacity` (see
 [sharding](sharding.md)).
 
-# Popularity tracking
+# Popularity tracking and auto-refresh
 
-Each domain also has an optional `PopularityBucket` (`src/resolver/cache/shard.rs`)
-— an integer leaky-bucket counter (level + last-drained timestamp),
-drained-then-incremented on every cache hit at the same point `lru.touch`
-already runs. It's cleared alongside the LRU token at the same two removal
-points (`ShardState::evict_domain`, `ShardState::drop_lru_if_domain_now_empty`),
-so a domain's popularity state normally can't outlive its cache data — except
-via `sweep_stale_namespace`, which clears the LRU token directly without going
-through either of those two functions, so a bucket can currently outlive its
-domain's data when cleared by a namespace sweep instead (an accepted gap, not
-yet addressed). This is the foundation for an in-progress auto-refresh feature
-(proactively refetching popular, near-expiry entries); see
-`docs/plans/auto_refresh/` for the full design as later pieces land.
-
-# Refresh worker pool
-
-A fixed pool of `RefreshConfig.worker_count` tasks (`spawn_refresh_worker_pool`,
-`src/resolver/mod.rs`) processes background refresh jobs enqueued from the
-cache-hit path. All workers share one bounded `tokio::sync::mpsc` channel via
-`Arc<tokio::sync::Mutex<Receiver<RefreshJob>>>` — this serializes only the
-dequeue point (one worker parks on `recv()` at a time), not job execution.
-Each dequeued job runs as its own `tokio::spawn`ed task, and the worker
-`.await`s that task's `JoinHandle` before dequeuing the next job: a panic in
-one job fails only its own `JoinHandle` (inspected via `JoinError::is_panic()`
-and logged), never the worker loop itself. Shutdown has no internal signal —
-`main.rs` holds the pool's `JoinHandle`s and `.abort()`s them at teardown,
-mirroring `spawn_sighup_reload_task`'s existing convention exactly. Job
-processing itself (`process_refresh_job`) is a no-op stub until the
-fetch/store logic lands; see `docs/plans/auto_refresh/` for the full design.
+Each domain also has an optional `PopularityBucket` (`ShardState.popularity`,
+`src/resolver/cache/shard.rs:59,168`) feeding a proactive-refresh feature that
+refetches popular, near-expiry entries before a client would ever see the
+miss. Full design, invariants, and file:line references:
+see [auto-refresh](auto-refresh.md).
 
 # See also
 
@@ -257,3 +234,5 @@ fetch/store logic lands; see `docs/plans/auto_refresh/` for the full design.
 - [sharding](sharding.md) — how domains route to shards, and what else shares this routing scheme.
 - [local-dns-entries](local-dns-entries.md) — the separate, non-cached structure for manually-loaded
   answers.
+- [auto-refresh](auto-refresh.md) — proactive cache refresh for popular domains nearing TTL expiry,
+  built on top of this cache's LRU/eviction lifecycle.
diff --git a/docs/knowledge/resolver/caching/auto-refresh.md b/docs/knowledge/resolver/caching/auto-refresh.md
new file mode 100644
index 0000000..2d86ea7
--- /dev/null
+++ b/docs/knowledge/resolver/caching/auto-refresh.md
@@ -0,0 +1,227 @@
+---
+type: Mechanism
+title: Auto-Refresh Popular Domains Before TTL Expiry
+description: >
+          Proactively refetches popular, near-expiry cache entries in the
+          background so a real client query never sees the reactive miss;
+          popularity tracking, the trigger formula, and the worker pool
+          that executes the refetch.
+resource: src/resolver/cache/shard.rs
+tags: [cache, dns, resolver, refresh, popularity, worker-pool]
+timestamp: 2026-07-16T00:00:00Z
+---
+
+The [answer-cache](answer-cache.md) is purely reactive by default: an entry
+sits until `expires_at` passes, then the next lookup pays a full backend
+round trip. This feature keeps genuinely popular domains "hot" by
+refreshing them from the backend just before they expire, without any
+fixed or configured list of "popular domains" — popularity is entirely
+derived from live, self-decaying state that rides along with the cache's
+existing per-domain lifecycle. Ships enabled by default
+(`RefreshConfig::enabled`, default `true`); design history and rejected
+alternatives: `docs/plans/auto_refresh/`.
+
+# Popularity tracking: per-domain leaky bucket
+
+`PopularityBucket` (`src/resolver/cache/shard.rs:59-129`) is an integer
+leaky-bucket counter — `level: u32` + `last_drained: SystemTime` — stored in
+a new `ShardState.popularity: HashMap<String, PopularityBucket>` field
+(`shard.rs:164,168`), at the same level as `ShardLru`. It's
+drained-then-incremented (`PopularityBucket::drain_and_increment`,
+`shard.rs:99-118`) on every cache hit, at the same 4 call sites
+`state.lru.touch(domain)` already runs inside `Shard::lookup_hop`
+(`shard.rs:621-633,641-648` for the `Answer`/`CnameHop` branches, via the
+shared `ShardState::record_hit_and_check_refresh` helper, `shard.rs:209-232`;
+`NoData`/`NxDomain` branches still call `record_popularity_hit` directly,
+`shard.rs:184-203`, since negative entries never produce a refresh signal —
+see below). Granularity is per-domain (qname only), matching `ShardLru`'s
+own granularity — any query for the domain, any record type, raises its
+popularity.
+
+Drain arithmetic is integer-only (no floats) to avoid long-uptime rounding
+drift, and advances `last_drained` by only the exact time "spent" on
+whole leaked units — never resets to `now` — so draining in many small
+steps can't systematically under-drain relative to one large step covering
+the same elapsed time.
+
+**Lifecycle**: a bucket is created on first hit and removed at exactly the
+same two points a domain's `ShardLru` token is removed —
+`ShardState::evict_domain` (`shard.rs:84`) and
+`ShardState::drop_lru_if_domain_now_empty` (`shard.rs:144`) — so popularity
+state can never outlive a domain's cached data through either of those
+paths. Accepted gap: `sweep_stale_namespace` clears a domain's LRU token
+directly without going through either function, so a bucket can currently
+outlive its domain's data when cleared by a namespace sweep instead — the
+same tradeoff the LRU itself already has under that path, not something
+this feature special-cases.
+
+When `RefreshConfig::enabled` is `false`, the increment call is skipped
+entirely at the call site — no `PopularityBucket` is ever allocated, not
+merely left untouched.
+
+# Trigger formula: three independent gates
+
+`wants_refresh` (`src/resolver/cache/shard.rs:449-467`) is a pure function
+(no I/O, no lock beyond what the caller already holds) checked alongside
+the existing `entry.expires_at <= now` liveness check, deciding whether a
+live entry should *additionally* signal "this wants a refresh" without
+changing what's actually served. All three gates must hold:
+
+1. **Eligibility floor**: `original_ttl >= config.eligibility_floor`
+   (default 15s) — entries below this floor are never refresh-eligible at
+   all, regardless of remaining TTL or popularity, avoiding refresh thrash
+   on very-short-TTL records.
+2. **Lead window**: `remaining_ttl <= max(original_ttl * config.lead_ratio,
+   config.min_lead)` (defaults 10% / 5s).
+3. **Popularity**: the domain's bucket, if present, is hot — `level >=
+   hot_threshold`, where `hot_threshold = round(hot_threshold_fraction *
+   bucket_capacity)` (default 50% of capacity 10, i.e. 5). A missing bucket
+   is never hot.
+
+Callers pass the bucket *after* recording the current hit
+(`ShardState::record_hit_and_check_refresh`, `shard.rs:209-232`), so a
+hit's own increment counts toward its own hot-threshold determination —
+deterministic (both happen under the same lock, back-to-back), not a race.
+**Known feedback-loop caveat**: the auto-refresh worker's own eligibility
+recheck (see below) reuses this exact same code path, and therefore also
+counts as a hit — a refresh cycle can contribute its own "traffic" toward
+staying hot, independent of real client demand. For a domain whose lead
+window recurs faster than its bucket's leak rate, this could theoretically
+sustain refreshing indefinitely after real demand stops. Not fixed
+(the alternative is a side-effect-free recheck path, which would duplicate
+`lookup_chain`'s logic) — flagged for anyone debugging why a domain keeps
+refreshing after traffic apparently stopped.
+
+`RefreshConfig` (`src/config/mod.rs:480-506`) carries all of these
+thresholds plus `worker_count`/`channel_capacity`, following
+`CacheConfig`'s three-piece pattern (real struct + `Default` + `RawRefreshConfig`
+shadow struct + `validate()`, wired into `RuntimeConfig::validate()`).
+`LeakRate` (`config/mod.rs:463-467`) — `units` drained per `per` elapsed
+duration — is defined in `config`, not `cache::shard`, specifically because
+it must be `pub` to appear on `RefreshConfig`'s public field; `cache::shard`
+imports it rather than defining its own copy.
+
+# Signal path: `ChainLookup` and multi-hop hints
+
+`RefreshHint { domain, qtype, qclass }` (`src/resolver/cache/assemble.rs:59-70`)
+is one hop's signal that it currently qualifies. `ChainLookup::Answered`
+carries `refresh_hints: Vec<RefreshHint>` (`assemble.rs:77`) — **every**
+qualifying positive hop in a CNAME chain gets its own hint during
+`resolve_from_cache`'s walk (`assemble.rs:143-...`), not just the terminal
+hop. This is a load-bearing invariant, not an implementation detail: a
+CNAME record is itself a positive RRset with its own independent expiry, so
+an intermediate hop can need a refresh even while the terminal hop stays
+fresh (and vice versa) — an earlier draft that only checked the terminal
+hop was a real bug caught during plan review. A CNAME hop's hint carries
+`qtype = CNAME_RECORD_TYPE`, never the original query's qtype, since the
+CNAME record set at that hop's domain — not whatever type was originally
+queried — is what's actually near expiry.
+
+`ChainLookup::NoData` never carries a hint at all (no field to add one to)
+— v1 scope is positive-entries-only; NODATA/NXDOMAIN are negative entries
+and never trigger refresh.
+
+`ResolveQuery::probe_cache` and the singleflight-follower path
+`cache_hit_after_coalesced_miss` (`src/resolver/mod.rs`) both read
+`refresh_hints` off the `ChainLookup` result and call
+`enqueue_refresh_job` (`resolver/mod.rs:5232-...`) once per hint — a
+non-blocking `try_send` onto the worker pool's channel. `RefreshTriggered`/
+`RefreshQueueFull` metrics (`resolver/mod.rs:8629,8634`) record success/drop;
+a dropped trigger has no correctness impact, the entry just expires
+normally.
+
+# Worker pool: bounded channel, per-job panic isolation
+
+`spawn_refresh_worker_pool` (`src/resolver/mod.rs:3593-3625`) spawns a fixed
+pool of `RefreshConfig.worker_count` tasks sharing one bounded
+`tokio::sync::mpsc::Receiver<RefreshJob>`, wrapped in
+`Arc<tokio::sync::Mutex<_>>` since `Receiver` is single-consumer — this
+serializes only the dequeue point (one worker parks on `recv()` at a time),
+not job *execution*. Each dequeued job (`refresh_worker_loop`,
+`resolver/mod.rs:3627-3653`) is spawned as its own `tokio::spawn`ed task,
+and the worker `.await`s that task's `JoinHandle` before dequeuing the
+next job: a panic in one job fails only its own `JoinHandle` (inspected via
+`JoinError::is_panic()` and logged via `tracing::error!`), never the worker
+loop itself — deliberately not `futures::FutureExt::catch_unwind`, since
+this codebase adds dependencies conservatively and already has no
+`futures` crate dependency.
+
+**Shutdown has no internal signal** — `main.rs` holds the pool's
+`JoinHandle`s and `.abort()`s them at teardown (`main.rs:326-329`),
+mirroring `spawn_sighup_reload_task`'s (`main.rs:605`) existing convention
+exactly: no `select!`, no shutdown channel, the loops just run until
+aborted from outside. Known gap: aborting the outer loop task while a job's
+inner spawned task is in flight only cancels the loop, not the inner
+task — left detached, harmless while job processing has no real I/O
+side effects beyond the cache store itself.
+
+`main.rs` creates the channel *before* building the resolver
+(`main.rs:132`), threads the sender in via `.with_refresh_config(...)` /
+`.with_refresh_sender(...)` on the `ResolveQuery` builder chain, and gates
+both the sender wiring and the pool spawn on `config.refresh.enabled`
+(`main.rs:152-173`): when disabled, no worker tasks are spawned at all —
+not merely idle ones.
+
+# Job processing: epoch-first recheck, DO=true fetch, direct store
+
+`process_refresh_job` (`resolver/mod.rs:3765-...`) does, per dequeued job:
+
+1. **Capture epoch once**: `BackendHandle::current()` is read exactly once
+   at the top and reused for every subsequent step — never re-read
+   mid-job, the same discipline every other store path in this codebase
+   follows (see [cache-epoch](cache-epoch.md)).
+2. **Re-check eligibility** by calling the same `lookup_chain` path a real
+   query uses, with the captured epoch and `dnssec_ok = false` (not
+   `true` — see below), confirming the re-probed hints still contain this
+   exact `(domain, qtype, qclass)`. A stale epoch from a reload that
+   happened while the job sat in the channel surfaces here as an ordinary
+   miss, since `lookup_hop` already treats an epoch mismatch as invisible —
+   no separate epoch check is needed.
+3. **Fetch via `ShardedSingleFlight`** (`MissKey = (domain, qtype, qclass,
+   epoch, dnssec_ok=true)`) using a new `build_refresh_query` production
+   helper (`resolver/mod.rs:3710-...`) to build a synthetic outbound query.
+   Fetches always use `dnssec_ok = true` — a refresh always upgrades to a
+   DNSSEC-complete fetch, regardless of the original entry's own DNSSEC
+   state. **Coalescing caveat**: because `MissKey` includes `dnssec_ok`,
+   this only coalesces with a concurrent client request that itself has
+   `dnssec_ok = true` — a DO=false client miss for the same key becomes its
+   own independent singleflight `Leader`, paying its own round trip. No
+   correctness impact, just narrower coalescing than "any concurrent miss."
+4. **Store directly** via `cache_store_for_response`/`store_cache_response`,
+   deliberately bypassing `prepare_backend_result`'s policy-block,
+   response-rewrite, and chaos-injection layers (none apply to a
+   server-internal refresh) — but *does* check
+   `ResolutionCacheDirective::is_cacheable()` first, same as
+   `prepare_backend_result` does, so a backend-declared "do not cache this"
+   signal is still honored.
+5. **No retry on any failure** (timeout, backend error, an uncacheable or
+   unparseable response) — the stale entry is simply left untouched and
+   falls back to ordinary reactive-miss behavior at its real expiry.
+   Best-effort by design, naturally bounded by the worker pool's fixed
+   size and channel capacity, not a backoff mechanism.
+
+Why the recheck uses `dnssec_ok = false` while the fetch always uses
+`true`: `Shard::take_live_positive`/`take_live_cname_hop` treat any entry
+with `dnssec_complete = false` as invisible to a `dnssec_ok = true` reader.
+Since the recheck's only job is confirming "still live, in-window, hot" —
+independent of DNSSEC completeness — using `true` there would permanently
+exclude every domain whose cached answer originated from a DO=false query,
+silently defeating refresh for that entire class of domain forever.
+
+# Metrics
+
+`ResolverMetric::RefreshTriggered`/`RefreshQueueFull`/`RefreshSucceeded`/
+`RefreshFailed` (`resolver/mod.rs:8629-8639`), following existing
+`CacheHit`/`CacheMiss`-style naming. `OpenTelemetryMetrics` in `main.rs`
+exposes each as its own Prometheus counter (`refresh_triggered_total`,
+etc.) — `ResolverMetric` and `OpenTelemetryMetrics::increment` are both
+exhaustive matches, so new variants force new counter wiring at compile
+time.
+
+# See also
+
+- [answer-cache](answer-cache.md) — the base cache structure this feature extends.
+- [sharding](sharding.md) — popularity is tracked per-shard, per-domain, at the same routing
+  granularity as everything else in the cache.
+- [cache-epoch](cache-epoch.md) — the epoch-recheck-before-fetch step depends directly on this
+  invalidation mechanism.
diff --git a/docs/knowledge/resolver/caching/index.md b/docs/knowledge/resolver/caching/index.md
index 0330849..53959ce 100644
--- a/docs/knowledge/resolver/caching/index.md
+++ b/docs/knowledge/resolver/caching/index.md
@@ -8,3 +8,5 @@
   does/doesn't share that sharding scheme.
 * [local-dns-entries](local-dns-entries.md) - Why manually-loaded DNS data is not in this cache at
   all, and what that means for reload invalidation.
+* [auto-refresh](auto-refresh.md) - Proactive cache refresh for popular domains nearing TTL expiry:
+  popularity tracking, the trigger formula, and the background worker pool.
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 556cad1..f07f7f8 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -17716,6 +17716,222 @@ mod tests {
         );
     }
 
+    // End-to-end verification: section-07-integration. Unlike the isolated
+    // unit/integration tests above, these drive the *real*
+    // `spawn_refresh_worker_pool` wired through a real channel, proving the
+    // whole chain (bucket increment -> trigger -> hint -> enqueue -> worker
+    // -> fetch -> store -> next lookup sees the refreshed entry) actually
+    // cooperates end to end, not just that each piece works in isolation.
+
+    /// Polls (via `yield_now`, never `sleep`) until `upstream` has recorded
+    /// at least `expected` requests, or panics after a generous bound --
+    /// used to deterministically wait for the background worker pool
+    /// (running concurrently in this test's own runtime) to finish
+    /// processing an enqueued job, without any wall-clock sleep.
+    async fn wait_for_upstream_requests(upstream: &StaticUpstream, expected: usize) {
+        for _ in 0..10_000 {
+            if upstream.requests.lock().unwrap().len() >= expected {
+                return;
+            }
+            tokio::task::yield_now().await;
+        }
+        panic!(
+            "timed out waiting for {expected} upstream request(s), saw {}",
+            upstream.requests.lock().unwrap().len()
+        );
+    }
+
+    #[tokio::test]
+    async fn e2e_hot_domain_refreshed_before_expiry() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let domain = "hot.example.com";
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x1234, domain, 60),
+        ))));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let mut service = resolve_service_with_cache(
+            upstream.clone(),
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            metrics.clone(),
+            1232,
+        );
+        service = service.with_refresh_config(permissive_refresh_config());
+        let (sender, receiver) = mpsc::channel(4);
+        service = service.with_refresh_sender(sender);
+        let service = Arc::new(service);
+        let workers = spawn_refresh_worker_pool(Arc::clone(&service), receiver, 1);
+
+        let now = SystemTime::UNIX_EPOCH;
+        // First call: genuine cache miss, populates the cache. No hint yet
+        // -- there's nothing cached to have a popularity bucket at all.
+        let first = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                now,
+                a_query(0x1111, domain),
+            ))
+            .await;
+        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
+        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
+
+        // Second call: now a cache hit. Under the permissive config, this
+        // hit's own popularity increment immediately crosses hot_threshold
+        // (0), and the entry is always "within lead window" -- producing a
+        // refresh hint, which probe_cache enqueues onto the real channel
+        // the real worker pool above is reading from.
+        let second = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.11".parse().unwrap(),
+                now,
+                a_query(0x2222, domain),
+            ))
+            .await;
+        assert_eq!(second.decision.kind, ResolveDecisionKind::CacheHit);
+
+        // The background worker processes the enqueued job concurrently --
+        // wait for its fetch to land, with no client-visible miss at all.
+        wait_for_upstream_requests(&upstream, 2).await;
+        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 1);
+
+        // A third call must still be an ordinary cache hit -- the
+        // background refresh happened without ever costing a client a
+        // miss.
+        let third = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.12".parse().unwrap(),
+                now,
+                a_query(0x3333, domain),
+            ))
+            .await;
+        assert_eq!(third.decision.kind, ResolveDecisionKind::CacheHit);
+
+        for worker in workers {
+            worker.abort();
+            let _ = worker.await;
+        }
+    }
+
+    #[tokio::test]
+    async fn e2e_cooling_domain_stops_being_refreshed() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let domain = "cooling.example.com";
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x4321, domain, 60),
+        ))));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let mut service = resolve_service_with_cache(
+            upstream.clone(),
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            metrics.clone(),
+            1232,
+        );
+        service = service.with_refresh_config(permissive_refresh_config());
+        let (sender, receiver) = mpsc::channel(4);
+        service = service.with_refresh_sender(sender);
+        let service = Arc::new(service);
+        let workers = spawn_refresh_worker_pool(Arc::clone(&service), receiver, 1);
+        let now = SystemTime::UNIX_EPOCH;
+
+        // Warm the domain hot and let one background refresh land, exactly
+        // as in `e2e_hot_domain_refreshed_before_expiry`.
+        let _ = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                now,
+                a_query(0x1111, domain),
+            ))
+            .await;
+        let _ = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.11".parse().unwrap(),
+                now,
+                a_query(0x2222, domain),
+            ))
+            .await;
+        wait_for_upstream_requests(&upstream, 2).await;
+        let requests_after_warm_refresh = upstream.requests.lock().unwrap().len();
+
+        // No further queries at all -- there is no periodic background
+        // scan in this design; refresh is purely reactive to real hits.
+        // Give any (incorrect) spontaneous background activity a generous
+        // window to show up.
+        for _ in 0..1000 {
+            tokio::task::yield_now().await;
+        }
+
+        assert_eq!(
+            upstream.requests.lock().unwrap().len(),
+            requests_after_warm_refresh,
+            "with no further real traffic, nothing should trigger another background refresh"
+        );
+
+        for worker in workers {
+            worker.abort();
+            let _ = worker.await;
+        }
+    }
+
+    #[tokio::test]
+    async fn e2e_disabled_feature_is_true_no_op() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let domain = "disabled.example.com";
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x5678, domain, 60),
+        ))));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let mut service = resolve_service_with_cache(
+            upstream.clone(),
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            metrics.clone(),
+            1232,
+        );
+        // Same thresholds that would trigger refresh in the two tests
+        // above, except disabled -- proving `enabled` is the load-bearing
+        // switch, not incidental.
+        service = service.with_refresh_config(RefreshConfig {
+            enabled: false,
+            ..permissive_refresh_config()
+        });
+        let service = Arc::new(service);
+        let now = SystemTime::UNIX_EPOCH;
+
+        for (id, client_ip) in [
+            (0x1111u16, "192.0.2.10"),
+            (0x2222, "192.0.2.11"),
+            (0x3333, "192.0.2.12"),
+        ] {
+            let _ = service
+                .resolve(ResolveRequest::new(
+                    client_ip.parse().unwrap(),
+                    now,
+                    a_query(id, domain),
+                ))
+                .await;
+        }
+
+        assert_eq!(
+            upstream.requests.lock().unwrap().len(),
+            1,
+            "only the first, genuine cache miss should ever reach the backend"
+        );
+        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 0);
+        assert_eq!(metrics.count(ResolverMetric::RefreshQueueFull), 0);
+        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 0);
+        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 0);
+    }
+
     #[tokio::test]
     async fn resolve_blocks_cached_response_with_malicious_cname_target() {
         let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
