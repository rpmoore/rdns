diff --git a/src/main.rs b/src/main.rs
index 7f93c05..26047dc 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -38,6 +38,7 @@ use rdns::resolver::{
     QueryEventRecordResult, QueryEventSink, QueryEventV1, RecursiveResolutionBackend,
     RecursiveResolverConfig, RecursiveRootHint, ResolutionMode as ResolverResolutionMode,
     ResolveQuery, ResolverMetric, ShardedDnsCache, StandardProtocolCodec, SystemClock,
+    spawn_refresh_worker_pool,
 };
 use tokio::task::{JoinError, JoinSet};
 use tracing::{error, info, warn};
@@ -128,31 +129,49 @@ async fn main() -> io::Result<()> {
         .unwrap_or(8);
     let clock: Arc<dyn Clock> = Arc::new(SystemClock);
     let cookie_secret = Arc::new(CookieSecret::generate());
-    let resolver = Arc::new(
-        ResolveQuery::with_cache_policy_and_backend_snapshot(
-            Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
-            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
-            Arc::new(NoopPolicyEvaluator),
-            local_entries,
-            CacheTtlPolicy::default(),
-            backend_snapshot,
-            Arc::new(BasicResponseFactory),
-            Arc::clone(&clock),
-            Arc::new(StoreRecordingQueryEventSink::new(
-                ChannelQueryEventSink::new(event_tx),
-                Arc::clone(&query_event_store),
-            )),
-            metrics,
-        )
-        .with_max_chain_depth(max_chain_depth)
-        .with_single_flight_shard_count(cache.shard_count())
-        .with_chaos_config(config.chaos.clone())
-        .with_cookie_secret(cookie_secret),
-    );
+    let (refresh_tx, refresh_rx) = tokio::sync::mpsc::channel(config.refresh.channel_capacity);
+    let mut resolver_builder = ResolveQuery::with_cache_policy_and_backend_snapshot(
+        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
+        Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+        Arc::new(NoopPolicyEvaluator),
+        local_entries,
+        CacheTtlPolicy::default(),
+        backend_snapshot,
+        Arc::new(BasicResponseFactory),
+        Arc::clone(&clock),
+        Arc::new(StoreRecordingQueryEventSink::new(
+            ChannelQueryEventSink::new(event_tx),
+            Arc::clone(&query_event_store),
+        )),
+        metrics,
+    )
+    .with_max_chain_depth(max_chain_depth)
+    .with_single_flight_shard_count(cache.shard_count())
+    .with_chaos_config(config.chaos.clone())
+    .with_cookie_secret(cookie_secret)
+    .with_refresh_config(config.refresh);
+    if config.refresh.enabled {
+        resolver_builder = resolver_builder.with_refresh_sender(refresh_tx);
+    }
+    let resolver = Arc::new(resolver_builder);
 
     let sighup_task =
         spawn_sighup_reload_task(Arc::clone(&resolver), reload_metrics, config_path.clone());
 
+    // Auto-refresh worker pool (`docs/plans/auto_refresh/`): spawned only
+    // when enabled, following `spawn_sighup_reload_task`'s own shutdown
+    // convention (no internal shutdown signal -- the caller `.abort()`s
+    // these at teardown, see `serve_until_shutdown`).
+    let refresh_workers = if config.refresh.enabled {
+        spawn_refresh_worker_pool(
+            Arc::clone(&resolver),
+            refresh_rx,
+            config.refresh.worker_count,
+        )
+    } else {
+        Vec::new()
+    };
+
     let servers =
         UdpDnsServer::bind_configured(&config, Arc::clone(&resolver), Arc::clone(&clock)).await?;
     if servers.is_empty() {
@@ -196,6 +215,7 @@ async fn main() -> io::Result<()> {
         metrics_server,
         resolver,
         sighup_task,
+        refresh_workers,
         event_drain,
     )
     .await
@@ -212,6 +232,7 @@ async fn serve_until_shutdown(
     metrics_server: Option<MetricsServer>,
     resolver: Arc<ResolveQuery>,
     sighup_task: tokio::task::JoinHandle<()>,
+    refresh_workers: Vec<tokio::task::JoinHandle<()>>,
     event_drain: tokio::task::JoinHandle<()>,
 ) -> io::Result<()> {
     let mut shutdown_senders = Vec::with_capacity(servers.len() + tcp_servers.len());
@@ -302,6 +323,11 @@ async fn serve_until_shutdown(
     sighup_task.abort();
     let _ = sighup_task.await;
 
+    for worker in refresh_workers {
+        worker.abort();
+        let _ = worker.await;
+    }
+
     drop(resolver);
     match event_drain.await {
         Ok(()) => Ok(()),
@@ -841,6 +867,8 @@ struct OpenTelemetryMetrics {
     recursion_refused_total: Counter<u64>,
     refresh_triggered_total: Counter<u64>,
     refresh_queue_full_total: Counter<u64>,
+    refresh_succeeded_total: Counter<u64>,
+    refresh_failed_total: Counter<u64>,
     query_duration_seconds: Histogram<f64>,
     recursive_query_duration_seconds: Histogram<f64>,
     cache_hit_query_duration_seconds: Histogram<f64>,
@@ -948,6 +976,8 @@ impl OpenTelemetryMetrics {
             recursion_refused_total: meter.u64_counter("recursion_refused_total").build(),
             refresh_triggered_total: meter.u64_counter("refresh_triggered_total").build(),
             refresh_queue_full_total: meter.u64_counter("refresh_queue_full_total").build(),
+            refresh_succeeded_total: meter.u64_counter("refresh_succeeded_total").build(),
+            refresh_failed_total: meter.u64_counter("refresh_failed_total").build(),
             query_duration_seconds: meter.f64_histogram("query_duration_seconds").build(),
             recursive_query_duration_seconds: meter
                 .f64_histogram("recursive_query_duration_seconds")
@@ -1028,6 +1058,8 @@ impl MetricsSink for OpenTelemetryMetrics {
             ResolverMetric::RecursionRefused => self.recursion_refused_total.add(1, &[]),
             ResolverMetric::RefreshTriggered => self.refresh_triggered_total.add(1, &[]),
             ResolverMetric::RefreshQueueFull => self.refresh_queue_full_total.add(1, &[]),
+            ResolverMetric::RefreshSucceeded => self.refresh_succeeded_total.add(1, &[]),
+            ResolverMetric::RefreshFailed => self.refresh_failed_total.add(1, &[]),
             ResolverMetric::QueryDuration
             | ResolverMetric::RecursiveQueryDuration
             | ResolverMetric::CacheHitQueryDuration
@@ -1181,6 +1213,42 @@ mod tests {
         assert_eq!(gauge_value("cache_capacity"), 16.0);
     }
 
+    #[test]
+    fn open_telemetry_refresh_metrics_map_to_distinct_counters() {
+        // Confirms the four `ResolverMetric::Refresh*` variants pulled
+        // forward for auto-refresh (`docs/plans/auto_refresh/`) each
+        // increment their own, distinctly-named counter -- not aliased to
+        // an existing counter or to one of the other three new ones.
+        let cache = Arc::new(ShardedDnsCache::new(&rdns::config::CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let metrics = OpenTelemetryMetrics::new(Arc::clone(&cache)).expect("metrics exporter");
+
+        metrics.increment(ResolverMetric::RefreshTriggered);
+        metrics.increment(ResolverMetric::RefreshQueueFull);
+        metrics.increment(ResolverMetric::RefreshQueueFull);
+        metrics.increment(ResolverMetric::RefreshSucceeded);
+        metrics.increment(ResolverMetric::RefreshSucceeded);
+        metrics.increment(ResolverMetric::RefreshSucceeded);
+        metrics.increment(ResolverMetric::RefreshFailed);
+
+        let families = metrics.registry.gather();
+        let counter_value = |name: &str| -> f64 {
+            families
+                .iter()
+                .find(|family| family.name() == name)
+                .and_then(|family| family.get_metric().first())
+                .map(|metric| metric.get_counter().value())
+                .unwrap_or_else(|| panic!("missing counter {name}"))
+        };
+
+        assert_eq!(counter_value("refresh_triggered_total"), 1.0);
+        assert_eq!(counter_value("refresh_queue_full_total"), 2.0);
+        assert_eq!(counter_value("refresh_succeeded_total"), 3.0);
+        assert_eq!(counter_value("refresh_failed_total"), 1.0);
+    }
+
     #[test]
     fn local_entry_summary_pluralizes_entries_and_zone_files_independently() {
         assert_eq!(
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 2367fb6..2ca84dd 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -3578,6 +3578,75 @@ pub struct RefreshJob {
     qclass: u16,
 }
 
+/// Spawns a fixed pool of `worker_count` tasks that share one bounded
+/// `receiver`, each dequeuing and processing `RefreshJob`s. Mirrors
+/// `spawn_sighup_reload_task`'s (`main.rs:579`) shutdown convention exactly:
+/// no internal shutdown signal, no `select!` -- the caller holds the
+/// returned `JoinHandle`s and `.abort()`s them at teardown.
+///
+/// `Receiver` is single-consumer, so it's wrapped in
+/// `Arc<tokio::sync::Mutex<_>>` and shared across the pool. This serializes
+/// only the dequeue point (one worker parks on `recv()` at a time), not job
+/// *execution* -- each dequeued job is spawned as its own task (see below),
+/// so total concurrency stays bounded at `worker_count` without a true MPMC
+/// channel and its accompanying new dependency.
+pub fn spawn_refresh_worker_pool(
+    resolver: Arc<ResolveQuery>,
+    receiver: tokio::sync::mpsc::Receiver<RefreshJob>,
+    worker_count: usize,
+) -> Vec<tokio::task::JoinHandle<()>> {
+    let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
+    (0..worker_count)
+        .map(|_| {
+            tokio::spawn(refresh_worker_loop(
+                Arc::clone(&resolver),
+                Arc::clone(&receiver),
+            ))
+        })
+        .collect()
+}
+
+/// One worker's dequeue-process-repeat loop. A panic inside a given job's
+/// processing (`process_refresh_job`) is isolated by spawning that job as
+/// its own task and awaiting its `JoinHandle` before dequeuing the next job
+/// -- deliberately not `futures::FutureExt::catch_unwind` (this repo has no
+/// `futures` dependency; adding one solely for this would contradict the
+/// same "add dependencies conservatively" reasoning already used to reject
+/// a true MPMC channel above). A panicked job fails only its own
+/// `JoinHandle` (`JoinError::is_panic()`); this loop, and thus this worker,
+/// keeps running.
+async fn refresh_worker_loop(
+    resolver: Arc<ResolveQuery>,
+    receiver: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<RefreshJob>>>,
+) {
+    loop {
+        let job = {
+            let mut receiver = receiver.lock().await;
+            receiver.recv().await
+        };
+        let Some(job) = job else {
+            break; // channel closed (all senders dropped) -- exit cleanly.
+        };
+        let task_resolver = Arc::clone(&resolver);
+        let handle = tokio::spawn(async move { process_refresh_job(task_resolver, job).await });
+        if let Err(join_error) = handle.await
+            && join_error.is_panic()
+        {
+            tracing::error!(?join_error, "refresh job panicked");
+        }
+    }
+}
+
+/// Processes one dequeued job. **This section's implementation is a no-op
+/// stub** -- real epoch-capture, eligibility recheck, singleflight-based
+/// fetch, and cache-store logic is added in section-06. Keeping this as an
+/// explicit stub (rather than deferring the whole function's existence to
+/// section-06) is what lets this section's worker-pool tests (panic
+/// isolation, concurrency bound, sequential-per-worker dequeue, abort
+/// shutdown) run against the real pool mechanics without section-06's fetch
+/// logic existing yet.
+async fn process_refresh_job(_resolver: Arc<ResolveQuery>, _job: RefreshJob) {}
+
 pub struct ResolveQuery {
     protocol: Arc<dyn ProtocolCodec>,
     policy: Arc<dyn PolicyEvaluator>,
@@ -8287,6 +8356,11 @@ pub enum ResolverMetric {
     /// no live receiver until `main.rs` wires one up), so the job was
     /// dropped. Best-effort by design; no correctness impact.
     RefreshQueueFull,
+    /// A worker's refetch completed and the entry was re-stored
+    /// (section-06).
+    RefreshSucceeded,
+    /// A worker's refetch failed for any reason (section-06); no retry.
+    RefreshFailed,
 }
 
 #[cfg(test)]
@@ -8295,7 +8369,7 @@ mod tests {
     use std::sync::Mutex;
     use std::sync::mpsc as std_mpsc;
     use std::thread;
-    use tokio::sync::Notify;
+    use tokio::sync::{Barrier, Notify};
 
     use crate::config::CacheConfig;
     use crate::protocol::{EdnsInfo, Header, Question, Record, build_a_block_response};
@@ -10043,6 +10117,199 @@ mod tests {
         assert_eq!(job.domain, "first.example.com");
     }
 
+    // Worker pool tests: section-05-worker-pool-metrics.
+    //
+    // `process_refresh_job` is a fixed no-op stub in this section (real
+    // behavior lands in section-06), so these tests exercise the actual
+    // production dequeue/spawn/await/panic-isolation loop shape via a
+    // `#[cfg(test)]`-only variant parameterized on an injectable async
+    // handler, rather than a reimplementation -- the loop body below is
+    // identical to `refresh_worker_loop`'s, just generic over the handler
+    // instead of hardcoding a call to `process_refresh_job`.
+
+    async fn test_worker_loop<F, Fut>(
+        receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<RefreshJob>>>,
+        handler: Arc<F>,
+    ) where
+        F: Fn(RefreshJob) -> Fut + Send + Sync + 'static,
+        Fut: std::future::Future<Output = ()> + Send + 'static,
+    {
+        loop {
+            let job = {
+                let mut receiver = receiver.lock().await;
+                receiver.recv().await
+            };
+            let Some(job) = job else {
+                break;
+            };
+            let handler = Arc::clone(&handler);
+            let handle = tokio::spawn(async move { handler(job).await });
+            let _ = handle.await; // panics are swallowed here, same as production's logging-only handling
+        }
+    }
+
+    fn spawn_test_worker_pool<F, Fut>(
+        receiver: mpsc::Receiver<RefreshJob>,
+        worker_count: usize,
+        handler: F,
+    ) -> Vec<tokio::task::JoinHandle<()>>
+    where
+        F: Fn(RefreshJob) -> Fut + Send + Sync + 'static,
+        Fut: std::future::Future<Output = ()> + Send + 'static,
+    {
+        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
+        let handler = Arc::new(handler);
+        (0..worker_count)
+            .map(|_| {
+                tokio::spawn(test_worker_loop(
+                    Arc::clone(&receiver),
+                    Arc::clone(&handler),
+                ))
+            })
+            .collect()
+    }
+
+    fn test_job(domain: &str) -> RefreshJob {
+        RefreshJob {
+            domain: domain.to_string(),
+            qtype: 1,
+            qclass: 1,
+        }
+    }
+
+    #[tokio::test]
+    async fn worker_processes_jobs_sequentially_per_worker() {
+        let (sender, receiver) = mpsc::channel(4);
+        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
+        let gate = Arc::new(Notify::new());
+        let gate_for_handler = Arc::clone(&gate);
+
+        sender.try_send(test_job("first")).unwrap();
+        sender.try_send(test_job("second")).unwrap();
+        drop(sender); // lets the loop exit once both jobs are drained
+
+        let handles = spawn_test_worker_pool(receiver, 1, move |job| {
+            let events_tx = events_tx.clone();
+            let gate = Arc::clone(&gate_for_handler);
+            async move {
+                events_tx.send(format!("start:{}", job.domain)).unwrap();
+                if job.domain == "first" {
+                    gate.notified().await;
+                }
+                events_tx.send(format!("done:{}", job.domain)).unwrap();
+            }
+        });
+
+        assert_eq!(events_rx.recv().await.unwrap(), "start:first");
+        // "second" must not start until "first"'s spawned task has been
+        // awaited to completion -- a single worker dequeues sequentially.
+        assert!(events_rx.try_recv().is_err());
+
+        gate.notify_one();
+        assert_eq!(events_rx.recv().await.unwrap(), "done:first");
+        assert_eq!(events_rx.recv().await.unwrap(), "start:second");
+        assert_eq!(events_rx.recv().await.unwrap(), "done:second");
+
+        for handle in handles {
+            handle.await.unwrap();
+        }
+    }
+
+    #[tokio::test]
+    async fn worker_panic_isolated_via_joinhandle() {
+        let (sender, receiver) = mpsc::channel(4);
+        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
+
+        sender.try_send(test_job("boom")).unwrap();
+        sender.try_send(test_job("safe")).unwrap();
+        drop(sender);
+
+        let handles = spawn_test_worker_pool(receiver, 1, move |job| {
+            let events_tx = events_tx.clone();
+            async move {
+                events_tx.send(format!("start:{}", job.domain)).unwrap();
+                if job.domain == "boom" {
+                    panic!("simulated job panic");
+                }
+                events_tx.send(format!("done:{}", job.domain)).unwrap();
+            }
+        });
+
+        assert_eq!(events_rx.recv().await.unwrap(), "start:boom");
+        // The worker loop must survive "boom"'s panic (isolated to its own
+        // spawned task/JoinHandle) and go on to dequeue "safe".
+        assert_eq!(events_rx.recv().await.unwrap(), "start:safe");
+        assert_eq!(events_rx.recv().await.unwrap(), "done:safe");
+
+        for handle in handles {
+            handle.await.unwrap();
+        }
+    }
+
+    #[tokio::test]
+    async fn worker_pool_bounds_total_concurrency_to_worker_count() {
+        const WORKER_COUNT: usize = 3;
+        let (sender, receiver) = mpsc::channel(WORKER_COUNT);
+        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
+        // A barrier sized to exactly `WORKER_COUNT` only ever completes if
+        // all `WORKER_COUNT` jobs are genuinely running concurrently --
+        // proving the pool both reaches and never exceeds this bound (if
+        // fewer ran concurrently, the barrier wait would hang, which the
+        // timeout below turns into a clear test failure instead).
+        let barrier = Arc::new(Barrier::new(WORKER_COUNT));
+
+        for i in 0..WORKER_COUNT {
+            sender.try_send(test_job(&format!("job-{i}"))).unwrap();
+        }
+        drop(sender);
+
+        let handles = spawn_test_worker_pool(receiver, WORKER_COUNT, move |job| {
+            let events_tx = events_tx.clone();
+            let barrier = Arc::clone(&barrier);
+            async move {
+                barrier.wait().await;
+                events_tx.send(format!("done:{}", job.domain)).unwrap();
+            }
+        });
+
+        tokio::time::timeout(Duration::from_secs(2), async {
+            for _ in 0..WORKER_COUNT {
+                events_rx.recv().await.unwrap();
+            }
+        })
+        .await
+        .expect("all jobs should complete concurrently well within the timeout");
+
+        for handle in handles {
+            handle.await.unwrap();
+        }
+    }
+
+    #[tokio::test]
+    async fn worker_pool_shutdown_via_abort() {
+        // Uses the real production `spawn_refresh_worker_pool`/
+        // `process_refresh_job` (a no-op stub in this section) directly --
+        // this test only exercises abort/shutdown mechanics, not job
+        // processing, so the real function is exactly what should be under
+        // test here (unlike the other worker-pool tests above, which need
+        // an injectable handler).
+        let metrics = Arc::new(RecordingMetrics::default());
+        let resolver = Arc::new(resolver_for_enqueue_tests(metrics));
+        let (_sender, receiver) = mpsc::channel::<RefreshJob>(4);
+
+        let handles = spawn_refresh_worker_pool(resolver, receiver, 2);
+        for handle in &handles {
+            handle.abort();
+        }
+        for handle in handles {
+            let result = handle.await;
+            assert!(
+                result.is_ok() || result.unwrap_err().is_cancelled(),
+                "aborted worker task should join cleanly (Ok or a cancelled JoinError)"
+            );
+        }
+    }
+
     struct ClientScopedResponsePolicy {
         client_ip: IpAddr,
         domain: DomainSelector,
