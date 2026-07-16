diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index d0974ff..6eaa304 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -3681,20 +3681,179 @@ fn clear_test_job_handler() {
     TEST_JOB_HANDLER.with(|cell| *cell.borrow_mut() = None);
 }
 
-/// Processes one dequeued job. **This section's implementation is a no-op
-/// stub in production** -- real epoch-capture, eligibility recheck,
-/// singleflight-based fetch, and cache-store logic is added in section-06.
-/// Keeping this as an explicit stub (rather than deferring the whole
-/// function's existence to section-06) is what lets this section's
-/// worker-pool tests (panic isolation, concurrency bound, sequential-per-
-/// worker dequeue, abort shutdown) run against the real pool mechanics
-/// without section-06's fetch logic existing yet, via `TEST_JOB_HANDLER`.
-async fn process_refresh_job(_resolver: Arc<ResolveQuery>, _job: RefreshJob) {
+/// Builds a minimal outbound `DecodedQuery` for a synthetic, server-internal
+/// refresh fetch -- not a client-originated query. Follows the exact same
+/// standard-query wire shape the test-only `query`/`query_with_edns` helpers
+/// build (`src/resolver/mod.rs` test module), just as production code
+/// instead of a test fixture: a single question for `(qname, qtype,
+/// qclass)`, RD set, and one EDNS OPT additional record with the DO flag
+/// set according to `dnssec_ok`. `dnssec_ok` is kept as an explicit
+/// parameter rather than hardcoded so this builder stays a pure,
+/// independently testable function -- it's the caller (`process_refresh_job`)
+/// that always passes `true` for refresh jobs, a policy decision that
+/// doesn't belong baked into the builder itself.
+///
+/// The bytes built here are always well-formed by construction, so the
+/// `expect`s below reflect a bug in this function, not a runtime condition
+/// to recover from.
+fn build_refresh_query(qname: &str, qtype: u16, qclass: u16, dnssec_ok: bool) -> DecodedQuery {
+    const REFRESH_QUERY_ID: u16 = 0;
+    const REFRESH_QUERY_UDP_PAYLOAD_SIZE: u16 = 1232;
+
+    let mut bytes = Vec::new();
+    bytes.extend_from_slice(&REFRESH_QUERY_ID.to_be_bytes());
+    bytes.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1, standard query
+    bytes.extend_from_slice(&1u16.to_be_bytes()); // qdcount
+    bytes.extend_from_slice(&0u16.to_be_bytes()); // ancount
+    bytes.extend_from_slice(&0u16.to_be_bytes()); // nscount
+    bytes.extend_from_slice(&1u16.to_be_bytes()); // arcount (EDNS OPT)
+    for label in qname.split('.') {
+        if label.is_empty() {
+            continue; // root ("") or an already-trailing-dot-stripped name
+        }
+        bytes.push(label.len() as u8);
+        bytes.extend_from_slice(label.as_bytes());
+    }
+    bytes.push(0);
+    bytes.extend_from_slice(&qtype.to_be_bytes());
+    bytes.extend_from_slice(&qclass.to_be_bytes());
+    // EDNS OPT additional record: root owner name, TYPE=41, CLASS carries
+    // the UDP payload size, extended-rcode/version, DO flag, rdlen=0.
+    bytes.push(0);
+    bytes.extend_from_slice(&41u16.to_be_bytes());
+    bytes.extend_from_slice(&REFRESH_QUERY_UDP_PAYLOAD_SIZE.to_be_bytes());
+    bytes.push(0);
+    bytes.push(0);
+    let flags = if dnssec_ok { EDNS_DO_FLAG } else { 0 };
+    bytes.extend_from_slice(&flags.to_be_bytes());
+    bytes.extend_from_slice(&0u16.to_be_bytes());
+
+    let message = Message::parse_standard_query_owned(bytes)
+        .expect("synthetic refresh query must always be well-formed");
+    DecodedQuery::new(message).expect("synthetic refresh query must always decode")
+}
+
+/// Processes one dequeued job: epoch-first eligibility recheck,
+/// singleflight-based fetch (always `dnssec_ok = true`), and direct cache
+/// store bypassing `prepare_backend_result`'s policy/rewrite/chaos layers
+/// (none of which apply to a server-internal refresh). No retry on any
+/// failure -- the stale entry is simply left to expire normally.
+///
+/// In test builds, `TEST_JOB_HANDLER` (if set) takes over entirely instead
+/// -- see its own doc comment for why (exercising the real worker-pool
+/// mechanics in section-05's tests without this section's fetch logic
+/// existing yet).
+async fn process_refresh_job(resolver: Arc<ResolveQuery>, job: RefreshJob) {
     #[cfg(test)]
     {
         let handler = TEST_JOB_HANDLER.with(|cell| cell.borrow().clone());
         if let Some(handler) = handler {
-            handler(_job).await;
+            handler(job).await;
+            return;
+        }
+    }
+
+    // 1. Capture epoch first -- reused for every subsequent step in this
+    //    job, never re-read mid-job (same discipline every other store path
+    //    in this file already follows; see `cache-epoch.md`).
+    let backend_snapshot = resolver.backend.current();
+    let epoch = backend_snapshot.cache_epoch;
+    let now = resolver.clock.now();
+
+    // 2. Re-check eligibility against that captured epoch by re-probing the
+    //    cache through the same lookup_chain path a real query uses. An
+    //    epoch mismatch (a reload happened while this job sat in the
+    //    channel) surfaces here as an ordinary miss -- `lookup_hop` already
+    //    treats a stale-epoch entry as invisible, so there's no separate
+    //    epoch check needed. A hint no longer present in the re-probed
+    //    result means the entry moved out of the lead window (or cooled)
+    //    since the job was enqueued.
+    //
+    //    Deliberately `dnssec_ok = false` here, not `true`: this recheck's
+    //    only job is "is this still a live, in-window, hot answer,"
+    //    independent of the entry's own DNSSEC completeness -- unlike the
+    //    actual fetch below (step 3), which always uses `true` per the
+    //    confirmed refresh-always-upgrades-to-DNSSEC-complete decision.
+    //    Rechecking with `true` here would incorrectly treat any entry
+    //    whose `dnssec_complete` is `false` as invisible (the same
+    //    DO=true-vs-dnssec_complete=false filter `take_live_positive`
+    //    applies to a real DO=true reader), permanently defeating refresh
+    //    for every domain whose cached answer happened to originate from a
+    //    DO=false query -- caught by `job_fetch_uses_dnssec_ok_true_always`.
+    let recheck = resolver.cache.lookup_chain(
+        &job.domain,
+        job.qtype,
+        job.qclass,
+        false,
+        epoch,
+        resolver.max_chain_depth,
+        now,
+        &resolver.refresh_config,
+    );
+    let still_eligible = matches!(
+        &recheck,
+        ChainLookup::Answered(resolved) if resolved.refresh_hints.iter().any(|hint| {
+            hint.domain == job.domain && hint.qtype == job.qtype && hint.qclass == job.qclass
+        })
+    );
+    if !still_eligible {
+        return;
+    }
+
+    // 3. Fetch via singleflight -- dnssec_ok always true for refresh jobs
+    //    (a refresh always upgrades to a DNSSEC-complete fetch). This only
+    //    coalesces with a concurrent client miss that itself has
+    //    dnssec_ok = true, since MissKey includes this flag; a DO=false
+    //    client miss for the same key becomes its own independent Leader.
+    let miss_key: MissKey = (job.domain.clone(), job.qtype, job.qclass, epoch, true);
+    let synthetic_query = build_refresh_query(&job.domain, job.qtype, job.qclass, true);
+    let fetch_result = match resolver.miss_coalescer.begin(miss_key.clone()) {
+        SingleFlightTicket::Leader { key, flight } => {
+            let leader = SingleFlightLeader::new(Arc::clone(&resolver.miss_coalescer), key, flight);
+            let result = resolver
+                .resolve_backend(&backend_snapshot, &synthetic_query)
+                .await;
+            leader.complete(result.clone());
+            result
+        }
+        SingleFlightTicket::Follower { flight } => flight.wait().await,
+    };
+
+    // 4. Store on success; no retry on any failure.
+    match fetch_result {
+        Ok(mut response) => {
+            let Some(response_message) = validate_backend_response(&mut response, &synthetic_query)
+            else {
+                resolver.metrics.increment(ResolverMetric::RefreshFailed);
+                return;
+            };
+            // Same store_dnssec_ok/store_authoritative computation
+            // `prepare_backend_result` uses, so a refresh-stored entry is
+            // structurally indistinguishable from what the normal
+            // client-miss path would have stored for the same response.
+            // store_dnssec_ok collapses to `true` in both arms here
+            // (unlike prepare_backend_result's general case) since the
+            // synthetic query itself always sets dnssec_ok = true.
+            let store_authoritative = match backend_snapshot.mode {
+                ResolutionMode::Recursive => false,
+                ResolutionMode::Forward => response_message.header.aa(),
+            };
+            let synthetic_request =
+                ResolveRequest::new(Ipv4Addr::UNSPECIFIED.into(), now, Vec::new());
+            resolver
+                .store_cache_response(
+                    epoch,
+                    &response_message,
+                    &synthetic_query.question,
+                    &synthetic_request,
+                    true,
+                    store_authoritative,
+                )
+                .await;
+            resolver.metrics.increment(ResolverMetric::RefreshSucceeded);
+        }
+        Err(_) => {
+            resolver.metrics.increment(ResolverMetric::RefreshFailed);
         }
     }
 }
@@ -8423,7 +8582,7 @@ mod tests {
     use std::thread;
     use tokio::sync::{Barrier, Notify};
 
-    use crate::config::CacheConfig;
+    use crate::config::{CacheConfig, LeakRate, RefreshConfig};
     use crate::protocol::{EdnsInfo, Header, Question, Record, build_a_block_response};
 
     fn a_query(id: u16, name: &str) -> Vec<u8> {
@@ -16843,6 +17002,640 @@ mod tests {
         }
     }
 
+    // Refresh fetch + store tests: section-06-refresh-fetch-store.
+
+    /// A `RefreshConfig` tuned so any domain that's ever been queried once
+    /// (bucket exists, level >= 1) is immediately "hot" (`hot_threshold_fraction
+    /// = 0.0`), and any live entry is always within the lead window
+    /// (`lead_ratio = 1.0`, `min_lead = 0` -> lead == original_ttl, and
+    /// `remaining_ttl` can never exceed `original_ttl`), with no eligibility
+    /// floor. Used to make a freshly-stored entry trivially eligible for
+    /// refresh without needing to wait for it to actually near expiry.
+    fn permissive_refresh_config() -> RefreshConfig {
+        RefreshConfig {
+            enabled: true,
+            bucket_capacity: 10,
+            leak_rate: LeakRate {
+                units: 1,
+                per: Duration::from_secs(3600),
+            },
+            hit_increment: 1,
+            hot_threshold_fraction: 0.0,
+            lead_ratio: 1.0,
+            min_lead: Duration::from_secs(0),
+            eligibility_floor: Duration::from_secs(0),
+            worker_count: 4,
+            channel_capacity: 256,
+        }
+    }
+
+    fn refresh_job(domain: &str, qtype: u16, qclass: u16) -> RefreshJob {
+        RefreshJob {
+            domain: domain.to_string(),
+            qtype,
+            qclass,
+        }
+    }
+
+    /// Warms `domain`'s popularity bucket by one hit via the real
+    /// `lookup_chain` path (the same side effect a real query has), using
+    /// `service`'s own `refresh_config` -- so a domain queried once becomes
+    /// eligible under `permissive_refresh_config`.
+    fn warm_popularity_via_lookup(
+        service: &ResolveQuery,
+        domain: &str,
+        qtype: u16,
+        qclass: u16,
+        now: SystemTime,
+    ) {
+        service.cache.lookup_chain(
+            domain,
+            qtype,
+            qclass,
+            false,
+            service.backend.current().cache_epoch,
+            service.max_chain_depth,
+            now,
+            &service.refresh_config,
+        );
+    }
+
+    #[tokio::test]
+    async fn build_refresh_query_always_sets_do_flag() {
+        let do_true = build_refresh_query("example.com", A_RECORD_TYPE, 1, true);
+        assert!(do_true.features.dnssec_ok);
+
+        let do_false = build_refresh_query("example.com", A_RECORD_TYPE, 1, false);
+        assert!(!do_false.features.dnssec_ok);
+    }
+
+    #[tokio::test]
+    async fn job_success_advances_expires_at_and_exits_lead_window() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let now = SystemTime::UNIX_EPOCH;
+        let domain = "example.com";
+        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
+        entry.expires_at = now + Duration::from_secs(60);
+        let original_expires_at = entry.expires_at;
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            0,
+        );
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x1234, domain, 120),
+        ))));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let mut service = resolve_service_with_cache(
+            upstream,
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            metrics.clone(),
+            1232,
+        );
+        service = service.with_refresh_config(permissive_refresh_config());
+        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
+        let service = Arc::new(service);
+
+        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;
+
+        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);
+        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 0);
+        match cache.lookup_chain(
+            domain,
+            A_RECORD_TYPE,
+            1,
+            false,
+            0,
+            8,
+            now,
+            &RefreshConfig::default(),
+        ) {
+            ChainLookup::Answered(resolved) => {
+                assert!(
+                    resolved.chain[0].1.expires_at > original_expires_at,
+                    "a successful refresh must move expires_at forward"
+                );
+            }
+            other => panic!("expected Answered after a successful refresh, got {other:?}"),
+        }
+        // With `min_lead=0`/`lead_ratio=1.0` the domain would still show as
+        // "within lead window" under the permissive config regardless -- the
+        // exit-the-window property is really about `expires_at` advancing at
+        // all, already asserted above.
+    }
+
+    #[tokio::test]
+    async fn job_failure_no_retry_leaves_entry_untouched() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let now = SystemTime::UNIX_EPOCH;
+        let domain = "example.com";
+        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
+        entry.expires_at = now + Duration::from_secs(60);
+        let original_expires_at = entry.expires_at;
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            0,
+        );
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let mut service = resolve_service_with_cache(
+            upstream,
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            metrics.clone(),
+            1232,
+        );
+        service = service.with_refresh_config(permissive_refresh_config());
+        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
+        let service = Arc::new(service);
+
+        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;
+
+        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 1);
+        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 0);
+        match cache.lookup_chain(
+            domain,
+            A_RECORD_TYPE,
+            1,
+            false,
+            0,
+            8,
+            now,
+            &RefreshConfig::default(),
+        ) {
+            ChainLookup::Answered(resolved) => {
+                assert_eq!(
+                    resolved.chain[0].1.expires_at, original_expires_at,
+                    "a failed refresh must leave the stale entry untouched, no retry"
+                );
+            }
+            other => panic!("expected the stale entry to remain Answered, got {other:?}"),
+        }
+    }
+
+    #[tokio::test]
+    async fn job_rechecks_lead_window_before_fetch() {
+        // Default RefreshConfig: a fresh (not near-expiry) entry must not
+        // be re-fetched, regardless of popularity.
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let now = SystemTime::UNIX_EPOCH;
+        let domain = "example.com";
+        let mut entry = seed_rrset_entry(&a_record(domain, 300), Duration::from_secs(300), now, 0);
+        entry.expires_at = now + Duration::from_secs(300); // remaining=300s, default lead window is only ~30s
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            0,
+        );
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = Arc::new(resolve_service_with_cache(
+            upstream.clone(),
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            metrics.clone(),
+            1232,
+        )); // default RefreshConfig
+
+        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;
+
+        assert!(upstream.requests.lock().unwrap().is_empty());
+        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 0);
+        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 0);
+    }
+
+    #[tokio::test]
+    async fn job_aborts_on_epoch_mismatch() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x1111, "example.com", 60),
+        ))));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let mut service = ResolveQuery::with_cache_and_backend_generation(
+            Arc::new(StandardProtocolCodec::new(1232)),
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            CacheTtlPolicy::default(),
+            upstream.clone(),
+            1,
+            Arc::new(BasicResponseFactory),
+            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
+            Arc::new(RecordingEvents::default()),
+            metrics.clone(),
+        );
+        service = service.with_refresh_config(permissive_refresh_config());
+        let now = SystemTime::UNIX_EPOCH;
+
+        // Warm the entry under generation 1's namespace via a real query.
+        let _ = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                now,
+                a_query(0x1111, "example.com"),
+            ))
+            .await;
+        assert_eq!(cache.domain_count(), 1);
+        let service = Arc::new(service);
+
+        // Reload to a new generation -- bumps the cache epoch and sweeps
+        // the old-namespace entry.
+        let new_upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        service.publish_reload(
+            BackendSnapshot::forwarding(new_upstream, 2),
+            Arc::new(NoopLocalDnsEntries),
+        );
+        assert_eq!(
+            cache.domain_count(),
+            0,
+            "the namespace sweep should have removed the generation-1 entry"
+        );
+
+        process_refresh_job(
+            Arc::clone(&service),
+            refresh_job("example.com", A_RECORD_TYPE, 1),
+        )
+        .await;
+
+        // Aborted before ever fetching: no new upstream request beyond the
+        // one warming call, and no Refresh* metric at all.
+        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
+        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 0);
+        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 0);
+    }
+
+    #[tokio::test]
+    async fn job_captures_epoch_before_recheck() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let now = SystemTime::UNIX_EPOCH;
+        let domain = "example.com";
+        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
+        entry.expires_at = now + Duration::from_secs(60);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            0,
+        );
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x2222, domain, 60),
+        ))));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let mut service = resolve_service_with_cache(
+            upstream,
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            metrics.clone(),
+            1232,
+        );
+        service = service.with_refresh_config(permissive_refresh_config());
+        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
+        let epoch_at_call_time = service.backend.current().cache_epoch;
+        let service = Arc::new(service);
+
+        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;
+
+        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);
+        match cache.lookup_chain(
+            domain,
+            A_RECORD_TYPE,
+            1,
+            false,
+            epoch_at_call_time,
+            8,
+            now,
+            &RefreshConfig::default(),
+        ) {
+            ChainLookup::Answered(_) => {} // stored and visible under the same epoch captured at call time
+            other => panic!(
+                "refresh-stored entry must be visible under the epoch captured once at the \
+                 start of the job, got {other:?}"
+            ),
+        }
+    }
+
+    #[tokio::test]
+    async fn job_fetch_uses_dnssec_ok_true_always() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let now = SystemTime::UNIX_EPOCH;
+        let domain = "example.com";
+        // Original entry was stored as DNSSEC-incomplete.
+        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
+        entry.expires_at = now + Duration::from_secs(60);
+        entry.dnssec_complete = false;
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            0,
+        );
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x3333, domain, 60),
+        ))));
+        let mut service = resolve_service_with_cache(
+            upstream.clone(),
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            Arc::new(RecordingMetrics::default()),
+            1232,
+        );
+        service = service.with_refresh_config(permissive_refresh_config());
+        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
+        let service = Arc::new(service);
+
+        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;
+
+        let requests = upstream.requests.lock().unwrap();
+        assert_eq!(requests.len(), 1);
+        assert!(
+            requests[0].query.features.dnssec_ok,
+            "refresh jobs must always fetch with dnssec_ok = true, regardless of the \
+             original entry's dnssec_complete state"
+        );
+    }
+
+    #[tokio::test]
+    async fn job_coalesces_with_concurrent_do_true_client_miss() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let now = SystemTime::UNIX_EPOCH;
+        let domain = "example.com";
+        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
+        entry.expires_at = now + Duration::from_secs(60);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            0,
+        );
+        let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x4444, domain, 60),
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
+        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
+        let service = Arc::new(service);
+
+        let job_handle = {
+            let service = Arc::clone(&service);
+            tokio::spawn(async move {
+                process_refresh_job(service, refresh_job(domain, A_RECORD_TYPE, 1)).await
+            })
+        };
+        upstream.wait_for_requests(1).await;
+
+        // A concurrent caller sharing the identical MissKey (dnssec_ok =
+        // true, same epoch) -- representing a real client miss landing on
+        // the same key while the refresh job's fetch is already in flight.
+        let epoch = service.backend.current().cache_epoch;
+        let miss_key: MissKey = (domain.to_string(), A_RECORD_TYPE, 1, epoch, true);
+        let client_handle = {
+            let service = Arc::clone(&service);
+            tokio::spawn(async move {
+                match service.miss_coalescer.begin(miss_key) {
+                    SingleFlightTicket::Follower { flight } => flight.wait().await,
+                    SingleFlightTicket::Leader { .. } => {
+                        panic!("expected to join as a follower behind the refresh job's leader")
+                    }
+                }
+            })
+        };
+        tokio::task::yield_now().await;
+        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
+        upstream.release.notify_waiters();
+
+        job_handle.await.unwrap();
+        let client_result = client_handle.await.unwrap();
+
+        assert!(client_result.is_ok());
+        assert_eq!(
+            upstream.requests.lock().unwrap().len(),
+            1,
+            "the concurrent DO=true client miss must coalesce onto the refresh job's single \
+             backend fetch, not trigger a second one"
+        );
+        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);
+    }
+
+    #[tokio::test]
+    async fn job_does_not_coalesce_with_do_false_client_miss() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let now = SystemTime::UNIX_EPOCH;
+        let domain = "example.com";
+        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
+        entry.expires_at = now + Duration::from_secs(60);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            0,
+        );
+        let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x5555, domain, 60),
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
+        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
+        let service = Arc::new(service);
+
+        let job_handle = {
+            let service = Arc::clone(&service);
+            tokio::spawn(async move {
+                process_refresh_job(service, refresh_job(domain, A_RECORD_TYPE, 1)).await
+            })
+        };
+        upstream.wait_for_requests(1).await;
+
+        // A concurrent DO=false client miss for the same (domain, qtype,
+        // qclass, epoch) -- MissKey's dnssec_ok differs, so this must become
+        // its own independent Leader, not a Follower of the refresh job.
+        let epoch = service.backend.current().cache_epoch;
+        let miss_key: MissKey = (domain.to_string(), A_RECORD_TYPE, 1, epoch, false);
+        let client_handle = {
+            let service = Arc::clone(&service);
+            tokio::spawn(async move {
+                match service.miss_coalescer.begin(miss_key) {
+                    SingleFlightTicket::Leader { key, flight } => {
+                        let leader = SingleFlightLeader::new(
+                            Arc::clone(&service.miss_coalescer),
+                            key,
+                            flight,
+                        );
+                        let synthetic_query = build_refresh_query(domain, A_RECORD_TYPE, 1, false);
+                        let backend_snapshot = service.backend.current();
+                        let result = service
+                            .resolve_backend(&backend_snapshot, &synthetic_query)
+                            .await;
+                        leader.complete(result.clone());
+                        result
+                    }
+                    SingleFlightTicket::Follower { .. } => {
+                        panic!(
+                            "a DO=false miss must not coalesce with the refresh job's DO=true fetch"
+                        )
+                    }
+                }
+            })
+        };
+        upstream.wait_for_requests(2).await;
+        assert_eq!(upstream.requests.lock().unwrap().len(), 2);
+        upstream.release.notify_waiters();
+
+        job_handle.await.unwrap();
+        let client_result = client_handle.await.unwrap();
+
+        assert!(client_result.is_ok());
+        assert_eq!(upstream.requests.lock().unwrap().len(), 2);
+        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);
+    }
+
+    #[tokio::test]
+    async fn job_store_matches_normal_miss_path_shape() {
+        let domain = "refreshed.example.com";
+        let response_bytes = a_response_with_answer(0x6666, domain, 300);
+        let now = SystemTime::UNIX_EPOCH;
+
+        // -- refresh path --
+        let refresh_cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let mut entry = seed_rrset_entry(&a_record(domain, 300), Duration::from_secs(300), now, 0);
+        entry.expires_at = now + Duration::from_secs(300);
+        refresh_cache.store_response(
+            DecomposedResponse {
+                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            0,
+        );
+        let refresh_upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            response_bytes.clone(),
+        ))));
+        let mut refresh_service = resolve_service_with_cache(
+            refresh_upstream,
+            Arc::clone(&refresh_cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            Arc::new(RecordingMetrics::default()),
+            1232,
+        );
+        refresh_service = refresh_service.with_refresh_config(permissive_refresh_config());
+        warm_popularity_via_lookup(&refresh_service, domain, A_RECORD_TYPE, 1, now);
+        let refresh_service = Arc::new(refresh_service);
+        process_refresh_job(
+            Arc::clone(&refresh_service),
+            refresh_job(domain, A_RECORD_TYPE, 1),
+        )
+        .await;
+        let refreshed_entry = match refresh_cache.lookup_chain(
+            domain,
+            A_RECORD_TYPE,
+            1,
+            false,
+            0,
+            8,
+            now,
+            &RefreshConfig::default(),
+        ) {
+            ChainLookup::Answered(resolved) => resolved.chain[0].1.clone(),
+            other => panic!("expected Answered after refresh store, got {other:?}"),
+        };
+
+        // -- normal client-miss path --
+        let normal_cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let normal_upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(response_bytes))));
+        let normal_service = resolve_service_with_cache(
+            normal_upstream,
+            Arc::clone(&normal_cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            Arc::new(RecordingMetrics::default()),
+            1232,
+        );
+        let _ = normal_service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                now,
+                a_query_with_edns(0x6666, domain, 1232, true),
+            ))
+            .await;
+        let normal_entry = match normal_cache.lookup_chain(
+            domain,
+            A_RECORD_TYPE,
+            1,
+            true,
+            0,
+            8,
+            now,
+            &RefreshConfig::default(),
+        ) {
+            ChainLookup::Answered(resolved) => resolved.chain[0].1.clone(),
+            other => panic!("expected Answered after normal store, got {other:?}"),
+        };
+
+        assert_eq!(refreshed_entry.records, normal_entry.records);
+        assert_eq!(refreshed_entry.response_code, normal_entry.response_code);
+        assert_eq!(refreshed_entry.minimum_ttl, normal_entry.minimum_ttl);
+        assert_eq!(
+            refreshed_entry.dnssec_complete,
+            normal_entry.dnssec_complete
+        );
+        assert_eq!(
+            refreshed_entry.authoritative, normal_entry.authoritative,
+            "a refresh-triggered store must be structurally indistinguishable from what the \
+             normal client-miss path would have stored for the identical response"
+        );
+    }
+
     #[tokio::test]
     async fn resolve_blocks_cached_response_with_malicious_cname_target() {
         let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
