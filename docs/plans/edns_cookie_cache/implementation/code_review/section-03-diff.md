diff --git a/src/protocol/mod.rs b/src/protocol/mod.rs
index f89e8a2..20c0d6d 100644
--- a/src/protocol/mod.rs
+++ b/src/protocol/mod.rs
@@ -21,7 +21,7 @@ use std::time::Duration;
 use bytes::Bytes;
 use serde::Serialize;
 
-mod edns_cookie;
+pub(crate) mod edns_cookie;
 
 pub(crate) const DNS_HEADER_LEN: usize = 12;
 pub const DNS_DEFAULT_UDP_PAYLOAD_SIZE: usize = 512;
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 7447333..56b5a06 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -5514,7 +5514,9 @@ fn cache_supported(query: &DecodedQuery) -> bool {
             edns.extended_rcode == 0
                 && edns.version == 0
                 && (edns.flags & !EDNS_DO_FLAG) == 0
-                && edns.options.is_empty()
+                && (edns.options.is_empty()
+                    || crate::protocol::edns_cookie::is_solely_cookie_option(&edns.options)
+                        .is_some())
         })
         .unwrap_or(true)
 }
@@ -19014,13 +19016,13 @@ mod tests {
         let metrics = Arc::new(RecordingMetrics::default());
         let service =
             resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
-        let edns_cookie = [0u8, 10, 0, 2, 0xaa, 0xbb];
+        let edns_nsid = [0u8, 3, 0, 2, 0xaa, 0xbb]; // option code 3 (NSID), length 2
 
         let _ = service
             .resolve(ResolveRequest::new(
                 "192.0.2.10".parse().unwrap(),
                 SystemTime::UNIX_EPOCH,
-                a_query_with_edns_options(0x7777, "example.com", 1232, false, &edns_cookie),
+                a_query_with_edns_options(0x7777, "example.com", 1232, false, &edns_nsid),
             ))
             .await;
 
@@ -19030,6 +19032,107 @@ mod tests {
         assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
     }
 
+    #[tokio::test]
+    async fn resolve_admits_well_formed_cookie_only_query_to_cache() {
+        let now = SystemTime::UNIX_EPOCH;
+        let record = a_record("example.com", 60);
+        let entry = seed_rrset_entry(&record, Duration::from_secs(60), now, 0);
+        let resolved = cache::ResolvedAnswer {
+            chain: vec![("example.com".to_string(), entry)],
+        };
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service =
+            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
+        let cookie_option = [
+            0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
+        ];
+
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                now,
+                a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option),
+            ))
+            .await;
+
+        assert!(!cache.lookups.lock().unwrap().is_empty());
+        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
+        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
+        assert_eq!(metrics.count(ResolverMetric::CacheBypass), 0);
+    }
+
+    #[tokio::test]
+    async fn resolve_bypasses_cache_for_cookie_combined_with_other_option() {
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x7777, "example.com", 60),
+        ))));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service =
+            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
+        // A well-formed COOKIE option (code 10, len 8) immediately followed
+        // by an NSID option (code 3, len 2) in the same options blob.
+        let mut options = vec![
+            0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
+        ];
+        options.extend_from_slice(&[0u8, 3, 0, 2, 0xaa, 0xbb]);
+
+        let _ = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                SystemTime::UNIX_EPOCH,
+                a_query_with_edns_options(0x7777, "example.com", 1232, false, &options),
+            ))
+            .await;
+
+        assert!(cache.lookups.lock().unwrap().is_empty());
+        assert!(cache.stores.lock().unwrap().is_empty());
+        assert_eq!(metrics.count(ResolverMetric::CacheBypass), 1);
+        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
+    }
+
+    #[tokio::test]
+    async fn resolve_cache_lookup_key_ignores_client_cookie_bytes() {
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x7777, "example.com", 60),
+        ))));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service =
+            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
+
+        let cookie_a = [
+            0u8, 10, 0, 8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
+        ];
+        let cookie_b = [
+            0u8, 10, 0, 8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
+        ];
+
+        let _ = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                SystemTime::UNIX_EPOCH,
+                a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_a),
+            ))
+            .await;
+        let _ = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.11".parse().unwrap(),
+                SystemTime::UNIX_EPOCH,
+                a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_b),
+            ))
+            .await;
+
+        let lookups = cache.lookups.lock().unwrap();
+        assert_eq!(lookups.len(), 2);
+        assert_eq!(lookups[0], lookups[1]); // identical (qname, qtype, qclass) despite different client cookies
+    }
+
     #[tokio::test]
     async fn resolve_bypasses_cache_for_unsupported_edns_flags_and_version() {
         for request in [
