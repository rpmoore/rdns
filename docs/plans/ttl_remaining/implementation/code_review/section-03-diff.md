diff --git a/src/resolver/cache/assemble.rs b/src/resolver/cache/assemble.rs
index 6989232..da91471 100644
--- a/src/resolver/cache/assemble.rs
+++ b/src/resolver/cache/assemble.rs
@@ -792,6 +792,35 @@ mod tests {
         assert_eq!(parsed.answers[0].ttl, 10);
     }
 
+    #[test]
+    fn compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime() {
+        // Origin TTL is 0 - a record that "should" expire almost
+        // immediately by its own TTL.
+        let now = SystemTime::now();
+        let stored_at = now - Duration::from_secs(5);
+        let mut entry = rrset_entry(
+            vec![a_record(0, 1)], // ttl_at_store = 0
+            Duration::from_secs(30),
+            stored_at,
+        );
+        // Simulate a min_positive_ttl floor extending this entry's actual
+        // cache lifetime to 30s, far past what the origin TTL of 0 implies.
+        entry.expires_at = stored_at + Duration::from_secs(30);
+        let resolved = ResolvedAnswer {
+            chain: vec![("example.com".to_string(), entry)],
+        };
+        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
+
+        let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
+        let parsed = Message::parse(&response).unwrap();
+
+        // Even though the entry is still servable for ~25 more seconds
+        // (floored expires_at), the wire TTL must reflect the record's own
+        // origin TTL of 0, aged - never the entry's floor-extended remaining
+        // lifetime.
+        assert_eq!(parsed.answers[0].ttl, 0);
+    }
+
     #[test]
     fn assemble_response_echoes_requesters_own_casing() {
         let now = SystemTime::now();
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 5e76715..9fcbca9 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -16364,6 +16364,71 @@ mod tests {
         assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
     }
 
+    #[tokio::test]
+    async fn resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let epoch = 0u64;
+        let now = SystemTime::UNIX_EPOCH;
+
+        // Chain-wide minimum origin TTL across the whole response is 60s (the
+        // intermediate hop's TTL) - this becomes every hop's `expires_at`
+        // ceiling, exactly as `decompose_response_for_store` computes it in
+        // production.
+        let chain_ceiling = Duration::from_secs(60);
+
+        let cname = cname_record("alias.example.com", 60, "target.example.com");
+        let terminal = a_record("target.example.com", 3600); // long origin TTL
+
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![
+                    (
+                        "alias.example.com".to_string(),
+                        CNAME_RECORD_TYPE,
+                        1,
+                        seed_rrset_entry(&cname, chain_ceiling, now, epoch),
+                    ),
+                    (
+                        "target.example.com".to_string(),
+                        A_RECORD_TYPE,
+                        1,
+                        // Same chain-wide ceiling applied here, even though
+                        // `terminal`'s own origin TTL is 3600 - mirrors
+                        // production `build_rrset_entry`'s single shared `ttl`.
+                        seed_rrset_entry(&terminal, chain_ceiling, now, epoch),
+                    ),
+                ],
+                negative: None,
+            },
+            epoch,
+        );
+
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);
+
+        // Second, independent query: look up the terminal name directly,
+        // NOT by re-resolving the alias.
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                now + Duration::from_secs(25),
+                a_query(0x2222, "target.example.com"),
+            ))
+            .await;
+
+        let parsed = Message::parse(&outcome.response_bytes).unwrap();
+        // Aged TTL from the terminal record's own 3600s origin TTL would be
+        // 3575 at t=25s - but the chain-wide ceiling (60s remaining lifetime,
+        // 35s left at t=25s) must win: min(3575, 35) == 35.
+        assert_eq!(parsed.answers[0].ttl, 35);
+        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
+    }
+
     #[tokio::test]
     async fn resolve_truncates_oversized_cached_response_for_current_request() {
         let now = SystemTime::UNIX_EPOCH;
