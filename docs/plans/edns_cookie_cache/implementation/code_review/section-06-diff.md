diff --git a/src/protocol/mod.rs b/src/protocol/mod.rs
index 20c0d6d..a27f51d 100644
--- a/src/protocol/mod.rs
+++ b/src/protocol/mod.rs
@@ -627,7 +627,7 @@ pub fn build_badvers_response(
     let question_count = u16::from(!request.questions.is_empty());
     let dnssec_ok = request.edns.as_ref().is_some_and(|edns| edns.dnssec_ok);
     let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
-    let opt = build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 1);
+    let opt = build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 1, Vec::new());
 
     write_message_header(
         &mut response,
@@ -1246,7 +1246,22 @@ fn from_hex(hex: &str) -> Vec<u8> {
 /// `Message` to read from at cache-hit serve time) so both build the exact
 /// same OPT shape rather than duplicating this construction.
 pub(crate) fn build_opt_record(udp_payload_size: u16, dnssec_ok: bool) -> Record {
-    build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 0)
+    build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 0, Vec::new())
+}
+
+/// `build_opt_record`, with a pre-built `options` TLV byte vector (e.g. a
+/// COOKIE option from `crate::protocol::edns_cookie::build_cookie_option`)
+/// attached to the OPT record's RDATA instead of always building an
+/// options-less OPT. Used by `resolver::cache::assemble::requester_opt_record`
+/// (cache-hit path) and `resolver::mirrored_client_opt_record`/
+/// `message_edns_opt_record` (cache-miss/recursive path) once a client
+/// cookie needs echoing back to the requester.
+pub(crate) fn build_opt_record_with_options(
+    udp_payload_size: u16,
+    dnssec_ok: bool,
+    options: Vec<u8>,
+) -> Record {
+    build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 0, options)
 }
 
 /// `build_opt_record`, with an explicit extended-RCODE byte (the upper 8
@@ -1260,6 +1275,7 @@ fn build_opt_record_with_extended_rcode(
     udp_payload_size: u16,
     dnssec_ok: bool,
     extended_rcode: u8,
+    options: Vec<u8>,
 ) -> Record {
     let flags = if dnssec_ok { EDNS_DO_FLAG } else { 0 };
     let ttl = (u32::from(extended_rcode) << 24) | u32::from(flags);
@@ -1274,7 +1290,7 @@ fn build_opt_record_with_extended_rcode(
             version: 0,
             flags,
             dnssec_ok,
-            options: Vec::new(),
+            options,
         }),
     }
 }
@@ -4905,6 +4921,34 @@ mod tests {
         }
     }
 
+    #[test]
+    fn build_opt_record_with_options_round_trips_cookie_option_bytes() {
+        let secret = edns_cookie::CookieSecret::generate();
+        let client_cookie: edns_cookie::ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let client_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
+        let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
+        let server_cookie =
+            edns_cookie::build_server_cookie(&secret, client_cookie, client_ip, now);
+        let options = edns_cookie::build_cookie_option(client_cookie, server_cookie);
+
+        let opt = build_opt_record_with_options(1232, true, options.clone());
+        let mut bytes = Vec::new();
+        write_opt_record(&mut bytes, &opt);
+
+        let parsed = parse_test_record(&bytes);
+        assert_eq!(parsed.rtype, OPT_RECORD_TYPE);
+        match parsed.record {
+            RecordData::OPT(info) => {
+                assert_eq!(info.options, options);
+                assert_eq!(info.udp_payload_size, 1232);
+                assert!(info.dnssec_ok);
+                assert_eq!(info.extended_rcode, 0);
+                assert_eq!(info.version, 0);
+            }
+            other => panic!("expected OPT, got {other:?}"),
+        }
+    }
+
     #[test]
     fn parse_record_cname_compressed_target() {
         let mut message = Vec::new();
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index a053ad2..6c68667 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -19212,6 +19212,125 @@ mod tests {
         assert_eq!(lookups[0], lookups[1]); // identical (qname, qtype, qclass) despite different client cookies
     }
 
+    #[tokio::test]
+    async fn resolve_cache_hit_response_carries_cookie_option_for_cookie_bearing_query() {
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
+        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);
+        let client_cookie = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
+        let mut cookie_option = vec![0u8, 10, 0, 8];
+        cookie_option.extend_from_slice(&client_cookie);
+
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                now,
+                a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option),
+            ))
+            .await;
+
+        let response = Message::parse(&outcome.response_bytes).unwrap();
+        let opt = response
+            .additionals
+            .iter()
+            .find(|record| matches!(record.record, RecordData::OPT(_)))
+            .expect("cache-hit response to a Cookie-bearing query must carry an OPT record");
+        let RecordData::OPT(edns) = &opt.record else {
+            unreachable!();
+        };
+        let echoed_client_cookie = crate::protocol::edns_cookie::parse_cookie_option(&edns.options)
+            .expect("OPT options must decode to a well-formed COOKIE option");
+        assert_eq!(echoed_client_cookie, client_cookie);
+        assert_eq!(
+            edns.options.len(),
+            4 + 8 + 16,
+            "COOKIE option TLV must carry the 8-byte client cookie plus a 16-byte server cookie"
+        );
+    }
+
+    #[tokio::test]
+    async fn resolve_shared_cache_hit_gives_each_requester_a_distinct_cookie() {
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
+        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);
+
+        let cookie_a = [0x11u8; 8];
+        let cookie_b = [0x22u8; 8];
+        let mut option_a = vec![0u8, 10, 0, 8];
+        option_a.extend_from_slice(&cookie_a);
+        let mut option_b = vec![0u8, 10, 0, 8];
+        option_b.extend_from_slice(&cookie_b);
+
+        let outcome_a = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                now,
+                a_query_with_edns_options(0x7777, "example.com", 1232, false, &option_a),
+            ))
+            .await;
+        let outcome_b = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.11".parse().unwrap(),
+                now,
+                a_query_with_edns_options(0x8888, "example.com", 1232, false, &option_b),
+            ))
+            .await;
+
+        let message_a = Message::parse(&outcome_a.response_bytes).unwrap();
+        let message_b = Message::parse(&outcome_b.response_bytes).unwrap();
+        assert_eq!(
+            message_a.answers, message_b.answers,
+            "both requesters share the same cached answer data"
+        );
+
+        let opt_options = |message: &Message| -> Vec<u8> {
+            let opt = message
+                .additionals
+                .iter()
+                .find(|record| matches!(record.record, RecordData::OPT(_)))
+                .expect("cache-hit response must carry an OPT record");
+            let RecordData::OPT(edns) = &opt.record else {
+                unreachable!();
+            };
+            edns.options.clone()
+        };
+        let options_a = opt_options(&message_a);
+        let options_b = opt_options(&message_b);
+
+        assert_eq!(
+            &options_a[4..12],
+            &cookie_a,
+            "response A must echo requester A's own client cookie"
+        );
+        assert_eq!(
+            &options_b[4..12],
+            &cookie_b,
+            "response B must echo requester B's own client cookie"
+        );
+        assert_ne!(
+            &options_a[12..28],
+            &options_b[12..28],
+            "each requester must get its own freshly-computed server cookie, \
+             never a shared/replayed one"
+        );
+    }
+
     #[tokio::test]
     async fn resolve_bypasses_cache_for_unsupported_edns_flags_and_version() {
         for request in [
