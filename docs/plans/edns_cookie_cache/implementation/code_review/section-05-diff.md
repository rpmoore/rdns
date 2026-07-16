diff --git a/src/protocol/mod.rs b/src/protocol/mod.rs
index a0b88e0..4013108 100644
--- a/src/protocol/mod.rs
+++ b/src/protocol/mod.rs
@@ -1322,6 +1322,45 @@ pub(crate) fn message_edns_opt_record(
     Some(build_opt_record(udp_payload_size, edns.dnssec_ok))
 }
 
+/// `message_edns_opt_record`, plus RFC 9018 server-cookie construction: if
+/// `message`'s EDNS options carry a well-formed RFC 7873 client cookie
+/// (`edns_cookie::parse_cookie_option`), the returned OPT record's options
+/// carry a freshly-built COOKIE option (`edns_cookie::build_server_cookie` +
+/// `build_cookie_option`) echoing that client cookie back with a fresh
+/// server cookie, instead of the options-less OPT `message_edns_opt_record`
+/// always builds.
+///
+/// A separate function rather than widening `message_edns_opt_record`
+/// in place: that function also backs `build_question_response` and
+/// `build_txt_answer_response` (the statically-configured local-entry
+/// response path), which section 05 of the EDNS-cookie plan explicitly
+/// leaves untouched. Used by `resolver::mirrored_client_opt_record_with_cookie`
+/// on the cache-miss/recursive path, mirroring
+/// `resolver::cache::assemble::requester_opt_record` on the cache-hit path.
+pub(crate) fn message_edns_opt_record_with_cookie(
+    message: &Message,
+    responder_udp_payload_size: usize,
+    cookie_secret: &edns_cookie::CookieSecret,
+    client_ip: std::net::IpAddr,
+    now: std::time::SystemTime,
+) -> Option<Record> {
+    let edns = message.edns.as_ref()?;
+    let udp_payload_size = responder_udp_payload_size.min(u16::MAX as usize) as u16;
+    match edns_cookie::parse_cookie_option(&edns.options) {
+        Some(client_cookie) => {
+            let server_cookie =
+                edns_cookie::build_server_cookie(cookie_secret, client_cookie, client_ip, now);
+            let options = edns_cookie::build_cookie_option(client_cookie, server_cookie);
+            Some(build_opt_record_with_options(
+                udp_payload_size,
+                edns.dnssec_ok,
+                options,
+            ))
+        }
+        None => Some(build_opt_record(udp_payload_size, edns.dnssec_ok)),
+    }
+}
+
 /// Encodes one arbitrary resource record to wire bytes: owner name, type,
 /// class, TTL, then a length-prefixed RDATA block sized to whatever
 /// `rdata` actually needs. Mirrors `parse_record_data`'s match arms in
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 6c68667..86ca52d 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -1646,6 +1646,40 @@ fn mirrored_client_opt_record(
     crate::protocol::message_edns_opt_record(original_query, configured_max_udp_payload_size)
 }
 
+/// `mirrored_client_opt_record`, plus a fresh RFC 9018 server cookie
+/// attached whenever `original_query` carries a well-formed client cookie
+/// -- see `crate::protocol::message_edns_opt_record_with_cookie`, which this
+/// delegates to.
+///
+/// Used by every miss-path/recursive-synthesis call site that rebuilds a
+/// *specific requester's own* framing (`rebuild_recursive_response_with_own_framing`,
+/// `truncated_response_for_query`, and `prepare_backend_result`'s direct
+/// DO=false-filtered-response call), all of which run inside
+/// `ResolveQuery::prepare_backend_result` and therefore have `self.cookie_secret`,
+/// `self.clock`, and `request.client_ip` in scope. Deliberately NOT used by
+/// `synthesize_recursive_cname_response` (which keeps calling the plain,
+/// cookie-unaware `mirrored_client_opt_record`): that function builds the
+/// shared, potentially-coalesced backend response, which has no single
+/// requester's client IP to compute a server cookie against, and whose OPT
+/// record is never trusted as final once a cookie is in play --
+/// `recursive_synthesis_reused_own_framing` forces every cookie-bearing
+/// response through this cookie-aware rebuild path downstream regardless.
+fn mirrored_client_opt_record_with_cookie(
+    original_query: &Message,
+    configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
+    now: SystemTime,
+) -> Option<Record> {
+    crate::protocol::message_edns_opt_record_with_cookie(
+        original_query,
+        configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
+    )
+}
+
 /// Rebuilds client-facing bytes for a recursive-synthesis response
 /// (`response.recursive_synthesis.is_some()`) using *this requester's own*
 /// header/echoed-question/OPT, sourced from `decoded.message` -- never
@@ -1684,11 +1718,15 @@ fn mirrored_client_opt_record(
 /// the leader-synthesized OPT verbatim) and a fresh
 /// `mirrored_client_opt_record` for *this* requester is appended in its
 /// place.
+#[allow(clippy::too_many_arguments)]
 fn rebuild_recursive_response_with_own_framing(
     decoded: &DecodedQuery,
     response_message: &Message,
     rcode: ResponseCode,
     configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
+    now: SystemTime,
 ) -> Result<Vec<u8>, ResolutionBackendError> {
     #[cfg(test)]
     REBUILD_RECURSIVE_RESPONSE_WITH_OWN_FRAMING_CALLS.with(|calls| calls.set(calls.get() + 1));
@@ -1699,8 +1737,13 @@ fn rebuild_recursive_response_with_own_framing(
         .filter(|record| !matches!(record.record, RecordData::OPT(_)))
         .cloned()
         .collect();
-    if let Some(opt) = mirrored_client_opt_record(&decoded.message, configured_max_udp_payload_size)
-    {
+    if let Some(opt) = mirrored_client_opt_record_with_cookie(
+        &decoded.message,
+        configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
+    ) {
         additionals.push(opt);
     }
     serialize_recursive_response(
@@ -1734,8 +1777,17 @@ fn truncated_response_for_query(
     decoded: &DecodedQuery,
     response_code: ResponseCode,
     configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
+    now: SystemTime,
 ) -> Vec<u8> {
-    let opt = mirrored_client_opt_record(&decoded.message, configured_max_udp_payload_size);
+    let opt = mirrored_client_opt_record_with_cookie(
+        &decoded.message,
+        configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
+    );
     crate::protocol::build_truncated_wire_response(
         decoded.message.header.id,
         decoded.message.header.rd(),
@@ -1778,6 +1830,23 @@ fn recursive_synthesis_reused_own_framing(
 
     let question_matches = decoded.message.questions.first() == original_query.questions.first();
 
+    // A server cookie is time-dependent (RFC 9018 §4.4 bakes in a fresh
+    // Unix timestamp) and must never be replayed. If either side carries a
+    // well-formed client cookie, framing is never considered reused --
+    // even when the echoed question and DO bit otherwise match -- forcing
+    // a rebuild through `mirrored_client_opt_record_with_cookie` so the
+    // cookie actually gets computed instead of silently reusing (or
+    // omitting) whichever OPT `synthesize_recursive_cname_response` baked
+    // in without cookie awareness.
+    let has_cookie = |message: &Message| {
+        message.edns.as_ref().is_some_and(|edns| {
+            crate::protocol::edns_cookie::parse_cookie_option(&edns.options).is_some()
+        })
+    };
+    if has_cookie(&decoded.message) || has_cookie(original_query) {
+        return false;
+    }
+
     let opt_matches = match (decoded.message.edns.as_ref(), original_query.edns.as_ref()) {
         (None, None) => true,
         (Some(this), Some(original)) => this.dnssec_ok == original.dnssec_ok,
@@ -1808,19 +1877,30 @@ fn recursive_synthesis_reused_own_framing(
 /// `is_udp_response` mirrors the same TCP gate `exceeds_unfiltered`
 /// itself uses (`!request.observed_source.is_tcp()`) -- a TCP response is
 /// never truncated this way, matching the rest of this function.
+#[allow(clippy::too_many_arguments)]
 fn enforce_udp_payload_limit_after_reserialize(
     decoded: &DecodedQuery,
     is_udp_response: bool,
     bytes: Vec<u8>,
     rcode: ResponseCode,
     configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
+    now: SystemTime,
 ) -> Vec<u8> {
     if is_udp_response
         && decoded
             .message
             .response_exceeds_udp_payload(bytes.len(), configured_max_udp_payload_size)
     {
-        truncated_response_for_query(decoded, rcode, configured_max_udp_payload_size)
+        truncated_response_for_query(
+            decoded,
+            rcode,
+            configured_max_udp_payload_size,
+            cookie_secret,
+            client_ip,
+            now,
+        )
     } else {
         bytes
     }
@@ -4431,6 +4511,9 @@ impl ResolveQuery {
                 decoded,
                 ResponseCode::NoError,
                 configured_max_udp_payload_size,
+                &self.cookie_secret,
+                request.client_ip,
+                self.clock.now(),
             )
         } else {
             response
@@ -4862,6 +4945,9 @@ impl ResolveQuery {
                 decoded,
                 response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                 configured_max_udp_payload_size,
+                &self.cookie_secret,
+                request.client_ip,
+                self.clock.now(),
             );
         } else if filterable {
             let synthesis = response
@@ -4920,6 +5006,9 @@ impl ResolveQuery {
                             decoded,
                             response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                             configured_max_udp_payload_size,
+                            &self.cookie_secret,
+                            request.client_ip,
+                            self.clock.now(),
                         );
                     }
                 } else if let Ok(bytes) = rebuild_recursive_response_with_own_framing(
@@ -4927,6 +5016,9 @@ impl ResolveQuery {
                     &response_message,
                     response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                     configured_max_udp_payload_size,
+                    &self.cookie_secret,
+                    request.client_ip,
+                    self.clock.now(),
                 ) {
                     // There's nothing DNSSEC-specific for a DO=false filter
                     // pass to remove, so the content of `response_bytes` (==
@@ -4965,6 +5057,9 @@ impl ResolveQuery {
                         bytes,
                         response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                         configured_max_udp_payload_size,
+                        &self.cookie_secret,
+                        request.client_ip,
+                        self.clock.now(),
                     );
                 }
             } else {
@@ -5000,9 +5095,13 @@ impl ResolveQuery {
                 // `questions` above) are still the right source for *which*
                 // records match during filtering -- that's about content,
                 // not header framing.
-                if let Some(opt) =
-                    mirrored_client_opt_record(&decoded.message, configured_max_udp_payload_size)
-                {
+                if let Some(opt) = mirrored_client_opt_record_with_cookie(
+                    &decoded.message,
+                    configured_max_udp_payload_size,
+                    &self.cookie_secret,
+                    request.client_ip,
+                    self.clock.now(),
+                ) {
                     additionals.push(opt);
                 }
                 if let Ok(filtered_bytes) = serialize_recursive_response(
@@ -5034,6 +5133,9 @@ impl ResolveQuery {
                         filtered_bytes,
                         response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                         configured_max_udp_payload_size,
+                        &self.cookie_secret,
+                        request.client_ip,
+                        self.clock.now(),
                     );
                 }
             }
@@ -5069,6 +5171,9 @@ impl ResolveQuery {
                     &response_message,
                     response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                     configured_max_udp_payload_size,
+                    &self.cookie_secret,
+                    request.client_ip,
+                    self.clock.now(),
                 )
             {
                 // Same growth risk as the DO=false fast path above:
@@ -5083,6 +5188,9 @@ impl ResolveQuery {
                     bytes,
                     response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                     configured_max_udp_payload_size,
+                    &self.cookie_secret,
+                    request.client_ip,
+                    self.clock.now(),
                 );
             }
         }
@@ -17387,6 +17495,258 @@ mod tests {
         );
     }
 
+    /// Section 05: a cache-miss (recursive-backend-forwarded) query
+    /// carrying a well-formed Cookie option must get a response whose OPT
+    /// record carries a fresh, correct RFC 9018 server cookie -- mirroring
+    /// the cache-hit case (`resolve_cache_hit_response_carries_cookie_option_for_cookie_bearing_query`)
+    /// but exercised through the recursive-miss/`mirrored_client_opt_record_with_cookie`
+    /// path instead. A single, non-coalesced `resolve()` call, so this also
+    /// proves `recursive_synthesis_reused_own_framing`'s cookie-forced
+    /// rebuild actually attaches the cookie on the ordinary path, not just
+    /// the coalesced-follower path.
+    #[tokio::test]
+    async fn resolve_recursive_miss_response_carries_cookie_option_for_cookie_bearing_query() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 0,
+            shard_count: Some(1),
+        }));
+        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
+        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
+            response_message_for_question(
+                question,
+                ResponseCode::NoError,
+                vec![a_record("example.com", 60)],
+                Vec::new(),
+                Vec::new(),
+                true,
+            ),
+        )]));
+        let backend: Arc<dyn ResolutionBackend> = Arc::new(recursive_backend(transport));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let cookie_secret = Arc::new(CookieSecret::generate());
+        let service = resolve_service_with_recursive_cache(backend, cache, events, metrics, 1232)
+            .with_cookie_secret(cookie_secret);
+
+        let client_cookie = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
+        let mut cookie_option = vec![0u8, 10, 0, 8];
+        cookie_option.extend_from_slice(&client_cookie);
+        let query = a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option);
+
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                SystemTime::UNIX_EPOCH,
+                query,
+            ))
+            .await;
+
+        let response = Message::parse(&outcome.response_bytes).unwrap();
+        let opt = response
+            .additionals
+            .iter()
+            .find(|record| matches!(record.record, RecordData::OPT(_)))
+            .expect("recursive-miss response to a Cookie-bearing query must carry an OPT record");
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
+    /// Section 05: two coalesced/in-flight requesters for the same
+    /// backend query, presenting different client cookies, must each
+    /// receive their own distinct, correctly-computed COOKIE option --
+    /// never a shared/replayed one. Builds on the same coalesced-follower
+    /// harness pattern as `resolve_coalesced_edns_follower_behind_non_edns_leader_keeps_its_own_opt`.
+    #[tokio::test]
+    async fn resolve_coalesced_miss_gives_each_requester_a_distinct_cookie() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 0,
+            shard_count: Some(1),
+        }));
+        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
+        let response = response_message_for_question(
+            question,
+            ResponseCode::NoError,
+            vec![a_record("example.com", 60)],
+            Vec::new(),
+            Vec::new(),
+            true,
+        );
+        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
+            response.clone(),
+            response,
+        ));
+        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
+            RecursiveResolverConfig {
+                root_hints: vec![RecursiveRootHint {
+                    name: "a.root-servers.example".to_string(),
+                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
+                }],
+                per_authority_timeout: Duration::from_millis(500),
+                per_query_deadline: Duration::from_secs(2),
+                max_recursion_depth: 8,
+                max_cname_restarts: 4,
+                configured_max_udp_payload_size: 1232,
+            },
+            transport.clone(),
+        ));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let cookie_secret = Arc::new(CookieSecret::generate());
+        let service = Arc::new(
+            resolve_service_with_recursive_cache(backend, cache, events, metrics.clone(), 1232)
+                .with_cookie_secret(cookie_secret),
+        );
+
+        let cookie_a = [0x11u8; 8];
+        let cookie_b = [0x22u8; 8];
+        let mut option_a = vec![0u8, 10, 0, 8];
+        option_a.extend_from_slice(&cookie_a);
+        let mut option_b = vec![0u8, 10, 0, 8];
+        option_b.extend_from_slice(&cookie_b);
+        let leader_query = a_query_with_edns_options(0x1111, "example.com", 1232, false, &option_a);
+        let follower_query =
+            a_query_with_edns_options(0x2222, "example.com", 1232, false, &option_b);
+
+        let leader = {
+            let service = Arc::clone(&service);
+            tokio::spawn(async move {
+                service
+                    .resolve(ResolveRequest::new(
+                        "192.0.2.10".parse().unwrap(),
+                        SystemTime::UNIX_EPOCH,
+                        leader_query,
+                    ))
+                    .await
+            })
+        };
+        transport.wait_for_requests(1).await;
+
+        let follower = {
+            let service = Arc::clone(&service);
+            tokio::spawn(async move {
+                service
+                    .resolve(ResolveRequest::new(
+                        "192.0.2.11".parse().unwrap(),
+                        SystemTime::UNIX_EPOCH,
+                        follower_query,
+                    ))
+                    .await
+            })
+        };
+        tokio::task::yield_now().await;
+        assert_eq!(
+            transport.requests.lock().unwrap().len(),
+            1,
+            "the follower must coalesce onto the leader's single in-flight fetch"
+        );
+
+        transport.release.notify_waiters();
+        let leader = leader.await.unwrap();
+        let follower = follower.await.unwrap();
+
+        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);
+
+        let opt_options = |bytes: &[u8]| -> Vec<u8> {
+            let message = Message::parse(bytes).unwrap();
+            let opt = message
+                .additionals
+                .iter()
+                .find(|record| matches!(record.record, RecordData::OPT(_)))
+                .expect("Cookie-bearing requester must get an OPT record back")
+                .clone();
+            let RecordData::OPT(edns) = opt.record else {
+                unreachable!();
+            };
+            edns.options
+        };
+        let options_leader = opt_options(&leader.response_bytes);
+        let options_follower = opt_options(&follower.response_bytes);
+
+        assert_eq!(
+            &options_leader[4..12],
+            &cookie_a,
+            "leader's response must echo its own client cookie, not the follower's"
+        );
+        assert_eq!(
+            &options_follower[4..12],
+            &cookie_b,
+            "follower's response must echo its own client cookie, not the leader's"
+        );
+        assert_ne!(
+            &options_leader[12..28],
+            &options_follower[12..28],
+            "each requester must get its own freshly-computed server cookie, \
+             never a shared/replayed one"
+        );
+    }
+
+    /// Section 05: `recursive_synthesis_reused_own_framing` must never
+    /// report reused framing when either side carries a well-formed client
+    /// cookie, even when the echoed question and DO bit otherwise match --
+    /// a server cookie is time-dependent (RFC 9018 §4.4) and must never be
+    /// replayed from whichever request originally synthesized the shared
+    /// response.
+    #[test]
+    fn recursive_synthesis_reused_own_framing_returns_false_when_cookie_present() {
+        let mut cookie_option = vec![0u8, 10, 0, 8];
+        cookie_option.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
+        let cookie_bytes =
+            a_query_with_edns_options(0x1111, "example.com", 1232, false, &cookie_option);
+        let no_cookie_bytes = a_query_with_edns(0x1111, "example.com", 1232, false);
+
+        let cookie_message = Message::parse_owned(cookie_bytes).unwrap();
+        let no_cookie_message = Message::parse_owned(no_cookie_bytes).unwrap();
+
+        let decoded = DecodedQuery::new(cookie_message.clone()).unwrap();
+        let synthesis = RecursiveSynthesisContext {
+            original_query: no_cookie_message.clone(),
+            original_question: decoded.question.clone(),
+            final_question: decoded.question.clone(),
+        };
+        assert!(
+            !recursive_synthesis_reused_own_framing(&decoded, &synthesis),
+            "this requester's own cookie-bearing query must force a rebuild, even \
+             though question and DO bit otherwise match"
+        );
+
+        // Symmetric case: this requester carries no cookie, but the
+        // request that originally synthesized the shared response did.
+        let decoded_no_cookie = DecodedQuery::new(no_cookie_message).unwrap();
+        let synthesis_original_had_cookie = RecursiveSynthesisContext {
+            original_query: cookie_message,
+            original_question: decoded_no_cookie.question.clone(),
+            final_question: decoded_no_cookie.question.clone(),
+        };
+        assert!(
+            !recursive_synthesis_reused_own_framing(
+                &decoded_no_cookie,
+                &synthesis_original_had_cookie
+            ),
+            "a cookie on the synthesizing request alone must also force a rebuild"
+        );
+
+        // Regression: no cookie on either side, question and DO bit match
+        // -- framing is genuinely reused, same as before this section.
+        let synthesis_no_cookie = RecursiveSynthesisContext {
+            original_query: decoded_no_cookie.message.clone(),
+            original_question: decoded_no_cookie.question.clone(),
+            final_question: decoded_no_cookie.question.clone(),
+        };
+        assert!(
+            recursive_synthesis_reused_own_framing(&decoded_no_cookie, &synthesis_no_cookie),
+            "regression: matching non-cookie framing must still be reported reused"
+        );
+    }
+
     /// Regression test for both independent Codex adversarial reviews'
     /// shared finding: `exceeds_unfiltered` is computed once, early, from
     /// the shared/leader-framed `response_bytes` -- *before* the DO=false
