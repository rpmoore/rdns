diff --git a/docs/knowledge/resolver/caching/answer-cache.md b/docs/knowledge/resolver/caching/answer-cache.md
index a6ef159..7a7c1e7 100644
--- a/docs/knowledge/resolver/caching/answer-cache.md
+++ b/docs/knowledge/resolver/caching/answer-cache.md
@@ -4,7 +4,7 @@ title: DNS Answer Cache
 description: Sharded, in-memory cache of backend/upstream DNS answers, keyed by domain name.
 resource: src/resolver/cache/mod.rs
 tags: [cache, dns, resolver]
-timestamp: 2026-07-19T00:00:00Z
+timestamp: 2026-07-19T01:00:00Z
 ---
 
 Caches responses obtained from actual backend resolution — forwarding or
@@ -210,35 +210,44 @@ details are applied at serve time" pattern already described above in
 read" — cookies are just another instance of it, not an exception.
 
 **Security trade-off — read this before assuming any anti-spoofing
-protection exists.** This resolver never validates an incoming *server*
-cookie's hash or timestamp window, never generates BADCOOKIE (RCODE 23), and
-never rejects a query for cookie-related reasons — every query is processed
-normally and every response gets a freshly-computed, valid server cookie,
-unconditionally. This is one of RFC 7873's own compliant behaviors (§5.2.3/
-§5.2.4 branch 3: "process the request and provide a normal response"), not a
-corner cut — but it means this implementation gains **no**
-anti-off-path-spoofing value from DNS Cookies. That protection comes from
-the incoming-cookie validation/rejection path this implementation
-deliberately does not build — see the module doc comment at
-`src/protocol/edns_cookie.rs:15-21` ("never validates an incoming server
-cookie's hash or timestamp") and `parse_cookie_option`
-(`src/protocol/edns_cookie.rs:113-131`, whose own doc comment repeats the
-same non-goal at the one function that actually reads an incoming cookie);
-the full non-goals list (no BADCOOKIE, no server-cookie verification, no
-secret rotation) is in
-`docs/plans/edns_cookie_cache/claude-plan.md`. If you're checking whether
-rdns has DNS Cookie *protection*: no — it has Cookie *echo/interop* only.
-
-**This is being actively closed, in stages** (`docs/plans/sec_work/`,
-Track B): `src/protocol/mod.rs`'s `build_badcookie_response` and
-`QueryValidationError::InvalidServerCookie` (added in section-07) already
-build the correct BADCOOKIE wire response and bucket it for metrics, and
-`ResponseFactory::protocol_error` already threads the `cookie_secret`/
-`client_ip`/`now` a real check will need — but nothing in the codebase can
-produce `InvalidServerCookie` yet, so every statement above is still
-accurate as of section-07. Section-08 wires actual server-cookie
-recompute-and-compare into `probe_cache`, at which point this section needs
-a rewrite, not an addendum.
+protection exists.** As of Track B (`docs/plans/sec_work/`), this resolver
+**does** validate an incoming *server* cookie (recompute-and-compare via
+`build_server_cookie`/`server_cookie_matches`, wired into `probe_cache` by
+`invalid_server_cookie`, `src/resolver/mod.rs:6875-6903`) and **does**
+generate BADCOOKIE (RCODE 23, `build_badcookie_response`) for a tampered,
+stale, or malformed server-cookie tail — but **only over UDP**. RFC 7873
+§5.2.3's TCP carve-out means the identical invalid cookie presented over
+TCP is still processed normally, unconditionally, exactly as this section
+described for *all* transports before Track B — `invalid_server_cookie`
+returns `None` immediately for any TCP request without inspecting the
+cookie at all. Say this transport split explicitly: a reader skimming only
+the first sentence should not conclude BADCOOKIE applies uniformly.
+
+A client cookie with **no server-cookie tail at all** (first contact, RFC
+7873 §5.2.3) is unchanged by Track B and still processed normally on both
+transports, with a fresh server cookie issued — `locate_cookie_for_verification`
+classifies this as `CookieVerification::ClientOnly`, which
+`invalid_server_cookie` never rejects. A request with more than one COOKIE
+option (`CookieVerification::Duplicate`) is treated the same way — not
+specially rejected, not specially trusted, just processed as if no cookie
+had been presented, mirroring `locate_cookie_option`'s pre-existing
+duplicate-collapsing behavior for cookie *echo*.
+
+Net effect: this resolver now gains **some** anti-off-path-spoofing value
+from DNS Cookies over UDP — an off-path attacker without visibility into a
+client's already-issued server cookie cannot forge a response the client
+will accept, matching RFC 7873's intended protection model for that
+transport. It still gains **none** over TCP, where the carve-out means a
+tampered cookie is silently tolerated; that's not a gap this implementation
+introduced, it's RFC 7873 §5.2.3 relying on TCP's own inherent
+difficulty-to-off-path-spoof instead. See
+`src/protocol/edns_cookie.rs:15-21`'s module doc comment and
+`parse_cookie_option`'s doc comment (`:113-131`) for where the validation
+logic actually lives — `parse_cookie_option`/`locate_cookie_option`
+themselves still only extract the client cookie and remain unchanged; the
+new verification path is `locate_cookie_for_verification` and
+`server_cookie_matches`, called from `src/resolver/mod.rs`, not from this
+module.
 
 # Concurrency model, in one sentence
 
diff --git a/src/protocol/edns_cookie.rs b/src/protocol/edns_cookie.rs
index 8ad5767..cbd7069 100644
--- a/src/protocol/edns_cookie.rs
+++ b/src/protocol/edns_cookie.rs
@@ -15,10 +15,17 @@
 //! RFC 7873 DNS Cookie EDNS option parsing, cache-admission narrowing, and
 //! RFC 9018 server-cookie construction.
 //!
-//! This module never validates an incoming server cookie's hash or
-//! timestamp (no BADCOOKIE handling, no secret rotation) -- see the parent
-//! plan's non-goals. It only extracts the client cookie from a query and
-//! computes a fresh server cookie to attach to every response.
+//! This module itself only extracts the client cookie from a query
+//! (`parse_cookie_option`/`locate_cookie_option`) and computes a fresh
+//! server cookie to attach to every response (`build_server_cookie`) --
+//! no secret rotation is implemented (see the parent plan's non-goals).
+//! Incoming server-cookie *verification* (recompute-and-compare,
+//! BADCOOKIE rejection) is not done here: `locate_cookie_for_verification`
+//! and `server_cookie_matches` below are the building blocks, but the
+//! transport-conditional gating decision (UDP rejects an invalid cookie,
+//! TCP doesn't -- RFC 7873 §5.2.3/§5.2.4) lives in
+//! `src/resolver/mod.rs`'s `invalid_server_cookie`, called from
+//! `probe_cache`.
 
 use std::net::IpAddr;
 use std::time::SystemTime;
@@ -115,9 +122,11 @@ fn locate_cookie_option(options: &[u8]) -> Option<(ClientCookie, bool)> {
 /// with code 10 (COOKIE). Returns `Some(client_cookie)` only when the
 /// option is present exactly once and has a well-formed RFC 7873 §4 length
 /// (8, or 16-40 inclusive) -- extracting just the first 8 bytes (the
-/// client cookie) and discarding any server-cookie bytes present (this
-/// implementation never validates an incoming server cookie, per the
-/// plan's decided non-goals).
+/// client cookie) and discarding any server-cookie bytes present. This
+/// function itself never validates a presented server cookie; that check
+/// (recompute-and-compare, transport-conditional BADCOOKIE gating) is
+/// `locate_cookie_for_verification`/`server_cookie_matches` below plus
+/// `src/resolver/mod.rs`'s `invalid_server_cookie`, not this function.
 ///
 /// Returns `None` when: no COOKIE option is present, more than one COOKIE
 /// option is present, or the option's length is malformed.
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 72635f7..8f91ff5 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -24491,6 +24491,80 @@ mod tests {
         assert!(!upstream.requests.lock().unwrap().is_empty());
     }
 
+    /// §B3 test: a request whose EDNS options contain **two** COOKIE
+    /// options must be processed identically to a cookie-less request --
+    /// no BADCOOKIE on either transport, and no bespoke duplicate-specific
+    /// handling. `locate_cookie_for_verification` collapses this case to
+    /// `CookieVerification::Duplicate`, which `invalid_server_cookie`
+    /// treats the same as `NoCookieOption` (never an error), mirroring
+    /// `locate_cookie_option`'s pre-existing duplicate-rejection behavior
+    /// pinned by `parse_cookie_option_rejects_duplicates` in
+    /// `edns_cookie.rs`.
+    #[tokio::test]
+    async fn resolve_duplicate_cookie_options_processed_normally_not_badcookie_udp() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service(upstream.clone(), events, metrics);
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let bogus_tail = [0xFFu8; 16];
+        let mut cookie_options = cookie_option_bytes_with_tail(client_cookie, &bogus_tail);
+        cookie_options
+            .extend_from_slice(&cookie_option_bytes_with_tail(client_cookie, &bogus_tail));
+        let request_bytes =
+            a_query_with_edns_options(0x100a, "example.com", 4096, false, &cookie_options);
+
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                SystemTime::UNIX_EPOCH,
+                request_bytes,
+            ))
+            .await;
+
+        assert_eq!(
+            outcome.decision.kind,
+            ResolveDecisionKind::BackendFailure,
+            "a duplicate-COOKIE-option request must never trigger BADCOOKIE -- it must fall \
+             through to exactly the same path a cookie-less request takes"
+        );
+        assert!(!upstream.requests.lock().unwrap().is_empty());
+    }
+
+    /// §B3 test: the TCP counterpart of
+    /// `resolve_duplicate_cookie_options_processed_normally_not_badcookie_udp`
+    /// -- duplicate COOKIE options are processed normally on TCP too (TCP
+    /// never runs the cookie check at all, but this pins the observable
+    /// behavior explicitly rather than relying on that implementation
+    /// detail).
+    #[tokio::test]
+    async fn resolve_duplicate_cookie_options_processed_normally_not_badcookie_tcp() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service(upstream.clone(), events, metrics);
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let bogus_tail = [0xFFu8; 16];
+        let mut cookie_options = cookie_option_bytes_with_tail(client_cookie, &bogus_tail);
+        cookie_options
+            .extend_from_slice(&cookie_option_bytes_with_tail(client_cookie, &bogus_tail));
+        let request_bytes =
+            a_query_with_edns_options(0x100b, "example.com", 4096, false, &cookie_options);
+
+        let outcome = service
+            .resolve(ResolveRequest::new_with_observed_source(
+                ObservedSourceEndpoint::tcp("192.0.2.10:5555".parse().unwrap(), None),
+                SystemTime::UNIX_EPOCH,
+                request_bytes,
+            ))
+            .await;
+
+        assert_eq!(outcome.decision.kind, ResolveDecisionKind::BackendFailure);
+        assert!(!upstream.requests.lock().unwrap().is_empty());
+    }
+
     /// RFC 1035 §4.1.1: RD=0 asks rdns not to pursue the query on the
     /// client's behalf. rdns has no authoritative-only mode with
     /// delegation data to hand back as a referral, so it implements this
diff --git a/tests/e2e_config_toml.rs b/tests/e2e_config_toml.rs
index 031e14a..36fdb83 100644
--- a/tests/e2e_config_toml.rs
+++ b/tests/e2e_config_toml.rs
@@ -965,6 +965,119 @@ async fn ad_bit_is_never_set_on_any_response() {
     server.shutdown().await;
 }
 
+/// Hand-built RFC 7873 COOKIE option TLV: an 8-byte client cookie plus a
+/// garbage (structurally well-formed but wrong) 16-byte server-cookie
+/// tail. Mirrors `cookie_option_bytes_with_tail` in
+/// `src/resolver/mod.rs`'s test module, re-derived here since that helper
+/// is private to its own crate module and not exported.
+fn tampered_cookie_option_bytes() -> Vec<u8> {
+    let mut out = Vec::with_capacity(4 + 8 + 16);
+    out.extend_from_slice(&10u16.to_be_bytes()); // COOKIE option code
+    out.extend_from_slice(&24u16.to_be_bytes()); // 8-byte client + 16-byte tail
+    out.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // client cookie
+    out.extend_from_slice(&[0xAAu8; 16]); // garbage server-cookie tail
+    out
+}
+
+// §B3 e2e test A: this is exactly the kind of behavior that's easy to get
+// right in a unit test against the check function but wrong in wiring
+// (e.g. forgetting to thread transport type through correctly) -- a
+// tampered server cookie sent over UDP to a real running server must be
+// rejected with BADCOOKIE (combined extended RCODE 23), and the response
+// must carry a well-formed 24-byte COOKIE option (RFC 7873 §4) echoing the
+// client cookie back, so a legitimate client can retry with a fresh
+// server cookie.
+#[tokio::test]
+async fn bad_server_cookie_over_udp_returns_badcookie_with_fresh_cookie() {
+    // Queries a name with no local-zone entry: `try_local_lookup` runs
+    // before `probe_cache` in `resolve()`'s pipeline, so a local-zone hit
+    // like `known-a.rdns.test` would short-circuit before the cookie check
+    // ever runs. A BADCOOKIE rejection never reaches the backend either
+    // way, so the upstream here only needs to exist, not actually answer.
+    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
+    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;
+
+    let request = RawQueryBuilder::new(0x2007, "cookie-check.rdns.test", 1)
+        .edns(1232, false)
+        .edns_options(tampered_cookie_option_bytes())
+        .build();
+    let response = send_udp(server.udp_addr, &request).await;
+    let message = parse_response(&response);
+
+    let opt = message
+        .additionals
+        .iter()
+        .find_map(|record| match &record.record {
+            RecordData::OPT(info) => Some(info),
+            _ => None,
+        })
+        .expect("expected an OPT record in the BADCOOKIE response");
+    let combined_extended_rcode =
+        (u16::from(opt.extended_rcode) << 4) | u16::from(message.header.r_code());
+    assert_eq!(combined_extended_rcode, 23, "23 == BADCOOKIE");
+    assert_eq!(
+        opt.options.len(),
+        4 + 8 + 16,
+        "well-formed COOKIE option: 4-byte TLV header + 8-byte client cookie + 16-byte server \
+         cookie"
+    );
+    assert_eq!(
+        &opt.options[0..2],
+        &10u16.to_be_bytes(),
+        "COOKIE option code"
+    );
+    assert_eq!(
+        &opt.options[2..4],
+        &24u16.to_be_bytes(),
+        "RFC 7873 COOKIE option length: 8-byte client + 16-byte server cookie"
+    );
+    assert_eq!(
+        &opt.options[4..12],
+        &[1, 2, 3, 4, 5, 6, 7, 8],
+        "client cookie must be echoed back unchanged"
+    );
+
+    server.shutdown().await;
+}
+
+// §B3 e2e test B: RFC 7873 §5.2.3's TCP carve-out -- the identical
+// tampered-cookie bytes from
+// `bad_server_cookie_over_udp_returns_badcookie_with_fresh_cookie` must be
+// processed normally (never BADCOOKIE) when sent over TCP instead,
+// proving the same tampered bytes get materially different treatment
+// purely based on transport.
+#[tokio::test]
+async fn bad_server_cookie_over_tcp_returns_normal_answer() {
+    // Same non-local-entry name as the UDP test above, but this time the
+    // query must actually reach the backend (TCP's carve-out means
+    // processing continues normally), so the upstream needs a real answer
+    // to hand back.
+    let (upstream_addr, _upstream_task) = spawn_canned_upstream(|id| {
+        a_response_from_upstream(id, "cookie-check.rdns.test", [203, 0, 113, 77])
+    })
+    .await;
+    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;
+
+    let request = RawQueryBuilder::new(0x2008, "cookie-check.rdns.test", 1)
+        .edns(1232, false)
+        .edns_options(tampered_cookie_option_bytes())
+        .build();
+    let response = send_tcp(server.tcp_addr, &request).await;
+    let message = parse_response(&response);
+
+    assert_eq!(
+        message.header.r_code(),
+        NOERROR,
+        "over TCP, a tampered server cookie must never trigger BADCOOKIE"
+    );
+    assert!(
+        !message.answers.is_empty(),
+        "processing must continue normally to a real answer, not short-circuit"
+    );
+
+    server.shutdown().await;
+}
+
 /// An NXDOMAIN response carrying a SOA record in the AUTHORITY section
 /// (RFC 2308 §2.2: the SOA's MINIMUM field lets a negative-caching
 /// resolver derive a negative-cache TTL for the name).
diff --git a/tests/support/mod.rs b/tests/support/mod.rs
index 16fd84e..617e4e6 100644
--- a/tests/support/mod.rs
+++ b/tests/support/mod.rs
@@ -568,6 +568,7 @@ pub struct RawQueryBuilder {
     qtype: u16,
     qclass: u16,
     edns: Option<(u16, bool)>,
+    edns_options: Option<Vec<u8>>,
     cd: bool,
 }
 
@@ -584,6 +585,7 @@ impl RawQueryBuilder {
             qtype,
             qclass: 1,
             edns: None,
+            edns_options: None,
             cd: false,
         }
     }
@@ -622,6 +624,14 @@ impl RawQueryBuilder {
         self
     }
 
+    /// Attaches raw EDNS option TLV bytes (e.g. a hand-built COOKIE option)
+    /// to the OPT record's RDATA. Requires `.edns(...)` to also have been
+    /// called -- the OPT record itself is still gated on `self.edns.is_some()`.
+    pub fn edns_options(mut self, options: Vec<u8>) -> Self {
+        self.edns_options = Some(options);
+        self
+    }
+
     pub fn cd(mut self, cd: bool) -> Self {
         self.cd = cd;
         self
@@ -671,7 +681,11 @@ impl RawQueryBuilder {
             // the low 16-bit flags half, i.e. 0x8000 of the full u32.
             let ext_flags: u32 = if dnssec_ok { 0x8000 } else { 0 };
             bytes.extend_from_slice(&ext_flags.to_be_bytes());
-            bytes.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
+            let rdlength = self.edns_options.as_ref().map_or(0, |o| o.len()) as u16;
+            bytes.extend_from_slice(&rdlength.to_be_bytes());
+            if let Some(options) = &self.edns_options {
+                bytes.extend_from_slice(options);
+            }
         }
 
         bytes
