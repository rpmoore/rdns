diff --git a/src/protocol/mod.rs b/src/protocol/mod.rs
index a113006..e838079 100644
--- a/src/protocol/mod.rs
+++ b/src/protocol/mod.rs
@@ -13,10 +13,10 @@
 // limitations under the License.
 
 use std::collections::{HashMap, HashSet};
-use std::net::{Ipv4Addr, Ipv6Addr};
+use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
 use std::ops::Range;
 use std::str;
-use std::time::Duration;
+use std::time::{Duration, SystemTime};
 
 use bytes::Bytes;
 use serde::Serialize;
@@ -71,6 +71,16 @@ pub enum QueryValidationError {
     UnsupportedEdnsVersion {
         version: u8,
     },
+    /// RFC 7873 §5.2.4/§5.3, RFC 9018 §5: the query presented a server
+    /// cookie (the tail of its COOKIE option after the 8-byte client
+    /// cookie) that is either malformed (wrong length/truncated TLV) or
+    /// fails the recompute-and-compare check against a freshly derived
+    /// server cookie -- either way the query must be answered BADCOOKIE
+    /// (extended RCODE 23), not treated as a generic FORMERR -- see
+    /// `build_badcookie_response`. Does NOT cover the case of no server
+    /// cookie at all (client cookie only, or no cookie option): that is
+    /// not an error (see section-08's detection logic).
+    InvalidServerCookie,
 }
 
 impl From<DnsParseError> for QueryValidationError {
@@ -109,13 +119,15 @@ impl QueryValidationError {
     /// Coarse classifier used for metrics/event bucketing
     /// (`ResolveDecisionKind::ProtocolError`) -- `ResponseCode` only models
     /// the header's 4-bit RCODE field, so it cannot represent BADVERS
-    /// (extended RCODE 16, split across the header's RCODE nibble and the
-    /// OPT record's extended-RCODE byte). `UnsupportedEdnsVersion` is
-    /// bucketed here as `FormErr` for that reason; the actual wire response
-    /// is still correctly BADVERS -- see
-    /// `resolver::BasicResponseFactory::protocol_error`, which special-cases
-    /// this variant before ever consulting `response_code()`, and
-    /// `build_badvers_response`.
+    /// (extended RCODE 16) or BADCOOKIE (extended RCODE 23), both split
+    /// across the header's RCODE nibble and the OPT record's
+    /// extended-RCODE byte. `UnsupportedEdnsVersion` and
+    /// `InvalidServerCookie` are both bucketed here as `FormErr` for that
+    /// reason; the actual wire response is still correctly BADVERS/
+    /// BADCOOKIE -- see `resolver::BasicResponseFactory::protocol_error`,
+    /// which special-cases both variants before ever consulting
+    /// `response_code()`, and `build_badvers_response`/
+    /// `build_badcookie_response`.
     pub fn response_code(&self) -> ResponseCode {
         match self {
             Self::UnsupportedOpcode { .. } => ResponseCode::NotImp,
@@ -124,7 +136,8 @@ impl QueryValidationError {
             | Self::UnexpectedSectionRecords { .. }
             | Self::InvalidEdns
             | Self::NotQuery
-            | Self::UnsupportedEdnsVersion { .. } => ResponseCode::FormErr,
+            | Self::UnsupportedEdnsVersion { .. }
+            | Self::InvalidServerCookie => ResponseCode::FormErr,
         }
     }
 }
@@ -653,6 +666,78 @@ pub fn build_badvers_response(
     response
 }
 
+/// Builds a BADCOOKIE response (RFC 7873 §5.2.4/§5.3, RFC 9018 §5:
+/// extended RCODE 23) for a query whose presented server cookie is invalid
+/// or malformed. Mirrors `build_badvers_response`'s shape (mirrored
+/// question, CD copied from `request`, always exactly one OPT record --
+/// this response only ever exists because `request` had a cookie option in
+/// the first place) with two differences: the header's own RCODE nibble is
+/// `7`, not `NoError`'s `0` (BADCOOKIE = 23 = `(1 << 4) | 7`, vs. BADVERS =
+/// 16 = `(1 << 4) | 0` -- see `QueryValidationError::InvalidServerCookie`'s
+/// doc comment), and the OPT record's `options` carry a freshly issued,
+/// correct server cookie (RFC 9018 §4.4) rather than being empty, so the
+/// client can retry with a cookie the resolver will accept.
+///
+/// `client_cookie` is taken as an explicit parameter rather than
+/// re-extracted from `request`: by the time this is called (from
+/// section-08's cookie-detection logic), the caller has already parsed and
+/// validated cookie-shape information as part of deciding to reject in the
+/// first place.
+///
+/// `write_message_header` can't be used here: it composes the header's
+/// RCODE nibble from a `ResponseCode`, and no `ResponseCode` variant maps
+/// to `7` (`ResponseCode` is deliberately never extended with
+/// extended-RCODE-only values -- see `response_code()`'s doc comment), so
+/// the flag bits are composed manually below, mirroring
+/// `write_message_header`'s own bit layout exactly.
+pub fn build_badcookie_response(
+    request: &Message,
+    client_cookie: edns_cookie::ClientCookie,
+    cookie_secret: &edns_cookie::CookieSecret,
+    client_ip: IpAddr,
+    now: SystemTime,
+    configured_max_udp_payload_size: usize,
+) -> Vec<u8> {
+    const BADCOOKIE_RCODE_NIBBLE: u8 = 7;
+
+    let mut response = Vec::new();
+    let question_count = u16::from(!request.questions.is_empty());
+    let dnssec_ok = request.edns.as_ref().is_some_and(|edns| edns.dnssec_ok);
+    let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
+
+    let server_cookie =
+        edns_cookie::build_server_cookie(cookie_secret, client_cookie, client_ip, now);
+    let options = edns_cookie::build_cookie_option(client_cookie, server_cookie);
+    let opt = build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 1, options);
+
+    write_u16(&mut response, request.header.id);
+    let mut flags = 0x8000; // QR = 1 (response)
+    if request.header.rd() {
+        flags |= 0x0100;
+    }
+    // truncated = false
+    // authoritative = false: synthetic local response, never authoritative
+    flags |= 0x0080; // RA = 1
+    // authenticated_data = false
+    if request.header.cd() {
+        flags |= 0x0010;
+    }
+    flags |= BADCOOKIE_RCODE_NIBBLE as u16;
+    write_u16(&mut response, flags);
+    write_u16(&mut response, question_count);
+    write_u16(&mut response, 0); // answer_count
+    write_u16(&mut response, 0); // authority_count
+    write_u16(&mut response, 1); // additional_count (the OPT record)
+
+    if let Some(question) = request.questions.first() {
+        let mut compressor = NameCompressor::new();
+        write_question(&mut response, &mut compressor, question);
+    }
+    write_opt_record(&mut response, &opt);
+
+    response
+}
+
 pub fn build_a_block_response(
     request: &Message,
     ipv4: Ipv4Addr,
@@ -4174,6 +4259,145 @@ mod tests {
         );
     }
 
+    fn cookie_option_bytes(client_cookie: edns_cookie::ClientCookie) -> Vec<u8> {
+        let mut out = Vec::with_capacity(4 + client_cookie.len());
+        out.extend_from_slice(&10u16.to_be_bytes()); // COOKIE option code
+        out.extend_from_slice(&(client_cookie.len() as u16).to_be_bytes());
+        out.extend_from_slice(&client_cookie);
+        out
+    }
+
+    /// RFC 7873 §5.2.4/§5.3, RFC 9018 §5: BADCOOKIE is extended RCODE 23,
+    /// split across the header's 4-bit RCODE field (the low nibble, which
+    /// must be 7 here) and the OPT record's 8-bit extended-RCODE byte
+    /// (which must be 1). Asserts the *combined* value rather than either
+    /// half in isolation, mirroring
+    /// `build_badvers_response_encodes_extended_rcode_and_mirrors_opt_and_cd`'s
+    /// rationale.
+    #[test]
+    fn build_badcookie_response_encodes_extended_rcode_and_mirrors_opt_and_cd() {
+        let client_cookie: edns_cookie::ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let mut request = Vec::new();
+        push_header_with_flags(&mut request, 0x0110, 1, 0, 0, 1); // RD=1, CD=1
+        push_question(&mut request, "example.com", 1, 1);
+        push_opt_record_with_version(
+            &mut request,
+            4096,
+            true,
+            0,
+            &cookie_option_bytes(client_cookie),
+        );
+        let request = Message::parse(&request).unwrap();
+        assert!(request.header.cd());
+
+        let secret = edns_cookie::CookieSecret::generate();
+        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
+        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
+        let configured_max_udp_payload_size = 700;
+
+        let response = Message::parse(&build_badcookie_response(
+            &request,
+            client_cookie,
+            &secret,
+            client_ip,
+            now,
+            configured_max_udp_payload_size,
+        ))
+        .unwrap();
+
+        assert_eq!(response.header.id, request.header.id);
+        assert_eq!(response.questions[0], request.questions[0]);
+        assert!(
+            response.header.cd(),
+            "CD must be copied from the request per RFC 4035 §3.2.2"
+        );
+
+        let opt = response
+            .additionals
+            .iter()
+            .find_map(|record| match &record.record {
+                RecordData::OPT(info) => Some(info),
+                _ => None,
+            })
+            .expect("expected an OPT record in the BADCOOKIE response");
+        let combined_extended_rcode =
+            (u16::from(opt.extended_rcode) << 4) | u16::from(response.header.r_code());
+        assert_eq!(combined_extended_rcode, 23, "23 == BADCOOKIE");
+        assert_eq!(
+            opt.udp_payload_size, 700,
+            "OPT must advertise this responder's own UDP payload size"
+        );
+    }
+
+    /// Proves the attached cookie is the real, freshly issued one, not a
+    /// stub/zeroed value: the OPT record's COOKIE option server-cookie half
+    /// must equal `build_server_cookie` computed independently with the
+    /// same inputs.
+    #[test]
+    fn build_badcookie_response_attaches_fresh_server_cookie() {
+        let client_cookie: edns_cookie::ClientCookie = [8, 7, 6, 5, 4, 3, 2, 1];
+        let mut request = Vec::new();
+        push_header(&mut request, 1, 0, 0, 1);
+        push_question(&mut request, "example.com", 1, 1);
+        push_opt_record_with_version(
+            &mut request,
+            4096,
+            false,
+            0,
+            &cookie_option_bytes(client_cookie),
+        );
+        let request = Message::parse(&request).unwrap();
+
+        let secret = edns_cookie::CookieSecret::generate();
+        let client_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
+        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100);
+
+        let response_bytes =
+            build_badcookie_response(&request, client_cookie, &secret, client_ip, now, 1232);
+        let response = Message::parse(&response_bytes).unwrap();
+
+        let opt = response
+            .additionals
+            .iter()
+            .find_map(|record| match &record.record {
+                RecordData::OPT(info) => Some(info),
+                _ => None,
+            })
+            .expect("expected an OPT record in the BADCOOKIE response");
+
+        assert_eq!(
+            opt.options.len(),
+            4 + 8 + 16,
+            "COOKIE option TLV header + client + server cookie"
+        );
+        assert_eq!(
+            &opt.options[0..2],
+            &10u16.to_be_bytes(),
+            "COOKIE option code"
+        );
+        assert_eq!(
+            &opt.options[4..12],
+            &client_cookie,
+            "client cookie must be echoed"
+        );
+
+        let expected_server_cookie =
+            edns_cookie::build_server_cookie(&secret, client_cookie, client_ip, now);
+        assert_eq!(
+            &opt.options[12..28],
+            &expected_server_cookie,
+            "attached server cookie must be the real, freshly issued one"
+        );
+    }
+
+    #[test]
+    fn invalid_server_cookie_buckets_to_form_err() {
+        assert_eq!(
+            QueryValidationError::InvalidServerCookie.response_code(),
+            ResponseCode::FormErr
+        );
+    }
+
     #[test]
     fn build_sinkhole_a_response_serializes_answer() {
         let mut request = Vec::new();
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 2d6666e..bb3eaba 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -34,10 +34,10 @@ pub use crate::protocol::edns_cookie::ClientCookie;
 use crate::protocol::{
     Message, NameCompressor, QueryDecodeFailure, QueryValidationError, Record, RecordData,
     ResponseCode, build_a_answers_response, build_a_block_response, build_aaaa_answers_response,
-    build_aaaa_block_response, build_badvers_response, build_nodata_response,
-    build_nxdomain_response, build_question_aware_error_response, build_refused_response,
-    build_servfail_response, build_txt_answer_response, message_question_wire, rewrite_response_id,
-    rewrite_response_request_fields,
+    build_aaaa_block_response, build_badcookie_response, build_badvers_response,
+    build_nodata_response, build_nxdomain_response, build_question_aware_error_response,
+    build_refused_response, build_servfail_response, build_txt_answer_response,
+    message_question_wire, rewrite_response_id, rewrite_response_request_fields,
 };
 // Re-exported (not just used privately): `src/main.rs` is a separate
 // binary crate and must construct one via `CookieSecret::generate()` to
@@ -4773,6 +4773,9 @@ impl ResolveQuery {
                     request_id,
                     &error,
                     recovered_message.as_deref(),
+                    &self.cookie_secret,
+                    request.client_ip,
+                    self.clock.now(),
                     self.protocol.configured_max_udp_payload_size(),
                 );
                 Err(self
@@ -6866,6 +6869,9 @@ impl ResponseFactory for BasicResponseFactory {
         request_id: Option<u16>,
         error: &QueryValidationError,
         request: Option<&Message>,
+        cookie_secret: &CookieSecret,
+        client_ip: IpAddr,
+        now: SystemTime,
         configured_max_udp_payload_size: usize,
     ) -> Vec<u8> {
         // BADVERS (RFC 6891 §6.1.3) doesn't fit `ResponseCode` (a plain
@@ -6886,6 +6892,35 @@ impl ResponseFactory for BasicResponseFactory {
             return build_badvers_response(request, configured_max_udp_payload_size);
         }
 
+        // BADCOOKIE (RFC 7873 §5.2.4/§5.3): same "doesn't fit `ResponseCode`"
+        // reasoning as BADVERS above. Unlike `UnsupportedEdnsVersion`, no
+        // caller produces this variant yet -- that's section-08's job, once
+        // cookie detection is wired into `probe_cache` -- so this arm is
+        // unreachable from any current code path. It's included now so
+        // section-08 only has to raise the error, not touch this routing.
+        // `QueryValidationError::InvalidServerCookie` carries no fields (the
+        // "invalid" and "malformed" cases share one variant -- see its doc
+        // comment), so the already-known-present client cookie is
+        // re-extracted here via `edns_cookie::parse_cookie_option`; this is
+        // sound because, by construction, this variant only ever occurs
+        // when a query had a client cookie in the first place (no cookie at
+        // all can't produce this error).
+        if let (QueryValidationError::InvalidServerCookie, Some(request)) = (error, request)
+            && let Some(client_cookie) = request
+                .edns
+                .as_ref()
+                .and_then(|edns| crate::protocol::edns_cookie::parse_cookie_option(&edns.options))
+        {
+            return build_badcookie_response(
+                request,
+                client_cookie,
+                cookie_secret,
+                client_ip,
+                now,
+                configured_max_udp_payload_size,
+            );
+        }
+
         // `QueryValidationError::response_code()` only ever actually
         // returns `FormErr` or `NotImp`; `ServFail`/`Refused`/`NxDomain`/
         // `NoError` are unreachable here today (kept only so this match
@@ -6959,12 +6994,18 @@ impl ResponseFactory for ConfiguredResponseFactory {
         request_id: Option<u16>,
         error: &QueryValidationError,
         request: Option<&Message>,
+        cookie_secret: &CookieSecret,
+        client_ip: IpAddr,
+        now: SystemTime,
         configured_max_udp_payload_size: usize,
     ) -> Vec<u8> {
         BasicResponseFactory.protocol_error(
             request_id,
             error,
             request,
+            cookie_secret,
+            client_ip,
+            now,
             configured_max_udp_payload_size,
         )
     }
@@ -9133,11 +9174,20 @@ pub trait ResponseFactory: Send + Sync {
     /// failed for a reason other than the wire format itself being
     /// unparseable (e.g. an unsupported opcode). It's `None` only when the
     /// packet genuinely couldn't be parsed at all.
+    ///
+    /// `cookie_secret`, `client_ip`, and `now` exist only for
+    /// `QueryValidationError::InvalidServerCookie`'s BADCOOKIE response
+    /// (`build_badcookie_response`), which must attach a freshly issued
+    /// server cookie -- every other variant ignores them.
+    #[allow(clippy::too_many_arguments)]
     fn protocol_error(
         &self,
         request_id: Option<u16>,
         error: &QueryValidationError,
         request: Option<&Message>,
+        cookie_secret: &CookieSecret,
+        client_ip: IpAddr,
+        now: SystemTime,
         configured_max_udp_payload_size: usize,
     ) -> Vec<u8>;
 
@@ -23758,6 +23808,73 @@ mod tests {
         assert!(upstream.requests.lock().unwrap().is_empty());
     }
 
+    /// `QueryValidationError::InvalidServerCookie` is not yet producible by
+    /// any real caller (that's section-08's job, once cookie detection is
+    /// wired into `probe_cache`), so this exercises `protocol_error`
+    /// directly rather than through a full `service.resolve(...)` --
+    /// matching how `query_validation_errors_map_to_response_codes` tests
+    /// `response_code()` directly in `protocol::tests`. Proves the special
+    /// case is actually reached (a BADCOOKIE response), not just defined,
+    /// and that `ConfiguredResponseFactory` delegates identically.
+    #[test]
+    fn protocol_error_routes_invalid_server_cookie_to_badcookie_response() {
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let mut cookie_option = Vec::new();
+        cookie_option.extend_from_slice(&10u16.to_be_bytes()); // COOKIE option code
+        cookie_option.extend_from_slice(&8u16.to_be_bytes());
+        cookie_option.extend_from_slice(&client_cookie);
+
+        let request_bytes =
+            a_query_with_edns_details(0x4242, "example.com", 4096, false, 0, 0, &cookie_option);
+        let request = Message::parse(&request_bytes).unwrap();
+
+        let cookie_secret = CookieSecret::generate();
+        let client_ip: IpAddr = "192.0.2.55".parse().unwrap();
+        let now = SystemTime::UNIX_EPOCH;
+
+        let basic_response = BasicResponseFactory.protocol_error(
+            Some(0x4242),
+            &QueryValidationError::InvalidServerCookie,
+            Some(&request),
+            &cookie_secret,
+            client_ip,
+            now,
+            1232,
+        );
+        let parsed = Message::parse(&basic_response).unwrap();
+        let opt = parsed
+            .additionals
+            .iter()
+            .find_map(|record| match &record.record {
+                RecordData::OPT(info) => Some(info),
+                _ => None,
+            })
+            .expect("expected an OPT record in the BADCOOKIE response");
+        let combined_extended_rcode =
+            (u16::from(opt.extended_rcode) << 4) | u16::from(parsed.header.r_code());
+        assert_eq!(
+            combined_extended_rcode, 23,
+            "23 == BADCOOKIE -- InvalidServerCookie must route to build_badcookie_response, \
+             not the generic FormErr path"
+        );
+
+        let configured_response = ConfiguredResponseFactory::new(BlockResponseConfig::default())
+            .unwrap()
+            .protocol_error(
+                Some(0x4242),
+                &QueryValidationError::InvalidServerCookie,
+                Some(&request),
+                &cookie_secret,
+                client_ip,
+                now,
+                1232,
+            );
+        assert_eq!(
+            basic_response, configured_response,
+            "ConfiguredResponseFactory must delegate identically to BasicResponseFactory"
+        );
+    }
+
     /// RFC 1035 §4.1.1: RD=0 asks rdns not to pursue the query on the
     /// client's behalf. rdns has no authoritative-only mode with
     /// delegation data to hand back as a referral, so it implements this
