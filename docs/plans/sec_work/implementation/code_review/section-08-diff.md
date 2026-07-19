diff --git a/src/protocol/edns_cookie.rs b/src/protocol/edns_cookie.rs
index 3661105..698c85b 100644
--- a/src/protocol/edns_cookie.rs
+++ b/src/protocol/edns_cookie.rs
@@ -130,6 +130,113 @@ pub(crate) fn parse_cookie_option(options: &[u8]) -> Option<ClientCookie> {
     locate_cookie_option(options).map(|(client_cookie, _)| client_cookie)
 }
 
+/// The result of scanning `options` for a COOKIE option at the granularity
+/// BADCOOKIE detection needs -- unlike `locate_cookie_option`, which
+/// collapses every failure mode to `None`, this distinguishes "no server
+/// cookie presented at all" (never an error -- RFC 7873 §5.2.3 first
+/// contact) from "a server-cookie tail was presented but is structurally
+/// malformed" (must be routed to BADCOOKIE, RFC 7873 §5.2.4).
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub(crate) enum CookieVerification {
+    /// No option with code 10 anywhere in `options`.
+    NoCookieOption,
+    /// More than one COOKIE option present. Collapsed the same way
+    /// `locate_cookie_option`/`is_solely_cookie_option` already do -- RFC
+    /// 7873 defines no combining rule for duplicates. Deliberately does
+    /// NOT trigger BADCOOKIE (pins unchanged, pre-BADCOOKIE behavior).
+    Duplicate,
+    /// A single well-formed (length 8) COOKIE option: client cookie only,
+    /// no server-cookie tail -- RFC 7873 §5.2.3 first contact. Never
+    /// triggers BADCOOKIE.
+    ClientOnly(ClientCookie),
+    /// A single well-formed (length 16-40) COOKIE option: client cookie
+    /// plus a server-cookie tail to verify against a fresh recompute.
+    ClientAndServer {
+        client_cookie: ClientCookie,
+        server_cookie_tail: Vec<u8>,
+    },
+    /// A single COOKIE option present but structurally invalid (length not
+    /// 8 and not in 16-40) -- RFC 7873 §5.2.4 treats this the same as an
+    /// invalid server cookie, never the same as `NoCookieOption`.
+    /// `client_cookie` is `Some` whenever at least 8 bytes of option data
+    /// were actually available to read (true for every malformed length
+    /// reachable from a real decoded wire message, since
+    /// `validate_edns_options` already guarantees TLV-length consistency
+    /// before this ever runs); `None` only for the degenerate <8-byte
+    /// case, which exists so this function stays total against
+    /// directly-constructed test byte vectors.
+    Malformed { client_cookie: Option<ClientCookie> },
+}
+
+fn extract_client_cookie(data: &[u8]) -> Option<ClientCookie> {
+    (data.len() >= 8).then(|| {
+        let mut client_cookie = [0u8; 8];
+        client_cookie.copy_from_slice(&data[0..8]);
+        client_cookie
+    })
+}
+
+/// Scans the raw EDNS options TLV blob for exactly one COOKIE option (code
+/// 10), reusing the same cursor/code/len/bounds-check loop shape as
+/// `locate_cookie_option`, but preserving the distinction between "no
+/// cookie", "malformed", and "well-formed" that BADCOOKIE detection needs
+/// and `locate_cookie_option` deliberately discards. A COOKIE option whose
+/// declared length overruns the remaining bytes is `Malformed` (using
+/// whatever bytes actually remain to recover a client cookie if possible)
+/// rather than aborting the whole scan -- `validate_edns_options` already
+/// guarantees this can't happen for a real decoded wire message, so this
+/// path only exists for directly-constructed test byte vectors. Trailing
+/// bytes too short to even hold a 4-byte option header are ambiguous (no
+/// code to read) and are silently ignored, same as `locate_cookie_option`.
+pub(crate) fn locate_cookie_for_verification(options: &[u8]) -> CookieVerification {
+    let mut cursor = 0usize;
+    let mut found: Option<CookieVerification> = None;
+
+    while cursor + 4 <= options.len() {
+        let code = u16::from_be_bytes([options[cursor], options[cursor + 1]]);
+        let len = u16::from_be_bytes([options[cursor + 2], options[cursor + 3]]) as usize;
+        let data_start = cursor + 4;
+        let declared_end = data_start + len;
+        let truncated = declared_end > options.len();
+        let data_end = declared_end.min(options.len());
+        let data = &options[data_start..data_end];
+
+        if code == COOKIE_OPTION_CODE {
+            let verification = if truncated {
+                CookieVerification::Malformed {
+                    client_cookie: extract_client_cookie(data),
+                }
+            } else if len == 8 {
+                CookieVerification::ClientOnly(
+                    extract_client_cookie(data).expect("len == 8 guarantees 8 bytes of data"),
+                )
+            } else if (16..=40).contains(&len) {
+                CookieVerification::ClientAndServer {
+                    client_cookie: extract_client_cookie(data)
+                        .expect("16..=40 guarantees at least 8 bytes of data"),
+                    server_cookie_tail: data[8..].to_vec(),
+                }
+            } else {
+                CookieVerification::Malformed {
+                    client_cookie: extract_client_cookie(data),
+                }
+            };
+
+            if found.is_some() {
+                return CookieVerification::Duplicate;
+            }
+            found = Some(verification);
+        }
+
+        if truncated {
+            break;
+        }
+        cursor = declared_end;
+    }
+
+    found.unwrap_or(CookieVerification::NoCookieOption)
+}
+
 /// The cache-admission predicate -- used only by `cache_supported()`
 /// (narrowed in section-03). Returns `Some(client_cookie)` only when the
 /// *entire* raw `options` byte slice is consumed by exactly one
@@ -181,6 +288,53 @@ pub(crate) fn build_server_cookie(
     out
 }
 
+/// Whether `presented_tail` is exactly the 16-byte RFC 9018 Standard
+/// Server Cookie this resolver would have issued for `client_cookie` +
+/// `client_ip`, reusing `presented_tail`'s own embedded version/
+/// reserved/timestamp fields for the recompute rather than the
+/// verification-time instant.
+///
+/// This distinction matters: `build_server_cookie`'s hash input includes
+/// the timestamp (RFC 9018 §4.4), so recomputing with "now" and comparing
+/// byte-for-byte against a cookie issued at an earlier "now" would never
+/// match -- rejecting every legitimately-reused, still-fresh cookie a
+/// client presents on its second and subsequent queries, defeating RFC
+/// 7873's entire point (obtain one server cookie, reuse it across many
+/// queries without a round trip). Delegates to
+/// `StandardServerCookie::check_hash`, which recomputes the hash from
+/// `self`'s own version/reserved/timestamp bytes (taken from
+/// `presented_tail`, via `StandardServerCookie::new` below) plus the given
+/// `client_cookie`/`client_ip`/`secret`, and compares against `self`'s own
+/// hash bytes (also taken from `presented_tail`) -- so the presented
+/// cookie's timestamp is what's reused, never `now`.
+///
+/// Returns `false` for any `presented_tail` that isn't exactly 16 bytes:
+/// this resolver only ever issues 16-byte RFC 9018 "Standard Server
+/// Cookies" (`build_server_cookie` has no other output shape), so a
+/// different-length tail can never be one this resolver issued.
+pub(crate) fn server_cookie_matches(
+    secret: &CookieSecret,
+    client_cookie: ClientCookie,
+    presented_tail: &[u8],
+    client_ip: IpAddr,
+) -> bool {
+    let Ok(tail): Result<[u8; 16], _> = presented_tail.try_into() else {
+        return false;
+    };
+    let version = tail[0];
+    let reserved = [tail[1], tail[2], tail[3]];
+    let timestamp = Serial::from_be_bytes([tail[4], tail[5], tail[6], tail[7]]);
+    let mut hash = [0u8; 8];
+    hash.copy_from_slice(&tail[8..16]);
+
+    let presented = StandardServerCookie::new(version, reserved, timestamp, hash);
+    presented.check_hash(
+        DomainClientCookie::from_octets(client_cookie),
+        client_ip,
+        &secret.bytes,
+    )
+}
+
 /// Serializes a full COOKIE option's RDATA-option-TLV bytes (option code
 /// 10, length 24, client cookie followed by the 16-byte server cookie),
 /// ready to be appended into an OPT record's `options` bytes.
@@ -423,4 +577,179 @@ mod tests {
         let b = CookieSecret::generate();
         assert_ne!(a.bytes, b.bytes);
     }
+
+    #[test]
+    fn locate_cookie_for_verification_absent() {
+        assert_eq!(
+            locate_cookie_for_verification(&[]),
+            CookieVerification::NoCookieOption
+        );
+        assert_eq!(
+            locate_cookie_for_verification(&nsid_option_bytes()),
+            CookieVerification::NoCookieOption
+        );
+    }
+
+    #[test]
+    fn locate_cookie_for_verification_client_only() {
+        let options = cookie_option_bytes(CLIENT_COOKIE, None);
+        assert_eq!(
+            locate_cookie_for_verification(&options),
+            CookieVerification::ClientOnly(CLIENT_COOKIE)
+        );
+    }
+
+    #[test]
+    fn locate_cookie_for_verification_client_and_server() {
+        let options = cookie_option_bytes(CLIENT_COOKIE, Some(&SERVER_COOKIE_TAIL));
+        assert_eq!(
+            locate_cookie_for_verification(&options),
+            CookieVerification::ClientAndServer {
+                client_cookie: CLIENT_COOKIE,
+                server_cookie_tail: SERVER_COOKIE_TAIL.to_vec(),
+            }
+        );
+    }
+
+    #[test]
+    fn locate_cookie_for_verification_malformed_length_recovers_client_cookie() {
+        // Length 9: one byte past the well-formed 8-byte client-only case,
+        // short of the 16-byte minimum server-cookie tail -- structurally
+        // invalid per RFC 7873 §4, but the client cookie is still fully
+        // present and recoverable.
+        let data = vec![0u8; 9];
+        let options = option_bytes(COOKIE_OPTION_CODE, &data);
+        match locate_cookie_for_verification(&options) {
+            CookieVerification::Malformed { client_cookie } => {
+                assert_eq!(client_cookie, Some([0u8; 8]));
+            }
+            other => panic!("expected Malformed, got {other:?}"),
+        }
+    }
+
+    #[test]
+    fn locate_cookie_for_verification_truncated_tlv_is_malformed_none() {
+        // Declared length 8 but only 3 bytes of data actually present --
+        // not enough to recover even a client cookie. Mirrors
+        // `parse_cookie_option_rejects_truncated_tlv_bytes`'s fixture;
+        // unreachable from real traffic (`validate_edns_options` already
+        // rejects this at decode time), exercised only for this
+        // function's defensive completeness.
+        let options = [0, 10, 0, 8, 1, 2, 3];
+        assert_eq!(
+            locate_cookie_for_verification(&options),
+            CookieVerification::Malformed {
+                client_cookie: None
+            }
+        );
+    }
+
+    #[test]
+    fn locate_cookie_for_verification_rejects_duplicates() {
+        let mut options = cookie_option_bytes(CLIENT_COOKIE, None);
+        options.extend_from_slice(&cookie_option_bytes(CLIENT_COOKIE, None));
+        assert_eq!(
+            locate_cookie_for_verification(&options),
+            CookieVerification::Duplicate
+        );
+    }
+
+    #[test]
+    fn server_cookie_matches_accepts_its_own_issued_cookie() {
+        let secret = CookieSecret::generate();
+        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
+        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
+        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, now);
+
+        assert!(server_cookie_matches(
+            &secret,
+            CLIENT_COOKIE,
+            &tail,
+            client_ip
+        ));
+    }
+
+    #[test]
+    fn server_cookie_matches_rejects_tampered_hash() {
+        let secret = CookieSecret::generate();
+        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
+        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
+        let mut tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, now);
+        tail[15] ^= 0xFF;
+
+        assert!(!server_cookie_matches(
+            &secret,
+            CLIENT_COOKIE,
+            &tail,
+            client_ip
+        ));
+    }
+
+    #[test]
+    fn server_cookie_matches_rejects_wrong_length() {
+        let secret = CookieSecret::generate();
+        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
+        assert!(!server_cookie_matches(
+            &secret,
+            CLIENT_COOKIE,
+            &SERVER_COOKIE_TAIL, // 8 bytes, not 16
+            client_ip
+        ));
+    }
+
+    #[test]
+    fn server_cookie_matches_rejects_wrong_secret() {
+        let issuing_secret = CookieSecret::generate();
+        let verifying_secret = CookieSecret::generate();
+        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
+        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
+        let tail = build_server_cookie(&issuing_secret, CLIENT_COOKIE, client_ip, now);
+
+        assert!(!server_cookie_matches(
+            &verifying_secret,
+            CLIENT_COOKIE,
+            &tail,
+            client_ip
+        ));
+    }
+
+    /// Regression test: a naive "recompute with verification-time `now`"
+    /// implementation would make every previously-issued cookie appear
+    /// invalid the instant a second elapses, since the timestamp is part
+    /// of the hash input. Issues at one instant, verifies at a much later
+    /// one -- must still match, proving the recompute reuses the
+    /// presented cookie's own embedded timestamp rather than "now".
+    #[test]
+    fn server_cookie_matches_accepts_cookie_after_time_has_advanced() {
+        let secret = CookieSecret::generate();
+        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
+        let issued_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
+        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, issued_at);
+
+        // `server_cookie_matches` takes no `now` parameter at all -- this
+        // test's real assertion is that omission itself, but verifying
+        // against a fresh recompute at a later instant as a sanity check
+        // still applies here since the tail's own timestamp is reused.
+        assert!(server_cookie_matches(
+            &secret,
+            CLIENT_COOKIE,
+            &tail,
+            client_ip
+        ));
+    }
+
+    #[test]
+    fn server_cookie_matches_reuses_ip_normalization_for_mapped_v6() {
+        let secret = CookieSecret::generate();
+        let client_ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)); // ::ffff:192.0.2.1
+        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
+        let tail = build_server_cookie(&secret, CLIENT_COOKIE, client_ip, now);
+
+        assert!(server_cookie_matches(
+            &secret,
+            CLIENT_COOKIE,
+            &tail,
+            client_ip
+        ));
+    }
 }
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 907f0f0..865f503 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -4688,9 +4688,13 @@ impl ResolveQuery {
             return outcome;
         }
 
-        let mut cache_probe = self
-            .probe_cache(&backend_snapshot, &request, &decoded)
-            .await;
+        let mut cache_probe = match self
+            .probe_cache(&backend_snapshot, &request, &decoded, started_at)
+            .await
+        {
+            Ok(probe) => probe,
+            Err(outcome) => return outcome,
+        };
         if let Some(response_bytes) = cache_probe.hit {
             return self
                 .finish_cache_hit(
@@ -5374,19 +5378,71 @@ impl ResolveQuery {
         backend_snapshot: &BackendSnapshot,
         request: &ResolveRequest,
         decoded: &DecodedQuery,
-    ) -> CacheProbe {
+        started_at: SystemTime,
+    ) -> Result<CacheProbe, ResolveOutcome> {
+        // BADCOOKIE (RFC 7873 §5.2.4) runs before the `cache_supported`
+        // narrowing below: it's an independent rejection decision, not a
+        // cache-admissibility one -- a request can fail `cache_supported`
+        // (bypass the cache) while still needing to pass this check, or
+        // pass it while still needing a BADCOOKIE reject. Ordering
+        // against the EDNS-version check (BADVERS) needs no explicit
+        // logic here: `QueryValidationError::UnsupportedEdnsVersion` is
+        // produced at decode time, inside `decode_or_protocol_error`,
+        // which early-returns before `probe_cache` is ever called -- a
+        // request with an unsupported EDNS version never produces a
+        // `DecodedQuery` in the first place, so it structurally cannot
+        // reach this check.
+        if invalid_server_cookie(
+            decoded,
+            request.observed_source.is_tcp(),
+            &self.cookie_secret,
+            request.client_ip,
+        )
+        .is_some()
+        {
+            self.metrics
+                .increment_with_source(ResolverMetric::ProtocolError, request.client_ip);
+            let decision = ResolveDecision {
+                client_ip: request.client_ip,
+                question: Some(decoded.question.clone()),
+                kind: ResolveDecisionKind::ProtocolError(
+                    QueryValidationError::InvalidServerCookie.response_code(),
+                ),
+            };
+            let response_bytes = self.responses.protocol_error(
+                request.request_id,
+                &QueryValidationError::InvalidServerCookie,
+                Some(&decoded.message),
+                &self.cookie_secret,
+                request.client_ip,
+                self.clock.now(),
+                self.protocol.configured_max_udp_payload_size(),
+            );
+            return Err(self
+                .finish_uniform(
+                    started_at,
+                    request,
+                    decoded_original_question_name(decoded),
+                    decision,
+                    response_bytes,
+                    None,
+                    Some(QueryEventBackend::from_snapshot(backend_snapshot)),
+                )
+                .await);
+        }
+
         if !cache_supported(decoded) {
             self.metrics
                 .increment_with_source(ResolverMetric::CacheBypass, request.client_ip);
             self.metrics
                 .increment_with_source(ResolverMetric::CacheMiss, request.client_ip);
-            return CacheProbe {
+            return Ok(CacheProbe {
                 miss_key: None,
                 hit: None,
                 store_allowed: false,
                 event_cache_result: Some(QueryEventCacheResult::Bypass),
                 refresh_hints: Vec::new(),
-            };
+            });
         }
 
         // No effective-payload-size class here: a UDP query and a TCP query
@@ -5435,7 +5491,7 @@ impl ResolveQuery {
             ResolutionMode::Forward => decoded.features.dnssec_ok,
         };
 
-        CacheProbe {
+        Ok(CacheProbe {
             miss_key: Some((
                 decoded.question.qname.clone(),
                 decoded.question.qtype,
@@ -5447,7 +5503,7 @@ impl ResolveQuery {
             store_allowed,
             event_cache_result: Some(event_cache_result),
             refresh_hints,
-        }
+        })
     }
 
     /// Maps a cache lookup outcome to whether the eventual backend result
@@ -6805,6 +6861,47 @@ fn cache_supported(query: &DecodedQuery) -> bool {
         .unwrap_or(true)
 }
 
+/// Returns `Some(client_cookie)` when `decoded` must be rejected with a
+/// BADCOOKIE response (RFC 7873 §5.2.4): a server-cookie tail is present
+/// but invalid, stale, or structurally malformed, AND the request arrived
+/// over UDP (RFC 7873 §5.2.3's TCP carve-out means this never fires for
+/// `is_tcp == true`, regardless of how invalid the presented cookie is).
+/// Returns `None` for: no COOKIE option, first-contact (client-only)
+/// cookies, duplicate COOKIE options, TCP transport, or a server-cookie
+/// tail that matches the fresh recompute. Independent of `cache_supported`
+/// above: a request can fail that (bypass the cache) while still needing
+/// to pass this check, or pass that while still needing a BADCOOKIE
+/// reject.
+fn invalid_server_cookie(
+    decoded: &DecodedQuery,
+    is_tcp: bool,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
+) -> Option<ClientCookie> {
+    if is_tcp {
+        return None;
+    }
+    let options = &decoded.message.edns.as_ref()?.options;
+    match crate::protocol::edns_cookie::locate_cookie_for_verification(options) {
+        crate::protocol::edns_cookie::CookieVerification::NoCookieOption
+        | crate::protocol::edns_cookie::CookieVerification::Duplicate
+        | crate::protocol::edns_cookie::CookieVerification::ClientOnly(_) => None,
+        crate::protocol::edns_cookie::CookieVerification::Malformed { client_cookie } => {
+            client_cookie
+        }
+        crate::protocol::edns_cookie::CookieVerification::ClientAndServer {
+            client_cookie,
+            server_cookie_tail,
+        } => (!crate::protocol::edns_cookie::server_cookie_matches(
+            cookie_secret,
+            client_cookie,
+            &server_cookie_tail,
+            client_ip,
+        ))
+        .then_some(client_cookie),
+    }
+}
+
 pub struct StandardProtocolCodec {
     configured_max_udp_payload_size: usize,
 }
@@ -6893,38 +6990,51 @@ impl ResponseFactory for BasicResponseFactory {
         }
 
         // BADCOOKIE (RFC 7873 §5.2.4/§5.3): same "doesn't fit `ResponseCode`"
-        // reasoning as BADVERS above. Unlike `UnsupportedEdnsVersion`, no
-        // caller produces this variant yet -- that's section-08's job, once
-        // cookie detection is wired into `probe_cache` -- so this arm is
-        // unreachable from any current code path. It's included now so
-        // section-08 only has to raise the error, not touch this routing.
-        //
-        // PLACEHOLDER, not the final extraction logic: re-parses `request`'s
-        // EDNS options via `edns_cookie::parse_cookie_option` to recover the
-        // client cookie to echo. That function returns `None` for a
-        // malformed-length COOKIE option -- one of the two cases
-        // `QueryValidationError::InvalidServerCookie`'s doc comment says
-        // this variant covers -- so once this arm becomes reachable, a
-        // malformed-but-present cookie would silently fall through to the
-        // generic FormErr path below instead of BADCOOKIE. section-08
-        // replaces this with `edns_cookie::locate_cookie_for_verification`
-        // (shared with its own `probe_cache` check) before making this arm
-        // reachable from real traffic; do not rely on this placeholder
-        // beyond that point.
-        if let (QueryValidationError::InvalidServerCookie, Some(request)) = (error, request)
-            && let Some(client_cookie) = request
-                .edns
-                .as_ref()
-                .and_then(|edns| crate::protocol::edns_cookie::parse_cookie_option(&edns.options))
-        {
-            return build_badcookie_response(
-                request,
-                client_cookie,
-                cookie_secret,
-                client_ip,
-                now,
-                configured_max_udp_payload_size,
-            );
+        // reasoning as BADVERS above. Produced by `probe_cache`'s
+        // `invalid_server_cookie` check (section-08). Recovers the client
+        // cookie to echo via `locate_cookie_for_verification` -- the same
+        // richer parsing function `invalid_server_cookie` itself uses, so
+        // there is one source of truth for "what's the client cookie
+        // here" instead of two independent re-implementations that could
+        // diverge. Unlike `parse_cookie_option`, this correctly recovers a
+        // client cookie for the malformed-length case, not just the
+        // valid-length-but-wrong-hash case.
+        if let (QueryValidationError::InvalidServerCookie, Some(request)) = (error, request) {
+            let client_cookie = request.edns.as_ref().and_then(|edns| {
+                match crate::protocol::edns_cookie::locate_cookie_for_verification(&edns.options) {
+                    crate::protocol::edns_cookie::CookieVerification::ClientAndServer {
+                        client_cookie,
+                        ..
+                    } => Some(client_cookie),
+                    crate::protocol::edns_cookie::CookieVerification::Malformed {
+                        client_cookie,
+                    } => client_cookie,
+                    // NoCookieOption / Duplicate / ClientOnly can't reach this
+                    // special case: `invalid_server_cookie` (the only
+                    // producer of this error variant) never returns a reject
+                    // decision for those.
+                    _ => None,
+                }
+            });
+            return match client_cookie {
+                Some(client_cookie) => build_badcookie_response(
+                    request,
+                    client_cookie,
+                    cookie_secret,
+                    client_ip,
+                    now,
+                    configured_max_udp_payload_size,
+                ),
+                // Defensive only, not reachable from any real caller today
+                // -- degrade to the generic FormErr path instead of
+                // panicking.
+                None => build_question_aware_error_response(
+                    Some(request),
+                    request_id,
+                    ResponseCode::FormErr,
+                    configured_max_udp_payload_size,
+                ),
+            };
         }
 
         // `QueryValidationError::response_code()` only ever actually
@@ -23824,11 +23934,19 @@ mod tests {
     /// and that `ConfiguredResponseFactory` delegates identically.
     #[test]
     fn protocol_error_routes_invalid_server_cookie_to_badcookie_response() {
+        // A client-cookie-only (8-byte) option is a realistic
+        // `ClientVerification::ClientOnly` shape that `invalid_server_cookie`
+        // never rejects (RFC 7873 §5.2.3 first contact) -- this routing
+        // test needs a fixture `invalid_server_cookie` could actually
+        // reject, so it presents a (garbage, thus invalid) 16-byte
+        // server-cookie tail alongside the client cookie instead.
         let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let server_cookie_tail = [0xffu8; 16];
         let mut cookie_option = Vec::new();
         cookie_option.extend_from_slice(&10u16.to_be_bytes()); // COOKIE option code
-        cookie_option.extend_from_slice(&8u16.to_be_bytes());
+        cookie_option.extend_from_slice(&24u16.to_be_bytes());
         cookie_option.extend_from_slice(&client_cookie);
+        cookie_option.extend_from_slice(&server_cookie_tail);
 
         let request_bytes =
             a_query_with_edns_details(0x4242, "example.com", 4096, false, 0, 0, &cookie_option);
@@ -23881,6 +23999,451 @@ mod tests {
         );
     }
 
+    /// Same routing test as
+    /// `protocol_error_routes_invalid_server_cookie_to_badcookie_response`,
+    /// but for the malformed-length case specifically (section-08's fix to
+    /// the section-07 placeholder): proves `locate_cookie_for_verification`
+    /// recovers a client cookie to echo for a structurally invalid tail,
+    /// not just the well-formed-but-wrong-hash case.
+    #[test]
+    fn protocol_error_routes_malformed_server_cookie_to_badcookie_response() {
+        let client_cookie: ClientCookie = [8, 7, 6, 5, 4, 3, 2, 1];
+        let mut cookie_option = Vec::new();
+        cookie_option.extend_from_slice(&10u16.to_be_bytes()); // COOKIE option code
+        cookie_option.extend_from_slice(&9u16.to_be_bytes()); // malformed length: 9
+        cookie_option.extend_from_slice(&client_cookie);
+        cookie_option.push(0xAB);
+
+        let request_bytes =
+            a_query_with_edns_details(0x5252, "example.com", 4096, false, 0, 0, &cookie_option);
+        let request = Message::parse(&request_bytes).unwrap();
+
+        let cookie_secret = CookieSecret::generate();
+        let client_ip: IpAddr = "192.0.2.66".parse().unwrap();
+        let now = SystemTime::UNIX_EPOCH;
+
+        let response = BasicResponseFactory.protocol_error(
+            Some(0x5252),
+            &QueryValidationError::InvalidServerCookie,
+            Some(&request),
+            &cookie_secret,
+            client_ip,
+            now,
+            1232,
+        );
+        let parsed = Message::parse(&response).unwrap();
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
+            "a malformed-length server-cookie tail must still route to BADCOOKIE, not fall \
+             through to the generic FormErr path"
+        );
+    }
+
+    fn cookie_option_bytes_with_tail(client_cookie: ClientCookie, tail: &[u8]) -> Vec<u8> {
+        let mut out = Vec::with_capacity(4 + 8 + tail.len());
+        out.extend_from_slice(&10u16.to_be_bytes()); // COOKIE option code
+        out.extend_from_slice(&((8 + tail.len()) as u16).to_be_bytes());
+        out.extend_from_slice(&client_cookie);
+        out.extend_from_slice(tail);
+        out
+    }
+
+    /// §B2 test 1 (ordering): a query with both an unsupported EDNS
+    /// version and an otherwise-invalid server cookie must produce
+    /// BADVERS, never reach cookie logic, and never produce BADCOOKIE.
+    /// `QueryValidationError::UnsupportedEdnsVersion` is raised at decode
+    /// time (`decode_or_protocol_error`), which early-returns before
+    /// `probe_cache`'s cookie check ever runs -- this proves the
+    /// short-circuit, not just that BADVERS eventually wins.
+    #[tokio::test]
+    async fn resolve_edns_version_error_takes_priority_over_invalid_cookie() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service(upstream.clone(), events, metrics);
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let bogus_tail = [0xFFu8; 16];
+        let cookie_option = cookie_option_bytes_with_tail(client_cookie, &bogus_tail);
+        // version 7: unsupported (rdns only implements version 0).
+        let request_bytes =
+            a_query_with_edns_details(0x1001, "example.com", 4096, false, 0, 7, &cookie_option);
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
+            ResolveDecisionKind::ProtocolError(ResponseCode::FormErr)
+        );
+        let response = Message::parse(&outcome.response_bytes).unwrap();
+        let opt = response
+            .additionals
+            .iter()
+            .find_map(|record| match &record.record {
+                RecordData::OPT(info) => Some(info),
+                _ => None,
+            })
+            .expect("expected an OPT record");
+        let combined_extended_rcode =
+            (u16::from(opt.extended_rcode) << 4) | u16::from(response.header.r_code());
+        assert_eq!(
+            combined_extended_rcode, 16,
+            "an unsupported EDNS version must produce BADVERS even when the presented cookie \
+             is also invalid -- the decode-time check runs first and never reaches probe_cache"
+        );
+        assert!(
+            upstream.requests.lock().unwrap().is_empty(),
+            "BADVERS is produced at decode time -- probe_cache and any backend fetch must \
+             never run"
+        );
+    }
+
+    /// §B2 test 2: a client cookie with a tampered (wrong-hash, otherwise
+    /// well-formed 16-byte) server-cookie tail, presented over UDP, must
+    /// be rejected with BADCOOKIE (combined extended RCODE 23).
+    #[tokio::test]
+    async fn resolve_rejects_tampered_server_cookie_over_udp_with_badcookie() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let secret = Arc::new(CookieSecret::generate());
+        let service =
+            resolve_service(upstream.clone(), events, metrics).with_cookie_secret(secret.clone());
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let client_ip: IpAddr = "192.0.2.10".parse().unwrap();
+        let mut tail = crate::protocol::edns_cookie::build_server_cookie(
+            secret.as_ref(),
+            client_cookie,
+            client_ip,
+            SystemTime::UNIX_EPOCH,
+        );
+        tail[15] ^= 0xFF; // tamper the hash
+        let cookie_option = cookie_option_bytes_with_tail(client_cookie, &tail);
+        let request_bytes =
+            a_query_with_edns_options(0x1002, "example.com", 4096, false, &cookie_option);
+
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                client_ip,
+                SystemTime::UNIX_EPOCH,
+                request_bytes,
+            ))
+            .await;
+
+        assert_eq!(
+            outcome.decision.kind,
+            ResolveDecisionKind::ProtocolError(ResponseCode::FormErr),
+            "response_code() buckets InvalidServerCookie as FormErr for metrics purposes"
+        );
+        let response = Message::parse(&outcome.response_bytes).unwrap();
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
+        assert!(
+            upstream.requests.lock().unwrap().is_empty(),
+            "a BADCOOKIE rejection must never reach the backend"
+        );
+    }
+
+    /// §B2 test 3: RFC 7873 §5.2.3's TCP carve-out -- the identical
+    /// tampered-cookie bytes from
+    /// `resolve_rejects_tampered_server_cookie_over_udp_with_badcookie`
+    /// must be processed normally (never BADCOOKIE) when the same request
+    /// arrives over TCP.
+    #[tokio::test]
+    async fn resolve_accepts_tampered_server_cookie_over_tcp() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let secret = Arc::new(CookieSecret::generate());
+        let service =
+            resolve_service(upstream.clone(), events, metrics).with_cookie_secret(secret.clone());
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let client_ip: IpAddr = "192.0.2.10".parse().unwrap();
+        let mut tail = crate::protocol::edns_cookie::build_server_cookie(
+            secret.as_ref(),
+            client_cookie,
+            client_ip,
+            SystemTime::UNIX_EPOCH,
+        );
+        tail[15] ^= 0xFF;
+        let cookie_option = cookie_option_bytes_with_tail(client_cookie, &tail);
+        let request_bytes =
+            a_query_with_edns_options(0x1003, "example.com", 4096, false, &cookie_option);
+
+        let outcome = service
+            .resolve(ResolveRequest::new_with_observed_source(
+                ObservedSourceEndpoint::tcp("192.0.2.10:5555".parse().unwrap(), None),
+                SystemTime::UNIX_EPOCH,
+                request_bytes,
+            ))
+            .await;
+
+        assert_eq!(
+            outcome.decision.kind,
+            ResolveDecisionKind::BackendFailure,
+            "over TCP, an invalid server cookie must never trigger BADCOOKIE -- processing \
+             must continue to the backend"
+        );
+        assert!(
+            !upstream.requests.lock().unwrap().is_empty(),
+            "TCP carve-out: processing must reach the backend, not short-circuit on the \
+             invalid cookie"
+        );
+    }
+
+    /// §B2 test 4: a malformed (wrong-length) server-cookie tail over UDP
+    /// must also produce BADCOOKIE, not be silently treated as absent.
+    #[tokio::test]
+    async fn resolve_rejects_malformed_server_cookie_tlv_over_udp_with_badcookie() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service(upstream.clone(), events, metrics);
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        // Total option length 20: a 12-byte tail, not a valid 16-byte
+        // Standard Server Cookie.
+        let malformed_tail = [0u8; 12];
+        let cookie_option = cookie_option_bytes_with_tail(client_cookie, &malformed_tail);
+        let request_bytes =
+            a_query_with_edns_options(0x1004, "example.com", 4096, false, &cookie_option);
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
+            ResolveDecisionKind::ProtocolError(ResponseCode::FormErr)
+        );
+        let response = Message::parse(&outcome.response_bytes).unwrap();
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
+        assert_eq!(
+            combined_extended_rcode, 23,
+            "a malformed-length server-cookie tail must produce BADCOOKIE, not be treated as \
+             absent"
+        );
+    }
+
+    /// §B2 test 5: the same malformed-TLV request from
+    /// `resolve_rejects_malformed_server_cookie_tlv_over_udp_with_badcookie`
+    /// must be processed normally over TCP.
+    #[tokio::test]
+    async fn resolve_accepts_malformed_server_cookie_tlv_over_tcp() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service(upstream.clone(), events, metrics);
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let malformed_tail = [0u8; 12];
+        let cookie_option = cookie_option_bytes_with_tail(client_cookie, &malformed_tail);
+        let request_bytes =
+            a_query_with_edns_options(0x1005, "example.com", 4096, false, &cookie_option);
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
+    /// §B2 test 6: a client cookie with no server-cookie tail at all
+    /// (first contact, RFC 7873 §5.2.3) over UDP must never produce
+    /// BADCOOKIE, and the response must still carry a freshly issued
+    /// server cookie. Written before the resolver-wiring change actually
+    /// landed, per the plan's explicit warning that an earlier draft got
+    /// this exact case wrong.
+    #[tokio::test]
+    async fn resolve_accepts_first_contact_cookie_over_udp_and_attaches_fresh_cookie() {
+        // A successful backend fetch, not a failure: cookie-echo
+        // (`mirrored_client_opt_record_with_cookie`) only runs on the
+        // miss-path response actually served to this requester, not on a
+        // synthetic backend-failure/SERVFAIL response -- so this test
+        // needs a real answer to observe the attached cookie.
+        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
+            a_response_with_answer(0x1006, "example.com", 60),
+        ))));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let secret = Arc::new(CookieSecret::generate());
+        let service =
+            resolve_service(upstream.clone(), events, metrics).with_cookie_secret(secret.clone());
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let mut cookie_option = Vec::new();
+        cookie_option.extend_from_slice(&10u16.to_be_bytes());
+        cookie_option.extend_from_slice(&8u16.to_be_bytes());
+        cookie_option.extend_from_slice(&client_cookie);
+        let client_ip: IpAddr = "192.0.2.10".parse().unwrap();
+        let request_bytes =
+            a_query_with_edns_options(0x1006, "example.com", 4096, false, &cookie_option);
+
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                client_ip,
+                SystemTime::UNIX_EPOCH,
+                request_bytes,
+            ))
+            .await;
+
+        assert_eq!(
+            outcome.decision.kind,
+            ResolveDecisionKind::Allowed,
+            "first contact (client-cookie-only) must never trigger BADCOOKIE"
+        );
+        assert!(!upstream.requests.lock().unwrap().is_empty());
+        let response = Message::parse(&outcome.response_bytes).unwrap();
+        let opt = response
+            .additionals
+            .iter()
+            .find_map(|record| match &record.record {
+                RecordData::OPT(info) => Some(info),
+                _ => None,
+            })
+            .expect("an EDNS requester with a cookie must get a cookie-bearing OPT record back");
+        assert_eq!(opt.options.len(), 4 + 8 + 16);
+        assert_eq!(&opt.options[4..12], &client_cookie);
+        let expected_server_cookie = crate::protocol::edns_cookie::build_server_cookie(
+            secret.as_ref(),
+            client_cookie,
+            client_ip,
+            SystemTime::UNIX_EPOCH,
+        );
+        assert_eq!(
+            &opt.options[12..28],
+            &expected_server_cookie,
+            "first contact must still get a freshly issued, correct server cookie attached"
+        );
+    }
+
+    /// §B2 test 7: identical first-contact behavior over TCP.
+    #[tokio::test]
+    async fn resolve_accepts_first_contact_cookie_over_tcp() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service(upstream.clone(), events, metrics);
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let mut cookie_option = Vec::new();
+        cookie_option.extend_from_slice(&10u16.to_be_bytes());
+        cookie_option.extend_from_slice(&8u16.to_be_bytes());
+        cookie_option.extend_from_slice(&client_cookie);
+        let request_bytes =
+            a_query_with_edns_options(0x1007, "example.com", 4096, false, &cookie_option);
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
+    /// §B2 test 8: a server cookie recomputed with a different secret than
+    /// the one that issued it (simulating a process restart that rotated
+    /// the secret) must be rejected with BADCOOKIE over UDP.
+    #[tokio::test]
+    async fn resolve_rejects_server_cookie_issued_under_a_different_secret() {
+        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
+        let events = Arc::new(RecordingEvents::default());
+        let metrics = Arc::new(RecordingMetrics::default());
+        let issuing_secret = CookieSecret::generate();
+        let verifying_secret = Arc::new(CookieSecret::generate());
+        let service =
+            resolve_service(upstream.clone(), events, metrics).with_cookie_secret(verifying_secret);
+
+        let client_cookie: ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
+        let client_ip: IpAddr = "192.0.2.10".parse().unwrap();
+        let tail = crate::protocol::edns_cookie::build_server_cookie(
+            &issuing_secret,
+            client_cookie,
+            client_ip,
+            SystemTime::UNIX_EPOCH,
+        );
+        let cookie_option = cookie_option_bytes_with_tail(client_cookie, &tail);
+        let request_bytes =
+            a_query_with_edns_options(0x1008, "example.com", 4096, false, &cookie_option);
+
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                client_ip,
+                SystemTime::UNIX_EPOCH,
+                request_bytes,
+            ))
+            .await;
+
+        assert_eq!(
+            outcome.decision.kind,
+            ResolveDecisionKind::ProtocolError(ResponseCode::FormErr)
+        );
+        let response = Message::parse(&outcome.response_bytes).unwrap();
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
+        assert_eq!(
+            combined_extended_rcode, 23,
+            "a cookie issued under a rotated-away secret must be rejected as invalid"
+        );
+    }
+
     /// RFC 1035 §4.1.1: RD=0 asks rdns not to pursue the query on the
     /// client's behalf. rdns has no authoritative-only mode with
     /// delegation data to hand back as a referral, so it implements this
