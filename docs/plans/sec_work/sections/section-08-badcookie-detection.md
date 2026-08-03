# Section 08: BADCOOKIE Detection and Transport-Conditional Gating

## Purpose

Implement the actual BADCOOKIE decision: recompute what this resolver would have issued as a server cookie for an incoming request's client cookie + source IP, compare it against whatever server-cookie tail the request presents, and reject over UDP (never over TCP) when it doesn't match or is structurally malformed. This is Track B's second section — it corresponds to plan section **B2** in `claude-plan.md` and the "B2. BADCOOKIE detection and transport-conditional gating" block in `claude-plan-tdd.md` (plus the parts of B3's unit-test list in `claude-plan.md` that TDD's own B2 section already subsumes — TDD explicitly notes "B2's tests above already cover the core matrix").

This section makes the plumbing section-07 built (the `InvalidServerCookie` error variant, `build_badcookie_response`, and `ResponseFactory::protocol_error`'s special case) reachable from a real client request for the first time. Before this section, nothing in the codebase can actually produce a BADCOOKIE response; after it, an invalid or malformed server cookie presented over UDP gets one.

## Dependencies

**section-07-badcookie-wire-rcode** (must land first). This section calls, and in one place completes, plumbing section-07 built:

- `crate::protocol::build_badcookie_response(request, client_cookie, cookie_secret, client_ip, now, configured_max_udp_payload_size) -> Vec<u8>` — the BADCOOKIE wire-response builder (`src/protocol/mod.rs`, after `build_badvers_response`).
- `QueryValidationError::InvalidServerCookie` — the new unit variant covering "server-cookie tail present but invalid/stale" and "server-cookie tail present but structurally malformed," bucketed to `ResponseCode::FormErr` via `response_code()` (`src/protocol/mod.rs`).
- `ResponseFactory::protocol_error`'s extended signature — now takes `cookie_secret: &edns_cookie::CookieSecret`, `client_ip: std::net::IpAddr`, and `now: std::time::SystemTime` in addition to its original parameters (`src/resolver/mod.rs`, `ResponseFactory` trait + both `BasicResponseFactory`/`ConfiguredResponseFactory` implementations).
- `BasicResponseFactory::protocol_error`'s `InvalidServerCookie` special case — section-07 left the exact client-cookie-extraction mechanism at this call site as an open decision ("the exact mechanism ... is acceptable here ... Document this reasoning inline"). **This section resolves that decision** (see "Fixing the extraction gap" below) since it's the first section to make this code path reachable from real traffic, where getting the extraction wrong would either panic or silently drop the malformed-cookie case.

Do not duplicate section-07's content here; read `docs/plans/sec_work/sections/section-07-badcookie-wire-rcode.md` (or the equivalent already-landed code) for the exact shapes of the above.

No dependency on Track A (DNSSEC). Can run in parallel with section-02.

## Background context

### Where this plugs in: `probe_cache`

`src/resolver/mod.rs:5228-5307`, `ResolveQuery::probe_cache`:

```rust
async fn probe_cache(
    &self,
    backend_snapshot: &BackendSnapshot,
    request: &ResolveRequest,
    decoded: &DecodedQuery,
) -> CacheProbe {
    if !cache_supported(decoded) {
        self.metrics.increment_with_source(ResolverMetric::CacheBypass, request.client_ip);
        self.metrics.increment_with_source(ResolverMetric::CacheMiss, request.client_ip);
        return CacheProbe { miss_key: None, hit: None, store_allowed: false,
            event_cache_result: Some(QueryEventCacheResult::Bypass), refresh_hints: Vec::new() };
    }
    // ... cache lookup, evaluate_cache_lookup, MissKey construction ...
    CacheProbe { miss_key: Some((...)), hit, store_allowed, event_cache_result: Some(event_cache_result), refresh_hints }
}
```

Called from exactly one place, `ResolveQuery::resolve` (`:4550-4552`):

```rust
let mut cache_probe = self.probe_cache(&backend_snapshot, &request, &decoded).await;
if let Some(response_bytes) = cache_probe.hit { ... }
```

`resolve`'s pipeline up to this point: `decode_or_protocol_error` → `try_policy_block` → `try_chaos_lookup` → `try_local_lookup` → `probe_cache`. The first four stages already establish the "helper returns `Option<ResolveOutcome>` or `Result<T, ResolveOutcome>`, caller does `if let`/`match` and returns early" pattern this section reuses. `decode_or_protocol_error` (`:4610-4650`) is the closest structural precedent: it returns `Result<DecodedQuery, ResolveOutcome>`, builds a `ResolveDecision { kind: ResolveDecisionKind::ProtocolError(error.response_code()), .. }`, calls `self.responses.protocol_error(...)`, and wraps the response bytes via `self.finish_uniform(...)`.

**This section changes `probe_cache`'s return type** from `CacheProbe` to `Result<CacheProbe, ResolveOutcome>`, and adds a `started_at: SystemTime` parameter (already computed in `resolve` at `:4496`, just not currently threaded into `probe_cache`). The new BADCOOKIE check runs as the very first thing inside `probe_cache`, before the existing `if !cache_supported(decoded)` line (`:5234`) — this is the plan's explicit ordering requirement ("invoked from `probe_cache` before the `cache_supported(decoded)` branch"). `resolve`'s one call site becomes:

```rust
let mut cache_probe = match self.probe_cache(&backend_snapshot, &request, &decoded, started_at).await {
    Ok(probe) => probe,
    Err(outcome) => return outcome,
};
```

`probe_cache` is a private method with exactly one call site and no test constructs `CacheProbe` by name directly (it's a private struct), so this signature change has no ripple beyond `resolve`'s one call site.

### Why this check doesn't need to worry about EDNS-version ordering explicitly

The plan calls out "this check must run only *after* the existing EDNS-version check (which produces BADVERS) has already passed." In this codebase, `QueryValidationError::UnsupportedEdnsVersion` is produced by `Message::parse_standard_query`/`parse_standard_query_owned_with_recovery` itself (`src/protocol/mod.rs:2099`) — i.e. at **decode time**, inside `decode_or_protocol_error`, which runs and can early-return *before* `probe_cache` is ever called at all (`resolve`'s pipeline, above). A request with an unsupported EDNS version never produces a `DecodedQuery` in the first place, so it structurally cannot reach `probe_cache`'s cookie check. The ordering requirement is therefore already satisfied by the existing pipeline shape — this section does not need to add any explicit ordering logic, just a test proving it (see Tests, test 1).

### `cache_supported` — the narrowing this check sits in front of

`src/resolver/mod.rs:6526-6540`:

```rust
fn cache_supported(query: &DecodedQuery) -> bool {
    query.message.edns.as_ref().map(|edns| {
        edns.extended_rcode == 0
            && edns.version == 0
            && (edns.flags & !EDNS_DO_FLAG) == 0
            && (edns.options.is_empty()
                || crate::protocol::edns_cookie::is_solely_cookie_option(&edns.options).is_some())
    }).unwrap_or(true)
}
```

This function is unrelated to BADCOOKIE and must not be modified by this section (the plan explicitly prefers "a sibling function ... rather than overloading `cache_supported`'s existing meaning"). It governs cache *admissibility*, not BADCOOKIE rejection — a request can fail this (bypass the cache) while still being processed normally, or can pass this while still needing a BADCOOKIE reject. The two checks are independent and both run inside `probe_cache`, cookie check first.

### `ObservedSourceEndpoint::is_tcp()` — transport is already available

`src/resolver/mod.rs:111-158`. `ResolveRequest.observed_source: ObservedSourceEndpoint` carries `transport: Option<QueryTransport>` (`Udp`/`Tcp`), and `is_tcp()` (`:156-158`) returns `true` only for an explicit `QueryTransport::Tcp`. `probe_cache` already receives `request: &ResolveRequest`, so `request.observed_source.is_tcp()` is available with no new parameter — this is the exact same expression already used at `:5183` and `:5442` for the existing truncation-eligibility check, confirming the plan's assumption ("confirm `probe_cache`/its callers already know UDP-vs-TCP") holds without any new threading.

### `edns_cookie.rs` — what exists today and what this section adds

`src/protocol/edns_cookie.rs` (full file — read it before starting; it's short). Key existing pieces:

- `ClientCookie = [u8; 8]` (`:38`).
- `CookieSecret` (`:56-68`) — process-lifetime secret, `Arc<CookieSecret>` held at `ResolveQuery.cookie_secret` (`:4073`), accessible as `&self.cookie_secret` from any `ResolveQuery` method (deref-coerces to `&CookieSecret`).
- `locate_cookie_option(options: &[u8]) -> Option<(ClientCookie, bool)>` (`:75-111`, **file-private**, not `pub(crate)`) — scans the raw EDNS options TLV blob for exactly one well-formed (length 8, or 16-40) COOKIE option (code 10), returning the first 8 bytes as the client cookie and whether it was the sole option present. Returns `None` uniformly for: no COOKIE option, a malformed length, a duplicate COOKIE option, or a truncated TLV — it cannot distinguish these cases from each other, which is exactly the granularity B2 needs and `parse_cookie_option`/`is_solely_cookie_option` (both built on top of it) don't expose.
- `parse_cookie_option(options: &[u8]) -> Option<ClientCookie>` (`:129-131`, `pub(crate)`) — used by `QueryFeatures::from_message` to populate `decoded.features.client_cookie`.
- `is_solely_cookie_option(options: &[u8]) -> Option<ClientCookie>` (`:144-147`, `pub(crate)`) — used by `cache_supported`.
- `build_server_cookie(secret: &CookieSecret, client_cookie: ClientCookie, client_ip: IpAddr, now: SystemTime) -> [u8; 16]` (`:158-182`, `pub(crate)`) — computes the RFC 9018 §4.4 16-byte server cookie: byte 0 = version (always `1`), bytes 1-3 = reserved (always `0,0,0`), bytes 4-7 = big-endian Unix timestamp built from `now`, bytes 8-15 = SipHash-2-4 output over `client_cookie | version | reserved | timestamp | client_ip`, keyed by `secret`. Delegates to `domain::base::opt::cookie::StandardServerCookie::calculate`.
- `build_cookie_option(client_cookie: ClientCookie, server_cookie: [u8; 16]) -> Vec<u8>` (`:187-194`, `pub(crate)`) — serializes the full COOKIE option TLV.

Note `parse_opt_record`/`validate_edns_options` (`src/protocol/mod.rs:2689-2723`) already guarantee, at decode time, that every EDNS option's declared length fits within the available bytes — a genuinely truncated-TLV COOKIE option (declared length overruns the buffer) cannot reach `probe_cache` from a real wire message. `locate_cookie_option`'s truncation guard is defensive and only exercised by hand-built byte-vector unit tests (matching `edns_cookie.rs`'s existing `parse_cookie_option_rejects_truncated_tlv_bytes` test). The only malformed-length case reachable from real traffic is a COOKIE option whose declared length is 8, and one that isn't 8 or in 16-40 (e.g. 9, 15, 41) — i.e. a client cookie with garbage bytes tacked on in a size the spec doesn't define.

### The critical correctness detail: recompute-and-compare must reuse the *presented* timestamp, not "now"

`build_server_cookie`'s hash input includes the timestamp (RFC 9018 §4.4: `Client Cookie | Version | Reserved | Timestamp | Client-IP`). **Recomputing with the verification-time `now` and comparing byte-for-byte against a cookie issued at an earlier `now` will never match** — the timestamp field alone guarantees a mismatch for any cookie older than the current second, which would make BADCOOKIE fire on every legitimately-reused, still-fresh cookie a client presents on its second and subsequent queries. That would defeat RFC 7873's entire point (a client obtains one server cookie and reuses it across many queries without a round trip).

The correct recompute-and-compare therefore must:
1. Extract the 4-byte big-endian timestamp embedded in the *presented* server-cookie tail (bytes `[4..8]` of a 16-byte tail — same offset `build_server_cookie` writes it to, `edns_cookie.rs:179`).
2. Recompute via `build_server_cookie(secret, client_cookie, client_ip, extracted_time)`, using the presented cookie's own timestamp, not the current instant.
3. Compare the full 16-byte recomputed output against the presented tail byte-for-byte.

A presented tail whose length isn't exactly 16 can never match (this resolver only ever issues 16-byte RFC 9018 "Standard Server Cookies" — `build_server_cookie` has no other output shape), so those short-circuit to "invalid" without attempting extraction. This also means every unit test in this section that expects a match (e.g. the IPv4-mapped-IPv6 test, or a "valid, unmodified" cookie round-trip) must issue the cookie via `build_server_cookie` at some fixed `now`, then verify at a *different* `now` to prove the comparison isn't accidentally relying on the verification instant matching the issuance instant.

Before writing `edns_cookie.rs`'s recompute-and-compare function, check whether `domain::base::opt::cookie::StandardServerCookie` (the type `build_server_cookie` already constructs via `::calculate`) exposes a direct verification helper (e.g. something that takes the presented 16 bytes plus inputs and returns whether they're internally consistent) — if so, prefer it over hand-slicing the timestamp out of the byte array. If no such helper exists (check via `cargo doc --open -p domain` or docs.rs for the installed `0.12.1` version), implement the byte-slice-and-recompute approach described above; it's a small, well-contained function and this repo already reassembles/deconstructs this exact 16-byte layout by hand in `build_server_cookie` itself.

### Fixing the extraction gap in `BasicResponseFactory::protocol_error`

Section-07's `InvalidServerCookie` special case in `BasicResponseFactory::protocol_error` (`src/resolver/mod.rs`, near `:6600-6645`) was left as a placeholder that re-parses `request`'s EDNS options via `edns_cookie::parse_cookie_option` to recover the client cookie to echo. That function returns `None` for exactly the malformed-length case this section must route to BADCOOKIE — so the placeholder cannot be used as-is once this section makes the path reachable (it would either panic on an `.expect()` or silently produce the wrong response for a malformed-but-present cookie).

This section fixes that special case to use the same richer parsing function (see next section) that the new `probe_cache` check itself uses, so there is one source of truth for "what's the client cookie to echo here" instead of two independent re-implementations:

```rust
if let (QueryValidationError::InvalidServerCookie, Some(request)) = (error, request) {
    let client_cookie = request
        .edns
        .as_ref()
        .and_then(|edns| match edns_cookie::locate_cookie_for_verification(&edns.options) {
            edns_cookie::CookieVerification::ClientAndServer { client_cookie, .. } => Some(client_cookie),
            edns_cookie::CookieVerification::Malformed { client_cookie } => client_cookie,
            // NoCookieOption / Duplicate / ClientOnly can't reach this special
            // case: `probe_cache`'s check (the only producer of this error
            // variant) never returns a reject decision for those.
            _ => None,
        });
    return match client_cookie {
        Some(client_cookie) => build_badcookie_response(
            request, client_cookie, cookie_secret, client_ip, now, configured_max_udp_payload_size,
        ),
        // Defensive only, not reachable from any real caller today --
        // degrade to the generic FormErr path instead of panicking.
        None => build_question_aware_error_response(
            Some(request), request_id, ResponseCode::FormErr, configured_max_udp_payload_size,
        ),
    };
}
```

(`ConfiguredResponseFactory::protocol_error` already delegates straight through to `BasicResponseFactory::protocol_error` per section-07 — no change needed there.)

## Implementation

Files to modify:

- `/home/rpmoore/code/rdns/src/protocol/edns_cookie.rs` — new `CookieVerification` enum, `locate_cookie_for_verification`, and the recompute-and-compare function.
- `/home/rpmoore/code/rdns/src/resolver/mod.rs` — new sibling check function near `cache_supported`, `probe_cache`'s signature/return-type change and new reject branch, `resolve`'s one call-site update, and the `BasicResponseFactory::protocol_error` fix described above.

Steps:

1. **`edns_cookie.rs`: `CookieVerification` enum and `locate_cookie_for_verification`** (`pub(crate)`, alongside `locate_cookie_option`). Reuse the same TLV-scanning loop shape as `locate_cookie_option` (`:75-111`) — same cursor/code/len/bounds-check structure — but instead of collapsing every failure mode to `None`, distinguish:
   ```rust
   pub(crate) enum CookieVerification {
       /// No option with code 10 anywhere in `options`.
       NoCookieOption,
       /// More than one COOKIE option present. Collapsed the same way
       /// `locate_cookie_option`/`is_solely_cookie_option` already do --
       /// RFC 7873 defines no combining rule for duplicates. Deliberately
       /// does NOT trigger BADCOOKIE (see B3/section-09's duplicate test,
       /// which pins this as unchanged, pre-BADCOOKIE behavior).
       Duplicate,
       /// A single well-formed (length 8) COOKIE option: client cookie
       /// only, no server-cookie tail -- RFC 7873 §5.2.3 first contact.
       /// Never triggers BADCOOKIE.
       ClientOnly(ClientCookie),
       /// A single well-formed (length 16-40) COOKIE option: client
       /// cookie plus a server-cookie tail to verify against a fresh
       /// recompute.
       ClientAndServer { client_cookie: ClientCookie, server_cookie_tail: Vec<u8> },
       /// A single COOKIE option present but structurally invalid (length
       /// not 8 and not in 16-40) -- RFC 7873 §5.2.4 treats this the same
       /// as an invalid server cookie, never the same as `NoCookieOption`.
       /// `client_cookie` is `Some` whenever at least 8 bytes of option
       /// data were actually available to read (true for every malformed
       /// length reachable from a real decoded wire message, since
       /// `validate_edns_options` already guarantees TLV-length
       /// consistency before this ever runs); `None` only for the
       /// degenerate <8-byte case, which exists so this function stays
       /// total against directly-constructed test byte vectors.
       Malformed { client_cookie: Option<ClientCookie> },
   }

   pub(crate) fn locate_cookie_for_verification(options: &[u8]) -> CookieVerification { ... }
   ```
2. **`edns_cookie.rs`: recompute-and-compare function**, e.g.:
   ```rust
   /// Whether `presented_tail` is exactly the 16-byte RFC 9018 Standard
   /// Server Cookie this resolver would have issued for `client_cookie` +
   /// `client_ip`, reusing `presented_tail`'s own embedded timestamp for
   /// the recompute (not the verification-time instant -- see this
   /// section's background notes on why using "now" would reject every
   /// legitimately-reused cookie).
   pub(crate) fn server_cookie_matches(
       secret: &CookieSecret,
       client_cookie: ClientCookie,
       presented_tail: &[u8],
       client_ip: IpAddr,
   ) -> bool { ... }
   ```
3. **New sibling check function** in `src/resolver/mod.rs`, near `cache_supported` (`:6526`), e.g.:
   ```rust
   /// Returns `Some(client_cookie)` when `decoded` must be rejected with a
   /// BADCOOKIE response: a server-cookie tail is present but invalid,
   /// stale, or structurally malformed, AND the request arrived over UDP
   /// (RFC 7873 §5.2.3's TCP carve-out means this never fires for `is_tcp
   /// == true`, regardless of how invalid the presented cookie is).
   /// Returns `None` for: no COOKIE option, first-contact (client-only)
   /// cookies, duplicate COOKIE options, TCP transport, or a
   /// server-cookie tail that matches the fresh recompute.
   fn invalid_server_cookie(
       decoded: &DecodedQuery,
       is_tcp: bool,
       cookie_secret: &CookieSecret,
       client_ip: IpAddr,
   ) -> Option<ClientCookie> {
       if is_tcp {
           return None;
       }
       let options = &decoded.message.edns.as_ref()?.options;
       match crate::protocol::edns_cookie::locate_cookie_for_verification(options) {
           CookieVerification::NoCookieOption
           | CookieVerification::Duplicate
           | CookieVerification::ClientOnly(_) => None,
           CookieVerification::Malformed { client_cookie } => client_cookie,
           CookieVerification::ClientAndServer { client_cookie, server_cookie_tail } => {
               (!crate::protocol::edns_cookie::server_cookie_matches(
                   cookie_secret, client_cookie, &server_cookie_tail, client_ip,
               ))
               .then_some(client_cookie)
           }
       }
   }
   ```
4. **`probe_cache` signature and reject branch** (`:5228-5307`): change the return type to `Result<CacheProbe, ResolveOutcome>`, add a `started_at: SystemTime` parameter, wrap both existing return points (`:5239-5245` and the trailing `CacheProbe { .. }` at `:5294-5306`) in `Ok(...)`, and add the new check as the first statement in the function body:
   ```rust
   if let Some(client_cookie) = invalid_server_cookie(
       decoded, request.observed_source.is_tcp(), &self.cookie_secret, request.client_ip,
   ) {
       self.metrics.increment_with_source(ResolverMetric::ProtocolError, request.client_ip);
       let decision = ResolveDecision {
           client_ip: request.client_ip,
           question: Some(decoded.question.clone()),
           kind: ResolveDecisionKind::ProtocolError(
               QueryValidationError::InvalidServerCookie.response_code(),
           ),
       };
       let response_bytes = self.responses.protocol_error(
           request.request_id,
           &QueryValidationError::InvalidServerCookie,
           Some(&decoded.message),
           &self.cookie_secret,
           request.client_ip,
           self.clock.now(),
           self.protocol.configured_max_udp_payload_size(),
       );
       return Err(self.finish_uniform(
           started_at, request, decoded_original_question_name(decoded),
           decision, response_bytes, None,
           Some(QueryEventBackend::from_snapshot(backend_snapshot)),
       ).await);
   }
   if !cache_supported(decoded) { ... } // unchanged body, now returns Ok(CacheProbe { .. })
   ```
   The exact parameter order for `self.responses.protocol_error(...)` must match whatever order section-07 chose when it extended the trait signature — confirm against the landed `ResponseFactory` trait definition rather than assuming the order shown above.
5. **`resolve`'s call site** (`:4550-4552`): pass `started_at` and handle the `Result`:
   ```rust
   let mut cache_probe = match self.probe_cache(&backend_snapshot, &request, &decoded, started_at).await {
       Ok(probe) => probe,
       Err(outcome) => return outcome,
   };
   ```
6. **Fix `BasicResponseFactory::protocol_error`'s `InvalidServerCookie` special case** as described in Background above, replacing section-07's placeholder extraction with `locate_cookie_for_verification`-based extraction.

## Tests

Write these in `src/protocol/edns_cookie.rs`'s `#[cfg(test)] mod tests` (parsing/recompute-function-level tests, hand-built byte vectors, matching the existing `parse_cookie_option_rejects_malformed_lengths`/`_rejects_truncated_tlv_bytes`/`_rejects_duplicates` style) and `src/resolver/mod.rs`'s test module (full `service.resolve(...)` end-to-end tests, matching `resolve_protocol_error_for_unsupported_edns_version_returns_badvers`'s style — construct via `a_query_with_edns_options(id, name, udp_payload_size, dnssec_ok, options)`, wrap in `ResolveRequest::new(...)` for UDP-equivalent default transport or `ResolveRequest::new_with_observed_source(ObservedSourceEndpoint::tcp(addr, None), ...)` for TCP, and assert on `outcome.decision.kind`/`Message::parse(&outcome.response_bytes)`). These are stubs — prose descriptions of what each test asserts, not full test code.

Directly from `claude-plan-tdd.md` §B2 (this section's core matrix):

1. **Ordering**: a request with both an unsupported EDNS version (e.g. version 7, mirroring `a_query_with_edns_details`'s BADVERS test setup) and an otherwise-invalid server cookie must produce BADVERS (`ResolveDecisionKind::ProtocolError(ResponseCode::FormErr)` with combined extended RCODE 16), never reach cookie logic, and never produce a BADCOOKIE response — proving the decode-time short-circuit, not just that BADVERS eventually wins.
2. Client cookie + tampered server cookie (valid 16-byte length, wrong hash bytes) + UDP → BADCOOKIE (combined extended RCODE 23, per the wire-split assertion style already established in section-07's tests).
3. Same tampered-cookie request over TCP (`ObservedSourceEndpoint::tcp(...)`) → normal processing, no BADCOOKIE, per §5.2.3's carve-out.
4. Client cookie + malformed (wrong-length, e.g. total option length 20 with a 12-byte tail, or length 9) server-cookie TLV + UDP → BADCOOKIE, not silently treated as absent.
5. Same malformed-TLV request over TCP → normal processing.
6. Client cookie + no server-cookie tail at all (first contact, option length 8) + UDP → normal processing with a freshly issued cookie attached in the response, explicitly **not** BADCOOKIE. Write this test before implementing the first-contact carve-out, not after (per the plan's explicit warning that this is exactly the case an earlier draft got wrong).
7. Same first-contact case + TCP → identical normal-processing behavior.
8. Server cookie recomputed with a different secret (construct two `CookieSecret`s, issue the presented cookie with one, verify with a service configured via `with_cookie_secret` using the other — simulating a process restart that rotated the secret) + UDP → BADCOOKIE.
9. IPv4-mapped IPv6 source address (`::ffff:192.0.2.1`-shaped `IpAddr::V6`) with an otherwise-valid server cookie → accepted, no BADCOOKIE. Derive the test's expected/presented cookie via `build_server_cookie` called with that exact mapped-V6 `client_ip`, not a separately-written comparison — this proves `invalid_server_cookie`/`server_cookie_matches` reuse the same code path issuance uses rather than re-deriving address handling, per the plan's IP-normalization-reuse requirement.

Additional tests this section should add (not explicitly itemized in the TDD doc but required by the design decisions above, since they're load-bearing correctness properties, not just wiring):

10. **Timestamp-reuse regression test**: issue a valid server cookie via `build_server_cookie` at one `SystemTime`, then verify it (via `server_cookie_matches` directly, or end-to-end with the service's clock advanced) at a *later* `SystemTime` — must still match. This is the test that would catch a naive "recompute with verification-time `now`" implementation, which would make every previously-issued cookie appear invalid.
11. **`locate_cookie_for_verification` unit tests** in `edns_cookie.rs`, mirroring the existing hand-built-byte-vector tests: absent COOKIE option → `NoCookieOption`; well-formed client-only → `ClientOnly`; well-formed client+16-byte-tail → `ClientAndServer`; length 9 → `Malformed { client_cookie: Some(_) }` (client cookie still recoverable); a directly-constructed truncated-TLV byte vector → `Malformed { client_cookie: None }`; duplicate COOKIE options → `Duplicate`.
12. **`BasicResponseFactory::protocol_error`'s fixed `InvalidServerCookie` special case**, for the malformed-length input specifically (not just the already-tested-in-section-07 valid-length-but-wrong-hash input) — proving the fix actually recovers a client cookie to echo rather than panicking or falling through to the generic FormErr path.

## Verification gates

Per this repo's standing rules (`RUST.md`), before considering this section done:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets` — pay attention to the `probe_cache` signature change not leaving any stale callers, and to `CookieVerification`'s match arms in both `invalid_server_cookie` and the fixed `protocol_error` special case being exhaustive.
- `cargo test` — full suite, including all tests above. Confirm no existing cookie-echo test (e.g. `resolve_coalesced_miss_gives_each_requester_a_distinct_cookie`, or the query-features extraction tests at `:9146-9180`) changes behavior — this section only adds a new *rejection* path in front of previously-unconditional cookie processing; every currently-passing well-formed-cookie or no-cookie request must still resolve exactly as before.

## Acceptance criteria

- `edns_cookie::CookieVerification` and `locate_cookie_for_verification` exist, distinguish no-option / duplicate / client-only / client-and-server / malformed (with best-effort client-cookie recovery), and are covered by direct byte-vector unit tests.
- `edns_cookie::server_cookie_matches` recomputes using the *presented* cookie's own embedded timestamp, not the verification-time instant, and is covered by a regression test proving a still-valid, previously-issued cookie is accepted after time has advanced.
- `probe_cache` runs the new BADCOOKIE check before its existing `cache_supported` branch, rejects only over UDP, and both of its existing return points now produce `Ok(CacheProbe { .. })`; `resolve`'s one call site handles the `Result`.
- A client cookie with an invalid, stale, or malformed server-cookie tail produces a real BADCOOKIE response (combined extended RCODE 23) over UDP via `service.resolve(...)`, and normal processing (no BADCOOKIE) over TCP for the identical bytes.
- A client cookie with no server-cookie tail at all (first contact) never produces BADCOOKIE on either transport, and still gets a freshly issued cookie attached to its response.
- A request with both an unsupported EDNS version and an invalid server cookie produces BADVERS, never BADCOOKIE.
- `BasicResponseFactory::protocol_error`'s `InvalidServerCookie` special case no longer relies on `parse_cookie_option` (which silently returns `None` for the malformed case this section makes reachable); it uses `locate_cookie_for_verification` and degrades to a generic FormErr response (never panics) in the defensive, believed-unreachable case where no client cookie is recoverable at all.
- All tests listed above exist and pass; no existing cookie-echo or non-cookie resolve test changes behavior.

## Implementation notes (actual)

Implemented as planned. `CookieVerification`/`locate_cookie_for_verification`/`server_cookie_matches` landed in `src/protocol/edns_cookie.rs`; `invalid_server_cookie`, `probe_cache`'s `Result<CacheProbe, ResolveOutcome>` signature change and reject branch, `resolve`'s call-site update, and the `BasicResponseFactory::protocol_error` extraction fix all landed in `src/resolver/mod.rs`, exactly as specified.

One deviation from the plan's literal example code: `server_cookie_matches` recovers the presented tail's version/reserved/timestamp/hash via `StandardServerCookie::new(...)` and calls its `check_hash(...)` method (found by checking `domain` 0.12.2's cookie module, per the plan's own suggestion to look for a direct verification helper before hand-rolling byte-slicing) rather than manually recomputing via `build_server_cookie` with an extracted timestamp and comparing byte-for-byte. Same effect (recompute reuses the presented cookie's own timestamp, not "now"), less code.

Code review (`section-08-review.md`) found two actionable gaps, both auto-fixed:
- `server_cookie_matches` didn't explicitly reject a non-1 version byte before hashing (RFC 9018 §4.3) — added an explicit check, even though forging a matching hash under a different version would already require the secret.
- Test-matrix item 9 (IPv4-mapped IPv6) was only unit-tested against `server_cookie_matches` directly, not proven end to end through `ResolveRequest.client_ip` → `probe_cache` → `invalid_server_cookie`. Added `resolve_accepts_valid_cookie_from_mapped_ipv6_client` in `src/resolver/mod.rs`.

Tests: all 12 items from the plan's test list are covered — items 1-9 and the mapped-v6 addition as full `service.resolve(...)` end-to-end tests in `src/resolver/mod.rs`; items 10-11 (timestamp-reuse regression, `locate_cookie_for_verification` unit tests) and the version-check regression in `src/protocol/edns_cookie.rs`; item 12 (fixed `protocol_error` extraction for the malformed case) as `protocol_error_routes_malformed_server_cookie_to_badcookie_response`.

Verification: `cargo fmt --all -- --check`, `cargo clippy --all-targets`, `cargo test --lib` (764 passed, 0 failed, 3 ignored) all clean.

## Summary for the parent agent

I read `docs/plans/sec_work/claude-plan.md` (§B1-B3), `docs/plans/sec_work/claude-plan-tdd.md` (Track B), `docs/plans/sec_work/sections/index.md`, the already-generated `docs/plans/sec_work/sections/section-07-badcookie-wire-rcode.md` (dependency), and the relevant portions of `/home/rpmoore/code/rdns/src/resolver/mod.rs` and `/home/rpmoore/code/rdns/src/protocol/edns_cookie.rs` to ground the section in real signatures/line numbers.

The section content has been written to `/home/rpmoore/code/rdns/docs/plans/sec_work/sections/section-08-badcookie-detection.md` (via the SubagentStop hook, from the markdown body above).

One substantive design point I resolved that the source plan left ambiguous, worth the parent agent's awareness: the plan's "recompute what this server would have issued ... and compare" phrasing, taken literally with the verification-time `now`, would make every previously-issued cookie appear invalid the instant a second elapses (since the timestamp is part of the hash input) — defeating RFC 7873's persistent-cookie design. I specified that the recompute must reuse the *presented* cookie's own embedded timestamp instead, and added an explicit regression test requirement for this. I also resolved section-07's deliberately-left-open question of how `BasicResponseFactory::protocol_error`'s `InvalidServerCookie` special case recovers the client cookie to echo (its placeholder used a function that returns `None` for the malformed-cookie case this section makes reachable) by having both the new `probe_cache` check and that special case share one richer parsing function (`edns_cookie::locate_cookie_for_verification`), avoiding duplicated/divergent parsing logic and a latent panic/silent-fallback bug.