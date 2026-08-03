# Section 07: BADCOOKIE Wire-Level RCODE 23 Support

## Purpose

Teach the wire-response layer to represent RCODE 23 (BADCOOKIE, RFC 7873 §5.2.4/§5.3) and add the plumbing needed to answer with it: a new response builder mirroring the existing BADVERS builder, a new `QueryValidationError` variant with its own metrics bucketing, and a `protocol_error` special case that routes to the new builder. This is Track B's first section — it corresponds to plan section **B1** in `claude-plan.md` and the "B1. Wire-level RCODE 23 support" block in `claude-plan-tdd.md`.

This section does **not** implement the actual cookie-comparison/detection logic (recomputing what the server cookie should be and deciding invalid-vs-first-contact) — that is section-08. This section only builds the tools section-08 will call: given "this request's server cookie is invalid," produce the correct wire bytes and route the right error type to the right builder. No code in this section is reachable from a real request yet; every test here constructs the new error variant directly and exercises the builder/routing plumbing in isolation.

## Dependencies

None. This is the first section in Track B and has no prerequisites. It can run in parallel with section-01 (Track A's first section) — the two tracks touch disjoint files (Track B touches `src/protocol/mod.rs`, `src/protocol/edns_cookie.rs`, `src/resolver/mod.rs`'s `BasicResponseFactory`/`ConfiguredResponseFactory`/`ResponseFactory` trait/`ResolveQuery`; Track A touches `Cargo.toml`, `src/config/mod.rs`, and new `src/resolver/dnssec_validation.rs`-style modules).

## Background context

### The problem: `ResponseCode` only models RCODE 0-5

`ResponseCode` (`src/protocol/mod.rs:92-100`) is the header's plain 4-bit RCODE field:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}
```

RFC 6891 §6.1.3 extends RCODE to 12 bits for EDNS-capable responses: the low 4 bits still live in the header's RCODE nibble, but the upper 8 bits live in the OPT record's own extended-RCODE byte. BADVERS (16) and BADCOOKIE (23) both require values that don't fit in the header nibble alone, so `ResponseCode` cannot represent either directly. BADVERS already solved this — Track B replicates that exact pattern instead of inventing a new one.

**Important extended-RCODE-split arithmetic** (verify this before writing code — the combined value is `(extended_rcode_byte << 4) | header_rcode_nibble`, confirmed by the existing BADVERS test at `src/protocol/mod.rs:4160-4162`):

- BADVERS = 16 = `(1 << 4) | 0` → header nibble `0` (`NoError`), OPT extended-RCODE byte `1`.
- BADCOOKIE = 23 = `(1 << 4) | 7` → header nibble `7`, OPT extended-RCODE byte `1`.

**This is a real gotcha, not just bookkeeping**: BADVERS could reuse `write_message_header`'s `ResponseCode` parameter unchanged because its header nibble is `0 == NoError`, an existing enum variant. BADCOOKIE's header nibble is `7`, which has **no corresponding `ResponseCode` variant** (the enum only goes up to `5`). `write_message_header` (`src/protocol/mod.rs:1125-1163`) composes flags via `flags |= rcode.as_u8() as u16;`, so it cannot be called as-is to produce a header nibble of `7`. The BADCOOKIE builder must either:
- write the header flags manually (copy `write_message_header`'s flag-composition logic inline, substituting a raw `u8` value of `7` for the RCODE bits instead of going through the `ResponseCode` enum), or
- add a small header-writing variant that accepts a raw `u8` RCODE nibble instead of the `ResponseCode` enum, used only by this builder.

Pick whichever keeps `write_message_header`'s existing callers untouched (they all pass a valid `ResponseCode` today and should keep doing so) — do not add a `ResponseCode::BadCookieNibble = 7` variant or similar, since `ResponseCode` is also `Serialize`d for metrics/event output and is documented (`response_code()`'s doc comment, `:108-118`) as deliberately staying a coarse classifier that never grows extended-RCODE-only values.

### `build_badvers_response` — the pattern to mirror

`src/protocol/mod.rs:609-654`:

```rust
/// Builds a BADVERS response (RFC 6891 §6.1.3: extended RCODE 16) for an
/// EDNS query advertising a version rdns doesn't support (rdns implements
/// version 0 only). The header's own RCODE nibble stays `NoError` (0) --
/// "16" only exists once that nibble and the OPT record's extended-RCODE
/// byte are combined, per §6.1.3's 12-bit extended-RCODE encoding -- and
/// the response OPT record advertises version 0, telling the client the
/// version rdns actually supports (RFC 6891 §6.1.3: "the version of EDNS
/// which the resolver supports"). Always carries an OPT record: this
/// response only ever exists because `request` had one --
/// `QueryValidationError::UnsupportedEdnsVersion` can't be produced by a
/// non-EDNS query in the first place. Doesn't reuse
/// `build_question_response` (used by every other generic error/policy
/// response) since that always zeroes the OPT's extended-RCODE byte.
pub fn build_badvers_response(
    request: &Message,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    let question_count = u16::from(!request.questions.is_empty());
    let dnssec_ok = request.edns.as_ref().is_some_and(|edns| edns.dnssec_ok);
    let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
    let opt = build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 1, Vec::new());

    write_message_header(
        &mut response,
        request.header.id,
        request.header.rd(),
        false, // truncated
        false, // synthetic local response, never authoritative
        false, // authenticated_data
        request.header.cd(),
        ResponseCode::NoError,
        question_count,
        0,
        0,
        1,
    );

    if let Some(question) = request.questions.first() {
        let mut compressor = NameCompressor::new();
        write_question(&mut response, &mut compressor, question);
    }
    write_opt_record(&mut response, &opt);

    response
}
```

Key building blocks it uses, all reusable by the new builder:

- `build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, extended_rcode, options)` (`src/protocol/mod.rs:1276-1298`) — builds the OPT `Record` with an explicit extended-RCODE byte and an arbitrary `options` byte blob (this is exactly where the fresh cookie option's bytes need to go for BADCOOKIE).
- `write_opt_record(out, opt)` (`:1417+`) — serializes an OPT record with its own throwaway `NameCompressor`.
- `NameCompressor::new()` + `write_question` — for the mirrored question section.
- CD is always copied from the request (`request.header.cd()`), matching RFC 4035 §3.2.2.
- The response always carries exactly one OPT record and mirrors the request's single question — same shape as BADVERS, since this response also can only ever exist for an EDNS query that had a cookie option in the first place.

### `QueryValidationError` and `response_code()` — the variant/bucketing pattern

`src/protocol/mod.rs:51-130`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryValidationError {
    Parse(DnsParseError),
    UnsupportedOpcode { opcode: u8 },
    InvalidQuestionCount { count: u16 },
    UnexpectedSectionRecords { answers: u16, authorities: u16, additionals: u16 },
    InvalidEdns,
    NotQuery,
    /// RFC 6891 §6.1.3: rdns implements EDNS version 0 only. A query
    /// advertising any other version must be answered BADVERS (extended
    /// RCODE 16), not treated as a generic FORMERR -- see
    /// `build_badvers_response`.
    UnsupportedEdnsVersion { version: u8 },
}

impl QueryValidationError {
    /// Coarse classifier used for metrics/event bucketing ...
    pub fn response_code(&self) -> ResponseCode {
        match self {
            Self::UnsupportedOpcode { .. } => ResponseCode::NotImp,
            Self::Parse(_)
            | Self::InvalidQuestionCount { .. }
            | Self::UnexpectedSectionRecords { .. }
            | Self::InvalidEdns
            | Self::NotQuery
            | Self::UnsupportedEdnsVersion { .. } => ResponseCode::FormErr,
        }
    }
}
```

Add a new unit variant (no fields needed — unlike `UnsupportedEdnsVersion`, there's no useful diagnostic payload to carry beyond "the presented server cookie is invalid"), e.g. `InvalidServerCookie`, to this enum, and add it to the `FormErr` match arm in `response_code()` — following the exact same "coarse classifier stays FormErr even though the real wire response is an extended RCODE" precedent `UnsupportedEdnsVersion` already established (see that method's doc comment, `:108-118`, which should be updated to also name the new variant as a second example of this pattern). Name the variant so its doc comment covers **both** cases the plan requires it to cover — do not create two separate variants for these:

1. A client cookie with a server-cookie tail present but invalid/stale (fails the recompute-and-compare check section-08 will add).
2. A client cookie with a server-cookie tail present but structurally malformed (wrong length, truncated TLV) — this must map to the **same** variant as case 1, not be silently treated the same as "no cookie option at all" (which is a different, non-error case entirely — see section-08).

### `protocol_error` routing — the special-case pattern

`src/resolver/mod.rs:6598-6667`, `BasicResponseFactory`:

```rust
pub struct BasicResponseFactory;

impl ResponseFactory for BasicResponseFactory {
    fn protocol_error(
        &self,
        request_id: Option<u16>,
        error: &QueryValidationError,
        request: Option<&Message>,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8> {
        // BADVERS (RFC 6891 §6.1.3) doesn't fit `ResponseCode` ...
        if let (QueryValidationError::UnsupportedEdnsVersion { .. }, Some(request)) =
            (error, request)
        {
            return build_badvers_response(request, configured_max_udp_payload_size);
        }

        let rcode = match error.response_code() {
            ResponseCode::NotImp => ResponseCode::NotImp,
            ResponseCode::ServFail => ResponseCode::ServFail,
            _ => ResponseCode::FormErr,
        };
        build_question_aware_error_response(
            request,
            request_id,
            rcode,
            configured_max_udp_payload_size,
        )
    }
    // ... blocked(), servfail() unchanged
}
```

`ConfiguredResponseFactory::protocol_error` (`:6693-6707`) just delegates to `BasicResponseFactory::protocol_error`, so a change to the special-case logic in `BasicResponseFactory` automatically covers both trait implementations — these are the **only two** `impl ResponseFactory for ...` blocks in the codebase (confirmed by search), so no other call site needs updating for the match logic itself.

### New requirement this section introduces: the trait signature must grow

Unlike BADVERS (which needs nothing beyond `request` and `configured_max_udp_payload_size`), the BADCOOKIE response must attach a **freshly issued, correct server cookie** (RFC 7873 §5.3), which requires three additional inputs the current `protocol_error` signature doesn't carry:

- `cookie_secret: &edns_cookie::CookieSecret` — the process-lifetime secret (`src/protocol/edns_cookie.rs:56-68`).
- `client_ip: std::net::IpAddr` — needed by `build_server_cookie`'s hash input.
- `now: std::time::SystemTime` — needed for the server cookie's timestamp field.

All three are already in scope at the one call site that invokes `protocol_error` today, `ResolveQuery::decode_or_protocol_error` (`src/resolver/mod.rs:4610-4649`):

```rust
async fn decode_or_protocol_error(
    &self,
    started_at: SystemTime,
    request: &ResolveRequest,
    request_id: Option<u16>,
    backend_snapshot: &BackendSnapshot,
    request_bytes: Bytes,
) -> Result<DecodedQuery, ResolveOutcome> {
    match self.protocol.decode_query_owned(request_bytes) {
        Ok(decoded) => Ok(decoded),
        Err(QueryDecodeFailure { error, recovered_message }) => {
            // ...
            let response_bytes = self.responses.protocol_error(
                request_id,
                &error,
                recovered_message.as_deref(),
                self.protocol.configured_max_udp_payload_size(),
            );
            // ...
        }
    }
}
```

`self.cookie_secret` (`ResolveQuery.cookie_secret: Arc<CookieSecret>`, `:4073`) and `self.clock` (`self.clock.now()`, used elsewhere e.g. `:4496`) and `request.client_ip` (`ResolveRequest.client_ip`) are all already fields/values in scope right here — confirmed by reading the surrounding struct and method. This section's job:

1. Extend the `ResponseFactory` trait's `protocol_error` method (`src/resolver/mod.rs:8866-8897`) to accept the three new parameters.
2. Update both implementations (`BasicResponseFactory`, `ConfiguredResponseFactory`) to accept and thread them through.
3. Update the one call site (`decode_or_protocol_error`, `:4631-4636`) to pass `&self.cookie_secret`, `request.client_ip`, and `self.clock.now()`.
4. **This section does not need to make `decode_or_protocol_error` itself ever actually produce `InvalidServerCookie`** — that only happens once section-08 wires cookie detection into `probe_cache`, which is a different call path entirely (`probe_cache` runs after decode succeeds, not during decode). This section only needs the plumbing to compile, be directly testable via unit tests that construct the error variant by hand, and be ready for section-08 to invoke. Note this explicitly in a comment near the new match arm so a future reader isn't confused about why it looks unreachable from any current caller.

Note there is no existing test asserting a full end-to-end `service.resolve(...)` path producing BADCOOKIE in this section — that end-to-end wiring doesn't exist until section-08. Tests in this section call `BasicResponseFactory::protocol_error(...)` directly (see Tests below), matching how `query_validation_errors_map_to_response_codes` (`src/protocol/mod.rs:3826-3840`) tests `response_code()` directly rather than through a full resolve.

### `build_server_cookie` — reuse exactly, don't re-derive

`src/protocol/edns_cookie.rs:158-182`:

```rust
pub(crate) fn build_server_cookie(
    secret: &CookieSecret,
    client_cookie: ClientCookie,
    client_ip: IpAddr,
    now: SystemTime,
) -> [u8; 16] {
    // ... RFC 9018 §4.4 construction via domain::base::opt::cookie::StandardServerCookie
}
```

`ClientCookie = [u8; 8]` (`:38`). `build_cookie_option(client_cookie, server_cookie) -> Vec<u8>` (`:187-194`) serializes the full COOKIE option TLV (code 10, echoing the client cookie, appending the fresh 16-byte server cookie) ready to drop into an OPT record's `options` bytes — this is the exact function `message_edns_opt_record_with_cookie` (`src/protocol/mod.rs:1340-1362`) already uses for the happy-path cookie-echo case; the BADCOOKIE builder needs the identical pair of calls (`build_server_cookie` then `build_cookie_option`), just wired into `build_opt_record_with_extended_rcode`'s `options` parameter instead of `build_opt_record_with_options`'s. `edns_cookie` is declared `pub(crate) mod edns_cookie;` at `src/protocol/mod.rs:24`, so the new builder (also in `protocol/mod.rs`) can call these directly without any crate-path qualification.

The new builder therefore needs the client's already-extracted client cookie (`ClientCookie`) as an input parameter — it should not re-parse `request`'s EDNS options itself to find it, since by the time this builder is called (from section-08's detection logic), the caller will already have extracted and validated cookie-shape information as part of deciding to reject in the first place. Take `client_cookie: edns_cookie::ClientCookie` as an explicit parameter rather than re-deriving it from `request`.

### Note: `IpAddr` and `SystemTime` are not currently imported in `protocol/mod.rs`

`src/protocol/mod.rs`'s current imports (`:15-22`) bring in `std::net::{Ipv4Addr, Ipv6Addr}` and `std::time::Duration`, but not `std::net::IpAddr` or `std::time::SystemTime` — both are needed for the new builder's signature. Add them to the existing `use` statements rather than fully-qualifying inline, matching this file's existing import style.

## Implementation

Files to modify:

- `/home/rpmoore/code/rdns/src/protocol/mod.rs` — new response builder, new `QueryValidationError` variant, `response_code()` match-arm update, new imports.
- `/home/rpmoore/code/rdns/src/resolver/mod.rs` — `ResponseFactory` trait signature change, both impls' `protocol_error` updates, the one call site's argument threading, the new `protocol_error` special case.

Steps:

1. **New response builder** in `src/protocol/mod.rs`, alongside `build_badvers_response` (after it, at `:655`): `pub fn build_badcookie_response(request: &Message, client_cookie: edns_cookie::ClientCookie, cookie_secret: &edns_cookie::CookieSecret, client_ip: std::net::IpAddr, now: std::time::SystemTime, configured_max_udp_payload_size: usize) -> Vec<u8>`. Mirror `build_badvers_response`'s structure exactly:
   - Compute `server_cookie = edns_cookie::build_server_cookie(cookie_secret, client_cookie, client_ip, now)`.
   - Compute `options = edns_cookie::build_cookie_option(client_cookie, server_cookie)`.
   - Build the OPT record via `build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 1, options)` — extended-RCODE byte is `1`, same numeric value as BADVERS (see the arithmetic above), but this time with a non-empty `options` blob carrying the fresh cookie.
   - Write the header with RCODE nibble `7` — **cannot** call `write_message_header` with a `ResponseCode` variant, since none maps to `7`; write flags manually (copy the bit-composition from `write_message_header`, substituting a literal `7` in place of `rcode.as_u8()`), or add a small raw-nibble variant of that helper used only here. Preserve every other flag `write_message_header` sets: QR=1, RD copied from request, TC=0, AA=0, AD=0, CD copied from request, RA=1.
   - Mirror the request's single question, same as BADVERS.
   - Always carries exactly one OPT record — this response only ever exists because `request` had a cookie option in the first place.
2. **New error variant** in `QueryValidationError` (`:51-74`): add `InvalidServerCookie` (unit variant, no fields). Update its enum doc-adjacent comment to describe both cases it covers (invalid/stale-but-present, and malformed-but-present server cookie) and explicitly note it does **not** cover "no server cookie at all" (that's not an error — see section-08).
3. **`response_code()` update** (`:119-129`): add `Self::InvalidServerCookie` to the `FormErr` match arm, alongside `UnsupportedEdnsVersion` and the other FormErr-bucketed variants. Update the method's doc comment to also name this as a second BADVERS-style example of "coarse metrics bucket differs from actual wire RCODE."
4. **`ResponseFactory` trait** (`src/resolver/mod.rs:8866-8897`): extend `protocol_error`'s signature with the three new parameters (`cookie_secret: &edns_cookie::CookieSecret`, `client_ip: std::net::IpAddr`, `now: std::time::SystemTime`) — place them in a sensible position (e.g. after `request`, before `configured_max_udp_payload_size`, or wherever reads most naturally given the existing parameter order) and update the trait's doc comment accordingly.
5. **`BasicResponseFactory::protocol_error`** (`:6600-6645`): accept the new parameters; add a new `if let` special case before/alongside the existing `UnsupportedEdnsVersion` one:
   ```rust
   if let (QueryValidationError::InvalidServerCookie, Some(request)) = (error, request) {
       // extract the client cookie from `request`'s EDNS options here (or
       // decide the exact contract with section-08 — see note below) and call
       // build_badcookie_response(...)
   }
   ```
   Since this variant is not yet producible by any real caller in this section, the exact mechanism for obtaining the already-known-invalid client cookie at this call site (re-parse `request`'s EDNS options via `edns_cookie::parse_cookie_option`, since `QueryValidationError::InvalidServerCookie` carries no fields) is acceptable here — `parse_cookie_option` (`edns_cookie.rs:129-131`) is the right function, since by construction this variant only occurs when a client cookie was present (the case with no client cookie at all can't produce this error). Document this reasoning inline.
6. **`ConfiguredResponseFactory::protocol_error`** (`:6693-6707`): thread the new parameters straight through to `BasicResponseFactory::protocol_error`, unchanged in spirit from today.
7. **Call site** (`decode_or_protocol_error`, `:4631-4636`): pass `&self.cookie_secret`, `request.client_ip`, and `self.clock.now()` alongside the existing arguments.
8. Add the missing `use std::net::IpAddr;` and `use std::time::SystemTime;` (or extend the existing `use std::net::{...}` / `use std::time::{...}` lines) to `src/protocol/mod.rs`'s imports.

## Tests

Write these in `src/protocol/mod.rs`'s `#[cfg(test)] mod tests` (builder + error-variant/bucketing tests) and `src/resolver/mod.rs`'s test module (the `protocol_error`-routing test), following this repo's existing hand-built-byte-vector, no-mocking-framework convention. These are stubs — prose descriptions of what each test asserts, not full test code; reuse existing test helpers (`push_header_with_flags`, `push_question`, `push_opt_record_with_version` in `protocol/mod.rs`'s test module) wherever the shape matches what `build_badvers_response_encodes_extended_rcode_and_mirrors_opt_and_cd` (`:4130-4168`) already does.

1. **Wire-split test** (`src/protocol/mod.rs`): build a BADCOOKIE response via `build_badcookie_response(...)` against a hand-built EDNS request (mirror `build_badvers_response_encodes_extended_rcode_and_mirrors_opt_and_cd`'s setup). Parse the response back with `Message::parse`. Assert the **combined** extended RCODE — `(u16::from(opt.extended_rcode) << 4) | u16::from(response.header.r_code())` — equals `23`, not either half in isolation (checking only one half would pass even if the split were wrong, same rationale as the existing BADVERS test's doc comment). Also assert `response.header.id`, mirrored question, and CD-copied-from-request, matching the BADVERS test's existing assertions.
2. **Server-cookie-attached test**: same response, additionally assert its OPT record's `options` bytes decode to a COOKIE option whose 16-byte server-cookie half equals `edns_cookie::build_server_cookie(...)` computed independently with the same secret/client-cookie/client-ip/timestamp inputs — proving the attached cookie is the real, freshly issued one, not a stub/zeroed value.
3. **`response_code()` bucketing test** (`src/protocol/mod.rs`, extend `query_validation_errors_map_to_response_codes` at `:3826-3840` or add a sibling test mirroring `parse_standard_query_rejects_unsupported_edns_version`'s bucketing assertion at `:3931`): `QueryValidationError::InvalidServerCookie.response_code()` returns `ResponseCode::FormErr`.
4. **`protocol_error` routing test** (`src/resolver/mod.rs`, near `BasicResponseFactory`'s other tests): construct a `QueryValidationError::InvalidServerCookie` and a hand-built EDNS request with a cookie option present, call `BasicResponseFactory.protocol_error(...)` directly (not through a full `service.resolve(...)` — no caller produces this variant yet in this section), and assert the returned bytes decode to a BADCOOKIE response (RCODE combined value 23, per test 1's assertion style) rather than a generic FormErr response — proving the special case is actually reached, not just defined (a no-regression-style test, matching the plan's phrasing). Also assert `ConfiguredResponseFactory::protocol_error` produces byte-identical output for the same inputs, confirming the delegation still holds for the new variant.

## Verification gates

Per this repo's standing rules (`RUST.md`), before considering this section done:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets` — pay particular attention to the manually-written header-flags code (item 1 above) not tripping any bit-manipulation lints, and to the trait-signature change not leaving any now-unused parameter warnings in either `ResponseFactory` impl.
- `cargo test` — full suite, including the new tests above; no existing test should change behavior (this section adds new plumbing, it does not change what any existing caller does, since `QueryValidationError::InvalidServerCookie` is never yet produced by any real code path).

## Implementation notes (actual)

Implemented as planned, with one documentation-only deviation:

- `build_badcookie_response`, `QueryValidationError::InvalidServerCookie`, the `response_code()` update, and the `ResponseFactory::protocol_error` signature/impl/call-site changes all landed exactly as specified, in `src/protocol/mod.rs` and `src/resolver/mod.rs`.
- Both concrete `protocol_error` impls needed `#[allow(clippy::too_many_arguments)]` was considered but turned out unnecessary in practice: clippy's `too_many_arguments` lint doesn't re-fire on trait-method impls once the trait declaration itself carries the allow, so only the trait's `fn protocol_error` in `ResponseFactory` (`src/resolver/mod.rs`) needed the attribute — confirmed via `cargo clippy --all-targets` passing clean with no per-impl allow.
- Code review flagged that `BasicResponseFactory::protocol_error`'s `InvalidServerCookie` branch re-extracts the client cookie via `edns_cookie::parse_cookie_option`, which returns `None` for a malformed-length COOKIE option — one of the two cases the variant's doc comment says it covers. Cross-checked against `section-08-badcookie-detection.md`, which already documents this exact gap as a known placeholder it resolves in its own scope (`locate_cookie_for_verification`, shared with the new `probe_cache` check). No code-logic change made here; the inline comment above the `parse_cookie_option` call was tightened to name the gap plainly and point at section-08's fix, so a reader hitting this code before section-08 lands isn't misled into thinking the extraction is always sound.
- Tests: 4 tests added, matching the plan's 4 stubs exactly — `build_badcookie_response_encodes_extended_rcode_and_mirrors_opt_and_cd`, `build_badcookie_response_attaches_fresh_server_cookie`, and `invalid_server_cookie_buckets_to_form_err` in `src/protocol/mod.rs`; `protocol_error_routes_invalid_server_cookie_to_badcookie_response` in `src/resolver/mod.rs` (asserts both `BasicResponseFactory` and `ConfiguredResponseFactory` produce byte-identical output).
- Verification: `cargo fmt --all -- --check`, `cargo clippy --all-targets`, `cargo test --lib` (742 passed, 0 failed, 3 ignored) all clean.

## Acceptance criteria

- `build_badcookie_response` exists in `src/protocol/mod.rs`, produces a wire response whose combined extended RCODE (header nibble + OPT extended-RCODE byte) is `23`, and attaches a freshly issued, correct server cookie computed via `edns_cookie::build_server_cookie`.
- `QueryValidationError::InvalidServerCookie` exists, covers both "invalid/stale-but-present" and "malformed-but-present" server-cookie cases (not "absent" — that is out of scope for this variant), and buckets to `ResponseCode::FormErr` via `response_code()`.
- `ResponseFactory::protocol_error`'s signature carries `cookie_secret`, `client_ip`, and `now`; both `BasicResponseFactory` and `ConfiguredResponseFactory` implement the extended signature; the one existing call site (`decode_or_protocol_error`) passes real values (`self.cookie_secret`, `request.client_ip`, `self.clock.now()`), not placeholders.
- `BasicResponseFactory::protocol_error` special-cases `QueryValidationError::InvalidServerCookie` (with `Some(request)`) by routing to `build_badcookie_response`, mirroring the existing `UnsupportedEdnsVersion`/`build_badvers_response` special case; `ConfiguredResponseFactory` delegates identically.
- All four tests above exist and pass; no existing test's behavior changes.
- No code in this section is yet reachable from a real client request — that wiring is section-08's job (`section-07-badcookie-wire-rcode` blocks `section-08-badcookie-detection`).