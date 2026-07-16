Now I have sufficient context. Let me write the section content.

---

## Output

# Section 02: `src/protocol/edns_cookie.rs` — EDNS Cookie parsing, cache-admission predicate, and server-cookie construction

## Dependency on other sections

Depends on **section-01-cargo-dependencies**: `domain`'s `siphasher` Cargo feature must already be enabled and `rand` must already be a direct dependency in `Cargo.toml` before this section starts (so `domain::base::opt::cookie::StandardServerCookie` and a `rand`-backed CSPRNG are both available). This section does not touch `Cargo.toml` itself.

This section produces a new, standalone module with **no other module depending on it yet** — `cache_supported()` narrowing (section-03), `QueryFeatures`/`requester_opt_record` threading (section-04), and OPT-record serialization (section-06) all consume this module's public items in later sections, but none of that wiring happens here. This section is fully unit-testable in isolation.

## Background

`rdns` is a Rust DNS resolver/proxy. This plan teaches it to recognize a well-formed RFC 7873 DNS COOKIE option (EDNS option code 10) as compatible with caching, and to always attach a freshly-computed, RFC 9018-correct server cookie on every response when a client cookie was present in the query — without ever validating an incoming server cookie's correctness, and without ever caching or replaying OPT-record/cookie bytes across requests.

This section builds the protocol-layer primitives that everything else in the plan is built on top of, per `AGENTS.md`'s layering rule ("`protocol` owns DNS wire-format parsing, validation, and encoding"). It has zero dependency on `resolver`-layer types.

### Server-cookie algorithm: RFC 9018, not RFC 7873 Appendix B

RFC 7873 Appendix B's example server-cookie algorithms (FNV-64, or HMAC-SHA256-64-with-nonce) are non-normative and non-interoperable across vendors. RFC 9018 ("Interoperable DNS Server Cookies") explicitly retires them and specifies the following §4.4 construction instead — use this, not Appendix B:

- 16-byte server cookie = 1-byte Version (`1`) + 3-byte Reserved (`0x00 0x00 0x00`) + 4-byte Timestamp (big-endian, seconds since Unix epoch) + 8-byte SipHash-2-4 output.
- SipHash-2-4 input (the hashed message): `Client Cookie(8) | Version(1) | Reserved(3) | Timestamp(4) | Client-IP(4 or 16)` — 20 bytes total for IPv4 client IPs, 32 bytes for IPv6. Keyed by the server's secret.
- §4.2: the secret should be ≥128 bits (16 bytes), CSPRNG-generated.
- §4.3 (validation window) and §5 (secret rotation) are explicitly **out of scope** for this plan — this implementation never validates an incoming server cookie's timestamp/hash at all (see Non-goals below), and uses one static in-memory secret for the process's lifetime.

**Documented gotcha** (confirmed in `domain` crate source, `base/opt/cookie.rs:641-644`): Version/Reserved/Timestamp are big-endian, but the 8-byte SipHash-2-4 output must be serialized **little-endian** — described in that source as "somewhat surprising." A naive full-big-endian implementation would self-validate (i.e. pass tests that only check round-tripping against itself) but silently fail interop with every other RFC-9018-compliant resolver. If the hash construction ends up hand-rolled instead of delegated to `domain::base::opt::cookie::StandardServerCookie::calculate`, unit tests **must** check against RFC 9018 Appendix A's published test vectors, not just self-consistency, to catch this class of bug.

Prefer calling `domain::base::opt::cookie::StandardServerCookie::calculate` directly — its signature takes a raw `secret: &[u8; 16]`, so rdns code never needs to import `siphasher` itself (that stays purely an internal `domain` implementation detail) and never needs to adopt `domain`'s `Message`/`Octets` abstractions elsewhere in the codebase. Only hand-roll the SipHash-2-4 call against `siphasher` directly if `domain`'s API turns out to be awkward to call from this module's raw-byte style once implementation is underway.

### Wire format (RFC 7873 §4)

COOKIE option code is 10. Two valid RDATA lengths for the option:
- 8 bytes: client-cookie-only (no server cookie attached by the client — first-contact case).
- 16-40 bytes inclusive: client cookie (8 bytes) + server cookie (8-32 bytes) the client is echoing back from a prior response.

Any other length is malformed (RFC 7873 §5.2.2 would call for FORMERR, but generating FORMERR for this case is an explicit **non-goal** of this plan — malformed-length COOKIE options fall back to today's existing generic "any weird EDNS content bypasses the cache" behavior, unchanged. This module just needs to recognize the malformed case and return `None`/reject it; it does not generate any response itself).

### Why extraction and cache-admission are two separate functions

A query can carry a well-formed COOKIE option **and** some other EDNS option (e.g. NSID) at the same time. In that case:
- The cookie should still be extracted and echoed back on the response (which will bypass the cache for the unrelated reason of the other option), so `parse_cookie_option` must return `Some`.
- But the query must **not** be treated as cache-admissible, because Goal 5 requires every non-Cookie EDNS-option case to keep bypassing the cache exactly as today, so the cache-admission predicate must return `None` for this same input.

Overloading a single function/predicate for both "is a cookie present to echo" and "is this query cache-safe" was flagged in plan review as an easy way to accidentally leak "a cookie is present" into "this query is cache-safe." This module therefore exposes **two** functions over the same input shape — `parse_cookie_option` (extraction) and `is_solely_cookie_option` (cache-admission) — and both must be tested against the *same* Cookie+NSID fixture to explicitly pin their divergence as intentional.

### Non-goals reiterated for this module (do not implement)

- No BADCOOKIE (RCODE 23) generation, and no branching on an incoming server cookie's hash/timestamp validity at all — this module never reads/validates the server-cookie portion of an incoming option; it only ever discards those bytes if present.
- No FORMERR generation for malformed-length COOKIE options — just detect and reject (return `None`) at this layer.
- No secret rotation — `CookieSecret` is one value for the process's lifetime.

## File to create

`/home/rpmoore/code/rdns/src/protocol/edns_cookie.rs`

This is a **new file** and must be declared as a submodule from the existing `src/protocol/mod.rs` (which today is `rdns`'s only file under `protocol/` — see `pub mod protocol;` in `src/lib.rs:17`). Add near the top of `src/protocol/mod.rs`, following the same pattern `src/resolver/mod.rs:40` uses for its `cache` submodule (`mod cache;`):

```rust
mod edns_cookie;
```

Visibility: keep items `pub(crate)` (matching this module's existing convention — e.g. `build_opt_record` at `protocol/mod.rs:1246` is `pub(crate)`) unless a specific item needs broader visibility once section-04/06 wire it up; err toward `pub(crate)` here since no other crate consumes this module.

Add a standard license header at the top of the new file, copied verbatim from the header block at the top of `src/protocol/mod.rs:1-13` (Apache 2.0, `Copyright 2026 Ryan Moore`).

## Existing constants/types this module's tests may need to reference

- `EDNS_DO_FLAG: u16 = 0x8000` (`protocol/mod.rs:30`) — private to `protocol/mod.rs`; not needed by this module directly but relevant context for how the option flags fit into the wider `EdnsInfo` shape this module's output eventually feeds into (sections 04/06).
- `OPT_RECORD_TYPE: u16 = 41` (`protocol/mod.rs:28`) — same, contextual only.
- No `COOKIE_OPTION_CODE` constant exists yet anywhere in the codebase (confirmed via grep during research — option code 10 is handled today only generically, as "any option," never by code number). Define it in this new module, e.g. `const COOKIE_OPTION_CODE: u16 = 10;`.

## Public API to implement

All of the following belong in `src/protocol/edns_cookie.rs`. Signatures/behavior below are decided; exact internal helper structure (e.g. whether TLV scanning is factored into a shared private helper used by both `parse_cookie_option` and `is_solely_cookie_option`) is the implementer's call — but per the "why extraction and cache-admission are two separate functions" note above, the two must remain **distinct public functions** with genuinely different behavior on the Cookie+other-option fixture, not two thin wrappers that both delegate to identical logic.

### `CookieSecret`

```rust
/// The resolver's one random, process-lifetime server-cookie secret
/// (RFC 9018 §4.2: SHOULD be >= 128 bits). Constructed once at process
/// startup, mirroring `SystemClock`'s role as the one process-lifetime
/// side-effect-holding value (`src/main.rs:739-741`). Held behind an
/// `Arc<CookieSecret>` at call sites that need it, exactly like
/// `Arc<dyn Clock>`.
pub(crate) struct CookieSecret {
    // raw secret bytes, >= 16 bytes (128 bits)
}

impl CookieSecret {
    /// Generates a fresh, CSPRNG-backed secret. Called exactly once, in
    /// `src/main.rs`, alongside where `SystemClock` is constructed
    /// (this call site is out of scope for this section -- section-04
    /// wires it up).
    pub(crate) fn generate() -> Self {
        todo!()
    }
}
```

Use the `rand` crate (added as a direct dependency in section-01) to generate the secret bytes — do not hand-roll a PRNG. Do not implement `Debug`/`Display`/`Serialize` in a way that would print the raw secret bytes (this is a security-review concern flagged for section-08, but avoid the footgun now by simply not deriving/implementing any trait that would expose the bytes).

### `ClientCookie`

```rust
/// The 8-byte client cookie extracted from an incoming query's COOKIE
/// option.
pub(crate) type ClientCookie = [u8; 8];
// (a newtype wrapper is also acceptable if it reads better once
// threaded through QueryFeatures in section-04 -- implementer's call)
```

### `parse_cookie_option`

```rust
/// Scans the raw EDNS options TLV blob (the same `edns.options: Vec<u8>`
/// field already populated by `parse_opt_record`,
/// `protocol/mod.rs:2617-2641`) for exactly one option with code 10
/// (COOKIE). Returns `Some(client_cookie)` only when the option is
/// present exactly once and has a well-formed RFC 7873 §4 length (8, or
/// 16-40 inclusive) -- extracting just the first 8 bytes (the client
/// cookie) and discarding any server-cookie bytes present (this
/// implementation never validates an incoming server cookie, per the
/// plan's decided non-goals).
///
/// Returns `None` when: no COOKIE option is present, more than one
/// COOKIE option is present, or the option's length is malformed.
///
/// This answers "is there a client cookie to echo on the response" --
/// a query can have a well-formed Cookie *and* some other EDNS option
/// (e.g. NSID) and this function still returns `Some` in that case. See
/// `is_solely_cookie_option` for the stricter cache-admission question.
pub(crate) fn parse_cookie_option(options: &[u8]) -> Option<ClientCookie> {
    todo!()
}
```

### `is_solely_cookie_option`

```rust
/// The cache-admission predicate -- used only by `cache_supported()`
/// (narrowed in section-03). Returns `Some(client_cookie)` only when
/// the *entire* raw `options` byte slice is consumed by exactly one
/// well-formed COOKIE option and nothing else -- any trailing bytes
/// (e.g. another option such as NSID or Padding) means `None`.
///
/// Deliberately stricter than `parse_cookie_option`: a query with a
/// well-formed Cookie *and* another option must extract/echo the
/// cookie (so `parse_cookie_option` returns `Some`) while still NOT
/// being treated as cache-admissible (so this function returns `None`
/// for the identical input). Must be tested against the same
/// Cookie+NSID fixture as `parse_cookie_option` to pin this divergence
/// as intentional.
pub(crate) fn is_solely_cookie_option(options: &[u8]) -> Option<ClientCookie> {
    todo!()
}
```

### `build_server_cookie`

```rust
use std::net::IpAddr;
use std::time::SystemTime;

/// Computes the RFC 9018 §4.4 16-byte server cookie: 1-byte Version(1),
/// 3-byte Reserved(0), 4-byte big-endian Unix timestamp, 8-byte
/// SipHash-2-4 output (serialized little-endian -- see the module-level
/// doc comment / this section's background notes for why). Hash input
/// is `client_cookie(8) | version(1) | reserved(3) | timestamp(4) |
/// client_ip(4 or 16, depending on v4/v6)`, keyed by `secret`.
///
/// Prefer delegating to
/// `domain::base::opt::cookie::StandardServerCookie::calculate`
/// directly; only hand-roll the SipHash-2-4 call against `siphasher`
/// if `domain`'s API is awkward to call from this module's raw-byte
/// style. If hand-rolled, unit tests MUST check RFC 9018 Appendix A's
/// published test vectors, not just internal round-tripping.
pub(crate) fn build_server_cookie(
    secret: &CookieSecret,
    client_cookie: ClientCookie,
    client_ip: IpAddr,
    now: SystemTime,
) -> [u8; 16] {
    todo!()
}
```

### `build_cookie_option`

```rust
/// Serializes a full COOKIE option's RDATA-option-TLV bytes (option
/// code 10, length 24, client cookie followed by the 16-byte server
/// cookie), ready to be appended into an OPT record's `options` bytes
/// (consumed by section-06's OPT-record wire encoder).
pub(crate) fn build_cookie_option(client_cookie: ClientCookie, server_cookie: [u8; 16]) -> Vec<u8> {
    todo!()
}
```

## Tests (write these first)

All tests live in a `#[cfg(test)] mod tests` block at the bottom of `src/protocol/edns_cookie.rs`, following this codebase's existing test-module convention (see `protocol/mod.rs:2790` `mod tests {`). These are unit tests only — no resolver-layer fixtures, no network I/O, no async runtime needed.

### `parse_cookie_option`

- Returns `Some(client_cookie)` for a well-formed 8-byte (client-cookie-only) COOKIE option.
- Returns `Some(client_cookie)` for a well-formed 16-40 byte (client + server cookie) COOKIE option, extracting only the first 8 bytes as the client cookie (assert the server-cookie bytes present in the fixture are *not* part of the returned value).
- Returns `None` for a malformed length (e.g. 9, 15, 41 bytes).
- Returns `None` when no COOKIE option is present in the options blob (e.g. an empty blob, or a blob containing only unrelated options).
- Returns `None` when more than one COOKIE option is present.
- Returns `Some(client_cookie)` when a well-formed COOKIE option is present **alongside** another EDNS option (e.g. NSID, option code 3) — extraction still succeeds even though cache-admission (below) must not. Build this fixture once and reuse it in the `is_solely_cookie_option` divergence test below.

### `is_solely_cookie_option`

- Returns `Some(client_cookie)` when the *entire* options blob is exactly one well-formed COOKIE option (byte-identical fixture to `parse_cookie_option`'s first test above; same expected `client_cookie` value).
- Returns `None` when a well-formed COOKIE option is present alongside another option (e.g. NSID) — using the *exact same fixture* as `parse_cookie_option`'s Cookie+NSID test, asserting the divergent result explicitly (this is the core cache-admission-vs-extraction distinction this section exists to get right).
- Returns `None` for the same malformed-length/absent/duplicate-option cases as `parse_cookie_option` (reuse those fixtures).

### `build_server_cookie`

- Produces a 16-byte output with the correct Version(1)/Reserved(0)/Timestamp byte layout (big-endian) for a fixed `now`/secret/client-cookie/client-IP input.
- If the hash construction is hand-rolled rather than delegated to `domain::base::opt::cookie::StandardServerCookie::calculate`: matches RFC 9018 Appendix A's published test vectors exactly, including the little-endian SipHash-2-4 output serialization gotcha called out above.
- Produces different output for different client IPs (both v4-vs-v6 and different-address-same-family cases) given the same client cookie and secret — confirms the client IP is genuinely part of the hash input rather than accidentally ignored. (This test would catch a bug where `client_ip` is accepted as a parameter but silently unused.)

### `build_cookie_option`

- Serializes the correct TLV shape: option code 10, length 24, client cookie (8 bytes) immediately followed by the 16-byte server cookie, for a fixed input pair.

### `CookieSecret`

- `CookieSecret::generate()` produces a secret of the expected byte length (>= 16 bytes / 128 bits).
- Two separate calls to `CookieSecret::generate()` produce different secret values (a basic randomness sanity check — not a statistical PRNG audit; this just guards against an accidental constant/all-zero secret).

## Verification for this section

- `cargo fmt`, `cargo clippy`, `cargo test` — this module's tests must pass in isolation; no other module in the codebase references it yet, so `cargo test` for the whole crate should otherwise be unaffected.
- If `RUST.md` gates apply (fmt/clippy/test), satisfy them before considering this section done, per `AGENTS.md`'s Change Workflow.
- No knowledge-bundle documentation update is expected yet for this section — the doc update is deferred to section-07, once the full Cookie behavior has actually landed end-to-end (this section alone doesn't change any observable resolver behavior).

## Implementation record

Implemented as planned, no deviations from the decided API shapes. Notes:

- `src/protocol/edns_cookie.rs` created; `mod edns_cookie;` added to
  `src/protocol/mod.rs` immediately after the top-level `use` block
  (matching `src/resolver/mod.rs:40`'s `mod cache;` placement pattern).
- `locate_cookie_option` is the shared private TLV-scanning helper behind
  both `parse_cookie_option` and `is_solely_cookie_option`, as the plan
  allowed. It tracks whether any non-COOKIE option was seen across the
  whole blob; `parse_cookie_option` ignores that flag, `is_solely_cookie_option`
  requires it be false. Rejects duplicate COOKIE options, malformed
  lengths, and truncated/overrunning TLV headers (returns `None`, never
  panics on adversarial input).
- `build_server_cookie` delegates to
  `domain::base::opt::cookie::StandardServerCookie::calculate` and
  reassembles the 16-byte output from its `version()/reserved()/timestamp()/hash()`
  accessors (the crate exposes no direct `[u8; 16]` accessor). Since
  `domain`'s `net::IpAddr` is a plain re-export of `std::net::IpAddr` under
  the `std` feature (already enabled), no IP-type conversion was needed.
- `CookieSecret` holds a private `bytes: [u8; 16]` field, generated via
  `rand::rng().fill_bytes(...)` (rand 0.10's `Rng` trait). No
  `Debug`/`Display`/`Serialize` implemented, so the secret can't leak via
  `{:?}`/logging.
- Module carries `#![allow(dead_code)]` with a one-line justification
  comment, since nothing calls it until sections 03/04/06 wire it up (per
  `RUST.md`'s warning-free baseline rule).
- Code review added two regression tests beyond the plan's enumerated
  list: `build_server_cookie_matches_rfc_9018_appendix_a1_vector` (pins the
  byte reassembly against RFC 9018's own published Appendix A.1 vector,
  since the plan's original tests only checked layout shape and
  IP-sensitivity, not an absolute known-correct value) and
  `parse_cookie_option_rejects_truncated_tlv_bytes` (covers a dangling
  option header and an overrunning declared length, since the module
  parses attacker-controlled wire bytes). See
  `implementation/code_review/section-02-interview.md` for the full
  review trail, including one reviewer finding (a claimed `rand` API
  compile error) that was verified to be a false alarm against the actual
  passing build.
- Verification: `cargo fmt --all -- --check` (clean), `cargo clippy
  --all-targets` (clean, no new warnings), `cargo test edns_cookie` (16/16
  passing), full `cargo test` (587 passing, 0 failed).