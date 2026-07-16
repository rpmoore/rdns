# Section 04 — `QueryFeatures` client-cookie field + `CookieSecret`/client-IP/clock threading through `requester_opt_record`

## Implementation status: complete

Implemented as planned, with two deviations worth flagging for later
sections:

1. **Visibility**: `CookieSecret` (struct + `generate()`) and `ClientCookie`
   (the type alias, since it now appears in the public
   `QueryFeatures.client_cookie` field) had to become `pub`, not
   `pub(crate)` as section-02 originally scoped them. `src/main.rs` is a
   *separate binary crate* depending on `rdns` as an external library — a
   `pub(crate)` item is unreachable from it regardless of any `pub use`
   re-export path. `CookieSecret` is re-exported at `crate::resolver::CookieSecret`
   (mirroring how `Clock`/`SystemClock` are already exposed there) so
   `main.rs`'s existing `use rdns::resolver::{...}` import block could just
   add it to the list. Every other item in `edns_cookie.rs`
   (`parse_cookie_option`, `build_server_cookie`, `build_cookie_option`,
   `is_solely_cookie_option`, `locate_cookie_option`) stays `pub(crate)` —
   `src/protocol/edns_cookie.rs` is therefore **not** a read-only
   dependency for this section as originally scoped; it required this
   minimal, documented visibility widening. `#![allow(dead_code)]` (and its
   now-inaccurate "intentionally unwired" comment) was removed from that
   file in this section too, since every item is now genuinely consumed.
2. **This section is already live, wire-observable behavior, not deferred
   plumbing.** The plan's Verification section claimed the wire encoder
   "still hardcodes empty options until section-06 lands." That's not
   accurate for the code as it exists: `write_rdata`'s `RecordData::OPT`
   arm (`src/protocol/mod.rs:1518`) already serializes whatever bytes sit
   in `EdnsInfo.options` unconditionally — there's no separate encoder gate.
   As of this section, a cache-hit response to a Cookie-bearing query
   already emits a real RFC-9018 COOKIE option on the wire in production.
   A wire-round-trip test
   (`assemble_response_serializes_server_cookie_option_on_wire_for_cookie_bearing_query`)
   was added to prove this, beyond the plan's original test list (which
   only asserted against the in-memory `Record`).

Files touched: `src/resolver/mod.rs` (`QueryFeatures.client_cookie` +
`from_message`, `ResolveQuery.cookie_secret` field + `with_cookie_secret`
setter, `serialize_cache_hit_answer`/`serialize_cache_hit_negative` call
sites, `pub use ... CookieSecret` re-export), `src/resolver/cache/assemble.rs`
(`requester_opt_record`/`build_servfail`/`finish_with_truncation_check`/
`assemble_response`/`assemble_negative_response` signatures + ~40 test
call sites mechanically threaded with `cookie_secret`/`client_ip`),
`src/protocol/edns_cookie.rs` (visibility widening only), `src/main.rs`
(`CookieSecret::generate()` + `.with_cookie_secret(...)` wiring).

Test count: 8 new tests (3 `QueryFeatures::from_message` cookie-field
cases in `mod.rs`; `requester_opt_record_attaches_server_cookie_when_client_cookie_present`,
`requester_opt_record_omits_options_when_no_client_cookie`, and the wire
round-trip test in `assemble.rs`) plus ~40 existing `assemble.rs` tests
mechanically updated for the widened signatures with unchanged
assertions. Full suite: 596 lib tests pass, `cargo fmt --check` and
`cargo clippy --all-targets` both clean.

## Scope and status

This section is the plumbing section connecting section-02's protocol-layer Cookie primitives to the cache-hit response-assembly path. It does three things:

1. Widens `QueryFeatures` (`src/resolver/mod.rs:241-274`) with a new field carrying the client's extracted Cookie (if any), populated in `QueryFeatures::from_message`.
2. Widens `requester_opt_record` (`src/resolver/cache/assemble.rs:437-447`) and its four cache-hit callers (`build_servfail`, `finish_with_truncation_check`, `assemble_response`, `assemble_negative_response`, all in `assemble.rs`) to accept a `CookieSecret`, the requester's `client_ip`, and a timestamp, and to build a COOKIE option into the OPT record when a client cookie is present.
3. Wires a process-lifetime `Arc<CookieSecret>` from `src/main.rs` down through `ResolveQuery` to the two call sites (`serialize_cache_hit_answer`/`serialize_cache_hit_negative`, `mod.rs:4544-4578`) that call into the widened `assemble_response`/`assemble_negative_response`.

This section covers only the **cache-hit** serve path. The cache-miss/recursive-response OPT-rebuild path (`mirrored_client_opt_record`/`message_edns_opt_record`) is section-05's job, done after this section and section-06 both land — section-05 explicitly depends on this section for its OPT-building helper and on section-06 for wire-serialization support to test end-to-end. This section does **not** need to wait for section-06: its tests assert against the in-memory `Record`/`EdnsInfo.options: Vec<u8>` field directly, not against serialized wire bytes (the actual non-empty-options wire *encoder* is section-06's job — today it's hardcoded to `Vec::new()`, and this section does not change that encoder).

## Dependencies

- **section-02 (`src/protocol/edns_cookie.rs`)** must already exist and be unit-tested. This section consumes its public API:
  - `pub(crate) type ClientCookie = [u8; 8]` (or an equivalent newtype — section-02's implementer's call).
  - `pub(crate) fn parse_cookie_option(options: &[u8]) -> Option<ClientCookie>` — used here (not the stricter `is_solely_cookie_option`, which is section-03's cache-admission-only concern) because `QueryFeatures::from_message` must extract/echo a cookie even for a query that also carries another EDNS option and therefore isn't cache-admissible.
  - `pub(crate) struct CookieSecret` with `CookieSecret::generate() -> Self`.
  - `pub(crate) fn build_server_cookie(secret: &CookieSecret, client_cookie: ClientCookie, client_ip: IpAddr, now: SystemTime) -> [u8; 16]`.
  - `pub(crate) fn build_cookie_option(client_cookie: ClientCookie, server_cookie: [u8; 16]) -> Vec<u8>`.

  This section does not add any new public API to `edns_cookie.rs` itself — it only calls into what section-02 built.

- This section can run in parallel with **section-03** (`cache_supported()` narrowing) and **section-06** (OPT wire serialization) — both depend only on section-02, per the index's dependency graph. This section does not touch `cache_supported()`, `probe_cache`, or the OPT-record wire encoder.

## Background

`rdns` is a Rust DNS resolver/proxy. `src/resolver/cache/assemble.rs` rebuilds every cache-hit response's wire bytes fresh, per request (not from a pre-built template), including the OPT pseudo-record via `requester_opt_record`. Today that function only mirrors the requester's own DO flag and this resolver's own UDP payload size — it never emits any EDNS options. This plan's Goal 2 requires attaching a fresh, RFC-9018-correct server cookie on every response (cache hit or miss) whenever the incoming query carried a well-formed COOKIE option, echoing that query's client cookie. This section makes the cache-hit half of that true.

Per RFC 9018/RFC 7873 §5.2.3/§5.2.4 branch 3 ("process the request and provide a normal response"), this resolver never rejects a query for cookie reasons and never validates an incoming server cookie's correctness — it always processes normally and always attaches a freshly computed, valid server cookie when a client cookie was present. No BADCOOKIE, no FORMERR, no validation logic is written anywhere in this section.

### Current `QueryFeatures` (`src/resolver/mod.rs:241-274`)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueryFeatures {
    pub recursion_desired: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub dnssec_ok: bool,
    pub edns_udp_payload_size: Option<u16>,
}

impl QueryFeatures {
    pub fn from_message(message: &Message) -> Self {
        Self {
            recursion_desired: message.header.rd(),
            authenticated_data: message.header.ad(),
            checking_disabled: message.header.cd(),
            dnssec_ok: message
                .edns
                .as_ref()
                .map(|edns| edns.dnssec_ok)
                .unwrap_or(false),
            edns_udp_payload_size: message.edns.as_ref().map(|edns| edns.udp_payload_size),
        }
    }
}
```

`QueryFeatures` derives `PartialEq, Eq, Hash` — whatever type the new field uses must support these too (a `[u8; 8]`-based `ClientCookie` does, trivially).

Add a new field, e.g. `pub client_cookie: Option<ClientCookie>` (exact naming is the implementer's call — a suitably-named alternative is fine as long as its meaning is unambiguous), populated by calling `crate::protocol::edns_cookie::parse_cookie_option` against `message.edns.as_ref().map(|e| &e.options)` (i.e. `None` if there's no EDNS OPT record at all, `parse_cookie_option(&edns.options)` otherwise — flatten the two `Option` layers).

`QueryFeatures` is already threaded from `DecodedQuery` (`mod.rs:276-279`, populated at `mod.rs:288`) into the assembly layer via `decoded.features` at every relevant call site (`mod.rs:4544-4578` — see `serialize_cache_hit_answer`/`serialize_cache_hit_negative` below) — no new plumbing is needed to get this value to `assemble.rs` beyond adding the field and populating it in `from_message`.

### Current `requester_opt_record` and its callers (`src/resolver/cache/assemble.rs:437-684`)

```rust
fn requester_opt_record(
    requester_features: &QueryFeatures,
    configured_max_udp_payload_size: usize,
) -> Option<Record> {
    requester_features.edns_udp_payload_size?;
    let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
    Some(crate::protocol::build_opt_record(
        udp_payload_size,
        requester_features.dnssec_ok,
    ))
}
```

Four call sites in the same file call this, all currently with only `(requester_features, configured_max_udp_payload_size)`:

- `build_servfail` (`assemble.rs:449-476`) — no `now` parameter today.
- `finish_with_truncation_check` (`assemble.rs:504-537`) — no `now` parameter today.
- `assemble_response` (`assemble.rs:546-605`, `pub(crate)`) — **already takes `now: SystemTime`** (used for TTL aging, per the already-landed `ttl_remaining` work) and calls both `requester_opt_record` directly and, internally, `build_servfail`/`finish_with_truncation_check`.
- `assemble_negative_response` (`assemble.rs:615-684`, `pub(crate)`) — same shape as `assemble_response`, also already takes `now: SystemTime`.

Because `assemble_response`/`assemble_negative_response` already receive `now: SystemTime` (for TTL aging), the simplest correct approach is to **reuse that same `now`** as the cookie-timestamp input rather than adding a second, separate clock parameter: thread it down into `build_servfail`/`finish_with_truncation_check` (which don't take `now` today and will need it added) and into `requester_opt_record` itself. This keeps `assemble.rs` consistent with its existing style of taking concrete `SystemTime`/other plain values rather than holding a `Clock` trait object itself (only `mod.rs`'s `ResolveQuery` holds `Arc<dyn Clock>`; `assemble.rs` is pure-function style). Do not call `SystemTime::now()` directly anywhere in `assemble.rs` — always take it as a parameter, so tests can pass a fixed value deterministically (mirroring the `ttl_remaining` Clock-DI convention already established for TTL aging in this same file).

The widened signatures (illustrative — exact parameter order/names are the implementer's call):

```rust
fn requester_opt_record(
    requester_features: &QueryFeatures,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Option<Record> {
    requester_features.edns_udp_payload_size?;
    let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
    let options = match requester_features.client_cookie {
        Some(client_cookie) => {
            let server_cookie = build_server_cookie(cookie_secret, client_cookie, client_ip, now);
            build_cookie_option(client_cookie, server_cookie)
        }
        None => Vec::new(),
    };
    // Construct the OPT `Record` with `options` in its `EdnsInfo` (either by
    // extending `crate::protocol::build_opt_record` to accept an options
    // byte vector, or by building the `Record`/`EdnsInfo` literal directly
    // here — confirm which is cleaner once section-06's wire-encoder work
    // is visible; either way, `EdnsInfo.options: Vec<u8>` is the field that
    // must end up non-empty).
    todo!()
}
```

`build_servfail`, `finish_with_truncation_check`, `assemble_response`, and `assemble_negative_response` each gain `cookie_secret: &CookieSecret` and `client_ip: IpAddr` parameters (mechanical threading — `assemble_response`/`assemble_negative_response` already have `now` in scope and pass it to the two internal helpers; the two internal helpers gain a `now: SystemTime` parameter for the first time). This is a mechanical signature change at each of the four call sites, not new logic at each site — `#[allow(clippy::too_many_arguments)]` already exists on some of these functions (e.g. `finish_with_truncation_check`, `assemble_negative_response`) and may need adding to the others once the parameter count grows.

When `requester_features.client_cookie` is `None`, behavior must be byte-for-byte identical to today (empty `options`, same `Record` shape) — this is an explicit regression test requirement below.

### `EdnsInfo` shape (`src/protocol/mod.rs:207-215`) — the field this section populates

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsInfo {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub flags: u16,
    pub dnssec_ok: bool,
    pub options: Vec<u8>,
}
```

`options` already exists as a field; this section is the first place in the *response-writing* direction that ever sets it to something non-empty. Whether `requester_opt_record` builds the `Record`/`EdnsInfo` by extending `crate::protocol::build_opt_record`/`build_opt_record_with_extended_rcode` (`protocol/mod.rs:1246-1278`, currently hardcoding `options: Vec::new()`) with a new parameter/variant, or constructs the `Record` literal directly in `assemble.rs`, is left to the implementer — coordinate naturally with section-06, which is the section that makes the *wire encoder* actually serialize a non-empty `options` byte vector into the OPT RDATA (this section only needs the in-memory struct field populated correctly; section-06's own e2e tests are what prove it round-trips through the wire).

### `CookieSecret` DI wiring: `main.rs` → `ResolveQuery` → `assemble.rs`

`CookieSecret::generate()` is called once in `src/main.rs`, alongside where `SystemClock` is constructed (`main.rs:129`, `let clock: Arc<dyn Clock> = Arc::new(SystemClock);`), and wrapped in an `Arc<CookieSecret>`:

```rust
let cookie_secret = Arc::new(CookieSecret::generate());
```

`ResolveQuery` (`src/resolver/mod.rs:3341-3373`) currently has ~8 constructors (`new`, `with_cache`, `with_cache_and_policy`, `with_cache_and_backend_snapshot`, `with_cache_and_backend_handle`, and more) that all take `clock: Arc<dyn Clock>` as a **mandatory positional parameter**, because `Clock` is a trait object callers need to substitute (`FixedClock`) for deterministic tests — dozens of existing tests already construct `ResolveQuery` this way.

`ResolveQuery` also has two *other* request-scoped-but-constructed-once values, `max_chain_depth: u8` and `chaos: crate::config::ChaosConfig`, which deliberately are **not** parameters of any constructor — every constructor sets them to a compile-time default (`DEFAULT_MAX_CHAIN_DEPTH`, `ChaosConfig::default()`), and `main.rs` overrides them via post-construction setter methods once real config is available:

```rust
pub fn with_max_chain_depth(mut self, max_chain_depth: u8) -> Self {
    self.max_chain_depth = max_chain_depth;
    self
}

pub fn with_chaos_config(mut self, chaos: crate::config::ChaosConfig) -> Self {
    self.chaos = chaos;
    self
}
```

`CookieSecret` is a concrete value type (not a trait object needed for mock substitution in the vast majority of existing tests, which don't exercise Cookie behavior at all) — **prefer this setter pattern** (`with_cookie_secret(mut self, secret: Arc<CookieSecret>) -> Self`, defaulting every constructor to `Arc::new(CookieSecret::generate())`) over threading a new mandatory parameter through all ~8 `with_cache*` constructors and every one of the ~40 existing test call sites that construct a `ResolveQuery` with a `FixedClock` and don't care about cookies. This keeps the "mirror the Clock DI pattern" instruction satisfied in the sense that matters (generated once in `main.rs`, `Arc`-wrapped, stored on `ResolveQuery`, threaded down to where `assemble_response` needs it) without the invasiveness of a mandatory-parameter approach for a value most existing tests are indifferent to. If a reviewer specifically wants the mandatory-parameter shape instead, that's a defensible alternative — but be aware it touches every constructor and its callers, including test fixtures, which is a much larger and mostly mechanical diff for no behavioral gain.

Wire the setter in `main.rs` alongside the existing ones:

```rust
let cookie_secret = Arc::new(CookieSecret::generate());
let resolver = Arc::new(
    ResolveQuery::with_cache_policy_and_backend_snapshot(
        /* ...unchanged... */
    )
    .with_max_chain_depth(max_chain_depth)
    .with_single_flight_shard_count(cache.shard_count())
    .with_chaos_config(config.chaos.clone())
    .with_cookie_secret(Arc::clone(&cookie_secret)),
);
```

### Reaching `assemble_response`/`assemble_negative_response` from `ResolveQuery`

`serialize_cache_hit_answer`/`serialize_cache_hit_negative` (`mod.rs:4544-4578`) are the two call sites that need the widened arguments:

```rust
fn serialize_cache_hit_answer(
    &self,
    decoded: &DecodedQuery,
    resolved: &cache::ResolvedAnswer,
    request: &ResolveRequest,
) -> Vec<u8> {
    assemble_response(
        decoded.message.header.id,
        &decoded.question_wire,
        &decoded.features,
        resolved,
        request.received_at.0,
        !request.observed_source.is_tcp(),
        self.protocol.configured_max_udp_payload_size(),
        // NEW: &self.cookie_secret, request.client_ip
    )
}
```

`request.client_ip: IpAddr` is already available on `ResolveRequest` (`mod.rs:167-183`) at both call sites — no new plumbing needed for that value beyond passing it through. `self.cookie_secret` is the new `ResolveQuery` field described above.

## Tests (write these first)

From `claude-plan-tdd.md` Section 4:

### `QueryFeatures::from_message` — unit tests in `src/resolver/mod.rs`'s existing `#[cfg(test)] mod tests` block

- Given a message built from `a_query_with_edns_options(id, name, udp_payload_size, dnssec_ok, options)` (existing fixture, `mod.rs:7955-7963`) with `options` set to a well-formed 8-byte COOKIE option TLV (e.g. `[0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]`, same shape used in section-03's fixtures), `QueryFeatures::from_message(&Message::parse(&bytes).unwrap())` populates the new client-cookie field to `Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])`.
- Given a message with no EDNS OPT record at all (`a_query(id, name)`, `mod.rs:7857-7859`), the field is `None`.
- Given a message with an EDNS OPT record but no COOKIE option (e.g. `a_query_with_edns(id, name, udp_payload_size, dnssec_ok)`, empty options), the field is `None`.

### `requester_opt_record` — unit tests in `src/resolver/cache/assemble.rs`'s existing `#[cfg(test)] mod tests` block

- Given a `QueryFeatures` with `client_cookie: Some(cookie)` plus a `CookieSecret`, `client_ip: IpAddr`, and `now: SystemTime`, `requester_opt_record` returns `Some(Record)` whose `EdnsInfo.options` bytes decode to a COOKIE option (code 10, length 24) whose first 8 bytes equal `cookie` exactly and whose remaining 16 bytes equal `crate::protocol::edns_cookie::build_server_cookie(&secret, cookie, client_ip, now)` called directly with the same inputs (don't re-derive the RFC 9018 byte layout in this section's tests — that's section-02's job; just assert this function's output matches what `build_server_cookie`/`build_cookie_option` produce for identical inputs).
- Given a `QueryFeatures` with `client_cookie: None`, `requester_opt_record` returns the same options-less `Record` as today — an explicit **regression** test asserting byte-identical behavior to pre-change for non-Cookie requests. The existing `features(dnssec_ok: bool)` test helper (`assemble.rs:708-716`) will need its literal to add `client_cookie: None` once the field exists; every existing call site using that helper continues to exercise the no-cookie path unchanged.
- The existing OPT/truncation/negative-response tests need updating for the widened signature (new `cookie_secret`/`client_ip` arguments threaded through their `assemble_response`/`assemble_negative_response` calls), with their **original assertions unchanged** since none of them involve a Cookie-bearing query:
  - `assemble_response_includes_opt_record_when_requester_used_edns` (`assemble.rs:903-938`)
  - the truncated-response OPT-presence assertions around `assemble.rs:1672-1681`
  - `assemble_negative_response_includes_opt_record_when_requester_used_edns` (`assemble.rs:1684-1727`+)

  For all of these, pass a `CookieSecret::generate()` (or, if section-02 exposes a deterministic test constructor, a fixed-bytes one) and an arbitrary `client_ip` (e.g. `"192.0.2.10".parse().unwrap()`) — since none of these fixtures set a client cookie, the exact secret/IP values are irrelevant to their existing assertions and no new assertions are required on them.

## File paths

- `src/resolver/mod.rs` — `QueryFeatures` struct + `from_message` (production code), `ResolveQuery` struct/constructors/setters, `main.rs` DI call sites reached via `serialize_cache_hit_answer`/`serialize_cache_hit_negative`, plus new/updated unit tests in the existing `#[cfg(test)] mod tests` block.
- `src/resolver/cache/assemble.rs` — `requester_opt_record`, `build_servfail`, `finish_with_truncation_check`, `assemble_response`, `assemble_negative_response` (production code), plus updated/new tests in the existing `#[cfg(test)] mod tests` block.
- `src/main.rs` — construct `Arc<CookieSecret>` once (near `main.rs:129`'s `SystemClock` construction) and pass it into `ResolveQuery` via the new setter/constructor parameter (near `main.rs:130-149`'s existing `ResolveQuery::with_cache_policy_and_backend_snapshot(...)` call chain).
- `src/protocol/edns_cookie.rs` — read-only dependency from section-02; not modified by this section.

## Verification for this section

Per `RUST.md`'s gates:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets`
- `cargo test` — run at minimum:
  - the new `QueryFeatures::from_message` client-cookie tests (present/absent/EDNS-without-cookie cases)
  - the new `requester_opt_record` Cookie-present and Cookie-absent (regression) tests
  - the updated `assemble_response_includes_opt_record_when_requester_used_edns`, the truncated-response OPT tests, and `assemble_negative_response_includes_opt_record_when_requester_used_edns` — all must still pass with their original assertions
  - full existing suite, to confirm the widened `ResolveQuery` constructor surface (if the setter-pattern approach is used, no existing constructor call site should need updating; if the mandatory-parameter approach is used instead, every existing test constructing `ResolveQuery` needs a `cookie_secret` argument added) compiles and passes unchanged for every non-Cookie test

This section introduces no new observable end-to-end (wire-level) behavior by itself — the OPT record's `options` field is populated in-memory, but the wire *encoder* still hardcodes empty options until section-06 lands, so a full e2e "response actually carries a COOKIE option on the wire" assertion belongs in section-06, not here. Do not consider this section done until `cargo fmt`/`clippy`/`test` all pass per `AGENTS.md`'s Change Workflow.