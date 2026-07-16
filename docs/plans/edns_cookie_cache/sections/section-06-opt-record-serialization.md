Now writing the final section content.

# Section 06: OPT-record wire-encoding gains an `options` payload

## Dependencies on other sections

- **Requires section-02** (`src/protocol/edns_cookie.rs`) to exist: this
  section's own round-trip test uses `build_cookie_option`/
  `build_server_cookie`/`CookieSecret` from that module to construct a
  realistic COOKIE-option byte blob to serialize. (A round-trip test could
  technically use hand-written raw bytes instead and skip this dependency,
  but using the real helper is more representative and is what the plan
  calls for.)
- **Does NOT require section-03 or section-04 to be merged** for its core
  wire-encoding change and round-trip test — those exercise
  `src/protocol/mod.rs` in isolation.
- **Important sequencing caveat**: this document (and `claude-plan-tdd.md`
  Section 6) also describes two "e2e" tests — "a cache-hit response to a
  Cookie-bearing query carries a COOKIE option" and "two independent
  requesters sharing a cache entry get distinct per-requester cookies."
  Those two tests exercise the *full* resolve path
  (`cache_supported()`/cache admission from **section-03**,
  `requester_opt_record`'s cookie-building plus `CookieSecret` DI into
  `ResolveQuery` from **section-04**). They will not compile/pass in a
  tree that only has section-02 and this section's protocol-layer change
  applied. If you are implementing this section in parallel with 03/04
  (per the plan's dependency graph, which allows that), write and land
  this section's own wire-encoding change and round-trip test first, and
  either defer the two e2e tests until 03 and 04 are also present in your
  working tree, or write them last once all three are merged together.
  Section-05 (cache-miss OPT path) already depends on this section AND
  section-04 landing first, so by the time section-05 starts, this
  ordering concern is moot.
- Blocks **section-05** (cache-miss/recursive-response OPT path needs this
  section's serialization support to test end-to-end) and **section-07**
  (knowledge-bundle docs, written after all behavior sections land).
- Deepens **section-04**'s own test coverage: once this section lands,
  section-04's `requester_opt_record` tests can assert on full wire-level
  round trips (`Message::parse` of the built response) instead of only
  checking the in-memory `EdnsInfo.options` field. That's a test-depth
  improvement for section-04, not a hard compile-time dependency.

## Background

`rdns` is a Rust DNS resolver/proxy. This plan (see
`docs/plans/edns_cookie_cache/claude-plan.md` for full context) teaches
the resolver to recognize a well-formed RFC 7873 DNS Cookie EDNS option as
cache-compatible and to attach a fresh, RFC 9018-correct server cookie on
every response (cache hit or miss) when the query carried a client
cookie. Section-02 already built the pure byte-construction logic for
that COOKIE option (`build_cookie_option` produces the option's TLV
bytes: code 10, length 24, client cookie + 16-byte server cookie).
Sections 04 and 05 are responsible for *deciding when* to call that
logic and *threading* the resulting bytes down to response assembly. This
section is the missing link between those two: the low-level function
that actually writes an OPT record's `options` bytes into the response's
wire bytes has never been exercised with a non-empty `options` value
before — this section makes that path work and proves it round-trips
correctly.

### Where the gap actually is

`src/protocol/mod.rs:1246-1278`:

```rust
pub(crate) fn build_opt_record(udp_payload_size: u16, dnssec_ok: bool) -> Record {
    build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 0)
}

fn build_opt_record_with_extended_rcode(
    udp_payload_size: u16,
    dnssec_ok: bool,
    extended_rcode: u8,
) -> Record {
    let flags = if dnssec_ok { EDNS_DO_FLAG } else { 0 };
    let ttl = (u32::from(extended_rcode) << 24) | u32::from(flags);
    Record {
        name: String::new(),
        rtype: OPT_RECORD_TYPE,
        rclass: udp_payload_size,
        ttl,
        record: RecordData::OPT(EdnsInfo {
            udp_payload_size,
            extended_rcode,
            version: 0,
            flags,
            dnssec_ok,
            options: Vec::new(),
        }),
    }
}
```

`options: Vec::new()` is hardcoded — there is no way today to build an
OPT `Record` with any options bytes attached. `build_opt_record` has
exactly three call sites today, none of which need to change behavior in
this section:

- `src/protocol/mod.rs:628` — `build_badvers_response` calls
  `build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 1)`
  directly (needs the non-zero extended RCODE variant).
- `src/protocol/mod.rs:1302` (inside `message_edns_opt_record`) — calls
  `build_opt_record(udp_payload_size, edns.dnssec_ok)`. This is the
  recursive-miss path's OPT builder; section-05 will change *this* call
  site to attach a cookie, not this section.
- `src/resolver/cache/assemble.rs:443` (inside `requester_opt_record`) —
  calls `crate::protocol::build_opt_record(udp_payload_size,
  requester_features.dnssec_ok)`. This is the cache-hit path's OPT
  builder; section-04 will change *this* call site to attach a cookie,
  not this section.

This section's job is narrower: add the ability to build an OPT `Record`
with non-empty `options` bytes at all, and prove that once built, those
bytes serialize to the wire correctly and parse back correctly. Sections
04 and 05 are the ones that will actually call the new/widened function
with real cookie bytes at their respective call sites — that wiring is
out of scope here.

### The write-direction serializer already exists — confirm, don't rewrite

`src/protocol/mod.rs:1358-1519` (`write_rdata`) is the generic RDATA
writer used by every response builder (`write_record` →
`write_opt_record` for OPT records specifically, `mod.rs:1345-1356`). Its
`OPT` arm, at `mod.rs:1516`, is:

```rust
RecordData::OPT(info) => out.extend_from_slice(&info.options),
```

This already writes whatever bytes are in `EdnsInfo.options` verbatim —
it does not need to change to support a non-empty `options` vector; it
was simply never exercised with one because nothing ever constructed an
`EdnsInfo` with non-empty `options` for a *response*. **Confirm this
during implementation** (re-read `write_rdata`'s OPT arm before writing
any new serialization code) rather than assuming a new writer is needed
— the plan explicitly calls out checking for this before writing
anything new from scratch. The actual gap is entirely on the
*construction* side (`build_opt_record*`), not the *serialization* side
(`write_rdata`).

The read-direction counterpart, `parse_opt_record`
(`src/protocol/mod.rs:2617-2641`), also already copies the raw options
bytes verbatim and validates their TLV framing via `validate_edns_options`
(`mod.rs:2643-2651`):

```rust
fn parse_opt_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    udp_payload_size: u16,
    ttl: u32,
) -> Result<RecordData> {
    let extended_rcode = ((ttl >> 24) & 0xff) as u8;
    let version = ((ttl >> 16) & 0xff) as u8;
    let flags = (ttl & 0xffff) as u16;
    let options = dns_message
        .get(offset..end)
        .ok_or(DnsParseError::UnexpectedEof)?
        .to_vec();
    validate_edns_options(&options)?;

    Ok(RecordData::OPT(EdnsInfo {
        udp_payload_size,
        extended_rcode,
        version,
        flags,
        dnssec_ok: (flags & EDNS_DO_FLAG) != 0,
        options,
    }))
}
```

So the read path is also already correct and needs no changes. This
section is purely: give `build_opt_record*` a way to accept a non-empty
`options: Vec<u8>`, and add a test proving the write path
(`write_rdata`/`write_opt_record`) and read path (`parse_opt_record`)
actually round-trip a non-empty options blob correctly end to end —
which has never been tested before, since nothing has ever produced one.

## File to modify

`/home/rpmoore/code/rdns/src/protocol/mod.rs`

### 1. Widen `build_opt_record_with_extended_rcode` to accept `options`

Change its signature to take an `options: Vec<u8>` parameter and use it
instead of the hardcoded `Vec::new()`:

```rust
fn build_opt_record_with_extended_rcode(
    udp_payload_size: u16,
    dnssec_ok: bool,
    extended_rcode: u8,
    options: Vec<u8>,
) -> Record {
    let flags = if dnssec_ok { EDNS_DO_FLAG } else { 0 };
    let ttl = (u32::from(extended_rcode) << 24) | u32::from(flags);
    Record {
        name: String::new(),
        rtype: OPT_RECORD_TYPE,
        rclass: udp_payload_size,
        ttl,
        record: RecordData::OPT(EdnsInfo {
            udp_payload_size,
            extended_rcode,
            version: 0,
            flags,
            dnssec_ok,
            options,
        }),
    }
}
```

Update its one direct caller outside `build_opt_record` itself —
`build_badvers_response` (`mod.rs:628`) — to pass `Vec::new()` explicitly,
preserving today's behavior byte-for-byte (BADVERS responses never carry
a Cookie option; that's out of scope for this plan):

```rust
let opt = build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 1, Vec::new());
```

### 2. Keep `build_opt_record` byte-for-byte unchanged in behavior

```rust
pub(crate) fn build_opt_record(udp_payload_size: u16, dnssec_ok: bool) -> Record {
    build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 0, Vec::new())
}
```

This keeps `build_opt_record`'s existing two-argument call sites
(`message_edns_opt_record` at `mod.rs:1302`, `requester_opt_record` in
`assemble.rs:443`, and the `protocol/mod.rs:4176` test) compiling
unchanged — sections 04/05 will later change *those specific call sites*
to call the new function below instead, when they have a cookie to
attach. This section does not touch either of those two call sites.

### 3. Add a new function that accepts options directly

```rust
/// `build_opt_record`, with a pre-built `options` TLV byte vector (e.g.
/// a COOKIE option from `crate::protocol::edns_cookie::build_cookie_option`)
/// attached to the OPT record's RDATA instead of always building an
/// options-less OPT. Used by `resolver::cache::assemble::requester_opt_record`
/// (section-04, cache-hit path) and `resolver::mirrored_client_opt_record`/
/// `message_edns_opt_record` (section-05, cache-miss/recursive path) once a
/// client cookie needs echoing back to the requester.
pub(crate) fn build_opt_record_with_options(
    udp_payload_size: u16,
    dnssec_ok: bool,
    options: Vec<u8>,
) -> Record {
    build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 0, options)
}
```

Naming is the implementer's call (`build_opt_record_with_options` matches
the existing `build_opt_record_with_extended_rcode` naming convention in
this file) — what matters is that a `pub(crate)` entry point exists that
lets a caller supply non-empty `options` bytes without touching the two
existing options-less call sites' behavior.

### 4. No changes needed to `write_rdata`, `write_opt_record`, `parse_opt_record`, or `validate_edns_options`

As established above, all four already handle non-empty `options` bytes
correctly — they were just never exercised with any before. Do not modify
them as part of this section; the round-trip test below is what proves
this.

## Tests (write these first)

All tests below live in `src/protocol/mod.rs`'s existing
`#[cfg(test)] mod tests` block (`mod.rs:2789`, `use super::*;`), following
this file's existing test conventions (e.g. `build_truncated_wire_response_includes_question_cd_and_mirrored_opt`
at `mod.rs:4169`, which already builds an OPT record via `build_opt_record`
and asserts on the parsed-back response — this section's round-trip test
follows the same shape but with non-empty `options`).

### Round-trip test: `build_opt_record_with_options` → wire bytes → `parse_opt_record`

- Build a COOKIE option's bytes via section-02's
  `crate::protocol::edns_cookie::build_cookie_option` (fed by
  `build_server_cookie`/a `CookieSecret`/a fixed client cookie/client
  IP/timestamp — all from section-02, all synchronous, no I/O).
- Call `build_opt_record_with_options(udp_payload_size, dnssec_ok, options)`
  to get a `Record`.
- Serialize it via `write_opt_record` into a `Vec<u8>` buffer (mirroring
  how `write_message`/response builders append an OPT record to the
  additional section today).
- Parse the resulting bytes back via `Message::parse` (constructing a
  minimal well-formed DNS message wrapper around just the header +
  question + this one additional record, following the existing
  `push_header`/`push_question` test-helper conventions used elsewhere in
  this file's test module, e.g. `mod.rs:4170-4176`) — or call
  `parse_opt_record` more directly if a helper already exists in this
  test module for parsing a single record's RDATA in isolation; check
  for one before writing new scaffolding.
- Assert the round-tripped `EdnsInfo.options` bytes are byte-identical to
  the original `options` vector; assert `udp_payload_size`, `dnssec_ok`,
  `extended_rcode` (0), and `version` (0) all survive the round trip
  unchanged too.
- This is `parse(serialize(x)) == x` for a COOKIE-bearing OPT record, per
  `claude-plan-tdd.md` Section 6's first test.

### Regression check: existing OPT tests still pass unchanged

- `build_truncated_wire_response_includes_question_cd_and_mirrored_opt`
  (`mod.rs:4169`) and the `build_badvers_response` tests both call
  `build_opt_record`/`build_opt_record_with_extended_rcode` with no
  options — confirm these still pass with their original assertions after
  the signature widening (they should require zero test-code changes,
  only production-code call-site updates at `mod.rs:628` per step 1
  above).

### e2e tests (require section-03 and section-04 to be present — see Dependencies above)

These two live in `src/resolver/mod.rs`'s test module, not
`protocol/mod.rs`, since they exercise the full resolve path
(`resolve_service_with_cache`/`RecordingCache` conventions, `mod.rs:9762-9846`
area) rather than just the protocol-layer OPT builder in isolation.
Use a new `a_query_with_cookie(id, name, client_cookie: [u8; 8]) -> Vec<u8>`
test-fixture helper built on top of the existing
`a_query_with_edns_flags(id, name, udp_payload_size, dnssec_ok,
extended_rcode, version, extra_flags, options) -> Vec<u8>`
(`mod.rs:7986-8009`), constructing the COOKIE option's TLV bytes (code 10,
length 8) as the `options` argument.

- **Test**: a cache-hit response to a Cookie-bearing query, decoded via
  `Message::parse`, has an OPT record containing a well-formed COOKIE
  option: client cookie exactly matches what the query sent, server
  cookie is present and 16 bytes long (don't assert its exact byte
  value here beyond length/presence — section-02's own tests already
  pin the hash construction's correctness against RFC 9018 vectors; this
  test is about the OPT record actually carrying it end to end). Follow
  the `RecordingCache`/`resolve_service_with_cache` pattern already used
  by `resolve_bypasses_cache_for_unsupported_edns_options`
  (`mod.rs:19008` area) and the new Cookie-participates-in-cache test
  from section-03, but assert on the OPT record of the final response
  instead of (or in addition to) the cache lookup/store counters.
- **Test**: two independent requesters — different client cookies,
  different client IPs — querying the same qname such that both hit the
  same shared cache entry (seed a `RecordingCache` with a hit, issue two
  separate `resolve` calls with two different `a_query_with_cookie`-built
  queries and two different `client_ip` values on their
  `ResolveRequest`s) each get their own correctly-computed, distinct
  COOKIE option in their respective responses. Assert the two responses'
  server-cookie bytes differ from each other (since client cookie and/or
  client IP differ, the SipHash-2-4 output must differ too) even though
  both responses carry byte-identical answer data from the shared cache
  entry. This is the test proving the OPT record is rebuilt per-request,
  never replayed from the cache, even though the underlying answer is
  shared — the core invariant Goal 3 of the plan depends on.

If section-03/04 are not yet merged into your working tree when you reach
this section, write the round-trip test and the two regression checks
above now, and leave a comment referencing this section's Dependencies
note explaining why the two e2e tests are deferred, rather than writing
code that won't compile.

## Verification for this section

- `cargo fmt`, `cargo clippy --all-targets`, `cargo test` per `RUST.md`.
- The round-trip test and existing-OPT-test regression checks must pass
  using only sections 01, 02, and this section's own protocol-layer
  change — no dependency on 03/04 for those.
- The two e2e tests require sections 03 and 04 to also be present in the
  same working tree/PR to compile and pass; confirm they pass once all of
  01–06 are merged together, before moving on to section-05 (which
  depends on this section plus section-04).
- No knowledge-bundle documentation update is expected yet for this
  section — deferred to section-07, once all behavior sections (03, 04,
  05, 06) have landed.

## What was actually implemented

Sections 03 and 04 were already landed by the time this section started, so
both e2e tests were written immediately rather than deferred.

- `build_opt_record_with_extended_rcode` (`src/protocol/mod.rs`) widened
  with an `options: Vec<u8>` parameter exactly as planned; its `build_badvers_response`
  call site updated to pass `Vec::new()` explicitly.
- `build_opt_record` kept byte-for-byte unchanged in behavior (delegates
  with `Vec::new()`).
- New `pub(crate) fn build_opt_record_with_options(udp_payload_size, dnssec_ok,
  options) -> Record` added, matching the planned shape/naming.
- `write_rdata`/`write_opt_record`/`parse_opt_record`/`validate_edns_options`
  confirmed unchanged, per the plan.
- **Deviation from the plan's stated assumption**: the plan doc's
  "Background" section describes `requester_opt_record`
  (`src/resolver/cache/assemble.rs`, section-04's cache-hit call site) as a
  future consumer of `build_opt_record_with_options`. In practice,
  section-04 had already implemented cookie-attachment by calling the
  existing `build_opt_record` and then mutating the resulting
  `EdnsInfo.options` field in place (`opt.record`'s `RecordData::OPT(edns)`
  arm, `edns.options = build_cookie_option(...)`), rather than switching to
  a widened/new constructor call. Both approaches produce identical wire
  bytes and the existing section-04 tests already passed pre-existing —
  no change to `assemble.rs` was made in this section, and the new
  `build_opt_record_with_options` function currently has zero production
  call sites (it's consumed only by this section's own round-trip test).
  It remains intended for `resolver::mirrored_client_opt_record`/
  `message_edns_opt_record` (section-05, cache-miss/recursive path) to
  call once that section lands — that dependency is unaffected by this
  deviation.
- Round-trip test: `build_opt_record_with_options_round_trips_cookie_option_bytes`
  (`src/protocol/mod.rs`, in `mod tests`) — builds a real COOKIE option via
  section-02's helpers, serializes via `write_opt_record`, and parses the
  resulting bytes back via `parse_record`/`parse_test_record` (a fresh,
  from-scratch parse, not a shortcut), asserting options/payload-size/DO/
  extended-rcode/version all round-trip correctly.
- Two e2e tests added to `src/resolver/mod.rs`'s `mod tests`:
  `resolve_cache_hit_response_carries_cookie_option_for_cookie_bearing_query`
  and `resolve_shared_cache_hit_gives_each_requester_a_distinct_cookie`,
  both exercising the full `ResolveQuery::resolve` cache-hit path and
  asserting on parsed wire bytes (`Message::parse`), per the plan.
- Test count: 3 new tests added (1 in `protocol/mod.rs`, 2 in
  `resolver/mod.rs`); full suite (`cargo test`) passes at 599 lib tests + 8
  integration tests, 0 failed.
- Code review: one low-severity finding (a doc comment on
  `build_opt_record_with_options` inaccurately claimed it was already used
  by `requester_opt_record`) — fixed by rewording the comment to describe
  the actual current cache-hit-path mechanism and mark section-05 as the
  pending consumer. See `implementation/code_review/section-06-diff.md` and
  `section-06-interview.md`.