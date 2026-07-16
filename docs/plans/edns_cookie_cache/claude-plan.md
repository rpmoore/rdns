# Implementation Plan: EDNS Cookie cache-bypass fix

## Overview

`rdns` is a Rust DNS resolver/proxy. Its answer cache currently refuses to
serve (or store into) the cache any query that carries an EDNS option of
any kind (`cache_supported()`, `src/resolver/mod.rs:5508-5520`). RFC 7873
DNS Cookies are attached by default by many modern stub resolvers/`dig`
invocations, so this bypass silently defeats caching — and the resolver's
recently-landed cache-hit TTL-remaining-time aging behavior — for a large
fraction of real-world traffic.

This plan implements a narrow, previously-decided fix: teach the resolver
to recognize a well-formed RFC 7873 COOKIE option (EDNS option code 10) as
compatible with caching. The cached *answer* data is unaffected; the OPT
pseudo-record (which carries the cookie) is never cached or replayed —
it is stripped from what gets stored and freshly rebuilt, with a
freshly-computed server cookie, on every response, cached or not. This
mirrors RFC 6891 §6.1's principle that OPT records are per-transaction,
not zone/answer data, and matches this codebase's existing
per-request-assembly architecture (`src/resolver/cache/assemble.rs`
already rebuilds the OPT record fresh per request for other reasons, e.g.
`requester_opt_record`, `assemble.rs:437-447`).

The server-cookie construction follows RFC 9018 ("Interoperable DNS
Server Cookies"), not RFC 7873 Appendix B's examples (which RFC 9018
explicitly retires as non-interoperable). This resolver will never reject
a query for cookie reasons and never validates an incoming server
cookie's correctness — it always processes the query normally and always
attaches a freshly-computed, valid server cookie. This is one of RFC
7873's own explicitly compliant behaviors (§5.2.3/§5.2.4 branch 3, "process
the request and provide a normal response"), not a corner cut, but it does
mean this implementation gains none of DNS Cookies' anti-off-path-spoofing
value — that comes from the rejection path this plan deliberately doesn't
build. This trade-off must be written down in the knowledge-bundle
documentation output so it isn't later mistaken for a security control.

This is a separate PR from the already-landed `ttl_remaining` work (docs,
Clock DI, edge-case tests — branch `fix_ttl_edns_bypass`, commits
`06b4da1`/`0b834cd`/`0130240`). It is security-sensitive (parses untrusted
network input to feed a caching decision) and the final section of this
plan is a mandatory `/security-review` pass before the PR opens, per
`AGENTS.md`.

## Goals

1. Enable a well-formed RFC 7873 COOKIE option (and nothing else besides
   the DO bit / version 0 / extended RCODE 0, exactly as today) to
   participate in cache lookup and cache store, instead of unconditionally
   bypassing.
2. Compute and attach a fresh, RFC-9018-correct server cookie on every
   response (cache hit or miss) when the incoming query carried a COOKIE
   option, echoing that query's client cookie.
3. Never cache or replay OPT-record bytes across requests — the OPT record,
   including the COOKIE option, is always rebuilt per request from
   per-request inputs (client cookie, client IP, the resolver's one
   startup-generated secret).
4. Do this with zero new top-level Cargo dependencies, by enabling optional
   features on the already-present `domain` crate.
5. Preserve all existing EDNS-bypass behavior for every case other than a
   well-formed Cookie option: non-zero extended RCODE, non-zero version,
   unrecognized flag bits, and any other/malformed EDNS option (including a
   malformed Cookie option) must continue to bypass the cache exactly as
   today.
6. Update the knowledge bundle to document the new Cookie-cache-compatible
   behavior and its explicit non-goals (no incoming-cookie validation, no
   BADCOOKIE, no anti-spoofing enforcement).
7. Land a mandatory `/security-review` pass as the final step before PR.

## Non-goals

- RFC 7830 Padding support (deferred to whenever DoT/DoH support exists).
- BADCOOKIE (RCODE 23) generation or any query-rejection behavior tied to
  cookie validity.
- Validating an incoming server cookie's hash or timestamp window at all —
  this implementation never branches on that validity, so no validation
  code is written.
- RFC 7873 §5.2.2 FORMERR for malformed-length COOKIE options — falls back
  to today's generic "any weird EDNS content bypasses the cache" behavior,
  unchanged.
- Secret rotation (RFC 9018 §5) — one static in-memory secret for the
  resolver's process lifetime.
- Any change to `CacheTtlPolicy`, TTL aging, or the `Clock` DI seam (already
  landed in `ttl_remaining`).
- Any change to `cache_supported()`'s handling of EDNS options/flags/version
  other than Cookie.
- New metrics or events — Cookie-bearing requests flow through existing
  `CacheHit`/`CacheMiss`/`CacheBypass` counters unchanged.

## Architecture

### Dependency configuration (one small new direct dependency, no new crypto crate)

`Cargo.toml`'s existing `domain` dependency changes from:

```
domain = { version = "0.12.1", default-features = false, features = ["zonefile", "bytes", "std"] }
```

to also include `"siphasher"` in the `features` list. This unlocks
`domain::base::opt::cookie::{Cookie, ClientCookie, ServerCookie,
StandardServerCookie}`, which implements the RFC 9018 server-cookie
construction with published test vectors (RFC 9018 Appendix A) already
covered by `domain`'s own test suite. `StandardServerCookie::calculate`
takes a raw `secret: &[u8; 16]` argument, so rdns code calls it directly
without ever importing `siphasher` itself — that crate stays purely an
internal `domain` implementation detail.

**Correction from plan review**: enabling `domain`'s `"rand"` feature
does *not* give rdns's own code a usable public API — that feature only
unlocks `domain`'s *internal* use of `rand` (e.g. inside its own
middleware). Generating `CookieSecret`'s random startup bytes requires
`rand` as **rdns's own small, direct dependency** — add it plainly to
`Cargo.toml`. This is a genuine (if minimal) new dependency, justified
under `RUST.md:20`'s "improve correctness" bar: rolling a bespoke PRNG for
a security-relevant secret is exactly the kind of thing that crate exists
to avoid getting wrong. Net dependency picture: one small new direct
dependency (`rand`), one feature-flag change on an existing dependency
(`domain`'s `siphasher`), zero new hashing/crypto crates. Verify via
`cargo tree` that `rand` doesn't pull in anything unexpectedly heavy.

### New module: `src/protocol/edns_cookie.rs`

Protocol-layer module (per `AGENTS.md`'s "protocol owns DNS wire-format
parsing, validation, and encoding" layering) owning:

- **`CookieSecret`** — a type wrapping the resolver's one random,
  process-lifetime server-cookie secret. Holds the raw secret bytes
  (RFC 9018 §4.2: SHOULD be ≥128 bits). Constructed once via a
  `CookieSecret::generate()` associated function using `domain`'s `rand`
  feature (or the `rand` crate directly if `domain`'s re-export isn't
  ergonomic for this) — mirrors `SystemClock`'s role as the one
  process-lifetime side-effect-holding value (`src/main.rs:739-741`).
  Held behind an `Arc<CookieSecret>` at the call sites that need it,
  exactly like `Arc<dyn Clock>`.

- **`ClientCookie`** — a `[u8; 8]` newtype (or direct type alias) for the
  8-byte client cookie extracted from an incoming query.

- **`parse_cookie_option(options: &[u8]) -> Option<ClientCookie>`** —
  scans the raw EDNS options TLV blob (the same `edns.options: Vec<u8>`
  field already populated by `parse_opt_record`, `src/protocol/mod.rs:2617-2641`)
  for exactly one option with code 10 (COOKIE). Returns `Some(client_cookie)`
  only when: the option is present exactly once, and its length is a
  well-formed RFC 7873 §4 length (8, or 16-40 inclusive) — extracting just
  the first 8 bytes (client cookie) and ignoring/discarding any server
  cookie bytes present, per the decided non-goal of not validating
  incoming server cookies. Returns `None` for: no COOKIE option, more than
  one COOKIE option, or a malformed length.

  This function answers "is there a client cookie to echo," a distinct
  question from cache admissibility (next bullet) — a query can have a
  well-formed Cookie *and* some other EDNS option (e.g. NSID); the cookie
  should still be extracted/echoed on the (bypassed) response, but the
  query must **not** be treated as cache-compatible in that case. Keeping
  extraction and cache-admission as two separate functions (rather than
  overloading one predicate for both) avoids the ambiguity a plan-review
  pass flagged: it's easy to accidentally let "a cookie is present"
  leak into "this query is cache-safe" if they're the same check.

- **`is_solely_cookie_option(options: &[u8]) -> Option<ClientCookie>`** —
  the cache-admission predicate used only by `cache_supported()` (next
  section). Returns `Some(client_cookie)` only when the *entire* raw
  `options` byte slice is consumed by exactly one well-formed COOKIE
  option and nothing else — any trailing bytes (another option, e.g. NSID
  or Padding) means `None`. This is intentionally stricter than
  `parse_cookie_option` and must have its own test explicitly covering
  the Cookie+NSID case (still bypasses cache) as distinct from the
  Cookie-only case (participates in cache).

- **`build_server_cookie(secret: &CookieSecret, client_cookie: ClientCookie, client_ip: IpAddr, now: SystemTime) -> [u8; 16]`**
  — computes the RFC 9018 §4.4 16-byte server cookie: 1-byte Version(1),
  3-byte Reserved(0), 4-byte big-endian Unix timestamp, 8-byte SipHash-2-4
  output (serialized **little-endian** per the documented `domain`-crate
  gotcha — cite RFC 9018 Appendix A test vectors in the accompanying unit
  tests if this hash construction is hand-rolled instead of delegated to
  `domain::base::opt::cookie::StandardServerCookie::calculate`). Hash input
  is `client_cookie(8) | version(1) | reserved(3) | timestamp(4) |
  client_ip(4 or 16, depending on v4/v6)`, keyed by `secret`. Prefer calling
  into `domain`'s `StandardServerCookie::calculate` directly if its type
  signature accommodates this codebase's raw-byte style without requiring
  adoption of `domain`'s `Message`/`Octets` abstractions elsewhere; only
  hand-roll the SipHash-2-4 call against `siphasher` directly if `domain`'s
  API is awkward to call from raw bytes.

- **`build_cookie_option(client_cookie: ClientCookie, server_cookie: [u8; 16]) -> Vec<u8>`**
  — serializes a full COOKIE option's RDATA-option-TLV bytes (option code
  10, length 24, client cookie + server cookie), ready to be appended into
  an OPT record's options bytes.

Unit tests for this module (per Goal in Verification section below) should
include RFC 9018 Appendix A's published test vectors if `build_server_cookie`
hand-rolls the hash construction, to guarantee interoperability with other
RFC-9018-compliant resolvers rather than only self-consistency.

### `cache_supported()` narrowing

`src/resolver/mod.rs:5508-5520` changes its `edns.options.is_empty()`
condition to: "`edns.options` is empty, **or**
`is_solely_cookie_option(&edns.options)` returns `Some(_)`." All other
conditions in `cache_supported` (extended RCODE 0, version 0, no flags
beyond DO) are unchanged. This keeps the function's existing shape and
single responsibility — it still answers "is this query cache-compatible,"
just with one more allowed case. Using the stricter
`is_solely_cookie_option` (rather than `parse_cookie_option`) here is
deliberate: it guarantees Goal 5 (every other EDNS-option case still
bypasses unchanged) holds even for the combination of a well-formed Cookie
alongside some other option.

This is the only change needed at the cache-admission gate
(`probe_cache`, `mod.rs:4409-4479`, is unaffected beyond calling the
updated `cache_supported`).

### Threading the client cookie through to response assembly

`QueryFeatures` (`mod.rs:241-274`) gains a new field, e.g.
`client_cookie: Option<ClientCookie>` (or reuse a suitably-named field —
implementer's call on exact naming), populated in
`QueryFeatures::from_message` by calling `parse_cookie_option` against
`message.edns.as_ref().map(|e| &e.options)`. This is the same struct
already threaded into `assemble_response`/`assemble_negative_response` at
serve time via `decoded.features` (`mod.rs:4544-4578`), so no new
plumbing is needed to get this value to the assembly layer beyond adding
the field and populating it.

### Threading the secret and client IP to `requester_opt_record`

`requester_opt_record` (`src/resolver/cache/assemble.rs:437-447`) is
extended to accept the additional inputs it needs to build a COOKIE
option when `requester_features.client_cookie` is `Some`: the
`Arc<CookieSecret>`, the requester's `client_ip: IpAddr` (already
available on `ResolveRequest`, `mod.rs:167-183`, at every call site that
currently calls `assemble_response`/`assemble_negative_response`/
`build_servfail`/`finish_with_truncation_check`), and a `now: SystemTime`
(available via the same `Clock`/`FixedClock` seam already threaded through
this codebase per the `ttl_remaining` Clock-DI work — reuse it rather than
calling `SystemTime::now()` directly, to stay consistent with that
already-landed convention and keep this path unit-testable with a fixed
clock).

When `client_cookie` is present, `requester_opt_record` calls
`build_server_cookie` and `build_cookie_option`, and passes the resulting
bytes into the OPT record it constructs (instead of building the
options-less OPT it builds today). When absent, behavior is byte-for-byte
identical to today.

Every caller of `requester_opt_record` (`build_servfail`,
`finish_with_truncation_check`, `assemble_response`,
`assemble_negative_response`, all in `src/resolver/cache/assemble.rs`)
needs the widened parameter list threaded through — this is a mechanical
signature change at each call site, not new logic at each site.

### Cache-miss / recursive-response path also needs cookie-aware OPT rebuilding

**Gap caught in plan review**: `requester_opt_record` and its four callers
above are exclusively on the **cache-hit** serve path. Goal 2 requires a
fresh server cookie on *every* response, including cache misses — but
cache misses that go to a live backend and get reshaped for the client use
a **separate** mechanism: `mirrored_client_opt_record`
(`src/resolver/mod.rs`, called from the recursive-miss/coalesced-response
trimming branch around `mod.rs:4960-4963` and `mod.rs:5023-5029`, itself
delegating to `crate::protocol::message_edns_opt_record`,
`protocol/mod.rs:1296-1303`) and the related per-requester OPT reattachment
described in the `filter_response_for_requester` doc comment
(`mod.rs:1628-1630,1685-1687,1721-1729`).

This is a second, parallel integration point that needs the same
treatment as `requester_opt_record`: when the requester's query carried a
well-formed Cookie (via `parse_cookie_option`, not the stricter cache-
admission predicate — a cache-miss response should still echo a Cookie
even for queries that wouldn't have been cache-admissible), compute and
attach a fresh server cookie here too, using the same `CookieSecret`/
`client_ip`/clock inputs. Confirm during implementation whether
`mirrored_client_opt_record`/`message_edns_opt_record` can be extended
directly, or whether the cleanest fix is a small shared helper that both
`requester_opt_record` (cache-hit path) and this recursive-miss path call
into, to avoid duplicating the cookie-building logic across the two OPT-
rebuild call sites.

Also check `recursive_synthesis_reused_own_framing`
(`mod.rs:1744-1768`) — an existing test that currently reuses response
framing across coalesced requesters by comparing only EDNS-presence and
the DO bit. Once responses carry per-requester Cookie data, this
comparison needs to account for the fact that two coalesced requesters
with different client cookies must still get their own, distinct OPT
records even though they share the same underlying backend answer — this
test's assumptions (or its assertions) will need revisiting.

### OPT-record wire encoding gains an options payload

`build_opt_record`/`build_opt_record_with_extended_rcode`
(`src/protocol/mod.rs:1246-1278`) currently hardcode `options: Vec::new()`
on the `EdnsInfo` they build. This plan adds a variant (or an additional
parameter) that accepts a pre-built `options: Vec<u8>` (the COOKIE-option
TLV bytes from `build_cookie_option`) and writes them into the OPT
record's RDATA — extending whatever function already serializes
`EdnsInfo.options` into wire bytes (the counterpart to the existing
`parse_opt_record`/`validate_edns_options` read path,
`protocol/mod.rs:2617-2651`) to handle a non-empty case for the first time
in the response-writing direction. Confirm during implementation whether
an options-serialization function already exists for some other code path
(e.g. any place that round-trips `EdnsInfo` back to wire bytes) before
writing a new one from scratch.

### Secret construction and DI wiring (mirrors `Clock`)

`CookieSecret::generate()` is called once in `src/main.rs`, alongside
where `SystemClock` is constructed (`main.rs:739-741`), and wrapped in an
`Arc<CookieSecret>`. This `Arc` is threaded into `ResolveQuery`
construction the same way `Arc<dyn Clock>` already is (per the
`ttl_remaining` section-02 Clock-DI precedent) and stored wherever the
resolver keeps its other request-scoped-but-constructed-once dependencies,
reaching `serialize_cache_hit_answer`/`serialize_cache_hit_negative`
(`mod.rs:4544-4578`) and from there into the widened
`assemble_response`/`assemble_negative_response`/`requester_opt_record`
call chain described above.

## Section breakdown guidance (for TDD plan / section splitting)

Natural section boundaries, in dependency order:

1. **Cargo dependency change** — enable `domain`'s `siphasher` feature and
   add `rand` as a new small direct dependency; confirm build succeeds and
   `cargo tree` shows no unwanted surprises.
2. **`src/protocol/edns_cookie.rs` module** — `CookieSecret`,
   `ClientCookie`, `parse_cookie_option`, `is_solely_cookie_option`,
   `build_server_cookie`, `build_cookie_option`, with unit tests including
   RFC 9018 Appendix A vectors (if hand-rolled) and malformed-length/
   multiple-option/mixed-with-other-option rejection cases for both
   `parse_cookie_option` and `is_solely_cookie_option` (these two must be
   tested against the same fixtures to confirm their divergence on the
   Cookie+NSID case is intentional and correct).
3. **`cache_supported()` narrowing + regression test repointing** —
   the allowlist change itself (using `is_solely_cookie_option`),
   repointing `resolve_bypasses_cache_for_unsupported_edns_options`
   (`mod.rs:18996-19019`) to a genuinely-still-unsupported option code
   (e.g. NSID = 3) since it currently uses a Cookie-shaped option as its
   example, and adding a new e2e test asserting a well-formed Cookie query
   now participates in cache lookup/store (mirroring
   `resolve_service_with_cache`/`RecordingCache` conventions,
   `mod.rs:9750-9829` area) plus a Cookie+NSID case still bypassing.
   Confirm `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
   (`mod.rs:19021-19047`) needs no change (it's version/flags, not
   options). Also add/verify a test asserting cache lookup/`MissKey`
   construction (`mod.rs:4433-4440,4467-4474`) never reads EDNS option
   bytes — pinning the cache-safety invariant this plan relies on, rather
   than leaving it as narrative reasoning only.
4. **`QueryFeatures` + secret/client-IP/clock threading through
   `requester_opt_record` and its callers** — the plumbing section: widen
   `QueryFeatures`, widen `requester_opt_record`'s signature and its four
   call sites, wire `CookieSecret` DI from `main.rs` down to
   `ResolveQuery`. Update existing `assemble.rs` OPT/truncation/negative-
   response tests (`assemble.rs:903-938,1672-1681,1684-1727`) for the
   widened signatures.
5. **Cache-miss/recursive-response OPT path** — extend
   `mirrored_client_opt_record`/`message_edns_opt_record` (or a shared
   helper factored out with `requester_opt_record`) so cache-miss
   responses also get a fresh, correct Cookie option when the query
   carried one. Revisit `recursive_synthesis_reused_own_framing`
   (`mod.rs:1744-1768`) for the coalesced-requesters-with-different-
   cookies case.
6. **OPT-record options serialization** — extend the write-direction OPT
   encoding to emit non-empty `options` bytes; e2e test asserting a
   cache-hit response to a Cookie-bearing query carries a correctly-shaped
   COOKIE option (client cookie echoed, server cookie present and the
   right length) in its OPT record, for two independent requesters with
   different client cookies/IPs against the same shared cache entry
   (proving the OPT record — unlike the cached answer — really is
   per-requester, not replayed).
7. **Knowledge-bundle documentation update** —
   `docs/knowledge/resolver/caching/answer-cache.md` (already touched by
   `ttl_remaining` section-01): document the Cookie cache-compatibility
   behavior, the OPT-record-never-cached invariant, and the explicit
   security trade-off (no incoming-cookie validation, no BADCOOKIE, no
   anti-spoofing enforcement gained).
8. **`/security-review` pass** — final section. Run against the complete
   diff. Confirm no regression in any non-Cookie EDNS-bypass case, confirm
   the malformed-Cookie-length case still bypasses safely, confirm the
   secret is never logged/exposed, confirm no cache-key dependency on
   cookie bytes was accidentally introduced.

## Verification

- `cargo fmt`, `cargo clippy`, `cargo test` (full suite) per `RUST.md`.
- Unit tests for `edns_cookie.rs` (parse edge cases, RFC 9018 vectors if
  hand-rolled).
- e2e tests: Cookie-bearing query gets cache hit/store (inverse of
  today's bypass test); non-Cookie EDNS options/flags/version still
  bypass unchanged; malformed-Cookie-length still bypasses; two
  requesters sharing a cache entry get distinct, correctly-shaped
  per-requester COOKIE options.
- `/security-review` before PR (mandatory, final section).
- Knowledge-bundle doc updated in the same change per `AGENTS.md`'s
  Knowledge Bundle trigger.
