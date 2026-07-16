# TDD Plan: EDNS Cookie cache-bypass fix

Mirrors `claude-plan.md`'s section breakdown. Rust's built-in `#[test]`/
`#[tokio::test]` framework, following this codebase's existing
`#[cfg(test)] mod tests` conventions (fixture helpers documented in
`claude-research.md` §7).

## Section 1: Cargo dependency change

- Test: `cargo build` succeeds after adding `rand` as a direct dependency
  and enabling `domain`'s `siphasher` feature (a build-passes check, not a
  unit test — verify via CI/`cargo test` running at all post-change).
- Test: `cargo tree` inspection confirms no unexpected heavy transitive
  dependencies were pulled in by `rand` (manual verification step, not an
  automated test).

## Section 2: `src/protocol/edns_cookie.rs` module

- Test: `parse_cookie_option` returns `Some(client_cookie)` for a
  well-formed 8-byte (client-cookie-only) COOKIE option.
- Test: `parse_cookie_option` returns `Some(client_cookie)` for a
  well-formed 16-40 byte (client+server cookie) COOKIE option, extracting
  only the first 8 bytes.
- Test: `parse_cookie_option` returns `None` for a malformed length (e.g.
  9, 15, 41 bytes).
- Test: `parse_cookie_option` returns `None` when no COOKIE option is
  present in the options blob.
- Test: `parse_cookie_option` returns `None` when more than one COOKIE
  option is present.
- Test: `parse_cookie_option` returns `Some(client_cookie)` when a
  well-formed COOKIE option is present **alongside** another EDNS option
  (e.g. NSID) — extraction still succeeds even though cache-admission
  (next test group) must not.
- Test: `is_solely_cookie_option` returns `Some(client_cookie)` when the
  *entire* options blob is exactly one well-formed COOKIE option.
- Test: `is_solely_cookie_option` returns `None` when a well-formed COOKIE
  option is present alongside another option (e.g. NSID) — the divergence
  from `parse_cookie_option` on this exact fixture is the core
  cache-admission-vs-extraction distinction and must be asserted
  explicitly.
- Test: `is_solely_cookie_option` returns `None` for the same malformed/
  absent/duplicate cases as `parse_cookie_option`.
- Test: `build_server_cookie` produces a 16-byte output with the correct
  Version(1)/Reserved(0)/Timestamp byte layout (big-endian) and, if the
  hash construction is hand-rolled rather than delegated to
  `domain::base::opt::cookie::StandardServerCookie::calculate`, matches
  RFC 9018 Appendix A's published test vectors exactly (including the
  little-endian SipHash-2-4 output serialization).
- Test: `build_server_cookie` produces different output for different
  client IPs (v4 vs v6, and different addresses) given the same client
  cookie and secret — confirms client IP is actually part of the hash
  input, not accidentally ignored.
- Test: `build_cookie_option` serializes the correct TLV shape (option
  code 10, length 24, client cookie followed by 16-byte server cookie).
- Test: `CookieSecret::generate()` produces a secret of the expected byte
  length (≥128 bits / 16 bytes) and two calls produce different secrets
  (basic randomness sanity check, not a statistical PRNG audit).

## Section 3: `cache_supported()` narrowing + regression test repointing

- Test: repoint `resolve_bypasses_cache_for_unsupported_edns_options`
  (`mod.rs:18996-19019`) to use a genuinely-still-unsupported option code
  (e.g. NSID = 3) instead of the currently-used Cookie-shaped bytes;
  confirm it still asserts bypass (`CacheBypass` metric, empty
  `cache.lookups`/`cache.stores`).
- Test (new): a well-formed Cookie-only query participates in cache
  lookup/store — inverse of the above, using a new `a_query_with_cookie`
  test-fixture helper (built on `a_query_with_edns_flags`,
  `mod.rs:7975+`) with a `RecordingCache` seeded to return a hit; assert
  `cache.lookups`/`cache.stores` are non-empty and `CacheBypass` is not
  incremented.
- Test (new): a query with both a well-formed Cookie option and another
  EDNS option (e.g. NSID) still bypasses the cache — confirms Goal 5 (no
  regression for other option combinations) holds through
  `is_solely_cookie_option`.
- Test: confirm `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
  (`mod.rs:19021-19047`) passes unmodified (no code change expected here,
  but re-run to confirm no incidental regression from the `cache_supported`
  edit).
- Test (new): cache lookup/`MissKey` construction
  (`mod.rs:4433-4440,4467-4474`) does not read EDNS option bytes at all —
  e.g. assert two Cookie-bearing queries for the same qname with
  *different* client cookies produce the identical cache lookup/key,
  pinning the cache-safety invariant this plan relies on.

## Section 4: `QueryFeatures` + secret/client-IP/clock threading through `requester_opt_record`

- Test: `QueryFeatures::from_message` populates the new client-cookie
  field correctly for a message with a well-formed COOKIE option, and
  leaves it `None` for a message without one.
- Test: `requester_opt_record` (`assemble.rs:437-447`), given a
  `QueryFeatures` with a client cookie present plus a `CookieSecret`/
  client IP/clock, returns an OPT record whose options bytes contain a
  correctly-shaped COOKIE option (client cookie echoed exactly, server
  cookie present and correctly computed for those inputs).
- Test: `requester_opt_record` returns the same options-less OPT record as
  today when no client cookie is present (regression check — behavior for
  non-Cookie requests must be byte-identical to pre-change).
- Test: existing `assemble.rs` OPT/truncation/negative-response tests
  (`assemble.rs:903-938,1672-1681,1684-1727`) updated for the widened
  `requester_opt_record` signature and still passing with their original
  assertions (these don't involve Cookie, so their expected output should
  be unchanged).

## Section 5: Cache-miss/recursive-response OPT path

- Test: a cache-miss (backend-forwarded) query carrying a well-formed
  Cookie option gets a response whose OPT record carries a fresh, correct
  server cookie — mirroring the cache-hit case in Section 6 but exercised
  through the recursive-miss/`mirrored_client_opt_record` path instead.
- Test: two coalesced/in-flight requesters for the same backend query,
  presenting *different* client cookies, each receive their own
  distinct, correctly-computed COOKIE option in their respective
  responses — not a shared/replayed one.
- Test: `recursive_synthesis_reused_own_framing` (`mod.rs:1744-1768`)
  updated/extended to cover the Cookie case: confirm coalesced requesters
  with different cookies do NOT get identical reused framing where the OPT
  record is concerned, even though other framing may still be shared.

## Section 6: OPT-record options serialization

- Test: the OPT-record wire-encoding function (whichever one currently
  hardcodes `options: Vec::new()` in `build_opt_record`/
  `build_opt_record_with_extended_rcode`, `protocol/mod.rs:1246-1278`)
  correctly serializes a non-empty `options` byte vector into the OPT
  RDATA, and round-trips correctly through the existing `parse_opt_record`
  read path (`protocol/mod.rs:2617-2641`) — parse(serialize(x)) == x for a
  COOKIE-bearing OPT record.
- Test (e2e): a cache-hit response to a Cookie-bearing query, decoded via
  `Message::parse`, has an OPT record containing a well-formed COOKIE
  option (correct client-cookie echo, correct-length server cookie).
- Test (e2e): two independent requesters (different client cookies,
  different client IPs) querying the same cached name each get their own
  correctly-computed, distinct COOKIE options in their respective
  responses — proving the OPT record is rebuilt per-request, never
  replayed from the cache, even though the underlying answer data is
  shared.

## Section 7: Knowledge-bundle documentation update

- No new tests — doc-only change. Confirm during review that the doc
  update accurately reflects Sections 1-6's actual landed behavior
  (including the explicit non-goals: no incoming-cookie validation, no
  BADCOOKIE, no anti-spoofing enforcement gained) rather than the
  as-planned behavior, per this repo's Knowledge Bundle change-workflow
  trigger.

## Section 8: `/security-review` pass

- No new tests — review-only. Confirm the review explicitly checks: no
  regression in any non-Cookie EDNS-bypass case (re-run the full
  `resolve_bypasses_cache_for_unsupported_*` test group), the
  malformed-Cookie-length case still bypasses safely, the `CookieSecret`
  is never logged/exposed/serialized anywhere reachable by a client, and
  no cache-key or `MissKey` code path was accidentally changed to depend
  on cookie bytes.
