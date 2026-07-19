## Section 08 (BADCOOKIE detection and transport-conditional gating) — code review

Reviewed by `deep-implement:code-reviewer` subagent against `section-08-badcookie-detection.md`'s acceptance criteria and `section-08-diff.md`.

### Findings and resolution

1. **MEDIUM (spec conformance)**: `server_cookie_matches` never explicitly checked the presented tail's version byte is `1` before calling `check_hash` — relied entirely on the version byte being folded into the hash input (so a forged version would need the secret anyway). Not exploitable, but doesn't match RFC 9018 §4.3's literal "MUST treat as invalid" requirement.
   - **Fixed**: added an explicit `if version != 1 { return false; }` check ahead of the hash comparison, with a comment explaining it's belt-and-suspenders given `check_hash` already ties version into the hash.

2. **MEDIUM (test coverage gap)**: test-matrix item 9 (IPv4-mapped IPv6) was only exercised as a unit test directly against `server_cookie_matches`, unlike items 1-8 which are all full `service.resolve(...)` end-to-end tests. Left the wiring from `ResolveRequest.client_ip` through `probe_cache`/`invalid_server_cookie` unverified for this case.
   - **Fixed**: added `resolve_accepts_valid_cookie_from_mapped_ipv6_client`, an end-to-end test using a `::ffff:192.0.2.1`-shaped client IP with a real `service.resolve(...)` call.

3. **LOW (weak regression test)**: `server_cookie_matches_accepts_cookie_after_time_has_advanced` doesn't advance any clock value since `server_cookie_matches` has no verification-time parameter at all — the test is behaviorally identical to the plain acceptance test. Its own comment already concedes this ("this test's real assertion is that omission itself"). No code change; the test still documents the intended property even though it can't independently prove it further than the function signature already guarantees.

4. **LOW (style, false positive)**: reviewer flagged fully-qualifying `crate::protocol::edns_cookie::...` at every call site instead of a `use` import as inconsistent with the file's conventions. Checked against existing code (`cache_supported`'s call to `crate::protocol::edns_cookie::is_solely_cookie_option`): fully-qualifying `edns_cookie` module items at the call site *is* this file's existing convention (only top-level `protocol::mod` items like `build_badcookie_response` get imported via the big `use` block). No change needed.

5. **LOW (minor redundancy)**: `probe_cache`'s reject branch discards the `ClientCookie` from `invalid_server_cookie`, and `protocol_error`'s `InvalidServerCookie` arm re-parses the same options a second time to recover it. Correct but scans the TLV twice per rejected request. Not fixed — this mirrors the exact shape the plan itself specified (`invalid_server_cookie` returning `Option<ClientCookie>` used only as a boolean signal at its one call site, with `protocol_error` re-deriving independently per the plan's own example code), and the extra scan only happens on the rejection path, not the common case.

6. **LOW (minor perf)**: `CookieVerification::ClientAndServer.server_cookie_tail: Vec<u8>` heap-allocates per well-formed cookie-bearing request. Not fixed — this is the exact field type the plan specified, and premature to optimize a bounded (≤32 byte) allocation without a demonstrated need.

7. **Informational**: `edns_cookie.rs`'s module doc comment still says "never validates an incoming server cookie's hash or timestamp," which this section's `server_cookie_matches` now contradicts. Confirmed this is explicitly section-09's job (`section-09-badcookie-review-docs.md` owns doc corrections) — not a gap in this section's scope.

### Verified correct (no changes needed)
- `locate_cookie_for_verification`'s TLV loop: truncation checked before the len==8/16-40 branches, so a truncated would-be-`ClientAndServer` correctly degrades to `Malformed`; duplicate detection fires on any second COOKIE option; non-COOKIE options are correctly skipped.
- `server_cookie_matches` reuses the presented tail's own timestamp (confirmed against `domain` 0.12.2's `StandardServerCookie::check_hash`, which hashes from `self`'s own bytes, never "now"); correctly rejects non-16-byte tails with no panic risk.
- Transport gating (`is_tcp` checked first, RFC 7873 §5.2.3), the BADVERS-before-BADCOOKIE ordering guarantee (structural, via `decode_or_protocol_error` running before `probe_cache`), the `probe_cache` `Result`/`Ok` wiring, and the `protocol_error` malformed-cookie fix (closing section-07's known placeholder gap) are all correct and covered by dedicated tests.
