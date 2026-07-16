<!-- PROJECT_CONFIG
runtime: rust-cargo
test_command: cargo test
END_PROJECT_CONFIG -->

<!-- SECTION_MANIFEST
section-01-cargo-dependencies
section-02-edns-cookie-module
section-03-cache-supported-narrowing
section-04-query-features-opt-threading
section-05-cache-miss-opt-path
section-06-opt-record-serialization
section-07-knowledge-bundle-docs
section-08-security-review
END_MANIFEST -->

# Implementation Sections Index: EDNS Cookie cache-bypass fix

See `../claude-plan.md` for full architecture, `../claude-plan-tdd.md` for
test stubs per section, `../claude-spec.md`/`../claude-interview.md` for
decided scope, and `../reviews/codex-review.md` +
`../claude-integration-notes.md` for the plan-review pass this index
already incorporates.

## Dependency Graph

| Section | Depends On | Blocks | Parallelizable |
|---|---|---|---|
| section-01-cargo-dependencies | - | section-02 | Yes |
| section-02-edns-cookie-module | section-01 | 03, 04, 06 | No |
| section-03-cache-supported-narrowing | section-02 | 07 | Yes (with 04, 06) |
| section-04-query-features-opt-threading | section-02 | 05, 07 | Yes (with 03, 06) |
| section-05-cache-miss-opt-path | section-04, section-06 | 07 | No |
| section-06-opt-record-serialization | section-02 | 04 (test depth), 05, 07 | Yes (with 03, 04) |
| section-07-knowledge-bundle-docs | 03, 04, 05, 06 | section-08 | No |
| section-08-security-review | section-07 | - | No |

## Execution Order

1. `section-01-cargo-dependencies` (no dependencies)
2. `section-02-edns-cookie-module` (after 01)
3. `section-03-cache-supported-narrowing`, `section-04-query-features-opt-threading`,
   `section-06-opt-record-serialization` (parallel, all depend only on 02)
4. `section-05-cache-miss-opt-path` (after 04 AND 06 — reuses the OPT-building
   helper from 04 and needs 06's wire-serialization support to test
   end-to-end)
5. `section-07-knowledge-bundle-docs` (after 03, 04, 05, 06 — documents final
   landed behavior across all of them)
6. `section-08-security-review` (final — full-diff review before PR)

## Section Summaries

### section-01-cargo-dependencies
Enable `domain`'s `siphasher` Cargo feature; add `rand` as a new small
direct dependency for `CookieSecret` generation. Verify build + `cargo
tree`. No behavior change yet.

### section-02-edns-cookie-module
New `src/protocol/edns_cookie.rs`: `CookieSecret`, `ClientCookie`,
`parse_cookie_option` (extraction), `is_solely_cookie_option`
(cache-admission predicate — deliberately distinct from extraction per the
plan-review finding), `build_server_cookie` (RFC 9018 SipHash-2-4
construction, little-endian hash-output gotcha), `build_cookie_option`
(TLV serialization). Fully unit-testable in isolation, no other module
depends on this yet.

### section-03-cache-supported-narrowing
Narrow `cache_supported()` (`mod.rs:5508-5520`) using
`is_solely_cookie_option`. Repoint
`resolve_bypasses_cache_for_unsupported_edns_options` to a genuinely
still-unsupported option code; add inverse Cookie-participates-in-cache
test and a Cookie+NSID-still-bypasses test; add a cache-key/`MissKey`
never-reads-option-bytes invariant test.

### section-04-query-features-opt-threading
Widen `QueryFeatures` with a client-cookie field populated in
`QueryFeatures::from_message`. Widen `requester_opt_record` and its four
cache-hit callers (`build_servfail`, `finish_with_truncation_check`,
`assemble_response`, `assemble_negative_response`) to accept
`CookieSecret`/client IP/clock and build a COOKIE option when a client
cookie is present. Wire `CookieSecret` DI from `main.rs` down to
`ResolveQuery`, mirroring the existing `Clock` DI pattern. Update existing
`assemble.rs` OPT/truncation/negative tests for the widened signatures.

### section-05-cache-miss-opt-path
Extend the recursive-miss/coalesced-response OPT rebuild
(`mirrored_client_opt_record`/`message_edns_opt_record`) to also attach a
fresh Cookie option, covering Goal 2's "every response, cache hit or miss."
Revisit `recursive_synthesis_reused_own_framing` for coalesced requesters
with different client cookies.

### section-06-opt-record-serialization
Extend the OPT-record wire encoder (`build_opt_record`/
`build_opt_record_with_extended_rcode`, currently hardcoding `options:
Vec::new()`) to serialize a non-empty `options` byte vector, with a
round-trip test against the existing `parse_opt_record` read path. Add the
first true e2e tests: a cache-hit response to a Cookie-bearing query
carries a correctly-shaped COOKIE option in its OPT record; two
independent requesters sharing a cache entry get distinct, correctly
per-requester cookies.

### section-07-knowledge-bundle-docs
Update `docs/knowledge/resolver/caching/answer-cache.md` (already touched
by `ttl_remaining` section-01) to document actual landed Cookie
cache-compatibility behavior, the OPT-record-never-cached invariant, and
the explicit security trade-off (no incoming-cookie validation, no
BADCOOKIE, no anti-spoofing enforcement gained by this implementation).

### section-08-security-review
Mandatory `/security-review` pass against the complete diff before PR, per
`AGENTS.md`'s untrusted-input/network-code trigger. Confirms no regression
in non-Cookie EDNS-bypass cases, malformed-Cookie-length still bypasses,
secret never exposed, no cache-key dependency on cookie bytes introduced.
