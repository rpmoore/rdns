Now I have all the context needed. Writing the final section content.

---

# section-09-badcookie-review-docs

## Overview

This is the final section of Track B (BADCOOKIE handling). By the time this section starts, section-07 (wire-level RCODE 23 support: `build_badcookie_response`, the `QueryValidationError::InvalidServerCookie` variant, `protocol_error` routing) and section-08 (the recompute-and-compare detection check wired into `probe_cache`, with its full transport-conditional/first-contact/malformed-cookie test matrix) have both landed. This section closes out Track B before its PR opens: it adds the handful of tests B2's matrix doesn't already cover (duplicate-cookie-option handling, plus the transport-conditional e2e pair), makes a documented judgment call on whether BADCOOKIE needs its own `docs/knowledge/` concept doc, and runs `/security-review` over the detection/comparison logic and the new wire-response builder.

This section corresponds to plan `§B3`, the BADCOOKIE portion of `§C1`, and the Track-B half of `§C2` in `/home/rpmoore/code/rdns/docs/plans/sec_work/claude-plan.md`. There is no `§C3` (rollout note) for Track B — that requirement is DNSSEC-specific (Track A's on-by-default/fail-closed-timeout risk) and belongs entirely to `section-06-dnssec-review-docs`.

## Dependencies

- **section-08-badcookie-detection** must be complete: this section's remaining tests build directly on the detection function section-08 wired into `probe_cache` (`src/resolver/mod.rs`, called just before the `cache_supported(decoded)` branch at `probe_cache`, `:5228-5246` as of this plan's writing — confirm current line numbers before editing, since section-08 will have added code here), and this section's `/security-review` covers that function plus the section-07 wire-response builder together as one reviewed surface.
- Transitively depends on section-07 for `build_badcookie_response`, `QueryValidationError::InvalidServerCookie`, and the extended `ResponseFactory::protocol_error` signature (`cookie_secret`, `client_ip`, `now` parameters) that section-08's detection path calls into on the reject-over-UDP branch.
- Nothing downstream depends on this section; it is the last step in Track B before the PR opens. Track A (sections 01-06) is fully independent and does not depend on this section or vice versa — the two tracks touch disjoint files (Track B: `src/protocol/mod.rs`, `src/protocol/edns_cookie.rs`, `src/resolver/mod.rs`'s `BasicResponseFactory`/`ConfiguredResponseFactory`/`ResponseFactory`/`probe_cache`; Track A: `Cargo.toml`, `src/config/mod.rs`, new `src/resolver/dnssec_validation.rs`-style modules).

## Background: what section-08 already tested vs. what's left

Per `claude-plan-tdd.md`'s own framing: "B2's tests above already cover the core matrix; this section covers what remains — duplicate-option handling and the e2e transport pair." Section-08's test suite (already landed by the time this section starts) covers:

- EDNS-version check (BADVERS) running and rejecting before cookie logic is reached at all, for a request with both an unsupported EDNS version and an invalid cookie (ordering).
- Tampered server cookie + UDP → BADCOOKIE; same + TCP → normal.
- Malformed (wrong-length/truncated) server-cookie TLV + UDP → BADCOOKIE; same + TCP → normal.
- No server-cookie tail at all (first contact) + UDP → normal, freshly issued cookie attached, explicitly not BADCOOKIE; same + TCP → identical normal-processing behavior.
- Server cookie computed with the wrong secret (simulated restart) + UDP → BADCOOKIE.
- IPv4-mapped IPv6 source address with an otherwise-valid server cookie → accepted identically to the equivalent plain IPv4 source (proves IP-normalization reuse).

This section does **not** re-derive or duplicate any of that matrix. It adds exactly two things: a duplicate-cookie-option test, and the e2e transport-conditional pair (unit tests can get the check-function logic right while still being wired wrong at the transport-threading level — this needs its own explicit coverage, not just unit tests against the check function in isolation).

## Tests

### Test 1: duplicate cookie options are handled consistently with the existing `_rejects_duplicates` behavior

Background: `locate_cookie_option` (`src/protocol/edns_cookie.rs:75-111`), the shared scanner underneath `parse_cookie_option` and `is_solely_cookie_option`, already rejects a request containing **more than one** COOKIE option by returning `None` for the whole scan — this predates this plan and is pinned by the existing `parse_cookie_option_rejects_duplicates` test (`edns_cookie.rs:274-278`):

```rust
#[test]
fn parse_cookie_option_rejects_duplicates() {
    let mut options = cookie_option_bytes(CLIENT_COOKIE, None);
    options.extend_from_slice(&cookie_option_bytes(CLIENT_COOKIE, None));
    assert_eq!(parse_cookie_option(&options), None);
}
```

Because `locate_cookie_option` returns `None` (not "a client cookie was found, but treat it as no-server-cookie" or "treat it as invalid") for a duplicate-COOKIE-option request, the request looks identical — from every downstream caller's perspective, including section-08's new detection function — to a request that had no COOKIE option in it at all. There is no separate "duplicate" code path to special-case; the existing scan-layer rejection already collapses it into the "absent" case before the new detection logic ever runs.

Add a test (in whichever test module section-08 placed its detection-function tests — likely `src/resolver/mod.rs`'s test module, alongside the tampered/malformed/first-contact tests listed above; reuse whatever helper section-08 built for constructing a decoded query with a given raw cookie-options byte blob) asserting:

- A request whose EDNS options contain **two** COOKIE options (mirror `parse_cookie_option_rejects_duplicates`'s byte construction: two full `cookie_option_bytes(...)` blobs concatenated, regardless of whether either one, in isolation, would look tampered/malformed/valid) is processed **normally on both UDP and TCP** — no BADCOOKIE on either transport, and (if section-08's detection path issues a fresh cookie on the "no server-cookie tail" branch) the same fresh-cookie-issuance behavior a genuinely cookie-less request would get.
- This is explicitly a "not specially bypassed" test, per the plan's own phrasing — assert that the duplicate case is *not* silently treated as an invalid/tampered cookie (which would incorrectly trigger BADCOOKIE over UDP) and *not* given any bespoke duplicate-specific handling; it must fall through to exactly the same code path a cookie-less request takes, because that's what `locate_cookie_option` already guarantees upstream of the new check.

Stub:

```rust
#[test]
fn probe_cache_duplicate_cookie_options_processed_normally_not_badcookie() {
    // Build a decoded query whose EDNS options bytes are two concatenated
    // well-formed COOKIE options (mirrors edns_cookie::tests::
    // parse_cookie_option_rejects_duplicates's byte construction).
    // Assert: UDP -> normal processing, no BADCOOKIE, fresh cookie issued
    // (same as the first-contact case). TCP -> identical normal processing.
}
```

### Test 2 & 3: e2e transport-conditional pair

Plan §B3 / TDD §B3 explicitly call for e2e coverage here, not just unit tests: "this is exactly the kind of behavior that's easy to get right in a unit test against the check function but wrong in wiring (e.g. forgetting to thread transport type through correctly)."

Add these to `tests/e2e_config_toml.rs` (this repo's synthetic-fixture, loopback-only e2e suite — see its existing `send_udp`/`send_tcp` request/response round-trip pattern used throughout that file, e.g. the DO-bit test around `:949-961`), using `tests/support/mod.rs`'s `RawQueryBuilder`/`send_udp`/`send_tcp`/`parse_response`/`opt_record` helpers:

- **e2e test A (UDP)**: build a raw query with a COOKIE option carrying a valid-length client cookie plus a garbage (structurally well-formed but wrong) 16-byte server-cookie tail, send it over UDP to a running test server, and assert the parsed response's combined extended RCODE — `(u16::from(opt.extended_rcode) << 4) | u16::from(response.header.r_code())` (same computation section-07's wire-split test used, `src/protocol/mod.rs:4160-4162`'s pattern) — equals `23`, and that the response's OPT record carries a well-formed 24-byte COOKIE option (code 10, 8-byte echoed client cookie + 16-byte server cookie) — a structural check, not a byte-for-byte secret-derived comparison, since `edns_cookie`'s items are `pub(crate)` and not reachable from this integration-test crate across the crate boundary.
- **e2e test B (TCP)**: the identical bad-cookie query, sent over TCP instead, asserts a normal answer (NOERROR, real answer data, no extended-RCODE-23 signaling) — proving the same tampered bytes get materially different treatment purely based on transport, which is precisely the wiring risk this pair exists to catch.

**`RawQueryBuilder` needs extending first** (`tests/support/mod.rs:560-679`): its current `edns(udp_payload_size, dnssec_ok)` method (`:620-623`) only tracks a `(u16, bool)` tuple and `build()` (`:635-678`) hardcodes the OPT record's RDLENGTH to `0` (`:674`, `bytes.extend_from_slice(&0u16.to_be_bytes())`) — there is no existing way to attach arbitrary EDNS option bytes (e.g. a COOKIE option) to a built query. Add support for this, e.g.:

- A new field `edns_options: Option<Vec<u8>>` and builder method `pub fn edns_options(mut self, options: Vec<u8>) -> Self` (requires `.edns(...)` to also have been called, since the OPT record itself is still gated on `self.edns.is_some()`).
- In `build()`'s EDNS branch (`:666-675`), replace the hardcoded `0u16` RDLENGTH with `self.edns_options.as_ref().map_or(0, |o| o.len()) as u16`, and append the option bytes (if present) after the RDLENGTH.

Construct the COOKIE option TLV by hand in the test (option code `10` as a 2-byte big-endian value, 2-byte big-endian length, 8-byte client cookie, 16-byte garbage/tampered server-cookie tail — same TLV shape `cookie_option_bytes` in `edns_cookie.rs`'s test module already builds internally, just re-derived here since that helper is also `#[cfg(test)]`-private to its own crate module and not exported).

Stubs:

```rust
#[tokio::test]
async fn bad_server_cookie_over_udp_returns_badcookie_with_fresh_cookie() {
    // RawQueryBuilder::new(...).edns(1232, false).edns_options(tampered_cookie_option_bytes())
    // send_udp -> parse_response -> assert combined extended rcode == 23,
    // assert OPT record carries a well-formed 24-byte COOKIE option.
}

#[tokio::test]
async fn bad_server_cookie_over_tcp_returns_normal_answer() {
    // Identical tampered-cookie query, sent via send_tcp instead.
    // Assert NOERROR / real answer data, not RCODE 23.
}
```

## Task: `docs/knowledge/` judgment call (plan §C1, BADCOOKIE portion)

Plan §C1 states: "Evaluate whether BADCOOKIE's addition to `edns_cookie.rs` warrants its own new concept doc or just an update to inline doc comments — use judgment per AGENTS.md (a subsystem with real invariants warrants a doc; a scoped addition to an already-tested, already-documented module may not need a standalone doc)."

**Regardless of which way that judgment call lands, one specific existing doc section is now factually wrong and must be updated either way** — this is not optional, and is more concrete than the open "new doc or not" question:

`/home/rpmoore/code/rdns/docs/knowledge/resolver/caching/answer-cache.md`, the "**Security trade-off — read this before assuming any anti-spoofing protection exists**" section (currently at `:212-230`), states:

> This resolver never validates an incoming *server* cookie's hash or timestamp window, never generates BADCOOKIE (RCODE 23), and never rejects a query for cookie-related reasons — every query is processed normally and every response gets a freshly-computed, valid server cookie, unconditionally. [...] this implementation gains **no** anti-off-path-spoofing value from DNS Cookies.

This is no longer true once Track B ships. Update this section to state:

- The resolver **does now** validate an incoming server cookie (recompute-and-compare via `build_server_cookie`, wired into `probe_cache` by section-08) and **does** generate BADCOOKIE (RCODE 23) — but **only over UDP**; the RFC 7873 §5.2.3 TCP carve-out means a tampered/stale/malformed server cookie over TCP is still processed normally, unconditionally, exactly as this paragraph currently describes for *all* transports today. Say this transport split explicitly — a reader skimming only the first sentence should not conclude BADCOOKIE applies uniformly.
- A client cookie with **no server-cookie tail at all** (first contact) is still processed normally on both transports with a fresh cookie issued — this specific case is unchanged by Track B and remains exactly as this paragraph already describes it; say so explicitly so a reader doesn't assume first-contact traffic is now also gated.
- Correct the anti-spoofing conclusion: this resolver now gains **some** anti-off-path-spoofing value from DNS Cookies over UDP (an off-path attacker without visibility into a legitimate client's already-issued server cookie cannot forge a response the client will accept, matching RFC 7873's intended protection model for that transport) — but still gains **none** over TCP, where the existing carve-out means a tampered cookie is silently tolerated. Do not overstate this: TCP's own inherent difficulty-to-off-path-spoof is what RFC 7873 §5.2.3 is relying on there, not anything this resolver newly does.
- Update the module doc comment at `src/protocol/edns_cookie.rs:15-21` (the doc header currently states "This module never validates an incoming server cookie's hash or timestamp (no BADCOOKIE handling, no secret rotation) -- see the parent plan's non-goals") and `parse_cookie_option`'s doc comment (`:113-131`, whose own comment repeats the same now-stale non-goal) to reflect that server-cookie validation now exists (in the section-08 detection path, not in `parse_cookie_option`/`locate_cookie_option` themselves, which still only extract the client cookie and remain otherwise unchanged) — point to wherever section-08 actually placed the new comparison function rather than re-describing its mechanics inline in this module's header comment.
- Update this file's `timestamp` frontmatter field to reflect the edit.

**Then make the actual judgment call** on a standalone concept doc:

- Arguments for a standalone doc: BADCOOKIE introduces a real invariant (the transport-conditional gating rule, the first-contact-is-not-an-error-case rule, the exact IP-normalization-reuse requirement between issuance and verification) that a future reader debugging "why did this UDP client get RCODE 23" would benefit from finding in one place rather than reverse-engineering from code comments across three files (`edns_cookie.rs`, `protocol/mod.rs`, `resolver/mod.rs`).
- Arguments against: `edns_cookie.rs` is already a well-documented, already-tested module (module-level doc comment, per-function doc comments, existing test suite) and this is a scoped addition to it, not a new subsystem — the updated `answer-cache.md` security-trade-off section above may already be sufficient context for the caching-relevant angle, with the transport/gating specifics covered by section-07/08's own code comments and this-plan-driven doc comment updates.
- If a standalone doc is warranted: suggested location `/home/rpmoore/code/rdns/docs/knowledge/resolver/edns-cookies.md` (or extend `answer-cache.md`'s existing cookie section further rather than forking — use judgment on which reads better once the actual section-07/08 code and its comments exist to ground it), following the same frontmatter/structure conventions as the DNSSEC concept doc in section-06 (YAML frontmatter: `type`, `title`, `description`, `resource`, `tags`, `timestamp`; grounded prose with real `file:line` references, not placeholders). Add an index entry in `/home/rpmoore/code/rdns/docs/knowledge/resolver/index.md` if created.
- If inline-only is chosen: state explicitly, in the PR description or a commit-message note, that this judgment call was made and why — per AGENTS.md's Knowledge Bundle instructions, this is a documented decision, not a silently skipped step.

Whichever way the doc-or-not call lands, do **not** skip the `answer-cache.md` security-trade-off update above — that one is not judgment-call-gated, since it currently states something now factually false.

## Task: Run `/security-review` over Track B (plan §C2)

Run `/security-review` covering the full surface Track B built:

- **The detection/comparison logic** (section-08): the recompute-and-compare check itself, its two-case split (invalid/stale/malformed-but-present vs. no-tail-at-all), the transport-conditional gating (UDP rejects, TCP doesn't), the ordering requirement relative to the EDNS-version check, and the IP-normalization-reuse requirement (any divergence between issuance-time and verification-time address normalization would either cause spurious BADCOOKIE rejections or, worse, silently accept a cookie that should have failed).
- **The new wire-response builder** (section-07): `build_badcookie_response`'s extended-RCODE split correctness, and that the manually-composed header-flags path (RCODE nibble `7`, which has no `ResponseCode` enum variant) doesn't introduce a flags-composition bug that a normal `write_message_header` call would have caught by construction.
- This is explicitly required because both tracks "handle attacker-controlled wire bytes ... that an adversary can craft to try to bypass validation" (plan overview) — cookie bytes specifically for this track: a malformed-but-present cookie option, a truncated TLV, or a duplicate-option request are all attacker-controlled inputs this pass must confirm are handled safely (no panics, no bypass of the check, no confusion between "absent" and "invalid").

Address findings, or document explicitly why a given finding is not being acted on, per `AGENTS.md`'s PR-feedback-resolution rule ("When reviewing GitHub PR feedback, always mark the feedback as resolved when the feedback has been addressed, or state why the comment was not addressed"). If addressing feedback materially changes the diff, run one follow-up `/codex:adversarial-review` on the updated diff before committing, per `AGENTS.md`'s standing Change Workflow rule.

Separately, per `AGENTS.md`'s standing rules (not specific to this section, but a gate this section must also satisfy before Track B's PR is considered done): run the `verify` skill and satisfy the fmt/clippy/test gates in `RUST.md`, independent of the security review.

## Verification gates

Per this repo's standing rules (`RUST.md`), before considering this section done:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets` — no new warnings, including in the extended `RawQueryBuilder`.
- `cargo test` — full suite, including the new duplicate-cookie-option unit test.
- `cargo test --test e2e_config_toml` (or whatever invocation this repo's e2e suite normally uses for `tests/e2e_config_toml.rs` specifically) — the two new e2e tests pass.
- `/security-review` run over the detection/comparison logic and the wire-response builder; findings addressed or explicitly documented as not-addressed.
- `verify` skill run against the affected flow (a bad-cookie UDP query producing RCODE 23, the same query over TCP producing a normal answer) before reporting done.

## Acceptance criteria

- [x] A duplicate-cookie-options request is confirmed, by a new test, to be processed identically to a cookie-less request on both UDP and TCP — no BADCOOKIE, no special-cased duplicate handling.
- [x] `RawQueryBuilder` (`tests/support/mod.rs`) supports attaching arbitrary EDNS option bytes to a built query.
- [x] Two new e2e tests in `tests/e2e_config_toml.rs` cover the transport-conditional pair: a tampered server cookie over UDP returns combined extended RCODE 23 with a well-formed COOKIE option attached; the identical query over TCP returns a normal answer.
- [x] `docs/knowledge/resolver/caching/answer-cache.md`'s "Security trade-off" section (`:212-230` as of this plan's writing) no longer states the resolver never generates BADCOOKIE or never rejects cookie-related queries — it accurately describes the UDP-only gating, the unchanged first-contact behavior, and the unchanged TCP carve-out; frontmatter `timestamp` updated.
- [x] `src/protocol/edns_cookie.rs`'s module doc comment (`:15-21`) and `parse_cookie_option`'s doc comment no longer claim server-cookie validation doesn't exist anywhere in the resolver.
- [x] The standalone-concept-doc-or-inline-only judgment call has been made and is documented (either the new doc exists and is indexed, or the PR description/commit note states the inline-only decision and why).
- [x] `/security-review` has been run over the detection/comparison logic and the wire-response builder; findings addressed or explicitly documented as not-addressed.
- [x] `verify` skill and `RUST.md`'s fmt/clippy/test gates pass.

## Implementation notes (what was actually built)

- **e2e test target name changed from the plan's suggestion.** The plan
  suggested querying `known-a.rdns.test` for both new e2e tests. During
  implementation this was found to be wrong: `try_local_lookup` runs
  before `probe_cache` in `ResolveQuery::resolve()`'s pipeline
  (`src/resolver/mod.rs:4677-4693`), so a local-zone hit like
  `known-a.rdns.test` would short-circuit before the cookie check ever
  ran, making the test pass for the wrong reason (or not exercise the
  intended code path at all). Both e2e tests were switched to query
  `cookie-check.rdns.test` instead (absent from `forward_toml`'s
  `[[local_dns_entries]]`), using `spawn_silent_upstream` for the
  UDP/BADCOOKIE test (the backend is never reached on a BADCOOKIE reject,
  so it only needs to exist) and `spawn_canned_upstream` with a real
  A-record response for the TCP test (which needs to reach the backend
  and return a real answer).
- **Duplicate-cookie-option unit tests assert cookie-echo absence, not
  just "not BADCOOKIE."** First code-review pass flagged that the initial
  tests only checked `BackendFailure`/`ResolveDecisionKind`, not the
  plan's stated "processed identically to a cookie-less request" claim.
  Strengthened both tests to assert no COOKIE option is echoed back. The
  first attempt at this assertion (`opt.options.is_empty()`, expecting an
  OPT record to be present) was itself wrong and failed: for a duplicate
  cookie, `parse_cookie_option` returns `None` (same as absent), so
  `prepare_backend_result`'s forward-mode own-cookie rebuild
  (`rebuild_forward_response_with_own_cookie`, gated on
  `decoded.features.client_cookie.is_some()`,
  `src/resolver/mod.rs:6213-6242`) never triggers — the response is the
  mocked upstream's raw relayed bytes verbatim, which carries no OPT
  record at all (not an OPT with empty options). The final assertion
  checks no COOKIE option is present in `additionals` at all, robust to
  OPT-present-vs-absent.
- **Judgment call: inline-only documentation, no standalone
  `docs/knowledge/resolver/edns-cookies.md`.** Confirmed with the user
  during the code-review interview. `src/protocol/edns_cookie.rs` already
  carries module-level and per-function doc comments plus a full test
  suite; `docs/knowledge/resolver/caching/answer-cache.md`'s "Security
  trade-off" section now states the transport-conditional gating rule,
  the first-contact rule, and the duplicate-collapses-to-absent rule
  explicitly, and is also the section a reader debugging cache/cookie
  interaction would land on first. No new file was created; no
  `docs/knowledge/resolver/index.md` entry was added.
- **`/security-review` result: no HIGH/MEDIUM findings.** Run over the
  full branch diff with focus on Track B's detection/comparison logic
  (section-08) and wire-response builder (section-07). Full report:
  `docs/plans/sec_work/implementation/code_review/section-09-security-review.md`.
- **Defensive addition beyond the plan's stub:** `RawQueryBuilder::edns_options`
  (`tests/support/mod.rs`) got a `debug_assert!` requiring `.edns(...)` to
  be called first, since the OPT-writing block (and thus RDLENGTH/options
  bytes) is gated on `self.edns.is_some()` — attaching options before
  that would otherwise be silently dropped.

Full code-review trail:
`docs/plans/sec_work/implementation/code_review/section-09-diff.md`,
`section-09-review.md`, `section-09-interview.md`,
`section-09-security-review.md`.

---

Relevant files for this section:
- `/home/rpmoore/code/rdns/src/resolver/mod.rs` (new duplicate-cookie-option tests, near section-08's detection-function tests and `probe_cache`)
- `/home/rpmoore/code/rdns/src/protocol/edns_cookie.rs` (module doc comment and `parse_cookie_option` doc comment updates; `locate_cookie_option`/`parse_cookie_option_rejects_duplicates` referenced, not modified)
- `/home/rpmoore/code/rdns/tests/support/mod.rs` (`RawQueryBuilder` extended with arbitrary EDNS-option-bytes support plus a `debug_assert!` ordering guard)
- `/home/rpmoore/code/rdns/tests/e2e_config_toml.rs` (two new e2e tests, querying `cookie-check.rdns.test` rather than the plan's suggested `known-a.rdns.test`)
- `/home/rpmoore/code/rdns/docs/knowledge/resolver/caching/answer-cache.md` (security-trade-off section rewrite)
- No standalone `docs/knowledge/resolver/edns-cookies.md` was created (inline-only judgment call, documented above)