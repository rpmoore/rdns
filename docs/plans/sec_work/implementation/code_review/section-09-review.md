# Code review: section-09-badcookie-review-docs

Reviewer: `deep-implement:code-reviewer` subagent, against
`docs/plans/sec_work/sections/section-09-badcookie-review-docs.md` and the
staged diff in `section-09-diff.md`.

## Summary

Overall this section is docs+tests only (no production logic changes), and
the doc rewrite is accurate and well-grounded against the actual code
(verified `invalid_server_cookie` at `src/resolver/mod.rs:6875-6903` matches
the `answer-cache.md` description line-for-line; the Duplicate/ClientOnly/
NoCookieOption collapse into identical no-BADCOOKIE, no-cookie-echoed
behavior was cross-checked against `message_edns_opt_record_with_cookie` in
`src/protocol/mod.rs:1425-1447`, which is accurate). The e2e-test transport
deviation (querying `cookie-check.rdns.test` instead of the plan's
suggested `known-a.rdns.test`) is sound and well-justified: `try_local_lookup`
genuinely runs before `probe_cache` (`src/resolver/mod.rs:4677-4693`), so the
original plan suggestion would have short-circuited before the cookie check
ever ran; `cookie-check.rdns.test` is confirmed absent from `forward_toml`'s
`[[local_dns_entries]]` (`tests/e2e_config_toml.rs:47-80`), and
`spawn_silent_upstream`/`spawn_canned_upstream` are used correctly for the
UDP-reject/TCP-passthrough split respectively.

## Findings

**MEDIUM** — the new duplicate-cookie-option unit tests don't actually
verify what the plan's own stub asked for.
`resolve_duplicate_cookie_options_processed_normally_not_badcookie_udp`/`_tcp`
(`src/resolver/mod.rs`, new tests after line 24491) both use
`StaticUpstream::new(Err(UpstreamError::Timeout))` and only assert
`ResolveDecisionKind::BackendFailure` plus that the backend was reached.
Neither parses `outcome.response_bytes`. The plan's Test 1 stub explicitly
says "the same fresh-cookie-issuance behavior a genuinely cookie-less
request would get" should be checked, and the section's own sibling
first-contact test
(`resolve_accepts_first_contact_cookie_over_udp_and_attaches_fresh_cookie`,
~line 24303) deliberately uses a *successful* upstream response specifically
so it can inspect the returned OPT record — the same technique needed here
but wasn't used. Traced by hand: `parse_cookie_option` returns `None` for
both `NoCookieOption` and `Duplicate`, so
`message_edns_opt_record_with_cookie` omits the COOKIE option in both cases
(`build_opt_record`, `src/protocol/mod.rs:1333-1335`, uses `Vec::new()` for
`options`) — the code is correct, but that correctness wasn't demonstrated
by the test as written.

**LOW/PROCESS** — two explicit plan acceptance criteria have no evidence of
being satisfied anywhere in this diff: (1) `/security-review` over the
detection/comparison logic and wire-response builder — not yet run. (2) The
standalone-concept-doc-or-inline-only judgment call documented in a
PR/commit note — not yet recorded anywhere.

**LOW** — `RawQueryBuilder::edns_options` (`tests/support/mod.rs`) silently
drops attached option bytes if `.edns(...)` was never called first, since
the OPT-writing block is gated on `self.edns.is_some()`. Not exploitable in
this diff (both call sites call `.edns(...)` first), but worth a
`debug_assert!` for defensiveness.

## Things that check out

- `answer-cache.md` security-trade-off rewrite is factually accurate
  against `invalid_server_cookie`'s real behavior, including the TCP
  short-circuit, the first-contact case, and the Duplicate-collapses-to-
  absent case.
- `edns_cookie.rs` module doc and `parse_cookie_option` doc comment updates
  correctly point to where verification now lives without re-describing
  mechanics inline.
- e2e UDP test's structural COOKIE-option assertions (option code, length,
  echoed client cookie, combined extended RCODE 23) are correct and
  consistent with section-07/08 precedent.
- e2e TCP test correctly proves the transport carve-out with a real backend
  answer.
- No panics, no attacker-input handling bugs, no bypass-of-check issues in
  what this section touches (appropriately narrow: tests/docs only, no new
  parsing/validation code).
