# Code review interview: section-09-badcookie-review-docs

## Interviewed with user

**Q: Standalone `docs/knowledge/resolver/edns-cookies.md` or inline-only
documentation for BADCOOKIE?**

Plan §C1 explicitly calls this a judgment call with real tradeoffs (a
future reader debugging "why did this client get RCODE 23" vs. `edns_cookie.rs`
already being a well-documented, well-tested, scoped-addition module).

**Decision: inline-only.** `src/protocol/edns_cookie.rs` already carries
module-level and per-function doc comments plus a full test suite; the
transport-conditional gating rule, the first-contact-is-not-an-error rule,
and the duplicate-collapses-to-absent rule are now all stated explicitly in
`docs/knowledge/resolver/caching/answer-cache.md`'s "Security trade-off"
section, which is also the section a reader debugging cache/cookie
interaction would land on first. No standalone
`docs/knowledge/resolver/edns-cookies.md` was created; no
`docs/knowledge/resolver/index.md` entry was added. This satisfies plan
§C1's requirement to record the decision explicitly rather than silently
skipping the standalone-doc option.

## Auto-fixed (no tradeoff, applied without asking)

1. **MEDIUM — duplicate-cookie-option tests didn't verify cookie-echo
   behavior.** `resolve_duplicate_cookie_options_processed_normally_not_badcookie_udp`/`_tcp`
   only asserted `BackendFailure` (not-BADCOOKIE), not the plan's stated
   "processed identically to a cookie-less request" claim, which includes
   cookie-echo behavior. Switched both to a successful upstream response and
   added an assertion that no COOKIE option is echoed back. First attempt
   asserted an OPT record was present with empty `options`, which failed:
   forward-mode's own-cookie rebuild
   (`rebuild_forward_response_with_own_cookie`, gated on
   `decoded.features.client_cookie.is_some()` in `prepare_backend_result`,
   `src/resolver/mod.rs:6213-6242`) never triggers for a duplicate cookie
   (`parse_cookie_option` returns `None` for it, same as absent), so the
   response is the mocked upstream's raw bytes relayed verbatim -- which,
   like a genuinely cookie-less request against the same mock, carries no
   OPT record at all, not an OPT with empty options. Corrected the
   assertion to check no COOKIE option is present in `additionals` at all
   (robust to OPT-present-vs-absent), matching the actual traced behavior.
2. **LOW — `RawQueryBuilder::edns_options` silent-drop footgun.** Added a
   `debug_assert!` requiring `.edns(...)` to have been called before
   `.edns_options(...)`, so a future test author gets a panic instead of a
   silently-passing false negative.

## `/security-review` (plan §C2, AGENTS.md standing pre-PR gate)

Run over the full branch diff with focus on Track B's detection/comparison
logic (section-08) and wire-response builder (section-07). Result: no
HIGH/MEDIUM findings above the 80% exploitability confidence bar. Full
report: `section-09-security-review.md`.
