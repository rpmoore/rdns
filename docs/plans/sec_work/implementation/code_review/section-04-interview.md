# Code Review Interview: Section 04 - DNSSEC Entry Wiring and CD-Bit Gating

**Date:** 2026-07-19

No live interview was needed — the one item with a real tradeoff (the HIGH
finding) is resolved by the plan's own explicit text rather than a fresh
decision, so it's handled as a documentation fix below rather than an
`AskUserQuestion`. Everything else is either an obvious auto-fix or a
let-go nitpick per the triage guidance.

## Resolved without asking (plan text is authoritative)

**HIGH — "validation is off the critical path" doc comment is false.**
Confirmed: `validate_for_store` is awaited synchronously inside
`prepare_backend_result`, which is on the client's reply path — a
cache-miss client really does block on the DS/DNSKEY chase. The review
is correct that the *comment* is wrong, but re-reading
`claude-plan.md`'s §A4 ("Timeout and error handling (fail-closed)")
shows this is a **deliberate, plan-sanctioned tradeoff**, not an
oversight introduced by this section:

> "validate_msg's DS/DNSKEY chase must be bounded by rdns's existing
> per-query/per-authority timeout budget... it must not add an
> unbounded wait on top of normal resolution... This is a deliberate
> fail-closed choice: transient upstream slowness during validation can
> produce a SERVFAIL for CD=0 requesters. Call this out in the PR
> description and in C3's rollout notes, since it's a real, intended
> trade-off, not an oversight."

So the fix here is **documentation, not redesign**: correct
`validate_for_store`'s doc comment to accurately state it runs
synchronously on the fetch-critical path, bounded by
`dnssec_validation_deadline`, and point at this as a known, intended
trade-off to watch via section-05's latency metrics (matching A7's own
"Not solved in this pass; watch A7's latency-relevant metrics after
rollout"). Decoupling this onto a background task is out of scope for
what the plan asked this section to build, and re-architecting it here
would be scope creep beyond what section-04 was asked to do.

Fixing: `src/resolver/mod.rs` — `validate_for_store`'s doc comment.

This also resolves the LOW finding about `main.rs` reusing
`config.per_query_deadline` for `dnssec_validation_deadline` — once the
comment accurately says this bounds critical-path latency, reusing the
existing per-query deadline value is the *correct* choice, not a
conflation. No code change needed there.

## Auto-fixed (obvious, low-risk)

**MEDIUM — silent trust-anchor parse failure.** Adding a `tracing::warn!`
when `TrustAnchors::from_u8` fails inside `validate_for_store`, so a
misconfigured anchor file is operator-visible instead of silently
degrading to "never validates." Low-risk, matches existing logging
conventions elsewhere in the codebase.

**LOW — missing §A6 AD-bit/CD no-regression test.** Adding a test that
varies `checking_disabled` against a `Secure` entry and asserts
`dnssec_ad_bit`'s AD-bit output is unaffected, per the plan's explicit
test list. Cheap, directly requested by the section plan.

## Let go (nitpicks / already-covered)

**MEDIUM — `#[allow(clippy::too_many_arguments)]` instead of a params
struct.** Matches this codebase's own established convention (already
used extensively, e.g. every `ResolveQuery::with_cache*` constructor).
Not a new smell introduced by this diff; a broader refactor here would
be scope creep for a single section.

**LOW — `validate_for_store` re-fetches `self.backend.current()` instead
of reusing the caller's captured snapshot.** Already has a doc comment
explaining this is intentional. No test covers the reload-during-
validation race, but this is a pre-existing, documented trade-off
pattern (same as other `self.backend.current()` call sites in this
file) rather than a defect this section introduced. Leaving as-is.
