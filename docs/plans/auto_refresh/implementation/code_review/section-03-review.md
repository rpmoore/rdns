# Code Review: section-03-trigger-formula

**Reviewer:** deep-implement:code-reviewer subagent
**Generated:** 2026-07-16

Implementation faithful to the plan — all three gates match the formula
exactly, correctly left as standalone/unwired dead code (section-04's job),
placed correctly, `pub(crate)` visibility correct. All 5 named tests plus
both additional min/max-dominance cases present.

## Findings

1. **Test-quality (medium)**: `trigger_boundary_at_exact_lead_window_edge`
   used `lead_ratio = 0.10`, which isn't exactly representable in `f32`
   (stored as ~0.100000001490116...). `300s * 0.10` computes to
   ~30.000000447s, not exactly 30s — so asserting `remaining_ttl = 30s`
   fires passed under both `<=` and `<` semantics, not actually pinning the
   operator a future refactor might flip.
2. **Coverage gap (low)**: no tests for `hot_threshold_fraction` at its
   valid extremes (0.0, 1.0). At `0.0`, `hot_threshold` rounds to 0, making
   the popularity gate a no-op for any existing bucket — a real, reachable
   operator configuration with no test coverage.
3. **Minor/theoretical**: `f32` multiply-then-round-then-cast for
   `hot_threshold` could drift for unrealistically large `bucket_capacity`
   values — unreachable at realistic scale, not actionable.

## Triage

Both real findings (1, 2) are test-quality/coverage gaps with no tradeoff —
auto-fixed directly:

1. **Fixed**: rewrote `trigger_boundary_at_exact_lead_window_edge` to use
   `lead_ratio = 0.25` (a power-of-two fraction, exactly representable in
   f32) with `original_ttl = 400s` (`400 * 0.25 = 100s`, computed exactly,
   no rounding error) so the boundary assertion actually exercises `<=` vs
   `<`, plus an explicit just-past-boundary negative assertion.
2. **Fixed**: added
   `trigger_hot_threshold_fraction_zero_makes_any_existing_bucket_hot` and
   `trigger_hot_threshold_fraction_one_requires_bucket_at_full_capacity`.
3. **Not acted on**: theoretical only, not reachable at realistic scale, per
   reviewer's own assessment.
