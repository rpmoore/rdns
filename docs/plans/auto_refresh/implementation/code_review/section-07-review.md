# Code Review: section-07-integration

**Reviewer:** deep-implement:code-reviewer subagent
**Generated:** 2026-07-16

Final integration section — mostly confirmatory, since Part 1 (main.rs wiring)
turned out to already be complete from section-05. Found no wiring bugs, but
did find a doc-accuracy defect and an unmet acceptance criterion from the plan.

## Findings

1. **REAL GAP**: the plan explicitly requires a test proving
   "`config.refresh.enabled = false` results in zero worker tasks spawned in
   `main.rs`" — no such test existed. Prior sections only cover no-op behavior
   one layer down, at the resolver level (e.g. `enqueue_refresh_job` being a
   no-op without a sender), never `main.rs`'s own spawn-or-not branch.
2. **REAL BUG (docs)**: `docs/knowledge/resolver/caching/auto-refresh.md` had
   two factually wrong `file:line` citations —
   `ShardState::evict_domain (shard.rs:84)` (actual: `shard.rs:176`) and
   `ShardState::drop_lru_if_domain_now_empty (shard.rs:144)` (actual:
   `shard.rs:288`) — plus drifted line-range citations for `PopularityBucket`
   (`59-129` vs actual `59-124`), `drain_and_increment` (`99-118` vs actual
   `92-111`), and `wants_refresh` (`449-467` vs actual `449-465`). Looked
   copied from an earlier draft/estimate rather than checked against the
   merged file — directly contradicts AGENTS.md's Knowledge Bundle
   requirement that every claim be grounded in the actually-implemented code.
3. **Test overclaim**: `e2e_hot_domain_refreshed_before_expiry` passes `now`
   as a fixed `SystemTime` to every `ResolveRequest` (no advancing `Clock`),
   so its final "still `CacheHit`" assertion would pass even if the entire
   refresh feature were deleted — it verifies plumbing (hit → hint → enqueue
   → worker fetch → store), not "before expiry" TTL-boundary timing, despite
   what the name and original doc comment implied.
4. **Minor**: the test's third `resolve()` call also qualifies under the
   permissive config and enqueues its own second refresh job, never awaited
   before the test's worker-abort loop — harmless (`tokio::test` tears down
   the runtime), but undocumented.

## Triage

All four are real and fixable directly; no genuine tradeoff needed user input.

1. **Fixed**: extracted the `main.rs` enable-gate into a standalone,
   independently testable function,
   `spawn_refresh_workers_if_enabled(enabled: bool, spawn: impl FnOnce() -> Vec<JoinHandle<()>>) -> Vec<JoinHandle<()>>`,
   called from `run()` in place of the inline `if`. Added
   `refresh_workers_not_spawned_when_disabled` (asserts the spawn closure is
   never invoked and the result is empty) and
   `refresh_workers_spawned_when_enabled` (asserts the closure runs and its
   handles are returned) to `main.rs`'s existing `#[cfg(test)] mod tests`.
   This satisfies the plan's acceptance criterion with a test, not just
   inspection.
2. **Fixed**: corrected all five citations in `auto-refresh.md` against the
   merged `shard.rs` (verified via `grep -n` against the actual file, not
   estimated): `evict_domain` → `shard.rs:176`, `drop_lru_if_domain_now_empty`
   → `shard.rs:288`, `PopularityBucket` → `shard.rs:59-124`,
   `drain_and_increment` → `shard.rs:92-111`, `wants_refresh` →
   `shard.rs:449-465`.
3. **Fixed**: reworded `e2e_hot_domain_refreshed_before_expiry`'s doc comment
   to state plainly that it cannot and does not verify TTL-boundary timing
   (fixed `now`, no advancing clock) — "before expiry" in the name refers to
   the production trigger condition (`wants_refresh`'s lead-window gate)
   being exercised via `permissive_refresh_config()`, not to the test
   observing real elapsed time. Left the test's logic and name unchanged, as
   recommended — the fix is honesty about what's verified, not new
   assertions the fixed-clock harness can't actually back up.
4. **Fixed**: added an inline comment at the third `resolve()` call
   explaining the second enqueued job is deliberately unawaited (no assertion
   depends on it) and why that's harmless given the worker-abort loop and
   `tokio::test`'s runtime teardown.

Not pursued: a config-parsing-through-main.rs-startup integration test
(reviewer's "would have been a good complement," not a defect) — already
covered in practice by section-02's TOML round-trip tests for `RefreshConfig`
plus a manual smoke test of the built binary against a real `config.toml`
during this section's own verification pass.
