# Code Review Interview: section-01-foundation

Review source: `section-01-review.md` (via `deep-implement:code-reviewer`
subagent).

## Findings triage

| Finding | Severity | Disposition |
|---|---|---|
| `shard_capacity`'s `shard_count == 0` branch untested | MEDIUM | Auto-fix — add test |
| `resolved_shard_count()` passes `Some(0)` through unchanged, silently yielding 0 shards | MEDIUM | Asked user — real tradeoff (validate vs. silent passthrough) |
| `shard_capacity` doesn't validate `index < shard_count` | LOW | Auto-fix — `debug_assert!` |
| `#[derive(Copy)]` on `CacheConfig` inconsistent with sibling config structs | LOW | Let go — harmless, two-`usize` struct is a reasonable `Copy` candidate |

## User decision

Asked: how should `CacheConfig { shard_count: Some(0), .. }` behave in
`resolved_shard_count()`?

- Option A (chosen): treat `Some(0)` the same as `None` — fall back to the
  computed default. Simple, no new error type, and it removes the
  divide-by-zero landmine for section-03/07 without adding config
  validation machinery this section doesn't otherwise need.
- Option B (not chosen): leave as-is, defer to section-07's `RuntimeConfig`
  validation path.

**Decision: Option A.**

## Fixes applied

1. `resolved_shard_count()` (`src/config/mod.rs`) — match arm changed from
   `Some(count) => count` to `Some(count) if count > 0 => count`, with the
   `None` arm's fallback logic now also catching `Some(0)` via `_ =>`.
   Doc comment updated to state the `Some(0)`-treated-as-unset behavior
   explicitly.
2. `shard_capacity()` (`src/config/mod.rs`) — added
   `debug_assert!(index < shard_count, "shard index out of bounds")` after
   the `shard_count == 0` early return.
3. New test `cache_config_shard_capacity_is_zero_when_shard_count_is_zero`
   — covers the previously-untested `shard_capacity(0, 0) == 0` branch.
4. New test
   `cache_config_resolved_shard_count_treats_explicit_zero_as_unset` —
   asserts `Some(0)` and `None` resolve to the same (nonzero) shard count.

## Verification after fixes

- `cargo fmt` — clean.
- `cargo test --locked cache_config` — 6/6 passed (2 new tests added).
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo test --locked` (full suite) — 412 passed, 0 failed.

## Let-go items (no action)

- `#[derive(Copy)]` on `CacheConfig`: nitpick, not worth reverting — the
  struct is `{ usize, Option<usize> }`, a legitimate `Copy` type, and nothing
  in the plan forbids it.
