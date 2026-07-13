# Code Review: section-05-namespace-sweep

Reviewer: `deep-implement:code-reviewer` subagent

## Summary

Algorithm and lock discipline are correct and match the plan closely.
`Shard::sweep_stale_namespace` correctly does per-entry `retain` on both
`positive.domains[*].record_sets` and `negative.domains[*].entries`,
computes removed-count via before/after len diffs (no under/over-counting),
only drops a domain's `ShardLru` token when it is absent from **both** maps
after the sweep, and never touches/reorders LRU entries for domains that
keep any surviving entry. Each shard's own `Mutex<ShardState>` is locked
only for that shard's own scan; `namespace::sweep_stale_namespace` just
sequentially sums per-shard results (plan-permitted — "sequential is
acceptable"). The `&[Shard]` signature deviation from the plan's literal
`&ShardedDnsCache` is well-justified (that type is section-06's, built in
parallel, and doesn't exist yet) and clearly documented. Scope is clean:
only `namespace.rs` (new) and `shard.rs` (new method + 3 `pub(crate)`
visibility widenings + 1 test helper) are touched.

## Findings

- **MEDIUM**: every test calls `sweep_stale_namespace(std::slice::from_ref(&shard), ...)`
  — a length-1 slice — including the test named
  `sweep_across_shards_does_not_require_a_shared_lock`. The top-level
  aggregation logic (`shards.iter().map(...).sum()`) — the actual
  "walks every shard" behavior the plan requires — is never exercised with
  more than one shard in the same call. A regression like `.first()`
  instead of `.iter()` would pass every test in this diff.
- **LOW**: tests don't verify the "LRU positions untouched" claim their own
  names/plan doc make — they check `has_any_data`/`contains_positive` but
  never `peek_oldest`/relative ordering. Holds in the implementation by code
  reading, but wouldn't catch a regression that spuriously touched a
  surviving domain's LRU position during sweep.
- **LOW**: in `Shard::sweep_stale_namespace`, a domain present in both maps
  that becomes empty in both gets pushed into `emptied_domains` (a `Vec`)
  twice. Not a correctness bug (the cleanup loop's `contains_key`/`lru.remove`
  are idempotent), but fragile-by-coincidence rather than by design.
- **LOW**: the cross-shard-lock-independence test is wall-clock/timing-based
  (200ms hold, 50ms offset, 150ms threshold). Given fully independent
  `Mutex`es there's no real mechanism for this to flake today, but under
  heavy CI load the margin could theoretically be eaten. Matches the
  timing-test style already used in section-04 (plan explicitly permits
  this approach).

## Scope check

Only `src/resolver/cache/namespace.rs` (new) and `src/resolver/cache/shard.rs`
(new method + visibility widenings + test helper) touched, matching the
plan's stated file list.
