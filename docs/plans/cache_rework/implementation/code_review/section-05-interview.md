# Code Review Interview: section-05-namespace-sweep

Review source: `section-05-review.md` (via `deep-implement:code-reviewer`
subagent).

## Findings triage

| Finding | Severity | Disposition |
|---|---|---|
| Every test called `sweep_stale_namespace` with a length-1 slice — the multi-shard aggregation loop (`shards.iter().map(...).sum()`) was never exercised with >1 shard in one call | MEDIUM | Auto-fix — add a real multi-shard test |
| Tests asserted presence/absence but never LRU relative ordering, despite claiming "LRU positions untouched" | LOW | Auto-fix — add an LRU-order-preserving accessor and assertions |
| A domain present in both maps that empties in both gets pushed into `emptied_domains` twice (harmless but fragile-by-coincidence) | LOW | Auto-fix — `Vec` → `HashSet` |
| Cross-shard-lock-independence test is wall-clock/timing-based | LOW | Let go — matches the timing-test style already used and accepted in section-04; independent `Mutex`es give no real contention mechanism to flake on |

No user interview was needed — all findings were test-coverage/robustness
gaps in code that already correctly implements the sweep algorithm, not
correctness bugs or design tradeoffs.

## Fixes applied

1. **Multi-shard aggregation test** (`src/resolver/cache/namespace.rs`) —
   added `sweep_stale_namespace_walks_every_shard_in_the_slice`, which
   builds 3 shards (2 with stale entries, 1 with a current entry), calls
   `sweep_stale_namespace` once against a 3-element slice, and asserts all
   3 shards were actually visited (`removed == 2`, per-shard presence
   checks). This would catch a regression like `.first()` replacing
   `.iter()`, which every pre-existing test would have missed.
2. **LRU-order preservation, verified not just asserted** —
   `src/resolver/cache/lru.rs`: added `ShardLru::order_for_test()`
   (`#[cfg(test)]`, oldest-touched-first `Vec<String>`).
   `src/resolver/cache/shard.rs`: added `Shard::lru_order_for_test()`
   wrapping it. `sweep_removes_only_entries_from_stale_namespace` and
   `sweep_keeps_domain_partially_when_some_record_sets_are_current`
   (`namespace.rs`) now snapshot LRU order before and after the sweep and
   assert surviving domains' relative order is unchanged, not just that
   they're still present.
3. **`emptied_domains` dedup by construction** —
   `Shard::sweep_stale_namespace` (`shard.rs`) now collects into a
   `HashSet<String>` instead of a `Vec<String>`, so a domain emptied in
   both the positive and negative maps is only ever processed once in the
   LRU-cleanup loop, by construction rather than by incidental idempotency
   of `contains_key`/`lru.remove`.

## Verification after fixes

- `cargo build --tests` — clean.
- `cargo test --locked -- namespace shard` — 27/27 passed (up from 23
  pre-fix: +1 multi-shard test, existing tests strengthened in place).
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo fmt` — clean.
- `cargo test --locked` (full suite) — 439 passed, 0 failed (up from 438
  before this section's fixes; +1 net new test).
