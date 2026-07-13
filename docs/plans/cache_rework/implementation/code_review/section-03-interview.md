# Code Review Interview: section-03-shard-and-lru

Review source: `section-03-review.md` (via `deep-implement:code-reviewer`
subagent).

## Findings triage

| Finding | Severity | Disposition |
|---|---|---|
| No test: adding a second qtype to an existing domain at full capacity never evicts | MEDIUM | Auto-fix — add test |
| No test: touching only the negative side of a dual-entry domain keeps it recently used | MEDIUM | Auto-fix — add test |
| `domain_is_tracked` duplicates `ShardLru`'s notion of "live domain" instead of consulting it | MEDIUM | Auto-fix — add `ShardLru::contains`, use it |
| `ShardLru::touch` allocates up to 3 `String`s per call | LOW | Let go — out of scope, not a correctness issue, plan didn't ask for zero-allocation touch |
| No test: `Shard::touch()` on an untracked domain is a no-op | LOW | Auto-fix — add test |

No user interview was needed — all findings were either obvious
correctness/coverage improvements (auto-fixed) or a cosmetic nitpick
outside the plan's scope (let go).

## Fixes applied

1. `ShardLru::contains(&self, domain: &str) -> bool`
   (`src/resolver/cache/lru.rs`) — new method, single source of truth for
   "is this domain live," delegating to `positions.contains_key`.
2. `ShardState::domain_is_tracked` (`src/resolver/cache/shard.rs`) — now
   calls `self.lru.contains(domain)` instead of independently unioning
   `positive.domains`/`negative.domains` key sets.
3. New test `adding_a_second_qtype_to_an_existing_domain_never_evicts_at_full_capacity`
   (`src/resolver/cache/shard.rs`) — fills a 2-capacity shard, adds a
   second qtype under an already-tracked domain, asserts no eviction and
   both qtypes present.
4. New test `touching_only_the_negative_side_of_a_dual_entry_domain_keeps_it_recently_used`
   (`src/resolver/cache/shard.rs`) — a domain with both positive and
   negative entries is touched only via `Shard::touch` (simulating a
   negative-side lookup), then survives an eviction that claims a less
   recently touched domain instead.
5. New test `touch_on_untracked_domain_is_a_no_op`
   (`src/resolver/cache/shard.rs`) — confirms `Shard::touch()` on a
   domain with no live data does not change `domain_count()` or create
   any map entry.

## Verification after fixes

- `cargo fmt` — clean.
- `cargo test --locked cache` — 11/11 (7 shard + 4 lru) passed (3 new
  tests added).
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo test --locked` (full suite) — 429 passed, 0 failed.
