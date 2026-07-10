# Code Review Interview: section-04-singleflight

Review source: `section-04-review.md` (via `deep-implement:code-reviewer`
subagent).

## Findings triage

| Finding | Severity | Disposition |
|---|---|---|
| No test exercises `wait()`'s parked-then-woken path (register-before-check ordering unverified) | MEDIUM | Auto-fix — strengthen concurrency test |
| `single_flight_coalesces_concurrent_misses_for_same_name_and_qtype` isn't actually concurrent | MEDIUM | Auto-fix — genuinely spawn N tasks |
| `single_flight_different_shards_do_not_contend` doesn't prove sharding reduces contention (would pass under the old global mutex too) | MEDIUM | Auto-fix — force real lock contention on shard A |
| `ShardedSingleFlight::new(0)` panics on first use | LOW | Let go — plan explicitly defers `shard_count > 0` validation to section-07's wiring |

No user interview was needed — all findings were test-design gaps in
code that already correctly implements the ported logic, not
correctness bugs or design tradeoffs.

## Fixes applied

1. `single_flight_coalesces_concurrent_misses_for_same_name_and_qtype`
   (`src/resolver/cache/singleflight.rs`) — rewritten to genuinely spawn
   5 concurrent `tokio::spawn` tasks calling `begin()` for the same key
   (rather than a sequential loop), then spawn each follower's `.wait()`
   call as its own task *before* completing the leader (with two
   `yield_now().await` calls to let them actually park in
   `notified().await`), then complete the leader and join the wait
   tasks. This now genuinely exercises real async-scheduler interleaving
   and the missed-wakeup-safe register-before-check ordering in
   `InFlightMiss::wait`, verified stable across 5 repeated local runs.
2. `single_flight_different_shards_do_not_contend`
   (`src/resolver/cache/singleflight.rs`) — rewritten to force actual
   lock contention: a background `std::thread` (not a tokio task, since
   `std::sync::MutexGuard` is `!Send` and cannot cross an `.await` point)
   directly locks shard A's raw `flights` mutex via the crate-internal
   `shard_for` accessor and holds it for 200ms, while the async test body
   asserts `begin()` on a different-shard domain completes within a
   100ms timeout. This would fail against a single-global-mutex
   implementation (shard A's held lock would block shard B's `begin()`
   too), so it now actually proves the sharding benefit this section
   exists to deliver.

## Verification after fixes

- `cargo build --tests` — clean.
- `cargo test --locked singleflight` — 4/4 passed, run 5 times
  consecutively with no flakes (relevant given the timing-based
  contention test).
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo fmt` — clean.
- `cargo test --locked` (full suite) — 433 passed, 0 failed.
