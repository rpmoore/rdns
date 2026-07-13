# Code Review: section-04-singleflight

Reviewer: `deep-implement:code-reviewer` subagent

## Summary

Overall this is a faithful, high-fidelity port. Line-by-line comparison
of `SingleFlightShard::begin`/`finish` against the original
`SingleFlightMisses::begin`/`finish` (`src/resolver/mod.rs:3856-3889`)
shows no behavioral deviation beyond the sanctioned key-type change and
per-shard map: the `Arc::ptr_eq` guard in `finish` is preserved verbatim,
the `Drop` impl synthesizes the identical
`ResolutionBackendError::Transport("single-flight leader cancelled")`,
and the notify-before-check ordering in `InFlightMiss::wait` is
unchanged. Shard routing is actually more robust than the plan's literal
spec: both `begin` and `finish` funnel through a single shared
`shard_for(&key.0)` helper rather than two independently-written
`shard_index` calls, so they structurally cannot diverge in routing.
Scope is clean — diff touches only
`src/resolver/cache/singleflight.rs`, no `src/resolver/mod.rs`
call-site wiring. `#![allow(dead_code)]` is justified/transient,
matching sections 01-03.

## Findings

- **MEDIUM**: no test actually exercised the concurrent-wakeup path the
  design exists for. In every test that called `.wait()`, the call
  happened strictly *after* `.complete()`/`drop(leader)` had already
  stored the result and fired `notify_waiters()`, so `wait()` always took
  the early-return branch without ever polling `notified.await`. The
  plan explicitly calls the register-before-check ordering "a subtle
  correctness property" that the test should verify — it wasn't.
- **MEDIUM**: `single_flight_coalesces_concurrent_misses_for_same_name_and_qtype`
  was not concurrent despite its name — it called `begin()` sequentially
  in a loop rather than spawning N tasks as the plan specified.
- **MEDIUM**: `single_flight_different_shards_do_not_contend` never
  actually forced lock contention on shard A — it discarded the leader's
  key/flight without holding a guard, so the test would have passed
  identically against the *old single-global-mutex* implementation (an
  outstanding leader never holds the lock while pending, sharded or
  not). It proved domain-independent map bookkeeping but not that
  sharding reduces lock contention, which is this section's stated
  purpose.
- **LOW (not a regression, spec-consistent)**: `ShardedSingleFlight::new(0)`
  combined with `shard_index`'s documented `shard_count == 0 -> 0`
  fallback will panic in `shard_for` (`self.shards[0]` on an empty
  `Vec`) on first `begin`/`finish` call. The plan explicitly leaves
  `shard_count > 0` unenforced here, deferring validation to section-07's
  wiring — flagged for that section, no action here.

## Scope check

No files outside `src/resolver/cache/singleflight.rs` were touched, and
`src/resolver/mod.rs`'s old single-flight definitions and call sites
remain untouched, matching the plan's explicit scope boundary.
