# Code Review: section-05-worker-pool-metrics

**Reviewer:** deep-implement:code-reviewer subagent
**Generated:** 2026-07-16

Overall solid: `main.rs` wiring order (channel before builder, enabled-gating
on both `with_refresh_sender` and pool spawn, abort/join before
`drop(resolver)`), and the 4 `ResolverMetric` variants + `OpenTelemetryMetrics`
wiring all matched the plan and this section's remaining scope correctly.
Manually smoke-tested (built binary, ran on a non-privileged port, confirmed
clean startup logging, SIGINT, clean shutdown with no hang; separately fired
a live `dig` query that resolved correctly).

## Findings

1. **Most significant**: the plan explicitly preferred reusing the real
   `refresh_worker_loop` via a test seam over a hand-rolled lookalike, but
   the initial diff did the latter (`test_worker_loop`/
   `spawn_test_worker_pool`) — 3 of 4 worker-pool tests exercised a copy,
   not production code, so a real bug in the actual dequeue/panic-isolation
   logic could slip through untested.
2. **Untested/unhandled abort-while-job-in-flight**: `.abort()`ing the outer
   worker loop task while parked in `handle.await` cancels only the loop
   task, not the inner spawned job — harmless with today's no-op stub, but
   a latent gap section-06 (real I/O per job) will inherit.
3. **Stale doc comment**: `serve_until_shutdown`'s doc block still described
   the pre-diff teardown sequence, missing the new refresh-worker-pool
   abort step.
4. **Style/architecture note**: `tracing::error!` used directly in
   `resolver/mod.rs` (the only such call in that file) rather than through
   an injected sink — flagged as worth reconsidering before it becomes
   precedent, but also noted this matches `main.rs`'s own
   `spawn_sighup_reload_task` convention for background-task error logging.
5. **Design-forward note**: no per-job timeout/stuck-job detection — not a
   bug in this section's no-op stub, flagged for section-06's awareness.
6. **Knowledge bundle gap**: no `docs/knowledge/` concept content for the
   worker pool's concurrency invariants (dequeue serialization, panic
   isolation, abort-only shutdown).

## Triage

- **Item 1**: **fixed** — added a `#[cfg(test)]`-only `TEST_JOB_HANDLER`
  thread-local seam (safe because these tests use the default current-thread
  `#[tokio::test]` runtime flavor, confirmed no test in this file uses
  `flavor = "multi_thread"`) so `process_refresh_job` dispatches to an
  injected handler in test builds. Rewrote all 3 affected tests to call the
  real `spawn_refresh_worker_pool` directly; each test now sets (or, for the
  abort test, explicitly clears) the handler at its own start, since the
  test harness's thread pool can reuse an OS thread across test functions.
- **Item 2**: documented directly in `refresh_worker_loop`'s doc comment as
  a known gap for section-06 to revisit — not fixed now, since fixing it
  requires design decisions (cancel in-flight jobs vs. let them finish)
  that belong with section-06's real I/O, not this section's stub.
- **Item 3**: fixed — updated the doc comment to mention the refresh-pool
  abort step.
- **Item 4**: not changed — confirmed this matches `main.rs`'s existing
  `spawn_sighup_reload_task` precedent for background-task error logging;
  reworking to an injected sink would be a bigger design change than this
  section's stub scope warrants, and no dedicated "log a bare error" sink
  trait exists in this codebase to route through.
- **Item 5**: not acted on — explicitly a forward note for section-06, not
  a defect in this section.
- **Item 6**: fixed — added a "Refresh worker pool" section to
  `docs/knowledge/resolver/caching/answer-cache.md` covering the pool
  shape, dequeue serialization, panic isolation, and abort-only shutdown.
