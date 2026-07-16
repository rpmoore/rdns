Now I'll produce the section content.

---

# Section 05: Refresh Worker Pool Skeleton and Metrics

## Purpose and Scope

This section builds the background execution machinery for auto-refresh: the
`RefreshJob` type, a bounded channel, a fixed-size worker pool that dequeues
and processes jobs with per-job panic isolation, the `main.rs` spawn/shutdown
wiring, and all new `ResolverMetric` variants plus their `MetricsSink`
implementations. **Jobs are a no-op in this section.** The real epoch-recheck
+ synthetic-fetch + cache-store logic that actually does something useful with
a dequeued `RefreshJob` is implemented in section-06 — this section only has
to make the pool run jobs to completion (including a stub job) without
blocking other jobs, isolate panics, and be cleanly abortable at shutdown.

This corresponds to `claude-plan.md` §4.2 ("Worker pool shape"), §4.4
("Spawning"), and §6 ("Metrics"), and to `claude-plan-tdd.md` §4.2 and §6.

### Dependencies

- **section-02-refresh-config**: this section reads `RefreshConfig`'s
  `worker_count: usize` and `channel_capacity: usize` fields (and, for the
  spawn-gating call site, `enabled: bool`). Do not re-derive or duplicate
  `RefreshConfig`'s definition here — it's assumed already implemented,
  reachable as `config.refresh` on `RuntimeConfig`, following the exact
  `CacheConfig` three-piece pattern (`RefreshConfig` /
  `RawRefreshConfig` / `try_into_refresh_config`).
- This section is a dependency of **section-06-refresh-fetch-store**, which
  will replace this section's no-op `process_refresh_job` body with the real
  fetch/store logic, and will call the metric variants
  (`RefreshSucceeded`/`RefreshFailed`) added here.
- This section is *also* a dependency of **section-04-chainlookup-plumbing**
  in practice (per the suggested implementation order in `claude-plan.md` §9,
  step 5 lands before step 4's `ChainLookup`/enqueue plumbing is written,
  even though the formal dependency graph in `index.md` doesn't list it) —
  section-04's `probe_cache` enqueue logic will read the `refresh_sender`
  field and call the `RefreshTriggered`/`RefreshQueueFull` metrics added
  here. This section must leave a clean extension point for that (see
  "Enqueue-side field" below), but must not itself implement the enqueue
  call — there is nothing in this codebase yet that produces `RefreshHint`s
  for it to enqueue.
- **Not** parallelizable against section-03/section-04 by the formal
  dependency graph, but *is* listed as parallelizable against section-03 in
  practice, since neither touches the same code region (section-03 touches
  `take_live_positive`/`take_live_cname_hop`; this section touches the
  worker-pool/metrics machinery and `main.rs`).

### Files touched

- `src/resolver/mod.rs` — `RefreshJob`, `ResolveQuery`'s new
  `refresh_sender` field + `with_refresh_sender` builder method,
  `spawn_refresh_worker_pool`, the worker loop, the no-op
  `process_refresh_job` stub, the four new `ResolverMetric` variants, and
  `RecordingMetrics` test-impl checks.
- `src/main.rs` — channel construction, worker-pool spawn/gate at startup,
  `serve_until_shutdown`'s new `.abort()` teardown step, `OpenTelemetryMetrics`
  struct fields + counters + `increment`/`observe_duration` match arms.

## Background: why the pieces fit together this way

`ResolveQuery` (`src/resolver/mod.rs:3552`) is built via a builder chain
(`with_cache_policy_and_backend_snapshot(...).with_max_chain_depth(...)....`)
and only wrapped in `Arc::new(...)` once, in `main.rs`'s startup path
(`main.rs:131-151`). The worker pool, however, needs an `Arc<ResolveQuery>` to
call back into resolver internals when it eventually processes jobs
(section-06). This creates an ordering constraint:

1. The **channel** (`mpsc::channel::<RefreshJob>(config.refresh.channel_capacity)`)
   must be created *before* `ResolveQuery` is built, so its `Sender` half can
   be handed to the builder chain via a new `.with_refresh_sender(sender)`
   method (mirroring the existing `.with_chaos_config(...)` /
   `.with_cookie_secret(...)` post-construction-setter pattern — these fields
   are deliberately *not* added to any of the `with_cache*` constructors'
   parameter lists, exactly like `chaos`/`cookie_secret`/`max_chain_depth`
   already aren't).
2. The **worker pool** (which needs `Arc<ResolveQuery>`) is spawned *after*
   `Arc::new(resolver)`, using the channel's `Receiver` half — the same
   ordering `spawn_sighup_reload_task` already uses (`main.rs:153-154`,
   called with `Arc::clone(&resolver)` right after the `Arc::new`).

This is why `ResolveQuery` gets a new `refresh_sender: Option<mpsc::Sender<RefreshJob>>`
field: the *enqueue* side (sender) lives inside `ResolveQuery` so section-04's
`probe_cache` can reach it (`self.refresh_sender`), while the *dequeue* side
(receiver) is handed directly to the worker-pool spawn function in `main.rs`,
never stored on `ResolveQuery` itself.

`tokio::sync::mpsc` is already imported in `src/resolver/mod.rs:27` (used
elsewhere in the module); no new dependency is needed for the channel itself,
nor for the shared-receiver `Arc<tokio::sync::Mutex<..>>` wrapper (per
`claude-plan.md` §4.2 — a true MPMC receiver like `async-channel` was
considered and explicitly rejected to avoid a new dependency for a small,
fixed-size pool).

`RefreshJob` and `spawn_refresh_worker_pool` must both be `pub` (not
`pub(crate)`): `main.rs` is a separate binary crate that only sees `rdns`'s
public API (confirmed by `src/lib.rs:18`, `pub mod resolver;`, and by
`main.rs`'s existing test module importing `rdns::resolver::{...}` items).
Making `RefreshJob` `pub(crate)` would leak a private type through
`with_refresh_sender`'s public signature (a `private_interfaces` lint) and
would make it impossible for `main.rs` to construct the channel at all.
`process_refresh_job` and the worker-loop function itself, by contrast, are
plain private (`fn`, no `pub`) — only called from within `resolver::mod`.

## Data structures

In `src/resolver/mod.rs`, near the existing metrics/type definitions:

```rust
/// One dequeued unit of refresh work: refetch and re-store the RRset for
/// (domain, qtype, qclass). Constructed by `probe_cache` (section-04) from a
/// `RefreshHint` and enqueued via non-blocking `try_send`.
#[derive(Debug, Clone)]
pub struct RefreshJob {
    pub domain: String,
    pub qtype: u16,
    pub qclass: u16,
}
```

Add to `ResolveQuery` (`src/resolver/mod.rs:3552`), alongside the other
post-construction-only fields (`chaos`, `cookie_secret`):

```rust
    // Not part of any constructor's parameter list by default (defaults to
    // `None`, meaning "auto-refresh has no enqueue target") -- same
    // reasoning as `chaos`/`cookie_secret` above. Set via
    // `with_refresh_sender` only when `RefreshConfig::enabled` is true;
    // left `None` otherwise so `probe_cache` (section-04) can treat "no
    // sender" and "feature disabled" as the same no-op case.
    refresh_sender: Option<mpsc::Sender<RefreshJob>>,
```

Default it to `None` in the `Self { ... }` literal inside
`with_cache_policy_and_backend_snapshot` (`src/resolver/mod.rs:3707+`, same
place `chaos`/`cookie_secret` already get their defaults), and add a builder
method next to `with_cookie_secret` (`src/resolver/mod.rs:3868`):

```rust
    /// Wires the auto-refresh job sender into this resolver. Left unset
    /// (`None`) when `RefreshConfig::enabled` is `false`, so `probe_cache`
    /// (section-04) never attempts to enqueue anything for a disabled
    /// feature.
    pub fn with_refresh_sender(mut self, sender: mpsc::Sender<RefreshJob>) -> Self {
        self.refresh_sender = Some(sender);
        self
    }
```

## Worker pool

In `src/resolver/mod.rs`:

```rust
/// Spawns a fixed pool of `worker_count` tasks that share one bounded
/// `receiver`, each dequeuing and processing `RefreshJob`s. Mirrors
/// `spawn_sighup_reload_task`'s (`main.rs:579`) shutdown convention exactly:
/// no internal shutdown signal, no `select!` -- the caller holds the
/// returned `JoinHandle`s and `.abort()`s them at teardown.
///
/// `Receiver` is single-consumer, so it's wrapped in
/// `Arc<tokio::sync::Mutex<_>>` and shared across the pool. This serializes
/// only the dequeue point (one worker parks on `recv()` at a time), not job
/// *execution* -- each dequeued job is spawned as its own task (see below),
/// so total concurrency stays bounded at `worker_count` without a true MPMC
/// channel and its accompanying new dependency.
pub fn spawn_refresh_worker_pool(
    resolver: Arc<ResolveQuery>,
    receiver: mpsc::Receiver<RefreshJob>,
    worker_count: usize,
) -> Vec<tokio::task::JoinHandle<()>> {
    let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
    (0..worker_count)
        .map(|_| {
            tokio::spawn(refresh_worker_loop(
                Arc::clone(&resolver),
                Arc::clone(&receiver),
            ))
        })
        .collect()
}

/// One worker's dequeue-process-repeat loop. A panic inside a given job's
/// processing (`process_refresh_job`) is isolated by spawning that job as
/// its own task and awaiting its `JoinHandle` before dequeuing the next job
/// -- deliberately *not* `futures::FutureExt::catch_unwind` (this repo has
/// no `futures` dependency today; adding one solely for this would
/// contradict the same "add dependencies conservatively" reasoning already
/// used to reject a true MPMC channel above). A panicked job fails only its
/// own `JoinHandle` (`JoinError::is_panic()`); this loop, and thus this
/// worker, keeps running.
async fn refresh_worker_loop(
    resolver: Arc<ResolveQuery>,
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<RefreshJob>>>,
) {
    loop {
        let job = {
            let mut receiver = receiver.lock().await;
            receiver.recv().await
        };
        let Some(job) = job else {
            break; // channel closed (all senders dropped) -- exit cleanly.
        };
        let task_resolver = Arc::clone(&resolver);
        let handle = tokio::spawn(async move { process_refresh_job(task_resolver, job).await });
        if let Err(join_error) = handle.await
            && join_error.is_panic()
        {
            // TODO(section-06 or here): log the panic. No metric beyond a
            // log line is specified for this case in claude-plan.md -- a
            // panicked job is not a `RefreshFailed` (that's for ordinary
            // fetch failures), just an isolated bug to surface via logging.
        }
    }
}

/// Processes one dequeued job. **This section's implementation is a no-op
/// stub** -- real epoch-capture, eligibility recheck, singleflight-based
/// fetch, and cache-store logic is added in section-06
/// (`claude-plan.md` §4.3, `claude-plan-tdd.md` §4.3). Keeping this as an
/// explicit stub (rather than deferring the whole function's existence to
/// section-06) is what lets this section's worker-pool tests (panic
/// isolation, concurrency bound, sequential-per-worker dequeue, abort
/// shutdown) run against the real pool mechanics without section-06's fetch
/// logic existing yet.
async fn process_refresh_job(_resolver: Arc<ResolveQuery>, _job: RefreshJob) {}
```

### `main.rs` wiring

In the startup path (`main.rs`, around where `resolver` is built and
`sighup_task` is spawned, `main.rs:104-154`):

1. Create the channel *before* building `resolver`:
   ```rust
   let (refresh_tx, refresh_rx) = tokio::sync::mpsc::channel(config.refresh.channel_capacity);
   ```
2. Thread `.with_refresh_sender(refresh_tx)` into the existing builder chain
   (`main.rs:131-150`) — but **only when `config.refresh.enabled` is true**;
   otherwise skip the call entirely so `refresh_sender` stays `None` (per
   `claude-plan.md` §5's "no `PopularityBucket` is ever allocated... no
   worker tasks are spawned, no signal is ever produced" no-op requirement).
   A small local `if`/builder-continuation is enough; don't over-engineer
   this into a second builder variant.
3. After `Arc::new(resolver)` (same point `sighup_task` is spawned,
   `main.rs:153-154`), spawn the worker pool, gated the same way:
   ```rust
   let refresh_workers = if config.refresh.enabled {
       rdns::resolver::spawn_refresh_worker_pool(
           Arc::clone(&resolver),
           refresh_rx,
           config.refresh.worker_count,
       )
   } else {
       Vec::new()
   };
   ```
   (Section-07 does a final confirmation pass on this gating as part of its
   end-to-end verification — this section just needs it to already be
   correct, not merely sketched.)
4. Thread `refresh_workers: Vec<tokio::task::JoinHandle<()>>` through to
   `serve_until_shutdown` (`main.rs:209-311`) as a new parameter, and abort
   them at the same point `sighup_task` is aborted (`main.rs:302-303`):
   ```rust
   for worker in refresh_workers {
       worker.abort();
       let _ = worker.await;
   }
   ```
   Order relative to `sighup_task`'s abort doesn't matter functionally (both
   are independent background tasks with no shared shutdown ordering
   requirement) — grouping them together right after `sighup_task.abort()`
   is fine.

## Metrics

### New `ResolverMetric` variants

Add to the enum at `src/resolver/mod.rs:8111-8151`, matching the existing
naming style:

```rust
    RefreshTriggered,
    RefreshQueueFull,
    RefreshSucceeded,
    RefreshFailed,
```

### `MetricsSink` implementations to update

- **`NoopMetricsSink`** (`src/resolver/mod.rs:8102-8108`): `increment`
  already takes `_metric: ResolverMetric` and ignores it (no `match`), so no
  code change is required for it to keep compiling — verify this by
  inspection, don't skip the check.
- **`OpenTelemetryMetrics`** (`src/main.rs:801-848` struct,
  `src/main.rs:963-1030` `impl MetricsSink`): this **is** an exhaustive
  `match` over `ResolverMetric` and needs real work:
  - Four new `Counter<u64>` fields on the struct, following the exact
    existing naming convention (`cache_hit_total: Counter<u64>` →
    `refresh_triggered_total: Counter<u64>`, etc.):
    ```rust
    refresh_triggered_total: Counter<u64>,
    refresh_queue_full_total: Counter<u64>,
    refresh_succeeded_total: Counter<u64>,
    refresh_failed_total: Counter<u64>,
    ```
  - Four new builder calls in `OpenTelemetryMetrics::new` (alongside
    `cache_hit_total: meter.u64_counter("cache_hit_total").build()` at
    `main.rs:886`):
    ```rust
    refresh_triggered_total: meter.u64_counter("refresh_triggered_total").build(),
    refresh_queue_full_total: meter.u64_counter("refresh_queue_full_total").build(),
    refresh_succeeded_total: meter.u64_counter("refresh_succeeded_total").build(),
    refresh_failed_total: meter.u64_counter("refresh_failed_total").build(),
    ```
  - Four new match arms in `increment` (`main.rs:963-1029`):
    ```rust
    ResolverMetric::RefreshTriggered => self.refresh_triggered_total.add(1, &[]),
    ResolverMetric::RefreshQueueFull => self.refresh_queue_full_total.add(1, &[]),
    ResolverMetric::RefreshSucceeded => self.refresh_succeeded_total.add(1, &[]),
    ResolverMetric::RefreshFailed => self.refresh_failed_total.add(1, &[]),
    ```
    These are pure counters (no duration), so no `observe_duration` arm is
    needed — the existing catch-all `_ => {}` in `observe_duration`
    (`main.rs:1050`) already covers them.
- **Test-only `RecordingMetrics`** (`src/resolver/mod.rs:9787-9805` and
  `src/delivery/upstream.rs:1076-1086`): both `increment` impls push the
  metric into a `Vec<ResolverMetric>` unconditionally with no `match` —
  check both by inspection; neither needs a code change to keep compiling,
  but both remain the tools later sections' tests will use to assert
  `RefreshTriggered`/`RefreshQueueFull`/`RefreshSucceeded`/`RefreshFailed`
  counts via their existing `.count(metric)` helper.

## Tests

Write these before/alongside the implementation above (plain `#[test]` where
no async runtime is needed, `#[tokio::test]` for anything exercising the
worker loop — per this plan's established convention: real concurrent
`tokio::spawn` interleaving, `tokio::task::yield_now()` to force scheduling
points where needed, no sleeps for correctness-load-bearing assertions).

### Worker pool shape (`claude-plan-tdd.md` §4.2 — this section's core tests)

- `worker_processes_jobs_sequentially_per_worker`: with a single worker
  (`worker_count = 1`) and a controllable stand-in job body (e.g. a test
  seam that increments a shared counter and optionally waits on a
  `tokio::sync::Notify` or similar before returning), confirm one job fully
  completes (its spawned task's `JoinHandle` resolves) before the next job
  is dequeued.
- `worker_panic_isolated_via_joinhandle`: a job that panics doesn't stop the
  worker loop — verified via the real per-job `tokio::spawn` +
  `JoinHandle`/`JoinError::is_panic()` mechanism (not `catch_unwind`,
  replacing the originally-planned test approach). After a panicking job,
  enqueue a second, normal job and confirm it still gets processed.
- `worker_pool_bounds_total_concurrency_to_worker_count`: with
  `worker_count = N` and a burst of jobs whose processing overlaps in time
  (e.g. each holds a shared `AtomicUsize` "currently running" counter up
  momentarily), confirm the observed concurrent-in-flight count never
  exceeds `N`.
- `worker_pool_shutdown_via_abort`: aborting the returned `JoinHandle`s
  (mirroring `spawn_sighup_reload_task`'s teardown pattern) stops the loops
  — no internal shutdown-`select!` exists or is exercised by design.

Since `process_refresh_job` is a fixed no-op stub in this section's
production code, these tests need a way to exercise controllable job
bodies. Prefer *not* adding a generic injectable-handler parameter to the
public `spawn_refresh_worker_pool` signature purely for this (that would be
over-engineering a production API around a test need, and section-06 will
give `process_refresh_job` real, non-trivial behavior anyway making such a
seam short-lived). Instead, test the worker-loop *mechanics*
(dequeue-then-spawn-then-await, panic isolation, bounded concurrency,
abort-ability) directly against a small test-local helper loop built the
same shape as `refresh_worker_loop` but parameterized on an injected async
closure, OR — preferred, since it avoids duplicating the loop logic between
production and test code — add a `#[cfg(test)]`-only internal variant of
`refresh_worker_loop` (or a `#[cfg(test)]` seam on `process_refresh_job`
itself, e.g. a test-only override hook) so the exact production loop is what
gets exercised. Use judgment on the cleanest seam; the important invariant
is that the *production* dequeue/spawn/await/panic-isolation code path is
what's under test, not a reimplementation of it.

### Metrics (`claude-plan-tdd.md` §6 — the subset testable in this section)

- `opentelemetry_metrics_exhaustive_match_compiles`: the four new variants
  compile against `OpenTelemetryMetrics::increment`'s exhaustive match
  (implicit — the code simply won't compile otherwise); add a runtime test
  (same style as the existing `open_telemetry_cache_gauges_report_approximate_domain_count`
  test at `main.rs:1148`, using `metrics.registry.gather()`) asserting that
  incrementing each of `RefreshTriggered`/`RefreshQueueFull`/
  `RefreshSucceeded`/`RefreshFailed` bumps its own distinctly-named counter
  (`refresh_triggered_total`/`refresh_queue_full_total`/
  `refresh_succeeded_total`/`refresh_failed_total`) and does **not**
  accidentally alias to an existing counter or to one of the other three new
  ones.

**Not owned by this section** (listed here only so the implementer doesn't
try to write them prematurely against code that doesn't exist yet):
`metrics_refresh_triggered_increments_on_signal` and
`metrics_refresh_queue_full_increments_on_drop` require section-04's
`probe_cache` enqueue call site (the actual `self.metrics.increment(...)`
calls at the trigger/drop points aren't added until then).
`metrics_refresh_succeeded_increments_on_store` and
`metrics_refresh_failed_increments_on_error` require section-06's real
`process_refresh_job` body. This section only has to guarantee the metric
variants and sink plumbing those later call sites will use are correct and
already wired end-to-end through every `MetricsSink` implementation.

## Verification

Before considering this section done: `cargo fmt --all -- --check`,
`cargo clippy --all-targets` (warning-free baseline), `cargo test` (narrow
first — the new worker-pool and metrics tests — then the full suite),
per `RUST.md`.

## Implementation Notes (post-implementation)

**Starting state deviated from this section's plan**: section-04, forced to
resolve a section-03 integration gap, had already built `RefreshJob` (as
`pub struct RefreshJob { domain, qtype, qclass }` with *private* fields, not
this plan's `pub domain`/`pub qtype`/`pub qclass`), the
`refresh_sender: tokio::sync::mpsc::Sender<RefreshJob>` field on
`ResolveQuery` (a plain always-present `Sender`, not this plan's
`Option<Sender>` — defaults to a sender whose paired receiver is already
dropped, so an enqueue on a disabled/unwired resolver is just a drop),
`with_refresh_sender`, and 2 of the 4 `ResolverMetric` variants
(`RefreshTriggered`/`RefreshQueueFull`) plus their `OpenTelemetryMetrics`
wiring. This section's actual remaining scope — `spawn_refresh_worker_pool`,
`refresh_worker_loop`, the `process_refresh_job` stub, the remaining 2
metric variants (`RefreshSucceeded`/`RefreshFailed`), and all `main.rs`
startup/shutdown wiring — was implemented as planned, adapted to build on
top of section-04's already-different shapes.

**Manually verified functionally, not just compiling**: built the binary,
ran it against a non-privileged port, confirmed clean startup logging (UDP/
TCP/metrics listeners), sent SIGINT, confirmed clean shutdown with no hang;
separately fired a live `dig` query against the running server and got a
correct `example.com` A-record response — proving the new
channel-creation/builder/worker-pool-spawn/abort wiring doesn't break normal
resolution or shutdown.

**Code review found and fixed a real test-design gap**: this section's plan
explicitly preferred exercising the *real* `refresh_worker_loop` via a test
seam over a hand-rolled lookalike ("preferred, since it avoids duplicating
the loop logic between production and test code") — the first draft did
the opposite (a `test_worker_loop`/`spawn_test_worker_pool` pair
duplicating the loop shape), meaning 3 of 4 worker-pool tests exercised a
copy, not production code. Fixed: added a `#[cfg(test)]`-only
`TEST_JOB_HANDLER` thread-local seam that `process_refresh_job` checks in
test builds only (production behavior — a true no-op — is unaffected).
Safe specifically because every test in this file uses the default
current-thread `#[tokio::test]` runtime flavor (confirmed via grep — none
use `flavor = "multi_thread"`), so a handler set before spawning is visible
to every task the pool spawns on that same OS thread. All 3 affected tests
now call the real `spawn_refresh_worker_pool` directly; each explicitly
sets (or, for the abort test, clears) the handler at its own start, since
the test harness's thread pool can reuse an OS thread across different test
functions.

**Other review fixes**: documented a known gap (not fixed — belongs to
section-06's scope) that `.abort()`ing the outer worker loop while a job's
inner spawned task is in flight only cancels the loop, leaving the job
task detached; fixed a stale `serve_until_shutdown` doc comment that
predated the refresh-pool abort step; added a "Refresh worker pool" section
to `docs/knowledge/resolver/caching/answer-cache.md` covering the pool's
concurrency invariants. `tracing::error!`'s direct use in
`resolver/mod.rs` (flagged by review) was kept as-is — confirmed to match
`main.rs`'s own `spawn_sighup_reload_task` precedent for background-task
error logging, not a deviation.

**Test coverage**: 5 new tests beyond the plan's list — the 4 named
worker-pool tests (now exercising real production code per the fix above)
plus `open_telemetry_refresh_metrics_map_to_distinct_counters` in
`main.rs` (increments each of the 4 refresh metrics a different number of
times, asserts each maps to its own distinct Prometheus counter).

All of `RUST.md`'s gates pass: `cargo fmt`, `cargo clippy --all-targets`
(warning-free), `cargo test` (full suite, 656 lib tests passing, run 3x to
confirm no flakiness in the concurrency-bound/gated tests).