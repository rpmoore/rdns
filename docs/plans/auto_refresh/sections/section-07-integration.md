# section-07-integration

## Dependencies

This section depends on **section-06-refresh-fetch-store** being complete: the
worker pool skeleton (from section-05) must already have real job-processing
logic (epoch recheck, synthetic query, singleflight fetch, store) plugged in,
and `RefreshConfig` (section-02) must already exist with its `enabled` field
and `worker_count`/`channel_capacity` fields. This section does not introduce
any new struct or business logic — it is the final wiring pass: confirming
`main.rs` only spawns the worker pool when the feature is enabled, writing the
knowledge-bundle doc for the whole feature, and running an end-to-end
verification pass that proves the previously-built pieces actually cooperate
correctly when wired together.

Nothing in this section is parallelizable with anything else — it is the last
step in the plan (`docs/plans/auto_refresh/sections/index.md`'s dependency
table: `section-07-integration` depends on `section-06`, blocks nothing).

## Background

`rdns` is a Rust DNS resolver. The auto-refresh feature (this plan) adds
proactive cache refresh: a popular ("hot") domain whose cached answer is close
to expiring gets a background refetch that updates the cache before a real
client query would see a miss. By the time this section starts, the following
already exist and are already tested (built in earlier sections, not
duplicated here):

- `PopularityBucket` on `ShardState` tracking per-domain hit rate
  (section-01).
- `RefreshConfig` in `src/config/mod.rs`, with `enabled: bool`,
  `worker_count: usize`, `channel_capacity: usize`, and the trigger-formula
  thresholds, following `CacheConfig`'s three-piece Raw/try_into/validate
  pattern (section-02).
- The eligibility-floor + lead-window + hot-threshold trigger formula wired
  into `Shard::lookup_hop`'s live-entry probes (section-03).
- `ChainLookup::Answered { refresh_hints: Vec<RefreshHint>, .. }` plumbed
  through `resolve_from_cache` for every qualifying positive hop, and
  `probe_cache` (`src/resolver/mod.rs`) reading those hints and doing a
  non-blocking `try_send` per hint (section-04).
- `RefreshJob`, the bounded `tokio::sync::mpsc` channel, and a fixed
  `worker_count`-sized pool of tokio tasks sharing one
  `Arc<tokio::sync::Mutex<Receiver<RefreshJob>>>`, with per-job
  `tokio::spawn` + `JoinHandle` panic isolation; new `ResolverMetric`
  variants `RefreshTriggered`/`RefreshQueueFull`/`RefreshSucceeded`/
  `RefreshFailed` and all `MetricsSink` impl updates (section-05).
- Real job processing inside each worker: epoch-captured-first eligibility
  recheck, `build_refresh_query` synthetic query builder, fetch via
  `ShardedSingleFlight` with `dnssec_ok` always `true`, store via
  `cache_store_for_response`/`store_cache_response` bypassing
  `prepare_backend_result`'s policy/rewrite/chaos layers, no-retry failure
  handling (section-06).

What is *not* yet done, and is exactly what this section covers:

1. `main.rs` doesn't yet spawn the worker pool at all (section-05/06 built the
   pool and its logic, but the spawn call site and its `enabled`-gating live
   here).
2. No `docs/knowledge/resolver/caching/` doc yet describes any of this — none
   of the existing docs (`sharding.md`, `cache-epoch.md`, `answer-cache.md`)
   mention popularity tracking, refresh triggers, or the worker pool.
3. No end-to-end test yet proves the whole chain — bucket increment → trigger
   → hint → enqueue → worker → fetch → store → next lookup sees the refreshed
   entry — actually works together against a fake backend.

## Part 1 — `main.rs` wiring

### Where and how

`src/main.rs` already has one precedent for a long-lived background task
spawned alongside the resolver: `spawn_sighup_reload_task` (`main.rs:579`),
called once in `main`/the async entrypoint (`main.rs:154`):

```rust
let sighup_task =
    spawn_sighup_reload_task(Arc::clone(&resolver), reload_metrics, config_path.clone());
```

Its `JoinHandle` is threaded into `serve_until_shutdown` (`main.rs:193-201`,
function defined at `main.rs:209`), which holds it for the duration of the
server's life and, on shutdown, calls `.abort()` and awaits it
(`main.rs:302-303`):

```rust
sighup_task.abort();
let _ = sighup_task.await;
```

The refresh worker pool follows this exact same shape, one level up:

1. Add a `spawn_refresh_worker_pool` function (or similarly named — match
   existing naming conventions in `main.rs`) that accepts `Arc<ResolveQuery>`
   (cloned at the call site the same way `resolver` is cloned for
   `spawn_sighup_reload_task`) plus whatever shared job-processing
   dependencies section-05/06 already defined (metrics sink, the shared
   `Receiver`, `worker_count`), and returns a `Vec<tokio::task::JoinHandle<()>>`
   — one handle per worker loop.
2. Call it once, near the `spawn_sighup_reload_task` call site
   (`main.rs:153-154`), **gated on `config.refresh.enabled`**:

   ```rust
   let refresh_worker_handles = if config.refresh.enabled {
       spawn_refresh_worker_pool(/* Arc<ResolveQuery>, channel receiver, worker_count, metrics */)
   } else {
       Vec::new()
   };
   ```

   This is the load-bearing check for the spec's "operator opt-out" and for
   this plan's stated invariant that `enabled = false` is a *true* no-op —
   not merely idle tasks. If `enabled` is `false`, **no worker tasks are
   spawned at all** — this must be an actual conditional branch that skips
   the `tokio::spawn` calls entirely, not a runtime early-return inside an
   always-spawned task. (The corresponding "no `PopularityBucket` allocated"
   half of the same no-op guarantee was already handled at the
   `lru.touch`/`popularity.entry(...)` call sites in section-01/03 — this
   section only owns the worker-spawn half of that guarantee.)
3. Thread `refresh_worker_handles` into `serve_until_shutdown` (add a
   parameter, e.g. `refresh_worker_handles: Vec<tokio::task::JoinHandle<()>>`,
   passed alongside `sighup_task` at the `main.rs:193-201` call site) and
   `.abort()` each handle at the same point in the teardown sequence where
   `sighup_task.abort()` currently runs (`main.rs:302-303`):

   ```rust
   sighup_task.abort();
   let _ = sighup_task.await;
   for handle in refresh_worker_handles {
       handle.abort();
       let _ = handle.await;
   }
   ```

   No internal shutdown `select!`, no shutdown channel for the worker loops
   themselves — this matches the SIGHUP task's own precedent exactly (per
   §4.2 of the plan, already implemented in section-05): the loops run until
   aborted from outside, never watching for their own shutdown signal.
4. If `config.refresh.enabled` is `false`, `refresh_worker_handles` is an
   empty `Vec`, so the abort loop above is simply a no-op at teardown too —
   no special-casing needed there.

### What NOT to do here

- Do not add any new business logic to the worker loop body itself — that
  already exists from section-05/06. This section is purely the call site
  and the `enabled` gate.
- Do not introduce a shutdown channel/`select!` for the worker loops; the
  `.abort()`-based convention is a deliberate, confirmed choice (plan §4.2)
  matching the one precedent this codebase already has.

## Part 2 — Documentation (Knowledge Bundle)

Per this repo's `AGENTS.md` Knowledge Bundle requirement, update
`docs/knowledge/resolver/caching/` now that the feature is fully implemented.
None of the existing docs under that directory (`sharding.md`,
`cache-epoch.md`, `answer-cache.md`, `local-dns-entries.md`) currently mention
popularity tracking, refresh triggers, or the worker pool.

Add a new concept doc, `docs/knowledge/resolver/caching/auto-refresh.md`
(recommended over folding into `answer-cache.md`, since this introduces real
new invariants — bucket lifecycle, trigger formula, worker-pool shutdown
semantics — that justify a standalone doc; only fold it into `answer-cache.md`
under a `## Auto-refresh` heading if, once written, it turns out to be small
enough to feel like an appendix rather than a first-class concept). Follow
the existing doc structure exactly, as in `answer-cache.md`
(`docs/knowledge/resolver/caching/answer-cache.md:1-8`) and `cache-epoch.md`
(`docs/knowledge/resolver/caching/cache-epoch.md:1-10`):

- Frontmatter: `type` (e.g. `Mechanism` or `System`), `title`, `description`,
  `resource` (primary source file, e.g. `src/resolver/cache/shard.rs` or
  `src/resolver/mod.rs`), `tags` (e.g. `[cache, dns, resolver, refresh,
  popularity]`), `timestamp`.
- Every behavioral claim grounded with a `file:line` reference to the
  actually-implemented code (not the plan — the plan is design history, per
  `AGENTS.md`: "for point-in-time design history... see `docs/plans/`
  instead"; `docs/knowledge/` documents *current, implemented* behavior).
- Cover, at minimum:
  - What `PopularityBucket` is, where it lives (`ShardState.popularity`), and
    its lifecycle tied to the LRU's own removal points (`evict_domain`,
    `drop_lru_if_domain_now_empty`) — so a reader understands popularity
    state can never outlive cached data for a domain, and can be lost under
    capacity eviction pressure (an accepted tradeoff, not a bug).
  - The three-gate trigger formula (eligibility floor, lead window, hot
    threshold) and where it lives relative to the existing
    `entry.expires_at <= now` check.
  - `ChainLookup::Answered`'s `refresh_hints` field, and the multi-hop
    invariant (every qualifying positive hop gets its own hint, not just the
    terminal one) — this was a real bug caught during plan review and is
    worth documenting as an invariant, not just an implementation detail.
  - The worker pool's shape (bounded channel, `Arc<Mutex<Receiver>>` shared
    across `worker_count` loops, per-job `tokio::spawn`+`JoinHandle` panic
    isolation) and its `.abort()`-based shutdown, explicitly cross-referenced
    to `spawn_sighup_reload_task` as the precedent it follows.
  - The epoch-recheck-before-fetch step and its relationship to
    [cache-epoch](cache-epoch.md) — a job that sits across a reload must not
    store under a stale epoch; link directly to `cache-epoch.md` rather than
    re-explaining the epoch mechanism.
  - The `dnssec_ok` always-`true` fetch behavior and its coalescing caveat
    (only coalesces with concurrent same-`dnssec_ok` client traffic) — this
    is a subtle enough behavior that an implementer six months from now
    debugging "why didn't this refresh coalesce" will need it documented,
    not just tested.
  - The no-retry-on-failure behavior and why (best-effort, no correctness
    impact, bounded naturally by pool size/channel capacity — not a bug that
    needs a backoff mechanism added later).
  - `enabled = false` as a true no-op: no bucket allocation, no worker spawn.
- Link the new doc from `docs/knowledge/resolver/caching/index.md`
  (currently a 4-line bullet list, `docs/knowledge/resolver/caching/index.md:1-11`)
  in the same one-line-summary style as the existing entries, e.g.:

  ```markdown
  * [auto-refresh](auto-refresh.md) - Proactive cache refresh for popular domains
    nearing TTL expiry: popularity tracking, trigger formula, and the
    background worker pool.
  ```

- Add "See also" cross-links both directions: `auto-refresh.md` should link
  back to `answer-cache.md` (for the base cache structure it extends),
  `sharding.md` (since popularity is per-shard, per-domain), and
  `cache-epoch.md` (for the epoch-recheck interaction); consider adding a
  one-line "See also" pointer from `answer-cache.md`'s own "See also" section
  (`answer-cache.md:222-227`) to the new doc, since a reader of the base
  cache doc will now want to know refresh exists.

No tests are required for this part — per `claude-plan-tdd.md` §7, doc updates
are prose, verified by manual review against the actually-implemented code's
`file:line` locations once merged (i.e. write this doc *after* section-06's
code exists and has real line numbers to cite, not from the plan's estimated
locations).

## Part 3 — End-to-end verification

### Tests to write (from `claude-plan-tdd.md` §8/9)

These are prose test-intent descriptions — write the actual test bodies
during implementation, following this repo's existing resolver-level test
conventions (`ResolveQuery::with_cache(...)`/`with_cache_and_backend_snapshot(...)`
with a `StaticUpstream` or `ScriptedAuthorityTransport` fake backend,
`#[tokio::test]`, `tokio::task::yield_now()` to force scheduling points where
needed):

- `e2e_hot_domain_refreshed_before_expiry`: configure a fake backend that logs
  every query's arrival timestamp for a given domain. Drive repeated lookups
  for that domain at a rate that keeps its `PopularityBucket` above
  `hot_threshold`, spanning multiple TTL cycles. Assert the backend's logged
  query timestamps land near each TTL boundary (inside the lead window) —
  i.e. proactive refreshes are actually happening — and that none of the
  driving lookups themselves observed a cache miss (no client-visible latency
  hit), proving the refresh completed before the entry's natural expiry.
- `e2e_cooling_domain_stops_being_refreshed`: drive the same domain hot long
  enough to establish refresh behavior, then stop querying it (or drop query
  rate below what keeps the bucket above threshold) and let enough time pass
  for the bucket to drain below `hot_threshold`. Assert no further backend
  refresh queries occur near the next TTL boundary — the domain reverts to
  ordinary reactive-miss behavior once it's no longer hot.
- `e2e_disabled_feature_is_true_no_op`: with `RefreshConfig::enabled = false`,
  assert behavior is bit-for-bit identical to today's reactive-only cache —
  no popularity-tracking overhead observable (no `PopularityBucket` ever
  allocated, per section-01/03's existing no-op tests), no worker activity
  (no jobs ever processed, no `Refresh*` metrics ever incremented), and that
  the full suite of pre-existing reactive-cache tests continues to pass
  unmodified with this config value. This test is primarily a confirmation
  pass tying together the individual no-op guarantees already unit-tested in
  earlier sections (bucket non-allocation from section-01/03, no worker spawn
  from this section's Part 1) into one full-stack assertion.

### What this verification pass is (and isn't) checking

This is not new business logic — every piece being exercised
(`PopularityBucket`, trigger formula, `ChainLookup` hints, worker pool,
job processing) was already unit- and integration-tested in its own section.
This pass exists specifically to catch integration bugs that only show up
when every piece runs together under realistic timing — e.g. a hot-then-
cooling domain transition, or a full multi-TTL-cycle run — which no single
section's isolated tests would surface. If any of these end-to-end tests
fail, the fix almost always belongs in an earlier section's code (bucket
drain math, trigger formula, worker job logic), not in this section; this
section's own scope is limited to the `main.rs` spawn wiring and the
documentation, so a failing e2e test here should be triaged back to the
section whose logic is actually implicated before assuming this section's
wiring is at fault.

### Standard gates

Before this step (and the whole feature) is considered done: `cargo fmt --all`,
`cargo fmt --all -- --check`, `cargo clippy --all-targets` (warning-free
baseline — a new warning must be fixed or justified with an `#[allow(...)]`
plus a one-line reason), `cargo test` (full suite, not just the new tests) —
per `RUST.md`. Per `AGENTS.md`'s Change Workflow, also run
`/codex:adversarial-review` on the diff and the `verify` skill before
reporting the whole multi-section feature done, since this is the final
integration point where the complete diff across all seven sections comes
together.

## File paths touched by this section

- `src/main.rs` — add the worker-pool spawn call (gated on
  `config.refresh.enabled`), thread the resulting `JoinHandle`s into
  `serve_until_shutdown`'s signature and its `.abort()`-based teardown
  sequence (near `main.rs:153-154`, `main.rs:193-201`, `main.rs:209`,
  `main.rs:302-303`).
- `docs/knowledge/resolver/caching/auto-refresh.md` — new concept doc (or a
  new `## Auto-refresh` section appended to
  `docs/knowledge/resolver/caching/answer-cache.md`, if the content ends up
  small enough).
- `docs/knowledge/resolver/caching/index.md` — add the link to the new doc.
- End-to-end tests: colocate with existing resolver-level integration tests
  (likely `src/resolver/mod.rs`'s `#[cfg(test)] mod tests`, matching where
  other `StaticUpstream`/`ScriptedAuthorityTransport`-based tests already
  live in that file).

## Summary of what "done" looks like for this section

1. `config.refresh.enabled = false` results in zero worker tasks spawned in
   `main.rs` — verified by a test, not just by inspection.
2. `config.refresh.enabled = true` (the default) results in `worker_count`
   tasks spawned alongside `spawn_sighup_reload_task`, all cleanly `.abort()`-ed
   during `serve_until_shutdown`'s teardown.
3. `docs/knowledge/resolver/caching/` has a doc describing the whole feature,
   grounded in real `file:line` references to the merged code, linked from
   that directory's `index.md`.
4. The three end-to-end tests above pass, demonstrating the full hot-domain
   refresh loop and the cooling-domain shutoff work correctly together, and
   that `enabled = false` is a genuine, fully-verified no-op.
5. All of `RUST.md`'s fmt/clippy/test gates pass for the complete, final diff.

## Implementation Notes (post-implementation)

**Part 1 (`main.rs` wiring) was already complete** by the time this section
started — section-05 had already added the channel creation, builder wiring,
the `config.refresh.enabled`-gated spawn call, and the `.abort()` teardown in
`serve_until_shutdown`, matching this section's plan almost exactly (the only
naming difference: the plan's `refresh_worker_handles` is `refresh_workers` in
the actual code). No changes were needed there beyond what code review found
missing (see below).

**Part 2 (documentation)**: wrote `docs/knowledge/resolver/caching/auto-refresh.md`
(227 lines) covering popularity tracking, the three-gate trigger formula, the
`ChainLookup`/multi-hop hint invariant, the worker pool's shape and shutdown,
job processing (including the `dnssec_ok=false`-for-recheck reasoning and the
DO=true-fetch coalescing caveat), metrics, and cross-links. Replaced the
interim "Popularity tracking"/"Refresh worker pool" sections section-01/05 had
added directly to `answer-cache.md` with a short pointer to the new doc, and
added the link to `docs/knowledge/resolver/caching/index.md`.

**Part 3 (end-to-end tests)**: wrote all three tests
(`e2e_hot_domain_refreshed_before_expiry`, `e2e_cooling_domain_stops_being_refreshed`,
`e2e_disabled_feature_is_true_no_op`) in `src/resolver/mod.rs`'s existing
`#[cfg(test)] mod tests`, plus a `wait_for_upstream_requests` polling helper
(no wall-clock sleep, matches this codebase's existing no-sleep testing
convention).

**Code review findings and fixes** (full detail:
`docs/plans/auto_refresh/implementation/code_review/section-07-review.md`):

1. The plan's own acceptance criterion #1 ("zero worker tasks spawned when
   disabled, verified by a test") had no corresponding test — prior no-op
   tests only covered the resolver level, never `main.rs`'s own spawn-or-not
   branch. Fixed by extracting the gate into a standalone, testable function,
   `spawn_refresh_workers_if_enabled(enabled: bool, spawn: impl FnOnce() -> Vec<JoinHandle<()>>) -> Vec<JoinHandle<()>>`,
   called from `run()` in place of the inline `if`/`else`. Added
   `refresh_workers_not_spawned_when_disabled` and
   `refresh_workers_spawned_when_enabled` to `main.rs`'s test module.
2. Two `file:line` citations in `auto-refresh.md` were factually wrong
   (`evict_domain` cited as `shard.rs:84`, actually `shard.rs:176`;
   `drop_lru_if_domain_now_empty` cited as `shard.rs:144`, actually
   `shard.rs:288`), plus drifted line ranges for `PopularityBucket`,
   `drain_and_increment`, and `wants_refresh`. All corrected against the
   merged file.
3. `e2e_hot_domain_refreshed_before_expiry` uses a fixed `now` (no advancing
   `Clock`), so its final assertion can't and doesn't verify TTL-boundary
   timing — reworded the doc comment to state this honestly rather than
   implying real elapsed-time verification. Test logic and name unchanged.
4. Added a comment noting the test's third `resolve()` call enqueues a second
   refresh job that's deliberately left unawaited (harmless given the
   worker-abort loop and `tokio::test`'s runtime teardown).

**Test coverage**: 3 new end-to-end tests in `resolver/mod.rs` plus 2 new
`main.rs`-level tests for the enable-gate. Full suite: 670 lib tests passing
(`cargo test --lib`), plus the 2 `main.rs`-level tests in the `rdns` binary
target. All of `RUST.md`'s gates pass: `cargo fmt --all`, `cargo clippy
--all-targets --all-features -- -D warnings` (warning-free), `cargo test`
(full suite).