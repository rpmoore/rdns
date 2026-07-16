# TDD Companion Plan: Auto-Refresh Popular Domains

Mirrors `claude-plan.md`'s section structure. For each section, lists the tests
to write *before* implementing that section's code. Test "stubs" here are prose
descriptions / test-function-name-and-intent only — no assertions, no fixtures,
no full bodies. The implementer writes the actual test code during
`deep-implement`.

Test framework/conventions (from `claude-research.md`'s codebase research —
follow exactly, don't invent new ones):
- Plain `#[test]` for pure in-memory struct logic (shard/lru-level): small
  fixture helpers (`stored_record()`, `rrset_entry()`, etc.), explicit `now:
  SystemTime` offsets for fake time, `#[cfg(test)]`-gated helper methods for
  assertions (e.g. `contains_positive`, `domain_count`).
- `#[tokio::test]` for anything touching singleflight or the resolver: real
  concurrent `tokio::spawn` interleaving where relevant, `tokio::task::yield_now()`
  to force scheduling points.
- Resolver-level tests built via `ResolveQuery::with_cache(...)`/
  `with_cache_and_backend_snapshot(...)` with `StaticUpstream` (scripted
  request/response recording) or `ScriptedAuthorityTransport` (queued scripted
  responses) as the fake backend.

## 2. Popularity Tracking (Leaky Bucket)

Write these tests before implementing `PopularityBucket`/`ShardState` wiring:

- `popularity_bucket_drains_by_elapsed_time`: level decreases proportionally to
  elapsed time since `last_drained`, using explicit `now` offsets.
- `popularity_bucket_increments_on_hit`: a hit adds `hit_increment` after
  draining.
- `popularity_bucket_saturates_at_capacity`: level never exceeds
  `bucket_capacity` regardless of hit burst size.
- `popularity_bucket_drain_no_truncation_bias`: advancing the clock in many
  small sub-unit-of-drain steps produces the same cumulative drain as one large
  step covering the same total elapsed time (the integer-truncation pitfall
  flagged by research).
- `popularity_bucket_treats_backward_clock_as_zero_elapsed`: a `now` earlier
  than `last_drained` doesn't underflow or panic.
- `popularity_cleared_on_evict_domain`: `ShardState::evict_domain` removes the
  domain's `PopularityBucket` alongside its LRU entry.
- `popularity_cleared_on_drop_lru_if_domain_now_empty`: same, via the other
  removal path.
- `popularity_not_allocated_when_disabled`: with the feature disabled (config
  check at the call site), no `PopularityBucket` entry is created on a hit at
  all — not merely "untouched."
- `is_hot_reflects_configured_threshold`: `is_hot()` returns true only at/above
  the configured `hot_threshold`, boundary-tested at exactly the threshold.

## 3. Refresh Trigger Detection

### 3.1 Eligibility and lead-window formula

- `trigger_requires_eligibility_floor`: an entry with original TTL below
  `eligibility_floor` never signals a refresh, regardless of remaining TTL or
  popularity.
- `trigger_fires_within_lead_window`: an eligible, hot entry with
  `remaining_ttl <= max(original_ttl * lead_ratio, min_lead)` signals refresh;
  just outside the window, it doesn't.
- `trigger_requires_hot_popularity`: an eligible, in-lead-window entry whose
  domain isn't hot does not signal refresh.
- `trigger_boundary_at_exact_lead_window_edge`: exact-equality case at the
  `<=` boundary.
- `trigger_boundary_at_exact_eligibility_floor`: exact-equality case for the
  eligibility floor.

### 3.2 Signal path: extending `ChainLookup`

- `chain_lookup_answered_carries_hints_for_qualifying_hops`: a chain with one
  qualifying hop produces exactly one `RefreshHint` in `refresh_hints`.
- `chain_lookup_multi_hop_all_qualifying_hops_produce_hints`: a multi-hop hot
  CNAME chain where more than one hop independently qualifies produces a hint
  per qualifying hop, not just the terminal one.
- `chain_lookup_intermediate_hop_only`: only an intermediate CNAME hop
  qualifies (terminal record is fresh) — hint still produced for that
  intermediate hop; this is the regression test for the terminal-only bug
  found during plan review.
- `chain_lookup_terminal_hop_only`: only the terminal hop qualifies —
  unaffected by the multi-hop change, still produces exactly one hint.
- `chain_lookup_no_data_never_carries_hint`: `ChainLookup::NoData` has no
  `refresh_hints` field/slot at all (compile-time or structural check that
  this variant cannot carry one).
- `chain_lookup_no_qualifying_hops_empty_hints`: a chain where nothing
  qualifies produces an empty `refresh_hints` vec, not a miss or error.

## 4. Refresh Execution: Worker Pool

### 4.1 Job enqueue

- `enqueue_try_send_succeeds_under_capacity`: a job under channel capacity is
  enqueued successfully.
- `enqueue_drops_and_counts_on_full_channel`: a full channel causes `try_send`
  to fail, job dropped, `RefreshQueueFull` incremented, no panic/blocking.
- `enqueue_per_hint_independent`: with multiple hints from one lookup, one
  channel-full drop doesn't prevent enqueueing the others.

### 4.2 Worker pool shape

- `worker_processes_jobs_sequentially_per_worker`: a single worker dequeues and
  completes one job (via its spawned task) before dequeuing the next.
- `worker_panic_isolated_via_joinhandle`: a job that panics is caught via
  `JoinError::is_panic()` on the awaited `JoinHandle`; the worker loop
  continues processing subsequent jobs afterward (replaces the originally
  planned `catch_unwind` test — verifies the actual per-job `tokio::spawn`
  mechanism instead).
- `worker_pool_bounds_total_concurrency_to_worker_count`: no more than
  `worker_count` jobs execute concurrently even under a burst of enqueued jobs.
- `worker_pool_shutdown_via_abort`: aborting the worker `JoinHandle`s (mirroring
  `spawn_sighup_reload_task`'s teardown pattern) stops the loops; no internal
  shutdown-select is exercised (there isn't one, by design).

### 4.3 Job processing

- `job_captures_epoch_before_recheck`: verifies ordering — epoch is read once,
  and the eligibility recheck is evaluated against that same epoch snapshot.
- `job_aborts_on_epoch_mismatch`: a job whose entry's `cache_epoch` no longer
  matches the freshly captured epoch (simulating a reload that happened while
  the job sat in the channel) aborts cleanly with no store, no crash.
- `job_rechecks_lead_window_before_fetch`: a job that's no longer within the
  lead window (entry already refreshed by another trigger, or naturally
  progressed) aborts without fetching.
- `job_fetch_uses_dnssec_ok_true_always`: the outbound synthetic query always
  sets DO=true, regardless of the original entry's DNSSEC state.
- `job_coalesces_with_concurrent_do_true_client_miss`: a refresh job and a
  concurrent real client miss for the same key, both with `dnssec_ok = true`,
  collapse to one backend fetch via `ShardedSingleFlight` (`Leader`/`Follower`).
- `job_does_not_coalesce_with_do_false_client_miss`: a refresh job (DO=true)
  and a concurrent real client miss with `dnssec_ok = false` do **not**
  coalesce — both become independent `Leader`s, both complete and store
  correctly. This is the corrected-claim regression test from plan review.
- `job_store_matches_normal_miss_path_shape`: for an identical backend
  response, a refresh-triggered store produces a structurally equivalent
  cached entry (TTL computation, RRset decomposition) to what the normal
  client-miss path (`prepare_backend_result` → `store_cache_response`) would
  produce — proving the skipped policy/rewrite/chaos layers don't corrupt the
  stored shape.
- `job_failure_no_retry_leaves_entry_untouched`: a failed refetch (timeout,
  SERVFAIL, NXDOMAIN, transport error) increments `RefreshFailed`, leaves the
  stale entry's `expires_at` unchanged, and does not retry within the same job.
- `job_success_advances_expires_at_and_exits_lead_window`: a successful refresh
  moves `expires_at` forward such that the entry is no longer within the lead
  window on a subsequent check.

## 5. Configuration

- `refresh_config_defaults_match_spec`: `RefreshConfig::default()` produces the
  exact values in the plan's defaults table (§5).
- `refresh_config_validate_rejects_out_of_range_hot_threshold`:
  `hot_threshold_fraction` outside `0.0..=1.0` fails `validate()`.
- `refresh_config_validate_rejects_zero_worker_count`: `worker_count == 0`
  fails `validate()`.
- `refresh_config_validate_rejects_zero_channel_capacity`: same for
  `channel_capacity == 0`.
- `raw_refresh_config_deserializes_with_partial_toml`: a TOML snippet
  overriding only some fields still produces correct defaults for the rest
  (mirrors `RawCacheConfig`'s per-field `#[serde(default = "...")]` pattern).
- `raw_refresh_config_rejects_unknown_fields`: `deny_unknown_fields` behavior
  matches `RawCacheConfig`'s.
- `refresh_config_disabled_skips_worker_spawn`: with `enabled = false`, no
  worker tasks are spawned at startup.

## 6. Metrics

- `metrics_refresh_triggered_increments_on_signal`: `RefreshTriggered` fires
  when `probe_cache` enqueues a job.
- `metrics_refresh_queue_full_increments_on_drop`: `RefreshQueueFull` fires on
  a dropped enqueue.
- `metrics_refresh_succeeded_increments_on_store`: `RefreshSucceeded` fires
  after a successful job.
- `metrics_refresh_failed_increments_on_error`: `RefreshFailed` fires after a
  failed job.
- `opentelemetry_metrics_exhaustive_match_compiles`: a compile-time check
  (implicit — the match is exhaustive) that `OpenTelemetryMetrics::increment`
  has arms for all four new variants; add a runtime test asserting each new
  variant increments its own distinct counter (not accidentally aliased to an
  existing one).

## 7. Documentation

No tests — `docs/knowledge/` updates are prose, verified by manual review
against the implemented code's actual `file:line` locations once merged.

## 8/9. End-to-End and Ordering

- `e2e_hot_domain_refreshed_before_expiry`: a fake backend logging query
  timestamps shows re-queries landing near each TTL boundary, not as a
  client-visible miss, for a domain queried steadily above the hot threshold.
- `e2e_cooling_domain_stops_being_refreshed`: a domain that stops being queried
  stops getting refreshed once its bucket drains below `hot_threshold`.
- `e2e_disabled_feature_is_true_no_op`: with `enabled = false`, behavior is
  bit-for-bit identical to today's reactive-only cache (no popularity
  overhead, no worker activity, existing reactive-miss tests still pass
  unmodified).

Follow `claude-plan.md` §9's implementation order (config before trigger logic,
metrics alongside the worker skeleton, fetch/store logic last) — each numbered
step above corresponds to that same ordering, so tests for a given step should
be written immediately before that step's implementation, not batched
up-front.
