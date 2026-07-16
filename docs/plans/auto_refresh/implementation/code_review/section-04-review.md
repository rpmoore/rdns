# Code Review: section-04-chainlookup-plumbing

**Reviewer:** deep-implement:code-reviewer subagent
**Generated:** 2026-07-16

This diff is significantly larger than section-04's plan anticipated, because
implementing it exposed a real integration gap between section-03's plan
(left `lookup_hop`/`HopResult` untouched) and section-04's plan (assumed
`HopResult` already carried a per-hop bool). User explicitly approved doing
the full fix rather than a workaround — see this section's git history for
the resulting scope (threading `&RefreshConfig` into `lookup_hop`/
`resolve_from_cache`/`lookup_chain`, extending `HopResult`, adding
`ResolveQuery.refresh_config`, pulling forward 2 of section-05's 4 metric
variants).

## Findings

1. **REAL BUG**: `cache_hit_after_coalesced_miss` (the single-flight
   *follower* path — exactly the concurrent/hot-domain scenario this
   feature targets) called `lookup_chain` correctly but its inline match
   never read `resolved.refresh_hints`, silently dropping them. Only
   `probe_cache`'s leader-side path actually enqueued.
2. **Duplication**: identical `record_popularity_hit` + `wants_refresh`
   computation copy-pasted between `lookup_hop`'s `Answer` and `CnameHop`
   branches.
3. **Readability**: `evaluate_cache_lookup` grew to a positional 4-tuple
   `(bool, Option<Vec<u8>>, QueryEventCacheResult, Vec<RefreshHint>)` —
   risk of an accidental field-order bug at the call site, when this file
   already has a `CacheProbe` named-struct convention for exactly this case.
4. **Production exposure note**: `main.rs` doesn't call `with_refresh_config`/
   `with_refresh_sender` yet, so `RefreshConfig::default()` (enabled=true)
   runs full popularity tracking in production ahead of section-05/07's
   worker pool/wiring existing. Expected given strict manifest-order
   implementation, not a bug — no kill switch at the `main.rs` layer until
   section-07.
5. **Doc gap**: `wants_refresh`'s "current hit counts toward its own
   hot-threshold" semantics (read-after-write in one lock scope) wasn't
   documented anywhere.
6. **Test coverage gap**: no test exercised the actual `probe_cache` →
   `evaluate_cache_lookup` → `enqueue_refresh_job` wiring end-to-end with a
   real `ChainLookup::Answered` — exactly the kind of gap that let finding
   #1 slip through.
7. **Informational**: the `warm_popularity` test helper technique
   (query a hop directly, bypassing chain-following, to selectively raise
   only that hop's popularity) is valid — works because popularity is keyed
   per-domain, not per-(domain,qtype). No action needed, just noted as an
   assumption the tests rely on.
8. **Confirmed clean**: pulling forward `RefreshTriggered`/`RefreshQueueFull`
   won't cause rework for section-05 — `ResolverMetric` and
   `OpenTelemetryMetrics::increment` are both exhaustive, so adding the
   remaining 2 variants there will be a normal compiler-forced addition.

## Triage

All real, no genuine tradeoffs needing user input — fixed directly:

1. **Fixed**: `cache_hit_after_coalesced_miss` now loops over
   `resolved.refresh_hints` and calls `enqueue_refresh_job`, same as
   `probe_cache`.
2. **Fixed**: factored into `ShardState::record_hit_and_check_refresh`,
   called from both `lookup_hop` branches.
3. **Fixed**: added `CacheLookupEvaluation` named struct (mirroring
   `CacheProbe`'s existing convention), replacing the positional 4-tuple.
4. **Not acted on**: documented here and in the section doc as an expected
   interim state, not a defect — `main.rs` wiring is section-07's scope.
5. **Fixed**: added a doc-comment note to `wants_refresh` explaining the
   read-after-write semantics.
6. **Fixed**: added two new end-to-end regression tests —
   `resolve_cache_hit_with_refresh_hint_enqueues_a_job` (real `.resolve()`
   call through `probe_cache`) and
   `cache_hit_after_coalesced_miss_enqueues_refresh_hints` (direct
   regression test for the bug fixed in item 1).
7. **Not acted on**: informational only.
8. **Not acted on**: confirmed already clean.
