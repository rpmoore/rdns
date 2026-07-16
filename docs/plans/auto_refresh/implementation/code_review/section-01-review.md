# Code Review: section-01-popularity-bucket

**Reviewer:** deep-implement:code-reviewer subagent
**Generated:** 2026-07-16

Overall the diff matches the plan's structure closely (LeakRate,
PopularityBucket, ShardState.popularity field, removal wiring in
evict_domain/drop_lru_if_domain_now_empty, record_popularity_hit helper, all 4
lookup_hop call sites, popularity_level test accessor, placeholder constants)
and the drain-then-increment arithmetic is fundamentally sound.

## Findings

1. **Silent truncation risk in `drain_and_increment`** (Major-ish, latent):
   bare `as u32` cast on a u128 result wraps silently instead of saturating if
   the computed value ever exceeds `u32::MAX`. Not live with today's fixed
   placeholder constants, but becomes a real risk once section-03 threads
   arbitrary `RefreshConfig::leak_rate` values through.
2. **`sweep_stale_namespace` doesn't clean up `popularity`**: a domain's
   bucket outlives its cache data when cleared via namespace sweep rather
   than `evict_domain`/`drop_lru_if_domain_now_empty`. Plan explicitly waives
   fixing this behavior, but the `PopularityBucket` doc comment overclaims
   ("gone in the same operation" — only true for 2 of 3 removal paths).
3. **Test coverage**: only the `Answer` call site is verified end-to-end via
   `lookup_hop_hit_increments_popularity_level`; `CnameHop`/`NoData`/
   `NxDomain` sites are untested copy-paste blocks.
4. **Test coverage**: every test uses `units: 1`, so the
   `leak_rate.per * leaked_units / leak_rate.units` division is a no-op in
   every test run — no coverage for `units != 1`.
5. **Knowledge docs stale**: `docs/knowledge/resolver/caching/answer-cache.md`
   doesn't mention the new `popularity` field, per AGENTS.md's Knowledge
   Bundle requirement.
6. **Minor style nit**: fully-qualified `std::time::Duration` instead of
   using the existing `use std::time::SystemTime;` import.

## Triage

All six findings are auto-fixable — none involve a real tradeoff requiring
user judgment. Applying fixes directly rather than interviewing:

1. **Fixed**: `leaked_units` computation now saturates via
   `u32::try_from(...).unwrap_or(u32::MAX)` instead of a wrapping `as u32`.
2. **Fixed**: doc comment reworded to state popularity state is cleared
   "alongside the LRU token's own two removal points" rather than
   unconditionally "whenever a domain's data is gone" — matches the plan's
   explicitly accepted `sweep_stale_namespace` gap without overclaiming.
3. **Fixed**: added end-to-end `lookup_hop` tests for the `CnameHop`,
   `NoData`, and `NxDomain` branches (mirroring the existing `Answer` test).
4. **Fixed**: added a `popularity_bucket_drain_with_non_unit_leak_rate` test
   using `units: 3` to exercise the reconstruction division with a non-1
   divisor.
5. **Fixed**: updated `docs/knowledge/resolver/caching/answer-cache.md` with
   a short section on the new `popularity` field and its lifecycle.
6. **Fixed**: added `Duration` to the existing `use std::time::SystemTime;`
   import, removed fully-qualified `std::time::Duration` usages.
