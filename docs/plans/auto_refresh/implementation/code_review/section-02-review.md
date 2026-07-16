# Code Review: section-02-refresh-config

**Reviewer:** deep-implement:code-reviewer subagent
**Generated:** 2026-07-16

Overall closely follows the CacheConfig three-piece template and matches
section-02's plan almost line-for-line. Verified no other `RuntimeConfig`
struct-literal call sites were missed.

## Findings

1. **`LeakRate` merge resolution** (config/mod.rs, resolver/cache/shard.rs):
   confirmed the only workable direction — `resolver::cache::shard`/`cache`
   modules are private (`mod cache;`/`mod shard;`), so `config` could never
   reach a type defined there regardless of the item's own visibility;
   reversing was not actually available without a bigger unplanned surface
   change. Two independent types with a conversion was correctly rejected too
   (exactly the drift risk section-01's own doc comment flagged). Confirmed
   reasonable — flagged only as worth a future architectural note (config
   and resolver now have a two-way type dependency), not something to fix
   in this section.
2. **Test coverage gap**: `refresh_config_explicit_override` only overrode 3
   of `RefreshConfig`'s 10 fields, unlike `cache_config_explicit_override`
   which exercises 100% of `CacheConfig`'s fields — left the ms-to-Duration
   and leak-rate-reassembly conversion logic in `try_into_refresh_config`
   completely untested on the override path.
3. **Validation scope**: `validate()` only checked 3 of the struct's fields
   per the plan's explicit scope — `lead_ratio`, `bucket_capacity`,
   `hit_increment`, and `leak_rate.units`/`leak_rate.per` were unguarded.
   Not a crash risk (shard.rs already treats `leak_rate.units == 0` as
   "never drains"), but a real gap in config-level invariant enforcement.
4. **Minor**: repeated `// Not Eq` comments across three types — cosmetic.

## Triage

- **Item 2 (test coverage)**: auto-fixed — expanded
  `refresh_config_explicit_override` to override and assert all 10 fields.
- **Item 3 (validation scope)**: real tradeoff, asked the user. Decision:
  **expand `validate()` now** rather than defer to section-03. Added
  `InvalidRefreshLeadRatio`, `InvalidRefreshBucketCapacity`,
  `InvalidRefreshHitIncrement`, `InvalidRefreshLeakRate` (covers both
  `units == 0` and `per.is_zero()`) `ConfigError` variants and their checks,
  plus 5 new tests covering each rejection case.
- **Item 1 (LeakRate architecture note)**: no code change — confirmed as the
  only workable resolution; noted here for future reference rather than
  acted on.
- **Item 4 (comment duplication)**: left as-is — cosmetic, not worth the
  churn.
