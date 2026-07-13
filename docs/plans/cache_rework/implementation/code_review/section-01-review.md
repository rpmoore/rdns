# Code Review: section-01-foundation

Reviewer: `deep-implement:code-reviewer` subagent

## Summary

Overall this is a faithful, low-risk implementation of the plan — no scope
creep into section-02/03/04 territory, `RuntimeConfig`/`RawRuntimeConfig`/
`main.rs` are untouched, all 7 new files
(`src/resolver/cache/{mod,shard,lru,entry,singleflight,assemble,namespace}.rs`)
carry the correct Apache-2.0 header, `mod cache;` is added privately at
`src/resolver/mod.rs:40` exactly where directed, and the six submodule
stubs contain only license + doc comments as required.

**Correctness**: `shard_index` (`src/resolver/cache/mod.rs:253-260`) and
`CacheConfig::shard_capacity`/`resolved_shard_count`
(`src/config/mod.rs:292-340`) match the spec's algorithms exactly —
`DefaultHasher` + mod reduction with a `shard_count==0` guard, and
base+remainder capacity splitting that sums exactly to `max_entries`. No
bugs found in the core math.

## Findings

- **MEDIUM — untested defensive branch**: `CacheConfig::shard_capacity`'s
  `if shard_count == 0 { return 0; }` guard (`src/config/mod.rs:295-296`)
  has zero test coverage; none of the six `(max_entries, shard_count)`
  cases in `cache_config_shard_capacity_sums_exactly_to_max_entries`
  (`mod.rs:83`) exercise `shard_count==0`. A `shard_capacity(0, 0) == 0`
  assertion is missing.
- **MEDIUM — latent landmine for later sections**: `resolved_shard_count()`
  (`config/mod.rs:298-308`) passes through `shard_count: Some(0)`
  unchanged, returning 0 instead of falling back to the computed default.
  Nothing in this section enforces `shard_count >= 1` for
  explicitly-configured values, and no test guards against it. Not
  required by section-01's spec, but worth flagging for section-03/07
  (divide-by-shard_count) if not addressed.
- **LOW**: `shard_capacity(&self, index, shard_count)` never validates
  `index < shard_count`; an out-of-range index silently returns a
  valid-looking capacity rather than panicking/asserting, which could mask
  caller bugs in later sections. A `debug_assert!(index < shard_count)`
  would be cheap and idiomatic.
- **LOW**: `#[derive(Copy)]` added to `CacheConfig` is not requested by the
  spec (`RuntimeConfig`/`MetricsConfig` nearby only derive `Clone`).
  Harmless given the struct is two `usize`-sized fields, but slightly
  inconsistent with sibling config struct conventions in this file.

## Test quality

All three required `shard_index` tests and all four required
`CacheConfig` tests are present with correct names/semantics; the diff
also adds a bonus `shard_index_returns_zero_for_zero_shard_count` test,
which is a welcome addition beyond the spec's minimum. No test-quality
gaps beyond the two noted above.

## Style/idiom

Code is rustfmt-clean, guard clauses are idiomatic, doc comments are
copied faithfully from the plan. No clippy risk spotted beyond the
untested branch.
