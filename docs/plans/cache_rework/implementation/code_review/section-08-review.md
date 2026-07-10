# Code Review: section-08-test-migration-and-benchmark

Reviewer: `deep-implement:code-reviewer` subagent

## Summary

Small, well-targeted diff — most of section-08's literal scope (deleting
`InMemoryDnsCache`, fixing `RecordingCache`/`OwnedOnlyProtocolCodec`,
migrating ~23 tests) was already completed during section-07 under the
user's explicit override. Reviewer independently re-verified (not just
trusted the summary) that Parts 1-4 are genuinely complete: no remaining
references to the old types anywhere in `src/resolver/mod.rs`,
`RecordingCache` implements `DomainDnsCache`, all five Cluster D test
names exist and are non-vacuous, `single_flight_leader_drop_wakes_followers_and_clears_key`
lives in `cache/singleflight.rs` as expected, and
`open_telemetry_cache_gauges_report_approximate_domain_count` exists in
`src/main.rs` (initially flagged as missing by the reviewer, then found —
a location false-alarm, not a real gap).

## Findings

- **Verified sound**: `backend_reload_sweep_invalidates_stale_generation_entries`
  is genuinely non-vacuous — traced the full chain (different-generation
  namespaces, `publish_reload`'s real `sweep_stale_namespace` call, a
  real `domain_count()` sum) and confirmed the pre-assert proves the
  store actually happened, so the post-assert proves the sweep actually
  removed it.
- **MEDIUM (design tradeoff, not a bug)**: widening `RRsetEntry`/
  `StoredRecord`'s fields and `DnssecState` to fully `pub` (needed so the
  external benchmark crate can construct real entries) makes them part of
  `rdns::resolver`'s permanent public surface for all consumers, not just
  the `#[ignore]`d benchmark — no feature gate was used to scope this to
  test/bench builds, the standard pattern for this exact problem. No
  invariant was broken by this (none was previously enforced by the type
  itself, e.g. `expires_at >= stored_at`), but external code can now
  construct malformed entries where before construction was confined to
  a few in-crate call sites.
- **LOW (nit)**: the benchmark's `seed_entry()` sets `cache_namespace`
  by hand, but `ShardedDnsCache::store_response` unconditionally
  overwrites that field with its own `namespace` argument — the
  hand-set value is dead/misleading.
- **LOW (methodology)**: the benchmark has no warm-up pass before timing
  starts, so early operations in each thread-count run pay cold-cache/
  allocation-growth cost inconsistently across runs, adding noise to a
  benchmark whose value is entirely relative-number eyeballing.
- **LOW-MEDIUM (scope)**: the plan's Part 5 still asks for the one-time
  manual before/after comparison against `InMemoryDnsCache` to be *run
  once* and its numbers *recorded* in the PR/commit description — only
  the "don't keep it running in CI long-term" part is optional. That
  specific artifact wasn't produced (reasonable given `InMemoryDnsCache`
  was already deleted in section-07 before section-08 began, requiring
  git archaeology to reconstruct now), and the observed 2.9x scaling at
  8 threads is modest enough to be ambiguous without a baseline to
  compare against. Recommends explicitly documenting the omission and
  rationale rather than leaving it silent.

## Scope check

No remaining references to retired types found by independent grep.
`src/resolver/mod.rs`, `src/resolver/cache/entry.rs`,
`tests/cache_concurrency_bench.rs`, `justfile` — matches the plan's file
list (plus the re-export widening in `resolver/mod.rs`, a necessary
consequence of the entry.rs widening, not scope creep).
