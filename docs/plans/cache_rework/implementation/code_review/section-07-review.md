# Code Review: section-07-call-site-migration

Reviewer: `deep-implement:code-reviewer` subagent

## Summary

Overall the rewiring is faithful to the plan. Both self-flagged risk areas
(namespace consistency between `probe_cache`/`store_cache_response`, and
the `cache_hit_after_coalesced_miss` metrics-parity bug found and fixed
during self-review) check out fine — `record_cache_hit_metrics` is called
from all three `ChainLookup`-consuming sites with matching semantics, no
second missed call site. A full sweep for stray old-type references
(`CacheKey`, `CacheLookup`, `CachedResponse`, `CacheStore`,
`InMemoryDnsCache`, `DnsCache`, `SingleFlightMisses`) found nothing left
over outside deleted lines. The `InMemoryDnsCache`-full-deletion and
obsolete-test-deletion scope decisions both held up under spot-checking
(LRU eviction still covered by section-03's `shard.rs` suite, malicious-
CNAME-target blocking rewritten not dropped, single-flight leader-drop
coverage explicitly deferred to section-04's suite with a pointer comment).

## Findings

- **MODERATE**: `decompose_response_for_store` uses its own terminal-record
  predicate (rtype/rclass/name match) to decide whether a hop is a positive
  answer, independent of `CacheTtlPolicy::ttl_for_response`'s classification
  of the same response (which additionally requires
  `recursive_response_record_supported` to hold). These diverge for direct
  queries of qtype 59 (CDS), 60 (CDNSKEY), or 32769 when `dnssec_ok` is
  false: `ttl_for_response` classifies the response as negative and computes
  `negative_meta`, but `decompose_response_for_store`'s independent terminal
  check still matches the record and returns a positive-only
  `DecomposedResponse`, silently discarding the already-computed
  `negative_meta` — storing as a satisfying positive answer something the
  live resolution path deliberately decided wasn't one.
- **MEDIUM (coverage gap)**: two plan-mandated tests are missing with no
  substitute coverage: the `src/config/mod.rs` test asserting
  `RuntimeConfig::from_toml_str` round-trips `cache: CacheConfig` (both
  default and explicit `[cache]` table), and
  `open_telemetry_cache_gauges_report_approximate_domain_count` in
  `src/main.rs` (no test constructs `OpenTelemetryMetrics::new` against a
  `ShardedDnsCache` at all).
- **LOW**: `recursive_perf_bench_constructs_sharded_cache`, the test the
  plan calls out by name as "the missed call site from the Codex review,"
  doesn't exist as its own dedicated test — only incidentally exercised by
  a pre-existing, network-requiring `#[ignore]`d benchmark test.
- **LOW (nit)**: several cache-internal types (`ChainLookup`,
  `ResolvedAnswer`, `ResolvedNegative`, `RRsetEntry`, `StoredRecord`,
  `NegativeKey`, `NegativeEntry`) were widened to fully `pub` rather than
  `pub(crate)`. Since `mod cache;` stays a private module declaration, this
  may have no actual external-API effect — worth confirming empirically
  whether `pub(crate)` would still satisfy the `DomainDnsCache` trait's
  private-in-public-interface requirements before narrowing.

## Scope check

No stray references to retired types found anywhere outside deleted diff
lines. `src/resolver/mod.rs`, `src/main.rs`, `src/config/mod.rs`,
`tests/recursive_perf.rs` are the only files touched, matching the plan's
file list.
