# Code Review Interview: section-07-call-site-migration

Review source: `section-07-review.md` (via `deep-implement:code-reviewer`
subagent).

## Findings triage

| Finding | Severity | Disposition |
|---|---|---|
| `decompose_response_for_store` independently re-derives "is this a satisfying answer" and can disagree with `ttl_for_response`'s classification for direct CDS/CDNSKEY/32769 queries | MODERATE | Auto-fix — trust `ttl_for_response`'s classification instead of re-deriving |
| Missing plan-mandated `RuntimeConfig.cache` TOML round-trip test | MEDIUM | Auto-fix — added `cache_config_defaults_when_absent`/`cache_config_explicit_override` |
| Missing plan-mandated `open_telemetry_cache_gauges_report_approximate_domain_count` test | MEDIUM | Auto-fix — added, using `registry.gather()` to trigger the `ObservableGauge` callback |
| Missing dedicated `recursive_perf_bench_constructs_sharded_cache` regression test | LOW | Auto-fix — added as a fast, non-`#[ignore]`d `#[test]` (construction only, no network) |
| `ChainLookup`/`ResolvedAnswer`/`ResolvedNegative`/`RRsetEntry`/`StoredRecord`/`NegativeKey`/`NegativeEntry` widened to `pub` — reviewer suspected `pub(crate)` would suffice since `mod cache;` stays private | LOW | Verified empirically, reviewer was wrong — `pub(crate) enum ChainLookup` + `pub use assemble::ChainLookup;` fails to compile (E0365: "only public within the crate, cannot be re-exported outside"), regardless of `mod cache;`'s own privacy. `pub` is required. Reverted the experiment, no change needed. |

No user interview was needed — the one real bug (decompose_response_for_store)
had an unambiguous fix once identified, and the coverage gaps were
plan-mandated tests to simply add, not design decisions.

## Fixes applied

1. **`decompose_response_for_store` classification-divergence bug**
   (`src/resolver/mod.rs`) — added a `treat_as_negative = negative_meta.is_some()`
   guard so the function never attempts its own terminal-positive match once
   `ttl_for_response` has already classified the response as negative,
   instead of running two independently-written "is this a satisfying
   answer" predicates that can disagree (they diverge for a directly-queried
   CDS/CDNSKEY/32769 record when `dnssec_ok` is false, since
   `has_requested_answer_for` always passes `dnssec_ok = false` internally
   regardless of the actual request). Added regression test
   `decompose_response_for_store_trusts_ttl_policy_negative_classification`.
2. **`src/config/mod.rs`** — added `cache_config_defaults_when_absent` and
   `cache_config_explicit_override`, mirroring the existing
   `metrics_config_*` TOML-parsing test pattern exactly.
3. **`src/main.rs`** — added
   `open_telemetry_cache_gauges_report_approximate_domain_count`, which
   builds a real (empty) `ShardedDnsCache`, constructs `OpenTelemetryMetrics`
   from it, calls `registry.gather()` (the same call the Prometheus HTTP
   exporter makes) to actually trigger the `ObservableGauge` callbacks, and
   asserts `cache_size == 0`/`cache_capacity == 16` for a single-shard,
   16-capacity, freshly-built cache.
4. **`tests/recursive_perf.rs`** — added
   `recursive_perf_bench_constructs_sharded_cache`, a fast `#[test]` (not
   `#[tokio::test]`, not `#[ignore]`d) that only calls `resolver_with_cache`
   — construction-only, no network I/O — so a future change to
   `ResolveQuery::with_cache`'s cache parameter type breaks a test that
   actually runs by default, not just the `#[ignore]`d live-network
   benchmarks that happen to also use the same helper.

## Verification after fixes

- `cargo build --all-targets` — clean.
- `cargo test --locked` (full workspace) — 449 lib + 19 bin + 8 forwarding +
  1 recursive_perf passed, 0 failed (up from 446 before this round of
  fixes; +4 net new tests: the decompose regression test, 2 config tests,
  1 OpenTelemetry gauge test, 1 recursive_perf test — 5 added, consistent
  with the diff).
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo fmt` — clean.
- Repeated `cargo test --locked` ~20x to check for flakiness in the
  concurrency-sensitive coalescing/chain-walk tests touched by this
  section: all passed every time. One unrelated pre-existing flake
  surfaced once (`delivery::dns::tests::tcp_bind_configured_uses_configured_max_connections`,
  a TCP-port-binding race in code this section never touches) — not a
  regression from this work.
