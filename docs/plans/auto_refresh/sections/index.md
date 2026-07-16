<!-- PROJECT_CONFIG
runtime: rust-cargo
test_command: cargo test
END_PROJECT_CONFIG -->

<!-- SECTION_MANIFEST
section-01-popularity-bucket
section-02-refresh-config
section-03-trigger-formula
section-04-chainlookup-plumbing
section-05-worker-pool-metrics
section-06-refresh-fetch-store
section-07-integration
END_MANIFEST -->

# Implementation Sections Index

## Dependency Graph

| Section | Depends On | Blocks | Parallelizable |
|---------|------------|--------|----------------|
| section-01-popularity-bucket | - | section-03 | Yes |
| section-02-refresh-config | - | section-03, section-05 | Yes |
| section-03-trigger-formula | section-01, section-02 | section-04 | Yes (vs. section-05) |
| section-04-chainlookup-plumbing | section-03 | section-06 | No |
| section-05-worker-pool-metrics | section-02 | section-06 | Yes (vs. section-03, section-04) |
| section-06-refresh-fetch-store | section-04, section-05 | section-07 | No |
| section-07-integration | section-06 | - | No |

## Execution Order

1. `section-01-popularity-bucket`, `section-02-refresh-config` (parallel, no dependencies)
2. `section-03-trigger-formula` (after 01 + 02), `section-05-worker-pool-metrics` (after 02) — parallel with each other
3. `section-04-chainlookup-plumbing` (after 03)
4. `section-06-refresh-fetch-store` (after 04 AND 05)
5. `section-07-integration` (final, after 06)

## Section Summaries

### section-01-popularity-bucket
`PopularityBucket` struct (integer level + `last_drained: SystemTime`),
drain-then-increment logic, wiring into `ShardState` as a new `HashMap<String,
PopularityBucket>` field alongside `lru: ShardLru`. Increment wired into the 4
existing `lru.touch` call sites in `Shard::lookup_hop`. Removal wired into the
existing `evict_domain`/`drop_lru_if_domain_now_empty` paths. Corresponds to
`claude-plan.md` §2 and `claude-plan-tdd.md` §2. Standalone — touches only
`src/resolver/cache/shard.rs`.

### section-02-refresh-config
`RefreshConfig` struct + `Default` impl + `RawRefreshConfig` shadow struct +
`try_into_refresh_config` conversion + `Option<RawRefreshConfig>` field on
`RawRuntimeConfig` + `validate()` wiring, following `CacheConfig`'s exact
three-piece pattern. Corresponds to `claude-plan.md` §5 and `claude-plan-tdd.md`
§5. Standalone — touches only `src/config/mod.rs`.

### section-03-trigger-formula
Eligibility-floor + lead-window + hot-threshold trigger formula as a pure
function alongside the existing `entry.expires_at <= now` check in
`Shard::lookup_hop`'s live-entry probes. Reads `PopularityBucket::is_hot()`
(section-01) and `RefreshConfig` thresholds (section-02). Corresponds to
`claude-plan.md` §3.1 and `claude-plan-tdd.md` §3.1. Touches
`src/resolver/cache/shard.rs`.

### section-04-chainlookup-plumbing
Extends `ChainLookup` (`Answered`/`NoData`/`NxDomain`/`Miss`) with a
`refresh_hints: Vec<RefreshHint>` payload on `Answered` only (never `NoData`,
per the positive-only v1 scope). Threads hints for *every* qualifying positive
hop through `resolve_from_cache`'s CNAME-hop walk — not just the terminal hop
(this was the multi-hop bug found during plan review). `probe_cache` reads the
hints and performs the non-blocking `try_send` enqueue per hint. Depends on
section-03's trigger logic being available to call during the hop walk.
Corresponds to `claude-plan.md` §3.2/§4.1 and `claude-plan-tdd.md` §3.2/§4.1.
Touches `src/resolver/cache/assemble.rs`, `src/resolver/mod.rs` (`probe_cache`).

### section-05-worker-pool-metrics
`RefreshJob` type, bounded `tokio::sync::mpsc` channel, `Arc<tokio::sync::Mutex<Receiver>>`-shared
fixed worker pool (`worker_count` from section-02's `RefreshConfig`), per-job
`tokio::spawn`+`JoinHandle` panic isolation (not `catch_unwind` — no new
dependency), spawned in `main.rs` alongside `spawn_sighup_reload_task` with the
same `.abort()`-based shutdown convention. New `ResolverMetric` variants
(`RefreshTriggered`/`RefreshQueueFull`/`RefreshSucceeded`/`RefreshFailed`) and
all `MetricsSink` impl updates (`OpenTelemetryMetrics`, `NoopMetricsSink`, test
`RecordingMetrics` impls). Jobs can no-op in this section (real fetch/store
logic lands in section-06). Corresponds to `claude-plan.md` §4.2/§4.4/§6 and
`claude-plan-tdd.md` §4.2/§6. Touches `src/resolver/mod.rs`, `src/main.rs`.

### section-06-refresh-fetch-store
Real job-processing logic: epoch-captured-first eligibility recheck (guards
against a stale-epoch job crossing a reload), synthetic query builder
(`build_refresh_query`, new production helper — no existing equivalent),
`ShardedSingleFlight`-based fetch (`dnssec_ok` always `true`) with the
corrected coalescing behavior (coalesces only with same-`dnssec_ok` concurrent
client requests), store via `cache_store_for_response`/`store_cache_response`
bypassing `prepare_backend_result`'s policy/rewrite/chaos layers, no-retry
failure handling. Depends on section-04's hints reaching the enqueue point and
section-05's worker pool skeleton to plug into. Corresponds to `claude-plan.md`
§4.3 and `claude-plan-tdd.md` §4.3. Touches `src/resolver/mod.rs`.

### section-07-integration
Final `main.rs` wiring confirming the worker pool spawn is gated on
`RefreshConfig::enabled`; `docs/knowledge/resolver/caching/` updates (new
`auto-refresh.md` or a section on `answer-cache.md`, per `AGENTS.md`'s
Knowledge Bundle requirement); end-to-end verification pass against a fake
backend proving hot domains get refreshed near TTL boundary and cooling
domains stop being refreshed. Corresponds to `claude-plan.md` §7/§9 (final
steps) and `claude-plan-tdd.md` §8/9. Touches `src/main.rs`,
`docs/knowledge/resolver/caching/`.
