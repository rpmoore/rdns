<!-- PROJECT_CONFIG
runtime: rust-cargo
test_command: cargo test --locked
END_PROJECT_CONFIG -->

<!-- SECTION_MANIFEST
section-01-foundation
section-02-data-model
section-03-shard-and-lru
section-04-singleflight
section-05-namespace-sweep
section-06-assembly-and-chains
section-07-call-site-migration
section-08-test-migration-and-benchmark
END_MANIFEST -->

# Implementation Sections Index

Splits `claude-plan.md`/`claude-plan-tdd.md` (answer-cache rework: sharded
locking, exact per-shard O(log n) LRU, domain-first key) into
implementable sections. Mirrors the rollout order in `claude-plan.md` §12.

## Dependency Graph

| Section | Depends On | Blocks | Parallelizable |
|---|---|---|---|
| section-01-foundation | - | all others | Yes (first) |
| section-02-data-model | section-01 | section-03 | No |
| section-03-shard-and-lru | section-02 | section-05, section-06 | No |
| section-04-singleflight | section-01 | section-07 | Yes (with 02/03/05/06) |
| section-05-namespace-sweep | section-03 | section-07 | Yes (with 06) |
| section-06-assembly-and-chains | section-03 | section-07 | Yes (with 05) |
| section-07-call-site-migration | section-04, section-05, section-06 | section-08 | No |
| section-08-test-migration-and-benchmark | section-07 | - | No |

## Execution Order

1. `section-01-foundation` (no dependencies)
2. `section-02-data-model` (after 01)
3. `section-03-shard-and-lru` (after 02)
4. `section-04-singleflight`, `section-05-namespace-sweep`,
   `section-06-assembly-and-chains` (parallel — 04 only needs 01; 05 and
   06 both only need 03)
5. `section-07-call-site-migration` (after 04, 05, AND 06)
6. `section-08-test-migration-and-benchmark` (final)

## Section Summaries

### section-01-foundation

New module skeleton (`src/resolver/cache/{mod,shard,lru,entry,singleflight,assemble,namespace}.rs`,
plan §10), the `shard_index(domain, shard_count) -> usize` hash-routing
utility shared by both the cache and single-flight structures, and
`CacheConfig` (plan §8) including the exact remainder-distributed
per-shard capacity split. No cache logic yet — this section only has to
compile and pass its own config/hashing unit tests.

### section-02-data-model

Positive and negative cache entry types: `RRsetEntry`, `StoredRecord`,
`DnssecState`, `NegativeEntry`, `NegativeKey`, `DomainRecordSets`,
`DomainNegativeEntries` (plan §3.1-§3.3). Pure data types plus whatever
minimal constructors are needed for section-03's tests — no shard/lock
wiring yet.

### section-03-shard-and-lru

`ShardLru` (BTreeSet + HashMap side-index, plan §4), `Shard`/`ShardState`
combining `PositiveShardState`/`NegativeShardState` behind one lock per
shard (plan §2, §3.3), and the eviction loop that removes a domain from
both maps and the LRU together. This is where exact per-shard LRU
touch/evict and capacity enforcement actually live.

### section-04-singleflight

`ShardedSingleFlight`, `InFlightMiss`, `SingleFlightTicket`/
`SingleFlightLeader` (plan §6) — ported from the current global-mutex
version to the new `(name, qtype, qclass)` key and per-shard structure,
reusing `shard_index` from section-01. Independently testable without the
cache data model.

### section-05-namespace-sweep

`sweep_stale_namespace` (plan §5) — walks a shard's positive and negative
maps, removing entries whose stored `cache_namespace` no longer matches,
removing fully-emptied domains from the LRU too. Depends on section-03's
shard/LRU structures existing.

### section-06-assembly-and-chains

`assemble_response` (plan §7, including the per-record TTL-aging vs.
entry-level-expiry split) and `resolve_from_cache`/`ChainLookup` CNAME
chain walking with the required one-shard-lock-at-a-time discipline (plan
§7.1). Plan §7.2 (prefetch hook point) is documentation-only — no code in
this section for it.

### section-07-call-site-migration

The new `DomainDnsCache` trait (plan §9.0) and every existing call site
that assumed a flat `CacheKey`: `probe_cache`, `cache_store_for_response`
(including the CNAME-hop-plus-terminal-negative combined store, plan §9),
`SingleFlightMisses` registration call sites, `serialize_cached_response`
replacement, `main.rs` cache construction and `OpenTelemetryMetrics`
gauges, the `Config::backend_cache_namespace`/`publish_reload` hook into
`sweep_stale_namespace`, `CacheConfig` wiring into `RuntimeConfig`, and
`tests/recursive_perf.rs`'s `resolver_with_cache` helper. This is the
mechanical rewiring step — all the genuinely new logic already exists and
is tested by the time this section starts.

### section-08-test-migration-and-benchmark

Migrate/rewrite the ~16 existing cache-related tests per plan §11 and
`claude-plan-tdd.md` §9 (rewrite, delete-deliberately, or replace as
specified), and add the new concurrency benchmark (`claude-plan-tdd.md`
§11) closing G8. Last section — everything it touches must already exist
and compile.
