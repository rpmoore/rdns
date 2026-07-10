# Usage Guide: Sharded DNS Answer Cache

This documents the sharded-locking, exact-LRU, domain-first-key cache
that replaced `InMemoryDnsCache`'s single-global-mutex design. Built
across 8 sections; see `docs/plans/cache_rework/sections/` for the full
design rationale and `docs/plans/cache_rework/implementation/code_review/`
for the per-section review trail.

## Quick Start

### Configuring the cache

```toml
# config.toml
[cache]
max_entries = 10000    # optional, default 10_000
shard_count = 16        # optional, default: available_parallelism() * 4,
                         # rounded to the next power of two
```

Both fields are optional; an absent `[cache]` table gets
`CacheConfig::default()`.

### Constructing it in code

```rust
use rdns::config::CacheConfig;
use rdns::resolver::{DomainDnsCache, ShardedDnsCache};

let cache = ShardedDnsCache::new(&CacheConfig::default());

// Used as a trait object everywhere ResolveQuery expects a cache:
let resolver = ResolveQuery::with_cache_policy_and_backend_snapshot(
    protocol_codec,
    Arc::new(cache) as Arc<dyn DomainDnsCache>,
    // ...
)
.with_max_chain_depth(8)              // bounds CNAME-chain walks
.with_single_flight_shard_count(16);  // match the cache's own shard count
```

`main.rs` does exactly this: `ShardedDnsCache::new(&config.cache)`, with
`max_chain_depth` sourced from
`config.resolution.recursive.max_cname_restarts` and
`with_single_flight_shard_count` from the cache's own `shard_count()`.

## What changed, from a caller's perspective

- **Cache key is now just the domain name.** Question wire casing and EDNS
  bufsize are no longer key dimensions — every hit assembles a fresh wire
  response per request (`assemble_response`/`assemble_negative_response`),
  echoing back whatever casing/bufsize *that* requester used.
- **One entry per domain, not per (name, qtype, flags-combination,
  namespace).** A domain can hold many cached record sets
  (`RRsetEntry`s) plus at most one negative result.
- **Reload-time cleanup is explicit, not incidental.** Where the old
  design let the cache key itself change on reload (silently orphaning
  stale entries), this design stores `cache_namespace` on every entry and
  actively sweeps stale-namespace entries once per `publish_reload` call
  (`sweep_stale_namespace`) — the one deliberate O(n) operation in the
  whole design.
- **`InMemoryDnsCache` no longer exists.** Deleted entirely once its own
  dependencies (`CacheKey`/`CacheLookup`/`CachedResponse`/`CacheStore`)
  were retired.

## Example Output

Cache miss → backend resolution → store → subsequent hit, observed via
`ResolveDecisionKind` and `ResolverMetric`:

```
QueryMiss   → ResolverMetric::CacheMiss
Backend OK  → ResolverMetric::CacheStore (+ CacheNegativeStore if negative)
Next query  → ResolveDecisionKind::CacheHit, ResolverMetric::CacheHit
```

Concurrent identical misses coalesce through `ShardedSingleFlight`
(replaces the old single-mutex `SingleFlightMisses`):

```
Query A (leader)   → backend call made
Query B (follower) → waits on A's result, no second backend call
                    → ResolverMetric::CacheCoalescedMiss
```

## API Reference

Public surface added under `rdns::resolver` (all re-exported from
`resolver::cache`, which itself stays a private module):

| Item | Purpose |
|---|---|
| `ShardedDnsCache` | The concrete cache type. `new(&CacheConfig)`, `shard_count()`. |
| `DomainDnsCache` (trait) | `lookup_chain`, `store_response`, `sweep_stale_namespace`, `domain_count`, `capacity`. Implemented by `ShardedDnsCache` and `NoopDnsCache`. |
| `DecomposedResponse` | What `store_response` consumes: `positive: Vec<(String, u16, u16, RRsetEntry)>`, `negative: Option<(String, NegativeKey, NegativeEntry)>`. |
| `RRsetEntry` / `StoredRecord` | One cached record set / one record within it. Constructible externally (needed by `tests/cache_concurrency_bench.rs`). |
| `NegativeEntry` / `NegativeKey` | One negative-cache result and its lookup key (`qtype: None` = whole-name NXDOMAIN, `Some(t)` = NODATA for type `t`). |

`ResolveQuery` gained two builder methods (post-construction, not new
constructor parameters, to avoid widening all 8 `with_cache*`
constructors):

- `with_max_chain_depth(u8)` — CNAME-chain walk bound, default 8.
- `with_single_flight_shard_count(usize)` — default from
  `CacheConfig::default().resolved_shard_count()`.

## Running the benchmark

```
just bench
```

Runs both `tests/recursive_perf.rs` (end-to-end resolve latency, needs
live network, `#[ignore]`d) and `tests/cache_concurrency_bench.rs` (raw
cache throughput under 1/2/4/8 concurrent threads, no network needed,
also `#[ignore]`d — prints a CSV table, no CI assertion since absolute
numbers are environment-dependent).

## Where to look next

- `docs/plans/cache_rework/sections/index.md` — the 8-section breakdown
  and dependency graph.
- `docs/plans/cache_rework/implementation/code_review/section-0N-*.md` —
  diff, reviewer findings, and triage/fix transcript for each section.
- `src/resolver/cache/mod.rs` — module-level doc comment and the
  `DomainDnsCache`/`ShardedDnsCache` definitions themselves.
