---
type: Mechanism
title: Cache Sharding
description: >
          How the answer cache splits into independently-locked shards,
          and what else shares that scheme.
resource: src/resolver/cache/mod.rs
tags: [cache, dns, resolver, sharding, concurrency]
timestamp: 2026-07-13T00:00:00Z
---

The [answer cache](answer-cache.md) is not one lock over one map — it's
`N` independent shards, each its own `Mutex`, routed to by a hash of the
domain name. Concurrent requests for different domains that land in
different shards never contend with each other.

# Routing: `shard_index`

`src/resolver/cache/mod.rs:231`:

```rust
pub(crate) fn shard_index(domain: &str, shard_count: usize) -> usize {
    if shard_count == 0 { return 0; }
    static PROCESS_SHARD_HASH_SEED: OnceLock<RandomState> = OnceLock::new();
    let build_hasher = PROCESS_SHARD_HASH_SEED.get_or_init(RandomState::new);
    (build_hasher.hash_one(domain) % shard_count as u64) as usize
}
```

- Hashes with `std::collections::hash_map::RandomState`, seeded once per
  *process* (not per call, not `DefaultHasher`'s fixed well-known seed).
  Reusing one seed for the process's lifetime is what keeps routing
  stable while the process is up — the same domain always lands in the
  same shard for as long as this resolver instance runs, or a lookup
  could miss its own just-stored entry. Routing is **not** stable across
  restarts, and isn't meant to be.
- `domain` must already be normalized (lowercased, trailing dot
  stripped) by the caller — this function does no normalization itself,
  so two differently-cased spellings only route together if the caller
  normalized first. `normalize_question_name` (`src/resolver/mod.rs:225-226`)
  does this; `QuestionKey::new` (`:211-217`) applies it, and
  `DecodedQuery::new` (`:262-274`) builds `question: QuestionKey` through
  that constructor for every decoded request — so every production
  caller of `lookup_chain`/`store_response` (e.g. `probe_cache`,
  `src/resolver/mod.rs:4255-4260`) is passing an already-normalized
  `decoded.question.qname`, never a raw wire-format name.
- Grouping granularity is **per domain name, not per (domain, qtype)**.
  All qtypes/qclasses for one name, its negative-cache entries, and its
  LRU token live in the same shard — see [answer-cache](answer-cache.md)'s
  `ShardState` layout. A hot name with many cached record types still
  contends on exactly one shard's lock, not several.

# Shard count and capacity

`CacheConfig` (`src/config/mod.rs:298`):

- `shard_count: Option<usize>` — `None` resolves to
  `available_parallelism() * 4`, rounded to the next power of two
  (`resolved_shard_count`, `:336`), following the DashMap/RocksDB
  convention of roughly 4x parallelism.
- `resolved_shard_count` also caps the result at `max_entries` whenever
  `max_entries > 0` — otherwise a `shard_count` exceeding `max_entries`
  would floor some shards' capacity to zero (`max_entries / shard_count`
  dividing to 0), permanently blackholing any domain hashed into one of
  those shards under a config that *looks* valid.
- Per-shard capacity (`shard_capacity`, `:360`) distributes `max_entries`
  as evenly as possible: `max_entries / shard_count` per shard, plus one
  extra for the first `max_entries % shard_count` shards, so the total
  sums exactly to `max_entries` rather than rounding up per shard and
  overshooting.

`ShardedDnsCache::new` (`src/resolver/cache/mod.rs:52`) builds exactly
`resolved_shard_count()` shards this way at construction; the shard
count is fixed for the process's lifetime — a reload never changes
shard topology, only what's inside the shards ([cache-epoch](cache-epoch.md)).

# Locking discipline

Each `Shard` is `{ state: Mutex<ShardState>, capacity: usize }`
(`src/resolver/cache/shard.rs:626`). Every operation — store, lookup,
one hop of a CNAME-chain walk, the epoch sweep — takes that one shard's
lock, does its work, and releases it:

- `Shard::lookup_hop` takes the lock for exactly one name in a
  CNAME-chain walk, not the whole chain (its own doc comment: "callers
  must not hold it across hops") — a multi-hop CNAME lookup that crosses
  shard boundaries acquires and releases multiple shards' locks in
  sequence, never more than one at a time.
- `Shard::sweep_stale_namespace` (called from
  `namespace::sweep_stale_namespace` across all shards after a
  [cache-epoch](cache-epoch.md) bump) locks one shard at a time — an O(n)
  walk of that shard's own maps, not a single O(n) walk under one global
  lock. Concurrent lookups against *other* shards are never blocked by
  a sweep in progress on one shard.
- No lock is ever held across an `.await`.

# What else shares this scheme, and what deliberately doesn't

`ShardedSingleFlight` (`src/resolver/cache/singleflight.rs:83`), the
miss-coalescing structure, uses the **same** `shard_index` routing —
`main.rs:146` calls `ResolveQuery::with_single_flight_shard_count`
(`src/resolver/mod.rs:3591`) with the real `ShardedDnsCache`'s own
`shard_count()`, once both are constructed, so "shard N" means the same
domain-bucket in both structures. But its lock is
**intentionally separate** from the cache shard's own lock: merging them
would widen the cache shard's critical section to include unrelated
in-flight-miss bookkeeping, reintroducing the "unrelated work serialized
under one lock" problem this sharding scheme exists to remove.

# See also

- [answer-cache](answer-cache.md) — what lives inside one shard.
- [cache-epoch](cache-epoch.md) — the sweep this document's locking discipline is described in
  service of.
