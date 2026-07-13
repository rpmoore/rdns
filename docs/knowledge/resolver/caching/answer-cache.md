---
type: System
title: DNS Answer Cache
description: Sharded, in-memory cache of backend/upstream DNS answers, keyed by domain name.
resource: src/resolver/cache/mod.rs
tags: [cache, dns, resolver]
timestamp: 2026-07-13T00:00:00Z
---

Caches responses obtained from actual backend resolution — forwarding or
recursive — so a repeated query for the same name doesn't re-do that
work until TTL expiry or [invalidation](cache-epoch.md). It does **not**
cache manually-loaded data (BIND zone files, `[[local_dns_entries]]`);
see [local-dns-entries](local-dns-entries.md) for why that's a separate
structure entirely.

# Structure

```
ShardedDnsCache { shards: Vec<Shard> }
Shard { state: Mutex<ShardState>, capacity: usize }
ShardState {
    positive: HashMap<domain, DomainRecordSets>,   // DomainRecordSets: HashMap<(qtype, qclass), RRsetEntry>
    negative: HashMap<domain, DomainNegativeEntries>,
    lru: ShardLru,
}
```

One domain name's positive records, negative (NXDOMAIN/NODATA) entries,
and LRU recency token all live in the same shard, mutated together under
that shard's single `Mutex`. See [sharding](sharding.md) for how a
domain is routed to a shard and why this grouping matters for
concurrency.

# What's stored per entry

`RRsetEntry` (positive) and `NegativeEntry` (negative),
`src/resolver/cache/entry.rs`:

| Field | Purpose |
|---|---|
| `records` / `soa_record` + proof records | The actual RRset or negative-cache proof material. |
| `stored_at` / `expires_at` | TTL bookkeeping — `expires_at` is checked on every lookup and read-time expiry deletes the entry immediately (not just filters it out), see `Shard::lookup_hop`. |
| `dnssec_state` | RFC 6840 §3.1 validation state; stays `Unvalidated` until real DNSSEC validation exists — orthogonal to everything else in this document. |
| `dnssec_complete` | Whether this entry was populated by a fetch that actually requested DNSSEC material (DO=1). A DO=1 reader must never be served an entry where this is `false`, even if TTL-valid — see `Shard::lookup_hop`'s DO-aware filtering. |
| `authoritative` | The backend response's own AA bit, replayed on a cache hit. |
| `cache_epoch` | Cache-identity tag, compared for equality at lookup/sweep time. See [cache-epoch](cache-epoch.md) for the whole mechanism — this field is the one piece of it that lives on the entry itself. |

Unlike an earlier design, no per-entry data is keyed by the *requester's*
casing, EDNS bufsize, or flags — one entry serves every requester for
that `(domain, qtype, qclass)`; request-specific details are applied at
serve time (`cache::assemble`).

# Concurrency model, in one sentence

Every lookup and every store takes exactly one shard's `Mutex`, for the
duration of one domain-name operation only — never a global lock, never
held across an `.await`, never held across more than one hop of a
CNAME-chain walk (`Shard::lookup_hop`'s doc comment: "takes and releases
this shard's lock for the duration of this one hop only"). Concurrent
requests for different domains that hash to different shards never
contend with each other at all.

# Eviction

Per-shard LRU (`cache::lru::ShardLru`), evicted **by domain**, not by
individual record set — evicting a domain removes its positive entries,
negative entries, and LRU token together (`ShardState::evict_domain`).
Capacity is domain-count-based, configured via `CacheConfig.max_entries`,
split across shards by `CacheConfig::shard_capacity` (see
[sharding](sharding.md)).

# See also

- [cache-epoch](cache-epoch.md) — how a SIGHUP reload invalidates entries here.
- [sharding](sharding.md) — how domains route to shards, and what else shares this routing scheme.
- [local-dns-entries](local-dns-entries.md) — the separate, non-cached structure for manually-loaded answers.
