---
type: System
title: DNS Answer Cache
description: Sharded, in-memory cache of backend/upstream DNS answers, keyed by domain name.
resource: src/resolver/cache/mod.rs
tags: [cache, dns, resolver]
timestamp: 2026-07-15T00:00:00Z
---

Caches responses obtained from actual backend resolution — forwarding or
recursive — so a repeated query for the same name doesn't re-do that
work until TTL expiry or [invalidation](cache-epoch.md). It does **not**
cache manually-loaded data (BIND zone files, `[[local_dns_entries]]`);
see [local-dns-entries](local-dns-entries.md) for why that's a separate
structure entirely.

# Structure

```text
ShardedDnsCache { shards: Vec<Shard> }
Shard { state: Mutex<ShardState>, capacity: usize }
ShardState {
    // DomainRecordSets: HashMap<(qtype, qclass), RRsetEntry>
    positive: HashMap<domain, DomainRecordSets>,
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

# Wire-TTL aging on read

Cache-hit responses serve **remaining time to expiry** as their wire
TTL, computed per-record by `compute_wire_ttl`
(`src/resolver/cache/assemble.rs:188-204`), never the raw origin TTL
that was stored — per RFC 1035 §3.2.1, a resolver replaying a cached RR
must decrement the TTL by elapsed time, not repeat the original value
forever. It is called once per record, independently, from
`write_rrset` (`assemble.rs:229-263`, positive answers) and
`write_negative_authority` (`assemble.rs:265-324`, SOA + its RRSIG +
each DNSSEC proof record). Both UDP and TCP responses go through the
same `assemble_response`/`assemble_negative_response` path
(`assemble.rs:546`, `:615`) — one wire-TTL-aging code path, shared by
every transport.

`compute_wire_ttl` combines two independently-bounded quantities and
takes the tighter of the two:

- `aged = ttl_at_store - elapsed_since(stored_at)` — the record's own
  origin TTL, decremented by how long it has actually been sitting in
  the cache.
- `remaining = expires_at - now` — how much longer the cache entry
  itself is allowed to live under this resolver's TTL policy.
- Final wire value = `min(aged, remaining)`.

**Chain-wide `expires_at` ceiling.** A CNAME chain's `expires_at` is
computed once, as the minimum origin TTL across every record in the
response, and applied identically to every hop including the terminal
record — so a long-TTL terminal record looked up again later, on its
own, is still capped by whatever chain it was first stored as part of.
Per the doc comment at `assemble.rs:181-187`: a CNAME chain combines
records from multiple `RRsetEntry`s with different `stored_at` values,
so a single scalar age applied to an assembled buffer can't represent
it correctly — hence per-record aging computed directly in Rust rather
than reused from a buffer-level `age_response_ttls`/`cap_response_ttls`
helper. This edge case is covered by a regression test,
`resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup`
in `src/resolver/mod.rs` (see `docs/plans/ttl_remaining/` section 03).

Even when a `min_positive_ttl` floor extends an entry's actual cache
lifetime (`expires_at`) well past what the record's own origin TTL
alone would justify, `compute_wire_ttl`'s `aged` term still comes from
the record's own `ttl_at_store` — so the served wire TTL correctly goes
to (and stays at) 0 once the origin TTL has elapsed, even though the
entry itself is still servable under the floor. Covered by a regression
test, `compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime`
in `assemble.rs` (see `docs/plans/ttl_remaining/` section 03).

`write_negative_authority`'s per-record `compute_wire_ttl` calls
(`assemble.rs:265-324` — wire-TTL aging, what gets sent on the wire for
the SOA, its RRSIG, and each DNSSEC proof record) are a different
computation from `NegativeEntry::dnssec_proof_material_fresh`
(`src/resolver/cache/entry.rs:224-238` — servability gating, whether a
DO=1 reader may be served this entry at all). Without the latter check,
a DO=true reader arriving after an individual proof record's own TTL
elapsed (but before the overall negative TTL elapsed) would still pass
the `dnssec_complete` gate and be served that record aged to wire TTL 0
by `compute_wire_ttl` — stale material silently masquerading as fresh.
These are two intentional, non-redundant mechanisms operating over the
same stored fields, not a duplicate check.

Separately: a cache entry's `stored_at` is set from the client
request's received timestamp, not the backend answer's arrival
timestamp, so a cached entry's apparent remaining TTL is understated by
roughly one backend round trip — pre-existing, low-severity, not fixed
by this plan.

This doc will need a follow-up edit once a separate, later PR (Part E of
`docs/plans/ttl_remaining/claude-plan.md`, the EDNS-Cookie cache
allowlist) lands, noting that EDNS-Cookie-bearing queries become
cache-compatible at that point. Today they bypass the cache entirely —
see `cache_supported`, `src/resolver/mod.rs:5508-5520`.

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
- [local-dns-entries](local-dns-entries.md) — the separate, non-cached structure for manually-loaded
  answers.
