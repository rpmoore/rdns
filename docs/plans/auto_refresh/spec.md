# Auto-Refresh Popular Domains Before TTL Expiry

## Context

`rdns`'s cache (`src/resolver/cache/`) is a passive, pull-based sharded cache:
entries sit until their `expires_at` (`RRsetEntry`/`NegativeEntry`, `src/resolver/cache/entry.rs`)
passes, then the next lookup for that name finds nothing and pays a full backend
round trip before anything is re-cached (`Shard::lookup_hop`, `src/resolver/cache/shard.rs:405`).
For domains queried repeatedly, that round trip repeats every TTL cycle, on the
client's own dime — the miss becomes visible latency for whoever happens to ask
right after expiry.

The ask: keep genuinely popular domains "hot" by refreshing them from the backend
proactively, at or just before TTL expiry, without maintaining a fixed popular-domain
list (query patterns drift over time) and without adding meaningful overhead or lock
contention to the query hot path.

## Research: refresh-trigger strategies considered

Four strategies were evaluated against this codebase's existing sharded-lock cache
(one `Mutex` per `Shard`, already taken on every lookup for LRU bookkeeping —
`ShardState`/`Shard::lookup_hop`, `src/resolver/cache/shard.rs:73,405`):

1. **Periodic full-cache scan** (walk every shard on a timer, check every domain's
   remaining TTL/popularity). Rejected: cost scales with total cache size
   (`CacheConfig::max_entries`, up to configured capacity), not with the actual
   popular-domain count — wasted lock acquisitions and CPU on a majority-cold cache,
   worse as `max_entries` grows.
2. **Background timer wheel** (min-heap of `(expires_at, domain, qtype, qclass)`,
   popped by a scheduler). Rejected: requires a second data structure kept in sync
   with every insert, eviction, and expiry the cache already tracks via its LRU
   (`ShardLru`, `src/resolver/cache/lru.rs`) — real risk of drift (stale heap entries
   after eviction) for a benefit the lazy approach below gets for free.
3. **Lazy refresh-on-read ("stale-while-revalidate")** — detect "near expiry + hot"
   at the exact point a real query already takes the shard lock
   (`Shard::lookup_hop`), serve the still-valid entry immediately, and kick a
   background refetch. Refresh cost is proportional to real traffic, not cache size;
   piggybacks on a lock already being taken for an unrelated reason (LRU touch), so
   the added cost per hit is a couple of field reads, not a new lock. Matches
   Unbound's/BIND's "prefetch popular near-expiry names" and CDN
   stale-while-revalidate behavior.
4. **Dedicated refresh queue/worker** — the actual backend refetch triggered by (3)
   never runs inline on the request path; it's handed to a bounded worker pool via a
   channel. Decouples backend I/O latency from the querying client entirely, and
   bounds total concurrent refresh work independent of how many "hot" entries expire
   in the same instant.

**Recommendation: (3) + (4) combined.** Detection reuses the shard lock already held
during every lookup (near-zero added cost); execution is fully decoupled onto a
capped worker pool so a burst of simultaneously-expiring hot entries can never turn
into a concurrency spike or block a real client's response. This also sidesteps (1)'s
and (2)'s core weakness: no new structure needs to stay in sync with the cache's
existing eviction/expiry bookkeeping — popularity state rides along with the same
per-domain LRU token lifecycle that already exists.

## Design

### 1. Popularity tracking: per-domain leaky bucket, inside the existing shard lock

Add a per-domain leaky-bucket counter (level + last-drained timestamp) alongside
`ShardLru`'s existing `HashMap<String, u64>` position index in `ShardState`
(`src/resolver/cache/shard.rs:73`) — same map lifecycle as the LRU token: created
when a domain is first stored, drained lazily (elapsed-time-based, no separate timer)
on each touch, and removed via the same `drop_lru_if_domain_now_empty` /
`evict_domain` paths that already clear LRU state (`src/resolver/cache/shard.rs:84,144`).
This is what keeps the popular set unbounded-list-free and self-adapting: a domain's
bucket only stays full under continued real traffic, and disappears entirely the
moment the domain is evicted or its data expires and isn't re-queried — no separate
cleanup pass, no fixed list anywhere.

Granularity: **per-domain (qname only)**, not per-`(qname,qtype,qclass)`. Any query
for the domain (A, AAAA, MX, ...) raises its popularity; the refresh trigger (below)
still acts on the specific `RRsetEntry` that's actually near expiry. This matches the
existing LRU's own granularity (`Shard::touch` already operates per-domain) and avoids
proliferating buckets per record type.

Increment happens inside `Shard::lookup_hop`'s existing lock section, at the same
point `state.lru.touch(domain)` already runs on a hit (`src/resolver/cache/shard.rs:426,436,448,459`).
Drain-then-increment is a pure O(1) arithmetic update (elapsed-time-based leak, no
background timer needed for draining itself) — no new lock, no allocation on the hit
path for domains already tracked.

### 2. Trigger: detected at read time, alongside the existing expiry check

`Shard::lookup_hop`'s live-entry probes (`take_live_positive`/`take_live_cname_hop`/
`take_live_negative`, `src/resolver/cache/shard.rs:163-268`) already compute
`entry.expires_at <= now` per lookup. Extend that same check: an entry that is live
but within a configurable *refresh lead window* of expiry, **and** whose domain's
popularity bucket is above a configurable hot-threshold, is still served normally
(unchanged response), but the lookup additionally signals "this entry wants a
refresh." The caller (resolver's cache-probe path, `ResolveQuery::probe_cache`,
`src/resolver/mod.rs:4656`) turns that signal into a non-blocking enqueue — see below.

Refresh lead window: recommend `remaining_ttl <= max(minimum_ttl * refresh_lead_ratio,
refresh_min_lead)`, both configurable (defaults e.g. 10% / 5s) — bounds the trigger
window sensibly at both very long and very short TTLs. Exact defaults/formula are a
detail for the TDD phase, not fixed here.

Re-trigger suppression: no new bookkeeping structure is introduced for this. The
worker (below) re-validates an entry is still within the lead window immediately
before fetching, and the actual backend call always goes through the existing
single-flight machinery, so duplicate triggers from a burst of queries in the same
window collapse to at most one backend fetch. Once a refresh succeeds, `expires_at`
moves forward and the entry falls back outside the lead window, which is what stops
further triggers — self-limiting by construction, same as the popularity bucket
itself.

### 3. Execution: bounded worker pool, reusing the existing single-flight and store paths

New background task(s), spawned in `main.rs` alongside the existing
`spawn_sighup_reload_task` pattern (`src/main.rs:579`) — this is the first periodic
non-reload background task in the codebase, so it should follow that file's existing
shape (accept an `Arc<ResolveQuery>`, `tokio::spawn`, run until shutdown).

- Hot-path trigger (§2) does a non-blocking send (`try_send`) of a small refresh job
  (`domain`, `qtype`, `qclass`, the DO flag the cached entry was fetched with) onto a
  bounded `tokio::sync::mpsc` channel. Full channel ⇒ drop the job — proactive
  refresh is best-effort by design; a dropped trigger just means that entry expires
  normally and gets a regular reactive miss, no correctness impact.
- A small fixed pool of worker tasks reads the channel. Each job: re-check the entry
  is still within the lead window (cheap shard-lock probe — guards against a job that
  went stale while queued), then perform the backend refetch and re-store.
- The refetch **must** go through `ShardedSingleFlight`'s existing `MissKey`
  machinery (`src/resolver/cache/singleflight.rs:73`, `(qname, qtype, qclass, epoch,
  dnssec_ok)`), not a bespoke call — this is what makes a refresh-in-flight coalesce
  for free with a real client request that happens to miss the same key at the same
  moment, and vice versa, with no additional dedup structure.
- Building the outgoing query and storing the result should reuse
  `ResolveQuery::resolve_backend` (`src/resolver/mod.rs:4575`) and the existing
  decompose/store pipeline (`cache_store_for_response` / `store_cache_response`,
  `src/resolver/mod.rs:5400,5434`) — a synthetic internal request bypasses policy
  evaluation, local-entries, and chaos-injection (none of that applies to a
  server-internal refresh), sourcing the current epoch from `BackendHandle::current()`
  (`src/resolver/mod.rs:2562`) the same way every other store path already does, so a
  refresh straddling a config reload naturally lands under the post-reload epoch.

Worker count and channel capacity should be configurable with conservative fixed
defaults (small pool, e.g. low single digits; modest channel depth) — sized for
"protects against a refresh storm," not for throughput tuning.

### 4. Configuration

New config surface (new struct in `src/config/mod.rs`, alongside `CacheConfig`,
`src/config/mod.rs:341`), covering: enable/disable, bucket capacity, leak rate, hit
increment, hot-threshold (fraction of bucket capacity), refresh lead ratio/min-lead,
worker count, channel capacity. **Ships default-on** with conservative defaults, but
every knob remains operator-overridable — this is new always-running behavior
touching the cache hot path, so the defaults should favor "barely noticeable" over
"aggressive," and a disable switch must exist for operators who want to opt out
entirely.

### 5. Metrics

New `ResolverMetric` variants (`src/resolver/mod.rs:8111`) following existing naming
(`CacheHit`/`CacheMiss`/... style): refresh triggered, refresh queue full/dropped,
refresh succeeded, refresh failed. Gives operators visibility into whether the
feature is doing anything and whether the worker pool/channel are sized correctly for
their traffic, without needing a new sink type.

## Non-goals

- No fixed/configured list of "popular domains" anywhere — popularity is entirely
  derived from the leaky bucket's live state.
- No change to reactive (on-miss) cache behavior — this is purely additive; disabling
  it (or a dropped/failed refresh) leaves today's behavior fully intact.
- No new locking primitive — reuses the existing per-shard `Mutex` and the existing
  `ShardedSingleFlight`.
- DNSSEC validation semantics are unaffected; a refresh preserves whatever DO-fetched
  state produced the entry it's replacing (open detail: derive from
  `RRsetEntry::dnssec_complete`, `src/resolver/cache/entry.rs:71`).

## Critical files / modules

- `src/resolver/cache/shard.rs` — `ShardState`/`Shard::lookup_hop`: popularity bucket
  storage + drain/increment, refresh-trigger detection alongside the existing expiry
  check.
- `src/resolver/cache/lru.rs` — reference for the "ride the existing per-domain
  map lifecycle" pattern the popularity bucket should follow.
- `src/resolver/cache/singleflight.rs` — `ShardedSingleFlight`/`MissKey`: reused
  unchanged for refresh-fetch dedup.
- `src/resolver/mod.rs` — `ResolveQuery::probe_cache` (near line 4656) to consume the
  trigger signal and enqueue; `resolve_backend` (4575), `cache_store_for_response`/
  `store_cache_response` (5400/5434), `BackendHandle` (2551) reused for the refresh
  worker's fetch+store; new `ResolverMetric` variants (8111).
- `src/main.rs` — `spawn_sighup_reload_task` (579) as the pattern to follow for
  spawning the new refresh-worker task(s).
- `src/config/mod.rs` — `CacheConfig` (341) as the pattern for the new refresh config
  struct.
- `docs/knowledge/resolver/caching/` — existing knowledge docs (`sharding.md`,
  `cache-epoch.md`, `answer-cache.md`) to extend once implemented, per this repo's
  `AGENTS.md` Knowledge Bundle requirement.

## Verification

- Unit tests near the popularity/trigger logic (`cache::shard`) using fake clocks —
  bucket fills/drains correctly, trigger fires only once both TTL-lead and
  hot-threshold conditions hold, and clears when a domain is evicted.
- Resolver-level tests (`resolver::mod` style, fake upstream/backend) proving: a
  triggered refresh updates the cache entry's `expires_at` without a client-visible
  cache miss; a dropped (channel-full) trigger leaves existing reactive-miss behavior
  intact; a refresh in flight coalesces with a concurrent real client miss for the
  same key via `ShardedSingleFlight`.
- End-to-end: run the resolver against a fake/backend that logs query timestamps for
  a domain queried steadily above the hot threshold; observe backend re-queries
  landing near each TTL boundary rather than a client-visible miss, and confirm a
  domain that stops being queried stops getting refreshed after its bucket drains.
- `cargo fmt`/`cargo clippy`/`cargo test` gates per `RUST.md`, run before considering
  any implementation step done.
