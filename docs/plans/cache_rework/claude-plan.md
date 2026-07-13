# Plan: Answer-cache rework — sharded locking, exact per-shard LRU, domain-first key

## Audience and scope of this document

This plan describes a from-scratch redesign of the DNS answer cache in
`src/resolver/mod.rs` (the resolver's `InMemoryDnsCache` and
`SingleFlightMisses`, described in full in `docs/caching.md`). It assumes
no prior context: read `docs/caching.md` first for how the *current* cache
works, then this document for how it changes. This is a blueprint, not
code — implementers write the actual Rust.

**Out of scope** (do not implement as part of this plan): the delegation
cache (`DelegationCache`), a byte-size/memory bound (G11), actual DNSSEC
signature validation logic. See `claude-spec.md` for the full non-goals
list and the reasoning behind every decision below.

## 1. Why the current design can't just be tuned

`docs/caching.md` §6-8 documents three compounding problems that motivate
a structural rewrite rather than an incremental fix:

1. **One lock for everything** — a single `std::sync::Mutex` covers the
   entire `entries` map and the entire LRU structure; every request,
   regardless of which key it touches, serializes through it (G2).
2. **The LRU is an approximation that periodically costs O(n)** — the
   current `VecDeque` ghost-token design requires a full-scan compaction
   pass under that same lock, and at steady state (cache full) this
   happens on nearly every store (G1 — "the most important finding" in
   `docs/caching.md`).
3. **The key is finer-grained than it needs to be** — `CacheKey` bakes in
   exact question-wire casing and raw EDNS bufsize as fragmentation
   dimensions, and folds DNSSEC-relevant flags (AD/CD/DO) into the key
   too, multiplying entries for what is conceptually the same cached data.

Fixing (1) requires sharding. Sharding is fundamentally in tension with a
single global recency order (§2 below resolves this). Fixing (2) requires
replacing the ghost-token `VecDeque` with a structure that doesn't need
periodic full scans. Fixing (3) requires changing what the key *is*, which
also happens to be a prerequisite for making the cache DNSSEC-shape-ready.
These three fixes are interdependent enough that this plan designs them
together rather than as three separate patches.

## 2. Architecture overview

The cache becomes **N independently-locked shards**, selected by hashing
the normalized owner (domain) name. All data for a given domain — its
positive record sets, its negative-cache entries, and its LRU recency
token — lives in exactly one shard, so a single domain's cache operations
never need to coordinate across shards.

```
                    hash(domain_name) % shard_count
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         ┌─────────┐    ┌─────────┐    ┌─────────┐
         │ Shard 0 │    │ Shard 1 │ …  │Shard N-1│
         │ (own    │    │ (own    │    │ (own    │
         │  lock)  │    │  lock)  │    │  lock)  │
         └─────────┘    └─────────┘    └─────────┘
```

Each shard independently:
- stores positive record sets, keyed by `(qtype, qclass)`, under the
  domain name;
- stores negative-cache entries (NXDOMAIN/NODATA) separately from
  positive entries, per the interview decision (Q12), but still under the
  same domain name and the same shard;
- maintains its own **exact** LRU order over the domains it holds (§4);
- enforces its own capacity bound, so eviction is exact-per-shard,
  approximate-globally — the same tradeoff RocksDB, Unbound, and PowerDNS
  Recursor all accept for the same reason (see `claude-research.md` B.1,
  B.3).

Request coalescing (single-flight) becomes a second, identically-sharded
structure (§6) — this closes the second global mutex from `docs/caching.md`
§6, not just the first.

## 3. Data model

### 3.1 Positive cache (per shard)

```rust
/// One shard's positive-cache state. Domain names are normalized
/// (lowercased, trailing dot stripped) the same way `QuestionKey` does
/// today — reuse `normalize_question_name` rather than re-deriving it.
struct PositiveShardState {
    domains: HashMap<String, DomainRecordSets>,
}

/// All cached record sets for one owner name, across every qtype/qclass
/// queried for it. This is the "many DNS record sets per domain" shape
/// from the spec's goal 3.
struct DomainRecordSets {
    record_sets: HashMap<(u16, u16), RRsetEntry>, // (qtype, qclass) -> entry
}

/// One cached RRset: the answer data for exactly one (name, qtype, qclass),
/// stored once regardless of how many different requesters' flag
/// combinations end up served from it.
struct RRsetEntry {
    records: Vec<StoredRecord>,
    rrsigs: Vec<StoredRecord>,       // empty if none were fetched/cached
    response_code: ResponseCode,     // almost always NoError; kept for parity
                                      // with today's CachedResponse shape
    minimum_ttl: Duration,
    stored_at: SystemTime,
    expires_at: SystemTime,
    dnssec_state: DnssecState,
    cache_namespace: String,         // see §5 — namespace is no longer part
                                      // of the lookup key, so it must be
                                      // stored per entry instead
}

/// A single stored resource record, minus anything request-specific
/// (original casing, transaction id, etc. — those are applied at serve
/// time, §7). Reuses the existing `RecordData` type from `src/protocol`.
struct StoredRecord {
    rtype: u16,
    rclass: u16,
    ttl_at_store: u32,
    rdata: RecordData,
}

/// Mirrors RFC 6840 §3.1's "BAD cache" concept and the Unbound/BIND
/// internal validation-state tracking described in claude-research.md B.3.
/// Every entry starts and stays `Unvalidated` until real DNSSEC validation
/// is implemented (out of scope here) — this enum exists so that future
/// work doesn't need to change the cache shape again.
enum DnssecState {
    Unvalidated,
    Insecure,
    Secure,
    Bogus(String), // reason, for diagnostics; short negative-style TTL applies
}
```

### 3.2 Negative cache (per shard, separate structure)

Per interview Q12, negative answers are **not** folded into
`DomainRecordSets`. They get their own per-domain map so "no data of this
type" and "this type's data" can never be confused, and so a positive
`RRsetEntry` for one qtype coexisting with a negative result for a
different qtype on the same name is representationally natural rather than
a special case.

```rust
struct NegativeShardState {
    domains: HashMap<String, DomainNegativeEntries>,
}

struct DomainNegativeEntries {
    entries: HashMap<NegativeKey, NegativeEntry>,
}

/// `qtype: None` represents a whole-name NXDOMAIN (RFC 2308) — the name
/// itself doesn't exist, independent of any specific qtype. `qtype:
/// Some(t)` represents NODATA for that specific type at an existing name.
struct NegativeKey {
    qtype: Option<u16>,
    qclass: u16,
}

struct NegativeEntry {
    kind: NegativeCacheKind,   // reuse existing enum: NxDomain | NoData
    /// The covering SOA record itself (owner, RDATA, TTL) — needed to
    /// rebuild the authority section of a servable negative response, not
    /// just to derive negative TTL. `soa_owner`/`soa_minimum_ttl` as
    /// separate scalar fields (today's NegativeCacheMetadata shape) are
    /// redundant once the full record is stored; derive them from this
    /// instead of duplicating.
    soa_record: StoredRecord,
    /// RRSIG covering `soa_record`, if DNSSEC data was fetched. None until
    /// real validation exists (mirrors DnssecState::Unvalidated on the
    /// positive side).
    soa_rrsig: Option<StoredRecord>,
    /// NSEC/NSEC3 (+ their RRSIGs) proving the negative result, if
    /// fetched. Empty today (no DNSSEC validation is implemented, per
    /// claude-spec.md's DNSSEC scope decision) — the field exists so
    /// RFC 8198 aggressive negative caching doesn't require another
    /// reshape later (claude-research.md B.3).
    proof_records: Vec<StoredRecord>,
    stored_at: SystemTime,
    expires_at: SystemTime,
    cache_namespace: String,
}
```

**Reconciling with `claude-spec.md`'s `(name, qtype-or-ANY, SOA-owner)`
phrasing**: that phrasing (carried over from the research doc's PowerDNS
description) is not a instruction to make SOA owner part of the lookup
key. Keeping SOA owner as *stored data* on the entry rather than a key
component is deliberate: there is exactly one active negative result per
(name, qtype) at a time — whichever SOA currently covers it — and this
matches how `NegativeCacheMetadata.soa_owner` is already treated as data,
not a key, in the current implementation (`mod.rs:591-598`). Making it a
key component would allow multiple simultaneous, potentially-conflicting
negative proofs for the same (name, qtype), which is not desired.

### 3.3 Why positive and negative share a shard but not a map

Both maps are keyed by the same normalized domain name and live behind the
same shard lock, because a single domain's LRU recency (§4) must account
for *all* cached data about it — positive and negative — as one eviction
unit (interview Q6: capacity counts **domains**, not individual record
sets). Splitting the maps keeps the negative-cache semantics clean (Q12)
without splitting the recency/capacity accounting, which would make "count
domains" ambiguous (does a domain with only a negative entry count? this
design says yes, uniformly).

## 4. Exact per-shard LRU

Per interview Q1/Q2, each shard tracks recency with an ordered structure
instead of the current ghost-token `VecDeque`, giving **O(log n)
average-case touch/evict**, no periodic full-scan compaction, and exact
(not approximate) ordering within the shard.

```rust
struct ShardLru {
    /// Ordered by (sequence, domain) so the numerically smallest entry is
    /// always the least-recently-touched domain in this shard.
    order: BTreeSet<(u64, String)>,
    /// Reverse index: domain -> its current sequence number, so a touch
    /// can find and remove its old position in `order` in O(log n) instead
    /// of scanning.
    positions: HashMap<String, u64>,
    next_sequence: u64,
}

impl ShardLru {
    /// Records that `domain` was just accessed (hit or store). Removes its
    /// old `(sequence, domain)` pair from `order` (O(log n)) if present,
    /// assigns a fresh sequence, and reinserts (O(log n)). Unlike today's
    /// ghost-token design, there is never more than one entry per domain
    /// in `order` — no compaction pass is ever needed.
    fn touch(&mut self, domain: &str) { ... }

    /// Removes `domain` from LRU tracking entirely (used when a domain's
    /// last record set/negative entry is deleted, whether by eviction,
    /// expiry, or the namespace sweep in §5).
    fn remove(&mut self, domain: &str) { ... }

    /// Returns the least-recently-touched domain without removing it, for
    /// the eviction loop to consult.
    fn peek_oldest(&self) -> Option<&str> { ... }
}
```

Eviction (on store, when a shard's domain count reaches its share of
`max_entries`, see §8): pop `order`'s minimum via `peek_oldest` +
`remove`, delete that domain from both `PositiveShardState.domains` and
`NegativeShardState.domains`. This is O(log n) per evicted domain — there
is no scenario in normal operation (bounded eviction, single-domain touch)
that costs more than O(log n). The **only** O(n) operation in this design
is the namespace sweep below, exactly matching the spec's goal 2 target.

## 5. Bulk invalidation: explicit namespace sweep

Today, `cache_namespace` is baked into every flat `CacheKey`, so a
namespace change (SIGHUP reload with a backend-affecting config change —
`docs/caching.md` §2) makes every old entry instantly unreachable "for
free," at the cost of orphaned capacity until eviction/expiry catches up
(G4/G5). **That trick no longer applies**: the new key is just the domain
name, with no namespace component, so namespace can no longer do the
invalidation by itself.

Per interview Q4, this rework replaces the implicit trick with an
**explicit active sweep**, run once per namespace change:

```rust
/// Called once, after a new BackendSnapshot is published (the same
/// SIGHUP-reload trigger point that recomputes cache_namespace today —
/// see main.rs's resolver.publish_reload(...) call and
/// Config::backend_cache_namespace in src/config/mod.rs). Walks every
/// shard and every record-set/negative-entry within each domain, removing
/// any entry whose stored cache_namespace no longer matches. A domain that
/// loses all of its record sets and its negative entry is also removed
/// from that shard's LRU.
///
/// This is the one deliberate O(n) operation in the design — n is the
/// total number of cached *entries* (RRsets + negative entries) across
/// all shards, not the number of domains: a domain can hold many record
/// sets, and the sweep must inspect each one's stored namespace
/// individually (they may have been cached at different times, some
/// possibly still current). It runs once per reload, not once per
/// request, and pays the cost immediately instead of leaving orphaned
/// capacity behind.
fn sweep_stale_namespace(cache: &ShardedDnsCache, current_namespace: &str) { ... }
```

Each shard's sweep takes that shard's lock for the duration of its own
scan — sweeps across different shards do not need to run under one global
lock, so a reload-triggered sweep does not reintroduce the single-lock
contention this rework removes elsewhere. (Whether shards are swept
sequentially or concurrently is an implementation detail; concurrent is
preferable since shards are already independent, but sequential is
acceptable if it simplifies the reload path — this doesn't affect
correctness either way.)

## 6. Single-flight coalescing, sharded and coarsened

Per interview Q5, coalescing moves from today's full-`CacheKey` granularity
to **per-(name, qtype, qclass)** — a direct consequence of §7 dropping
casing and EDNS bufsize from what identifies "the same query" for caching
purposes. It becomes a second sharded structure, mirroring the cache
shards (same shard-count, same hash-by-domain-name), closing the second
global mutex identified in `docs/caching.md` §6.

```rust
struct SingleFlightShard {
    flights: HashMap<(String, u16, u16), Arc<InFlightMiss>>, // domain, qtype, qclass
}
```

`InFlightMiss`, `SingleFlightTicket`, `SingleFlightLeader`, and their
begin/finish/wait semantics (`docs/caching.md` §6, `mod.rs:3820-3931`)
carry over unchanged in behavior — only the key type and the fact that the
map is now one-per-shard instead of one-global change. The
leader-drop-wakes-followers guarantee
(`single_flight_leader_drop_wakes_followers_and_clears_key`) must keep
passing unmodified.

**Design note for the plan's implementer**: keep single-flight as its own
sharded structure rather than merging it into `ShardState`'s lock. This
preserves the existing separation of concerns (cache storage vs. in-flight
miss tracking are independently testable today, per
`docs/caching.md` §6's description of them as separate mutexes) and avoids
widening the cache-shard critical section to include single-flight
bookkeeping.

## 7. Response assembly moves to serve time

Per interview Q8/Q9/Q13, cache entries stop storing pre-built wire
templates and start storing raw record data (§3). Every cache hit now
assembles the wire response fresh, per request. This is a strictly larger
change in *where* logic lives (serve time, not store time) than in *what*
logic exists — the TTL-aging, transaction-ID-rewriting, and
truncation-decision logic already run per-hit today (`docs/caching.md`
§3); what's new is that record-to-wire serialization also becomes
per-hit instead of happening once at store time.

```rust
/// Replaces today's serialize_cached_response for the new entry shape.
/// Builds a complete wire response from one or more RRsetEntry/
/// NegativeEntry lookups (see §7.1 for CNAME chains), using the
/// *requester's own* question wire bytes for name casing (interview Q9)
/// and the *requester's own* advertised EDNS bufsize for truncation
/// (interview Q13) — both of which are no longer cache-key dimensions,
/// just per-response-assembly inputs.
fn assemble_response(
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
    resolved: &ResolvedAnswer,   // from resolve_from_cache, §7.1
    now: SystemTime,
    allow_udp_truncation: bool,
) -> Vec<u8> { ... }
```

**TTL handling at assembly time — two levels, must not be conflated.**
Today's `age_response_ttls` (`mod.rs:472-481`) ages every record in a
cached response *individually* by wall-clock elapsed time since it was
stored — it does not collapse all records to one shared TTL. Separately,
`minimum_ttl`/`expires_at` on the entry (the minimum TTL across the
RRset, per `docs/caching.md` §4) governs only when the *whole entry*
expires from the cache, not what TTL each record reports on the wire.
`assemble_response` must preserve this split: age each `StoredRecord`'s
own `ttl_at_store` (§3.1) independently by elapsed time since the
`RRsetEntry`'s `stored_at`, capped at each record's own remaining
lifetime — reuse `age_response_ttls`'/`cap_response_ttls`'s per-record
logic rather than substituting the entry-level `minimum_ttl` for every
record's wire TTL, which would be observably wrong for an RRset whose
records were originally cached with different TTLs.

DNSSEC-relevant assembly rules, applied here per RFC 6840 (`claude-research.md`
B.3), now that AD/CD/DO are inputs to assembly rather than key
dimensions:
- Include RRSIGs in the response only if the requester's `dnssec_ok` (DO)
  is set.
- Set the response's AD bit only if the relevant `RRsetEntry`s'
  `dnssec_state` is `Secure` **and** the requester set DO or AD.
- If `checking_disabled` (CD) is false and any relevant `RRsetEntry` is
  `Bogus`, serve SERVFAIL instead of the cached data. If CD is true, serve
  the cached data regardless of validation state.

### 7.1 CNAME chains under a domain-first cache

This is the one place where decomposing the flat cache into per-(name,
type) RRsets adds real complexity the old design didn't have: a query
answered via a CNAME chain today caches (and replays) one flat template
covering the whole chain. Under this design, each name in the chain is a
separate `DomainRecordSets` lookup — plausibly in a **different shard**
than the one the original query name hashed to.

```rust
/// Walks a (possibly empty) CNAME chain starting at `qname`, doing one
/// independent per-shard lookup per name in the chain, up to a bounded
/// depth. Reuses `max_cname_restarts` (the existing per-resolve config
/// bound already enforced by the recursive backend, `mod.rs:5520`, checked
/// at `mod.rs:6000`) as the chain-depth limit rather than introducing a
/// second, possibly-inconsistent one.
///
/// **Lock discipline (required, not optional)**: never hold more than one
/// shard's lock at a time while walking. For each hop: acquire that name's
/// shard lock, clone whatever `RRsetEntry`/`NegativeEntry` data is needed,
/// release the lock, *then* move to the next name. Holding a lock across
/// hops risks deadlock (two chains crossing shards in opposite order) or
/// self-deadlock (a later hop hashing back to an already-held shard).
/// Track visited names within one call to guard against cyclical cached
/// data defensively — the backend already prevents storing a cycle, but
/// cache entries are long-lived and independently expirable, so treat this
/// as a cache-layer invariant, not just an inherited guarantee.
///
/// Returns enough information for assemble_response to build a complete
/// answer, or a variant indicating the cache doesn't (fully) have it, so
/// the caller falls back to backend resolution.
fn resolve_from_cache(
    cache: &ShardedDnsCache,
    qname: &str,
    qtype: u16,
    qclass: u16,
    current_namespace: &str,
    now: SystemTime,
) -> ChainLookup { ... }

enum ChainLookup {
    /// Every name in the chain was found, unexpired, in the current
    /// namespace.
    Answered(ResolvedAnswer),
    /// Whole-name NXDOMAIN at some point in the chain.
    NxDomain(NegativeEntry),
    /// NODATA for the queried type at the terminal name.
    NoData(NegativeEntry),
    /// Any name in the chain missed, expired, or was stale-namespace —
    /// caller must fall back to backend resolution. (No partial-chain
    /// caching of a backend re-fetch — that's a store-side concern, not
    /// this function's.)
    Miss,
}
```

This decomposition is a net win, not just added complexity: a CNAME
target's own record set becomes independently reusable by any other query
that names it directly, which the current one-entry-per-original-query
design can't do. This matches how Unbound structures its RRset cache
underneath its message cache (`claude-research.md` B.3) — the "message
cache" concept (one entry per original query, referencing shared RRsets)
doesn't need to be reintroduced here as its own layer since single-flight
(§6) and the chain-walker above already do the equivalent job on the read
path.

### 7.2 Prefetch: reserved hook point, not implemented in this rework

Refreshing a hot record set shortly before/at TTL expiry (so a popular
name never actually misses) was raised during plan review as a
capability worth checking for, but is **not part of this rework's scope**
— it's a new capability, not one of the three original goals, and the
current codebase has no prefetch logic today (`docs/caching.md` doesn't
mention it; nothing like it exists to preserve or migrate). This section
exists only to record that the data model above was deliberately checked
against this requirement and needs no reshape to support it later:

- `RRsetEntry.stored_at`/`expires_at`/`minimum_ttl` (§3.1) already carry
  everything needed to decide "this record set is close to expiring" — no
  new field is required just to detect the condition.
- The sharded single-flight structure (§6) is the correct primitive to
  dedupe a prefetch trigger: a future prefetch implementation would call
  the same `begin()`/`finish()` path a normal miss uses today, keyed by
  the same `(name, qtype, qclass)`, so concurrent hits landing in the
  "about to expire" window collapse into one background refresh instead
  of stampeding upstream.
- The one invariant a future prefetch implementation must respect, stated
  here so it isn't rediscovered the hard way: **never trigger the
  background refetch while still holding the shard lock** — the trigger
  check (comparing `now` to `expires_at`) happens inside a lookup's
  existing critical section, but the actual upstream I/O must start only
  after that lock is released, exactly mirroring how single-flight
  registration already happens strictly after (not inside) today's cache
  lookup (`claude-research.md` A.1). Doing otherwise would reintroduce the
  lock-held-during-I/O problem this whole rework exists to remove.

No config knobs, trigger thresholds, or background-task wiring are added
by this plan — a follow-on plan should scope those when prefetch is
actually prioritized.

## 8. Configuration

Per interview Q7 (G10 fixed, G11 stays out of scope), capacity and shard
count move from `main.rs`'s hardcoded `DEFAULT_CACHE_ENTRIES = 10_000`
into `src/config`, alongside `RuntimeConfig`:

```rust
pub struct CacheConfig {
    /// Total domain-count capacity across the whole cache (interview Q6:
    /// counts domains, not individual record sets). Replaces the current
    /// main.rs DEFAULT_CACHE_ENTRIES constant. Default: 10_000, preserving
    /// today's behavior for anyone not setting this explicitly.
    pub max_entries: usize,
    /// Number of shards. None means "pick a sensible default" (interview
    /// Q11) — a power of two near available_parallelism, following the
    /// DashMap/RocksDB convention of roughly 4x parallelism noted in
    /// claude-research.md B.1.
    pub shard_count: Option<usize>,
}
```

**Per-shard capacity must sum exactly to `max_entries`, not merely
approximate it.** Naively giving every shard `ceil(max_entries /
shard_count)` overshoots the configured total — e.g. `max_entries=10,
shard_count=8` gives each shard capacity 2, an effective ceiling of 16,
silently violating the configured bound. Instead, distribute the
remainder explicitly: shard `i`'s capacity is `max_entries / shard_count`
(integer division), plus one extra if `i < max_entries % shard_count`.
This sums to exactly `max_entries` for any `shard_count`, and correctly
gives every shard capacity 0 (preserving the existing "zero capacity
stores nothing" invariant, `mod.rs:12213`) when `max_entries == 0`.

Wire `RuntimeConfig.cache: CacheConfig` through the same config-parsing
path as the existing `resolution`/`metrics` fields
(`src/config/mod.rs:30-40`). `main.rs` constructs the sharded cache from
this config instead of the hardcoded constant.

## 9. Call sites that change

### 9.0 New cache trait boundary

Today's `DnsCache` trait (`mod.rs:4435-4439`) is shaped around a flat
key: `lookup(&CacheLookupRequest) -> CacheLookup` and
`store(CacheStore) -> ()`. That shape doesn't fit a domain-first,
chain-aware cache — it needs replacing, not adapting. The new interface
(name/exact signatures are the implementer's call; this defines the
required surface):

```rust
trait DomainDnsCache: Send + Sync {
    /// Chain-aware lookup — replaces the old flat `lookup`. Internally
    /// calls resolve_from_cache (§7.1).
    fn lookup_chain(
        &self,
        qname: &str,
        qtype: u16,
        qclass: u16,
        namespace: &str,
        now: SystemTime,
    ) -> ChainLookup;

    /// Replaces the old flat `store` — called once per backend response,
    /// internally decomposing into the RRsetEntry/NegativeEntry stores
    /// described in §9's cache_store_for_response entry.
    fn store_response(&self, decomposed: DecomposedResponse, namespace: &str);

    /// Runs the §5 sweep; called from the reload path.
    fn sweep_stale_namespace(&self, current_namespace: &str);

    /// Approximate (sum-across-shards, no single lock) domain count, for
    /// the metrics gauges in §9's OpenTelemetryMetrics entry.
    fn domain_count(&self) -> usize;

    fn capacity(&self) -> usize;
}
```

`NoopDnsCache` (`mod.rs:4441-4451`) gets an equivalent no-op
implementation of this trait for the same reason it exists today
(disable caching entirely via config).

### 9.1 Existing call sites

Everything below currently assumes a flat `CacheKey`
(`claude-research.md` A.3) and needs updating for the new shape:

- **`probe_cache`** (`mod.rs:3380-3429`) — instead of building one
  `CacheKey` and calling `cache.lookup()` once, calls
  `resolve_from_cache` (§7.1) with `(qname, qtype, qclass)` plus the
  current `cache_namespace` (still computed the same way — per-config, on
  `BackendSnapshot` publish — just no longer folded into a stored key).
- **`cache_store_for_response`** (`mod.rs:3688-3717`) — instead of one
  `CacheStore { key, .. }`, decomposes a backend response into: an
  `RRsetEntry` store per (name, qtype, qclass) actually present in the
  answer, including every CNAME hop's own RRset; **and, additionally**, if
  the response's terminal result is negative (NXDOMAIN, or NODATA at the
  chain's terminal name), a `NegativeEntry` store for that terminal name.
  These are not mutually exclusive — a CNAME chain ending in NODATA stores
  both the CNAME RRset(s) along the way *and* the terminal negative entry,
  matching how `negative_covered_name` already walks the chain to find
  what the SOA needs to cover today (`mod.rs:780-796`).
- **`SingleFlightMisses` registration** (`mod.rs:3827-3931` and its call
  sites in the resolve path) — moves to `(name, qtype, qclass)` keying
  per §6.
- **`serialize_cached_response`** (`mod.rs:4228-4256`) — replaced by
  `assemble_response` (§7); the TTL-aging and truncation logic it already
  contains should be reused/adapted, not rewritten from scratch, since
  those rules are unchanged (only the input shape — raw records instead of
  a pre-built template — changes).
- **`OpenTelemetryMetrics`** (`main.rs:842-863`) — currently holds
  `Arc<InMemoryDnsCache>` directly and calls `cache.len()`/`cache.capacity()`
  on the concrete type for two Prometheus gauges. The new sharded cache's
  `len()`-equivalent (`domain_count()`) sums across shards without a
  single global lock — this makes the gauge an eventually-consistent
  approximation under concurrent mutation instead of an exact
  point-in-time read. This is an acceptable, standard tradeoff for a
  sharded structure (the same tradeoff DashMap's `len()` makes) and should
  be noted in the gauge's help text if OpenTelemetry metric metadata
  supports it, but does not need a design workaround.
- **`Config::backend_cache_namespace`** (`src/config/mod.rs:218-242`) —
  unchanged in how it's computed; what changes is what happens when it
  changes (§5's sweep, instead of the current implicit-key-change trick).
  The call site that currently just recomputes the namespace on reload
  (`main.rs`'s `resolver.publish_reload(...)` path) gains a call to
  `sweep_stale_namespace`.
- **`tests/recursive_perf.rs:141-148`** (`resolver_with_cache` helper) —
  constructs `InMemoryDnsCache::new(256)` directly for a benchmark; needs
  updating to construct the new sharded cache type instead. Easy to miss
  since it's a test helper, not production code, but the benchmark won't
  compile without it.

## 10. Suggested module layout

`src/resolver/mod.rs` is already large (`docs/caching.md` notes it's the
single file all cache line-number references point into, and it's well
over ten thousand lines). Given this rework replaces essentially all
cache-related code in that file, split it out into a dedicated module
rather than growing `mod.rs` further:

```
src/resolver/
  mod.rs                  # unchanged responsibilities minus cache internals;
                           # imports from resolver::cache instead
  cache/
    mod.rs                 # ShardedDnsCache, DnsCache trait impl, public API
    shard.rs                # Shard, ShardState, PositiveShardState,
                             # NegativeShardState, eviction loop
    lru.rs                   # ShardLru (BTreeSet + HashMap side-index, §4)
    entry.rs                  # RRsetEntry, StoredRecord, DnssecState,
                               # NegativeEntry, NegativeKey (§3)
    singleflight.rs             # ShardedSingleFlight, InFlightMiss,
                                 # SingleFlightTicket/Leader (§6, mostly
                                 # moved verbatim from mod.rs)
    assemble.rs                  # assemble_response, resolve_from_cache,
                                  # ChainLookup (§7)
    namespace.rs                  # sweep_stale_namespace (§5)
```

`DnsCache` trait, `CacheLookup`, `CacheStore`/`CacheLookupRequest`-equivalent
request/response shapes stay wherever callers expect them (likely
re-exported from `resolver::cache` back through `resolver::mod` so
`probe_cache` and friends don't need import-path churn beyond what this
rework already requires).

## 11. Testing strategy

`claude-research.md` A.4 lists the ~16 existing tests that touch the
cache. This rework needs to address each one — not necessarily preserve
its literal behavior (some, like the casing/bufsize-fragmentation tests,
test behavior this rework deliberately removes, per Q9/Q13), but decide
explicitly what happens to it:

- **Tests to rewrite for the new shape, same intent**: eviction-order
  tests (`in_memory_cache_evicts_least_recently_used_entry_when_bounded`),
  expiry tests (`in_memory_cache_expires_entries_on_lookup`,
  `in_memory_cache_prunes_expired_entries_before_eviction`), zero-capacity
  behavior (`in_memory_cache_zero_capacity_stores_nothing`), and the
  resolve-level integration tests (cached-template reuse, TTL aging,
  malicious-CNAME blocking on both direct and coalesced-miss paths,
  request coalescing itself, `backend_generation_separates_cache_entries`
  — the last one becomes a namespace-sweep test, §5;
  `resolve_truncates_oversized_cached_response_for_current_request`,
  `mod.rs:13888`, and `resolve_treats_expired_cache_backend_hit_as_miss`,
  `mod.rs:13924`, both directly exercise serve-time assembly/expiry
  mechanics this rework changes, though not the observable contract).
- **Tests to delete, deliberately**: `cache_key_from_query_includes_supported_semantics`
  and `cache_key_separates_exact_wire_question_casing_for_templates`
  assert exactly the key-fragmentation behavior this rework removes
  (casing, EDNS bufsize, and folding `QueryFeatures` into the lookup key
  all go away, Q9/Q13). Replace with tests asserting the *opposite*: that
  differently-cased or differently-bufsize'd requests for the same name
  now share one entry.
- **`in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits`** — this
  test exists specifically to verify the ghost-token compaction threshold
  behavior. That mechanism is gone entirely (§4 has no ghost tokens); this
  test is replaced by one asserting the new LRU has exactly one live
  position per domain at all times, regardless of repeat-hit count.
- **New tests required**: a domain with multiple cached qtypes sharing one
  LRU/capacity slot (validates Q6); a `DnssecState` field present and
  defaulting to `Unvalidated` on stored entries (validates Q3's
  shape-readiness without validation logic); negative and positive entries
  for the same name coexisting and being evicted together (validates §3.3);
  the namespace sweep actually removing stale entries and leaving current
  ones (validates §5's O(n)-only-on-invalidation claim); CNAME chain
  resolution spanning multiple shards (§7.1).
- **New concurrency benchmark, per interview Q10**: closes G8
  (`docs/caching.md` — "no test or benchmark exercises the cache under
  real concurrent load"). Needs multiple threads issuing concurrent
  lookups/stores across a mix of colliding and non-colliding domain names,
  measuring throughput or contention (e.g. total wall-clock time for a
  fixed workload) with the new sharded design vs. a single-mutex baseline
  — the existing `tests/recursive_perf.rs` runs sequentially
  (`--test-threads=1`, `#[ignore]`d) and is not a suitable home for this;
  either a new `#[ignore]`d perf test alongside it, or a `just bench`
  target, following that file's existing conventions for how
  network/timing-sensitive tests are kept out of the default `cargo test`
  run.

Full TDD test-first stubs for each of the above are produced in the next
planning stage (`claude-plan-tdd.md`), not this document.

## 12. Rollout

Per interview Q14: straight in-place rewrite, no feature flag, no
dual-running old and new implementations. Suggested implementation order
(each step should land with its own tests passing before the next
begins, even though this document doesn't prescribe literal commit
boundaries):

1. New data model + per-shard LRU (§3, §4) with unit tests, no wiring into
   the resolver yet.
2. Sharded single-flight (§6) as a standalone replacement for
   `SingleFlightMisses`, unit-tested independently.
3. Response assembly + CNAME chain walking (§7) against the new data
   model, unit-tested against hand-constructed cache state.
4. Namespace sweep (§5), unit-tested for the "some domains partially
   stale" case described in §3.3/§5.
5. Config wiring (§8).
6. Call-site migration (§9) — `probe_cache`, `cache_store_for_response`,
   `main.rs` construction and metrics gauges.
7. Test migration/rewrite (§11), then the new concurrency benchmark.

This order front-loads the genuinely new logic (data model, LRU,
assembly, sweep) where it can be tested in isolation, and leaves the
mechanical call-site rewiring for last, once the new pieces are known to
work on their own.
