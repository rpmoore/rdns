# DNS Resolver Caching — Current Implementation

Describes caching as actually implemented today (snapshot as of
2026-07-09). This is a snapshot of the code, not a design proposal — see
`docs/plan/02-resolver-cache.md` (original design intent) and
`docs/plans/cache_key.md` (a landed key-simplification change) for history.
All line numbers reference `src/resolver/mod.rs` unless stated otherwise.

There are **two independent in-memory caches** in this codebase. Don't
conflate them:

| | Answer cache (`InMemoryDnsCache`) | Delegation cache (`DelegationCache`) |
|---|---|---|
| Caches | Final client-facing response templates | NS/glue delegation info for recursive resolution |
| Keyed by | `CacheKey` (question + features + namespace) | zone name |
| Used by | Both forward and recursive modes | Recursive backend only, internally |
| Trait | Implements `DnsCache` | No trait, backend-internal only |
| Eviction | TTL + approximate LRU, entry-count bound | TTL + FIFO, entry-count bound (4096, `mod.rs:5573`) |

This document covers the **answer cache**, which is what "the DNS cache"
means everywhere else in the codebase and what client-visible cache
hit/miss behavior depends on. The delegation cache gets one paragraph at
the end.

## 1. What gets cached, and why

`ResolveQuery::resolve` runs, in order: policy check → local static-entry
check → cache probe → backend resolution → cache store (`mod.rs:2893-2912`
and `probe_cache`, `mod.rs:3380-3429`). Two request classes never touch the
cache at all:

- **Policy-blocked queries** (`try_policy_block`, `mod.rs:2995-3027`) — the
  block response is synthesized fresh every time.
- **Local static-entry matches** (`try_local_lookup`, `mod.rs:3033-3078`) —
  answers built from the in-memory local-entries snapshot, never cached and
  never read from cache.

Only queries that reach the backend (forward or recursive resolution) are
candidates for caching, and only if the resulting response is *cacheable*
(§4) and the query itself didn't ask for something the cache layer doesn't
understand (§5).

## 2. What's used to index into the cache

`CacheKey` (`mod.rs:218-249`):

```rust
pub struct CacheKey {
    pub question: QuestionKey,       // lowercased/trailing-dot-stripped name, qtype, qclass
    pub question_wire: Vec<u8>,      // exact wire bytes of the question, incl. original casing
    pub features: QueryFeatures,     // RD, AD, CD, DO, raw EDNS UDP bufsize
    pub cache_namespace: Option<String>,
}
```

Notable properties:

- **Case-sensitive wire bytes are part of the key** (`question_wire`,
  `cache_key_separates_exact_wire_question_casing_for_templates`,
  `mod.rs:12305`). Two requests for `example.com` and `Example.COM` get
  separate cache entries even though `QuestionKey` normalizes the name,
  because the cached *template* is built from one specific requester's wire
  encoding and reused as-is (transaction ID and TTLs get rewritten per
  request, but the name bytes don't).
- **UDP and TCP share entries.** There used to be a separate
  `effective_udp_payload_size` field that fragmented the key by transport
  and EDNS bufsize class (see `docs/plans/cache_key.md`); that field has
  been removed. `probe_cache` (`mod.rs:3380-3429`) builds one key
  regardless of transport, and `resolve_shares_cache_entry_between_udp_and_tcp_queries`
  (`mod.rs:10624`) proves a UDP miss followed by a TCP query for the same
  question is a hit. Per-request UDP truncation is decided fresh at serve
  time (`serialize_cached_response`, `mod.rs:4228-4256`), not by key
  partitioning. The *raw* advertised EDNS bufsize (`QueryFeatures.edns_udp_payload_size`)
  still fragments the key — that part was explicitly kept (see "Out of
  scope" in `cache_key.md`), so `dig` from two stub resolvers advertising
  different EDNS bufsizes for the same name still get separate entries.
- **`cache_namespace` is the invalidation lever — but it doesn't cover
  every backend-affecting setting.** It's an opaque string folded into
  every key so that changing what the backend *would* answer invalidates
  the whole cache without an explicit sweep — a different namespace is a
  different key, so old entries simply become unreachable (they still
  occupy a slot until evicted/expired, see §7). Computed by
  `Config::backend_cache_namespace` (`src/config/mod.rs:218-242`):
  - Forward mode: `mode:forward;generation:{n};upstreams:{hash}` — the hash
    (`forwarding_upstream_set_hash`, `config/mod.rs:244-262`) covers
    name/endpoint/protocol/priority/timeout of every enabled UDP upstream,
    so adding, removing, reordering, or retiming an upstream auto-invalidates
    the cache.
  - Recursive mode: `mode:recursive;generation:{n};root-hints:{version};dnssec:{label};authorities:{hash}`.
  - `generation` is an operator-set integer in config (`ResolutionConfig::generation`,
    `config/mod.rs:289-291`), not auto-incremented — bumping it is the
    manual "flush everything" lever.
  - Recomputed only when a new `BackendSnapshot` is published, i.e. on
    SIGHUP reload (`main.rs:597-635` → `resolver.publish_reload(...)`).
  - **Exception:** `RuntimeConfig::per_query_deadline` is *not* part of the
    hash (`config/mod.rs:218-262` — only the upstream set's own per-upstream
    `timeout` is hashed, not the global deadline). A SIGHUP that only
    tightens or loosens `per_query_deadline` changes how long resolution is
    allowed to run — and therefore can change whether a given query now
    times out to SERVFAIL — without changing `cache_namespace`, so answers
    cached under the old deadline stay addressable under the same key. The
    cached *content* isn't wrong, but "changing what the backend would
    answer invalidates the whole cache" isn't quite true for this one
    setting.
  - Local DNS entry changes do **not** touch `cache_namespace` — they don't
    need to for correctness of the local answers themselves, since local
    entries are checked before `probe_cache` ever runs and are never stored
    in this cache. But this can still surface stale *backend* answers: if a
    name was resolved and cached before a local entry for it existed, then
    the local entry is later removed (e.g. on reload), `try_local_lookup`
    stops shadowing that name and the next query falls through to
    `probe_cache` — which may still hold the old, unexpired backend-cache
    entry from before the override existed. Removing a local entry can
    un-shadow an old cached answer rather than guarantee a fresh lookup.

## 3. What's stored per entry

```rust
// mod.rs:579-587
pub struct CachedResponse {
    pub response_template: Vec<u8>,   // full, untruncated wire response, id rewritten to 0
    pub response_code: ResponseCode,
    pub minimum_ttl: Duration,
    pub negative_cache: Option<NegativeCacheMetadata>,
    pub stored_at: SystemTime,
    pub expires_at: SystemTime,
}
```

The stored bytes are the complete answer, not a truncated-for-someone
copy — every cache entry can serve both UDP and TCP requesters. Serving a
hit (`serialize_cached_response`, `mod.rs:4228-4256`) clones the template,
rewrites the requester's transaction ID/flags, ages TTLs by elapsed time
since `stored_at`, caps them to remaining lifetime, and only then decides
whether to truncate for the *current* request's UDP payload size. This
re-derivation happens on every hit, not just once.

## 4. TTL / expiry policy

`CacheTtlPolicy` (`mod.rs:623-725`), defaults:

| Field | Default |
|---|---|
| `max_positive_ttl` | 24h |
| `min_positive_ttl` | none |
| `max_negative_ttl` | 1h |
| `min_negative_ttl` | none |
| `failure_ttl` (SERVFAIL) | `None` — SERVFAIL is not cached unless explicitly configured, and even then capped at 5 minutes (`MAX_FAILURE_CACHE_TTL`, `mod.rs:50`) |

Positive TTL = minimum TTL across all answer records, then
`ttl.min(cap).max(floor).min(cap)` (`apply_ttl_bounds`, `mod.rs:1492-1498` —
the trailing `.min(cap)` guarantees a configured floor can't push the
effective value back over the ceiling).

Negative TTL (NXDOMAIN / NODATA) is derived per RFC 2308 from the SOA
record in the response's authority section: `min(SOA TTL, SOA MINIMUM)`
(`negative_ttl`, `mod.rs:746-777`). This requires the SOA's owner name to
be at-or-above the covered name and its class to match the question — if
no covering SOA is present, negative caching is refused outright
(`ttl_policy_rejects_negative_cache_when_soa_does_not_cover_name`,
`mod.rs:11565`). CNAME chains are walked to find the real terminal name
the SOA needs to cover (`negative_covered_name`, `mod.rs:780-796`).

## 5. Cache bypass conditions

| Condition | Where |
|---|---|
| EDNS present with nonzero extended rcode/version, non-DO flags, or any EDNS option | `cache_supported`, `mod.rs:4179-4191` |
| Cache backend returns `Bypass`/`Unavailable` | `evaluate_cache_lookup`, `mod.rs:3459-3468` |
| Response question doesn't match request, or ≠1 question | `cache_store_for_response`, `mod.rs:3696-3702` |
| Response code not cacheable (only `NoError`+answers or SOA-backed negative, or configured-only SERVFAIL) | `CacheTtlPolicy::ttl_for_response`, `mod.rs:653-711` |
| Backend explicitly marks `ResolutionCacheDirective::DoNotCache` | `prepare_backend_result`, `mod.rs:3593-3605` |
| Would-be entry expires immediately (TTL rewritten to 0) | `store_now`, `mod.rs:5406-5411` |
| `max_entries == 0` configured | `store_now`, `mod.rs:5399-5403` |
| Response-content policy blocks a freshly-resolved answer | `prepare_backend_result`, block check precedes store, `mod.rs:3573-3605` |

## 6. Concurrency model

```rust
// mod.rs:5322-5337
pub struct InMemoryDnsCache {
    max_entries: usize,
    state: Mutex<InMemoryDnsCacheState>,   // std::sync::Mutex — one global lock, not sharded
}
struct InMemoryDnsCacheState {
    entries: HashMap<CacheKey, InMemoryDnsCacheEntry>,
    lru: VecDeque<(CacheKey, u64)>,        // append-only "ghost queue" LRU approximation
    next_sequence: u64,
}
```

One `std::sync::Mutex` guards the entire cache — every lookup and every
store for every key funnels through this single lock. It's never held
across an `.await` (`lookup`/`store` on the `DnsCache` trait wrap the sync
`lookup_now`/`store_now` in `Box::pin(async move {...})` with no await
inside, `mod.rs:5489-5499`), so it can't deadlock or get cancelled mid-hold
the way an `.await`-spanning lock could. That does **not** make it free of
async task starvation, though: `Mutex::lock()` blocks the calling OS
thread, and that thread is a Tokio worker running other tasks' futures.
While one task holds this lock through the O(n) scan in G1 (§8), the
worker thread it's running on can't poll any other task, so unrelated
async work scheduled on that thread stalls until the scan finishes — a
real (if bounded, single-worker-at-a-time) starvation effect, not just
lock-wait latency. It is still a single serialization point across every
concurrent request regardless of which key they touch (see §8).

Separately, **request coalescing** (`SingleFlightMisses`, `mod.rs:3826-3931`)
uses its own global `std::sync::Mutex<HashMap<CacheKey, Arc<InFlightMiss>>>`,
keyed identically to the cache. The first concurrent miss for a key becomes
the "leader" and does the real upstream resolve; concurrent misses for the
same key become "followers" that `tokio::sync::Notify`-wait on the leader,
then re-run a normal cache lookup once it completes (`mod.rs:3472-3489`) —
so a follower goes through the same TTL/serialize path as any other hit,
rather than getting a raw clone of the leader's bytes. If the leader's
response turns out non-cacheable, followers fall back to the leader's raw
backend result instead of doing their own upstream round-trip
(`mod.rs:3232-3248`). A `Drop` guard on the leader ensures followers are
never left hanging if the leader task panics or is cancelled
(`single_flight_leader_drop_wakes_followers_and_clears_key`, `mod.rs:14140`).

Request handling itself is one task per datagram/connection
(`UdpDnsServer::serve_until`, `src/delivery/dns.rs:175-205`): `recv_from`
happens under a bounded `Semaphore` (default 1024 in-flight,
`DEFAULT_MAX_IN_FLIGHT_REQUESTS`, `dns.rs:32`), then each datagram is
handed to a freshly spawned task tracked in a `JoinSet` — the receive loop
does not await resolution before reading the next packet. Tokio runs
multi-threaded (`#[tokio::main]`, default flavor = one worker per core,
`main.rs:67`), so genuinely parallel requests do hit the cache mutex from
multiple OS threads simultaneously.

`TcpDnsServer` spawns one task per *accepted connection* the same way
(its own `Semaphore`/`JoinSet`, plus a per-source-IP cap,
`max_connections`/`max_connections_per_ip`) — so many concurrent TCP
clients do get real parallelism, same as UDP. But **within one TCP
connection, pipelined queries are not concurrent**:
`serve_tcp_connection` (`dns.rs:528-606`) is a single `loop` that reads one
length-prefixed query, `.await`s the full `resolver.resolve(...)`
(`dns.rs:575-581`), writes the response, and only then reads the next
query off the same socket. RFC 7766 §6.2 permits a client to pipeline
several queries back-to-back on one connection without waiting for each
answer; this server accepts that framing but still answers them one at a
time in submission order. A slow query (cache miss, single-flight wait, or
a lock-contended cache op per §8) head-of-line-blocks every later query
pipelined on that same connection, even though it doesn't block other
connections or UDP traffic.

## 7. Eviction / capacity behavior as the cache grows

Capacity is a fixed entry count set at construction:
`InMemoryDnsCache::new(DEFAULT_CACHE_ENTRIES)` where
`DEFAULT_CACHE_ENTRIES = 10_000` (`main.rs:46,105`) — **hardcoded in the
binary, not exposed through `src/config`.** There is no byte-size/memory
bound; a working set of large responses (many-answer RRsets, big TXT
records) inflates memory per entry with no cap other than entry count.

```rust
// mod.rs:5370-5436, abbreviated
fn lookup_now(&self, request) -> CacheLookup {
    // single HashMap::get on the requested key only — targeted expiry check,
    // no full-cache scan
    ...
    state.maybe_compact_lru(self.max_entries);   // O(n) VecDeque::retain, but only
                                                   // if lru.len() > max_entries * 4
}

fn store_now(&self, entry) {
    ...
    if state.entries.len() >= self.max_entries {
        state.remove_expired(now);   // O(n) HashMap::retain over the WHOLE cache
        state.compact_lru();         // O(n) VecDeque::retain
    }
    state.entries.insert(...);
    state.lru.push_back(...);
    state.evict_to_bound(self.max_entries);   // pop_front loop, O(1) amortized
    state.maybe_compact_lru(self.max_entries);
}
```

This replaced an earlier version that ran the O(n) scans on *every* lookup
and store (`docs/review/perf-01.md` Finding 2); both `lookup_now` and
`store_now` are *amortized* O(1) — but neither is unconditionally O(1).
`store_now` has a capacity-gated full scan that, at steady state, isn't
rare at all (§8 G1, the single biggest bottleneck this document
identifies). `lookup_now` calls the same `maybe_compact_lru` as `store_now`
(`mod.rs:5393`) — a sustained run of cache *hits* also pushes one LRU
token per hit and eventually crosses the `4×max_entries` threshold,
triggering the same O(n) `VecDeque::retain` under the lock on a hit path,
not just a miss/store path (§8 G6).

The LRU itself is an approximation, not an exact structure: every touch
(hit or store) appends a `(key, sequence)` token to a `VecDeque` rather
than moving a node in a linked list; a token is "live" only if its
sequence still matches the entry's current sequence. Stale tokens
accumulate until `compact_lru` runs (bounded to `max_entries * 4`
outstanding tokens before a compaction is forced,
`in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits`, `mod.rs:12232`).
This bounds memory (never more than 4x `max_entries` ghost tokens) but
means eviction order is "approximately least-recently-used within the last
~4x-capacity window of touches," not exact LRU.

## 8. Performance under concurrent/parallel load — bottleneck analysis

This is code-inspection analysis (there is no in-repo benchmark exercising
the cache under real concurrent load — see gap G8 below), but it follows
directly from the mechanisms in §6-7.

**G1 — Steady-state-full cache: every `store()` does an O(n) scan, not just some.**
This is the most important finding in this document. Once
`entries.len() >= max_entries` (which is the *normal steady state* for any
resolver serving more unique names than fit in 10,000 slots — a very small
number for a busy resolver), **every single store hits the
`remove_expired` + `compact_lru` branch** (`mod.rs:5412-5415`), because
eviction (`evict_to_bound`) brings the count right back down to exactly
`max_entries` after each insert, so the next store's `len() >=
max_entries` check is true again. If TTLs are long enough that few
entries have actually expired between stores (`remove_expired` finds
little to remove), this degenerates to: **a full `O(n)` `HashMap::retain`
scan over the entire cache, plus a full `O(n)` `VecDeque::retain` scan,
under the single global mutex, on every cache miss that gets stored** —
which is exactly the "O(n) on every access" problem `docs/review/perf-01.md`
Finding 2 set out to fix, reintroduced specifically for the full-cache
case rather than fixed for it. Under concurrent load this compounds: while
one thread holds the lock doing a 10,000+-entry scan, *every other
concurrent request* — even for completely unrelated keys — blocks on the
same mutex. This is precisely the combination the task asked about
(large cache + high parallelism): it's the regime where this cost is worst.

**G2 — No sharding: the cache is one lock domain regardless of key.**
`InMemoryDnsCache` and `SingleFlightMisses` each use exactly one
`std::sync::Mutex` for the whole keyspace (not sharded by key hash, not
`DashMap`). For non-colliding, unrelated concurrent queries (the common
multi-record case — a client resolving several different names, or many
clients querying different domains at once), correctness is fine but
throughput is capped by how fast one thread at a time can run a lookup or
store critical section — cache ops don't parallelize across cores even
though request *handling* does. Under G1's full-scan condition, this
single lock is held for O(n) time instead of O(1), so contention scales
with cache size, not just QPS.

**G3 — Thundering-herd behavior for the same key is handled, but adds its own serialization.**
Single-flight coalescing correctly collapses N concurrent misses for the
same key into 1 upstream call — this works and is tested
(`resolve_coalesces_duplicate_cache_misses`, `mod.rs:13965`). But all N
followers, once woken, re-acquire the *same* cache mutex from §6 to do
their post-wait lookup, so a burst of same-key followers still serializes
through the global cache lock one at a time after the leader completes
(cheap individually — O(1) each outside the G1 condition — but still
serialized, and compounds with G1 if the cache happens to be full at that
moment).

**G4 — Reload-triggered cold-cache stampede.** Because `cache_namespace`
changes wholesale on any backend-affecting config change (upstream set
hash, root hints version, generation bump — §2), a SIGHUP reload that
touches any of those instantly makes 100% of existing entries
unaddressable. The next burst of traffic after a reload is effectively an
all-miss burst — every query becomes a single-flight leader doing a fresh
upstream round trip, and every one of those results in an insert under
the (now key-space-fragmented, growing-from-empty-under-the-old-namespace-orphans)
mutex. This is a correctness-necessary tradeoff (stale answers must not
survive a backend-affecting change) but its performance shape is worth
knowing operationally: a reload is a full cache-cold event, not a partial
invalidation.

**G5 — Orphaned entries under the old namespace aren't reclaimed
proactively.** After a namespace change (G4), old entries are simply
unreachable, not deleted — they still occupy `entries`/`lru` capacity
slots until the *new*-namespace traffic fills the cache and pushes them
out via `evict_to_bound`, or until they expire and get swept by the next
`remove_expired` triggered under G1. Effective usable capacity is reduced
for a while after every reload.

**G6 — Hits aren't exempt either: lock-held cloning and hit-triggered
compaction.** `lookup_now` (`mod.rs:5370-5395`) clones the entire
`CachedResponse` — including the full `response_template` byte buffer —
**while holding the cache mutex** (`mod.rs:5387`). Every hit's critical
section is therefore proportional to that response's size, not O(1)
regardless of size; a cache full of large RRsets (wide `TXT`/`MX` sets,
many-address answers, see G11) makes every hit hold the single global lock
longer, compounding G2's contention for all other concurrent requests
regardless of key. Separately, every hit also calls `maybe_compact_lru`
(`mod.rs:5393`), which pushes one LRU token per hit and, once the ghost
queue crosses `4×max_entries` outstanding tokens, runs the same O(n)
`VecDeque::retain` compaction under the lock (`mod.rs:5446,5460`) that
G1 describes for stores. A sustained high-hit-rate workload — the case
the cache exists to serve well — periodically pays this scan too, it's
just less frequent than the at-capacity store case in G1 because the
threshold is `4×max_entries` touches rather than every single store.

**G7 — TCP pipelining serializes on the resolver, including cache ops,
within one connection.** As noted in §6, `serve_tcp_connection`
(`dns.rs:528-606`) fully awaits `resolve()` — cache lookup, single-flight
wait, and cache store all included — before reading the next pipelined
query on that socket. A client that pipelines several queries (RFC 7766
§6.2) gets them answered strictly in order at the speed of the slowest one
in the batch; a single cache miss or lock-contended cache op (G1, G6) in
the middle of a pipelined batch delays every query queued behind it on
that connection, even though the cache and every other connection are
otherwise healthy.

**G8 — No test or benchmark exercises the cache under real concurrent
load.** `tests/recursive_perf.rs`'s cache-related benchmarks
(`recursive_resolver_perf_with_cache`, `:480`) issue queries in a
sequential loop against one resolver and are `#[ignore]`d (require live
network) — they measure single-threaded hit latency, not throughput or
contention under parallelism. `tests/forwarding.rs` never touches the
cache at all. The only concurrency test in the whole delivery/resolver
path is `udp_server_handles_next_datagram_while_first_request_is_in_flight`
(`src/delivery/dns.rs:1286`), which proves two requests don't serialize on
each other's *upstream I/O*, not that the cache holds up under many
parallel hits/misses/evictions, and nothing exercises TCP pipelining
concurrency (G7) either. None of G1-G7 above are backed by a regression
test; they're derived from reading the store/lookup/connection code paths.

## 9. Other gaps

- **G9 — No periodic/background eviction.** `InMemoryDnsCache::remove_expired`
  (the public maintenance method, `mod.rs:5359-5363`) is never called from
  `main.rs` — there's no sweep task. Expired-but-unbounded-by-capacity
  entries (cache below `max_entries`, long TTLs still technically "not
  expired but stale in practice") linger until touched by a lookup or
  until the cache fills enough to trigger the capacity-based scan in G1.
- **G10 — Capacity is not configurable.** `DEFAULT_CACHE_ENTRIES = 10_000`
  is a `main.rs` constant, not wired to `src/config`. Operators can't tune
  this without a code change/rebuild.
- **G11 — No memory/byte-size bound**, only an entry-count bound — a
  working set with large RRsets (e.g. wide `TXT`, `MX` sets, or many
  addresses per name) has no ceiling on cache memory beyond
  `max_entries × (average response size)`.
- **G12 — No observability into the store-time or hit-time O(n) scans.**
  Existing cache metrics (`CacheHit`, `CacheMiss`, `CacheStore`, etc.,
  `main.rs:799-883`) and the `cache_size`/`cache_capacity` gauges don't
  expose scan frequency/duration, so G1's and G6's cost is invisible in
  production telemetry today. There's no lock-wait-time or
  lookup/store-latency histogram to catch a regression here.
- **Approximate LRU (§7)** means eviction order is "recent within roughly
  the last `4×max_entries` touches," not exact recency — acceptable for a
  cache, but worth knowing if debugging why a hot entry got evicted.

## Delegation cache (recursive mode only)

`DelegationCache` (`mod.rs:5606+`) caches NS/glue delegation info
per-zone for the recursive backend's internal iterative walk. It is
entirely separate from everything above: keyed by zone name (not
`CacheKey`), guarded by its own lock, capacity 4096
(`DEFAULT_DELEGATION_CACHE_CAPACITY`, `mod.rs:5573`), TTL capped at 24h
(`DELEGATION_CACHE_MAX_TTL_SECONDS`, `mod.rs:5579`), and evicted FIFO on
insert past capacity rather than LRU. It doesn't implement `DnsCache` and
never interacts with the answer cache's lock — a client-facing cache hit
never touches it, and a recursive resolve that walks several delegations
takes and releases this lock independently at each hop. It's mentioned
here only so it isn't confused with the answer cache when reading
`resolver/mod.rs`.
