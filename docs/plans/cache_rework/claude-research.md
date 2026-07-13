# Research: answer-cache rework

Combines codebase research (`general-purpose` agent, read-only exploration
of `src/resolver/mod.rs` and friends) and web research (best practices for
sharded caches, O(log n) LRU, DNSSEC caching). Both run 2026-07-09, prior to
the interview. See `docs/caching.md` for the baseline description this
builds on — this file only adds detail relevant to the three planned
changes (lock scoping, exact LRU, domain-first key).

## A. Codebase findings

### A.1 Lock scoping

Two independent `std::sync::Mutex`s today:

- `InMemoryDnsCache.state: Mutex<InMemoryDnsCacheState>` (`mod.rs:5324`) —
  guards `entries: HashMap<CacheKey, InMemoryDnsCacheEntry>`, `lru:
  VecDeque<(CacheKey, u64)>`, and `next_sequence: u64` **together, as one
  atomic unit**. Every method (`len` 5348, `remove_expired` 5360,
  `lookup_now` 5371, `store_now` 5398) takes the lock once and does its
  full read-modify-write inside it.
- `SingleFlightMisses.flights: Mutex<HashMap<CacheKey, Arc<InFlightMiss>>>`
  (`3828`), plus a per-flight `Mutex<Option<Result<...>>>` inside each
  `InFlightMiss` (`3842`). Independently locked from the cache-state mutex
  — no cross-lock invariant assumed between them today. `probe_cache`
  (`3380`) does a cache lookup, then *separately* (different lock
  acquisition) calls into single-flight registration on miss — sharding
  either lock independently is safe; they don't need to be coupled.

**Invariant that any sharding scheme must preserve**: `lookup_now` bumps an
entry's `sequence` and pushes a fresh LRU token together (`5388-5393`);
`store_now` inserts into `entries` and pushes an LRU token together
(`5426-5435`); eviction (`evict_to_bound`, `5466-5480`) pops LRU tokens and
compares `entry.sequence == token.sequence` to detect staleness. **The
sequence counter and the entries it stamps must live in the same lock
domain** — a naive per-key shard is fine as long as `(entries, lru,
next_sequence)` moves as one atomic unit per shard, or `next_sequence`
becomes a global atomic (cheap, since it's already just a `u64` counter with
no other coupling).

**One call site bypasses the `DnsCache` trait and must be accounted for**:
`src/main.rs:842-863` — `OpenTelemetryMetrics::new` holds `Arc<InMemoryDnsCache>`
directly (not `Arc<dyn DnsCache>`) and its two Prometheus `ObservableGauge`
callbacks call `cache.len()` (858) and `cache.capacity()` (862) on the
concrete type. Under sharding, `len()` becomes a sum across shards — no
single lock covers the whole cache anymore, so this becomes an
approximation (a gauge read racing concurrent mutations) unless shards are
locked sequentially for this read. No delivery-layer or admin-API code
reaches into cache internals (grepped `src/delivery/*.rs` for
`.entries`/`.lru`/`state.lock` — no hits; there is no `src/admin` module,
only a planning doc).

### A.2 LRU structure (ghost-token detail)

Full implementation, `mod.rs:5439-5487`:
- `next_sequence` (5440-5444): monotonic `u64`, wraps on overflow.
- `compact_lru` (5446-5453): retains only tokens whose `(key, sequence)`
  still matches the live entry's current sequence.
- `remove_expired` (5455-5458): drops TTL-expired entries from `entries`
  only — does not touch `lru`; relies on the staleness check elsewhere to
  lazily clean up.
- `maybe_compact_lru` (5460-5464): compacts only once `lru.len()` exceeds
  `max_entries * LRU_COMPACTION_MULTIPLIER`.
- `evict_to_bound` (5466-5480): pops `lru.pop_front()` while `entries.len()
  > max_entries`; ghost tokens (stale sequence) are skipped, not counted
  toward eviction.

Repeat hits append a *new* token rather than moving an existing one — that
append-only behavior is the entire reason this is "approximate": there's no
single source of truth for an entry's position, just the newest live token
for it, with older tokens rotting until compaction notices the mismatch.

**Cargo.toml** (root workspace — `.worktrees/check_root_zone_drift/Cargo.toml`
is a stale unrelated worktree copy, ignore it): `bytes`, `domain` (0.12.1),
`http-body-util`, `hyper`, `hyper-util`, `idna`, `opentelemetry`,
`opentelemetry-prometheus`, `opentelemetry_sdk`, `prometheus`, `serde`,
`serde_json`, `socket2`, `tokio` (full), `toml`, `tracing`,
`tracing-subscriber`. Dev-dep: `tokio` `test-util`. **No `indexmap`,
`linked-hash-map`, `lru`, `dashmap`, or `moka` currently in the dependency
tree** — adopting any ordered-map/sharded-cache crate is a new dependency,
not already available.

### A.3 DNSSEC / cache-key call sites

DNSSEC support is a stub today: `src/config/mod.rs:717-719` — `enum
DnssecValidationMode { Disabled }` is the **only variant that exists**; no
`Enabled`/`Validating` mode. `cache_namespace_label()` (`717-727`) always
returns `"disabled"`. There is **no signature-validation logic anywhere in
the codebase** — `RRSIG_RECORD_TYPE`/`NSEC_RECORD_TYPE`/`NSEC3_RECORD_TYPE`/
`NSEC3PARAM_RECORD_TYPE` constants exist (`config/mod.rs:55-58`) but are
only consulted by a record-type-classification helper used to strip
non-cacheable types before storage (`1159-1163`) and in one test fixture.
`QueryFeatures` (`mod.rs:194-216`) already captures `authenticated_data`
(AD), `checking_disabled` (CD), and `dnssec_ok` (DO) per request, and
`CacheKey` folds the whole struct into the key (`219-224`) — so AD/CD/DO
differences already fragment the cache today, matching what `docs/caching.md`
already flags.

**Call sites that assume `CacheKey` is a single flat lookup key** (all need
reshaping for a domain-first/nested-record-set cache): `probe_cache`
(`3380-3429`, one key → one `cache.lookup()`), `cache_hit_after_coalesced_miss`
(`3472-3489`, re-looks-up by the same flat key post-coalesce),
`cache_store_for_response` (`3688-3717`, one `CacheStore { key, .. }` per
response), `SingleFlightMisses` (`3827-3931`, keyed by the same flat
`CacheKey` — needs a decision: stay flat per (question, features) for
dedup purposes even if storage becomes nested, or move dedup to
per-owner-name granularity), and `InMemoryDnsCacheState.entries`/`.lru`
(`5329-5330`, both keyed by flat `CacheKey`). No metrics/observability code
logs by full `CacheKey` value (counters are by `ResolverMetric` variant);
`QueryEventV1` events already carry `original_question_name` as a plain
string independent of `CacheKey` (`finish`, `3729-3823`), which is already
compatible with a domain-first redesign.

### A.4 Existing cache tests

All `InMemoryDnsCache` tests live in the single `#[cfg(test)] mod tests`
block at `mod.rs:6533` (99 `#[test]` fns total in the file). Pure
cache-unit tests, `mod.rs:12078-12253` (8 tests):
`cache_capacity_returns_configured_max_entries`,
`in_memory_cache_returns_unexpired_entry`,
`in_memory_cache_expires_entries_on_lookup`,
`in_memory_cache_evicts_least_recently_used_entry_when_bounded`,
`in_memory_cache_prunes_expired_entries_before_eviction`,
`in_memory_cache_zero_capacity_stores_nothing`,
`in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits`,
`cache_key_from_query_includes_supported_semantics`.

Resolver-level integration tests exercising the cache end-to-end via
`resolve()` (~8 more): `resolve_blocks_cached_response_with_malicious_cname_target`
(13440), `resolve_returns_cached_template_with_current_request_id` (13713),
`resolve_rewrites_cached_response_rd_flag_for_current_request` (13781),
`resolve_ages_cached_response_ttls_for_current_request_time` (13817),
`resolve_caps_cached_response_ttls_to_remaining_cache_lifetime` (13853),
`resolve_coalesces_duplicate_cache_misses` (13965),
`resolve_blocks_coalesced_cache_hit_with_malicious_cname_target` (14035),
`backend_generation_separates_cache_entries` (14346). ~16 tests total
directly exercise cache behavior today — all of these encode assumptions
about the current flat-key shape and will need review under a redesign.

`tests/recursive_perf.rs:144` builds an `InMemoryDnsCache` for a perf
benchmark, run via `just bench` (`cargo test --locked --release --test
recursive_perf -- --ignored --nocapture --test-threads=1`, sequential
single-threaded — **not** a concurrency benchmark, matches G8 in
`docs/caching.md`).

CI (`.github/workflows/ci.yml`): `cargo fmt --check`, `cargo clippy
--all-targets --all-features -D warnings`, `cargo check`, `cargo deny
check`, `cargo audit --deny warnings`, `reuse lint`, `cargo test --locked`
(standard suite), `cargo test --locked --test live_dns -- --ignored`
(optional, `continue-on-error: true`). No Makefile test target.

## B. Web research findings

### B.1 Sharded / low-contention concurrent caches in Rust

**DashMap**: shards an internal `Vec<CachePadded<RwLock<HashMap<K,V>>>>`,
default shard count = `available_parallelism() * 4` rounded to a power of
two. Drop-in `RwLock<HashMap>` replacement, safe behind `Arc`, no `&mut
self` needed. **Real footgun**: holding a `Ref`/`RefMut` guard from
`get`/`get_mut` while calling another DashMap method that hashes to the
*same shard* deadlocks — no reentrancy protection; any "look up, then maybe
insert" sequence must drop the guard first or use `entry()`. Sharding helps
starting around 2-4 contending threads. MIT licensed, mature (v6.2.1, MSRV
1.70). [github.com/xacrimon/dashmap](https://github.com/xacrimon/dashmap),
[docs.rs](https://docs.rs/dashmap/latest/dashmap/struct.DashMap.html).

**moka**: lock-free internal hash table (no user-visible shard knobs),
TinyLFU (LRU+LFU admission) eviction by default, background housekeeping
threads. `moka::future::Cache::get_with`/`try_get_with` (and sync
equivalents) **natively implement single-flight** — concurrent misses for
the same key coalesce into one `init` future, other callers await the
result. This would directly replace the separate global dedup mutex.
Supports per-entry `expire_after` policies (plausibly sufficient for
DNS-TTL-driven expiry). `moka::sync::Cache` variant avoids a hard Tokio
coupling if that's a concern. Dual MIT/Apache-2.0, mature, active.
[github.com/moka-rs/moka](https://github.com/moka-rs/moka),
[docs.rs](https://docs.rs/moka/latest/moka/future/struct.Cache.html).

**General sharded-cache pattern** (RocksDB `LRUCache`, Unbound's slabbed
caches): each shard owns its own hash table **and its own LRU list** —
there is **no global recency order**; eviction is locally-optimal per
shard, not globally optimal. This is the standard, accepted tradeoff for
sharding (perfect global LRU needs one lock, which defeats sharding).
Typical shard counts: 8-64, scaled to expected concurrent threads, not
raw core count. RocksDB engineers have documented this exact contention
mode persisting even with per-shard locks under heavy churn, motivating
further lock-free work.
[smalldatum.blogspot.com RocksDB LRU internals](http://smalldatum.blogspot.com/2022/05/rocksdb-internals-lru.html),
[RocksDB lock-free clock cache issue](https://github.com/facebook/rocksdb/issues/10306).

**Recommendation from research**: adopt `moka` rather than hand-rolling —
it solves sharded/lock-free storage *and* single-flight coalescing in one
crate, removing the need for a separate global dedup mutex entirely. Build
custom only if exact global LRU ordering or DNS-TTL-specific eviction
semantics that moka's `expire_after` can't cleanly express are required. If
building custom regardless (e.g. for the O(log n) requirement below), use
DashMap as the shard/storage layer and accept **per-shard, not global**
LRU ordering, matching RocksDB/Unbound practice — this is a explicit
tradeoff to raise in the interview: sharding is close to fundamentally
incompatible with exact *global* recency ordering; "sharded" and "exact
global LRU" pull in opposite directions and the plan needs to pick which
one wins, or accept per-shard-approximate-global recency.

### B.2 Exact LRU with O(log n) operations

`BTreeSet<(sequence, key)>` + `HashMap<key, sequence>` side-index is a
recognized, if less common than O(1) intrusive-list, pattern. Touch: look
up old sequence via the HashMap (O(1)), remove `(old_seq, key)` from the
BTreeSet (O(log n)), insert `(new_seq, key)` (O(log n)), update the
HashMap (O(1)) — net O(log n) per touch. Eviction pops the BTreeSet's
minimum element. Gives **exact** LRU order with no ghost tokens and no
periodic compaction, because every touch actively removes the old position
rather than leaving a tombstone.

Rust's `BTreeMap`/`BTreeSet` are B-Trees (branching factor ~11), so real
constant factors beat a naive binary tree but are still worse than
intrusive-list O(1) (a touch walks several tree nodes/cache lines vs. a
few pointer swaps). Tradeoff in the other direction: the BTree approach
needs **zero unsafe code** — an intrusive doubly-linked list generally
needs raw pointers or an arena+index scheme (`unsafe`) to satisfy the
borrow checker, which the BTree approach avoids entirely, and its
self-contained-per-shard structure (no raw pointers) is easier to reason
about under sharding.

Existing crate: **`lrumap`** (khonsulabs) ships both `LruHashMap` (arena/
`Vec`-indexed intrusive list, O(1), the crate's recommended default) *and*
**`LruBTreeMap`** (BTreeMap-tracked, exposing ordered/range operations like
`most_recent_in_range()`) — confirming this is a recognized, already-
implemented Rust design point, not a novel idea.
[docs.rs/lrumap](https://docs.rs/lrumap/),
[github.com/khonsulabs/lrumap](https://github.com/khonsulabs/lrumap),
[std::collections::BTreeMap](https://doc.rust-lang.org/std/collections/struct.BTreeMap.html).

**Recommendation from research**: the `BTreeSet<(sequence, key)>` +
`HashMap<key, sequence>` pattern (or `lrumap::LruBTreeMap` directly) is the
right structure for the stated O(log n) requirement, and pairs naturally
with per-shard sharding from B.1 — one `BTreeSet`+`HashMap` pair per shard,
each behind its own shard lock, sequence numbers can be per-shard
monotonic counters (avoids a global atomic bottleneck). Expect roughly
2-4x higher constant-factor latency per touch vs. intrusive-list O(1) —
almost certainly irrelevant next to DNS I/O costs, but worth confirming
with a benchmark before committing, per G8 in `docs/caching.md` (no
existing concurrency benchmark).

### B.3 DNS resolver cache key design and DNSSEC caching

**Hierarchical key is the norm in production resolvers.** PowerDNS
Recursor's `MemRecursorCache` keys on a compound **(name, type)** —
effectively name → {type → RRset} — not one entry per full query; entries
are "sequenced" (each access moves the entry, LRU-style), and a *separate*
`NegCache` handles NXDOMAIN/NODATA plus an `AggressiveNSECCache`
implementing RFC 8198 synthesis. Unbound separates concerns similarly: an
**RRset cache** keyed by name+type+class (independent of the full query), a
thin **message cache** keyed by full query that references RRsets in the
shared RRset store, plus separate infra and DNSSEC-key caches. Both size
slab/shard counts as a power of two near the thread count, same rationale
as B.1. [PowerDNS Recursor internals](https://deepwiki.com/PowerDNS/pdns/4-powerdns-recursor),
[PowerDNS issue #6186](https://github.com/PowerDNS/pdns/issues/6186),
[Unbound requirements doc](https://unbound.docs.nlnetlabs.nl/en/latest/reference/history/requirements.html).

**DNSSEC caching per RFC 4035 §4.5**: a security-aware resolver "SHOULD
cache each response as a single atomic entry containing the entire answer,
including the named RRset and any associated DNSSEC RRs," and "SHOULD
discard the entire atomic entry when any of the RRs contained in it
expire" — RRSIGs are cached *with* their RRset as one unit, sharing one
expiry (min of RRset TTL and RRSIG expiration), not as separate entries.
RFC 6840 adds: a "BAD cache" for entries that failed validation (§3.1, so
repeated queries for known-bad data skip re-validation), and AD-bit policy
— set AD=1 only when data validated **and** the request had DO or AD set
(§5.8); CD should be set on **all upstream queries** regardless of the
downstream client's flags, so the resolver always fetches/caches DNSSEC
material it needs (§5.9). **Key architectural takeaway: validation and
DNSSEC-RR retrieval are independent of the querying client's DO/CD flags**
— the resolver always requests+validates with DNSSEC data, caches a
validation outcome once per RRset, and only at **response-assembly/serve
time** decides per-request whether to include RRSIGs (DO=1), whether to
set AD (validated + requester DO/AD=1), or return SERVFAIL vs. serve
anyway based on CD. [RFC 4035 §4.5](https://datatracker.ietf.org/doc/html/rfc4035),
[RFC 6840](https://datatracker.ietf.org/doc/html/rfc6840).

**Negative/NSEC caching**: RFC 8198 lets validating resolvers synthesize
negative (and wildcard-derived positive) answers from cached NSEC/NSEC3
ranges instead of one entry per queried-but-nonexistent name — another
argument for storing DNSSEC proof material independent of the specific
queries that triggered capturing it, reusable across future queries.
[RFC 8198](https://datatracker.ietf.org/doc/html/rfc8198).

**Recommended cache-entry shape** (from research, to validate in
interview/plan):
- Store once per **(owner name, type, class)**: RDATA set, TTL/expiry,
  covering RRSIG(s) raw/unmodified, and a small validation-state enum
  (`Unvalidated | Insecure | Secure | Bogus(reason)` — mirrors Unbound/BIND
  internals and RFC 6840's BAD-cache; `Bogus` entries get a short
  negative-cache-style TTL to prevent retry storms).
- Store **separately**: negative-cache entries per (name, qtype-or-ANY,
  SOA-owner) for NXDOMAIN/NODATA, and NSEC/NSEC3 range records reusable
  across queries (RFC 8198).
- **Do not key by DO, CD, or AD** — these become per-request
  response-assembly decisions, not cache dimensions: include RRSIGs only
  if DO=1; set AD only if `Secure` and (DO=1 or AD=1 requested); CD=0 +
  `Bogus` → SERVFAIL instead of serving; CD=1 → serve regardless of
  validation state.
- This is directly compatible with A.3/B.1's domain-first, hierarchical
  key shape: outer key is owner name, next level is {type/class → entry},
  each leaf is validation-tagged and signature-bearing, DO/AD/CD logic
  lives entirely in the response builder, never in cache key or storage.

## C. Open questions this raises for the interview

1. **Sharding vs. exact global LRU is in tension.** B.1 and B.2 both flag
   this: sharding (needed for goal 1, lock scope) naturally gives
   per-shard eviction ordering, not a single global recency order.
   Need to confirm with the user whether "real LRU" (goal 2) means *exact
   within a shard* (acceptable, matches RocksDB/Unbound/PowerDNS practice)
   or *exact globally across the whole cache* (much harder to reconcile
   with sharding — would need a cross-shard coordination mechanism that
   reintroduces contention).
2. **Build custom vs. adopt `moka`.** `moka` would satisfy goals 1
   (sharded/lock-free) and partially goal 2 (LRU-ish eviction via TinyLFU,
   though not a literal O(log n) BTree-backed exact LRU) essentially for
   free, and also replaces `SingleFlightMisses` outright. But it doesn't
   give the literal "O(log n) average, O(n) worst case only on full
   invalidation" complexity the user specified — that requirement points
   toward a custom `BTreeSet`+`HashMap` structure per shard instead. Worth
   surfacing this tradeoff explicitly: adopt moka and relax the O(log n)
   requirement to "TinyLFU-approximated recency, sharded," or build custom
   to hit the exact stated complexity target.
3. **DNSSEC is currently a no-op stub** (`DnssecValidationMode::Disabled`
   is the only variant). The domain-first/nested-key redesign should be
   validation-state-ready (per B.3's `Unvalidated | Insecure | Secure |
   Bogus` enum) without requiring this project to also implement DNSSEC
   validation itself — confirm scope: cache-shape-ready-for-DNSSEC vs.
   actually-implementing-validation are very different sized efforts.
4. **Bulk invalidation mechanism under the new key.** Current
   `cache_namespace` (opaque string folded into every flat key) is the
   existing "make everything unreachable at once" lever (`docs/caching.md`
   §2, G4/G5). Under a domain-first key, does namespace invalidation still
   work the same way (still folded in, now at some level of the nested
   structure), or does goal 2's "O(n) only when everything is invalidated"
   language imply an explicit sweep/generation-check per entry instead of
   the current instant-unreachability trick? These have different
   performance shapes (G4/G5 already describe the orphan-capacity cost of
   the current instant-unreachable approach).
5. **Single-flight granularity under a nested key.** If storage becomes
   name → {type → entry}, does request coalescing (dedup concurrent
   misses) stay keyed by the full flat (question, features) as today, or
   move to a coarser per-(name,type) granularity? Affects whether two
   requests differing only in EDNS bufsize still coalesce into one
   upstream fetch.
