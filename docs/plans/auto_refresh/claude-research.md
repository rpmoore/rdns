# Research: Auto-Refresh Popular Domains

## Codebase Research

### 1. Testing conventions

- **No `Clock` trait inside `src/resolver/cache/`.** Cache functions take `now: SystemTime` as a plain parameter (`Shard::lookup_hop(&self, domain, qtype, qclass, dnssec_ok, current_epoch, now: SystemTime)`, `src/resolver/cache/shard.rs:405-413`). Tests fake time via explicit offsets: `let now = SystemTime::now(); entry.expires_at = now - Duration::from_secs(300);` (`shard.rs:959-971`). The new leaky-bucket drain function should follow this exact convention — take `now: SystemTime` explicitly — not introduce a new `Clock` trait into `cache::shard`.
- A real `Clock` trait *does* exist, one layer up: `pub trait Clock { fn now(&self) -> SystemTime; }` (`src/resolver/mod.rs:8065-8079`), `SystemClock` impl at `:8073`, test-only `FixedClock` at `:8354-8360`. `ResolveQuery` holds `clock: Arc<dyn Clock>` (`mod.rs:3573`). Only used at resolver-orchestration layer today (e.g. EDNS cookie timestamps), not threaded into cache lookups.
- **Shard-level tests** (`shard.rs:560-1090`): plain `#[test]`, small fixture helpers (`stored_record()`, `rrset_entry()`, `negative_entry()`), direct `Shard::new(capacity)`, assertions via `#[cfg(test)]` helper methods (`contains_positive`, `contains_negative`, `has_any_data`, `domain_count`, `lru_order_for_test`, `hold_lock_for_test`). Pure in-memory struct testing, no mock backend needed at this layer.
- **LRU tests** (`lru.rs:105-180`): same style — plain `#[test]`, direct `ShardLru::new()` + `touch`/`remove`/`peek_oldest`, `#[cfg(test)] order_for_test()` helper.
- **Singleflight tests** (`singleflight.rs:235-519`): `#[tokio::test]` async, real concurrent `tokio::spawn` interleaving (not mocked), `tokio::task::yield_now()` to force scheduling points, plus a real OS thread + `std::sync::Mutex` guard to prove cross-shard non-contention.
- **Resolver-level tests** (`src/resolver/mod.rs`): `#[tokio::test]`, built via `ResolveQuery::with_cache(...)` / `with_cache_and_backend_snapshot(...)` (`mod.rs:3618-3707`) with fake `ResolutionBackend` impls — `StaticUpstream` (`mod.rs:9903-9927`, records requests in `Mutex<Vec<UpstreamRequest>>`, returns scripted `Result`) or `ScriptedAuthorityTransport` (`mod.rs:9929-9957`, queue of scripted responses). `FixedClock` substitutes for real time where needed.

### 2. Background task pattern — `spawn_sighup_reload_task`

Exact shape (`src/main.rs:578-615`, unix-only; no-op stub for non-unix at `:652-659`):

```rust
#[cfg(unix)]
fn spawn_sighup_reload_task(
    resolver: Arc<ResolveQuery>,
    metrics: Arc<dyn MetricsSink>,
    config_path: Option<PathBuf>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut hangup = match tokio::signal::unix::signal(...) { ... };
        loop {
            if hangup.recv().await.is_none() { return; }
            ...
        }
    })
}
```

- Takes `Arc<ResolveQuery>` by value (cloned at call site) + `Arc<dyn MetricsSink>` + task-specific config.
- Returns `JoinHandle<()>`. **No internal shutdown-select exists anywhere in this codebase's one existing background task** — shutdown is external: `main.rs:153-154` spawns once at startup; `serve_until_shutdown` (`main.rs:209-311`) holds the handle and at teardown does `sighup_task.abort(); let _ = sighup_task.await;` (`:301-302`). This is the concrete precedent: the new refresh-worker task(s) should follow the same "loop forever, get `.abort()`-ed externally" shape, not add a new `select!`-based shutdown mechanism.
- Errors logged via `tracing` (`error!`/`warn!`), never propagated.
- Call site (`main.rs:131-154`): resolver `Arc` built first, then `spawn_sighup_reload_task(Arc::clone(&resolver), ...)`.

### 3. Config pattern — `CacheConfig`

`src/config/mod.rs:340-445`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub shard_count: Option<usize>,
}
impl Default for CacheConfig { fn default() -> Self { Self { max_entries: 10_000, shard_count: None } } }
impl CacheConfig {
    pub fn resolved_shard_count(&self) -> usize { ... }      // :379
    pub fn shard_capacity(&self, index, shard_count) -> usize { ... } // :403
    pub fn validate(&self) -> Result<(), ConfigError> { ... } // :425
}
```
- `RuntimeConfig.cache: CacheConfig` (`config/mod.rs:40`), defaulted via `CacheConfig::default()`.
- TOML deserialization goes through a shadow struct: `RawCacheConfig` (`config/mod.rs:1390-1409`, `#[derive(Deserialize)] #[serde(deny_unknown_fields)]`, per-field `#[serde(default = "...")]`), with `try_into_cache_config(self) -> Result<CacheConfig, ConfigError>`. `RawRuntimeConfig.cache: Option<RawCacheConfig>` (`:1362`); top-level parse does `raw.cache.map(RawCacheConfig::try_into_cache_config).transpose()?.unwrap_or_default()` (`:1730-1734`).
- **New refresh-config struct should follow this exact three-piece shape**: real struct + `Default` impl + `Raw*` shadow struct + `try_into_*` conversion + `Option<Raw*>` field on `RawRuntimeConfig`.
- `RuntimeConfig::validate()` calls `self.cache.validate()?` (`:196`) — new struct's `validate()` wired the same way.
- Threaded through: `main.rs:104` (`ShardedDnsCache::new(&config.cache)`), resolver test helpers, `delivery/dns.rs:920`.

### 4. `ShardState`/`ShardLru` internals

`ShardState` (`shard.rs:72-77`):
```rust
struct ShardState {
    positive: PositiveShardState,   // domains: HashMap<String, DomainRecordSets>
    negative: NegativeShardState,   // domains: HashMap<String, DomainNegativeEntries>
    lru: ShardLru,
}
```
`ShardLru` (`lru.rs:33-41`):
```rust
pub(crate) struct ShardLru {
    order: BTreeSet<(u64, String)>,   // (sequence, domain), smallest = oldest
    positions: HashMap<String, u64>,  // domain -> its own sequence number
    next_sequence: u64,
}
```
- `touch(domain)` (`lru.rs:54-62`): remove-old-position + insert-new-position, O(log n) each; at most one live `order` entry per domain.
- `remove(domain)` (`lru.rs:67-71`): drops both `positions` entry and its `order` pair — called from `ShardState::evict_domain` (`shard.rs:84-88`) and `ShardState::drop_lru_if_domain_now_empty` (`shard.rs:144-150`, itself called from `remove_positive_entry`/`remove_negative_entry`, `shard.rs:122-142`).
- **New per-domain leaky bucket** (level + last-drained timestamp) should live in `ShardState` alongside `lru: ShardLru`, as its own `HashMap<String, BucketState>`, cleared via the same two call sites (`drop_lru_if_domain_now_empty`, `evict_domain`) that already clear `lru` — those are the two places a domain fully disappears from a shard.
- `lookup_hop` (`shard.rs:405-463`) takes the shard's single `Mutex` once, probes via `take_live_positive`/`take_live_cname_hop`/`take_live_negative` (`shard.rs:163-268`), calls `state.lru.touch(domain)` on every live hit (lines 426, 436, 448, 458) — exactly the 4 call sites where a bucket increment hangs alongside the existing `lru.touch`.

### 5. Singleflight — `ShardedSingleFlight`/`MissKey`

```rust
pub(crate) type MissKey = (String, u16, u16, u64, bool); // qname, qtype, qclass, cache_epoch, dnssec_ok
pub(crate) struct ShardedSingleFlight { shards: Vec<SingleFlightShard> }
impl ShardedSingleFlight {
    pub(crate) fn new(shard_count: usize) -> Self;
    pub(crate) fn begin(&self, key: MissKey) -> SingleFlightTicket;  // :135
}
pub(crate) enum SingleFlightTicket { Leader { key: MissKey, flight: Arc<InFlightMiss> }, Follower { flight: Arc<InFlightMiss> } }
impl SingleFlightLeader {
    pub(crate) fn new(coalescer: Arc<ShardedSingleFlight>, key: MissKey, flight: Arc<InFlightMiss>) -> Self;
    pub(crate) fn complete(mut self, result: Result<ResolutionResponse, ResolutionBackendError>); // :201
}
impl InFlightMiss { pub(crate) async fn wait(&self) -> Result<ResolutionResponse, ResolutionBackendError>; } // :223
```
Caller pattern: `begin(key)` → on `Leader`, do the real fetch then `leader.complete(result)` (or drop it — `Drop` auto-completes with `Transport("single-flight leader cancelled")`, `singleflight.rs:207-219`); on `Follower`, `flight.wait().await`. A refresh worker becoming a `Follower` on a key a real client is already fetching is exactly the "collapse to one backend fetch" behavior the spec wants for free.

### 6. `ResolveQuery` internals

- **Gap found**: `probe_cache` (`resolver/mod.rs:4656-4726`) does **not** call `Shard::lookup_hop` directly. It calls `self.cache.lookup_chain(...)` (`DomainDnsCache` trait, `cache/mod.rs:120-129`), which for `ShardedDnsCache` delegates to `assemble::resolve_from_cache` (`cache/mod.rs:151-172`), which walks `Shard::lookup_hop` per CNAME hop internally. `ChainLookup` (`cache/assemble.rs:84-95`) only has `Answered`/`NxDomain`/`NoData`/`Miss` variants — **no room for a side-channel "refresh wanted" signal today.** The plan must either add a signal field/variant payload to `ChainLookup` and thread it through `resolve_from_cache`, or have the refresh trigger surface via a separate cheap post-lookup shard probe rather than piggybacking on `lookup_chain`'s existing return path. This contradicts the spec's phrasing that the signal flows straight from `lookup_hop` to `probe_cache` — there's a layer in between that needs modification too.
- `resolve_backend` (`resolver/mod.rs:4575-4595`): `async fn resolve_backend(&self, backend_snapshot: &BackendSnapshot, decoded: &DecodedQuery) -> Result<ResolutionResponse, ResolutionBackendError>`. Requires a real `DecodedQuery` — a synthetic refresh fetch needs a fabricated wire-format `Message`/`DecodedQuery` for `(domain, qtype, qclass, dnssec_ok)`, not just the four scalars.
- `cache_store_for_response` (`:5434-5458`) / `store_cache_response` (`:5400-5424`): `store_cache_response(&self, epoch: u64, response: &Message, question: &QuestionKey, request: &ResolveRequest, dnssec_ok: bool, store_authoritative: bool)`. `request: &ResolveRequest` is only read for `request.received_at.0` — a refresh worker can fabricate a minimal `ResolveRequest` just to carry that timestamp.
- **Production stores only happen via `prepare_backend_result`** (`:4915-5017`), which does policy-block checks, response-rewriting, DNSSEC/authoritative-flag derivation *before* `store_cache_response`. Confirmed: spec's design (§3, bypass policy/local-entries/chaos, call `resolve_backend` + `cache_store_for_response`/`store_cache_response` directly) is correct — none of `prepare_backend_result`'s layers are reusable as-is nor desired for a refresh.
- `BackendHandle::current()` (`:2562-2568`): `pub fn current(&self) -> Arc<BackendSnapshot>` — `Arc` clone under `RwLock` read lock. `ResolveQuery.backend: BackendHandle` (`:3567`) is the swappable-on-reload snapshot source; refresh worker calls this once per attempt (not twice — avoid tearing across a mid-refresh reload).
- `ResolverMetric` (`:8110-8151`): plain `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum` (`QueryReceived`, `CacheHit`, `CacheMiss`, `CacheStore`, `CacheStoreSkipped`, `CacheCoalescedMiss`, `UpstreamSuccess`, `UpstreamFailure`, ...). New variants (`RefreshTriggered`, `RefreshQueueFull`/`RefreshDropped`, `RefreshSucceeded`, `RefreshFailed`) are simple new unit variants. `MetricsSink::increment`/`observe_duration` (`:8094-8100`) — check any concrete sink for match exhaustiveness at implementation time.
- Other shapes reviewed: `QuestionKey` (`:220-240`), `DecodedQuery` (`:293-313`), `ResolveRequest` (`:173-218`), `BackendSnapshot` (`:2441-2499`, fields `backend`/`mode`/`generation`/`health`/`cache_namespace`/`cache_epoch`/`root_hints`).

### 7. `docs/knowledge/resolver/caching/` invariants

- **`answer-cache.md`**: `ShardedDnsCache { shards: Vec<Shard> }`, `Shard { state: Mutex<ShardState>, capacity }`. One domain's positive/negative/LRU state lives in exactly one shard, mutated atomically together. Wire-TTL is always "remaining time to expiry," computed fresh per read — relevant because a refresh moving `expires_at` forward is what visibly "extends" an entry, consistent with existing TTL-aging machinery. Shard lock never held across `.await`, never across more than one CNAME hop.
- **`sharding.md`**: routing is `shard_index(domain, shard_count)` (`cache/mod.rs:231`), hashed with process-lifetime-seeded `RandomState`. Grouping is per-domain-name, not per-(domain,qtype) — matches spec's popularity-bucket granularity choice. `ShardedSingleFlight` deliberately uses the same `shard_index` routing as the cache but an **intentionally separate lock** — merging was explicitly rejected as reintroducing "unrelated work under one lock."
- **`cache-epoch.md`**: every entry carries `cache_epoch: u64`; reload bumps a global counter only when the backend cache-namespace fingerprint changes; `lookup_hop` checks `entry.cache_epoch == current_epoch` on every lookup. `MissKey` includes epoch for exactly the reason a refresh worker cares about: a refresh started under an old epoch must not coalesce with a request already observing the new epoch. Requests capture `backend_snapshot` once at the top and carry it through to any store — refresh worker must follow the same discipline (fetch `BackendHandle::current()` once per attempt).

All three docs currently say nothing about popularity tracking, refresh workers, or leaky buckets — new content needed, either a new `docs/knowledge/resolver/caching/auto-refresh.md` or a `## Auto-refresh` section on `answer-cache.md`, once implemented (per this repo's Knowledge Bundle requirement).

---

## Web Research

### 1. DNS resolver prefetch / stale-while-revalidate

- **Unbound `prefetch`** (`unbound.conf(5)`): flat, hardcoded **10% of original TTL**, on/off only (`prefetch: yes/no`, default no), not tunable. Docs note the direct cost: "about 10 percent more traffic and load." Separate `prefetch-key` prefetches DNSKEYs early (different mechanism). Unbound's `serve-expired`/RFC 8767 (default no) is reactive/complementary, not proactive — `serve-expired-ttl` (86400s max staleness), `serve-expired-client-timeout` (1800ms since v1.23, wait for live refresh before falling back to stale). Sources: [unbound.conf(5)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html), [Serving Stale Data](https://unbound.docs.nlnetlabs.nl/en/latest/topics/core/serve-stale.html).
- **BIND9 `prefetch trigger [eligibility];`**: two absolute-second params, defaults **trigger=2s, eligibility=9s**. Trigger: refresh fires when TTL remaining < trigger. Eligibility: only records with *original* TTL > eligibility are candidates at all — explicitly to avoid prefetch thrash on short-TTL records. `prefetch 0;` disables; global-only. Source: [ISC KB aa-01122](https://kb.isc.org/docs/aa-01122).
- **RFC 5861 `stale-while-revalidate=N`**: fixed grace-window seconds set per-response by origin, not a TTL fraction. Reactive only — revalidation fires only if a request lands inside the window. Source: [RFC 5861](https://www.rfc-editor.org/rfc/rfc5861.html).
- **Sanity check vs. spec's `max(minimum_ttl * refresh_lead_ratio, refresh_min_lead)`**: directionally reasonable hybrid (Unbound=pure ratio, BIND=pure floor+separate eligibility gate, RFC5861=pure fixed window — nobody uses exactly this hybrid, but it degrades sensibly at both ends). **Recommend adopting BIND's separate eligibility floor**: a minimum *original* TTL below which a domain is never marked hot-refreshable at all, distinct from lead-time clamping — prevents refresh thrash on very-short-TTL records, a real documented BIND pain point that lead-ratio/floor alone doesn't solve.

### 2. Leaky bucket for per-domain popularity

Standard drain-then-increment:
```
elapsed = now - last_update_time
leaked  = elapsed * leak_rate
level   = max(0, level - leaked)     // drain first
level  += 1                          // then add new event
last_update_time = now
is_hot = level > threshold
```
- **Clock monotonicity**: use monotonic time (`Instant`-equivalent), never wall-clock — matches this codebase's existing `SystemTime`-param convention at the cache layer (see Codebase §1); worth flagging as a risk if `SystemTime` can go backward (NTP step) — `governor` crate models time as an opaque monotonic `Nanos` for exactly this reason.
- **Integer over float**: prefer integer/fixed-point drain math over `f64` to avoid long-uptime rounding drift; the `ratelimit` crate uses scaled integer "milli-units" internally for this reason.
- **Integer truncation on drain**: naive integer division in `elapsed * leak_rate` can systematically under-drain (inflate hotness) over many small updates — worth an explicit test stepping the clock by sub-unit-of-drain increments.
- **Lock-held critical section**: a single global mutex over all per-domain buckets would crater concurrency — this is moot here since the bucket rides inside the existing per-shard `Mutex<ShardState>`, already sharded.
Sources: [Leaky Bucket Algorithm](https://dev.to/0xtanzim/understanding-the-leaky-bucket-algorithm-for-system-design-4fpo), [governor clock docs](https://docs.rs/governor/latest/governor/clock/index.html).

### 3. Tokio bounded mpsc + fixed worker pool

- `mpsc::channel(N)` bounded; `Sender::try_send()` returns `Err(Full)` immediately without awaiting — correct primitive for "drop on full, never block hot path." Hot path calls `try_send`, logs/counts on `Full`, never retries inline. Source: [Tokio channels tutorial](https://tokio.rs/tokio/tutorial/channels).
- **Shutdown**: dropping every `Sender` clone makes `Receiver::recv()` return `None` — standard idiomatic shutdown. Matches this codebase's pattern of external-abort-based shutdown (no internal `select!` used anywhere today, see Codebase §2) — though for a worker pool the drop-last-sender approach is the more idiomatic fit than `.abort()`.
- **mpsc::Receiver is single-consumer.** For N workers pulling off one shared queue: either wrap `Receiver` in `Mutex<Receiver<T>>`, use `async-channel`'s true MPMC receiver, or fan out via a dispatcher + N per-worker channels (static partition, simpler, no load balancing).
- **Fixed worker pool vs. semaphore**: community consensus favors N fixed worker tasks for background/batch work (predictable bounded resource use) over single-dispatcher+semaphore (better for dynamic/request-scoped concurrency). Maps cleanly to this feature's fixed-size refresh pool.
- **Panic isolation gotcha**: Tokio isolates panics per *spawned task* by default — but if each job runs *inline* inside a long-running worker loop (not its own `tokio::spawn`), a panicking job kills that whole worker (same task/stack). To get true per-job isolation without spawning-per-job (which would defeat the fixed-N bound), wrap each job's execution in `FutureExt::catch_unwind` inside the worker loop.
Sources: [Tokio spawning tutorial](https://tokio.rs/tokio/tutorial/spawning), [JoinError docs](https://docs.rs/tokio/latest/tokio/task/struct.JoinError.html).

### Actionable recommendations feeding into the plan

1. Add a BIND-style **eligibility floor** (min original TTL) alongside the lead-ratio/floor formula, distinct from lead-time clamping.
2. Leaky bucket: integer drain-then-increment math, explicit `now: SystemTime` param (matching existing cache-layer convention, no new `Clock` trait needed in `cache::shard`).
3. Worker pool: N fixed tokio tasks, bounded `mpsc` (or `async-channel` if true MPMC fan-out wanted), `try_send`+drop-on-full at the hot path, `catch_unwind` per job inside each worker's loop, shutdown via dropping the last `Sender` (reconcile with this codebase's existing abort-based shutdown convention — see interview).
4. **Must resolve in the plan**: `ChainLookup` has no slot for a refresh-wanted signal today — `resolve_from_cache`/`lookup_chain` sit between `lookup_hop` and `probe_cache`. Plan needs an explicit design decision here, not just "the caller turns the signal into an enqueue."
