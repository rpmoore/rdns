# section-07-call-site-migration: Rewiring the resolver's call sites onto the new sharded cache

## Scope

This section is the mechanical rewiring step referenced by `claude-plan.md`
§9 and §12 step 6. By the time this section starts, every genuinely new
piece of cache logic already exists and is independently tested:

- section-01-foundation: module skeleton, `shard_index(domain, shard_count)
  -> usize`, `CacheConfig` (including the exact remainder-distributed
  per-shard capacity split).
- section-02-data-model: `RRsetEntry`, `StoredRecord`, `DnssecState`,
  `NegativeEntry`, `NegativeKey`, `DomainRecordSets`,
  `DomainNegativeEntries`.
- section-03-shard-and-lru: `ShardLru`, `Shard`/`ShardState`, the
  eviction loop.
- section-04-singleflight: `ShardedSingleFlight`, `InFlightMiss`,
  `SingleFlightTicket`/`SingleFlightLeader`, keyed by
  `(name: String, qtype: u16, qclass: u16)` and sharded via
  `shard_index`.
- section-05-namespace-sweep: `sweep_stale_namespace(cache:
  &ShardedDnsCache, current_namespace: &str)`.
- section-06-assembly-and-chains: `assemble_response`,
  `resolve_from_cache`/`ChainLookup`, and the top-level `ShardedDnsCache`
  type that owns `Vec<Shard>` and routes lookups/stores through
  `shard_index` (per section-03's closing note: "Wiring `Shard` into a
  top-level `ShardedDnsCache`... happens in later sections (section-06
  for lookup/assembly, section-07 for the trait implementation and
  call-site migration)").

This section's job is to **not reimplement any of that** — only to:

1. Define the `DomainDnsCache` trait (plan §9.0) and implement it for
   `ShardedDnsCache` (delegating straight to `resolve_from_cache`,
   the store-decomposition logic below, and `sweep_stale_namespace`) and
   for a no-op cache (replacing today's `NoopDnsCache`).
2. Rewrite every existing call site in `src/resolver/mod.rs` that assumes
   the old flat `CacheKey`/`CacheLookup`/`CacheStore`/`CachedResponse`
   shapes to use the new trait and types instead.
3. Wire `CacheConfig` into `RuntimeConfig` and thread it from
   `src/main.rs` into the cache constructor.
4. Hook `sweep_stale_namespace` into the SIGHUP reload path.
5. Update `main.rs`'s `OpenTelemetryMetrics` gauges and
   `tests/recursive_perf.rs`'s `resolver_with_cache` helper, both of
   which construct the cache type directly.

**Do not** implement `assemble_response`, `resolve_from_cache`,
`sweep_stale_namespace`'s internals, `ShardedSingleFlight`, or
`Shard`/`ShardLru` here — those are section-04/05/06's code, already
built and tested. This section only calls into them from new locations.

**Expected transitional state**: `src/resolver/mod.rs` has one very large
`#[cfg(test)] mod tests` block (~16 existing cache-related tests, plus a
custom `ProtocolCodec` test double at `mod.rs:8164-8214` and a custom
`DnsCache` test double at `mod.rs:8367`, per `claude-plan.md` §11). This
section changes the trait these test doubles implement and removes/renames
types they reference (`CachedResponse`, `CacheKey`, `CacheLookup`,
`CacheStore`). Fully migrating those existing tests is
section-08-test-migration-and-benchmark's explicit job, not this section's.
It is expected and acceptable for `cargo test` on `src/resolver/mod.rs` to
not fully compile again until section-08 lands, **as long as this
section's own new code (the trait impl, the rewritten call sites, the
config-wiring tests below) compiles and its own tests pass.** Section-08
is blocked on this section finishing precisely because of this ordering.

## Background: current call sites (before this section)

All line numbers below are from the current (pre-rework)
`src/resolver/mod.rs`, `src/main.rs`, and `src/config/mod.rs` — they will
have shifted somewhat once sections 01-06 land their own new files, but
the functions/types themselves are unchanged by those sections (sections
01-06 add new files under `src/resolver/cache/`; they do not touch
`mod.rs`'s existing cache call sites — that is what makes this section
necessary).

### The old flat types this section retires

```rust
// mod.rs:193-249 — every one of these goes away as a *cache-lookup* key.
// QueryFeatures itself survives (still used for DNSSEC/truncation inputs
// at assembly time, per plan §7), but CacheKey (question + question_wire +
// features + cache_namespace, all folded together) does not.
pub struct QueryFeatures { recursion_desired: bool, authenticated_data: bool,
    checking_disabled: bool, dnssec_ok: bool, edns_udp_payload_size: Option<u16> }
pub struct CacheKey { question: QuestionKey, question_wire: Vec<u8>,
    features: QueryFeatures, cache_namespace: Option<String> }
pub struct CacheLookupRequest { key: CacheKey, received_at: SystemTime }

// mod.rs:571-621
pub enum CacheLookup { Hit(CachedResponse), Miss, Expired, Bypass(CacheBypassReason), Unavailable }
pub struct CachedResponse { response_template: Vec<u8>, response_code: ResponseCode,
    minimum_ttl: Duration, negative_cache: Option<NegativeCacheMetadata>,
    stored_at: SystemTime, expires_at: SystemTime }
pub struct CacheStore { key: CacheKey, response_template: Vec<u8>, response_code: ResponseCode,
    minimum_ttl: Duration, negative_cache: Option<NegativeCacheMetadata>,
    stored_at: SystemTime, ttl: Duration }
```

`NegativeCacheMetadata` (mod.rs:589-598) and `negative_ttl`/
`negative_covered_name` (mod.rs:746-796) are **not** retired — they still
compute TTL-policy decisions from a backend `Message`
(`CacheTtlPolicy::ttl_for_response`, mod.rs:649-712, is section-02/06
territory to consume, not rewrite here). What changes is what happens
*after* that computation: instead of packing the result into a
`CacheStore { key, response_template, .. }`, this section's rewritten
`cache_store_for_response` decomposes it into the new entry shapes.

### `ResolveQuery`'s cache-touching fields and constructors (mod.rs:2597-2841)

```rust
pub struct ResolveQuery {
    // ...
    cache: Arc<dyn DnsCache>,           // -> Arc<dyn DomainDnsCache>
    ttl_policy: CacheTtlPolicy,         // unchanged
    miss_coalescer: Arc<SingleFlightMisses>,  // -> Arc<ShardedSingleFlight> (section-04)
    // ...
}
```

Every one of `ResolveQuery::new`, `with_cache`, `with_cache_and_policy`,
`with_cache_and_backend_snapshot`, `with_cache_policy_and_backend_snapshot`,
`with_cache_and_backend_handle`, `with_cache_policy_and_backend_handle`,
`with_cache_and_backend_generation` (mod.rs:2617-2841) takes a `cache:
Arc<dyn DnsCache>` parameter and constructs `miss_coalescer:
Arc::new(SingleFlightMisses::default())` internally. All of these need
their `cache` parameter type changed to `Arc<dyn DomainDnsCache>` and
their internal `miss_coalescer` construction changed to
`Arc::new(ShardedSingleFlight::new(shard_count))` (or however section-04
names its constructor — it needs a shard count consistent with the
cache's own, see "Config wiring" below).

**Why the ~13 existing `Arc::new(NoopDnsCache)` call sites across
`mod.rs`'s tests don't need editing**: `NoopDnsCache` keeps its name; only
which trait it implements changes (`DomainDnsCache` instead of `DnsCache`,
see below). `Arc::new(NoopDnsCache)` unsize-coerces to `Arc<dyn
DomainDnsCache>` automatically at each call site once the trait impl is
updated, so none of those call sites themselves need to change — only the
`ResolveQuery` constructor signatures they call into.

### `probe_cache` (mod.rs:3380-3429) and `evaluate_cache_lookup`/`serialize_cache_hit` (mod.rs:3436-3515)

```rust
async fn probe_cache(
    &self,
    backend_snapshot: &BackendSnapshot,
    request: &ResolveRequest,
    decoded: &DecodedQuery,
) -> CacheProbe {
    // ... builds one CacheKey::new(question, question_wire, features, namespace)
    // ... calls self.cache.lookup(&CacheLookupRequest { key, received_at }).await
    // ... self.evaluate_cache_lookup(lookup, decoded, request) maps CacheLookup::Hit(cached)
    //     to self.serialize_cache_hit(decoded, &cached, request), which calls
    //     self.protocol.serialize_cached_response(decoded, cached, now, allow_udp_truncation)
}
```

`CacheProbe` (mod.rs:2590-2595, `key: Option<CacheKey>`, `hit:
Option<Vec<u8>>`, `store_allowed: bool`, `event_cache_result:
Option<QueryEventCacheResult>`) is the return shape `resolve()`
(mod.rs:2865-2956) branches on: a hit finishes immediately; a miss with
`store_allowed` and a `key` goes to `resolve_coalesced_miss`; anything
else falls through to `resolve_backend_and_finish`.

### `cache_store_for_response` / `store_cache_response` (mod.rs:3663-3717)

```rust
async fn store_cache_response(&self, cache_key: CacheKey, response_bytes: Vec<u8>,
    response: &Message, decoded: &DecodedQuery, request: &ResolveRequest) {
    if let Some(store) = self.cache_store_for_response(cache_key, response_bytes, response, decoded, request.received_at.0) {
        // metrics, then self.cache.store(store).await
    }
}

fn cache_store_for_response(&self, key: CacheKey, mut response_template: Vec<u8>,
    response: &Message, query: &DecodedQuery, stored_at: SystemTime) -> Option<CacheStore> {
    // validates response shape, computes (ttl, negative_cache) via self.ttl_policy.ttl_for_response(response),
    // rewrites the response id to 0, returns one CacheStore { key, response_template, .. }
}
```

### `SingleFlightMisses` and its call sites (mod.rs:3131-3220, struct at 3827-3931)

`resolve_coalesced_miss` calls `self.miss_coalescer.begin(cache_key.clone())`
(mod.rs:3142), dispatching to `resolve_coalesced_leader` (constructs a
`SingleFlightLeader::new(Arc::clone(&self.miss_coalescer), key, flight)`
guard at mod.rs:3188, then resolves against the backend and completes the
guard) or `resolve_coalesced_follower` (mod.rs:3219, waits on the shared
`InFlightMiss`). All three currently key on the full `CacheKey`.

### `serialize_cached_response` on `ProtocolCodec` (trait at mod.rs:4387-4393, impl at mod.rs:4228-4256, test double at mod.rs:8200-8213)

```rust
pub trait ProtocolCodec: Send + Sync {
    // ...
    fn serialize_cached_response(&self, query: &DecodedQuery, cached: &CachedResponse,
        now: SystemTime, allow_udp_truncation: bool) -> crate::protocol::Result<Vec<u8>>;
}
```

`StandardProtocolCodec`'s implementation (mod.rs:4228-4256) does the
template-clone, `rewrite_response_request_fields`, `age_response_ttls`,
`cap_response_ttls`, and UDP-truncation-check work that section-06's
`assemble_response` replaces (per plan §7's note: "the TTL-aging,
transaction-ID-rewriting, and truncation-decision logic already run per-hit
today; what's new is that record-to-wire serialization also becomes
per-hit"). `assemble_response` takes raw `RRsetEntry`/`NegativeEntry` data,
not a `CachedResponse` template, so this trait method's signature can no
longer be satisfied the old way.

### `DnsCache` trait and `NoopDnsCache` (mod.rs:4435-4451)

```rust
pub trait DnsCache: Send + Sync {
    fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup>;
    fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()>;
}
pub struct NoopDnsCache;
impl DnsCache for NoopDnsCache {
    fn lookup<'a>(&'a self, _r: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> { Box::pin(async { CacheLookup::Miss }) }
    fn store<'a>(&'a self, _e: CacheStore) -> BoxFuture<'a, ()> { Box::pin(async {}) }
}
```

`InMemoryDnsCache` (`impl DnsCache for InMemoryDnsCache`, mod.rs:5489) is
the concrete type this whole rework replaces; it is **out of scope to
delete** in this section (section-08 handles migrating/deleting its
tests) but this section must stop constructing it anywhere in production
code (`main.rs`) and test infra (`tests/recursive_perf.rs`) that this
section owns.

### `main.rs` cache construction and metrics (main.rs:46, 105, 793-863)

```rust
const DEFAULT_CACHE_ENTRIES: usize = 10_000;
// ...
let cache = Arc::new(InMemoryDnsCache::new(DEFAULT_CACHE_ENTRIES));
let (metrics, metrics_registry) = if !config.metrics.enabled {
    (Arc::new(NoopMetrics), Registry::new())
} else {
    match OpenTelemetryMetrics::new(Arc::clone(&cache)) { /* ... */ }
};
// ...
let resolver = Arc::new(ResolveQuery::with_cache_policy_and_backend_snapshot(
    Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
    Arc::clone(&cache) as Arc<dyn DnsCache>,
    // ...
));
```

```rust
struct OpenTelemetryMetrics {
    // ...
    _cache_size_gauge: ObservableGauge<u64>,
    _cache_capacity_gauge: ObservableGauge<u64>,
}
impl OpenTelemetryMetrics {
    fn new(cache: Arc<InMemoryDnsCache>) -> Result<Self, String> {
        // ...
        let cache_size_gauge = meter.u64_observable_gauge("cache_size")
            .with_callback(move |observer| observer.observe(cache_for_size.len() as u64, &[])).build();
        let cache_capacity_gauge = meter.u64_observable_gauge("cache_capacity")
            .with_callback(move |observer| observer.observe(cache.capacity() as u64, &[])).build();
        // ...
    }
}
```

### `Config::backend_cache_namespace` / reload path (config/mod.rs:218-242, main.rs:602-628, mod.rs:2768-2780)

`Config::backend_cache_namespace(&self) -> String` (config/mod.rs:218) is
unchanged by this rework — it still computes a namespace string from
resolution mode/generation/root-hints/dnssec-mode/authority-set-hash.
`main.rs`'s `apply_reload_result` (main.rs:605-628) currently just calls
`resolver.publish_reload(backend_snapshot, local_entries)`
(main.rs:617); `ResolveQuery::publish_reload` (mod.rs:2771-2780) publishes
the new `BackendSnapshot` (which already carries `cache_namespace:
Option<String>` computed via `config.backend_cache_namespace()`, see
main.rs:646-666/709) and the new local entries under one write-guard, with
no cache-sweep call at all today.

### `RuntimeConfig` (config/mod.rs:30-40) and its constructors

```rust
pub struct RuntimeConfig {
    pub dns_listen: Vec<SocketAddr>,
    pub resolution: ResolutionConfig,
    pub upstreams: Vec<UpstreamConfig>,
    pub per_query_deadline: Duration,
    pub max_udp_payload_size: usize,
    pub max_tcp_connections: usize,
    pub local_dns_entries: Vec<LocalDnsEntryConfig>,
    pub local_zones: Vec<LocalZoneConfig>,
    pub metrics: MetricsConfig,
    // no cache field yet
}
```

Three places construct `RuntimeConfig` as a literal: `new_with_resolution`
(config/mod.rs:63-83), `development_default` (config/mod.rs:85-107), and
the `TryFrom<RawRuntimeConfig> for RuntimeConfig` impl
(config/mod.rs:1484-1529+, fed by `RawRuntimeConfig` at
config/mod.rs:1177-1193 and `from_toml_str`, config/mod.rs:109-115). No
other production code builds a `RuntimeConfig` literal — everywhere else
(`main.rs`, `tests/recursive_perf.rs`, `tests/forwarding.rs`, etc.) calls
one of these constructors, so only these three sites need editing for the
new field.

### `tests/recursive_perf.rs:141-152`

```rust
fn resolver_with_cache(config: &RuntimeConfig) -> ResolveQuery {
    ResolveQuery::with_cache(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(InMemoryDnsCache::new(256)),
        CacheTtlPolicy::default(),
        recursive_backend(config),
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(NoopEvents),
        Arc::new(NoopMetrics),
    )
}
```

## Implementation

### 1. `DomainDnsCache` trait (new file or `src/resolver/cache/mod.rs`)

Per plan §9.0, exact method names/signatures below are required surface,
not prescriptive Rust syntax details (async-trait vs. `BoxFuture` is the
implementer's call — match whatever pattern section-04's
`ShardedSingleFlight` and section-06's `resolve_from_cache` already use,
since `lookup_chain` calls straight into `resolve_from_cache` and
`resolve_from_cache`'s signature in the plan is synchronous, taking `now:
SystemTime` rather than doing its own clock read — keep `lookup_chain`
synchronous too unless section-06 made it async for a documented reason):

```rust
pub trait DomainDnsCache: Send + Sync {
    /// Chain-aware lookup — replaces the old flat `lookup`. Internally
    /// calls resolve_from_cache (section-06).
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
    /// described below.
    fn store_response(&self, decomposed: DecomposedResponse, namespace: &str);

    /// Runs the section-05 sweep; called from the reload path.
    fn sweep_stale_namespace(&self, current_namespace: &str);

    /// Approximate (sum-across-shards, no single lock) domain count, for
    /// the OpenTelemetryMetrics gauges below.
    fn domain_count(&self) -> usize;

    fn capacity(&self) -> usize;
}
```

`ShardedDnsCache` (section-06's top-level type) implements this trait.
Add a `NoopDnsCache`-equivalent (reuse the name `NoopDnsCache` — see the
"why the ~13 existing call sites don't need editing" note above) whose
`lookup_chain` always returns `ChainLookup::Miss`, `store_response`/
`sweep_stale_namespace` are no-ops, and `domain_count`/`capacity` return
`0`.

Remove the old `DnsCache` trait (mod.rs:4435-4439) and its `NoopDnsCache`
impl (mod.rs:4441-4451) — replaced by the above.

### 2. `DecomposedResponse`: new type owned by this section

Nothing upstream defines the shape `store_response` consumes — this
section must define it, since it is purely a call-site concern (how a
backend `Message` gets decomposed before being handed to the cache), not
cache-internal logic. Minimal required shape, per plan §9.1's
`cache_store_for_response` description:

```rust
/// One backend response, decomposed into what the sharded cache actually
/// stores: an RRsetEntry per (name, qtype, qclass) that was actually
/// present in the answer (every CNAME hop's own RRset included), plus,
/// if the terminal result was negative, a single NegativeEntry for that
/// terminal name. These are not mutually exclusive — see
/// `store_response_persists_cname_hop_and_terminal_negative_together`.
struct DecomposedResponse {
    positive: Vec<(String, u16, u16, RRsetEntry)>, // (name, qtype, qclass, entry)
    negative: Option<(String, NegativeEntry)>,      // (terminal name, entry)
}
```

Building a `DecomposedResponse` from a backend `Message` is this section's
rewrite of `cache_store_for_response` (§4 below) — reuse
`CacheTtlPolicy::ttl_for_response` (mod.rs:649-712, unchanged) and
`negative_covered_name`'s existing CNAME-chain-walking logic
(mod.rs:780-796, unchanged) rather than re-deriving either.

### 3. `probe_cache` rewrite

Replace the `CacheKey`/`self.cache.lookup(&CacheLookupRequest {..})` call
with:

```rust
let namespace = backend_snapshot.cache_namespace.clone().unwrap_or_default();
let chain_lookup = self.cache.lookup_chain(
    &decoded.question.qname,
    decoded.question.qtype,
    decoded.question.qclass,
    &namespace,
    request.received_at.0,
);
```

`evaluate_cache_lookup`'s `CacheLookup::Hit(cached) =>
self.serialize_cache_hit(...)` branch becomes a match on `ChainLookup`
(`Answered`/`NxDomain`/`NoData` => call `assemble_response` with
`decoded.question_wire`, a `QueryFeatures`-equivalent built from
`decoded.features`, the resolved data, `now`, and
`!request.observed_source.is_tcp()`; `Miss` => the existing miss path).
`CacheProbe.key: Option<CacheKey>` becomes whatever minimal identifier
`resolve_coalesced_miss` and the later store call need to re-run the
lookup key and single-flight key — `(String, u16, u16)` (normalized name,
qtype, qclass) is sufficient and matches section-04's single-flight key
type directly; a dedicated small struct wrapping the same three fields is
an equally acceptable, purely cosmetic choice. `event_cache_result`
mapping (`Bypass`/`Hit`/`Miss`/`Expired`/`Unavailable`) is unchanged in
meaning — only what produces each variant changes.

`serialize_cache_hit` (mod.rs:3491-3515) stops calling
`self.protocol.serialize_cached_response(...)` and instead calls
`resolver::cache::assemble_response` directly; the
`ResolverMetric::CacheExpired`/`CacheHit`/`CacheNegativeHit`/
`CacheResponseTruncated` bookkeeping around it is unchanged in behavior
(still driven by the same conditions — entry expired at lookup time,
served a negative result, produced a truncated wire response — just
sourced from the new return shapes instead of `CachedResponse`).

### 4. `cache_store_for_response` rewrite

Replace `CacheStore { key, response_template, .. }` construction with
building a `DecomposedResponse` from `response: &Message` and calling
`self.cache.store_response(decomposed, &namespace)`. The per-CNAME-hop
walk needed to populate `DecomposedResponse.positive` should reuse
`negative_covered_name`'s existing chain-walking pattern (mod.rs:780-796)
rather than re-deriving it — that function already knows how to follow
`response.answers`' CNAME records from the query name to the terminal
name; this section needs the equivalent walk but collecting each hop's
own RRset (not just the terminal covered name). `store_cache_response`
(mod.rs:3663-3686)'s metrics bookkeeping (`CacheNegativeStore`,
`CacheStore`, `CacheStoreSkipped`) is unchanged in trigger conditions.

### 5. Single-flight call sites

- `ResolveQuery.miss_coalescer: Arc<SingleFlightMisses>` becomes
  `Arc<ShardedSingleFlight>` (section-04's type name — use whatever
  section-04 actually settled on).
- `resolve_coalesced_miss`/`resolve_coalesced_leader`/
  `resolve_coalesced_follower` (mod.rs:3131-3280) stop threading a
  `CacheKey` through and instead thread `(name: String, qtype: u16,
  qclass: u16)` — the same identifier `probe_cache` now returns in
  `CacheProbe`.
- `self.miss_coalescer.begin(cache_key.clone())` becomes
  `self.miss_coalescer.begin((name.clone(), qtype, qclass))` (or
  section-04's equivalent constructor for its key type).
- `SingleFlightLeader::new(Arc::clone(&self.miss_coalescer), key, flight)`
  — same shape, new key type.

### 6. `ProtocolCodec::serialize_cached_response` removal

Remove `serialize_cached_response` from the `ProtocolCodec` trait
(mod.rs:4387-4393) and its implementation on `StandardProtocolCodec`
(mod.rs:4228-4256) — its logic (template clone,
`rewrite_response_request_fields`, `age_response_ttls`,
`cap_response_ttls`, truncation check) is superseded by
`assemble_response` (section-06), which callers now invoke directly (see
§3 above) rather than through the codec trait. `rewrite_response_id`, the
other `ProtocolCodec` methods, and `age_response_ttls`/`cap_response_ttls`
themselves (the free functions, not the trait method) are **not**
removed — `assemble_response` (section-06) is documented to reuse them
directly, not reimplement their logic.

Note for the implementer: removing a trait method breaks every `impl
ProtocolCodec for ...` block that previously implemented it, including
the `OwnedOnlyProtocolCodec` test double at mod.rs:8164-8214. Per the
"Expected transitional state" note above, fixing that test double is
acceptable to leave for section-08 if it's entangled with other
test-only cache types; if it's a trivial one-line removal (deleting the
now-nonexistent trait-method override), doing it here to keep
`cargo build --tests` closer to green is a reasonable judgment call
either way.

### 7. `main.rs` cache construction and `OpenTelemetryMetrics`

```rust
let cache = Arc::new(ShardedDnsCache::new(config.cache.clone())); // section-06's constructor, config-driven
let (metrics, metrics_registry) = if !config.metrics.enabled {
    (Arc::new(NoopMetrics), Registry::new())
} else {
    match OpenTelemetryMetrics::new(Arc::clone(&cache)) { /* unchanged shape */ }
};
// ...
let resolver = Arc::new(ResolveQuery::with_cache_policy_and_backend_snapshot(
    Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
    Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
    // ...
));
```

Delete `const DEFAULT_CACHE_ENTRIES: usize = 10_000;` (main.rs:46) — its
value moves to `CacheConfig::default()` (section-01), and the
`main.rs`-level constant becomes redundant/dead. `OpenTelemetryMetrics::new`'s
parameter type changes from `Arc<InMemoryDnsCache>` to whatever
`ShardedDnsCache` is concretely named (or `Arc<dyn DomainDnsCache>`, if
preferring trait-object flexibility — either is acceptable, since only
`domain_count()`/`capacity()` are needed). The two gauge callbacks change
from `cache.len()`/`cache.capacity()` to `cache.domain_count()`/
`cache.capacity()`; per plan §9.1, this makes the gauge an
eventually-consistent approximation under concurrent mutation rather than
an exact point-in-time read (the same tradeoff DashMap's `len()` makes) —
note this in the gauge's help text if the OpenTelemetry builder API
supports setting one, but no other workaround is needed.

### 8. Namespace-sweep reload hook

Per plan §9.1's `Config::backend_cache_namespace` entry, wire the
already-computed namespace into a `sweep_stale_namespace` call on reload.
The natural location is inside `ResolveQuery::publish_reload`
(mod.rs:2771-2780), since it already holds `snapshot.cache_namespace` and
`self.cache` at the same point:

```rust
pub fn publish_reload(&self, snapshot: BackendSnapshot, entries: Arc<dyn LocalDnsEntries>) {
    let _gate = self.reload_gate.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    let status = snapshot.status();
    if let Some(namespace) = snapshot.cache_namespace.clone() {
        self.cache.sweep_stale_namespace(&namespace);
    }
    self.backend.publish(snapshot);
    self.local_entries.publish(entries);
    self.metrics.record_backend_status(&status);
}
```

Whether the sweep runs before or after `self.backend.publish(snapshot)`
is an implementer's call with one constraint: it must happen while still
holding `reload_gate` (so a concurrent reader can't observe the new
namespace published but stale entries not yet swept — though note the
sweep itself does not need `reload_gate`'s protection *during* its own
per-shard locking, only the "don't publish the new namespace without
also triggering the sweep" ordering needs the gate). `main.rs`'s
`apply_reload_result` (main.rs:605-628) needs no changes under this
approach — it already calls `resolver.publish_reload(...)` and that's
sufficient. (Doing the sweep call from `main.rs` directly instead,
alongside its own `cache` handle, is an equally valid alternative if the
implementer prefers keeping `ResolveQuery` unaware of sweep timing — pick
one and be consistent; the test in §9 below (`backend_reload_sweep_invalidates_stale_generation_entries`)
should pass either way.)

### 9. `CacheConfig` wiring into `RuntimeConfig`

Add the field:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    // ... existing fields unchanged ...
    pub metrics: MetricsConfig,
    pub cache: CacheConfig, // new
}
```

Update the three construction sites:

- `RuntimeConfig::new_with_resolution` (config/mod.rs:63-83) and
  `RuntimeConfig::development_default` (config/mod.rs:85-107): add
  `cache: CacheConfig::default()` to each struct literal (section-01's
  `CacheConfig` should implement `Default`, matching
  `cache_config_defaults_preserve_current_max_entries`'s expectation of
  an unconfigured `CacheConfig` yielding `max_entries == 10_000`; if it
  doesn't implement `Default`, use the explicit equivalent literal
  instead).
- TOML parsing path (config/mod.rs:1175-1529): follow the exact pattern
  `metrics`/`RawMetricsConfig` already uses —

  ```rust
  #[derive(Debug, Deserialize)]
  #[serde(deny_unknown_fields)]
  struct RawRuntimeConfig {
      // ... existing fields ...
      #[serde(default)]
      cache: Option<RawCacheConfig>,
  }

  #[derive(Debug, Deserialize)]
  #[serde(deny_unknown_fields)]
  struct RawCacheConfig {
      #[serde(default = "default_cache_max_entries")]
      max_entries: usize,
      #[serde(default)]
      shard_count: Option<usize>,
  }

  fn default_cache_max_entries() -> usize { 10_000 } // matches CacheConfig::default()

  impl RawCacheConfig {
      fn try_into_cache_config(self) -> Result<CacheConfig, ConfigError> {
          Ok(CacheConfig { max_entries: self.max_entries, shard_count: self.shard_count })
      }
  }
  ```

  Then in `TryFrom<RawRuntimeConfig> for RuntimeConfig`
  (config/mod.rs:1484+), alongside the existing `let metrics = raw.metrics
  .map(RawMetricsConfig::try_into_metrics_config).transpose()?
  .unwrap_or_else(MetricsConfig::default_enabled);` pattern:

  ```rust
  let cache = raw.cache
      .map(RawCacheConfig::try_into_cache_config)
      .transpose()?
      .unwrap_or_default();
  ```

  and add `cache,` to the final `RuntimeConfig { ... }` literal
  (config/mod.rs:1519+).

`main.rs` passes `config.cache.clone()` (or `config.cache` if `Copy`, but
`CacheConfig` likely isn't since `shard_count: Option<usize>` is fine as
`Copy` actually — either is acceptable) into the `ShardedDnsCache`
constructor from §7 above, replacing the hardcoded
`DEFAULT_CACHE_ENTRIES`.

`ShardedSingleFlight`'s shard count (section-04) should be derived from
the same `config.cache.shard_count` resolution the cache itself uses —
either by having `ShardedDnsCache::new` expose its resolved shard count
(e.g. a `shard_count()` accessor) for `ResolveQuery`'s constructor to
pass along to `ShardedSingleFlight::new`, or by having both independently
call the same shard-count-resolution helper from section-01 with the same
`config.cache.shard_count` input — either approach is fine as long as the
cache and the single-flight structure end up with the *same* shard count
(not a correctness requirement per se, since they're independent
structures, but keeping them consistent avoids surprising a future reader
who assumes "shard N" means the same thing in both).

### 10. `tests/recursive_perf.rs` helper

```rust
fn resolver_with_cache(config: &RuntimeConfig) -> ResolveQuery {
    ResolveQuery::with_cache(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(ShardedDnsCache::new(CacheConfig { max_entries: 256, shard_count: None })),
        CacheTtlPolicy::default(),
        recursive_backend(config),
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(NoopEvents),
        Arc::new(NoopMetrics),
    )
}
```

Preserves the existing `256`-entry benchmark sizing; only the
constructor call changes. This is explicitly called out in
`claude-plan-tdd.md` §9 (`recursive_perf_bench_constructs_sharded_cache`)
as "the missed call site from the Codex review" — easy to forget since
it's a test helper, not production code, but `tests/recursive_perf.rs`
won't compile without this change once `InMemoryDnsCache` stops being
constructible the old way in this section's other edits (it doesn't stop
existing — `InMemoryDnsCache` itself is untouched by this section — but
`ResolveQuery::with_cache`'s parameter type change from `Arc<dyn
DnsCache>` to `Arc<dyn DomainDnsCache>` means `Arc::new(InMemoryDnsCache::new(256))`
no longer type-checks there).

## Tests to write first

These exercise the cache through the resolver's public `resolve()` path
and the config-parsing path — write them before doing the rewiring above,
even though (per the "Expected transitional state" note) the broader
`mod.rs` test module may not fully compile until section-08. These new
tests should live in whichever test module they naturally belong to
(`src/resolver/mod.rs`'s existing `#[cfg(test)] mod tests` for the
resolve-path ones, `src/config/mod.rs`'s test module for the config-wiring
one) and should compile and pass on their own once this section's
production code exists, independent of whether other pre-existing tests
in the same file are currently broken:

- `resolve_returns_assembled_response_for_current_request_id` —
  replacement for `resolve_returns_cached_template_with_current_request_id`;
  a cache hit's assembled response carries the *current* request's
  transaction ID, not a stale/reused one.
- `resolve_rewrites_rd_flag_for_current_request_on_cache_hit` — port of
  `resolve_rewrites_cached_response_rd_flag_for_current_request` against
  the new assembly path.
- `resolve_blocks_cached_response_with_malicious_cname_target` and
  `resolve_blocks_coalesced_cache_hit_with_malicious_cname_target` —
  direct ports; malicious-CNAME-target blocking must still apply after
  response assembly moves to serve time — both the direct-hit and
  coalesced-miss paths.
- `backend_reload_sweep_invalidates_stale_generation_entries` —
  replacement for `backend_generation_separates_cache_entries`; after a
  simulated `publish_reload` with a changed `cache_namespace`, previously
  cached entries under the old namespace are actually gone (not just
  unreachable) — verifies `sweep_stale_namespace` is wired into the
  reload path (§8 above), not just unit-tested in isolation
  (section-05's tests only prove the sweep function itself is correct
  against hand-built shard state; this test proves it's actually called).
- `open_telemetry_cache_gauges_report_approximate_domain_count` — the
  `main.rs` metrics construction (§7 above) compiles against the new
  cache type and its gauge callback reads `domain_count()`/`capacity()`
  without holding a single global lock; assert the gauge's value is
  within the expected range under concurrent mutation (exact equality
  isn't guaranteed — assert "plausible," not "exact," per the documented
  approximate-under-sharding tradeoff).
- `recursive_perf_bench_constructs_sharded_cache` —
  `tests/recursive_perf.rs`'s `resolver_with_cache` helper (§10 above)
  compiles and runs against the new cache type.
- New, not in the original TDD list but implied by §9 above (config
  wiring has no dedicated TDD subsection of its own — it's covered by
  section-01's `cache_config_*` tests for the `CacheConfig` type itself,
  but not for `RuntimeConfig` actually carrying one): a test in
  `src/config/mod.rs`'s test module asserting that
  `RuntimeConfig::from_toml_str` with no `[cache]` table present yields
  `RuntimeConfig.cache == CacheConfig::default()`, and that a `[cache]`
  table with `max_entries`/`shard_count` set is parsed into the
  corresponding `CacheConfig` fields — follow the existing
  `RawMetricsConfig`-parsing tests in the same file as the pattern to
  mirror.

## File paths touched by this section

- `src/resolver/cache/mod.rs` (or wherever section-01 put the module
  root) — `DomainDnsCache` trait, `DecomposedResponse`, the
  `ShardedDnsCache` trait impl, the no-op cache impl.
- `src/resolver/mod.rs` — `probe_cache`, `evaluate_cache_lookup`,
  `serialize_cache_hit`, `store_cache_response`,
  `cache_store_for_response`, `resolve_coalesced_miss`/
  `resolve_coalesced_leader`/`resolve_coalesced_follower`, `CacheProbe`,
  `ResolveQuery` struct and its `with_cache*`/`new` constructors,
  `ProtocolCodec` trait and `StandardProtocolCodec`'s impl (removing
  `serialize_cached_response`), `DnsCache` trait removal, `NoopDnsCache`'s
  trait impl, `publish_reload`. Deletion of the old flat types
  (`CacheKey`, `CacheLookupRequest`, `CacheLookup`, `CachedResponse`,
  `CacheStore`) — but **not** `NegativeCacheMetadata`, `negative_ttl`,
  `negative_covered_name`, `CacheTtlPolicy`, `QueryFeatures`, or
  `age_response_ttls`/`cap_response_ttls`, all of which survive unchanged
  or are reused by section-06.
- `src/main.rs` — cache construction (deleting
  `DEFAULT_CACHE_ENTRIES`), `OpenTelemetryMetrics::new`'s signature and
  gauge callbacks, the `resolver` construction's cache-argument cast.
- `src/config/mod.rs` — `RuntimeConfig.cache` field,
  `new_with_resolution`/`development_default`, `RawRuntimeConfig`/
  `RawCacheConfig`, the `TryFrom<RawRuntimeConfig>` impl.
- `tests/recursive_perf.rs` — `resolver_with_cache` helper.

## Notes for the implementer

- This section changes a large number of function signatures across a
  single very large file (`mod.rs`); expect a wide, shallow diff rather
  than deep new logic — that is the intended nature of "call-site
  migration."
- Do not add DNSSEC validation, prefetch, or byte-size bounds here — none
  of that is in scope for this rework (plan's "out of scope" list); this
  section only rewires existing behavior onto the new cache shape.
- If any call site's exact required shape is ambiguous from this
  document (e.g. whether `CacheProbe`'s replacement identifier is a
  bare tuple or a named struct), prefer whatever section-04's
  `ShardedSingleFlight` key type already is — reusing the same type in
  both places avoids an unnecessary conversion at the single-flight
  call sites in §5.
- Keep `sweep_stale_namespace`'s call (§8) to exactly once per
  `publish_reload`, not once per request — the whole point of the
  explicit-sweep design (plan §5) is that it is a bounded, reload-triggered
  cost, not a per-lookup one.