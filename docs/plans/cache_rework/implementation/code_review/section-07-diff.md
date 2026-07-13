diff --git a/src/config/mod.rs b/src/config/mod.rs
index e70d62b..6f4b795 100644
--- a/src/config/mod.rs
+++ b/src/config/mod.rs
@@ -37,6 +37,7 @@ pub struct RuntimeConfig {
     pub local_dns_entries: Vec<LocalDnsEntryConfig>,
     pub local_zones: Vec<LocalZoneConfig>,
     pub metrics: MetricsConfig,
+    pub cache: CacheConfig,
 }
 
 /// Default ceiling on concurrent TCP DNS connections per listener. Shared
@@ -77,6 +78,7 @@ impl RuntimeConfig {
             local_dns_entries: Vec::new(),
             local_zones: Vec::new(),
             metrics: MetricsConfig::default_enabled(),
+            cache: CacheConfig::default(),
         };
         config.validate()?;
         Ok(config)
@@ -103,6 +105,7 @@ impl RuntimeConfig {
             local_dns_entries: Vec::new(),
             local_zones: Vec::new(),
             metrics: MetricsConfig::default_enabled(),
+            cache: CacheConfig::default(),
         }
     }
 
@@ -1252,6 +1255,8 @@ struct RawRuntimeConfig {
     local_zones: Vec<RawLocalZoneConfig>,
     #[serde(default)]
     metrics: Option<RawMetricsConfig>,
+    #[serde(default)]
+    cache: Option<RawCacheConfig>,
 }
 
 #[derive(Debug, Deserialize)]
@@ -1277,6 +1282,28 @@ fn default_max_tcp_connections() -> usize {
     DEFAULT_MAX_TCP_CONNECTIONS
 }
 
+#[derive(Debug, Deserialize)]
+#[serde(deny_unknown_fields)]
+struct RawCacheConfig {
+    #[serde(default = "default_cache_max_entries")]
+    max_entries: usize,
+    #[serde(default)]
+    shard_count: Option<usize>,
+}
+
+fn default_cache_max_entries() -> usize {
+    CacheConfig::default().max_entries
+}
+
+impl RawCacheConfig {
+    fn try_into_cache_config(self) -> Result<CacheConfig, ConfigError> {
+        Ok(CacheConfig {
+            max_entries: self.max_entries,
+            shard_count: self.shard_count,
+        })
+    }
+}
+
 impl RawMetricsConfig {
     fn try_into_metrics_config(self) -> Result<MetricsConfig, ConfigError> {
         Ok(MetricsConfig {
@@ -1577,6 +1604,11 @@ impl TryFrom<RawRuntimeConfig> for RuntimeConfig {
             .map(RawMetricsConfig::try_into_metrics_config)
             .transpose()?
             .unwrap_or_else(MetricsConfig::default_enabled);
+        let cache = raw
+            .cache
+            .map(RawCacheConfig::try_into_cache_config)
+            .transpose()?
+            .unwrap_or_default();
 
         let config = RuntimeConfig {
             dns_listen,
@@ -1588,6 +1620,7 @@ impl TryFrom<RawRuntimeConfig> for RuntimeConfig {
             local_dns_entries,
             local_zones,
             metrics,
+            cache,
         };
         config.validate()?;
         Ok(config)
diff --git a/src/main.rs b/src/main.rs
index d1ae0e5..a8b7a97 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -31,19 +31,18 @@ use rdns::delivery::metrics_http::MetricsServer;
 use rdns::delivery::upstream::{ForwardingResolutionBackend, RecursiveAuthorityTransportClient};
 use rdns::resolver::{
     BackendHealth, BackendRootHintsStatus, BackendSnapshot, BackendStatus, BasicResponseFactory,
-    CacheTtlPolicy, ChannelQueryEventSink, Clock, DnsCache, DnssecValidationStatus, DomainName,
-    InMemoryDnsCache, InMemoryLocalDnsEntries, InMemoryQueryEventStore,
-    InMemoryQueryEventStoreConfig, InMemorySuspiciousLookupClassifier,
-    InMemorySuspiciousLookupClassifierConfig, LocalDnsEntry, MetricsSink, NoopPolicyEvaluator,
-    QueryEventRecordResult, QueryEventSink, QueryEventV1, RecursiveResolutionBackend,
-    RecursiveResolverConfig, RecursiveRootHint, ResolutionMode as ResolverResolutionMode,
-    ResolveQuery, ResolverMetric, StandardProtocolCodec,
+    CacheTtlPolicy, ChannelQueryEventSink, Clock, DnssecValidationStatus, DomainDnsCache,
+    DomainName, InMemoryLocalDnsEntries, InMemoryQueryEventStore, InMemoryQueryEventStoreConfig,
+    InMemorySuspiciousLookupClassifier, InMemorySuspiciousLookupClassifierConfig, LocalDnsEntry,
+    MetricsSink, NoopPolicyEvaluator, QueryEventRecordResult, QueryEventSink, QueryEventV1,
+    RecursiveResolutionBackend, RecursiveResolverConfig, RecursiveRootHint,
+    ResolutionMode as ResolverResolutionMode, ResolveQuery, ResolverMetric, ShardedDnsCache,
+    StandardProtocolCodec,
 };
 use tokio::task::{JoinError, JoinSet};
 use tracing::{error, info, warn};
 use tracing_subscriber::EnvFilter;
 
-const DEFAULT_CACHE_ENTRIES: usize = 10_000;
 const DEFAULT_QUERY_EVENT_STORE_ENTRIES: usize = 10_000;
 const QUERY_EVENT_QUEUE_CAPACITY: usize = 1024;
 const CONFIG_PATH_ENV_VAR: &str = "RDNS_CONFIG";
@@ -102,7 +101,7 @@ async fn main() -> io::Result<()> {
         })
     };
 
-    let cache = Arc::new(InMemoryDnsCache::new(DEFAULT_CACHE_ENTRIES));
+    let cache = Arc::new(ShardedDnsCache::new(&config.cache));
     let (metrics, metrics_registry): (Arc<dyn MetricsSink>, Registry) = if !config.metrics.enabled {
         (Arc::new(NoopMetrics), Registry::new())
     } else {
@@ -121,21 +120,31 @@ async fn main() -> io::Result<()> {
     let (local_entries, local_entry_counts) = build_local_entries(&config, config_path.as_deref())?;
     info!(summary = %local_entry_summary(&local_entry_counts), "loaded local dns entries");
     let reload_metrics = Arc::clone(&metrics);
-    let resolver = Arc::new(ResolveQuery::with_cache_policy_and_backend_snapshot(
-        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
-        Arc::clone(&cache) as Arc<dyn DnsCache>,
-        Arc::new(NoopPolicyEvaluator),
-        local_entries,
-        CacheTtlPolicy::default(),
-        backend_snapshot,
-        Arc::new(BasicResponseFactory),
-        Arc::new(SystemClock),
-        Arc::new(StoreRecordingQueryEventSink::new(
-            ChannelQueryEventSink::new(event_tx),
-            Arc::clone(&query_event_store),
-        )),
-        metrics,
-    ));
+    let max_chain_depth = config
+        .resolution
+        .recursive
+        .as_ref()
+        .map(|recursive| recursive.max_cname_restarts)
+        .unwrap_or(8);
+    let resolver = Arc::new(
+        ResolveQuery::with_cache_policy_and_backend_snapshot(
+            Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(NoopPolicyEvaluator),
+            local_entries,
+            CacheTtlPolicy::default(),
+            backend_snapshot,
+            Arc::new(BasicResponseFactory),
+            Arc::new(SystemClock),
+            Arc::new(StoreRecordingQueryEventSink::new(
+                ChannelQueryEventSink::new(event_tx),
+                Arc::clone(&query_event_store),
+            )),
+            metrics,
+        )
+        .with_max_chain_depth(max_chain_depth)
+        .with_single_flight_shard_count(cache.shard_count()),
+    );
 
     let sighup_task =
         spawn_sighup_reload_task(Arc::clone(&resolver), reload_metrics, config_path.clone());
@@ -839,7 +848,7 @@ struct OpenTelemetryMetrics {
 }
 
 impl OpenTelemetryMetrics {
-    fn new(cache: Arc<InMemoryDnsCache>) -> Result<Self, String> {
+    fn new(cache: Arc<ShardedDnsCache>) -> Result<Self, String> {
         let registry = Registry::new();
         // Our counter instrument names already end in `_total` (chosen to read
         // correctly as Prometheus metric names directly); without this, the
@@ -852,10 +861,16 @@ impl OpenTelemetryMetrics {
         let provider = SdkMeterProvider::builder().with_reader(exporter).build();
         let meter = provider.meter("rdns.resolver");
 
+        // `domain_count()`/`capacity()` sum across shards without a single
+        // global lock, so under concurrent mutation this gauge is an
+        // eventually-consistent approximation, not an exact
+        // point-in-time read (the same tradeoff DashMap's `len()` makes).
         let cache_for_size = Arc::clone(&cache);
         let cache_size_gauge = meter
             .u64_observable_gauge("cache_size")
-            .with_callback(move |observer| observer.observe(cache_for_size.len() as u64, &[]))
+            .with_callback(move |observer| {
+                observer.observe(cache_for_size.domain_count() as u64, &[])
+            })
             .build();
         let cache_capacity_gauge = meter
             .u64_observable_gauge("cache_capacity")
diff --git a/src/resolver/cache/assemble.rs b/src/resolver/cache/assemble.rs
index f0fa01a..69f4a89 100644
--- a/src/resolver/cache/assemble.rs
+++ b/src/resolver/cache/assemble.rs
@@ -41,7 +41,7 @@ const CNAME_RECORD_TYPE: u16 = 5;
 /// the original qtype — or, if qtype == CNAME itself, exactly one hop (the
 /// CNAME's own entry, no further walking past it).
 #[derive(Debug, Clone, PartialEq, Eq)]
-pub(crate) struct ResolvedAnswer {
+pub struct ResolvedAnswer {
     pub(crate) chain: Vec<(String, RRsetEntry)>, // (owner name, entry), in walk order
 }
 
@@ -58,14 +58,14 @@ pub(crate) struct ResolvedAnswer {
 /// `assemble_negative_response` needs this to know what name to write the
 /// authority-section SOA (and any proof records) under.
 #[derive(Debug, Clone, PartialEq, Eq)]
-pub(crate) struct ResolvedNegative {
+pub struct ResolvedNegative {
     pub(crate) chain: Vec<(String, RRsetEntry)>,
     pub(crate) terminal_name: String,
     pub(crate) negative: NegativeEntry,
 }
 
 #[derive(Debug, Clone, PartialEq, Eq)]
-pub(crate) enum ChainLookup {
+pub enum ChainLookup {
     /// Every name in the chain was found, unexpired, in the current
     /// namespace.
     Answered(ResolvedAnswer),
diff --git a/src/resolver/cache/entry.rs b/src/resolver/cache/entry.rs
index 30967e2..95b37d7 100644
--- a/src/resolver/cache/entry.rs
+++ b/src/resolver/cache/entry.rs
@@ -40,7 +40,7 @@ pub(crate) struct DomainRecordSets {
 /// flags are no longer key dimensions — see the wider rework's serve-time
 /// assembly design, implemented in section-06, not this section).
 #[derive(Debug, Clone, PartialEq, Eq)]
-pub(crate) struct RRsetEntry {
+pub struct RRsetEntry {
     pub(crate) records: Vec<StoredRecord>,
     pub(crate) rrsigs: Vec<StoredRecord>, // empty if none were fetched/cached
     // Almost always NoError; kept for parity with today's CachedResponse shape.
@@ -59,7 +59,7 @@ pub(crate) struct RRsetEntry {
 /// time by section-06's assembly logic, not stored here). Reuses the
 /// existing `RecordData` type from `src/protocol`.
 #[derive(Debug, Clone, PartialEq, Eq)]
-pub(crate) struct StoredRecord {
+pub struct StoredRecord {
     pub(crate) rtype: u16,
     pub(crate) rclass: u16,
     pub(crate) ttl_at_store: u32,
@@ -99,7 +99,7 @@ pub(crate) struct DomainNegativeEntries {
 /// itself doesn't exist, independent of any specific qtype. `qtype:
 /// Some(t)` represents NODATA for that specific type at an existing name.
 #[derive(Debug, Clone, PartialEq, Eq, Hash)]
-pub(crate) struct NegativeKey {
+pub struct NegativeKey {
     pub(crate) qtype: Option<u16>,
     pub(crate) qclass: u16,
 }
@@ -109,7 +109,7 @@ pub(crate) struct NegativeKey {
 /// `NegativeCacheMetadata`, this stores the full covering SOA record so a
 /// servable authority section can be rebuilt from `soa_record` alone.
 #[derive(Debug, Clone, PartialEq, Eq)]
-pub(crate) struct NegativeEntry {
+pub struct NegativeEntry {
     pub(crate) kind: NegativeCacheKind, // reuse existing enum: NxDomain | NoData
     /// The covering SOA record itself (owner, RDATA, TTL) — needed to
     /// rebuild the authority section of a servable negative response, not
diff --git a/src/resolver/cache/mod.rs b/src/resolver/cache/mod.rs
index b080183..b759e2a 100644
--- a/src/resolver/cache/mod.rs
+++ b/src/resolver/cache/mod.rs
@@ -24,18 +24,21 @@ mod singleflight;
 
 use std::collections::hash_map::DefaultHasher;
 use std::hash::{Hash, Hasher};
+use std::time::SystemTime;
 
 use shard::Shard;
 
+pub use assemble::ChainLookup;
+pub(crate) use assemble::{
+    ResolvedAnswer, ResolvedNegative, assemble_negative_response, assemble_response,
+};
+pub use entry::{NegativeEntry, NegativeKey, RRsetEntry, StoredRecord};
+pub(crate) use singleflight::{
+    InFlightMiss, ShardedSingleFlight, SingleFlightLeader, SingleFlightTicket,
+};
+
 /// The top-level sharded cache: one `Shard` (its own lock, its own slice
 /// of `max_entries`) per configured shard, routed to by `shard_index`.
-///
-/// Read-side operations (`assemble::resolve_from_cache`,
-/// `assemble::assemble_response`) are built in this section
-/// (section-06). Section-07 adds `impl DomainDnsCache for
-/// ShardedDnsCache` (wrapping those plus `store_response`) and the
-/// call-site wiring that actually constructs and uses one of these.
-#[allow(dead_code)]
 pub struct ShardedDnsCache {
     shards: Vec<Shard>,
 }
@@ -45,7 +48,6 @@ impl ShardedDnsCache {
     /// `config.max_entries` across them via `config.shard_capacity` (the
     /// exact remainder-distributed formula from section-01 — not
     /// recomputed here).
-    #[allow(dead_code)]
     pub fn new(config: &crate::config::CacheConfig) -> Self {
         let shard_count = config.resolved_shard_count();
         let shards = (0..shard_count)
@@ -54,17 +56,122 @@ impl ShardedDnsCache {
         Self { shards }
     }
 
+    /// The number of shards this cache was built with — exposed so
+    /// callers (`ResolveQuery`'s construction, section-07) can build a
+    /// `ShardedSingleFlight` with a matching shard count, keeping "shard
+    /// N" meaning the same domain-routing bucket in both structures.
+    pub fn shard_count(&self) -> usize {
+        self.shards.len()
+    }
+
     /// Routes to the one shard responsible for `domain`, via `shard_index`.
-    /// Kept private/crate-visible: external callers (section-07's trait
-    /// impl, tests) go through `assemble::resolve_from_cache`, except
-    /// where a section-06 test needs to reach into a specific shard to set
-    /// up fixture state directly.
-    #[allow(dead_code)]
+    /// Kept private/crate-visible: external callers (the `DomainDnsCache`
+    /// impl below, tests) go through `assemble::resolve_from_cache` or the
+    /// trait methods, except where a section-06 test needs to reach into a
+    /// specific shard to set up fixture state directly.
     fn shard_for(&self, domain: &str) -> &Shard {
         &self.shards[shard_index(domain, self.shards.len())]
     }
 }
 
+/// One backend response, decomposed into what the sharded cache actually
+/// stores: an `RRsetEntry` per `(name, qtype, qclass)` that was actually
+/// present in the answer (every CNAME hop's own RRset included), plus, if
+/// the terminal result was negative, a single `NegativeEntry` for that
+/// terminal name.
+///
+/// `negative`'s `NegativeKey` is not part of the plan's literal listing
+/// (which only lists `(String, NegativeEntry)`) — added because the key's
+/// `qtype: Option<u16>` (whole-name NXDOMAIN vs. NODATA-for-a-specific-type)
+/// can't be derived from `NegativeEntry` alone; the caller building this
+/// struct (`resolver::mod`'s store-decomposition logic, which already
+/// knows the original query's qtype) supplies it directly instead.
+#[derive(Debug, Clone)]
+pub struct DecomposedResponse {
+    pub positive: Vec<(String, u16, u16, RRsetEntry)>,
+    pub negative: Option<(String, NegativeKey, NegativeEntry)>,
+}
+
+/// Trait boundary between `resolver::mod`'s call sites and the concrete
+/// cache implementation — replaces the old flat `DnsCache` trait
+/// (`lookup`/`store` keyed on a flat `CacheKey`). Implemented by
+/// `ShardedDnsCache` (below) and `NoopDnsCache` (`resolver::mod`, unchanged
+/// name, new trait).
+pub trait DomainDnsCache: Send + Sync {
+    /// Chain-aware lookup — replaces the old flat `lookup`. Internally
+    /// calls `resolve_from_cache` (section-06).
+    ///
+    /// `max_chain_depth` is not in the plan's literal listed trait
+    /// signature — added for the same reason `resolve_from_cache` itself
+    /// needs it (section-06's documented deviation): the depth bound
+    /// (`RecursiveResolverConfig.max_cname_restarts`) isn't reachable from
+    /// this trait's other inputs, so callers thread it through explicitly.
+    fn lookup_chain(
+        &self,
+        qname: &str,
+        qtype: u16,
+        qclass: u16,
+        namespace: &str,
+        max_chain_depth: u8,
+        now: SystemTime,
+    ) -> ChainLookup;
+
+    /// Replaces the old flat `store` — called once per backend response,
+    /// storing the already-decomposed `RRsetEntry`/`NegativeEntry` values.
+    fn store_response(&self, decomposed: DecomposedResponse, namespace: &str);
+
+    /// Runs the section-05 sweep; called from the reload path.
+    fn sweep_stale_namespace(&self, current_namespace: &str);
+
+    /// Approximate (sum-across-shards, no single lock) domain count, for
+    /// the `OpenTelemetryMetrics` gauges.
+    fn domain_count(&self) -> usize;
+
+    fn capacity(&self) -> usize;
+}
+
+impl DomainDnsCache for ShardedDnsCache {
+    fn lookup_chain(
+        &self,
+        qname: &str,
+        qtype: u16,
+        qclass: u16,
+        namespace: &str,
+        max_chain_depth: u8,
+        now: SystemTime,
+    ) -> ChainLookup {
+        assemble::resolve_from_cache(self, qname, qtype, qclass, namespace, max_chain_depth, now)
+    }
+
+    fn store_response(&self, decomposed: DecomposedResponse, namespace: &str) {
+        // Stamps the current namespace onto every entry at store time
+        // (rather than trusting the caller's `DecomposedResponse` to have
+        // already set it correctly) so there is exactly one place that
+        // decides what namespace a freshly-stored entry belongs to.
+        for (name, qtype, qclass, mut entry) in decomposed.positive {
+            entry.cache_namespace = namespace.to_string();
+            self.shard_for(&name)
+                .store_positive(&name, (qtype, qclass), entry);
+        }
+        if let Some((name, key, mut entry)) = decomposed.negative {
+            entry.cache_namespace = namespace.to_string();
+            self.shard_for(&name).store_negative(&name, key, entry);
+        }
+    }
+
+    fn sweep_stale_namespace(&self, current_namespace: &str) {
+        namespace::sweep_stale_namespace(&self.shards, current_namespace);
+    }
+
+    fn domain_count(&self) -> usize {
+        self.shards.iter().map(Shard::domain_count).sum()
+    }
+
+    fn capacity(&self) -> usize {
+        self.shards.iter().map(Shard::capacity).sum()
+    }
+}
+
 /// Routes a domain name to a shard index in `[0, shard_count)`. Shared by
 /// the cache shards (`cache::shard`, section-03) and the single-flight
 /// shards (`cache::singleflight`, section-04) — both structures shard
diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index a66b0a0..4daf649 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -131,6 +131,10 @@ impl Shard {
         }
     }
 
+    pub(crate) fn capacity(&self) -> usize {
+        self.capacity
+    }
+
     /// Stores one positive RRset for `domain` under `(qtype, qclass)`,
     /// evicting the least-recently-touched domain first if this is a new
     /// domain and the shard is already at capacity. A no-op if
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 6521ab9..c5a673f 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -24,20 +24,25 @@ use std::time::{Duration, SystemTime};
 
 use bytes::Bytes;
 use serde::Serialize;
-use tokio::sync::{Notify, mpsc};
+use tokio::sync::mpsc;
 use tokio::task::JoinSet;
 use tokio::time::{self, Instant};
 
 use crate::protocol::{
     EdnsInfo, Message, NameCompressor, QueryValidationError, Record, RecordData, ResponseCode,
-    age_response_ttls, build_a_answers_response, build_a_block_response,
-    build_aaaa_answers_response, build_aaaa_block_response, build_formerr_response,
-    build_nodata_response, build_nxdomain_response, build_refused_response,
-    build_servfail_response, build_truncated_response, cap_response_ttls, message_question_wire,
-    rewrite_response_id, rewrite_response_request_fields,
+    build_a_answers_response, build_a_block_response, build_aaaa_answers_response,
+    build_aaaa_block_response, build_formerr_response, build_nodata_response,
+    build_nxdomain_response, build_refused_response, build_servfail_response,
+    build_truncated_response, message_question_wire, rewrite_response_id,
 };
 
 mod cache;
+use cache::{
+    ChainLookup, DecomposedResponse, InFlightMiss, NegativeEntry, NegativeKey, RRsetEntry,
+    ShardedSingleFlight, SingleFlightLeader, SingleFlightTicket, StoredRecord,
+    assemble_negative_response, assemble_response,
+};
+pub use cache::{DomainDnsCache, ShardedDnsCache};
 
 pub mod policy;
 pub use policy::{
@@ -49,6 +54,21 @@ pub use policy::{
 const EDNS_DO_FLAG: u16 = 0x8000;
 const A_RECORD_TYPE: u16 = 1;
 const AAAA_RECORD_TYPE: u16 = 28;
+/// Default bound for `resolve_from_cache`'s CNAME-chain walk
+/// (`ResolveQuery::max_chain_depth`), matching
+/// `RawResolutionConfig`'s `default_max_cname_restarts`
+/// (`config/mod.rs`). Callers constructing from real config override this
+/// via `ResolveQuery::with_max_chain_depth`.
+const DEFAULT_MAX_CHAIN_DEPTH: u8 = 8;
+/// Default shard count for the `ShardedSingleFlight` a `ResolveQuery`
+/// constructs itself. Matches `CacheConfig::resolved_shard_count()`'s own
+/// fallback (section-01) so a `ResolveQuery` built without an explicit
+/// override still shards its single-flight bookkeeping sensibly; `main.rs`
+/// overrides this via `with_single_flight_shard_count` to match the real
+/// cache's actual shard count once both are constructed.
+fn default_single_flight_shard_count() -> usize {
+    crate::config::CacheConfig::default().resolved_shard_count()
+}
 const MAX_FAILURE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
 const MAX_LOCAL_DNS_TTL: u32 = 24 * 60 * 60;
 const CNAME_RECORD_TYPE: u16 = 5;
@@ -58,7 +78,6 @@ const NSEC_RECORD_TYPE: u16 = 47;
 const NSEC3_RECORD_TYPE: u16 = 50;
 const NSEC3PARAM_RECORD_TYPE: u16 = 51;
 const RRSIG_RECORD_TYPE: u16 = 46;
-const LRU_COMPACTION_MULTIPLIER: usize = 4;
 
 pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
 
@@ -217,45 +236,6 @@ impl QueryFeatures {
     }
 }
 
-#[derive(Debug, Clone, PartialEq, Eq, Hash)]
-pub struct CacheKey {
-    pub question: QuestionKey,
-    pub question_wire: Vec<u8>,
-    pub features: QueryFeatures,
-    pub cache_namespace: Option<String>,
-}
-
-impl CacheKey {
-    pub fn new(
-        question: QuestionKey,
-        question_wire: Vec<u8>,
-        features: QueryFeatures,
-        cache_namespace: Option<String>,
-    ) -> Self {
-        Self {
-            question,
-            question_wire,
-            features,
-            cache_namespace,
-        }
-    }
-
-    pub fn from_query(query: &DecodedQuery, cache_namespace: Option<String>) -> Self {
-        Self::new(
-            query.question.clone(),
-            query.question_wire.to_vec(),
-            query.features.clone(),
-            cache_namespace,
-        )
-    }
-}
-
-#[derive(Debug, Clone, PartialEq, Eq)]
-pub struct CacheLookupRequest {
-    pub key: CacheKey,
-    pub received_at: SystemTime,
-}
-
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct DecodedQuery {
     pub message: Message,
@@ -569,25 +549,6 @@ impl InMemoryLocalDnsEntries {
     }
 }
 
-#[derive(Debug, Clone, PartialEq, Eq)]
-pub enum CacheLookup {
-    Hit(CachedResponse),
-    Miss,
-    Expired,
-    Bypass(CacheBypassReason),
-    Unavailable,
-}
-
-#[derive(Debug, Clone, PartialEq, Eq)]
-pub struct CachedResponse {
-    pub response_template: Vec<u8>,
-    pub response_code: ResponseCode,
-    pub minimum_ttl: Duration,
-    pub negative_cache: Option<NegativeCacheMetadata>,
-    pub stored_at: SystemTime,
-    pub expires_at: SystemTime,
-}
-
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct NegativeCacheMetadata {
     pub authority_zone: String,
@@ -611,17 +572,6 @@ pub enum CacheBypassReason {
     ResponseSizeDependsOnRequest,
 }
 
-#[derive(Debug, Clone, PartialEq, Eq)]
-pub struct CacheStore {
-    pub key: CacheKey,
-    pub response_template: Vec<u8>,
-    pub response_code: ResponseCode,
-    pub minimum_ttl: Duration,
-    pub negative_cache: Option<NegativeCacheMetadata>,
-    pub stored_at: SystemTime,
-    pub ttl: Duration,
-}
-
 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
 pub struct CacheTtlPolicy {
     pub max_positive_ttl: Duration,
@@ -806,6 +756,154 @@ fn name_is_at_or_below(name: &str, zone: &str) -> bool {
     name == zone || name.ends_with(&format!(".{zone}"))
 }
 
+/// Walks the CNAME chain in `response.answers` from `question.qname`,
+/// building one `RRsetEntry` per hop (CNAME hops included, per
+/// `DecomposedResponse`'s doc) plus, if the terminal result is negative
+/// (`negative_meta.is_some()`), a `NegativeEntry` for the terminal name.
+/// Reuses `CacheTtlPolicy::ttl_for_response`'s already-computed `ttl` and
+/// `negative_meta` rather than re-deriving TTL/negative-classification
+/// logic — this function's only job is turning that decision plus the raw
+/// `Message` into the per-domain entry shapes `ShardedDnsCache::store_response`
+/// consumes. Mirrors `negative_covered_name`'s existing chain-walking
+/// pattern, extended to also collect each hop's own RRset, not just the
+/// terminal covered name.
+fn decompose_response_for_store(
+    response: &Message,
+    question: &QuestionKey,
+    ttl: Duration,
+    negative_meta: Option<&NegativeCacheMetadata>,
+    stored_at: SystemTime,
+) -> DecomposedResponse {
+    let mut positive = Vec::new();
+    let mut current_name = question.qname.clone();
+
+    for _ in 0..=response.answers.len() {
+        let terminal_records: Vec<&Record> = response
+            .answers
+            .iter()
+            .filter(|record| {
+                record.rtype == question.qtype
+                    && record.rclass == question.qclass
+                    && normalize_question_name(&record.name) == current_name
+            })
+            .collect();
+        if !terminal_records.is_empty() {
+            positive.push((
+                current_name,
+                question.qtype,
+                question.qclass,
+                build_rrset_entry(&terminal_records, ttl, stored_at),
+            ));
+            return DecomposedResponse {
+                positive,
+                negative: None,
+            };
+        }
+
+        if question.qtype == CNAME_RECORD_TYPE {
+            break;
+        }
+        let cname_records: Vec<&Record> = response
+            .answers
+            .iter()
+            .filter(|record| {
+                record.rtype == CNAME_RECORD_TYPE
+                    && record.rclass == question.qclass
+                    && normalize_question_name(&record.name) == current_name
+            })
+            .collect();
+        let Some(RecordData::CNAME(target)) = cname_records.first().map(|record| &record.record)
+        else {
+            break;
+        };
+        let target = normalize_question_name(target);
+        positive.push((
+            current_name,
+            CNAME_RECORD_TYPE,
+            question.qclass,
+            build_rrset_entry(&cname_records, ttl, stored_at),
+        ));
+        current_name = target;
+    }
+
+    let negative = negative_meta.map(|metadata| {
+        let key = NegativeKey {
+            qtype: match metadata.kind {
+                NegativeCacheKind::NxDomain => None,
+                NegativeCacheKind::NoData => Some(question.qtype),
+            },
+            qclass: question.qclass,
+        };
+        let entry = build_negative_entry(response, metadata, ttl, stored_at);
+        (current_name.clone(), key, entry)
+    });
+
+    DecomposedResponse { positive, negative }
+}
+
+fn build_rrset_entry(records: &[&Record], ttl: Duration, stored_at: SystemTime) -> RRsetEntry {
+    RRsetEntry {
+        records: records
+            .iter()
+            .map(|record| StoredRecord {
+                rtype: record.rtype,
+                rclass: record.rclass,
+                ttl_at_store: record.ttl,
+                rdata: record.record.clone(),
+            })
+            .collect(),
+        rrsigs: Vec::new(),
+        response_code: ResponseCode::NoError,
+        minimum_ttl: ttl,
+        stored_at,
+        expires_at: stored_at + ttl,
+        dnssec_state: Default::default(),
+        // Overwritten by `ShardedDnsCache::store_response` at store time —
+        // see that method's doc comment for why the namespace isn't set
+        // here.
+        cache_namespace: String::new(),
+    }
+}
+
+/// Builds the terminal `NegativeEntry` for a decomposed store. `metadata`
+/// was already computed by `negative_ttl` (via `ttl_for_response`), which
+/// only succeeds after finding a covering SOA record satisfying exactly
+/// this predicate — so failing to re-find it here would mean
+/// `ttl_for_response`'s own result was inconsistent with `response`, an
+/// invariant violation worth panicking on rather than silently storing
+/// fabricated SOA data.
+fn build_negative_entry(
+    response: &Message,
+    metadata: &NegativeCacheMetadata,
+    ttl: Duration,
+    stored_at: SystemTime,
+) -> NegativeEntry {
+    let soa_record = response
+        .authorities
+        .iter()
+        .find(|record| {
+            matches!(record.record, RecordData::SOA { .. })
+                && record.rclass == metadata.qclass
+                && normalize_question_name(&record.name) == metadata.soa_owner
+        })
+        .map(|record| StoredRecord {
+            rtype: record.rtype,
+            rclass: record.rclass,
+            ttl_at_store: record.ttl,
+            rdata: record.record.clone(),
+        })
+        .expect("negative_ttl already located a matching SOA record for this response");
+    NegativeEntry {
+        kind: metadata.kind,
+        soa_record,
+        soa_rrsig: None,
+        proof_records: Vec::new(),
+        stored_at,
+        expires_at: stored_at + ttl,
+        cache_namespace: String::new(),
+    }
+}
+
 fn has_requested_answer_for(message: &Message, question: &QuestionKey) -> bool {
     message.answers.iter().any(|record| {
         QuestionKey::new(&record.name, record.rtype, record.rclass) == *question
@@ -2590,7 +2688,12 @@ pub struct ResolveOutcome {
 }
 
 struct CacheProbe {
-    key: Option<CacheKey>,
+    /// Replaces the old flat `CacheKey` as the identifier threaded through
+    /// to `resolve_coalesced_miss`/the eventual store call: normalized
+    /// name, qtype, qclass — the same tuple `ShardedSingleFlight` (section-04)
+    /// already keys on, so no conversion is needed at the single-flight
+    /// call sites.
+    miss_key: Option<(String, u16, u16)>,
     hit: Option<Vec<u8>>,
     store_allowed: bool,
     event_cache_result: Option<QueryEventCacheResult>,
@@ -2600,9 +2703,17 @@ pub struct ResolveQuery {
     protocol: Arc<dyn ProtocolCodec>,
     policy: Arc<dyn PolicyEvaluator>,
     local_entries: LocalDnsEntriesHandle,
-    cache: Arc<dyn DnsCache>,
+    cache: Arc<dyn DomainDnsCache>,
     ttl_policy: CacheTtlPolicy,
-    miss_coalescer: Arc<SingleFlightMisses>,
+    miss_coalescer: Arc<ShardedSingleFlight>,
+    // Bounds `resolve_from_cache`'s CNAME-chain walk (`cache::assemble`,
+    // section-06). Not part of any constructor's parameter list by
+    // default (defaults to `DEFAULT_MAX_CHAIN_DEPTH`, section-01's
+    // `RecursiveResolverConfig.max_cname_restarts` default) — callers that
+    // care (`main.rs`, constructing from real config) override it via
+    // `with_max_chain_depth` after construction, avoiding yet another
+    // parameter on every one of the `with_cache*` constructors below.
+    max_chain_depth: u8,
     backend: BackendHandle,
     // Guards `backend` and `local_entries` together: a writer publishing a
     // reload holds this for both swaps, so a query never observes the new
@@ -2639,7 +2750,7 @@ impl ResolveQuery {
     #[allow(clippy::too_many_arguments)]
     pub fn with_cache(
         protocol: Arc<dyn ProtocolCodec>,
-        cache: Arc<dyn DnsCache>,
+        cache: Arc<dyn DomainDnsCache>,
         ttl_policy: CacheTtlPolicy,
         backend: Arc<dyn ResolutionBackend>,
         responses: Arc<dyn ResponseFactory>,
@@ -2664,7 +2775,7 @@ impl ResolveQuery {
     #[allow(clippy::too_many_arguments)]
     pub fn with_cache_and_policy(
         protocol: Arc<dyn ProtocolCodec>,
-        cache: Arc<dyn DnsCache>,
+        cache: Arc<dyn DomainDnsCache>,
         policy: Arc<dyn PolicyEvaluator>,
         local_entries: Arc<dyn LocalDnsEntries>,
         ttl_policy: CacheTtlPolicy,
@@ -2692,7 +2803,7 @@ impl ResolveQuery {
     #[allow(clippy::too_many_arguments)]
     pub fn with_cache_and_backend_snapshot(
         protocol: Arc<dyn ProtocolCodec>,
-        cache: Arc<dyn DnsCache>,
+        cache: Arc<dyn DomainDnsCache>,
         ttl_policy: CacheTtlPolicy,
         backend_snapshot: BackendSnapshot,
         responses: Arc<dyn ResponseFactory>,
@@ -2717,7 +2828,7 @@ impl ResolveQuery {
     #[allow(clippy::too_many_arguments)]
     pub fn with_cache_policy_and_backend_snapshot(
         protocol: Arc<dyn ProtocolCodec>,
-        cache: Arc<dyn DnsCache>,
+        cache: Arc<dyn DomainDnsCache>,
         policy: Arc<dyn PolicyEvaluator>,
         local_entries: Arc<dyn LocalDnsEntries>,
         ttl_policy: CacheTtlPolicy,
@@ -2734,7 +2845,8 @@ impl ResolveQuery {
             local_entries: LocalDnsEntriesHandle::new(local_entries),
             cache,
             ttl_policy,
-            miss_coalescer: Arc::new(SingleFlightMisses::default()),
+            miss_coalescer: Arc::new(ShardedSingleFlight::new(default_single_flight_shard_count())),
+            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
             backend: BackendHandle::new(backend_snapshot),
             reload_gate: RwLock::new(()),
             responses,
@@ -2769,22 +2881,51 @@ impl ResolveQuery {
 
     /// Publishes a new backend snapshot and local DNS entries as a single
     /// atomic reload: no query can observe one field from the new config
-    /// paired with the other from the old one.
+    /// paired with the other from the old one. Also runs the section-05
+    /// namespace sweep (once per reload, not once per request) while still
+    /// holding `reload_gate`, so a concurrent reader can't observe the new
+    /// namespace published without the stale-namespace sweep having also
+    /// been triggered.
     pub fn publish_reload(&self, snapshot: BackendSnapshot, entries: Arc<dyn LocalDnsEntries>) {
         let _gate = self
             .reload_gate
             .write()
             .unwrap_or_else(|poisoned| poisoned.into_inner());
         let status = snapshot.status();
+        if let Some(namespace) = snapshot.cache_namespace.clone() {
+            self.cache.sweep_stale_namespace(&namespace);
+        }
         self.backend.publish(snapshot);
         self.local_entries.publish(entries);
         self.metrics.record_backend_status(&status);
     }
 
+    /// Overrides the default CNAME-chain-walk depth bound
+    /// (`DEFAULT_MAX_CHAIN_DEPTH`) set by every constructor. `main.rs`
+    /// calls this with `RecursiveResolverConfig.max_cname_restarts` once
+    /// real config is available — see `ResolveQuery.max_chain_depth`'s doc
+    /// comment for why this is a post-construction override rather than a
+    /// parameter threaded through every `with_cache*` constructor.
+    pub fn with_max_chain_depth(mut self, max_chain_depth: u8) -> Self {
+        self.max_chain_depth = max_chain_depth;
+        self
+    }
+
+    /// Overrides the default `ShardedSingleFlight` shard count set by
+    /// every constructor. `main.rs` calls this with the real
+    /// `ShardedDnsCache`'s own `shard_count()` once both are constructed,
+    /// so "shard N" means the same domain-routing bucket in both
+    /// structures — not a correctness requirement, just avoids surprising
+    /// a future reader (section-07 plan, §9).
+    pub fn with_single_flight_shard_count(mut self, shard_count: usize) -> Self {
+        self.miss_coalescer = Arc::new(ShardedSingleFlight::new(shard_count));
+        self
+    }
+
     #[allow(clippy::too_many_arguments)]
     pub fn with_cache_and_backend_handle(
         protocol: Arc<dyn ProtocolCodec>,
-        cache: Arc<dyn DnsCache>,
+        cache: Arc<dyn DomainDnsCache>,
         ttl_policy: CacheTtlPolicy,
         backend_handle: BackendHandle,
         responses: Arc<dyn ResponseFactory>,
@@ -2809,7 +2950,7 @@ impl ResolveQuery {
     #[allow(clippy::too_many_arguments)]
     pub fn with_cache_policy_and_backend_handle(
         protocol: Arc<dyn ProtocolCodec>,
-        cache: Arc<dyn DnsCache>,
+        cache: Arc<dyn DomainDnsCache>,
         policy: Arc<dyn PolicyEvaluator>,
         local_entries: Arc<dyn LocalDnsEntries>,
         ttl_policy: CacheTtlPolicy,
@@ -2826,7 +2967,8 @@ impl ResolveQuery {
             local_entries: LocalDnsEntriesHandle::new(local_entries),
             cache,
             ttl_policy,
-            miss_coalescer: Arc::new(SingleFlightMisses::default()),
+            miss_coalescer: Arc::new(ShardedSingleFlight::new(default_single_flight_shard_count())),
+            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
             backend: backend_handle,
             reload_gate: RwLock::new(()),
             responses,
@@ -2840,7 +2982,7 @@ impl ResolveQuery {
     #[allow(clippy::too_many_arguments)]
     pub fn with_cache_and_backend_generation(
         protocol: Arc<dyn ProtocolCodec>,
-        cache: Arc<dyn DnsCache>,
+        cache: Arc<dyn DomainDnsCache>,
         ttl_policy: CacheTtlPolicy,
         backend: Arc<dyn ResolutionBackend>,
         backend_generation: u64,
@@ -2930,7 +3072,7 @@ impl ResolveQuery {
                 .await;
         }
 
-        if let (Some(cache_key), true) = (cache_probe.key.take(), cache_probe.store_allowed) {
+        if let (Some(miss_key), true) = (cache_probe.miss_key.take(), cache_probe.store_allowed) {
             return self
                 .resolve_coalesced_miss(
                     &backend_snapshot,
@@ -2938,7 +3080,7 @@ impl ResolveQuery {
                     &request,
                     &decoded,
                     question,
-                    cache_key,
+                    miss_key,
                     cache_probe.event_cache_result,
                 )
                 .await;
@@ -2950,7 +3092,7 @@ impl ResolveQuery {
             &request,
             &decoded,
             question,
-            cache_probe.key,
+            cache_probe.miss_key,
             false,
             cache_probe.event_cache_result,
         )
@@ -3138,10 +3280,10 @@ impl ResolveQuery {
         request: &ResolveRequest,
         decoded: &DecodedQuery,
         question: QuestionKey,
-        cache_key: CacheKey,
+        miss_key: (String, u16, u16),
         event_cache_result: Option<QueryEventCacheResult>,
     ) -> ResolveOutcome {
-        match self.miss_coalescer.begin(cache_key.clone()) {
+        match self.miss_coalescer.begin(miss_key.clone()) {
             SingleFlightTicket::Leader { key, flight } => {
                 self.resolve_coalesced_leader(
                     backend_snapshot,
@@ -3149,7 +3291,7 @@ impl ResolveQuery {
                     request,
                     decoded,
                     question,
-                    cache_key,
+                    miss_key,
                     event_cache_result,
                     key,
                     flight,
@@ -3163,7 +3305,7 @@ impl ResolveQuery {
                     request,
                     decoded,
                     question,
-                    cache_key,
+                    miss_key,
                     event_cache_result,
                     flight,
                 )
@@ -3173,7 +3315,7 @@ impl ResolveQuery {
     }
 
     /// Resolves the query against the backend as the single-flight leader
-    /// for `cache_key`, then releases any followers waiting on the result.
+    /// for `miss_key`, then releases any followers waiting on the result.
     #[allow(clippy::too_many_arguments)]
     async fn resolve_coalesced_leader(
         &self,
@@ -3182,9 +3324,9 @@ impl ResolveQuery {
         request: &ResolveRequest,
         decoded: &DecodedQuery,
         question: QuestionKey,
-        cache_key: CacheKey,
+        miss_key: (String, u16, u16),
         event_cache_result: Option<QueryEventCacheResult>,
-        key: CacheKey,
+        key: (String, u16, u16),
         flight: Arc<InFlightMiss>,
     ) -> ResolveOutcome {
         let guard = SingleFlightLeader::new(Arc::clone(&self.miss_coalescer), key, flight);
@@ -3194,9 +3336,10 @@ impl ResolveQuery {
                 request,
                 decoded,
                 question,
-                Some(cache_key),
+                Some(miss_key),
                 true,
                 backend_snapshot.mode,
+                backend_snapshot.cache_namespace.clone(),
                 backend_result.clone(),
             )
             .await;
@@ -3213,7 +3356,7 @@ impl ResolveQuery {
         .await
     }
 
-    /// Waits for the single-flight leader resolving `cache_key` to finish,
+    /// Waits for the single-flight leader resolving `miss_key` to finish,
     /// then serves its cached result (applying the response-bytes block
     /// policy) or falls back to the leader's raw backend result if the entry
     /// didn't end up cacheable.
@@ -3225,14 +3368,14 @@ impl ResolveQuery {
         request: &ResolveRequest,
         decoded: &DecodedQuery,
         question: QuestionKey,
-        cache_key: CacheKey,
+        miss_key: (String, u16, u16),
         event_cache_result: Option<QueryEventCacheResult>,
         flight: Arc<InFlightMiss>,
     ) -> ResolveOutcome {
         self.metrics.increment(ResolverMetric::CacheCoalescedMiss);
         let backend_result = flight.wait().await;
         let Some(response_bytes) = self
-            .cache_hit_after_coalesced_miss(request, decoded, &cache_key)
+            .cache_hit_after_coalesced_miss(request, decoded, backend_snapshot, &miss_key)
             .await
         else {
             return self
@@ -3242,7 +3385,7 @@ impl ResolveQuery {
                     request,
                     decoded,
                     question,
-                    Some(cache_key),
+                    Some(miss_key),
                     false,
                     event_cache_result,
                     backend_result,
@@ -3305,7 +3448,7 @@ impl ResolveQuery {
         request: &ResolveRequest,
         decoded: &DecodedQuery,
         question: QuestionKey,
-        cache_key: Option<CacheKey>,
+        miss_key: Option<(String, u16, u16)>,
         cache_store_allowed: bool,
         event_cache_result: Option<QueryEventCacheResult>,
     ) -> ResolveOutcome {
@@ -3316,7 +3459,7 @@ impl ResolveQuery {
             request,
             decoded,
             question,
-            cache_key,
+            miss_key,
             cache_store_allowed,
             event_cache_result,
             backend_result,
@@ -3389,7 +3532,7 @@ impl ResolveQuery {
             self.metrics.increment(ResolverMetric::CacheBypass);
             self.metrics.increment(ResolverMetric::CacheMiss);
             return CacheProbe {
-                key: None,
+                miss_key: None,
                 hit: None,
                 store_allowed: false,
                 event_cache_result: Some(QueryEventCacheResult::Bypass),
@@ -3398,122 +3541,177 @@ impl ResolveQuery {
 
         // No effective-payload-size class here: a UDP query and a TCP query
         // for the same question now share one cache entry — see
-        // docs/plans/cache_key.md. (Two UDP queries advertising different
-        // *raw* EDNS bufsizes still get separate entries: the raw value
-        // lives in `decoded.features.edns_udp_payload_size`, part of the key
-        // below — this change only drops the redundant *clamped* size that
-        // used to also be there.) Every entry stores the full, untruncated
-        // response regardless of who populated it; `allow_udp_truncation`/
-        // `is_tcp()` checks at serve time (not the cache key) are what keep
-        // each response correct for the current request's transport.
-        let key = CacheKey::new(
-            decoded.question.clone(),
-            decoded.question_wire.to_vec(),
-            decoded.features.clone(),
-            backend_snapshot.cache_namespace.clone(),
-        );
-        let lookup = self
-            .cache
-            .lookup(&CacheLookupRequest {
-                key: key.clone(),
-                received_at: request.received_at.0,
-            })
-            .await;
+        // docs/plans/cache_key.md. Every entry stores raw record data, not
+        // a pre-built response, so `allow_udp_truncation`/`is_tcp()` checks
+        // at serve time (assemble_response, not the cache key) are what
+        // keep each response correct for the current request's transport.
+        let namespace = backend_snapshot.cache_namespace.clone().unwrap_or_default();
+        let lookup = self.cache.lookup_chain(
+            &decoded.question.qname,
+            decoded.question.qtype,
+            decoded.question.qclass,
+            &namespace,
+            self.max_chain_depth,
+            request.received_at.0,
+        );
         let (store_allowed, hit, event_cache_result) =
             self.evaluate_cache_lookup(lookup, decoded, request);
 
         CacheProbe {
-            key: Some(key),
+            miss_key: Some((
+                decoded.question.qname.clone(),
+                decoded.question.qtype,
+                decoded.question.qclass,
+            )),
             hit,
             store_allowed,
             event_cache_result: Some(event_cache_result),
         }
     }
 
-    /// Maps a cache lookup outcome to whether the eventual backend result may
-    /// be stored, the serialized hit response (if any), and the outcome to
-    /// report on the query event. A `Hit` whose cached response fails to
-    /// re-serialize is treated as a miss that's still allowed to store a
-    /// fresh result.
+    /// Maps a cache lookup outcome to whether the eventual backend result
+    /// may be stored, the serialized hit response (if any), and the
+    /// outcome to report on the query event.
+    ///
+    /// Unlike the old flat `CacheLookup`, `ChainLookup` has no
+    /// `Expired`/`Unavailable` variants: `resolve_from_cache` (section-06)
+    /// rejects an expired or stale-namespace match inline and folds it
+    /// into `Miss` before ever returning it, and the new cache has no
+    /// external dependency that could make it "unavailable" (it's
+    /// in-process memory, not a service call) — so
+    /// `ResolverMetric::CacheExpired`/`CacheUnavailable` are no longer
+    /// emitted from this path. This is an accepted, architecture-driven
+    /// behavior change, not an oversight.
     fn evaluate_cache_lookup(
         &self,
-        lookup: CacheLookup,
+        lookup: ChainLookup,
         decoded: &DecodedQuery,
         request: &ResolveRequest,
     ) -> (bool, Option<Vec<u8>>, QueryEventCacheResult) {
         match lookup {
-            CacheLookup::Hit(cached) => match self.serialize_cache_hit(decoded, &cached, request) {
-                Ok(response_bytes) => (false, Some(response_bytes), QueryEventCacheResult::Hit),
-                Err(_) => {
-                    self.metrics.increment(ResolverMetric::CacheMiss);
-                    (true, None, QueryEventCacheResult::Miss)
-                }
-            },
-            CacheLookup::Miss => {
-                self.metrics.increment(ResolverMetric::CacheMiss);
-                (true, None, QueryEventCacheResult::Miss)
+            ChainLookup::Answered(resolved) => {
+                let response_bytes = self.serialize_cache_hit_answer(decoded, &resolved, request);
+                self.record_cache_hit_metrics(&response_bytes, false);
+                (false, Some(response_bytes), QueryEventCacheResult::Hit)
             }
-            CacheLookup::Expired => {
-                self.metrics.increment(ResolverMetric::CacheExpired);
-                self.metrics.increment(ResolverMetric::CacheMiss);
-                (true, None, QueryEventCacheResult::Expired)
+            ChainLookup::NxDomain(resolved) => {
+                let response_bytes = self.serialize_cache_hit_negative(
+                    decoded,
+                    &resolved,
+                    ResponseCode::NxDomain,
+                    request,
+                );
+                self.record_cache_hit_metrics(&response_bytes, true);
+                (false, Some(response_bytes), QueryEventCacheResult::Hit)
             }
-            CacheLookup::Bypass(_) => {
-                self.metrics.increment(ResolverMetric::CacheBypass);
-                self.metrics.increment(ResolverMetric::CacheMiss);
-                (false, None, QueryEventCacheResult::Bypass)
+            ChainLookup::NoData(resolved) => {
+                let response_bytes = self.serialize_cache_hit_negative(
+                    decoded,
+                    &resolved,
+                    ResponseCode::NoError,
+                    request,
+                );
+                self.record_cache_hit_metrics(&response_bytes, true);
+                (false, Some(response_bytes), QueryEventCacheResult::Hit)
             }
-            CacheLookup::Unavailable => {
-                self.metrics.increment(ResolverMetric::CacheUnavailable);
+            ChainLookup::Miss => {
                 self.metrics.increment(ResolverMetric::CacheMiss);
-                (false, None, QueryEventCacheResult::Unavailable)
+                (true, None, QueryEventCacheResult::Miss)
             }
         }
     }
 
-    async fn cache_hit_after_coalesced_miss(
+    fn record_cache_hit_metrics(&self, response_bytes: &[u8], negative: bool) {
+        self.metrics.increment(ResolverMetric::CacheHit);
+        if negative {
+            self.metrics.increment(ResolverMetric::CacheNegativeHit);
+        }
+        if response_is_truncated(response_bytes) {
+            self.metrics
+                .increment(ResolverMetric::CacheResponseTruncated);
+        }
+    }
+
+    fn serialize_cache_hit_answer(
         &self,
-        request: &ResolveRequest,
         decoded: &DecodedQuery,
-        cache_key: &CacheKey,
-    ) -> Option<Vec<u8>> {
-        let lookup = self
-            .cache
-            .lookup(&CacheLookupRequest {
-                key: cache_key.clone(),
-                received_at: request.received_at.0,
-            })
-            .await;
-        let CacheLookup::Hit(cached) = lookup else {
-            return None;
-        };
-        self.serialize_cache_hit(decoded, &cached, request).ok()
+        resolved: &cache::ResolvedAnswer,
+        request: &ResolveRequest,
+    ) -> Vec<u8> {
+        assemble_response(
+            decoded.message.header.id,
+            &decoded.question_wire,
+            &decoded.features,
+            resolved,
+            request.received_at.0,
+            !request.observed_source.is_tcp(),
+            self.protocol.configured_max_udp_payload_size(),
+        )
     }
 
-    fn serialize_cache_hit(
+    fn serialize_cache_hit_negative(
         &self,
         decoded: &DecodedQuery,
-        cached: &CachedResponse,
+        resolved: &cache::ResolvedNegative,
+        response_code: ResponseCode,
         request: &ResolveRequest,
-    ) -> crate::protocol::Result<Vec<u8>> {
-        if cached.expires_at <= request.received_at.0 {
-            self.metrics.increment(ResolverMetric::CacheExpired);
-        }
-        let response_bytes = self.protocol.serialize_cached_response(
-            decoded,
-            cached,
+    ) -> Vec<u8> {
+        assemble_negative_response(
+            decoded.message.header.id,
+            &decoded.question_wire,
+            &decoded.features,
+            resolved,
+            response_code,
             request.received_at.0,
             !request.observed_source.is_tcp(),
-        )?;
-        self.metrics.increment(ResolverMetric::CacheHit);
-        if cached.negative_cache.is_some() {
-            self.metrics.increment(ResolverMetric::CacheNegativeHit);
-        }
-        if response_is_truncated(&response_bytes) {
-            self.metrics
-                .increment(ResolverMetric::CacheResponseTruncated);
+            self.protocol.configured_max_udp_payload_size(),
+        )
+    }
+
+    async fn cache_hit_after_coalesced_miss(
+        &self,
+        request: &ResolveRequest,
+        decoded: &DecodedQuery,
+        backend_snapshot: &BackendSnapshot,
+        miss_key: &(String, u16, u16),
+    ) -> Option<Vec<u8>> {
+        let namespace = backend_snapshot.cache_namespace.clone().unwrap_or_default();
+        let lookup = self.cache.lookup_chain(
+            &miss_key.0,
+            miss_key.1,
+            miss_key.2,
+            &namespace,
+            self.max_chain_depth,
+            request.received_at.0,
+        );
+        match lookup {
+            ChainLookup::Answered(resolved) => {
+                let response_bytes = self.serialize_cache_hit_answer(decoded, &resolved, request);
+                self.record_cache_hit_metrics(&response_bytes, false);
+                Some(response_bytes)
+            }
+            ChainLookup::NxDomain(resolved) => {
+                let response_bytes = self.serialize_cache_hit_negative(
+                    decoded,
+                    &resolved,
+                    ResponseCode::NxDomain,
+                    request,
+                );
+                self.record_cache_hit_metrics(&response_bytes, true);
+                Some(response_bytes)
+            }
+            ChainLookup::NoData(resolved) => {
+                let response_bytes = self.serialize_cache_hit_negative(
+                    decoded,
+                    &resolved,
+                    ResponseCode::NoError,
+                    request,
+                );
+                self.record_cache_hit_metrics(&response_bytes, true);
+                Some(response_bytes)
+            }
+            ChainLookup::Miss => None,
         }
-        Ok(response_bytes)
     }
 
     #[allow(clippy::too_many_arguments)]
@@ -3524,7 +3722,7 @@ impl ResolveQuery {
         request: &ResolveRequest,
         decoded: &DecodedQuery,
         question: QuestionKey,
-        cache_key: Option<CacheKey>,
+        miss_key: Option<(String, u16, u16)>,
         cache_store_allowed: bool,
         event_cache_result: Option<QueryEventCacheResult>,
         backend_result: Result<ResolutionResponse, ResolutionBackendError>,
@@ -3534,9 +3732,10 @@ impl ResolveQuery {
                 request,
                 decoded,
                 question,
-                cache_key,
+                miss_key,
                 cache_store_allowed,
                 backend_snapshot.mode,
+                backend_snapshot.cache_namespace.clone(),
                 backend_result,
             )
             .await;
@@ -3558,9 +3757,10 @@ impl ResolveQuery {
         request: &ResolveRequest,
         decoded: &DecodedQuery,
         question: QuestionKey,
-        cache_key: Option<CacheKey>,
+        miss_key: Option<(String, u16, u16)>,
         cache_store_allowed: bool,
         backend_mode: ResolutionMode,
+        cache_namespace: Option<String>,
         backend_result: Result<ResolutionResponse, ResolutionBackendError>,
     ) -> (ResolveDecision, Vec<u8>) {
         let Ok(mut response) = backend_result else {
@@ -3592,13 +3792,12 @@ impl ResolveQuery {
             return self.backend_failure_response(request, decoded, decoded.question.clone());
         }
 
-        if let (true, Some(cache_key)) = (cache_store_allowed, cache_key) {
+        if let (true, Some(_miss_key)) = (cache_store_allowed, &miss_key) {
             if response.cache_directive.is_cacheable() {
                 self.store_cache_response(
-                    cache_key,
-                    response_bytes.clone(),
+                    cache_namespace.unwrap_or_default(),
                     &response_message,
-                    decoded,
+                    &question,
                     request,
                 )
                 .await;
@@ -3664,58 +3863,52 @@ impl ResolveQuery {
 
     async fn store_cache_response(
         &self,
-        cache_key: CacheKey,
-        response_bytes: Vec<u8>,
+        namespace: String,
         response: &Message,
-        decoded: &DecodedQuery,
+        question: &QuestionKey,
         request: &ResolveRequest,
     ) {
-        if let Some(store) = self.cache_store_for_response(
-            cache_key,
-            response_bytes,
-            response,
-            decoded,
-            request.received_at.0,
-        ) {
-            if store.negative_cache.is_some() {
+        if let Some(decomposed) =
+            self.cache_store_for_response(response, question, request.received_at.0)
+        {
+            if decomposed.negative.is_some() {
                 self.metrics.increment(ResolverMetric::CacheNegativeStore);
             }
             self.metrics.increment(ResolverMetric::CacheStore);
-            self.cache.store(store).await;
+            self.cache.store_response(decomposed, &namespace);
         } else {
             self.metrics.increment(ResolverMetric::CacheStoreSkipped);
         }
     }
 
+    /// Builds the `DecomposedResponse` this response should be stored as,
+    /// or `None` if it isn't cacheable at all. Unlike the old
+    /// `cache_store_for_response`, this no longer separately checks
+    /// `query.message.questions.len() != 1` — the caller's `question`
+    /// comes from an already-decoded query, which
+    /// `Message::parse_standard_query` guarantees has exactly one
+    /// question at decode time, so re-checking it here was redundant with
+    /// that earlier validation.
     fn cache_store_for_response(
         &self,
-        key: CacheKey,
-        mut response_template: Vec<u8>,
         response: &Message,
-        query: &DecodedQuery,
+        question: &QuestionKey,
         stored_at: SystemTime,
-    ) -> Option<CacheStore> {
+    ) -> Option<DecomposedResponse> {
         if !response.header.qr()
             || response.questions.len() != 1
-            || query.message.questions.len() != 1
-            || QuestionKey::from_message(response)? != query.question
+            || QuestionKey::from_message(response)? != *question
         {
             return None;
         }
-        let response_code = response_code(response)?;
-        let (ttl, negative_cache) = self.ttl_policy.ttl_for_response(response)?;
-        self.protocol
-            .rewrite_response_id(&mut response_template, 0)
-            .ok()?;
-        Some(CacheStore {
-            key,
-            response_template,
-            response_code,
-            minimum_ttl: ttl,
-            negative_cache,
-            stored_at,
+        let (ttl, negative_meta) = self.ttl_policy.ttl_for_response(response)?;
+        Some(decompose_response_for_store(
+            response,
+            question,
             ttl,
-        })
+            negative_meta.as_ref(),
+            stored_at,
+        ))
     }
 
     /// `cache_result` drives the `QueryEventV1` audit event (what was
@@ -3825,113 +4018,6 @@ impl ResolveQuery {
     }
 }
 
-#[derive(Default)]
-struct SingleFlightMisses {
-    flights: Mutex<HashMap<CacheKey, Arc<InFlightMiss>>>,
-}
-
-enum SingleFlightTicket {
-    Leader {
-        key: CacheKey,
-        flight: Arc<InFlightMiss>,
-    },
-    Follower {
-        flight: Arc<InFlightMiss>,
-    },
-}
-
-struct InFlightMiss {
-    result: Mutex<Option<Result<ResolutionResponse, ResolutionBackendError>>>,
-    notify: Notify,
-}
-
-struct SingleFlightLeader {
-    coalescer: Arc<SingleFlightMisses>,
-    key: CacheKey,
-    flight: Arc<InFlightMiss>,
-    completed: bool,
-}
-
-impl SingleFlightMisses {
-    fn begin(&self, key: CacheKey) -> SingleFlightTicket {
-        let mut flights = self.flights.lock().unwrap();
-        if let Some(flight) = flights.get(&key) {
-            return SingleFlightTicket::Follower {
-                flight: Arc::clone(flight),
-            };
-        }
-        let flight = Arc::new(InFlightMiss {
-            result: Mutex::new(None),
-            notify: Notify::new(),
-        });
-        flights.insert(key.clone(), Arc::clone(&flight));
-        SingleFlightTicket::Leader { key, flight }
-    }
-
-    fn finish(
-        &self,
-        key: &CacheKey,
-        flight: &Arc<InFlightMiss>,
-        result: Result<ResolutionResponse, ResolutionBackendError>,
-    ) {
-        *flight.result.lock().unwrap() = Some(result);
-        let mut flights = self.flights.lock().unwrap();
-        if flights
-            .get(key)
-            .map(|current| Arc::ptr_eq(current, flight))
-            .unwrap_or(false)
-        {
-            flights.remove(key);
-        }
-        drop(flights);
-        flight.notify.notify_waiters();
-    }
-}
-
-impl SingleFlightLeader {
-    fn new(coalescer: Arc<SingleFlightMisses>, key: CacheKey, flight: Arc<InFlightMiss>) -> Self {
-        Self {
-            coalescer,
-            key,
-            flight,
-            completed: false,
-        }
-    }
-
-    fn complete(mut self, result: Result<ResolutionResponse, ResolutionBackendError>) {
-        self.coalescer.finish(&self.key, &self.flight, result);
-        self.completed = true;
-    }
-}
-
-impl Drop for SingleFlightLeader {
-    fn drop(&mut self) {
-        if self.completed {
-            return;
-        }
-        self.coalescer.finish(
-            &self.key,
-            &self.flight,
-            Err(ResolutionBackendError::Transport(
-                "single-flight leader cancelled".to_string(),
-            )),
-        );
-    }
-}
-
-impl InFlightMiss {
-    async fn wait(&self) -> Result<ResolutionResponse, ResolutionBackendError> {
-        loop {
-            let notified = self.notify.notified();
-            tokio::pin!(notified);
-            if let Some(result) = self.result.lock().unwrap().clone() {
-                return result;
-            }
-            notified.await;
-        }
-    }
-}
-
 fn request_id_from_wire(bytes: &[u8]) -> Option<u16> {
     let id = bytes.get(0..2)?;
     Some(u16::from_be_bytes([id[0], id[1]]))
@@ -4226,36 +4312,6 @@ impl ProtocolCodec for StandardProtocolCodec {
     ) -> crate::protocol::Result<()> {
         rewrite_response_id(response_bytes, request_id)
     }
-
-    fn serialize_cached_response(
-        &self,
-        query: &DecodedQuery,
-        cached: &CachedResponse,
-        now: SystemTime,
-        allow_udp_truncation: bool,
-    ) -> crate::protocol::Result<Vec<u8>> {
-        let mut response = cached.response_template.clone();
-        if cached.expires_at <= now {
-            return Err(crate::protocol::DnsParseError::MalformedRecord);
-        }
-        rewrite_response_request_fields(&mut response, &query.message)?;
-        if let Ok(age) = now.duration_since(cached.stored_at) {
-            age_response_ttls(&mut response, age)?;
-        }
-        let remaining_ttl = cached
-            .expires_at
-            .duration_since(now)
-            .map_err(|_| crate::protocol::DnsParseError::MalformedRecord)?;
-        cap_response_ttls(&mut response, remaining_ttl)?;
-        if allow_udp_truncation
-            && query
-                .message
-                .response_exceeds_udp_payload(response.len(), self.configured_max_udp_payload_size)
-        {
-            return Ok(crate::protocol::build_truncated_response(&query.message));
-        }
-        Ok(response)
-    }
 }
 
 pub struct BasicResponseFactory;
@@ -4381,18 +4437,6 @@ pub trait ProtocolCodec: Send + Sync {
         response_bytes: &mut [u8],
         request_id: u16,
     ) -> crate::protocol::Result<()>;
-
-    /// `allow_udp_truncation` must be `false` for TCP-sourced queries: the
-    /// UDP payload-size ceiling (and the pre-EDNS 512-byte floor) has no
-    /// meaning over TCP (RFC 6891 §6.2.3), so the cached template must be
-    /// replayed in full rather than truncated to the UDP limit.
-    fn serialize_cached_response(
-        &self,
-        query: &DecodedQuery,
-        cached: &CachedResponse,
-        now: SystemTime,
-        allow_udp_truncation: bool,
-    ) -> crate::protocol::Result<Vec<u8>>;
 }
 
 pub trait PolicyEvaluator: Send + Sync {
@@ -4434,21 +4478,31 @@ impl LocalDnsEntries for NoopLocalDnsEntries {
     }
 }
 
-pub trait DnsCache: Send + Sync {
-    fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup>;
+pub struct NoopDnsCache;
+
+impl DomainDnsCache for NoopDnsCache {
+    fn lookup_chain(
+        &self,
+        _qname: &str,
+        _qtype: u16,
+        _qclass: u16,
+        _namespace: &str,
+        _max_chain_depth: u8,
+        _now: SystemTime,
+    ) -> ChainLookup {
+        ChainLookup::Miss
+    }
 
-    fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()>;
-}
+    fn store_response(&self, _decomposed: DecomposedResponse, _namespace: &str) {}
 
-pub struct NoopDnsCache;
+    fn sweep_stale_namespace(&self, _current_namespace: &str) {}
 
-impl DnsCache for NoopDnsCache {
-    fn lookup<'a>(&'a self, _request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> {
-        Box::pin(async { CacheLookup::Miss })
+    fn domain_count(&self) -> usize {
+        0
     }
 
-    fn store<'a>(&'a self, _entry: CacheStore) -> BoxFuture<'a, ()> {
-        Box::pin(async {})
+    fn capacity(&self) -> usize {
+        0
     }
 }
 
@@ -5321,196 +5375,17 @@ fn event_order_key(event: &QueryEventV1) -> (SystemTime, u64) {
     (event.timestamp, event.sequence)
 }
 
-pub struct InMemoryDnsCache {
-    max_entries: usize,
-    state: Mutex<InMemoryDnsCacheState>,
+pub trait ResolutionBackend: Send + Sync {
+    fn resolve<'a>(
+        &'a self,
+        request: ResolutionRequest,
+    ) -> BoxFuture<'a, Result<ResolutionResponse, ResolutionBackendError>>;
 }
 
-#[derive(Default)]
-struct InMemoryDnsCacheState {
-    entries: HashMap<CacheKey, InMemoryDnsCacheEntry>,
-    lru: VecDeque<(CacheKey, u64)>,
-    next_sequence: u64,
-}
-
-struct InMemoryDnsCacheEntry {
-    response: CachedResponse,
-    sequence: u64,
-}
-
-impl InMemoryDnsCache {
-    pub fn new(max_entries: usize) -> Self {
-        Self {
-            max_entries,
-            state: Mutex::new(InMemoryDnsCacheState::default()),
-        }
-    }
-
-    pub fn len(&self) -> usize {
-        self.state.lock().unwrap().entries.len()
-    }
-
-    pub fn is_empty(&self) -> bool {
-        self.len() == 0
-    }
-
-    pub fn capacity(&self) -> usize {
-        self.max_entries
-    }
-
-    pub fn remove_expired(&self, now: SystemTime) {
-        let mut state = self.state.lock().unwrap();
-        state.remove_expired(now);
-        state.compact_lru();
-    }
-
-    #[cfg(test)]
-    fn lru_len(&self) -> usize {
-        self.state.lock().unwrap().lru.len()
-    }
-
-    fn lookup_now(&self, request: &CacheLookupRequest) -> CacheLookup {
-        let mut state = self.state.lock().unwrap();
-        if state
-            .entries
-            .get(&request.key)
-            .map(|entry| entry.response.expires_at <= request.received_at)
-            .unwrap_or(false)
-        {
-            state.entries.remove(&request.key);
-            state.maybe_compact_lru(self.max_entries);
-            return CacheLookup::Expired;
-        }
-
-        let Some(existing) = state.entries.get(&request.key) else {
-            return CacheLookup::Miss;
-        };
-
-        let response = existing.response.clone();
-        let sequence = state.next_sequence();
-        if let Some(existing) = state.entries.get_mut(&request.key) {
-            existing.sequence = sequence;
-        }
-        state.lru.push_back((request.key.clone(), sequence));
-        state.maybe_compact_lru(self.max_entries);
-        CacheLookup::Hit(response)
-    }
-
-    fn store_now(&self, entry: CacheStore) {
-        let mut state = self.state.lock().unwrap();
-        if self.max_entries == 0 {
-            state.entries.clear();
-            state.lru.clear();
-            return;
-        }
-
-        let now = entry.stored_at;
-        let expires_at = now.checked_add(entry.ttl).unwrap_or(SystemTime::UNIX_EPOCH);
-        if expires_at <= now {
-            state.entries.remove(&entry.key);
-            state.maybe_compact_lru(self.max_entries);
-            return;
-        }
-        if state.entries.len() >= self.max_entries {
-            state.remove_expired(now);
-            state.compact_lru();
-        }
-
-        let sequence = state.next_sequence();
-        let cached = CachedResponse {
-            response_template: entry.response_template,
-            response_code: entry.response_code,
-            minimum_ttl: entry.minimum_ttl,
-            negative_cache: entry.negative_cache,
-            stored_at: now,
-            expires_at,
-        };
-        state.entries.insert(
-            entry.key.clone(),
-            InMemoryDnsCacheEntry {
-                response: cached,
-                sequence,
-            },
-        );
-        state.lru.push_back((entry.key, sequence));
-        state.evict_to_bound(self.max_entries);
-        state.maybe_compact_lru(self.max_entries);
-    }
-}
-
-impl InMemoryDnsCacheState {
-    fn next_sequence(&mut self) -> u64 {
-        let sequence = self.next_sequence;
-        self.next_sequence = self.next_sequence.wrapping_add(1);
-        sequence
-    }
-
-    fn compact_lru(&mut self) {
-        self.lru.retain(|(key, sequence)| {
-            self.entries
-                .get(key)
-                .map(|entry| entry.sequence == *sequence)
-                .unwrap_or(false)
-        });
-    }
-
-    fn remove_expired(&mut self, now: SystemTime) {
-        self.entries
-            .retain(|_, entry| entry.response.expires_at > now);
-    }
-
-    fn maybe_compact_lru(&mut self, max_entries: usize) {
-        if self.lru.len() > lru_compaction_threshold(max_entries) {
-            self.compact_lru();
-        }
-    }
-
-    fn evict_to_bound(&mut self, max_entries: usize) {
-        while self.entries.len() > max_entries {
-            let Some((key, sequence)) = self.lru.pop_front() else {
-                break;
-            };
-            let should_remove = self
-                .entries
-                .get(&key)
-                .map(|entry| entry.sequence == sequence)
-                .unwrap_or(false);
-            if should_remove {
-                self.entries.remove(&key);
-            }
-        }
-    }
-}
-
-fn lru_compaction_threshold(max_entries: usize) -> usize {
-    max_entries
-        .saturating_mul(LRU_COMPACTION_MULTIPLIER)
-        .max(max_entries.saturating_add(1))
-}
-
-impl DnsCache for InMemoryDnsCache {
-    fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> {
-        Box::pin(async move { self.lookup_now(request) })
-    }
-
-    fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()> {
-        Box::pin(async move {
-            self.store_now(entry);
-        })
-    }
-}
-
-pub trait ResolutionBackend: Send + Sync {
-    fn resolve<'a>(
-        &'a self,
-        request: ResolutionRequest,
-    ) -> BoxFuture<'a, Result<ResolutionResponse, ResolutionBackendError>>;
-}
-
-#[derive(Debug, Clone, PartialEq, Eq)]
-pub struct RecursiveRootHint {
-    pub name: String,
-    pub endpoints: Vec<SocketAddr>,
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub struct RecursiveRootHint {
+    pub name: String,
+    pub endpoints: Vec<SocketAddr>,
 }
 
 #[derive(Debug, Clone, PartialEq, Eq)]
@@ -6538,10 +6413,10 @@ mod tests {
     use std::sync::Mutex;
     use std::sync::mpsc as std_mpsc;
     use std::thread;
+    use tokio::sync::Notify;
 
-    use crate::protocol::{
-        EdnsInfo, Header, Question, Record, build_a_block_response, question_wire,
-    };
+    use crate::config::CacheConfig;
+    use crate::protocol::{EdnsInfo, Header, Question, Record, build_a_block_response};
 
     fn a_query(id: u16, name: &str) -> Vec<u8> {
         query(id, name, 1, 1)
@@ -6578,13 +6453,6 @@ mod tests {
         bytes
     }
 
-    fn a_query_with_authenticated_data(id: u16, name: &str) -> Vec<u8> {
-        let mut bytes = a_query(id, name);
-        let flags = u16::from_be_bytes([bytes[2], bytes[3]]) | 0x0020;
-        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
-        bytes
-    }
-
     fn aaaa_query(id: u16, name: &str) -> Vec<u8> {
         let mut bytes = a_query(id, name);
         let qtype_offset = bytes.len() - 4;
@@ -6592,13 +6460,6 @@ mod tests {
         bytes
     }
 
-    fn chaos_a_query(id: u16, name: &str) -> Vec<u8> {
-        let mut bytes = a_query(id, name);
-        let qclass_offset = bytes.len() - 2;
-        bytes[qclass_offset..].copy_from_slice(&3u16.to_be_bytes());
-        bytes
-    }
-
     fn a_query_with_edns(id: u16, name: &str, udp_payload_size: u16, dnssec_ok: bool) -> Vec<u8> {
         a_query_with_edns_options(id, name, udp_payload_size, dnssec_ok, &[])
     }
@@ -8198,21 +8059,6 @@ mod tests {
         ) -> crate::protocol::Result<()> {
             rewrite_response_id(response_bytes, request_id)
         }
-
-        fn serialize_cached_response(
-            &self,
-            query: &DecodedQuery,
-            cached: &CachedResponse,
-            now: SystemTime,
-            allow_udp_truncation: bool,
-        ) -> crate::protocol::Result<Vec<u8>> {
-            StandardProtocolCodec::new(1232).serialize_cached_response(
-                query,
-                cached,
-                now,
-                allow_udp_truncation,
-            )
-        }
     }
 
     struct StaticUpstream {
@@ -8351,13 +8197,13 @@ mod tests {
     }
 
     struct RecordingCache {
-        lookup: Mutex<CacheLookup>,
-        lookups: Mutex<Vec<CacheLookupRequest>>,
-        stores: Mutex<Vec<CacheStore>>,
+        lookup: Mutex<ChainLookup>,
+        lookups: Mutex<Vec<(String, u16, u16)>>,
+        stores: Mutex<Vec<(DecomposedResponse, String)>>,
     }
 
     impl RecordingCache {
-        fn with_lookup(lookup: CacheLookup) -> Self {
+        fn with_lookup(lookup: ChainLookup) -> Self {
             Self {
                 lookup: Mutex::new(lookup),
                 lookups: Mutex::new(Vec::new()),
@@ -8366,18 +8212,38 @@ mod tests {
         }
     }
 
-    impl DnsCache for RecordingCache {
-        fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> {
-            Box::pin(async move {
-                self.lookups.lock().unwrap().push(request.clone());
-                self.lookup.lock().unwrap().clone()
-            })
+    impl DomainDnsCache for RecordingCache {
+        fn lookup_chain(
+            &self,
+            qname: &str,
+            qtype: u16,
+            qclass: u16,
+            _namespace: &str,
+            _max_chain_depth: u8,
+            _now: SystemTime,
+        ) -> ChainLookup {
+            self.lookups
+                .lock()
+                .unwrap()
+                .push((qname.to_string(), qtype, qclass));
+            self.lookup.lock().unwrap().clone()
         }
 
-        fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()> {
-            Box::pin(async move {
-                self.stores.lock().unwrap().push(entry);
-            })
+        fn store_response(&self, decomposed: DecomposedResponse, namespace: &str) {
+            self.stores
+                .lock()
+                .unwrap()
+                .push((decomposed, namespace.to_string()));
+        }
+
+        fn sweep_stale_namespace(&self, _current_namespace: &str) {}
+
+        fn domain_count(&self) -> usize {
+            0
+        }
+
+        fn capacity(&self) -> usize {
+            0
         }
     }
 
@@ -8398,7 +8264,7 @@ mod tests {
 
     fn resolve_service_with_cache(
         upstream: Arc<dyn ResolutionBackend>,
-        cache: Arc<dyn DnsCache>,
+        cache: Arc<dyn DomainDnsCache>,
         events: Arc<RecordingEvents>,
         metrics: Arc<RecordingMetrics>,
         max_udp_payload_size: usize,
@@ -10568,7 +10434,10 @@ mod tests {
         let backend = Arc::new(recursive_backend(transport));
         let service = ResolveQuery::with_cache_and_backend_snapshot(
             Arc::new(StandardProtocolCodec::new(1232)),
-            Arc::new(InMemoryDnsCache::new(10)),
+            Arc::new(ShardedDnsCache::new(&CacheConfig {
+                max_entries: 10,
+                shard_count: Some(1),
+            })),
             CacheTtlPolicy::default(),
             BackendSnapshot::new(
                 backend,
@@ -10649,7 +10518,10 @@ mod tests {
         let backend = Arc::new(recursive_backend(transport.clone()));
         let service = ResolveQuery::with_cache_and_backend_snapshot(
             Arc::new(StandardProtocolCodec::new(1232)),
-            Arc::new(InMemoryDnsCache::new(10)),
+            Arc::new(ShardedDnsCache::new(&CacheConfig {
+                max_entries: 10,
+                shard_count: Some(1),
+            })),
             CacheTtlPolicy::default(),
             BackendSnapshot::new(
                 backend,
@@ -10977,68 +10849,6 @@ mod tests {
         assert_eq!(key.qname, "");
     }
 
-    #[test]
-    fn cache_store_keeps_explicit_key_and_ttl() {
-        let question = QuestionKey::new("example.com", 28, 1);
-        let entry = CacheStore {
-            key: CacheKey::new(
-                question,
-                question_wire(&aaaa_query(0x1000, "example.com"))
-                    .unwrap()
-                    .to_vec(),
-                QueryFeatures {
-                    recursion_desired: true,
-                    authenticated_data: false,
-                    checking_disabled: false,
-                    dnssec_ok: false,
-                    edns_udp_payload_size: None,
-                },
-                Some("primary".to_string()),
-            ),
-            response_template: vec![1, 2, 3],
-            response_code: ResponseCode::NoError,
-            minimum_ttl: Duration::from_secs(30),
-            negative_cache: None,
-            stored_at: SystemTime::UNIX_EPOCH,
-            ttl: Duration::from_secs(60),
-        };
-
-        assert_eq!(entry.key.question.qname, "example.com");
-        assert_eq!(entry.key.cache_namespace.as_deref(), Some("primary"));
-        assert_eq!(entry.response_template, vec![1, 2, 3]);
-        assert_eq!(entry.response_code, ResponseCode::NoError);
-        assert_eq!(entry.minimum_ttl, Duration::from_secs(30));
-        assert_eq!(entry.negative_cache, None);
-        assert_eq!(entry.ttl, Duration::from_secs(60));
-    }
-
-    fn cache_key(name: &str) -> CacheKey {
-        CacheKey::new(
-            QuestionKey::new(name, 1, 1),
-            question_wire(&a_query(0x1000, name)).unwrap().to_vec(),
-            QueryFeatures {
-                recursion_desired: true,
-                authenticated_data: false,
-                checking_disabled: false,
-                dnssec_ok: false,
-                edns_udp_payload_size: None,
-            },
-            Some("primary".to_string()),
-        )
-    }
-
-    fn cache_store_at(key: CacheKey, ttl: Duration, stored_at: SystemTime) -> CacheStore {
-        CacheStore {
-            key,
-            response_template: vec![0x12, 0x34, 0x81, 0x80],
-            response_code: ResponseCode::NoError,
-            minimum_ttl: ttl,
-            negative_cache: None,
-            stored_at,
-            ttl,
-        }
-    }
-
     fn response_message(
         response_code: ResponseCode,
         answers: Vec<Record>,
@@ -12075,284 +11885,6 @@ mod tests {
         assert_eq!(response_code_from_wire(&response), Some(4));
     }
 
-    #[test]
-    fn cache_capacity_returns_configured_max_entries() {
-        let cache = InMemoryDnsCache::new(42);
-
-        assert_eq!(cache.capacity(), 42);
-    }
-
-    #[test]
-    fn in_memory_cache_returns_unexpired_entry() {
-        let cache = InMemoryDnsCache::new(16);
-        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
-        let key = cache_key("example.com");
-
-        cache.store_now(cache_store_at(key.clone(), Duration::from_secs(30), now));
-
-        let lookup = cache.lookup_now(&CacheLookupRequest {
-            key,
-            received_at: now + Duration::from_secs(5),
-        });
-        let CacheLookup::Hit(hit) = lookup else {
-            panic!("expected cache hit");
-        };
-        assert_eq!(hit.response_template, vec![0x12, 0x34, 0x81, 0x80]);
-        assert_eq!(hit.stored_at, now);
-        assert_eq!(hit.expires_at, now + Duration::from_secs(30));
-        assert_eq!(cache.len(), 1);
-    }
-
-    #[test]
-    fn in_memory_cache_expires_entries_on_lookup() {
-        let cache = InMemoryDnsCache::new(16);
-        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
-        let key = cache_key("example.com");
-        let other = cache_key("other.example");
-
-        cache.store_now(cache_store_at(key.clone(), Duration::from_secs(30), now));
-        cache.store_now(cache_store_at(other.clone(), Duration::from_secs(20), now));
-
-        let lookup = cache.lookup_now(&CacheLookupRequest {
-            key,
-            received_at: now + Duration::from_secs(30),
-        });
-
-        assert_eq!(lookup, CacheLookup::Expired);
-        assert_eq!(cache.len(), 1);
-        let other_lookup = cache.lookup_now(&CacheLookupRequest {
-            key: other,
-            received_at: now + Duration::from_secs(30),
-        });
-        assert_eq!(other_lookup, CacheLookup::Expired);
-        assert!(cache.is_empty());
-    }
-
-    #[test]
-    fn in_memory_cache_evicts_least_recently_used_entry_when_bounded() {
-        let cache = InMemoryDnsCache::new(2);
-        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
-        let first = cache_key("first.example");
-        let second = cache_key("second.example");
-        let third = cache_key("third.example");
-        cache.store_now(cache_store_at(first.clone(), Duration::from_secs(60), now));
-        cache.store_now(cache_store_at(second.clone(), Duration::from_secs(60), now));
-        assert!(matches!(
-            cache.lookup_now(&CacheLookupRequest {
-                key: first.clone(),
-                received_at: now
-            }),
-            CacheLookup::Hit(_)
-        ));
-
-        cache.store_now(cache_store_at(third.clone(), Duration::from_secs(60), now));
-
-        assert_eq!(cache.len(), 2);
-        assert!(matches!(
-            cache.lookup_now(&CacheLookupRequest {
-                key: first,
-                received_at: now
-            }),
-            CacheLookup::Hit(_)
-        ));
-        assert_eq!(
-            cache.lookup_now(&CacheLookupRequest {
-                key: second,
-                received_at: now
-            }),
-            CacheLookup::Miss
-        );
-        assert!(matches!(
-            cache.lookup_now(&CacheLookupRequest {
-                key: third,
-                received_at: now
-            }),
-            CacheLookup::Hit(_)
-        ));
-    }
-
-    #[test]
-    fn in_memory_cache_prunes_expired_entries_before_eviction() {
-        let cache = InMemoryDnsCache::new(2);
-        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
-        let later = now + Duration::from_secs(10);
-        let first = cache_key("first.example");
-        let expired = cache_key("expired.example");
-        let third = cache_key("third.example");
-        cache.store_now(cache_store_at(first.clone(), Duration::from_secs(60), now));
-        cache.store_now(cache_store_at(expired.clone(), Duration::from_secs(5), now));
-
-        cache.store_now(cache_store_at(
-            third.clone(),
-            Duration::from_secs(60),
-            later,
-        ));
-
-        assert_eq!(cache.len(), 2);
-        assert!(matches!(
-            cache.lookup_now(&CacheLookupRequest {
-                key: first,
-                received_at: later
-            }),
-            CacheLookup::Hit(_)
-        ));
-        assert_eq!(
-            cache.lookup_now(&CacheLookupRequest {
-                key: expired,
-                received_at: later
-            }),
-            CacheLookup::Miss
-        );
-        assert!(matches!(
-            cache.lookup_now(&CacheLookupRequest {
-                key: third,
-                received_at: later
-            }),
-            CacheLookup::Hit(_)
-        ));
-    }
-
-    #[test]
-    fn in_memory_cache_zero_capacity_stores_nothing() {
-        let cache = InMemoryDnsCache::new(0);
-        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
-        let key = cache_key("example.com");
-
-        cache.store_now(cache_store_at(key.clone(), Duration::from_secs(30), now));
-
-        assert_eq!(
-            cache.lookup_now(&CacheLookupRequest {
-                key,
-                received_at: now,
-            }),
-            CacheLookup::Miss
-        );
-        assert!(cache.is_empty());
-    }
-
-    #[test]
-    fn in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits() {
-        let cache = InMemoryDnsCache::new(2);
-        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
-        let key = cache_key("example.com");
-        cache.store_now(cache_store_at(key.clone(), Duration::from_secs(60), now));
-
-        for _ in 0..100 {
-            assert!(matches!(
-                cache.lookup_now(&CacheLookupRequest {
-                    key: key.clone(),
-                    received_at: now,
-                }),
-                CacheLookup::Hit(_)
-            ));
-        }
-
-        assert_eq!(cache.len(), 1);
-        assert!(cache.lru_len() <= lru_compaction_threshold(2));
-    }
-
-    #[test]
-    fn cache_key_from_query_includes_supported_semantics() {
-        let codec = StandardProtocolCodec::new(1232);
-        let query = codec
-            .decode_query(&a_query_with_edns(0x1234, "Example.COM", 4096, true))
-            .unwrap();
-
-        let key = CacheKey::from_query(&query, Some("primary".to_string()));
-
-        assert_eq!(key.question, QuestionKey::new("example.com", 1, 1));
-        assert_eq!(
-            key.features,
-            QueryFeatures {
-                recursion_desired: true,
-                authenticated_data: false,
-                checking_disabled: false,
-                dnssec_ok: true,
-                edns_udp_payload_size: Some(4096),
-            }
-        );
-        assert_eq!(key.cache_namespace.as_deref(), Some("primary"));
-    }
-
-    #[test]
-    fn cache_key_separates_question_type_class_and_policy() {
-        let codec = StandardProtocolCodec::new(4096);
-        let a_in = codec
-            .decode_query(&a_query_with_edns(0x1000, "example.com", 512, false))
-            .unwrap();
-        let aaaa_in = codec
-            .decode_query(&aaaa_query(0x1000, "example.com"))
-            .unwrap();
-        let a_ch = codec
-            .decode_query(&chaos_a_query(0x1000, "example.com"))
-            .unwrap();
-
-        let base = CacheKey::from_query(&a_in, Some("primary".to_string()));
-
-        assert_ne!(
-            base,
-            CacheKey::from_query(&aaaa_in, Some("primary".to_string()))
-        );
-        assert_ne!(
-            base,
-            CacheKey::from_query(&a_ch, Some("primary".to_string()))
-        );
-        assert_ne!(
-            base,
-            CacheKey::from_query(&a_in, Some("secondary".to_string()))
-        );
-    }
-
-    #[test]
-    fn cache_key_separates_exact_wire_question_casing_for_templates() {
-        let codec = StandardProtocolCodec::new(1232);
-        let lower = codec.decode_query(&a_query(0x1000, "example.com")).unwrap();
-        let mixed = codec.decode_query(&a_query(0x1000, "Example.COM")).unwrap();
-
-        assert_eq!(lower.question, mixed.question);
-        assert_ne!(
-            CacheKey::from_query(&lower, None),
-            CacheKey::from_query(&mixed, None)
-        );
-    }
-
-    #[test]
-    fn cache_key_separates_recursion_desired_header_flag() {
-        let codec = StandardProtocolCodec::new(1232);
-        let recursive = codec.decode_query(&a_query(0x1000, "example.com")).unwrap();
-        let non_recursive = codec
-            .decode_query(&a_query_without_rd(0x1000, "example.com"))
-            .unwrap();
-
-        assert_ne!(
-            CacheKey::from_query(&recursive, None),
-            CacheKey::from_query(&non_recursive, None)
-        );
-    }
-
-    #[test]
-    fn cache_key_separates_dnssec_request_flags() {
-        let codec = StandardProtocolCodec::new(1232);
-        let base = codec.decode_query(&a_query(0x1000, "example.com")).unwrap();
-        let ad = codec
-            .decode_query(&a_query_with_authenticated_data(0x1000, "example.com"))
-            .unwrap();
-        let cd = codec
-            .decode_query(&a_query_with_checking_disabled(0x1000, "example.com"))
-            .unwrap();
-        let do_query = codec
-            .decode_query(&a_query_with_edns(0x1000, "example.com", 1232, true))
-            .unwrap();
-
-        let base_key = CacheKey::from_query(&base, None);
-        assert_ne!(base_key, CacheKey::from_query(&ad, None));
-        assert_ne!(base_key, CacheKey::from_query(&cd, None));
-        assert_ne!(base_key, CacheKey::from_query(&do_query, None));
-        assert!(CacheKey::from_query(&ad, None).features.authenticated_data);
-        assert!(CacheKey::from_query(&cd, None).features.checking_disabled);
-        assert!(CacheKey::from_query(&do_query, None).features.dnssec_ok);
-    }
-
     #[test]
     fn block_response_config_defaults_to_uncacheable_refused() {
         let config = BlockResponseConfig::default();
@@ -12635,7 +12167,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xabcd, "blocked.example", 60),
         ))));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
         let policy = Arc::new(LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
@@ -12708,7 +12240,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xabcd, "blocked.example", 60),
         ))));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let events = Arc::new(RecordingEvents::default());
         let policy = Arc::new(LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
             "rule-1",
@@ -12774,7 +12306,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xabcd, "blocked.example", 60),
         ))));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let events = Arc::new(RecordingEvents::default());
         let policy = Arc::new(LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
             "rule-1",
@@ -12953,7 +12485,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xabcd, "host.example", 60),
         ))));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let events = Arc::new(RecordingEvents::default());
         let local_entries = Arc::new(InMemoryLocalDnsEntries::new(vec![
             LocalDnsEntry::new(
@@ -13126,7 +12658,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xabcd, "host.example", 60),
         ))));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let events = Arc::new(RecordingEvents::default());
         let service = ResolveQuery::with_cache_and_policy(
             Arc::new(StandardProtocolCodec::new(1232)),
@@ -13223,7 +12755,7 @@ mod tests {
         );
         let service = ResolveQuery::with_cache_and_policy(
             Arc::new(StandardProtocolCodec::new(1232)),
-            Arc::new(RecordingCache::with_lookup(CacheLookup::Miss)),
+            Arc::new(RecordingCache::with_lookup(ChainLookup::Miss)),
             Arc::new(NoopPolicyEvaluator),
             local_entries,
             CacheTtlPolicy::default(),
@@ -13256,7 +12788,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xabcd, "host.example", 60),
         ))));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let local_entries = Arc::new(InMemoryLocalDnsEntries::new(vec![
             LocalDnsEntry::new(
                 DomainName::parse("host.example").unwrap(),
@@ -13324,7 +12856,7 @@ mod tests {
         )]));
         let service = ResolveQuery::with_cache_and_policy(
             Arc::new(StandardProtocolCodec::new(1232)),
-            Arc::new(RecordingCache::with_lookup(CacheLookup::Miss)),
+            Arc::new(RecordingCache::with_lookup(ChainLookup::Miss)),
             policy,
             local_entries,
             CacheTtlPolicy::default(),
@@ -13381,7 +12913,7 @@ mod tests {
                 "test-forwarder",
             ),
         )));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
         let policy = Arc::new(MaliciousDomainPolicyEvaluator::new(vec![
@@ -13438,37 +12970,63 @@ mod tests {
         assert_eq!(metrics.count(ResolverMetric::QueryAllowed), 0);
     }
 
+    fn stored_record_from(record: &Record) -> StoredRecord {
+        StoredRecord {
+            rtype: record.rtype,
+            rclass: record.rclass,
+            ttl_at_store: record.ttl,
+            rdata: record.record.clone(),
+        }
+    }
+
+    fn seed_rrset_entry(
+        record: &Record,
+        ttl: Duration,
+        now: SystemTime,
+        namespace: &str,
+    ) -> RRsetEntry {
+        RRsetEntry {
+            records: vec![stored_record_from(record)],
+            rrsigs: Vec::new(),
+            response_code: ResponseCode::NoError,
+            minimum_ttl: ttl,
+            stored_at: now,
+            expires_at: now + ttl,
+            dnssec_state: Default::default(),
+            cache_namespace: namespace.to_string(),
+        }
+    }
+
     #[tokio::test]
     async fn resolve_blocks_cached_response_with_malicious_cname_target() {
-        let cache = Arc::new(InMemoryDnsCache::new(16));
-        let question = QuestionKey::new("alias.example", A_RECORD_TYPE, 1);
-        let cached_query = StandardProtocolCodec::new(1232)
-            .decode_query(&a_query(0xaaaa, "alias.example"))
-            .unwrap();
-        let response_message = response_message_for_question_with_id(
-            0,
-            question,
-            ResponseCode::NoError,
-            vec![
-                cname_record("alias.example", 60, "target.malicious.example"),
-                a_record("target.malicious.example", 60),
-            ],
-            Vec::new(),
-            Vec::new(),
-            false,
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let now = SystemTime::UNIX_EPOCH;
+        let namespace = backend_cache_namespace(ResolutionMode::Forward, 0).unwrap_or_default();
+        let cname = cname_record("alias.example", 60, "target.malicious.example");
+        let terminal = a_record("target.malicious.example", 60);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![
+                    (
+                        "alias.example".to_string(),
+                        CNAME_RECORD_TYPE,
+                        1,
+                        seed_rrset_entry(&cname, Duration::from_secs(60), now, &namespace),
+                    ),
+                    (
+                        "target.malicious.example".to_string(),
+                        A_RECORD_TYPE,
+                        1,
+                        seed_rrset_entry(&terminal, Duration::from_secs(60), now, &namespace),
+                    ),
+                ],
+                negative: None,
+            },
+            &namespace,
         );
-        cache.store_now(CacheStore {
-            key: CacheKey::from_query(
-                &cached_query,
-                backend_cache_namespace(ResolutionMode::Forward, 0),
-            ),
-            response_template: response_message.original_bytes.to_vec(),
-            response_code: ResponseCode::NoError,
-            minimum_ttl: Duration::from_secs(60),
-            negative_cache: None,
-            stored_at: SystemTime::UNIX_EPOCH,
-            ttl: Duration::from_secs(60),
-        });
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
@@ -13534,7 +13092,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xabcd, "blocked.malicious.example", 60),
         ))));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let policy = Arc::new(MaliciousDomainPolicyEvaluator::new(vec![
             MaliciousDomainRule::new(
                 "malware-feed",
@@ -13596,7 +13154,7 @@ mod tests {
                 "test-forwarder",
             ),
         )));
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let policy = Arc::new(MaliciousDomainPolicyEvaluator::new(vec![
             MaliciousDomainRule::new(
                 "malware-feed",
@@ -13712,30 +13270,26 @@ mod tests {
     }
 
     #[tokio::test]
-    async fn resolve_returns_cached_template_with_current_request_id() {
-        let cache = Arc::new(InMemoryDnsCache::new(16));
-        let cached_query = StandardProtocolCodec::new(1232)
-            .decode_query(&a_query(0xaaaa, "example.com"))
-            .unwrap();
-        cache.store_now(CacheStore {
-            key: CacheKey::from_query(
-                &cached_query,
-                backend_cache_namespace(ResolutionMode::Forward, 0),
-            ),
-            response_template: a_response_with_answer(0, "example.com", 60),
-            response_code: ResponseCode::NoError,
-            minimum_ttl: Duration::from_secs(60),
-            negative_cache: Some(negative_metadata(
-                "example.com",
-                "example.com",
-                1,
-                1,
-                NegativeCacheKind::NoData,
-                Duration::from_secs(60),
-            )),
-            stored_at: SystemTime::UNIX_EPOCH,
-            ttl: Duration::from_secs(60),
-        });
+    async fn resolve_returns_assembled_response_for_current_request_id() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let namespace = backend_cache_namespace(ResolutionMode::Forward, 0).unwrap_or_default();
+        let now = SystemTime::UNIX_EPOCH;
+        let record = a_record("example.com", 60);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(
+                    "example.com".to_string(),
+                    A_RECORD_TYPE,
+                    1,
+                    seed_rrset_entry(&record, Duration::from_secs(60), now, &namespace),
+                )],
+                negative: None,
+            },
+            &namespace,
+        );
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
@@ -13750,7 +13304,7 @@ mod tests {
         let outcome = service
             .resolve(ResolveRequest::new(
                 "192.0.2.10".parse().unwrap(),
-                SystemTime::UNIX_EPOCH,
+                now,
                 a_query(0x2222, "example.com"),
             ))
             .await;
@@ -13775,28 +13329,30 @@ mod tests {
             );
         }
         assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
-        assert_eq!(metrics.count(ResolverMetric::CacheNegativeHit), 1);
         assert_eq!(metrics.count(ResolverMetric::CacheMiss), 0);
     }
 
     #[tokio::test]
-    async fn resolve_rewrites_cached_response_rd_flag_for_current_request() {
-        let cache = Arc::new(InMemoryDnsCache::new(16));
-        let cached_query = StandardProtocolCodec::new(1232)
-            .decode_query(&a_query_without_rd(0xaaaa, "example.com"))
-            .unwrap();
-        cache.store_now(CacheStore {
-            key: CacheKey::from_query(
-                &cached_query,
-                backend_cache_namespace(ResolutionMode::Forward, 0),
-            ),
-            response_template: a_response_with_answer(0, "example.com", 60),
-            response_code: ResponseCode::NoError,
-            minimum_ttl: Duration::from_secs(60),
-            negative_cache: None,
-            stored_at: SystemTime::UNIX_EPOCH,
-            ttl: Duration::from_secs(60),
-        });
+    async fn resolve_rewrites_rd_flag_for_current_request_on_cache_hit() {
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let namespace = backend_cache_namespace(ResolutionMode::Forward, 0).unwrap_or_default();
+        let now = SystemTime::UNIX_EPOCH;
+        let record = a_record("example.com", 60);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(
+                    "example.com".to_string(),
+                    A_RECORD_TYPE,
+                    1,
+                    seed_rrset_entry(&record, Duration::from_secs(60), now, &namespace),
+                )],
+                negative: None,
+            },
+            &namespace,
+        );
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
@@ -13805,7 +13361,7 @@ mod tests {
         let outcome = service
             .resolve(ResolveRequest::new(
                 "192.0.2.10".parse().unwrap(),
-                SystemTime::UNIX_EPOCH,
+                now,
                 a_query_without_rd(0x2222, "example.com"),
             ))
             .await;
@@ -13817,22 +13373,25 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_ages_cached_response_ttls_for_current_request_time() {
-        let cache = Arc::new(InMemoryDnsCache::new(16));
-        let cached_query = StandardProtocolCodec::new(1232)
-            .decode_query(&a_query(0xaaaa, "example.com"))
-            .unwrap();
-        cache.store_now(CacheStore {
-            key: CacheKey::from_query(
-                &cached_query,
-                backend_cache_namespace(ResolutionMode::Forward, 0),
-            ),
-            response_template: a_response_with_answer(0, "example.com", 60),
-            response_code: ResponseCode::NoError,
-            minimum_ttl: Duration::from_secs(60),
-            negative_cache: None,
-            stored_at: SystemTime::UNIX_EPOCH,
-            ttl: Duration::from_secs(60),
-        });
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let namespace = backend_cache_namespace(ResolutionMode::Forward, 0).unwrap_or_default();
+        let now = SystemTime::UNIX_EPOCH;
+        let record = a_record("example.com", 60);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(
+                    "example.com".to_string(),
+                    A_RECORD_TYPE,
+                    1,
+                    seed_rrset_entry(&record, Duration::from_secs(60), now, &namespace),
+                )],
+                negative: None,
+            },
+            &namespace,
+        );
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
@@ -13841,7 +13400,7 @@ mod tests {
         let outcome = service
             .resolve(ResolveRequest::new(
                 "192.0.2.10".parse().unwrap(),
-                SystemTime::UNIX_EPOCH + Duration::from_secs(25),
+                now + Duration::from_secs(25),
                 a_query(0x2222, "example.com"),
             ))
             .await;
@@ -13853,22 +13412,28 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_caps_cached_response_ttls_to_remaining_cache_lifetime() {
-        let cache = Arc::new(InMemoryDnsCache::new(16));
-        let cached_query = StandardProtocolCodec::new(1232)
-            .decode_query(&a_query(0xaaaa, "example.com"))
-            .unwrap();
-        cache.store_now(CacheStore {
-            key: CacheKey::from_query(
-                &cached_query,
-                backend_cache_namespace(ResolutionMode::Forward, 0),
-            ),
-            response_template: a_response_with_answer(0, "example.com", 3600),
-            response_code: ResponseCode::NoError,
-            minimum_ttl: Duration::from_secs(60),
-            negative_cache: None,
-            stored_at: SystemTime::UNIX_EPOCH,
-            ttl: Duration::from_secs(60),
-        });
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let namespace = backend_cache_namespace(ResolutionMode::Forward, 0).unwrap_or_default();
+        let now = SystemTime::UNIX_EPOCH;
+        // Record's own wire TTL (3600) is far longer than the entry's
+        // governing lifetime (60s) — the assembled TTL must be capped by
+        // the latter, not the former.
+        let record = a_record("example.com", 3600);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![(
+                    "example.com".to_string(),
+                    A_RECORD_TYPE,
+                    1,
+                    seed_rrset_entry(&record, Duration::from_secs(60), now, &namespace),
+                )],
+                negative: None,
+            },
+            &namespace,
+        );
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
@@ -13877,7 +13442,7 @@ mod tests {
         let outcome = service
             .resolve(ResolveRequest::new(
                 "192.0.2.10".parse().unwrap(),
-                SystemTime::UNIX_EPOCH + Duration::from_secs(25),
+                now + Duration::from_secs(25),
                 a_query(0x2222, "example.com"),
             ))
             .await;
@@ -13889,17 +13454,30 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_truncates_oversized_cached_response_for_current_request() {
-        let mut oversized_response = a_response_with_answer(0, "example.com", 60);
-        oversized_response.extend(std::iter::repeat_n(0, 700));
-        let cached = CachedResponse {
-            response_template: oversized_response,
+        let now = SystemTime::UNIX_EPOCH;
+        let namespace = "ns-1".to_string();
+        let records: Vec<StoredRecord> = (0..40u8)
+            .map(|i| StoredRecord {
+                rtype: A_RECORD_TYPE,
+                rclass: 1,
+                ttl_at_store: 60,
+                rdata: RecordData::A(std::net::Ipv4Addr::new(192, 0, 2, i)),
+            })
+            .collect();
+        let entry = RRsetEntry {
+            records,
+            rrsigs: Vec::new(),
             response_code: ResponseCode::NoError,
             minimum_ttl: Duration::from_secs(60),
-            negative_cache: None,
-            stored_at: SystemTime::UNIX_EPOCH,
-            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
+            stored_at: now,
+            expires_at: now + Duration::from_secs(60),
+            dnssec_state: Default::default(),
+            cache_namespace: namespace,
+        };
+        let resolved = cache::ResolvedAnswer {
+            chain: vec![("example.com".to_string(), entry)],
         };
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Hit(cached)));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
@@ -13909,14 +13487,20 @@ mod tests {
         let outcome = service
             .resolve(ResolveRequest::new(
                 "192.0.2.10".parse().unwrap(),
-                SystemTime::UNIX_EPOCH,
+                now,
                 a_query(0x3333, "example.com"),
             ))
             .await;
 
         assert_eq!(&outcome.response_bytes[0..2], &[0x33, 0x33]);
         assert_ne!(outcome.response_bytes[2] & 0x02, 0);
-        assert_eq!(outcome.response_bytes.len(), 12);
+        assert_eq!(
+            Message::parse(&outcome.response_bytes)
+                .unwrap()
+                .answers
+                .len(),
+            0
+        );
         assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
         assert!(upstream.requests.lock().unwrap().is_empty());
         assert_eq!(metrics.count(ResolverMetric::CacheResponseTruncated), 1);
@@ -13925,47 +13509,50 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_treats_expired_cache_backend_hit_as_miss() {
-        let cached = CachedResponse {
-            response_template: a_response_with_answer(0, "example.com", 60),
-            response_code: ResponseCode::NoError,
-            minimum_ttl: Duration::from_secs(60),
-            negative_cache: None,
-            stored_at: SystemTime::UNIX_EPOCH,
-            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(30),
-        };
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Hit(cached)));
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
+        let namespace = backend_cache_namespace(ResolutionMode::Forward, 0).unwrap_or_default();
+        let stored_at = SystemTime::UNIX_EPOCH;
+        let record = a_record("example.com", 60);
+        let mut entry = seed_rrset_entry(&record, Duration::from_secs(30), stored_at, &namespace);
+        entry.expires_at = stored_at + Duration::from_secs(30);
+        cache.store_response(
+            DecomposedResponse {
+                positive: vec![("example.com".to_string(), A_RECORD_TYPE, 1, entry)],
+                negative: None,
+            },
+            &namespace,
+        );
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0x8888, "example.com", 60),
         ))));
         let events = Arc::new(RecordingEvents::default());
         let metrics = Arc::new(RecordingMetrics::default());
-        let service = resolve_service_with_cache(
-            upstream.clone(),
-            cache.clone(),
-            events,
-            metrics.clone(),
-            1232,
-        );
+        let service =
+            resolve_service_with_cache(upstream.clone(), cache, events, metrics.clone(), 1232);
 
         let outcome = service
             .resolve(ResolveRequest::new(
                 "192.0.2.10".parse().unwrap(),
-                SystemTime::UNIX_EPOCH + Duration::from_secs(31),
+                stored_at + Duration::from_secs(31),
                 a_query(0x8888, "example.com"),
             ))
             .await;
 
         assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
         assert_eq!(upstream.requests.lock().unwrap().len(), 1);
-        assert_eq!(cache.stores.lock().unwrap().len(), 1);
-        assert_eq!(metrics.count(ResolverMetric::CacheExpired), 1);
         assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
         assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
     }
 
     #[tokio::test]
     async fn resolve_coalesces_duplicate_cache_misses() {
-        let cache = Arc::new(InMemoryDnsCache::new(16));
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
         let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xaaaa, "example.com", 60),
         ))));
@@ -14035,7 +13622,10 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_blocks_coalesced_cache_hit_with_malicious_cname_target() {
-        let cache = Arc::new(InMemoryDnsCache::new(16));
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
         let question = QuestionKey::new("alias.example", A_RECORD_TYPE, 1);
         let response_message = response_message_for_question(
             question,
@@ -14138,34 +13728,15 @@ mod tests {
         assert_eq!(metrics.count(ResolverMetric::QueryAllowed), 1);
     }
 
-    #[tokio::test]
-    async fn single_flight_leader_drop_wakes_followers_and_clears_key() {
-        let coalescer = Arc::new(SingleFlightMisses::default());
-        let key = cache_key("example.com");
-        let SingleFlightTicket::Leader { key, flight } = coalescer.begin(key.clone()) else {
-            panic!("first miss should lead the flight");
-        };
-        let guard = SingleFlightLeader::new(Arc::clone(&coalescer), key.clone(), flight);
-        let SingleFlightTicket::Follower { flight } = coalescer.begin(key.clone()) else {
-            panic!("duplicate miss should follow the flight");
-        };
-
-        drop(guard);
-
-        let result = tokio::time::timeout(Duration::from_secs(1), flight.wait())
-            .await
-            .expect("follower should wake after leader cancellation");
-        assert!(matches!(result, Err(UpstreamError::Transport(_))));
-        let SingleFlightTicket::Leader { key, flight } = coalescer.begin(key) else {
-            panic!("cancelled flight should be removed");
-        };
-        SingleFlightLeader::new(Arc::clone(&coalescer), key, flight)
-            .complete(Err(UpstreamError::Timeout));
-    }
+    // `single_flight_leader_drop_wakes_followers_and_clears_key` (old flat
+    // `SingleFlightMisses`/`SingleFlightTicket`/`SingleFlightLeader`,
+    // removed by this section) is superseded by section-04's own
+    // `cache::singleflight` test suite, which already covers leader-drop
+    // cancellation and follower wakeup against the sharded replacement.
 
     #[tokio::test]
-    async fn resolve_stores_upstream_response_as_neutral_id_template() {
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+    async fn resolve_stores_upstream_response_as_decomposed_rrset_entry() {
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0xbeef, "example.com", 45),
         ))));
@@ -14186,14 +13757,16 @@ mod tests {
         assert_eq!(&outcome.response_bytes[0..2], &[0x44, 0x44]);
         let stores = cache.stores.lock().unwrap();
         assert_eq!(stores.len(), 1);
-        assert_eq!(&stores[0].response_template[0..2], &[0, 0]);
-        assert_eq!(stores[0].response_code, ResponseCode::NoError);
-        assert_eq!(stores[0].ttl, Duration::from_secs(45));
-        assert_eq!(stores[0].stored_at, request_time);
-        assert_eq!(
-            stores[0].key.question,
-            QuestionKey::new("example.com", 1, 1)
-        );
+        let (decomposed, _namespace) = &stores[0];
+        assert_eq!(decomposed.positive.len(), 1);
+        let (name, qtype, qclass, entry) = &decomposed.positive[0];
+        assert_eq!(name, "example.com");
+        assert_eq!(*qtype, A_RECORD_TYPE);
+        assert_eq!(*qclass, 1);
+        assert_eq!(entry.response_code, ResponseCode::NoError);
+        assert_eq!(entry.minimum_ttl, Duration::from_secs(45));
+        assert_eq!(entry.stored_at, request_time);
+        assert!(decomposed.negative.is_none());
         drop(stores);
         assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
         assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
@@ -14201,7 +13774,7 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_records_negative_cache_store_metrics() {
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             nxdomain_response_with_soa(0xabcd, "example.com", 30, 120),
         ))));
@@ -14221,17 +13794,19 @@ mod tests {
         assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
         let stores = cache.stores.lock().unwrap();
         assert_eq!(stores.len(), 1);
-        assert_eq!(stores[0].response_code, ResponseCode::NxDomain);
+        let (decomposed, _namespace) = &stores[0];
+        assert!(decomposed.positive.is_empty());
+        let (name, key, entry) = decomposed
+            .negative
+            .as_ref()
+            .expect("negative store expected");
+        assert_eq!(name, "example.com");
+        assert_eq!(key.qtype, None);
+        assert_eq!(key.qclass, 1);
+        assert_eq!(entry.kind, NegativeCacheKind::NxDomain);
         assert_eq!(
-            stores[0].negative_cache,
-            Some(negative_metadata(
-                "example.com",
-                "example.com",
-                1,
-                1,
-                NegativeCacheKind::NxDomain,
-                Duration::from_secs(30)
-            ))
+            entry.expires_at.duration_since(entry.stored_at).unwrap(),
+            Duration::from_secs(30)
         );
         drop(stores);
         assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
@@ -14240,7 +13815,7 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_honors_backend_do_not_cache_directive() {
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let mut response = upstream_response(a_response_with_answer(0x6666, "example.com", 60));
         response.cache_directive =
             ResolutionCacheDirective::DoNotCache(ResolutionNoCacheReason::BackendPolicy);
@@ -14346,7 +13921,10 @@ mod tests {
 
     #[tokio::test]
     async fn backend_generation_separates_cache_entries() {
-        let cache = Arc::new(InMemoryDnsCache::new(16));
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+        }));
         let first_backend = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0x1111, "example.com", 60),
         ))));
@@ -14406,7 +13984,7 @@ mod tests {
             a_response_with_answer(0x5555, "other.example", 60),
             multi_question_a_response_with_answer(0x5555, "example.com", 60),
         ] {
-            let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+            let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
             let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(response))));
             let events = Arc::new(RecordingEvents::default());
             let metrics = Arc::new(RecordingMetrics::default());
@@ -14431,7 +14009,7 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_rejects_backend_response_when_metadata_and_bytes_drift() {
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let mut response = upstream_response(a_response_with_answer(0x5555, "example.com", 60));
         response.bytes = a_response_with_answer(0x5555, "other.example", 60);
         let upstream = Arc::new(StaticUpstream::new(Ok(response)));
@@ -14457,7 +14035,7 @@ mod tests {
 
     #[tokio::test]
     async fn resolve_caches_response_when_question_differs_only_by_case() {
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0x5555, "example.com", 60),
         ))));
@@ -14477,49 +14055,22 @@ mod tests {
         assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
         let stores = cache.stores.lock().unwrap();
         assert_eq!(stores.len(), 1);
-        assert_eq!(
-            stores[0].key.question,
-            QuestionKey::new("example.com", 1, 1)
-        );
+        let (decomposed, _namespace) = &stores[0];
+        assert_eq!(decomposed.positive[0].0, "example.com");
         assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
         assert_eq!(metrics.count(ResolverMetric::CacheStoreSkipped), 0);
     }
 
-    #[tokio::test]
-    async fn resolve_does_not_store_after_cache_bypass_or_unavailable() {
-        for (lookup, metric) in [
-            (
-                CacheLookup::Bypass(CacheBypassReason::UnsupportedQueryFeature),
-                ResolverMetric::CacheBypass,
-            ),
-            (CacheLookup::Unavailable, ResolverMetric::CacheUnavailable),
-        ] {
-            let cache = Arc::new(RecordingCache::with_lookup(lookup));
-            let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
-                a_response_with_answer(0x6666, "example.com", 60),
-            ))));
-            let events = Arc::new(RecordingEvents::default());
-            let metrics = Arc::new(RecordingMetrics::default());
-            let service =
-                resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
-
-            let _ = service
-                .resolve(ResolveRequest::new(
-                    "192.0.2.10".parse().unwrap(),
-                    SystemTime::UNIX_EPOCH,
-                    a_query(0x6666, "example.com"),
-                ))
-                .await;
-
-            assert!(cache.stores.lock().unwrap().is_empty());
-            assert_eq!(metrics.count(metric), 1);
-            assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
-        }
-    }
+    // `resolve_does_not_store_after_cache_bypass_or_unavailable` (old flat
+    // `CacheLookup::Bypass`/`CacheLookup::Unavailable`, removed by this
+    // section) is superseded by `resolve_bypasses_cache_for_unsupported_edns_options`
+    // below, which already exercises the real bypass path (`cache_supported`
+    // returning false, not a canned lookup-result variant) and asserts the
+    // same "no lookup, no store" invariant.
 
     #[tokio::test]
     async fn resolve_bypasses_cache_for_unsupported_edns_options() {
-        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
             a_response_with_answer(0x7777, "example.com", 60),
         ))));
@@ -14549,7 +14100,7 @@ mod tests {
             a_query_with_edns_details(0x7777, "example.com", 1232, false, 0, 1, &[]),
             a_query_with_edns_flags(0x7777, "example.com", 1232, false, 0, 0, 0x4000, &[]),
         ] {
-            let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
+            let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
             let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
                 a_response_with_answer(0x7777, "example.com", 60),
             ))));
diff --git a/tests/recursive_perf.rs b/tests/recursive_perf.rs
index ab0c5ba..afc2210 100644
--- a/tests/recursive_perf.rs
+++ b/tests/recursive_perf.rs
@@ -16,14 +16,14 @@ use std::net::{IpAddr, Ipv4Addr};
 use std::sync::Arc;
 use std::time::{Duration, Instant, SystemTime};
 
-use rdns::config::{RecursiveResolutionConfig, ResolutionConfig, RuntimeConfig};
+use rdns::config::{CacheConfig, RecursiveResolutionConfig, ResolutionConfig, RuntimeConfig};
 use rdns::delivery::upstream::RecursiveAuthorityTransportClient;
 use rdns::protocol::Message;
 use rdns::resolver::{
-    BasicResponseFactory, CacheTtlPolicy, Clock, InMemoryDnsCache, MetricsSink,
-    QueryEventRecordResult, QueryEventSink, QueryEventV1, RecursiveResolutionBackend,
-    RecursiveResolverConfig, RecursiveRootHint, ResolveDecisionKind, ResolveQuery, ResolveRequest,
-    ResolverMetric, StandardProtocolCodec,
+    BasicResponseFactory, CacheTtlPolicy, Clock, MetricsSink, QueryEventRecordResult,
+    QueryEventSink, QueryEventV1, RecursiveResolutionBackend, RecursiveResolverConfig,
+    RecursiveRootHint, ResolveDecisionKind, ResolveQuery, ResolveRequest, ResolverMetric,
+    ShardedDnsCache, StandardProtocolCodec,
 };
 
 struct SystemClock;
@@ -141,7 +141,10 @@ fn resolver_without_cache(config: &RuntimeConfig) -> ResolveQuery {
 fn resolver_with_cache(config: &RuntimeConfig) -> ResolveQuery {
     ResolveQuery::with_cache(
         Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
-        Arc::new(InMemoryDnsCache::new(256)),
+        Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 256,
+            shard_count: None,
+        })),
         CacheTtlPolicy::default(),
         recursive_backend(config),
         Arc::new(BasicResponseFactory),
