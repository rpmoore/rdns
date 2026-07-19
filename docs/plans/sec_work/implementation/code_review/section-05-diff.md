diff --git a/src/config/mod.rs b/src/config/mod.rs
index 6d7c0a9..52713d4 100644
--- a/src/config/mod.rs
+++ b/src/config/mod.rs
@@ -1187,12 +1187,14 @@ fn canonical_authority_name(name: &str) -> Result<String, ConfigError> {
 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
 pub enum DnssecValidationMode {
     Disabled,
+    Enabled,
 }
 
 impl DnssecValidationMode {
     fn cache_namespace_label(self) -> &'static str {
         match self {
             Self::Disabled => "disabled",
+            Self::Enabled => "enabled",
         }
     }
 }
@@ -1996,7 +1998,8 @@ impl RawRecursiveResolutionConfig {
         self,
     ) -> Result<RecursiveResolutionConfig, ConfigError> {
         let dnssec_validation = match self.dnssec_validation.as_deref() {
-            None | Some("disabled") => DnssecValidationMode::Disabled,
+            None | Some("enabled") => DnssecValidationMode::Enabled,
+            Some("disabled") => DnssecValidationMode::Disabled,
             Some(other) => {
                 return Err(ConfigError::InvalidTomlConfig {
                     message: format!("unknown dnssec_validation mode: {other}"),
@@ -4014,10 +4017,85 @@ a.root-servers.net.      3600000      Aaaa  2001:503:ba3e::2:30
             recursive.allowed_transports,
             vec![RecursiveTransport::Udp, RecursiveTransport::Tcp]
         );
-        assert_eq!(recursive.dnssec_validation, DnssecValidationMode::Disabled);
+        assert_eq!(recursive.dnssec_validation, DnssecValidationMode::Enabled);
         assert_eq!(recursive.dname_handling, DnameHandlingPolicy::Defer);
     }
 
+    #[test]
+    fn dnssec_validation_mode_cache_namespace_labels_differ() {
+        assert_eq!(
+            DnssecValidationMode::Enabled.cache_namespace_label(),
+            "enabled"
+        );
+        assert_eq!(
+            DnssecValidationMode::Disabled.cache_namespace_label(),
+            "disabled"
+        );
+        assert_ne!(
+            DnssecValidationMode::Enabled.cache_namespace_label(),
+            DnssecValidationMode::Disabled.cache_namespace_label()
+        );
+    }
+
+    #[test]
+    fn toml_config_round_trip_honors_explicit_dnssec_validation_disabled() {
+        let mut toml = valid_toml();
+        toml.push_str(
+            r#"
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            dnssec_validation = "disabled"
+            "#,
+        );
+
+        let config = RuntimeConfig::from_toml_str(&toml).unwrap();
+        let recursive = config.resolution.recursive.as_ref().unwrap();
+        assert_eq!(recursive.dnssec_validation, DnssecValidationMode::Disabled);
+    }
+
+    #[test]
+    fn toml_config_round_trip_honors_explicit_dnssec_validation_enabled() {
+        let mut toml = valid_toml();
+        toml.push_str(
+            r#"
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            dnssec_validation = "enabled"
+            "#,
+        );
+
+        let config = RuntimeConfig::from_toml_str(&toml).unwrap();
+        let recursive = config.resolution.recursive.as_ref().unwrap();
+        assert_eq!(recursive.dnssec_validation, DnssecValidationMode::Enabled);
+    }
+
+    #[test]
+    fn toml_config_round_trip_rejects_unknown_dnssec_validation_mode() {
+        let mut toml = valid_toml();
+        toml.push_str(
+            r#"
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            dnssec_validation = "sometimes"
+            "#,
+        );
+
+        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();
+        assert!(matches!(error, ConfigError::InvalidTomlConfig { .. }));
+    }
+
     #[test]
     fn toml_config_round_trip_loads_custom_recursive_root_hints() {
         // Recursive mode doesn't require any forwarding upstreams to be configured.
diff --git a/src/main.rs b/src/main.rs
index be7a2f2..41839f5 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -25,7 +25,7 @@ use opentelemetry::metrics::{Counter, Gauge, Histogram, MeterProvider, Observabl
 use opentelemetry_sdk::metrics::SdkMeterProvider;
 use prometheus::Registry;
 use rdns::config::{
-    LocalZoneConfig, MAX_LOCAL_ZONE_FILE_BYTES, RefreshConfig,
+    DnssecValidationMode, LocalZoneConfig, MAX_LOCAL_ZONE_FILE_BYTES, RefreshConfig,
     ResolutionMode as ConfigResolutionMode, RootHintsSource as ConfigRootHintsSource,
     RuntimeConfig, parse_local_zone_file,
 };
@@ -34,9 +34,9 @@ use rdns::delivery::metrics_http::MetricsServer;
 use rdns::delivery::upstream::{ForwardingResolutionBackend, RecursiveAuthorityTransportClient};
 use rdns::resolver::{
     BackendHealth, BackendRootHintsStatus, BackendSnapshot, BackendStatus, BasicResponseFactory,
-    CacheTtlPolicy, ChannelQueryEventSink, Clock, CookieSecret, DnssecValidationStatus,
-    DomainDnsCache, DomainName, InMemoryLocalDnsEntries, InMemoryQueryEventStore,
-    InMemoryQueryEventStoreConfig, InMemorySuspiciousLookupClassifier,
+    CacheTtlPolicy, ChannelQueryEventSink, Clock, CookieSecret, DnssecValidationOutcome,
+    DnssecValidationStatus, DomainDnsCache, DomainName, InMemoryLocalDnsEntries,
+    InMemoryQueryEventStore, InMemoryQueryEventStoreConfig, InMemorySuspiciousLookupClassifier,
     InMemorySuspiciousLookupClassifierConfig, LocalDnsEntry, MetricsSink, NoopPolicyEvaluator,
     QueryEventRecordResult, QueryEventSink, QueryEventV1, RecursiveResolutionBackend,
     RecursiveResolverConfig, RecursiveRootHint, ResolutionMode as ResolverResolutionMode,
@@ -134,21 +134,6 @@ async fn main() -> io::Result<()> {
     let cookie_secret = Arc::new(CookieSecret::generate());
     let (refresh_tx, refresh_rx) =
         tokio::sync::mpsc::channel(refresh_channel_capacity(&config.refresh));
-    // `ResolveQuery::with_trust_anchors` is deliberately NOT called here yet.
-    // `DnssecValidationMode` (`config/mod.rs`) currently only has a
-    // `Disabled` variant -- there is no config-level way to opt into
-    // validation yet, so wiring real trust anchors in unconditionally would
-    // make every `ResolutionMode::Recursive` fetch validate regardless of
-    // that mode, with no kill switch. Confirmed against a live recursive
-    // instance: ordinary (unsigned) domains started coming back SERVFAIL,
-    // since a domain with no DS/DNSKEY chain validates as `Bogus` in some
-    // paths, not `Insecure`, and `dnssec_servfail_check` then forces
-    // SERVFAIL for any CD=0 requester -- a severe regression for the
-    // current (validation-off) default. Section-05 (`DnssecValidationMode::
-    // Enabled`, defaulted on deliberately, with its own rollout/metrics
-    // story) is where this gets wired live; until then the mechanism stays
-    // built and tested (`ResolveQuery::validate_for_store`) but unreachable
-    // in production, matching every existing `ResolveQuery` default.
     let mut resolver_builder = ResolveQuery::with_cache_policy_and_backend_snapshot(
         Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
         Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
@@ -173,6 +158,14 @@ async fn main() -> io::Result<()> {
     if config.refresh.enabled {
         resolver_builder = resolver_builder.with_refresh_sender(refresh_tx);
     }
+    // Leaving `ResolveQuery::trust_anchors` at its default `None` is the
+    // actual DNSSEC kill switch: `validate_for_store` treats "no trust
+    // anchors configured" as "don't run the DS/DNSKEY chase at all" (see
+    // its doc comment), so this is the one place that decision takes
+    // effect in production, not just in tests.
+    if let Some(trust_anchors) = trust_anchors_to_wire_in(&config)? {
+        resolver_builder = resolver_builder.with_trust_anchors(trust_anchors);
+    }
     let resolver = Arc::new(resolver_builder);
 
     let sighup_task =
@@ -764,6 +757,11 @@ fn build_forward_backend_snapshot(config: &RuntimeConfig) -> io::Result<BackendS
         ForwardingResolutionBackend::from_runtime_config(config)
             .map_err(|error| io::Error::other(format!("invalid upstream config: {error:?}")))?,
     );
+    // No `.with_dnssec_validation_status(...)` call -- `BackendSnapshot::new`'s
+    // default (`Disabled`) is correct and intentional here, not a missed
+    // wiring spot: Forward mode has no DNSSEC validation concept at all
+    // (see `ResolveQuery::validate_for_store`'s doc comment), so its status
+    // must always read `Disabled` regardless of any config value.
     Ok(BackendSnapshot::new(
         backend,
         ResolverResolutionMode::Forward,
@@ -819,6 +817,9 @@ fn build_recursive_backend_snapshot(
         root_hints_source_label(&recursive.root_hints_source),
         recursive.root_hints_version.clone(),
         SystemTime::now(),
+    ))
+    .with_dnssec_validation_status(dnssec_validation_status_for_mode(
+        recursive.dnssec_validation,
     )))
 }
 
@@ -829,6 +830,38 @@ fn root_hints_source_label(source: &ConfigRootHintsSource) -> &'static str {
     }
 }
 
+/// Maps the config-level `DnssecValidationMode` onto the resolver-level
+/// `DnssecValidationStatus` -- kept as a free function rather than a method
+/// on either enum since the two types are deliberately duplicated across
+/// the config/resolver layer boundary (mirrors `ResolutionMode`/
+/// `ResolverResolutionMode`).
+fn dnssec_validation_status_for_mode(mode: DnssecValidationMode) -> DnssecValidationStatus {
+    match mode {
+        DnssecValidationMode::Disabled => DnssecValidationStatus::Disabled,
+        DnssecValidationMode::Enabled => DnssecValidationStatus::Enabled,
+    }
+}
+
+/// The trust anchors to hand `ResolveQuery::with_trust_anchors`, or `None`
+/// to leave the resolver's default (`None`, meaning "never validate")
+/// untouched. `None` is returned both for `ResolutionMode::Forward` (no
+/// `[resolution.recursive]` section at all) and for
+/// `DnssecValidationMode::Disabled` -- either way, `validate_for_store`
+/// must never see any configured anchors, since their mere presence is
+/// the sole signal it uses to decide whether to run the DS/DNSKEY chase.
+fn trust_anchors_to_wire_in(config: &RuntimeConfig) -> io::Result<Option<Vec<String>>> {
+    let Some(recursive) = config.resolution.recursive.as_ref() else {
+        return Ok(None);
+    };
+    if recursive.dnssec_validation != DnssecValidationMode::Enabled {
+        return Ok(None);
+    }
+    recursive
+        .load_trust_anchors()
+        .map(Some)
+        .map_err(|error| io::Error::other(format!("invalid trust anchors: {error:?}")))
+}
+
 fn listener_task_result_to_io(result: Result<io::Result<()>, JoinError>) -> io::Result<()> {
     result.map_err(|error| io::Error::other(format!("dns listener task failed: {error}")))?
 }
@@ -930,6 +963,7 @@ struct OpenTelemetryMetrics {
     backend_generation: Gauge<u64>,
     root_hints_age_seconds: Gauge<f64>,
     dnssec_validation_disabled: Gauge<u64>,
+    dnssec_validation_results_total: Counter<u64>,
     protocol_error_total: Counter<u64>,
     recursion_refused_total: Counter<u64>,
     refresh_triggered_total: Counter<u64>,
@@ -1041,6 +1075,9 @@ impl OpenTelemetryMetrics {
             backend_generation: meter.u64_gauge("backend_generation").build(),
             root_hints_age_seconds: meter.f64_gauge("root_hints_age_seconds").build(),
             dnssec_validation_disabled: meter.u64_gauge("dnssec_validation_disabled").build(),
+            dnssec_validation_results_total: meter
+                .u64_counter("dnssec_validation_results_total")
+                .build(),
             protocol_error_total: meter.u64_counter("protocol_error_total").build(),
             recursion_refused_total: meter.u64_counter("recursion_refused_total").build(),
             refresh_triggered_total: meter.u64_counter("refresh_triggered_total").build(),
@@ -1267,6 +1304,13 @@ impl MetricsSink for OpenTelemetryMetrics {
                 .record(age.as_secs_f64(), &attributes);
         }
     }
+
+    fn record_dnssec_validation_outcome(&self, outcome: DnssecValidationOutcome) {
+        self.dnssec_validation_results_total.add(
+            1,
+            &[KeyValue::new("outcome", dnssec_outcome_label(outcome))],
+        );
+    }
 }
 
 fn backend_status_attributes(status: &BackendStatus) -> Vec<KeyValue> {
@@ -1310,6 +1354,17 @@ fn backend_health_label(health: BackendHealth) -> &'static str {
 fn dnssec_validation_label(status: DnssecValidationStatus) -> &'static str {
     match status {
         DnssecValidationStatus::Disabled => "disabled",
+        DnssecValidationStatus::Enabled => "enabled",
+    }
+}
+
+fn dnssec_outcome_label(outcome: DnssecValidationOutcome) -> &'static str {
+    match outcome {
+        DnssecValidationOutcome::Secure => "secure",
+        DnssecValidationOutcome::Insecure => "insecure",
+        DnssecValidationOutcome::Bogus => "bogus",
+        DnssecValidationOutcome::Indeterminate => "indeterminate",
+        DnssecValidationOutcome::NotAttempted => "not_attempted",
     }
 }
 
@@ -1538,6 +1593,245 @@ mod tests {
         assert_eq!(labeled.get_histogram().get_sample_count(), 1);
     }
 
+    #[test]
+    fn dnssec_validation_label_differs_by_status() {
+        assert_eq!(
+            dnssec_validation_label(DnssecValidationStatus::Enabled),
+            "enabled"
+        );
+        assert_eq!(
+            dnssec_validation_label(DnssecValidationStatus::Disabled),
+            "disabled"
+        );
+    }
+
+    #[test]
+    fn dnssec_outcome_label_covers_every_outcome() {
+        assert_eq!(
+            dnssec_outcome_label(DnssecValidationOutcome::Secure),
+            "secure"
+        );
+        assert_eq!(
+            dnssec_outcome_label(DnssecValidationOutcome::Insecure),
+            "insecure"
+        );
+        assert_eq!(
+            dnssec_outcome_label(DnssecValidationOutcome::Bogus),
+            "bogus"
+        );
+        assert_eq!(
+            dnssec_outcome_label(DnssecValidationOutcome::Indeterminate),
+            "indeterminate"
+        );
+        assert_eq!(
+            dnssec_outcome_label(DnssecValidationOutcome::NotAttempted),
+            "not_attempted"
+        );
+    }
+
+    fn sample_backend_status(dnssec_validation: DnssecValidationStatus) -> BackendStatus {
+        BackendStatus {
+            mode: ResolverResolutionMode::Recursive,
+            generation: 1,
+            health: BackendHealth::Healthy,
+            dnssec_validation,
+            cache_namespace: None,
+            root_hints: None,
+        }
+    }
+
+    #[test]
+    fn record_backend_status_dnssec_gauge_reflects_enabled_and_disabled() {
+        let cache = Arc::new(ShardedDnsCache::new(&rdns::config::CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+            ..rdns::config::CacheConfig::default()
+        }));
+        let metrics =
+            OpenTelemetryMetrics::new(Arc::clone(&cache), true).expect("metrics exporter");
+        let gauge_value = |families: &prometheus::proto::MetricFamily| -> f64 {
+            families.get_metric().first().unwrap().get_gauge().value()
+        };
+
+        metrics.record_backend_status(&sample_backend_status(DnssecValidationStatus::Enabled));
+        let families = metrics.registry.gather();
+        let family = families
+            .iter()
+            .find(|family| family.name() == "dnssec_validation_disabled")
+            .expect("dnssec_validation_disabled family");
+        assert_eq!(gauge_value(family), 0.0);
+
+        metrics.record_backend_status(&sample_backend_status(DnssecValidationStatus::Disabled));
+        let families = metrics.registry.gather();
+        let family = families
+            .iter()
+            .find(|family| family.name() == "dnssec_validation_disabled")
+            .expect("dnssec_validation_disabled family");
+        assert_eq!(gauge_value(family), 1.0);
+    }
+
+    #[test]
+    fn record_dnssec_validation_outcome_increments_labeled_counter() {
+        let cache = Arc::new(ShardedDnsCache::new(&rdns::config::CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+            ..rdns::config::CacheConfig::default()
+        }));
+        let metrics =
+            OpenTelemetryMetrics::new(Arc::clone(&cache), true).expect("metrics exporter");
+
+        metrics.record_dnssec_validation_outcome(DnssecValidationOutcome::Secure);
+        metrics.record_dnssec_validation_outcome(DnssecValidationOutcome::Secure);
+        metrics.record_dnssec_validation_outcome(DnssecValidationOutcome::NotAttempted);
+
+        let families = metrics.registry.gather();
+        let series_value = |outcome: &str| -> f64 {
+            families
+                .iter()
+                .find(|family| family.name() == "dnssec_validation_results_total")
+                .and_then(|family| {
+                    family.get_metric().iter().find(|metric| {
+                        metric
+                            .get_label()
+                            .iter()
+                            .any(|label| label.name() == "outcome" && label.value() == outcome)
+                    })
+                })
+                .map(|metric| metric.get_counter().value())
+                .unwrap_or_else(|| panic!("missing outcome={outcome} series"))
+        };
+
+        assert_eq!(series_value("secure"), 2.0);
+        assert_eq!(series_value("not_attempted"), 1.0);
+    }
+
+    #[test]
+    fn dnssec_validation_status_for_mode_maps_both_variants() {
+        assert_eq!(
+            dnssec_validation_status_for_mode(DnssecValidationMode::Enabled),
+            DnssecValidationStatus::Enabled
+        );
+        assert_eq!(
+            dnssec_validation_status_for_mode(DnssecValidationMode::Disabled),
+            DnssecValidationStatus::Disabled
+        );
+    }
+
+    /// Closes the gap section-05 found: before this section,
+    /// `build_recursive_backend_snapshot` always produced
+    /// `DnssecValidationStatus::Disabled` regardless of config.
+    #[test]
+    fn build_recursive_backend_snapshot_reflects_configured_dnssec_validation() {
+        let mut toml = sample_config_toml().to_string();
+        toml.push_str(
+            r#"
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            dnssec_validation = "enabled"
+            "#,
+        );
+        let config = RuntimeConfig::from_toml_str(&toml).unwrap();
+        let cache = Arc::new(ShardedDnsCache::new(&rdns::config::CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+            ..rdns::config::CacheConfig::default()
+        }));
+        let metrics: Arc<dyn MetricsSink> =
+            Arc::new(OpenTelemetryMetrics::new(cache, true).expect("metrics exporter"));
+
+        let snapshot = build_recursive_backend_snapshot(&config, metrics).unwrap();
+        assert_eq!(snapshot.dnssec_validation, DnssecValidationStatus::Enabled);
+    }
+
+    #[test]
+    fn build_recursive_backend_snapshot_stays_disabled_when_configured_disabled() {
+        let mut toml = sample_config_toml().to_string();
+        toml.push_str(
+            r#"
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            dnssec_validation = "disabled"
+            "#,
+        );
+        let config = RuntimeConfig::from_toml_str(&toml).unwrap();
+        let cache = Arc::new(ShardedDnsCache::new(&rdns::config::CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+            ..rdns::config::CacheConfig::default()
+        }));
+        let metrics: Arc<dyn MetricsSink> =
+            Arc::new(OpenTelemetryMetrics::new(cache, true).expect("metrics exporter"));
+
+        let snapshot = build_recursive_backend_snapshot(&config, metrics).unwrap();
+        assert_eq!(snapshot.dnssec_validation, DnssecValidationStatus::Disabled);
+    }
+
+    /// Forward mode has no DNSSEC concept at all (A5's scope) -- its status
+    /// must stay `Disabled` no matter what, since there is no
+    /// `[resolution.recursive]` section to read a mode from.
+    #[test]
+    fn build_forward_backend_snapshot_is_always_dnssec_disabled() {
+        let config = RuntimeConfig::from_toml_str(sample_config_toml()).unwrap();
+        let snapshot = build_forward_backend_snapshot(&config).unwrap();
+        assert_eq!(snapshot.dnssec_validation, DnssecValidationStatus::Disabled);
+    }
+
+    #[test]
+    fn trust_anchors_to_wire_in_is_none_when_dnssec_validation_disabled() {
+        let mut toml = sample_config_toml().to_string();
+        toml.push_str(
+            r#"
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            dnssec_validation = "disabled"
+            "#,
+        );
+        let config = RuntimeConfig::from_toml_str(&toml).unwrap();
+        assert!(trust_anchors_to_wire_in(&config).unwrap().is_none());
+    }
+
+    #[test]
+    fn trust_anchors_to_wire_in_is_none_for_forward_mode() {
+        let config = RuntimeConfig::from_toml_str(sample_config_toml()).unwrap();
+        assert!(trust_anchors_to_wire_in(&config).unwrap().is_none());
+    }
+
+    #[test]
+    fn trust_anchors_to_wire_in_loads_bundled_anchors_when_enabled() {
+        let mut toml = sample_config_toml().to_string();
+        toml.push_str(
+            r#"
+            [resolution]
+            mode = "recursive"
+
+            [resolution.recursive]
+            root_hints = "bundled"
+            root_hints_version = "bundled:v1"
+            dnssec_validation = "enabled"
+            "#,
+        );
+        let config = RuntimeConfig::from_toml_str(&toml).unwrap();
+        let trust_anchors = trust_anchors_to_wire_in(&config)
+            .unwrap()
+            .expect("Enabled mode must produce Some(trust anchors)");
+        assert!(
+            !trust_anchors.is_empty(),
+            "bundled trust anchor source must yield at least one anchor line"
+        );
+    }
+
     /// Interning returns the identical attribute set for repeats of one
     /// IP, and IPs past `MAX_SOURCE_IP_SERIES` collapse into the shared
     /// `source_ip="other"` set instead of growing the cache — the
diff --git a/src/resolver/cache/entry.rs b/src/resolver/cache/entry.rs
index b752a0d..3503188 100644
--- a/src/resolver/cache/entry.rs
+++ b/src/resolver/cache/entry.rs
@@ -100,9 +100,9 @@ pub struct StoredRecord {
 /// covers both "never validated" (DNSSEC validation not attempted for this
 /// entry) and `domain`'s `ValidationState::Indeterminate` (ran but
 /// inconclusive) — `dnssec_validation::validate_response`'s
-/// `DnssecValidationOutcome` carries the raw `ValidationState` alongside
+/// `ValidationRunOutcome` carries the raw `ValidationState` alongside
 /// this collapsed value so callers that need to tell those two cases apart
-/// (e.g. section-05's metrics) still can.
+/// (e.g. section-05's `DnssecValidationOutcome` metric) still can.
 #[derive(Debug, Clone, PartialEq, Eq, Default)]
 pub enum DnssecState {
     #[default]
diff --git a/src/resolver/dnssec_validation.rs b/src/resolver/dnssec_validation.rs
index defae95..ddee63d 100644
--- a/src/resolver/dnssec_validation.rs
+++ b/src/resolver/dnssec_validation.rs
@@ -75,7 +75,7 @@ pub(crate) fn validator_config() -> ValidatorConfig {
 /// ran" (section-05's metrics) still can -- `DnssecState::Unvalidated`
 /// alone can't tell those apart.
 #[derive(Debug, Clone, PartialEq)]
-pub(crate) struct DnssecValidationOutcome {
+pub(crate) struct ValidationRunOutcome {
     pub(crate) state: DnssecState,
     pub(crate) validation_state: ValidationState,
 }
@@ -93,8 +93,8 @@ fn map_validation_state(state: ValidationState, reason: Option<String>) -> Dnsse
     }
 }
 
-fn bogus_outcome(reason: impl Into<String>) -> DnssecValidationOutcome {
-    DnssecValidationOutcome {
+fn bogus_outcome(reason: impl Into<String>) -> ValidationRunOutcome {
+    ValidationRunOutcome {
         state: DnssecState::Bogus(reason.into()),
         validation_state: ValidationState::Bogus,
     }
@@ -121,7 +121,7 @@ pub(crate) async fn validate_response(
     backend: Arc<dyn ResolutionBackend>,
     backend_generation: u64,
     deadline: Instant,
-) -> DnssecValidationOutcome {
+) -> ValidationRunOutcome {
     let bytes = Bytes::copy_from_slice(response.original_bytes.as_ref());
     let mut domain_msg = match DomainMessage::from_octets(bytes) {
         Ok(msg) => msg,
@@ -149,7 +149,7 @@ pub(crate) async fn validate_response(
     match outcome {
         Ok(Ok((state, ede))) => {
             let reason = ede.map(|e| e.to_string());
-            DnssecValidationOutcome {
+            ValidationRunOutcome {
                 state: map_validation_state(state, reason),
                 validation_state: state,
             }
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index a8923d9..c387c01 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -24,6 +24,7 @@ use std::time::{Duration, SystemTime};
 
 use bytes::Bytes;
 use domain::dnssec::validator::anchor::TrustAnchors;
+use domain::dnssec::validator::context::ValidationState;
 use serde::Serialize;
 use tokio::sync::mpsc;
 use tokio::task::JoinSet;
@@ -60,7 +61,7 @@ pub use cache::{
 
 mod dnssec_validation;
 #[allow(unused_imports)] // wired in by section-04
-pub(crate) use dnssec_validation::{DnssecValidationOutcome, validate_response, validator_config};
+pub(crate) use dnssec_validation::{ValidationRunOutcome, validate_response, validator_config};
 
 pub mod policy;
 pub use policy::{
@@ -2470,6 +2471,28 @@ pub enum BackendHealth {
 #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
 pub enum DnssecValidationStatus {
     Disabled,
+    Enabled,
+}
+
+/// Per-query DNSSEC validation outcome, recorded via
+/// `MetricsSink::record_dnssec_validation_outcome` as the
+/// `dnssec_validation_results_total` counter's `outcome` label. Distinct
+/// from `dnssec_validation::ValidationRunOutcome` (the internal
+/// state/`ValidationState` pair `validate_for_store` consumes) -- this is
+/// the metrics-facing, five-way label set, not a richer status/mode enum.
+#[derive(Debug, Clone, Copy, PartialEq, Eq)]
+pub enum DnssecValidationOutcome {
+    Secure,
+    Insecure,
+    Bogus,
+    Indeterminate,
+    /// Validation did not run for this query: either
+    /// `DnssecValidationMode::Disabled` (no trust anchors configured), or
+    /// the query never reached the recursive validation path at all.
+    /// Distinct from `Indeterminate` (validation ran and came back
+    /// inconclusive) -- collapsing the two would make it impossible for an
+    /// operator to tell "DNSSEC is off" from "DNSSEC is on and confused."
+    NotAttempted,
 }
 
 #[derive(Debug, Clone, PartialEq, Eq)]
@@ -2573,6 +2596,11 @@ impl BackendSnapshot {
         self
     }
 
+    pub fn with_dnssec_validation_status(mut self, status: DnssecValidationStatus) -> Self {
+        self.dnssec_validation = status;
+        self
+    }
+
     pub fn status(&self) -> BackendStatus {
         BackendStatus {
             mode: self.mode,
@@ -6238,6 +6266,13 @@ impl ResolveQuery {
     /// treating this as a bug to silently fix later.
     async fn validate_for_store(&self, response: &Message) -> DnssecState {
         let Some(trust_anchor_lines) = self.trust_anchors.as_ref() else {
+            // No trust anchors configured -- either `DnssecValidationMode::
+            // Disabled` (main.rs never wires anchors in for that mode) or a
+            // constructor that never called `with_trust_anchors`. Either
+            // way, the DS/DNSKEY chase never runs, so this is
+            // `NotAttempted`, not `Indeterminate`.
+            self.metrics
+                .record_dnssec_validation_outcome(DnssecValidationOutcome::NotAttempted);
             return DnssecState::Unvalidated;
         };
         let trust_anchors = match TrustAnchors::from_u8(trust_anchor_lines.join("\n").as_bytes()) {
@@ -6254,6 +6289,13 @@ impl ResolveQuery {
                     "configured DNSSEC trust anchors failed to parse; \
                      validation unavailable for this fetch"
                 );
+                // The chase never ran here either (parsing failed before any
+                // query was sent), so this is `NotAttempted` for metrics
+                // purposes too, same as "no trust anchors configured" above
+                // -- distinct from the stored `DnssecState::Unvalidated`,
+                // which is a separate signal.
+                self.metrics
+                    .record_dnssec_validation_outcome(DnssecValidationOutcome::NotAttempted);
                 return DnssecState::Unvalidated;
             }
         };
@@ -6267,6 +6309,8 @@ impl ResolveQuery {
             deadline,
         )
         .await;
+        self.metrics
+            .record_dnssec_validation_outcome(dnssec_outcome_metric(outcome.validation_state));
         outcome.state
     }
 
@@ -6453,6 +6497,19 @@ impl ResolveQuery {
     }
 }
 
+/// Maps `domain`'s raw `ValidationState` (from a completed validator run --
+/// i.e. `validate_response` was actually called, unlike the `NotAttempted`
+/// cases in `validate_for_store`) onto the metrics-facing
+/// `DnssecValidationOutcome`.
+fn dnssec_outcome_metric(state: ValidationState) -> DnssecValidationOutcome {
+    match state {
+        ValidationState::Secure => DnssecValidationOutcome::Secure,
+        ValidationState::Insecure => DnssecValidationOutcome::Insecure,
+        ValidationState::Bogus => DnssecValidationOutcome::Bogus,
+        ValidationState::Indeterminate => DnssecValidationOutcome::Indeterminate,
+    }
+}
+
 fn request_id_from_wire(bytes: &[u8]) -> Option<u16> {
     let id = bytes.get(0..2)?;
     Some(u16::from_be_bytes([id[0], id[1]]))
@@ -9133,6 +9190,12 @@ pub trait MetricsSink: Send + Sync {
 
     fn record_backend_status(&self, _status: &BackendStatus) {}
 
+    /// Records one DNSSEC validation outcome for a stored cache entry.
+    /// Called exactly once per `ResolutionMode::Recursive` store (never for
+    /// `Forward`, which has no DNSSEC concept -- see `validate_for_store`'s
+    /// call sites).
+    fn record_dnssec_validation_outcome(&self, _outcome: DnssecValidationOutcome) {}
+
     /// Per-query variant of `increment` carrying the requesting client's
     /// source IP, so sinks can label the metric by where the query came
     /// from. The resolver calls this (never plain `increment`) for every
@@ -10898,9 +10961,14 @@ mod tests {
         backend_statuses: Mutex<Vec<BackendStatus>>,
         source_increments: Mutex<Vec<(ResolverMetric, IpAddr)>>,
         source_durations: Mutex<Vec<(ResolverMetric, IpAddr)>>,
+        dnssec_outcomes: Mutex<Vec<DnssecValidationOutcome>>,
     }
 
     impl MetricsSink for RecordingMetrics {
+        fn record_dnssec_validation_outcome(&self, outcome: DnssecValidationOutcome) {
+            self.dnssec_outcomes.lock().unwrap().push(outcome);
+        }
+
         fn increment(&self, metric: ResolverMetric) {
             self.increments.lock().unwrap().push(metric);
         }
@@ -11778,11 +11846,12 @@ mod tests {
             DNSKEY_RECORD_TYPE,
             material.dnskey_response_wire.clone(),
         )]));
+        let metrics = Arc::new(RecordingMetrics::default());
         let service = resolve_service_with_recursive_cache(
             backend,
             Arc::new(NoopDnsCache),
             Arc::new(RecordingEvents::default()),
-            Arc::new(RecordingMetrics::default()),
+            Arc::clone(&metrics),
             1232,
         )
         .with_trust_anchors(vec![material.trust_anchor_line.clone()]);
@@ -11795,6 +11864,45 @@ mod tests {
             DnssecState::Secure,
             "expected a real validator run against a known-good signed response to produce Secure"
         );
+        assert_eq!(
+            *metrics.dnssec_outcomes.lock().unwrap(),
+            vec![DnssecValidationOutcome::Secure]
+        );
+    }
+
+    #[tokio::test]
+    async fn validate_for_store_records_bogus_outcome_for_a_tampered_signature() {
+        use crate::resolver::dnssec_validation::tests::fixture;
+        use domain::rdata::dnssec::Timestamp;
+
+        let now = Timestamp::now();
+        let expiration = Timestamp::from(now.into_int().wrapping_add(3600));
+        let material = fixture::build_zone("example.test.", now, expiration);
+        let mut wire = material.a_response_wire.clone();
+        fixture::flip_last_byte_of(&mut wire, &material.a_rrsig_rdata);
+        let backend: Arc<dyn ResolutionBackend> = Arc::new(ScriptedNameKeyedBackend::new(vec![(
+            material.apex.trim_end_matches('.').to_string(),
+            DNSKEY_RECORD_TYPE,
+            material.dnskey_response_wire.clone(),
+        )]));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service_with_recursive_cache(
+            backend,
+            Arc::new(NoopDnsCache),
+            Arc::new(RecordingEvents::default()),
+            Arc::clone(&metrics),
+            1232,
+        )
+        .with_trust_anchors(vec![material.trust_anchor_line.clone()]);
+
+        let response = fixture::rdns_message(wire);
+        let dnssec_state = service.validate_for_store(&response).await;
+
+        assert!(matches!(dnssec_state, DnssecState::Bogus(_)));
+        assert_eq!(
+            *metrics.dnssec_outcomes.lock().unwrap(),
+            vec![DnssecValidationOutcome::Bogus]
+        );
     }
 
     #[tokio::test]
@@ -11813,11 +11921,12 @@ mod tests {
             DNSKEY_RECORD_TYPE,
             material.dnskey_response_wire.clone(),
         )]));
+        let metrics = Arc::new(RecordingMetrics::default());
         let service = resolve_service_with_recursive_cache(
             Arc::clone(&backend) as Arc<dyn ResolutionBackend>,
             Arc::new(NoopDnsCache),
             Arc::new(RecordingEvents::default()),
-            Arc::new(RecordingMetrics::default()),
+            Arc::clone(&metrics),
             1232,
         );
 
@@ -11830,6 +11939,67 @@ mod tests {
             0,
             "no trust anchors configured must skip the validator entirely, never touching the backend"
         );
+        assert_eq!(
+            *metrics.dnssec_outcomes.lock().unwrap(),
+            vec![DnssecValidationOutcome::NotAttempted],
+            "no trust anchors configured (mode disabled) must record NotAttempted, not silence \
+             and not Indeterminate"
+        );
+    }
+
+    #[tokio::test]
+    async fn validate_for_store_records_not_attempted_when_trust_anchors_fail_to_parse() {
+        // Trust anchors *are* configured (so this isn't the "mode disabled"
+        // path above), but they're not valid zonefile data -- the chase
+        // never runs here either, so this is still NotAttempted, not Bogus
+        // or Indeterminate.
+        let backend: Arc<dyn ResolutionBackend> =
+            Arc::new(ScriptedNameKeyedBackend::new(Vec::new()));
+        let metrics = Arc::new(RecordingMetrics::default());
+        let service = resolve_service_with_recursive_cache(
+            Arc::clone(&backend),
+            Arc::new(NoopDnsCache),
+            Arc::new(RecordingEvents::default()),
+            Arc::clone(&metrics),
+            1232,
+        )
+        .with_trust_anchors(vec!["not a valid zonefile trust anchor line".to_string()]);
+
+        let response = response_message_for_question(
+            QuestionKey::new("example.com", A_RECORD_TYPE, 1),
+            ResponseCode::NoError,
+            vec![a_record("example.com", 60)],
+            Vec::new(),
+            Vec::new(),
+            false,
+        );
+        let dnssec_state = service.validate_for_store(&response).await;
+
+        assert_eq!(dnssec_state, DnssecState::Unvalidated);
+        assert_eq!(
+            *metrics.dnssec_outcomes.lock().unwrap(),
+            vec![DnssecValidationOutcome::NotAttempted]
+        );
+    }
+
+    #[test]
+    fn dnssec_outcome_metric_maps_every_validation_state() {
+        assert_eq!(
+            dnssec_outcome_metric(ValidationState::Secure),
+            DnssecValidationOutcome::Secure
+        );
+        assert_eq!(
+            dnssec_outcome_metric(ValidationState::Insecure),
+            DnssecValidationOutcome::Insecure
+        );
+        assert_eq!(
+            dnssec_outcome_metric(ValidationState::Bogus),
+            DnssecValidationOutcome::Bogus
+        );
+        assert_eq!(
+            dnssec_outcome_metric(ValidationState::Indeterminate),
+            DnssecValidationOutcome::Indeterminate
+        );
     }
 
     #[tokio::test]
@@ -11860,11 +12030,12 @@ mod tests {
             shard_count: Some(1),
             ..CacheConfig::default()
         }));
+        let metrics = Arc::new(RecordingMetrics::default());
         let service = resolve_service_with_cache(
             Arc::clone(&backend) as Arc<dyn ResolutionBackend>,
             Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
             Arc::new(RecordingEvents::default()),
-            Arc::new(RecordingMetrics::default()),
+            Arc::clone(&metrics),
             1232,
         )
         // Anchors configured but unparseable as real zonefile data -- if
@@ -11904,6 +12075,12 @@ mod tests {
             }
             other => panic!("expected Answered after storing the fetched entry, got {other:?}"),
         }
+
+        assert!(
+            metrics.dnssec_outcomes.lock().unwrap().is_empty(),
+            "Forward mode must never call record_dnssec_validation_outcome -- silence, \
+             not an explicit NotAttempted emission, since Forward has no DNSSEC concept"
+        );
     }
 
     #[tokio::test]
