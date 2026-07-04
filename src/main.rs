// Copyright 2023 Ryan Moore
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use opentelemetry::metrics::{Counter, Gauge, Histogram, MeterProvider};
use opentelemetry::KeyValue;
use opentelemetry_otlp::MetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use rdns::config::{
    ResolutionMode as ConfigResolutionMode, RootHintsSource as ConfigRootHintsSource, RuntimeConfig,
};
use rdns::delivery::dns::UdpDnsServer;
use rdns::delivery::upstream::{ForwardingResolutionBackend, RecursiveAuthorityTransportClient};
use rdns::resolver::{
    BackendHealth, BackendRootHintsStatus, BackendSnapshot, BackendStatus, BasicResponseFactory,
    CacheTtlPolicy, ChannelQueryEventSink, Clock, DnssecValidationStatus, InMemoryDnsCache,
    InMemoryLocalDnsEntries, InMemoryQueryEventStore, InMemoryQueryEventStoreConfig,
    InMemorySuspiciousLookupClassifier, InMemorySuspiciousLookupClassifierConfig, MetricsSink,
    NoopPolicyEvaluator, QueryEventRecordResult, QueryEventSink, QueryEventV1,
    RecursiveResolutionBackend, RecursiveResolverConfig, RecursiveRootHint,
    ResolutionMode as ResolverResolutionMode, ResolveQuery, ResolverMetric, StandardProtocolCodec,
};
use tokio::task::{JoinError, JoinSet};

const DEFAULT_CACHE_ENTRIES: usize = 10_000;
const DEFAULT_QUERY_EVENT_STORE_ENTRIES: usize = 10_000;
const QUERY_EVENT_QUEUE_CAPACITY: usize = 1024;
const CONFIG_PATH_ENV_VAR: &str = "RDNS_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "config.toml";

#[tokio::main]
async fn main() -> io::Result<()> {
    let config_path = resolve_config_path();
    let config = load_runtime_config(config_path.as_deref())?;
    config
        .validate()
        .map_err(|error| io::Error::other(format!("invalid runtime config: {error:?}")))?;
    match &config_path {
        Some(path) => println!("loaded config from {}", path.display()),
        None => println!("no config file found; using built-in development defaults"),
    }

    let stdout_events = Arc::new(StdoutEvents);
    let query_event_store = Arc::new(InMemoryQueryEventStore::new(
        InMemoryQueryEventStoreConfig {
            max_retained_events: DEFAULT_QUERY_EVENT_STORE_ENTRIES,
            ..InMemoryQueryEventStoreConfig::default()
        },
    ));
    let (event_tx, mut event_rx) =
        tokio::sync::mpsc::channel::<QueryEventV1>(QUERY_EVENT_QUEUE_CAPACITY);
    let event_drain = {
        let stdout_events = Arc::clone(&stdout_events);
        let query_event_store = Arc::clone(&query_event_store);
        let classifier = InMemorySuspiciousLookupClassifier::new(
            InMemorySuspiciousLookupClassifierConfig::default(),
        );
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let event = query_event_store.record_classified(event, &classifier);
                stdout_events.record_ref(&event);
            }
        })
    };

    let metrics = OpenTelemetryMetrics::new()
        .map(|metrics| Arc::new(metrics) as Arc<dyn MetricsSink>)
        .unwrap_or_else(|error| {
            eprintln!("failed to initialize OpenTelemetry metrics exporter: {error}");
            Arc::new(NoopMetrics)
        });
    let backend_snapshot = build_backend_snapshot(&config, Arc::clone(&metrics))?;
    let local_entries = build_local_entries(&config)?;
    let reload_metrics = Arc::clone(&metrics);
    let resolver = Arc::new(ResolveQuery::with_cache_policy_and_backend_snapshot(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(InMemoryDnsCache::new(DEFAULT_CACHE_ENTRIES)),
        Arc::new(NoopPolicyEvaluator),
        local_entries,
        CacheTtlPolicy::default(),
        backend_snapshot,
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(StoreRecordingQueryEventSink::new(
            ChannelQueryEventSink::new(event_tx),
            Arc::clone(&query_event_store),
        )),
        metrics,
    ));

    let sighup_task =
        spawn_sighup_reload_task(Arc::clone(&resolver), reload_metrics, config_path.clone());

    let servers = UdpDnsServer::bind_configured(&config, Arc::clone(&resolver)).await?;
    if servers.is_empty() {
        return Err(io::Error::other("no DNS listeners configured"));
    }

    let mut shutdown_senders = Vec::with_capacity(servers.len());
    let mut server_tasks = JoinSet::new();
    for server in servers {
        let address = server.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        shutdown_senders.push(shutdown_tx);
        println!("rdns listening on udp://{address}");
        server_tasks.spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
    }

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            println!("shutdown requested");
        }
        result = server_tasks.join_next() => {
            match result {
                Some(result) => {
                    listener_task_result_to_io(result)?;
                    println!("DNS listener stopped");
                }
                None => return Ok(()),
            }
        }
    }

    for shutdown_tx in shutdown_senders {
        let _ = shutdown_tx.send(());
    }

    while let Some(result) = server_tasks.join_next().await {
        listener_task_result_to_io(result)?;
    }

    sighup_task.abort();
    let _ = sighup_task.await;

    drop(resolver);
    match event_drain.await {
        Ok(()) => {}
        Err(error) => {
            return Err(io::Error::other(format!(
                "query event drain task failed: {error}"
            )));
        }
    }

    Ok(())
}

fn resolve_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(CONFIG_PATH_ENV_VAR) {
        return Some(PathBuf::from(path));
    }
    let default_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    default_path.exists().then_some(default_path)
}

fn load_runtime_config(path: Option<&Path>) -> io::Result<RuntimeConfig> {
    let Some(path) = path else {
        return Ok(RuntimeConfig::development_default());
    };
    let source = std::fs::read_to_string(path)
        .map_err(|error| io::Error::other(format!("failed to read {}: {error}", path.display())))?;
    RuntimeConfig::from_toml_str(&source).map_err(|error| {
        io::Error::other(format!("invalid config at {}: {error:?}", path.display()))
    })
}

fn build_local_entries(config: &RuntimeConfig) -> io::Result<Arc<InMemoryLocalDnsEntries>> {
    let entries = config
        .local_dns_entries
        .iter()
        .map(|entry| entry.to_local_dns_entry())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::other(format!("invalid local DNS entry config: {error:?}")))?;
    Ok(Arc::new(InMemoryLocalDnsEntries::new(entries)))
}

fn reload_resolver(
    resolver: &ResolveQuery,
    config: &RuntimeConfig,
    metrics: Arc<dyn MetricsSink>,
) -> io::Result<()> {
    let backend_snapshot = build_backend_snapshot(config, metrics)?;
    let local_entries = build_local_entries(config)?;
    resolver.publish_backend_snapshot(backend_snapshot);
    resolver.publish_local_entries(local_entries);
    Ok(())
}

#[cfg(unix)]
fn spawn_sighup_reload_task(
    resolver: Arc<ResolveQuery>,
    metrics: Arc<dyn MetricsSink>,
    config_path: Option<PathBuf>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("failed to install SIGHUP handler: {error}");
                return;
            }
        };
        loop {
            if hangup.recv().await.is_none() {
                eprintln!("SIGHUP signal stream closed; stopping reload task");
                return;
            }
            let Some(path) = config_path.as_deref() else {
                eprintln!("SIGHUP received but no config file was loaded at startup; ignoring");
                continue;
            };
            match load_runtime_config(Some(path)) {
                Ok(config) => match reload_resolver(&resolver, &config, Arc::clone(&metrics)) {
                    Ok(()) => println!(
                        "reloaded config from {} ({} upstream(s), {} local DNS entr{})",
                        path.display(),
                        config.upstreams.len(),
                        config.local_dns_entries.len(),
                        if config.local_dns_entries.len() == 1 {
                            "y"
                        } else {
                            "ies"
                        }
                    ),
                    Err(error) => eprintln!("failed to apply reloaded config: {error}"),
                },
                Err(error) => eprintln!("failed to reload config from {}: {error}", path.display()),
            }
        }
    })
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(
    _resolver: Arc<ResolveQuery>,
    _metrics: Arc<dyn MetricsSink>,
    _config_path: Option<PathBuf>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {})
}

fn build_backend_snapshot(
    config: &RuntimeConfig,
    metrics: Arc<dyn MetricsSink>,
) -> io::Result<BackendSnapshot> {
    match config.resolution.mode {
        ConfigResolutionMode::Forward => {
            let backend = Arc::new(
                ForwardingResolutionBackend::from_runtime_config(config).map_err(|error| {
                    io::Error::other(format!("invalid upstream config: {error:?}"))
                })?,
            );
            Ok(BackendSnapshot::new(
                backend,
                ResolverResolutionMode::Forward,
                config.resolution.generation,
                BackendHealth::Healthy,
                Some(config.backend_cache_namespace()),
            ))
        }
        ConfigResolutionMode::Recursive => {
            let recursive = config
                .resolution
                .recursive
                .as_ref()
                .ok_or_else(|| io::Error::other("recursive resolution config is missing"))?;
            let root_hints = recursive
                .load_root_hints()
                .map_err(|error| io::Error::other(format!("invalid root hints: {error:?}")))?
                .into_iter()
                .map(|hint| RecursiveRootHint {
                    name: hint.name,
                    endpoints: hint.endpoints,
                })
                .collect();
            let transport = Arc::new(
                RecursiveAuthorityTransportClient::from_runtime_config(config)
                    .map_err(|error| {
                        io::Error::other(format!("invalid recursive transport: {error:?}"))
                    })?
                    .with_metrics(Arc::clone(&metrics)),
            );
            let backend = Arc::new(RecursiveResolutionBackend::with_metrics(
                RecursiveResolverConfig {
                    root_hints,
                    per_authority_timeout: recursive.per_authority_timeout,
                    per_query_deadline: config.per_query_deadline,
                    max_recursion_depth: recursive.max_recursion_depth,
                    max_cname_restarts: recursive.max_cname_restarts,
                },
                transport,
                metrics,
            ));
            Ok(BackendSnapshot::new(
                backend,
                ResolverResolutionMode::Recursive,
                config.resolution.generation,
                BackendHealth::Healthy,
                Some(config.backend_cache_namespace()),
            )
            .with_root_hints_status(BackendRootHintsStatus::loaded(
                root_hints_source_label(&recursive.root_hints_source),
                recursive.root_hints_version.clone(),
                SystemTime::now(),
            )))
        }
    }
}

fn root_hints_source_label(source: &ConfigRootHintsSource) -> &'static str {
    match source {
        ConfigRootHintsSource::Bundled => "bundled",
        ConfigRootHintsSource::Static(_) => "static",
    }
}

fn listener_task_result_to_io(result: Result<io::Result<()>, JoinError>) -> io::Result<()> {
    result.map_err(|error| io::Error::other(format!("DNS listener task failed: {error}")))?
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct StdoutEvents;

impl StdoutEvents {
    fn record_ref(&self, event: &QueryEventV1) {
        println!("{event:?}");
    }
}

impl QueryEventSink for StdoutEvents {
    fn record(&self, event: QueryEventV1) -> QueryEventRecordResult {
        self.record_ref(&event);
        QueryEventRecordResult::Accepted
    }
}

struct StoreRecordingQueryEventSink {
    inner: ChannelQueryEventSink,
    store: Arc<InMemoryQueryEventStore>,
}

impl StoreRecordingQueryEventSink {
    fn new(inner: ChannelQueryEventSink, store: Arc<InMemoryQueryEventStore>) -> Self {
        Self { inner, store }
    }
}

impl QueryEventSink for StoreRecordingQueryEventSink {
    fn record(&self, event: QueryEventV1) -> QueryEventRecordResult {
        let result = self.inner.record(event);
        if !matches!(result, QueryEventRecordResult::Accepted) {
            self.store.record_outcome(result);
        }
        result
    }
}

struct NoopMetrics;

impl MetricsSink for NoopMetrics {
    fn increment(&self, _metric: ResolverMetric) {}

    fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
}

struct OpenTelemetryMetrics {
    _provider: SdkMeterProvider,
    query_received_total: Counter<u64>,
    query_allowed_total: Counter<u64>,
    query_blocked_total: Counter<u64>,
    cache_hit_total: Counter<u64>,
    cache_miss_total: Counter<u64>,
    cache_expired_total: Counter<u64>,
    cache_bypass_total: Counter<u64>,
    cache_unavailable_total: Counter<u64>,
    cache_store_total: Counter<u64>,
    cache_store_skipped_total: Counter<u64>,
    cache_negative_store_total: Counter<u64>,
    cache_negative_hit_total: Counter<u64>,
    cache_response_truncated_total: Counter<u64>,
    cache_coalesced_miss_total: Counter<u64>,
    query_event_accepted_total: Counter<u64>,
    query_event_disabled_total: Counter<u64>,
    query_event_dropped_newest_total: Counter<u64>,
    query_event_dropped_oldest_total: Counter<u64>,
    query_event_sampled_total: Counter<u64>,
    upstream_success_total: Counter<u64>,
    upstream_failure_total: Counter<u64>,
    recursive_query_total: Counter<u64>,
    recursive_authority_attempt_total: Counter<u64>,
    recursive_authority_timeout_total: Counter<u64>,
    recursive_authority_error_total: Counter<u64>,
    recursive_bailiwick_reject_total: Counter<u64>,
    recursive_lame_delegation_total: Counter<u64>,
    recursive_referral_loop_total: Counter<u64>,
    recursive_limit_hit_total: Counter<u64>,
    recursive_tcp_fallback_attempt_total: Counter<u64>,
    recursive_tcp_fallback_success_total: Counter<u64>,
    recursive_tcp_fallback_failure_total: Counter<u64>,
    recursive_tcp_fallback_timeout_total: Counter<u64>,
    backend_generation: Gauge<u64>,
    root_hints_age_seconds: Gauge<f64>,
    dnssec_validation_disabled: Gauge<u64>,
    protocol_error_total: Counter<u64>,
    query_duration_seconds: Histogram<f64>,
    recursive_query_duration_seconds: Histogram<f64>,
}

impl OpenTelemetryMetrics {
    fn new() -> Result<Self, String> {
        let exporter = MetricExporter::builder()
            .with_tonic()
            .build()
            .map_err(|error| format!("failed to build OTLP metrics exporter: {error}"))?;
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("rdns.resolver");

        Ok(Self {
            _provider: provider,
            query_received_total: meter.u64_counter("query_received_total").build(),
            query_allowed_total: meter.u64_counter("query_allowed_total").build(),
            query_blocked_total: meter.u64_counter("query_blocked_total").build(),
            cache_hit_total: meter.u64_counter("cache_hit_total").build(),
            cache_miss_total: meter.u64_counter("cache_miss_total").build(),
            cache_expired_total: meter.u64_counter("cache_expired_total").build(),
            cache_bypass_total: meter.u64_counter("cache_bypass_total").build(),
            cache_unavailable_total: meter.u64_counter("cache_unavailable_total").build(),
            cache_store_total: meter.u64_counter("cache_store_total").build(),
            cache_store_skipped_total: meter.u64_counter("cache_store_skipped_total").build(),
            cache_negative_store_total: meter.u64_counter("cache_negative_store_total").build(),
            cache_negative_hit_total: meter.u64_counter("cache_negative_hit_total").build(),
            cache_response_truncated_total: meter
                .u64_counter("cache_response_truncated_total")
                .build(),
            cache_coalesced_miss_total: meter.u64_counter("cache_coalesced_miss_total").build(),
            query_event_accepted_total: meter.u64_counter("query_event_accepted_total").build(),
            query_event_disabled_total: meter.u64_counter("query_event_disabled_total").build(),
            query_event_dropped_newest_total: meter
                .u64_counter("query_event_dropped_newest_total")
                .build(),
            query_event_dropped_oldest_total: meter
                .u64_counter("query_event_dropped_oldest_total")
                .build(),
            query_event_sampled_total: meter.u64_counter("query_event_sampled_total").build(),
            upstream_success_total: meter.u64_counter("upstream_success_total").build(),
            upstream_failure_total: meter.u64_counter("upstream_failure_total").build(),
            recursive_query_total: meter.u64_counter("recursive_query_total").build(),
            recursive_authority_attempt_total: meter
                .u64_counter("recursive_authority_attempt_total")
                .build(),
            recursive_authority_timeout_total: meter
                .u64_counter("recursive_authority_timeout_total")
                .build(),
            recursive_authority_error_total: meter
                .u64_counter("recursive_authority_error_total")
                .build(),
            recursive_bailiwick_reject_total: meter
                .u64_counter("recursive_bailiwick_reject_total")
                .build(),
            recursive_lame_delegation_total: meter
                .u64_counter("recursive_lame_delegation_total")
                .build(),
            recursive_referral_loop_total: meter
                .u64_counter("recursive_referral_loop_total")
                .build(),
            recursive_limit_hit_total: meter.u64_counter("recursive_limit_hit_total").build(),
            recursive_tcp_fallback_attempt_total: meter
                .u64_counter("recursive_tcp_fallback_attempt_total")
                .build(),
            recursive_tcp_fallback_success_total: meter
                .u64_counter("recursive_tcp_fallback_success_total")
                .build(),
            recursive_tcp_fallback_failure_total: meter
                .u64_counter("recursive_tcp_fallback_failure_total")
                .build(),
            recursive_tcp_fallback_timeout_total: meter
                .u64_counter("recursive_tcp_fallback_timeout_total")
                .build(),
            backend_generation: meter.u64_gauge("backend_generation").build(),
            root_hints_age_seconds: meter.f64_gauge("root_hints_age_seconds").build(),
            dnssec_validation_disabled: meter.u64_gauge("dnssec_validation_disabled").build(),
            protocol_error_total: meter.u64_counter("protocol_error_total").build(),
            query_duration_seconds: meter.f64_histogram("query_duration_seconds").build(),
            recursive_query_duration_seconds: meter
                .f64_histogram("recursive_query_duration_seconds")
                .build(),
        })
    }
}

impl MetricsSink for OpenTelemetryMetrics {
    fn increment(&self, metric: ResolverMetric) {
        match metric {
            ResolverMetric::QueryReceived => self.query_received_total.add(1, &[]),
            ResolverMetric::QueryAllowed => self.query_allowed_total.add(1, &[]),
            ResolverMetric::QueryBlocked => self.query_blocked_total.add(1, &[]),
            ResolverMetric::CacheHit => self.cache_hit_total.add(1, &[]),
            ResolverMetric::CacheMiss => self.cache_miss_total.add(1, &[]),
            ResolverMetric::CacheExpired => self.cache_expired_total.add(1, &[]),
            ResolverMetric::CacheBypass => self.cache_bypass_total.add(1, &[]),
            ResolverMetric::CacheUnavailable => self.cache_unavailable_total.add(1, &[]),
            ResolverMetric::CacheStore => self.cache_store_total.add(1, &[]),
            ResolverMetric::CacheStoreSkipped => self.cache_store_skipped_total.add(1, &[]),
            ResolverMetric::CacheNegativeStore => self.cache_negative_store_total.add(1, &[]),
            ResolverMetric::CacheNegativeHit => self.cache_negative_hit_total.add(1, &[]),
            ResolverMetric::CacheResponseTruncated => {
                self.cache_response_truncated_total.add(1, &[])
            }
            ResolverMetric::CacheCoalescedMiss => self.cache_coalesced_miss_total.add(1, &[]),
            ResolverMetric::QueryEventAccepted => self.query_event_accepted_total.add(1, &[]),
            ResolverMetric::QueryEventDisabled => self.query_event_disabled_total.add(1, &[]),
            ResolverMetric::QueryEventDroppedNewest => {
                self.query_event_dropped_newest_total.add(1, &[])
            }
            ResolverMetric::QueryEventDroppedOldest => {
                self.query_event_dropped_oldest_total.add(1, &[])
            }
            ResolverMetric::QueryEventSampled => self.query_event_sampled_total.add(1, &[]),
            ResolverMetric::UpstreamSuccess => self.upstream_success_total.add(1, &[]),
            ResolverMetric::UpstreamFailure => self.upstream_failure_total.add(1, &[]),
            ResolverMetric::RecursiveQuery => self.recursive_query_total.add(1, &[]),
            ResolverMetric::RecursiveAuthorityAttempt => {
                self.recursive_authority_attempt_total.add(1, &[])
            }
            ResolverMetric::RecursiveAuthorityTimeout => {
                self.recursive_authority_timeout_total.add(1, &[])
            }
            ResolverMetric::RecursiveAuthorityError => {
                self.recursive_authority_error_total.add(1, &[])
            }
            ResolverMetric::RecursiveBailiwickReject => {
                self.recursive_bailiwick_reject_total.add(1, &[])
            }
            ResolverMetric::RecursiveLameDelegation => {
                self.recursive_lame_delegation_total.add(1, &[])
            }
            ResolverMetric::RecursiveReferralLoop => self.recursive_referral_loop_total.add(1, &[]),
            ResolverMetric::RecursiveLimitHit => self.recursive_limit_hit_total.add(1, &[]),
            ResolverMetric::RecursiveTcpFallbackAttempt => {
                self.recursive_tcp_fallback_attempt_total.add(1, &[])
            }
            ResolverMetric::RecursiveTcpFallbackSuccess => {
                self.recursive_tcp_fallback_success_total.add(1, &[])
            }
            ResolverMetric::RecursiveTcpFallbackFailure => {
                self.recursive_tcp_fallback_failure_total.add(1, &[])
            }
            ResolverMetric::RecursiveTcpFallbackTimeout => {
                self.recursive_tcp_fallback_timeout_total.add(1, &[])
            }
            ResolverMetric::ProtocolError => self.protocol_error_total.add(1, &[]),
            ResolverMetric::QueryDuration | ResolverMetric::RecursiveQueryDuration => {}
        }
    }

    fn observe_duration(&self, metric: ResolverMetric, duration: Duration) {
        match metric {
            ResolverMetric::QueryDuration => {
                self.query_duration_seconds
                    .record(duration.as_secs_f64(), &[]);
            }
            ResolverMetric::RecursiveQueryDuration => {
                self.recursive_query_duration_seconds
                    .record(duration.as_secs_f64(), &[]);
            }
            _ => {}
        }
    }

    fn record_backend_status(&self, status: &BackendStatus) {
        let attributes = backend_status_attributes(status);
        self.backend_generation
            .record(status.generation, &attributes);
        self.dnssec_validation_disabled.record(
            u64::from(status.dnssec_validation == DnssecValidationStatus::Disabled),
            &attributes,
        );
        if let Some(root_hints) = &status.root_hints {
            if let Some(age) = root_hints.age_at(SystemTime::now()) {
                self.root_hints_age_seconds
                    .record(age.as_secs_f64(), &attributes);
            }
        }
    }
}

fn backend_status_attributes(status: &BackendStatus) -> Vec<KeyValue> {
    let mut attributes = vec![
        KeyValue::new("mode", resolver_mode_label(status.mode)),
        KeyValue::new("health", backend_health_label(status.health)),
        KeyValue::new(
            "dnssec_validation",
            dnssec_validation_label(status.dnssec_validation),
        ),
    ];
    if let Some(root_hints) = &status.root_hints {
        attributes.push(KeyValue::new(
            "root_hints_source",
            root_hints.source.clone(),
        ));
        attributes.push(KeyValue::new(
            "root_hints_version",
            root_hints.version.clone(),
        ));
    }
    attributes
}

fn resolver_mode_label(mode: ResolverResolutionMode) -> &'static str {
    match mode {
        ResolverResolutionMode::Forward => "forward",
        ResolverResolutionMode::Recursive => "recursive",
    }
}

fn backend_health_label(health: BackendHealth) -> &'static str {
    match health {
        BackendHealth::Healthy => "healthy",
        BackendHealth::Degraded => "degraded",
        BackendHealth::Unavailable => "unavailable",
        BackendHealth::Unknown => "unknown",
    }
}

fn dnssec_validation_label(status: DnssecValidationStatus) -> &'static str {
    match status {
        DnssecValidationStatus::Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdns::resolver::{
        LocalDnsEntries, LocalDnsLookup, QueryEventReadModel, QuestionKey, ResolveDecision,
        ResolveDecisionKind,
    };

    fn sample_config_toml() -> &'static str {
        r#"
            dns_listen = ["127.0.0.1:5300"]
            per_query_deadline_ms = 2000
            max_udp_payload_size = 1232

            [[upstreams]]
            name = "cloudflare"
            endpoint = "1.1.1.1:53"
            protocol = "udp"
            enabled = true
            priority = 10
            timeout_ms = 750

            [[local_dns_entries]]
            name = "nas.lan"
            ipv4 = ["192.168.1.10"]
            ttl = 300
            enabled = true
            public_address_acknowledged = false
        "#
    }

    #[test]
    fn config_driven_local_entries_answer_configured_names_only() {
        let config = RuntimeConfig::from_toml_str(sample_config_toml()).unwrap();

        let local_entries = build_local_entries(&config).unwrap();

        let local_question = QuestionKey::new("nas.lan", 1, 1);
        match local_entries.lookup(&local_question) {
            LocalDnsLookup::Answer(entry) => {
                assert_eq!(entry.ipv4[0].to_string(), "192.168.1.10");
            }
            other => panic!("expected a local answer, got {other:?}"),
        }

        let unrelated_question = QuestionKey::new("example.com", 1, 1);
        assert_eq!(
            local_entries.lookup(&unrelated_question),
            LocalDnsLookup::NoMatch
        );
    }

    #[test]
    fn load_runtime_config_falls_back_to_development_default_without_a_path() {
        let config = load_runtime_config(None).unwrap();

        assert_eq!(config, RuntimeConfig::development_default());
    }

    fn event_for(name: &str) -> QueryEventV1 {
        let decision = ResolveDecision {
            client_ip: "127.0.0.1".parse().unwrap(),
            question: Some(QuestionKey::new(name, 1, 1)),
            kind: ResolveDecisionKind::Allowed,
        };
        QueryEventV1::from_decision(0, SystemTime::UNIX_EPOCH, &decision, None, None, None)
    }

    #[tokio::test]
    async fn store_recording_query_event_sink_counts_channel_drops() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(event_for("queued.example")).unwrap();
        let store = Arc::new(InMemoryQueryEventStore::new(
            InMemoryQueryEventStoreConfig::default(),
        ));
        let sink = StoreRecordingQueryEventSink::new(ChannelQueryEventSink::new(tx), store.clone());

        let result = sink.record(event_for("dropped.example"));

        assert_eq!(result, QueryEventRecordResult::DroppedNewest);
        assert_eq!(store.summary().dropped_newest_event_count, 1);
        assert_eq!(
            rx.recv().await.unwrap().normalized_question.unwrap().qname,
            "queued.example"
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn record_classified_attaches_advisory_findings_before_storage() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                high_entropy_min_label_len: 8,
                high_entropy_score_threshold: 60,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });

        let event = store.record_classified(event_for("a9x4qz7m2p8v.example"), &classifier);

        assert!(!event.advisory_findings.is_empty());
        assert_eq!(store.suspicious_query_events(8).len(), 1);
    }
}
