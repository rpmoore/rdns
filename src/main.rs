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
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use opentelemetry::metrics::{Counter, Histogram, MeterProvider};
use opentelemetry_otlp::MetricExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use rdns::config::RuntimeConfig;
use rdns::delivery::dns::UdpDnsServer;
use rdns::delivery::upstream::UdpUpstreamResolver;
use rdns::resolver::{
    BasicResponseFactory, CacheTtlPolicy, ChannelQueryEventSink, Clock, InMemoryDnsCache,
    InMemoryQueryEventStore, InMemoryQueryEventStoreConfig, MetricsSink, QueryEventRecordResult,
    QueryEventSink, QueryEventV1, ResolveQuery, ResolverMetric, StandardProtocolCodec,
};
use tokio::task::{JoinError, JoinSet};

const DEFAULT_CACHE_ENTRIES: usize = 10_000;
const DEFAULT_QUERY_EVENT_STORE_ENTRIES: usize = 10_000;
const QUERY_EVENT_QUEUE_CAPACITY: usize = 1024;

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = RuntimeConfig::development_default();
    config
        .validate()
        .map_err(|error| io::Error::other(format!("invalid runtime config: {error:?}")))?;

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
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                query_event_store.record(event.clone());
                let _ = stdout_events.record(event);
            }
        })
    };

    let resolver = Arc::new(ResolveQuery::with_cache(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(InMemoryDnsCache::new(DEFAULT_CACHE_ENTRIES)),
        CacheTtlPolicy::default(),
        Arc::new(
            UdpUpstreamResolver::from_runtime_config(&config)
                .map_err(|error| io::Error::other(format!("invalid upstream config: {error:?}")))?,
        ),
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(ChannelQueryEventSink::new(event_tx)),
        OpenTelemetryMetrics::new()
            .map(|metrics| Arc::new(metrics) as Arc<dyn MetricsSink>)
            .unwrap_or_else(|error| {
                eprintln!("failed to initialize OpenTelemetry metrics exporter: {error}");
                Arc::new(NoopMetrics)
            }),
    ));

    let servers = UdpDnsServer::bind_configured(&config, resolver).await?;
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

    event_drain.abort();
    match event_drain.await {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {}
        Err(error) => {
            return Err(io::Error::other(format!(
                "query event drain task failed: {error}"
            )));
        }
    }

    Ok(())
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

impl QueryEventSink for StdoutEvents {
    fn record(&self, event: QueryEventV1) -> QueryEventRecordResult {
        println!("{event:?}");
        QueryEventRecordResult::Accepted
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
    cache_response_truncated_total: Counter<u64>,
    cache_coalesced_miss_total: Counter<u64>,
    query_event_accepted_total: Counter<u64>,
    query_event_disabled_total: Counter<u64>,
    query_event_dropped_newest_total: Counter<u64>,
    query_event_dropped_oldest_total: Counter<u64>,
    query_event_sampled_total: Counter<u64>,
    upstream_success_total: Counter<u64>,
    upstream_failure_total: Counter<u64>,
    protocol_error_total: Counter<u64>,
    query_duration_seconds: Histogram<f64>,
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
            protocol_error_total: meter.u64_counter("protocol_error_total").build(),
            query_duration_seconds: meter.f64_histogram("query_duration_seconds").build(),
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
            ResolverMetric::ProtocolError => self.protocol_error_total.add(1, &[]),
            ResolverMetric::QueryDuration => {}
        }
    }

    fn observe_duration(&self, metric: ResolverMetric, duration: Duration) {
        if metric == ResolverMetric::QueryDuration {
            self.query_duration_seconds
                .record(duration.as_secs_f64(), &[]);
        }
    }
}
