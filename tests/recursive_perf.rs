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

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rdns::config::{RecursiveResolutionConfig, ResolutionConfig, RuntimeConfig};
use rdns::delivery::upstream::RecursiveAuthorityTransportClient;
use rdns::protocol::Message;
use rdns::resolver::{
    BasicResponseFactory, CacheTtlPolicy, Clock, InMemoryDnsCache, MetricsSink,
    QueryEventRecordResult, QueryEventSink, QueryEventV1, RecursiveResolutionBackend,
    RecursiveResolverConfig, RecursiveRootHint, ResolveDecisionKind, ResolveQuery, ResolveRequest,
    ResolverMetric, StandardProtocolCodec,
};

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct NoopEvents;

impl QueryEventSink for NoopEvents {
    fn record(&self, _event: QueryEventV1) -> QueryEventRecordResult {
        QueryEventRecordResult::Accepted
    }
}

struct NoopMetrics;

impl MetricsSink for NoopMetrics {
    fn increment(&self, _metric: ResolverMetric) {}

    fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
}

const DOMAINS: [&str; 5] = [
    "google.com",
    "facebook.com",
    "amazon.com",
    "cloudflare.com",
    "wikipedia.org",
];
const ITERATIONS: usize = 10;

fn a_query(id: u16, name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&0x0100u16.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes
}

fn recursive_runtime_config() -> RuntimeConfig {
    let recursive = RecursiveResolutionConfig::bundled("perf-test");
    RuntimeConfig::new_with_resolution(
        vec!["127.0.0.1:5300".parse().unwrap()],
        ResolutionConfig::recursive(0, recursive),
        Vec::new(),
        Duration::from_secs(3),
        1232,
    )
    .unwrap()
}

fn recursive_backend(config: &RuntimeConfig) -> Arc<RecursiveResolutionBackend> {
    let recursive = config.resolution.recursive.as_ref().unwrap();
    let root_hints = recursive
        .load_root_hints()
        .unwrap()
        .into_iter()
        .map(|hint| RecursiveRootHint {
            name: hint.name,
            endpoints: hint.endpoints,
        })
        .collect();
    let transport =
        Arc::new(RecursiveAuthorityTransportClient::from_runtime_config(config).unwrap());
    Arc::new(RecursiveResolutionBackend::new(
        RecursiveResolverConfig {
            root_hints,
            per_authority_timeout: recursive.per_authority_timeout,
            per_query_deadline: config.per_query_deadline,
            max_recursion_depth: recursive.max_recursion_depth,
            max_cname_restarts: recursive.max_cname_restarts,
        },
        transport,
    ))
}

fn resolver_without_cache(config: &RuntimeConfig) -> ResolveQuery {
    ResolveQuery::new(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        recursive_backend(config),
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(NoopEvents),
        Arc::new(NoopMetrics),
    )
}

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

struct IterationResult {
    latency: Duration,
}

struct Summary {
    domain: &'static str,
    avg_ms: f64,
    min_ms: f64,
    min_iter: usize,
    max_ms: f64,
    max_iter: usize,
    stddev_ms: f64,
}

fn summarize(domain: &'static str, results: &[IterationResult]) -> Summary {
    let millis: Vec<f64> = results
        .iter()
        .map(|r| r.latency.as_secs_f64() * 1000.0)
        .collect();
    let count = millis.len() as f64;
    let avg_ms = millis.iter().sum::<f64>() / count;

    let (min_iter, min_ms) = millis
        .iter()
        .enumerate()
        .min_by(|a, b| a.1.partial_cmp(b.1).unwrap())
        .map(|(idx, value)| (idx + 1, *value))
        .unwrap();
    let (max_iter, max_ms) = millis
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
        .map(|(idx, value)| (idx + 1, *value))
        .unwrap();

    let variance = if millis.len() > 1 {
        millis.iter().map(|v| (v - avg_ms).powi(2)).sum::<f64>() / (count - 1.0)
    } else {
        0.0
    };
    let stddev_ms = variance.sqrt();

    Summary {
        domain,
        avg_ms,
        min_ms,
        min_iter,
        max_ms,
        max_iter,
        stddev_ms,
    }
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (idx, cell) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.len());
        }
    }

    let header_line = headers
        .iter()
        .enumerate()
        .map(|(idx, h)| format!("{:<width$}", h, width = widths[idx]))
        .collect::<Vec<_>>()
        .join(" | ");
    println!("{header_line}");

    let separator = widths
        .iter()
        .map(|w| "-".repeat(*w))
        .collect::<Vec<_>>()
        .join("-+-");
    println!("{separator}");

    for row in rows {
        let line = row
            .iter()
            .enumerate()
            .map(|(idx, cell)| format!("{:<width$}", cell, width = widths[idx]))
            .collect::<Vec<_>>()
            .join(" | ");
        println!("{line}");
    }
}

async fn run_domain(
    resolver: &ResolveQuery,
    domain: &'static str,
    detail_rows: &mut Vec<Vec<String>>,
) -> Vec<IterationResult> {
    let client_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mut results = Vec::with_capacity(ITERATIONS);

    for iteration in 1..=ITERATIONS {
        let request_bytes = a_query(iteration as u16, domain);
        let request = ResolveRequest::new(client_ip, SystemTime::now(), request_bytes);

        let started_at = Instant::now();
        let outcome = resolver.resolve(request).await;
        let latency = started_at.elapsed();

        let message = Message::parse(&outcome.response_bytes).unwrap_or_else(|error| {
            panic!("{domain} iteration {iteration}: malformed response: {error:?}")
        });
        assert_eq!(
            message.header.r_code(),
            0,
            "{domain} iteration {iteration}: expected NOERROR, got rcode {}",
            message.header.r_code()
        );
        assert!(
            !message.answers.is_empty(),
            "{domain} iteration {iteration}: expected at least one answer record"
        );

        let outcome_label = match outcome.decision.kind {
            ResolveDecisionKind::CacheHit => "hit",
            ResolveDecisionKind::Allowed | ResolveDecisionKind::CacheMiss => "miss",
            _ => "n/a",
        };

        detail_rows.push(vec![
            domain.to_string(),
            iteration.to_string(),
            format!("{:.2}", latency.as_secs_f64() * 1000.0),
            outcome_label.to_string(),
        ]);

        results.push(IterationResult { latency });
    }

    results
}

async fn run_benchmark(resolver: ResolveQuery, title: &str) {
    println!("\n== recursive resolver perf: {title} ==\n");

    let mut detail_rows = Vec::new();
    let mut summaries = Vec::new();

    for &domain in DOMAINS.iter() {
        let results = run_domain(&resolver, domain, &mut detail_rows).await;
        summaries.push(summarize(domain, &results));
    }

    print_table(&["domain", "iter", "latency_ms", "outcome"], &detail_rows);

    println!();

    let summary_rows: Vec<Vec<String>> = summaries
        .iter()
        .map(|s| {
            vec![
                s.domain.to_string(),
                format!("{:.2}", s.avg_ms),
                format!("{:.2} (#{})", s.min_ms, s.min_iter),
                format!("{:.2} (#{})", s.max_ms, s.max_iter),
                format!("{:.2}", s.stddev_ms),
            ]
        })
        .collect();

    print_table(
        &[
            "domain",
            "avg_ms",
            "min_ms (iter)",
            "max_ms (iter)",
            "stddev_ms",
        ],
        &summary_rows,
    );
}

#[tokio::test]
#[ignore = "requires outbound UDP/TCP DNS access to public root/TLD servers"]
async fn recursive_resolver_perf_without_cache() {
    let config = recursive_runtime_config();
    let resolver = resolver_without_cache(&config);
    run_benchmark(resolver, "cache DISABLED").await;
}

#[tokio::test]
#[ignore = "requires outbound UDP/TCP DNS access to public root/TLD servers"]
async fn recursive_resolver_perf_with_cache() {
    let config = recursive_runtime_config();
    let resolver = resolver_with_cache(&config);
    run_benchmark(resolver, "cache ENABLED").await;
}
