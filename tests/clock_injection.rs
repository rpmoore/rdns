// Copyright 2026 Ryan Moore
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

//! Live, end-to-end regression test for Clock dependency injection
//! (`docs/plans/ttl_remaining/` section 02). Drives the actual
//! socket -> `handle_datagram` -> resolver -> cache -> `assemble_response`
//! pipeline with an injected, advanceable fake clock, rather than
//! hand-constructing `now`/`stored_at` values the way unit tests do.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use rdns::config::{CacheConfig, RuntimeConfig, UpstreamConfig, UpstreamProtocol};
use rdns::delivery::dns::UdpDnsServer;
use rdns::delivery::upstream::ForwardingResolutionBackend;
use rdns::protocol::Message;
use rdns::resolver::{
    BasicResponseFactory, CacheTtlPolicy, Clock, DomainDnsCache, MetricsSink,
    QueryEventRecordResult, QueryEventSink, QueryEventV1, ResolveQuery, ResolverMetric,
    ShardedDnsCache, StandardProtocolCodec,
};
use tokio::net::UdpSocket;

/// A `Clock` whose value can be advanced in place between two requests in
/// the same test, unlike this repo's existing `FixedClock` variants (all
/// single-value, none mutate) -- see the section-02 plan's "FixedClock
/// precedent" note for why a fourth shape was needed here.
struct AdvanceableClock {
    offset_secs: AtomicU64,
}

impl AdvanceableClock {
    fn new() -> Self {
        Self {
            offset_secs: AtomicU64::new(0),
        }
    }

    fn advance(&self, secs: u64) {
        self.offset_secs.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for AdvanceableClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.offset_secs.load(Ordering::SeqCst))
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

/// A minimal, fully-parseable A response with one answer record carrying
/// `ttl`, following the same record shape as `dns.rs`'s
/// `oversized_a_response` test helper (name pointer to the question, TYPE=A,
/// CLASS=IN, 4-byte RDATA).
fn a_response_with_ttl(id: u16, name: &str, ttl: u32) -> Vec<u8> {
    let mut bytes = a_query(id, name);
    bytes[2] = 0x81;
    bytes[3] = 0x80;
    bytes[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    bytes.extend_from_slice(&0xc00cu16.to_be_bytes()); // name: pointer to question at offset 12
    bytes.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
    bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    bytes
}

fn upstream_config(name: &str, endpoint: SocketAddr, priority: u16) -> UpstreamConfig {
    UpstreamConfig {
        name: name.to_string(),
        endpoint,
        protocol: UpstreamProtocol::Udp,
        enabled: true,
        priority,
        timeout: Duration::from_millis(200),
    }
}

fn config_with_upstream(upstream: SocketAddr) -> RuntimeConfig {
    RuntimeConfig::new(
        vec!["127.0.0.1:5300".parse().unwrap()],
        vec![upstream_config("primary", upstream, 10)],
        Duration::from_millis(200),
        1232,
    )
    .unwrap()
}

/// Builds a real `UdpDnsServer` and its backing resolver, both sharing one
/// injected clock -- mirrors `main.rs`'s production wiring, where the
/// resolver and both transports are handed clones of the same
/// `Arc<dyn Clock>`.
async fn run_server_with_clock(
    config: &RuntimeConfig,
    clock: Arc<dyn Clock>,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let cache = Arc::new(ShardedDnsCache::new(&CacheConfig::default()));
    let resolver = Arc::new(ResolveQuery::with_cache(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        cache as Arc<dyn DomainDnsCache>,
        CacheTtlPolicy::default(),
        Arc::new(ForwardingResolutionBackend::from_runtime_config(config).unwrap()),
        Arc::new(BasicResponseFactory),
        Arc::clone(&clock),
        Arc::new(NoopEvents),
        Arc::new(NoopMetrics),
    ));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = UdpDnsServer::new(socket, resolver, clock, config.max_udp_payload_size);
    let server_addr = server.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        server
            .serve_until(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    (server_addr, shutdown_tx, server_task)
}

async fn send_query(server_addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(request, server_addr).await.unwrap();
    let mut response = [0u8; 512];
    let (response_len, source) = client.recv_from(&mut response).await.unwrap();
    assert_eq!(source, server_addr);
    response[..response_len].to_vec()
}

fn answer_ttl(response_bytes: &[u8]) -> u32 {
    let message = Message::parse(response_bytes).expect("valid dns response");
    message.answers[0].ttl
}

/// Regression test for section 02 of `docs/plans/ttl_remaining/`: before
/// this section's wiring, `handle_datagram` called raw `SystemTime::now()`
/// with no way to inject a fixed/advanceable time, so this test could not
/// have been written -- there was nothing to control. It now proves the
/// whole transport-to-cache pipeline ages a cache-hit's TTL by exactly the
/// amount the injected clock is advanced between two live requests.
#[tokio::test]
async fn clock_injection_ages_cache_hit_ttl_end_to_end() {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();
    let origin_ttl = 100u32;
    // The fake upstream answers exactly once, then this task exits and
    // drops the socket: if the second query below reached the backend
    // instead of hitting the cache, nothing would be listening to answer
    // it, so the resolver would time out (or hit a fast connection-refused)
    // and return SERVFAIL instead of the aged TTL -- so a passing test also
    // proves the second query was served from cache, not re-resolved.
    let upstream_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let (request_len, source) = upstream_socket.recv_from(&mut request).await.unwrap();
        assert_ne!(request_len, 0);
        let upstream_id = u16::from_be_bytes([request[0], request[1]]);
        upstream_socket
            .send_to(
                &a_response_with_ttl(upstream_id, "example.com", origin_ttl),
                source,
            )
            .await
            .unwrap();
    });

    let config = config_with_upstream(upstream_addr);
    let clock: Arc<AdvanceableClock> = Arc::new(AdvanceableClock::new());
    let clock_dyn: Arc<dyn Clock> = clock.clone();
    let (server_addr, shutdown_tx, server_task) = run_server_with_clock(&config, clock_dyn).await;

    let first_response = send_query(server_addr, &a_query(0x1111, "example.com")).await;
    assert_eq!(answer_ttl(&first_response), origin_ttl);

    let advance_by = 40u64;
    clock.advance(advance_by);

    let second_response = send_query(server_addr, &a_query(0x2222, "example.com")).await;
    assert_eq!(
        answer_ttl(&second_response),
        origin_ttl - advance_by as u32,
        "cache-hit ttl should be aged by exactly the injected clock's advance"
    );

    upstream_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}
