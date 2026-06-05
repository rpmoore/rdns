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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rdns::config::{RuntimeConfig, UpstreamConfig, UpstreamProtocol};
use rdns::delivery::dns::UdpDnsServer;
use rdns::delivery::upstream::ForwardingResolutionBackend;
use rdns::protocol::Message;
use rdns::resolver::{
    BasicResponseFactory, Clock, MetricsSink, QueryEventRecordResult, QueryEventSink, QueryEventV1,
    ResolveQuery, ResolverMetric, StandardProtocolCodec,
};
use tokio::net::UdpSocket;
use tokio::time;

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

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
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
    bytes.extend_from_slice(&qtype.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes
}

fn live_upstream(name: &str, endpoint: &str) -> UpstreamConfig {
    UpstreamConfig {
        name: name.to_string(),
        endpoint: endpoint.parse().unwrap(),
        protocol: UpstreamProtocol::Udp,
        enabled: true,
        priority: 10,
        timeout: Duration::from_secs(2),
    }
}

async fn run_live_server(
    upstream: UpstreamConfig,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let config = RuntimeConfig::new(
        vec!["127.0.0.1:5300".parse().unwrap()],
        vec![upstream],
        Duration::from_secs(3),
        1232,
    )
    .unwrap();
    let resolver = Arc::new(ResolveQuery::new(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(ForwardingResolutionBackend::from_runtime_config(&config).unwrap()),
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(NoopEvents),
        Arc::new(NoopMetrics),
    ));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = UdpDnsServer::new(socket, resolver, config.max_udp_payload_size);
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

async fn resolve_via_server(server_addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(request, server_addr).await.unwrap();
    let mut response = [0u8; 4096];
    let (response_len, source) =
        time::timeout(Duration::from_secs(5), client.recv_from(&mut response))
            .await
            .expect("live DNS query timed out")
            .unwrap();
    assert_eq!(source, server_addr);
    response[..response_len].to_vec()
}

async fn assert_live_resolution(upstream: UpstreamConfig, request: Vec<u8>, expected_id: u16) {
    let (server_addr, shutdown_tx, server_task) = run_live_server(upstream).await;

    let response = resolve_via_server(server_addr, &request).await;
    let message = Message::parse(&response).unwrap();

    assert_eq!(message.header.id, expected_id);
    assert!(message.header.qr());
    assert_eq!(message.header.r_code(), 0);
    assert!(!message.answers.is_empty());
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
#[ignore = "requires outbound UDP DNS access to a public resolver"]
async fn live_dns_resolves_google_a_through_cloudflare() {
    assert_live_resolution(
        live_upstream("cloudflare", "1.1.1.1:53"),
        query(0x1234, "google.com", 1),
        0x1234,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires outbound UDP DNS access to a public resolver"]
async fn live_dns_resolves_example_a_through_google_dns() {
    assert_live_resolution(
        live_upstream("google", "8.8.8.8:53"),
        query(0x5678, "example.com", 1),
        0x5678,
    )
    .await;
}
