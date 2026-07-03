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
use rdns::protocol::encode_tcp_frame;
use rdns::resolver::{
    BasicResponseFactory, Clock, MetricsSink, QueryEventRecordResult, QueryEventSink, QueryEventV1,
    ResolveQuery, ResolverMetric, StandardProtocolCodec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
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

fn a_response(id: u16, name: &str) -> Vec<u8> {
    let mut bytes = a_query(id, name);
    bytes[2] = 0x81;
    bytes[3] = 0x80;
    bytes
}

fn truncated_response(id: u16, name: &str) -> Vec<u8> {
    let mut bytes = a_response(id, name);
    bytes[2] |= 0x02;
    bytes
}

fn upstream_config(name: &str, endpoint: SocketAddr, priority: u16) -> UpstreamConfig {
    UpstreamConfig {
        name: name.to_string(),
        endpoint,
        protocol: UpstreamProtocol::Udp,
        enabled: true,
        priority,
        timeout: Duration::from_millis(50),
    }
}

fn resolver_from_config(config: &RuntimeConfig) -> Arc<ResolveQuery> {
    Arc::new(ResolveQuery::new(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(ForwardingResolutionBackend::from_runtime_config(config).unwrap()),
        Arc::new(BasicResponseFactory),
        Arc::new(FixedClock),
        Arc::new(NoopEvents),
        Arc::new(NoopMetrics),
    ))
}

async fn run_server(
    config: &RuntimeConfig,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let resolver = resolver_from_config(config);
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

async fn send_query(server_addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(request, server_addr).await.unwrap();
    let mut response = [0u8; 512];
    let (response_len, source) = client.recv_from(&mut response).await.unwrap();
    assert_eq!(source, server_addr);
    response[..response_len].to_vec()
}

async fn read_tcp_query(stream: &mut TcpStream) -> Vec<u8> {
    let mut length_prefix = [0u8; 2];
    stream.read_exact(&mut length_prefix).await.unwrap();
    let query_len = u16::from_be_bytes(length_prefix) as usize;
    let mut query = vec![0u8; query_len];
    stream.read_exact(&mut query).await.unwrap();
    query
}

fn config_with_upstreams(upstreams: Vec<UpstreamConfig>, deadline: Duration) -> RuntimeConfig {
    RuntimeConfig::new(
        vec!["127.0.0.1:5300".parse().unwrap()],
        upstreams,
        deadline,
        1232,
    )
    .unwrap()
}

#[tokio::test]
async fn dns_server_forwards_to_udp_upstream() {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let (request_len, source) = upstream_socket.recv_from(&mut request).await.unwrap();
        let upstream_id = u16::from_be_bytes([request[0], request[1]]);
        assert_ne!(request_len, 0);
        upstream_socket
            .send_to(&a_response(upstream_id, "example.com"), source)
            .await
            .unwrap();
    });
    let config = config_with_upstreams(
        vec![upstream_config("primary", upstream_addr, 10)],
        Duration::from_millis(200),
    );
    let (server_addr, shutdown_tx, server_task) = run_server(&config).await;

    let response = send_query(server_addr, &a_query(0x1234, "example.com")).await;

    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(response[3] & 0x0f, 0);
    upstream_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_server_maps_upstream_timeout_to_servfail() {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let _ = upstream_socket.recv_from(&mut request).await.unwrap();
    });
    let config = config_with_upstreams(
        vec![upstream_config("primary", upstream_addr, 10)],
        Duration::from_millis(150),
    );
    let (server_addr, shutdown_tx, server_task) = run_server(&config).await;

    let response = send_query(server_addr, &a_query(0x1234, "example.com")).await;

    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(response[3] & 0x0f, 2);
    upstream_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_server_fails_over_between_udp_upstreams() {
    let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first_socket.local_addr().unwrap();
    let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second_socket.local_addr().unwrap();
    let first_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let _ = first_socket.recv_from(&mut request).await.unwrap();
    });
    let second_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let (_, source) = second_socket.recv_from(&mut request).await.unwrap();
        let upstream_id = u16::from_be_bytes([request[0], request[1]]);
        second_socket
            .send_to(&a_response(upstream_id, "example.com"), source)
            .await
            .unwrap();
    });
    let config = config_with_upstreams(
        vec![
            upstream_config("primary", first_addr, 10),
            upstream_config("secondary", second_addr, 20),
        ],
        Duration::from_millis(200),
    );
    let (server_addr, shutdown_tx, server_task) = run_server(&config).await;

    let response = send_query(server_addr, &a_query(0x1234, "example.com")).await;

    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(response[3] & 0x0f, 0);
    first_task.await.unwrap();
    second_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_server_rejects_malformed_upstream_response() {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let (_, source) = upstream_socket.recv_from(&mut request).await.unwrap();
        let upstream_id = u16::from_be_bytes([request[0], request[1]]);
        upstream_socket
            .send_to(&a_query(upstream_id, "example.com"), source)
            .await
            .unwrap();
    });
    let config = config_with_upstreams(
        vec![upstream_config("primary", upstream_addr, 10)],
        Duration::from_millis(150),
    );
    let (server_addr, shutdown_tx, server_task) = run_server(&config).await;

    let response = send_query(server_addr, &a_query(0x1234, "example.com")).await;

    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(response[3] & 0x0f, 2);
    upstream_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_server_rejects_upstream_response_from_wrong_source() {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let (_, resolver_source) = upstream_socket.recv_from(&mut request).await.unwrap();
        let upstream_id = u16::from_be_bytes([request[0], request[1]]);
        let wrong_source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        wrong_source
            .send_to(&a_response(upstream_id, "example.com"), resolver_source)
            .await
            .unwrap();
    });
    let config = config_with_upstreams(
        vec![upstream_config("primary", upstream_addr, 10)],
        Duration::from_millis(150),
    );
    let (server_addr, shutdown_tx, server_task) = run_server(&config).await;

    let response = send_query(server_addr, &a_query(0x1234, "example.com")).await;

    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(response[3] & 0x0f, 2);
    upstream_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_server_rejects_upstream_response_id_mismatch() {
    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_socket.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let (_, source) = upstream_socket.recv_from(&mut request).await.unwrap();
        upstream_socket
            .send_to(&a_response(0xabcd, "example.com"), source)
            .await
            .unwrap();
    });
    let config = config_with_upstreams(
        vec![upstream_config("primary", upstream_addr, 10)],
        Duration::from_millis(150),
    );
    let (server_addr, shutdown_tx, server_task) = run_server(&config).await;

    let response = send_query(server_addr, &a_query(0x1234, "example.com")).await;

    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(response[3] & 0x0f, 2);
    upstream_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_server_uses_tcp_fallback_for_truncated_udp_upstream() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = tcp_listener.local_addr().unwrap();
    let udp_socket = UdpSocket::bind(upstream_addr).await.unwrap();
    let udp_task = tokio::spawn(async move {
        let mut request = [0u8; 512];
        let (_, source) = udp_socket.recv_from(&mut request).await.unwrap();
        let upstream_id = u16::from_be_bytes([request[0], request[1]]);
        udp_socket
            .send_to(&truncated_response(upstream_id, "example.com"), source)
            .await
            .unwrap();
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp_listener.accept().await.unwrap();
        let query = read_tcp_query(&mut stream).await;
        let upstream_id = u16::from_be_bytes([query[0], query[1]]);
        let response = encode_tcp_frame(&a_response(upstream_id, "example.com"), 512).unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let config = config_with_upstreams(
        vec![upstream_config("primary", upstream_addr, 10)],
        Duration::from_millis(200),
    );
    let (server_addr, shutdown_tx, server_task) = run_server(&config).await;

    let response = send_query(server_addr, &a_query(0x1234, "example.com")).await;

    assert_eq!(&response[0..2], &[0x12, 0x34]);
    assert_eq!(response[3] & 0x0f, 0);
    assert_eq!(response[2] & 0x02, 0);
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn dns_server_shuts_down_gracefully() {
    let config = config_with_upstreams(
        vec![upstream_config(
            "primary",
            "127.0.0.1:53535".parse().unwrap(),
            10,
        )],
        Duration::from_millis(150),
    );
    let (_server_addr, shutdown_tx, server_task) = run_server(&config).await;

    shutdown_tx.send(()).unwrap();

    server_task.await.unwrap().unwrap();
}
