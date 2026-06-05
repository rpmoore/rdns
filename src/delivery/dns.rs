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

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::config::RuntimeConfig;
use crate::resolver::{ObservedSourceEndpoint, ResolveQuery, ResolveRequest};

const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 1024;

/// Bind a UDP socket for the DNS listener.
///
/// On Linux, `SO_REUSEPORT` is set so that multiple processes or tasks can each
/// bind their own socket to the same address and the kernel distributes incoming
/// datagrams across them, enabling true parallel receive.
///
/// On macOS and other platforms, `SO_REUSEPORT` does not provide kernel-level
/// UDP load-balancing, so we fall back to a standard `tokio::net::UdpSocket`
/// bind which is the performant approach on those systems.
#[cfg(target_os = "linux")]
async fn bind_listener_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

#[cfg(not(target_os = "linux"))]
async fn bind_listener_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(address).await
}

pub struct UdpDnsServer {
    socket: Arc<UdpSocket>,
    resolver: Arc<ResolveQuery>,
    listener: Option<SocketAddr>,
    max_request_size: usize,
    max_in_flight_requests: usize,
}

impl UdpDnsServer {
    pub fn new(socket: UdpSocket, resolver: Arc<ResolveQuery>, max_request_size: usize) -> Self {
        Self::with_max_in_flight_requests(
            socket,
            resolver,
            max_request_size,
            DEFAULT_MAX_IN_FLIGHT_REQUESTS,
        )
    }

    pub fn with_max_in_flight_requests(
        socket: UdpSocket,
        resolver: Arc<ResolveQuery>,
        max_request_size: usize,
        max_in_flight_requests: usize,
    ) -> Self {
        let listener = socket.local_addr().ok();
        Self {
            socket: Arc::new(socket),
            resolver,
            listener,
            max_request_size,
            max_in_flight_requests,
        }
    }

    pub async fn bind(
        address: SocketAddr,
        resolver: Arc<ResolveQuery>,
        max_request_size: usize,
    ) -> io::Result<Self> {
        let socket = bind_listener_socket(address).await?;
        Ok(Self::new(socket, resolver, max_request_size))
    }

    pub async fn bind_configured(
        config: &RuntimeConfig,
        resolver: Arc<ResolveQuery>,
    ) -> io::Result<Vec<Self>> {
        let mut servers = Vec::with_capacity(config.dns_listen.len());
        for address in &config.dns_listen {
            servers
                .push(Self::bind(*address, resolver.clone(), config.max_udp_payload_size).await?);
        }
        Ok(servers)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn serve_until<S>(&self, shutdown: S) -> io::Result<()>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let semaphore = Arc::new(Semaphore::new(self.max_in_flight_requests));
        let mut tasks = JoinSet::new();
        loop {
            if tasks.is_empty() {
                tokio::select! {
                    _ = &mut shutdown => break,
                    result = self.receive_permitted_datagram(semaphore.clone()) => {
                        if !self.spawn_received_datagram(result?, &mut tasks) {
                            break;
                        }
                    }
                }
            } else {
                tokio::select! {
                    _ = &mut shutdown => break,
                    result = self.receive_permitted_datagram(semaphore.clone()) => {
                        if !self.spawn_received_datagram(result?, &mut tasks) {
                            break;
                        }
                    }
                    result = tasks.join_next() => {
                        if let Some(result) = result {
                            task_result_to_io(result)??;
                        }
                    }
                }
            }
        }

        while let Some(result) = tasks.join_next().await {
            task_result_to_io(result)??;
        }
        Ok(())
    }

    fn spawn_received_datagram(
        &self,
        datagram: Option<ReceivedDatagram>,
        tasks: &mut JoinSet<io::Result<()>>,
    ) -> bool {
        let Some(datagram) = datagram else {
            return false;
        };
        self.spawn_datagram_task(datagram, tasks);
        true
    }

    async fn receive_permitted_datagram(
        &self,
        semaphore: Arc<Semaphore>,
    ) -> io::Result<Option<ReceivedDatagram>> {
        let permit = match semaphore.acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return Ok(None),
        };
        let mut request_bytes = vec![0; self.max_request_size];
        let (request_len, source) = self.socket.recv_from(&mut request_bytes).await?;
        request_bytes.truncate(request_len);
        Ok(Some(ReceivedDatagram {
            permit,
            request_bytes,
            source,
        }))
    }

    fn spawn_datagram_task(&self, datagram: ReceivedDatagram, tasks: &mut JoinSet<io::Result<()>>) {
        let socket = Arc::clone(&self.socket);
        let resolver = Arc::clone(&self.resolver);
        let listener = self.listener;
        tasks.spawn(async move { handle_datagram(socket, resolver, listener, datagram).await });
    }
}

struct ReceivedDatagram {
    permit: OwnedSemaphorePermit,
    request_bytes: Vec<u8>,
    source: SocketAddr,
}

async fn handle_datagram(
    socket: Arc<UdpSocket>,
    resolver: Arc<ResolveQuery>,
    listener: Option<SocketAddr>,
    datagram: ReceivedDatagram,
) -> io::Result<()> {
    let _permit = datagram.permit;
    let outcome = resolver
        .resolve(ResolveRequest::new_with_observed_source(
            ObservedSourceEndpoint::udp(datagram.source, listener),
            SystemTime::now(),
            datagram.request_bytes,
        ))
        .await;
    socket
        .send_to(&outcome.response_bytes, datagram.source)
        .await
        .map(|_| ())
}

fn task_result_to_io(
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> io::Result<io::Result<()>> {
    result.map_err(|error| io::Error::other(format!("DNS request task failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::sync::Notify;
    use tokio::time;

    use crate::resolver::{
        BasicResponseFactory, Clock, MetricsSink, QueryEventRecordResult, QueryEventSink,
        QueryEventV1, QueryTransport, ResolutionBackend, ResolverMetric, StandardProtocolCodec,
        UpstreamError, UpstreamRequest, UpstreamResponse,
    };

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

    struct FixedClock(SystemTime);

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    #[derive(Default)]
    struct RecordingEvents {
        events: Mutex<Vec<QueryEventV1>>,
    }

    impl QueryEventSink for RecordingEvents {
        fn record(&self, event: QueryEventV1) -> QueryEventRecordResult {
            self.events.lock().unwrap().push(event);
            QueryEventRecordResult::Accepted
        }
    }

    #[derive(Default)]
    struct NoopMetrics;

    impl MetricsSink for NoopMetrics {
        fn increment(&self, _metric: ResolverMetric) {}

        fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
    }

    struct StaticUpstream {
        response: Result<UpstreamResponse, UpstreamError>,
        requests: Mutex<Vec<UpstreamRequest>>,
    }

    impl StaticUpstream {
        fn new(response: Result<UpstreamResponse, UpstreamError>) -> Self {
            Self {
                response,
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl ResolutionBackend for StaticUpstream {
        fn resolve<'a>(
            &'a self,
            request: UpstreamRequest,
        ) -> Pin<Box<dyn Future<Output = Result<UpstreamResponse, UpstreamError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request);
                self.response.clone()
            })
        }
    }

    fn upstream_response(bytes: Vec<u8>) -> UpstreamResponse {
        UpstreamResponse::forwarded_bytes(bytes, SystemTime::UNIX_EPOCH, 0, "test-forwarder")
    }

    struct DelayedFirstUpstream {
        first_started: Notify,
        first_release: Notify,
        requests: Mutex<usize>,
    }

    impl DelayedFirstUpstream {
        fn new() -> Self {
            Self {
                first_started: Notify::new(),
                first_release: Notify::new(),
                requests: Mutex::new(0),
            }
        }
    }

    impl ResolutionBackend for DelayedFirstUpstream {
        fn resolve<'a>(
            &'a self,
            _request: UpstreamRequest,
        ) -> Pin<Box<dyn Future<Output = Result<UpstreamResponse, UpstreamError>> + Send + 'a>>
        {
            Box::pin(async move {
                let request_number = {
                    let mut requests = self.requests.lock().unwrap();
                    *requests += 1;
                    *requests
                };
                if request_number == 1 {
                    self.first_started.notify_waiters();
                    self.first_release.notified().await;
                }
                Ok(upstream_response(vec![0, 0, 0x81, 0x80]))
            })
        }
    }

    fn resolve_service(
        upstream: Arc<StaticUpstream>,
        events: Arc<RecordingEvents>,
    ) -> Arc<ResolveQuery> {
        Arc::new(ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            upstream,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            Arc::new(NoopMetrics),
        ))
    }

    async fn unused_high_local_address() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        assert!(address.port() > 1024);
        address
    }

    async fn recv_response(client: &UdpSocket) -> Vec<u8> {
        let mut response = [0u8; 64];
        let (response_len, _) = client.recv_from(&mut response).await.unwrap();
        response[..response_len].to_vec()
    }

    #[tokio::test]
    async fn udp_server_passes_raw_query_and_client_ip_to_resolver() {
        let backend_bytes = vec![0xab, 0xcd, 0x81, 0x80];
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(backend_bytes))));
        let events = Arc::new(RecordingEvents::default());
        let resolver = resolve_service(upstream.clone(), events.clone());
        let server = UdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, 1232)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        client
            .send_to(&a_query(0x1234, "example.com"), server_addr)
            .await
            .unwrap();
        let mut response = [0u8; 64];
        let (response_len, source) = client.recv_from(&mut response).await.unwrap();

        assert_eq!(source, server_addr);
        assert_eq!(&response[..response_len], &[0x12, 0x34, 0x81, 0x80]);
        {
            let upstream_requests = upstream.requests.lock().unwrap();
            assert_eq!(upstream_requests.len(), 1);
            assert_eq!(upstream_requests[0].query.question.qname, "example.com");
        }
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(recorded_events[0].observed_source.ip, client_addr.ip());
            assert_eq!(
                recorded_events[0].observed_source.port,
                Some(client_addr.port())
            );
            assert_eq!(
                recorded_events[0].observed_source.transport,
                Some(QueryTransport::Udp)
            );
            assert_eq!(
                recorded_events[0].observed_source.listener,
                Some(server_addr)
            );
        }

        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn bind_configured_creates_one_server_per_dns_listener() {
        let first_address = unused_high_local_address().await;
        let second_address = unused_high_local_address().await;
        let config = RuntimeConfig::new(
            vec![first_address, second_address],
            vec![crate::config::UpstreamConfig {
                name: "primary".to_string(),
                endpoint: "192.0.2.53:53".parse().unwrap(),
                protocol: crate::config::UpstreamProtocol::Udp,
                enabled: true,
                priority: 10,
                timeout: Duration::from_millis(500),
            }],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));

        let servers = UdpDnsServer::bind_configured(&config, resolver)
            .await
            .unwrap();

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].local_addr().unwrap(), first_address);
        assert_eq!(servers[1].local_addr().unwrap(), second_address);
    }

    #[tokio::test]
    async fn udp_server_handles_next_datagram_while_first_request_is_in_flight() {
        let upstream = Arc::new(DelayedFirstUpstream::new());
        let resolver = Arc::new(ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(NoopMetrics),
        ));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = UdpDnsServer::with_max_in_flight_requests(socket, resolver, 1232, 2);
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let slow_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_started = upstream.first_started.notified();
        slow_client
            .send_to(&a_query(0x1111, "slow.example"), server_addr)
            .await
            .unwrap();
        first_started.await;

        let fast_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        fast_client
            .send_to(&a_query(0x2222, "fast.example"), server_addr)
            .await
            .unwrap();

        let fast_response = time::timeout(Duration::from_millis(100), recv_response(&fast_client))
            .await
            .unwrap();

        assert_eq!(&fast_response[0..2], &[0x22, 0x22]);
        upstream.first_release.notify_waiters();
        assert_eq!(&recv_response(&slow_client).await[0..2], &[0x11, 0x11]);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_server_drains_in_flight_request_after_shutdown() {
        let upstream = Arc::new(DelayedFirstUpstream::new());
        let resolver = Arc::new(ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(NoopMetrics),
        ));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = UdpDnsServer::with_max_in_flight_requests(socket, resolver, 1232, 2);
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let mut server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_started = upstream.first_started.notified();
        client
            .send_to(&a_query(0x3333, "slow.example"), server_addr)
            .await
            .unwrap();
        first_started.await;
        shutdown_tx.send(()).unwrap();

        assert!(time::timeout(Duration::from_millis(50), &mut server_task)
            .await
            .is_err());
        upstream.first_release.notify_waiters();
        server_task.await.unwrap().unwrap();
    }
}
