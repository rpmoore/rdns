use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::net::UdpSocket;

use crate::config::RuntimeConfig;
use crate::resolver::{ResolveQuery, ResolveRequest};

pub struct UdpDnsServer {
    socket: UdpSocket,
    resolver: Arc<ResolveQuery>,
    max_request_size: usize,
}

impl UdpDnsServer {
    pub fn new(socket: UdpSocket, resolver: Arc<ResolveQuery>, max_request_size: usize) -> Self {
        Self {
            socket,
            resolver,
            max_request_size,
        }
    }

    pub async fn bind(
        address: SocketAddr,
        resolver: Arc<ResolveQuery>,
        max_request_size: usize,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(address).await?;
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
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                result = self.handle_next_datagram() => result?,
            }
        }
    }

    async fn handle_next_datagram(&self) -> io::Result<()> {
        let mut request_bytes = vec![0; self.max_request_size];
        let (request_len, source) = self.socket.recv_from(&mut request_bytes).await?;
        request_bytes.truncate(request_len);

        let outcome = self
            .resolver
            .resolve(ResolveRequest::new(
                source.ip(),
                SystemTime::now(),
                request_bytes,
            ))
            .await;
        self.socket
            .send_to(&outcome.response_bytes, source)
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::time::Duration;

    use crate::resolver::{
        BasicResponseFactory, BoxFuture, Clock, MetricsSink, QueryEventSink, ResolveDecision,
        ResolverMetric, StandardProtocolCodec, UpstreamError, UpstreamRequest, UpstreamResolver,
        UpstreamResponse,
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
        decisions: Mutex<Vec<ResolveDecision>>,
    }

    impl QueryEventSink for RecordingEvents {
        fn record<'a>(&'a self, decision: ResolveDecision) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.decisions.lock().unwrap().push(decision);
            })
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

    impl UpstreamResolver for StaticUpstream {
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

    #[tokio::test]
    async fn udp_server_passes_raw_query_and_client_ip_to_resolver() {
        let upstream_response = vec![0xab, 0xcd, 0x81, 0x80];
        let upstream = Arc::new(StaticUpstream::new(Ok(UpstreamResponse {
            bytes: upstream_response,
            received_at: SystemTime::UNIX_EPOCH,
        })));
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
        let upstream_requests = upstream.requests.lock().unwrap();
        assert_eq!(upstream_requests.len(), 1);
        assert_eq!(upstream_requests[0].query.question.qname, "example.com");
        drop(upstream_requests);
        let decisions = events.decisions.lock().unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].client_ip, client_addr.ip());

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
}
