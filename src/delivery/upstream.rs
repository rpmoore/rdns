use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::time;

use crate::config::{UpstreamConfig, UpstreamProtocol};
use crate::protocol::{rewrite_response_id, Message};
use crate::resolver::{UpstreamError, UpstreamRequest, UpstreamResolver, UpstreamResponse};

pub trait TransactionIdGenerator: Send + Sync {
    fn next_id(&self) -> u16;
}

pub struct MonotonicTransactionIdGenerator {
    next: AtomicU16,
}

impl MonotonicTransactionIdGenerator {
    pub fn new(seed: u16) -> Self {
        Self {
            next: AtomicU16::new(seed),
        }
    }

    pub fn seeded_from_time() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos())
            .unwrap_or(0);
        Self::new((nanos as u16).max(1))
    }
}

impl TransactionIdGenerator for MonotonicTransactionIdGenerator {
    fn next_id(&self) -> u16 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

pub struct UdpUpstreamResolver {
    upstream: UpstreamConfig,
    id_generator: Arc<dyn TransactionIdGenerator>,
}

impl UdpUpstreamResolver {
    pub fn new(upstream: UpstreamConfig) -> Self {
        Self::with_id_generator(
            upstream,
            Arc::new(MonotonicTransactionIdGenerator::seeded_from_time()),
        )
    }

    pub fn with_id_generator(
        upstream: UpstreamConfig,
        id_generator: Arc<dyn TransactionIdGenerator>,
    ) -> Self {
        Self {
            upstream,
            id_generator,
        }
    }

    pub fn from_config(upstreams: &[UpstreamConfig]) -> Result<Self, UpstreamError> {
        let upstream = upstreams
            .iter()
            .filter(|upstream| upstream.enabled && upstream.protocol == UpstreamProtocol::Udp)
            .min_by_key(|upstream| upstream.priority)
            .cloned()
            .ok_or(UpstreamError::NoUpstreamsAvailable)?;
        Ok(Self::new(upstream))
    }

    async fn resolve_once(
        &self,
        request: UpstreamRequest,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let upstream_id = self.id_generator.next_id();
        let client_id = request.query.message.header.id;
        let mut upstream_query = request.query.message.original_bytes.clone();
        rewrite_response_id(&mut upstream_query, upstream_id)
            .map_err(|_| UpstreamError::MalformedResponse)?;

        let socket = bind_ephemeral_for(self.upstream.endpoint).await?;
        socket
            .send_to(&upstream_query, self.upstream.endpoint)
            .await
            .map_err(transport_error)?;

        let mut response_bytes = vec![0; 4096];
        let (response_len, source) =
            time::timeout(self.upstream.timeout, socket.recv_from(&mut response_bytes))
                .await
                .map_err(|_| UpstreamError::Timeout)?
                .map_err(transport_error)?;
        response_bytes.truncate(response_len);

        validate_upstream_response_source(source, self.upstream.endpoint)?;
        validate_upstream_response(&request, &response_bytes, upstream_id)?;
        rewrite_response_id(&mut response_bytes, client_id)
            .map_err(|_| UpstreamError::MalformedResponse)?;

        Ok(UpstreamResponse {
            bytes: response_bytes,
            received_at: SystemTime::now(),
        })
    }
}

impl UpstreamResolver for UdpUpstreamResolver {
    fn resolve<'a>(
        &'a self,
        request: UpstreamRequest,
    ) -> crate::resolver::BoxFuture<'a, Result<UpstreamResponse, UpstreamError>> {
        Box::pin(async move { self.resolve_once(request).await })
    }
}

async fn bind_ephemeral_for(upstream: SocketAddr) -> Result<UdpSocket, UpstreamError> {
    let bind_address = match upstream {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    UdpSocket::bind(bind_address).await.map_err(transport_error)
}

fn validate_upstream_response_source(
    source: SocketAddr,
    expected: SocketAddr,
) -> Result<(), UpstreamError> {
    if source == expected {
        Ok(())
    } else {
        Err(UpstreamError::Transport(format!(
            "unexpected upstream source {source}, expected {expected}"
        )))
    }
}

fn validate_upstream_response(
    request: &UpstreamRequest,
    response_bytes: &[u8],
    upstream_id: u16,
) -> Result<(), UpstreamError> {
    let response = Message::parse(response_bytes).map_err(|_| UpstreamError::MalformedResponse)?;
    if response.header.id != upstream_id {
        return Err(UpstreamError::MalformedResponse);
    }
    if !response.header.qr() {
        return Err(UpstreamError::MalformedResponse);
    }
    if response.questions.len() != 1 || response.questions[0] != request.query.message.questions[0]
    {
        return Err(UpstreamError::QuestionMismatch);
    }
    Ok(())
}

fn transport_error(error: io::Error) -> UpstreamError {
    UpstreamError::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    use crate::config::UpstreamConfig;
    use crate::resolver::{DecodedQuery, QueryFeatures, QuestionKey};

    struct FixedTransactionId(u16);

    impl TransactionIdGenerator for FixedTransactionId {
        fn next_id(&self) -> u16 {
            self.0
        }
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

    fn upstream_config(endpoint: SocketAddr) -> UpstreamConfig {
        UpstreamConfig {
            name: "test".to_string(),
            endpoint,
            protocol: UpstreamProtocol::Udp,
            enabled: true,
            priority: 10,
            timeout: Duration::from_secs(1),
        }
    }

    fn upstream_request(id: u16, name: &str) -> UpstreamRequest {
        let message = Message::parse_standard_query(&a_query(id, name)).unwrap();
        UpstreamRequest {
            query: DecodedQuery {
                question: QuestionKey::from_message(&message).unwrap(),
                features: QueryFeatures::from_message(&message),
                message,
            },
        }
    }

    #[tokio::test]
    async fn udp_upstream_forwards_with_fresh_id_and_maps_response_back() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();
        let seen_query = Arc::new(Mutex::new(Vec::new()));
        let seen_query_task = seen_query.clone();
        let upstream_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (request_len, source) = upstream_socket.recv_from(&mut request).await.unwrap();
            seen_query_task
                .lock()
                .unwrap()
                .extend_from_slice(&request[..request_len]);
            upstream_socket
                .send_to(&a_response(0xbeef, "example.com"), source)
                .await
                .unwrap();
        });
        let resolver = UdpUpstreamResolver::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let response = resolver
            .resolve_once(upstream_request(0x1234, "example.com"))
            .await
            .unwrap();

        upstream_task.await.unwrap();
        assert_eq!(&seen_query.lock().unwrap()[0..2], &[0xbe, 0xef]);
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
    }

    #[tokio::test]
    async fn udp_upstream_rejects_response_id_mismatch() {
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
        let resolver = UdpUpstreamResolver::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let error = resolver
            .resolve_once(upstream_request(0x1234, "example.com"))
            .await
            .unwrap_err();

        upstream_task.await.unwrap();
        assert_eq!(error, UpstreamError::MalformedResponse);
    }

    #[tokio::test]
    async fn udp_upstream_rejects_query_shaped_packet() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = upstream_socket.recv_from(&mut request).await.unwrap();
            upstream_socket
                .send_to(&a_query(0xbeef, "example.com"), source)
                .await
                .unwrap();
        });
        let resolver = UdpUpstreamResolver::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let error = resolver
            .resolve_once(upstream_request(0x1234, "example.com"))
            .await
            .unwrap_err();

        upstream_task.await.unwrap();
        assert_eq!(error, UpstreamError::MalformedResponse);
    }

    #[tokio::test]
    async fn udp_upstream_rejects_question_mismatch() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = upstream_socket.recv_from(&mut request).await.unwrap();
            upstream_socket
                .send_to(&a_response(0xbeef, "other.example"), source)
                .await
                .unwrap();
        });
        let resolver = UdpUpstreamResolver::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let error = resolver
            .resolve_once(upstream_request(0x1234, "example.com"))
            .await
            .unwrap_err();

        upstream_task.await.unwrap();
        assert_eq!(error, UpstreamError::QuestionMismatch);
    }
}
