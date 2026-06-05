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
use std::net::SocketAddr;
use std::process;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::time::{self, Instant};

use crate::config::{RecursiveTransport, RuntimeConfig, UpstreamConfig, UpstreamProtocol};
use crate::protocol::{encode_tcp_frame, first_question, rewrite_response_id, Message};
use crate::resolver::{
    MetricsSink, NoopMetricsSink, QuestionKey, RecursiveAuthorityResponse,
    RecursiveAuthorityTransport, ResolutionBackend, ResolverMetric, UpstreamError, UpstreamRequest,
    UpstreamResponse,
};

const DEGRADED_FAILURE_THRESHOLD: u32 = 2;
const DEGRADED_RETRY_AFTER: Duration = Duration::from_secs(30);
const SPLITMIX_INCREMENT: u64 = 0x9e37_79b9_7f4a_7c15;
const MAX_TCP_MESSAGE_SIZE: usize = u16::MAX as usize;

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

pub struct MixedTransactionIdGenerator {
    state: AtomicU64,
}

impl MixedTransactionIdGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            state: AtomicU64::new(seed),
        }
    }

    pub fn seeded_from_environment() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| {
                let nanos = duration.as_nanos();
                (nanos as u64) ^ ((nanos >> 64) as u64)
            })
            .unwrap_or(0);
        let process_seed = u64::from(process::id()) << 32;
        Self::new(now ^ process_seed ^ SPLITMIX_INCREMENT)
    }
}

impl TransactionIdGenerator for MixedTransactionIdGenerator {
    fn next_id(&self) -> u16 {
        let state = self.state.fetch_add(SPLITMIX_INCREMENT, Ordering::Relaxed);
        splitmix64(state) as u16
    }
}

fn splitmix64(value: u64) -> u64 {
    let mut mixed = value.wrapping_add(SPLITMIX_INCREMENT);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

pub struct ForwardingResolutionBackend {
    upstreams: Vec<UpstreamConfig>,
    id_generator: Arc<dyn TransactionIdGenerator>,
    per_query_deadline: Duration,
    health: Vec<Mutex<UpstreamHealth>>,
}

pub struct RecursiveAuthorityTransportClient {
    id_generator: Arc<dyn TransactionIdGenerator>,
    allowed_transports: Vec<RecursiveTransport>,
    max_udp_payload_size: usize,
    metrics: Arc<dyn MetricsSink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHealthSnapshot {
    pub name: String,
    pub endpoint: SocketAddr,
    pub consecutive_failures: u32,
    pub degraded: bool,
}

#[derive(Debug, Clone, Default)]
struct UpstreamHealth {
    consecutive_failures: u32,
    degraded: bool,
    retry_after: Option<Instant>,
}

#[derive(Clone, Copy)]
struct UpstreamAttempt {
    upstream_id: u16,
    client_id: u16,
    deadline: Instant,
}

impl ForwardingResolutionBackend {
    pub fn new(upstream: UpstreamConfig) -> Self {
        Self::with_id_generator(
            upstream,
            Arc::new(MixedTransactionIdGenerator::seeded_from_environment()),
        )
    }

    pub fn with_id_generator(
        upstream: UpstreamConfig,
        id_generator: Arc<dyn TransactionIdGenerator>,
    ) -> Self {
        Self::with_upstreams_and_id_generator(
            vec![upstream.clone()],
            upstream.timeout,
            id_generator,
        )
        .expect("single upstream resolver requires one upstream")
    }

    pub fn with_upstreams_and_id_generator(
        upstreams: Vec<UpstreamConfig>,
        per_query_deadline: Duration,
        id_generator: Arc<dyn TransactionIdGenerator>,
    ) -> Result<Self, UpstreamError> {
        let upstreams = ordered_enabled_udp_upstreams(upstreams);
        if upstreams.is_empty() {
            return Err(UpstreamError::NoBackendsAvailable);
        }
        let health = upstreams
            .iter()
            .map(|_| Mutex::new(UpstreamHealth::default()))
            .collect();
        Ok(Self {
            upstreams,
            id_generator,
            per_query_deadline,
            health,
        })
    }

    pub fn from_config(upstreams: &[UpstreamConfig]) -> Result<Self, UpstreamError> {
        let deadline = upstreams
            .iter()
            .filter(|upstream| upstream.enabled && upstream.protocol == UpstreamProtocol::Udp)
            .fold(Duration::ZERO, |deadline, upstream| {
                deadline + upstream.timeout
            });
        Self::with_upstreams_and_id_generator(
            upstreams.to_vec(),
            deadline,
            Arc::new(MixedTransactionIdGenerator::seeded_from_environment()),
        )
    }

    pub fn from_runtime_config(config: &RuntimeConfig) -> Result<Self, UpstreamError> {
        Self::with_upstreams_and_id_generator(
            config.upstreams.clone(),
            config.per_query_deadline,
            Arc::new(MixedTransactionIdGenerator::seeded_from_environment()),
        )
    }

    pub fn health_snapshots(&self) -> Vec<UpstreamHealthSnapshot> {
        self.upstreams
            .iter()
            .zip(&self.health)
            .map(|(upstream, health)| {
                let health = health.lock().unwrap();
                UpstreamHealthSnapshot {
                    name: upstream.name.clone(),
                    endpoint: upstream.endpoint,
                    consecutive_failures: health.consecutive_failures,
                    degraded: health.degraded,
                }
            })
            .collect()
    }

    #[cfg(test)]
    async fn resolve_once(
        &self,
        request: UpstreamRequest,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let mut upstream_query = request.query.message.original_bytes.to_vec();
        self.resolve_attempt(
            &self.upstreams[0],
            &request,
            &mut upstream_query,
            self.upstreams[0].timeout,
        )
        .await
    }

    async fn resolve_attempt(
        &self,
        upstream: &UpstreamConfig,
        request: &UpstreamRequest,
        upstream_query: &mut [u8],
        attempt_timeout: Duration,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let attempt = UpstreamAttempt {
            upstream_id: self.id_generator.next_id(),
            client_id: request.query.message.header.id,
            deadline: Instant::now() + attempt_timeout,
        };
        rewrite_response_id(upstream_query, attempt.upstream_id)
            .map_err(|_| UpstreamError::MalformedResponse)?;

        let socket = bind_ephemeral_for(upstream.endpoint).await?;
        socket
            .send_to(upstream_query, upstream.endpoint)
            .await
            .map_err(transport_error)?;

        let mut response_bytes = vec![0; 4096];
        let (response_len, source) = time::timeout(
            remaining_until(attempt.deadline)?,
            socket.recv_from(&mut response_bytes),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(transport_error)?;
        response_bytes.truncate(response_len);

        validate_upstream_response_source(source, upstream.endpoint)?;
        if truncated_response_matches_request(request, &response_bytes, attempt.upstream_id)? {
            return self
                .resolve_tcp_fallback_attempt(upstream, request, upstream_query, attempt)
                .await;
        }
        let mut response =
            validate_upstream_response(request, &response_bytes, attempt.upstream_id)?;
        if response.header.tc() {
            return self
                .resolve_tcp_fallback_attempt(upstream, request, upstream_query, attempt)
                .await;
        }
        rewrite_response_id(&mut response_bytes, attempt.client_id)
            .map_err(|_| UpstreamError::MalformedResponse)?;
        response.header.id = attempt.client_id;
        response.original_bytes = Bytes::copy_from_slice(&response_bytes);

        Ok(UpstreamResponse::forwarded_message(
            response_bytes,
            response,
            SystemTime::now(),
            request.backend_generation,
            upstream.name.clone(),
        ))
    }

    async fn resolve_with_failover(
        &self,
        request: UpstreamRequest,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let deadline = Instant::now() + self.per_query_deadline;
        let mut last_error = None;
        let mut upstream_query = request.query.message.original_bytes.to_vec();

        for index in self.attempt_order(Instant::now()) {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }

            let upstream = &self.upstreams[index];
            let attempt_timeout = remaining.min(upstream.timeout);
            let result = self
                .resolve_attempt(upstream, &request, &mut upstream_query, attempt_timeout)
                .await;
            match result {
                Ok(response) => {
                    self.mark_success(index);
                    return Ok(response);
                }
                Err(error) => {
                    self.mark_failure(index, &error);
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or(UpstreamError::Timeout))
    }

    async fn resolve_tcp_fallback_attempt(
        &self,
        upstream: &UpstreamConfig,
        request: &UpstreamRequest,
        upstream_query: &[u8],
        attempt: UpstreamAttempt,
    ) -> Result<UpstreamResponse, UpstreamError> {
        resolve_tcp_fallback(
            upstream,
            request,
            upstream_query,
            attempt.upstream_id,
            attempt.client_id,
            attempt.deadline,
        )
        .await
    }

    fn attempt_order(&self, now: Instant) -> Vec<usize> {
        let mut healthy = Vec::with_capacity(self.upstreams.len());
        let mut degraded = Vec::new();
        for (index, health) in self.health.iter().enumerate() {
            if health.lock().unwrap().is_degraded(now) {
                degraded.push(index);
            } else {
                healthy.push(index);
            }
        }
        healthy.extend(degraded);
        healthy
    }

    fn mark_success(&self, index: usize) {
        let mut health = self.health[index].lock().unwrap();
        health.consecutive_failures = 0;
        health.degraded = false;
        health.retry_after = None;
    }

    fn mark_failure(&self, index: usize, error: &UpstreamError) {
        if !matches!(
            error,
            UpstreamError::Timeout | UpstreamError::MalformedResponse
        ) {
            return;
        }
        let mut health = self.health[index].lock().unwrap();
        health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        if health.consecutive_failures >= DEGRADED_FAILURE_THRESHOLD {
            health.degraded = true;
            health.retry_after = Some(Instant::now() + DEGRADED_RETRY_AFTER);
        }
    }
}

impl RecursiveAuthorityTransportClient {
    pub fn from_runtime_config(config: &RuntimeConfig) -> Result<Self, UpstreamError> {
        let Some(recursive) = config.resolution.recursive.as_ref() else {
            return Err(UpstreamError::NoBackendsAvailable);
        };
        Ok(Self::with_id_generator(
            recursive.allowed_transports.clone(),
            config.max_udp_payload_size,
            Arc::new(MixedTransactionIdGenerator::seeded_from_environment()),
        ))
    }

    pub fn with_id_generator(
        allowed_transports: Vec<RecursiveTransport>,
        max_udp_payload_size: usize,
        id_generator: Arc<dyn TransactionIdGenerator>,
    ) -> Self {
        Self {
            id_generator,
            allowed_transports,
            max_udp_payload_size,
            metrics: Arc::new(NoopMetricsSink),
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<dyn MetricsSink>) -> Self {
        self.metrics = metrics;
        self
    }

    async fn query_authority(
        &self,
        authority: SocketAddr,
        question: QuestionKey,
        dnssec_ok: bool,
        timeout: Duration,
    ) -> Result<RecursiveAuthorityResponse, UpstreamError> {
        let authority_id = self.id_generator.next_id();
        let query = build_authority_query(
            authority_id,
            &question,
            self.max_udp_payload_size,
            dnssec_ok,
        )?;
        let deadline = Instant::now() + timeout;

        if self.transport_allowed(RecursiveTransport::Udp) {
            return self
                .query_authority_udp(authority, &question, &query, authority_id, deadline)
                .await;
        }
        if self.transport_allowed(RecursiveTransport::Tcp) {
            return query_authority_tcp(authority, &question, &query, authority_id, deadline).await;
        }

        Err(UpstreamError::NoBackendsAvailable)
    }

    async fn query_authority_udp(
        &self,
        authority: SocketAddr,
        question: &QuestionKey,
        query: &[u8],
        authority_id: u16,
        deadline: Instant,
    ) -> Result<RecursiveAuthorityResponse, UpstreamError> {
        let socket = bind_ephemeral_for(authority).await?;
        socket
            .send_to(query, authority)
            .await
            .map_err(transport_error)?;

        let mut response_bytes = vec![0; self.max_udp_payload_size];
        let (response_len, source) = time::timeout(
            remaining_until(deadline)?,
            socket.recv_from(&mut response_bytes),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(transport_error)?;
        response_bytes.truncate(response_len);

        validate_upstream_response_source(source, authority)?;
        if truncated_authority_response_matches_question(question, &response_bytes, authority_id)? {
            if self.transport_allowed(RecursiveTransport::Tcp) {
                return self
                    .query_authority_tcp_fallback(
                        authority,
                        question,
                        query,
                        authority_id,
                        deadline,
                    )
                    .await;
            }
            return Err(UpstreamError::MalformedResponse);
        }

        let response = validate_authority_response(question, &response_bytes, authority_id)?;
        if response.header.tc() {
            if self.transport_allowed(RecursiveTransport::Tcp) {
                return self
                    .query_authority_tcp_fallback(
                        authority,
                        question,
                        query,
                        authority_id,
                        deadline,
                    )
                    .await;
            }
            return Err(UpstreamError::MalformedResponse);
        }
        RecursiveAuthorityResponse::new(response_bytes, response)
    }

    async fn query_authority_tcp_fallback(
        &self,
        authority: SocketAddr,
        question: &QuestionKey,
        query: &[u8],
        authority_id: u16,
        deadline: Instant,
    ) -> Result<RecursiveAuthorityResponse, UpstreamError> {
        self.metrics
            .increment(ResolverMetric::RecursiveTcpFallbackAttempt);
        let result = query_authority_tcp(authority, question, query, authority_id, deadline).await;
        match &result {
            Ok(_) => self
                .metrics
                .increment(ResolverMetric::RecursiveTcpFallbackSuccess),
            Err(UpstreamError::Timeout) => self
                .metrics
                .increment(ResolverMetric::RecursiveTcpFallbackTimeout),
            Err(_) => self
                .metrics
                .increment(ResolverMetric::RecursiveTcpFallbackFailure),
        }
        result
    }

    fn transport_allowed(&self, transport: RecursiveTransport) -> bool {
        self.allowed_transports.contains(&transport)
    }
}

impl RecursiveAuthorityTransport for RecursiveAuthorityTransportClient {
    fn query<'a>(
        &'a self,
        authority: SocketAddr,
        question: QuestionKey,
        dnssec_ok: bool,
        timeout: Duration,
    ) -> crate::resolver::BoxFuture<'a, Result<RecursiveAuthorityResponse, UpstreamError>> {
        Box::pin(async move {
            self.query_authority(authority, question, dnssec_ok, timeout)
                .await
        })
    }
}

impl UpstreamHealth {
    fn is_degraded(&self, now: Instant) -> bool {
        self.degraded
            && self
                .retry_after
                .map(|retry_after| retry_after > now)
                .unwrap_or(true)
    }
}

async fn resolve_tcp_fallback(
    upstream: &UpstreamConfig,
    request: &UpstreamRequest,
    upstream_query: &[u8],
    upstream_id: u16,
    client_id: u16,
    attempt_deadline: Instant,
) -> Result<UpstreamResponse, UpstreamError> {
    let frame = encode_tcp_frame(upstream_query, MAX_TCP_MESSAGE_SIZE)
        .map_err(|_| UpstreamError::MalformedResponse)?;
    let mut stream = time::timeout(
        remaining_until(attempt_deadline)?,
        TcpStream::connect(upstream.endpoint),
    )
    .await
    .map_err(|_| UpstreamError::Timeout)?
    .map_err(transport_error)?;

    time::timeout(remaining_until(attempt_deadline)?, stream.write_all(&frame))
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(transport_error)?;

    let mut length_prefix = [0u8; 2];
    time::timeout(
        remaining_until(attempt_deadline)?,
        stream.read_exact(&mut length_prefix),
    )
    .await
    .map_err(|_| UpstreamError::Timeout)?
    .map_err(transport_error)?;
    let message_len = u16::from_be_bytes(length_prefix) as usize;
    if message_len > MAX_TCP_MESSAGE_SIZE {
        return Err(UpstreamError::MalformedResponse);
    }

    let mut response_bytes = vec![0; message_len];
    time::timeout(
        remaining_until(attempt_deadline)?,
        stream.read_exact(&mut response_bytes),
    )
    .await
    .map_err(|_| UpstreamError::Timeout)?
    .map_err(transport_error)?;

    let mut response = validate_upstream_response(request, &response_bytes, upstream_id)?;
    rewrite_response_id(&mut response_bytes, client_id)
        .map_err(|_| UpstreamError::MalformedResponse)?;
    response.header.id = client_id;
    response.original_bytes = Bytes::copy_from_slice(&response_bytes);
    Ok(UpstreamResponse::forwarded_message(
        response_bytes,
        response,
        SystemTime::now(),
        request.backend_generation,
        upstream.name.clone(),
    ))
}

async fn query_authority_tcp(
    authority: SocketAddr,
    question: &QuestionKey,
    query: &[u8],
    authority_id: u16,
    attempt_deadline: Instant,
) -> Result<RecursiveAuthorityResponse, UpstreamError> {
    let frame = encode_tcp_frame(query, MAX_TCP_MESSAGE_SIZE)
        .map_err(|_| UpstreamError::MalformedResponse)?;
    let mut stream = time::timeout(
        remaining_until(attempt_deadline)?,
        TcpStream::connect(authority),
    )
    .await
    .map_err(|_| UpstreamError::Timeout)?
    .map_err(transport_error)?;

    time::timeout(remaining_until(attempt_deadline)?, stream.write_all(&frame))
        .await
        .map_err(|_| UpstreamError::Timeout)?
        .map_err(transport_error)?;

    let mut length_prefix = [0u8; 2];
    time::timeout(
        remaining_until(attempt_deadline)?,
        stream.read_exact(&mut length_prefix),
    )
    .await
    .map_err(|_| UpstreamError::Timeout)?
    .map_err(transport_error)?;
    let message_len = u16::from_be_bytes(length_prefix) as usize;
    if message_len > MAX_TCP_MESSAGE_SIZE {
        return Err(UpstreamError::MalformedResponse);
    }

    let mut response_bytes = vec![0; message_len];
    time::timeout(
        remaining_until(attempt_deadline)?,
        stream.read_exact(&mut response_bytes),
    )
    .await
    .map_err(|_| UpstreamError::Timeout)?
    .map_err(transport_error)?;

    let response = validate_authority_response(question, &response_bytes, authority_id)?;
    if response.header.tc() {
        return Err(UpstreamError::MalformedResponse);
    }
    RecursiveAuthorityResponse::new(response_bytes, response)
}

fn remaining_until(deadline: Instant) -> Result<Duration, UpstreamError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(UpstreamError::Timeout)
}

fn truncated_response_matches_request(
    request: &UpstreamRequest,
    response_bytes: &[u8],
    upstream_id: u16,
) -> Result<bool, UpstreamError> {
    let header = response_header_prefix(response_bytes)?;
    if header.id != upstream_id {
        return Err(UpstreamError::MalformedResponse);
    }
    if !header.qr {
        return Err(UpstreamError::MalformedResponse);
    }
    if !header.tc {
        return Ok(false);
    }
    if header.qd_count != 1 {
        return Err(UpstreamError::QuestionMismatch);
    }
    validate_response_question_prefix(request, response_bytes)?;
    Ok(true)
}

fn truncated_authority_response_matches_question(
    question: &QuestionKey,
    response_bytes: &[u8],
    authority_id: u16,
) -> Result<bool, UpstreamError> {
    let header = response_header_prefix(response_bytes)?;
    if header.id != authority_id {
        return Err(UpstreamError::MalformedResponse);
    }
    if !header.qr {
        return Err(UpstreamError::MalformedResponse);
    }
    if !header.tc {
        return Ok(false);
    }
    if header.qd_count != 1 {
        return Err(UpstreamError::QuestionMismatch);
    }
    validate_authority_response_question_prefix(question, response_bytes)?;
    Ok(true)
}

struct ResponseHeaderPrefix {
    id: u16,
    qr: bool,
    tc: bool,
    qd_count: u16,
}

fn response_header_prefix(response_bytes: &[u8]) -> Result<ResponseHeaderPrefix, UpstreamError> {
    if response_bytes.len() < 12 {
        return Err(UpstreamError::MalformedResponse);
    }
    let id = u16::from_be_bytes([response_bytes[0], response_bytes[1]]);
    let flags = u16::from_be_bytes([response_bytes[2], response_bytes[3]]);
    let qd_count = u16::from_be_bytes([response_bytes[4], response_bytes[5]]);
    Ok(ResponseHeaderPrefix {
        id,
        qr: (flags & 0x8000) != 0,
        tc: (flags & 0x0200) != 0,
        qd_count,
    })
}

fn validate_response_question_prefix(
    request: &UpstreamRequest,
    response_bytes: &[u8],
) -> Result<(), UpstreamError> {
    let question = first_question(response_bytes).map_err(|_| UpstreamError::MalformedResponse)?;
    let response_question = QuestionKey::new(&question.qname, question.qtype, question.qclass);
    if response_question != request.query.question {
        return Err(UpstreamError::QuestionMismatch);
    }
    Ok(())
}

fn validate_authority_response_question_prefix(
    question: &QuestionKey,
    response_bytes: &[u8],
) -> Result<(), UpstreamError> {
    let response_question =
        first_question(response_bytes).map_err(|_| UpstreamError::MalformedResponse)?;
    let response_question = QuestionKey::new(
        &response_question.qname,
        response_question.qtype,
        response_question.qclass,
    );
    if response_question != *question {
        return Err(UpstreamError::QuestionMismatch);
    }
    Ok(())
}

impl ResolutionBackend for ForwardingResolutionBackend {
    fn resolve<'a>(
        &'a self,
        request: UpstreamRequest,
    ) -> crate::resolver::BoxFuture<'a, Result<UpstreamResponse, UpstreamError>> {
        Box::pin(async move { self.resolve_with_failover(request).await })
    }
}

fn ordered_enabled_udp_upstreams(mut upstreams: Vec<UpstreamConfig>) -> Vec<UpstreamConfig> {
    upstreams.retain(|upstream| upstream.enabled && upstream.protocol == UpstreamProtocol::Udp);
    upstreams.sort_by_key(|upstream| upstream.priority);
    upstreams
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
) -> Result<Message, UpstreamError> {
    let response = Message::parse(response_bytes).map_err(|_| UpstreamError::MalformedResponse)?;
    if response.header.id != upstream_id {
        return Err(UpstreamError::MalformedResponse);
    }
    if !response.header.qr() {
        return Err(UpstreamError::MalformedResponse);
    }
    if response.questions.len() != 1
        || QuestionKey::from_message(&response).ok_or(UpstreamError::QuestionMismatch)?
            != request.query.question
    {
        return Err(UpstreamError::QuestionMismatch);
    }
    Ok(response)
}

fn validate_authority_response(
    question: &QuestionKey,
    response_bytes: &[u8],
    authority_id: u16,
) -> Result<Message, UpstreamError> {
    let response = Message::parse(response_bytes).map_err(|_| UpstreamError::MalformedResponse)?;
    if response.header.id != authority_id {
        return Err(UpstreamError::MalformedResponse);
    }
    if !response.header.qr() {
        return Err(UpstreamError::MalformedResponse);
    }
    if response.questions.len() != 1
        || QuestionKey::from_message(&response).ok_or(UpstreamError::QuestionMismatch)? != *question
    {
        return Err(UpstreamError::QuestionMismatch);
    }
    Ok(response)
}

fn build_authority_query(
    authority_id: u16,
    question: &QuestionKey,
    max_udp_payload_size: usize,
    dnssec_ok: bool,
) -> Result<Vec<u8>, UpstreamError> {
    if max_udp_payload_size > u16::MAX as usize {
        return Err(UpstreamError::MalformedResponse);
    }
    let mut bytes = Vec::new();
    write_dns_u16(&mut bytes, authority_id);
    write_dns_u16(&mut bytes, 0);
    write_dns_u16(&mut bytes, 1);
    write_dns_u16(&mut bytes, 0);
    write_dns_u16(&mut bytes, 0);
    write_dns_u16(&mut bytes, 1);
    write_dns_name(&mut bytes, &question.qname)?;
    write_dns_u16(&mut bytes, question.qtype);
    write_dns_u16(&mut bytes, question.qclass);
    bytes.push(0);
    write_dns_u16(&mut bytes, 41);
    write_dns_u16(&mut bytes, max_udp_payload_size as u16);
    let edns_flags = if dnssec_ok { 0x8000u32 } else { 0 };
    write_dns_u32(&mut bytes, edns_flags);
    write_dns_u16(&mut bytes, 0);
    Ok(bytes)
}

fn write_dns_name(bytes: &mut Vec<u8>, name: &str) -> Result<(), UpstreamError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        bytes.push(0);
        return Ok(());
    }
    for label in name.split('.') {
        if label.len() > 63 {
            return Err(UpstreamError::MalformedResponse);
        }
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    Ok(())
}

fn write_dns_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn write_dns_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn transport_error(error: io::Error) -> UpstreamError {
    UpstreamError::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::net::TcpListener;

    use crate::config::UpstreamConfig;
    use crate::resolver::DecodedQuery;

    static PORT_PAIR_BIND: Mutex<()> = Mutex::new(());

    struct FixedTransactionId(u16);

    impl TransactionIdGenerator for FixedTransactionId {
        fn next_id(&self) -> u16 {
            self.0
        }
    }

    struct SequenceTransactionIds(Mutex<VecDeque<u16>>);

    impl SequenceTransactionIds {
        fn new(ids: impl IntoIterator<Item = u16>) -> Self {
            Self(Mutex::new(ids.into_iter().collect()))
        }
    }

    impl TransactionIdGenerator for SequenceTransactionIds {
        fn next_id(&self) -> u16 {
            self.0.lock().unwrap().pop_front().unwrap()
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

    fn nxdomain_response(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_response(id, name);
        bytes[3] = (bytes[3] & 0xf0) | 3;
        bytes
    }

    fn truncated_response(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_response(id, name);
        bytes[2] |= 0x02;
        bytes
    }

    fn incomplete_truncated_response(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = truncated_response(id, name);
        bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
        bytes
    }

    fn upstream_config(endpoint: SocketAddr) -> UpstreamConfig {
        upstream_config_with("test", endpoint, 10, Duration::from_secs(1))
    }

    fn upstream_config_with(
        name: &str,
        endpoint: SocketAddr,
        priority: u16,
        timeout: Duration,
    ) -> UpstreamConfig {
        UpstreamConfig {
            name: name.to_string(),
            endpoint,
            protocol: UpstreamProtocol::Udp,
            enabled: true,
            priority,
            timeout,
        }
    }

    fn upstream_request(id: u16, name: &str) -> UpstreamRequest {
        let message = Message::parse_standard_query(&a_query(id, name)).unwrap();
        let query = DecodedQuery::new(message).unwrap();
        UpstreamRequest {
            query,
            backend_generation: 0,
        }
    }

    fn authority_question(name: &str) -> QuestionKey {
        QuestionKey::new(name, 1, 1)
    }

    fn recursive_transport_with(
        transports: Vec<RecursiveTransport>,
        id_generator: Arc<dyn TransactionIdGenerator>,
    ) -> RecursiveAuthorityTransportClient {
        RecursiveAuthorityTransportClient::with_id_generator(transports, 1232, id_generator)
    }

    #[derive(Default)]
    struct RecordingMetrics {
        increments: Mutex<Vec<ResolverMetric>>,
    }

    impl MetricsSink for RecordingMetrics {
        fn increment(&self, metric: ResolverMetric) {
            self.increments.lock().unwrap().push(metric);
        }

        fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
    }

    impl RecordingMetrics {
        fn count(&self, metric: ResolverMetric) -> usize {
            self.increments
                .lock()
                .unwrap()
                .iter()
                .filter(|increment| **increment == metric)
                .count()
        }
    }

    #[test]
    fn validate_upstream_response_accepts_normalized_question_name() {
        let request = upstream_request(0x1234, "Example.COM");
        let response = a_response(0x5555, "example.com");

        let parsed = validate_upstream_response(&request, &response, 0x5555).unwrap();

        assert_eq!(
            QuestionKey::from_message(&parsed),
            Some(QuestionKey::new("example.com", 1, 1))
        );
    }

    #[test]
    fn truncated_response_prefix_accepts_normalized_question_name() {
        let request = upstream_request(0x1234, "Example.COM");
        let response = truncated_response(0x5555, "example.com");

        assert!(truncated_response_matches_request(&request, &response, 0x5555).unwrap());
    }

    async fn read_tcp_query(stream: &mut TcpStream) -> Vec<u8> {
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = u16::from_be_bytes(length_prefix) as usize;
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();
        query
    }

    async fn write_tcp_response(stream: &mut TcpStream, response: &[u8]) {
        let frame = encode_tcp_frame(response, MAX_TCP_MESSAGE_SIZE).unwrap();
        stream.write_all(&frame).await.unwrap();
    }

    fn bind_udp_tcp_pair() -> (UdpSocket, TcpListener, SocketAddr) {
        let _guard = PORT_PAIR_BIND.lock().unwrap();
        for _ in 0..100 {
            let udp_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let addr = udp_socket.local_addr().unwrap();
            let Ok(tcp_listener) = std::net::TcpListener::bind(addr) else {
                continue;
            };
            udp_socket.set_nonblocking(true).unwrap();
            tcp_listener.set_nonblocking(true).unwrap();
            return (
                UdpSocket::from_std(udp_socket).unwrap(),
                TcpListener::from_std(tcp_listener).unwrap(),
                addr,
            );
        }
        panic!("failed to bind paired UDP/TCP test sockets");
    }

    #[test]
    fn mixed_transaction_ids_are_not_sequential() {
        let generator = MixedTransactionIdGenerator::new(0x1234_5678_9abc_def0);
        let first = generator.next_id();
        let second = generator.next_id();
        let third = generator.next_id();

        assert_ne!(second, first.wrapping_add(1));
        assert_ne!(third, second.wrapping_add(1));
    }

    #[tokio::test]
    async fn recursive_authority_udp_uses_fresh_id_and_edns_bound() {
        let authority_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let authority_addr = authority_socket.local_addr().unwrap();
        let seen_query = Arc::new(Mutex::new(Vec::new()));
        let seen_query_task = Arc::clone(&seen_query);
        let authority_task = tokio::spawn(async move {
            let mut request = [0u8; 1500];
            let (request_len, source) = authority_socket.recv_from(&mut request).await.unwrap();
            seen_query_task
                .lock()
                .unwrap()
                .extend_from_slice(&request[..request_len]);
            authority_socket
                .send_to(&a_response(0xbeef, "example.com"), source)
                .await
                .unwrap();
        });
        let transport = recursive_transport_with(
            vec![RecursiveTransport::Udp],
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let response = transport
            .query(
                authority_addr,
                authority_question("example.com"),
                true,
                Duration::from_secs(1),
            )
            .await
            .unwrap();

        authority_task.await.unwrap();
        let query = Message::parse(&seen_query.lock().unwrap()).unwrap();
        assert_eq!(query.header.id, 0xbeef);
        assert!(!query.header.rd());
        assert_eq!(
            query.edns.as_ref().map(|edns| edns.udp_payload_size),
            Some(1232)
        );
        assert_eq!(query.edns.as_ref().map(|edns| edns.dnssec_ok), Some(true));
        assert_eq!(response.message.header.id, 0xbeef);
    }

    #[tokio::test]
    async fn recursive_authority_udp_rejects_response_from_wrong_source() {
        let authority_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let authority_addr = authority_socket.local_addr().unwrap();
        let rogue_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let authority_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = authority_socket.recv_from(&mut request).await.unwrap();
            rogue_socket
                .send_to(&a_response(0xbeef, "example.com"), source)
                .await
                .unwrap();
        });
        let transport = recursive_transport_with(
            vec![RecursiveTransport::Udp],
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let error = transport
            .query(
                authority_addr,
                authority_question("example.com"),
                false,
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();

        authority_task.await.unwrap();
        assert!(matches!(error, UpstreamError::Transport(_)));
    }

    #[tokio::test]
    async fn recursive_authority_udp_rejects_question_mismatch() {
        let authority_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let authority_addr = authority_socket.local_addr().unwrap();
        let authority_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = authority_socket.recv_from(&mut request).await.unwrap();
            authority_socket
                .send_to(&a_response(0xbeef, "other.example"), source)
                .await
                .unwrap();
        });
        let transport = recursive_transport_with(
            vec![RecursiveTransport::Udp],
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let error = transport
            .query(
                authority_addr,
                authority_question("example.com"),
                false,
                Duration::from_secs(1),
            )
            .await
            .unwrap_err();

        authority_task.await.unwrap();
        assert_eq!(error, UpstreamError::QuestionMismatch);
    }

    #[tokio::test]
    async fn recursive_authority_udp_truncation_falls_back_to_tcp() {
        let (udp_socket, tcp_listener, authority_addr) = bind_udp_tcp_pair();
        let authority_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = udp_socket.recv_from(&mut request).await.unwrap();
            udp_socket
                .send_to(&truncated_response(0xbeef, "example.com"), source)
                .await
                .unwrap();
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let tcp_query = read_tcp_query(&mut stream).await;
            assert_eq!(&tcp_query[0..2], &[0xbe, 0xef]);
            write_tcp_response(&mut stream, &a_response(0xbeef, "example.com")).await;
        });
        let transport = recursive_transport_with(
            vec![RecursiveTransport::Udp, RecursiveTransport::Tcp],
            Arc::new(FixedTransactionId(0xbeef)),
        );
        let metrics = Arc::new(RecordingMetrics::default());
        let transport = transport.with_metrics(metrics.clone());

        let response = transport
            .query(
                authority_addr,
                authority_question("example.com"),
                false,
                Duration::from_secs(1),
            )
            .await
            .unwrap();

        authority_task.await.unwrap();
        assert_eq!(response.message.header.id, 0xbeef);
        assert_eq!(
            metrics.count(ResolverMetric::RecursiveTcpFallbackAttempt),
            1
        );
        assert_eq!(
            metrics.count(ResolverMetric::RecursiveTcpFallbackSuccess),
            1
        );
        assert_eq!(
            metrics.count(ResolverMetric::RecursiveTcpFallbackFailure),
            0
        );
        assert_eq!(
            metrics.count(ResolverMetric::RecursiveTcpFallbackTimeout),
            0
        );
    }

    #[tokio::test]
    async fn recursive_authority_tcp_only_skips_udp() {
        let (udp_socket, tcp_listener, authority_addr) = bind_udp_tcp_pair();
        let authority_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let tcp_query = read_tcp_query(&mut stream).await;
            assert_eq!(&tcp_query[0..2], &[0xbe, 0xef]);
            write_tcp_response(&mut stream, &a_response(0xbeef, "example.com")).await;
            assert!(time::timeout(Duration::from_millis(50), async {
                let mut request = [0u8; 512];
                udp_socket.recv_from(&mut request).await.unwrap();
            })
            .await
            .is_err());
        });
        let transport = recursive_transport_with(
            vec![RecursiveTransport::Tcp],
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let response = transport
            .query(
                authority_addr,
                authority_question("example.com"),
                false,
                Duration::from_secs(1),
            )
            .await
            .unwrap();

        authority_task.await.unwrap();
        assert_eq!(response.message.header.id, 0xbeef);
    }

    #[tokio::test]
    async fn recursive_authority_udp_timeout_uses_attempt_deadline() {
        let authority_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let authority_addr = authority_socket.local_addr().unwrap();
        let transport = recursive_transport_with(
            vec![RecursiveTransport::Udp],
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let error = transport
            .query(
                authority_addr,
                authority_question("example.com"),
                false,
                Duration::from_millis(20),
            )
            .await
            .unwrap_err();

        assert_eq!(error, UpstreamError::Timeout);
    }

    #[test]
    fn runtime_config_constructor_filters_and_orders_udp_upstreams() {
        let primary: SocketAddr = "192.0.2.10:53".parse().unwrap();
        let secondary: SocketAddr = "192.0.2.11:53".parse().unwrap();
        let disabled: SocketAddr = "192.0.2.12:53".parse().unwrap();
        let tcp_only: SocketAddr = "192.0.2.13:53".parse().unwrap();
        let config = RuntimeConfig::new(
            vec!["127.0.0.1:5300".parse().unwrap()],
            vec![
                upstream_config_with("secondary", secondary, 20, Duration::from_millis(500)),
                UpstreamConfig {
                    enabled: false,
                    ..upstream_config_with("disabled", disabled, 5, Duration::from_millis(500))
                },
                UpstreamConfig {
                    protocol: UpstreamProtocol::Tcp,
                    ..upstream_config_with("tcp", tcp_only, 1, Duration::from_millis(500))
                },
                upstream_config_with("primary", primary, 10, Duration::from_millis(500)),
            ],
            Duration::from_secs(1),
            1232,
        )
        .unwrap();

        let resolver = ForwardingResolutionBackend::from_runtime_config(&config).unwrap();
        let health = resolver.health_snapshots();

        assert_eq!(
            health
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["primary", "secondary"]
        );
        assert_eq!(health[0].endpoint, primary);
        assert_eq!(health[1].endpoint, secondary);
    }

    #[test]
    fn runtime_config_constructor_rejects_no_enabled_udp_upstreams() {
        let config = RuntimeConfig::new(
            vec!["127.0.0.1:5300".parse().unwrap()],
            vec![UpstreamConfig {
                protocol: UpstreamProtocol::Tcp,
                ..upstream_config_with(
                    "tcp-only",
                    "192.0.2.53:53".parse().unwrap(),
                    10,
                    Duration::from_millis(500),
                )
            }],
            Duration::from_secs(1),
            1232,
        )
        .unwrap();

        let error = match ForwardingResolutionBackend::from_runtime_config(&config) {
            Ok(_) => panic!("expected no enabled UDP upstreams"),
            Err(error) => error,
        };

        assert_eq!(error, UpstreamError::NoBackendsAvailable);
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
        let resolver = ForwardingResolutionBackend::with_id_generator(
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
        let resolver = ForwardingResolutionBackend::with_id_generator(
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
        let resolver = ForwardingResolutionBackend::with_id_generator(
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
        let resolver = ForwardingResolutionBackend::with_id_generator(
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

    #[tokio::test]
    async fn udp_upstream_accepts_matching_nxdomain_response() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = upstream_socket.recv_from(&mut request).await.unwrap();
            upstream_socket
                .send_to(&nxdomain_response(0xbeef, "missing.example"), source)
                .await
                .unwrap();
        });
        let resolver = ForwardingResolutionBackend::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let response = resolver
            .resolve_once(upstream_request(0x1234, "missing.example"))
            .await
            .unwrap();

        upstream_task.await.unwrap();
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
        assert_eq!(response.bytes[3] & 0x0f, 3);
    }

    #[tokio::test]
    async fn udp_upstream_falls_back_to_tcp_on_truncated_response() {
        let (udp_socket, tcp_listener, upstream_addr) = bind_udp_tcp_pair();
        let seen_tcp_query = Arc::new(Mutex::new(Vec::new()));

        let udp_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = udp_socket.recv_from(&mut request).await.unwrap();
            udp_socket
                .send_to(&truncated_response(0xbeef, "example.com"), source)
                .await
                .unwrap();
        });

        let seen_tcp_query_task = seen_tcp_query.clone();
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let query = read_tcp_query(&mut stream).await;
            seen_tcp_query_task
                .lock()
                .unwrap()
                .extend_from_slice(&query);

            let response = encode_tcp_frame(&a_response(0xbeef, "example.com"), 512).unwrap();
            stream.write_all(&response).await.unwrap();
        });

        let resolver = ForwardingResolutionBackend::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let response = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap();

        udp_task.await.unwrap();
        tcp_task.await.unwrap();
        assert_eq!(&seen_tcp_query.lock().unwrap()[0..2], &[0xbe, 0xef]);
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
        assert!(!Message::parse(&response.bytes).unwrap().header.tc());
    }

    #[tokio::test]
    async fn udp_upstream_falls_back_to_tcp_when_truncated_udp_parse_fails() {
        let (udp_socket, tcp_listener, upstream_addr) = bind_udp_tcp_pair();

        let udp_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = udp_socket.recv_from(&mut request).await.unwrap();
            udp_socket
                .send_to(
                    &incomplete_truncated_response(0xbeef, "example.com"),
                    source,
                )
                .await
                .unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let _query = read_tcp_query(&mut stream).await;
            let response = encode_tcp_frame(&a_response(0xbeef, "example.com"), 512).unwrap();
            stream.write_all(&response).await.unwrap();
        });

        let resolver = ForwardingResolutionBackend::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let response = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap();

        udp_task.await.unwrap();
        tcp_task.await.unwrap();
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
        assert_eq!(response.bytes[3] & 0x0f, 0);
    }

    #[tokio::test]
    async fn tcp_fallback_rejects_response_id_mismatch() {
        let (udp_socket, tcp_listener, upstream_addr) = bind_udp_tcp_pair();

        let udp_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = udp_socket.recv_from(&mut request).await.unwrap();
            udp_socket
                .send_to(&truncated_response(0xbeef, "example.com"), source)
                .await
                .unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let _query = read_tcp_query(&mut stream).await;
            let response = encode_tcp_frame(&a_response(0xabcd, "example.com"), 512).unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let resolver = ForwardingResolutionBackend::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        let error = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap_err();

        udp_task.await.unwrap();
        tcp_task.await.unwrap();
        assert_eq!(error, UpstreamError::MalformedResponse);
    }

    #[tokio::test]
    async fn tcp_fallback_timeout_returns_timeout() {
        let (udp_socket, tcp_listener, upstream_addr) = bind_udp_tcp_pair();

        let udp_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = udp_socket.recv_from(&mut request).await.unwrap();
            udp_socket
                .send_to(&truncated_response(0xbeef, "example.com"), source)
                .await
                .unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let _query = read_tcp_query(&mut stream).await;
            time::sleep(Duration::from_millis(80)).await;
        });
        let resolver = ForwardingResolutionBackend::with_upstreams_and_id_generator(
            vec![upstream_config_with(
                "primary",
                upstream_addr,
                10,
                Duration::from_millis(25),
            )],
            Duration::from_millis(25),
            Arc::new(FixedTransactionId(0xbeef)),
        )
        .unwrap();

        let error = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap_err();

        udp_task.await.unwrap();
        tcp_task.await.unwrap();
        assert_eq!(error, UpstreamError::Timeout);
    }

    #[tokio::test]
    async fn udp_upstream_fails_over_in_priority_order() {
        let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_socket.local_addr().unwrap();
        let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_addr = second_socket.local_addr().unwrap();

        let first_seen = Arc::new(Mutex::new(Vec::new()));
        let first_seen_task = first_seen.clone();
        let first_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (request_len, source) = first_socket.recv_from(&mut request).await.unwrap();
            first_seen_task
                .lock()
                .unwrap()
                .extend_from_slice(&request[..request_len]);
            first_socket
                .send_to(&a_response(0x9999, "example.com"), source)
                .await
                .unwrap();
        });

        let second_seen = Arc::new(Mutex::new(Vec::new()));
        let second_seen_task = second_seen.clone();
        let second_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (request_len, source) = second_socket.recv_from(&mut request).await.unwrap();
            second_seen_task
                .lock()
                .unwrap()
                .extend_from_slice(&request[..request_len]);
            second_socket
                .send_to(&a_response(0x2222, "example.com"), source)
                .await
                .unwrap();
        });

        let resolver = ForwardingResolutionBackend::with_upstreams_and_id_generator(
            vec![
                upstream_config_with("secondary", second_addr, 20, Duration::from_secs(1)),
                upstream_config_with("primary", first_addr, 10, Duration::from_secs(1)),
            ],
            Duration::from_secs(2),
            Arc::new(SequenceTransactionIds::new([0x1111, 0x2222])),
        )
        .unwrap();

        let response = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap();

        first_task.await.unwrap();
        second_task.await.unwrap();
        assert_eq!(&first_seen.lock().unwrap()[0..2], &[0x11, 0x11]);
        assert_eq!(&second_seen.lock().unwrap()[0..2], &[0x22, 0x22]);
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
        let health = resolver.health_snapshots();
        assert_eq!(health[0].name, "primary");
        assert_eq!(health[0].consecutive_failures, 1);
        assert!(!health[0].degraded);
        assert_eq!(health[1].name, "secondary");
        assert_eq!(health[1].consecutive_failures, 0);
    }

    #[tokio::test]
    async fn udp_upstream_reuses_query_buffer_for_failover_tcp_fallback() {
        let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_socket.local_addr().unwrap();
        let (second_socket, tcp_listener, second_addr) = bind_udp_tcp_pair();

        let second_udp_query = Arc::new(Mutex::new(Vec::new()));
        let second_tcp_query = Arc::new(Mutex::new(Vec::new()));

        let first_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = first_socket.recv_from(&mut request).await.unwrap();
            first_socket
                .send_to(&a_response(0x9999, "example.com"), source)
                .await
                .unwrap();
        });

        let second_udp_query_task = second_udp_query.clone();
        let second_udp_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (request_len, source) = second_socket.recv_from(&mut request).await.unwrap();
            second_udp_query_task
                .lock()
                .unwrap()
                .extend_from_slice(&request[..request_len]);
            second_socket
                .send_to(&truncated_response(0x2222, "example.com"), source)
                .await
                .unwrap();
        });

        let second_tcp_query_task = second_tcp_query.clone();
        let second_tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let query = read_tcp_query(&mut stream).await;
            second_tcp_query_task
                .lock()
                .unwrap()
                .extend_from_slice(&query);
            let response = encode_tcp_frame(&a_response(0x2222, "example.com"), 512).unwrap();
            stream.write_all(&response).await.unwrap();
        });

        let resolver = ForwardingResolutionBackend::with_upstreams_and_id_generator(
            vec![
                upstream_config_with("primary", first_addr, 10, Duration::from_secs(1)),
                upstream_config_with("secondary", second_addr, 20, Duration::from_secs(1)),
            ],
            Duration::from_secs(2),
            Arc::new(SequenceTransactionIds::new([0x1111, 0x2222])),
        )
        .unwrap();

        let original_query = a_query(0x1234, "example.com");
        let response = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap();

        first_task.await.unwrap();
        second_udp_task.await.unwrap();
        second_tcp_task.await.unwrap();
        let second_udp_query = second_udp_query.lock().unwrap();
        let second_tcp_query = second_tcp_query.lock().unwrap();
        assert_eq!(&second_udp_query[0..2], &[0x22, 0x22]);
        assert_eq!(&second_tcp_query[0..2], &[0x22, 0x22]);
        assert_eq!(&second_udp_query[2..], &original_query[2..]);
        assert_eq!(&second_tcp_query[2..], &original_query[2..]);
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
    }

    #[tokio::test]
    async fn udp_upstream_fails_over_after_question_mismatch() {
        let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_socket.local_addr().unwrap();
        let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_addr = second_socket.local_addr().unwrap();

        let first_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = first_socket.recv_from(&mut request).await.unwrap();
            first_socket
                .send_to(&a_response(0x1111, "other.example"), source)
                .await
                .unwrap();
        });
        let second_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = second_socket.recv_from(&mut request).await.unwrap();
            second_socket
                .send_to(&a_response(0x2222, "example.com"), source)
                .await
                .unwrap();
        });

        let resolver = ForwardingResolutionBackend::with_upstreams_and_id_generator(
            vec![
                upstream_config_with("primary", first_addr, 10, Duration::from_secs(1)),
                upstream_config_with("secondary", second_addr, 20, Duration::from_secs(1)),
            ],
            Duration::from_secs(2),
            Arc::new(SequenceTransactionIds::new([0x1111, 0x2222])),
        )
        .unwrap();

        let response = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap();

        first_task.await.unwrap();
        second_task.await.unwrap();
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
        assert_eq!(response.bytes[3] & 0x0f, 0);
        let health = resolver.health_snapshots();
        assert_eq!(health[0].consecutive_failures, 0);
        assert!(!health[0].degraded);
    }

    #[tokio::test]
    async fn udp_upstream_deadline_bounds_failover_attempts() {
        let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first_socket.local_addr().unwrap();
        let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_addr = second_socket.local_addr().unwrap();
        let first_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let _ = first_socket.recv_from(&mut request).await.unwrap();
        });

        let resolver = ForwardingResolutionBackend::with_upstreams_and_id_generator(
            vec![
                upstream_config_with("primary", first_addr, 10, Duration::from_millis(40)),
                upstream_config_with("secondary", second_addr, 20, Duration::from_millis(40)),
            ],
            Duration::from_millis(40),
            Arc::new(SequenceTransactionIds::new([0x1111, 0x2222])),
        )
        .unwrap();

        let error = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap_err();

        first_task.await.unwrap();
        let mut unexpected = [0u8; 512];
        let second_receive = time::timeout(
            Duration::from_millis(80),
            second_socket.recv_from(&mut unexpected),
        )
        .await;
        assert!(second_receive.is_err());
        assert_eq!(error, UpstreamError::Timeout);
    }

    #[tokio::test]
    async fn udp_upstream_tries_each_enabled_upstream_once_before_timeout() {
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
            let _ = second_socket.recv_from(&mut request).await.unwrap();
        });
        let resolver = ForwardingResolutionBackend::with_upstreams_and_id_generator(
            vec![
                upstream_config_with("primary", first_addr, 10, Duration::from_millis(20)),
                upstream_config_with("secondary", second_addr, 20, Duration::from_millis(20)),
            ],
            Duration::from_secs(1),
            Arc::new(SequenceTransactionIds::new([0x1111, 0x2222, 0x3333])),
        )
        .unwrap();

        let error = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap_err();

        first_task.await.unwrap();
        second_task.await.unwrap();
        assert_eq!(error, UpstreamError::Timeout);
        let health = resolver.health_snapshots();
        assert_eq!(health.len(), 2);
        assert_eq!(health[0].consecutive_failures, 1);
        assert_eq!(health[1].consecutive_failures, 1);
    }

    #[tokio::test]
    async fn udp_upstream_marks_degraded_and_recovers_on_success() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let responses = [
                a_response(0x9999, "example.com"),
                a_response(0x9999, "example.com"),
                a_response(0xbeef, "example.com"),
            ];
            for response in responses {
                let mut request = [0u8; 512];
                let (_, source) = upstream_socket.recv_from(&mut request).await.unwrap();
                upstream_socket.send_to(&response, source).await.unwrap();
            }
        });
        let resolver = ForwardingResolutionBackend::with_id_generator(
            upstream_config(upstream_addr),
            Arc::new(FixedTransactionId(0xbeef)),
        );

        assert_eq!(
            resolver
                .resolve(upstream_request(0x1234, "example.com"))
                .await
                .unwrap_err(),
            UpstreamError::MalformedResponse
        );
        assert_eq!(
            resolver
                .resolve(upstream_request(0x1234, "example.com"))
                .await
                .unwrap_err(),
            UpstreamError::MalformedResponse
        );
        let degraded = resolver.health_snapshots();
        assert_eq!(degraded[0].consecutive_failures, 2);
        assert!(degraded[0].degraded);

        let response = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap();

        upstream_task.await.unwrap();
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
        let recovered = resolver.health_snapshots();
        assert_eq!(recovered[0].consecutive_failures, 0);
        assert!(!recovered[0].degraded);
    }

    #[tokio::test]
    async fn udp_upstream_moves_degraded_primary_after_healthy_secondary() {
        let primary_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary_socket.local_addr().unwrap();
        let secondary_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let secondary_addr = secondary_socket.local_addr().unwrap();
        let secondary_task = tokio::spawn(async move {
            let mut request = [0u8; 512];
            let (_, source) = secondary_socket.recv_from(&mut request).await.unwrap();
            let upstream_id = u16::from_be_bytes([request[0], request[1]]);
            secondary_socket
                .send_to(&a_response(upstream_id, "example.com"), source)
                .await
                .unwrap();
        });
        let resolver = ForwardingResolutionBackend::with_upstreams_and_id_generator(
            vec![
                upstream_config_with("primary", primary_addr, 10, Duration::from_millis(50)),
                upstream_config_with("secondary", secondary_addr, 20, Duration::from_millis(50)),
            ],
            Duration::from_millis(150),
            Arc::new(SequenceTransactionIds::new([0x2222])),
        )
        .unwrap();
        resolver.mark_failure(0, &UpstreamError::Timeout);
        resolver.mark_failure(0, &UpstreamError::Timeout);

        let response = resolver
            .resolve(upstream_request(0x1234, "example.com"))
            .await
            .unwrap();

        secondary_task.await.unwrap();
        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
        let mut unexpected = [0u8; 512];
        let primary_receive = time::timeout(
            Duration::from_millis(80),
            primary_socket.recv_from(&mut unexpected),
        )
        .await;
        assert!(primary_receive.is_err());
        let health = resolver.health_snapshots();
        assert!(health[0].degraded);
        assert!(!health[1].degraded);
    }

    #[test]
    fn udp_upstream_attempt_order_preserves_original_indices() {
        let primary: SocketAddr = "192.0.2.10:53".parse().unwrap();
        let secondary: SocketAddr = "192.0.2.11:53".parse().unwrap();
        let resolver = ForwardingResolutionBackend::with_upstreams_and_id_generator(
            vec![
                upstream_config_with("secondary", secondary, 20, Duration::from_millis(50)),
                upstream_config_with("primary", primary, 10, Duration::from_millis(50)),
            ],
            Duration::from_millis(150),
            Arc::new(SequenceTransactionIds::new([0x1111])),
        )
        .unwrap();
        resolver.mark_failure(0, &UpstreamError::Timeout);
        resolver.mark_failure(0, &UpstreamError::Timeout);

        let now = Instant::now();
        assert_eq!(resolver.attempt_order(now), vec![1, 0]);
        assert_eq!(
            resolver.attempt_order(now + DEGRADED_RETRY_AFTER + Duration::from_secs(1)),
            vec![0, 1]
        );
        resolver.mark_success(0);

        let health = resolver.health_snapshots();
        assert_eq!(health[0].name, "primary");
        assert!(!health[0].degraded);
        assert_eq!(resolver.attempt_order(Instant::now()), vec![0, 1]);
    }
}
