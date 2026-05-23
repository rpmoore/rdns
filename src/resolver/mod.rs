use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::protocol::{
    build_formerr_response, build_refused_response, build_servfail_response, rewrite_response_id,
    Message, QueryValidationError, RecordData, ResponseCode,
};

const MAX_FAILURE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const CNAME_RECORD_TYPE: u16 = 5;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedAt(pub SystemTime);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRequest {
    pub client_ip: IpAddr,
    pub received_at: ReceivedAt,
    pub bytes: Vec<u8>,
}

impl ResolveRequest {
    pub fn new(client_ip: IpAddr, received_at: SystemTime, bytes: Vec<u8>) -> Self {
        Self {
            client_ip,
            received_at: ReceivedAt(received_at),
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuestionKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl QuestionKey {
    pub fn new(qname: impl AsRef<str>, qtype: u16, qclass: u16) -> Self {
        Self {
            qname: normalize_question_name(qname.as_ref()),
            qtype,
            qclass,
        }
    }

    pub fn from_message(message: &Message) -> Option<Self> {
        let question = message.questions.first()?;
        Some(Self::new(&question.qname, question.qtype, question.qclass))
    }
}

fn normalize_question_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueryFeatures {
    pub dnssec_ok: bool,
    pub edns_udp_payload_size: Option<u16>,
}

impl QueryFeatures {
    pub fn from_message(message: &Message) -> Self {
        Self {
            dnssec_ok: message
                .edns
                .as_ref()
                .map(|edns| edns.dnssec_ok)
                .unwrap_or(false),
            edns_udp_payload_size: message.edns.as_ref().map(|edns| edns.udp_payload_size),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub question: QuestionKey,
    pub features: QueryFeatures,
    pub upstream_policy_variant: Option<String>,
    pub effective_udp_payload_size: usize,
}

impl CacheKey {
    pub fn new(
        question: QuestionKey,
        features: QueryFeatures,
        upstream_policy_variant: Option<String>,
        effective_udp_payload_size: usize,
    ) -> Self {
        Self {
            question,
            features,
            upstream_policy_variant,
            effective_udp_payload_size,
        }
    }

    pub fn from_query(
        query: &DecodedQuery,
        upstream_policy_variant: Option<String>,
        configured_max_udp_payload_size: usize,
    ) -> Self {
        Self::new(
            query.question.clone(),
            query.features.clone(),
            upstream_policy_variant,
            query
                .message
                .effective_udp_payload_size(configured_max_udp_payload_size),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheLookupRequest {
    pub key: CacheKey,
    pub received_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedQuery {
    pub message: Message,
    pub question: QuestionKey,
    pub features: QueryFeatures,
}

impl DecodedQuery {
    pub fn new(message: Message) -> Option<Self> {
        let question = QuestionKey::from_message(&message)?;
        let features = QueryFeatures::from_message(&message);
        Some(Self {
            message,
            question,
            features,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Block(PolicyBlock),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBlock {
    pub reason: BlockReason,
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    LocalRule,
    MaliciousDomain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    Hit(CachedResponse),
    Miss,
    Bypass(CacheBypassReason),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedResponse {
    pub response_template: Vec<u8>,
    pub response_code: ResponseCode,
    pub minimum_ttl: Duration,
    pub negative_cache: Option<NegativeCacheMetadata>,
    pub stored_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeCacheMetadata {
    pub authority_name: String,
    pub soa_minimum_ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheBypassReason {
    UnsupportedQueryFeature,
    ResponseSizeDependsOnRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheStore {
    pub key: CacheKey,
    pub response_template: Vec<u8>,
    pub response_code: ResponseCode,
    pub minimum_ttl: Duration,
    pub negative_cache: Option<NegativeCacheMetadata>,
    pub ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTtlPolicy {
    pub max_positive_ttl: Duration,
    pub min_positive_ttl: Option<Duration>,
    pub max_negative_ttl: Duration,
    pub min_negative_ttl: Option<Duration>,
    pub failure_ttl: Option<Duration>,
}

impl CacheTtlPolicy {
    pub fn new(
        max_positive_ttl: Duration,
        min_positive_ttl: Option<Duration>,
        max_negative_ttl: Duration,
        min_negative_ttl: Option<Duration>,
        failure_ttl: Option<Duration>,
    ) -> Self {
        Self {
            max_positive_ttl,
            min_positive_ttl,
            max_negative_ttl,
            min_negative_ttl,
            failure_ttl,
        }
    }

    pub fn ttl_for_response(
        &self,
        response: &Message,
    ) -> Option<(Duration, Option<NegativeCacheMetadata>)> {
        let response_code = response_code(response)?;
        if response_code == ResponseCode::ServFail {
            return self
                .failure_ttl
                .map(|ttl| (ttl.min(MAX_FAILURE_CACHE_TTL), None));
        }
        if !is_cacheable_response_code(response_code) {
            return None;
        }

        if !response.answers.is_empty() {
            let answer_ttl = response.answers.iter().map(|record| record.ttl).min()?;
            if let Some(metadata) = negative_ttl(response) {
                let cname_chain_nodata = response_code == ResponseCode::NoError
                    && question_type(response) != Some(CNAME_RECORD_TYPE)
                    && !has_requested_answer(response);
                if response_code == ResponseCode::NxDomain || cname_chain_nodata {
                    let positive_ttl = apply_ttl_bounds(
                        Duration::from_secs(u64::from(answer_ttl)),
                        self.min_positive_ttl,
                        self.max_positive_ttl,
                    );
                    let negative_ttl = apply_ttl_bounds(
                        metadata.soa_minimum_ttl,
                        self.min_negative_ttl,
                        self.max_negative_ttl,
                    );
                    return Some((positive_ttl.min(negative_ttl), Some(metadata)));
                }
            }
            return Some((
                apply_ttl_bounds(
                    Duration::from_secs(u64::from(answer_ttl)),
                    self.min_positive_ttl,
                    self.max_positive_ttl,
                ),
                None,
            ));
        }

        if response_code == ResponseCode::NxDomain || response_code == ResponseCode::NoError {
            return negative_ttl(response).map(|metadata| {
                (
                    apply_ttl_bounds(
                        metadata.soa_minimum_ttl,
                        self.min_negative_ttl,
                        self.max_negative_ttl,
                    ),
                    Some(metadata),
                )
            });
        }

        None
    }
}

impl Default for CacheTtlPolicy {
    fn default() -> Self {
        Self {
            max_positive_ttl: Duration::from_secs(24 * 60 * 60),
            min_positive_ttl: None,
            max_negative_ttl: Duration::from_secs(60 * 60),
            min_negative_ttl: None,
            failure_ttl: None,
        }
    }
}

fn response_code(message: &Message) -> Option<ResponseCode> {
    match message.header.r_code() {
        0 => Some(ResponseCode::NoError),
        1 => Some(ResponseCode::FormErr),
        2 => Some(ResponseCode::ServFail),
        3 => Some(ResponseCode::NxDomain),
        4 => Some(ResponseCode::NotImp),
        5 => Some(ResponseCode::Refused),
        _ => None,
    }
}

fn is_cacheable_response_code(response_code: ResponseCode) -> bool {
    matches!(
        response_code,
        ResponseCode::NoError | ResponseCode::NxDomain
    )
}

fn negative_ttl(response: &Message) -> Option<NegativeCacheMetadata> {
    response.authorities.iter().find_map(|record| {
        let RecordData::SOA { minimum, .. } = &record.record else {
            return None;
        };
        let ttl = record.ttl.min(*minimum);
        Some(NegativeCacheMetadata {
            authority_name: record.name.clone(),
            soa_minimum_ttl: Duration::from_secs(u64::from(ttl)),
        })
    })
}

fn has_requested_answer(message: &Message) -> bool {
    let Some(qtype) = question_type(message) else {
        return false;
    };
    message.answers.iter().any(|record| {
        if record.rtype != qtype {
            return false;
        }
        !matches!(record.record, RecordData::RRSIG { .. })
    })
}

fn question_type(message: &Message) -> Option<u16> {
    message.questions.first().map(|question| question.qtype)
}

fn apply_ttl_bounds(ttl: Duration, min_ttl: Option<Duration>, max_ttl: Duration) -> Duration {
    let capped = ttl.min(max_ttl);
    match min_ttl {
        Some(min_ttl) => capped.max(min_ttl).min(max_ttl),
        None => capped,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRequest {
    pub query: DecodedQuery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamResponse {
    pub bytes: Vec<u8>,
    pub received_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    Timeout,
    MalformedResponse,
    QuestionMismatch,
    NoUpstreamsAvailable,
    Transport(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveDecisionKind {
    Allowed,
    Blocked(BlockReason),
    CacheHit,
    CacheMiss,
    ProtocolError(ResponseCode),
    UpstreamFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveDecision {
    pub client_ip: IpAddr,
    pub question: Option<QuestionKey>,
    pub kind: ResolveDecisionKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOutcome {
    pub response_bytes: Vec<u8>,
    pub decision: ResolveDecision,
}

pub struct ResolveQuery {
    protocol: Arc<dyn ProtocolCodec>,
    upstream: Arc<dyn UpstreamResolver>,
    responses: Arc<dyn ResponseFactory>,
    clock: Arc<dyn Clock>,
    events: Arc<dyn QueryEventSink>,
    metrics: Arc<dyn MetricsSink>,
}

impl ResolveQuery {
    pub fn new(
        protocol: Arc<dyn ProtocolCodec>,
        upstream: Arc<dyn UpstreamResolver>,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        Self {
            protocol,
            upstream,
            responses,
            clock,
            events,
            metrics,
        }
    }

    pub async fn resolve(&self, request: ResolveRequest) -> ResolveOutcome {
        self.metrics.increment(ResolverMetric::QueryReceived);
        let started_at = self.clock.now();
        let request_id = request_id_from_wire(&request.bytes);

        let decoded = match self.protocol.decode_query(&request.bytes) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.metrics.increment(ResolverMetric::ProtocolError);
                let decision = ResolveDecision {
                    client_ip: request.client_ip,
                    question: None,
                    kind: ResolveDecisionKind::ProtocolError(error.response_code()),
                };
                let response_bytes = self.responses.protocol_error(request_id, &error);
                return self.finish(started_at, decision, response_bytes).await;
            }
        };

        self.metrics.increment(ResolverMetric::QueryAllowed);
        let question = decoded.question.clone();
        match self
            .upstream
            .resolve(UpstreamRequest {
                query: decoded.clone(),
            })
            .await
        {
            Ok(response) => {
                self.metrics.increment(ResolverMetric::UpstreamSuccess);
                let decision = ResolveDecision {
                    client_ip: request.client_ip,
                    question: Some(question),
                    kind: ResolveDecisionKind::Allowed,
                };
                let mut response_bytes = response.bytes;
                if self
                    .protocol
                    .rewrite_response_id(&mut response_bytes, decoded.message.header.id)
                    .is_err()
                {
                    self.metrics.increment(ResolverMetric::UpstreamFailure);
                    let decision = ResolveDecision {
                        client_ip: request.client_ip,
                        question: Some(decoded.question.clone()),
                        kind: ResolveDecisionKind::UpstreamFailure,
                    };
                    let response_bytes = self.responses.servfail(Some(&decoded));
                    return self.finish(started_at, decision, response_bytes).await;
                }
                self.finish(started_at, decision, response_bytes).await
            }
            Err(_) => {
                self.metrics.increment(ResolverMetric::UpstreamFailure);
                let decision = ResolveDecision {
                    client_ip: request.client_ip,
                    question: Some(question),
                    kind: ResolveDecisionKind::UpstreamFailure,
                };
                let response_bytes = self.responses.servfail(Some(&decoded));
                self.finish(started_at, decision, response_bytes).await
            }
        }
    }

    async fn finish(
        &self,
        started_at: SystemTime,
        decision: ResolveDecision,
        response_bytes: Vec<u8>,
    ) -> ResolveOutcome {
        self.events.record(decision.clone()).await;
        if let Ok(duration) = self.clock.now().duration_since(started_at) {
            self.metrics
                .observe_duration(ResolverMetric::QueryDuration, duration);
        }
        ResolveOutcome {
            response_bytes,
            decision,
        }
    }
}

fn request_id_from_wire(bytes: &[u8]) -> Option<u16> {
    let id = bytes.get(0..2)?;
    Some(u16::from_be_bytes([id[0], id[1]]))
}

pub struct StandardProtocolCodec {
    configured_max_udp_payload_size: usize,
}

impl StandardProtocolCodec {
    pub fn new(configured_max_udp_payload_size: usize) -> Self {
        Self {
            configured_max_udp_payload_size,
        }
    }
}

impl ProtocolCodec for StandardProtocolCodec {
    fn decode_query(&self, bytes: &[u8]) -> Result<DecodedQuery, QueryValidationError> {
        let message = Message::parse_standard_query(bytes)?;
        DecodedQuery::new(message).ok_or(QueryValidationError::InvalidQuestionCount { count: 0 })
    }

    fn rewrite_response_id(
        &self,
        response_bytes: &mut [u8],
        request_id: u16,
    ) -> crate::protocol::Result<()> {
        rewrite_response_id(response_bytes, request_id)
    }

    fn serialize_cached_response(
        &self,
        query: &DecodedQuery,
        cached: &CachedResponse,
    ) -> crate::protocol::Result<Vec<u8>> {
        let mut response = cached.response_template.clone();
        self.rewrite_response_id(&mut response, query.message.header.id)?;
        if query
            .message
            .response_exceeds_udp_payload(response.len(), self.configured_max_udp_payload_size)
        {
            return Ok(crate::protocol::build_truncated_response(&query.message));
        }
        Ok(response)
    }
}

pub struct BasicResponseFactory;

impl ResponseFactory for BasicResponseFactory {
    fn protocol_error(&self, request_id: Option<u16>, error: &QueryValidationError) -> Vec<u8> {
        match error.response_code() {
            ResponseCode::FormErr => build_formerr_response(request_id.unwrap_or(0)),
            ResponseCode::ServFail => build_servfail_response(None, request_id),
            ResponseCode::Refused => build_formerr_response(request_id.unwrap_or(0)),
            ResponseCode::NxDomain => build_formerr_response(request_id.unwrap_or(0)),
            ResponseCode::NoError => build_formerr_response(request_id.unwrap_or(0)),
            ResponseCode::NotImp => {
                build_header_only_protocol_error(request_id.unwrap_or(0), ResponseCode::NotImp)
            }
        }
    }

    fn blocked(&self, query: &DecodedQuery, _block: &PolicyBlock) -> Vec<u8> {
        build_refused_response(&query.message)
    }

    fn servfail(&self, query: Option<&DecodedQuery>) -> Vec<u8> {
        build_servfail_response(query.map(|query| &query.message), None)
    }
}

fn build_header_only_protocol_error(request_id: u16, rcode: ResponseCode) -> Vec<u8> {
    let mut response = build_formerr_response(request_id);
    response[3] = (response[3] & 0xf0) | rcode as u8;
    response
}

pub trait ProtocolCodec: Send + Sync {
    fn decode_query(&self, bytes: &[u8]) -> Result<DecodedQuery, QueryValidationError>;

    fn rewrite_response_id(
        &self,
        response_bytes: &mut [u8],
        request_id: u16,
    ) -> crate::protocol::Result<()>;

    fn serialize_cached_response(
        &self,
        query: &DecodedQuery,
        cached: &CachedResponse,
    ) -> crate::protocol::Result<Vec<u8>>;
}

pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, client_ip: IpAddr, question: &QuestionKey) -> PolicyDecision;
}

pub trait DnsCache: Send + Sync {
    fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup>;

    fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()>;
}

pub struct InMemoryDnsCache {
    max_entries: usize,
    state: Mutex<InMemoryDnsCacheState>,
}

#[derive(Default)]
struct InMemoryDnsCacheState {
    entries: HashMap<CacheKey, InMemoryDnsCacheEntry>,
    lru: VecDeque<(CacheKey, u64)>,
    next_sequence: u64,
}

struct InMemoryDnsCacheEntry {
    response: CachedResponse,
    sequence: u64,
}

impl InMemoryDnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            state: Mutex::new(InMemoryDnsCacheState::default()),
        }
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    fn lru_len(&self) -> usize {
        self.state.lock().unwrap().lru.len()
    }

    fn lookup_now(&self, request: &CacheLookupRequest) -> CacheLookup {
        let mut state = self.state.lock().unwrap();
        state.remove_expired(request.received_at);
        state.compact_lru();

        let Some(existing) = state.entries.get(&request.key) else {
            return CacheLookup::Miss;
        };

        let response = existing.response.clone();
        let sequence = state.next_sequence();
        if let Some(existing) = state.entries.get_mut(&request.key) {
            existing.sequence = sequence;
        }
        state.lru.push_back((request.key.clone(), sequence));
        state.compact_lru();
        CacheLookup::Hit(response)
    }

    fn store_now(&self, entry: CacheStore, now: SystemTime) {
        let mut state = self.state.lock().unwrap();
        if self.max_entries == 0 {
            state.entries.clear();
            state.lru.clear();
            return;
        }

        state.remove_expired(now);
        state.compact_lru();
        let expires_at = now.checked_add(entry.ttl).unwrap_or(SystemTime::UNIX_EPOCH);
        if expires_at <= now {
            state.entries.remove(&entry.key);
            state.compact_lru();
            return;
        }

        let sequence = state.next_sequence();
        let cached = CachedResponse {
            response_template: entry.response_template,
            response_code: entry.response_code,
            minimum_ttl: entry.minimum_ttl,
            negative_cache: entry.negative_cache,
            stored_at: now,
            expires_at,
        };
        state.entries.insert(
            entry.key.clone(),
            InMemoryDnsCacheEntry {
                response: cached,
                sequence,
            },
        );
        state.lru.push_back((entry.key, sequence));
        state.evict_to_bound(self.max_entries);
    }
}

impl InMemoryDnsCacheState {
    fn next_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        sequence
    }

    fn remove_expired(&mut self, now: SystemTime) {
        self.entries
            .retain(|_, entry| entry.response.expires_at > now);
    }

    fn compact_lru(&mut self) {
        self.lru.retain(|(key, sequence)| {
            self.entries
                .get(key)
                .map(|entry| entry.sequence == *sequence)
                .unwrap_or(false)
        });
    }

    fn evict_to_bound(&mut self, max_entries: usize) {
        self.compact_lru();
        while self.entries.len() > max_entries {
            let Some((key, sequence)) = self.lru.pop_front() else {
                break;
            };
            let should_remove = self
                .entries
                .get(&key)
                .map(|entry| entry.sequence == sequence)
                .unwrap_or(false);
            if should_remove {
                self.entries.remove(&key);
            }
        }
    }
}

impl DnsCache for InMemoryDnsCache {
    fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> {
        Box::pin(async move { self.lookup_now(request) })
    }

    fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.store_now(entry, SystemTime::now());
        })
    }
}

pub trait UpstreamResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        request: UpstreamRequest,
    ) -> BoxFuture<'a, Result<UpstreamResponse, UpstreamError>>;
}

pub trait ResponseFactory: Send + Sync {
    fn protocol_error(&self, request_id: Option<u16>, error: &QueryValidationError) -> Vec<u8>;

    fn blocked(&self, query: &DecodedQuery, block: &PolicyBlock) -> Vec<u8>;

    fn servfail(&self, query: Option<&DecodedQuery>) -> Vec<u8>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

pub trait QueryEventSink: Send + Sync {
    fn record<'a>(&'a self, decision: ResolveDecision) -> BoxFuture<'a, ()>;
}

pub trait MetricsSink: Send + Sync {
    fn increment(&self, metric: ResolverMetric);

    fn observe_duration(&self, metric: ResolverMetric, duration: Duration);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverMetric {
    QueryReceived,
    QueryAllowed,
    QueryBlocked,
    CacheHit,
    CacheMiss,
    UpstreamSuccess,
    UpstreamFailure,
    QueryDuration,
    ProtocolError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::protocol::{Header, Question, Record};

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

    fn aaaa_query(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        let qtype_offset = bytes.len() - 4;
        bytes[qtype_offset..qtype_offset + 2].copy_from_slice(&28u16.to_be_bytes());
        bytes
    }

    fn chaos_a_query(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        let qclass_offset = bytes.len() - 2;
        bytes[qclass_offset..].copy_from_slice(&3u16.to_be_bytes());
        bytes
    }

    fn a_query_with_edns(id: u16, name: &str, udp_payload_size: u16, dnssec_ok: bool) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        bytes[10..12].copy_from_slice(&1u16.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&41u16.to_be_bytes());
        bytes.extend_from_slice(&udp_payload_size.to_be_bytes());
        bytes.push(0);
        bytes.push(0);
        let flags = if dnssec_ok { 0x8000u16 } else { 0 };
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
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
    struct RecordingMetrics {
        increments: Mutex<Vec<ResolverMetric>>,
        durations: Mutex<Vec<(ResolverMetric, Duration)>>,
    }

    impl MetricsSink for RecordingMetrics {
        fn increment(&self, metric: ResolverMetric) {
            self.increments.lock().unwrap().push(metric);
        }

        fn observe_duration(&self, metric: ResolverMetric, duration: Duration) {
            self.durations.lock().unwrap().push((metric, duration));
        }
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
        ) -> BoxFuture<'a, Result<UpstreamResponse, UpstreamError>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request);
                self.response.clone()
            })
        }
    }

    fn resolve_service(
        upstream: Arc<StaticUpstream>,
        events: Arc<RecordingEvents>,
        metrics: Arc<RecordingMetrics>,
    ) -> ResolveQuery {
        ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            upstream,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            metrics,
        )
    }

    #[test]
    fn question_key_normalizes_case_and_trailing_root() {
        let key = QuestionKey::new("Example.COM.", 1, 1);

        assert_eq!(key.qname, "example.com");
        assert_eq!(key.qtype, 1);
        assert_eq!(key.qclass, 1);
    }

    #[test]
    fn root_question_stays_root_name() {
        let key = QuestionKey::new(".", 1, 1);

        assert_eq!(key.qname, "");
    }

    #[test]
    fn cache_store_keeps_explicit_key_and_ttl() {
        let question = QuestionKey::new("example.com", 28, 1);
        let entry = CacheStore {
            key: CacheKey::new(
                question,
                QueryFeatures {
                    dnssec_ok: false,
                    edns_udp_payload_size: None,
                },
                Some("primary".to_string()),
                512,
            ),
            response_template: vec![1, 2, 3],
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(30),
            negative_cache: None,
            ttl: Duration::from_secs(60),
        };

        assert_eq!(entry.key.question.qname, "example.com");
        assert_eq!(
            entry.key.upstream_policy_variant.as_deref(),
            Some("primary")
        );
        assert_eq!(entry.key.effective_udp_payload_size, 512);
        assert_eq!(entry.response_template, vec![1, 2, 3]);
        assert_eq!(entry.response_code, ResponseCode::NoError);
        assert_eq!(entry.minimum_ttl, Duration::from_secs(30));
        assert_eq!(entry.negative_cache, None);
        assert_eq!(entry.ttl, Duration::from_secs(60));
    }

    fn cache_key(name: &str) -> CacheKey {
        CacheKey::new(
            QuestionKey::new(name, 1, 1),
            QueryFeatures {
                dnssec_ok: false,
                edns_udp_payload_size: None,
            },
            Some("primary".to_string()),
            512,
        )
    }

    fn cache_store(key: CacheKey, ttl: Duration) -> CacheStore {
        CacheStore {
            key,
            response_template: vec![0x12, 0x34, 0x81, 0x80],
            response_code: ResponseCode::NoError,
            minimum_ttl: ttl,
            negative_cache: None,
            ttl,
        }
    }

    fn response_message(
        response_code: ResponseCode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
    ) -> Message {
        Message {
            header: Header {
                id: 0x1234,
                flags: 0x8000 | response_code as u16,
                qd_count: 1,
                an_count: answers.len() as u16,
                ns_count: authorities.len() as u16,
                ar_count: 0,
            },
            original_bytes: Vec::new(),
            questions: vec![Question {
                qname: "example.com".to_string(),
                qtype: 1,
                qclass: 1,
            }],
            answers,
            authorities,
            additionals: Vec::new(),
            edns: None,
        }
    }

    fn a_record(name: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: 1,
            rclass: 1,
            ttl,
            record: RecordData::A("192.0.2.10".parse().unwrap()),
        }
    }

    fn cname_record(name: &str, ttl: u32, target: &str) -> Record {
        Record {
            name: name.to_string(),
            rtype: 5,
            rclass: 1,
            ttl,
            record: RecordData::CNAME(target.to_string()),
        }
    }

    fn rrsig_record(name: &str, ttl: u32, type_covered: u16) -> Record {
        Record {
            name: name.to_string(),
            rtype: 46,
            rclass: 1,
            ttl,
            record: RecordData::RRSIG {
                type_covered,
                algorithm: 8,
                labels: 2,
                original_ttl: ttl,
                signature_expiration: 0,
                signature_inception: 0,
                key_tag: 0,
                signer_name: "example.com".to_string(),
                signature: Vec::new(),
            },
        }
    }

    fn soa_record(name: &str, ttl: u32, minimum: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: 6,
            rclass: 1,
            ttl,
            record: RecordData::SOA {
                ttl,
                rname: "hostmaster.example.com".to_string(),
                mname: "ns.example.com".to_string(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum,
            },
        }
    }

    #[test]
    fn ttl_policy_uses_minimum_answer_ttl_for_positive_response() {
        let policy = CacheTtlPolicy::default();
        let response = response_message(
            ResponseCode::NoError,
            vec![a_record("example.com", 120), a_record("example.com", 30)],
            Vec::new(),
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(30));
        assert_eq!(metadata, None);
    }

    #[test]
    fn ttl_policy_applies_positive_minimum_and_maximum_bounds() {
        let policy = CacheTtlPolicy::new(
            Duration::from_secs(60),
            Some(Duration::from_secs(20)),
            Duration::from_secs(60),
            None,
            None,
        );

        let high = response_message(
            ResponseCode::NoError,
            vec![a_record("example.com", 3600)],
            Vec::new(),
        );
        let low = response_message(
            ResponseCode::NoError,
            vec![a_record("example.com", 5)],
            Vec::new(),
        );

        assert_eq!(
            policy.ttl_for_response(&high).unwrap().0,
            Duration::from_secs(60)
        );
        assert_eq!(
            policy.ttl_for_response(&low).unwrap().0,
            Duration::from_secs(20)
        );
    }

    #[test]
    fn ttl_policy_uses_soa_ttl_for_negative_response() {
        let policy = CacheTtlPolicy::default();
        let response = response_message(
            ResponseCode::NxDomain,
            Vec::new(),
            vec![soa_record("example.com", 90, 300)],
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(90));
        assert_eq!(
            metadata,
            Some(NegativeCacheMetadata {
                authority_name: "example.com".to_string(),
                soa_minimum_ttl: Duration::from_secs(90),
            })
        );
    }

    #[test]
    fn ttl_policy_preserves_negative_metadata_for_nxdomain_with_cname_answer() {
        let policy = CacheTtlPolicy::default();
        let response = response_message(
            ResponseCode::NxDomain,
            vec![cname_record("www.example.com", 300, "missing.example.com")],
            vec![soa_record("example.com", 60, 120)],
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(60));
        assert_eq!(
            metadata,
            Some(NegativeCacheMetadata {
                authority_name: "example.com".to_string(),
                soa_minimum_ttl: Duration::from_secs(60),
            })
        );
    }

    #[test]
    fn ttl_policy_preserves_negative_metadata_for_nodata_with_cname_answer() {
        let policy = CacheTtlPolicy::default();
        let response = response_message(
            ResponseCode::NoError,
            vec![cname_record("www.example.com", 300, "target.example.com")],
            vec![soa_record("example.com", 30, 120)],
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(30));
        assert_eq!(
            metadata,
            Some(NegativeCacheMetadata {
                authority_name: "example.com".to_string(),
                soa_minimum_ttl: Duration::from_secs(30),
            })
        );
    }

    #[test]
    fn ttl_policy_preserves_negative_metadata_for_dnssec_signed_cname_nodata() {
        let policy = CacheTtlPolicy::default();
        let response = response_message(
            ResponseCode::NoError,
            vec![
                cname_record("www.example.com", 300, "target.example.com"),
                rrsig_record("www.example.com", 300, CNAME_RECORD_TYPE),
            ],
            vec![soa_record("example.com", 30, 120)],
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(30));
        assert_eq!(
            metadata,
            Some(NegativeCacheMetadata {
                authority_name: "example.com".to_string(),
                soa_minimum_ttl: Duration::from_secs(30),
            })
        );
    }

    #[test]
    fn ttl_policy_keeps_direct_cname_answer_positive() {
        let policy = CacheTtlPolicy::default();
        let mut response = response_message(
            ResponseCode::NoError,
            vec![cname_record("www.example.com", 300, "target.example.com")],
            vec![soa_record("example.com", 30, 120)],
        );
        response.questions[0].qtype = CNAME_RECORD_TYPE;

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(300));
        assert_eq!(metadata, None);
    }

    #[test]
    fn ttl_policy_applies_negative_bounds_and_requires_soa() {
        let policy = CacheTtlPolicy::new(
            Duration::from_secs(60),
            None,
            Duration::from_secs(30),
            Some(Duration::from_secs(10)),
            None,
        );
        let high = response_message(
            ResponseCode::NxDomain,
            Vec::new(),
            vec![soa_record("example.com", 120, 120)],
        );
        let low = response_message(
            ResponseCode::NoError,
            Vec::new(),
            vec![soa_record("example.com", 5, 5)],
        );
        let no_soa = response_message(ResponseCode::NxDomain, Vec::new(), Vec::new());

        assert_eq!(
            policy.ttl_for_response(&high).unwrap().0,
            Duration::from_secs(30)
        );
        assert_eq!(
            policy.ttl_for_response(&low).unwrap().0,
            Duration::from_secs(10)
        );
        assert_eq!(policy.ttl_for_response(&no_soa), None);
    }

    #[test]
    fn ttl_policy_does_not_cache_failures_without_explicit_failure_ttl() {
        let default_policy = CacheTtlPolicy::default();
        let failure = response_message(ResponseCode::ServFail, Vec::new(), Vec::new());
        let refused = response_message(ResponseCode::Refused, Vec::new(), Vec::new());
        let failure_policy = CacheTtlPolicy::new(
            Duration::from_secs(60),
            None,
            Duration::from_secs(60),
            None,
            Some(Duration::from_secs(2)),
        );

        assert_eq!(default_policy.ttl_for_response(&failure), None);
        assert_eq!(default_policy.ttl_for_response(&refused), None);
        assert_eq!(
            failure_policy.ttl_for_response(&failure),
            Some((Duration::from_secs(2), None))
        );
    }

    #[test]
    fn ttl_policy_caps_explicit_failure_ttl() {
        let failure = response_message(ResponseCode::ServFail, Vec::new(), Vec::new());
        let failure_policy = CacheTtlPolicy::new(
            Duration::from_secs(60),
            None,
            Duration::from_secs(60),
            None,
            Some(Duration::from_secs(3600)),
        );

        assert_eq!(
            failure_policy.ttl_for_response(&failure),
            Some((MAX_FAILURE_CACHE_TTL, None))
        );
    }

    #[test]
    fn in_memory_cache_returns_unexpired_entry() {
        let cache = InMemoryDnsCache::new(16);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let key = cache_key("example.com");

        cache.store_now(cache_store(key.clone(), Duration::from_secs(30)), now);

        let lookup = cache.lookup_now(&CacheLookupRequest {
            key,
            received_at: now + Duration::from_secs(5),
        });
        let CacheLookup::Hit(hit) = lookup else {
            panic!("expected cache hit");
        };
        assert_eq!(hit.response_template, vec![0x12, 0x34, 0x81, 0x80]);
        assert_eq!(hit.stored_at, now);
        assert_eq!(hit.expires_at, now + Duration::from_secs(30));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn in_memory_cache_expires_entries_on_lookup() {
        let cache = InMemoryDnsCache::new(16);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let key = cache_key("example.com");

        cache.store_now(cache_store(key.clone(), Duration::from_secs(30)), now);

        let lookup = cache.lookup_now(&CacheLookupRequest {
            key,
            received_at: now + Duration::from_secs(30),
        });

        assert_eq!(lookup, CacheLookup::Miss);
        assert!(cache.is_empty());
    }

    #[test]
    fn in_memory_cache_evicts_least_recently_used_entry_when_bounded() {
        let cache = InMemoryDnsCache::new(2);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let first = cache_key("first.example");
        let second = cache_key("second.example");
        let third = cache_key("third.example");
        cache.store_now(cache_store(first.clone(), Duration::from_secs(60)), now);
        cache.store_now(cache_store(second.clone(), Duration::from_secs(60)), now);
        assert!(matches!(
            cache.lookup_now(&CacheLookupRequest {
                key: first.clone(),
                received_at: now
            }),
            CacheLookup::Hit(_)
        ));

        cache.store_now(cache_store(third.clone(), Duration::from_secs(60)), now);

        assert_eq!(cache.len(), 2);
        assert!(matches!(
            cache.lookup_now(&CacheLookupRequest {
                key: first,
                received_at: now
            }),
            CacheLookup::Hit(_)
        ));
        assert_eq!(
            cache.lookup_now(&CacheLookupRequest {
                key: second,
                received_at: now
            }),
            CacheLookup::Miss
        );
        assert!(matches!(
            cache.lookup_now(&CacheLookupRequest {
                key: third,
                received_at: now
            }),
            CacheLookup::Hit(_)
        ));
    }

    #[test]
    fn in_memory_cache_zero_capacity_stores_nothing() {
        let cache = InMemoryDnsCache::new(0);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let key = cache_key("example.com");

        cache.store_now(cache_store(key.clone(), Duration::from_secs(30)), now);

        assert_eq!(
            cache.lookup_now(&CacheLookupRequest {
                key,
                received_at: now,
            }),
            CacheLookup::Miss
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn in_memory_cache_prunes_stale_lru_tokens_on_repeated_hits() {
        let cache = InMemoryDnsCache::new(2);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let key = cache_key("example.com");
        cache.store_now(cache_store(key.clone(), Duration::from_secs(60)), now);

        for _ in 0..100 {
            assert!(matches!(
                cache.lookup_now(&CacheLookupRequest {
                    key: key.clone(),
                    received_at: now,
                }),
                CacheLookup::Hit(_)
            ));
        }

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.lru_len(), 1);
    }

    #[test]
    fn cache_key_from_query_includes_supported_semantics() {
        let codec = StandardProtocolCodec::new(1232);
        let query = codec
            .decode_query(&a_query_with_edns(0x1234, "Example.COM", 4096, true))
            .unwrap();

        let key = CacheKey::from_query(&query, Some("primary".to_string()), 1232);

        assert_eq!(key.question, QuestionKey::new("example.com", 1, 1));
        assert_eq!(
            key.features,
            QueryFeatures {
                dnssec_ok: true,
                edns_udp_payload_size: Some(4096),
            }
        );
        assert_eq!(key.upstream_policy_variant.as_deref(), Some("primary"));
        assert_eq!(key.effective_udp_payload_size, 1232);
    }

    #[test]
    fn cache_key_separates_question_type_class_policy_and_udp_size() {
        let codec = StandardProtocolCodec::new(4096);
        let a_in = codec
            .decode_query(&a_query_with_edns(0x1000, "example.com", 512, false))
            .unwrap();
        let aaaa_in = codec
            .decode_query(&aaaa_query(0x1000, "example.com"))
            .unwrap();
        let a_ch = codec
            .decode_query(&chaos_a_query(0x1000, "example.com"))
            .unwrap();
        let a_in_larger_udp = codec
            .decode_query(&a_query_with_edns(0x1000, "example.com", 1232, false))
            .unwrap();

        let base = CacheKey::from_query(&a_in, Some("primary".to_string()), 4096);

        assert_ne!(
            base,
            CacheKey::from_query(&aaaa_in, Some("primary".to_string()), 4096)
        );
        assert_ne!(
            base,
            CacheKey::from_query(&a_ch, Some("primary".to_string()), 4096)
        );
        assert_ne!(
            base,
            CacheKey::from_query(&a_in, Some("secondary".to_string()), 4096)
        );
        assert_ne!(
            base,
            CacheKey::from_query(&a_in_larger_udp, Some("primary".to_string()), 4096)
        );
    }

    #[tokio::test]
    async fn resolve_forwards_valid_query_to_upstream() {
        let response = vec![0xab, 0xcd, 0x81, 0x80];
        let upstream = Arc::new(StaticUpstream::new(Ok(UpstreamResponse {
            bytes: response.clone(),
            received_at: SystemTime::UNIX_EPOCH,
        })));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream.clone(), events.clone(), metrics.clone());

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "Example.COM"),
            ))
            .await;

        assert_eq!(&outcome.response_bytes[0..2], &[0x12, 0x34]);
        assert_eq!(&outcome.response_bytes[2..], &response[2..]);
        assert_eq!(outcome.decision.question.unwrap().qname, "example.com");
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        assert_eq!(events.decisions.lock().unwrap().len(), 1);
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::UpstreamSuccess));
    }

    #[tokio::test]
    async fn resolve_returns_protocol_error_without_upstream_lookup() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream.clone(), events.clone(), metrics.clone());

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                vec![0xbe, 0xef],
            ))
            .await;

        assert_eq!(&outcome.response_bytes[0..2], &[0xbe, 0xef]);
        assert_eq!(
            outcome.response_bytes[3] & 0x0f,
            ResponseCode::FormErr as u8
        );
        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::ProtocolError(ResponseCode::FormErr)
        );
        assert!(upstream.requests.lock().unwrap().is_empty());
        assert_eq!(events.decisions.lock().unwrap().len(), 1);
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::ProtocolError));
    }

    #[tokio::test]
    async fn resolve_maps_upstream_failure_to_servfail() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream, events, metrics.clone());

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(
            outcome.response_bytes[3] & 0x0f,
            ResponseCode::ServFail as u8
        );
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::UpstreamFailure);
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::UpstreamFailure));
    }

    #[tokio::test]
    async fn resolve_maps_no_upstreams_to_servfail() {
        let upstream = Arc::new(StaticUpstream::new(Err(
            UpstreamError::NoUpstreamsAvailable,
        )));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream, events, metrics.clone());

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(
            outcome.response_bytes[3] & 0x0f,
            ResponseCode::ServFail as u8
        );
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::UpstreamFailure);
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::UpstreamFailure));
    }
}
