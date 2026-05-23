use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use crate::protocol::{Message, QueryValidationError, ResponseCode};

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
    ProtocolError,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
