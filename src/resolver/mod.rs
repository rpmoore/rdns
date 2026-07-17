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

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::{self, Instant};

pub use crate::protocol::edns_cookie::ClientCookie;
use crate::protocol::{
    Message, NameCompressor, QueryDecodeFailure, QueryValidationError, Record, RecordData,
    ResponseCode, build_a_answers_response, build_a_block_response, build_aaaa_answers_response,
    build_aaaa_block_response, build_badvers_response, build_nodata_response,
    build_nxdomain_response, build_question_aware_error_response, build_refused_response,
    build_servfail_response, build_txt_answer_response, message_question_wire, rewrite_response_id,
    rewrite_response_request_fields,
};
// Re-exported (not just used privately): `src/main.rs` is a separate
// binary crate and must construct one via `CookieSecret::generate()` to
// hand to `ResolveQuery::with_cookie_secret`, mirroring how it constructs
// `SystemClock` from this same module.
pub use crate::protocol::edns_cookie::CookieSecret;

mod cache;
use cache::{
    ChainLookup, InFlightMiss, MissKey, ShardedSingleFlight, SingleFlightLeader,
    SingleFlightTicket, assemble_negative_response, assemble_response,
};
// `DecomposedResponse`/`RRsetEntry`/`StoredRecord`/`NegativeKey`/`NegativeEntry`
// are re-exported (not just used privately) so external test crates — see
// `tests/cache_concurrency_bench.rs` (section-08) — can drive
// `DomainDnsCache::store_response` with real data, not just the read path.
pub use cache::{
    DecomposedResponse, DomainDnsCache, NegativeEntry, NegativeKey, RRsetEntry, ShardedDnsCache,
    StoredRecord,
};

pub mod policy;
pub use policy::{
    CidrPrefixError, ClientIdentity, ClientSelector, DomainName, DomainNameError, DomainSelector,
    IpCidr, LocalDenyRule, LocalPolicyEvaluator, MaliciousDomainPolicyEvaluator,
    MaliciousDomainRule, NoopPolicyEvaluator, PolicyChain,
};

const EDNS_DO_FLAG: u16 = 0x8000;
const A_RECORD_TYPE: u16 = 1;
const AAAA_RECORD_TYPE: u16 = 28;
/// Default bound for `resolve_from_cache`'s CNAME-chain walk
/// (`ResolveQuery::max_chain_depth`), matching
/// `RawResolutionConfig`'s `default_max_cname_restarts`
/// (`config/mod.rs`). Callers constructing from real config override this
/// via `ResolveQuery::with_max_chain_depth`.
const DEFAULT_MAX_CHAIN_DEPTH: u8 = 8;
/// Default shard count for the `ShardedSingleFlight` a `ResolveQuery`
/// constructs itself. Matches `CacheConfig::resolved_shard_count()`'s own
/// fallback (section-01) so a `ResolveQuery` built without an explicit
/// override still shards its single-flight bookkeeping sensibly; `main.rs`
/// overrides this via `with_single_flight_shard_count` to match the real
/// cache's actual shard count once both are constructed.
fn default_single_flight_shard_count() -> usize {
    crate::config::CacheConfig::default().resolved_shard_count()
}
const MAX_FAILURE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_LOCAL_DNS_TTL: u32 = 24 * 60 * 60;
const CNAME_RECORD_TYPE: u16 = 5;
const DNSKEY_RECORD_TYPE: u16 = 48;
const DS_RECORD_TYPE: u16 = 43;
const NSEC_RECORD_TYPE: u16 = 47;
const NSEC3_RECORD_TYPE: u16 = 50;
const NSEC3PARAM_RECORD_TYPE: u16 = 51;
const RRSIG_RECORD_TYPE: u16 = 46;
const SOA_RECORD_TYPE: u16 = 6;
const TXT_RECORD_TYPE: u16 = 16;
/// RFC 1035 §3.2.4 CLASS value for CHAOS, the class BIND's operator-info
/// pseudo-zone (`version.bind.`, `hostname.bind.`) is conventionally
/// queried under -- never IN. See `ResolveQuery::try_chaos_lookup`.
const CHAOS_CLASS: u16 = 3;
/// TTL rdns answers `version.bind.` with -- 0, matching BIND's own
/// convention for CHAOS-class operator-info answers (never cached).
const CHAOS_ANSWER_TTL: u32 = 0;
/// Normalized (`normalize_question_name`) form of `version.bind.`.
const VERSION_BIND_QNAME: &str = "version.bind";

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedAt(pub SystemTime);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ObservedSourceEndpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub transport: Option<QueryTransport>,
    pub listener: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum QueryTransport {
    Udp,
    Tcp,
}

impl ObservedSourceEndpoint {
    pub fn ip(ip: IpAddr) -> Self {
        Self {
            ip,
            port: None,
            transport: None,
            listener: None,
        }
    }

    pub fn udp(source: SocketAddr, listener: Option<SocketAddr>) -> Self {
        Self {
            ip: source.ip(),
            port: Some(source.port()),
            transport: Some(QueryTransport::Udp),
            listener,
        }
    }

    pub fn tcp(source: SocketAddr, listener: Option<SocketAddr>) -> Self {
        Self {
            ip: source.ip(),
            port: Some(source.port()),
            transport: Some(QueryTransport::Tcp),
            listener,
        }
    }

    /// EDNS UDP payload-size limits (and the 512-byte pre-EDNS default) are
    /// meaningless over TCP (RFC 6891 §6.2.3) — a TCP-sourced query's
    /// response must never be truncated on that basis.
    pub fn is_tcp(&self) -> bool {
        matches!(self.transport, Some(QueryTransport::Tcp))
    }
}

impl From<SocketAddr> for ObservedSourceEndpoint {
    fn from(endpoint: SocketAddr) -> Self {
        Self {
            ip: endpoint.ip(),
            port: Some(endpoint.port()),
            transport: None,
            listener: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRequest {
    pub client_ip: IpAddr,
    pub observed_source: ObservedSourceEndpoint,
    pub received_at: ReceivedAt,
    /// The DNS wire transaction ID, captured up front because `bytes` is
    /// consumed (via `mem::take`) early in `ResolveQuery::resolve` — every
    /// query-processing log statement downstream reads it from here so a
    /// single query's log lines can be correlated.
    pub request_id: Option<u16>,
    /// `Bytes` rather than `Vec<u8>` so a caller that needs to retain its
    /// own handle to the same wire bytes alongside what it hands to
    /// `resolve()` (e.g. the TCP server keeping a copy around for the
    /// rare oversized-response SERVFAIL fallback, see
    /// `serve_tcp_connection`) can do so with a cheap refcount-bump clone
    /// instead of a full `Vec<u8>` allocation + memcpy on every query.
    pub bytes: Bytes,
}

impl ResolveRequest {
    pub fn new(client_ip: IpAddr, received_at: SystemTime, bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        Self {
            client_ip,
            observed_source: ObservedSourceEndpoint::ip(client_ip),
            received_at: ReceivedAt(received_at),
            request_id: request_id_from_wire(&bytes),
            bytes,
        }
    }

    pub fn new_with_observed_source(
        observed_source: impl Into<ObservedSourceEndpoint>,
        received_at: SystemTime,
        bytes: impl Into<Bytes>,
    ) -> Self {
        let observed_source = observed_source.into();
        let bytes = bytes.into();
        Self {
            client_ip: observed_source.ip,
            observed_source,
            received_at: ReceivedAt(received_at),
            request_id: request_id_from_wire(&bytes),
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
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
    /// RFC 1035 §4.1.1: RD is copied from query to response regardless of
    /// its value (unconditional mirroring, handled separately at
    /// serialization time). It's *also* read in `ResolveQuery::resolve`
    /// to gate resolution itself: RD=0 restricts a query to data rdns
    /// already has (a local entry or an existing cache hit) and refuses
    /// with SERVFAIL rather than doing fresh backend work for a miss --
    /// see `refuse_recursion` and `docs/knowledge/resolver/rd-bit-handling.md`.
    /// Pinned down by `rd_zero_query_is_refused_on_a_cache_miss` and
    /// `resolve_rewrites_rd_flag_for_current_request_on_cache_hit`
    /// (resolver tests), and `rd_zero_still_serves_a_local_entry` /
    /// `rd_zero_query_is_refused_on_a_cache_miss` (`tests/e2e_config_toml.rs`).
    pub recursion_desired: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub dnssec_ok: bool,
    pub edns_udp_payload_size: Option<u16>,
    /// The requester's client cookie, extracted via
    /// `edns_cookie::parse_cookie_option` (not the stricter
    /// `is_solely_cookie_option`, which is section-03's cache-admission-only
    /// concern) -- a query carrying a well-formed Cookie alongside another
    /// EDNS option still gets its cookie echoed here, even though such a
    /// query isn't cache-admissible.
    pub client_cookie: Option<ClientCookie>,
}

impl QueryFeatures {
    pub fn from_message(message: &Message) -> Self {
        Self {
            recursion_desired: message.header.rd(),
            authenticated_data: message.header.ad(),
            checking_disabled: message.header.cd(),
            dnssec_ok: message
                .edns
                .as_ref()
                .map(|edns| edns.dnssec_ok)
                .unwrap_or(false),
            edns_udp_payload_size: message.edns.as_ref().map(|edns| edns.udp_payload_size),
            client_cookie: message
                .edns
                .as_ref()
                .and_then(|edns| crate::protocol::edns_cookie::parse_cookie_option(&edns.options)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedQuery {
    pub message: Message,
    pub question: QuestionKey,
    pub question_wire: Bytes,
    pub features: QueryFeatures,
}

impl DecodedQuery {
    pub fn new(message: Message) -> Option<Self> {
        let question = QuestionKey::from_message(&message)?;
        let question_wire = message_question_wire(&message).ok()?;
        let features = QueryFeatures::from_message(&message);
        Some(Self {
            message,
            question,
            question_wire,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BlockReason {
    LocalRule,
    MaliciousDomain,
    InvalidDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BlockResponseMode {
    Refused,
    NxDomain,
    NoData,
    Sinkhole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockResponseConfig {
    pub local_rule_mode: BlockResponseMode,
    pub malicious_domain_mode: BlockResponseMode,
    pub invalid_domain_mode: BlockResponseMode,
    pub blocked_response_ttl: u32,
    pub cacheable_by_clients: bool,
    pub sinkhole_ipv4: Option<Ipv4Addr>,
    pub sinkhole_ipv6: Option<Ipv6Addr>,
}

impl BlockResponseConfig {
    pub fn new(
        local_rule_mode: BlockResponseMode,
        malicious_domain_mode: BlockResponseMode,
        invalid_domain_mode: BlockResponseMode,
        blocked_response_ttl: u32,
        cacheable_by_clients: bool,
        sinkhole_ipv4: Option<Ipv4Addr>,
        sinkhole_ipv6: Option<Ipv6Addr>,
    ) -> Result<Self, BlockResponseConfigError> {
        let config = Self {
            local_rule_mode,
            malicious_domain_mode,
            invalid_domain_mode,
            blocked_response_ttl,
            cacheable_by_clients,
            sinkhole_ipv4,
            sinkhole_ipv6,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn mode_for(&self, reason: &BlockReason) -> BlockResponseMode {
        match reason {
            BlockReason::LocalRule => self.local_rule_mode,
            BlockReason::MaliciousDomain => self.malicious_domain_mode,
            BlockReason::InvalidDomain => self.invalid_domain_mode,
        }
    }

    pub fn validate(&self) -> Result<(), BlockResponseConfigError> {
        if self.uses_sinkhole() && self.sinkhole_ipv4.is_none() && self.sinkhole_ipv6.is_none() {
            return Err(BlockResponseConfigError::MissingSinkholeAddress);
        }
        if self.blocked_response_ttl > 0
            && self.cacheable_by_clients
            && self.uses_non_sinkhole_mode()
        {
            return Err(BlockResponseConfigError::ClientCachingUnsupportedForNonSinkhole);
        }
        Ok(())
    }

    fn uses_sinkhole(&self) -> bool {
        [
            self.local_rule_mode,
            self.malicious_domain_mode,
            self.invalid_domain_mode,
        ]
        .contains(&BlockResponseMode::Sinkhole)
    }

    fn uses_non_sinkhole_mode(&self) -> bool {
        [
            self.local_rule_mode,
            self.malicious_domain_mode,
            self.invalid_domain_mode,
        ]
        .iter()
        .any(|mode| !matches!(mode, BlockResponseMode::Sinkhole))
    }
}

impl Default for BlockResponseConfig {
    fn default() -> Self {
        Self {
            local_rule_mode: BlockResponseMode::Refused,
            malicious_domain_mode: BlockResponseMode::Refused,
            invalid_domain_mode: BlockResponseMode::Refused,
            blocked_response_ttl: 0,
            cacheable_by_clients: false,
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockResponseConfigError {
    ClientCachingUnsupportedForNonSinkhole,
    MissingSinkholeAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDnsEntry {
    pub id: Option<String>,
    pub name: DomainName,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub ttl: u32,
    pub enabled: bool,
    pub generation: u64,
}

impl LocalDnsEntry {
    pub fn new(
        name: DomainName,
        ipv4: Vec<Ipv4Addr>,
        ipv6: Vec<Ipv6Addr>,
        ttl: u32,
        enabled: bool,
    ) -> Self {
        Self {
            id: None,
            name,
            ipv4,
            ipv6,
            ttl,
            enabled,
            generation: 0,
        }
    }

    pub fn with_metadata(mut self, id: impl Into<String>, generation: u64) -> Self {
        self.id = Some(id.into());
        self.generation = generation;
        self
    }

    pub fn validate(
        &self,
        public_address_acknowledged: bool,
    ) -> Result<LocalDnsEntryValidation, LocalDnsEntryValidationError> {
        if self.ipv4.is_empty() && self.ipv6.is_empty() {
            return Err(LocalDnsEntryValidationError::NoAddresses);
        }
        if self.ttl == 0 {
            return Err(LocalDnsEntryValidationError::TtlTooLow);
        }
        if self.ttl > MAX_LOCAL_DNS_TTL {
            return Err(LocalDnsEntryValidationError::TtlTooHigh {
                max: MAX_LOCAL_DNS_TTL,
            });
        }
        let uses_public_address = self.ipv4.iter().any(|address| !ipv4_is_local_use(*address))
            || self.ipv6.iter().any(|address| !ipv6_is_local_use(*address));
        if uses_public_address && !public_address_acknowledged {
            return Err(LocalDnsEntryValidationError::PublicAddressRequiresAcknowledgement);
        }

        let mut warnings = Vec::new();
        if local_dns_name_uses_mdns_suffix(&self.name) {
            warnings.push(LocalDnsEntryWarning::ReservedMdnsSuffix);
        }
        Ok(LocalDnsEntryValidation { warnings })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDnsEntryValidation {
    pub warnings: Vec<LocalDnsEntryWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDnsEntryWarning {
    ReservedMdnsSuffix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDnsEntryValidationError {
    NoAddresses,
    TtlTooLow,
    TtlTooHigh { max: u32 },
    PublicAddressRequiresAcknowledgement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalAnswerMetadata {
    pub entry_id: Option<String>,
    pub generation: u64,
    pub family: LocalAnswerFamily,
    pub ttl: u32,
}

impl LocalAnswerMetadata {
    fn from_entry(entry: &LocalDnsEntry, family: LocalAnswerFamily) -> Self {
        Self {
            entry_id: entry.id.clone(),
            generation: entry.generation,
            family,
            ttl: entry.ttl,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LocalAnswerFamily {
    A,
    Aaaa,
    NoDataA,
    NoDataAaaa,
}

fn local_dns_name_uses_mdns_suffix(name: &DomainName) -> bool {
    let name = name.as_str();
    name == "local" || name.ends_with(".local")
}

fn ipv4_is_local_use(address: Ipv4Addr) -> bool {
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.octets()[0] == 0
        || address.octets()[0] == 127
}

fn ipv6_is_local_use(address: Ipv6Addr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address.is_unique_local()
        || address.is_unicast_link_local()
}

fn local_answer_family(qtype: u16) -> LocalAnswerFamily {
    match qtype {
        A_RECORD_TYPE => LocalAnswerFamily::A,
        AAAA_RECORD_TYPE => LocalAnswerFamily::Aaaa,
        _ => LocalAnswerFamily::NoDataA,
    }
}

fn local_nodata_family(qtype: u16) -> LocalAnswerFamily {
    match qtype {
        A_RECORD_TYPE => LocalAnswerFamily::NoDataA,
        AAAA_RECORD_TYPE => LocalAnswerFamily::NoDataAaaa,
        _ => LocalAnswerFamily::NoDataA,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalDnsLookup {
    NoMatch,
    Answer(LocalDnsEntry),
    NoData(LocalDnsEntry),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InMemoryLocalDnsEntries {
    entries: HashMap<DomainName, LocalDnsEntry>,
}

impl InMemoryLocalDnsEntries {
    pub fn new(entries: Vec<LocalDnsEntry>) -> Self {
        let entries = entries
            .into_iter()
            .filter(|entry| entry.enabled)
            .map(|entry| (entry.name.clone(), entry))
            .collect();
        Self { entries }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeCacheMetadata {
    pub authority_zone: String,
    pub covered_name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub kind: NegativeCacheKind,
    pub soa_owner: String,
    pub soa_minimum_ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegativeCacheKind {
    NxDomain,
    NoData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheBypassReason {
    UnsupportedQueryFeature,
    ResponseSizeDependsOnRequest,
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
            let response_question = QuestionKey::from_message(response);
            let cname_chain_nodata = response_code == ResponseCode::NoError
                && response_question
                    .as_ref()
                    .map(|question| {
                        question.qtype != CNAME_RECORD_TYPE
                            && !has_requested_answer_after_cname_chain(response, question)
                    })
                    .unwrap_or(false);
            if response_code == ResponseCode::NxDomain || cname_chain_nodata {
                let metadata = negative_ttl(response)?;
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
    let response_code = response_code(response)?;
    let question = response.questions.first()?;
    let question_key = QuestionKey::new(&question.qname, question.qtype, question.qclass);
    let kind = match response_code {
        ResponseCode::NxDomain => NegativeCacheKind::NxDomain,
        ResponseCode::NoError => NegativeCacheKind::NoData,
        _ => return None,
    };
    let covered_name = negative_covered_name(response, &question_key)?;
    response.authorities.iter().find_map(|record| {
        let RecordData::SOA { minimum, .. } = &record.record else {
            return None;
        };
        if record.rclass != question.qclass {
            return None;
        }
        let soa_owner = normalize_question_name(&record.name);
        if !name_is_at_or_below(&covered_name, &soa_owner) {
            return None;
        }
        let ttl = record.ttl.min(*minimum);
        Some(NegativeCacheMetadata {
            authority_zone: soa_owner.clone(),
            covered_name: covered_name.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
            kind,
            soa_owner,
            soa_minimum_ttl: Duration::from_secs(u64::from(ttl)),
        })
    })
}

fn negative_covered_name(response: &Message, question: &QuestionKey) -> Option<String> {
    let mut covered_name = question.qname.clone();
    for _ in 0..=response.answers.len() {
        let Some(record) = response.answers.iter().find(|record| {
            record.rtype == CNAME_RECORD_TYPE
                && record.rclass == question.qclass
                && normalize_question_name(&record.name) == covered_name
        }) else {
            return Some(covered_name);
        };
        let RecordData::CNAME(target) = &record.record else {
            return None;
        };
        covered_name = normalize_question_name(target);
    }
    None
}

fn name_is_at_or_below(name: &str, zone: &str) -> bool {
    let name = normalize_question_name(name);
    let zone = normalize_question_name(zone);
    if zone.is_empty() {
        return true;
    }
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// Walks the CNAME chain in `response.answers` from `question.qname`,
/// building one `RRsetEntry` per hop (CNAME hops included, per
/// `DecomposedResponse`'s doc) plus, if the terminal result is negative
/// (`negative_meta.is_some()`), a `NegativeEntry` for the terminal name.
/// Reuses `CacheTtlPolicy::ttl_for_response`'s already-computed `ttl` and
/// `negative_meta` rather than re-deriving TTL/negative-classification
/// logic — this function's only job is turning that decision plus the raw
/// `Message` into the per-domain entry shapes `ShardedDnsCache::store_response`
/// consumes. Mirrors `negative_covered_name`'s existing chain-walking
/// pattern, extended to also collect each hop's own RRset, not just the
/// terminal covered name.
///
/// `dnssec_ok` is the *storing* request's own DO flag — forwarded verbatim
/// to upstream authorities during resolution, so it's the only reliable
/// signal for whether this particular backend response's DNSSEC material
/// (or lack thereof) can be trusted as confirmed vs. simply never asked
/// for. Stamped onto every produced entry's `dnssec_complete` field (see
/// `RRsetEntry`/`NegativeEntry`'s doc comments) — this is the fix for the
/// stale-DO-false-entry bug.
///
/// `store_authoritative` is the AA bit to stamp onto every produced
/// entry's `authoritative` field — *not* simply `response.header.aa()`.
/// Per RFC 1035 §4.1.1, AA describes the *responding server's* own
/// authority over the zone, not whatever server this resolver happened to
/// fetch the answer from. For a recursive fetch, `response` is an upstream
/// authority's answer, not this resolver's own — rdns is never itself
/// authoritative when recursing, so the caller must always pass `false`
/// here for `ResolutionMode::Recursive`. Only `ResolutionMode::Forward`
/// (a transparent proxy, which may legitimately relay a forwarder that
/// really is authoritative for the zone) may pass the response's real AA
/// bit through. See `prepare_backend_result`'s `store_authoritative`
/// computation, which mirrors `store_dnssec_ok`'s existing per-mode gate.
fn decompose_response_for_store(
    response: &Message,
    question: &QuestionKey,
    ttl: Duration,
    negative_meta: Option<&NegativeCacheMetadata>,
    stored_at: SystemTime,
    dnssec_ok: bool,
    store_authoritative: bool,
) -> DecomposedResponse {
    let mut positive = Vec::new();
    let mut current_name = question.qname.clone();
    // `ttl_for_response` (via `negative_ttl`/`has_requested_answer_after_cname_chain`)
    // already made the authoritative positive-vs-negative call for this
    // response — including a `recursive_response_record_supported` check
    // this function has no independent way to reproduce (e.g. an Unknown
    // record type queried directly with `dnssec_ok == false`). Trust that
    // classification rather than re-deriving "is this a satisfying answer"
    // from a second, independently-written predicate: when `negative_meta`
    // is `Some`, never take the terminal-positive branch, even if a
    // same-name/type/class record happens to be physically present in
    // `response.answers`.
    let treat_as_negative = negative_meta.is_some();

    for _ in 0..=response.answers.len() {
        if !treat_as_negative {
            let terminal_records: Vec<&Record> = response
                .answers
                .iter()
                .filter(|record| {
                    record.rtype == question.qtype
                        && record.rclass == question.qclass
                        && normalize_question_name(&record.name) == current_name
                })
                .collect();
            if !terminal_records.is_empty() {
                let entry = build_rrset_entry(
                    response,
                    &terminal_records,
                    &current_name,
                    ttl,
                    stored_at,
                    dnssec_ok,
                    store_authoritative,
                );
                positive.push((current_name, question.qtype, question.qclass, entry));
                return DecomposedResponse {
                    positive,
                    negative: None,
                };
            }
        }

        if question.qtype == CNAME_RECORD_TYPE {
            break;
        }
        let cname_records: Vec<&Record> = response
            .answers
            .iter()
            .filter(|record| {
                record.rtype == CNAME_RECORD_TYPE
                    && record.rclass == question.qclass
                    && normalize_question_name(&record.name) == current_name
            })
            .collect();
        let Some(RecordData::CNAME(target)) = cname_records.first().map(|record| &record.record)
        else {
            break;
        };
        let target = normalize_question_name(target);
        let entry = build_rrset_entry(
            response,
            &cname_records,
            &current_name,
            ttl,
            stored_at,
            dnssec_ok,
            store_authoritative,
        );
        positive.push((current_name, CNAME_RECORD_TYPE, question.qclass, entry));
        current_name = target;
    }

    let negative = negative_meta.map(|metadata| {
        let key = NegativeKey {
            qtype: match metadata.kind {
                NegativeCacheKind::NxDomain => None,
                NegativeCacheKind::NoData => Some(question.qtype),
            },
            qclass: question.qclass,
        };
        let entry = build_negative_entry(
            response,
            metadata,
            ttl,
            stored_at,
            dnssec_ok,
            store_authoritative,
        );
        (current_name.clone(), key, entry)
    });

    DecomposedResponse { positive, negative }
}

fn to_stored_record(record: &Record) -> StoredRecord {
    StoredRecord {
        rtype: record.rtype,
        rclass: record.rclass,
        ttl_at_store: record.ttl,
        rdata: record.record.clone(),
    }
}

/// Finds every RRSIG in `records` that covers `(owner, covered_type,
/// rclass)`. Used to pull DNSSEC signatures for a just-fetched RRset out
/// of the backend response so they can be stored alongside it —
/// independent of whether *this particular* requester set DO, since
/// `assemble_response`/`assemble_negative_response` (section-06) are
/// responsible for filtering DNSSEC material back out at serve time based
/// on the *reading* requester's own DO flag. Whether a backend response
/// contains any RRSIGs at all still depends on whether upstream was asked
/// for them (the *fetching* requester's DO flag, forwarded verbatim to
/// authorities by `resolve_one_hop`) — this function only decides what to
/// do with RRSIGs that are actually present, it doesn't request them.
fn matching_rrsigs(
    records: &[Record],
    owner: &str,
    covered_type: u16,
    rclass: u16,
) -> Vec<StoredRecord> {
    records
        .iter()
        .filter(|record| {
            record.rclass == rclass
                && normalize_question_name(&record.name) == owner
                && matches!(
                    &record.record,
                    RecordData::RRSIG { type_covered, .. } if *type_covered == covered_type
                )
        })
        .map(to_stored_record)
        .collect()
}

/// Finds NSEC/NSEC3/NSEC3PARAM proof records (and their covering RRSIGs)
/// in `authorities`, for storage in `NegativeEntry.proof_records`. Unlike
/// `matching_rrsigs`, this isn't scoped to one owner name — an NSEC/NSEC3
/// negative proof legitimately spans records owned by names other than
/// the queried name (e.g. the NSEC covering the "next" name in the zone),
/// so this only filters by class, mirroring
/// `recursive_response_authority_supported`'s own DNSSEC-record handling.
///
/// Returns each record paired with its own owner name (from the backend
/// response's actual `Record::name`, normalized) rather than bare
/// `StoredRecord`s — `StoredRecord` has no owner field, and NSEC/NSEC3
/// proof records are very often owned by names other than the covered
/// name or the SOA zone apex (they bracket the queried name with adjacent
/// existing names in the zone). Dropping the owner here was the bug this
/// pairing fixes; see `NegativeEntry::proof_records`'s doc comment.
fn negative_proof_records(authorities: &[Record], qclass: u16) -> Vec<(String, StoredRecord)> {
    authorities
        .iter()
        .filter(|record| {
            record.rclass == qclass
                && (matches!(
                    record.record,
                    RecordData::NSEC { .. } | RecordData::NSEC3 { .. } | RecordData::NSEC3PARAM { .. }
                ) || matches!(
                    &record.record,
                    RecordData::RRSIG { type_covered, .. }
                        if matches!(*type_covered, NSEC_RECORD_TYPE | NSEC3_RECORD_TYPE | NSEC3PARAM_RECORD_TYPE)
                ))
        })
        .map(|record| (normalize_question_name(&record.name), to_stored_record(record)))
        .collect()
}

/// Builds one `RRsetEntry` from `records` (all sharing the same owner
/// name, rtype, and rclass — a single terminal answer or CNAME hop) plus
/// whatever RRSIGs `response` carries covering that same RRset. RRSIGs are
/// stored whenever the backend response contains them, regardless of
/// whether the requester that triggered this particular fetch had DO
/// set — DNSSEC inclusion is a per-request *assembly* decision
/// (`assemble_response`), not a store-time one (see
/// `docs/plans/cache_rework/sections/section-06-assembly-and-chains.md`).
///
/// `dnssec_ok` is the storing request's own DO flag, stamped onto the
/// produced entry's `dnssec_complete` field: only a DO=true-driven fetch's
/// `rrsigs` (empty or not) can be trusted as the confirmed DNSSEC state —
/// see `RRsetEntry::dnssec_complete`'s doc comment.
///
/// `store_authoritative` is stamped verbatim onto the produced entry's
/// `authoritative` field — see `decompose_response_for_store`'s doc
/// comment for why this must not simply be `response.header.aa()`.
fn build_rrset_entry(
    response: &Message,
    records: &[&Record],
    owner: &str,
    ttl: Duration,
    stored_at: SystemTime,
    dnssec_ok: bool,
    store_authoritative: bool,
) -> RRsetEntry {
    let rtype = records.first().map_or(0, |record| record.rtype);
    let rclass = records.first().map_or(0, |record| record.rclass);
    RRsetEntry {
        records: records.iter().copied().map(to_stored_record).collect(),
        rrsigs: matching_rrsigs(&response.answers, owner, rtype, rclass),
        response_code: ResponseCode::NoError,
        minimum_ttl: ttl,
        stored_at,
        expires_at: stored_at + ttl,
        dnssec_state: Default::default(),
        // Overwritten by `ShardedDnsCache::store_response` at store time —
        // see that method's doc comment for why the epoch isn't set here.
        cache_epoch: 0,
        dnssec_complete: dnssec_ok,
        authoritative: store_authoritative,
    }
}

/// Builds the terminal `NegativeEntry` for a decomposed store. `metadata`
/// was already computed by `negative_ttl` (via `ttl_for_response`), which
/// only succeeds after finding a covering SOA record satisfying exactly
/// this predicate — so failing to re-find it here would mean
/// `ttl_for_response`'s own result was inconsistent with `response`, an
/// invariant violation worth panicking on rather than silently storing
/// fabricated SOA data. `soa_rrsig`/`proof_records` are populated from
/// whatever DNSSEC material the backend response actually carries, same
/// as `build_rrset_entry`; `dnssec_ok` (the storing request's own DO flag)
/// is stamped onto `dnssec_complete` for the same reason as
/// `build_rrset_entry` — see `NegativeEntry::dnssec_complete`'s doc
/// comment. `store_authoritative` is stamped onto `authoritative` for the
/// same reason as `build_rrset_entry` — see
/// `decompose_response_for_store`'s doc comment.
fn build_negative_entry(
    response: &Message,
    metadata: &NegativeCacheMetadata,
    ttl: Duration,
    stored_at: SystemTime,
    dnssec_ok: bool,
    store_authoritative: bool,
) -> NegativeEntry {
    let soa_record = response
        .authorities
        .iter()
        .find(|record| {
            matches!(record.record, RecordData::SOA { .. })
                && record.rclass == metadata.qclass
                && normalize_question_name(&record.name) == metadata.soa_owner
        })
        .map(to_stored_record)
        .expect("negative_ttl already located a matching SOA record for this response");
    let soa_rrsig = matching_rrsigs(
        &response.authorities,
        &metadata.soa_owner,
        SOA_RECORD_TYPE,
        metadata.qclass,
    )
    .into_iter()
    .next();
    let proof_records = negative_proof_records(&response.authorities, metadata.qclass);
    NegativeEntry {
        kind: metadata.kind,
        soa_owner: metadata.soa_owner.clone(),
        soa_record,
        soa_rrsig,
        proof_records,
        stored_at,
        expires_at: stored_at + ttl,
        cache_epoch: 0,
        dnssec_complete: dnssec_ok,
        dnssec_state: Default::default(),
        authoritative: store_authoritative,
    }
}

fn has_requested_answer_for(message: &Message, question: &QuestionKey) -> bool {
    message.answers.iter().any(|record| {
        QuestionKey::new(&record.name, record.rtype, record.rclass) == *question
            && recursive_response_record_supported(record, false, &[question])
    })
}

fn has_requested_answer_after_cname_chain(message: &Message, question: &QuestionKey) -> bool {
    if has_requested_answer_for(message, question) {
        return true;
    }
    let Some(covered_name) = negative_covered_name(message, question) else {
        return false;
    };
    let target_question = QuestionKey::new(covered_name, question.qtype, question.qclass);
    has_requested_answer_for(message, &target_question)
}

fn cname_record_for<'a>(message: &'a Message, question: &QuestionKey) -> Option<&'a Record> {
    message.answers.iter().find(|record| {
        if record.rclass == question.qclass
            && record.rtype == CNAME_RECORD_TYPE
            && QuestionKey::new(&record.name, question.qtype, question.qclass).qname
                == question.qname
        {
            matches!(record.record, RecordData::CNAME(_))
        } else {
            false
        }
    })
}

/// Captures the CNAME record plus its covering RRSIG (if present) for a
/// CNAME hop, so both can be carried forward into `state.cname_chain`.
/// Always captures the covering RRSIG when present -- independent of the
/// querying client's own DO flag -- for the same reason `resolve_one_hop`
/// always requests DNSSEC material from upstream: what a *fetch* asks for
/// and stores is decided independently of what a given *reader* is handed
/// back at serve time (RFC 4035 §4.5; RFC 6840 §5.9).
fn cname_chain_records(message: &Message, cname_record: &Record) -> Vec<Record> {
    let mut records = vec![cname_record.clone()];
    let cname_owner = normalize_question_name(&cname_record.name);
    records.extend(message.answers.iter().filter_map(|record| {
        let RecordData::RRSIG { type_covered, .. } = &record.record else {
            return None;
        };
        if *type_covered == CNAME_RECORD_TYPE
            && record.rclass == cname_record.rclass
            && normalize_question_name(&record.name) == cname_owner
        {
            Some(record.clone())
        } else {
            None
        }
    }));
    records
}

fn authority_response_error(
    message: &Message,
    question: &QuestionKey,
) -> Option<ResolutionBackendError> {
    if !message.header.qr() || message.questions.len() != 1 {
        return Some(ResolutionBackendError::MalformedResponse);
    }
    if QuestionKey::from_message(message).as_ref() != Some(question) {
        return Some(ResolutionBackendError::QuestionMismatch);
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferralAuthorities {
    owner: String,
    endpoints: Vec<SocketAddr>,
    min_ttl: u32,
}

/// The longest NS-record owner in `message.authorities` that is an
/// ancestor-or-equal of `question.qname` -- i.e. the zone cut a delegation
/// response claims to be for.
fn delegation_owner(message: &Message, question: &QuestionKey) -> Option<String> {
    message
        .authorities
        .iter()
        .filter_map(|record| {
            if !matches!(record.record, RecordData::NS(_)) {
                return None;
            }
            if record.rclass != question.qclass {
                return None;
            }
            let owner = normalize_question_name(&record.name);
            if is_delegation_owner_for_question(&owner, &question.qname) {
                Some(owner)
            } else {
                None
            }
        })
        .max_by_key(|owner| owner.len())
}

/// NS record target names owned by `owner`, plus their minimum TTL.
///
/// When `require_bailiwick` is true, only in-bailiwick names are returned --
/// safe to use for *trusting glue addresses* supplied in the same response,
/// since accepting glue for an arbitrary out-of-bailiwick name is a classic
/// cache-poisoning vector. When false, all target names are returned
/// regardless of bailiwick -- safe only when those names will subsequently
/// be resolved via an independent, fully-validated recursive lookup rather
/// than trusted from this response directly (see glueless delegations).
fn ns_names_for_owner(
    message: &Message,
    owner: &str,
    qclass: u16,
    require_bailiwick: bool,
) -> (HashSet<String>, u32) {
    let mut min_ttl: Option<u32> = None;
    let names = message
        .authorities
        .iter()
        .filter_map(|record| match &record.record {
            RecordData::NS(name)
                if normalize_question_name(&record.name) == owner
                    && record.rclass == qclass
                    && (!require_bailiwick || ns_name_allowed_for_delegation(owner, name)) =>
            {
                min_ttl = Some(min_ttl.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
                Some(normalize_question_name(name))
            }
            _ => None,
        })
        .collect();
    (names, min_ttl.unwrap_or(0))
}

fn referral_authorities(message: &Message, question: &QuestionKey) -> Option<ReferralAuthorities> {
    let owner = delegation_owner(message, question)?;
    let (names, mut min_ttl) = ns_names_for_owner(message, &owner, question.qclass, true);
    if names.is_empty() {
        return None;
    }

    let endpoints = message
        .additionals
        .iter()
        .filter_map(|record| {
            if record.rclass != question.qclass {
                return None;
            }
            if !names.contains(&normalize_question_name(&record.name)) {
                return None;
            }
            let endpoint = match record.record {
                RecordData::A(address) => Some(SocketAddr::new(IpAddr::V4(address), 53)),
                RecordData::AAAA(address) => Some(SocketAddr::new(IpAddr::V6(address), 53)),
                _ => None,
            };
            // Bound the cached delegation lifetime by the glue address TTLs
            // too, not just the NS TTL, so a shorter-lived A/AAAA record
            // can't outlive its own freshness in the delegation cache.
            if endpoint.is_some() {
                min_ttl = min_ttl.min(record.ttl);
            }
            endpoint
        })
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        return None;
    }
    Some(ReferralAuthorities {
        owner,
        endpoints,
        min_ttl,
    })
}

/// A valid NS delegation for the question with no usable glue in this
/// response (a "glueless" delegation) -- e.g. a zone delegating to
/// nameservers hosted under a different, unrelated domain that the parent
/// zone can't supply glue for. The returned names still need to be resolved
/// independently (their own A/AAAA lookup) before they can be queried.
fn glueless_delegation_names(
    message: &Message,
    question: &QuestionKey,
) -> Option<(String, HashSet<String>, u32)> {
    let owner = delegation_owner(message, question)?;
    let (names, min_ttl) = ns_names_for_owner(message, &owner, question.qclass, false);
    if names.is_empty() {
        return None;
    }
    Some((owner, names, min_ttl))
}

fn has_delegation_for_question(message: &Message, question: &QuestionKey) -> bool {
    message.authorities.iter().any(|record| {
        matches!(record.record, RecordData::NS(_))
            && record.rclass == question.qclass
            && is_delegation_owner_for_question(&record.name, &question.qname)
    })
}

fn is_delegation_owner_for_question(owner: &str, qname: &str) -> bool {
    let owner = normalize_question_name(owner);
    let qname = normalize_question_name(qname);
    owner.is_empty() || qname == owner || qname.ends_with(&format!(".{owner}"))
}

fn ns_name_allowed_for_delegation(owner: &str, name: &str) -> bool {
    is_delegation_owner_for_question(owner, name) || name_is_at_or_below(name, &parent_zone(owner))
}

fn parent_zone(name: &str) -> String {
    let name = normalize_question_name(name);
    let Some((_, parent)) = name.split_once('.') else {
        return String::new();
    };
    parent.to_string()
}

fn is_negative_answer(message: &Message) -> bool {
    (response_code(message) == Some(ResponseCode::NxDomain)
        && message.header.aa()
        && negative_ttl(message).is_some())
        || (response_code(message) == Some(ResponseCode::NoError)
            && message.header.aa()
            && message.answers.is_empty()
            && negative_ttl(message).is_some())
}

/// Builds the recursive backend's single, always-DNSSEC-complete response
/// message for `final_response` (plus the captured `cname_chain`), along
/// with the `(original_question, final_question)` pair used to filter it.
///
/// This message always keeps DNSKEY/DS/RRSIG/NSEC/NSEC3/NSEC3PARAM
/// material regardless of the requesting client's own DO flag -- the
/// message this function returns is used verbatim for cache storage
/// (`ResolutionResponse::recursive_response`), so it must be complete
/// independent of which client happened to trigger the fetch (RFC 4035
/// §4.5; RFC 6840 §5.9). What actually goes out on the wire to a DO=false
/// client is trimmed *afterward*, from a second copy, by
/// `filter_response_for_requester` in `prepare_backend_result` -- using
/// the same `(original_question, final_question)` pair returned here, so
/// it filters against the terminal (post-CNAME-walk) question rather than
/// re-deriving the wrong one from the already-synthesized message.
fn synthesize_recursive_cname_response(
    original_query: &Message,
    cname_chain: &[Record],
    final_response: &Message,
    configured_max_udp_payload_size: usize,
) -> Result<(Message, QuestionKey, QuestionKey), ResolutionBackendError> {
    let dnssec_ok = true;
    let original_question = QuestionKey::from_message(original_query)
        .ok_or(ResolutionBackendError::MalformedResponse)?;
    let final_question = QuestionKey::from_message(final_response)
        .ok_or(ResolutionBackendError::MalformedResponse)?;
    let mut answers = cname_chain.to_vec();
    answers.extend(
        final_response
            .answers
            .iter()
            .filter(|record| {
                recursive_response_record_supported(
                    record,
                    dnssec_ok,
                    &[&original_question, &final_question],
                )
            })
            .cloned(),
    );
    let authorities = final_response
        .authorities
        .iter()
        .filter(|record| {
            recursive_response_authority_supported(
                record,
                dnssec_ok,
                &[&original_question, &final_question],
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut additionals = final_response
        .additionals
        .iter()
        .filter(|record| {
            recursive_response_record_supported(
                record,
                dnssec_ok,
                &[&original_question, &final_question],
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    if let Some(opt) = mirrored_client_opt_record(original_query, configured_max_udp_payload_size) {
        additionals.push(opt);
    }
    let bytes = serialize_recursive_response(
        original_query,
        response_code(final_response).unwrap_or(ResponseCode::ServFail),
        false,
        &answers,
        &authorities,
        &additionals,
    )?;
    let message =
        Message::parse_owned(bytes).map_err(|_| ResolutionBackendError::MalformedResponse)?;
    Ok((message, original_question, final_question))
}

// Test-only call counter for `filter_response_for_requester` --
// `prepare_backend_result` only skips this call entirely for a DO=true (or
// non-recursive) oversized response, where filtering would be a no-op; a
// DO=false response always runs it once it's known to be filterable,
// whether or not the unfiltered bytes fit, because for DO=false the
// filtered size has to actually be measured before truncation can be
// decided (see the `exceeds_unfiltered`/`filterable` split above). This
// counter is the only way to prove the DO=true skip is actually happening
// rather than the filter running unconditionally. `#[cfg(test)]`-gated,
// compiled out of release builds.
#[cfg(test)]
thread_local! {
    static FILTER_RESPONSE_FOR_REQUESTER_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_filter_response_for_requester_calls() {
    FILTER_RESPONSE_FOR_REQUESTER_CALLS.with(|calls| calls.set(0));
}

// Test-only call counter for `rebuild_recursive_response_with_own_framing`
// -- `prepare_backend_result`'s two fast paths (DO=false no-op-filter, and
// DO=true) now only pay for this clone-heavy reserialize when
// `recursive_synthesis_reused_own_framing` has actually detected a
// framing mismatch (a coalesced follower whose own EDNS presence/DO/
// question-casing differs from whichever request originally synthesized
// the shared response), not unconditionally on every non-truncated
// recursive-synthesis response. This counter is the only way to prove the
// ordinary, non-coalesced hot path really skips the rebuild rather than
// running it every time. `#[cfg(test)]`-gated, compiled out of release
// builds.
#[cfg(test)]
thread_local! {
    static REBUILD_RECURSIVE_RESPONSE_WITH_OWN_FRAMING_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_rebuild_recursive_response_with_own_framing_calls() {
    REBUILD_RECURSIVE_RESPONSE_WITH_OWN_FRAMING_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn rebuild_recursive_response_with_own_framing_call_count() -> usize {
    REBUILD_RECURSIVE_RESPONSE_WITH_OWN_FRAMING_CALLS.with(|calls| calls.get())
}

#[cfg(test)]
fn filter_response_for_requester_call_count() -> usize {
    FILTER_RESPONSE_FOR_REQUESTER_CALLS.with(|calls| calls.get())
}

/// Applies the *existing* `recursive_response_record_supported` /
/// `recursive_response_authority_supported` predicates (unchanged) to an
/// already-built message's answers/authorities/additionals, for a
/// specific reader's own `dnssec_ok`. Used by `prepare_backend_result` to
/// build a second, client-facing copy of an always-DNSSEC-complete
/// recursive response, trimmed to what the *requesting* client actually
/// asked for -- the same filtering `synthesize_recursive_cname_response`
/// used to do inline before response construction, now applied after the
/// fact so the stored copy can stay complete. Does not handle the OPT
/// record (the predicates never matched `RecordData::OPT`) -- callers
/// must re-append `mirrored_client_opt_record` themselves, same as
/// `synthesize_recursive_cname_response` does.
fn filter_response_for_requester(
    message: &Message,
    dnssec_ok: bool,
    questions: &[&QuestionKey],
) -> (Vec<Record>, Vec<Record>, Vec<Record>) {
    #[cfg(test)]
    FILTER_RESPONSE_FOR_REQUESTER_CALLS.with(|calls| calls.set(calls.get() + 1));

    let answers = message
        .answers
        .iter()
        .filter(|record| recursive_response_record_supported(record, dnssec_ok, questions))
        .cloned()
        .collect();
    let authorities = message
        .authorities
        .iter()
        .filter(|record| recursive_response_authority_supported(record, dnssec_ok, questions))
        .cloned()
        .collect();
    let additionals = message
        .additionals
        .iter()
        .filter(|record| recursive_response_record_supported(record, dnssec_ok, questions))
        .cloned()
        .collect();
    (answers, authorities, additionals)
}

/// Cheap pre-check for whether `filter_response_for_requester(message,
/// false, questions)` would actually remove anything from `message`'s
/// answers/authorities/additionals -- reuses the exact same
/// `recursive_response_record_supported` / `recursive_response_authority_supported`
/// predicates the real filter applies (so this can never classify a record
/// differently than the filter itself would), rather than a scan or two
/// clones of the message content.
///
/// `RecordData::OPT` is skipped: neither predicate ever matches it (it
/// always evaluates to "unsupported"), but the OPT record is invariant to
/// DO=false filtering -- both `synthesize_recursive_cname_response` and
/// `filter_response_for_requester`'s callers re-append a mirrored OPT
/// record unconditionally rather than letting these predicates decide its
/// fate, so it must not count as "filtering would change this".
///
/// Used by `prepare_backend_result` to skip the clone-heavy filter + a
/// second full `serialize_recursive_response` pass entirely on the common
/// no-op case: an unsigned response, or one where the client explicitly
/// asked for the only DNSSEC-type records present, has nothing for
/// filtering to remove, so the already-built `response.bytes` from
/// `synthesize_recursive_cname_response` -- which a DO=false requester
/// would just get straight back if a filter pass ran and changed nothing
/// -- can be reused verbatim instead.
fn filtering_would_change_response(message: &Message, questions: &[&QuestionKey]) -> bool {
    let dnssec_ok = false;
    let is_opt = |record: &&Record| matches!(record.record, RecordData::OPT(_));
    message
        .answers
        .iter()
        .chain(message.additionals.iter())
        .filter(|record| !is_opt(record))
        .any(|record| !recursive_response_record_supported(record, dnssec_ok, questions))
        || message
            .authorities
            .iter()
            .any(|record| !recursive_response_authority_supported(record, dnssec_ok, questions))
}

fn recursive_response_record_supported(
    record: &Record,
    dnssec_ok: bool,
    questions: &[&QuestionKey],
) -> bool {
    match record.record {
        RecordData::A(_)
        | RecordData::AAAA(_)
        | RecordData::CAA { .. }
        | RecordData::CERT { .. }
        | RecordData::CNAME(_)
        | RecordData::MX { .. }
        | RecordData::NS(_)
        | RecordData::PTR(_)
        | RecordData::RP { .. }
        | RecordData::SOA { .. }
        | RecordData::SRV { .. }
        | RecordData::TXT(_) => true,
        RecordData::DNSKEY { .. }
        | RecordData::DS { .. }
        | RecordData::NSEC { .. }
        | RecordData::NSEC3 { .. }
        | RecordData::NSEC3PARAM { .. }
        | RecordData::RRSIG { .. } => dnssec_ok || record_matches_any_question(record, questions),
        RecordData::Unknown { rtype, .. } => dnssec_ok || !is_dnssec_record_type(rtype),
        _ => false,
    }
}

/// Filters records copied into the AUTHORITY section of the client-facing
/// response. Unlike `recursive_response_record_supported` (used for answers
/// and additionals), this excludes `NS` and other non-SOA types: an
/// authoritative server may echo the zone's NS set in its AUTHORITY section
/// alongside a satisfying answer, but that's not useful to a stub client and
/// other recursors (e.g. Cloudflare) omit it. Only SOA (needed for negative
/// caching) and DNSSEC signing records survive.
fn recursive_response_authority_supported(
    record: &Record,
    dnssec_ok: bool,
    questions: &[&QuestionKey],
) -> bool {
    match record.record {
        RecordData::SOA { .. } => true,
        RecordData::DNSKEY { .. }
        | RecordData::DS { .. }
        | RecordData::NSEC { .. }
        | RecordData::NSEC3 { .. }
        | RecordData::NSEC3PARAM { .. }
        | RecordData::RRSIG { .. } => dnssec_ok || record_matches_any_question(record, questions),
        RecordData::Unknown { rtype, .. } => {
            is_dnssec_record_type(rtype)
                && (dnssec_ok || record_matches_any_question(record, questions))
        }
        _ => false,
    }
}

fn is_dnssec_record_type(rtype: u16) -> bool {
    matches!(
        rtype,
        DS_RECORD_TYPE
            | RRSIG_RECORD_TYPE
            | NSEC_RECORD_TYPE
            | DNSKEY_RECORD_TYPE
            | NSEC3_RECORD_TYPE
            | NSEC3PARAM_RECORD_TYPE
            | 59
            | 60
            | 32769
    )
}

fn record_matches_any_question(record: &Record, questions: &[&QuestionKey]) -> bool {
    questions
        .iter()
        .any(|question| QuestionKey::new(&record.name, record.rtype, record.rclass) == **question)
}

fn mirrored_client_opt_record(
    original_query: &Message,
    configured_max_udp_payload_size: usize,
) -> Option<Record> {
    crate::protocol::message_edns_opt_record(original_query, configured_max_udp_payload_size)
}

/// `mirrored_client_opt_record`, plus a fresh RFC 9018 server cookie
/// attached whenever `original_query` carries a well-formed client cookie
/// -- see `crate::protocol::message_edns_opt_record_with_cookie`, which this
/// delegates to.
///
/// Used by every miss-path/recursive-synthesis call site that rebuilds a
/// *specific requester's own* framing (`rebuild_recursive_response_with_own_framing`,
/// `truncated_response_for_query`, and `prepare_backend_result`'s direct
/// DO=false-filtered-response call), all of which run inside
/// `ResolveQuery::prepare_backend_result` and therefore have `self.cookie_secret`,
/// `self.clock`, and `request.client_ip` in scope. Deliberately NOT used by
/// `synthesize_recursive_cname_response` (which keeps calling the plain,
/// cookie-unaware `mirrored_client_opt_record`): that function builds the
/// shared, potentially-coalesced backend response, which has no single
/// requester's client IP to compute a server cookie against, and whose OPT
/// record is never trusted as final once a cookie is in play --
/// `recursive_synthesis_reused_own_framing` forces every cookie-bearing
/// response through this cookie-aware rebuild path downstream regardless.
fn mirrored_client_opt_record_with_cookie(
    original_query: &Message,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Option<Record> {
    crate::protocol::message_edns_opt_record_with_cookie(
        original_query,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    )
}

/// Rebuilds client-facing bytes for a recursive-synthesis response
/// (`response.recursive_synthesis.is_some()`) using *this requester's own*
/// header/echoed-question/OPT, sourced from `decoded.message` -- never
/// from whichever query originally synthesized `response_message` via
/// `synthesize_recursive_cname_response`.
///
/// Used by `prepare_backend_result`'s two "nothing to filter" fast paths
/// (DO=true, and DO=false-but-nothing-DNSSEC-specific-present), both of
/// which used to just reuse `response.bytes`/`response_message`'s own
/// baked-in additionals verbatim (after only rewriting ID/RD/CD). On a
/// coalesced-follower fallback (leader's fetch result wasn't cacheable, or
/// the cache entry didn't land, so there's no fresh cache-hit reassembly
/// to build a follower-specific response from -- see
/// `resolve_coalesced_follower` -> `finish_backend_result` ->
/// `prepare_backend_result`), `response_message`'s OPT reflects
/// `synthesis.original_query`'s own EDNS presence/DO/UDP-bufsize
/// (`synthesize_recursive_cname_response` builds it via
/// `mirrored_client_opt_record(original_query, ...)`), which is whichever
/// request happened to synthesize this particular shared response -- not
/// necessarily this follower's own. `MissKey` coalesces on
/// name/type/class/namespace/DO only, not EDNS presence, UDP payload size,
/// or question-name casing, so a follower's own request can legitimately
/// differ from `synthesis.original_query` on any of those (RFC 6891
/// §6.1.1/§7, RFC 4035 §3.2.1, RFC 1035 §4.1.2).
///
/// `answers`/`authorities` need no content filtering here -- both call
/// sites only reach this function when nothing DNSSEC-specific would be
/// stripped (DO=true keeps everything by construction; DO=false already
/// proved via `filtering_would_change_response` that there's nothing to
/// remove) -- so they're reused by reference straight off
/// `response_message`, with no clone-heavy `filter_response_for_requester`
/// pass. Only `additionals` needs work: any existing `RecordData::OPT` is
/// stripped out (defensively -- `recursive_response_record_supported`
/// already excludes OPT from anything `filter_response_for_requester`
/// would produce, but `response_message.additionals` itself still carries
/// the leader-synthesized OPT verbatim) and a fresh
/// `mirrored_client_opt_record` for *this* requester is appended in its
/// place.
#[allow(clippy::too_many_arguments)]
fn rebuild_recursive_response_with_own_framing(
    decoded: &DecodedQuery,
    response_message: &Message,
    rcode: ResponseCode,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Result<Vec<u8>, ResolutionBackendError> {
    #[cfg(test)]
    REBUILD_RECURSIVE_RESPONSE_WITH_OWN_FRAMING_CALLS.with(|calls| calls.set(calls.get() + 1));

    let mut additionals: Vec<Record> = response_message
        .additionals
        .iter()
        .filter(|record| !matches!(record.record, RecordData::OPT(_)))
        .cloned()
        .collect();
    if let Some(opt) = mirrored_client_opt_record_with_cookie(
        &decoded.message,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    ) {
        additionals.push(opt);
    }
    serialize_recursive_response(
        &decoded.message,
        rcode,
        false,
        &response_message.answers,
        &response_message.authorities,
        &additionals,
    )
}

/// Rebuilds a forward-mode (`ResolutionMode::Forward`) response's OPT
/// record so it carries a fresh, rdns-owned RFC 9018 server cookie tied to
/// *this specific requester's* own client cookie and client IP, instead of
/// trusting whatever cookie (if any) the upstream forwarder's raw response
/// already carries.
///
/// Two things can otherwise go wrong once a Cookie-only query became
/// cache-admissible for the forward backend too (this covers both, per the
/// PR review that caught this gap):
///
/// 1. **Coalesced-follower fallback.** `MissKey` coalesces on
///    name/type/class/namespace/DO only, never on cookie bytes or client
///    IP -- so a follower can share the *leader's* raw forwarded bytes
///    verbatim (`prepare_backend_result`'s callers reuse `response.bytes`
///    for every coalesced requester whose fetch wasn't independently
///    re-run). Without this rebuild, a follower presenting its own client
///    cookie could receive the *leader's* echoed client-cookie bytes back
///    -- a genuine RFC 7873 §5.2 violation (the server must echo the
///    requester's own cookie), not just an imprecise one.
/// 2. **Upstream-computed server cookie.** The forwarding backend relays
///    the client's original query bytes verbatim
///    (`ForwardingResolutionBackend::resolve_once`), so any server cookie
///    the upstream computed is bound to *rdns's own* outbound IP (per RFC
///    9018 §4.4's `Client-IP` input), not this downstream client's --
///    relaying it verbatim would be a foreign resolver's cookie wearing
///    rdns's `CookieSecret`-less clothing.
///
/// Every other byte of the upstream's real response is preserved
/// verbatim -- AA/RA/AD/TC flags, rcode, and all answer/authority/other
/// -additional content -- consistent with forward mode's transparent-proxy
/// contract elsewhere in this file (e.g. `store_authoritative` preserving
/// the forwarder's real AA bit in `prepare_backend_result`). ID/RD/CD are
/// rewritten from `decoded.message`, reproducing what
/// `crate::protocol::rewrite_response_request_fields` already did to
/// `response_bytes` earlier in `prepare_backend_result` -- this function
/// must redo that rewrite itself since it reserializes from
/// `response_message` (parsed from the original bytes, before that
/// byte-level rewrite ran), not from the already-rewritten
/// `response_bytes`.
fn rebuild_forward_response_with_own_cookie(
    decoded: &DecodedQuery,
    response_message: &Message,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Result<Vec<u8>, ResolutionBackendError> {
    let Some(question) = response_message.questions.first() else {
        return Err(ResolutionBackendError::MalformedResponse);
    };

    let mut additionals: Vec<Record> = response_message
        .additionals
        .iter()
        .filter(|record| !matches!(record.record, RecordData::OPT(_)))
        .cloned()
        .collect();
    if let Some(opt) = mirrored_client_opt_record_with_cookie(
        &decoded.message,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    ) {
        additionals.push(opt);
    }

    let mut bytes = Vec::new();
    write_dns_u16(&mut bytes, decoded.message.header.id);
    let mut flags = 0x8000u16; // QR = 1 (response)
    if response_message.header.aa() {
        flags |= 0x0400;
    }
    if response_message.header.tc() {
        flags |= 0x0200;
    }
    if decoded.message.header.rd() {
        flags |= 0x0100;
    }
    if response_message.header.ra() {
        flags |= 0x0080;
    }
    if response_message.header.ad() {
        flags |= 0x0020;
    }
    if decoded.message.header.cd() {
        flags |= 0x0010;
    }
    flags |= u16::from(response_message.header.r_code() & 0x0f);
    write_dns_u16(&mut bytes, flags);
    write_dns_u16(&mut bytes, 1);
    write_dns_u16(&mut bytes, response_message.answers.len() as u16);
    write_dns_u16(&mut bytes, response_message.authorities.len() as u16);
    write_dns_u16(&mut bytes, additionals.len() as u16);
    let mut compressor = NameCompressor::new();
    write_dns_question(
        &mut bytes,
        &mut compressor,
        &question.qname,
        question.qtype,
        question.qclass,
    );
    for record in &response_message.answers {
        write_dns_record(&mut bytes, &mut compressor, record)?;
    }
    for record in &response_message.authorities {
        write_dns_record(&mut bytes, &mut compressor, record)?;
    }
    for record in &additionals {
        write_dns_record(&mut bytes, &mut compressor, record)?;
    }
    Ok(bytes)
}

/// Builds a truncated (TC=1) response for `decoded`'s original query:
/// header + question + a mirrored OPT record (RFC 6891 §7) if the query
/// carried EDNS, no answer/authority/other additional records, and CD
/// copied from the query (RFC 4035 §3.2.2). Used whenever a same-request
/// response exceeds the requester's UDP payload size -- see
/// `local_entry_response` and `prepare_backend_result`, the two call sites
/// this replaced `crate::protocol::build_truncated_response` at (that
/// function wrote a header-only response with no question/OPT/CD at all,
/// which is what Codex's DNS-compliance review flagged).
///
/// Builds on `crate::protocol::build_truncated_wire_response`, the same
/// primitive `cache::assemble::finish_with_truncation_check` uses for the
/// cache-hit truncation path, so the two truncation call sites can't drift
/// out of RFC compliance independently of each other again -- this is the
/// `DecodedQuery`-sourced half (question wire bytes and OPT read straight
/// off the request), mirroring `finish_with_truncation_check`'s
/// `QueryFeatures`-sourced half.
fn truncated_response_for_query(
    decoded: &DecodedQuery,
    response_code: ResponseCode,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Vec<u8> {
    let opt = mirrored_client_opt_record_with_cookie(
        &decoded.message,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    );
    crate::protocol::build_truncated_wire_response(
        decoded.message.header.id,
        decoded.message.header.rd(),
        false, // no resolved backend answer at this point to be authoritative about
        decoded.message.header.cd(),
        response_code,
        &decoded.question_wire,
        opt.as_ref(),
    )
}

/// Whether `decoded`'s own request would already produce byte-identical
/// question-echo and OPT framing to what `synthesis.original_query` (the
/// request that actually synthesized the shared recursive response) baked
/// into it -- i.e. whether this really is the ordinary, non-coalesced
/// path (or a coalesced follower whose own framing happens to exactly
/// match the leader's), where `rebuild_recursive_response_with_own_framing`
/// would just reproduce `response_bytes` byte-for-byte and is pure waste,
/// as opposed to a coalesced follower whose own EDNS presence, DO flag,
/// or question-name casing genuinely differs from whoever synthesized
/// this shared response and therefore needs the rebuild.
///
/// Only two things ever differ between the two requests' framing here:
/// the echoed question (RFC 1035 §4.1.2 requires it be copied back
/// verbatim, including case -- `MissKey` normalizes case away, so
/// coalesced requests can legitimately differ here) and the OPT record
/// (`mirrored_client_opt_record`/`message_edns_opt_record` derive it from
/// only two things about the *request*: whether EDNS is present at all,
/// and the DO flag -- the UDP payload size it writes is this resolver's
/// own configured/effective size, identical across every response
/// regardless of which request is asking, so it never needs comparing
/// here). ID/RD/CD are handled generically and cheaply by the earlier
/// `rewrite_response_request_fields` call in `prepare_backend_result` and
/// don't need rebuilding at all, matching or not.
fn recursive_synthesis_reused_own_framing(
    decoded: &DecodedQuery,
    synthesis: &RecursiveSynthesisContext,
) -> bool {
    let original_query = &synthesis.original_query;

    let question_matches = decoded.message.questions.first() == original_query.questions.first();

    // A server cookie is time-dependent (RFC 9018 §4.4 bakes in a fresh
    // Unix timestamp) and must never be replayed. If either side carries a
    // well-formed client cookie, framing is never considered reused --
    // even when the echoed question and DO bit otherwise match -- forcing
    // a rebuild through `mirrored_client_opt_record_with_cookie` so the
    // cookie actually gets computed instead of silently reusing (or
    // omitting) whichever OPT `synthesize_recursive_cname_response` baked
    // in without cookie awareness.
    let has_cookie = |message: &Message| {
        message.edns.as_ref().is_some_and(|edns| {
            crate::protocol::edns_cookie::parse_cookie_option(&edns.options).is_some()
        })
    };
    if has_cookie(&decoded.message) || has_cookie(original_query) {
        return false;
    }

    let opt_matches = match (decoded.message.edns.as_ref(), original_query.edns.as_ref()) {
        (None, None) => true,
        (Some(this), Some(original)) => this.dnssec_ok == original.dnssec_ok,
        _ => false,
    };

    question_matches && opt_matches
}

/// Final over-the-wire size guard applied to *any* bytes built by a
/// per-requester reserialization pass in `prepare_backend_result`
/// (`rebuild_recursive_response_with_own_framing`'s two call sites, and
/// the DO=false filtered-response `serialize_recursive_response` call).
/// `exceeds_unfiltered`, computed once early in `prepare_backend_result`,
/// only measures the shared/leader-framed `response_bytes` -- *before*
/// any of this requester's own framing is rebuilt in. Appending this
/// requester's own OPT record (see
/// `recursive_synthesis_reused_own_framing`'s doc comment on what can
/// differ) can grow a response that fit under the leader's framing past
/// *this* requester's own UDP payload limit; trusting the stale,
/// pre-rebuild `exceeds_unfiltered` value instead of re-measuring the
/// actual bytes about to be sent would ship an oversized response with
/// TC=0 -- an RFC 6891 §6.2.3/§7 + RFC 1035 §4.1.1 truncation-semantics
/// violation. Both of Codex's independent adversarial reviews (a
/// performance-focused pass and a DNS-compliance-focused pass) flagged
/// this same gap independently.
///
/// `is_udp_response` mirrors the same TCP gate `exceeds_unfiltered`
/// itself uses (`!request.observed_source.is_tcp()`) -- a TCP response is
/// never truncated this way, matching the rest of this function.
#[allow(clippy::too_many_arguments)]
fn enforce_udp_payload_limit_after_reserialize(
    decoded: &DecodedQuery,
    is_udp_response: bool,
    bytes: Vec<u8>,
    rcode: ResponseCode,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Vec<u8> {
    if is_udp_response
        && decoded
            .message
            .response_exceeds_udp_payload(bytes.len(), configured_max_udp_payload_size)
    {
        truncated_response_for_query(
            decoded,
            rcode,
            configured_max_udp_payload_size,
            cookie_secret,
            client_ip,
            now,
        )
    } else {
        bytes
    }
}

fn serialize_recursive_response(
    original_query: &Message,
    rcode: ResponseCode,
    authoritative: bool,
    answers: &[Record],
    authorities: &[Record],
    additionals: &[Record],
) -> Result<Vec<u8>, ResolutionBackendError> {
    let Some(question) = original_query.questions.first() else {
        return Err(ResolutionBackendError::MalformedResponse);
    };

    let mut bytes = Vec::new();
    write_dns_u16(&mut bytes, original_query.header.id);
    let mut flags = 0x8000u16 | 0x0080u16 | rcode as u16;
    if original_query.header.rd() {
        flags |= 0x0100;
    }
    if authoritative {
        flags |= 0x0400;
    }
    // RFC 4035 §3.2.2: a security-aware recursive name server MUST copy
    // the CD (checking disabled) bit from the query to the response, so a
    // validating stub that set CD=1 can tell its request was honored.
    if original_query.header.cd() {
        flags |= 0x0010;
    }
    write_dns_u16(&mut bytes, flags);
    write_dns_u16(&mut bytes, 1);
    write_dns_u16(&mut bytes, answers.len() as u16);
    write_dns_u16(&mut bytes, authorities.len() as u16);
    write_dns_u16(&mut bytes, additionals.len() as u16);
    let mut compressor = NameCompressor::new();
    write_dns_question(
        &mut bytes,
        &mut compressor,
        &question.qname,
        question.qtype,
        question.qclass,
    );
    for record in answers {
        write_dns_record(&mut bytes, &mut compressor, record)?;
    }
    for record in authorities {
        write_dns_record(&mut bytes, &mut compressor, record)?;
    }
    for record in additionals {
        write_dns_record(&mut bytes, &mut compressor, record)?;
    }
    Ok(bytes)
}

fn write_dns_question(
    bytes: &mut Vec<u8>,
    compressor: &mut NameCompressor,
    name: &str,
    qtype: u16,
    qclass: u16,
) {
    compressor.write_name(bytes, name);
    write_dns_u16(bytes, qtype);
    write_dns_u16(bytes, qclass);
}

fn write_dns_record(
    bytes: &mut Vec<u8>,
    compressor: &mut NameCompressor,
    record: &Record,
) -> Result<(), ResolutionBackendError> {
    compressor.write_name(bytes, &record.name);
    write_dns_u16(bytes, record.rtype);
    write_dns_u16(bytes, record.rclass);
    write_dns_u32(bytes, record.ttl);
    let rdlength_index = bytes.len();
    write_dns_u16(bytes, 0);
    let rdata_start = bytes.len();
    match &record.record {
        RecordData::A(address) => bytes.extend_from_slice(&address.octets()),
        RecordData::AAAA(address) => bytes.extend_from_slice(&address.octets()),
        RecordData::CAA { flags, tag, value } => {
            if tag.len() > u8::MAX as usize {
                return Err(ResolutionBackendError::MalformedResponse);
            }
            bytes.push(*flags);
            bytes.push(tag.len() as u8);
            bytes.extend_from_slice(tag.as_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        RecordData::CERT {
            cert_type,
            key_tag,
            algorithm,
            cert,
        } => {
            write_dns_u16(bytes, *cert_type);
            write_dns_u16(bytes, *key_tag);
            bytes.push(*algorithm);
            bytes.extend_from_slice(cert);
        }
        RecordData::CNAME(name) | RecordData::NS(name) => compressor.write_name(bytes, name),
        RecordData::MX {
            preference,
            exchange,
        } => {
            write_dns_u16(bytes, *preference);
            compressor.write_name(bytes, exchange);
        }
        RecordData::DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
        } => {
            write_dns_u16(bytes, *flags);
            bytes.push(*protocol);
            bytes.push(*algorithm);
            bytes.extend_from_slice(public_key);
        }
        RecordData::DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            write_dns_u16(bytes, *key_tag);
            bytes.push(*algorithm);
            bytes.push(*digest_type);
            bytes.extend_from_slice(digest);
        }
        RecordData::NSEC {
            next_domain,
            type_bit_maps,
        } => {
            // RFC 4034 §4.1.1: MUST NOT compress the Next Domain Name field.
            write_dns_name(bytes, next_domain);
            bytes.extend_from_slice(type_bit_maps);
        }
        RecordData::NSEC3 {
            hash_algorithm,
            flags,
            iterations,
            salt_length,
            salt,
            hash_length,
            next_domain,
            type_bit_maps,
        } => {
            bytes.push(*hash_algorithm);
            bytes.push(*flags);
            write_dns_u16(bytes, *iterations);
            bytes.push(*salt_length);
            bytes.extend_from_slice(salt);
            bytes.push(*hash_length);
            write_hex_bytes(bytes, next_domain)?;
            bytes.extend_from_slice(type_bit_maps);
        }
        RecordData::NSEC3PARAM {
            hash_algorithm,
            flags,
            iterations,
            salt_length,
            salt,
        } => {
            bytes.push(*hash_algorithm);
            bytes.push(*flags);
            write_dns_u16(bytes, *iterations);
            bytes.push(*salt_length);
            bytes.extend_from_slice(salt);
        }
        RecordData::PTR(name) => compressor.write_name(bytes, name),
        RecordData::RP {
            mboxdname,
            txtdname,
        } => {
            // RFC 3597 §4: RP isn't an RFC 1035 well-known type, so its
            // embedded names must not be compressed when writing.
            write_dns_name(bytes, mboxdname);
            write_dns_name(bytes, txtdname);
        }
        RecordData::SOA {
            ttl: _,
            rname,
            mname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            compressor.write_name(bytes, mname);
            compressor.write_name(bytes, rname);
            write_dns_u32(bytes, *serial);
            write_dns_u32(bytes, *refresh);
            write_dns_u32(bytes, *retry);
            write_dns_u32(bytes, *expire);
            write_dns_u32(bytes, *minimum);
        }
        RecordData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            write_dns_u16(bytes, *priority);
            write_dns_u16(bytes, *weight);
            write_dns_u16(bytes, *port);
            // RFC 2782: "name compression is not to be used for this field."
            write_dns_name(bytes, target);
        }
        RecordData::TXT(text) => {
            for chunk in text.as_bytes().chunks(255) {
                bytes.push(chunk.len() as u8);
                bytes.extend_from_slice(chunk);
            }
        }
        RecordData::RRSIG {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        } => {
            write_dns_u16(bytes, *type_covered);
            bytes.push(*algorithm);
            bytes.push(*labels);
            write_dns_u32(bytes, *original_ttl);
            write_dns_u32(bytes, *signature_expiration);
            write_dns_u32(bytes, *signature_inception);
            write_dns_u16(bytes, *key_tag);
            // RFC 4034 §3.1.7: MUST NOT compress the Signer's Name field.
            // Confirmed against Cloudflare's production authoritative
            // servers: a raw DO-bit query for the DNSSEC-signed
            // cloudflare.com zone (sent directly to ns3.cloudflare.com)
            // shows every RRSIG's owner name compressed back to the
            // question (0xC00C), but the Signer's Name field spelled out
            // in full even though it repeats that same "cloudflare.com"
            // suffix already written earlier in the message.
            write_dns_name(bytes, signer_name);
            bytes.extend_from_slice(signature);
        }
        RecordData::OPT(info) => {
            bytes.extend_from_slice(&info.options);
        }
        RecordData::Unknown { rtype, bytes: data } if *rtype == record.rtype => {
            bytes.extend_from_slice(data);
        }
        _ => return Err(ResolutionBackendError::MalformedResponse),
    }
    let rdlength = bytes.len() - rdata_start;
    if rdlength > u16::MAX as usize {
        return Err(ResolutionBackendError::MalformedResponse);
    }
    bytes[rdlength_index..rdlength_index + 2].copy_from_slice(&(rdlength as u16).to_be_bytes());
    Ok(())
}

fn write_dns_name(bytes: &mut Vec<u8>, name: &str) {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        bytes.push(0);
        return;
    }
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
}

fn write_dns_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn write_dns_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn write_hex_bytes(bytes: &mut Vec<u8>, hex: &str) -> Result<(), ResolutionBackendError> {
    if !hex.len().is_multiple_of(2) {
        return Err(ResolutionBackendError::MalformedResponse);
    }
    let mut chars = hex.as_bytes().chunks_exact(2);
    for chunk in &mut chars {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(())
}

fn hex_nibble(byte: u8) -> Result<u8, ResolutionBackendError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ResolutionBackendError::MalformedResponse),
    }
}

/// Applies the configured floor/ceiling to a response-derived TTL. A TTL of
/// exactly 0 is exempt from the floor: RFC 1035 §3.2.1 (and RFC 2308 §5 for
/// negative answers) defines TTL 0 as "this transaction only", so a
/// configured `min_positive_ttl`/`min_negative_ttl` must not resurrect it
/// into a cacheable lifetime — flooring it would keep transaction-only data
/// servable (at wire TTL 0) until the floor expired, and would sidestep the
/// serve-stale TTL-0 eviction guard, which only sees entries *after* expiry
/// (PR #142 review finding). Left at 0, the entry expires at store time and
/// the first lookup evicts it.
fn apply_ttl_bounds(ttl: Duration, min_ttl: Option<Duration>, max_ttl: Duration) -> Duration {
    let capped = ttl.min(max_ttl);
    if ttl.is_zero() {
        return capped;
    }
    match min_ttl {
        Some(min_ttl) => capped.max(min_ttl).min(max_ttl),
        None => capped,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionRequest {
    pub query: DecodedQuery,
    pub backend_generation: u64,
}

/// The exact `original_query` message and `(original_question,
/// final_question)` pair `synthesize_recursive_cname_response` used to
/// build a recursive response's stored/full message. Retained so
/// `prepare_backend_result` can build a second, requester-DO-filtered
/// copy of the response bytes (via `filter_response_for_requester`) using
/// the *same* inputs the initial synthesis used, rather than re-deriving
/// them incorrectly from the already-synthesized message (see
/// `ResolutionResponse::final_question`, which is a different value --
/// derived from the synthesized message itself, not the terminal
/// post-CNAME question). Only populated for recursive-backend responses;
/// the forwarding backend doesn't go through
/// `synthesize_recursive_cname_response` and has no equivalent filter
/// step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecursiveSynthesisContext {
    pub(crate) original_query: Message,
    pub(crate) original_question: QuestionKey,
    pub(crate) final_question: QuestionKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionResponse {
    /// The backend response wire bytes. `Bytes` rather than `Vec<u8>` so
    /// the transport layer can share one allocation between this field and
    /// `response_message.original_bytes`, and so cloning a
    /// `ResolutionResponse` (single-flight leader/follower handoff) bumps a
    /// refcount instead of copying the payload.
    pub bytes: Bytes,
    pub received_at: SystemTime,
    response_message: Option<Message>,
    pub response_code: Option<ResponseCode>,
    pub final_question: Option<QuestionKey>,
    pub canonical_chain: Vec<String>,
    pub negative_cache: Option<NegativeCacheMetadata>,
    pub source_credibility: SourceCredibility,
    pub backend_provenance: BackendProvenance,
    pub cache_directive: ResolutionCacheDirective,
    recursive_synthesis: Option<RecursiveSynthesisContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionBackendError {
    Timeout,
    MalformedResponse,
    QuestionMismatch,
    NoBackendsAvailable,
    #[deprecated(note = "use NoBackendsAvailable for backend-agnostic resolution failures")]
    NoUpstreamsAvailable,
    Transport(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ResolutionMode {
    Forward,
    Recursive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BackendHealth {
    Healthy,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DnssecValidationStatus {
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendStatus {
    pub mode: ResolutionMode,
    pub generation: u64,
    pub health: BackendHealth,
    pub dnssec_validation: DnssecValidationStatus,
    pub cache_namespace: Option<String>,
    pub root_hints: Option<BackendRootHintsStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRootHintsStatus {
    pub source: String,
    pub version: String,
    pub loaded_at: SystemTime,
}

impl BackendRootHintsStatus {
    pub fn loaded(
        source: impl Into<String>,
        version: impl Into<String>,
        loaded_at: SystemTime,
    ) -> Self {
        Self {
            source: source.into(),
            version: version.into(),
            loaded_at,
        }
    }

    pub fn age_at(&self, now: SystemTime) -> Option<Duration> {
        now.duration_since(self.loaded_at).ok()
    }
}

#[derive(Clone)]
pub struct BackendSnapshot {
    pub backend: Arc<dyn ResolutionBackend>,
    pub mode: ResolutionMode,
    pub generation: u64,
    pub health: BackendHealth,
    pub dnssec_validation: DnssecValidationStatus,
    /// Descriptive fingerprint of resolution-affecting config
    /// (`Config::backend_cache_namespace`), kept for operator-facing
    /// status/event output (`BackendStatus`/`QueryEventBackend`) and to
    /// detect, at reload time, whether the cache's own `cache_epoch` needs
    /// to bump (see `next_cache_epoch`). No longer threaded into per-entry
    /// cache storage — that's `cache_epoch` below.
    pub cache_namespace: Option<String>,
    /// The cache-identity epoch actually stamped onto cache entries and
    /// compared at lookup/sweep time (`DomainDnsCache::lookup_chain`/
    /// `store_response`/`sweep_stale_namespace`). Always a real value (not
    /// optional, unlike `cache_namespace`): a fresh snapshot starts at `0`,
    /// and `next_cache_epoch` bumps it by exactly 1 whenever
    /// `cache_namespace` actually changes from the previous published
    /// snapshot — see `ResolveQuery::publish_reload`/
    /// `publish_backend_snapshot`, the only two places that mutate it.
    pub cache_epoch: u64,
    pub root_hints: Option<BackendRootHintsStatus>,
}

impl BackendSnapshot {
    /// Every freshly-constructed snapshot starts at `cache_epoch: 0`,
    /// regardless of `generation` or `cache_namespace` — the epoch carries
    /// no content-derived uniqueness of its own; only `next_cache_epoch`,
    /// called from `publish_reload`/`publish_backend_snapshot` relative to
    /// a *previously-published* snapshot, ever bumps it. This is safe only
    /// because production has exactly one long-lived `ResolveQuery`
    /// backed by one `ShardedDnsCache`, so "backend changed" is always
    /// observed by comparing against that one instance's own previous
    /// snapshot (see `main.rs`'s single `ShardedDnsCache::new` /
    /// `ResolveQuery::with_cache_policy_and_backend_snapshot` call sites).
    /// Two independently-constructed `BackendSnapshot`s that were never
    /// linked through that same `ResolveQuery` both start at epoch 0 and
    /// would collide if made to share one cache — see
    /// `backend_generation_separates_cache_entries`'s doc comment for the
    /// regression test covering this distinction.
    pub fn new(
        backend: Arc<dyn ResolutionBackend>,
        mode: ResolutionMode,
        generation: u64,
        health: BackendHealth,
        cache_namespace: Option<String>,
    ) -> Self {
        Self {
            backend,
            mode,
            generation,
            health,
            dnssec_validation: DnssecValidationStatus::Disabled,
            cache_namespace,
            cache_epoch: 0,
            root_hints: None,
        }
    }

    pub fn with_root_hints_status(mut self, root_hints: BackendRootHintsStatus) -> Self {
        self.root_hints = Some(root_hints);
        self
    }

    pub fn status(&self) -> BackendStatus {
        BackendStatus {
            mode: self.mode,
            generation: self.generation,
            health: self.health,
            dnssec_validation: self.dnssec_validation,
            cache_namespace: self.cache_namespace.clone(),
            root_hints: self.root_hints.clone(),
        }
    }

    fn forwarding(backend: Arc<dyn ResolutionBackend>, generation: u64) -> Self {
        Self::new(
            backend,
            ResolutionMode::Forward,
            generation,
            BackendHealth::Healthy,
            backend_cache_namespace(ResolutionMode::Forward, generation),
        )
    }
}

/// The cache epoch `new_snapshot` should publish under, given the
/// previously-published snapshot: unchanged if `new_snapshot.cache_namespace`
/// matches `previous`'s (an unrelated reload leaves every existing cache
/// entry's epoch matching, so the sweep can be skipped entirely — see
/// callers), or `previous.cache_epoch.wrapping_add(1)` if the descriptive
/// fingerprint actually changed. Wrapping, not checked/saturating, is
/// deliberate: a `u64` only wraps after ~1.8e19 reloads, which is not a
/// reachable count for a long-lived process reloaded on SIGHUP, so treating
/// overflow as an error case would add handling for something that cannot
/// occur in practice. Shared by `publish_reload` and `publish_backend_snapshot`
/// so both publishers apply the exact same cache-identity semantics — the
/// single-flight-only publisher must never let a caller-supplied
/// `BackendSnapshot`'s default `cache_epoch: 0` silently roll the epoch
/// backwards.
fn next_cache_epoch(previous: &BackendSnapshot, new_snapshot: &BackendSnapshot) -> u64 {
    if previous.cache_namespace == new_snapshot.cache_namespace {
        previous.cache_epoch
    } else {
        previous.cache_epoch.wrapping_add(1)
    }
}

#[derive(Clone)]
pub struct BackendHandle {
    snapshot: Arc<RwLock<Arc<BackendSnapshot>>>,
}

impl BackendHandle {
    pub fn new(snapshot: BackendSnapshot) -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(snapshot))),
        }
    }

    pub fn current(&self) -> Arc<BackendSnapshot> {
        let snapshot = self
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(&snapshot)
    }

    pub fn status(&self) -> BackendStatus {
        self.current().status()
    }

    fn publish(&self, snapshot: BackendSnapshot) {
        let mut current = self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = Arc::new(snapshot);
    }
}

#[derive(Clone)]
pub struct LocalDnsEntriesHandle {
    entries: Arc<RwLock<Arc<dyn LocalDnsEntries>>>,
}

impl LocalDnsEntriesHandle {
    pub fn new(entries: Arc<dyn LocalDnsEntries>) -> Self {
        Self {
            entries: Arc::new(RwLock::new(entries)),
        }
    }

    pub fn current(&self) -> Arc<dyn LocalDnsEntries> {
        let entries = self
            .entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(&entries)
    }

    pub fn publish(&self, entries: Arc<dyn LocalDnsEntries>) {
        let mut current = self
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = entries;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCredibility {
    ForwarderValidated,
    Authoritative,
    InsecureReferral,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendProvenance {
    pub mode: ResolutionMode,
    pub generation: u64,
    pub backend_name: Option<String>,
}

impl BackendProvenance {
    pub fn forwarding(generation: u64, backend_name: impl Into<String>) -> Self {
        Self {
            mode: ResolutionMode::Forward,
            generation,
            backend_name: Some(backend_name.into()),
        }
    }

    pub fn recursive(generation: u64, backend_name: impl Into<String>) -> Self {
        Self {
            mode: ResolutionMode::Recursive,
            generation,
            backend_name: Some(backend_name.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionCacheDirective {
    Cacheable,
    DoNotCache(ResolutionNoCacheReason),
}

impl ResolutionCacheDirective {
    fn is_cacheable(&self) -> bool {
        matches!(self, Self::Cacheable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionNoCacheReason {
    BackendPolicy,
    UnsupportedResponseSemantics,
    ValidationIncomplete,
}

impl ResolutionResponse {
    pub fn forwarded_bytes(
        bytes: impl Into<Bytes>,
        received_at: SystemTime,
        backend_generation: u64,
        backend_name: impl Into<String>,
    ) -> Self {
        let bytes = bytes.into();
        let backend_name = backend_name.into();
        match Message::parse(&bytes) {
            Ok(message) => Self::forwarded_parsed_bytes(
                bytes,
                message,
                received_at,
                backend_generation,
                backend_name,
            ),
            Err(_) => {
                Self::unparsed_forwarded_bytes(bytes, received_at, backend_generation, backend_name)
            }
        }
    }

    pub(crate) fn forwarded_message(
        bytes: impl Into<Bytes>,
        response_message: Message,
        received_at: SystemTime,
        backend_generation: u64,
        backend_name: impl Into<String>,
    ) -> Self {
        let bytes = bytes.into();
        let backend_name = backend_name.into();
        if !same_bytes(&response_message.original_bytes, &bytes) {
            return Self::forwarded_bytes(bytes, received_at, backend_generation, backend_name);
        }
        Self::forwarded_parsed_bytes(
            bytes,
            response_message,
            received_at,
            backend_generation,
            backend_name,
        )
    }

    fn forwarded_parsed_bytes(
        bytes: Bytes,
        response_message: Message,
        received_at: SystemTime,
        backend_generation: u64,
        backend_name: impl Into<String>,
    ) -> Self {
        let response_code = response_code(&response_message);
        let final_question = QuestionKey::from_message(&response_message);
        let canonical_chain = canonical_chain_from_response(&response_message);
        let negative_cache = negative_ttl(&response_message);
        Self {
            bytes,
            received_at,
            response_message: Some(response_message),
            response_code,
            final_question,
            canonical_chain,
            negative_cache,
            source_credibility: SourceCredibility::ForwarderValidated,
            backend_provenance: BackendProvenance::forwarding(backend_generation, backend_name),
            cache_directive: ResolutionCacheDirective::Cacheable,
            recursive_synthesis: None,
        }
    }

    fn unparsed_forwarded_bytes(
        bytes: Bytes,
        received_at: SystemTime,
        backend_generation: u64,
        backend_name: impl Into<String>,
    ) -> Self {
        Self {
            bytes,
            received_at,
            response_message: None,
            response_code: None,
            final_question: None,
            canonical_chain: Vec::new(),
            negative_cache: None,
            source_credibility: SourceCredibility::ForwarderValidated,
            backend_provenance: BackendProvenance::forwarding(backend_generation, backend_name),
            cache_directive: ResolutionCacheDirective::DoNotCache(
                ResolutionNoCacheReason::ValidationIncomplete,
            ),
            recursive_synthesis: None,
        }
    }

    pub(crate) fn recursive_response(
        original_query: &DecodedQuery,
        authority_response: RecursiveAuthorityResponse,
        cname_chain: &[Record],
        received_at: SystemTime,
        backend_generation: u64,
        authority: SocketAddr,
        configured_max_udp_payload_size: usize,
    ) -> Result<Self, ResolutionBackendError> {
        let (response_message, synthesis_original_question, synthesis_final_question) =
            synthesize_recursive_cname_response(
                &original_query.message,
                cname_chain,
                &authority_response.message,
                configured_max_udp_payload_size,
            )?;
        let bytes = response_message.original_bytes.clone();
        let response_code = response_code(&response_message);
        let final_question = QuestionKey::from_message(&response_message);
        let canonical_chain = canonical_chain_from_response(&response_message);
        let negative_cache = negative_ttl(&response_message);
        let recursive_synthesis = Some(RecursiveSynthesisContext {
            original_query: original_query.message.clone(),
            original_question: synthesis_original_question,
            final_question: synthesis_final_question,
        });
        Ok(Self {
            bytes,
            received_at,
            response_message: Some(response_message),
            response_code,
            final_question,
            canonical_chain,
            negative_cache,
            source_credibility: SourceCredibility::Authoritative,
            backend_provenance: BackendProvenance::recursive(
                backend_generation,
                format!("authority:{authority}"),
            ),
            cache_directive: ResolutionCacheDirective::Cacheable,
            recursive_synthesis,
        })
    }

    pub fn answers(&self) -> &[Record] {
        self.response_message
            .as_ref()
            .map(|message| message.answers.as_slice())
            .unwrap_or_default()
    }

    pub fn response_message(&self) -> Option<&Message> {
        self.response_message.as_ref()
    }

    pub fn authorities(&self) -> &[Record] {
        self.response_message
            .as_ref()
            .map(|message| message.authorities.as_slice())
            .unwrap_or_default()
    }

    pub fn additionals(&self) -> &[Record] {
        self.response_message
            .as_ref()
            .map(|message| message.additionals.as_slice())
            .unwrap_or_default()
    }
}

pub type UpstreamRequest = ResolutionRequest;
pub type UpstreamResponse = ResolutionResponse;
pub type UpstreamError = ResolutionBackendError;

fn canonical_chain_from_response(response: &Message) -> Vec<String> {
    response
        .answers
        .iter()
        .filter_map(|record| {
            if let RecordData::CNAME(cname) = &record.record {
                Some(normalize_question_name(cname))
            } else {
                None
            }
        })
        .collect()
}

fn response_policy_domains(response: &Message) -> impl Iterator<Item = DomainName> + '_ {
    response.answers.iter().flat_map(|record| {
        let owner = DomainName::parse(&record.name).ok();
        let target = match &record.record {
            RecordData::CNAME(target) => DomainName::parse(target).ok(),
            _ => None,
        };
        owner.into_iter().chain(target)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveDecisionKind {
    Allowed,
    Blocked(PolicyBlock),
    LocalAnswer(LocalAnswerMetadata),
    /// A synthetic CHAOS-class answer (currently only `version.bind. CH
    /// TXT`) served from `[chaos]` config -- see
    /// `ResolveQuery::try_chaos_lookup`.
    ChaosAnswer,
    CacheHit,
    CacheMiss,
    ProtocolError(ResponseCode),
    BackendFailure,
    /// RFC 1035 §4.1.1: RD=0 asks rdns not to pursue the query on the
    /// client's behalf. rdns still answers from local entries and from
    /// cache (that's data it already has, not new work), but a genuine
    /// cache miss under RD=0 is refused with SERVFAIL rather than
    /// triggering a fresh upstream fetch or recursive resolution --
    /// matching how a public recursive resolver like 1.1.1.1 treats RD=0
    /// as "cache-only".
    RecursionRefused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveDecision {
    pub client_ip: IpAddr,
    pub question: Option<QuestionKey>,
    pub kind: ResolveDecisionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryEventV1 {
    pub schema_version: u8,
    pub sequence: u64,
    /// DNS wire transaction ID for this query, threaded through from
    /// `ResolveRequest::request_id` so this event's log line can be
    /// correlated with anything else recorded against the same request.
    pub request_id: Option<u16>,
    pub timestamp: SystemTime,
    pub observed_source: ObservedSourceEndpoint,
    pub original_question_name: Option<String>,
    pub normalized_question: Option<QuestionKey>,
    pub qtype: Option<u16>,
    pub qclass: Option<u16>,
    pub terminal_outcome: QueryEventOutcome,
    pub block_response_mode: Option<BlockResponseMode>,
    pub local_answer: Option<LocalAnswerMetadata>,
    pub response_code: Option<u16>,
    pub cache_result: Option<QueryEventCacheResult>,
    pub backend: Option<QueryEventBackend>,
    pub latency: Option<Duration>,
    pub advisory_findings: Vec<QueryEventClassifierFinding>,
}

impl QueryEventV1 {
    // v6: `cache_result` gained the `Stale` value (RFC 8767 serve-stale) —
    // bumped so strict consumers validating the v5 enum get a version
    // signal instead of an unexpected variant.
    pub const SCHEMA_VERSION: u8 = 6;

    #[allow(clippy::too_many_arguments)]
    pub fn from_decision(
        sequence: u64,
        request_id: Option<u16>,
        timestamp: SystemTime,
        decision: &ResolveDecision,
        response_code: Option<u16>,
        cache_result: Option<QueryEventCacheResult>,
        latency: Option<Duration>,
    ) -> Self {
        Self::from_decision_context(
            sequence,
            request_id,
            timestamp,
            ObservedSourceEndpoint::ip(decision.client_ip),
            None,
            decision,
            response_code,
            cache_result,
            latency,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_decision_context(
        sequence: u64,
        request_id: Option<u16>,
        timestamp: SystemTime,
        observed_source: ObservedSourceEndpoint,
        original_question_name: Option<String>,
        decision: &ResolveDecision,
        response_code: Option<u16>,
        cache_result: Option<QueryEventCacheResult>,
        latency: Option<Duration>,
    ) -> Self {
        let normalized_question = decision.question.clone();
        Self {
            schema_version: Self::SCHEMA_VERSION,
            sequence,
            request_id,
            timestamp,
            observed_source,
            original_question_name,
            qtype: normalized_question.as_ref().map(|question| question.qtype),
            qclass: normalized_question.as_ref().map(|question| question.qclass),
            normalized_question,
            terminal_outcome: QueryEventOutcome::from_decision_kind(&decision.kind),
            block_response_mode: None,
            local_answer: local_answer_metadata(&decision.kind),
            response_code,
            cache_result,
            backend: None,
            latency,
            advisory_findings: Vec::new(),
        }
    }
}

fn local_answer_metadata(kind: &ResolveDecisionKind) -> Option<LocalAnswerMetadata> {
    match kind {
        ResolveDecisionKind::LocalAnswer(metadata) => Some(metadata.clone()),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryEventBackend {
    pub mode: ResolutionMode,
    pub generation: u64,
    pub health: BackendHealth,
    pub cache_namespace: Option<String>,
    pub dnssec_validation: DnssecValidationStatus,
}

impl QueryEventBackend {
    fn from_snapshot(snapshot: &BackendSnapshot) -> Self {
        Self {
            mode: snapshot.mode,
            generation: snapshot.generation,
            health: snapshot.health,
            cache_namespace: snapshot.cache_namespace.clone(),
            dnssec_validation: snapshot.dnssec_validation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum QueryEventOutcome {
    AllowedFromBackend,
    AllowedFromLocal,
    AllowedFromCache,
    Blocked(BlockReason),
    ProtocolError(ResponseCode),
    BackendFailure,
    RecursionRefused,
}

impl QueryEventOutcome {
    fn from_decision_kind(kind: &ResolveDecisionKind) -> Self {
        match kind {
            ResolveDecisionKind::Allowed => Self::AllowedFromBackend,
            ResolveDecisionKind::Blocked(block) => Self::Blocked(block.reason.clone()),
            ResolveDecisionKind::LocalAnswer(_) => Self::AllowedFromLocal,
            ResolveDecisionKind::ChaosAnswer => Self::AllowedFromLocal,
            ResolveDecisionKind::CacheHit => Self::AllowedFromCache,
            ResolveDecisionKind::CacheMiss => Self::AllowedFromBackend,
            ResolveDecisionKind::ProtocolError(code) => Self::ProtocolError(*code),
            ResolveDecisionKind::BackendFailure => Self::BackendFailure,
            ResolveDecisionKind::RecursionRefused => Self::RecursionRefused,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum QueryEventCacheResult {
    Hit,
    /// A hit that served at least one expired entry under RFC 8767
    /// serve-stale. (A background refresh is *typically* signaled too, but
    /// not guaranteed — the enqueue is best-effort and some paths drop
    /// hints; see `docs/knowledge/resolver/caching/serve-stale.md`.)
    Stale,
    Miss,
    Expired,
    Bypass,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryEventClassifierFinding {
    pub classifier_version: String,
    pub config_generation: u64,
    pub reason: QueryEventClassifierReason,
    pub severity: QueryEventClassifierSeverity,
    pub score: u8,
    pub evaluated_window: QueryEventClassifierWindow,
    pub details: Vec<QueryEventClassifierDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum QueryEventClassifierReason {
    NxdomainBurst,
    ServfailBurst,
    HighEntropyName,
    RepeatedTxtLookup,
    RareDomain,
    NewDomain,
    SuspiciousSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum QueryEventClassifierSeverity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryEventClassifierWindow {
    pub started_at: SystemTime,
    pub ended_at: SystemTime,
    pub retained_event_count: usize,
    pub incomplete_reasons: Vec<QueryEventClassifierWindowIncompleteReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum QueryEventClassifierWindowIncompleteReason {
    ColdStart,
    RetentionEviction,
    SampledEvents,
    DroppedEvents,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryEventClassifierDetail {
    pub key: String,
    pub value: String,
}

pub struct SuspiciousLookupClassifierInput<'a> {
    pub event: &'a QueryEventV1,
    pub retained_events: &'a [Arc<QueryEventV1>],
    pub window: QueryEventClassifierWindow,
}

pub trait SuspiciousLookupClassifier: Send + Sync {
    fn classify(
        &self,
        input: SuspiciousLookupClassifierInput<'_>,
    ) -> Vec<QueryEventClassifierFinding>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoopSuspiciousLookupClassifier {
    pub classifier_version: String,
    pub config_generation: u64,
}

impl NoopSuspiciousLookupClassifier {
    pub fn new(classifier_version: impl Into<String>, config_generation: u64) -> Self {
        Self {
            classifier_version: classifier_version.into(),
            config_generation,
        }
    }
}

impl SuspiciousLookupClassifier for NoopSuspiciousLookupClassifier {
    fn classify(
        &self,
        _input: SuspiciousLookupClassifierInput<'_>,
    ) -> Vec<QueryEventClassifierFinding> {
        Vec::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemorySuspiciousLookupClassifierConfig {
    pub classifier_version: String,
    pub config_generation: u64,
    pub nxdomain_burst_threshold: usize,
    pub servfail_burst_threshold: usize,
    pub repeated_txt_threshold: usize,
    pub burst_window: Duration,
    pub repeated_txt_window: Duration,
    pub baseline_complete_after_events: usize,
    pub enable_domain_frequency_findings: bool,
    pub rare_domain_threshold: usize,
    pub high_entropy_min_label_len: usize,
    pub high_entropy_score_threshold: u8,
    pub suspicious_tlds: Vec<String>,
    pub suspicious_domains: Vec<String>,
}

impl Default for InMemorySuspiciousLookupClassifierConfig {
    fn default() -> Self {
        Self {
            classifier_version: "in-memory-heuristics-v1".to_string(),
            config_generation: 0,
            nxdomain_burst_threshold: 5,
            servfail_burst_threshold: 5,
            repeated_txt_threshold: 5,
            burst_window: Duration::from_secs(60),
            repeated_txt_window: Duration::from_secs(60),
            baseline_complete_after_events: 100,
            enable_domain_frequency_findings: false,
            rare_domain_threshold: 2,
            high_entropy_min_label_len: 12,
            high_entropy_score_threshold: 70,
            suspicious_tlds: Vec::new(),
            suspicious_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemorySuspiciousLookupClassifier {
    config: InMemorySuspiciousLookupClassifierConfig,
    suspicious_tlds: Vec<String>,
    suspicious_domains: Vec<String>,
}

impl InMemorySuspiciousLookupClassifier {
    pub fn new(config: InMemorySuspiciousLookupClassifierConfig) -> Self {
        let suspicious_tlds = config
            .suspicious_tlds
            .iter()
            .map(|tld| {
                normalize_question_name(tld)
                    .trim_start_matches('.')
                    .to_string()
            })
            .collect();
        let suspicious_domains = config
            .suspicious_domains
            .iter()
            .map(|domain| {
                normalize_question_name(domain)
                    .trim_start_matches('.')
                    .to_string()
            })
            .collect();
        Self {
            config,
            suspicious_tlds,
            suspicious_domains,
        }
    }
}

impl SuspiciousLookupClassifier for InMemorySuspiciousLookupClassifier {
    fn classify(
        &self,
        input: SuspiciousLookupClassifierInput<'_>,
    ) -> Vec<QueryEventClassifierFinding> {
        let Some(question) = input.event.normalized_question.as_ref() else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        self.classify_response_bursts(&input, &mut findings);
        self.classify_repeated_txt(&input, &mut findings);
        self.classify_high_entropy_name(question, &input, &mut findings);
        self.classify_domain_frequency(question, &input, &mut findings);
        self.classify_suspicious_selectors(question, &input, &mut findings);
        findings
    }
}

impl InMemorySuspiciousLookupClassifier {
    fn classify_response_bursts(
        &self,
        input: &SuspiciousLookupClassifierInput<'_>,
        findings: &mut Vec<QueryEventClassifierFinding>,
    ) {
        if input.event.response_code == Some(ResponseCode::NxDomain as u16) {
            let count = count_source_response_code(
                input.retained_events,
                &input.event.observed_source,
                ResponseCode::NxDomain as u16,
                input.event.timestamp,
                self.config.burst_window,
            );
            if count >= self.config.nxdomain_burst_threshold {
                findings.push(self.finding(
                    QueryEventClassifierReason::NxdomainBurst,
                    QueryEventClassifierSeverity::Medium,
                    70,
                    input,
                    vec![
                        detail("source_response_count", count),
                        detail("threshold", self.config.nxdomain_burst_threshold),
                    ],
                ));
            }
        }

        if input.event.response_code == Some(ResponseCode::ServFail as u16) {
            let count = count_source_response_code(
                input.retained_events,
                &input.event.observed_source,
                ResponseCode::ServFail as u16,
                input.event.timestamp,
                self.config.burst_window,
            );
            if count >= self.config.servfail_burst_threshold {
                findings.push(self.finding(
                    QueryEventClassifierReason::ServfailBurst,
                    QueryEventClassifierSeverity::Medium,
                    65,
                    input,
                    vec![
                        detail("source_response_count", count),
                        detail("threshold", self.config.servfail_burst_threshold),
                    ],
                ));
            }
        }
    }

    fn classify_repeated_txt(
        &self,
        input: &SuspiciousLookupClassifierInput<'_>,
        findings: &mut Vec<QueryEventClassifierFinding>,
    ) {
        if input.event.qtype != Some(16) {
            return;
        }
        let count = input
            .retained_events
            .iter()
            .filter(|event| {
                event_in_window(
                    event.as_ref(),
                    input.event.timestamp,
                    self.config.repeated_txt_window,
                )
            })
            .filter(|event| event.observed_source == input.event.observed_source)
            .filter(|event| event.qtype == Some(16))
            .count();
        if count >= self.config.repeated_txt_threshold {
            findings.push(self.finding(
                QueryEventClassifierReason::RepeatedTxtLookup,
                QueryEventClassifierSeverity::Low,
                55,
                input,
                vec![
                    detail("source_txt_count", count),
                    detail("threshold", self.config.repeated_txt_threshold),
                ],
            ));
        }
    }

    fn classify_high_entropy_name(
        &self,
        question: &QuestionKey,
        input: &SuspiciousLookupClassifierInput<'_>,
        findings: &mut Vec<QueryEventClassifierFinding>,
    ) {
        let Some(label) = question.qname.split('.').next() else {
            return;
        };
        if label.len() < self.config.high_entropy_min_label_len {
            return;
        }
        let score = entropy_score(label);
        if score >= self.config.high_entropy_score_threshold {
            findings.push(self.finding(
                QueryEventClassifierReason::HighEntropyName,
                QueryEventClassifierSeverity::Medium,
                score,
                input,
                vec![
                    detail("label", label),
                    detail("score", score),
                    detail("threshold", self.config.high_entropy_score_threshold),
                ],
            ));
        }
    }

    fn classify_domain_frequency(
        &self,
        question: &QuestionKey,
        input: &SuspiciousLookupClassifierInput<'_>,
        findings: &mut Vec<QueryEventClassifierFinding>,
    ) {
        if !self.config.enable_domain_frequency_findings {
            return;
        }
        let count = input
            .retained_events
            .iter()
            .filter_map(|event| event.normalized_question.as_ref())
            .filter(|retained_question| retained_question.qname == question.qname)
            .count();
        if count == 1 {
            findings.push(self.finding(
                QueryEventClassifierReason::NewDomain,
                QueryEventClassifierSeverity::Low,
                35,
                input,
                vec![detail("retained_domain_count", count)],
            ));
        } else if count > 1 && count <= self.config.rare_domain_threshold {
            findings.push(self.finding(
                QueryEventClassifierReason::RareDomain,
                QueryEventClassifierSeverity::Low,
                30,
                input,
                vec![
                    detail("retained_domain_count", count),
                    detail("threshold", self.config.rare_domain_threshold),
                ],
            ));
        }
    }

    fn classify_suspicious_selectors(
        &self,
        question: &QuestionKey,
        input: &SuspiciousLookupClassifierInput<'_>,
        findings: &mut Vec<QueryEventClassifierFinding>,
    ) {
        if let Some(selector) = matching_suspicious_selector(
            &question.qname,
            &self.suspicious_tlds,
            &self.suspicious_domains,
        ) {
            findings.push(self.finding(
                QueryEventClassifierReason::SuspiciousSelector,
                QueryEventClassifierSeverity::High,
                90,
                input,
                vec![detail("selector", selector)],
            ));
        }
    }

    fn finding(
        &self,
        reason: QueryEventClassifierReason,
        severity: QueryEventClassifierSeverity,
        score: u8,
        input: &SuspiciousLookupClassifierInput<'_>,
        mut details: Vec<QueryEventClassifierDetail>,
    ) -> QueryEventClassifierFinding {
        let mut evaluated_window = input.window.clone();
        if is_baseline_dependent_reason(&reason)
            && evaluated_window.retained_event_count < self.config.baseline_complete_after_events
            && !evaluated_window
                .incomplete_reasons
                .contains(&QueryEventClassifierWindowIncompleteReason::ColdStart)
        {
            evaluated_window
                .incomplete_reasons
                .push(QueryEventClassifierWindowIncompleteReason::ColdStart);
        }
        for incomplete_reason in &evaluated_window.incomplete_reasons {
            details.push(detail(
                "window_incomplete_reason",
                classifier_window_incomplete_reason_value(*incomplete_reason),
            ));
        }
        QueryEventClassifierFinding {
            classifier_version: self.config.classifier_version.clone(),
            config_generation: self.config.config_generation,
            reason,
            severity,
            score,
            evaluated_window,
            details,
        }
    }
}

fn classifier_window_incomplete_reason_value(
    reason: QueryEventClassifierWindowIncompleteReason,
) -> &'static str {
    match reason {
        QueryEventClassifierWindowIncompleteReason::ColdStart => "cold_start",
        QueryEventClassifierWindowIncompleteReason::RetentionEviction => "retention_eviction",
        QueryEventClassifierWindowIncompleteReason::SampledEvents => "sampled_events",
        QueryEventClassifierWindowIncompleteReason::DroppedEvents => "dropped_events",
    }
}

fn is_baseline_dependent_reason(reason: &QueryEventClassifierReason) -> bool {
    matches!(
        reason,
        QueryEventClassifierReason::NxdomainBurst
            | QueryEventClassifierReason::ServfailBurst
            | QueryEventClassifierReason::RepeatedTxtLookup
            | QueryEventClassifierReason::RareDomain
            | QueryEventClassifierReason::NewDomain
    )
}

fn count_source_response_code(
    retained_events: &[Arc<QueryEventV1>],
    source: &ObservedSourceEndpoint,
    response_code: u16,
    ended_at: SystemTime,
    window: Duration,
) -> usize {
    retained_events
        .iter()
        .filter(|event| event_in_window(event.as_ref(), ended_at, window))
        .filter(|event| event.observed_source == *source)
        .filter(|event| event.response_code == Some(response_code))
        .count()
}

fn event_in_window(event: &QueryEventV1, ended_at: SystemTime, window: Duration) -> bool {
    event
        .timestamp
        .checked_add(window)
        .map(|expires_at| expires_at >= ended_at)
        .unwrap_or(true)
        && event.timestamp <= ended_at
}

fn entropy_score(label: &str) -> u8 {
    if label.is_empty() {
        return 0;
    }
    let mut counts = HashMap::<char, usize>::new();
    let mut len = 0usize;
    for ch in label.chars() {
        *counts.entry(ch).or_insert(0) += 1;
        len = len.saturating_add(1);
    }
    let len = len as f64;
    let entropy = counts.values().fold(0.0, |sum, count| {
        let probability = *count as f64 / len;
        sum - probability * probability.log2()
    });
    ((entropy / 5.0) * 100.0).round().clamp(0.0, 100.0) as u8
}

fn matching_suspicious_selector(
    qname: &str,
    suspicious_tlds: &[String],
    suspicious_domains: &[String],
) -> Option<String> {
    for domain in suspicious_domains {
        if qname == domain
            || qname
                .strip_suffix(domain)
                .map(|prefix| prefix.ends_with('.'))
                .unwrap_or(false)
        {
            return Some(domain.clone());
        }
    }

    let tld = qname.rsplit('.').next()?;
    for configured_tld in suspicious_tlds {
        if tld == configured_tld {
            return Some(format!(".{tld}"));
        }
    }
    None
}

fn detail(key: impl Into<String>, value: impl ToString) -> QueryEventClassifierDetail {
    QueryEventClassifierDetail {
        key: key.into(),
        value: value.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOutcome {
    pub response_bytes: Vec<u8>,
    pub decision: ResolveDecision,
}

struct CacheProbe {
    /// Replaces the old flat `CacheKey` as the identifier threaded through
    /// to `resolve_coalesced_miss`/the eventual store call: normalized
    /// name, qtype, qclass, cache namespace, and a DO flag — the same
    /// `MissKey` `ShardedSingleFlight` (section-04) already keys on, so no
    /// conversion is needed at the single-flight call sites. The namespace
    /// must be part of this key: without it, a request that misses just
    /// before a reload publishes a new backend generation could coalesce
    /// with one that misses just after, serving a stale-generation result
    /// under the new namespace.
    ///
    /// The DO flag's meaning is mode-dependent (see `probe_cache`, which
    /// computes it): for `ResolutionMode::Forward`, it's the requester's
    /// real `dnssec_ok`, since the forwarding backend relays that flag
    /// verbatim and a DO=0/DO=1 request pair can get genuinely different
    /// backend bytes. For `ResolutionMode::Recursive`, it's canonicalized
    /// to `true` regardless of the requester's own flag, since
    /// `resolve_one_hop` always queries upstream authorities with
    /// `dnssec_ok = true` -- backend work is identical either way, so
    /// keying on the real per-requester flag there would only cost
    /// duplicate upstream fetches for mixed-DO bursts on the same name
    /// (see `MissKey`'s doc comment).
    miss_key: Option<MissKey>,
    hit: Option<Vec<u8>>,
    store_allowed: bool,
    event_cache_result: Option<QueryEventCacheResult>,
    /// Deliberately *not* enqueued here -- see `probe_cache`'s doc comment.
    /// Carried forward so the caller can enqueue only once a hit is fully
    /// admitted (passes the `recursion_desired` check and response policy).
    refresh_hints: Vec<cache::RefreshHint>,
}

/// Named return shape for `evaluate_cache_lookup`, matching this file's
/// existing `CacheProbe` convention -- avoids a positional 4-tuple at the
/// call site, where an accidental field reorder would compile but silently
/// swap meanings.
struct CacheLookupEvaluation {
    store_allowed: bool,
    hit: Option<Vec<u8>>,
    event_cache_result: QueryEventCacheResult,
    refresh_hints: Vec<cache::RefreshHint>,
}

/// Return shape for `cache_hit_after_coalesced_miss` -- carries
/// `refresh_hints` alongside the serialized hit response rather than
/// enqueueing them inline, so the caller (`resolve_coalesced_follower`) can
/// enqueue only once this hit passes the response-block policy check.
struct CoalescedFollowerHit {
    response_bytes: Vec<u8>,
    refresh_hints: Vec<cache::RefreshHint>,
    /// `Hit` or `Stale` — what the follower's re-probe actually found, so
    /// the audit event matches what was served (the stale-hit *metric* is
    /// already recorded inside `cache_hit_after_coalesced_miss`; without
    /// this field the event would hard-code `Hit` and disagree with it).
    event_cache_result: QueryEventCacheResult,
}

/// One background refresh attempt: a domain/qtype/qclass to refetch and
/// re-store before its cached entry actually expires. Built from a
/// `RefreshHint` at enqueue time (`ResolveQuery::probe_cache`); consumed by
/// the worker pool (section-05) and processed by job-processing logic
/// (section-06). `pub`, not `pub(crate)`: `main.rs` is a separate binary
/// crate and needs to name this type to construct the channel
/// (`with_refresh_sender`) once the worker pool exists.
///
/// Fields are inert (never read) until section-06's job-processing logic
/// consumes them — `#[allow(dead_code)]` until then.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RefreshJob {
    domain: String,
    qtype: u16,
    qclass: u16,
}

/// Spawns a fixed pool of `worker_count` tasks that share one bounded
/// `receiver`, each dequeuing and processing `RefreshJob`s. Mirrors
/// `spawn_sighup_reload_task`'s (`main.rs:579`) shutdown convention exactly:
/// no internal shutdown signal, no `select!` -- the caller holds the
/// returned `JoinHandle`s and `.abort()`s them at teardown.
///
/// `Receiver` is single-consumer, so it's wrapped in
/// `Arc<tokio::sync::Mutex<_>>` and shared across the pool. This serializes
/// only the dequeue point (one worker parks on `recv()` at a time), not job
/// *execution* -- each dequeued job is spawned as its own task (see below),
/// so total concurrency stays bounded at `worker_count` without a true MPMC
/// channel and its accompanying new dependency.
pub fn spawn_refresh_worker_pool(
    resolver: Arc<ResolveQuery>,
    receiver: tokio::sync::mpsc::Receiver<RefreshJob>,
    worker_count: usize,
) -> Vec<tokio::task::JoinHandle<()>> {
    let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
    (0..worker_count)
        .map(|_| {
            tokio::spawn(refresh_worker_loop(
                Arc::clone(&resolver),
                Arc::clone(&receiver),
            ))
        })
        .collect()
}

/// One worker's dequeue-process-repeat loop. A panic inside a given job's
/// processing (`process_refresh_job`) is isolated by spawning that job as
/// its own task and awaiting its `JoinHandle` before dequeuing the next job
/// -- deliberately not `futures::FutureExt::catch_unwind` (this repo has no
/// `futures` dependency; adding one solely for this would contradict the
/// same "add dependencies conservatively" reasoning already used to reject
/// a true MPMC channel above). A panicked job fails only its own
/// `JoinHandle` (`JoinError::is_panic()`); this loop, and thus this worker,
/// keeps running.
///
/// Shutdown correctness: `.abort()`ing this outer loop task (at shutdown,
/// see `main.rs`) while it's parked in `handle.await` only cancels the loop
/// task's own future -- it does not, by itself, abort the inner spawned job
/// task. Left alone, that inner task would keep running detached, still
/// holding its own `Arc<ResolveQuery>` clone (`task_resolver`), which can
/// prevent `drop(resolver)` from ever happening and hang shutdown's
/// `event_drain.await` (found by review: `docs/plans/auto_refresh/`).
/// `_abort_inner_job_on_drop` closes this gap: it holds an `AbortHandle` for
/// the just-spawned inner task, tied to this stack frame's lifetime via
/// `AbortOnDrop`'s `Drop` impl. Aborting *this* outer task drops its future
/// (and everything on its stack, including this guard) at whatever point it
/// was parked -- including mid-`handle.await` -- so the inner job task is
/// reliably requested to cancel too, releasing its `Arc<ResolveQuery>` clone
/// promptly instead of only whenever that job's own I/O happens to finish.
async fn refresh_worker_loop(
    resolver: Arc<ResolveQuery>,
    receiver: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<RefreshJob>>>,
) {
    loop {
        let job = {
            let mut receiver = receiver.lock().await;
            receiver.recv().await
        };
        let Some(job) = job else {
            break; // channel closed (all senders dropped) -- exit cleanly.
        };
        let task_resolver = Arc::clone(&resolver);
        let handle = tokio::spawn(async move { process_refresh_job(task_resolver, job).await });
        let _abort_inner_job_on_drop = AbortOnDrop(handle.abort_handle());
        if let Err(join_error) = handle.await
            && join_error.is_panic()
        {
            tracing::error!(?join_error, "refresh job panicked");
        }
    }
}

/// Aborts the wrapped task on drop -- used to tie an inner spawned job
/// task's lifetime to its outer worker loop's stack frame, so cancelling
/// the outer task (via `JoinHandle::abort`) reliably cancels the inner one
/// too, even if the outer future is dropped mid-`.await` on the inner
/// task's own `JoinHandle`. Aborting an already-finished task is a
/// documented no-op, so this is safe to run unconditionally on every drop,
/// not just the cancelled-outer-task case.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Test-only injectable job handler, so worker-pool tests can exercise the
/// *real* `spawn_refresh_worker_pool`/`refresh_worker_loop` (dequeue, spawn,
/// await, panic isolation) instead of a hand-rolled lookalike, without
/// section-06's real fetch/store logic existing yet. `thread_local` is safe
/// here specifically because these tests use the default `#[tokio::test]`
/// current-thread runtime flavor (never `flavor = "multi_thread"`): the
/// whole runtime, including every spawned task, runs on the one OS thread
/// that called `block_on`, so a handler set before spawning is visible to
/// every task the pool spawns on that same thread. Each worker-pool test
/// explicitly sets (or clears) this at its own start, since the test
/// harness's thread pool can reuse an OS thread across different test
/// functions.
#[cfg(test)]
type TestJobHandler = std::sync::Arc<
    dyn Fn(RefreshJob) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

#[cfg(test)]
thread_local! {
    static TEST_JOB_HANDLER: std::cell::RefCell<Option<TestJobHandler>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_test_job_handler(handler: TestJobHandler) {
    TEST_JOB_HANDLER.with(|cell| *cell.borrow_mut() = Some(handler));
}

#[cfg(test)]
fn clear_test_job_handler() {
    TEST_JOB_HANDLER.with(|cell| *cell.borrow_mut() = None);
}

/// Builds a minimal outbound `DecodedQuery` for a synthetic, server-internal
/// refresh fetch -- not a client-originated query. Follows the exact same
/// standard-query wire shape the test-only `query`/`query_with_edns` helpers
/// build (`src/resolver/mod.rs` test module), just as production code
/// instead of a test fixture: a single question for `(qname, qtype,
/// qclass)`, RD set, and one EDNS OPT additional record with the DO flag
/// set according to `dnssec_ok`. `dnssec_ok` is kept as an explicit
/// parameter rather than hardcoded so this builder stays a pure,
/// independently testable function -- it's the caller (`process_refresh_job`)
/// that always passes `true` for refresh jobs, a policy decision that
/// doesn't belong baked into the builder itself. `udp_payload_size` is the
/// operator's own `configured_max_udp_payload_size()` (not a fixed
/// constant): review found the previous hard-coded 1232 bytes could
/// truncate/fail a large DNSSEC refresh response for an operator who
/// configured a bigger buffer, since only `ResolutionMode::Recursive`
/// backend calls get their EDNS size rewritten downstream
/// (`resolve_backend` -> `backend_query_with_configured_udp_limit`) --
/// `ResolutionMode::Forward` sends whatever this builder encoded, verbatim.
///
/// The bytes built here are always well-formed by construction, so the
/// `expect`s below reflect a bug in this function, not a runtime condition
/// to recover from.
/// Returns `None` (never panics) if `qname` can't be encoded as a valid DNS
/// name -- in practice `qname` always originates from an already-cached,
/// already-validated name (every name that ever reaches the cache passed
/// through this same label-length limit at original decode time), so this
/// is a defense-in-depth guard against a pathological input, not an
/// expected path. `job.domain` splitting on `.` (matching the test-only
/// `query`/`query_with_edns` helpers this mirrors) does not attempt to
/// un-escape a label containing a literal embedded dot -- not reachable
/// from any name this codebase itself decodes and re-serializes today, but
/// worth a future reader's awareness if `job.domain` ever gained a
/// different source.
fn build_refresh_query(
    qname: &str,
    qtype: u16,
    qclass: u16,
    dnssec_ok: bool,
    udp_payload_size: u16,
) -> Option<DecodedQuery> {
    const REFRESH_QUERY_ID: u16 = 0;
    const MAX_LABEL_LEN: usize = 63;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&REFRESH_QUERY_ID.to_be_bytes());
    bytes.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1, standard query
    bytes.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    bytes.extend_from_slice(&0u16.to_be_bytes()); // ancount
    bytes.extend_from_slice(&0u16.to_be_bytes()); // nscount
    bytes.extend_from_slice(&1u16.to_be_bytes()); // arcount (EDNS OPT)
    for label in qname.split('.') {
        if label.is_empty() {
            continue; // root ("") or an already-trailing-dot-stripped name
        }
        if label.len() > MAX_LABEL_LEN {
            return None;
        }
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&qtype.to_be_bytes());
    bytes.extend_from_slice(&qclass.to_be_bytes());
    // EDNS OPT additional record: root owner name, TYPE=41, CLASS carries
    // the UDP payload size, extended-rcode/version, DO flag, rdlen=0.
    bytes.push(0);
    bytes.extend_from_slice(&41u16.to_be_bytes());
    bytes.extend_from_slice(&udp_payload_size.to_be_bytes());
    bytes.push(0);
    bytes.push(0);
    let flags = if dnssec_ok { EDNS_DO_FLAG } else { 0 };
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());

    let message = Message::parse_standard_query_owned(bytes).ok()?;
    DecodedQuery::new(message)
}

/// Processes one dequeued job: epoch-first eligibility recheck,
/// singleflight-based fetch (always `dnssec_ok = true`), and direct cache
/// store bypassing `prepare_backend_result`'s policy/rewrite/chaos layers
/// (none of which apply to a server-internal refresh). No retry on any
/// failure -- the stale entry is simply left to expire normally.
///
/// In test builds, `TEST_JOB_HANDLER` (if set) takes over entirely instead
/// -- see its own doc comment for why (exercising the real worker-pool
/// mechanics in section-05's tests without this section's fetch logic
/// existing yet).
async fn process_refresh_job(resolver: Arc<ResolveQuery>, job: RefreshJob) {
    #[cfg(test)]
    {
        let handler = TEST_JOB_HANDLER.with(|cell| cell.borrow().clone());
        if let Some(handler) = handler {
            handler(job).await;
            return;
        }
    }

    // 1. Capture epoch first -- reused for every subsequent step in this
    //    job, never re-read mid-job (same discipline every other store path
    //    in this file already follows; see `cache-epoch.md`).
    let backend_snapshot = resolver.backend.current();
    let epoch = backend_snapshot.cache_epoch;
    let now = resolver.clock.now();

    // 2. Re-check eligibility against that captured epoch by re-probing the
    //    cache through the same lookup_chain path a real query uses. An
    //    epoch mismatch (a reload happened while this job sat in the
    //    channel) surfaces here as an ordinary miss -- `lookup_hop` already
    //    treats a stale-epoch entry as invisible, so there's no separate
    //    epoch check needed. A hint no longer present in the re-probed
    //    result means the entry moved out of the lead window (or cooled)
    //    since the job was enqueued.
    //
    //    Deliberately `dnssec_ok = false` here, not `true`: this recheck's
    //    only job is "is this still a live, in-window, hot answer,"
    //    independent of the entry's own DNSSEC completeness -- unlike the
    //    actual fetch below (step 3), which always uses `true` per the
    //    confirmed refresh-always-upgrades-to-DNSSEC-complete decision.
    //    Rechecking with `true` here would incorrectly treat any entry
    //    whose `dnssec_complete` is `false` as invisible (the same
    //    DO=true-vs-dnssec_complete=false filter `take_live_positive`
    //    applies to a real DO=true reader), permanently defeating refresh
    //    for every domain whose cached answer happened to originate from a
    //    DO=false query -- caught by `job_fetch_uses_dnssec_ok_true_always`.
    //
    //    Known feedback-loop caveat (flagged during review, not fixed here):
    //    this recheck reuses the exact same `lookup_hop` code path a real
    //    query uses, which unconditionally records a popularity hit and
    //    touches the domain's LRU position on every live match -- including
    //    this recheck itself. A successful refresh cycle alone (independent
    //    of any real client traffic) therefore contributes its own hit
    //    toward keeping the domain "hot," which for a domain whose lead
    //    window recurs faster than the popularity bucket's leak rate could
    //    theoretically sustain refreshing indefinitely even after real
    //    demand stops. Deliberately not fixed here -- the alternative is a
    //    second, side-effect-free recheck path, contradicting this design's
    //    explicit choice to reuse `lookup_chain` rather than hand-roll a
    //    parallel one. Section-07's end-to-end verification ("a domain that
    //    stops being queried stops getting refreshed") should specifically
    //    probe a short-TTL/fast-refresh-cycle domain to confirm whether
    //    this is a practical problem with the shipped defaults, not just a
    //    long-TTL domain where natural leak easily outpaces one hit/cycle.
    let recheck = resolver.cache.lookup_chain(
        &job.domain,
        job.qtype,
        job.qclass,
        false,
        epoch,
        resolver.max_chain_depth,
        now,
        &resolver.refresh_config,
    );
    let still_eligible = matches!(
        &recheck,
        ChainLookup::Answered(resolved) if resolved.refresh_hints.iter().any(|hint| {
            hint.domain == job.domain && hint.qtype == job.qtype && hint.qclass == job.qclass
        })
    );
    if !still_eligible {
        return;
    }

    // 3. Fetch via singleflight -- dnssec_ok always true for refresh jobs
    //    (a refresh always upgrades to a DNSSEC-complete fetch). This only
    //    coalesces with a concurrent client miss that itself has
    //    dnssec_ok = true, since MissKey includes this flag; a DO=false
    //    client miss for the same key becomes its own independent Leader.
    //    `udp_payload_size` uses the operator's own configured limit (review
    //    found the previous hard-coded 1232 bytes could truncate/fail a
    //    large DNSSEC refresh response when a larger limit was configured --
    //    see `build_refresh_query`'s doc comment).
    let miss_key: MissKey = (job.domain.clone(), job.qtype, job.qclass, epoch, true);
    let udp_payload_size = resolver
        .configured_max_udp_payload_size()
        .min(u16::MAX as usize) as u16;
    let Some(synthetic_query) =
        build_refresh_query(&job.domain, job.qtype, job.qclass, true, udp_payload_size)
    else {
        resolver.metrics.increment(ResolverMetric::RefreshFailed);
        return;
    };
    let (leader, fetch_result) = match resolver.miss_coalescer.begin(miss_key) {
        SingleFlightTicket::Leader { key, flight } => {
            let leader = SingleFlightLeader::new(Arc::clone(&resolver.miss_coalescer), key, flight);
            let result = resolver
                .resolve_backend(&backend_snapshot, &synthetic_query)
                .await;
            (Some(leader), result)
        }
        SingleFlightTicket::Follower { flight } => (None, flight.wait().await),
    };

    // 4. Store on success (*before* notifying any singleflight followers via
    //    `leader.complete` below), no retry on any failure.
    //
    //    Ordering matters (found by review): completing the leader's flight
    //    wakes any waiting follower immediately, and a follower re-probes
    //    the cache right after waking (`cache_hit_after_coalesced_miss`). If
    //    that happened *before* this job's own store landed, the follower
    //    could still see the stale (or by-then-expired) entry, miss, and
    //    fall back to this job's raw synthetic backend result -- which in
    //    forward mode only has its ID/RD/CD rewritten for the real client,
    //    not reframed with that client's own question/OPT. Storing first
    //    (mirroring `resolve_coalesced_leader`'s own store-then-complete
    //    ordering) means a follower's cache re-probe always sees the fresh
    //    entry.
    //
    //    Note: this runs identically whether this job ended up as the
    //    singleflight Leader or a Follower -- if some other party (a real
    //    client miss, or another refresh job racing the same key) was
    //    already the Leader, this job still independently calls
    //    store_cache_response on the shared result once it wakes from
    //    `flight.wait()`. That's a deliberate, harmless redundancy (last
    //    store wins with materially the same data, since both sides are
    //    storing the identical backend response) rather than a bug worth
    //    special-casing away -- the alternative (skip storing when a
    //    Follower) would depend on the other party's own store path having
    //    already run by the time this one observes the result, which isn't
    //    guaranteed.
    match fetch_result {
        Ok(mut response) => {
            if !response.cache_directive.is_cacheable() {
                // The backend itself declared this specific response
                // not cacheable (e.g. DNSSEC validation was incomplete,
                // or a backend policy said so) -- `prepare_backend_result`
                // honors this same directive before its own store call
                // (see its `cache_directive.is_cacheable()` check), and a
                // refresh must not force-cache something the backend
                // explicitly said not to.
                resolver.metrics.increment(ResolverMetric::RefreshFailed);
                if let Some(leader) = leader {
                    leader.complete(Ok(response));
                }
                return;
            }
            let Some(response_message) = validate_backend_response(&mut response, &synthetic_query)
            else {
                resolver.metrics.increment(ResolverMetric::RefreshFailed);
                if let Some(leader) = leader {
                    leader.complete(Ok(response));
                }
                return;
            };
            // Same store_dnssec_ok/store_authoritative computation
            // `prepare_backend_result` uses, so a refresh-stored entry is
            // structurally indistinguishable from what the normal
            // client-miss path would have stored for the same response.
            // store_dnssec_ok collapses to `true` in both arms here
            // (unlike prepare_backend_result's general case) since the
            // synthetic query itself always sets dnssec_ok = true.
            let store_authoritative = match backend_snapshot.mode {
                ResolutionMode::Recursive => false,
                ResolutionMode::Forward => response_message.header.aa(),
            };
            let synthetic_request =
                ResolveRequest::new(Ipv4Addr::UNSPECIFIED.into(), now, Vec::new());
            resolver
                .store_cache_response(
                    epoch,
                    &response_message,
                    &synthetic_query.question,
                    &synthetic_request,
                    true,
                    store_authoritative,
                )
                .await;
            resolver.metrics.increment(ResolverMetric::RefreshSucceeded);
            if let Some(leader) = leader {
                leader.complete(Ok(response));
            }
        }
        Err(error) => {
            resolver.metrics.increment(ResolverMetric::RefreshFailed);
            if let Some(leader) = leader {
                leader.complete(Err(error));
            }
        }
    }
}

pub struct ResolveQuery {
    protocol: Arc<dyn ProtocolCodec>,
    policy: Arc<dyn PolicyEvaluator>,
    local_entries: LocalDnsEntriesHandle,
    cache: Arc<dyn DomainDnsCache>,
    ttl_policy: CacheTtlPolicy,
    miss_coalescer: Arc<ShardedSingleFlight>,
    // Bounds `resolve_from_cache`'s CNAME-chain walk (`cache::assemble`,
    // section-06). Not part of any constructor's parameter list by
    // default (defaults to `DEFAULT_MAX_CHAIN_DEPTH`, section-01's
    // `RecursiveResolverConfig.max_cname_restarts` default) — callers that
    // care (`main.rs`, constructing from real config) override it via
    // `with_max_chain_depth` after construction, avoiding yet another
    // parameter on every one of the `with_cache*` constructors below.
    max_chain_depth: u8,
    backend: BackendHandle,
    // Guards `backend` and `local_entries` together: a writer publishing a
    // reload holds this for both swaps, so a query never observes the new
    // value of one field paired with the stale value of the other.
    reload_gate: RwLock<()>,
    responses: Arc<dyn ResponseFactory>,
    clock: Arc<dyn Clock>,
    events: Arc<dyn QueryEventSink>,
    event_sequence: AtomicU64,
    metrics: Arc<dyn MetricsSink>,
    // Not part of any constructor's parameter list by default (defaults to
    // `ChaosConfig::default()`, i.e. enabled) -- same reasoning as
    // `max_chain_depth` above: `main.rs` overrides it via
    // `with_chaos_config` once real config is available, rather than
    // threading yet another parameter through every `with_cache*`
    // constructor.
    chaos: crate::config::ChaosConfig,
    // Not part of any constructor's parameter list by default (defaults to
    // `Arc::new(CookieSecret::generate())`) -- same reasoning as
    // `max_chain_depth`/`chaos` above: unlike `clock`, `CookieSecret` isn't
    // a trait object the vast majority of existing tests need to
    // substitute (they don't exercise Cookie behavior at all), so a
    // post-construction setter (`with_cookie_secret`) avoids threading a
    // new mandatory parameter through every `with_cache*` constructor and
    // every existing test call site. `main.rs` overrides it with a real,
    // process-lifetime secret once available.
    cookie_secret: Arc<CookieSecret>,
    // Not part of any constructor's parameter list by default (defaults to
    // `RefreshConfig::default()`) -- same reasoning as `max_chain_depth`/
    // `chaos`/`cookie_secret` above. Threaded into every `self.cache.lookup_chain(...)`
    // call so `Shard::lookup_hop` (via `resolve_from_cache`) can compute the
    // auto-refresh trigger formula (`docs/plans/auto_refresh/`) with real
    // thresholds instead of a hardcoded default. `main.rs` overrides it via
    // `with_refresh_config` once real config is available.
    refresh_config: crate::config::RefreshConfig,
    // Non-blocking enqueue point for background refresh jobs (see
    // `docs/knowledge/resolver/caching/auto-refresh.md`). Every constructor
    // defaults this to a sender whose paired receiver has already been
    // dropped, so any enqueue attempt in an existing test (none currently
    // configure a hot popularity bucket) simply counts as a dropped job
    // (`ResolverMetric::RefreshQueueFull`) rather than panicking or
    // blocking. `main.rs` overrides this via `with_refresh_sender` once the
    // real worker pool's channel exists (section-05).
    refresh_sender: tokio::sync::mpsc::Sender<RefreshJob>,
}

impl ResolveQuery {
    pub fn new(
        protocol: Arc<dyn ProtocolCodec>,
        backend: Arc<dyn ResolutionBackend>,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        Self::with_cache(
            protocol,
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            backend,
            responses,
            clock,
            events,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DomainDnsCache>,
        ttl_policy: CacheTtlPolicy,
        backend: Arc<dyn ResolutionBackend>,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        Self::with_cache_and_policy(
            protocol,
            cache,
            Arc::new(NoopPolicyEvaluator),
            Arc::new(NoopLocalDnsEntries),
            ttl_policy,
            backend,
            responses,
            clock,
            events,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_and_policy(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DomainDnsCache>,
        policy: Arc<dyn PolicyEvaluator>,
        local_entries: Arc<dyn LocalDnsEntries>,
        ttl_policy: CacheTtlPolicy,
        backend: Arc<dyn ResolutionBackend>,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        let snapshot = BackendSnapshot::forwarding(backend, 0);
        Self::with_cache_policy_and_backend_snapshot(
            protocol,
            cache,
            policy,
            local_entries,
            ttl_policy,
            snapshot,
            responses,
            clock,
            events,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_and_backend_snapshot(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DomainDnsCache>,
        ttl_policy: CacheTtlPolicy,
        backend_snapshot: BackendSnapshot,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        Self::with_cache_policy_and_backend_snapshot(
            protocol,
            cache,
            Arc::new(NoopPolicyEvaluator),
            Arc::new(NoopLocalDnsEntries),
            ttl_policy,
            backend_snapshot,
            responses,
            clock,
            events,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_policy_and_backend_snapshot(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DomainDnsCache>,
        policy: Arc<dyn PolicyEvaluator>,
        local_entries: Arc<dyn LocalDnsEntries>,
        ttl_policy: CacheTtlPolicy,
        backend_snapshot: BackendSnapshot,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        metrics.record_backend_status(&backend_snapshot.status());
        let (refresh_sender, _dropped_refresh_receiver) = tokio::sync::mpsc::channel(1);
        Self {
            protocol,
            policy,
            local_entries: LocalDnsEntriesHandle::new(local_entries),
            cache,
            ttl_policy,
            miss_coalescer: Arc::new(ShardedSingleFlight::new(default_single_flight_shard_count())),
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            backend: BackendHandle::new(backend_snapshot),
            reload_gate: RwLock::new(()),
            responses,
            clock,
            events,
            event_sequence: AtomicU64::new(0),
            metrics,
            chaos: crate::config::ChaosConfig::default(),
            cookie_secret: Arc::new(CookieSecret::generate()),
            refresh_config: crate::config::RefreshConfig::default(),
            refresh_sender,
        }
    }

    pub fn backend_status(&self) -> BackendStatus {
        self.backend.status()
    }

    /// The resolver's own configured UDP payload size, for callers (such as
    /// the TCP delivery layer's oversized-response SERVFAIL fallback) that
    /// need to build an EDNS-aware response outside of the normal
    /// `resolve` path and must advertise this resolver's size rather than
    /// echoing the requester's.
    pub fn configured_max_udp_payload_size(&self) -> usize {
        self.protocol.configured_max_udp_payload_size()
    }

    /// Publishes a backend-only snapshot (no local-entries swap, no sweep)
    /// — used where a full `publish_reload` isn't warranted. Still applies
    /// `next_cache_epoch` against the previously-published snapshot, same as
    /// `publish_reload`: `snapshot`'s own `cache_epoch` field (whatever the
    /// caller set it to, typically the constructor default `0`) is never
    /// trusted directly, so this can never roll the live epoch backwards and
    /// resurrect entries from an older, unrelated generation. Not sweeping
    /// here just delays reclaiming any newly-stale entries' memory until the
    /// next `publish_reload` — correctness is unaffected, since lookup-time
    /// epoch checks already make them invisible immediately.
    pub fn publish_backend_snapshot(&self, mut snapshot: BackendSnapshot) {
        let _gate = self
            .reload_gate
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = self.backend.current();
        snapshot.cache_epoch = next_cache_epoch(&previous, &snapshot);
        let status = snapshot.status();
        self.backend.publish(snapshot);
        self.metrics.record_backend_status(&status);
    }

    pub fn publish_local_entries(&self, entries: Arc<dyn LocalDnsEntries>) {
        let _gate = self
            .reload_gate
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.local_entries.publish(entries);
    }

    /// Publishes a new backend snapshot and local DNS entries as a single
    /// atomic reload: no query can observe one field from the new config
    /// paired with the other from the old one. Also runs the section-05
    /// namespace sweep (once per reload, not once per request) — but,
    /// unlike an earlier version of this method, *after* releasing
    /// `reload_gate`, not while still holding it.
    ///
    /// `reload_gate` only needs to cover the atomic swap of `backend` and
    /// `local_entries`; the sweep is pure cleanup/memory reclamation, not
    /// something a reader depends on for correctness. A cached entry's own
    /// `cache_epoch` is checked against the current epoch on every lookup
    /// (`ChainLookup`/`Shard::lookup_hop`), so a stale-epoch entry is
    /// already invisible to readers the instant the new snapshot is
    /// published — the sweep merely reclaims the memory later. Holding
    /// `reload_gate` (a `std::sync::RwLock`, so a writer blocks every new
    /// reader) across `sweep_stale_namespace`'s full per-shard scan would
    /// stall every concurrent `resolve()` call for the duration of the
    /// sweep, reintroducing exactly the kind of single-lock-serializes-
    /// everything problem this cache rework was meant to eliminate — just
    /// moved from the cache's own lock onto `reload_gate`. Running the
    /// sweep after the guard drops avoids that while keeping the same
    /// correctness guarantee.
    ///
    /// The epoch bump itself (`next_cache_epoch`, compared against the
    /// previously-published snapshot) happens inside the same `reload_gate`
    /// write section as the backend/local-entries swap, so every reader
    /// that captures a `BackendSnapshot` under `reload_gate`'s read side
    /// always sees a `cache_epoch` paired with the backend it was actually
    /// bumped for — never an old backend with a new epoch or vice versa.
    /// The sweep only runs when the epoch actually changed: an unrelated
    /// reload (e.g. a metrics-only config edit) leaves every entry stored
    /// *before this reload* matching, so sweeping now would find nothing new
    /// to remove for those — skipping it is strictly cheaper than today's
    /// unconditional sweep-every-reload behavior.
    ///
    /// One bounded exception: a request that captured the *previous*,
    /// epoch-changing snapshot can still be in flight when that reload's
    /// sweep runs, and store an old-epoch entry after the sweep already
    /// passed over it. Such an entry is never a correctness problem (an
    /// epoch mismatch is already an unconditional miss at lookup time, see
    /// `sweep_stale_namespace`'s doc), and it will still be swept by
    /// whichever *next* reload actually changes the epoch again — but a
    /// long run of unrelated, same-namespace reloads won't sweep it away
    /// itself. It sits invisible, occupying one domain slot, until ordinary
    /// LRU pressure reclaims it. This is the same trade-off described in
    /// `ResolveQuery::resolve`'s per-request snapshot pinning: correctness
    /// doesn't depend on the sweep, only prompt memory reclamation does.
    pub fn publish_reload(&self, mut snapshot: BackendSnapshot, entries: Arc<dyn LocalDnsEntries>) {
        let new_epoch;
        let epoch_changed;
        {
            let _gate = self
                .reload_gate
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = self.backend.current();
            new_epoch = next_cache_epoch(&previous, &snapshot);
            epoch_changed = new_epoch != previous.cache_epoch;
            snapshot.cache_epoch = new_epoch;
            let status = snapshot.status();
            self.backend.publish(snapshot);
            self.local_entries.publish(entries);
            self.metrics.record_backend_status(&status);
        }
        if epoch_changed {
            self.cache.sweep_stale_namespace(new_epoch);
        }
    }

    /// Overrides the default CNAME-chain-walk depth bound
    /// (`DEFAULT_MAX_CHAIN_DEPTH`) set by every constructor. `main.rs`
    /// calls this with `RecursiveResolverConfig.max_cname_restarts` once
    /// real config is available — see `ResolveQuery.max_chain_depth`'s doc
    /// comment for why this is a post-construction override rather than a
    /// parameter threaded through every `with_cache*` constructor.
    pub fn with_max_chain_depth(mut self, max_chain_depth: u8) -> Self {
        self.max_chain_depth = max_chain_depth;
        self
    }

    /// Overrides the default CHAOS-class config set by every constructor
    /// (enabled, answering `"rdns"`). `main.rs` calls this with the real
    /// `[chaos]` config
    /// once available -- see `ResolveQuery.chaos`'s doc comment for why
    /// this is a post-construction override rather than a parameter
    /// threaded through every `with_cache*` constructor.
    pub fn with_chaos_config(mut self, chaos: crate::config::ChaosConfig) -> Self {
        self.chaos = chaos;
        self
    }

    /// Overrides the default process-lifetime `CookieSecret` set by every
    /// constructor. `main.rs` calls this with the one real secret generated
    /// alongside `SystemClock` -- see `ResolveQuery.cookie_secret`'s doc
    /// comment for why this is a post-construction override rather than a
    /// parameter threaded through every `with_cache*` constructor.
    pub fn with_cookie_secret(mut self, cookie_secret: Arc<CookieSecret>) -> Self {
        self.cookie_secret = cookie_secret;
        self
    }

    /// Overrides the default `RefreshConfig` set by every constructor.
    /// `main.rs` calls this with the real `[refresh]` config once available
    /// -- see `ResolveQuery.refresh_config`'s doc comment for why this is a
    /// post-construction override rather than a parameter threaded through
    /// every `with_cache*` constructor.
    pub fn with_refresh_config(mut self, refresh_config: crate::config::RefreshConfig) -> Self {
        self.refresh_config = refresh_config;
        self
    }

    /// Wires the auto-refresh job sender into this resolver. Left at its
    /// default (a sender whose receiver has already been dropped) when
    /// `RefreshConfig::enabled` is `false`, or before the worker pool
    /// (section-05) exists -- see `ResolveQuery.refresh_sender`'s doc
    /// comment.
    pub fn with_refresh_sender(mut self, sender: tokio::sync::mpsc::Sender<RefreshJob>) -> Self {
        self.refresh_sender = sender;
        self
    }

    /// Overrides the default `ShardedSingleFlight` shard count set by
    /// every constructor. `main.rs` calls this with the real
    /// `ShardedDnsCache`'s own `shard_count()` once both are constructed,
    /// so "shard N" means the same domain-routing bucket in both
    /// structures — not a correctness requirement, just avoids surprising
    /// a future reader (section-07 plan, §9).
    pub fn with_single_flight_shard_count(mut self, shard_count: usize) -> Self {
        self.miss_coalescer = Arc::new(ShardedSingleFlight::new(shard_count));
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_and_backend_handle(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DomainDnsCache>,
        ttl_policy: CacheTtlPolicy,
        backend_handle: BackendHandle,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        Self::with_cache_policy_and_backend_handle(
            protocol,
            cache,
            Arc::new(NoopPolicyEvaluator),
            Arc::new(NoopLocalDnsEntries),
            ttl_policy,
            backend_handle,
            responses,
            clock,
            events,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_policy_and_backend_handle(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DomainDnsCache>,
        policy: Arc<dyn PolicyEvaluator>,
        local_entries: Arc<dyn LocalDnsEntries>,
        ttl_policy: CacheTtlPolicy,
        backend_handle: BackendHandle,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        metrics.record_backend_status(&backend_handle.status());
        let (refresh_sender, _dropped_refresh_receiver) = tokio::sync::mpsc::channel(1);
        Self {
            protocol,
            policy,
            local_entries: LocalDnsEntriesHandle::new(local_entries),
            cache,
            ttl_policy,
            miss_coalescer: Arc::new(ShardedSingleFlight::new(default_single_flight_shard_count())),
            max_chain_depth: DEFAULT_MAX_CHAIN_DEPTH,
            backend: backend_handle,
            reload_gate: RwLock::new(()),
            responses,
            clock,
            events,
            event_sequence: AtomicU64::new(0),
            metrics,
            chaos: crate::config::ChaosConfig::default(),
            cookie_secret: Arc::new(CookieSecret::generate()),
            refresh_config: crate::config::RefreshConfig::default(),
            refresh_sender,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_and_backend_generation(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DomainDnsCache>,
        ttl_policy: CacheTtlPolicy,
        backend: Arc<dyn ResolutionBackend>,
        backend_generation: u64,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        let snapshot = BackendSnapshot::forwarding(backend, backend_generation);
        Self::with_cache_policy_and_backend_snapshot(
            protocol,
            cache,
            Arc::new(NoopPolicyEvaluator),
            Arc::new(NoopLocalDnsEntries),
            ttl_policy,
            snapshot,
            responses,
            clock,
            events,
            metrics,
        )
    }

    pub async fn resolve(&self, mut request: ResolveRequest) -> ResolveOutcome {
        self.metrics
            .increment_with_source(ResolverMetric::QueryReceived, request.client_ip);
        let started_at = self.clock.now();
        let (backend_snapshot, local_entries) = {
            let _gate = self
                .reload_gate
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (self.backend.current(), self.local_entries.current())
        };
        let request_id = request.request_id;
        let request_bytes = std::mem::take(&mut request.bytes);

        let decoded = match self
            .decode_or_protocol_error(
                started_at,
                &request,
                request_id,
                &backend_snapshot,
                request_bytes,
            )
            .await
        {
            Ok(decoded) => decoded,
            Err(outcome) => return outcome,
        };

        let question = decoded.question.clone();
        if let Some(outcome) = self
            .try_policy_block(started_at, &request, &decoded, &question, &backend_snapshot)
            .await
        {
            return outcome;
        }

        if let Some(outcome) = self
            .try_chaos_lookup(started_at, &request, &decoded, &question, &backend_snapshot)
            .await
        {
            return outcome;
        }

        if let Some(outcome) = self
            .try_local_lookup(
                started_at,
                &request,
                &decoded,
                &question,
                &local_entries,
                &backend_snapshot,
            )
            .await
        {
            return outcome;
        }

        let mut cache_probe = self
            .probe_cache(&backend_snapshot, &request, &decoded)
            .await;
        if let Some(response_bytes) = cache_probe.hit {
            return self
                .finish_cache_hit(
                    started_at,
                    &request,
                    &decoded,
                    &question,
                    response_bytes,
                    cache_probe.event_cache_result,
                    &backend_snapshot,
                    cache_probe.refresh_hints,
                )
                .await;
        }

        if !decoded.features.recursion_desired {
            return self
                .refuse_recursion(
                    started_at,
                    &request,
                    &decoded,
                    question,
                    cache_probe.event_cache_result,
                    &backend_snapshot,
                )
                .await;
        }

        if let (Some(miss_key), true) = (cache_probe.miss_key.take(), cache_probe.store_allowed) {
            return self
                .resolve_coalesced_miss(
                    &backend_snapshot,
                    started_at,
                    &request,
                    &decoded,
                    question,
                    miss_key,
                    cache_probe.event_cache_result,
                )
                .await;
        }

        self.resolve_backend_and_finish(
            &backend_snapshot,
            started_at,
            &request,
            &decoded,
            question,
            cache_probe.miss_key,
            false,
            cache_probe.event_cache_result,
        )
        .await
    }

    /// Decodes the raw query bytes, converting a decode failure directly
    /// into the protocol-error `ResolveOutcome` the caller should return.
    async fn decode_or_protocol_error(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        request_id: Option<u16>,
        backend_snapshot: &BackendSnapshot,
        request_bytes: Bytes,
    ) -> Result<DecodedQuery, ResolveOutcome> {
        match self.protocol.decode_query_owned(request_bytes) {
            Ok(decoded) => Ok(decoded),
            Err(QueryDecodeFailure {
                error,
                recovered_message,
            }) => {
                self.metrics
                    .increment_with_source(ResolverMetric::ProtocolError, request.client_ip);
                let decision = ResolveDecision {
                    client_ip: request.client_ip,
                    question: None,
                    kind: ResolveDecisionKind::ProtocolError(error.response_code()),
                };
                let response_bytes = self.responses.protocol_error(
                    request_id,
                    &error,
                    recovered_message.as_deref(),
                    self.protocol.configured_max_udp_payload_size(),
                );
                Err(self
                    .finish_uniform(
                        started_at,
                        request,
                        None,
                        decision,
                        response_bytes,
                        None,
                        Some(QueryEventBackend::from_snapshot(backend_snapshot)),
                    )
                    .await)
            }
        }
    }

    /// Returns the blocked-response `ResolveOutcome` if policy evaluation
    /// blocks this query, otherwise `None` so the caller keeps going.
    async fn try_policy_block(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: &QuestionKey,
        backend_snapshot: &BackendSnapshot,
    ) -> Option<ResolveOutcome> {
        let PolicyDecision::Block(block) =
            self.policy.evaluate(request.client_ip, &decoded.question)
        else {
            return None;
        };
        self.metrics
            .increment_with_source(ResolverMetric::QueryBlocked, request.client_ip);
        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question.clone()),
            kind: ResolveDecisionKind::Blocked(block.clone()),
        };
        let response_bytes = self.responses.blocked(
            decoded,
            &block,
            self.protocol.configured_max_udp_payload_size(),
        );
        Some(
            self.finish_uniform(
                started_at,
                request,
                decoded_original_question_name(decoded),
                decision,
                response_bytes,
                None,
                Some(QueryEventBackend::from_snapshot(backend_snapshot)),
            )
            .await,
        )
    }

    /// Answers `version.bind. CH TXT` -- BIND's classic operator-info
    /// query -- with the operator-configured `[chaos].version_bind` string
    /// when `[chaos].enabled` is set, rather than letting it fall through
    /// to the cache/backend like any other query. Returns `None` (falling
    /// through as normal) when CHAOS support is disabled, or the question
    /// doesn't match class CHAOS / type TXT / name `version.bind.` exactly.
    async fn try_chaos_lookup(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: &QuestionKey,
        backend_snapshot: &BackendSnapshot,
    ) -> Option<ResolveOutcome> {
        if !self.chaos.enabled
            || question.qclass != CHAOS_CLASS
            || question.qtype != TXT_RECORD_TYPE
            || question.qname != VERSION_BIND_QNAME
        {
            return None;
        }
        let response_bytes = build_txt_answer_response(
            &decoded.message,
            &self.chaos.version_bind,
            CHAOS_ANSWER_TTL,
            self.protocol.configured_max_udp_payload_size(),
        );
        self.metrics
            .increment_with_source(ResolverMetric::QueryAllowed, request.client_ip);
        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question.clone()),
            kind: ResolveDecisionKind::ChaosAnswer,
        };
        Some(
            self.finish_uniform(
                started_at,
                request,
                decoded_original_question_name(decoded),
                decision,
                response_bytes,
                None,
                Some(QueryEventBackend::from_snapshot(backend_snapshot)),
            )
            .await,
        )
    }

    /// Returns the local-DNS-answer `ResolveOutcome` if `decoded.question`
    /// matches a configured local entry (answer or explicit NODATA),
    /// otherwise `None` so the caller falls through to the cache/backend.
    #[allow(clippy::too_many_arguments)]
    async fn try_local_lookup(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: &QuestionKey,
        local_entries: &Arc<dyn LocalDnsEntries>,
        backend_snapshot: &BackendSnapshot,
    ) -> Option<ResolveOutcome> {
        let (response_bytes, kind) = match local_entries.lookup(&decoded.question) {
            LocalDnsLookup::Answer(entry) => {
                let response_bytes = self.local_entry_response(request, decoded, &entry);
                let kind = ResolveDecisionKind::LocalAnswer(
                    self.local_entry_answer_metadata(decoded, &entry),
                );
                (response_bytes, kind)
            }
            LocalDnsLookup::NoData(entry) => {
                let response_bytes = build_nodata_response(
                    &decoded.message,
                    self.protocol.configured_max_udp_payload_size(),
                );
                let kind = ResolveDecisionKind::LocalAnswer(LocalAnswerMetadata::from_entry(
                    &entry,
                    local_nodata_family(decoded.question.qtype),
                ));
                (response_bytes, kind)
            }
            LocalDnsLookup::NoMatch => return None,
        };
        self.metrics
            .increment_with_source(ResolverMetric::QueryAllowed, request.client_ip);
        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question.clone()),
            kind,
        };
        Some(
            self.finish_uniform(
                started_at,
                request,
                decoded_original_question_name(decoded),
                decision,
                response_bytes,
                None,
                Some(QueryEventBackend::from_snapshot(backend_snapshot)),
            )
            .await,
        )
    }

    /// RFC 1035 §4.1.1: RD=0 asks rdns not to pursue the query on the
    /// client's behalf. Reached only once local entries and cache have
    /// both already missed (see `resolve`'s ordering) -- serving those is
    /// "data rdns already has", not new work, so they still answer under
    /// RD=0. A genuine miss past that point would require a fresh
    /// upstream fetch or recursive resolution, which RD=0 declines; rdns
    /// answers SERVFAIL instead, the same way a public resolver like
    /// 1.1.1.1 refuses a cold RD=0 lookup rather than silently promoting
    /// it to a recursive one.
    ///
    /// SERVFAIL vs. REFUSED here is a real, deliberately-made choice, not
    /// an oversight: some resolvers (e.g. PowerDNS's `allow-no-rd`,
    /// Unbound's `allow_snoop`) refuse non-recursive cache-only queries
    /// with REFUSED by default. rdns follows 1.1.1.1's observed behavior
    /// (SERVFAIL) instead, since that's the concrete reference behavior
    /// this feature was modeled on.
    async fn refuse_recursion(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        event_cache_result: Option<QueryEventCacheResult>,
        backend_snapshot: &BackendSnapshot,
    ) -> ResolveOutcome {
        self.metrics
            .increment_with_source(ResolverMetric::RecursionRefused, request.client_ip);
        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question),
            kind: ResolveDecisionKind::RecursionRefused,
        };
        let response_bytes = self.responses.servfail(
            Some(decoded),
            self.protocol.configured_max_udp_payload_size(),
        );
        // `finish`, not `finish_uniform`: this refusal never performs a
        // backend miss/fetch -- it returns SERVFAIL immediately -- so its
        // latency must not land in `CacheMissQueryDuration` (that bucket
        // means "how long a real backend round trip took"), even though
        // the query event itself should still honestly report the cache
        // state that led to the refusal.
        self.finish(
            started_at,
            request,
            decoded_original_question_name(decoded),
            decision,
            response_bytes,
            event_cache_result,
            None,
            Some(QueryEventBackend::from_snapshot(backend_snapshot)),
        )
        .await
    }

    /// Finishes a cache-probe hit: applies the response-bytes block policy,
    /// then serves the blocked response or the cached one.
    ///
    /// `refresh_hints` are enqueued here, not in `probe_cache` where they
    /// were originally produced -- review found the original call site
    /// enqueued unconditionally, which could trigger a background refresh
    /// (a real backend fetch) for a hit that turns out to be response-policy
    /// blocked just below, or for an RD=0 cache-only query that shouldn't
    /// cause any fresh upstream work at all. Only enqueue once the hit is
    /// fully admitted: not blocked, and `recursion_desired`.
    #[allow(clippy::too_many_arguments)]
    async fn finish_cache_hit(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: &QuestionKey,
        response_bytes: Vec<u8>,
        event_cache_result: Option<QueryEventCacheResult>,
        backend_snapshot: &BackendSnapshot,
        refresh_hints: Vec<cache::RefreshHint>,
    ) -> ResolveOutcome {
        if let Some(block) = self.response_bytes_policy_block(request.client_ip, &response_bytes) {
            self.metrics
                .increment_with_source(ResolverMetric::QueryBlocked, request.client_ip);
            let decision = ResolveDecision {
                client_ip: request.client_ip,
                question: Some(question.clone()),
                kind: ResolveDecisionKind::Blocked(block.clone()),
            };
            let response_bytes = self.responses.blocked(
                decoded,
                &block,
                self.protocol.configured_max_udp_payload_size(),
            );
            return self
                .finish_uniform(
                    started_at,
                    request,
                    decoded_original_question_name(decoded),
                    decision,
                    response_bytes,
                    event_cache_result,
                    Some(QueryEventBackend::from_snapshot(backend_snapshot)),
                )
                .await;
        }
        if decoded.features.recursion_desired {
            for hint in refresh_hints {
                self.enqueue_refresh_job(hint);
            }
        }
        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question.clone()),
            kind: ResolveDecisionKind::CacheHit,
        };
        self.metrics
            .increment_with_source(ResolverMetric::QueryAllowed, request.client_ip);
        self.finish_uniform(
            started_at,
            request,
            decoded_original_question_name(decoded),
            decision,
            response_bytes,
            event_cache_result,
            Some(QueryEventBackend::from_snapshot(backend_snapshot)),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_coalesced_miss(
        &self,
        backend_snapshot: &BackendSnapshot,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        miss_key: MissKey,
        event_cache_result: Option<QueryEventCacheResult>,
    ) -> ResolveOutcome {
        match self.miss_coalescer.begin(miss_key.clone()) {
            SingleFlightTicket::Leader { key, flight } => {
                self.resolve_coalesced_leader(
                    backend_snapshot,
                    started_at,
                    request,
                    decoded,
                    question,
                    miss_key,
                    event_cache_result,
                    key,
                    flight,
                )
                .await
            }
            SingleFlightTicket::Follower { flight } => {
                self.resolve_coalesced_follower(
                    backend_snapshot,
                    started_at,
                    request,
                    decoded,
                    question,
                    miss_key,
                    event_cache_result,
                    flight,
                )
                .await
            }
        }
    }

    /// Resolves the query against the backend as the single-flight leader
    /// for `miss_key`, then releases any followers waiting on the result.
    #[allow(clippy::too_many_arguments)]
    async fn resolve_coalesced_leader(
        &self,
        backend_snapshot: &BackendSnapshot,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        miss_key: MissKey,
        event_cache_result: Option<QueryEventCacheResult>,
        key: MissKey,
        flight: Arc<InFlightMiss>,
    ) -> ResolveOutcome {
        let guard = SingleFlightLeader::new(Arc::clone(&self.miss_coalescer), key, flight);
        let backend_result = self.resolve_backend(backend_snapshot, decoded).await;
        let (decision, response_bytes) = self
            .prepare_backend_result(
                request,
                decoded,
                question,
                Some(miss_key),
                true,
                backend_snapshot.mode,
                backend_snapshot.cache_epoch,
                backend_result.clone(),
            )
            .await;
        guard.complete(backend_result);
        self.finish_uniform(
            started_at,
            request,
            decoded_original_question_name(decoded),
            decision,
            response_bytes,
            event_cache_result,
            Some(QueryEventBackend::from_snapshot(backend_snapshot)),
        )
        .await
    }

    /// Waits for the single-flight leader resolving `miss_key` to finish,
    /// then serves its cached result (applying the response-bytes block
    /// policy) or falls back to the leader's raw backend result if the entry
    /// didn't end up cacheable.
    #[allow(clippy::too_many_arguments)]
    async fn resolve_coalesced_follower(
        &self,
        backend_snapshot: &BackendSnapshot,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        miss_key: MissKey,
        event_cache_result: Option<QueryEventCacheResult>,
        flight: Arc<InFlightMiss>,
    ) -> ResolveOutcome {
        self.metrics
            .increment_with_source(ResolverMetric::CacheCoalescedMiss, request.client_ip);
        let backend_result = flight.wait().await;
        let Some(CoalescedFollowerHit {
            response_bytes,
            refresh_hints,
            event_cache_result: served_cache_result,
        }) = self
            .cache_hit_after_coalesced_miss(request, decoded, backend_snapshot, &miss_key)
            .await
        else {
            return self
                .finish_backend_result(
                    backend_snapshot,
                    started_at,
                    request,
                    decoded,
                    question,
                    Some(miss_key),
                    false,
                    event_cache_result,
                    backend_result,
                )
                .await;
        };

        if let Some(block) = self.response_bytes_policy_block(request.client_ip, &response_bytes) {
            self.metrics
                .increment_with_source(ResolverMetric::QueryBlocked, request.client_ip);
            let decision = ResolveDecision {
                client_ip: request.client_ip,
                question: Some(question),
                kind: ResolveDecisionKind::Blocked(block.clone()),
            };
            let response_bytes = self.responses.blocked(
                decoded,
                &block,
                self.protocol.configured_max_udp_payload_size(),
            );
            return self
                .finish(
                    started_at,
                    request,
                    decoded_original_question_name(decoded),
                    decision,
                    response_bytes,
                    // What the re-probe actually found (`Hit`, or `Stale` if
                    // the leader-populated entry already expired relative to
                    // this follower's own received_at), but latency here is
                    // dominated by `flight.wait().await` above, not a fast
                    // cache lookup, so bucket it by the pre-coalescing result.
                    Some(served_cache_result),
                    event_cache_result,
                    Some(QueryEventBackend::from_snapshot(backend_snapshot)),
                )
                .await;
        }

        // Admitted: not policy-blocked. `resolve_coalesced_follower` is only
        // ever reached with `recursion_desired = true` (an RD=0 query never
        // gets past `refuse_recursion` on a genuine miss), so unlike
        // `finish_cache_hit`'s hit path, no separate RD check is needed here.
        for hint in refresh_hints {
            self.enqueue_refresh_job(hint);
        }

        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question),
            kind: ResolveDecisionKind::CacheHit,
        };
        self.metrics
            .increment_with_source(ResolverMetric::QueryAllowed, request.client_ip);
        self.finish(
            started_at,
            request,
            decoded_original_question_name(decoded),
            decision,
            response_bytes,
            // Same reasoning as above: the audit result is what the re-probe
            // actually found, while latency buckets by the pre-coalescing
            // result since this follower waited on the leader's full backend
            // round trip.
            Some(served_cache_result),
            event_cache_result,
            Some(QueryEventBackend::from_snapshot(backend_snapshot)),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_backend_and_finish(
        &self,
        backend_snapshot: &BackendSnapshot,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        miss_key: Option<MissKey>,
        cache_store_allowed: bool,
        event_cache_result: Option<QueryEventCacheResult>,
    ) -> ResolveOutcome {
        let backend_result = self.resolve_backend(backend_snapshot, decoded).await;
        self.finish_backend_result(
            backend_snapshot,
            started_at,
            request,
            decoded,
            question,
            miss_key,
            cache_store_allowed,
            event_cache_result,
            backend_result,
        )
        .await
    }

    async fn resolve_backend(
        &self,
        backend_snapshot: &BackendSnapshot,
        decoded: &DecodedQuery,
    ) -> Result<ResolutionResponse, ResolutionBackendError> {
        let query = if backend_snapshot.mode == ResolutionMode::Recursive {
            backend_query_with_configured_udp_limit(
                decoded,
                self.protocol.configured_max_udp_payload_size(),
            )
        } else {
            decoded.clone()
        };
        backend_snapshot
            .backend
            .resolve(ResolutionRequest {
                query,
                backend_generation: backend_snapshot.generation,
            })
            .await
    }

    fn local_entry_response(
        &self,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        entry: &LocalDnsEntry,
    ) -> Vec<u8> {
        let configured_max_udp_payload_size = self.protocol.configured_max_udp_payload_size();
        let response = match decoded.question.qtype {
            A_RECORD_TYPE => build_a_answers_response(
                &decoded.message,
                &entry.ipv4,
                entry.ttl,
                configured_max_udp_payload_size,
            ),
            AAAA_RECORD_TYPE => build_aaaa_answers_response(
                &decoded.message,
                &entry.ipv6,
                entry.ttl,
                configured_max_udp_payload_size,
            ),
            _ => build_nodata_response(&decoded.message, configured_max_udp_payload_size),
        };
        if !request.observed_source.is_tcp()
            && decoded
                .message
                .response_exceeds_udp_payload(response.len(), configured_max_udp_payload_size)
        {
            // Deliberately the plain, cookie-unaware `mirrored_client_opt_record`
            // here, not `truncated_response_for_query` (which now attaches a
            // server cookie) -- `local_entry_response` and everything it calls
            // are explicitly out of scope for cookie-echoing (section 05 of the
            // EDNS-cookie plan): the untruncated branch above already never
            // echoes a cookie (`build_a_answers_response`/`build_aaaa_answers_response`/
            // `build_nodata_response` all build via the cookie-unaware
            // `message_edns_opt_record`), so truncation must not be the one
            // path that suddenly does.
            let opt = mirrored_client_opt_record(&decoded.message, configured_max_udp_payload_size);
            crate::protocol::build_truncated_wire_response(
                decoded.message.header.id,
                decoded.message.header.rd(),
                false,
                decoded.message.header.cd(),
                ResponseCode::NoError,
                &decoded.question_wire,
                opt.as_ref(),
            )
        } else {
            response
        }
    }

    fn local_entry_answer_metadata(
        &self,
        decoded: &DecodedQuery,
        entry: &LocalDnsEntry,
    ) -> LocalAnswerMetadata {
        LocalAnswerMetadata::from_entry(entry, local_answer_family(decoded.question.qtype))
    }

    /// Note: `refresh_hints` are deliberately *not* enqueued here, even
    /// though this is where `ChainLookup::Answered` first produces them.
    /// Review found that enqueueing this early could trigger a background
    /// refresh (a real, if server-internal, backend fetch) for a query that
    /// the rest of the pipeline hasn't yet admitted -- an RD=0 cache-only
    /// query, or a hit the response-block policy is about to reject in
    /// `finish_cache_hit`. `CacheProbe::refresh_hints` carries them forward
    /// so the caller enqueues only once a hit is fully admitted.
    async fn probe_cache(
        &self,
        backend_snapshot: &BackendSnapshot,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
    ) -> CacheProbe {
        if !cache_supported(decoded) {
            self.metrics
                .increment_with_source(ResolverMetric::CacheBypass, request.client_ip);
            self.metrics
                .increment_with_source(ResolverMetric::CacheMiss, request.client_ip);
            return CacheProbe {
                miss_key: None,
                hit: None,
                store_allowed: false,
                event_cache_result: Some(QueryEventCacheResult::Bypass),
                refresh_hints: Vec::new(),
            };
        }

        // No effective-payload-size class here: a UDP query and a TCP query
        // for the same question now share one cache entry — see
        // docs/plans/cache_key.md. Every entry stores raw record data, not
        // a pre-built response, so `allow_udp_truncation`/`is_tcp()` checks
        // at serve time (assemble_response, not the cache key) are what
        // keep each response correct for the current request's transport.
        let epoch = backend_snapshot.cache_epoch;
        let lookup = self.cache.lookup_chain(
            &decoded.question.qname,
            decoded.question.qtype,
            decoded.question.qclass,
            decoded.features.dnssec_ok,
            epoch,
            self.max_chain_depth,
            request.received_at.0,
            &self.refresh_config,
        );
        let CacheLookupEvaluation {
            store_allowed,
            hit,
            event_cache_result,
            refresh_hints,
        } = self.evaluate_cache_lookup(lookup, decoded, request);

        // The DO dimension of `MissKey` only needs to distinguish backend
        // fetches that can genuinely differ. The forwarding backend still
        // relays the requester's own DO flag verbatim to whatever it
        // forwards to, so a DO=false and a DO=true miss for the same name
        // can still get different bytes back and must stay separate
        // single-flight leaders. The recursive backend, since the
        // always-fetch-DNSSEC change in `resolve_one_hop`, now queries
        // upstream authorities with `dnssec_ok = true` unconditionally --
        // backend behavior is identical for every requester regardless of
        // their own DO flag, so canonicalizing this dimension to `true`
        // lets concurrent mixed-DO misses for the same name coalesce onto
        // one backend fetch instead of duplicating it. The per-requester
        // DO=false/DO=true response difference is still handled correctly
        // downstream by `filter_response_for_requester` in
        // `prepare_backend_result`, which trims the client-facing bytes to
        // this specific requester's DO flag after the shared fetch/store
        // completes.
        let miss_key_dnssec_ok = match backend_snapshot.mode {
            ResolutionMode::Recursive => true,
            ResolutionMode::Forward => decoded.features.dnssec_ok,
        };

        CacheProbe {
            miss_key: Some((
                decoded.question.qname.clone(),
                decoded.question.qtype,
                decoded.question.qclass,
                epoch,
                miss_key_dnssec_ok,
            )),
            hit,
            store_allowed,
            event_cache_result: Some(event_cache_result),
            refresh_hints,
        }
    }

    /// Maps a cache lookup outcome to whether the eventual backend result
    /// may be stored, the serialized hit response (if any), and the
    /// outcome to report on the query event.
    ///
    /// Unlike the old flat `CacheLookup`, `ChainLookup` has no
    /// `Expired`/`Unavailable` variants: `resolve_from_cache` (section-06)
    /// folds a stale-namespace match — and, with serve-stale disabled or
    /// beyond the stale window, an expired match — into `Miss` before ever
    /// returning it (an expired *positive* entry inside the RFC 8767 stale
    /// window is instead returned as an `Answered` stale serve, classified
    /// here via `chain_contains_stale`), and the new cache has no
    /// external dependency that could make it "unavailable" (it's
    /// in-process memory, not a service call) — so
    /// `ResolverMetric::CacheExpired`/`CacheUnavailable` are no longer
    /// emitted from this path. This is an accepted, architecture-driven
    /// behavior change, not an oversight.
    fn evaluate_cache_lookup(
        &self,
        lookup: ChainLookup,
        decoded: &DecodedQuery,
        request: &ResolveRequest,
    ) -> CacheLookupEvaluation {
        match lookup {
            ChainLookup::Answered(resolved) => {
                let refresh_hints = resolved.refresh_hints.clone();
                let stale = chain_contains_stale(&resolved.chain, request.received_at.0);
                let response_bytes = self.serialize_cache_hit_answer(decoded, &resolved, request);
                self.record_cache_hit_metrics(&response_bytes, false, stale, request.client_ip);
                CacheLookupEvaluation {
                    store_allowed: false,
                    hit: Some(response_bytes),
                    event_cache_result: cache_hit_event_result(stale),
                    refresh_hints,
                }
            }
            ChainLookup::NxDomain(resolved) => {
                let stale = chain_contains_stale(&resolved.chain, request.received_at.0);
                let response_bytes = self.serialize_cache_hit_negative(
                    decoded,
                    &resolved,
                    ResponseCode::NxDomain,
                    request,
                );
                self.record_cache_hit_metrics(&response_bytes, true, stale, request.client_ip);
                CacheLookupEvaluation {
                    store_allowed: false,
                    hit: Some(response_bytes),
                    event_cache_result: cache_hit_event_result(stale),
                    refresh_hints: Vec::new(),
                }
            }
            ChainLookup::NoData(resolved) => {
                let stale = chain_contains_stale(&resolved.chain, request.received_at.0);
                let response_bytes = self.serialize_cache_hit_negative(
                    decoded,
                    &resolved,
                    ResponseCode::NoError,
                    request,
                );
                self.record_cache_hit_metrics(&response_bytes, true, stale, request.client_ip);
                CacheLookupEvaluation {
                    store_allowed: false,
                    hit: Some(response_bytes),
                    event_cache_result: cache_hit_event_result(stale),
                    refresh_hints: Vec::new(),
                }
            }
            ChainLookup::Miss => {
                self.metrics
                    .increment_with_source(ResolverMetric::CacheMiss, request.client_ip);
                CacheLookupEvaluation {
                    store_allowed: true,
                    hit: None,
                    event_cache_result: QueryEventCacheResult::Miss,
                    refresh_hints: Vec::new(),
                }
            }
        }
    }

    /// Non-blocking, best-effort enqueue: a full (or closed, e.g. no
    /// worker pool wired up yet) channel counts as a dropped trigger
    /// (`RefreshQueueFull`), never blocks, never panics. Applies
    /// independently per hint — one drop from a multi-hop chain doesn't
    /// affect the others, each already enqueued in its own loop iteration
    /// by the caller.
    fn enqueue_refresh_job(&self, hint: cache::RefreshHint) {
        let job = RefreshJob {
            domain: hint.domain,
            qtype: hint.qtype,
            qclass: hint.qclass,
        };
        match self.refresh_sender.try_send(job) {
            Ok(()) => self.metrics.increment(ResolverMetric::RefreshTriggered),
            Err(_) => self.metrics.increment(ResolverMetric::RefreshQueueFull),
        }
    }

    fn record_cache_hit_metrics(
        &self,
        response_bytes: &[u8],
        negative: bool,
        stale: bool,
        client_ip: IpAddr,
    ) {
        self.metrics
            .increment_with_source(ResolverMetric::CacheHit, client_ip);
        if negative {
            self.metrics
                .increment_with_source(ResolverMetric::CacheNegativeHit, client_ip);
        }
        if stale {
            self.metrics
                .increment_with_source(ResolverMetric::CacheStaleHit, client_ip);
        }
        if response_is_truncated(response_bytes) {
            self.metrics
                .increment_with_source(ResolverMetric::CacheResponseTruncated, client_ip);
        }
    }

    fn serialize_cache_hit_answer(
        &self,
        decoded: &DecodedQuery,
        resolved: &cache::ResolvedAnswer,
        request: &ResolveRequest,
    ) -> Vec<u8> {
        assemble_response(
            decoded.message.header.id,
            &decoded.question_wire,
            &decoded.features,
            resolved,
            request.received_at.0,
            !request.observed_source.is_tcp(),
            self.protocol.configured_max_udp_payload_size(),
            &self.cookie_secret,
            request.client_ip,
        )
    }

    fn serialize_cache_hit_negative(
        &self,
        decoded: &DecodedQuery,
        resolved: &cache::ResolvedNegative,
        response_code: ResponseCode,
        request: &ResolveRequest,
    ) -> Vec<u8> {
        assemble_negative_response(
            decoded.message.header.id,
            &decoded.question_wire,
            &decoded.features,
            resolved,
            response_code,
            request.received_at.0,
            !request.observed_source.is_tcp(),
            self.protocol.configured_max_udp_payload_size(),
            &self.cookie_secret,
            request.client_ip,
        )
    }

    /// Note: `refresh_hints` are carried in the return value rather than
    /// enqueued here, for the same reason `probe_cache` no longer enqueues
    /// directly (see its doc comment) -- this follower-side hit still has
    /// to pass the response-block policy check in `resolve_coalesced_follower`
    /// before it's genuinely admitted.
    async fn cache_hit_after_coalesced_miss(
        &self,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        backend_snapshot: &BackendSnapshot,
        miss_key: &MissKey,
    ) -> Option<CoalescedFollowerHit> {
        let epoch = backend_snapshot.cache_epoch;
        let lookup = self.cache.lookup_chain(
            &miss_key.0,
            miss_key.1,
            miss_key.2,
            miss_key.4,
            epoch,
            self.max_chain_depth,
            request.received_at.0,
            &self.refresh_config,
        );
        match lookup {
            ChainLookup::Answered(resolved) => {
                // This is the single-flight *follower* path -- exactly the
                // concurrent/hot-domain scenario the refresh feature
                // targets, so hints from here must reach the caller too,
                // the same as `probe_cache`'s leader-side path.
                let refresh_hints = resolved.refresh_hints.clone();
                let stale = chain_contains_stale(&resolved.chain, request.received_at.0);
                let response_bytes = self.serialize_cache_hit_answer(decoded, &resolved, request);
                self.record_cache_hit_metrics(&response_bytes, false, stale, request.client_ip);
                Some(CoalescedFollowerHit {
                    response_bytes,
                    refresh_hints,
                    event_cache_result: cache_hit_event_result(stale),
                })
            }
            ChainLookup::NxDomain(resolved) => {
                let response_bytes = self.serialize_cache_hit_negative(
                    decoded,
                    &resolved,
                    ResponseCode::NxDomain,
                    request,
                );
                let stale = chain_contains_stale(&resolved.chain, request.received_at.0);
                self.record_cache_hit_metrics(&response_bytes, true, stale, request.client_ip);
                Some(CoalescedFollowerHit {
                    response_bytes,
                    refresh_hints: Vec::new(),
                    event_cache_result: cache_hit_event_result(stale),
                })
            }
            ChainLookup::NoData(resolved) => {
                let response_bytes = self.serialize_cache_hit_negative(
                    decoded,
                    &resolved,
                    ResponseCode::NoError,
                    request,
                );
                let stale = chain_contains_stale(&resolved.chain, request.received_at.0);
                self.record_cache_hit_metrics(&response_bytes, true, stale, request.client_ip);
                Some(CoalescedFollowerHit {
                    response_bytes,
                    refresh_hints: Vec::new(),
                    event_cache_result: cache_hit_event_result(stale),
                })
            }
            ChainLookup::Miss => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_backend_result(
        &self,
        backend_snapshot: &BackendSnapshot,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        miss_key: Option<MissKey>,
        cache_store_allowed: bool,
        event_cache_result: Option<QueryEventCacheResult>,
        backend_result: Result<ResolutionResponse, ResolutionBackendError>,
    ) -> ResolveOutcome {
        let (decision, response_bytes) = self
            .prepare_backend_result(
                request,
                decoded,
                question,
                miss_key,
                cache_store_allowed,
                backend_snapshot.mode,
                backend_snapshot.cache_epoch,
                backend_result,
            )
            .await;
        self.finish_uniform(
            started_at,
            request,
            decoded_original_question_name(decoded),
            decision,
            response_bytes,
            event_cache_result,
            Some(QueryEventBackend::from_snapshot(backend_snapshot)),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_backend_result(
        &self,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        miss_key: Option<MissKey>,
        cache_store_allowed: bool,
        backend_mode: ResolutionMode,
        cache_epoch: u64,
        backend_result: Result<ResolutionResponse, ResolutionBackendError>,
    ) -> (ResolveDecision, Vec<u8>) {
        let Ok(mut response) = backend_result else {
            return self.backend_failure_response(request, decoded, question);
        };

        let Some(response_message) = validate_backend_response(&mut response, decoded) else {
            return self.backend_failure_response(request, decoded, question);
        };

        // Deliberately unlabeled: with single-flight coalescing this
        // increment only runs for whichever client's request ended up as
        // the fetch leader (followers re-probe the cache and never reach
        // here), so a `source_ip` label would attribute a shared backend
        // fetch to an arbitrary race winner. `UpstreamFailure` in
        // `backend_failure_response` stays unlabeled for the same reason.
        self.metrics.increment(ResolverMetric::UpstreamSuccess);
        if let Some(block) = self.response_policy_block(request.client_ip, &response_message) {
            self.metrics
                .increment_with_source(ResolverMetric::QueryBlocked, request.client_ip);
            let decision = ResolveDecision {
                client_ip: request.client_ip,
                question: Some(question),
                kind: ResolveDecisionKind::Blocked(block.clone()),
            };
            let response_bytes = self.responses.blocked(
                decoded,
                &block,
                self.protocol.configured_max_udp_payload_size(),
            );
            return (decision, response_bytes);
        }

        // `to_vec` here is a genuine per-request copy, not waste: this
        // response may be shared with coalesced followers (the `Bytes`
        // payload is refcounted across them), and the id/RD rewrite below
        // is per-requester, so each serve needs its own mutable buffer.
        let mut response_bytes = response.bytes.to_vec();
        // This response may be the coalescing leader's own fetch result,
        // reused verbatim for a follower whose request wasn't identical to
        // the leader's (see `resolve_coalesced_follower` ->
        // `finish_backend_result` -> here) -- `MissKey` coalesces on
        // name/type/class/namespace/DO only, not RD or casing, so the
        // leader's RD bit is not necessarily this request's own. Rewriting
        // both the ID and RD bit from `decoded.message` (rather than just
        // the ID) keeps a follower's own reported RD flag accurate even
        // when this is a shared/reused backend result.
        if self
            .protocol
            .rewrite_response_request_fields(&mut response_bytes, &decoded.message)
            .is_err()
        {
            return self.backend_failure_response(request, decoded, decoded.question.clone());
        }

        if let (true, Some(_miss_key)) = (cache_store_allowed, &miss_key) {
            if response.cache_directive.is_cacheable() {
                // For the recursive backend, upstream is now always asked for
                // DNSSEC material regardless of this requester's own DO flag
                // (see `resolve_one_hop`), so the stored entry is always
                // DNSSEC-complete -- stamp `dnssec_complete: true`
                // unconditionally rather than gating on
                // `decoded.features.dnssec_ok`. Without this, a DO=false
                // requester's fetch would still tag the entry
                // `dnssec_complete: false`, and `lookup_hop`'s DO=true gate
                // would keep rejecting it on a cache hit -- silently
                // defeating the whole point of this change. The forwarding
                // backend is unaffected and still needs the real per-request
                // gate: it relays client wire bytes verbatim with no EDNS
                // construction of its own, so it still only has DNSSEC
                // material when the requester itself asked for it.
                let store_dnssec_ok = match backend_mode {
                    ResolutionMode::Recursive => true,
                    ResolutionMode::Forward => decoded.features.dnssec_ok,
                };
                // AA (RFC 1035 §4.1.1) describes *this resolver's* own
                // authority over the zone, not whichever upstream server
                // this response happened to come from. For a recursive
                // fetch, `response_message` is an upstream authority's
                // answer, not rdns's own -- rdns is never itself
                // authoritative while recursing, so a recursive cache hit
                // must never claim AA=1 (this must stay consistent with the
                // recursive miss path, which already always serializes its
                // synthesized responses with AA=false). The forwarding
                // backend is a transparent proxy and may legitimately relay
                // an answer from a forwarder that really is authoritative
                // for the zone, so its real AA bit is preserved.
                let store_authoritative = match backend_mode {
                    ResolutionMode::Recursive => false,
                    ResolutionMode::Forward => response_message.header.aa(),
                };
                self.store_cache_response(
                    cache_epoch,
                    &response_message,
                    &question,
                    request,
                    store_dnssec_ok,
                    store_authoritative,
                )
                .await;
            } else {
                self.metrics.increment(ResolverMetric::CacheStoreSkipped);
            }
        }

        // Whether the *unfiltered*, DNSSEC-complete bytes fit the
        // requester's UDP payload size. Filtering only ever removes bytes
        // (RRSIGs/DNSKEY/DS/etc. the requester didn't ask for), so if the
        // unfiltered material already fits, the filtered result is
        // guaranteed to fit too -- no truncation risk, and no need to
        // guess. But the converse does NOT hold: unfiltered exceeding the
        // limit does not mean the *filtered* response would too, since for
        // a DO=false requester the excess may be entirely DNSSEC material
        // that filtering is about to strip anyway. Deciding truncation
        // from `exceeds_unfiltered` alone (without ever computing the
        // filtered size) was exactly that invalid inference, and sent
        // needless TC=1/TCP-fallback round trips to ordinary DO=false
        // clients whenever DNSSEC material alone pushed the response over
        // the limit -- see the two independent Codex adversarial reviews
        // that flagged this. Only the DO=true (or non-recursive) case
        // still gets to skip straight to truncation: filtering is a no-op
        // there (DO=true keeps DNSSEC material; the forwarding backend has
        // no filter step at all), so there is genuinely nothing filtering
        // could change and paying for the clone-heavy
        // `filter_response_for_requester` + a second full
        // `serialize_recursive_response` pass would be pure waste.
        let configured_max_udp_payload_size = self.protocol.configured_max_udp_payload_size();
        // Shared by `exceeds_unfiltered` below and by
        // `enforce_udp_payload_limit_after_reserialize` further down --
        // TCP responses are never truncated this way, regardless of
        // whether the size check runs against the pre-rebuild leader
        // framing or the actual per-requester reserialized bytes.
        let is_udp_response = !request.observed_source.is_tcp();
        let exceeds_unfiltered = backend_mode == ResolutionMode::Recursive
            && is_udp_response
            && decoded.message.response_exceeds_udp_payload(
                response_bytes.len(),
                configured_max_udp_payload_size,
            );

        // Whether a DO=false client-facing filter pass is even applicable:
        // recursive backend (the forwarding backend never routed through
        // `synthesize_recursive_cname_response` and has no
        // `recursive_synthesis` context to filter with; its bytes must
        // pass through unchanged) and a requester that didn't ask for
        // DNSSEC material (DO=true wants everything already stored in
        // `response_message` -- filtering would be a no-op).
        let filterable = backend_mode == ResolutionMode::Recursive
            && !decoded.features.dnssec_ok
            && response.recursive_synthesis.is_some();

        if exceeds_unfiltered && !filterable {
            // DO=true (or no synthesis context to filter with): filtering
            // wouldn't change anything, so there is no reason to attempt
            // it before truncating.
            response_bytes = truncated_response_for_query(
                decoded,
                response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                configured_max_udp_payload_size,
                &self.cookie_secret,
                request.client_ip,
                self.clock.now(),
            );
        } else if filterable {
            let synthesis = response
                .recursive_synthesis
                .as_ref()
                .expect("filterable guarantees recursive_synthesis is Some");
            let questions = [&synthesis.original_question, &synthesis.final_question];

            // Cheap no-op check: if there's nothing in `response_message`
            // that a DO=false filter pass would actually remove (no
            // DNSSEC-only material, or all of it directly answers this
            // client's own question), the filtered result is proven --
            // exactly, not just for the already-fits case -- to be
            // byte-for-byte identical to what filtering would produce.
            // `filtering_would_change_response` doesn't look at size at
            // all, so this check is valid regardless of whether the
            // unfiltered bytes fit: cloning every record and reserializing
            // only to reproduce (or fail to shrink) the same content is
            // pure waste either way. This is distinct from the case below
            // where filtering *would* change something: there, the
            // filtered size genuinely has to be measured before truncation
            // can be decided, since filtering may be exactly what brings
            // it back under the limit.
            //
            // Content is settled either way, but *framing* (question-echo
            // casing, OPT presence) is not: `exceeds_unfiltered` was
            // measured once, early, against the leader/synthesizer-framed
            // `response_bytes` -- only trustworthy for *this* requester if
            // `recursive_synthesis_reused_own_framing` says its own framing
            // is the same framing that measurement was taken against. When
            // it differs (a coalesced follower whose own EDNS
            // presence/DO/question casing doesn't match whoever actually
            // synthesized this shared response), the requester's own
            // framing must be rebuilt and *re-measured* before truncation
            // can be decided -- rebuilding can push a leader-fitting
            // response over the requester's own limit (e.g. a larger own
            // OPT record) just as easily as it can pull a leader-oversized
            // one back under it (e.g. dropping the leader's OPT entirely),
            // so the stale `exceeds_unfiltered` verdict cannot be trusted
            // in either direction once framing differs.
            if !filtering_would_change_response(&response_message, &questions) {
                if recursive_synthesis_reused_own_framing(decoded, synthesis) {
                    // This requester's own question-echo/OPT framing
                    // already matches whatever `response_bytes` (==
                    // `response.bytes`) has baked in -- the ordinary,
                    // non-coalesced path, or a coalesced follower whose
                    // framing happens to exactly match the leader's.
                    // `rebuild_recursive_response_with_own_framing` would
                    // just reproduce the same bytes; skip the clone-heavy
                    // reserialize entirely. `response_bytes` is unchanged
                    // and *is* this requester's own framing, so
                    // `exceeds_unfiltered` (measured against those same
                    // bytes) is a trustworthy, non-stale size verdict here.
                    if exceeds_unfiltered {
                        response_bytes = truncated_response_for_query(
                            decoded,
                            response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                            configured_max_udp_payload_size,
                            &self.cookie_secret,
                            request.client_ip,
                            self.clock.now(),
                        );
                    }
                } else if let Ok(bytes) = rebuild_recursive_response_with_own_framing(
                    decoded,
                    &response_message,
                    response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                    configured_max_udp_payload_size,
                    &self.cookie_secret,
                    request.client_ip,
                    self.clock.now(),
                ) {
                    // There's nothing DNSSEC-specific for a DO=false filter
                    // pass to remove, so the content of `response_bytes` (==
                    // `response.bytes`) is already right -- but its baked-in
                    // OPT record and echoed question still reflect whichever
                    // request originally synthesized this response
                    // (`synthesis.original_query`), not necessarily *this*
                    // requester's own (a coalesced follower can legitimately
                    // differ from the leader on EDNS presence or question-name
                    // casing even though both share the same DO=false
                    // `MissKey` dimension -- see
                    // `rebuild_recursive_response_with_own_framing`'s doc
                    // comment). Rebuild header/question/OPT from
                    // `decoded.message` cheaply, without paying for a
                    // clone-heavy `filter_response_for_requester` pass that
                    // would just reproduce the same answers/authorities.
                    //
                    // This requester's own framing can move the size either
                    // direction relative to the stale, pre-rebuild
                    // `exceeds_unfiltered` measurement of the leader-framed
                    // bytes -- appending this requester's own (larger) OPT
                    // record can push a leader-fitting response over the
                    // limit, and dropping/shrinking it relative to the
                    // leader's can just as easily pull a leader-oversized
                    // response back under it (e.g. an EDNS leader with a
                    // non-EDNS follower: the leader-framed bytes may exceed
                    // the limit purely due to the leader's own OPT record,
                    // while the follower's own OPT-less framing genuinely
                    // fits). Always re-check the *actual* rebuilt bytes
                    // about to be sent, regardless of what
                    // `exceeds_unfiltered` said about the leader's framing
                    // (RFC 6891 §6.2.3/§7, RFC 1035 §4.1.1).
                    response_bytes = enforce_udp_payload_limit_after_reserialize(
                        decoded,
                        is_udp_response,
                        bytes,
                        response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                        configured_max_udp_payload_size,
                        &self.cookie_secret,
                        request.client_ip,
                        self.clock.now(),
                    );
                }
            } else {
                // Client-facing filter: storage above always saw the full,
                // DNSSEC-complete `response_message`. The bytes actually
                // sent to *this* client still need to be trimmed to what it
                // asked for -- recursive misses go straight to the wire
                // with no `assemble_response`-style filtering pass in
                // between, unlike cache hits. This runs whenever filtering
                // could plausibly matter: when it would actually remove
                // something, or when the unfiltered bytes don't fit and the
                // filtered size has to be measured before truncation can be
                // decided, since filtering may be exactly what brings it
                // back under the limit.
                let (answers, authorities, mut additionals) =
                    filter_response_for_requester(&response_message, false, &questions);
                // `recursive_response_record_supported` never matches
                // `RecordData::OPT` -- re-append the mirrored client OPT
                // record separately, same as
                // `synthesize_recursive_cname_response` does, or a DO=false
                // client's filtered response would silently lose EDNS (UDP
                // payload size negotiation, etc.).
                // Header fields (ID/RD/CD) and the echoed question must
                // come from *this* requester's own query, not
                // `synthesis.original_query` -- that's whichever request
                // originally synthesized this response, which on a
                // coalesced-follower fallback (leader's result wasn't
                // cacheable, so no cache-hit path reran per-follower) is
                // the leader's request, not this follower's. Using it here
                // would put the leader's transaction ID/RD/CD back on this
                // follower's response (RFC 1035 §4.1.1, RFC 4035 §3.2.2).
                // `synthesis.original_question`/`final_question` (via
                // `questions` above) are still the right source for *which*
                // records match during filtering -- that's about content,
                // not header framing.
                if let Some(opt) = mirrored_client_opt_record_with_cookie(
                    &decoded.message,
                    configured_max_udp_payload_size,
                    &self.cookie_secret,
                    request.client_ip,
                    self.clock.now(),
                ) {
                    additionals.push(opt);
                }
                if let Ok(filtered_bytes) = serialize_recursive_response(
                    &decoded.message,
                    response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                    false,
                    &answers,
                    &authorities,
                    &additionals,
                ) {
                    // Re-check the *actual* filtered-and-reframed bytes
                    // against this requester's own UDP payload limit,
                    // unconditionally -- not just when the earlier,
                    // pre-rebuild `exceeds_unfiltered` (measured from the
                    // leader-framed `response_bytes`) was already true.
                    // `exceeds_unfiltered` being false only proves the
                    // *leader's* framing fit; this requester's own OPT (or
                    // the leader having had none at all) can still push
                    // `filtered_bytes` past the limit even though
                    // `exceeds_unfiltered` was false, since filtering can
                    // both remove DNSSEC material *and* add this
                    // requester's own (possibly larger) OPT record. Trusting
                    // the stale flag here was the second half of the same
                    // RFC 6891 §6.2.3/§7 + RFC 1035 §4.1.1 gap the DO=false
                    // and DO=true fast paths had.
                    response_bytes = enforce_udp_payload_limit_after_reserialize(
                        decoded,
                        is_udp_response,
                        filtered_bytes,
                        response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                        configured_max_udp_payload_size,
                        &self.cookie_secret,
                        request.client_ip,
                        self.clock.now(),
                    );
                }
            }
        } else if let Some(synthesis) = response
            .recursive_synthesis
            .as_ref()
            .filter(|_| backend_mode == ResolutionMode::Recursive)
        {
            // DO=true (the only way to reach here with a recursive-synthesis
            // response and `filterable == false`, since `filterable` only
            // excludes DO=true and non-recursive/non-synthesis responses,
            // and the non-recursive/no-synthesis case has no baked-in-OPT
            // problem to begin with -- see this branch's doc comment on
            // `rebuild_recursive_response_with_own_framing`). Filtering is a
            // genuine no-op for DO=true (it keeps every DNSSEC record), and
            // the unfiltered bytes already fit
            // (`!exceeds_unfiltered`), so the content of `response_bytes`
            // (== `response.bytes`) needs no changes -- but same as the
            // DO=false no-op case above, its OPT record and echoed question
            // still reflect whichever request originally synthesized this
            // response, not necessarily this requester's own, on a
            // coalesced-follower fallback. Rebuild header/question/OPT from
            // `decoded.message` cheaply rather than leaving the leader's
            // framing on this follower's response -- but only when that
            // framing has actually been detected to differ; the ordinary,
            // non-coalesced path (or a coalesced follower whose framing
            // happens to exactly match) needs no reserialize at all, and
            // `response_bytes` unchanged is still covered by the
            // `exceeds_unfiltered` check above.
            if !recursive_synthesis_reused_own_framing(decoded, synthesis)
                && let Ok(bytes) = rebuild_recursive_response_with_own_framing(
                    decoded,
                    &response_message,
                    response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                    configured_max_udp_payload_size,
                    &self.cookie_secret,
                    request.client_ip,
                    self.clock.now(),
                )
            {
                // Same growth risk as the DO=false fast path above:
                // appending this requester's own OPT record can push the
                // rebuilt response past its UDP payload limit even though
                // the leader-framed bytes fit -- re-check the actual
                // bytes, not the stale pre-rebuild `exceeds_unfiltered`
                // measurement.
                response_bytes = enforce_udp_payload_limit_after_reserialize(
                    decoded,
                    is_udp_response,
                    bytes,
                    response_code(&response_message).unwrap_or(ResponseCode::ServFail),
                    configured_max_udp_payload_size,
                    &self.cookie_secret,
                    request.client_ip,
                    self.clock.now(),
                );
            }
        } else if backend_mode == ResolutionMode::Forward
            && decoded.features.client_cookie.is_some()
        {
            // Cookie-only queries are cache-admissible regardless of
            // backend mode (`cache_supported()` doesn't distinguish), so a
            // forward-mode miss can reach here with a Cookie-bearing
            // `decoded` query too -- every branch above is gated on
            // `backend_mode == Recursive` and does nothing for forward
            // mode, so without this branch `response_bytes` would stay
            // whatever `response.bytes` already was: the upstream
            // forwarder's raw relayed bytes, which may echo a different
            // requester's client cookie (coalesced-follower fallback) or a
            // server cookie computed against rdns's own outbound IP rather
            // than this client's. See
            // `rebuild_forward_response_with_own_cookie`'s doc comment for
            // the full reasoning (this gap was caught by PR review, not
            // originally scoped into section-05 of the EDNS-cookie plan,
            // which only enumerated `mirrored_client_opt_record` call sites
            // reachable from recursive-synthesis responses).
            if let Ok(bytes) = rebuild_forward_response_with_own_cookie(
                decoded,
                &response_message,
                configured_max_udp_payload_size,
                &self.cookie_secret,
                request.client_ip,
                self.clock.now(),
            ) {
                response_bytes = bytes;
            }
        }

        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question),
            kind: ResolveDecisionKind::Allowed,
        };
        self.metrics
            .increment_with_source(ResolverMetric::QueryAllowed, request.client_ip);
        (decision, response_bytes)
    }

    fn response_policy_block(&self, client_ip: IpAddr, response: &Message) -> Option<PolicyBlock> {
        response_policy_domains(response).find_map(|domain| {
            let PolicyDecision::Block(block) =
                self.policy.evaluate_response_name(client_ip, &domain)
            else {
                return None;
            };
            Some(block)
        })
    }

    fn response_bytes_policy_block(
        &self,
        client_ip: IpAddr,
        response_bytes: &[u8],
    ) -> Option<PolicyBlock> {
        let response = Message::parse(response_bytes).ok()?;
        self.response_policy_block(client_ip, &response)
    }

    fn backend_failure_response(
        &self,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
    ) -> (ResolveDecision, Vec<u8>) {
        self.metrics.increment(ResolverMetric::UpstreamFailure);
        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question),
            kind: ResolveDecisionKind::BackendFailure,
        };
        let response_bytes = self.responses.servfail(
            Some(decoded),
            self.protocol.configured_max_udp_payload_size(),
        );
        (decision, response_bytes)
    }

    async fn store_cache_response(
        &self,
        epoch: u64,
        response: &Message,
        question: &QuestionKey,
        request: &ResolveRequest,
        dnssec_ok: bool,
        store_authoritative: bool,
    ) {
        if let Some(decomposed) = self.cache_store_for_response(
            response,
            question,
            request.received_at.0,
            dnssec_ok,
            store_authoritative,
        ) {
            if decomposed.negative.is_some() {
                self.metrics.increment(ResolverMetric::CacheNegativeStore);
            }
            self.metrics.increment(ResolverMetric::CacheStore);
            self.cache.store_response(decomposed, epoch);
        } else {
            self.metrics.increment(ResolverMetric::CacheStoreSkipped);
        }
    }

    /// Builds the `DecomposedResponse` this response should be stored as,
    /// or `None` if it isn't cacheable at all. Unlike the old
    /// `cache_store_for_response`, this no longer separately checks
    /// `query.message.questions.len() != 1` — the caller's `question`
    /// comes from an already-decoded query, which
    /// `Message::parse_standard_query` guarantees has exactly one
    /// question at decode time, so re-checking it here was redundant with
    /// that earlier validation.
    fn cache_store_for_response(
        &self,
        response: &Message,
        question: &QuestionKey,
        stored_at: SystemTime,
        dnssec_ok: bool,
        store_authoritative: bool,
    ) -> Option<DecomposedResponse> {
        if !response.header.qr()
            || response.questions.len() != 1
            || QuestionKey::from_message(response)? != *question
        {
            return None;
        }
        let (ttl, negative_meta) = self.ttl_policy.ttl_for_response(response)?;
        Some(decompose_response_for_store(
            response,
            question,
            ttl,
            negative_meta.as_ref(),
            stored_at,
            dnssec_ok,
            store_authoritative,
        ))
    }

    /// `cache_result` drives the `QueryEventV1` audit event (what was
    /// actually served). `latency_cache_result` drives which latency
    /// histogram this query's duration lands in, and is usually identical to
    /// `cache_result` — the one exception is a single-flight coalesced
    /// follower, which is correctly labeled `Hit` for the audit event (it was
    /// served from the cache entry the leader just populated) but whose
    /// *latency* is dominated by waiting on the leader's full backend round
    /// trip, not a fast cache lookup. Callers on that path pass the original
    /// pre-coalescing classification for `latency_cache_result` instead.
    #[allow(clippy::too_many_arguments)]
    async fn finish(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        original_question_name: Option<String>,
        decision: ResolveDecision,
        response_bytes: Vec<u8>,
        cache_result: Option<QueryEventCacheResult>,
        latency_cache_result: Option<QueryEventCacheResult>,
        backend: Option<QueryEventBackend>,
    ) -> ResolveOutcome {
        let finished_at = self.clock.now();
        let latency = finished_at.duration_since(started_at).ok();
        let mut event = QueryEventV1::from_decision_context(
            self.event_sequence.fetch_add(1, Ordering::Relaxed),
            request.request_id,
            finished_at,
            request.observed_source.clone(),
            original_question_name,
            &decision,
            response_code_from_wire(&response_bytes),
            cache_result,
            latency,
        );
        if let ResolveDecisionKind::Blocked(block) = &decision.kind {
            let qtype = decision.question.as_ref().map(|q| q.qtype).unwrap_or(0);
            event.block_response_mode = Some(self.responses.block_response_mode(block, qtype));
        }
        event.backend = backend;
        self.record_query_event(event);
        self.metrics.record_backend_status(&self.backend.status());
        if let Some(duration) = latency {
            self.metrics.observe_duration_with_source(
                ResolverMetric::QueryDuration,
                duration,
                request.client_ip,
            );
            match latency_cache_result {
                // A stale serve is latency-wise a hit: answered from cache
                // memory, backend work deferred to the background refresh.
                Some(QueryEventCacheResult::Hit) | Some(QueryEventCacheResult::Stale) => {
                    self.metrics.observe_duration_with_source(
                        ResolverMetric::CacheHitQueryDuration,
                        duration,
                        request.client_ip,
                    );
                }
                Some(QueryEventCacheResult::Miss) | Some(QueryEventCacheResult::Expired) => {
                    self.metrics.observe_duration_with_source(
                        ResolverMetric::CacheMissQueryDuration,
                        duration,
                        request.client_ip,
                    );
                }
                // Bypass/Unavailable didn't go through a normal cache lookup, and
                // None covers protocol errors/policy blocks/local answers — none
                // of these are cache-hit or backend-round-trip latency.
                Some(QueryEventCacheResult::Bypass)
                | Some(QueryEventCacheResult::Unavailable)
                | None => {}
            }
        }
        ResolveOutcome {
            response_bytes,
            decision,
        }
    }

    /// Calls `finish` with the same value for both `cache_result` and
    /// `latency_cache_result` — the common case everywhere except the
    /// single-flight coalesced-follower paths, which call `finish` directly
    /// so the two can deliberately diverge (see `finish`'s doc comment).
    #[allow(clippy::too_many_arguments)]
    async fn finish_uniform(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        original_question_name: Option<String>,
        decision: ResolveDecision,
        response_bytes: Vec<u8>,
        cache_result: Option<QueryEventCacheResult>,
        backend: Option<QueryEventBackend>,
    ) -> ResolveOutcome {
        self.finish(
            started_at,
            request,
            original_question_name,
            decision,
            response_bytes,
            cache_result,
            cache_result,
            backend,
        )
        .await
    }

    fn record_query_event(&self, event: QueryEventV1) {
        let metric = match self.events.record(event) {
            QueryEventRecordResult::Accepted => ResolverMetric::QueryEventAccepted,
            QueryEventRecordResult::Disabled => ResolverMetric::QueryEventDisabled,
            QueryEventRecordResult::DroppedNewest => ResolverMetric::QueryEventDroppedNewest,
            QueryEventRecordResult::DroppedOldest => ResolverMetric::QueryEventDroppedOldest,
            QueryEventRecordResult::Sampled => ResolverMetric::QueryEventSampled,
        };
        self.metrics.increment(metric);
    }
}

fn request_id_from_wire(bytes: &[u8]) -> Option<u16> {
    let id = bytes.get(0..2)?;
    Some(u16::from_be_bytes([id[0], id[1]]))
}

fn response_is_truncated(bytes: &[u8]) -> bool {
    bytes
        .get(2)
        .map(|flags| (flags & 0x02) != 0)
        .unwrap_or(false)
}

fn response_code_from_wire(bytes: &[u8]) -> Option<u16> {
    let base = bytes.get(3).map(|flags| u16::from(flags & 0x0f))?;
    let extended = opt_extended_rcode_from_wire(bytes).unwrap_or(0);
    Some((u16::from(extended) << 4) | base)
}

fn opt_extended_rcode_from_wire(bytes: &[u8]) -> Option<u8> {
    let qd_count = read_dns_u16(bytes, 4).unwrap_or(0);
    let an_count = read_dns_u16(bytes, 6).unwrap_or(0);
    let ns_count = read_dns_u16(bytes, 8).unwrap_or(0);
    let ar_count = read_dns_u16(bytes, 10).unwrap_or(0);
    if ar_count == 0 {
        return Some(0);
    }

    let mut offset = 12usize;
    skip_dns_questions(bytes, &mut offset, qd_count)?;
    skip_dns_records(bytes, &mut offset, an_count)?;
    skip_dns_records(bytes, &mut offset, ns_count)?;
    let mut extended_rcode = None;
    for _ in 0..ar_count {
        let has_root_owner = matches!(bytes.get(offset), Some(0));
        skip_dns_name(bytes, &mut offset)?;
        let record_start = offset;
        let rtype = read_dns_u16(bytes, offset)?;
        let ttl = read_dns_u32(bytes, offset.checked_add(4)?)?;
        let rdlength = read_dns_u16(bytes, offset.checked_add(8)?)? as usize;
        let rdata_start = offset.checked_add(10)?;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        bytes.get(record_start..rdata_end)?;
        if has_root_owner && rtype == 41 {
            extended_rcode = Some(((ttl >> 24) & 0xff) as u8);
        }
        offset = rdata_end;
    }
    Some(extended_rcode.unwrap_or(0))
}

fn skip_dns_questions(bytes: &[u8], offset: &mut usize, count: u16) -> Option<()> {
    for _ in 0..count {
        skip_dns_name(bytes, offset)?;
        let question_end = offset.checked_add(4)?;
        bytes.get(*offset..question_end)?;
        *offset = question_end;
    }
    Some(())
}

fn skip_dns_records(bytes: &[u8], offset: &mut usize, count: u16) -> Option<()> {
    for _ in 0..count {
        skip_dns_name(bytes, offset)?;
        let record_start = *offset;
        let rdlength = read_dns_u16(bytes, record_start.checked_add(8)?)? as usize;
        let rdata_start = record_start.checked_add(10)?;
        let record_end = rdata_start.checked_add(rdlength)?;
        bytes.get(record_start..record_end)?;
        *offset = record_end;
    }
    Some(())
}

fn skip_dns_name(bytes: &[u8], offset: &mut usize) -> Option<()> {
    loop {
        let length = *bytes.get(*offset)?;
        match length & 0b1100_0000 {
            0b0000_0000 => {
                *offset = offset.checked_add(1)?;
                if length == 0 {
                    return Some(());
                }
                if length > 63 {
                    return None;
                }
                let label_end = offset.checked_add(length as usize)?;
                bytes.get(*offset..label_end)?;
                *offset = label_end;
            }
            0b1100_0000 => {
                let pointer_start = *offset;
                let pointer_end = offset.checked_add(2)?;
                bytes.get(*offset..pointer_end)?;
                let pointer = (((u16::from(length) & 0x3f) << 8)
                    | u16::from(*bytes.get(pointer_start.checked_add(1)?)?))
                    as usize;
                if !dns_name_pointer_target_is_valid(bytes, pointer, pointer_start) {
                    return None;
                }
                *offset = pointer_end;
                return Some(());
            }
            _ => return None,
        }
    }
}

fn dns_name_pointer_target_is_valid(bytes: &[u8], mut offset: usize, limit: usize) -> bool {
    if offset < 12 || offset >= limit {
        return false;
    }

    for _ in 0..128 {
        let Some(length) = bytes.get(offset).copied() else {
            return false;
        };
        match length & 0b1100_0000 {
            0b0000_0000 => {
                offset = match offset.checked_add(1) {
                    Some(offset) => offset,
                    None => return false,
                };
                if length == 0 {
                    return true;
                }
                if length > 63 {
                    return false;
                }
                let label_end = match offset.checked_add(length as usize) {
                    Some(label_end) => label_end,
                    None => return false,
                };
                if label_end > limit || bytes.get(offset..label_end).is_none() {
                    return false;
                }
                offset = label_end;
            }
            0b1100_0000 => {
                let Some(next) = bytes.get(offset.saturating_add(1)).copied() else {
                    return false;
                };
                let pointer = (((u16::from(length) & 0x3f) << 8) | u16::from(next)) as usize;
                if pointer < 12 || pointer >= offset || pointer >= limit {
                    return false;
                }
                offset = pointer;
            }
            _ => return false,
        }
    }

    false
}

fn read_dns_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([value[0], value[1]]))
}

fn read_dns_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn decoded_original_question_name(decoded: &DecodedQuery) -> Option<String> {
    decoded
        .message
        .questions
        .first()
        .map(|question| question.qname.clone())
}

fn backend_cache_namespace(mode: ResolutionMode, backend_generation: u64) -> Option<String> {
    Some(format!(
        "mode:{};generation:{backend_generation}",
        mode.cache_namespace_label()
    ))
}

impl ResolutionMode {
    fn cache_namespace_label(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Recursive => "recursive",
        }
    }
}

/// Content equality between two `Bytes`, with a pointer fast path: the
/// transport layer now shares one allocation between a response's `bytes`
/// and its parsed message's `original_bytes`, so the common case is the
/// same buffer and needs no O(n) memcmp.
fn same_bytes(a: &Bytes, b: &Bytes) -> bool {
    (a.as_ptr() == b.as_ptr() && a.len() == b.len()) || a == b
}

fn validate_backend_response(
    response: &mut ResolutionResponse,
    query: &DecodedQuery,
) -> Option<Message> {
    if let Some(message) = response.response_message.take() {
        validate_backend_response_message(&message, query)?;
        if !same_bytes(&message.original_bytes, &response.bytes) {
            return None;
        }
        return Some(message);
    }

    validate_backend_response_bytes(&response.bytes, query)
}

fn validate_backend_response_message<'a>(
    response: &'a Message,
    query: &DecodedQuery,
) -> Option<&'a Message> {
    if !response.header.qr() || response.questions.len() != 1 {
        return None;
    }
    if QuestionKey::from_message(response)? != query.question {
        return None;
    }
    Some(response)
}

fn validate_backend_response_bytes(bytes: &[u8], query: &DecodedQuery) -> Option<Message> {
    let response = Message::parse(bytes).ok()?;
    validate_backend_response_message(&response, query)?;
    Some(response)
}

fn backend_query_with_configured_udp_limit(
    query: &DecodedQuery,
    configured_max_udp_payload_size: usize,
) -> DecodedQuery {
    let mut query = query.clone();
    let bounded_payload = query
        .message
        .effective_udp_payload_size(configured_max_udp_payload_size)
        .min(u16::MAX as usize) as u16;
    let Some(edns) = query.message.edns.as_mut() else {
        return query;
    };
    edns.udp_payload_size = bounded_payload;
    query.features.edns_udp_payload_size = Some(bounded_payload);
    for record in &mut query.message.additionals {
        let RecordData::OPT(opt) = &mut record.record else {
            continue;
        };
        record.rclass = bounded_payload;
        opt.udp_payload_size = bounded_payload;
    }
    query
}

/// Whether any hop of a cache-hit chain is an expired entry admitted under
/// RFC 8767 serve-stale. `now` must be the same timestamp the lookup itself
/// ran with (`request.received_at`) — lookup, response assembly
/// (`cache::assemble::write_rrset`), and this classification all share that
/// one instant, so they can never disagree about staleness.
fn chain_contains_stale(chain: &[(String, Arc<cache::RRsetEntry>)], now: SystemTime) -> bool {
    chain.iter().any(|(_, entry)| entry.expires_at <= now)
}

fn cache_hit_event_result(stale: bool) -> QueryEventCacheResult {
    if stale {
        QueryEventCacheResult::Stale
    } else {
        QueryEventCacheResult::Hit
    }
}

fn cache_supported(query: &DecodedQuery) -> bool {
    query
        .message
        .edns
        .as_ref()
        .map(|edns| {
            edns.extended_rcode == 0
                && edns.version == 0
                && (edns.flags & !EDNS_DO_FLAG) == 0
                && (edns.options.is_empty()
                    || crate::protocol::edns_cookie::is_solely_cookie_option(&edns.options)
                        .is_some())
        })
        .unwrap_or(true)
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

    fn decode_query_owned(&self, bytes: Bytes) -> Result<DecodedQuery, QueryDecodeFailure> {
        let message = Message::parse_standard_query_owned_with_recovery(bytes)?;
        DecodedQuery::new(message).ok_or_else(|| QueryDecodeFailure {
            error: QueryValidationError::InvalidQuestionCount { count: 0 },
            // `parse_standard_query_owned_with_recovery` already guarantees
            // exactly one question by the time it returns `Ok` (standard
            // query validation requires `qd_count == 1`, and a successful
            // parse yields exactly that many `questions`), so
            // `DecodedQuery::new` failing here is unreachable in practice.
            // Recovering `message` would need cloning it before this call
            // on every successful decode just to cover a branch that never
            // actually runs, so this stays `None` like the pre-fix
            // behavior.
            recovered_message: None,
        })
    }

    fn configured_max_udp_payload_size(&self) -> usize {
        self.configured_max_udp_payload_size
    }

    fn rewrite_response_id(
        &self,
        response_bytes: &mut [u8],
        request_id: u16,
    ) -> crate::protocol::Result<()> {
        rewrite_response_id(response_bytes, request_id)
    }

    fn rewrite_response_request_fields(
        &self,
        response_bytes: &mut [u8],
        request: &Message,
    ) -> crate::protocol::Result<()> {
        rewrite_response_request_fields(response_bytes, request)
    }
}

pub struct BasicResponseFactory;

impl ResponseFactory for BasicResponseFactory {
    fn protocol_error(
        &self,
        request_id: Option<u16>,
        error: &QueryValidationError,
        request: Option<&Message>,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8> {
        // BADVERS (RFC 6891 §6.1.3) doesn't fit `ResponseCode` (a plain
        // 4-bit header RCODE) -- it's a 12-bit extended code split across
        // the header's RCODE nibble and the OPT record's extended-RCODE
        // byte, so it's special-cased here via `build_badvers_response`
        // rather than going through `response_code()`/
        // `build_question_aware_error_response` like every other protocol
        // error. `request` is always `Some` when this variant occurs: it
        // can only be produced by `validate_standard_query_body` after a
        // full, successful parse (see that function and
        // `QueryValidationError::UnsupportedEdnsVersion`'s doc comment),
        // so there's always a recovered/parsed message to build the
        // BADVERS response from.
        if let (QueryValidationError::UnsupportedEdnsVersion { .. }, Some(request)) =
            (error, request)
        {
            return build_badvers_response(request, configured_max_udp_payload_size);
        }

        // `QueryValidationError::response_code()` only ever actually
        // returns `FormErr` or `NotImp`; `ServFail`/`Refused`/`NxDomain`/
        // `NoError` are unreachable here today (kept only so this match
        // stays exhaustive against `ResponseCode`) and, matching the
        // pre-fix behavior, are normalized to a FormErr-coded response.
        // Every arm is now EDNS/CD-aware (RFC 6891 §6.1.1, RFC 4035
        // §3.2.2) whenever `request` was recovered, falling back to a
        // header-only response only when it wasn't.
        let rcode = match error.response_code() {
            ResponseCode::NotImp => ResponseCode::NotImp,
            ResponseCode::ServFail => ResponseCode::ServFail,
            _ => ResponseCode::FormErr,
        };
        build_question_aware_error_response(
            request,
            request_id,
            rcode,
            configured_max_udp_payload_size,
        )
    }

    fn blocked(
        &self,
        query: &DecodedQuery,
        _block: &PolicyBlock,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8> {
        build_refused_response(&query.message, configured_max_udp_payload_size)
    }

    fn servfail(
        &self,
        query: Option<&DecodedQuery>,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8> {
        build_servfail_response(
            query.map(|query| &query.message),
            None,
            configured_max_udp_payload_size,
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfiguredResponseFactory {
    block_config: BlockResponseConfig,
}

impl ConfiguredResponseFactory {
    pub fn new(block_config: BlockResponseConfig) -> Result<Self, BlockResponseConfigError> {
        block_config.validate()?;
        Ok(Self { block_config })
    }

    pub fn block_config(&self) -> &BlockResponseConfig {
        &self.block_config
    }

    fn block_ttl(&self) -> u32 {
        if self.block_config.cacheable_by_clients {
            self.block_config.blocked_response_ttl
        } else {
            0
        }
    }
}

impl ResponseFactory for ConfiguredResponseFactory {
    fn protocol_error(
        &self,
        request_id: Option<u16>,
        error: &QueryValidationError,
        request: Option<&Message>,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8> {
        BasicResponseFactory.protocol_error(
            request_id,
            error,
            request,
            configured_max_udp_payload_size,
        )
    }

    fn block_response_mode(&self, block: &PolicyBlock, qtype: u16) -> BlockResponseMode {
        let mode = self.block_config.mode_for(&block.reason);
        if mode != BlockResponseMode::Sinkhole {
            return mode;
        }
        match qtype {
            A_RECORD_TYPE if self.block_config.sinkhole_ipv4.is_some() => {
                BlockResponseMode::Sinkhole
            }
            AAAA_RECORD_TYPE if self.block_config.sinkhole_ipv6.is_some() => {
                BlockResponseMode::Sinkhole
            }
            A_RECORD_TYPE | AAAA_RECORD_TYPE => BlockResponseMode::NoData,
            _ => BlockResponseMode::Refused,
        }
    }

    fn blocked(
        &self,
        query: &DecodedQuery,
        block: &PolicyBlock,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8> {
        match self.block_config.mode_for(&block.reason) {
            BlockResponseMode::Refused => {
                build_refused_response(&query.message, configured_max_udp_payload_size)
            }
            BlockResponseMode::NxDomain => {
                build_nxdomain_response(&query.message, configured_max_udp_payload_size)
            }
            BlockResponseMode::NoData => {
                build_nodata_response(&query.message, configured_max_udp_payload_size)
            }
            BlockResponseMode::Sinkhole => {
                self.sinkhole_response(query, configured_max_udp_payload_size)
            }
        }
    }

    fn servfail(
        &self,
        query: Option<&DecodedQuery>,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8> {
        BasicResponseFactory.servfail(query, configured_max_udp_payload_size)
    }
}

impl ConfiguredResponseFactory {
    fn sinkhole_response(
        &self,
        query: &DecodedQuery,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8> {
        match query.question.qtype {
            A_RECORD_TYPE => self
                .block_config
                .sinkhole_ipv4
                .map(|address| {
                    build_a_block_response(
                        &query.message,
                        address,
                        self.block_ttl(),
                        configured_max_udp_payload_size,
                    )
                })
                .unwrap_or_else(|| {
                    build_nodata_response(&query.message, configured_max_udp_payload_size)
                }),
            AAAA_RECORD_TYPE => self
                .block_config
                .sinkhole_ipv6
                .map(|address| {
                    build_aaaa_block_response(
                        &query.message,
                        address,
                        self.block_ttl(),
                        configured_max_udp_payload_size,
                    )
                })
                .unwrap_or_else(|| {
                    build_nodata_response(&query.message, configured_max_udp_payload_size)
                }),
            _ => build_refused_response(&query.message, configured_max_udp_payload_size),
        }
    }
}

pub trait ProtocolCodec: Send + Sync {
    fn decode_query(&self, bytes: &[u8]) -> Result<DecodedQuery, QueryValidationError>;

    /// Default implementation for codecs that don't need the zero-copy
    /// optimization `StandardProtocolCodec` overrides this with: on
    /// failure, `bytes` is still owned here (only `&bytes` was lent to
    /// `decode_query`), so a best-effort `Message::parse` recovers the
    /// EDNS/CD context an error response should carry (RFC 6891 §6.1.1,
    /// RFC 4035 §3.2.2) at no cost to the success path.
    fn decode_query_owned(&self, bytes: Bytes) -> Result<DecodedQuery, QueryDecodeFailure> {
        self.decode_query(&bytes)
            .map_err(|error| QueryDecodeFailure {
                error,
                recovered_message: Message::parse(&bytes).ok().map(Box::new),
            })
    }

    fn configured_max_udp_payload_size(&self) -> usize;

    fn rewrite_response_id(
        &self,
        response_bytes: &mut [u8],
        request_id: u16,
    ) -> crate::protocol::Result<()>;

    /// Rewrites both the transaction ID and the RD bit of `response_bytes`
    /// to match `request`. Unlike `rewrite_response_id` alone, this is
    /// needed whenever `response_bytes` was built for a *different*
    /// request than the one it's about to be served to — the single-flight
    /// follower fallback path (`prepare_backend_result`) is the one caller:
    /// a follower's own request can differ from the coalescing leader's in
    /// its RD flag (and casing, though casing is handled separately), since
    /// `MissKey` coalesces on name/type/class/namespace/DO only, not RD.
    /// Serving the leader's raw RD bit back to a follower that asked with a
    /// different RD would silently misreport what the follower itself
    /// requested.
    fn rewrite_response_request_fields(
        &self,
        response_bytes: &mut [u8],
        request: &Message,
    ) -> crate::protocol::Result<()>;
}

pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, client_ip: IpAddr, question: &QuestionKey) -> PolicyDecision;

    fn evaluate_response_name(&self, _client_ip: IpAddr, _domain: &DomainName) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

pub trait LocalDnsEntries: Send + Sync {
    fn lookup(&self, question: &QuestionKey) -> LocalDnsLookup;
}

impl LocalDnsEntries for InMemoryLocalDnsEntries {
    fn lookup(&self, question: &QuestionKey) -> LocalDnsLookup {
        if question.qclass != 1 || !matches!(question.qtype, A_RECORD_TYPE | AAAA_RECORD_TYPE) {
            return LocalDnsLookup::NoMatch;
        }
        let Ok(name) = DomainName::parse(&question.qname) else {
            return LocalDnsLookup::NoMatch;
        };
        let Some(entry) = self.entries.get(&name) else {
            return LocalDnsLookup::NoMatch;
        };
        match question.qtype {
            A_RECORD_TYPE if !entry.ipv4.is_empty() => LocalDnsLookup::Answer(entry.clone()),
            AAAA_RECORD_TYPE if !entry.ipv6.is_empty() => LocalDnsLookup::Answer(entry.clone()),
            _ => LocalDnsLookup::NoData(entry.clone()),
        }
    }
}

pub struct NoopLocalDnsEntries;

impl LocalDnsEntries for NoopLocalDnsEntries {
    fn lookup(&self, _question: &QuestionKey) -> LocalDnsLookup {
        LocalDnsLookup::NoMatch
    }
}

pub struct NoopDnsCache;

impl DomainDnsCache for NoopDnsCache {
    fn lookup_chain(
        &self,
        _qname: &str,
        _qtype: u16,
        _qclass: u16,
        _dnssec_ok: bool,
        _epoch: u64,
        _max_chain_depth: u8,
        _now: SystemTime,
        _refresh_config: &crate::config::RefreshConfig,
    ) -> ChainLookup {
        ChainLookup::Miss
    }

    fn store_response(&self, _decomposed: DecomposedResponse, _epoch: u64) {}

    fn sweep_stale_namespace(&self, _current_epoch: u64) {}

    fn domain_count(&self) -> usize {
        0
    }

    fn capacity(&self) -> usize {
        0
    }
}

pub struct ChannelQueryEventSink {
    sender: mpsc::Sender<QueryEventV1>,
}

impl ChannelQueryEventSink {
    pub fn new(sender: mpsc::Sender<QueryEventV1>) -> Self {
        Self { sender }
    }
}

impl QueryEventSink for ChannelQueryEventSink {
    fn record(&self, event: QueryEventV1) -> QueryEventRecordResult {
        match self.sender.try_send(event) {
            Ok(()) => QueryEventRecordResult::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => QueryEventRecordResult::DroppedNewest,
            Err(mpsc::error::TrySendError::Closed(_)) => QueryEventRecordResult::Disabled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryQueryEventStoreConfig {
    pub max_retained_events: usize,
    pub max_indexed_sources: usize,
    pub max_indexed_domains: usize,
    pub retention: Option<Duration>,
}

impl Default for InMemoryQueryEventStoreConfig {
    fn default() -> Self {
        Self {
            max_retained_events: 10_000,
            max_indexed_sources: 1_024,
            max_indexed_domains: 10_000,
            retention: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryEventStoreSummary {
    pub retained_event_count: usize,
    pub indexed_source_count: usize,
    pub indexed_domain_count: usize,
    pub evicted_event_count: u64,
    pub unindexed_source_event_count: u64,
    pub unindexed_domain_event_count: u64,
    pub dropped_newest_event_count: u64,
    pub dropped_oldest_event_count: u64,
    pub sampled_event_count: u64,
}

pub struct InMemoryQueryEventStore {
    config: InMemoryQueryEventStoreConfig,
    state: Mutex<InMemoryQueryEventStoreState>,
    classification: Mutex<()>,
}

pub trait QueryEventReadModel: Send + Sync {
    fn recent_query_events(&self, limit: usize) -> Vec<QueryEventV1>;

    fn suspicious_query_events(&self, limit: usize) -> Vec<QueryEventV1>;

    fn query_events_for_source(
        &self,
        source: &ObservedSourceEndpoint,
        limit: usize,
    ) -> Vec<QueryEventV1>;

    fn suspicious_summary_for_source(
        &self,
        source: &ObservedSourceEndpoint,
    ) -> QueryEventSuspiciousSourceSummary;

    fn query_events_for_domain(&self, domain: &str, limit: usize) -> Vec<QueryEventV1>;

    fn top_suspicious_sources(&self, limit: usize) -> Vec<QueryEventSuspiciousSourceSummary>;

    fn top_suspicious_domains(&self, limit: usize) -> Vec<QueryEventSuspiciousDomainSummary>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEventSuspiciousSourceSummary {
    pub observed_source: ObservedSourceEndpoint,
    pub suspicious_event_count: usize,
    pub finding_count: usize,
    pub highest_severity: Option<QueryEventClassifierSeverity>,
    pub last_seen: Option<SystemTime>,
    pub window: QueryEventReadModelWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEventSuspiciousDomainSummary {
    pub domain: String,
    pub suspicious_event_count: usize,
    pub finding_count: usize,
    pub highest_severity: Option<QueryEventClassifierSeverity>,
    pub last_seen: Option<SystemTime>,
    pub window: QueryEventReadModelWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEventReadModelWindow {
    pub retained_event_count: usize,
    pub incomplete_reasons: Vec<QueryEventReadModelIncompleteReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryEventReadModelIncompleteReason {
    RetentionEviction,
    DroppedEvents,
    SampledEvents,
}

#[derive(Default)]
struct InMemoryQueryEventStoreState {
    events: VecDeque<StoredQueryEvent>,
    indexed_sources: HashMap<ObservedSourceEndpoint, usize>,
    indexed_domains: HashMap<String, usize>,
    evicted_event_count: u64,
    unindexed_source_event_count: u64,
    unindexed_domain_event_count: u64,
    dropped_newest_event_count: u64,
    dropped_oldest_event_count: u64,
    sampled_event_count: u64,
}

struct StoredQueryEvent {
    event: Arc<QueryEventV1>,
    indexed_source: bool,
    indexed_domain: bool,
    classified: bool,
}

impl InMemoryQueryEventStore {
    pub fn new(config: InMemoryQueryEventStoreConfig) -> Self {
        Self {
            config,
            state: Mutex::new(InMemoryQueryEventStoreState::default()),
            classification: Mutex::new(()),
        }
    }

    pub fn record(&self, event: QueryEventV1) {
        let mut state = self.state.lock().unwrap();
        state.record(event, &self.config, true);
    }

    pub fn record_classified(
        &self,
        event: QueryEventV1,
        classifier: &dyn SuspiciousLookupClassifier,
    ) -> QueryEventV1 {
        self.record_classified_with_lock_hooks(event, classifier, || {}, || {})
    }

    fn record_classified_with_lock_hooks(
        &self,
        event: QueryEventV1,
        classifier: &dyn SuspiciousLookupClassifier,
        before_classification_lock: impl FnOnce(),
        after_classification_lock: impl FnOnce(),
    ) -> QueryEventV1 {
        before_classification_lock();
        let _classification = self.classification.lock().unwrap();
        after_classification_lock();
        let (retained_events, window) = {
            let state = self.state.lock().unwrap();
            let (retained_events, retention_evicted_for_event) =
                state.classifier_events_through(&event, &self.config);
            let window =
                classifier_window_for_event(&retained_events, &state, retention_evicted_for_event);
            (retained_events, window)
        };
        let advisory_findings = classifier.classify(SuspiciousLookupClassifierInput {
            event: &event,
            retained_events: &retained_events,
            window,
        });

        let mut classified_event = event;
        classified_event.advisory_findings = advisory_findings;
        self.state
            .lock()
            .unwrap()
            .record(classified_event.clone(), &self.config, true);
        classified_event
    }

    pub fn record_outcome(&self, result: QueryEventRecordResult) {
        let mut state = self.state.lock().unwrap();
        match result {
            QueryEventRecordResult::Accepted | QueryEventRecordResult::Disabled => {}
            QueryEventRecordResult::DroppedNewest => {
                state.dropped_newest_event_count =
                    state.dropped_newest_event_count.saturating_add(1);
            }
            QueryEventRecordResult::DroppedOldest => {
                state.dropped_oldest_event_count =
                    state.dropped_oldest_event_count.saturating_add(1);
            }
            QueryEventRecordResult::Sampled => {
                state.sampled_event_count = state.sampled_event_count.saturating_add(1);
            }
        }
    }

    /// Returns retained query events in chronological order, oldest first.
    pub fn recent_events(&self) -> Vec<QueryEventV1> {
        self.state
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|entry| entry.classified)
            .map(|entry| entry.event.as_ref().clone())
            .collect()
    }

    pub fn summary(&self) -> QueryEventStoreSummary {
        let state = self.state.lock().unwrap();
        QueryEventStoreSummary {
            retained_event_count: state.events.iter().filter(|entry| entry.classified).count(),
            indexed_source_count: state.indexed_sources.len(),
            indexed_domain_count: state.indexed_domains.len(),
            evicted_event_count: state.evicted_event_count,
            unindexed_source_event_count: state.unindexed_source_event_count,
            unindexed_domain_event_count: state.unindexed_domain_event_count,
            dropped_newest_event_count: state.dropped_newest_event_count,
            dropped_oldest_event_count: state.dropped_oldest_event_count,
            sampled_event_count: state.sampled_event_count,
        }
    }
}

impl QueryEventReadModel for InMemoryQueryEventStore {
    fn recent_query_events(&self, limit: usize) -> Vec<QueryEventV1> {
        let state = self.state.lock().unwrap();
        clone_recent_matching(state.events.iter(), limit, |_| true)
    }

    fn suspicious_query_events(&self, limit: usize) -> Vec<QueryEventV1> {
        let state = self.state.lock().unwrap();
        clone_recent_matching(state.events.iter(), limit, is_suspicious_event)
    }

    fn query_events_for_source(
        &self,
        source: &ObservedSourceEndpoint,
        limit: usize,
    ) -> Vec<QueryEventV1> {
        let state = self.state.lock().unwrap();
        clone_recent_matching(state.events.iter(), limit, |event| {
            event.observed_source == *source
        })
    }

    fn suspicious_summary_for_source(
        &self,
        source: &ObservedSourceEndpoint,
    ) -> QueryEventSuspiciousSourceSummary {
        let state = self.state.lock().unwrap();
        let mut summary = QueryEventSuspiciousSourceSummary {
            observed_source: source.clone(),
            suspicious_event_count: 0,
            finding_count: 0,
            highest_severity: None,
            last_seen: None,
            window: read_model_window(&state),
        };
        for event in state
            .events
            .iter()
            .filter(|entry| entry.classified)
            .map(|entry| &entry.event)
        {
            if event.observed_source == *source && is_suspicious_event(event) {
                update_source_summary(&mut summary, event);
            }
        }
        summary
    }

    fn query_events_for_domain(&self, domain: &str, limit: usize) -> Vec<QueryEventV1> {
        let domain = normalize_question_name(domain);
        let state = self.state.lock().unwrap();
        clone_recent_matching(state.events.iter(), limit, |event| {
            event
                .normalized_question
                .as_ref()
                .map(|question| question.qname == domain)
                .unwrap_or(false)
        })
    }

    fn top_suspicious_sources(&self, limit: usize) -> Vec<QueryEventSuspiciousSourceSummary> {
        let state = self.state.lock().unwrap();
        let window = read_model_window(&state);
        let mut summaries =
            HashMap::<ObservedSourceEndpoint, QueryEventSuspiciousSourceSummary>::new();
        for event in state
            .events
            .iter()
            .filter(|entry| entry.classified)
            .map(|entry| &entry.event)
        {
            if !is_suspicious_event(event) {
                continue;
            }
            let summary = summaries
                .entry(event.observed_source.clone())
                .or_insert_with(|| QueryEventSuspiciousSourceSummary {
                    observed_source: event.observed_source.clone(),
                    suspicious_event_count: 0,
                    finding_count: 0,
                    highest_severity: None,
                    last_seen: None,
                    window: window.clone(),
                });
            update_source_summary(summary, event);
        }
        let mut summaries = summaries.into_values().collect::<Vec<_>>();
        summaries.sort_by(compare_source_summaries);
        summaries.truncate(limit);
        summaries
    }

    fn top_suspicious_domains(&self, limit: usize) -> Vec<QueryEventSuspiciousDomainSummary> {
        let state = self.state.lock().unwrap();
        let window = read_model_window(&state);
        let mut summaries = HashMap::<String, QueryEventSuspiciousDomainSummary>::new();
        for event in state
            .events
            .iter()
            .filter(|entry| entry.classified)
            .map(|entry| &entry.event)
        {
            if !is_suspicious_event(event) {
                continue;
            }
            let Some(domain) = event
                .normalized_question
                .as_ref()
                .map(|question| question.qname.clone())
            else {
                continue;
            };
            let summary = summaries.entry(domain.clone()).or_insert_with(|| {
                QueryEventSuspiciousDomainSummary {
                    domain,
                    suspicious_event_count: 0,
                    finding_count: 0,
                    highest_severity: None,
                    last_seen: None,
                    window: window.clone(),
                }
            });
            update_domain_summary(summary, event);
        }
        let mut summaries = summaries.into_values().collect::<Vec<_>>();
        summaries.sort_by(compare_domain_summaries);
        summaries.truncate(limit);
        summaries
    }
}

fn clone_recent_matching<'a>(
    events: impl DoubleEndedIterator<Item = &'a StoredQueryEvent>,
    limit: usize,
    matches: impl Fn(&QueryEventV1) -> bool,
) -> Vec<QueryEventV1> {
    let mut events = events
        .rev()
        .filter(|entry| entry.classified)
        .filter_map(|entry| {
            if matches(&entry.event) {
                Some(entry.event.as_ref().clone())
            } else {
                None
            }
        })
        .take(limit)
        .collect::<Vec<_>>();
    events.reverse();
    events
}

fn is_suspicious_event(event: &QueryEventV1) -> bool {
    !event.advisory_findings.is_empty()
}

fn read_model_window(state: &InMemoryQueryEventStoreState) -> QueryEventReadModelWindow {
    let mut incomplete_reasons = Vec::new();
    if state.evicted_event_count > 0 {
        incomplete_reasons.push(QueryEventReadModelIncompleteReason::RetentionEviction);
    }
    if state.dropped_newest_event_count > 0 || state.dropped_oldest_event_count > 0 {
        incomplete_reasons.push(QueryEventReadModelIncompleteReason::DroppedEvents);
    }
    if state.sampled_event_count > 0 {
        incomplete_reasons.push(QueryEventReadModelIncompleteReason::SampledEvents);
    }

    QueryEventReadModelWindow {
        retained_event_count: state.events.iter().filter(|entry| entry.classified).count(),
        incomplete_reasons,
    }
}

fn classifier_window_for_event(
    retained_events: &[Arc<QueryEventV1>],
    state: &InMemoryQueryEventStoreState,
    retention_evicted_for_event: bool,
) -> QueryEventClassifierWindow {
    let started_at = retained_events
        .first()
        .map(|event| event.timestamp)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let ended_at = retained_events
        .last()
        .map(|event| event.timestamp)
        .unwrap_or(started_at);
    let mut incomplete_reasons = Vec::new();
    if retained_events.len() <= 1 {
        incomplete_reasons.push(QueryEventClassifierWindowIncompleteReason::ColdStart);
    }
    if state.evicted_event_count > 0 || retention_evicted_for_event {
        incomplete_reasons.push(QueryEventClassifierWindowIncompleteReason::RetentionEviction);
    }
    if state.dropped_newest_event_count > 0 || state.dropped_oldest_event_count > 0 {
        incomplete_reasons.push(QueryEventClassifierWindowIncompleteReason::DroppedEvents);
    }
    if state.sampled_event_count > 0 {
        incomplete_reasons.push(QueryEventClassifierWindowIncompleteReason::SampledEvents);
    }

    QueryEventClassifierWindow {
        started_at,
        ended_at,
        retained_event_count: retained_events.len(),
        incomplete_reasons,
    }
}

fn update_source_summary(summary: &mut QueryEventSuspiciousSourceSummary, event: &QueryEventV1) {
    summary.suspicious_event_count = summary.suspicious_event_count.saturating_add(1);
    update_suspicious_counts(
        &mut summary.finding_count,
        &mut summary.highest_severity,
        &mut summary.last_seen,
        event,
    );
}

fn update_domain_summary(summary: &mut QueryEventSuspiciousDomainSummary, event: &QueryEventV1) {
    summary.suspicious_event_count = summary.suspicious_event_count.saturating_add(1);
    update_suspicious_counts(
        &mut summary.finding_count,
        &mut summary.highest_severity,
        &mut summary.last_seen,
        event,
    );
}

fn update_suspicious_counts(
    finding_count: &mut usize,
    highest_severity: &mut Option<QueryEventClassifierSeverity>,
    last_seen: &mut Option<SystemTime>,
    event: &QueryEventV1,
) {
    *finding_count = finding_count.saturating_add(event.advisory_findings.len());
    for finding in &event.advisory_findings {
        *highest_severity = Some(
            highest_severity
                .map(|current| current.max(finding.severity))
                .unwrap_or(finding.severity),
        );
    }
    *last_seen = Some(
        last_seen
            .map(|current| current.max(event.timestamp))
            .unwrap_or(event.timestamp),
    );
}

fn compare_source_summaries(
    left: &QueryEventSuspiciousSourceSummary,
    right: &QueryEventSuspiciousSourceSummary,
) -> std::cmp::Ordering {
    compare_suspicious_rank_fields(
        left.suspicious_event_count,
        left.finding_count,
        left.highest_severity,
        left.last_seen,
        right.suspicious_event_count,
        right.finding_count,
        right.highest_severity,
        right.last_seen,
    )
    .then_with(|| compare_observed_source_endpoints(&left.observed_source, &right.observed_source))
}

fn compare_observed_source_endpoints(
    left: &ObservedSourceEndpoint,
    right: &ObservedSourceEndpoint,
) -> std::cmp::Ordering {
    left.ip
        .cmp(&right.ip)
        .then_with(|| left.port.cmp(&right.port))
        .then_with(|| compare_optional_transport(left.transport, right.transport))
        .then_with(|| left.listener.cmp(&right.listener))
}

fn compare_optional_transport(
    left: Option<QueryTransport>,
    right: Option<QueryTransport>,
) -> std::cmp::Ordering {
    transport_rank(left).cmp(&transport_rank(right))
}

fn transport_rank(transport: Option<QueryTransport>) -> u8 {
    match transport {
        None => 0,
        Some(QueryTransport::Udp) => 1,
        Some(QueryTransport::Tcp) => 2,
    }
}

fn compare_domain_summaries(
    left: &QueryEventSuspiciousDomainSummary,
    right: &QueryEventSuspiciousDomainSummary,
) -> std::cmp::Ordering {
    compare_suspicious_rank_fields(
        left.suspicious_event_count,
        left.finding_count,
        left.highest_severity,
        left.last_seen,
        right.suspicious_event_count,
        right.finding_count,
        right.highest_severity,
        right.last_seen,
    )
    .then_with(|| left.domain.cmp(&right.domain))
}

#[allow(clippy::too_many_arguments)]
fn compare_suspicious_rank_fields(
    left_event_count: usize,
    left_finding_count: usize,
    left_severity: Option<QueryEventClassifierSeverity>,
    left_last_seen: Option<SystemTime>,
    right_event_count: usize,
    right_finding_count: usize,
    right_severity: Option<QueryEventClassifierSeverity>,
    right_last_seen: Option<SystemTime>,
) -> std::cmp::Ordering {
    right_event_count
        .cmp(&left_event_count)
        .then_with(|| right_finding_count.cmp(&left_finding_count))
        .then_with(|| right_severity.cmp(&left_severity))
        .then_with(|| right_last_seen.cmp(&left_last_seen))
}

impl InMemoryQueryEventStoreState {
    fn classifier_events_through(
        &self,
        event: &QueryEventV1,
        config: &InMemoryQueryEventStoreConfig,
    ) -> (Vec<Arc<QueryEventV1>>, bool) {
        let key = event_order_key(event);
        let mut events = self
            .events
            .iter()
            .filter(|entry| entry.classified)
            .filter(|entry| event_order_key(&entry.event) <= key)
            .map(|entry| Arc::clone(&entry.event))
            .collect::<Vec<_>>();
        events.push(Arc::new(event.clone()));

        let mut retention_evicted_for_event = false;
        let pre_retention_len = events.len();
        if let Some(retention) = config.retention {
            events.retain(|retained_event| {
                retained_event
                    .timestamp
                    .checked_add(retention)
                    .map(|expires_at| expires_at > event.timestamp)
                    .unwrap_or(true)
            });
        }
        retention_evicted_for_event |= events.len() < pre_retention_len;
        if config.max_retained_events > 0 && events.len() > config.max_retained_events {
            retention_evicted_for_event = true;
            events = events.split_off(events.len().saturating_sub(config.max_retained_events));
        } else if config.max_retained_events == 0 {
            retention_evicted_for_event = true;
            events.clear();
        }
        if events.is_empty() {
            events.push(Arc::new(event.clone()));
        }
        retention_evicted_for_event |= self.event_would_be_evicted_after_record(event, config);
        (events, retention_evicted_for_event)
    }

    fn event_would_be_evicted_after_record(
        &self,
        event: &QueryEventV1,
        config: &InMemoryQueryEventStoreConfig,
    ) -> bool {
        if config.max_retained_events == 0 {
            return true;
        }

        let key = event_order_key(event);
        let newest_timestamp = self
            .events
            .back()
            .map(|entry| entry.event.timestamp.max(event.timestamp))
            .unwrap_or(event.timestamp);
        let mut retained_keys = self
            .events
            .iter()
            .filter(|entry| entry.classified)
            .map(|entry| event_order_key(&entry.event))
            .collect::<Vec<_>>();
        retained_keys.push(key);
        if let Some(retention) = config.retention {
            retained_keys.retain(|retained_key| {
                retained_key
                    .0
                    .checked_add(retention)
                    .map(|expires_at| expires_at > newest_timestamp)
                    .unwrap_or(true)
            });
        }
        retained_keys.sort();
        let Some(position) = retained_keys
            .iter()
            .position(|retained_key| *retained_key == key)
        else {
            return true;
        };
        retained_keys.len().saturating_sub(position) > config.max_retained_events
    }

    fn record(
        &mut self,
        event: QueryEventV1,
        config: &InMemoryQueryEventStoreConfig,
        classified: bool,
    ) {
        let key = event_order_key(&event);
        let appends_to_tail = self
            .events
            .back()
            .map(|existing| event_order_key(&existing.event) <= key)
            .unwrap_or(true);

        if appends_to_tail {
            self.evict_expired_before(event.timestamp, config.retention);
            if config.max_retained_events == 0 {
                self.evicted_event_count = self.evicted_event_count.saturating_add(1);
                return;
            }
            while self.events.len() >= config.max_retained_events {
                self.evict_front();
            }
            let (indexed_source, indexed_domain) = self.record_index_membership(&event, config);
            self.events.push_back(StoredQueryEvent {
                event: Arc::new(event),
                indexed_source,
                indexed_domain,
                classified,
            });
            return;
        }

        self.insert_ordered(event, classified);
        self.evict_expired(config.retention);
        self.evict_to_bound(config.max_retained_events);
        self.rebuild_indexes(config);
    }

    fn record_index_membership(
        &mut self,
        event: &QueryEventV1,
        config: &InMemoryQueryEventStoreConfig,
    ) -> (bool, bool) {
        let indexed_source = if let Some(count) =
            self.indexed_sources.get_mut(&event.observed_source)
        {
            *count = count.saturating_add(1);
            true
        } else if self.indexed_sources.len() < config.max_indexed_sources {
            self.indexed_sources
                .insert(event.observed_source.clone(), 1);
            true
        } else {
            self.unindexed_source_event_count = self.unindexed_source_event_count.saturating_add(1);
            false
        };

        let indexed_domain = self.record_domain_index_membership(event, config);
        (indexed_source, indexed_domain)
    }

    fn record_domain_index_membership(
        &mut self,
        event: &QueryEventV1,
        config: &InMemoryQueryEventStoreConfig,
    ) -> bool {
        let Some(domain) = event
            .normalized_question
            .as_ref()
            .map(|question| &question.qname)
        else {
            return false;
        };
        if let Some(count) = self.indexed_domains.get_mut(domain) {
            *count = count.saturating_add(1);
            true
        } else if self.indexed_domains.len() < config.max_indexed_domains {
            self.indexed_domains.insert(domain.clone(), 1);
            true
        } else {
            self.unindexed_domain_event_count = self.unindexed_domain_event_count.saturating_add(1);
            false
        }
    }

    fn insert_ordered(&mut self, event: QueryEventV1, classified: bool) {
        let key = event_order_key(&event);
        let position = self
            .events
            .iter()
            .position(|existing| event_order_key(&existing.event) > key);
        let entry = StoredQueryEvent {
            event: Arc::new(event),
            indexed_source: false,
            indexed_domain: false,
            classified,
        };
        match position {
            Some(position) => self.events.insert(position, entry),
            None => self.events.push_back(entry),
        }
    }

    fn evict_expired(&mut self, retention: Option<Duration>) {
        let Some(retention) = retention else {
            return;
        };
        let Some(newest_timestamp) = self.events.back().map(|entry| entry.event.timestamp) else {
            return;
        };
        self.evict_expired_before(newest_timestamp, Some(retention));
    }

    fn evict_expired_before(&mut self, newest_timestamp: SystemTime, retention: Option<Duration>) {
        let Some(retention) = retention else {
            return;
        };
        while self
            .events
            .front()
            .and_then(|entry| entry.event.timestamp.checked_add(retention))
            .map(|expires_at| expires_at <= newest_timestamp)
            .unwrap_or(false)
        {
            self.evict_front();
        }
    }

    fn evict_to_bound(&mut self, max_retained_events: usize) {
        while self.events.len() > max_retained_events {
            self.evict_front();
        }
    }

    fn evict_front(&mut self) {
        let Some(entry) = self.events.pop_front() else {
            return;
        };
        self.remove_index_membership(&entry);
        self.evicted_event_count = self.evicted_event_count.saturating_add(1);
    }

    fn remove_index_membership(&mut self, entry: &StoredQueryEvent) {
        let event = &entry.event;
        if entry.indexed_source {
            if let Some(count) = self.indexed_sources.get_mut(&event.observed_source) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.indexed_sources.remove(&event.observed_source);
                }
            }
        } else {
            self.unindexed_source_event_count = self.unindexed_source_event_count.saturating_sub(1);
        }

        let Some(domain) = event
            .normalized_question
            .as_ref()
            .map(|question| &question.qname)
        else {
            return;
        };
        if entry.indexed_domain {
            if let Some(count) = self.indexed_domains.get_mut(domain) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.indexed_domains.remove(domain);
                }
            }
        } else {
            self.unindexed_domain_event_count = self.unindexed_domain_event_count.saturating_sub(1);
        }
    }

    fn rebuild_indexes(&mut self, config: &InMemoryQueryEventStoreConfig) {
        self.indexed_sources.clear();
        self.indexed_domains.clear();
        self.unindexed_source_event_count = 0;
        self.unindexed_domain_event_count = 0;

        for entry in &mut self.events {
            entry.indexed_source =
                if let Some(count) = self.indexed_sources.get_mut(&entry.event.observed_source) {
                    *count = count.saturating_add(1);
                    true
                } else if self.indexed_sources.len() < config.max_indexed_sources {
                    self.indexed_sources
                        .insert(entry.event.observed_source.clone(), 1);
                    true
                } else {
                    self.unindexed_source_event_count =
                        self.unindexed_source_event_count.saturating_add(1);
                    false
                };

            entry.indexed_domain = if let Some(domain) = entry
                .event
                .normalized_question
                .as_ref()
                .map(|question| &question.qname)
            {
                if let Some(count) = self.indexed_domains.get_mut(domain) {
                    *count = count.saturating_add(1);
                    true
                } else if self.indexed_domains.len() < config.max_indexed_domains {
                    self.indexed_domains.insert(domain.clone(), 1);
                    true
                } else {
                    self.unindexed_domain_event_count =
                        self.unindexed_domain_event_count.saturating_add(1);
                    false
                }
            } else {
                false
            };
        }
    }
}

fn event_order_key(event: &QueryEventV1) -> (SystemTime, u64) {
    (event.timestamp, event.sequence)
}

pub trait ResolutionBackend: Send + Sync {
    fn resolve<'a>(
        &'a self,
        request: ResolutionRequest,
    ) -> BoxFuture<'a, Result<ResolutionResponse, ResolutionBackendError>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveRootHint {
    pub name: String,
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveResolverConfig {
    pub root_hints: Vec<RecursiveRootHint>,
    pub per_authority_timeout: Duration,
    pub per_query_deadline: Duration,
    pub max_recursion_depth: u8,
    pub max_cname_restarts: u8,
    /// This resolver's own UDP payload size, used for the OPT record on
    /// every response `synthesize_recursive_cname_response` builds (RFC
    /// 6891 §6.1.1: a response's OPT record describes the responder's own
    /// size, never an echo of the requester's). Should be the same value
    /// passed to the sibling `StandardProtocolCodec::new` for the same
    /// resolver instance.
    pub configured_max_udp_payload_size: usize,
}

/// How many authorities within a delegation set to race concurrently.
/// Internal tuning, not caller-configurable -- keeping it out of the public
/// `RecursiveResolverConfig` means adding/changing it later isn't a
/// breaking change for anything constructing that struct.
const MAX_CONCURRENT_AUTHORITY_QUERIES: usize = 3;

/// Bounds nested glueless-delegation NS-name resolution: each glueless
/// referral encountered while resolving another glueless NS name's address
/// decrements this budget by one, so a cycle of NS names that keep
/// requiring each other's glueless resolution can't recurse forever.
const MAX_GLUELESS_NS_DEPTH: u8 = 4;
/// How many candidate NS hostnames a glueless delegation will try to
/// resolve before giving up, stopping early at the first success. Bounds
/// the worst-case extra latency added when names are also unresolvable.
const MAX_GLUELESS_NS_NAMES: usize = 2;

pub trait RecursiveAuthorityTransport: Send + Sync {
    fn query<'a>(
        &'a self,
        authority: SocketAddr,
        question: QuestionKey,
        dnssec_ok: bool,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<RecursiveAuthorityResponse, ResolutionBackendError>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveAuthorityResponse {
    pub bytes: Vec<u8>,
    pub message: Message,
}

impl RecursiveAuthorityResponse {
    pub fn new(bytes: Vec<u8>, message: Message) -> Result<Self, ResolutionBackendError> {
        if message.original_bytes.as_ref() != bytes.as_slice() {
            return Err(ResolutionBackendError::MalformedResponse);
        }
        Ok(Self { bytes, message })
    }
}

struct DelegationEntry {
    endpoints: Vec<SocketAddr>,
    expires_at: Instant,
    /// Which `insertion_order` slot owns this entry: `insert` stamps every
    /// stored entry with a fresh sequence and pushes a matching
    /// `(qclass, owner, sequence)` slot, and eviction only honors a slot
    /// whose sequence still matches the live entry. A slot left behind by
    /// an earlier generation of the same zone cut (the entry expired, was
    /// lazily removed by `lookup`, or was replaced by a refresh) has a
    /// stale sequence and is skipped/compacted instead of evicting the
    /// fresh entry — without this, FIFO eviction through a stale slot
    /// would delete a just-refreshed live delegation (wrong victim).
    sequence: u64,
}

/// Hard cap on distinct zone-cut entries the delegation cache will retain.
/// Bounds memory even if a client drives resolution of many unique delegated
/// zones (e.g. many distinct subdomains under an attacker-controlled zone
/// with high-TTL glue records).
const DEFAULT_DELEGATION_CACHE_CAPACITY: usize = 4096;

/// Ceiling on how long a learned delegation is trusted, regardless of the
/// NS/glue TTL an authority returned. Mirrors `CacheTtlPolicy::default`'s
/// 24h positive-answer cap so a malicious or misconfigured authority can't
/// pin resolver-wide routing for a zone cut indefinitely via an oversized TTL.
const DELEGATION_CACHE_MAX_TTL_SECONDS: u32 = 24 * 60 * 60;

#[derive(Default)]
struct DelegationCacheState {
    /// Two-level map (qclass -> owner -> entry) rather than a flat map
    /// keyed on a `format!("{qclass}:{owner}")` string: the outer map has
    /// a handful of keys in practice (almost always just IN), and the
    /// inner map's `String` keys let `lookup` probe each zone suffix with
    /// a borrowed `&str` — no per-suffix key allocation per lookup.
    entries: HashMap<u16, HashMap<String, DelegationEntry>>,
    /// FIFO of `(qclass, owner, sequence)` slots, deliberately *not*
    /// deduped on insert (the old unconditional per-insert `retain` was an
    /// O(capacity) scan on every referral store): a refresh strands the
    /// previous generation's slot with a now-stale sequence, and stale
    /// slots are skipped at eviction time (`DelegationEntry::sequence`),
    /// dropped when they surface at the front (`purge_front`), and
    /// reclaimed in bulk by `compact` once the queue outgrows
    /// `2 * max_entries` — so queue growth stays bounded even while the
    /// entry count sits below capacity.
    insertion_order: VecDeque<(u16, String, u64)>,
    next_sequence: u64,
}

impl DelegationCacheState {
    fn total_entries(&self) -> usize {
        self.entries.values().map(HashMap::len).sum()
    }

    /// Removes one `(qclass, owner)` entry, dropping the emptied inner map
    /// with it. Shared by every removal site so the two-level-map cleanup
    /// invariant lives in one place.
    fn remove_entry(&mut self, qclass: u16, owner: &str) {
        if let Some(by_owner) = self.entries.get_mut(&qclass) {
            by_owner.remove(owner);
            if by_owner.is_empty() {
                self.entries.remove(&qclass);
            }
        }
    }

    /// Whether `sequence` still identifies the live entry for
    /// `(qclass, owner)` — false for a slot stranded by expiry, lazy
    /// removal, or a refresh.
    fn slot_is_live(&self, qclass: u16, owner: &str, sequence: u64) -> bool {
        self.entries
            .get(&qclass)
            .and_then(|by_owner| by_owner.get(owner))
            .is_some_and(|entry| entry.sequence == sequence)
    }

    /// Opportunistic expiry purge, amortized O(1) per insert: pops slots
    /// off the FIFO front while they are stale (dangling or superseded) or
    /// name an expired live entry, removing the entry in the latter case.
    /// FIFO order isn't strict expiry order, so this doesn't catch every
    /// expired entry immediately — `lookup`'s lazy removal and
    /// `evict`/`compact` cover the rest.
    fn purge_front(&mut self, now: Instant) {
        while let Some((front_qclass, front_owner, front_sequence)) = self.insertion_order.front() {
            let live = self.slot_is_live(*front_qclass, front_owner, *front_sequence);
            let expired = live
                && self
                    .entries
                    .get(front_qclass)
                    .and_then(|by_owner| by_owner.get(front_owner))
                    .is_some_and(|entry| entry.expires_at <= now);
            if live && !expired {
                break;
            }
            let (front_qclass, front_owner, _) = self
                .insertion_order
                .pop_front()
                .expect("front() just returned Some");
            if expired {
                self.remove_entry(front_qclass, &front_owner);
            }
        }
    }

    /// Purges expired entries, then evicts oldest-inserted live entries
    /// (FIFO, skipping stale slots — see `DelegationEntry::sequence`)
    /// until at or under `max_entries`, then compacts the slot queue.
    /// Only called once an insert actually pushes the cache over capacity
    /// — running it on every insert (the previous shape) made each
    /// referral store an O(capacity) full scan.
    fn evict(&mut self, max_entries: usize) {
        let now = Instant::now();
        for by_owner in self.entries.values_mut() {
            by_owner.retain(|_, entry| entry.expires_at > now);
        }
        self.entries.retain(|_, by_owner| !by_owner.is_empty());
        let mut total = self.total_entries();
        while total > max_entries {
            let Some((qclass, owner, sequence)) = self.insertion_order.pop_front() else {
                break;
            };
            if self.slot_is_live(qclass, &owner, sequence) {
                self.remove_entry(qclass, &owner);
                total -= 1;
            }
        }
        self.compact();
    }

    /// Drops every slot that no longer identifies a live entry. O(queue
    /// length), so callers gate it: `evict` (already over capacity) and
    /// `insert`'s queue-growth trigger (queue past `2 * max_entries`,
    /// making the scan amortized O(1) per insert).
    fn compact(&mut self) {
        let entries = &self.entries;
        self.insertion_order.retain(|(qclass, owner, sequence)| {
            entries
                .get(qclass)
                .and_then(|by_owner| by_owner.get(owner))
                .is_some_and(|entry| entry.sequence == *sequence)
        });
    }
}

struct DelegationCache {
    max_entries: usize,
    state: Mutex<DelegationCacheState>,
}

impl DelegationCache {
    fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            state: Mutex::new(DelegationCacheState::default()),
        }
    }

    fn insert(&self, owner: String, qclass: u16, endpoints: Vec<SocketAddr>, ttl_seconds: u32) {
        if ttl_seconds == 0 || self.max_entries == 0 {
            return;
        }
        let ttl_seconds = ttl_seconds.min(DELEGATION_CACHE_MAX_TTL_SECONDS);
        let now = Instant::now();
        let expires_at = now + Duration::from_secs(u64::from(ttl_seconds));
        let mut state = self.state.lock().unwrap();
        state.purge_front(now);
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        // A refresh of an already-live key strands the previous slot with a
        // stale sequence rather than scanning the queue to dedupe it — see
        // `DelegationCacheState::insertion_order`.
        state.entries.entry(qclass).or_default().insert(
            owner.clone(),
            DelegationEntry {
                endpoints,
                expires_at,
                sequence,
            },
        );
        state.insertion_order.push_back((qclass, owner, sequence));
        if state.total_entries() > self.max_entries {
            state.evict(self.max_entries);
        } else if state.insertion_order.len() > (2 * self.max_entries).max(8) {
            state.compact();
        }
    }

    /// Longest-suffix match against cached zone cuts, e.g. for "www.example.com"
    /// tries "www.example.com", then "example.com", then "com". Scoped by
    /// `qclass` so a referral learned for one DNS class (e.g. CHAOS) can
    /// never be reused to route a query in another class (e.g. IN). Returns
    /// the matched zone cut alongside the endpoints so the caller can track
    /// which zone it's currently querying within.
    fn lookup(&self, qname: &str, qclass: u16) -> Option<(String, Vec<SocketAddr>)> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let by_owner = state.entries.get_mut(&qclass)?;
        let mut matched = None;
        for suffix in zone_suffixes(qname) {
            match by_owner.get(suffix) {
                Some(entry) if entry.expires_at > now => {
                    matched = Some((suffix.to_string(), entry.endpoints.clone()));
                    break;
                }
                Some(_) => {
                    // Expired: drop lazily. Its `insertion_order` slot is
                    // now stale and gets skipped/reclaimed by
                    // `purge_front`/`evict`/`compact`.
                    by_owner.remove(suffix);
                }
                None => {}
            }
        }
        // Uphold `remove_entry`'s emptied-inner-map invariant here too: if
        // lazy expiry just removed this qclass's last entry, drop the outer
        // key rather than parking an empty map on it.
        if by_owner.is_empty() {
            state.entries.remove(&qclass);
        }
        matched
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state.lock().unwrap().total_entries()
    }

    #[cfg(test)]
    fn insertion_order_len(&self) -> usize {
        self.state.lock().unwrap().insertion_order.len()
    }

    #[cfg(test)]
    fn qclass_key_count(&self) -> usize {
        self.state.lock().unwrap().entries.len()
    }

    #[cfg(test)]
    fn ttl_remaining_secs(&self, qname: &str, qclass: u16) -> Option<u64> {
        let now = Instant::now();
        let state = self.state.lock().unwrap();
        let by_owner = state.entries.get(&qclass)?;
        for suffix in zone_suffixes(qname) {
            if let Some(entry) = by_owner.get(suffix) {
                return Some(entry.expires_at.saturating_duration_since(now).as_secs());
            }
        }
        None
    }
}

fn zone_suffixes(qname: &str) -> impl Iterator<Item = &str> {
    let mut current = if qname.is_empty() { None } else { Some(qname) };
    std::iter::from_fn(move || {
        let value = current?;
        current = value.split_once('.').map(|(_, rest)| rest);
        Some(value)
    })
}

pub struct RecursiveResolutionBackend {
    config: RecursiveResolverConfig,
    transport: Arc<dyn RecursiveAuthorityTransport>,
    metrics: Option<Arc<dyn MetricsSink>>,
    delegation_cache: DelegationCache,
}

/// Mutable state threaded through one `resolve_iterative` call as it walks
/// the delegation chain and follows CNAME restarts.
struct IterativeQueryState {
    question: QuestionKey,
    current_zone: String,
    seen_referrals: HashSet<String>,
    seen_cnames: HashSet<String>,
    cname_chain: Vec<Record>,
    cname_restarts: u8,
}

/// What a single authority's response means for the in-flight iterative
/// query: it's finished (answer or fatal error), it points to a new
/// authority set to try next, or it just wasn't usable and other authorities
/// in this hop should still be tried.
enum AuthorityResponseOutcome {
    Return(Box<Result<ResolutionResponse, ResolutionBackendError>>),
    Advance(Vec<SocketAddr>),
    Reject(ResolutionBackendError),
}

/// What racing every authority in one hop produced: either the query is
/// finished, or the next authority set to try (from a referral or CNAME
/// restart) is ready.
enum HopOutcome {
    Return(Box<Result<ResolutionResponse, ResolutionBackendError>>),
    Advance(Vec<SocketAddr>),
}

/// Mutable state threaded through one `resolve_ns_addresses_for_qtype` walk.
struct NsWalkState {
    current_zone: String,
    seen_referrals: HashSet<String>,
}

/// What a single authority's response means for an in-flight NS-address
/// walk: resolved addresses (possibly empty, meaning "give up"), a referral
/// or glueless delegation to advance to, or nothing usable (try other
/// authorities in this hop).
enum NsResponseOutcome {
    Return(Vec<SocketAddr>, u32),
    Advance(Vec<SocketAddr>),
    Continue,
}

/// What racing every authority in one NS-address-walk hop produced.
enum NsHopOutcome {
    Return(Vec<SocketAddr>, u32),
    Advance(Vec<SocketAddr>),
}

impl RecursiveResolutionBackend {
    pub fn new(
        config: RecursiveResolverConfig,
        transport: Arc<dyn RecursiveAuthorityTransport>,
    ) -> Self {
        Self {
            config,
            transport,
            metrics: None,
            delegation_cache: DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY),
        }
    }

    pub fn with_metrics(
        config: RecursiveResolverConfig,
        transport: Arc<dyn RecursiveAuthorityTransport>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        Self {
            config,
            transport,
            metrics: Some(metrics),
            delegation_cache: DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY),
        }
    }

    fn increment_metric(&self, metric: ResolverMetric) {
        if let Some(metrics) = &self.metrics {
            metrics.increment(metric);
        }
    }

    fn observe_metric(&self, metric: ResolverMetric, duration: Duration) {
        if let Some(metrics) = &self.metrics {
            metrics.observe_duration(metric, duration);
        }
    }

    async fn resolve_iterative(
        &self,
        request: ResolutionRequest,
    ) -> Result<ResolutionResponse, ResolutionBackendError> {
        if self.config.root_hints.is_empty() {
            self.increment_metric(ResolverMetric::RecursiveLimitHit);
            return Err(ResolutionBackendError::NoBackendsAvailable);
        }

        let question = request.query.question.clone();
        let (current_zone, mut authorities) =
            self.authorities_for(&question.qname, question.qclass);
        let mut state = IterativeQueryState {
            seen_cnames: HashSet::from([question.qname.clone()]),
            question,
            current_zone,
            seen_referrals: HashSet::new(),
            cname_chain: Vec::new(),
            cname_restarts: 0,
        };
        let query_deadline = Instant::now() + self.config.per_query_deadline;

        for _ in 0..self.config.max_recursion_depth {
            if authorities.is_empty() {
                self.increment_metric(ResolverMetric::RecursiveLimitHit);
                return Err(ResolutionBackendError::NoBackendsAvailable);
            }

            match self
                .resolve_one_hop(&request, &mut state, &authorities, query_deadline)
                .await
            {
                HopOutcome::Return(result) => return *result,
                HopOutcome::Advance(next) => authorities = next,
            }
        }

        self.increment_metric(ResolverMetric::RecursiveLimitHit);
        Err(ResolutionBackendError::NoBackendsAvailable)
    }

    /// Races every authority in `authorities` (in bounded-size chunks,
    /// respecting `query_deadline`) and returns either the finished query
    /// result or the next authority set to advance to.
    async fn resolve_one_hop(
        &self,
        request: &ResolutionRequest,
        state: &mut IterativeQueryState,
        authorities: &[SocketAddr],
        query_deadline: Instant,
    ) -> HopOutcome {
        let mut last_error = None;

        for authority_chunk in authorities.chunks(MAX_CONCURRENT_AUTHORITY_QUERIES) {
            let Some(remaining) = query_deadline.checked_duration_since(Instant::now()) else {
                self.increment_metric(ResolverMetric::RecursiveAuthorityTimeout);
                return HopOutcome::Return(Box::new(Err(ResolutionBackendError::Timeout)));
            };
            if remaining.is_zero() {
                self.increment_metric(ResolverMetric::RecursiveAuthorityTimeout);
                return HopOutcome::Return(Box::new(Err(ResolutionBackendError::Timeout)));
            }
            let attempt_timeout = remaining.min(self.config.per_authority_timeout);

            let mut join_set = JoinSet::new();
            for &authority in authority_chunk {
                self.increment_metric(ResolverMetric::RecursiveAuthorityAttempt);
                let transport = Arc::clone(&self.transport);
                let question_for_task = state.question.clone();
                // Always request DNSSEC material from every authority,
                // independent of the querying client's own DO flag: a
                // security-aware resolver should fetch/cache DNSSEC data
                // regardless of the requester that happens to trigger the
                // fetch, and decide what to hand back only at
                // response-assembly time (RFC 4035 §4.5; RFC 6840 §5.9).
                // What actually reaches this particular client is still
                // filtered per its own DO flag -- see
                // `filter_response_for_requester` in `prepare_backend_result`.
                let dnssec_ok = true;
                join_set.spawn(async move {
                    let outcome = time::timeout(
                        attempt_timeout,
                        transport.query(authority, question_for_task, dnssec_ok, attempt_timeout),
                    )
                    .await;
                    (authority, outcome)
                });
            }

            while let Some(joined) = join_set.join_next().await {
                let Ok((authority, outcome)) = joined else {
                    continue;
                };
                let response = match self.record_transport_outcome(outcome) {
                    Ok(response) => response,
                    Err(error) => {
                        last_error = Some(error);
                        continue;
                    }
                };

                match self
                    .evaluate_authority_response(
                        state,
                        request,
                        authority,
                        response,
                        query_deadline,
                    )
                    .await
                {
                    AuthorityResponseOutcome::Return(result) => {
                        return HopOutcome::Return(result);
                    }
                    AuthorityResponseOutcome::Advance(next) => {
                        return HopOutcome::Advance(next);
                    }
                    AuthorityResponseOutcome::Reject(error) => {
                        last_error = Some(error);
                    }
                }
            }
        }

        HopOutcome::Return(Box::new(Err(
            last_error.unwrap_or(ResolutionBackendError::NoBackendsAvailable)
        )))
    }

    /// Maps a single authority's raced transport outcome to a response,
    /// recording the appropriate metric for a transport-level error or
    /// attempt timeout.
    fn record_transport_outcome(
        &self,
        outcome: Result<
            Result<RecursiveAuthorityResponse, ResolutionBackendError>,
            time::error::Elapsed,
        >,
    ) -> Result<RecursiveAuthorityResponse, ResolutionBackendError> {
        match outcome {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => {
                if error == ResolutionBackendError::Timeout {
                    self.increment_metric(ResolverMetric::RecursiveAuthorityTimeout);
                } else {
                    self.increment_metric(ResolverMetric::RecursiveAuthorityError);
                }
                Err(error)
            }
            Err(_) => {
                self.increment_metric(ResolverMetric::RecursiveAuthorityTimeout);
                Err(ResolutionBackendError::Timeout)
            }
        }
    }

    /// Interprets one authority's response: a usable answer, a CNAME restart,
    /// a referral to follow, or neither (in which case the caller should try
    /// other authorities in this hop).
    async fn evaluate_authority_response(
        &self,
        state: &mut IterativeQueryState,
        request: &ResolutionRequest,
        authority: SocketAddr,
        response: RecursiveAuthorityResponse,
        query_deadline: Instant,
    ) -> AuthorityResponseOutcome {
        let message = &response.message;

        if let Some(error) = authority_response_error(message, &state.question) {
            self.increment_metric(ResolverMetric::RecursiveAuthorityError);
            return AuthorityResponseOutcome::Reject(error);
        }

        if (message.header.aa() && has_requested_answer_for(message, &state.question))
            || is_negative_answer(message)
        {
            return AuthorityResponseOutcome::Return(Box::new(
                ResolutionResponse::recursive_response(
                    &request.query,
                    response,
                    &state.cname_chain,
                    SystemTime::now(),
                    request.backend_generation,
                    authority,
                    self.config.configured_max_udp_payload_size,
                ),
            ));
        }

        if message.header.aa()
            && let Some(cname_record) = cname_record_for(message, &state.question)
        {
            let RecordData::CNAME(cname_target) = &cname_record.record else {
                unreachable!();
            };
            let target_question =
                QuestionKey::new(cname_target, state.question.qtype, state.question.qclass);
            if has_requested_answer_for(message, &target_question) {
                return AuthorityResponseOutcome::Return(Box::new(
                    ResolutionResponse::recursive_response(
                        &request.query,
                        response,
                        &state.cname_chain,
                        SystemTime::now(),
                        request.backend_generation,
                        authority,
                        self.config.configured_max_udp_payload_size,
                    ),
                ));
            }
            let next_name = normalize_question_name(cname_target);
            if state.cname_restarts >= self.config.max_cname_restarts
                || !state.seen_cnames.insert(next_name)
            {
                self.increment_metric(ResolverMetric::RecursiveLimitHit);
                return AuthorityResponseOutcome::Return(Box::new(Err(
                    ResolutionBackendError::NoBackendsAvailable,
                )));
            }
            state
                .cname_chain
                .extend(cname_chain_records(message, cname_record));
            state.cname_restarts = state.cname_restarts.saturating_add(1);
            state.question =
                QuestionKey::new(cname_target, state.question.qtype, state.question.qclass);
            state.seen_referrals.clear();
            let (zone, next) = self.authorities_for(&state.question.qname, state.question.qclass);
            state.current_zone = zone;
            return AuthorityResponseOutcome::Advance(next);
        }

        let Some(referral) = referral_authorities(message, &state.question) else {
            return self
                .handle_missing_referral(state, query_deadline, message)
                .await;
        };

        self.handle_referral(state, referral)
    }

    /// Handles a response that carries no trustable referral glue: tries a
    /// glueless-delegation resolution if one applies, otherwise records why
    /// the response was unusable and tells the caller to try other
    /// authorities in this hop.
    async fn handle_missing_referral(
        &self,
        state: &mut IterativeQueryState,
        query_deadline: Instant,
        message: &Message,
    ) -> AuthorityResponseOutcome {
        if let Some((owner, names, min_ttl)) = glueless_delegation_names(message, &state.question)
            && is_valid_zone_progression(&state.current_zone, &owner)
        {
            let (resolved, resolved_ttl) = self
                .resolve_glueless_endpoints(
                    &names,
                    state.question.qclass,
                    query_deadline,
                    MAX_GLUELESS_NS_DEPTH,
                )
                .await;
            if !resolved.is_empty() {
                self.delegation_cache.insert(
                    owner.clone(),
                    state.question.qclass,
                    resolved.clone(),
                    min_ttl.min(resolved_ttl),
                );
                state.current_zone = owner;
                return AuthorityResponseOutcome::Advance(resolved);
            }
        }
        if has_delegation_for_question(message, &state.question) {
            self.increment_metric(ResolverMetric::RecursiveBailiwickReject);
        } else {
            self.increment_metric(ResolverMetric::RecursiveLameDelegation);
        }
        AuthorityResponseOutcome::Reject(ResolutionBackendError::NoBackendsAvailable)
    }

    /// Validates a referral against the current zone and the in-flight
    /// referral-loop set, then advances to it, caching the delegation.
    fn handle_referral(
        &self,
        state: &mut IterativeQueryState,
        referral: ReferralAuthorities,
    ) -> AuthorityResponseOutcome {
        if !is_valid_zone_progression(&state.current_zone, &referral.owner) {
            // An authority reached via `current_zone` claimed a referral to
            // an ancestor, sibling, or its own zone instead of a proper
            // child -- reject outright rather than follow it or let it
            // poison the shared delegation cache for unrelated future
            // queries.
            self.increment_metric(ResolverMetric::RecursiveBailiwickReject);
            return AuthorityResponseOutcome::Reject(ResolutionBackendError::NoBackendsAvailable);
        }
        let referral_key = referral_loop_key(&referral);
        if !state.seen_referrals.insert(referral_key) {
            self.increment_metric(ResolverMetric::RecursiveReferralLoop);
            return AuthorityResponseOutcome::Return(Box::new(Err(
                ResolutionBackendError::NoBackendsAvailable,
            )));
        }
        self.delegation_cache.insert(
            referral.owner.clone(),
            state.question.qclass,
            referral.endpoints.clone(),
            referral.min_ttl,
        );
        state.current_zone = referral.owner.clone();
        AuthorityResponseOutcome::Advance(referral.endpoints)
    }

    fn root_authorities(&self) -> Vec<SocketAddr> {
        self.config
            .root_hints
            .iter()
            .flat_map(|hint| hint.endpoints.iter().copied())
            .collect()
    }

    /// Resolves the authority set to start querying for `qname`, either from
    /// a cached delegation or (on a miss) the root hints. Returns the zone
    /// cut the returned authorities are for ("" for root), so the caller can
    /// track its current position in the delegation chain.
    fn authorities_for(&self, qname: &str, qclass: u16) -> (String, Vec<SocketAddr>) {
        match self.delegation_cache.lookup(qname, qclass) {
            Some((zone, endpoints)) => (zone, endpoints),
            None => (String::new(), self.root_authorities()),
        }
    }

    /// Tries NS hostnames in turn (each via its own independent, fully
    /// bailiwick-validated recursive lookup) and returns the first one that
    /// resolves to at least one address (plus that address record's TTL),
    /// to fill in a glueless delegation. Stops at the first success rather
    /// than resolving every candidate, to bound the extra latency this adds
    /// to the outer query.
    async fn resolve_glueless_endpoints(
        &self,
        names: &HashSet<String>,
        qclass: u16,
        deadline: Instant,
        depth_budget: u8,
    ) -> (Vec<SocketAddr>, u32) {
        // HashSet iteration order is arbitrary, so sort first -- otherwise
        // which NS names get tried (and thus whether resolution succeeds)
        // when there are more candidates than MAX_GLUELESS_NS_NAMES would be
        // nondeterministic from one run to the next.
        let mut candidates: Vec<&String> = names.iter().collect();
        candidates.sort();

        for name in candidates.into_iter().take(MAX_GLUELESS_NS_NAMES) {
            if Instant::now() >= deadline {
                break;
            }
            let (addresses, ttl) = self
                .resolve_ns_addresses(name, qclass, deadline, depth_budget)
                .await;
            if !addresses.is_empty() {
                return (addresses, ttl);
            }
        }
        (Vec::new(), 0)
    }

    /// Resolves a bare hostname (an NS target with no glue) to its A and
    /// AAAA addresses, querying both qtypes independently and merging the
    /// results -- an IPv6-only glueless nameserver would otherwise never
    /// produce endpoints since only A was queried. Returns the union of
    /// both address families, bounded by the minimum TTL across whichever
    /// queries actually returned addresses.
    async fn resolve_ns_addresses(
        &self,
        ns_name: &str,
        qclass: u16,
        deadline: Instant,
        depth_budget: u8,
    ) -> (Vec<SocketAddr>, u32) {
        let (mut a_endpoints, a_ttl) = self
            .resolve_ns_addresses_for_qtype(ns_name, A_RECORD_TYPE, qclass, deadline, depth_budget)
            .await;
        let (aaaa_endpoints, aaaa_ttl) = self
            .resolve_ns_addresses_for_qtype(
                ns_name,
                AAAA_RECORD_TYPE,
                qclass,
                deadline,
                depth_budget,
            )
            .await;

        let ttl = match (a_endpoints.is_empty(), aaaa_endpoints.is_empty()) {
            (true, true) => 0,
            (false, true) => a_ttl,
            (true, false) => aaaa_ttl,
            (false, false) => a_ttl.min(aaaa_ttl),
        };
        a_endpoints.extend(aaaa_endpoints);
        (a_endpoints, ttl)
    }

    /// Resolves a bare hostname (an NS target with no glue) to its addresses
    /// for a single qtype via its own independent iterative walk -- the same
    /// referral-following, bailiwick validation, and delegation caching as
    /// the main query path, just returning raw addresses instead of a
    /// client-facing response. `depth_budget` bounds nested glueless
    /// resolutions specifically (separate from `max_recursion_depth`, which
    /// bounds this walk's own referral chain), so a cycle of NS names that
    /// keep requiring each other's glueless resolution can't recurse
    /// forever. NS records must not point to CNAMEs (RFC 2181), so unlike
    /// the main path this walk does not need to follow CNAME chains.
    fn resolve_ns_addresses_for_qtype<'a>(
        &'a self,
        ns_name: &'a str,
        qtype: u16,
        qclass: u16,
        deadline: Instant,
        depth_budget: u8,
    ) -> BoxFuture<'a, (Vec<SocketAddr>, u32)> {
        Box::pin(async move {
            if depth_budget == 0 {
                return (Vec::new(), 0);
            }
            let question = QuestionKey::new(ns_name, qtype, qclass);
            let (current_zone, mut authorities) = self.authorities_for(&question.qname, qclass);
            let mut state = NsWalkState {
                current_zone,
                seen_referrals: HashSet::new(),
            };

            for _ in 0..self.config.max_recursion_depth {
                if authorities.is_empty() || Instant::now() >= deadline {
                    return (Vec::new(), 0);
                }

                match self
                    .resolve_ns_hop(
                        &question,
                        &mut state,
                        &authorities,
                        qclass,
                        deadline,
                        depth_budget,
                    )
                    .await
                {
                    NsHopOutcome::Return(endpoints, ttl) => return (endpoints, ttl),
                    NsHopOutcome::Advance(next) => authorities = next,
                }
            }

            (Vec::new(), 0)
        })
    }

    /// Races every authority in `authorities` for one NS-address-walk hop.
    async fn resolve_ns_hop(
        &self,
        question: &QuestionKey,
        state: &mut NsWalkState,
        authorities: &[SocketAddr],
        qclass: u16,
        deadline: Instant,
        depth_budget: u8,
    ) -> NsHopOutcome {
        for authority_chunk in authorities.chunks(MAX_CONCURRENT_AUTHORITY_QUERIES) {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return NsHopOutcome::Return(Vec::new(), 0);
            };
            if remaining.is_zero() {
                return NsHopOutcome::Return(Vec::new(), 0);
            }
            let attempt_timeout = remaining.min(self.config.per_authority_timeout);

            let mut join_set = JoinSet::new();
            for &authority in authority_chunk {
                self.increment_metric(ResolverMetric::RecursiveAuthorityAttempt);
                let transport = Arc::clone(&self.transport);
                let question_for_task = question.clone();
                join_set.spawn(async move {
                    time::timeout(
                        attempt_timeout,
                        transport.query(authority, question_for_task, false, attempt_timeout),
                    )
                    .await
                });
            }

            while let Some(joined) = join_set.join_next().await {
                let Ok(outcome) = joined else {
                    continue;
                };
                let response = match outcome {
                    Ok(Ok(response)) => response,
                    _ => continue,
                };

                match self
                    .evaluate_ns_response(
                        question,
                        state,
                        qclass,
                        deadline,
                        depth_budget,
                        &response,
                    )
                    .await
                {
                    NsResponseOutcome::Return(endpoints, ttl) => {
                        return NsHopOutcome::Return(endpoints, ttl);
                    }
                    NsResponseOutcome::Advance(next) => return NsHopOutcome::Advance(next),
                    NsResponseOutcome::Continue => {}
                }
            }
        }

        NsHopOutcome::Return(Vec::new(), 0)
    }

    /// Interprets one authority's response during an NS-address walk:
    /// resolved addresses, a referral or glueless delegation to follow, or
    /// nothing usable.
    async fn evaluate_ns_response(
        &self,
        question: &QuestionKey,
        state: &mut NsWalkState,
        qclass: u16,
        deadline: Instant,
        depth_budget: u8,
        response: &RecursiveAuthorityResponse,
    ) -> NsResponseOutcome {
        let message = &response.message;
        if authority_response_error(message, question).is_some() {
            return NsResponseOutcome::Continue;
        }
        if is_negative_answer(message) {
            return NsResponseOutcome::Return(Vec::new(), 0);
        }
        if message.header.aa() && has_requested_answer_for(message, question) {
            let (endpoints, ttl) = a_record_endpoints(message, question);
            return NsResponseOutcome::Return(endpoints, ttl);
        }

        if let Some(referral) = referral_authorities(message, question) {
            if !is_valid_zone_progression(&state.current_zone, &referral.owner) {
                return NsResponseOutcome::Continue;
            }
            let referral_key = referral_loop_key(&referral);
            if !state.seen_referrals.insert(referral_key) {
                return NsResponseOutcome::Return(Vec::new(), 0);
            }
            self.delegation_cache.insert(
                referral.owner.clone(),
                qclass,
                referral.endpoints.clone(),
                referral.min_ttl,
            );
            state.current_zone = referral.owner;
            return NsResponseOutcome::Advance(referral.endpoints);
        }

        if let Some((owner, names, min_ttl)) = glueless_delegation_names(message, question) {
            if !is_valid_zone_progression(&state.current_zone, &owner) {
                return NsResponseOutcome::Continue;
            }
            let (resolved, resolved_ttl) = self
                .resolve_glueless_endpoints(&names, qclass, deadline, depth_budget - 1)
                .await;
            if resolved.is_empty() {
                return NsResponseOutcome::Continue;
            }
            self.delegation_cache.insert(
                owner.clone(),
                qclass,
                resolved.clone(),
                min_ttl.min(resolved_ttl),
            );
            state.current_zone = owner;
            return NsResponseOutcome::Advance(resolved);
        }

        NsResponseOutcome::Continue
    }
}

/// Extracts A/AAAA answer endpoints for `question`, plus their minimum TTL
/// -- callers resolving a glueless NS name's address need that TTL to bound
/// how long the resulting delegation-cache entry can be trusted, the same
/// way in-response glue TTLs already bound normal referrals.
fn a_record_endpoints(message: &Message, question: &QuestionKey) -> (Vec<SocketAddr>, u32) {
    let mut min_ttl: Option<u32> = None;
    let endpoints = message
        .answers
        .iter()
        .filter_map(|record| {
            if record.rclass != question.qclass
                || normalize_question_name(&record.name) != question.qname
            {
                return None;
            }
            let endpoint = match record.record {
                RecordData::A(address) => Some(SocketAddr::new(IpAddr::V4(address), 53)),
                RecordData::AAAA(address) => Some(SocketAddr::new(IpAddr::V6(address), 53)),
                _ => None,
            };
            if endpoint.is_some() {
                min_ttl = Some(min_ttl.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
            }
            endpoint
        })
        .collect();
    (endpoints, min_ttl.unwrap_or(0))
}

/// Whether a referral learned while querying within `current_zone` may
/// legitimately delegate to `candidate_owner`. `candidate_owner` must be
/// `current_zone` itself (an authority re-affirming the zone it's already
/// known for) or a proper descendant of it; an authority reached via a valid
/// delegation must never be able to redirect the resolver back up to an
/// ancestor or sideways to an unrelated zone (e.g. an `example.com`
/// authority claiming to redelegate `com`), which would otherwise let one
/// bad response poison unrelated future queries through the shared
/// delegation cache.
fn is_valid_zone_progression(current_zone: &str, candidate_owner: &str) -> bool {
    is_delegation_owner_for_question(current_zone, candidate_owner)
}

fn referral_loop_key(referral: &ReferralAuthorities) -> String {
    let mut endpoints = referral.endpoints.clone();
    endpoints.sort_unstable();
    let endpoints = endpoints
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("{}|{endpoints}", referral.owner)
}

impl ResolutionBackend for RecursiveResolutionBackend {
    fn resolve<'a>(
        &'a self,
        request: ResolutionRequest,
    ) -> BoxFuture<'a, Result<ResolutionResponse, ResolutionBackendError>> {
        Box::pin(async move {
            self.increment_metric(ResolverMetric::RecursiveQuery);
            let started = Instant::now();
            let result = self.resolve_iterative(request).await;
            self.observe_metric(ResolverMetric::RecursiveQueryDuration, started.elapsed());
            result
        })
    }
}

/// `configured_max_udp_payload_size` on every method here is this
/// resolver's own configured/effective UDP payload size (see
/// `ProtocolCodec::configured_max_udp_payload_size`) -- per RFC 6891
/// §6.1.1, the OPT record any of these builders may attach to a *response*
/// must describe the responder's own size, never an echo of the
/// requester's advertised size, so callers must thread it in explicitly
/// rather than these builders inferring it from the query.
pub trait ResponseFactory: Send + Sync {
    /// `request` is the `Message` recovered from the failing query when
    /// possible (see `Message::parse_standard_query_owned_with_recovery`),
    /// so an EDNS/CD-aware error response can be built even when decoding
    /// failed for a reason other than the wire format itself being
    /// unparseable (e.g. an unsupported opcode). It's `None` only when the
    /// packet genuinely couldn't be parsed at all.
    fn protocol_error(
        &self,
        request_id: Option<u16>,
        error: &QueryValidationError,
        request: Option<&Message>,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8>;

    fn block_response_mode(&self, _block: &PolicyBlock, _qtype: u16) -> BlockResponseMode {
        BlockResponseMode::Refused
    }

    fn blocked(
        &self,
        query: &DecodedQuery,
        block: &PolicyBlock,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8>;

    fn servfail(
        &self,
        query: Option<&DecodedQuery>,
        configured_max_udp_payload_size: usize,
    ) -> Vec<u8>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// [`Clock`] backed by the OS wall clock. Library consumers constructing
/// [`crate::delivery::dns::UdpDnsServer`]/[`crate::delivery::dns::TcpDnsServer`]
/// outside this crate's `main.rs` can use this instead of writing their own.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub trait QueryEventSink: Send + Sync {
    fn record(&self, event: QueryEventV1) -> QueryEventRecordResult;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryEventRecordResult {
    Accepted,
    Disabled,
    DroppedNewest,
    DroppedOldest,
    Sampled,
}

pub trait MetricsSink: Send + Sync {
    fn increment(&self, metric: ResolverMetric);

    fn observe_duration(&self, metric: ResolverMetric, duration: Duration);

    fn record_backend_status(&self, _status: &BackendStatus) {}

    /// Per-query variant of `increment` carrying the requesting client's
    /// source IP, so sinks can label the metric by where the query came
    /// from. The resolver calls this (never plain `increment`) for every
    /// metric that is scoped to a single client query; metrics emitted
    /// from background or shared work (refresh workers, event-queue
    /// accounting, recursion internals, cache stores shared with the
    /// refresh path, and upstream fetches — which single-flight
    /// coalescing shares across clients) stay on the unlabeled
    /// `increment` so each metric family is consistently labeled or
    /// consistently not.
    ///
    /// Sinks that don't label by source keep this default, which discards
    /// the IP. Sinks that do should note the cardinality cost: one time
    /// series per distinct client IP per metric.
    fn increment_with_source(&self, metric: ResolverMetric, _source_ip: IpAddr) {
        self.increment(metric);
    }

    /// Per-query variant of `observe_duration`; same contract as
    /// `increment_with_source`.
    fn observe_duration_with_source(
        &self,
        metric: ResolverMetric,
        duration: Duration,
        _source_ip: IpAddr,
    ) {
        self.observe_duration(metric, duration);
    }
}

pub struct NoopMetricsSink;

impl MetricsSink for NoopMetricsSink {
    fn increment(&self, _metric: ResolverMetric) {}

    fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverMetric {
    QueryReceived,
    QueryAllowed,
    QueryBlocked,
    CacheHit,
    CacheMiss,
    CacheExpired,
    CacheBypass,
    CacheUnavailable,
    CacheStore,
    CacheStoreSkipped,
    CacheNegativeStore,
    CacheNegativeHit,
    /// A cache hit whose response includes at least one expired entry
    /// served under RFC 8767 serve-stale (`docs/knowledge/resolver/caching/`).
    /// Incremented *in addition to* `CacheHit`, mirroring how
    /// `CacheNegativeHit` subdivides hits rather than replacing them.
    CacheStaleHit,
    CacheResponseTruncated,
    CacheCoalescedMiss,
    QueryEventAccepted,
    QueryEventDisabled,
    QueryEventDroppedNewest,
    QueryEventDroppedOldest,
    QueryEventSampled,
    UpstreamSuccess,
    UpstreamFailure,
    RecursiveQuery,
    RecursiveAuthorityAttempt,
    RecursiveAuthorityTimeout,
    RecursiveAuthorityError,
    RecursiveBailiwickReject,
    RecursiveLameDelegation,
    RecursiveReferralLoop,
    RecursiveLimitHit,
    RecursiveTcpFallbackAttempt,
    RecursiveTcpFallbackSuccess,
    RecursiveTcpFallbackFailure,
    RecursiveTcpFallbackTimeout,
    QueryDuration,
    RecursiveQueryDuration,
    CacheHitQueryDuration,
    CacheMissQueryDuration,
    ProtocolError,
    RecursionRefused,
    /// A hot, near-expiry entry was seen and a `RefreshJob` was enqueued
    /// (`docs/plans/auto_refresh/`). Pulled forward from section-05's
    /// scope: needed here since section-04's enqueue path must compile,
    /// even though the worker pool that consumes these jobs doesn't exist
    /// yet.
    RefreshTriggered,
    /// A refresh trigger fired but the channel was full (or, before
    /// section-05's worker pool exists, always — every `ResolveQuery` has
    /// no live receiver until `main.rs` wires one up), so the job was
    /// dropped. Best-effort by design; no correctness impact.
    RefreshQueueFull,
    /// A worker's refetch completed and the entry was re-stored
    /// (section-06).
    RefreshSucceeded,
    /// A worker's refetch failed for any reason (section-06); no retry.
    RefreshFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::mpsc as std_mpsc;
    use std::thread;
    use tokio::sync::{Barrier, Notify};

    use crate::config::{CacheConfig, LeakRate, RefreshConfig};
    use crate::protocol::{EdnsInfo, Header, Question, Record, build_a_block_response};

    fn a_query(id: u16, name: &str) -> Vec<u8> {
        query(id, name, 1, 1)
    }

    fn query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
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
        bytes.extend_from_slice(&qclass.to_be_bytes());
        bytes
    }

    /// Like `a_query_with_edns`, but for an arbitrary `qtype` rather than
    /// always A -- needed for direct queries of DNSSEC record types
    /// (DNSKEY, RRSIG, ...) with EDNS attached.
    fn query_with_edns(
        id: u16,
        name: &str,
        qtype: u16,
        qclass: u16,
        udp_payload_size: u16,
        dnssec_ok: bool,
    ) -> Vec<u8> {
        let mut bytes = query(id, name, qtype, qclass);
        bytes[10..12].copy_from_slice(&1u16.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&41u16.to_be_bytes());
        bytes.extend_from_slice(&udp_payload_size.to_be_bytes());
        bytes.push(0);
        bytes.push(0);
        let flags = if dnssec_ok { EDNS_DO_FLAG } else { 0 };
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes
    }

    fn a_query_without_rd(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        bytes[2..4].copy_from_slice(&0u16.to_be_bytes());
        bytes
    }

    /// Sets or clears the AA bit (0x0400) on an already-built response's
    /// wire bytes -- used to simulate an upstream backend response that
    /// claims to be an authoritative answer, since the shared response
    /// builders used elsewhere in these tests don't expose an `aa`
    /// parameter of their own.
    fn set_response_aa(mut bytes: Vec<u8>, aa: bool) -> Vec<u8> {
        let mut flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        if aa {
            flags |= 0x0400;
        } else {
            flags &= !0x0400;
        }
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        bytes
    }

    fn a_query_with_checking_disabled(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]) | 0x0010;
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        bytes
    }

    fn a_query_with_edns_and_checking_disabled(
        id: u16,
        name: &str,
        udp_payload_size: u16,
        dnssec_ok: bool,
    ) -> Vec<u8> {
        let mut bytes = a_query_with_edns(id, name, udp_payload_size, dnssec_ok);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]) | 0x0010;
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        bytes
    }

    fn aaaa_query(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        let qtype_offset = bytes.len() - 4;
        bytes[qtype_offset..qtype_offset + 2].copy_from_slice(&28u16.to_be_bytes());
        bytes
    }

    fn a_query_with_edns(id: u16, name: &str, udp_payload_size: u16, dnssec_ok: bool) -> Vec<u8> {
        a_query_with_edns_options(id, name, udp_payload_size, dnssec_ok, &[])
    }

    #[test]
    fn query_features_from_message_extracts_client_cookie() {
        let cookie_option = [
            0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let bytes = a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option);
        let message = Message::parse(&bytes).unwrap();

        let features = QueryFeatures::from_message(&message);

        assert_eq!(
            features.client_cookie,
            Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
        );
    }

    #[test]
    fn query_features_from_message_has_no_client_cookie_without_edns() {
        let bytes = a_query(0x7777, "example.com");
        let message = Message::parse(&bytes).unwrap();

        let features = QueryFeatures::from_message(&message);

        assert_eq!(features.client_cookie, None);
    }

    #[test]
    fn query_features_from_message_has_no_client_cookie_when_edns_options_empty() {
        let bytes = a_query_with_edns(0x7777, "example.com", 1232, false);
        let message = Message::parse(&bytes).unwrap();

        let features = QueryFeatures::from_message(&message);

        assert_eq!(features.client_cookie, None);
    }

    fn a_query_with_edns_options(
        id: u16,
        name: &str,
        udp_payload_size: u16,
        dnssec_ok: bool,
        options: &[u8],
    ) -> Vec<u8> {
        a_query_with_edns_details(id, name, udp_payload_size, dnssec_ok, 0, 0, options)
    }

    fn a_query_with_edns_details(
        id: u16,
        name: &str,
        udp_payload_size: u16,
        dnssec_ok: bool,
        extended_rcode: u8,
        version: u8,
        options: &[u8],
    ) -> Vec<u8> {
        a_query_with_edns_flags(
            id,
            name,
            udp_payload_size,
            dnssec_ok,
            extended_rcode,
            version,
            0,
            options,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn a_query_with_edns_flags(
        id: u16,
        name: &str,
        udp_payload_size: u16,
        dnssec_ok: bool,
        extended_rcode: u8,
        version: u8,
        extra_flags: u16,
        options: &[u8],
    ) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        bytes[10..12].copy_from_slice(&1u16.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&41u16.to_be_bytes());
        bytes.extend_from_slice(&udp_payload_size.to_be_bytes());
        bytes.push(extended_rcode);
        bytes.push(version);
        let flags = if dnssec_ok { EDNS_DO_FLAG } else { 0 } | extra_flags;
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&(options.len() as u16).to_be_bytes());
        bytes.extend_from_slice(options);
        bytes
    }

    struct FixedClock(SystemTime);

    /// A test clock whose `now` can be advanced mid-test — needed by the
    /// serve-stale end-to-end test, where `process_refresh_job`'s
    /// eligibility recheck runs against the *clock's* now (as production
    /// does), which must agree with the synthetic request timestamps that
    /// made the entry stale in the first place.
    struct SettableClock(Mutex<SystemTime>);

    impl SettableClock {
        fn new(start: SystemTime) -> Self {
            Self(Mutex::new(start))
        }

        fn set(&self, now: SystemTime) {
            *self.0.lock().unwrap() = now;
        }
    }

    impl Clock for SettableClock {
        fn now(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }
    }

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

    struct DisabledEvents;

    impl QueryEventSink for DisabledEvents {
        fn record(&self, _event: QueryEventV1) -> QueryEventRecordResult {
            QueryEventRecordResult::Disabled
        }
    }

    fn event_for(name: &str) -> QueryEventV1 {
        let decision = ResolveDecision {
            client_ip: "127.0.0.1".parse().unwrap(),
            question: Some(QuestionKey::new(name, 1, 1)),
            kind: ResolveDecisionKind::Allowed,
        };
        QueryEventV1::from_decision(0, None, SystemTime::UNIX_EPOCH, &decision, None, None, None)
    }

    fn event_with(sequence: u64, seconds: u64, source_ip: &str, name: &str) -> QueryEventV1 {
        event_with_response(
            sequence,
            seconds,
            source_ip,
            name,
            1,
            ResponseCode::NoError as u16,
        )
    }

    fn event_with_response(
        sequence: u64,
        seconds: u64,
        source_ip: &str,
        name: &str,
        qtype: u16,
        response_code: u16,
    ) -> QueryEventV1 {
        let decision = ResolveDecision {
            client_ip: source_ip.parse().unwrap(),
            question: Some(QuestionKey::new(name, qtype, 1)),
            kind: ResolveDecisionKind::Allowed,
        };
        QueryEventV1::from_decision(
            sequence,
            None,
            SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
            &decision,
            Some(response_code),
            Some(QueryEventCacheResult::Miss),
            Some(Duration::from_millis(1)),
        )
    }

    fn suspicious_event_with(
        sequence: u64,
        seconds: u64,
        source_ip: &str,
        name: &str,
        severity: QueryEventClassifierSeverity,
    ) -> QueryEventV1 {
        let mut event = event_with(sequence, seconds, source_ip, name);
        event.advisory_findings.push(QueryEventClassifierFinding {
            classifier_version: "test".to_string(),
            config_generation: 1,
            reason: QueryEventClassifierReason::HighEntropyName,
            severity,
            score: 80,
            evaluated_window: QueryEventClassifierWindow {
                started_at: SystemTime::UNIX_EPOCH,
                ended_at: event.timestamp,
                retained_event_count: 1,
                incomplete_reasons: Vec::new(),
            },
            details: vec![QueryEventClassifierDetail {
                key: "qname".to_string(),
                value: name.to_string(),
            }],
        });
        event
    }

    fn arc_events(events: &[QueryEventV1]) -> Vec<Arc<QueryEventV1>> {
        events.iter().cloned().map(Arc::new).collect()
    }

    fn classifier_window(
        retained_events: &[Arc<QueryEventV1>],
        incomplete_reasons: Vec<QueryEventClassifierWindowIncompleteReason>,
    ) -> QueryEventClassifierWindow {
        QueryEventClassifierWindow {
            started_at: retained_events
                .first()
                .map(|event| event.timestamp)
                .unwrap_or(SystemTime::UNIX_EPOCH),
            ended_at: retained_events
                .last()
                .map(|event| event.timestamp)
                .unwrap_or(SystemTime::UNIX_EPOCH),
            retained_event_count: retained_events.len(),
            incomplete_reasons,
        }
    }

    fn finding_reasons(
        classifier: &InMemorySuspiciousLookupClassifier,
        event: &QueryEventV1,
        retained_events: &[QueryEventV1],
    ) -> Vec<QueryEventClassifierReason> {
        let retained_events = arc_events(retained_events);
        classifier
            .classify(SuspiciousLookupClassifierInput {
                event,
                retained_events: &retained_events,
                window: classifier_window(&retained_events, Vec::new()),
            })
            .into_iter()
            .map(|finding| finding.reason)
            .collect()
    }

    fn detail_value<'a>(finding: &'a QueryEventClassifierFinding, key: &str) -> Option<&'a str> {
        finding
            .details
            .iter()
            .find(|detail| detail.key == key)
            .map(|detail| detail.value.as_str())
    }

    #[tokio::test]
    async fn channel_query_event_sink_enqueues_when_capacity_is_available() {
        let (tx, mut rx) = mpsc::channel(1);
        let sink = ChannelQueryEventSink::new(tx);

        let result = sink.record(event_for("accepted.example"));

        assert_eq!(result, QueryEventRecordResult::Accepted);
        let received = rx.recv().await.unwrap();
        assert_eq!(
            received.normalized_question.unwrap().qname,
            "accepted.example"
        );
    }

    #[tokio::test]
    async fn channel_query_event_sink_drops_promptly_when_full() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(event_for("existing.example")).unwrap();
        let sink = ChannelQueryEventSink::new(tx);

        let result = sink.record(event_for("dropped.example"));

        assert_eq!(result, QueryEventRecordResult::DroppedNewest);
        let received = rx.recv().await.unwrap();
        assert_eq!(
            received.normalized_question.unwrap().qname,
            "existing.example"
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn channel_query_event_sink_reports_disabled_when_closed() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let sink = ChannelQueryEventSink::new(tx);

        let result = sink.record(event_for("disabled.example"));

        assert_eq!(result, QueryEventRecordResult::Disabled);
    }

    #[test]
    fn in_memory_query_event_store_orders_and_bounds_recent_events() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 2,
            ..InMemoryQueryEventStoreConfig::default()
        });

        store.record(event_with(2, 2, "192.0.2.2", "second.example"));
        store.record(event_with(1, 1, "192.0.2.1", "first.example"));
        store.record(event_with(3, 3, "192.0.2.3", "third.example"));

        let events = store.recent_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 2);
        assert_eq!(events[1].sequence, 3);
        assert_eq!(store.summary().evicted_event_count, 1);
    }

    #[test]
    fn in_memory_query_event_store_applies_retention_duration() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 16,
            retention: Some(Duration::from_secs(10)),
            ..InMemoryQueryEventStoreConfig::default()
        });

        store.record(event_with(1, 0, "192.0.2.1", "old.example"));
        store.record(event_with(2, 5, "192.0.2.1", "kept.example"));
        store.record(event_with(3, 11, "192.0.2.1", "new.example"));

        let events = store.recent_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 2);
        assert_eq!(events[1].sequence, 3);
        assert_eq!(store.summary().evicted_event_count, 1);
    }

    #[test]
    fn in_memory_query_event_store_caps_source_and_domain_indexes() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 16,
            max_indexed_sources: 1,
            max_indexed_domains: 1,
            ..InMemoryQueryEventStoreConfig::default()
        });

        store.record(event_with(1, 1, "192.0.2.1", "first.example"));
        store.record(event_with(2, 2, "192.0.2.2", "second.example"));

        let summary = store.summary();
        assert_eq!(summary.retained_event_count, 2);
        assert_eq!(summary.indexed_source_count, 1);
        assert_eq!(summary.indexed_domain_count, 1);
        assert_eq!(summary.unindexed_source_event_count, 1);
        assert_eq!(summary.unindexed_domain_event_count, 1);
    }

    #[test]
    fn in_memory_query_event_store_releases_index_slots_after_eviction() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 1,
            max_indexed_sources: 1,
            max_indexed_domains: 1,
            ..InMemoryQueryEventStoreConfig::default()
        });

        store.record(event_with(1, 1, "192.0.2.1", "first.example"));
        store.record(event_with(2, 2, "192.0.2.2", "second.example"));

        let summary = store.summary();
        assert_eq!(summary.retained_event_count, 1);
        assert_eq!(summary.indexed_source_count, 1);
        assert_eq!(summary.indexed_domain_count, 1);
        assert_eq!(summary.unindexed_source_event_count, 0);
        assert_eq!(summary.unindexed_domain_event_count, 0);
        assert_eq!(store.recent_events()[0].sequence, 2);
    }

    #[test]
    fn in_memory_query_event_store_releases_unindexed_counts_after_eviction() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 1,
            max_indexed_sources: 0,
            max_indexed_domains: 0,
            ..InMemoryQueryEventStoreConfig::default()
        });

        store.record(event_with(1, 1, "192.0.2.1", "first.example"));
        store.record(event_with(2, 2, "192.0.2.2", "second.example"));

        let summary = store.summary();
        assert_eq!(summary.retained_event_count, 1);
        assert_eq!(summary.unindexed_source_event_count, 1);
        assert_eq!(summary.unindexed_domain_event_count, 1);
        assert_eq!(store.recent_events()[0].sequence, 2);
    }

    #[test]
    fn in_memory_query_event_store_evicts_unindexed_event_without_removing_later_indexed_key() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 3,
            max_indexed_sources: 1,
            max_indexed_domains: 1,
            ..InMemoryQueryEventStoreConfig::default()
        });

        store.record(event_with(1, 1, "192.0.2.1", "first.example"));
        store.record(event_with(2, 2, "192.0.2.2", "second.example"));
        store.record(event_with(3, 3, "192.0.2.3", "third.example"));
        store.record(event_with(4, 4, "192.0.2.2", "second.example"));
        store.record(event_with(5, 5, "192.0.2.4", "fourth.example"));

        let indexed_source = ObservedSourceEndpoint::ip("192.0.2.2".parse().unwrap());
        let state = store.state.lock().unwrap();
        assert_eq!(state.indexed_sources.get(&indexed_source), Some(&1));
        assert_eq!(state.indexed_domains.get("second.example"), Some(&1));
        assert_eq!(state.unindexed_source_event_count, 2);
        assert_eq!(state.unindexed_domain_event_count, 2);
    }

    #[test]
    fn query_event_context_preserves_observed_source_and_original_question() {
        let decision = ResolveDecision {
            client_ip: "192.0.2.10".parse().unwrap(),
            question: Some(QuestionKey::new("example.com", 1, 1)),
            kind: ResolveDecisionKind::Allowed,
        };
        let source: SocketAddr = "192.0.2.10:53000".parse().unwrap();

        let event = QueryEventV1::from_decision_context(
            1,
            Some(0xaaaa),
            SystemTime::UNIX_EPOCH,
            source.into(),
            Some("Example.COM.".to_string()),
            &decision,
            Some(ResponseCode::NoError as u16),
            Some(QueryEventCacheResult::Miss),
            Some(Duration::from_millis(1)),
        );

        assert_eq!(event.request_id, Some(0xaaaa));
        assert_eq!(event.observed_source.ip, decision.client_ip);
        assert_eq!(event.observed_source.port, Some(53000));
        assert_eq!(
            event.original_question_name.as_deref(),
            Some("Example.COM.")
        );
        assert_eq!(event.normalized_question.unwrap().qname, "example.com");
    }

    #[test]
    fn in_memory_query_event_store_tracks_dropped_and_sampled_indicators() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());

        store.record_outcome(QueryEventRecordResult::DroppedNewest);
        store.record_outcome(QueryEventRecordResult::DroppedOldest);
        store.record_outcome(QueryEventRecordResult::Sampled);
        store.record_outcome(QueryEventRecordResult::Accepted);

        let summary = store.summary();
        assert_eq!(summary.dropped_newest_event_count, 1);
        assert_eq!(summary.dropped_oldest_event_count, 1);
        assert_eq!(summary.sampled_event_count, 1);
    }

    #[test]
    fn in_memory_query_event_store_ignores_disabled_outcome_for_retention_state() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());

        store.record_outcome(QueryEventRecordResult::Disabled);

        assert_eq!(store.summary(), QueryEventStoreSummary::default());
    }

    #[test]
    fn query_event_read_model_limits_recent_source_and_domain_history() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());
        store.record(event_with(1, 1, "192.0.2.1", "first.example"));
        store.record(event_with(2, 2, "192.0.2.2", "other.example"));
        store.record(event_with(3, 3, "192.0.2.1", "second.example"));
        store.record(event_with(4, 4, "192.0.2.1", "second.example"));

        let source = ObservedSourceEndpoint::ip("192.0.2.1".parse().unwrap());
        let source_events = store.query_events_for_source(&source, 2);
        assert_eq!(
            source_events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );

        let domain_events = store.query_events_for_domain("Second.Example.", 8);
        assert_eq!(
            domain_events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );

        let recent_events = store.recent_query_events(2);
        assert_eq!(
            recent_events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn query_event_read_model_filters_suspicious_events() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());
        store.record(event_with(1, 1, "192.0.2.1", "allowed.example"));
        store.record(suspicious_event_with(
            2,
            2,
            "192.0.2.1",
            "first-bad.example",
            QueryEventClassifierSeverity::Low,
        ));
        store.record(suspicious_event_with(
            3,
            3,
            "192.0.2.2",
            "second-bad.example",
            QueryEventClassifierSeverity::High,
        ));

        let events = store.suspicious_query_events(8);
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn query_event_read_model_summarizes_suspicious_source() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());
        let source = ObservedSourceEndpoint::ip("192.0.2.1".parse().unwrap());
        store.record(event_with(1, 1, "192.0.2.1", "allowed.example"));
        store.record(suspicious_event_with(
            2,
            2,
            "192.0.2.1",
            "first-bad.example",
            QueryEventClassifierSeverity::Low,
        ));
        let mut high = suspicious_event_with(
            3,
            3,
            "192.0.2.1",
            "second-bad.example",
            QueryEventClassifierSeverity::High,
        );
        high.advisory_findings.push(QueryEventClassifierFinding {
            classifier_version: "test".to_string(),
            config_generation: 1,
            reason: QueryEventClassifierReason::SuspiciousSelector,
            severity: QueryEventClassifierSeverity::Medium,
            score: 70,
            evaluated_window: QueryEventClassifierWindow {
                started_at: SystemTime::UNIX_EPOCH,
                ended_at: high.timestamp,
                retained_event_count: 2,
                incomplete_reasons: Vec::new(),
            },
            details: Vec::new(),
        });
        store.record(high);

        let summary = store.suspicious_summary_for_source(&source);
        assert_eq!(summary.observed_source, source);
        assert_eq!(summary.suspicious_event_count, 2);
        assert_eq!(summary.finding_count, 3);
        assert_eq!(
            summary.highest_severity,
            Some(QueryEventClassifierSeverity::High)
        );
        assert_eq!(
            summary.last_seen,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(3))
        );
    }

    #[test]
    fn query_event_read_model_ranks_top_suspicious_sources_and_domains() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());
        store.record(suspicious_event_with(
            1,
            1,
            "192.0.2.1",
            "alpha.example",
            QueryEventClassifierSeverity::Low,
        ));
        store.record(suspicious_event_with(
            2,
            2,
            "192.0.2.2",
            "beta.example",
            QueryEventClassifierSeverity::High,
        ));
        store.record(suspicious_event_with(
            3,
            3,
            "192.0.2.2",
            "beta.example",
            QueryEventClassifierSeverity::Medium,
        ));

        let sources = store.top_suspicious_sources(1);
        assert_eq!(sources.len(), 1);
        assert_eq!(
            sources[0].observed_source,
            ObservedSourceEndpoint::ip("192.0.2.2".parse().unwrap())
        );
        assert_eq!(sources[0].suspicious_event_count, 2);
        assert_eq!(
            sources[0].highest_severity,
            Some(QueryEventClassifierSeverity::High)
        );

        let domains = store.top_suspicious_domains(2);
        assert_eq!(
            domains
                .iter()
                .map(|summary| summary.domain.as_str())
                .collect::<Vec<_>>(),
            vec!["beta.example", "alpha.example"]
        );
        assert_eq!(domains[0].suspicious_event_count, 2);
    }

    #[test]
    fn query_event_read_model_marks_incomplete_summaries() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 1,
            ..InMemoryQueryEventStoreConfig::default()
        });
        store.record(suspicious_event_with(
            1,
            1,
            "192.0.2.1",
            "old.example",
            QueryEventClassifierSeverity::Low,
        ));
        store.record(suspicious_event_with(
            2,
            2,
            "192.0.2.1",
            "new.example",
            QueryEventClassifierSeverity::High,
        ));
        store.record_outcome(QueryEventRecordResult::DroppedNewest);
        store.record_outcome(QueryEventRecordResult::Sampled);

        let source = ObservedSourceEndpoint::ip("192.0.2.1".parse().unwrap());
        let source_summary = store.suspicious_summary_for_source(&source);
        assert_eq!(source_summary.window.retained_event_count, 1);
        assert_eq!(
            source_summary.window.incomplete_reasons,
            vec![
                QueryEventReadModelIncompleteReason::RetentionEviction,
                QueryEventReadModelIncompleteReason::DroppedEvents,
                QueryEventReadModelIncompleteReason::SampledEvents,
            ]
        );

        let domain_summary = store.top_suspicious_domains(1).remove(0);
        assert_eq!(
            domain_summary.window.incomplete_reasons,
            source_summary.window.incomplete_reasons
        );
    }

    #[test]
    fn noop_suspicious_lookup_classifier_is_advisory_scaffolding() {
        let classifier = NoopSuspiciousLookupClassifier::new("noop-test", 7);
        let event = event_with(1, 1, "192.0.2.1", "allowed.example");
        let retained_events = vec![event.clone()];
        let retained_event_refs = arc_events(&retained_events);
        let window = QueryEventClassifierWindow {
            started_at: SystemTime::UNIX_EPOCH,
            ended_at: event.timestamp,
            retained_event_count: retained_events.len(),
            incomplete_reasons: vec![QueryEventClassifierWindowIncompleteReason::ColdStart],
        };

        let findings = classifier.classify(SuspiciousLookupClassifierInput {
            event: &event,
            retained_events: &retained_event_refs,
            window,
        });

        assert!(findings.is_empty());
        assert_eq!(classifier.classifier_version, "noop-test");
        assert_eq!(classifier.config_generation, 7);
    }

    #[test]
    fn suspicious_lookup_classifier_flags_response_code_bursts() {
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                nxdomain_burst_threshold: 3,
                servfail_burst_threshold: 2,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        let retained_events = vec![
            event_with_response(
                1,
                1,
                "192.0.2.1",
                "one.example",
                1,
                ResponseCode::NxDomain as u16,
            ),
            event_with_response(
                2,
                2,
                "192.0.2.1",
                "two.example",
                1,
                ResponseCode::NxDomain as u16,
            ),
            event_with_response(
                3,
                3,
                "192.0.2.1",
                "three.example",
                1,
                ResponseCode::NxDomain as u16,
            ),
            event_with_response(
                4,
                4,
                "192.0.2.2",
                "other.example",
                1,
                ResponseCode::NxDomain as u16,
            ),
        ];

        let reasons = finding_reasons(&classifier, &retained_events[2], &retained_events);

        assert!(reasons.contains(&QueryEventClassifierReason::NxdomainBurst));

        let retained_events = vec![
            event_with_response(
                1,
                1,
                "192.0.2.1",
                "one.example",
                1,
                ResponseCode::ServFail as u16,
            ),
            event_with_response(
                2,
                2,
                "192.0.2.1",
                "two.example",
                1,
                ResponseCode::ServFail as u16,
            ),
        ];
        let reasons = finding_reasons(&classifier, &retained_events[1], &retained_events);

        assert!(reasons.contains(&QueryEventClassifierReason::ServfailBurst));
    }

    #[test]
    fn suspicious_lookup_classifier_respects_threshold_boundaries() {
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                nxdomain_burst_threshold: 3,
                servfail_burst_threshold: 2,
                repeated_txt_threshold: 3,
                high_entropy_min_label_len: 8,
                high_entropy_score_threshold: 60,
                rare_domain_threshold: 2,
                enable_domain_frequency_findings: true,
                baseline_complete_after_events: 1,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });

        let below_nxdomain = vec![
            event_with_response(
                1,
                1,
                "192.0.2.1",
                "one.example",
                1,
                ResponseCode::NxDomain as u16,
            ),
            event_with_response(
                2,
                2,
                "192.0.2.1",
                "two.example",
                1,
                ResponseCode::NxDomain as u16,
            ),
        ];
        let at_nxdomain = vec![
            below_nxdomain[0].clone(),
            below_nxdomain[1].clone(),
            event_with_response(
                3,
                3,
                "192.0.2.1",
                "three.example",
                1,
                ResponseCode::NxDomain as u16,
            ),
        ];

        assert!(
            !finding_reasons(&classifier, &below_nxdomain[1], &below_nxdomain)
                .contains(&QueryEventClassifierReason::NxdomainBurst)
        );
        assert!(
            finding_reasons(&classifier, &at_nxdomain[2], &at_nxdomain)
                .contains(&QueryEventClassifierReason::NxdomainBurst)
        );

        let below_servfail = vec![event_with_response(
            4,
            4,
            "192.0.2.1",
            "one.example",
            1,
            ResponseCode::ServFail as u16,
        )];
        let at_servfail = vec![
            below_servfail[0].clone(),
            event_with_response(
                5,
                5,
                "192.0.2.1",
                "two.example",
                1,
                ResponseCode::ServFail as u16,
            ),
        ];

        assert!(
            !finding_reasons(&classifier, &below_servfail[0], &below_servfail)
                .contains(&QueryEventClassifierReason::ServfailBurst)
        );
        assert!(
            finding_reasons(&classifier, &at_servfail[1], &at_servfail)
                .contains(&QueryEventClassifierReason::ServfailBurst)
        );

        let below_txt = vec![
            event_with_response(
                6,
                6,
                "192.0.2.1",
                "one.example",
                16,
                ResponseCode::NoError as u16,
            ),
            event_with_response(
                7,
                7,
                "192.0.2.1",
                "two.example",
                16,
                ResponseCode::NoError as u16,
            ),
        ];
        let at_txt = vec![
            below_txt[0].clone(),
            below_txt[1].clone(),
            event_with_response(
                8,
                8,
                "192.0.2.1",
                "three.example",
                16,
                ResponseCode::NoError as u16,
            ),
        ];

        assert!(
            !finding_reasons(&classifier, &below_txt[1], &below_txt)
                .contains(&QueryEventClassifierReason::RepeatedTxtLookup)
        );
        assert!(
            finding_reasons(&classifier, &at_txt[2], &at_txt)
                .contains(&QueryEventClassifierReason::RepeatedTxtLookup)
        );

        let short_entropy = vec![event_with(9, 9, "192.0.2.1", "a9x4qz7.example")];
        let long_entropy = vec![event_with(10, 10, "192.0.2.1", "a9x4qz7m.example")];
        assert!(
            !finding_reasons(&classifier, &short_entropy[0], &short_entropy)
                .contains(&QueryEventClassifierReason::HighEntropyName)
        );
        assert!(
            finding_reasons(&classifier, &long_entropy[0], &long_entropy)
                .contains(&QueryEventClassifierReason::HighEntropyName)
        );

        let rare_at_threshold = vec![
            event_with(11, 11, "192.0.2.1", "rare.example"),
            event_with(12, 12, "192.0.2.2", "rare.example"),
        ];
        let rare_above_threshold = vec![
            rare_at_threshold[0].clone(),
            rare_at_threshold[1].clone(),
            event_with(13, 13, "192.0.2.3", "rare.example"),
        ];
        assert!(
            finding_reasons(&classifier, &rare_at_threshold[1], &rare_at_threshold)
                .contains(&QueryEventClassifierReason::RareDomain)
        );
        assert!(
            !finding_reasons(&classifier, &rare_above_threshold[2], &rare_above_threshold)
                .contains(&QueryEventClassifierReason::RareDomain)
        );
    }

    #[test]
    fn suspicious_lookup_classifier_records_explanatory_finding_details() {
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                classifier_version: "test-classifier".to_string(),
                config_generation: 42,
                repeated_txt_threshold: 2,
                repeated_txt_window: Duration::from_secs(60),
                high_entropy_min_label_len: 8,
                high_entropy_score_threshold: 60,
                suspicious_domains: vec!["blocked.example".to_string()],
                baseline_complete_after_events: 1,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        let retained_events = vec![
            event_with_response(
                1,
                1,
                "192.0.2.1",
                "txt-one.example",
                16,
                ResponseCode::NoError as u16,
            ),
            event_with_response(
                2,
                2,
                "192.0.2.1",
                "a9x4qz7m2p8v.blocked.example",
                16,
                ResponseCode::NoError as u16,
            ),
        ];
        let retained_event_refs = arc_events(&retained_events);

        let findings = classifier.classify(SuspiciousLookupClassifierInput {
            event: &retained_events[1],
            retained_events: &retained_event_refs,
            window: classifier_window(
                &retained_event_refs,
                vec![QueryEventClassifierWindowIncompleteReason::SampledEvents],
            ),
        });

        let txt = findings
            .iter()
            .find(|finding| finding.reason == QueryEventClassifierReason::RepeatedTxtLookup)
            .unwrap();
        assert_eq!(txt.classifier_version, "test-classifier");
        assert_eq!(txt.config_generation, 42);
        assert_eq!(txt.score, 55);
        assert_eq!(detail_value(txt, "source_txt_count"), Some("2"));
        assert_eq!(detail_value(txt, "threshold"), Some("2"));
        assert_eq!(
            detail_value(txt, "window_incomplete_reason"),
            Some("sampled_events")
        );

        let entropy = findings
            .iter()
            .find(|finding| finding.reason == QueryEventClassifierReason::HighEntropyName)
            .unwrap();
        assert_eq!(detail_value(entropy, "label"), Some("a9x4qz7m2p8v"));
        assert_eq!(detail_value(entropy, "threshold"), Some("60"));

        let selector = findings
            .iter()
            .find(|finding| finding.reason == QueryEventClassifierReason::SuspiciousSelector)
            .unwrap();
        assert_eq!(selector.severity, QueryEventClassifierSeverity::High);
        assert_eq!(selector.score, 90);
        assert_eq!(detail_value(selector, "selector"), Some("blocked.example"));
    }

    #[test]
    fn suspicious_lookup_classifier_ignores_stale_burst_events() {
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                nxdomain_burst_threshold: 3,
                repeated_txt_threshold: 3,
                burst_window: Duration::from_secs(10),
                repeated_txt_window: Duration::from_secs(10),
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        let retained_events = vec![
            event_with_response(
                1,
                1,
                "192.0.2.1",
                "old-one.example",
                1,
                ResponseCode::NxDomain as u16,
            ),
            event_with_response(
                2,
                2,
                "192.0.2.1",
                "old-two.example",
                16,
                ResponseCode::NxDomain as u16,
            ),
            event_with_response(
                3,
                3,
                "192.0.2.1",
                "old-three.example",
                16,
                ResponseCode::NxDomain as u16,
            ),
            event_with_response(
                4,
                30,
                "192.0.2.1",
                "current.example",
                16,
                ResponseCode::NxDomain as u16,
            ),
        ];

        let reasons = finding_reasons(&classifier, &retained_events[3], &retained_events);

        assert!(!reasons.contains(&QueryEventClassifierReason::NxdomainBurst));
        assert!(!reasons.contains(&QueryEventClassifierReason::RepeatedTxtLookup));
    }

    #[test]
    fn suspicious_lookup_classifier_flags_txt_entropy_and_selectors() {
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                repeated_txt_threshold: 2,
                high_entropy_min_label_len: 8,
                high_entropy_score_threshold: 60,
                suspicious_tlds: vec!["bad".to_string()],
                suspicious_domains: vec!["blocked.example".to_string()],
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        let retained_events = vec![
            event_with_response(
                1,
                1,
                "192.0.2.1",
                "txt-one.example",
                16,
                ResponseCode::NoError as u16,
            ),
            event_with_response(
                2,
                2,
                "192.0.2.1",
                "a9x4qz7m2p8v.blocked.example",
                16,
                ResponseCode::NoError as u16,
            ),
        ];

        let reasons = finding_reasons(&classifier, &retained_events[1], &retained_events);

        assert!(reasons.contains(&QueryEventClassifierReason::RepeatedTxtLookup));
        assert!(reasons.contains(&QueryEventClassifierReason::HighEntropyName));
        assert!(reasons.contains(&QueryEventClassifierReason::SuspiciousSelector));

        let tld_event = event_with(3, 3, "192.0.2.1", "selector.bad");
        let retained_events = vec![tld_event];
        let reasons = finding_reasons(&classifier, &retained_events[0], &retained_events);

        assert!(reasons.contains(&QueryEventClassifierReason::SuspiciousSelector));

        let dotted_domain_classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                high_entropy_score_threshold: 100,
                suspicious_domains: vec![".blocked.example".to_string()],
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        let domain_event = event_with(4, 4, "192.0.2.1", "selector.blocked.example");
        let retained_events = vec![domain_event];
        let reasons = finding_reasons(
            &dotted_domain_classifier,
            &retained_events[0],
            &retained_events,
        );

        assert!(reasons.contains(&QueryEventClassifierReason::SuspiciousSelector));
    }

    #[test]
    fn suspicious_lookup_classifier_flags_new_and_rare_domains() {
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                rare_domain_threshold: 2,
                enable_domain_frequency_findings: true,
                high_entropy_score_threshold: 100,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        let new_domain = event_with(1, 1, "192.0.2.1", "new.example");
        let retained_events = vec![new_domain];
        let reasons = finding_reasons(&classifier, &retained_events[0], &retained_events);
        assert!(reasons.contains(&QueryEventClassifierReason::NewDomain));

        let retained_events = vec![
            event_with(1, 1, "192.0.2.1", "rare.example"),
            event_with(2, 2, "192.0.2.2", "rare.example"),
        ];
        let reasons = finding_reasons(&classifier, &retained_events[1], &retained_events);
        assert!(reasons.contains(&QueryEventClassifierReason::RareDomain));
    }

    #[test]
    fn suspicious_lookup_classifier_marks_incomplete_windows() {
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                suspicious_domains: vec!["blocked.example".to_string()],
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        let event = event_with(1, 1, "192.0.2.1", "blocked.example");
        let retained_events = vec![event.clone()];
        let retained_event_refs = arc_events(&retained_events);

        let findings = classifier.classify(SuspiciousLookupClassifierInput {
            event: &event,
            retained_events: &retained_event_refs,
            window: classifier_window(
                &retained_event_refs,
                vec![
                    QueryEventClassifierWindowIncompleteReason::RetentionEviction,
                    QueryEventClassifierWindowIncompleteReason::DroppedEvents,
                ],
            ),
        });

        let incomplete_reasons = findings
            .iter()
            .flat_map(|finding| finding.details.iter())
            .filter(|detail| detail.key == "window_incomplete_reason")
            .map(|detail| detail.value.as_str())
            .collect::<Vec<_>>();
        assert!(incomplete_reasons.contains(&"retention_eviction"));
        assert!(incomplete_reasons.contains(&"dropped_events"));
    }

    #[test]
    fn suspicious_lookup_classifier_marks_baseline_findings_cold_until_horizon() {
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                repeated_txt_threshold: 2,
                repeated_txt_window: Duration::from_secs(60),
                baseline_complete_after_events: 3,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        let retained_events = vec![
            event_with_response(
                1,
                1,
                "192.0.2.1",
                "first.example",
                16,
                ResponseCode::NoError as u16,
            ),
            event_with_response(
                2,
                2,
                "192.0.2.1",
                "second.example",
                16,
                ResponseCode::NoError as u16,
            ),
        ];
        let retained_event_refs = arc_events(&retained_events);

        let findings = classifier.classify(SuspiciousLookupClassifierInput {
            event: &retained_events[1],
            retained_events: &retained_event_refs,
            window: classifier_window(&retained_event_refs, Vec::new()),
        });

        let txt_finding = findings
            .iter()
            .find(|finding| finding.reason == QueryEventClassifierReason::RepeatedTxtLookup)
            .unwrap();
        assert!(
            txt_finding
                .evaluated_window
                .incomplete_reasons
                .contains(&QueryEventClassifierWindowIncompleteReason::ColdStart)
        );
        assert!(txt_finding.details.iter().any(|detail| {
            detail.key == "window_incomplete_reason" && detail.value == "cold_start"
        }));
    }

    #[test]
    fn record_classified_marks_event_that_triggers_retention_eviction() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 2,
            ..InMemoryQueryEventStoreConfig::default()
        });
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                repeated_txt_threshold: 2,
                repeated_txt_window: Duration::from_secs(60),
                baseline_complete_after_events: 1,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        store.record_classified(
            event_with_response(
                1,
                1,
                "192.0.2.1",
                "one.example",
                16,
                ResponseCode::NoError as u16,
            ),
            &classifier,
        );
        store.record_classified(
            event_with_response(
                2,
                2,
                "192.0.2.1",
                "two.example",
                16,
                ResponseCode::NoError as u16,
            ),
            &classifier,
        );

        let event = store.record_classified(
            event_with_response(
                3,
                3,
                "192.0.2.1",
                "three.example",
                16,
                ResponseCode::NoError as u16,
            ),
            &classifier,
        );

        let txt_finding = event
            .advisory_findings
            .iter()
            .find(|finding| finding.reason == QueryEventClassifierReason::RepeatedTxtLookup)
            .unwrap();
        assert!(
            txt_finding
                .evaluated_window
                .incomplete_reasons
                .contains(&QueryEventClassifierWindowIncompleteReason::RetentionEviction)
        );
    }

    #[test]
    fn record_classified_includes_current_event_when_store_retains_none() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 0,
            ..InMemoryQueryEventStoreConfig::default()
        });
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                high_entropy_min_label_len: 8,
                high_entropy_score_threshold: 60,
                baseline_complete_after_events: 1,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });

        let event = store.record_classified(
            event_with(1, 10, "192.0.2.1", "a9x4qz7m2p8v.example"),
            &classifier,
        );

        let finding = event
            .advisory_findings
            .iter()
            .find(|finding| finding.reason == QueryEventClassifierReason::HighEntropyName)
            .unwrap();
        assert_eq!(
            finding.evaluated_window.started_at,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10)
        );
        assert_eq!(
            finding.evaluated_window.ended_at,
            SystemTime::UNIX_EPOCH + Duration::from_secs(10)
        );
        assert_eq!(finding.evaluated_window.retained_event_count, 1);
        assert_eq!(store.recent_events().len(), 0);
    }

    struct ReentrantReadClassifier {
        store: Arc<InMemoryQueryEventStore>,
        visible_recent_during_classify: Mutex<usize>,
        visible_summary_during_classify: Mutex<usize>,
        visible_summary_window_during_classify: Mutex<usize>,
    }

    impl SuspiciousLookupClassifier for ReentrantReadClassifier {
        fn classify(
            &self,
            input: SuspiciousLookupClassifierInput<'_>,
        ) -> Vec<QueryEventClassifierFinding> {
            *self.visible_recent_during_classify.lock().unwrap() = self.store.recent_events().len();
            *self.visible_summary_during_classify.lock().unwrap() =
                self.store.summary().retained_event_count;
            *self.visible_summary_window_during_classify.lock().unwrap() = self
                .store
                .suspicious_summary_for_source(&input.event.observed_source)
                .window
                .retained_event_count;
            vec![QueryEventClassifierFinding {
                classifier_version: "reentrant-test".to_string(),
                config_generation: 1,
                reason: QueryEventClassifierReason::SuspiciousSelector,
                severity: QueryEventClassifierSeverity::Low,
                score: 1,
                evaluated_window: input.window.clone(),
                details: Vec::new(),
            }]
        }
    }

    #[test]
    fn record_classified_hides_pending_event_during_reentrant_read() {
        let store = Arc::new(InMemoryQueryEventStore::new(
            InMemoryQueryEventStoreConfig::default(),
        ));
        let classifier = ReentrantReadClassifier {
            store: Arc::clone(&store),
            visible_recent_during_classify: Mutex::new(usize::MAX),
            visible_summary_during_classify: Mutex::new(usize::MAX),
            visible_summary_window_during_classify: Mutex::new(usize::MAX),
        };

        store.record_classified(
            event_with(1, 1, "192.0.2.1", "pending.example"),
            &classifier,
        );

        assert_eq!(
            *classifier.visible_recent_during_classify.lock().unwrap(),
            0
        );
        assert_eq!(
            *classifier.visible_summary_during_classify.lock().unwrap(),
            0
        );
        assert_eq!(
            *classifier
                .visible_summary_window_during_classify
                .lock()
                .unwrap(),
            0
        );
        assert_eq!(store.recent_events().len(), 1);
        assert_eq!(store.suspicious_query_events(8).len(), 1);
    }

    struct BlockingFirstClassifier {
        inner: InMemorySuspiciousLookupClassifier,
        first_entered: Mutex<Option<std_mpsc::Sender<()>>>,
        release_first: Mutex<std_mpsc::Receiver<()>>,
    }

    impl SuspiciousLookupClassifier for BlockingFirstClassifier {
        fn classify(
            &self,
            input: SuspiciousLookupClassifierInput<'_>,
        ) -> Vec<QueryEventClassifierFinding> {
            if input.event.sequence == 1 {
                if let Some(first_entered) = self.first_entered.lock().unwrap().take() {
                    first_entered.send(()).unwrap();
                }
                self.release_first.lock().unwrap().recv().unwrap();
            }
            self.inner.classify(input)
        }
    }

    #[test]
    fn record_classified_serializes_snapshot_and_storage() {
        let store = Arc::new(InMemoryQueryEventStore::new(
            InMemoryQueryEventStoreConfig::default(),
        ));
        let (first_entered_tx, first_entered_rx) = std_mpsc::channel();
        let (release_first_tx, release_first_rx) = std_mpsc::channel();
        let classifier = Arc::new(BlockingFirstClassifier {
            inner: InMemorySuspiciousLookupClassifier::new(
                InMemorySuspiciousLookupClassifierConfig {
                    repeated_txt_threshold: 2,
                    repeated_txt_window: Duration::from_secs(60),
                    baseline_complete_after_events: 1,
                    ..InMemorySuspiciousLookupClassifierConfig::default()
                },
            ),
            first_entered: Mutex::new(Some(first_entered_tx)),
            release_first: Mutex::new(release_first_rx),
        });

        let first_store = Arc::clone(&store);
        let first_classifier = Arc::clone(&classifier);
        let first = thread::spawn(move || {
            first_store.record_classified(
                event_with_response(
                    1,
                    1,
                    "192.0.2.1",
                    "one.example",
                    16,
                    ResponseCode::NoError as u16,
                ),
                first_classifier.as_ref(),
            )
        });

        first_entered_rx.recv().unwrap();

        let (second_attempting_tx, second_attempting_rx) = std_mpsc::channel();
        let (second_acquired_tx, second_acquired_rx) = std_mpsc::channel();
        let second_store = Arc::clone(&store);
        let second_classifier = Arc::clone(&classifier);
        let second = thread::spawn(move || {
            second_store.record_classified_with_lock_hooks(
                event_with_response(
                    2,
                    2,
                    "192.0.2.1",
                    "two.example",
                    16,
                    ResponseCode::NoError as u16,
                ),
                second_classifier.as_ref(),
                || second_attempting_tx.send(()).unwrap(),
                || second_acquired_tx.send(()).unwrap(),
            )
        });

        second_attempting_rx.recv().unwrap();
        assert!(second_acquired_rx.try_recv().is_err());
        release_first_tx.send(()).unwrap();
        second_acquired_rx.recv().unwrap();

        let _first_event = first.join().unwrap();
        let second_event = second.join().unwrap();
        assert!(
            second_event
                .advisory_findings
                .iter()
                .any(|finding| finding.reason == QueryEventClassifierReason::RepeatedTxtLookup)
        );
    }

    #[test]
    fn record_classified_ignores_future_events_for_out_of_order_insert() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                enable_domain_frequency_findings: true,
                baseline_complete_after_events: 1,
                high_entropy_score_threshold: 100,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });
        store.record_classified(event_with(2, 20, "192.0.2.1", "same.example"), &classifier);

        let event =
            store.record_classified(event_with(1, 10, "192.0.2.1", "same.example"), &classifier);

        assert!(
            event
                .advisory_findings
                .iter()
                .any(|finding| finding.reason == QueryEventClassifierReason::NewDomain)
        );
        assert!(
            !event
                .advisory_findings
                .iter()
                .any(|finding| finding.reason == QueryEventClassifierReason::RareDomain)
        );
    }

    #[test]
    fn record_classified_marks_out_of_order_event_evicted_by_retention() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig {
            max_retained_events: 16,
            retention: Some(Duration::from_secs(10)),
            ..InMemoryQueryEventStoreConfig::default()
        });
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                high_entropy_min_label_len: 8,
                high_entropy_score_threshold: 60,
                baseline_complete_after_events: 1,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });

        store.record_classified(event_with(2, 20, "192.0.2.1", "newer.example"), &classifier);

        let event = store.record_classified(
            event_with(1, 5, "192.0.2.1", "a9x4qz7m2p8v.example"),
            &classifier,
        );

        let finding = event
            .advisory_findings
            .iter()
            .find(|finding| finding.reason == QueryEventClassifierReason::HighEntropyName)
            .unwrap();
        assert!(
            finding
                .evaluated_window
                .incomplete_reasons
                .contains(&QueryEventClassifierWindowIncompleteReason::RetentionEviction)
        );
        let retained = store.recent_events();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].sequence, 2);
    }

    #[derive(Default)]
    struct RecordingMetrics {
        increments: Mutex<Vec<ResolverMetric>>,
        durations: Mutex<Vec<(ResolverMetric, Duration)>>,
        backend_statuses: Mutex<Vec<BackendStatus>>,
        source_increments: Mutex<Vec<(ResolverMetric, IpAddr)>>,
        source_durations: Mutex<Vec<(ResolverMetric, IpAddr)>>,
    }

    impl MetricsSink for RecordingMetrics {
        fn increment(&self, metric: ResolverMetric) {
            self.increments.lock().unwrap().push(metric);
        }

        fn observe_duration(&self, metric: ResolverMetric, duration: Duration) {
            self.durations.lock().unwrap().push((metric, duration));
        }

        fn record_backend_status(&self, status: &BackendStatus) {
            self.backend_statuses.lock().unwrap().push(status.clone());
        }

        // The `*_with_source` overrides also feed the unlabeled vectors so
        // `count`/`duration_count` keep seeing every emission regardless of
        // which variant the resolver used — mirroring how a real sink's
        // labeled series still roll up into the same metric family.
        fn increment_with_source(&self, metric: ResolverMetric, source_ip: IpAddr) {
            self.source_increments
                .lock()
                .unwrap()
                .push((metric, source_ip));
            self.increment(metric);
        }

        fn observe_duration_with_source(
            &self,
            metric: ResolverMetric,
            duration: Duration,
            source_ip: IpAddr,
        ) {
            self.source_durations
                .lock()
                .unwrap()
                .push((metric, source_ip));
            self.observe_duration(metric, duration);
        }
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

        fn duration_count(&self, metric: ResolverMetric) -> usize {
            self.durations
                .lock()
                .unwrap()
                .iter()
                .filter(|(observed, _)| *observed == metric)
                .count()
        }
    }

    // Job enqueue tests: section-04-chainlookup-plumbing.

    fn resolver_for_enqueue_tests(metrics: Arc<RecordingMetrics>) -> ResolveQuery {
        ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout))),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            metrics,
        )
    }

    fn test_refresh_hint(domain: &str) -> cache::RefreshHint {
        cache::RefreshHint {
            domain: domain.to_string(),
            qtype: 1,
            qclass: 1,
        }
    }

    /// Per-client-query metrics reach the sink through the `*_with_source`
    /// variants carrying the requesting client's IP, so a labeling sink
    /// (like main.rs's OpenTelemetry one) can attribute traffic to where
    /// it came from. Asserts both that the expected metrics arrive with
    /// the IP and that no per-query emission ever carries a different one.
    #[tokio::test]
    async fn per_query_metrics_carry_client_source_ip() {
        let metrics = Arc::new(RecordingMetrics::default());
        let resolver = resolver_for_enqueue_tests(metrics.clone());
        let client_ip: IpAddr = "192.0.2.77".parse().unwrap();

        // Upstream is a hardwired timeout, so this exercises the full miss
        // path: received -> cache miss -> upstream failure -> durations.
        resolver
            .resolve(ResolveRequest::new(
                client_ip,
                SystemTime::UNIX_EPOCH,
                a_query(7, "example.com"),
            ))
            .await;

        let source_increments = metrics.source_increments.lock().unwrap().clone();
        for expected in [ResolverMetric::QueryReceived, ResolverMetric::CacheMiss] {
            assert!(
                source_increments.contains(&(expected, client_ip)),
                "{expected:?} should be recorded with the client source ip, got {source_increments:?}"
            );
        }
        for (metric, ip) in &source_increments {
            assert_eq!(
                *ip, client_ip,
                "{metric:?} was recorded with a source ip other than the requesting client's"
            );
        }
        // Upstream fetch metrics stay unlabeled: single-flight coalescing
        // shares one fetch across clients, so attributing it to a single
        // source IP would be race-dependent.
        assert_eq!(metrics.count(ResolverMetric::UpstreamFailure), 1);
        assert!(
            !source_increments
                .iter()
                .any(|(metric, _)| *metric == ResolverMetric::UpstreamFailure),
            "UpstreamFailure must not carry a source ip label"
        );

        let source_durations = metrics.source_durations.lock().unwrap().clone();
        for expected in [
            ResolverMetric::QueryDuration,
            ResolverMetric::CacheMissQueryDuration,
        ] {
            assert!(
                source_durations.contains(&(expected, client_ip)),
                "{expected:?} should be observed with the client source ip, got {source_durations:?}"
            );
        }
    }

    #[tokio::test]
    async fn enqueue_try_send_succeeds_under_capacity() {
        let metrics = Arc::new(RecordingMetrics::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let resolver = resolver_for_enqueue_tests(metrics.clone()).with_refresh_sender(sender);

        resolver.enqueue_refresh_job(test_refresh_hint("hot.example.com"));

        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 1);
        assert_eq!(metrics.count(ResolverMetric::RefreshQueueFull), 0);
        let job = receiver.try_recv().expect("job should be enqueued");
        assert_eq!(job.domain, "hot.example.com");
    }

    #[tokio::test]
    async fn enqueue_drops_and_counts_on_full_channel() {
        let metrics = Arc::new(RecordingMetrics::default());
        // Capacity 1, pre-filled, so the next try_send is guaranteed to see
        // a full channel.
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send(RefreshJob {
                domain: "already-queued.example.com".to_string(),
                qtype: 1,
                qclass: 1,
            })
            .unwrap();
        let resolver = resolver_for_enqueue_tests(metrics.clone()).with_refresh_sender(sender);

        resolver.enqueue_refresh_job(test_refresh_hint("dropped.example.com"));

        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 0);
        assert_eq!(metrics.count(ResolverMetric::RefreshQueueFull), 1);
        // The channel still only has the pre-filled job -- the dropped one
        // never made it in, and nothing panicked or blocked.
        let job = receiver.try_recv().expect("pre-filled job still present");
        assert_eq!(job.domain, "already-queued.example.com");
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn enqueue_per_hint_independent() {
        let metrics = Arc::new(RecordingMetrics::default());
        // Capacity 1, pre-filled, so exactly one of the two hints below
        // finds room and the other is dropped -- independently.
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let resolver = resolver_for_enqueue_tests(metrics.clone()).with_refresh_sender(sender);

        resolver.enqueue_refresh_job(test_refresh_hint("first.example.com"));
        resolver.enqueue_refresh_job(test_refresh_hint("second.example.com"));

        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 1);
        assert_eq!(metrics.count(ResolverMetric::RefreshQueueFull), 1);
        let job = receiver
            .try_recv()
            .expect("first hint should have been enqueued");
        assert_eq!(job.domain, "first.example.com");
    }

    // Worker pool tests: section-05-worker-pool-metrics.
    //
    // `process_refresh_job` is a fixed no-op stub in this section (real
    // behavior lands in section-06). Rather than a hand-rolled lookalike of
    // `refresh_worker_loop`, these tests drive the *real*
    // `spawn_refresh_worker_pool`/`refresh_worker_loop`/`process_refresh_job`
    // via the `TEST_JOB_HANDLER` thread-local seam, so a real bug in the
    // production dequeue/spawn/await/panic-isolation path would actually be
    // caught here.

    fn test_job(domain: &str) -> RefreshJob {
        RefreshJob {
            domain: domain.to_string(),
            qtype: 1,
            qclass: 1,
        }
    }

    fn resolver_for_worker_pool_tests() -> Arc<ResolveQuery> {
        Arc::new(resolver_for_enqueue_tests(Arc::new(
            RecordingMetrics::default(),
        )))
    }

    #[tokio::test]
    async fn worker_processes_jobs_sequentially_per_worker() {
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let gate = Arc::new(Notify::new());
        let gate_for_handler = Arc::clone(&gate);
        set_test_job_handler(std::sync::Arc::new(move |job: RefreshJob| {
            let events_tx = events_tx.clone();
            let gate = Arc::clone(&gate_for_handler);
            Box::pin(async move {
                events_tx.send(format!("start:{}", job.domain)).unwrap();
                if job.domain == "first" {
                    gate.notified().await;
                }
                events_tx.send(format!("done:{}", job.domain)).unwrap();
            })
        }));

        let (sender, receiver) = mpsc::channel(4);
        sender.try_send(test_job("first")).unwrap();
        sender.try_send(test_job("second")).unwrap();
        drop(sender); // lets the loop exit once both jobs are drained

        let handles = spawn_refresh_worker_pool(resolver_for_worker_pool_tests(), receiver, 1);

        assert_eq!(events_rx.recv().await.unwrap(), "start:first");
        // "second" must not start until "first"'s spawned task has been
        // awaited to completion -- a single worker dequeues sequentially.
        assert!(events_rx.try_recv().is_err());

        gate.notify_one();
        assert_eq!(events_rx.recv().await.unwrap(), "done:first");
        assert_eq!(events_rx.recv().await.unwrap(), "start:second");
        assert_eq!(events_rx.recv().await.unwrap(), "done:second");

        for handle in handles {
            handle.await.unwrap();
        }
        // TEST_JOB_HANDLER is thread-local, and the test harness can reuse
        // this OS thread for a later test -- clear it so this stub doesn't
        // leak into whatever runs next on this thread.
        clear_test_job_handler();
    }

    #[tokio::test]
    async fn worker_panic_isolated_via_joinhandle() {
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        set_test_job_handler(std::sync::Arc::new(move |job: RefreshJob| {
            let events_tx = events_tx.clone();
            Box::pin(async move {
                events_tx.send(format!("start:{}", job.domain)).unwrap();
                if job.domain == "boom" {
                    panic!("simulated job panic");
                }
                events_tx.send(format!("done:{}", job.domain)).unwrap();
            })
        }));

        let (sender, receiver) = mpsc::channel(4);
        sender.try_send(test_job("boom")).unwrap();
        sender.try_send(test_job("safe")).unwrap();
        drop(sender);

        let handles = spawn_refresh_worker_pool(resolver_for_worker_pool_tests(), receiver, 1);

        assert_eq!(events_rx.recv().await.unwrap(), "start:boom");
        // The real worker loop must survive "boom"'s panic (isolated to its
        // own spawned task/JoinHandle) and go on to dequeue "safe".
        assert_eq!(events_rx.recv().await.unwrap(), "start:safe");
        assert_eq!(events_rx.recv().await.unwrap(), "done:safe");

        for handle in handles {
            handle.await.unwrap();
        }
        clear_test_job_handler();
    }

    #[tokio::test]
    async fn worker_pool_bounds_total_concurrency_to_worker_count() {
        const WORKER_COUNT: usize = 3;
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        // A barrier sized to exactly `WORKER_COUNT` only ever completes if
        // all `WORKER_COUNT` jobs are genuinely running concurrently --
        // proving the pool both reaches and never exceeds this bound (if
        // fewer ran concurrently, the barrier wait would hang, which the
        // timeout below turns into a clear test failure instead).
        let barrier = Arc::new(Barrier::new(WORKER_COUNT));
        set_test_job_handler(std::sync::Arc::new(move |job: RefreshJob| {
            let events_tx = events_tx.clone();
            let barrier = Arc::clone(&barrier);
            Box::pin(async move {
                barrier.wait().await;
                events_tx.send(format!("done:{}", job.domain)).unwrap();
            })
        }));

        let (sender, receiver) = mpsc::channel(WORKER_COUNT);
        for i in 0..WORKER_COUNT {
            sender.try_send(test_job(&format!("job-{i}"))).unwrap();
        }
        drop(sender);

        let handles =
            spawn_refresh_worker_pool(resolver_for_worker_pool_tests(), receiver, WORKER_COUNT);

        tokio::time::timeout(Duration::from_secs(2), async {
            for _ in 0..WORKER_COUNT {
                events_rx.recv().await.unwrap();
            }
        })
        .await
        .expect("all jobs should complete concurrently well within the timeout");

        for handle in handles {
            handle.await.unwrap();
        }
        clear_test_job_handler();
    }

    #[tokio::test]
    async fn worker_pool_shutdown_via_abort() {
        // Explicitly clears the test hook (rather than relying on it never
        // having been set) since the test harness's thread pool can reuse
        // an OS thread across different test functions, and this test
        // relies on the true production no-op `process_refresh_job` -- not
        // whatever handler a previous test on this same thread happened to
        // leave behind.
        clear_test_job_handler();

        let (_sender, receiver) = mpsc::channel::<RefreshJob>(4);
        let handles = spawn_refresh_worker_pool(resolver_for_worker_pool_tests(), receiver, 2);
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let result = handle.await;
            assert!(
                result.is_ok() || result.unwrap_err().is_cancelled(),
                "aborted worker task should join cleanly (Ok or a cancelled JoinError)"
            );
        }
    }

    /// Regression test for the bug code review found: aborting the outer
    /// worker-loop task while a job is in flight must also cancel that
    /// job's own spawned task, not leave it detached running forever (which
    /// would keep its own `Arc<ResolveQuery>` clone alive and could hang
    /// shutdown's `event_drain.await`). Uses a job handler that never
    /// completes on its own (`std::future::pending`) with a drop marker, so
    /// the only way "job_dropped" is ever sent is if aborting the outer
    /// `JoinHandle` really did cancel the inner job task too.
    #[tokio::test]
    async fn worker_pool_abort_also_cancels_in_flight_job() {
        clear_test_job_handler();

        struct DropMarker(tokio::sync::mpsc::UnboundedSender<String>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                let _ = self.0.send("job_dropped".to_string());
            }
        }

        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        set_test_job_handler(std::sync::Arc::new(move |job: RefreshJob| {
            let events_tx = events_tx.clone();
            Box::pin(async move {
                events_tx.send(format!("start:{}", job.domain)).unwrap();
                let _marker = DropMarker(events_tx);
                std::future::pending::<()>().await;
            })
        }));

        let (sender, receiver) = mpsc::channel(4);
        sender.try_send(test_job("stuck")).unwrap();

        let handles = spawn_refresh_worker_pool(resolver_for_worker_pool_tests(), receiver, 1);
        assert_eq!(events_rx.recv().await.unwrap(), "start:stuck");
        // Give the spawned inner job task a scheduling turn so it's
        // genuinely parked in `pending().await` before aborting the loop.
        tokio::task::yield_now().await;

        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }

        tokio::time::timeout(Duration::from_secs(2), async {
            assert_eq!(events_rx.recv().await.unwrap(), "job_dropped");
        })
        .await
        .expect(
            "aborting the outer worker loop must also cancel its in-flight inner job task, \
             not leave it detached and running forever",
        );
        clear_test_job_handler();
    }

    struct ClientScopedResponsePolicy {
        client_ip: IpAddr,
        domain: DomainSelector,
        rule_id: String,
    }

    impl PolicyEvaluator for ClientScopedResponsePolicy {
        fn evaluate(&self, _client_ip: IpAddr, _question: &QuestionKey) -> PolicyDecision {
            PolicyDecision::Allow
        }

        fn evaluate_response_name(&self, client_ip: IpAddr, domain: &DomainName) -> PolicyDecision {
            if client_ip == self.client_ip && self.domain.matches(domain) {
                PolicyDecision::Block(PolicyBlock {
                    reason: BlockReason::MaliciousDomain,
                    rule_id: Some(self.rule_id.clone()),
                })
            } else {
                PolicyDecision::Allow
            }
        }
    }

    #[derive(Default)]
    struct OwnedOnlyProtocolCodec {
        borrowed_calls: Mutex<usize>,
        owned_calls: Mutex<usize>,
        expected_owned_ptr: Mutex<Option<usize>>,
        received_owned_ptr: Mutex<Option<usize>>,
    }

    impl OwnedOnlyProtocolCodec {
        fn expect_owned_ptr(expected_owned_ptr: *const u8) -> Self {
            Self {
                expected_owned_ptr: Mutex::new(Some(expected_owned_ptr as usize)),
                ..Self::default()
            }
        }
    }

    impl ProtocolCodec for OwnedOnlyProtocolCodec {
        fn decode_query(&self, _bytes: &[u8]) -> Result<DecodedQuery, QueryValidationError> {
            *self.borrowed_calls.lock().unwrap() += 1;
            panic!("resolve should decode owned request bytes");
        }

        fn decode_query_owned(&self, bytes: Bytes) -> Result<DecodedQuery, QueryDecodeFailure> {
            *self.owned_calls.lock().unwrap() += 1;
            *self.received_owned_ptr.lock().unwrap() = Some(bytes.as_ptr() as usize);
            if let Some(expected) = *self.expected_owned_ptr.lock().unwrap() {
                assert_eq!(bytes.as_ptr() as usize, expected);
            }
            StandardProtocolCodec::new(1232).decode_query_owned(bytes)
        }

        fn configured_max_udp_payload_size(&self) -> usize {
            1232
        }

        fn rewrite_response_id(
            &self,
            response_bytes: &mut [u8],
            request_id: u16,
        ) -> crate::protocol::Result<()> {
            rewrite_response_id(response_bytes, request_id)
        }

        fn rewrite_response_request_fields(
            &self,
            response_bytes: &mut [u8],
            request: &Message,
        ) -> crate::protocol::Result<()> {
            rewrite_response_request_fields(response_bytes, request)
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

    impl ResolutionBackend for StaticUpstream {
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

    struct ScriptedAuthorityTransport {
        responses: Mutex<VecDeque<Result<RecursiveAuthorityResponse, ResolutionBackendError>>>,
        requests: Mutex<Vec<(SocketAddr, QuestionKey, bool)>>,
        timeouts: Mutex<Vec<Duration>>,
    }

    impl ScriptedAuthorityTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<Message, ResolutionBackendError>>,
        ) -> Self {
            Self {
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .map(|response| {
                            response.and_then(|message| {
                                RecursiveAuthorityResponse::new(
                                    message.original_bytes.to_vec(),
                                    message,
                                )
                            })
                        })
                        .collect(),
                ),
                requests: Mutex::new(Vec::new()),
                timeouts: Mutex::new(Vec::new()),
            }
        }
    }

    impl RecursiveAuthorityTransport for ScriptedAuthorityTransport {
        fn query<'a>(
            &'a self,
            authority: SocketAddr,
            question: QuestionKey,
            dnssec_ok: bool,
            timeout: Duration,
        ) -> BoxFuture<'a, Result<RecursiveAuthorityResponse, ResolutionBackendError>> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .unwrap()
                    .push((authority, question, dnssec_ok));
                self.timeouts.lock().unwrap().push(timeout);
                self.responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Err(ResolutionBackendError::NoBackendsAvailable))
            })
        }
    }

    /// Test-only `RecursiveAuthorityTransport` for exercising the
    /// DO-aware single-flight regression: blocks every call on a shared
    /// `release` `Notify` (so a test can hold multiple concurrent calls
    /// open at once, mirroring `BlockingUpstream`'s pattern one layer
    /// down), then returns one of two canned responses selected by the
    /// *requested* `dnssec_ok` flag (not FIFO order, since two
    /// concurrently-released calls racing on a shared queue would make
    /// which response goes to which caller nondeterministic).
    struct DnssecAwareBlockingAuthorityTransport {
        requests: Mutex<Vec<(SocketAddr, QuestionKey, bool)>>,
        release: Notify,
        response_without_do: RecursiveAuthorityResponse,
        response_with_do: RecursiveAuthorityResponse,
    }

    impl DnssecAwareBlockingAuthorityTransport {
        fn new(response_without_do: Message, response_with_do: Message) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                release: Notify::new(),
                response_without_do: RecursiveAuthorityResponse::new(
                    response_without_do.original_bytes.to_vec(),
                    response_without_do,
                )
                .unwrap(),
                response_with_do: RecursiveAuthorityResponse::new(
                    response_with_do.original_bytes.to_vec(),
                    response_with_do,
                )
                .unwrap(),
            }
        }

        async fn wait_for_requests(&self, expected: usize) {
            for _ in 0..100 {
                if self.requests.lock().unwrap().len() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("timed out waiting for {expected} authority request(s)");
        }
    }

    impl RecursiveAuthorityTransport for DnssecAwareBlockingAuthorityTransport {
        fn query<'a>(
            &'a self,
            authority: SocketAddr,
            question: QuestionKey,
            dnssec_ok: bool,
            _timeout: Duration,
        ) -> BoxFuture<'a, Result<RecursiveAuthorityResponse, ResolutionBackendError>> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .unwrap()
                    .push((authority, question, dnssec_ok));
                self.release.notified().await;
                Ok(if dnssec_ok {
                    self.response_with_do.clone()
                } else {
                    self.response_without_do.clone()
                })
            })
        }
    }

    struct HangingAuthorityTransport;

    impl RecursiveAuthorityTransport for HangingAuthorityTransport {
        fn query<'a>(
            &'a self,
            _authority: SocketAddr,
            _question: QuestionKey,
            _dnssec_ok: bool,
            _timeout: Duration,
        ) -> BoxFuture<'a, Result<RecursiveAuthorityResponse, ResolutionBackendError>> {
            Box::pin(async move {
                std::future::pending::<Result<RecursiveAuthorityResponse, ResolutionBackendError>>()
                    .await
            })
        }
    }

    struct BlockingUpstream {
        response: Result<UpstreamResponse, UpstreamError>,
        requests: Mutex<Vec<UpstreamRequest>>,
        release: Notify,
    }

    impl BlockingUpstream {
        fn new(response: Result<UpstreamResponse, UpstreamError>) -> Self {
            Self {
                response,
                requests: Mutex::new(Vec::new()),
                release: Notify::new(),
            }
        }

        async fn wait_for_requests(&self, expected: usize) {
            for _ in 0..100 {
                if self.requests.lock().unwrap().len() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!("timed out waiting for {expected} upstream request(s)");
        }
    }

    impl ResolutionBackend for BlockingUpstream {
        fn resolve<'a>(
            &'a self,
            request: UpstreamRequest,
        ) -> BoxFuture<'a, Result<UpstreamResponse, UpstreamError>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request);
                self.release.notified().await;
                self.response.clone()
            })
        }
    }

    struct RecordingCache {
        lookup: Mutex<ChainLookup>,
        lookups: Mutex<Vec<(String, u16, u16)>>,
        stores: Mutex<Vec<(DecomposedResponse, u64)>>,
    }

    impl RecordingCache {
        fn with_lookup(lookup: ChainLookup) -> Self {
            Self {
                lookup: Mutex::new(lookup),
                lookups: Mutex::new(Vec::new()),
                stores: Mutex::new(Vec::new()),
            }
        }
    }

    impl DomainDnsCache for RecordingCache {
        fn lookup_chain(
            &self,
            qname: &str,
            qtype: u16,
            qclass: u16,
            _dnssec_ok: bool,
            _epoch: u64,
            _max_chain_depth: u8,
            _now: SystemTime,
            _refresh_config: &crate::config::RefreshConfig,
        ) -> ChainLookup {
            self.lookups
                .lock()
                .unwrap()
                .push((qname.to_string(), qtype, qclass));
            self.lookup.lock().unwrap().clone()
        }

        fn store_response(&self, decomposed: DecomposedResponse, epoch: u64) {
            self.stores.lock().unwrap().push((decomposed, epoch));
        }

        fn sweep_stale_namespace(&self, _current_epoch: u64) {}

        fn domain_count(&self) -> usize {
            0
        }

        fn capacity(&self) -> usize {
            0
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

    fn resolve_service_with_cache(
        upstream: Arc<dyn ResolutionBackend>,
        cache: Arc<dyn DomainDnsCache>,
        events: Arc<RecordingEvents>,
        metrics: Arc<RecordingMetrics>,
        max_udp_payload_size: usize,
    ) -> ResolveQuery {
        ResolveQuery::with_cache(
            Arc::new(StandardProtocolCodec::new(max_udp_payload_size)),
            cache,
            CacheTtlPolicy::default(),
            upstream,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            metrics,
        )
    }

    /// Like `resolve_service_with_cache`, but wires `backend` in as a
    /// `ResolutionMode::Recursive` backend snapshot rather than
    /// `resolve_service_with_cache`'s always-`Forward` default (via
    /// `BackendSnapshot::forwarding`). Needed for any test exercising
    /// `prepare_backend_result`'s recursive-only behavior end to end
    /// through `ResolveQuery::resolve` -- e.g. the client-facing DNSSEC
    /// filter step (`filter_response_for_requester`) and the
    /// always-`dnssec_complete: true` cache store for the recursive
    /// backend -- both gated on `backend_mode == ResolutionMode::Recursive`
    /// and otherwise silently skipped.
    fn resolve_service_with_recursive_cache(
        backend: Arc<dyn ResolutionBackend>,
        cache: Arc<dyn DomainDnsCache>,
        events: Arc<RecordingEvents>,
        metrics: Arc<RecordingMetrics>,
        max_udp_payload_size: usize,
    ) -> ResolveQuery {
        ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(max_udp_payload_size)),
            cache,
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                0,
                BackendHealth::Healthy,
                None,
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            metrics,
        )
    }

    fn a_response_with_answer(id: u16, name: &str, ttl: u32) -> Vec<u8> {
        let query = Message::parse_standard_query(&a_query(id, name)).unwrap();
        // `a_query` never carries EDNS, so the OPT-record-bearing branch of
        // `build_a_block_response` never triggers here -- the size passed
        // is inconsequential, any value works.
        build_a_block_response(&query, "192.0.2.10".parse().unwrap(), ttl, 1232)
    }

    fn upstream_response(bytes: Vec<u8>) -> UpstreamResponse {
        UpstreamResponse::forwarded_bytes(bytes, SystemTime::UNIX_EPOCH, 0, "test-forwarder")
    }

    fn recursive_backend(transport: Arc<ScriptedAuthorityTransport>) -> RecursiveResolutionBackend {
        recursive_backend_with_root_endpoints(
            transport,
            vec!["198.51.100.53:53".parse().unwrap()],
            8,
        )
    }

    /// Like `recursive_backend`, but with an explicit
    /// `configured_max_udp_payload_size` instead of the shared helpers'
    /// hardcoded `1232` -- needed whenever a test pairs the backend with a
    /// `StandardProtocolCodec` configured to a *different* size and then
    /// checks the served response's own OPT payload size: in production
    /// both come from the same config value (see `main.rs`), so a test that
    /// observes that value must keep the two in sync itself.
    fn recursive_backend_with_udp_payload_limit(
        transport: Arc<ScriptedAuthorityTransport>,
        configured_max_udp_payload_size: usize,
    ) -> RecursiveResolutionBackend {
        RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size,
            },
            transport,
        )
    }

    fn recursive_backend_with_root_endpoints(
        transport: Arc<ScriptedAuthorityTransport>,
        endpoints: Vec<SocketAddr>,
        max_recursion_depth: u8,
    ) -> RecursiveResolutionBackend {
        recursive_backend_with_timing(
            transport,
            endpoints,
            Duration::from_millis(500),
            Duration::from_secs(2),
            max_recursion_depth,
        )
    }

    fn recursive_backend_with_timing(
        transport: Arc<ScriptedAuthorityTransport>,
        endpoints: Vec<SocketAddr>,
        per_authority_timeout: Duration,
        per_query_deadline: Duration,
        max_recursion_depth: u8,
    ) -> RecursiveResolutionBackend {
        RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints,
                }],
                per_authority_timeout,
                per_query_deadline,
                max_recursion_depth,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport,
        )
    }

    fn recursive_request(name: &str) -> ResolutionRequest {
        recursive_request_from_bytes(a_query(0x1234, name))
    }

    fn recursive_request_from_bytes(bytes: Vec<u8>) -> ResolutionRequest {
        let query = StandardProtocolCodec::new(1232)
            .decode_query(&bytes)
            .unwrap();
        ResolutionRequest {
            query,
            backend_generation: 7,
        }
    }

    #[tokio::test]
    async fn recursive_backend_returns_authoritative_answer() {
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();

        assert_eq!(
            response.source_credibility,
            SourceCredibility::Authoritative
        );
        assert_eq!(response.backend_provenance.mode, ResolutionMode::Recursive);
        assert_eq!(response.backend_provenance.generation, 7);
        assert_eq!(response.final_question, Some(question.clone()));
        assert_eq!(response.answers().len(), 1);
        // Upstream is always asked for DNSSEC material now, independent of
        // this (DO-less) client's own request -- see `resolve_one_hop`.
        assert_eq!(
            transport.requests.lock().unwrap().as_slice(),
            &[("198.51.100.53:53".parse().unwrap(), question, true)]
        );
    }

    #[tokio::test]
    async fn recursive_backend_rewrites_authority_response_id() {
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();

        assert_eq!(&response.bytes[0..2], &[0x12, 0x34]);
        assert_eq!(
            response
                .response_message
                .as_ref()
                .map(|message| message.header.id),
            Some(0x1234)
        );
    }

    #[tokio::test]
    async fn recursive_backend_filters_unsupported_records_from_synthesized_response() {
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![
                    a_record("example.com", 60),
                    rrsig_record("example.com", 60, 1),
                ],
                Vec::new(),
                vec![opt_record(1232)],
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();

        // The backend's own synthesized message is always DNSSEC-complete
        // now, regardless of this (DO-less) client's own request -- the
        // RRSIG is kept. Trimming DNSSEC material back out for a DO=false
        // *client* is `prepare_backend_result`'s job (see
        // `filter_response_for_requester`), one layer up from the backend
        // under test here. The authority's own OPT record is still always
        // dropped -- `recursive_response_record_supported` never matches
        // `RecordData::OPT` at all, DO-independent.
        let message = response.response_message.as_ref().unwrap();
        assert_eq!(message.answers.len(), 2);
        assert!(message.additionals.is_empty());
    }

    #[tokio::test]
    async fn recursive_backend_preserves_supported_non_address_answers() {
        let question = QuestionKey::new("example.com", 15, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![mx_record("example.com", 60, "mail.example.com")],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request_from_bytes(query(
                0x1234,
                "example.com",
                15,
                1,
            )))
            .await
            .unwrap();

        let answers = response.answers();
        assert_eq!(answers.len(), 1);
        assert!(matches!(answers[0].record, RecordData::MX { .. }));
    }

    #[tokio::test]
    async fn recursive_backend_preserves_txt_answers() {
        let question = QuestionKey::new("example.com", 16, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![txt_record("example.com", 60, "v=spf1 -all")],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request_from_bytes(query(
                0x1234,
                "example.com",
                16,
                1,
            )))
            .await
            .unwrap();

        let answers = response.answers();
        assert_eq!(answers.len(), 1);
        assert!(matches!(answers[0].record, RecordData::TXT(_)));
    }

    #[tokio::test]
    async fn recursive_backend_returns_requested_dnssec_type_without_do() {
        let question = QuestionKey::new("example.com", DNSKEY_RECORD_TYPE, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![dnskey_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request_from_bytes(query(
                0x1234,
                "example.com",
                DNSKEY_RECORD_TYPE,
                1,
            )))
            .await
            .unwrap();

        let answers = response.answers();
        assert_eq!(answers.len(), 1);
        assert!(matches!(answers[0].record, RecordData::DNSKEY { .. }));
    }

    #[tokio::test]
    async fn recursive_backend_returns_requested_dnssec_type_after_cname_without_do() {
        let first = QuestionKey::new("alias.example.com", DNSKEY_RECORD_TYPE, 1);
        let second = QuestionKey::new("target.example.com", DNSKEY_RECORD_TYPE, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                first.clone(),
                ResponseCode::NoError,
                vec![cname_record("alias.example.com", 60, "target.example.com")],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                second,
                ResponseCode::NoError,
                vec![dnskey_record("target.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request_from_bytes(query(
                0x1234,
                "alias.example.com",
                DNSKEY_RECORD_TYPE,
                1,
            )))
            .await
            .unwrap();

        let answers = response.answers();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].rtype, CNAME_RECORD_TYPE);
        assert!(matches!(answers[1].record, RecordData::DNSKEY { .. }));
    }

    #[tokio::test]
    async fn recursive_backend_propagates_do_and_returns_dnssec_records_when_requested() {
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![
                    a_record("example.com", 60),
                    rrsig_record("example.com", 60, 1),
                ],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request_from_bytes(a_query_with_edns(
                0x1234,
                "example.com",
                1232,
                true,
            )))
            .await
            .unwrap();

        let message = response.response_message.as_ref().unwrap();
        assert_eq!(message.answers.len(), 2);
        assert!(!message.header.aa());
        assert!(message.edns.as_ref().is_some_and(|edns| edns.dnssec_ok));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(
            requests.as_slice(),
            &[("198.51.100.53:53".parse().unwrap(), question, true)]
        );
    }

    #[tokio::test]
    async fn recursive_backend_preserves_oversized_response_for_resolver_boundary() {
        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..40)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();

        let message = response.response_message.as_ref().unwrap();
        assert!(!message.header.tc());
        assert_eq!(message.answers.len(), 40);
    }

    #[tokio::test]
    async fn recursive_backend_synthesizes_raw_dnssec_records_regardless_of_client_do() {
        // The backend's synthesized message is now always DNSSEC-complete,
        // independent of the querying client's own DO flag -- upstream is
        // always asked for DNSSEC material (`resolve_one_hop`) and
        // `synthesize_recursive_cname_response` always keeps it. A DO=false
        // client's own filtered response is `prepare_backend_result`'s
        // concern (`filter_response_for_requester`), not this backend's --
        // both a DO-less and a DO=true request must see the same complete
        // backend-level answer set here.
        let question = QuestionKey::new("example.com", 1, 1);
        let raw_dnssec_record = unknown_record("example.com", 59, 60, &[1, 2, 3, 4]);
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("example.com", 60), raw_dnssec_record.clone()],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![a_record("example.com", 60), raw_dnssec_record],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport);

        let without_do = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();
        let without_do_answers = &without_do.response_message.as_ref().unwrap().answers;
        assert_eq!(without_do_answers.len(), 2);
        assert_eq!(without_do_answers[1].rtype, 59);

        let with_do = backend
            .resolve(recursive_request_from_bytes(a_query_with_edns(
                0x1234,
                "example.com",
                1232,
                true,
            )))
            .await
            .unwrap();
        let answers = &with_do.response_message.as_ref().unwrap().answers;
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[1].rtype, 59);
    }

    #[tokio::test]
    async fn recursive_backend_preserves_nsec3_records_when_do_requested() {
        let question = QuestionKey::new("missing.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                Vec::new(),
                vec![
                    soa_record("example.com", 60, 60),
                    nsec3_record("example.com", 60),
                ],
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request_from_bytes(a_query_with_edns(
                0x1234,
                "missing.example.com",
                1232,
                true,
            )))
            .await
            .unwrap();

        let authorities = response.authorities();
        assert_eq!(authorities.len(), 2);
        assert!(matches!(authorities[1].record, RecordData::NSEC3 { .. }));
    }

    #[tokio::test]
    async fn recursive_backend_strips_echoed_ns_from_authority_on_positive_answer() {
        // Some authoritative servers (e.g. NS1/AWS DNS) echo the zone's NS
        // set in the AUTHORITY section even when the ANSWER section already
        // satisfies the question. That's not useful to a stub client and
        // other recursors (e.g. Cloudflare) omit it from the final response.
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                vec![ns_record("example.com", 300, "ns1.example.com")],
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        assert!(response.authorities().is_empty());
    }

    #[tokio::test]
    async fn recursive_backend_preserves_cname_dnssec_records_when_restarting() {
        let first = QuestionKey::new("alias.example.com", 1, 1);
        let second = QuestionKey::new("target.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                first.clone(),
                ResponseCode::NoError,
                vec![
                    cname_record("alias.example.com", 60, "target.example.com"),
                    rrsig_record("alias.example.com", 60, CNAME_RECORD_TYPE),
                ],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                second,
                ResponseCode::NoError,
                vec![a_record("target.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request_from_bytes(a_query_with_edns(
                0x1234,
                "alias.example.com",
                1232,
                true,
            )))
            .await
            .unwrap();

        let answers = response.answers();
        assert_eq!(answers.len(), 3);
        assert_eq!(answers[0].rtype, CNAME_RECORD_TYPE);
        assert!(matches!(
            answers[1].record,
            RecordData::RRSIG {
                type_covered: CNAME_RECORD_TYPE,
                ..
            }
        ));
        assert_eq!(answers[2].rtype, 1);
    }

    #[tokio::test]
    async fn recursive_backend_clears_dnssec_validation_flags_while_disabled() {
        let question = QuestionKey::new("example.com", 1, 1);
        // extra_flags = 0x0030 forges AD+CD on the *upstream authority's*
        // response -- an authority should never set either bit on its own
        // reply, so this proves the backend doesn't blindly forward
        // whatever flags upstream happened to send.
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_extra_flags(
                question,
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
                0x0030,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request_from_bytes(
                a_query_with_checking_disabled(0x1234, "example.com"),
            ))
            .await
            .unwrap();

        let message = response.response_message.as_ref().unwrap();
        // AD is computed from this backend's own (disabled) validation
        // state, not copied from upstream's forged AD=1.
        assert!(!message.header.ad());
        // CD, per RFC 4035 §3.2.2, must be copied from the *client's own
        // query* (CD=1, via `a_query_with_checking_disabled`) -- not from
        // upstream's forged CD=1, and not cleared just because DNSSEC
        // validation is disabled. It happens to agree with upstream's
        // forged bit here, but for the right reason: this assertion would
        // still hold with the upstream CD bit flipped to 0.
        assert!(message.header.cd());
    }

    #[tokio::test]
    async fn recursive_backend_follows_referral_with_glue() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let referred = "203.0.113.10:53".parse().unwrap();
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.com", 300, "ns1.example.com")],
                vec![glue_a_record(
                    "ns1.example.com",
                    300,
                    "203.0.113.10".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("www.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("www.example.com"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(requests[1], (referred, question, true));
    }

    #[tokio::test]
    async fn recursive_backend_resolves_glueless_delegation_by_querying_ns_name_directly() {
        // A zone cut delegates to a nameserver hosted under a completely
        // different, unrelated domain -- the parent zone (e.g. a TLD) can't
        // supply glue for it (a "glueless" delegation, as seen with e.g.
        // redis.io -> ns-*.awsdns-*.{org,com,co.uk,net}). The resolver must
        // fall back to resolving the NS hostname's address itself instead
        // of giving up.
        let question = QuestionKey::new("example.io", 1, 1);
        let ns_question = QuestionKey::new("ns1.example.net", 1, 1);
        let ns_aaaa_question = QuestionKey::new("ns1.example.net", AAAA_RECORD_TYPE, 1);
        let resolved_ns_addr: SocketAddr = "192.0.2.10:53".parse().unwrap();

        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.io", 300, "ns1.example.net")],
                Vec::new(),
                false,
            )),
            Ok(response_message_for_question(
                ns_question,
                ResponseCode::NoError,
                vec![a_record("ns1.example.net", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                ns_aaaa_question,
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.net", 300, 60)],
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("example.io", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("example.io"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        {
            let requests = transport.requests.lock().unwrap();
            assert_eq!(requests.len(), 4);
            // The final answer was fetched from the address resolved for
            // the glueless NS name, not straight from the root.
            assert_eq!(requests[3].0, resolved_ns_addr);
        }

        // The glueless delegation gets cached like a normal referral, so a
        // repeat query for the same zone skips straight to it.
        assert!(backend.delegation_cache.lookup("example.io", 1).is_some());
    }

    #[tokio::test]
    async fn recursive_backend_bounds_glueless_delegation_ttl_by_resolved_address_ttl() {
        // The referral's own NS TTL is long-lived, but the address record
        // we resolve for the glueless NS name is short-lived. The cached
        // delegation must be bounded by the shorter of the two -- otherwise
        // the resolver could keep routing to a stale/changed authority
        // address long after that address record itself expired.
        let question = QuestionKey::new("example.io", 1, 1);
        let ns_question = QuestionKey::new("ns1.example.net", 1, 1);
        let ns_aaaa_question = QuestionKey::new("ns1.example.net", AAAA_RECORD_TYPE, 1);

        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.io", 300, "ns1.example.net")],
                Vec::new(),
                false,
            )),
            Ok(response_message_for_question(
                ns_question,
                ResponseCode::NoError,
                vec![a_record("ns1.example.net", 5)],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                ns_aaaa_question,
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.net", 300, 60)],
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![a_record("example.io", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport);

        backend
            .resolve(recursive_request("example.io"))
            .await
            .unwrap();

        let remaining = backend
            .delegation_cache
            .ttl_remaining_secs("example.io", 1)
            .expect("glueless delegation should be cached");
        assert!(
            remaining <= 5,
            "expected delegation TTL bounded by the resolved address's 5s TTL, got {remaining}s"
        );
    }

    #[tokio::test]
    async fn recursive_backend_tries_glueless_ns_names_in_sorted_order() {
        // More NS names than MAX_GLUELESS_NS_NAMES (2): the candidates must
        // be tried in a deterministic (sorted) order rather than whatever
        // order a HashSet happens to iterate in, so which names get
        // attempted -- and thus whether resolution succeeds -- doesn't vary
        // from run to run.
        let question = QuestionKey::new("example.io", 1, 1);
        let a_question = QuestionKey::new("a.example.net", 1, 1);
        let a_aaaa_question = QuestionKey::new("a.example.net", AAAA_RECORD_TYPE, 1);
        let b_question = QuestionKey::new("b.example.net", 1, 1);
        let b_aaaa_question = QuestionKey::new("b.example.net", AAAA_RECORD_TYPE, 1);

        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![
                    ns_record("example.io", 300, "c.example.net"),
                    ns_record("example.io", 300, "a.example.net"),
                    ns_record("example.io", 300, "b.example.net"),
                ],
                Vec::new(),
                false,
            )),
            Ok(response_message_for_question(
                a_question,
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.net", 300, 60)],
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                a_aaaa_question,
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.net", 300, 60)],
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                b_question,
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.net", 300, 60)],
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                b_aaaa_question,
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.net", 300, 60)],
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        assert_eq!(
            backend.resolve(recursive_request("example.io")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );

        let requests = transport.requests.lock().unwrap();
        let queried_names: Vec<&str> = requests
            .iter()
            .map(|(_, question, _)| question.qname.as_str())
            .collect();
        assert_eq!(
            queried_names,
            vec![
                "example.io",
                "a.example.net",
                "a.example.net",
                "b.example.net",
                "b.example.net",
            ],
            "expected the two lexicographically-first NS names to be tried (each queried for A and AAAA), never c.example.net"
        );
    }

    #[tokio::test]
    async fn recursive_backend_resolves_glueless_delegation_via_aaaa_only_nameserver() {
        // The glueless NS hostname has no A record at all, only AAAA -- the
        // resolver must still find it by querying both qtypes rather than
        // giving up after an empty/negative A answer.
        let question = QuestionKey::new("example.io", 1, 1);
        let ns_a_question = QuestionKey::new("ns1.example.net", 1, 1);
        let ns_aaaa_question = QuestionKey::new("ns1.example.net", AAAA_RECORD_TYPE, 1);
        let resolved_ns_addr: SocketAddr =
            "[2001:db8::1]:53".parse().expect("valid IPv6 socket addr");

        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.io", 300, "ns1.example.net")],
                Vec::new(),
                false,
            )),
            Ok(response_message_for_question(
                ns_a_question,
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.net", 300, 60)],
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                ns_aaaa_question,
                ResponseCode::NoError,
                vec![aaaa_record("ns1.example.net", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("example.io", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("example.io"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[3].0, resolved_ns_addr);
    }

    #[tokio::test]
    async fn recursive_backend_filters_referrals_by_query_class() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let mut chaos_ns = ns_record("example.com", 300, "ns1.example.com");
        chaos_ns.rclass = 3;
        let mut chaos_glue = glue_a_record("ns1.example.com", 300, "203.0.113.10".parse().unwrap());
        chaos_glue.rclass = 3;
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                Vec::new(),
                vec![chaos_ns],
                vec![chaos_glue],
                false,
            ),
        )]));
        let backend = recursive_backend(transport);

        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );
    }

    #[tokio::test]
    async fn recursive_backend_walks_root_tld_and_authority_for_answer() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let tld_authority = "203.0.113.10:53".parse().unwrap();
        let domain_authority = "203.0.113.20:53".parse().unwrap();
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("com", 300, "a.gtld-servers.net")],
                vec![glue_a_record(
                    "a.gtld-servers.net",
                    300,
                    "203.0.113.10".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.com", 300, "ns1.example.com")],
                vec![glue_a_record(
                    "ns1.example.com",
                    300,
                    "203.0.113.20".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("www.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("www.example.com"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        assert_eq!(
            response.source_credibility,
            SourceCredibility::Authoritative
        );
        let requests = transport.requests.lock().unwrap();
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(
            requests.as_slice(),
            &[
                ("198.51.100.53:53".parse().unwrap(), question.clone(), true),
                (tld_authority, question.clone(), true),
                (domain_authority, question, true),
            ]
        );
    }

    #[tokio::test]
    async fn recursive_backend_accepts_parent_zone_glue_for_multilabel_delegation() {
        let question = QuestionKey::new("www.example.co.uk", 1, 1);
        let tld_authority = "203.0.113.10:53".parse().unwrap();
        let domain_authority = "203.0.113.20:53".parse().unwrap();
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("uk", 300, "dns.nic.uk")],
                vec![glue_a_record(
                    "dns.nic.uk",
                    300,
                    "203.0.113.10".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("co.uk", 300, "dns.nic.uk")],
                vec![glue_a_record(
                    "dns.nic.uk",
                    300,
                    "203.0.113.20".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("www.example.co.uk", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("www.example.co.uk"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let requests = transport.requests.lock().unwrap();
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(
            requests.as_slice(),
            &[
                ("198.51.100.53:53".parse().unwrap(), question.clone(), true),
                (tld_authority, question.clone(), true),
                (domain_authority, question, true),
            ]
        );
    }

    #[tokio::test]
    async fn recursive_backend_walks_root_tld_and_authority_for_negative_answer() {
        let question = QuestionKey::new("missing.example.com", 1, 1);
        let tld_authority = "203.0.113.10:53".parse().unwrap();
        let domain_authority = "203.0.113.20:53".parse().unwrap();
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("com", 300, "a.gtld-servers.net")],
                vec![glue_a_record(
                    "a.gtld-servers.net",
                    300,
                    "203.0.113.10".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.com", 300, "ns1.example.com")],
                vec![glue_a_record(
                    "ns1.example.com",
                    300,
                    "203.0.113.20".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.com", 300, 60)],
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("missing.example.com"))
            .await
            .unwrap();

        assert_eq!(response.response_code, Some(ResponseCode::NxDomain));
        assert_eq!(
            response.negative_cache,
            Some(negative_metadata(
                "example.com",
                "missing.example.com",
                1,
                1,
                NegativeCacheKind::NxDomain,
                Duration::from_secs(60),
            ))
        );
        let requests = transport.requests.lock().unwrap();
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(
            requests.as_slice(),
            &[
                ("198.51.100.53:53".parse().unwrap(), question.clone(), true),
                (tld_authority, question.clone(), true),
                (domain_authority, question, true),
            ]
        );
    }

    #[tokio::test]
    async fn recursive_backend_rejects_unrelated_referral() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("attacker.test", 300, "ns1.attacker.test")],
                vec![glue_a_record(
                    "ns1.attacker.test",
                    300,
                    "203.0.113.66".parse().unwrap(),
                )],
                false,
            ),
        )]));
        let backend = recursive_backend(transport);

        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );
    }

    #[tokio::test]
    async fn recursive_backend_rejects_and_does_not_cache_upward_referral_from_child_authority() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let legit_referral = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            Vec::new(),
            vec![ns_record("example.com", 300, "ns1.example.com")],
            vec![glue_a_record(
                "ns1.example.com",
                300,
                "203.0.113.10".parse().unwrap(),
            )],
            false,
        );
        // A compromised/misbehaving ns1.example.com, reached via the
        // legitimate referral above, tries to claim a referral for the
        // *parent* zone "com" pointing at attacker-controlled endpoints.
        let malicious_upward_referral = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            Vec::new(),
            vec![ns_record("com", 300, "attacker-ns.evil")],
            vec![Record {
                name: "attacker-ns.evil".to_string(),
                rtype: 1,
                rclass: 1,
                ttl: 300,
                record: RecordData::A("198.51.100.66".parse().unwrap()),
            }],
            false,
        );

        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(legit_referral),
            Ok(malicious_upward_referral),
        ]));
        let metrics = Arc::new(RecordingMetrics::default());
        let backend = RecursiveResolutionBackend::with_metrics(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport,
            metrics.clone(),
        );

        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );

        // The malicious "com" referral must never be cached -- otherwise
        // every future .com lookup would start from attacker endpoints
        // instead of root hints.
        assert!(backend.delegation_cache.lookup("com", 1).is_none());
        assert!(
            metrics.count(ResolverMetric::RecursiveBailiwickReject) >= 1,
            "expected the upward referral to be rejected as a bailiwick violation"
        );
    }

    #[tokio::test]
    async fn recursive_backend_defers_out_of_bailiwick_glue() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.com", 300, "ns1.attacker.test")],
                vec![glue_a_record(
                    "ns1.attacker.test",
                    300,
                    "203.0.113.66".parse().unwrap(),
                )],
                false,
            ),
        )]));
        let backend = recursive_backend(transport);

        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );
    }

    #[tokio::test]
    async fn recursive_backend_allows_same_authority_for_nested_delegations() {
        let question = QuestionKey::new("www.child.example.com", 1, 1);
        let shared_authority = "203.0.113.10:53".parse().unwrap();
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.com", 300, "ns1.example.com")],
                vec![glue_a_record(
                    "ns1.example.com",
                    300,
                    "203.0.113.10".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("child.example.com", 300, "ns1.child.example.com")],
                vec![glue_a_record(
                    "ns1.child.example.com",
                    300,
                    "203.0.113.10".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("www.child.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("www.child.example.com"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(requests[1], (shared_authority, question.clone(), true));
        assert_eq!(requests[2], (shared_authority, question, true));
    }

    #[tokio::test]
    async fn recursive_backend_restarts_for_cname() {
        let first = QuestionKey::new("alias.example.com", 1, 1);
        let second = QuestionKey::new("target.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                first.clone(),
                ResponseCode::NoError,
                vec![cname_record("alias.example.com", 60, "target.example.com")],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                second.clone(),
                ResponseCode::NoError,
                vec![a_record("target.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("alias.example.com"))
            .await
            .unwrap();

        assert_eq!(response.final_question, Some(first.clone()));
        assert_eq!(response.answers().len(), 2);
        let requests = transport.requests.lock().unwrap();
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(requests[0].1, first);
        assert!(requests[0].2);
        assert_eq!(requests[1].1, second);
        assert!(requests[1].2);
    }

    #[tokio::test]
    async fn recursive_backend_accepts_complete_cname_answer() {
        let first = QuestionKey::new("alias.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                first.clone(),
                ResponseCode::NoError,
                vec![
                    cname_record("alias.example.com", 60, "target.example.com"),
                    a_record("target.example.com", 60),
                ],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("alias.example.com"))
            .await
            .unwrap();

        assert_eq!(response.final_question, Some(first.clone()));
        assert_eq!(response.answers().len(), 2);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(requests[0].1, first);
        assert!(requests[0].2);
    }

    #[tokio::test]
    async fn recursive_backend_rejects_referral_loop_and_depth_exhaustion() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let referral = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            Vec::new(),
            vec![ns_record("example.com", 300, "ns1.example.com")],
            vec![glue_a_record(
                "ns1.example.com",
                300,
                "203.0.113.10".parse().unwrap(),
            )],
            false,
        );
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(referral.clone()),
            Ok(referral),
        ]));
        let backend = recursive_backend(transport);

        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );

        let referral = response_message_for_question(
            QuestionKey::new("www.example.com", 1, 1),
            ResponseCode::NoError,
            Vec::new(),
            vec![ns_record("example.com", 300, "ns1.example.com")],
            vec![glue_a_record(
                "ns1.example.com",
                300,
                "203.0.113.10".parse().unwrap(),
            )],
            false,
        );
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(referral)]));
        let backend = recursive_backend_with_root_endpoints(
            transport,
            vec!["198.51.100.53:53".parse().unwrap()],
            1,
        );
        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );

        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
            ),
        )]));
        let backend = RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 1,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport,
        );
        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );
    }

    #[tokio::test]
    async fn recursive_backend_records_query_attempt_and_referral_loop_metrics() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let referral = response_message_for_question(
            question,
            ResponseCode::NoError,
            Vec::new(),
            vec![ns_record("example.com", 300, "ns1.example.com")],
            vec![glue_a_record(
                "ns1.example.com",
                300,
                "203.0.113.10".parse().unwrap(),
            )],
            false,
        );
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(referral.clone()),
            Ok(referral),
        ]));
        let metrics = Arc::new(RecordingMetrics::default());
        let backend = RecursiveResolutionBackend::with_metrics(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport,
            metrics.clone(),
        );

        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );

        assert_eq!(metrics.count(ResolverMetric::RecursiveQuery), 1);
        assert_eq!(metrics.count(ResolverMetric::RecursiveAuthorityAttempt), 2);
        assert_eq!(metrics.count(ResolverMetric::RecursiveReferralLoop), 1);
        assert!(
            metrics
                .durations
                .lock()
                .unwrap()
                .iter()
                .any(|(metric, _)| *metric == ResolverMetric::RecursiveQueryDuration)
        );
    }

    #[tokio::test]
    async fn recursive_backend_detects_reordered_referral_endpoint_loop() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let first_referral = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            Vec::new(),
            vec![
                ns_record("example.com", 300, "ns1.example.com"),
                ns_record("example.com", 300, "ns2.example.com"),
            ],
            vec![
                glue_a_record("ns1.example.com", 300, "203.0.113.10".parse().unwrap()),
                glue_a_record("ns2.example.com", 300, "203.0.113.11".parse().unwrap()),
            ],
            false,
        );
        let reordered_referral = response_message_for_question(
            question,
            ResponseCode::NoError,
            Vec::new(),
            vec![
                ns_record("example.com", 300, "ns2.example.com"),
                ns_record("example.com", 300, "ns1.example.com"),
            ],
            vec![
                glue_a_record("ns2.example.com", 300, "203.0.113.11".parse().unwrap()),
                glue_a_record("ns1.example.com", 300, "203.0.113.10".parse().unwrap()),
            ],
            false,
        );
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(first_referral),
            Ok(reordered_referral),
        ]));
        let metrics = Arc::new(RecordingMetrics::default());
        let backend = RecursiveResolutionBackend::with_metrics(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport.clone(),
            metrics.clone(),
        );

        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );

        assert_eq!(metrics.count(ResolverMetric::RecursiveReferralLoop), 1);
        // Root query, plus both ns1/ns2 raced concurrently within the same
        // delegation set (bounded by MAX_CONCURRENT_AUTHORITY_QUERIES).
        assert_eq!(transport.requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn recursive_backend_records_lame_delegation_metric() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
            ),
        )]));
        let metrics = Arc::new(RecordingMetrics::default());
        let backend = RecursiveResolutionBackend::with_metrics(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport,
            metrics.clone(),
        );

        assert_eq!(
            backend.resolve(recursive_request("www.example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );

        assert_eq!(metrics.count(ResolverMetric::RecursiveLameDelegation), 1);
        assert_eq!(metrics.count(ResolverMetric::RecursiveBailiwickReject), 0);
    }

    #[tokio::test]
    async fn recursive_backend_fails_over_to_alternate_authority() {
        let question = QuestionKey::new("example.com", 1, 1);
        let second_authority = "198.51.100.54:53".parse().unwrap();
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Err(ResolutionBackendError::Timeout),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend_with_root_endpoints(
            transport.clone(),
            vec!["198.51.100.53:53".parse().unwrap(), second_authority],
            8,
        );

        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(requests[1], (second_authority, question, true));
    }

    #[tokio::test]
    async fn recursive_backend_bounds_attempt_timeout_by_query_deadline() {
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend_with_timing(
            transport.clone(),
            vec!["198.51.100.53:53".parse().unwrap()],
            Duration::from_secs(5),
            Duration::from_millis(50),
            8,
        );

        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let timeouts = transport.timeouts.lock().unwrap();
        assert_eq!(timeouts.len(), 1);
        assert!(timeouts[0] <= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn recursive_backend_enforces_transport_attempt_timeout() {
        let backend = RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(20),
                per_query_deadline: Duration::from_secs(1),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            Arc::new(HangingAuthorityTransport),
        );

        let result = time::timeout(
            Duration::from_millis(200),
            backend.resolve(recursive_request("example.com")),
        )
        .await;

        assert_eq!(result.unwrap(), Err(ResolutionBackendError::Timeout));
    }

    #[tokio::test]
    async fn recursive_backend_fails_over_after_mismatched_question() {
        let question = QuestionKey::new("example.com", 1, 1);
        let second_authority = "198.51.100.54:53".parse().unwrap();
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                QuestionKey::new("other.example.com", 1, 1),
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend_with_root_endpoints(
            transport.clone(),
            vec!["198.51.100.53:53".parse().unwrap(), second_authority],
            8,
        );

        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 1);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(requests[1], (second_authority, question, true));
    }

    #[tokio::test]
    async fn recursive_backend_detects_cname_loop() {
        let alias = QuestionKey::new("alias.example.com", 1, 1);
        let target = QuestionKey::new("target.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                alias.clone(),
                ResponseCode::NoError,
                vec![cname_record("alias.example.com", 60, "target.example.com")],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                target,
                ResponseCode::NoError,
                vec![cname_record("target.example.com", 60, "alias.example.com")],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport);

        assert_eq!(
            backend
                .resolve(recursive_request("alias.example.com"))
                .await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );
    }

    #[tokio::test]
    async fn recursive_backend_allows_same_referral_after_cname_restart() {
        let alias = QuestionKey::new("alias.example.com", 1, 1);
        let target = QuestionKey::new("target.example.com", 1, 1);
        let referral_authority = "203.0.113.10:53".parse().unwrap();
        let referral_for_alias = response_message_for_question(
            alias.clone(),
            ResponseCode::NoError,
            Vec::new(),
            vec![ns_record("example.com", 300, "ns1.example.com")],
            vec![glue_a_record(
                "ns1.example.com",
                300,
                "203.0.113.10".parse().unwrap(),
            )],
            false,
        );
        let referral_for_target = response_message_for_question(
            target.clone(),
            ResponseCode::NoError,
            Vec::new(),
            vec![ns_record("example.com", 300, "ns1.example.com")],
            vec![glue_a_record(
                "ns1.example.com",
                300,
                "203.0.113.10".parse().unwrap(),
            )],
            false,
        );
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(referral_for_alias),
            Ok(response_message_for_question(
                alias.clone(),
                ResponseCode::NoError,
                vec![cname_record("alias.example.com", 60, "target.example.com")],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(referral_for_target),
            Ok(response_message_for_question(
                target.clone(),
                ResponseCode::NoError,
                vec![a_record("target.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        let response = backend
            .resolve(recursive_request("alias.example.com"))
            .await
            .unwrap();

        assert_eq!(response.answers().len(), 2);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        // Upstream is always asked for DNSSEC material now, independent of
        // the querying client's own DO flag -- see `resolve_one_hop`.
        assert_eq!(requests[1], (referral_authority, alias, true));
        assert_eq!(requests[3], (referral_authority, target, true));
    }

    #[tokio::test]
    async fn recursive_backend_requires_authoritative_negative_answer() {
        let question = QuestionKey::new("missing.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question.clone(),
                ResponseCode::NxDomain,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
            ),
        )]));
        let backend = recursive_backend(transport);

        assert_eq!(
            backend
                .resolve(recursive_request("missing.example.com"))
                .await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );

        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NxDomain,
                Vec::new(),
                vec![soa_record("example.com", 300, 60)],
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        let response = backend
            .resolve(recursive_request("missing.example.com"))
            .await
            .unwrap();

        assert_eq!(response.response_code, Some(ResponseCode::NxDomain));
        assert_eq!(
            response
                .negative_cache
                .as_ref()
                .map(|metadata| metadata.soa_minimum_ttl),
            Some(Duration::from_secs(60))
        );
    }

    #[tokio::test]
    async fn recursive_backend_requires_authoritative_positive_answer() {
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                false,
            ),
        )]));
        let backend = recursive_backend(transport);

        assert_eq!(
            backend.resolve(recursive_request("example.com")).await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );
    }

    #[tokio::test]
    async fn recursive_backend_defers_dname_handling_as_failure() {
        let question = QuestionKey::new("child.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question.clone(),
                ResponseCode::NoError,
                vec![dname_record("example.com", 60, "example.net")],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = recursive_backend(transport);

        assert_eq!(
            backend
                .resolve(recursive_request("child.example.com"))
                .await,
            Err(ResolutionBackendError::NoBackendsAvailable)
        );
    }

    #[tokio::test]
    async fn resolve_query_accepts_recursive_backend_response() {
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question.clone(),
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport.clone()));
        let events = Arc::new(RecordingEvents::default());
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(&outcome.response_bytes[0..2], &[0x12, 0x34]);
        assert_eq!(
            service.backend.current().dnssec_validation,
            DnssecValidationStatus::Disabled
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
        let recorded_events = events.events.lock().unwrap();
        assert_eq!(
            recorded_events[0].backend,
            Some(QueryEventBackend {
                mode: ResolutionMode::Recursive,
                generation: 7,
                health: BackendHealth::Healthy,
                cache_namespace: Some("mode:recursive;generation:7".to_string()),
                dnssec_validation: DnssecValidationStatus::Disabled,
            })
        );
    }

    #[tokio::test]
    async fn resolve_truncates_fresh_recursive_response_to_configured_udp_limit() {
        let question = QuestionKey::new("example.com", 1, 1);
        // Name compression shrinks each repeated "example.com" owner name to
        // a 2-byte pointer, so this needs far more records than an
        // uncompressed encoder would to still exceed the configured limit.
        let answers = (0..200)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(response.header.tc());
        assert!(response.answers.is_empty());
    }

    /// Regression test for Finding A of the section-08 Codex adversarial
    /// review round: `prepare_backend_result`'s recursive-miss truncation
    /// path used to call `build_truncated_response`, which wrote a
    /// header-only response with QDCOUNT=0/ARCOUNT=0 and no CD copy --
    /// dropping the question and OPT record even for an EDNS requester
    /// (RFC 6891 §6.1.1/§7) and silently resetting CD to 0 (RFC 4035
    /// §3.2.2). A DO=false requester's oversized response must still
    /// truncate to header + question + a mirrored OPT record advertising
    /// its own DO=false, with no answer section (so no RRSIGs leak through
    /// regardless of what DO=false filtering would otherwise have done to
    /// the answer section -- there is no answer section left to filter).
    #[tokio::test]
    async fn resolve_truncated_recursive_response_do_false_includes_question_and_opt() {
        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..200)
            .flat_map(|_| {
                [
                    a_record("example.com", 60),
                    rrsig_record("example.com", 60, A_RECORD_TYPE),
                ]
            })
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(response.header.tc());
        assert!(!response.header.cd());
        assert!(response.answers.is_empty());
        assert!(!response_contains_rrsig(&outcome.response_bytes));
        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.questions[0].qname, "example.com");
        let opt = response
            .additionals
            .iter()
            .find_map(|record| match &record.record {
                RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .expect("a truncated response to an EDNS requester must still carry an OPT record");
        assert_eq!(
            opt.udp_payload_size, 700,
            "OPT must advertise this resolver's own configured UDP payload size (700), \
             not echo the requester's 4096"
        );
        assert!(!opt.dnssec_ok);
    }

    /// Same scenario as `resolve_truncated_recursive_response_do_false_includes_question_and_opt`
    /// but with the requester's own DO=1 -- the truncated response's
    /// mirrored OPT record must reflect DO=1 back, same as any other
    /// response type.
    #[tokio::test]
    async fn resolve_truncated_recursive_response_do_true_includes_opt() {
        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..200)
            .flat_map(|_| {
                [
                    a_record("example.com", 60),
                    rrsig_record("example.com", 60, A_RECORD_TYPE),
                ]
            })
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, true),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(response.header.tc());
        assert!(response.answers.is_empty());
        let opt = response
            .additionals
            .iter()
            .find_map(|record| match &record.record {
                RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .expect("a truncated response to an EDNS requester must still carry an OPT record");
        assert_eq!(
            opt.udp_payload_size, 700,
            "OPT must advertise this resolver's own configured UDP payload size (700), \
             not echo the requester's 4096"
        );
        assert!(opt.dnssec_ok);
    }

    /// A CD=1 requester whose recursive-miss response truncates must still
    /// get CD=1 copied onto the truncated response (RFC 4035 §3.2.2) --
    /// before the Finding A fix, the header-only `build_truncated_response`
    /// path silently reset CD to 0.
    #[tokio::test]
    async fn resolve_truncated_recursive_response_copies_checking_disabled() {
        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..200)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns_and_checking_disabled(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(response.header.tc());
        assert!(response.header.cd());
    }

    /// A DO=true requester whose recursive response is oversized must
    /// truncate immediately without ever attempting the DO=false
    /// clone+reserialize filter pass: filtering is a no-op for DO=true (it
    /// keeps DNSSEC material already), so there's nothing filtering could
    /// change and attempting it first would be pure waste. This is the one
    /// case where "unfiltered doesn't fit" is still a valid, safe basis for
    /// an immediate truncation decision -- see the sibling DO=false tests
    /// below for why the same shortcut is *not* valid when DO=false.
    #[tokio::test]
    async fn resolve_do_true_truncating_recursive_response_skips_filter_pass() {
        reset_filter_response_for_requester_calls();

        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..200)
            .flat_map(|_| {
                [
                    a_record("example.com", 60),
                    rrsig_record("example.com", 60, A_RECORD_TYPE),
                ]
            })
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, true),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(response.header.tc());
        assert_eq!(
            filter_response_for_requester_call_count(),
            0,
            "a DO=true response that's going to truncate anyway must never reach the \
             clone+reserialize DO=false filter pass -- filtering is a no-op for DO=true"
        );
    }

    /// Regression test for the "unfiltered doesn't fit" -> "filtered won't
    /// fit either, so skip filtering and truncate" bug: that inference is
    /// invalid for DO=false. `filter_response_for_requester` strips
    /// RRSIG/DNSKEY/NSEC/etc. for DO=false requesters, and since the
    /// recursive backend now always fetches DNSSEC-complete responses from
    /// upstream, it's a common case that a response only exceeds the UDP
    /// payload size *because of* that DNSSEC material -- meaning the
    /// DO=false-filtered response actually fits fine. Here the unfiltered
    /// response (5 A + 20 RRSIG records) exceeds the 700-byte configured
    /// limit, but the filtered response (the same 5 A records, RRSIGs
    /// stripped) fits comfortably under it. The response actually sent to
    /// this DO=false requester must be the filtered, non-truncated one:
    /// TC=0, no DNSSEC records, and the real answer content intact -- not
    /// an unnecessary TC=1 forcing an avoidable TCP fallback round trip.
    #[tokio::test]
    async fn resolve_do_false_oversized_purely_from_dnssec_fits_after_filter() {
        reset_filter_response_for_requester_calls();

        let question = QuestionKey::new("example.com", 1, 1);
        let mut answers = (0..5)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        answers.extend((0..20).map(|_| rrsig_record("example.com", 60, A_RECORD_TYPE)));
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(
            !response.header.tc(),
            "the DO=false-filtered response fits under the payload limit and must not truncate"
        );
        assert!(!response_contains_rrsig(&outcome.response_bytes));
        assert_eq!(
            response
                .answers
                .iter()
                .filter(|record| matches!(record.record, RecordData::A(_)))
                .count(),
            5,
            "the real answer content must survive filtering intact"
        );
        assert_eq!(
            filter_response_for_requester_call_count(),
            1,
            "the filtered size has to actually be measured before truncation can be decided"
        );
    }

    /// Companion to `resolve_do_false_oversized_purely_from_dnssec_fits_after_filter`:
    /// when the DO=false-filtered response *still* doesn't fit (the excess
    /// isn't solely DNSSEC material), truncation is genuinely unavoidable
    /// and must still carry a correct TC=1 response -- question, mirrored
    /// OPT, and CD copied from the request (RFC 4035 §3.2.2), per the prior
    /// round's `truncated_response_for_query` fix. This reuses the same
    /// 200x(A+RRSIG) oversized fixture as the DO=true test above, but with
    /// DO=false and CD=1, where even the A-only filtered content (200 A
    /// records, ~3.2KB) still vastly exceeds the 700-byte limit.
    #[tokio::test]
    async fn resolve_do_false_truncates_when_filtered_response_still_exceeds_limit() {
        reset_filter_response_for_requester_calls();

        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..200)
            .flat_map(|_| {
                [
                    a_record("example.com", 60),
                    rrsig_record("example.com", 60, A_RECORD_TYPE),
                ]
            })
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns_and_checking_disabled(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(response.header.tc());
        assert!(response.answers.is_empty());
        assert_eq!(response.questions.len(), 1);
        assert!(
            response.header.cd(),
            "CD must be copied per RFC 4035 §3.2.2"
        );
        let opt = response
            .additionals
            .iter()
            .find_map(|record| match &record.record {
                RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .expect("a truncated response to an EDNS requester must still carry an OPT record");
        assert_eq!(
            opt.udp_payload_size, 700,
            "OPT must advertise this resolver's own configured UDP payload size (700), \
             not echo the requester's 4096"
        );
        assert_eq!(
            filter_response_for_requester_call_count(),
            1,
            "the filtered size still has to be measured -- it's what proves truncation \
             is genuinely unavoidable here, not just assumed from the unfiltered length"
        );
    }

    /// A DO=false response that does *not* need to truncate must still go
    /// through the filter pass exactly once, proving the DO=true skip above
    /// is specific to the truncating+DO=true case and not a blanket
    /// regression that stopped DO=false filtering from running at all.
    #[tokio::test]
    async fn resolve_non_truncating_recursive_response_still_runs_do_false_filter_pass() {
        reset_filter_response_for_requester_calls();

        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                vec![
                    a_record("example.com", 60),
                    rrsig_record("example.com", 60, A_RECORD_TYPE),
                ],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(!response.header.tc());
        assert!(!response_contains_rrsig(&outcome.response_bytes));
        assert_eq!(filter_response_for_requester_call_count(), 1);
    }

    /// Performance regression test for the second Codex review's finding:
    /// a DO=false recursive miss with nothing for the filter to remove (no
    /// RRSIG/DNSKEY/DS/NSEC/NSEC3/NSEC3PARAM at all) and unfiltered bytes
    /// that already fit the UDP payload limit must reuse the bytes
    /// `synthesize_recursive_cname_response` already built, rather than
    /// paying for a second clone-heavy `filter_response_for_requester` +
    /// full `serialize_recursive_response` pass that would just reproduce
    /// the same bytes. Contrast with
    /// `resolve_non_truncating_recursive_response_still_runs_do_false_filter_pass`
    /// immediately above, which proves the filter pass still runs exactly
    /// once when there *is* DNSSEC material to strip.
    #[tokio::test]
    async fn resolve_do_false_unsigned_response_skips_filter_pass_when_already_fits() {
        reset_filter_response_for_requester_calls();

        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(!response.header.tc());
        assert_eq!(response.answers.len(), 1);
        assert!(!response_contains_rrsig(&outcome.response_bytes));
        assert_eq!(
            filter_response_for_requester_call_count(),
            0,
            "nothing DNSSEC-shaped is present and the response already fits -- the filter \
             pass must be skipped entirely, not run only to reproduce the same bytes"
        );
    }

    /// Performance regression test for the third Codex review's finding: an
    /// *oversized* DO=false recursive miss with nothing for the filter to
    /// remove (no RRSIG/DNSKEY/DS/NSEC/NSEC3/NSEC3PARAM at all) must skip
    /// the clone-heavy `filter_response_for_requester` +
    /// `serialize_recursive_response` pass entirely rather than running it
    /// only to discover the filtered result is still oversized and fall
    /// through to truncation anyway. `filtering_would_change_response` is
    /// exact regardless of response size, so this is knowable up front.
    /// Contrast with `resolve_do_false_unsigned_response_skips_filter_pass_when_already_fits`
    /// immediately above (same no-op content, but already fits) and
    /// `resolve_do_false_truncates_when_filtered_response_still_exceeds_limit`
    /// (also truncates, but *does* need the filter pass because there's
    /// real DNSSEC material for it to strip).
    #[tokio::test]
    async fn resolve_do_false_unsigned_oversized_response_skips_filter_pass_and_truncates() {
        reset_filter_response_for_requester_calls();

        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..200)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns_and_checking_disabled(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(
            response.header.tc(),
            "200 unsigned A records at a 700-byte limit must still be oversized and truncate"
        );
        assert!(response.answers.is_empty());
        assert_eq!(response.questions.len(), 1);
        assert!(
            response.header.cd(),
            "CD must be copied per RFC 4035 §3.2.2"
        );
        let opt = response
            .additionals
            .iter()
            .find_map(|record| match &record.record {
                RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .expect("a truncated response to an EDNS requester must still carry an OPT record");
        assert_eq!(
            opt.udp_payload_size, 700,
            "OPT must advertise this resolver's own configured UDP payload size (700), \
             not echo the requester's 4096"
        );
        assert_eq!(
            filter_response_for_requester_call_count(),
            0,
            "nothing DNSSEC-shaped is present -- filtering is proven ahead of time to be a \
             no-op, so the clone+reserialize filter pass must never run even though the \
             response is oversized and ends up truncated anyway"
        );
    }

    #[tokio::test]
    async fn resolve_bounds_recursive_response_opt_payload_to_configured_udp_limit() {
        let question = QuestionKey::new("example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend_with_udp_payload_limit(transport, 700));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, true),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(
            response
                .edns
                .as_ref()
                .map(|edns| (edns.udp_payload_size, edns.dnssec_ok)),
            Some((700, true)),
            "the response OPT must advertise this resolver's own configured UDP payload \
             size (700), not an echo of the client's 4096"
        );
    }

    #[tokio::test]
    async fn resolve_truncates_fresh_recursive_response_to_default_udp_limit() {
        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..40)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(response.header.tc());
        assert!(response.answers.is_empty());
    }

    /// dig against a live rdns instance found this: a query with no EDNS OPT
    /// (so the pre-EDNS 512-byte UDP ceiling applies — see
    /// `resolve_truncates_fresh_recursive_response_to_default_udp_limit`
    /// above) sent over TCP must NOT be truncated. RFC 6891 §6.2.3: the UDP
    /// payload size has no meaning over TCP. Before the transport-aware fix,
    /// this test failed identically to the UDP test above (`tc()` set,
    /// answers dropped) because truncation was decided purely from the
    /// query's own EDNS/512-byte floor, never from which socket it arrived on.
    #[tokio::test]
    async fn resolve_does_not_truncate_tcp_sourced_response_at_default_udp_limit() {
        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..40)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new_with_observed_source(
                ObservedSourceEndpoint::tcp(
                    "192.0.2.10:5555".parse().unwrap(),
                    Some("127.0.0.1:53".parse().unwrap()),
                ),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(!response.header.tc());
        assert_eq!(response.answers.len(), 40);
    }

    /// Same scenario as `resolve_does_not_truncate_tcp_sourced_response_at_default_udp_limit`,
    /// but for a cache HIT rather than a fresh backend response — this
    /// exercises `serialize_cached_response`'s own truncation check, a
    /// separate code path from the fresh-response one above. Two TCP-sourced
    /// queries for the same question are used here: the first is a cache
    /// miss that populates the entry, the second a hit.
    #[tokio::test]
    async fn resolve_does_not_truncate_tcp_sourced_cache_hit() {
        let question = QuestionKey::new("example.com", 1, 1);
        let answers = (0..40)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(ShardedDnsCache::new(&CacheConfig {
                max_entries: 10,
                shard_count: Some(1),
                ..CacheConfig::default()
            })),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );
        let tcp_source = || {
            ObservedSourceEndpoint::tcp(
                "192.0.2.11:5555".parse().unwrap(),
                Some("127.0.0.1:53".parse().unwrap()),
            )
        };

        // First TCP query: cache miss, resolves fresh and populates the
        // TCP-namespaced cache entry.
        let first = service
            .resolve(ResolveRequest::new_with_observed_source(
                tcp_source(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;
        let first_response = Message::parse(&first.response_bytes).unwrap();
        assert!(!first_response.header.tc());
        assert_eq!(first_response.answers.len(), 40);

        // Second TCP query: cache hit, served through `serialize_cached_response`.
        let second = service
            .resolve(ResolveRequest::new_with_observed_source(
                tcp_source(),
                SystemTime::UNIX_EPOCH,
                a_query(0x4321, "example.com"),
            ))
            .await;
        let second_response = Message::parse(&second.response_bytes).unwrap();
        assert!(!second_response.header.tc());
        assert_eq!(second_response.answers.len(), 40);
    }

    /// `CacheKey` no longer partitions on payload size (see
    /// docs/plans/cache_key.md): a UDP query and a TCP query for the same
    /// question must land on the same cache entry, in either order. Proven
    /// here by scripting exactly one backend response per question — if a
    /// second query for the same question ever missed the cache, the
    /// backend transport would be asked for a response it doesn't have and
    /// the resolve would fail closed instead of serving the cached answer.
    #[tokio::test]
    async fn resolve_shares_cache_entry_between_udp_and_tcp_queries() {
        let udp_first_question = QuestionKey::new("udp-then-tcp.example.com", 1, 1);
        let tcp_first_question = QuestionKey::new("tcp-then-udp.example.com", 1, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question_with_id(
                0xbeef,
                udp_first_question,
                ResponseCode::NoError,
                vec![a_record("udp-then-tcp.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question_with_id(
                0xbeef,
                tcp_first_question,
                ResponseCode::NoError,
                vec![a_record("tcp-then-udp.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = Arc::new(recursive_backend(transport.clone()));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(ShardedDnsCache::new(&CacheConfig {
                max_entries: 10,
                shard_count: Some(1),
                ..CacheConfig::default()
            })),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );
        let udp_source = || ObservedSourceEndpoint::udp("192.0.2.11:5555".parse().unwrap(), None);
        let tcp_source = || {
            ObservedSourceEndpoint::tcp(
                "192.0.2.11:5555".parse().unwrap(),
                Some("127.0.0.1:53".parse().unwrap()),
            )
        };

        // UDP populates the entry; a same-question TCP query must hit it
        // rather than issue a second backend query.
        let udp_first = service
            .resolve(ResolveRequest::new_with_observed_source(
                udp_source(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1111, "udp-then-tcp.example.com"),
            ))
            .await;
        assert_eq!(
            Message::parse(&udp_first.response_bytes)
                .unwrap()
                .answers
                .len(),
            1
        );
        let tcp_hit = service
            .resolve(ResolveRequest::new_with_observed_source(
                tcp_source(),
                SystemTime::UNIX_EPOCH,
                a_query(0x2222, "udp-then-tcp.example.com"),
            ))
            .await;
        assert_eq!(
            Message::parse(&tcp_hit.response_bytes)
                .unwrap()
                .answers
                .len(),
            1
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 1);

        // And the reverse: TCP populates the entry, UDP hits it.
        let tcp_first = service
            .resolve(ResolveRequest::new_with_observed_source(
                tcp_source(),
                SystemTime::UNIX_EPOCH,
                a_query(0x3333, "tcp-then-udp.example.com"),
            ))
            .await;
        assert_eq!(
            Message::parse(&tcp_first.response_bytes)
                .unwrap()
                .answers
                .len(),
            1
        );
        let udp_hit = service
            .resolve(ResolveRequest::new_with_observed_source(
                udp_source(),
                SystemTime::UNIX_EPOCH,
                a_query(0x4444, "tcp-then-udp.example.com"),
            ))
            .await;
        assert_eq!(
            Message::parse(&udp_hit.response_bytes)
                .unwrap()
                .answers
                .len(),
            1
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn resolve_decodes_owned_request_bytes() {
        let request_bytes = a_query(0x1234, "example.com");
        let request_ptr = request_bytes.as_ptr();
        let codec = Arc::new(OwnedOnlyProtocolCodec::expect_owned_ptr(request_ptr));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1234, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = ResolveQuery::new(
            codec.clone(),
            upstream,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            metrics,
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                request_bytes,
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(*codec.owned_calls.lock().unwrap(), 1);
        assert_eq!(*codec.borrowed_calls.lock().unwrap(), 0);
        assert_eq!(
            *codec.received_owned_ptr.lock().unwrap(),
            Some(request_ptr as usize)
        );
    }

    #[tokio::test]
    async fn resolve_records_accepted_query_event_metric() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1234, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream, events.clone(), metrics.clone());

        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(events.events.lock().unwrap().len(), 1);
        assert!(
            metrics
                .increments
                .lock()
                .unwrap()
                .contains(&ResolverMetric::QueryEventAccepted)
        );
    }

    #[tokio::test]
    async fn resolve_isolates_disabled_query_event_sink() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1234, "example.com", 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let service = ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(DisabledEvents),
            metrics.clone(),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        assert_eq!(metrics.count(ResolverMetric::QueryEventDisabled), 1);
        assert_eq!(metrics.count(ResolverMetric::QueryEventAccepted), 0);
        assert_eq!(metrics.count(ResolverMetric::UpstreamSuccess), 1);
    }

    #[test]
    fn decoded_query_question_wire_slices_original_message_bytes() {
        let query_bytes = a_query(0x1234, "Example.COM");
        let message = Message::parse_standard_query_owned(query_bytes.clone()).unwrap();
        let decoded = DecodedQuery::new(message).unwrap();

        assert_eq!(decoded.question_wire.as_ref(), &query_bytes[12..]);
        assert_eq!(
            decoded.question_wire.as_ptr(),
            decoded.message.original_bytes.as_ptr().wrapping_add(12)
        );
    }

    #[test]
    fn standard_protocol_codec_owned_decode_reuses_input_buffer() {
        let query_bytes = a_query(0x1234, "example.com");
        let original_ptr = query_bytes.as_ptr();

        let decoded = StandardProtocolCodec::new(1232)
            .decode_query_owned(Bytes::from(query_bytes))
            .unwrap();

        assert_eq!(decoded.message.original_bytes.as_ptr(), original_ptr);
    }

    fn multi_question_a_response_with_answer(id: u16, name: &str, ttl: u32) -> Vec<u8> {
        let query = a_query(id, name);
        let mut response = a_response_with_answer(id, name, ttl);
        response[4..6].copy_from_slice(&2u16.to_be_bytes());
        response.splice(query.len()..query.len(), query[12..].iter().copied());
        response
    }

    fn nxdomain_response_with_soa(id: u16, name: &str, ttl: u32, minimum: u32) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&0x8183u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            response.push(label.len() as u8);
            response.extend_from_slice(label.as_bytes());
        }
        response.push(0);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0xc00cu16.to_be_bytes());
        response.extend_from_slice(&6u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());

        let mut rdata = Vec::new();
        for label in ["ns", "example", "com"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        for label in ["hostmaster", "example", "com"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        for value in [1, 2, 3, 4, minimum] {
            rdata.extend_from_slice(&value.to_be_bytes());
        }
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
        response
    }

    #[test]
    fn forwarded_resolution_response_exposes_backend_metadata() {
        let response = ResolutionResponse::forwarded_bytes(
            nxdomain_response_with_soa(0x1234, "example.com", 30, 120),
            SystemTime::UNIX_EPOCH,
            42,
            "forward-primary",
        );

        assert_eq!(response.response_code, Some(ResponseCode::NxDomain));
        assert!(response.response_message.is_some());
        assert_eq!(
            response.final_question,
            Some(QuestionKey::new("example.com", 1, 1))
        );
        assert!(response.answers().is_empty());
        assert_eq!(response.authorities().len(), 1);
        assert!(response.additionals().is_empty());
        assert_eq!(
            response.negative_cache,
            Some(negative_metadata(
                "example.com",
                "example.com",
                1,
                1,
                NegativeCacheKind::NxDomain,
                Duration::from_secs(30)
            ))
        );
        assert_eq!(
            response.source_credibility,
            SourceCredibility::ForwarderValidated
        );
        assert_eq!(response.backend_provenance.mode, ResolutionMode::Forward);
        assert_eq!(response.backend_provenance.generation, 42);
        assert_eq!(
            response.backend_provenance.backend_name.as_deref(),
            Some("forward-primary")
        );
        assert_eq!(
            response.cache_directive,
            ResolutionCacheDirective::Cacheable
        );
    }

    #[test]
    fn unparsed_forwarded_response_is_marked_not_cacheable() {
        let response = ResolutionResponse::forwarded_bytes(
            vec![0x12],
            SystemTime::UNIX_EPOCH,
            42,
            "forward-primary",
        );

        assert_eq!(response.response_message(), None);
        assert_eq!(
            response.cache_directive,
            ResolutionCacheDirective::DoNotCache(ResolutionNoCacheReason::ValidationIncomplete)
        );
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
            original_bytes: Vec::new().into(),
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

    fn response_message_for_question(
        question: QuestionKey,
        response_code: ResponseCode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        additionals: Vec<Record>,
        authoritative: bool,
    ) -> Message {
        response_message_for_question_with_id(
            0x1234,
            question,
            response_code,
            answers,
            authorities,
            additionals,
            authoritative,
        )
    }

    fn response_message_for_question_with_id(
        id: u16,
        question: QuestionKey,
        response_code: ResponseCode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        additionals: Vec<Record>,
        authoritative: bool,
    ) -> Message {
        let original_query =
            Message::parse_owned(query(id, &question.qname, question.qtype, question.qclass))
                .unwrap();
        let bytes = serialize_recursive_response(
            &original_query,
            response_code,
            authoritative,
            &answers,
            &authorities,
            &additionals,
        )
        .unwrap();
        Message::parse_owned(bytes).unwrap()
    }

    fn response_message_for_question_with_extra_flags(
        question: QuestionKey,
        response_code: ResponseCode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        additionals: Vec<Record>,
        authoritative: bool,
        extra_flags: u16,
    ) -> Message {
        let response = response_message_for_question(
            question,
            response_code,
            answers,
            authorities,
            additionals,
            authoritative,
        );
        let mut bytes = response.original_bytes.to_vec();
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]) | extra_flags;
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        Message::parse_owned(bytes).unwrap()
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

    fn aaaa_record(name: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: AAAA_RECORD_TYPE,
            rclass: 1,
            ttl,
            record: RecordData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        }
    }

    fn mx_record(name: &str, ttl: u32, exchange: &str) -> Record {
        Record {
            name: name.to_string(),
            rtype: 15,
            rclass: 1,
            ttl,
            record: RecordData::MX {
                preference: 10,
                exchange: exchange.to_string(),
            },
        }
    }

    fn dnskey_record(name: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: DNSKEY_RECORD_TYPE,
            rclass: 1,
            ttl,
            record: RecordData::DNSKEY {
                flags: 256,
                protocol: 3,
                algorithm: 8,
                public_key: vec![1, 2, 3, 4],
            },
        }
    }

    fn txt_record(name: &str, ttl: u32, text: &str) -> Record {
        Record {
            name: name.to_string(),
            rtype: 16,
            rclass: 1,
            ttl,
            record: RecordData::TXT(text.to_string()),
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

    fn ns_record(zone: &str, ttl: u32, ns: &str) -> Record {
        Record {
            name: zone.to_string(),
            rtype: 2,
            rclass: 1,
            ttl,
            record: RecordData::NS(ns.to_string()),
        }
    }

    fn glue_a_record(name: &str, ttl: u32, address: std::net::Ipv4Addr) -> Record {
        Record {
            name: name.to_string(),
            rtype: 1,
            rclass: 1,
            ttl,
            record: RecordData::A(address),
        }
    }

    fn dname_record(name: &str, ttl: u32, target: &str) -> Record {
        let mut bytes = Vec::new();
        write_dns_name(&mut bytes, target);
        Record {
            name: name.to_string(),
            rtype: 39,
            rclass: 1,
            ttl,
            record: RecordData::Unknown { rtype: 39, bytes },
        }
    }

    #[test]
    fn serialize_recursive_response_compresses_repeated_names() {
        let question = QuestionKey::new("collector.github.com", 1, 1);
        let original_query = Message::parse_owned(query(
            0xbeef,
            &question.qname,
            question.qtype,
            question.qclass,
        ))
        .unwrap();
        let answers = vec![
            cname_record(
                "collector.github.com",
                3600,
                "glb-db52c2cf8be544.github.com",
            ),
            a_record("glb-db52c2cf8be544.github.com", 60),
        ];

        let bytes = serialize_recursive_response(
            &original_query,
            ResponseCode::NoError,
            false,
            &answers,
            &[],
            &[],
        )
        .unwrap();

        // The CNAME's owner name repeats the question name, and the A
        // record's owner name repeats the CNAME's target: both should
        // collapse to 2-byte compression pointers (0xC0 high bits) instead
        // of being spelled out again. Matching on the high bits alone is
        // ambiguous with arbitrary payload bytes (e.g. the A record's first
        // octet, 192, is 0xC0), so also decode the pointer's 14-bit offset
        // and require it to point backward at an earlier, past-header byte
        // in the message — that's the only way a real compression pointer
        // can decode.
        let pointer_count = (0..bytes.len().saturating_sub(1))
            .filter(|&i| {
                if bytes[i] & 0xC0 != 0xC0 {
                    return false;
                }
                let offset = (((bytes[i] as u16) & 0x3F) << 8) | bytes[i + 1] as u16;
                offset >= 12 && (offset as usize) < i
            })
            .count();
        assert!(
            pointer_count >= 2,
            "expected at least 2 compression pointers, found {pointer_count} in {bytes:?}"
        );

        let round_tripped = Message::parse_owned(bytes).unwrap();
        assert_eq!(round_tripped.answers.len(), 2);
        assert_eq!(round_tripped.answers[0].name, "collector.github.com");
        assert_eq!(
            round_tripped.answers[0].record,
            RecordData::CNAME("glb-db52c2cf8be544.github.com".to_string())
        );
        assert_eq!(
            round_tripped.answers[1].name,
            "glb-db52c2cf8be544.github.com"
        );
        assert_eq!(
            round_tripped.answers[1].record,
            RecordData::A("192.0.2.10".parse().unwrap())
        );
    }

    // Regression test for RFC 4035 §3.2.2: a security-aware recursive name
    // server MUST copy the CD (checking disabled) bit from the query to
    // the corresponding response, so a validating stub that set CD=1 can
    // tell its request was honored. Before this fix,
    // `serialize_recursive_response` copied RD from the query but never
    // CD.
    #[test]
    fn serialize_recursive_response_copies_cd_bit_from_query() {
        let question = QuestionKey::new("example.com", 1, 1);

        let cd_query =
            Message::parse_owned(a_query_with_checking_disabled(0x1234, &question.qname)).unwrap();
        let cd_bytes = serialize_recursive_response(
            &cd_query,
            ResponseCode::NoError,
            false,
            &[a_record("example.com", 60)],
            &[],
            &[],
        )
        .unwrap();
        assert!(
            Message::parse_owned(cd_bytes).unwrap().header.cd(),
            "CD=1 on the query must produce CD=1 on the recursive-miss response"
        );

        let no_cd_query = Message::parse_owned(query(
            0x1234,
            &question.qname,
            question.qtype,
            question.qclass,
        ))
        .unwrap();
        let no_cd_bytes = serialize_recursive_response(
            &no_cd_query,
            ResponseCode::NoError,
            false,
            &[a_record("example.com", 60)],
            &[],
            &[],
        )
        .unwrap();
        assert!(
            !Message::parse_owned(no_cd_bytes).unwrap().header.cd(),
            "CD=0 on the query must produce CD=0 on the recursive-miss response"
        );
    }

    #[test]
    fn serialize_recursive_response_never_compresses_rfc_forbidden_rdata_names() {
        // RFC 4034 §3.1.7/§4.1.1 forbid compressing RRSIG's signer name and
        // NSEC's next domain name; RFC 2782 forbids it for SRV's target;
        // RFC 3597 §4 forbids it for RP (not an RFC 1035 well-known type).
        // Every name below deliberately shares the "example.com" suffix
        // already written for the question, so an implementation that
        // (wrongly) compresses these fields would elide it as a 2-byte
        // pointer instead of writing it out in full.
        let question = QuestionKey::new("alpha.example.com", 1, 1);
        let original_query = Message::parse_owned(query(
            0xbeef,
            &question.qname,
            question.qtype,
            question.qclass,
        ))
        .unwrap();

        // rrsig_record's signer_name defaults to "example.com".
        let rrsig = rrsig_record("alpha.example.com", 3600, 1);
        let nsec = Record {
            name: "alpha.example.com".to_string(),
            rtype: NSEC_RECORD_TYPE,
            rclass: 1,
            ttl: 3600,
            record: RecordData::NSEC {
                next_domain: "beta.example.com".to_string(),
                type_bit_maps: vec![0, 1, 0x40],
            },
        };
        let srv = Record {
            name: "_sip._tcp.example.com".to_string(),
            rtype: 33,
            rclass: 1,
            ttl: 3600,
            record: RecordData::SRV {
                priority: 10,
                weight: 20,
                port: 5060,
                target: "host.example.com".to_string(),
            },
        };
        let rp = Record {
            name: "alpha.example.com".to_string(),
            rtype: 17,
            rclass: 1,
            ttl: 3600,
            record: RecordData::RP {
                mboxdname: "admin.example.com".to_string(),
                txtdname: "info.example.com".to_string(),
            },
        };
        let answers = vec![rrsig, nsec, srv, rp];

        let bytes = serialize_recursive_response(
            &original_query,
            ResponseCode::NoError,
            false,
            &answers,
            &[],
            &[],
        )
        .unwrap();

        // "example.com" written out in full (7'example'3'com'0) should
        // appear once for the question and once more for each of the 5
        // RFC-forbidden fields above (signer_name, next_domain, target,
        // mboxdname, txtdname) — 6 total. A regression that compresses any
        // of them would drop this count.
        let uncompressed_example_com: &[u8] = b"\x07example\x03com\x00";
        let literal_count = bytes
            .windows(uncompressed_example_com.len())
            .filter(|w| *w == uncompressed_example_com)
            .count();
        assert_eq!(
            literal_count, 6,
            "expected 6 literal writes of \"example.com\" (question + 5 \
             forbidden rdata fields), found {literal_count} in {bytes:?}"
        );

        let round_tripped = Message::parse_owned(bytes).unwrap();
        assert_eq!(round_tripped.answers.len(), 4);
    }

    fn opt_record(udp_payload_size: u16) -> Record {
        Record {
            name: String::new(),
            rtype: 41,
            rclass: udp_payload_size,
            ttl: 0,
            record: RecordData::OPT(EdnsInfo {
                udp_payload_size,
                extended_rcode: 0,
                version: 0,
                flags: 0,
                dnssec_ok: false,
                options: Vec::new(),
            }),
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

    fn nsec3_record(name: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: 50,
            rclass: 1,
            ttl,
            record: RecordData::NSEC3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 1,
                salt_length: 1,
                salt: vec![0xaa],
                hash_length: 2,
                next_domain: "bbcc".to_string(),
                type_bit_maps: vec![0, 1, 0x40],
            },
        }
    }

    fn unknown_record(name: &str, rtype: u16, ttl: u32, bytes: &[u8]) -> Record {
        Record {
            name: name.to_string(),
            rtype,
            rclass: 1,
            ttl,
            record: RecordData::Unknown {
                rtype,
                bytes: bytes.to_vec(),
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

    fn negative_metadata(
        authority_zone: &str,
        covered_name: &str,
        qtype: u16,
        qclass: u16,
        kind: NegativeCacheKind,
        ttl: Duration,
    ) -> NegativeCacheMetadata {
        NegativeCacheMetadata {
            authority_zone: authority_zone.to_string(),
            covered_name: covered_name.to_string(),
            qtype,
            qclass,
            kind,
            soa_owner: authority_zone.to_string(),
            soa_minimum_ttl: ttl,
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

    /// A configured `min_positive_ttl` floor must not lift an origin TTL of
    /// exactly 0 (RFC 1035 §3.2.1: "this transaction only") into a cacheable
    /// lifetime — flooring it would keep transaction-only data servable
    /// until the floor expired and would sidestep the serve-stale TTL-0
    /// eviction guard, which only inspects entries after expiry (PR #142
    /// review finding).
    #[test]
    fn ttl_policy_floor_does_not_lift_zero_origin_ttl() {
        let policy = CacheTtlPolicy::new(
            Duration::from_secs(3600),
            Some(Duration::from_secs(120)),
            Duration::from_secs(3600),
            Some(Duration::from_secs(120)),
            None,
        );

        let zero_positive = response_message(
            ResponseCode::NoError,
            vec![a_record("example.com", 0)],
            Vec::new(),
        );
        assert_eq!(
            policy.ttl_for_response(&zero_positive).unwrap().0,
            Duration::ZERO,
            "a TTL-0 answer must stay uncacheable despite the floor"
        );

        // Same rule for the negative floor: a SOA-minimum of 0 (RFC 2308
        // §5) means "do not negatively cache", floor or no floor.
        let zero_negative = response_message(
            ResponseCode::NxDomain,
            Vec::new(),
            vec![soa_record("example.com", 0, 0)],
        );
        assert_eq!(
            policy.ttl_for_response(&zero_negative).unwrap().0,
            Duration::ZERO,
            "a SOA-minimum-0 negative answer must stay uncacheable despite the floor"
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
            Some(negative_metadata(
                "example.com",
                "example.com",
                1,
                1,
                NegativeCacheKind::NxDomain,
                Duration::from_secs(90)
            ))
        );
    }

    #[test]
    fn ttl_policy_uses_soa_minimum_when_lower_than_soa_ttl() {
        // RFC 2308 §5: negative-cache TTL is min(SOA record TTL, SOA
        // MINIMUM field) -- the sibling test above only ever exercises SOA
        // TTL < MINIMUM, where that min is a no-op. Pin down the other
        // bound too, where MINIMUM is actually the binding constraint.
        let policy = CacheTtlPolicy::default();
        let response = response_message(
            ResponseCode::NxDomain,
            Vec::new(),
            vec![soa_record("example.com", 300, 90)],
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(90));
        assert_eq!(
            metadata,
            Some(negative_metadata(
                "example.com",
                "example.com",
                1,
                1,
                NegativeCacheKind::NxDomain,
                Duration::from_secs(90)
            ))
        );
    }

    #[test]
    fn ttl_policy_rejects_negative_cache_when_soa_does_not_cover_name() {
        let policy = CacheTtlPolicy::default();
        let response = response_message(
            ResponseCode::NxDomain,
            Vec::new(),
            vec![soa_record("attacker.test", 90, 300)],
        );

        assert_eq!(policy.ttl_for_response(&response), None);
    }

    #[test]
    fn ttl_policy_preserves_negative_metadata_for_nxdomain_with_cname_answer() {
        let policy = CacheTtlPolicy::default();
        let response = response_message_for_question(
            QuestionKey::new("www.example.com", 1, 1),
            ResponseCode::NxDomain,
            vec![cname_record("www.example.com", 300, "missing.example.com")],
            vec![soa_record("example.com", 60, 120)],
            Vec::new(),
            true,
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(60));
        assert_eq!(
            metadata,
            Some(negative_metadata(
                "example.com",
                "missing.example.com",
                1,
                1,
                NegativeCacheKind::NxDomain,
                Duration::from_secs(60)
            ))
        );
    }

    #[test]
    fn ttl_policy_preserves_negative_metadata_for_nodata_with_cname_answer() {
        let policy = CacheTtlPolicy::default();
        let response = response_message_for_question(
            QuestionKey::new("www.example.com", 1, 1),
            ResponseCode::NoError,
            vec![cname_record("www.example.com", 300, "target.example.com")],
            vec![soa_record("example.com", 30, 120)],
            Vec::new(),
            true,
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(30));
        assert_eq!(
            metadata,
            Some(negative_metadata(
                "example.com",
                "target.example.com",
                1,
                1,
                NegativeCacheKind::NoData,
                Duration::from_secs(30)
            ))
        );
    }

    #[test]
    fn ttl_policy_rejects_cname_nodata_when_soa_does_not_cover_target() {
        let policy = CacheTtlPolicy::default();
        let response = response_message_for_question(
            QuestionKey::new("www.example.com", 1, 1),
            ResponseCode::NoError,
            vec![cname_record("www.example.com", 300, "target.attacker.test")],
            vec![soa_record("example.com", 30, 120)],
            Vec::new(),
            true,
        );

        assert_eq!(policy.ttl_for_response(&response), None);
    }

    #[test]
    fn ttl_policy_ignores_unrelated_cname_when_validating_negative_coverage() {
        let policy = CacheTtlPolicy::default();
        let response = response_message_for_question(
            QuestionKey::new("www.example.com", 1, 1),
            ResponseCode::NoError,
            vec![
                cname_record("www.example.com", 300, "target.attacker.test"),
                cname_record("unrelated.example.com", 300, "target.example.com"),
            ],
            vec![soa_record("example.com", 30, 120)],
            Vec::new(),
            true,
        );

        assert_eq!(policy.ttl_for_response(&response), None);
    }

    #[test]
    fn ttl_policy_treats_unrelated_answer_as_cname_nodata() {
        let policy = CacheTtlPolicy::default();
        let response = response_message_for_question(
            QuestionKey::new("www.example.com", 1, 1),
            ResponseCode::NoError,
            vec![
                cname_record("www.example.com", 300, "target.example.com"),
                a_record("unrelated.example.com", 300),
            ],
            vec![soa_record("example.com", 30, 120)],
            Vec::new(),
            true,
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(30));
        assert_eq!(
            metadata,
            Some(negative_metadata(
                "example.com",
                "target.example.com",
                1,
                1,
                NegativeCacheKind::NoData,
                Duration::from_secs(30)
            ))
        );
    }

    #[test]
    fn ttl_policy_rejects_negative_cache_when_soa_class_differs() {
        let policy = CacheTtlPolicy::default();
        let mut soa = soa_record("example.com", 30, 120);
        soa.rclass = 3;
        let response = response_message(ResponseCode::NxDomain, Vec::new(), vec![soa]);

        assert_eq!(policy.ttl_for_response(&response), None);
    }

    #[test]
    fn ttl_policy_allows_root_soa_negative_cache() {
        let policy = CacheTtlPolicy::default();
        let response = response_message(
            ResponseCode::NxDomain,
            Vec::new(),
            vec![soa_record("", 30, 120)],
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(30));
        assert_eq!(
            metadata,
            Some(negative_metadata(
                "",
                "example.com",
                1,
                1,
                NegativeCacheKind::NxDomain,
                Duration::from_secs(30)
            ))
        );
    }

    #[test]
    fn ttl_policy_preserves_negative_metadata_for_dnssec_signed_cname_nodata() {
        let policy = CacheTtlPolicy::default();
        let response = response_message_for_question(
            QuestionKey::new("www.example.com", 1, 1),
            ResponseCode::NoError,
            vec![
                cname_record("www.example.com", 300, "target.example.com"),
                rrsig_record("www.example.com", 300, CNAME_RECORD_TYPE),
            ],
            vec![soa_record("example.com", 30, 120)],
            Vec::new(),
            true,
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(30));
        assert_eq!(
            metadata,
            Some(negative_metadata(
                "example.com",
                "target.example.com",
                1,
                1,
                NegativeCacheKind::NoData,
                Duration::from_secs(30)
            ))
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
    fn ttl_policy_keeps_cname_chain_with_target_answer_positive() {
        let policy = CacheTtlPolicy::default();
        let response = response_message_for_question(
            QuestionKey::new("www.example.com", 1, 1),
            ResponseCode::NoError,
            vec![
                cname_record("www.example.com", 300, "target.example.com"),
                a_record("target.example.com", 120),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );

        let (ttl, metadata) = policy.ttl_for_response(&response).unwrap();

        assert_eq!(ttl, Duration::from_secs(120));
        assert_eq!(metadata, None);
    }

    #[test]
    fn decompose_response_for_store_trusts_ttl_policy_negative_classification() {
        // CDS (qtype 59) is DNSSEC-metadata: `has_requested_answer_for`
        // always passes `dnssec_ok = false` internally, so `ttl_for_response`
        // classifies a directly-queried CDS answer as negative (NoData) even
        // though the record is physically present in the answer section —
        // the store-decomposition logic must trust that classification
        // rather than independently re-deriving "is this a satisfying
        // answer" via its own predicate and disagreeing with it.
        let question = QuestionKey::new("example.com", 59, 1);
        let response = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            vec![unknown_record("example.com", 59, 60, &[0xaa])],
            vec![soa_record("example.com", 3600, 120)],
            Vec::new(),
            true,
        );
        let policy = CacheTtlPolicy::default();
        let (ttl, negative_meta) = policy.ttl_for_response(&response).expect("cacheable");
        assert!(
            negative_meta.is_some(),
            "ttl_for_response should classify a directly-queried CDS answer as negative"
        );

        let decomposed = decompose_response_for_store(
            &response,
            &question,
            ttl,
            negative_meta.as_ref(),
            SystemTime::UNIX_EPOCH,
            true,
            true,
        );

        assert!(
            decomposed.positive.is_empty(),
            "must not store the unsupported CDS record as a positive answer"
        );
        assert!(decomposed.negative.is_some());
    }

    #[test]
    fn decompose_response_for_store_captures_rrsigs_for_terminal_positive_answer() {
        // Regression test: `build_rrset_entry` used to hardcode `rrsigs`
        // to empty regardless of what the backend response actually
        // contained, silently dropping DNSSEC material a DO=true fetch
        // legitimately received. RRSIGs covering the terminal answer must
        // be captured into the stored `RRsetEntry`.
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let response = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            vec![
                a_record("example.com", 60),
                rrsig_record("example.com", 60, A_RECORD_TYPE),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );
        let policy = CacheTtlPolicy::default();
        let (ttl, negative_meta) = policy.ttl_for_response(&response).expect("cacheable");
        assert!(negative_meta.is_none());

        let decomposed = decompose_response_for_store(
            &response,
            &question,
            ttl,
            negative_meta.as_ref(),
            SystemTime::UNIX_EPOCH,
            true,
            true,
        );

        assert_eq!(decomposed.positive.len(), 1);
        let (_, _, _, entry) = &decomposed.positive[0];
        assert_eq!(entry.records.len(), 1);
        assert_eq!(
            entry.rrsigs.len(),
            1,
            "expected the covering RRSIG to be stored"
        );
        assert!(
            entry.dnssec_complete,
            "a DO=true-driven fetch's entry must be marked dnssec-complete"
        );
        assert!(matches!(
            entry.rrsigs[0].rdata,
            RecordData::RRSIG {
                type_covered: A_RECORD_TYPE,
                ..
            }
        ));
    }

    #[test]
    fn decompose_response_for_store_captures_rrsigs_for_cname_hop() {
        // Same regression as above, but for an intermediate CNAME hop's
        // own RRset rather than the terminal answer.
        let question = QuestionKey::new("alias.example.com", A_RECORD_TYPE, 1);
        let response = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            vec![
                cname_record("alias.example.com", 60, "target.example.com"),
                rrsig_record("alias.example.com", 60, CNAME_RECORD_TYPE),
                a_record("target.example.com", 60),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );
        let policy = CacheTtlPolicy::default();
        let (ttl, negative_meta) = policy.ttl_for_response(&response).expect("cacheable");

        let decomposed = decompose_response_for_store(
            &response,
            &question,
            ttl,
            negative_meta.as_ref(),
            SystemTime::UNIX_EPOCH,
            true,
            true,
        );

        assert_eq!(decomposed.positive.len(), 2);
        let (cname_owner, cname_qtype, _, cname_entry) = &decomposed.positive[0];
        assert_eq!(cname_owner, "alias.example.com");
        assert_eq!(*cname_qtype, CNAME_RECORD_TYPE);
        assert_eq!(
            cname_entry.rrsigs.len(),
            1,
            "expected the CNAME hop's own covering RRSIG to be stored"
        );
        let (_, _, _, terminal_entry) = &decomposed.positive[1];
        assert!(
            terminal_entry.rrsigs.is_empty(),
            "terminal answer had no covering RRSIG in the response"
        );
    }

    #[test]
    fn decompose_response_for_store_captures_negative_dnssec_material() {
        // Regression test: `build_negative_entry` used to hardcode
        // `soa_rrsig: None, proof_records: Vec::new()` regardless of what
        // the backend response actually contained. A DO=true NXDOMAIN/
        // NODATA fetch's SOA RRSIG and NSEC/NSEC3 proof records must be
        // captured into the stored `NegativeEntry`.
        let question = QuestionKey::new("nx.example.com", A_RECORD_TYPE, 1);
        let response = response_message_for_question(
            question.clone(),
            ResponseCode::NxDomain,
            Vec::new(),
            vec![
                soa_record("example.com", 3600, 120),
                rrsig_record("example.com", 3600, SOA_RECORD_TYPE),
                nsec3_record("somehash.example.com", 3600),
                rrsig_record("somehash.example.com", 3600, NSEC3_RECORD_TYPE),
            ],
            Vec::new(),
            true,
        );
        let policy = CacheTtlPolicy::default();
        let (ttl, negative_meta) = policy.ttl_for_response(&response).expect("cacheable");
        assert!(negative_meta.is_some());

        let decomposed = decompose_response_for_store(
            &response,
            &question,
            ttl,
            negative_meta.as_ref(),
            SystemTime::UNIX_EPOCH,
            true,
            true,
        );

        let (_, _, negative_entry) = decomposed.negative.expect("expected a negative entry");
        assert!(
            negative_entry.dnssec_complete,
            "a DO=true-driven fetch's negative entry must be marked dnssec-complete"
        );
        let soa_rrsig = negative_entry
            .soa_rrsig
            .expect("expected the SOA's covering RRSIG to be stored");
        assert!(matches!(
            soa_rrsig.rdata,
            RecordData::RRSIG {
                type_covered: SOA_RECORD_TYPE,
                ..
            }
        ));
        assert_eq!(
            negative_entry.proof_records.len(),
            2,
            "expected the NSEC3 record and its covering RRSIG to be stored"
        );
        assert!(
            negative_entry
                .proof_records
                .iter()
                .any(|(_, record)| matches!(record.rdata, RecordData::NSEC3 { .. }))
        );
        assert!(
            negative_entry
                .proof_records
                .iter()
                .any(|(_, record)| matches!(
                    record.rdata,
                    RecordData::RRSIG {
                        type_covered: NSEC3_RECORD_TYPE,
                        ..
                    }
                ))
        );
        // Regression assertion for the proof-record-owner bug: the NSEC3
        // proof and its RRSIG are owned by "somehash.example.com", not the
        // covered name ("nx.example.com") or the SOA zone apex
        // ("example.com") — the owner must be preserved as-is.
        assert!(
            negative_entry
                .proof_records
                .iter()
                .all(|(owner, _)| owner == "somehash.example.com"),
            "expected every proof record's owner to be preserved as \"somehash.example.com\", got {:?}",
            negative_entry
                .proof_records
                .iter()
                .map(|(owner, _)| owner.clone())
                .collect::<Vec<_>>()
        );
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
    fn query_event_v1_uses_schema_and_decision_fields() {
        let decision = ResolveDecision {
            client_ip: "192.0.2.10".parse().unwrap(),
            question: Some(QuestionKey::new("Example.COM.", 1, 1)),
            kind: ResolveDecisionKind::CacheHit,
        };
        let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let event = QueryEventV1::from_decision(
            7,
            Some(0xbeef),
            timestamp,
            &decision,
            Some(ResponseCode::NoError as u16),
            Some(QueryEventCacheResult::Hit),
            Some(Duration::from_millis(12)),
        );

        assert_eq!(event.schema_version, QueryEventV1::SCHEMA_VERSION);
        assert_eq!(event.sequence, 7);
        assert_eq!(event.request_id, Some(0xbeef));
        assert_eq!(event.timestamp, timestamp);
        assert_eq!(
            event.observed_source,
            ObservedSourceEndpoint::ip(decision.client_ip)
        );
        assert_eq!(event.original_question_name, None);
        assert_eq!(event.normalized_question, decision.question);
        assert_eq!(event.qtype, Some(1));
        assert_eq!(event.qclass, Some(1));
        assert_eq!(event.terminal_outcome, QueryEventOutcome::AllowedFromCache);
        assert_eq!(event.block_response_mode, None);
        assert_eq!(event.local_answer, None);
        assert_eq!(event.response_code, Some(ResponseCode::NoError as u16));
        assert_eq!(event.cache_result, Some(QueryEventCacheResult::Hit));
        assert_eq!(event.backend, None);
        assert_eq!(event.latency, Some(Duration::from_millis(12)));
        assert!(event.advisory_findings.is_empty());
    }

    #[test]
    fn backend_snapshot_status_reports_backend_and_root_hints() {
        let loaded_at = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let snapshot = BackendSnapshot::new(
            Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout))),
            ResolutionMode::Recursive,
            7,
            BackendHealth::Healthy,
            Some("mode:recursive;generation:7".to_string()),
        )
        .with_root_hints_status(BackendRootHintsStatus::loaded(
            "bundled",
            "root-hints:v1",
            loaded_at,
        ));

        let status = snapshot.status();

        assert_eq!(status.mode, ResolutionMode::Recursive);
        assert_eq!(status.generation, 7);
        assert_eq!(status.health, BackendHealth::Healthy);
        assert_eq!(status.dnssec_validation, DnssecValidationStatus::Disabled);
        assert_eq!(
            status.cache_namespace.as_deref(),
            Some("mode:recursive;generation:7")
        );
        let root_hints = status.root_hints.unwrap();
        assert_eq!(root_hints.source, "bundled");
        assert_eq!(root_hints.version, "root-hints:v1");
        assert_eq!(
            root_hints.age_at(loaded_at + Duration::from_secs(5)),
            Some(Duration::from_secs(5))
        );

        let metrics = Arc::new(RecordingMetrics::default());
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            snapshot,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
        );

        assert_eq!(
            metrics.backend_statuses.lock().unwrap().as_slice(),
            &[service.backend_status()]
        );

        service.publish_backend_snapshot(BackendSnapshot::new(
            Arc::new(StaticUpstream::new(Err(UpstreamError::NoBackendsAvailable))),
            ResolutionMode::Forward,
            8,
            BackendHealth::Degraded,
            Some("mode:forward;generation:8".to_string()),
        ));

        let status = service.backend_status();
        assert_eq!(status.mode, ResolutionMode::Forward);
        assert_eq!(status.generation, 8);
        assert_eq!(status.health, BackendHealth::Degraded);
        assert_eq!(status.root_hints, None);
        assert_eq!(
            metrics.backend_statuses.lock().unwrap().as_slice(),
            &[
                BackendStatus {
                    mode: ResolutionMode::Recursive,
                    generation: 7,
                    health: BackendHealth::Healthy,
                    dnssec_validation: DnssecValidationStatus::Disabled,
                    cache_namespace: Some("mode:recursive;generation:7".to_string()),
                    root_hints: Some(BackendRootHintsStatus::loaded(
                        "bundled",
                        "root-hints:v1",
                        loaded_at,
                    )),
                },
                status,
            ]
        );
    }

    #[test]
    fn response_code_from_wire_includes_edns_extended_rcode() {
        let mut response = a_query_with_edns_details(0x1234, "example.com", 1232, false, 1, 0, &[]);
        response[2] = 0x81;
        response[3] = 0x80;

        assert_eq!(response_code_from_wire(&response), Some(16));
    }

    #[test]
    fn response_code_from_wire_returns_base_rcode_when_additional_parse_fails() {
        let mut response = a_query(0x1234, "example.com");
        response[2] = 0x81;
        response[3] = 0x82;
        response[10..12].copy_from_slice(&1u16.to_be_bytes());

        assert_eq!(response_code_from_wire(&response), Some(2));
    }

    #[test]
    fn response_code_from_wire_returns_base_rcode_without_opt_additional() {
        let mut response = a_query(0x1234, "example.com");
        response[2] = 0x81;
        response[3] = 0x85;
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
        response.push(0);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[192, 0, 2, 1]);

        assert_eq!(response_code_from_wire(&response), Some(5));
    }

    #[test]
    fn response_code_from_wire_ignores_type_41_with_non_root_owner() {
        let mut response = a_query(0x1234, "example.com");
        response[2] = 0x81;
        response[3] = 0x83;
        response[10..12].copy_from_slice(&1u16.to_be_bytes());
        response.push(3);
        response.extend_from_slice(b"bad");
        response.push(0);
        response.extend_from_slice(&41u16.to_be_bytes());
        response.extend_from_slice(&1232u16.to_be_bytes());
        response.push(1);
        response.push(0);
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        assert_eq!(response_code_from_wire(&response), Some(3));
    }

    #[test]
    fn response_code_from_wire_returns_base_rcode_after_malformed_pointer_before_opt() {
        let mut response = a_query_with_edns_details(0x1234, "example.com", 1232, false, 1, 0, &[]);
        response[2] = 0x81;
        response[3] = 0x82;
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        let opt = response.split_off(response.len() - 11);
        response.extend_from_slice(&[0xc0, 0x00]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[192, 0, 2, 1]);
        response.extend_from_slice(&opt);

        assert_eq!(response_code_from_wire(&response), Some(2));
    }

    #[test]
    fn response_code_from_wire_returns_base_rcode_when_later_additional_is_malformed() {
        let mut response = a_query_with_edns_details(0x1234, "example.com", 1232, false, 1, 0, &[]);
        response[2] = 0x81;
        response[3] = 0x84;
        response[10..12].copy_from_slice(&2u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x00]);

        assert_eq!(response_code_from_wire(&response), Some(4));
    }

    #[test]
    fn block_response_config_defaults_to_uncacheable_refused() {
        let config = BlockResponseConfig::default();

        assert_eq!(config.local_rule_mode, BlockResponseMode::Refused);
        assert_eq!(config.malicious_domain_mode, BlockResponseMode::Refused);
        assert_eq!(config.invalid_domain_mode, BlockResponseMode::Refused);
        assert_eq!(config.blocked_response_ttl, 0);
        assert!(!config.cacheable_by_clients);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn block_response_config_requires_at_least_one_sinkhole_address() {
        assert_eq!(
            BlockResponseConfig::new(
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                60,
                true,
                None,
                None,
            ),
            Err(BlockResponseConfigError::MissingSinkholeAddress)
        );
        assert!(
            BlockResponseConfig::new(
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                60,
                true,
                Some(Ipv4Addr::new(192, 0, 2, 1)),
                None,
            )
            .is_ok()
        );
        assert!(
            BlockResponseConfig::new(
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                60,
                true,
                None,
                Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            )
            .is_ok()
        );
    }

    #[test]
    fn block_response_config_rejects_client_caching_for_non_sinkhole_modes() {
        assert_eq!(
            BlockResponseConfig::new(
                BlockResponseMode::NxDomain,
                BlockResponseMode::Refused,
                BlockResponseMode::Refused,
                60,
                true,
                None,
                None,
            ),
            Err(BlockResponseConfigError::ClientCachingUnsupportedForNonSinkhole)
        );
        assert!(
            BlockResponseConfig::new(
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                60,
                true,
                Some(Ipv4Addr::new(192, 0, 2, 1)),
                Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            )
            .is_ok()
        );
    }

    #[test]
    fn block_response_config_allows_internal_ttl_for_uncacheable_negative_modes() {
        assert!(
            BlockResponseConfig::new(
                BlockResponseMode::NxDomain,
                BlockResponseMode::Refused,
                BlockResponseMode::Refused,
                60,
                false,
                None,
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn configured_response_factory_selects_block_mode_by_reason() {
        let query = StandardProtocolCodec::new(1232)
            .decode_query(&a_query(0x1234, "blocked.example"))
            .unwrap();
        let factory = ConfiguredResponseFactory::new(
            BlockResponseConfig::new(
                BlockResponseMode::NxDomain,
                BlockResponseMode::NoData,
                BlockResponseMode::Refused,
                0,
                false,
                None,
                None,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            response_code_from_wire(&factory.blocked(
                &query,
                &PolicyBlock {
                    reason: BlockReason::LocalRule,
                    rule_id: Some("rule-1".to_string()),
                },
                1232,
            )),
            Some(ResponseCode::NxDomain as u16)
        );
        let nodata = Message::parse(&factory.blocked(
            &query,
            &PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("source-1".to_string()),
            },
            1232,
        ))
        .unwrap();
        assert_eq!(nodata.header.r_code(), ResponseCode::NoError as u8);
        assert!(nodata.answers.is_empty());
    }

    #[test]
    fn configured_response_factory_builds_family_specific_sinkholes() {
        let factory = ConfiguredResponseFactory::new(
            BlockResponseConfig::new(
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                60,
                true,
                Some(Ipv4Addr::new(192, 0, 2, 1)),
                Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            )
            .unwrap(),
        )
        .unwrap();
        let a_query = StandardProtocolCodec::new(1232)
            .decode_query(&a_query(0x1234, "blocked.example"))
            .unwrap();
        let aaaa_query = StandardProtocolCodec::new(1232)
            .decode_query(&aaaa_query(0x1234, "blocked.example"))
            .unwrap();

        let a_response = Message::parse(&factory.blocked(
            &a_query,
            &PolicyBlock {
                reason: BlockReason::LocalRule,
                rule_id: Some("rule-1".to_string()),
            },
            1232,
        ))
        .unwrap();
        assert_eq!(a_response.answers.len(), 1);
        assert_eq!(a_response.answers[0].ttl, 60);
        assert_eq!(
            a_response.answers[0].record,
            RecordData::A(Ipv4Addr::new(192, 0, 2, 1))
        );

        let aaaa_response = Message::parse(&factory.blocked(
            &aaaa_query,
            &PolicyBlock {
                reason: BlockReason::LocalRule,
                rule_id: Some("rule-1".to_string()),
            },
            1232,
        ))
        .unwrap();
        assert_eq!(aaaa_response.answers.len(), 1);
        assert_eq!(
            aaaa_response.answers[0].record,
            RecordData::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn configured_response_factory_refuses_non_address_sinkhole_queries() {
        let factory = ConfiguredResponseFactory::new(
            BlockResponseConfig::new(
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                BlockResponseMode::Sinkhole,
                60,
                true,
                Some(Ipv4Addr::new(192, 0, 2, 1)),
                Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            )
            .unwrap(),
        )
        .unwrap();
        let mx_query = StandardProtocolCodec::new(1232)
            .decode_query(&query(0x1234, "blocked.example", 15, 1))
            .unwrap();

        assert_eq!(
            response_code_from_wire(&factory.blocked(
                &mx_query,
                &PolicyBlock {
                    reason: BlockReason::LocalRule,
                    rule_id: Some("rule-1".to_string()),
                },
                1232,
            )),
            Some(ResponseCode::Refused as u16)
        );
    }

    #[tokio::test]
    async fn resolve_forwards_valid_query_to_upstream() {
        let response = a_response_with_answer(0xabcd, "Example.COM", 60);
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(response.clone()))));
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
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(
                recorded_events[0].terminal_outcome,
                QueryEventOutcome::AllowedFromBackend
            );
            assert_eq!(
                recorded_events[0].original_question_name.as_deref(),
                Some("Example.COM")
            );
            assert_eq!(
                recorded_events[0]
                    .normalized_question
                    .as_ref()
                    .map(|question| question.qname.as_str()),
                Some("example.com")
            );
            assert_eq!(
                recorded_events[0].response_code,
                Some(ResponseCode::NoError as u16)
            );
            assert_eq!(
                recorded_events[0].cache_result,
                Some(QueryEventCacheResult::Miss)
            );
        }
        assert!(
            metrics
                .increments
                .lock()
                .unwrap()
                .contains(&ResolverMetric::UpstreamSuccess)
        );
    }

    #[tokio::test]
    async fn resolve_applies_local_deny_policy_before_cache_or_backend() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "blocked.example", 60),
        ))));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let policy = Arc::new(LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
            "rule-1",
            ClientSelector::exact_ip("192.0.2.10".parse().unwrap()),
            DomainSelector::exact("blocked.example").unwrap(),
            true,
        )]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            policy,
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            metrics.clone(),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "Blocked.Example"),
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::Blocked(PolicyBlock {
                reason: BlockReason::LocalRule,
                rule_id: Some("rule-1".to_string()),
            })
        );
        assert_eq!(outcome.decision.question.unwrap().qname, "blocked.example");
        assert_eq!(upstream.requests.lock().unwrap().len(), 0);
        assert_eq!(cache.lookups.lock().unwrap().len(), 0);
        assert_eq!(cache.stores.lock().unwrap().len(), 0);
        assert_eq!(
            response_code_from_wire(&outcome.response_bytes),
            Some(ResponseCode::Refused as u16)
        );
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(
                recorded_events[0].terminal_outcome,
                QueryEventOutcome::Blocked(BlockReason::LocalRule)
            );
            assert_eq!(recorded_events[0].cache_result, None);
            assert_eq!(
                recorded_events[0].original_question_name.as_deref(),
                Some("Blocked.Example")
            );
        }
        assert!(
            !metrics
                .increments
                .lock()
                .unwrap()
                .contains(&ResolverMetric::QueryAllowed)
        );
        assert_eq!(metrics.count(ResolverMetric::QueryBlocked), 1);
    }

    #[tokio::test]
    async fn resolve_logs_block_response_mode_separately_from_policy_reason() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "blocked.example", 60),
        ))));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let events = Arc::new(RecordingEvents::default());
        let policy = Arc::new(LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
            "rule-1",
            ClientSelector::exact_ip("192.0.2.10".parse().unwrap()),
            DomainSelector::exact("blocked.example").unwrap(),
            true,
        )]));
        let responses = Arc::new(
            ConfiguredResponseFactory::new(
                BlockResponseConfig::new(
                    BlockResponseMode::NoData,
                    BlockResponseMode::Refused,
                    BlockResponseMode::Refused,
                    0,
                    false,
                    None,
                    None,
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            policy,
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            responses,
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "blocked.example"),
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.r_code(), ResponseCode::NoError as u8);
        assert!(response.answers.is_empty());
        assert_eq!(upstream.requests.lock().unwrap().len(), 0);
        assert_eq!(cache.lookups.lock().unwrap().len(), 0);
        let recorded_events = events.events.lock().unwrap();
        assert_eq!(recorded_events.len(), 1);
        assert_eq!(
            recorded_events[0].terminal_outcome,
            QueryEventOutcome::Blocked(BlockReason::LocalRule)
        );
        assert_eq!(
            recorded_events[0].block_response_mode,
            Some(BlockResponseMode::NoData)
        );
    }

    #[tokio::test]
    async fn resolve_logs_nodata_mode_for_sinkhole_family_without_configured_address() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "blocked.example", 60),
        ))));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let events = Arc::new(RecordingEvents::default());
        let policy = Arc::new(LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
            "rule-1",
            ClientSelector::exact_ip("192.0.2.10".parse().unwrap()),
            DomainSelector::exact("blocked.example").unwrap(),
            true,
        )]));
        let responses = Arc::new(
            ConfiguredResponseFactory::new(
                BlockResponseConfig::new(
                    BlockResponseMode::Sinkhole,
                    BlockResponseMode::Refused,
                    BlockResponseMode::Refused,
                    0,
                    false,
                    Some("198.51.100.1".parse().unwrap()),
                    None,
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            policy,
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            responses,
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                aaaa_query(0x1234, "blocked.example"),
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.r_code(), ResponseCode::NoError as u8);
        assert!(response.answers.is_empty());
        let recorded_events = events.events.lock().unwrap();
        assert_eq!(recorded_events.len(), 1);
        assert_eq!(
            recorded_events[0].block_response_mode,
            Some(BlockResponseMode::NoData)
        );
    }

    #[tokio::test]
    async fn chaos_lookup_answers_version_bind_when_enabled() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let chaos = crate::config::ChaosConfig {
            enabled: true,
            version_bind: "rdns-test-build".to_string(),
        };
        let service = ResolveQuery::with_cache(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache,
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        )
        .with_chaos_config(chaos);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                query(0x2222, "version.bind", TXT_RECORD_TYPE, CHAOS_CLASS),
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.r_code(), ResponseCode::NoError as u8);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rclass, CHAOS_CLASS);
        assert_eq!(
            response.answers[0].record,
            RecordData::TXT("rdns-test-build".to_string())
        );
        assert!(
            upstream.requests.lock().unwrap().is_empty(),
            "an enabled chaos answer must not touch the backend"
        );
    }

    #[tokio::test]
    async fn chaos_lookup_answers_version_bind_with_rdns_by_default() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        // No `with_chaos_config` call -- exercises the constructor default.
        let service = ResolveQuery::with_cache(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache,
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                query(0x2223, "version.bind", TXT_RECORD_TYPE, CHAOS_CLASS),
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.r_code(), ResponseCode::NoError as u8);
        assert_eq!(
            response.answers.first().map(|answer| &answer.record),
            Some(&RecordData::TXT("rdns".to_string())),
            "chaos support is on by default, answering \"rdns\""
        );
        assert!(
            upstream.requests.lock().unwrap().is_empty(),
            "a default-enabled chaos answer must not touch the backend"
        );
    }

    #[tokio::test]
    async fn chaos_lookup_falls_through_to_backend_when_explicitly_disabled() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x2223, "version.bind", 60),
        ))));
        let chaos = crate::config::ChaosConfig {
            enabled: false,
            ..crate::config::ChaosConfig::default()
        };
        let service = ResolveQuery::with_cache(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache,
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        )
        .with_chaos_config(chaos);

        service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                query(0x2223, "version.bind", TXT_RECORD_TYPE, CHAOS_CLASS),
            ))
            .await;

        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            1,
            "explicitly disabled chaos config must resolve version.bind normally"
        );
    }

    #[tokio::test]
    async fn chaos_lookup_ignores_non_chaos_class_even_when_enabled() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x2224, "version.bind", 60),
        ))));
        let chaos = crate::config::ChaosConfig {
            enabled: true,
            ..crate::config::ChaosConfig::default()
        };
        let service = ResolveQuery::with_cache(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache,
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        )
        .with_chaos_config(chaos);

        // Same qname/qtype as the CHAOS case, but class IN (1) -- must not
        // be mistaken for the CHAOS-class version.bind query.
        service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                query(0x2224, "version.bind", TXT_RECORD_TYPE, 1),
            ))
            .await;

        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            1,
            "class IN version.bind must resolve normally, not hit the CHAOS answer"
        );
    }

    #[test]
    fn local_dns_entry_validation_requires_addresses_and_public_acknowledgement() {
        let empty = LocalDnsEntry::new(
            DomainName::parse("host.example").unwrap(),
            Vec::new(),
            Vec::new(),
            120,
            true,
        );
        assert_eq!(
            empty.validate(false),
            Err(LocalDnsEntryValidationError::NoAddresses)
        );

        let public = LocalDnsEntry::new(
            DomainName::parse("host.example").unwrap(),
            vec![Ipv4Addr::new(8, 8, 8, 8)],
            Vec::new(),
            120,
            true,
        );
        assert_eq!(
            public.validate(false),
            Err(LocalDnsEntryValidationError::PublicAddressRequiresAcknowledgement)
        );
        assert_eq!(
            public.validate(true),
            Ok(LocalDnsEntryValidation {
                warnings: Vec::new(),
            })
        );
        let zero_ttl = LocalDnsEntry::new(
            DomainName::parse("host.example").unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 7)],
            Vec::new(),
            0,
            true,
        );
        assert_eq!(
            zero_ttl.validate(false),
            Err(LocalDnsEntryValidationError::TtlTooLow)
        );
        let excessive_ttl = LocalDnsEntry::new(
            DomainName::parse("host.example").unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 7)],
            Vec::new(),
            MAX_LOCAL_DNS_TTL + 1,
            true,
        );
        assert_eq!(
            excessive_ttl.validate(false),
            Err(LocalDnsEntryValidationError::TtlTooHigh {
                max: MAX_LOCAL_DNS_TTL,
            })
        );
    }

    #[test]
    fn local_dns_entry_validation_accepts_local_addresses_and_warns_for_mdns_suffix() {
        let entry = LocalDnsEntry::new(
            DomainName::parse("dev1.local").unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 7)],
            vec![Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 7)],
            120,
            true,
        );

        assert_eq!(
            entry.validate(false),
            Ok(LocalDnsEntryValidation {
                warnings: vec![LocalDnsEntryWarning::ReservedMdnsSuffix],
            })
        );
    }

    #[test]
    fn local_dns_entries_match_exact_enabled_address_queries_only() {
        let enabled = LocalDnsEntry::new(
            DomainName::parse("host.example").unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 7)],
            Vec::new(),
            120,
            true,
        );
        let disabled = LocalDnsEntry::new(
            DomainName::parse("disabled.example").unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 8)],
            Vec::new(),
            120,
            false,
        );
        let entries = InMemoryLocalDnsEntries::new(vec![enabled.clone(), disabled]);

        assert_eq!(
            entries.lookup(&QuestionKey::new("Host.Example.", A_RECORD_TYPE, 1)),
            LocalDnsLookup::Answer(enabled.clone())
        );
        assert_eq!(
            entries.lookup(&QuestionKey::new("host.example", AAAA_RECORD_TYPE, 1)),
            LocalDnsLookup::NoData(enabled)
        );
        assert_eq!(
            entries.lookup(&QuestionKey::new("child.host.example", A_RECORD_TYPE, 1)),
            LocalDnsLookup::NoMatch
        );
        assert_eq!(
            entries.lookup(&QuestionKey::new("disabled.example", A_RECORD_TYPE, 1)),
            LocalDnsLookup::NoMatch
        );
        assert_eq!(
            entries.lookup(&QuestionKey::new("host.example", 15, 1)),
            LocalDnsLookup::NoMatch
        );
        assert_eq!(
            entries.lookup(&QuestionKey::new("host.example", A_RECORD_TYPE, 3)),
            LocalDnsLookup::NoMatch
        );
    }

    #[tokio::test]
    async fn resolve_answers_exact_local_dns_entry_before_cache_or_backend() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "host.example", 60),
        ))));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let events = Arc::new(RecordingEvents::default());
        let local_entries = Arc::new(InMemoryLocalDnsEntries::new(vec![
            LocalDnsEntry::new(
                DomainName::parse("host.example").unwrap(),
                vec![Ipv4Addr::new(192, 0, 2, 44), Ipv4Addr::new(192, 0, 2, 45)],
                vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 44)],
                120,
                true,
            )
            .with_metadata("entry-1", 7),
        ]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            Arc::new(NoopPolicyEvaluator),
            local_entries,
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "Host.Example"),
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::LocalAnswer(LocalAnswerMetadata {
                entry_id: Some("entry-1".to_string()),
                generation: 7,
                family: LocalAnswerFamily::A,
                ttl: 120,
            })
        );
        assert_eq!(upstream.requests.lock().unwrap().len(), 0);
        assert_eq!(cache.lookups.lock().unwrap().len(), 0);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.answers.len(), 2);
        assert_eq!(response.answers[0].ttl, 120);
        assert_eq!(
            response
                .answers
                .iter()
                .map(|record| record.record.clone())
                .collect::<Vec<_>>(),
            vec![
                RecordData::A(Ipv4Addr::new(192, 0, 2, 44)),
                RecordData::A(Ipv4Addr::new(192, 0, 2, 45)),
            ]
        );
        let recorded_events = events.events.lock().unwrap();
        assert_eq!(
            recorded_events[0].terminal_outcome,
            QueryEventOutcome::AllowedFromLocal
        );
        assert_eq!(
            recorded_events[0].local_answer,
            Some(LocalAnswerMetadata {
                entry_id: Some("entry-1".to_string()),
                generation: 7,
                family: LocalAnswerFamily::A,
                ttl: 120,
            })
        );
    }

    /// Section 05 code-review finding: `local_entry_response` and
    /// everything it calls are explicitly out of scope for cookie-echoing
    /// (statically-configured local entries, not the recursive-miss path
    /// this section targets) -- its untruncated branch never echoes a
    /// cookie (`build_a_answers_response` builds via the cookie-unaware
    /// `message_edns_opt_record`), so its truncation fallback must not
    /// become the one path that suddenly does, just because it now shares
    /// a helper (`mirrored_client_opt_record`, not `_with_cookie`) that was
    /// widened for the recursive-miss path elsewhere in this section.
    #[tokio::test]
    async fn resolve_truncated_local_entry_response_omits_cookie_option() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let events = Arc::new(RecordingEvents::default());
        // Enough addresses that the unfiltered A response exceeds the tiny
        // configured UDP payload size below, forcing the truncation branch.
        let addresses: Vec<Ipv4Addr> = (0..10).map(|i| Ipv4Addr::new(192, 0, 2, i)).collect();
        let local_entries = Arc::new(InMemoryLocalDnsEntries::new(vec![LocalDnsEntry::new(
            DomainName::parse("host.example").unwrap(),
            addresses,
            Vec::new(),
            120,
            true,
        )]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(60)),
            cache,
            Arc::new(NoopPolicyEvaluator),
            local_entries,
            CacheTtlPolicy::default(),
            upstream,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            Arc::new(RecordingMetrics::default()),
        )
        .with_cookie_secret(Arc::new(CookieSecret::generate()));

        let mut cookie_option = vec![0u8, 10, 0, 8];
        cookie_option.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let query = a_query_with_edns_options(0x1234, "host.example", 4096, false, &cookie_option);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                query,
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(
            response.header.tc(),
            "sanity check: the local entry's unfiltered answers must exceed \
             the tiny configured UDP payload size"
        );
        let opt = response
            .additionals
            .iter()
            .find(|record| matches!(record.record, RecordData::OPT(_)))
            .expect("truncated response to an EDNS requester must still carry an OPT record");
        let RecordData::OPT(edns) = &opt.record else {
            unreachable!();
        };
        assert!(
            edns.options.is_empty(),
            "local-entry responses are out of scope for cookie-echoing -- the \
             truncation fallback must stay cookie-unaware just like the \
             untruncated branch"
        );
    }

    // Needs a real second OS thread: the reload task blocks inside a std
    // (non-async-aware) RwLock::write() while this task still holds the
    // paired read lock, so a single-thread runtime would deadlock instead
    // of letting this task run concurrently to drop its guard. Holding the
    // read guard across the yield below is the point of the test (it
    // proves the writer can't proceed until this guard drops), hence the
    // clippy allow.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publish_reload_blocks_concurrent_query_until_both_fields_are_swapped() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "host.example", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let service = Arc::new(ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            Arc::new(NoopPolicyEvaluator),
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            Arc::new(RecordingMetrics::default()),
        ));

        // Hold the same read lock a query holds while capturing its
        // backend/local-entries pair, simulating a query in flight.
        let in_flight_query_guard = service
            .reload_gate
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let reload_service = Arc::clone(&service);
        let new_backend = BackendSnapshot::forwarding(upstream.clone(), 7);
        let new_local_entries: Arc<dyn LocalDnsEntries> =
            Arc::new(InMemoryLocalDnsEntries::new(vec![LocalDnsEntry::new(
                DomainName::parse("host.example").unwrap(),
                vec![Ipv4Addr::new(192, 0, 2, 44)],
                Vec::new(),
                120,
                true,
            )]));
        // The task proves its own contention before signaling, rather than
        // the test asserting contention from outside (which would only show
        // the guard blocks writers in general, not that this task hit it):
        // it spins on try_write() until it observes Err itself, then signals
        // and immediately (no intervening await) makes the real blocking
        // write call via publish_reload. That ordering guarantees the
        // is_finished() check below can't pass merely because the task
        // hasn't been polled far enough yet.
        let (about_to_reload_tx, about_to_reload_rx) = tokio::sync::oneshot::channel::<()>();
        let reload_task = tokio::spawn(async move {
            while reload_service.reload_gate.try_write().is_ok() {
                tokio::task::yield_now().await;
            }
            let _ = about_to_reload_tx.send(());
            reload_service.publish_reload(new_backend, new_local_entries);
        });

        about_to_reload_rx.await.unwrap();
        assert!(
            !reload_task.is_finished(),
            "publish_reload must block while a query holds the paired-read lock, \
             otherwise a query could read one field before the swap and the other after"
        );

        drop(in_flight_query_guard);
        reload_task.await.unwrap();

        // Once the reload completes, both fields must have swapped together:
        // the backend generation is the new one, and the local entry (which
        // only exists in the new config) now answers instead of forwarding.
        assert_eq!(service.backend_status().generation, 7);
        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x2222, "host.example"),
            ))
            .await;
        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::LocalAnswer(LocalAnswerMetadata {
                entry_id: None,
                generation: 0,
                family: LocalAnswerFamily::A,
                ttl: 120,
            })
        );
        assert_eq!(upstream.requests.lock().unwrap().len(), 0);
    }

    /// Test-only cache whose `sweep_stale_namespace` blocks for a
    /// controllable duration, standing in for a large real namespace
    /// sweep. Used by
    /// `publish_reload_does_not_block_concurrent_resolve_during_namespace_sweep`
    /// below to deterministically prove `resolve()` isn't blocked behind
    /// the sweep, without needing to seed thousands of real cache entries
    /// (whose scan time would be too fast, and too dependent on machine
    /// speed, to assert on reliably in CI).
    struct SlowSweepCache {
        sweep_delay: Duration,
    }

    impl DomainDnsCache for SlowSweepCache {
        fn lookup_chain(
            &self,
            _qname: &str,
            _qtype: u16,
            _qclass: u16,
            _dnssec_ok: bool,
            _epoch: u64,
            _max_chain_depth: u8,
            _now: SystemTime,
            _refresh_config: &crate::config::RefreshConfig,
        ) -> ChainLookup {
            ChainLookup::Miss
        }

        fn store_response(&self, _decomposed: DecomposedResponse, _epoch: u64) {}

        fn sweep_stale_namespace(&self, _current_epoch: u64) {
            std::thread::sleep(self.sweep_delay);
        }

        fn domain_count(&self) -> usize {
            0
        }

        fn capacity(&self) -> usize {
            0
        }
    }

    // Regression test for the bug where `publish_reload` held `reload_gate`
    // (a `std::sync::RwLock`, so a writer blocks every new reader) across
    // the full namespace sweep, stalling every concurrent `resolve()` call
    // for the sweep's duration. Needs a real second OS thread for the same
    // reason `publish_reload_blocks_concurrent_query_until_both_fields_are_swapped`
    // does: `publish_reload` is a blocking (non-async-aware) call.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn publish_reload_does_not_block_concurrent_resolve_during_namespace_sweep() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "host.example", 60),
        ))));
        let cache = Arc::new(SlowSweepCache {
            sweep_delay: Duration::from_millis(250),
        });
        let events = Arc::new(RecordingEvents::default());
        let service = Arc::new(ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache,
            Arc::new(NoopPolicyEvaluator),
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            Arc::new(RecordingMetrics::default()),
        ));

        // `BackendSnapshot::forwarding` always sets a real `cache_namespace`,
        // so this reload actually triggers the (slow) sweep.
        let new_backend = BackendSnapshot::forwarding(upstream.clone(), 7);
        let reload_service = Arc::clone(&service);
        let reload_task = tokio::spawn(async move {
            reload_service.publish_reload(new_backend, Arc::new(NoopLocalDnsEntries));
        });

        // Give the reload task time to acquire+release `reload_gate` and
        // enter the slow sweep before starting the concurrent resolve.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !reload_task.is_finished(),
            "the reload should still be inside its 250ms sweep at this point"
        );

        let resolve_started = Instant::now();
        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x2222, "host.example"),
            ))
            .await;
        let resolve_elapsed = resolve_started.elapsed();

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert!(
            resolve_elapsed < Duration::from_millis(150),
            "resolve() must not be blocked behind publish_reload's namespace sweep \
             (reload_gate must be released before the sweep runs); took {resolve_elapsed:?}"
        );
        assert!(
            !reload_task.is_finished(),
            "resolve() finishing quickly must not itself be evidence the sweep already \
             finished — the sweep (250ms sleep) should still be running"
        );

        reload_task.await.unwrap();
    }

    #[tokio::test]
    async fn publish_local_entries_updates_lookups_without_restarting_resolver() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "host.example", 60),
        ))));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let events = Arc::new(RecordingEvents::default());
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            Arc::new(NoopPolicyEvaluator),
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            Arc::new(RecordingMetrics::default()),
        );

        let before = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "host.example"),
            ))
            .await;
        assert_ne!(
            before.decision.kind,
            ResolveDecisionKind::LocalAnswer(LocalAnswerMetadata {
                entry_id: None,
                generation: 0,
                family: LocalAnswerFamily::A,
                ttl: 120,
            })
        );
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);

        service.publish_local_entries(Arc::new(InMemoryLocalDnsEntries::new(vec![
            LocalDnsEntry::new(
                DomainName::parse("host.example").unwrap(),
                vec![Ipv4Addr::new(192, 0, 2, 44)],
                Vec::new(),
                120,
                true,
            ),
        ])));

        let after = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1235, "host.example"),
            ))
            .await;

        assert_eq!(
            after.decision.kind,
            ResolveDecisionKind::LocalAnswer(LocalAnswerMetadata {
                entry_id: None,
                generation: 0,
                family: LocalAnswerFamily::A,
                ttl: 120,
            })
        );
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        let response = Message::parse(&after.response_bytes).unwrap();
        assert_eq!(
            response.answers[0].record,
            RecordData::A(Ipv4Addr::new(192, 0, 2, 44))
        );
    }

    #[tokio::test]
    async fn resolve_local_dns_uses_entry_addresses_not_sinkhole_configuration() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "host.example", 60),
        ))));
        let local_entries = Arc::new(InMemoryLocalDnsEntries::new(vec![LocalDnsEntry::new(
            DomainName::parse("host.example").unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 7)],
            Vec::new(),
            120,
            true,
        )]));
        let responses = Arc::new(
            ConfiguredResponseFactory::new(
                BlockResponseConfig::new(
                    BlockResponseMode::Sinkhole,
                    BlockResponseMode::Sinkhole,
                    BlockResponseMode::Sinkhole,
                    60,
                    true,
                    Some(Ipv4Addr::new(192, 0, 2, 1)),
                    Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(RecordingCache::with_lookup(ChainLookup::Miss)),
            Arc::new(NoopPolicyEvaluator),
            local_entries,
            CacheTtlPolicy::default(),
            upstream.clone(),
            responses,
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "host.example"),
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(
            response.answers[0].record,
            RecordData::A(Ipv4Addr::new(10, 0, 0, 7))
        );
        assert_eq!(upstream.requests.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn resolve_returns_nodata_for_local_entry_missing_requested_family() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "host.example", 60),
        ))));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let local_entries = Arc::new(InMemoryLocalDnsEntries::new(vec![
            LocalDnsEntry::new(
                DomainName::parse("host.example").unwrap(),
                vec![Ipv4Addr::new(192, 0, 2, 44)],
                Vec::new(),
                120,
                true,
            )
            .with_metadata("entry-2", 8),
        ]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            Arc::new(NoopPolicyEvaluator),
            local_entries,
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                aaaa_query(0x1234, "host.example"),
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::LocalAnswer(LocalAnswerMetadata {
                entry_id: Some("entry-2".to_string()),
                generation: 8,
                family: LocalAnswerFamily::NoDataAaaa,
                ttl: 120,
            })
        );
        assert_eq!(upstream.requests.lock().unwrap().len(), 0);
        assert_eq!(cache.lookups.lock().unwrap().len(), 0);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.r_code(), ResponseCode::NoError as u8);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn resolve_applies_policy_before_local_dns_entries() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "host.example", 60),
        ))));
        let policy = Arc::new(LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
            "rule-1",
            ClientSelector::exact_ip("192.0.2.10".parse().unwrap()),
            DomainSelector::exact("host.example").unwrap(),
            true,
        )]));
        let local_entries = Arc::new(InMemoryLocalDnsEntries::new(vec![LocalDnsEntry::new(
            DomainName::parse("host.example").unwrap(),
            vec![Ipv4Addr::new(192, 0, 2, 44)],
            Vec::new(),
            120,
            true,
        )]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(RecordingCache::with_lookup(ChainLookup::Miss)),
            policy,
            local_entries,
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "host.example"),
            ))
            .await;

        assert!(matches!(
            outcome.decision.kind,
            ResolveDecisionKind::Blocked(PolicyBlock {
                reason: BlockReason::LocalRule,
                ..
            })
        ));
        assert_eq!(
            response_code_from_wire(&outcome.response_bytes),
            Some(ResponseCode::Refused as u16)
        );
        assert_eq!(upstream.requests.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn resolve_blocks_upstream_response_with_malicious_cname_target() {
        let question = QuestionKey::new("alias.example", A_RECORD_TYPE, 1);
        let response_message = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            vec![
                cname_record("alias.example", 60, "target.malicious.example"),
                a_record("target.malicious.example", 60),
            ],
            Vec::new(),
            Vec::new(),
            false,
        );
        let response_bytes = response_message.original_bytes.to_vec();
        let upstream = Arc::new(StaticUpstream::new(Ok(
            ResolutionResponse::forwarded_message(
                response_bytes,
                response_message,
                SystemTime::UNIX_EPOCH,
                0,
                "test-forwarder",
            ),
        )));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let policy = Arc::new(MaliciousDomainPolicyEvaluator::new(vec![
            MaliciousDomainRule::new(
                "malware-feed",
                DomainSelector::subtree("malicious.example").unwrap(),
                true,
            ),
        ]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            policy,
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(ConfiguredResponseFactory::default()),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            metrics.clone(),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "alias.example"),
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::Blocked(PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("malware-feed".to_string()),
            })
        );
        assert_eq!(
            response_code_from_wire(&outcome.response_bytes),
            Some(ResponseCode::Refused as u16)
        );
        assert_eq!(cache.lookups.lock().unwrap().len(), 1);
        assert_eq!(cache.stores.lock().unwrap().len(), 0);
        let recorded_events = events.events.lock().unwrap();
        assert_eq!(
            recorded_events[0].terminal_outcome,
            QueryEventOutcome::Blocked(BlockReason::MaliciousDomain)
        );
        assert_eq!(
            recorded_events[0].block_response_mode,
            Some(BlockResponseMode::Refused)
        );
        assert_eq!(metrics.count(ResolverMetric::QueryBlocked), 1);
        assert_eq!(metrics.count(ResolverMetric::QueryAllowed), 0);
    }

    fn stored_record_from(record: &Record) -> StoredRecord {
        StoredRecord {
            rtype: record.rtype,
            rclass: record.rclass,
            ttl_at_store: record.ttl,
            rdata: record.record.clone(),
        }
    }

    fn seed_rrset_entry(record: &Record, ttl: Duration, now: SystemTime, epoch: u64) -> RRsetEntry {
        RRsetEntry {
            records: vec![stored_record_from(record)],
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl: ttl,
            stored_at: now,
            expires_at: now + ttl,
            dnssec_state: Default::default(),
            cache_epoch: epoch,
            dnssec_complete: true,
            authoritative: false,
        }
    }

    // Refresh fetch + store tests: section-06-refresh-fetch-store.

    /// A `RefreshConfig` tuned so any domain that's ever been queried once
    /// (bucket exists, level >= 1) is immediately "hot" (`hot_threshold_fraction
    /// = 0.0`), and any live entry is always within the lead window
    /// (`lead_ratio = 1.0`, `min_lead = 0` -> lead == original_ttl, and
    /// `remaining_ttl` can never exceed `original_ttl`), with no eligibility
    /// floor. Used to make a freshly-stored entry trivially eligible for
    /// refresh without needing to wait for it to actually near expiry.
    fn permissive_refresh_config() -> RefreshConfig {
        RefreshConfig {
            enabled: true,
            bucket_capacity: 10,
            leak_rate: LeakRate {
                units: 1,
                per: Duration::from_secs(3600),
            },
            hit_increment: 1,
            hot_threshold_fraction: 0.0,
            lead_ratio: 1.0,
            min_lead: Duration::from_secs(0),
            eligibility_floor: Duration::from_secs(0),
            worker_count: 4,
            channel_capacity: 256,
        }
    }

    fn refresh_job(domain: &str, qtype: u16, qclass: u16) -> RefreshJob {
        RefreshJob {
            domain: domain.to_string(),
            qtype,
            qclass,
        }
    }

    /// Warms `domain`'s popularity bucket by one hit via the real
    /// `lookup_chain` path (the same side effect a real query has), using
    /// `service`'s own `refresh_config` -- so a domain queried once becomes
    /// eligible under `permissive_refresh_config`.
    fn warm_popularity_via_lookup(
        service: &ResolveQuery,
        domain: &str,
        qtype: u16,
        qclass: u16,
        now: SystemTime,
    ) {
        service.cache.lookup_chain(
            domain,
            qtype,
            qclass,
            false,
            service.backend.current().cache_epoch,
            service.max_chain_depth,
            now,
            &service.refresh_config,
        );
    }

    #[tokio::test]
    async fn build_refresh_query_always_sets_do_flag() {
        let do_true = build_refresh_query("example.com", A_RECORD_TYPE, 1, true, 1232).unwrap();
        assert!(do_true.features.dnssec_ok);

        let do_false = build_refresh_query("example.com", A_RECORD_TYPE, 1, false, 1232).unwrap();
        assert!(!do_false.features.dnssec_ok);
    }

    #[tokio::test]
    async fn build_refresh_query_rejects_oversized_label() {
        let oversized_label = "a".repeat(64);
        assert!(build_refresh_query(&oversized_label, A_RECORD_TYPE, 1, true, 1232).is_none());
    }

    /// Regression test for the bug code review found: the previous
    /// hard-coded 1232-byte EDNS buffer ignored `max_udp_payload_size`, so
    /// an operator who configured a larger buffer still got refresh queries
    /// bounded to 1232 -- silently defeating large-DNSSEC-response refresh
    /// for that operator.
    #[tokio::test]
    async fn build_refresh_query_uses_the_configured_udp_payload_size() {
        let query = build_refresh_query("example.com", A_RECORD_TYPE, 1, true, 4096).unwrap();
        let edns = query.message.edns.expect("synthetic query must carry EDNS");
        assert_eq!(edns.udp_payload_size, 4096);
    }

    #[tokio::test]
    async fn job_success_advances_expires_at_and_exits_lead_window() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let now = SystemTime::UNIX_EPOCH;
        let domain = "example.com";
        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
        entry.expires_at = now + Duration::from_secs(60);
        let original_expires_at = entry.expires_at;
        cache.store_response(
            DecomposedResponse {
                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            0,
        );
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1234, domain, 120),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = resolve_service_with_cache(
            upstream,
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        );
        service = service.with_refresh_config(permissive_refresh_config());
        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
        let service = Arc::new(service);

        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;

        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);
        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 0);
        match cache.lookup_chain(
            domain,
            A_RECORD_TYPE,
            1,
            false,
            0,
            8,
            now,
            &RefreshConfig::default(),
        ) {
            ChainLookup::Answered(resolved) => {
                assert!(
                    resolved.chain[0].1.expires_at > original_expires_at,
                    "a successful refresh must move expires_at forward"
                );
                // Re-probing under the *default* (non-permissive)
                // RefreshConfig -- rather than the permissive config used
                // to warm/trigger this test -- is what actually verifies
                // "exits the lead window": the refreshed entry's remaining
                // TTL is now 120s, well outside the default config's
                // ~12s lead window (max(120s * 0.10, 5s)), so it no longer
                // produces a refresh hint under realistic thresholds.
                assert!(
                    resolved.refresh_hints.is_empty(),
                    "a freshly-refreshed entry must not immediately re-qualify for refresh \
                     under a realistic (non-permissive) config"
                );
            }
            other => panic!("expected Answered after a successful refresh, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn job_failure_no_retry_leaves_entry_untouched() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let now = SystemTime::UNIX_EPOCH;
        let domain = "example.com";
        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
        entry.expires_at = now + Duration::from_secs(60);
        let original_expires_at = entry.expires_at;
        cache.store_response(
            DecomposedResponse {
                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            0,
        );
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = resolve_service_with_cache(
            upstream,
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        );
        service = service.with_refresh_config(permissive_refresh_config());
        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
        let service = Arc::new(service);

        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;

        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 1);
        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 0);
        match cache.lookup_chain(
            domain,
            A_RECORD_TYPE,
            1,
            false,
            0,
            8,
            now,
            &RefreshConfig::default(),
        ) {
            ChainLookup::Answered(resolved) => {
                assert_eq!(
                    resolved.chain[0].1.expires_at, original_expires_at,
                    "a failed refresh must leave the stale entry untouched, no retry"
                );
            }
            other => panic!("expected the stale entry to remain Answered, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn job_rechecks_lead_window_before_fetch() {
        // Default RefreshConfig: a fresh (not near-expiry) entry must not
        // be re-fetched, regardless of popularity.
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let now = SystemTime::UNIX_EPOCH;
        let domain = "example.com";
        let mut entry = seed_rrset_entry(&a_record(domain, 300), Duration::from_secs(300), now, 0);
        entry.expires_at = now + Duration::from_secs(300); // remaining=300s, default lead window is only ~30s
        cache.store_response(
            DecomposedResponse {
                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            0,
        );
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_cache(
            upstream.clone(),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        )); // default RefreshConfig

        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;

        assert!(upstream.requests.lock().unwrap().is_empty());
        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 0);
        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 0);
    }

    #[tokio::test]
    async fn job_aborts_on_epoch_mismatch() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1111, "example.com", 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = ResolveQuery::with_cache_and_backend_generation(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            CacheTtlPolicy::default(),
            upstream.clone(),
            1,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
        );
        service = service.with_refresh_config(permissive_refresh_config());
        let now = SystemTime::UNIX_EPOCH;

        // Warm the entry under generation 1's namespace via a real query.
        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query(0x1111, "example.com"),
            ))
            .await;
        assert_eq!(cache.domain_count(), 1);
        let service = Arc::new(service);

        // Reload to a new generation -- bumps the cache epoch and sweeps
        // the old-namespace entry.
        let new_upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        service.publish_reload(
            BackendSnapshot::forwarding(new_upstream, 2),
            Arc::new(NoopLocalDnsEntries),
        );
        assert_eq!(
            cache.domain_count(),
            0,
            "the namespace sweep should have removed the generation-1 entry"
        );

        process_refresh_job(
            Arc::clone(&service),
            refresh_job("example.com", A_RECORD_TYPE, 1),
        )
        .await;

        // Aborted before ever fetching: no new upstream request beyond the
        // one warming call, and no Refresh* metric at all.
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 0);
        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 0);
    }

    #[tokio::test]
    async fn job_captures_epoch_before_recheck() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let now = SystemTime::UNIX_EPOCH;
        let domain = "example.com";
        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
        entry.expires_at = now + Duration::from_secs(60);
        cache.store_response(
            DecomposedResponse {
                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            0,
        );
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x2222, domain, 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = resolve_service_with_cache(
            upstream,
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        );
        service = service.with_refresh_config(permissive_refresh_config());
        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
        let epoch_at_call_time = service.backend.current().cache_epoch;
        let service = Arc::new(service);

        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;

        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);
        match cache.lookup_chain(
            domain,
            A_RECORD_TYPE,
            1,
            false,
            epoch_at_call_time,
            8,
            now,
            &RefreshConfig::default(),
        ) {
            ChainLookup::Answered(_) => {} // stored and visible under the same epoch captured at call time
            other => panic!(
                "refresh-stored entry must be visible under the epoch captured once at the \
                 start of the job, got {other:?}"
            ),
        }
    }

    #[tokio::test]
    async fn job_fetch_uses_dnssec_ok_true_always() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let now = SystemTime::UNIX_EPOCH;
        let domain = "example.com";
        // Original entry was stored as DNSSEC-incomplete.
        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
        entry.expires_at = now + Duration::from_secs(60);
        entry.dnssec_complete = false;
        cache.store_response(
            DecomposedResponse {
                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            0,
        );
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x3333, domain, 60),
        ))));
        let mut service = resolve_service_with_cache(
            upstream.clone(),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
            1232,
        );
        service = service.with_refresh_config(permissive_refresh_config());
        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
        let service = Arc::new(service);

        process_refresh_job(Arc::clone(&service), refresh_job(domain, A_RECORD_TYPE, 1)).await;

        let requests = upstream.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].query.features.dnssec_ok,
            "refresh jobs must always fetch with dnssec_ok = true, regardless of the \
             original entry's dnssec_complete state"
        );
    }

    #[tokio::test]
    async fn job_coalesces_with_concurrent_do_true_client_miss() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let now = SystemTime::UNIX_EPOCH;
        let domain = "example.com";
        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
        entry.expires_at = now + Duration::from_secs(60);
        cache.store_response(
            DecomposedResponse {
                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            0,
        );
        let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x4444, domain, 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = resolve_service_with_cache(
            upstream.clone(),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        );
        service = service.with_refresh_config(permissive_refresh_config());
        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
        let service = Arc::new(service);

        let job_handle = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                process_refresh_job(service, refresh_job(domain, A_RECORD_TYPE, 1)).await
            })
        };
        upstream.wait_for_requests(1).await;

        // A concurrent caller sharing the identical MissKey (dnssec_ok =
        // true, same epoch) -- representing a real client miss landing on
        // the same key while the refresh job's fetch is already in flight.
        let epoch = service.backend.current().cache_epoch;
        let miss_key: MissKey = (domain.to_string(), A_RECORD_TYPE, 1, epoch, true);
        let client_handle = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                match service.miss_coalescer.begin(miss_key) {
                    SingleFlightTicket::Follower { flight } => flight.wait().await,
                    SingleFlightTicket::Leader { .. } => {
                        panic!("expected to join as a follower behind the refresh job's leader")
                    }
                }
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        upstream.release.notify_waiters();

        job_handle.await.unwrap();
        let client_result = client_handle.await.unwrap();

        assert!(client_result.is_ok());
        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            1,
            "the concurrent DO=true client miss must coalesce onto the refresh job's single \
             backend fetch, not trigger a second one"
        );
        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);
    }

    #[tokio::test]
    async fn job_does_not_coalesce_with_do_false_client_miss() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let now = SystemTime::UNIX_EPOCH;
        let domain = "example.com";
        let mut entry = seed_rrset_entry(&a_record(domain, 60), Duration::from_secs(60), now, 0);
        entry.expires_at = now + Duration::from_secs(60);
        cache.store_response(
            DecomposedResponse {
                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            0,
        );
        let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x5555, domain, 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = resolve_service_with_cache(
            upstream.clone(),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        );
        service = service.with_refresh_config(permissive_refresh_config());
        warm_popularity_via_lookup(&service, domain, A_RECORD_TYPE, 1, now);
        let service = Arc::new(service);

        let job_handle = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                process_refresh_job(service, refresh_job(domain, A_RECORD_TYPE, 1)).await
            })
        };
        upstream.wait_for_requests(1).await;

        // A concurrent DO=false client miss for the same (domain, qtype,
        // qclass, epoch) -- MissKey's dnssec_ok differs, so this must become
        // its own independent Leader, not a Follower of the refresh job.
        let epoch = service.backend.current().cache_epoch;
        let miss_key: MissKey = (domain.to_string(), A_RECORD_TYPE, 1, epoch, false);
        let client_handle = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                match service.miss_coalescer.begin(miss_key) {
                    SingleFlightTicket::Leader { key, flight } => {
                        let leader = SingleFlightLeader::new(
                            Arc::clone(&service.miss_coalescer),
                            key,
                            flight,
                        );
                        let synthetic_query =
                            build_refresh_query(domain, A_RECORD_TYPE, 1, false, 1232).unwrap();
                        let backend_snapshot = service.backend.current();
                        let result = service
                            .resolve_backend(&backend_snapshot, &synthetic_query)
                            .await;
                        leader.complete(result.clone());
                        result
                    }
                    SingleFlightTicket::Follower { .. } => {
                        panic!(
                            "a DO=false miss must not coalesce with the refresh job's DO=true fetch"
                        )
                    }
                }
            })
        };
        upstream.wait_for_requests(2).await;
        assert_eq!(upstream.requests.lock().unwrap().len(), 2);
        upstream.release.notify_waiters();

        job_handle.await.unwrap();
        let client_result = client_handle.await.unwrap();

        assert!(client_result.is_ok());
        assert_eq!(upstream.requests.lock().unwrap().len(), 2);
        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);
    }

    #[tokio::test]
    async fn job_store_matches_normal_miss_path_shape() {
        let domain = "refreshed.example.com";
        let response_bytes = a_response_with_answer(0x6666, domain, 300);
        let now = SystemTime::UNIX_EPOCH;

        // -- refresh path --
        let refresh_cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let mut entry = seed_rrset_entry(&a_record(domain, 300), Duration::from_secs(300), now, 0);
        entry.expires_at = now + Duration::from_secs(300);
        refresh_cache.store_response(
            DecomposedResponse {
                positive: vec![(domain.to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            0,
        );
        let refresh_upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            response_bytes.clone(),
        ))));
        let mut refresh_service = resolve_service_with_cache(
            refresh_upstream,
            Arc::clone(&refresh_cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
            1232,
        );
        refresh_service = refresh_service.with_refresh_config(permissive_refresh_config());
        warm_popularity_via_lookup(&refresh_service, domain, A_RECORD_TYPE, 1, now);
        let refresh_service = Arc::new(refresh_service);
        process_refresh_job(
            Arc::clone(&refresh_service),
            refresh_job(domain, A_RECORD_TYPE, 1),
        )
        .await;
        let refreshed_entry = match refresh_cache.lookup_chain(
            domain,
            A_RECORD_TYPE,
            1,
            false,
            0,
            8,
            now,
            &RefreshConfig::default(),
        ) {
            ChainLookup::Answered(resolved) => resolved.chain[0].1.clone(),
            other => panic!("expected Answered after refresh store, got {other:?}"),
        };

        // -- normal client-miss path --
        let normal_cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let normal_upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(response_bytes))));
        let normal_service = resolve_service_with_cache(
            normal_upstream,
            Arc::clone(&normal_cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
            1232,
        );
        let _ = normal_service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query_with_edns(0x6666, domain, 1232, true),
            ))
            .await;
        let normal_entry = match normal_cache.lookup_chain(
            domain,
            A_RECORD_TYPE,
            1,
            true,
            0,
            8,
            now,
            &RefreshConfig::default(),
        ) {
            ChainLookup::Answered(resolved) => resolved.chain[0].1.clone(),
            other => panic!("expected Answered after normal store, got {other:?}"),
        };

        assert_eq!(refreshed_entry.records, normal_entry.records);
        assert_eq!(refreshed_entry.response_code, normal_entry.response_code);
        assert_eq!(refreshed_entry.minimum_ttl, normal_entry.minimum_ttl);
        assert_eq!(
            refreshed_entry.dnssec_complete,
            normal_entry.dnssec_complete
        );
        assert_eq!(
            refreshed_entry.authoritative, normal_entry.authoritative,
            "a refresh-triggered store must be structurally indistinguishable from what the \
             normal client-miss path would have stored for the identical response"
        );
    }

    // End-to-end verification: section-07-integration. Unlike the isolated
    // unit/integration tests above, these drive the *real*
    // `spawn_refresh_worker_pool` wired through a real channel, proving the
    // whole chain (bucket increment -> trigger -> hint -> enqueue -> worker
    // -> fetch -> store -> next lookup sees the refreshed entry) actually
    // cooperates end to end, not just that each piece works in isolation.

    /// Polls (via `yield_now`, never `sleep`) until `upstream` has recorded
    /// at least `expected` requests, or panics after a generous bound --
    /// used to deterministically wait for the background worker pool
    /// (running concurrently in this test's own runtime) to finish
    /// processing an enqueued job, without any wall-clock sleep.
    async fn wait_for_upstream_requests(upstream: &StaticUpstream, expected: usize) {
        for _ in 0..10_000 {
            if upstream.requests.lock().unwrap().len() >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "timed out waiting for {expected} upstream request(s), saw {}",
            upstream.requests.lock().unwrap().len()
        );
    }

    /// End-to-end: a hot domain's cache entry gets a background refresh
    /// fetch without ever costing a client a miss. Honesty note: this test
    /// uses a fixed `now` passed explicitly to every `ResolveRequest` (no
    /// `Clock` impl that advances), so it cannot and does not verify
    /// TTL-boundary timing -- "before expiry" in the name refers to the
    /// production trigger condition (`wants_refresh`'s lead-window gate,
    /// exercised via `permissive_refresh_config()`), not to this test
    /// observing time actually elapse toward `expires_at`. What it does
    /// verify: the full plumbing fires end-to-end (popularity hit -> hint ->
    /// enqueue -> worker fetch -> store) and the client-visible read path
    /// never regresses to a miss because of it.
    #[tokio::test]
    async fn e2e_hot_domain_refreshed_before_expiry() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let domain = "hot.example.com";
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1234, domain, 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = resolve_service_with_cache(
            upstream.clone(),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        );
        service = service.with_refresh_config(permissive_refresh_config());
        let (sender, receiver) = mpsc::channel(4);
        service = service.with_refresh_sender(sender);
        let service = Arc::new(service);
        let workers = spawn_refresh_worker_pool(Arc::clone(&service), receiver, 1);

        let now = SystemTime::UNIX_EPOCH;
        // First call: genuine cache miss, populates the cache. No hint yet
        // -- there's nothing cached to have a popularity bucket at all.
        let first = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query(0x1111, domain),
            ))
            .await;
        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);

        // Second call: now a cache hit. Under the permissive config, this
        // hit's own popularity increment immediately crosses hot_threshold
        // (0), and the entry is always "within lead window" -- producing a
        // refresh hint, which probe_cache enqueues onto the real channel
        // the real worker pool above is reading from.
        let second = service
            .resolve(ResolveRequest::new(
                "192.0.2.11".parse().unwrap(),
                now,
                a_query(0x2222, domain),
            ))
            .await;
        assert_eq!(second.decision.kind, ResolveDecisionKind::CacheHit);

        // The background worker processes the enqueued job concurrently --
        // wait for its fetch to land, with no client-visible miss at all.
        wait_for_upstream_requests(&upstream, 2).await;
        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 1);

        // A third call must still be an ordinary cache hit -- the
        // background refresh happened without ever costing a client a
        // miss. Note: under the permissive config this third hit also
        // qualifies and enqueues its own second refresh job; it's
        // deliberately not awaited here (no assertion depends on it) --
        // the worker abort below and the test runtime's teardown make
        // leaving it in flight harmless.
        let third = service
            .resolve(ResolveRequest::new(
                "192.0.2.12".parse().unwrap(),
                now,
                a_query(0x3333, domain),
            ))
            .await;
        assert_eq!(third.decision.kind, ResolveDecisionKind::CacheHit);

        for worker in workers {
            worker.abort();
            let _ = worker.await;
        }
    }

    #[tokio::test]
    async fn e2e_cooling_domain_stops_being_refreshed() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let domain = "cooling.example.com";
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x4321, domain, 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = resolve_service_with_cache(
            upstream.clone(),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        );
        service = service.with_refresh_config(permissive_refresh_config());
        let (sender, receiver) = mpsc::channel(4);
        service = service.with_refresh_sender(sender);
        let service = Arc::new(service);
        let workers = spawn_refresh_worker_pool(Arc::clone(&service), receiver, 1);
        let now = SystemTime::UNIX_EPOCH;

        // Warm the domain hot and let one background refresh land, exactly
        // as in `e2e_hot_domain_refreshed_before_expiry`.
        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query(0x1111, domain),
            ))
            .await;
        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.11".parse().unwrap(),
                now,
                a_query(0x2222, domain),
            ))
            .await;
        wait_for_upstream_requests(&upstream, 2).await;
        let requests_after_warm_refresh = upstream.requests.lock().unwrap().len();

        // No further queries at all -- there is no periodic background
        // scan in this design; refresh is purely reactive to real hits.
        // Give any (incorrect) spontaneous background activity a generous
        // window to show up.
        for _ in 0..1000 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            requests_after_warm_refresh,
            "with no further real traffic, nothing should trigger another background refresh"
        );

        for worker in workers {
            worker.abort();
            let _ = worker.await;
        }
    }

    #[tokio::test]
    async fn e2e_disabled_feature_is_true_no_op() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let domain = "disabled.example.com";
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x5678, domain, 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let mut service = resolve_service_with_cache(
            upstream.clone(),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
            1232,
        );
        // Same thresholds that would trigger refresh in the two tests
        // above, except disabled -- proving `enabled` is the load-bearing
        // switch, not incidental.
        service = service.with_refresh_config(RefreshConfig {
            enabled: false,
            ..permissive_refresh_config()
        });
        let service = Arc::new(service);
        let now = SystemTime::UNIX_EPOCH;

        for (id, client_ip) in [
            (0x1111u16, "192.0.2.10"),
            (0x2222, "192.0.2.11"),
            (0x3333, "192.0.2.12"),
        ] {
            let _ = service
                .resolve(ResolveRequest::new(
                    client_ip.parse().unwrap(),
                    now,
                    a_query(id, domain),
                ))
                .await;
        }

        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            1,
            "only the first, genuine cache miss should ever reach the backend"
        );
        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 0);
        assert_eq!(metrics.count(ResolverMetric::RefreshQueueFull), 0);
        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 0);
        assert_eq!(metrics.count(ResolverMetric::RefreshFailed), 0);
    }

    #[tokio::test]
    async fn resolve_blocks_cached_response_with_malicious_cname_target() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let now = SystemTime::UNIX_EPOCH;
        let epoch = 0u64;
        let cname = cname_record("alias.example", 60, "target.malicious.example");
        let terminal = a_record("target.malicious.example", 60);
        cache.store_response(
            DecomposedResponse {
                positive: vec![
                    (
                        "alias.example".to_string(),
                        CNAME_RECORD_TYPE,
                        1,
                        seed_rrset_entry(&cname, Duration::from_secs(60), now, epoch),
                    ),
                    (
                        "target.malicious.example".to_string(),
                        A_RECORD_TYPE,
                        1,
                        seed_rrset_entry(&terminal, Duration::from_secs(60), now, epoch),
                    ),
                ],
                negative: None,
            },
            epoch,
        );
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let policy = Arc::new(MaliciousDomainPolicyEvaluator::new(vec![
            MaliciousDomainRule::new(
                "malware-feed",
                DomainSelector::subtree("malicious.example").unwrap(),
                true,
            ),
        ]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache,
            policy,
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(ConfiguredResponseFactory::default()),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            metrics.clone(),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "alias.example"),
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::Blocked(PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("malware-feed".to_string()),
            })
        );
        assert_eq!(
            response_code_from_wire(&outcome.response_bytes),
            Some(ResponseCode::Refused as u16)
        );
        assert!(upstream.requests.lock().unwrap().is_empty());
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(
                recorded_events[0].terminal_outcome,
                QueryEventOutcome::Blocked(BlockReason::MaliciousDomain)
            );
            assert_eq!(
                recorded_events[0].cache_result,
                Some(QueryEventCacheResult::Hit)
            );
        }
        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
        assert_eq!(metrics.count(ResolverMetric::QueryBlocked), 1);
        assert_eq!(metrics.count(ResolverMetric::QueryAllowed), 0);
    }

    #[tokio::test]
    async fn resolve_blocks_malicious_requested_domain_before_cache_or_backend() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xabcd, "blocked.malicious.example", 60),
        ))));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let policy = Arc::new(MaliciousDomainPolicyEvaluator::new(vec![
            MaliciousDomainRule::new(
                "malware-feed",
                DomainSelector::subtree("malicious.example").unwrap(),
                true,
            ),
        ]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            policy,
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(ConfiguredResponseFactory::default()),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "blocked.malicious.example"),
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::Blocked(PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("malware-feed".to_string()),
            })
        );
        assert_eq!(upstream.requests.lock().unwrap().len(), 0);
        assert_eq!(cache.lookups.lock().unwrap().len(), 0);
        assert_eq!(cache.stores.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn resolve_blocks_upstream_response_with_malicious_answer_owner() {
        let question = QuestionKey::new("host.example", A_RECORD_TYPE, 1);
        let response_message = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            vec![a_record("host.malicious.example", 60)],
            Vec::new(),
            Vec::new(),
            false,
        );
        let response_bytes = response_message.original_bytes.to_vec();
        let upstream = Arc::new(StaticUpstream::new(Ok(
            ResolutionResponse::forwarded_message(
                response_bytes,
                response_message,
                SystemTime::UNIX_EPOCH,
                0,
                "test-forwarder",
            ),
        )));
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let policy = Arc::new(MaliciousDomainPolicyEvaluator::new(vec![
            MaliciousDomainRule::new(
                "malware-feed",
                DomainSelector::subtree("malicious.example").unwrap(),
                true,
            ),
        ]));
        let service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            policy,
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(ConfiguredResponseFactory::default()),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "host.example"),
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::Blocked(PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("malware-feed".to_string()),
            })
        );
        assert_eq!(cache.stores.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn resolve_preserves_forwarding_backend_query_edns_payload() {
        let response = a_response_with_answer(0xabcd, "example.com", 60);
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(response))));
        let service = ResolveQuery::with_cache(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, true),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let requests = upstream.requests.lock().unwrap();
        assert_eq!(
            requests[0]
                .query
                .message
                .edns
                .as_ref()
                .map(|edns| edns.udp_payload_size),
            Some(4096)
        );
    }

    #[tokio::test]
    async fn resolve_preserves_large_forwarded_response_with_client_edns_payload() {
        let question = QuestionKey::new("example.com", 1, 1);
        let response = response_message_for_question_with_id(
            0xabcd,
            question,
            ResponseCode::NoError,
            (0..40).map(|_| a_record("example.com", 60)).collect(),
            Vec::new(),
            Vec::new(),
            true,
        )
        .original_bytes
        .to_vec();
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(response))));
        let service = ResolveQuery::with_cache(
            Arc::new(StandardProtocolCodec::new(700)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            upstream,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 4096, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(!response.header.tc());
        assert_eq!(response.answers.len(), 40);
    }

    #[tokio::test]
    async fn resolve_returns_assembled_response_for_current_request_id() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let epoch = 0u64;
        let now = SystemTime::UNIX_EPOCH;
        let record = a_record("example.com", 60);
        cache.store_response(
            DecomposedResponse {
                positive: vec![(
                    "example.com".to_string(),
                    A_RECORD_TYPE,
                    1,
                    seed_rrset_entry(&record, Duration::from_secs(60), now, epoch),
                )],
                negative: None,
            },
            epoch,
        );
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(
            upstream.clone(),
            cache,
            events.clone(),
            metrics.clone(),
            1232,
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query(0x2222, "example.com"),
            ))
            .await;

        assert_eq!(&outcome.response_bytes[0..2], &[0x22, 0x22]);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
        assert!(upstream.requests.lock().unwrap().is_empty());
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(
                recorded_events[0].terminal_outcome,
                QueryEventOutcome::AllowedFromCache
            );
            assert_eq!(
                recorded_events[0].response_code,
                Some(ResponseCode::NoError as u16)
            );
            assert_eq!(
                recorded_events[0].cache_result,
                Some(QueryEventCacheResult::Hit)
            );
        }
        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 0);
    }

    #[tokio::test]
    async fn resolve_rewrites_rd_flag_for_current_request_on_cache_hit() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let epoch = 0u64;
        let now = SystemTime::UNIX_EPOCH;
        let record = a_record("example.com", 60);
        cache.store_response(
            DecomposedResponse {
                positive: vec![(
                    "example.com".to_string(),
                    A_RECORD_TYPE,
                    1,
                    seed_rrset_entry(&record, Duration::from_secs(60), now, epoch),
                )],
                negative: None,
            },
            epoch,
        );
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query_without_rd(0x2222, "example.com"),
            ))
            .await;

        assert_eq!(&outcome.response_bytes[0..2], &[0x22, 0x22]);
        assert_eq!(outcome.response_bytes[2] & 0x01, 0);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
    }

    #[tokio::test]
    async fn resolve_ages_cached_response_ttls_for_current_request_time() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let epoch = 0u64;
        let now = SystemTime::UNIX_EPOCH;
        let record = a_record("example.com", 60);
        cache.store_response(
            DecomposedResponse {
                positive: vec![(
                    "example.com".to_string(),
                    A_RECORD_TYPE,
                    1,
                    seed_rrset_entry(&record, Duration::from_secs(60), now, epoch),
                )],
                negative: None,
            },
            epoch,
        );
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now + Duration::from_secs(25),
                a_query(0x2222, "example.com"),
            ))
            .await;

        let parsed = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(parsed.answers[0].ttl, 35);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
    }

    #[tokio::test]
    async fn resolve_caps_cached_response_ttls_to_remaining_cache_lifetime() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let epoch = 0u64;
        let now = SystemTime::UNIX_EPOCH;
        // Record's own wire TTL (3600) is far longer than the entry's
        // governing lifetime (60s) — the assembled TTL must be capped by
        // the latter, not the former.
        let record = a_record("example.com", 3600);
        cache.store_response(
            DecomposedResponse {
                positive: vec![(
                    "example.com".to_string(),
                    A_RECORD_TYPE,
                    1,
                    seed_rrset_entry(&record, Duration::from_secs(60), now, epoch),
                )],
                negative: None,
            },
            epoch,
        );
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now + Duration::from_secs(25),
                a_query(0x2222, "example.com"),
            ))
            .await;

        let parsed = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(parsed.answers[0].ttl, 35);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
    }

    #[tokio::test]
    async fn resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let epoch = 0u64;
        let now = SystemTime::UNIX_EPOCH;

        // Chain-wide minimum origin TTL across the whole response is 60s (the
        // intermediate hop's TTL) - this becomes every hop's `expires_at`
        // ceiling, exactly as `decompose_response_for_store` computes it in
        // production.
        let chain_ceiling = Duration::from_secs(60);

        let cname = cname_record("alias.example.com", 60, "target.example.com");
        let terminal = a_record("target.example.com", 3600); // long origin TTL

        cache.store_response(
            DecomposedResponse {
                positive: vec![
                    (
                        "alias.example.com".to_string(),
                        CNAME_RECORD_TYPE,
                        1,
                        seed_rrset_entry(&cname, chain_ceiling, now, epoch),
                    ),
                    (
                        "target.example.com".to_string(),
                        A_RECORD_TYPE,
                        1,
                        // Same chain-wide ceiling applied here, even though
                        // `terminal`'s own origin TTL is 3600 - mirrors
                        // production `build_rrset_entry`'s single shared `ttl`.
                        seed_rrset_entry(&terminal, chain_ceiling, now, epoch),
                    ),
                ],
                negative: None,
            },
            epoch,
        );

        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        // Second, independent query: look up the terminal name directly,
        // NOT by re-resolving the alias.
        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now + Duration::from_secs(25),
                a_query(0x2222, "target.example.com"),
            ))
            .await;

        let parsed = Message::parse(&outcome.response_bytes).unwrap();
        // Aged TTL from the terminal record's own 3600s origin TTL would be
        // 3575 at t=25s - but the chain-wide ceiling (60s remaining lifetime,
        // 35s left at t=25s) must win: min(3575, 35) == 35.
        assert_eq!(parsed.answers[0].ttl, 35);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
    }

    #[tokio::test]
    async fn resolve_truncates_oversized_cached_response_for_current_request() {
        let now = SystemTime::UNIX_EPOCH;
        let records: Vec<StoredRecord> = (0..40u8)
            .map(|i| StoredRecord {
                rtype: A_RECORD_TYPE,
                rclass: 1,
                ttl_at_store: 60,
                rdata: RecordData::A(std::net::Ipv4Addr::new(192, 0, 2, i)),
            })
            .collect();
        let entry = RRsetEntry {
            records,
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            stored_at: now,
            expires_at: now + Duration::from_secs(60),
            dnssec_state: Default::default(),
            cache_epoch: 1,
            dnssec_complete: true,
            authoritative: false,
        };
        let resolved = cache::ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry.into())],
            refresh_hints: Vec::new(),
        };
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream.clone(), cache, events, metrics.clone(), 512);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query(0x3333, "example.com"),
            ))
            .await;

        assert_eq!(&outcome.response_bytes[0..2], &[0x33, 0x33]);
        assert_ne!(outcome.response_bytes[2] & 0x02, 0);
        assert_eq!(
            Message::parse(&outcome.response_bytes)
                .unwrap()
                .answers
                .len(),
            0
        );
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
        assert!(upstream.requests.lock().unwrap().is_empty());
        assert_eq!(metrics.count(ResolverMetric::CacheResponseTruncated), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
    }

    /// End-to-end regression test for the seam connecting
    /// `resolve_from_cache`'s hint production to the actual enqueue: a real
    /// `.resolve()` call against a cache hit whose `ChainLookup::Answered`
    /// carries a `refresh_hints` entry must result in a job landing on the
    /// resolver's `refresh_sender` and a `RefreshTriggered` increment — not
    /// just `evaluate_cache_lookup`/`enqueue_refresh_job` exercised in
    /// isolation with hand-built values (code review flagged this seam as
    /// untested, which is exactly what let a missed call site slip through
    /// on the coalesced-follower path).
    #[tokio::test]
    async fn resolve_cache_hit_with_refresh_hint_enqueues_a_job() {
        let now = SystemTime::UNIX_EPOCH;
        let entry = RRsetEntry {
            records: vec![StoredRecord {
                rtype: A_RECORD_TYPE,
                rclass: 1,
                ttl_at_store: 60,
                rdata: RecordData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            }],
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            stored_at: now,
            expires_at: now + Duration::from_secs(60),
            dnssec_state: Default::default(),
            cache_epoch: 1,
            dnssec_complete: true,
            authoritative: false,
        };
        let resolved = cache::ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry.into())],
            refresh_hints: vec![cache::RefreshHint {
                domain: "example.com".to_string(),
                qtype: A_RECORD_TYPE,
                qclass: 1,
            }],
        };
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let service = resolve_service_with_cache(upstream, cache, events, metrics.clone(), 1232)
            .with_refresh_sender(sender);

        let _outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query(0x4444, "example.com"),
            ))
            .await;

        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 1);
        let job = receiver
            .try_recv()
            .expect("resolve() should have enqueued the scripted refresh hint");
        assert_eq!(job.domain, "example.com");
    }

    /// Regression test for the bug code review found: an RD=0 (cache-only)
    /// query that happens to hit cache must not trigger a background
    /// refresh -- refresh is itself a real backend fetch, i.e. exactly the
    /// "fresh upstream work" RD=0 asks rdns not to do on the client's
    /// behalf. Same scripted-cache setup as
    /// `resolve_cache_hit_with_refresh_hint_enqueues_a_job` above, just with
    /// RD=0 on the query.
    #[tokio::test]
    async fn resolve_rd_zero_cache_hit_does_not_enqueue_refresh() {
        let now = SystemTime::UNIX_EPOCH;
        let entry = RRsetEntry {
            records: vec![StoredRecord {
                rtype: A_RECORD_TYPE,
                rclass: 1,
                ttl_at_store: 60,
                rdata: RecordData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            }],
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            stored_at: now,
            expires_at: now + Duration::from_secs(60),
            dnssec_state: Default::default(),
            cache_epoch: 1,
            dnssec_complete: true,
            authoritative: false,
        };
        let resolved = cache::ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry.into())],
            refresh_hints: vec![cache::RefreshHint {
                domain: "example.com".to_string(),
                qtype: A_RECORD_TYPE,
                qclass: 1,
            }],
        };
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let service = resolve_service_with_cache(upstream, cache, events, metrics.clone(), 1232)
            .with_refresh_sender(sender);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query_without_rd(0x4444, "example.com"),
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::CacheHit,
            "RD=0 still gets served from cache -- only the refresh side effect is gated"
        );
        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 0);
        assert!(receiver.try_recv().is_err());
    }

    /// Regression test for the bug code review found: the single-flight
    /// *follower* path (`cache_hit_after_coalesced_miss`) must also surface
    /// `refresh_hints`, not just the leader-side `probe_cache` path — exactly
    /// the hot/concurrent scenario the refresh feature targets. Checks the
    /// *returned* hints, not an immediate enqueue: a later review pass found
    /// enqueueing directly from this function ran before the caller's
    /// response-policy-block check, so hints are now returned for the caller
    /// (`resolve_coalesced_follower`) to enqueue only once admitted --
    /// covered end-to-end by
    /// `resolve_coalesced_follower_policy_blocked_hit_does_not_enqueue_refresh`
    /// below.
    #[tokio::test]
    async fn cache_hit_after_coalesced_miss_returns_refresh_hints() {
        let now = SystemTime::UNIX_EPOCH;
        let entry = RRsetEntry {
            records: vec![StoredRecord {
                rtype: A_RECORD_TYPE,
                rclass: 1,
                ttl_at_store: 60,
                rdata: RecordData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            }],
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            stored_at: now,
            expires_at: now + Duration::from_secs(60),
            dnssec_state: Default::default(),
            cache_epoch: 1,
            dnssec_complete: true,
            authoritative: false,
        };
        let resolved = cache::ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry.into())],
            refresh_hints: vec![cache::RefreshHint {
                domain: "example.com".to_string(),
                qtype: A_RECORD_TYPE,
                qclass: 1,
            }],
        };
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let service = resolve_service_with_cache(upstream, cache, events, metrics.clone(), 1232)
            .with_refresh_sender(sender);

        let message = Message::parse_owned(a_query(0x5555, "example.com")).unwrap();
        let decoded = DecodedQuery::new(message).unwrap();
        let request = ResolveRequest::new(
            "192.0.2.10".parse().unwrap(),
            now,
            a_query(0x5555, "example.com"),
        );
        let backend_snapshot = service.backend.current();
        let miss_key: MissKey = (
            "example.com".to_string(),
            A_RECORD_TYPE,
            1,
            backend_snapshot.cache_epoch,
            false,
        );

        let hit = service
            .cache_hit_after_coalesced_miss(&request, &decoded, &backend_snapshot, &miss_key)
            .await
            .expect("scripted lookup is ChainLookup::Answered");

        // Not enqueued by this function itself -- see its doc comment.
        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 0);
        assert!(receiver.try_recv().is_err());
        assert_eq!(hit.refresh_hints.len(), 1);
        assert_eq!(hit.refresh_hints[0].domain, "example.com");
    }

    /// Regression test for the fix to the bug above: a follower hit whose
    /// response the policy blocks must not have triggered a background
    /// refresh fetch for it -- the whole point of moving the enqueue behind
    /// the policy-block check in `resolve_coalesced_follower`.
    #[tokio::test]
    async fn resolve_coalesced_follower_policy_blocked_hit_does_not_enqueue_refresh() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let domain = "blocked.example.com";
        let follower_ip: IpAddr = "192.0.2.11".parse().unwrap();
        let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xaaaa, domain, 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let mut service = ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(ClientScopedResponsePolicy {
                client_ip: follower_ip,
                domain: DomainSelector::exact(domain).unwrap(),
                rule_id: "blocked-follower".to_string(),
            }),
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            metrics.clone(),
        );
        service = service.with_refresh_config(permissive_refresh_config());
        service = service.with_refresh_sender(sender);
        let service = Arc::new(service);

        let leader_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let leader = {
            let service = Arc::clone(&service);
            let query = a_query(0x1111, domain);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        leader_ip,
                        SystemTime::UNIX_EPOCH,
                        query,
                    ))
                    .await
            })
        };
        upstream.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            let query = a_query(0x2222, domain);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        follower_ip,
                        SystemTime::UNIX_EPOCH,
                        query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        upstream.release.notify_waiters();
        let leader_outcome = leader.await.unwrap();
        let follower_outcome = follower.await.unwrap();

        assert_eq!(
            leader_outcome.decision.kind,
            ResolveDecisionKind::Allowed,
            "the leader took a genuine cache miss -> backend fetch, not a cache hit"
        );
        assert!(matches!(
            follower_outcome.decision.kind,
            ResolveDecisionKind::Blocked(_)
        ));
        assert_eq!(
            metrics.count(ResolverMetric::RefreshTriggered),
            0,
            "the follower's hit was policy-blocked, so no refresh job must have been enqueued \
             for it"
        );
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn resolve_treats_expired_cache_backend_hit_as_miss() {
        // Serve-stale off: pins the original expired-means-miss behavior.
        // The serve-stale-on counterpart is
        // `resolve_serves_stale_hit_then_background_refresh_restores_freshness`.
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            serve_stale_enabled: false,
            ..CacheConfig::default()
        }));
        let epoch = 0u64;
        let stored_at = SystemTime::UNIX_EPOCH;
        let record = a_record("example.com", 60);
        let mut entry = seed_rrset_entry(&record, Duration::from_secs(30), stored_at, epoch);
        entry.expires_at = stored_at + Duration::from_secs(30);
        cache.store_response(
            DecomposedResponse {
                positive: vec![("example.com".to_string(), A_RECORD_TYPE, 1, entry)],
                negative: None,
            },
            epoch,
        );
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x8888, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream.clone(), cache, events, metrics.clone(), 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                stored_at + Duration::from_secs(31),
                a_query(0x8888, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
    }

    /// Full RFC 8767 serve-stale cycle under the default (serve-stale-on)
    /// config: a query for an expired-but-in-window entry is answered
    /// immediately from cache with the 30s stale wire TTL and enqueues a
    /// refresh job; processing that job refetches and re-stores; the next
    /// query is an ordinary live hit serving aged origin TTL again.
    #[tokio::test]
    async fn resolve_serves_stale_hit_then_background_refresh_restores_freshness() {
        clear_test_job_handler();
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let domain = "stale-e2e.example.com";
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x4444, domain, 60),
        ))));
        let metrics = Arc::new(RecordingMetrics::default());
        let t0 = SystemTime::UNIX_EPOCH;
        let clock = Arc::new(SettableClock::new(t0));
        let (sender, mut receiver) = mpsc::channel(4);
        let service = Arc::new(
            ResolveQuery::with_cache(
                Arc::new(StandardProtocolCodec::new(1232)),
                Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
                CacheTtlPolicy::default(),
                upstream.clone(),
                Arc::new(BasicResponseFactory),
                Arc::clone(&clock) as Arc<dyn Clock>,
                Arc::new(RecordingEvents::default()),
                metrics.clone(),
            )
            .with_refresh_sender(sender),
        );

        // t0: genuine miss populates the cache (origin TTL 60 ⇒ expires
        // at t0+60).
        let first = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                t0,
                a_query(0x4444, domain),
            ))
            .await;
        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);

        // t0+61: entry expired 1s ago, well inside the default 1-day stale
        // window — served as a hit, stale wire TTL, refresh job enqueued,
        // and no inline backend round trip.
        let t_stale = t0 + Duration::from_secs(61);
        clock.set(t_stale);
        let second = service
            .resolve(ResolveRequest::new(
                "192.0.2.11".parse().unwrap(),
                t_stale,
                a_query(0x5555, domain),
            ))
            .await;
        assert_eq!(second.decision.kind, ResolveDecisionKind::CacheHit);
        let parsed = Message::parse(&second.response_bytes).unwrap();
        assert_eq!(
            parsed.answers[0].ttl,
            cache::STALE_WIRE_TTL_SECS,
            "stale records must serve the RFC 8767 fixed stale TTL"
        );
        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheStaleHit), 1);
        assert_eq!(
            metrics.count(ResolverMetric::CacheMiss),
            1,
            "only the initial population was a miss — the stale serve must not count as one"
        );
        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 1);
        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            1,
            "a stale serve must never pay an inline backend round trip"
        );

        // Drive the enqueued refresh to completion, exactly as a worker
        // would — the job's eligibility recheck must accept the stale
        // entry (its refresh signal is unconditional) and re-store.
        let job = receiver
            .try_recv()
            .expect("a stale serve must enqueue a refresh job");
        process_refresh_job(Arc::clone(&service), job).await;
        assert_eq!(upstream.requests.lock().unwrap().len(), 2);
        assert_eq!(metrics.count(ResolverMetric::RefreshSucceeded), 1);

        // t0+62: the refreshed entry serves as an ordinary live hit again,
        // aged origin TTL (60 − 1), not the stale TTL.
        let t_after = t0 + Duration::from_secs(62);
        clock.set(t_after);
        let third = service
            .resolve(ResolveRequest::new(
                "192.0.2.12".parse().unwrap(),
                t_after,
                a_query(0x6666, domain),
            ))
            .await;
        assert_eq!(third.decision.kind, ResolveDecisionKind::CacheHit);
        let parsed = Message::parse(&third.response_bytes).unwrap();
        assert_eq!(parsed.answers[0].ttl, 59);
        assert_eq!(
            metrics.count(ResolverMetric::CacheStaleHit),
            1,
            "the post-refresh query is a fresh hit, not another stale serve"
        );
    }

    #[tokio::test]
    async fn resolve_coalesces_duplicate_cache_misses() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xaaaa, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_cache(
            upstream.clone(),
            cache,
            events,
            metrics.clone(),
            1232,
        ));
        let first = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        a_query(0x1111, "example.com"),
                    ))
                    .await
            })
        };
        upstream.wait_for_requests(1).await;
        let second = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        a_query(0x2222, "example.com"),
                    ))
                    .await
            })
        };

        tokio::task::yield_now().await;
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        upstream.release.notify_waiters();
        let first = first.await.unwrap();
        let second = second.await.unwrap();

        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        assert_eq!(&first.response_bytes[0..2], &[0x11, 0x11]);
        assert_eq!(&second.response_bytes[0..2], &[0x22, 0x22]);
        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(second.decision.kind, ResolveDecisionKind::CacheHit);
        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 2);
        // The follower's QueryEventV1 is legitimately labeled `Hit` (served
        // from the cache entry the leader just populated), but its latency is
        // dominated by waiting on the leader's full backend round trip — it
        // must not land in the fast-hit latency bucket alongside genuine
        // cache hits.
        assert_eq!(
            metrics.duration_count(ResolverMetric::CacheHitQueryDuration),
            0
        );
        assert_eq!(
            metrics.duration_count(ResolverMetric::CacheMissQueryDuration),
            2
        );
    }

    /// RFC 1035 §4.1.1: RD=0's cache-only gate (`refuse_recursion`) is
    /// checked before a query would ever join an in-flight coalesced
    /// fetch, not just before a cold fetch would be started from scratch.
    /// An RD=0 query for a name another (RD=1) requester is already
    /// fetching must still be refused immediately -- it must not
    /// piggyback on the leader's in-flight work, and the leader's own
    /// fetch must be unaffected (still exactly one upstream request).
    #[tokio::test]
    async fn rd_zero_follower_is_refused_even_while_leaders_fetch_is_in_flight() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let response = upstream_response(a_response_with_answer(0xaaaa, "example.com", 60));
        let upstream = Arc::new(BlockingUpstream::new(Ok(response)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_cache(
            upstream.clone(),
            cache,
            events,
            metrics.clone(),
            1232,
        ));

        // Leader: RD=1, blocked on the upstream until released below.
        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        a_query(0x1111, "example.com"),
                    ))
                    .await
            })
        };
        upstream.wait_for_requests(1).await;

        // Follower: same name/type/class as the in-flight leader fetch,
        // but RD=0 -- must be refused, not coalesced onto it.
        let follower = service
            .resolve(ResolveRequest::new(
                "192.0.2.11".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_without_rd(0x2222, "example.com"),
            ))
            .await;

        assert_eq!(
            follower.decision.kind,
            ResolveDecisionKind::RecursionRefused
        );
        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            1,
            "the RD=0 follower must not add a second upstream request, and must not have \
             joined the leader's in-flight fetch either"
        );
        assert_eq!(metrics.count(ResolverMetric::RecursionRefused), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 0);

        let follower_message = Message::parse(&follower.response_bytes).unwrap();
        assert_eq!(follower_message.header.id, 0x2222);
        assert!(!follower_message.header.rd(), "RD=0 must echo RD=0");
        assert_eq!(
            follower_message.header.r_code(),
            ResponseCode::ServFail as u8
        );

        upstream.release.notify_waiters();
        let leader = leader.await.unwrap();
        assert_eq!(leader.decision.kind, ResolveDecisionKind::Allowed);
    }

    /// Regression test for RFC 4035 §3.2.2: same fallback path as
    /// `resolve_coalesced_follower_fallback_preserves_its_own_rd_bit`, but
    /// for the CD (checking disabled) bit. `MissKey` coalesces on
    /// name/type/class/namespace/DO only, not CD, so a follower whose own
    /// request set a *different* CD bit than the leader's must still get
    /// its own CD bit back in the shared/reused backend response bytes, not
    /// the leader's.
    #[tokio::test]
    async fn resolve_coalesced_follower_fallback_preserves_its_own_cd_bit() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let mut response = upstream_response(a_response_with_answer(0xaaaa, "example.com", 60));
        // Not cacheable, so the follower can't get a fresh cache-hit
        // reassembly and must fall back to the leader's raw response bytes.
        response.cache_directive =
            ResolutionCacheDirective::DoNotCache(ResolutionNoCacheReason::BackendPolicy);
        let upstream = Arc::new(BlockingUpstream::new(Ok(response)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_cache(
            upstream.clone(),
            cache,
            events,
            metrics.clone(),
            1232,
        ));

        // Leader: CD=0.
        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        a_query(0x1111, "example.com"),
                    ))
                    .await
            })
        };
        upstream.wait_for_requests(1).await;

        // Follower: same name/type/class, but CD=1 -- differs from the
        // leader's own request, which `MissKey` doesn't distinguish on.
        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        a_query_with_checking_disabled(0x2222, "example.com"),
                    ))
                    .await
            })
        };

        tokio::task::yield_now().await;
        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );
        upstream.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        let leader_message = Message::parse(&leader.response_bytes).unwrap();
        let follower_message = Message::parse(&follower.response_bytes).unwrap();
        assert!(
            !leader_message.header.cd(),
            "the leader's own request set CD=0"
        );
        assert!(
            follower_message.header.cd(),
            "the follower's own request set CD=1 -- it must not be overwritten with the \
             leader's CD=0 from the shared/reused backend response bytes"
        );
        assert_eq!(follower_message.header.id, 0x2222);
    }

    /// Regression test for the recursive-mode filtered-fallback header bug:
    /// unlike the two tests above (which use a generic `ResolutionBackend`
    /// mock with no `recursive_synthesis`, so `prepare_backend_result`'s
    /// DO=false filter branch never runs), this exercises the *real*
    /// recursive backend with a DNSSEC-bearing response, forcing a
    /// coalesced follower down the filtered-fallback path
    /// (`response.recursive_synthesis.is_some()` and
    /// `filtering_would_change_response` both true). A zero-capacity cache
    /// makes `store_cache_response` a silent no-op (`Shard::store_*`
    /// early-returns when `capacity == 0`), so the follower's
    /// `cache_hit_after_coalesced_miss` finds nothing and falls back to
    /// `prepare_backend_result` reusing the leader's synthesized response --
    /// exactly the scenario where the filtered branch used to reserialize
    /// with `synthesis.original_query` (the *leader's* request) instead of
    /// this follower's own `decoded.message`, putting the leader's ID/RD/CD
    /// on the follower's response (RFC 1035 §4.1.1, RFC 4035 §3.2.2).
    #[tokio::test]
    async fn resolve_coalesced_follower_filtered_fallback_preserves_its_own_header_fields() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 0,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let response_with_do = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![
                a_record("example.com", 60),
                rrsig_record("example.com", 60, A_RECORD_TYPE),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );
        // Only the `dnssec_ok = true` branch is ever exercised --
        // `resolve_one_hop` always requests DNSSEC from upstream now,
        // regardless of either requester's own DO flag.
        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
            response_with_do.clone(),
            response_with_do,
        ));
        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport.clone(),
        ));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend,
            cache,
            events,
            metrics.clone(),
            1232,
        ));

        // Leader: ID=0x1111, RD=1, CD=0, DO=false.
        let leader_query = a_query_with_edns(0x1111, "example.com", 1232, false);
        // Follower: same name/type/class (so it coalesces onto the same
        // `MissKey`), but a different ID and CD=1 -- neither of which
        // `MissKey` distinguishes on, and neither of which the leader's own
        // request shares. RD stays 1 here (unlike an earlier version of
        // this test): RD=0 now short-circuits to `RecursionRefused` before
        // ever reaching the coalescing path under test -- see
        // `rd_zero_still_gets_a_full_answer_but_echoes_rd_zero`.
        let mut follower_query = a_query_with_edns(0x2222, "example.com", 1232, false);
        let follower_flags = u16::from_be_bytes([follower_query[2], follower_query[3]]) | 0x0010;
        follower_query[2..4].copy_from_slice(&follower_flags.to_be_bytes());

        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        leader_query,
                    ))
                    .await
            })
        };
        transport.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        follower_query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );

        transport.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        assert!(
            !response_contains_rrsig(&leader.response_bytes),
            "the leader is DO=false and must not receive RRSIGs"
        );
        assert!(
            !response_contains_rrsig(&follower.response_bytes),
            "the follower is DO=false and must not receive RRSIGs either"
        );

        let leader_message = Message::parse(&leader.response_bytes).unwrap();
        let follower_message = Message::parse(&follower.response_bytes).unwrap();

        assert_eq!(leader_message.header.id, 0x1111);
        assert!(leader_message.header.rd(), "leader's own request set RD=1");
        assert!(!leader_message.header.cd(), "leader's own request set CD=0");

        assert_eq!(
            follower_message.header.id, 0x2222,
            "the follower's own transaction ID must survive the filtered fallback, \
             not the leader's"
        );
        assert!(
            follower_message.header.rd(),
            "the follower's own request set RD=1"
        );
        assert!(
            follower_message.header.cd(),
            "the follower's own request set CD=1 -- it must not be overwritten with the \
             leader's CD=0 by the filtered-fallback reserialization path"
        );
    }

    /// Regression test for the recursive-mode DO=true "nothing to filter"
    /// fast path (the third Codex adversarial-review finding in this area,
    /// after the ID/RD/CD-rewrite fix and the DO=false filtered-fallback
    /// header fix above): `prepare_backend_result` used to just reuse
    /// `response.bytes` -- built by `synthesize_recursive_cname_response`
    /// from whichever query happened to synthesize this shared response --
    /// for a DO=true requester whenever the unfiltered response already fit
    /// the UDP payload size, after only rewriting ID/RD/CD. On a
    /// coalesced-follower fallback (this test's zero-capacity cache forces
    /// one, same as the test above), that means a follower's own echoed
    /// question and OPT record could silently be the *leader's*, not its
    /// own: `MissKey` coalesces on name/type/class/namespace only for the
    /// recursive backend (its DO dimension is always canonicalized to
    /// `true` -- see `probe_cache`), not question-name casing, so a
    /// follower can legitimately send a differently-cased qname than the
    /// leader's and still coalesce onto the same in-flight fetch. Exercises
    /// the fix in `rebuild_recursive_response_with_own_framing`, invoked
    /// from `prepare_backend_result`'s final
    /// `else if backend_mode == ResolutionMode::Recursive && ...` branch.
    #[tokio::test]
    async fn resolve_coalesced_follower_do_true_fast_path_preserves_its_own_question_and_opt() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 0,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let response_with_do = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![
                a_record("example.com", 60),
                rrsig_record("example.com", 60, A_RECORD_TYPE),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );
        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
            response_with_do.clone(),
            response_with_do,
        ));
        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport.clone(),
        ));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend,
            cache,
            events,
            metrics.clone(),
            1232,
        ));

        // Leader: DO=true, lowercase qname.
        let leader_query = a_query_with_edns(0x1111, "example.com", 1232, true);
        // Follower: also DO=true (both requests land in the same
        // `MissKey` bucket for the recursive backend regardless of DO, but
        // keeping both DO=true here isolates this test to the DO=true
        // fast path rather than the DO=false filtered-fallback path
        // already covered above) and the same name/type/class, but a
        // differently-cased qname -- `MissKey` never distinguishes on
        // casing, so this still coalesces onto the leader's single
        // in-flight fetch.
        let follower_query = a_query_with_edns(0x2222, "EXAMPLE.com", 1232, true);

        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        leader_query,
                    ))
                    .await
            })
        };
        transport.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        follower_query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );

        transport.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        let leader_message = Message::parse(&leader.response_bytes).unwrap();
        let follower_message = Message::parse(&follower.response_bytes).unwrap();

        assert_eq!(leader_message.questions[0].qname, "example.com");
        assert_eq!(
            follower_message.questions[0].qname, "EXAMPLE.com",
            "the follower's own echoed question casing must survive the DO=true \
             fast path, not the leader's -- the echoed question must be sourced \
             from `decoded.message`, not `response.bytes`/`response_message`"
        );

        let follower_opt = follower_message
            .additionals
            .iter()
            .find(|record| matches!(record.record, RecordData::OPT(_)))
            .expect("the DO=true follower's own response must carry an OPT record");
        let RecordData::OPT(follower_edns) = &follower_opt.record else {
            unreachable!();
        };
        assert!(
            follower_edns.dnssec_ok,
            "the follower's own request set DO=1"
        );
    }

    /// Regression test for the exact scenario Codex's third adversarial
    /// review called out: an EDNS follower (DO=false, but it did advertise
    /// EDNS) coalescing behind a leader whose own request carried no EDNS
    /// OPT record at all, where the shared response contains nothing
    /// DNSSEC-specific for a DO=false filter pass to remove
    /// (`filtering_would_change_response` is false, landing in
    /// `prepare_backend_result`'s DO=false "nothing to filter" fast path).
    /// Before the fix, that path reused `response.bytes` verbatim -- built
    /// by `synthesize_recursive_cname_response` from the *leader's*
    /// non-EDNS query -- so the follower's own advertised EDNS silently
    /// vanished from its response even though it asked for it (RFC 6891
    /// §6.1.1/§7).
    #[tokio::test]
    async fn resolve_coalesced_edns_follower_behind_non_edns_leader_keeps_its_own_opt() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 0,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        // No DNSSEC-type records at all, so a DO=false filter pass is
        // proven to be a no-op (`filtering_would_change_response` false)
        // regardless of which requester's `dnssec_ok` it runs under.
        let response = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![a_record("example.com", 60)],
            Vec::new(),
            Vec::new(),
            true,
        );
        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
            response.clone(),
            response,
        ));
        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport.clone(),
        ));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend,
            cache,
            events,
            metrics.clone(),
            1232,
        ));

        // Leader: no EDNS at all -- no OPT record in its own request.
        let leader_query = a_query(0x1111, "example.com");
        // Follower: same name/type/class (coalesces onto the leader's
        // single in-flight fetch), but its own request *does* carry EDNS
        // (DO=false).
        let follower_query = a_query_with_edns(0x2222, "example.com", 1232, false);

        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        leader_query,
                    ))
                    .await
            })
        };
        transport.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        follower_query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );

        transport.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        let leader_message = Message::parse(&leader.response_bytes).unwrap();
        assert!(
            !leader_message
                .additionals
                .iter()
                .any(|record| matches!(record.record, RecordData::OPT(_))),
            "sanity check: the leader's own request carried no EDNS, so its own \
             response must carry no OPT record either"
        );

        let follower_message = Message::parse(&follower.response_bytes).unwrap();
        let follower_opt = follower_message
            .additionals
            .iter()
            .find(|record| matches!(record.record, RecordData::OPT(_)))
            .expect(
                "the follower advertised EDNS itself and must get its own OPT record \
                 back, not silently lose it just because the leader's synthesizing \
                 query had none",
            );
        let RecordData::OPT(follower_edns) = &follower_opt.record else {
            unreachable!();
        };
        assert!(
            !follower_edns.dnssec_ok,
            "the follower's own request set DO=0"
        );
    }

    /// The reverse of the test above: a non-EDNS follower coalescing
    /// behind an EDNS leader must not get an unsolicited OPT record it
    /// never asked for.
    #[tokio::test]
    async fn resolve_coalesced_non_edns_follower_behind_edns_leader_gets_no_opt() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 0,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let response = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![a_record("example.com", 60)],
            Vec::new(),
            Vec::new(),
            true,
        );
        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
            response.clone(),
            response,
        ));
        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport.clone(),
        ));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend,
            cache,
            events,
            metrics.clone(),
            1232,
        ));

        // Leader: EDNS, DO=false.
        let leader_query = a_query_with_edns(0x1111, "example.com", 1232, false);
        // Follower: no EDNS at all.
        let follower_query = a_query(0x2222, "example.com");

        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        leader_query,
                    ))
                    .await
            })
        };
        transport.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        follower_query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );

        transport.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        let leader_message = Message::parse(&leader.response_bytes).unwrap();
        assert!(
            leader_message
                .additionals
                .iter()
                .any(|record| matches!(record.record, RecordData::OPT(_))),
            "sanity check: the leader's own request carried EDNS, so its own \
             response must carry an OPT record"
        );

        let follower_message = Message::parse(&follower.response_bytes).unwrap();
        assert!(
            !follower_message
                .additionals
                .iter()
                .any(|record| matches!(record.record, RecordData::OPT(_))),
            "the follower's own request carried no EDNS -- it must not get an \
             unsolicited OPT record just because the leader's synthesizing query \
             had one"
        );
    }

    /// Section 05: a cache-miss (recursive-backend-forwarded) query
    /// carrying a well-formed Cookie option must get a response whose OPT
    /// record carries a fresh, correct RFC 9018 server cookie -- mirroring
    /// the cache-hit case (`resolve_cache_hit_response_carries_cookie_option_for_cookie_bearing_query`)
    /// but exercised through the recursive-miss/`mirrored_client_opt_record_with_cookie`
    /// path instead. A single, non-coalesced `resolve()` call, so this also
    /// proves `recursive_synthesis_reused_own_framing`'s cookie-forced
    /// rebuild actually attaches the cookie on the ordinary path, not just
    /// the coalesced-follower path.
    #[tokio::test]
    async fn resolve_recursive_miss_response_carries_cookie_option_for_cookie_bearing_query() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 0,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![a_record("example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend: Arc<dyn ResolutionBackend> = Arc::new(recursive_backend(transport));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let cookie_secret = Arc::new(CookieSecret::generate());
        let service = resolve_service_with_recursive_cache(backend, cache, events, metrics, 1232)
            .with_cookie_secret(cookie_secret);

        let client_cookie = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut cookie_option = vec![0u8, 10, 0, 8];
        cookie_option.extend_from_slice(&client_cookie);
        let query = a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                query,
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        let opt = response
            .additionals
            .iter()
            .find(|record| matches!(record.record, RecordData::OPT(_)))
            .expect("recursive-miss response to a Cookie-bearing query must carry an OPT record");
        let RecordData::OPT(edns) = &opt.record else {
            unreachable!();
        };
        let echoed_client_cookie = crate::protocol::edns_cookie::parse_cookie_option(&edns.options)
            .expect("OPT options must decode to a well-formed COOKIE option");
        assert_eq!(echoed_client_cookie, client_cookie);
        assert_eq!(
            edns.options.len(),
            4 + 8 + 16,
            "COOKIE option TLV must carry the 8-byte client cookie plus a 16-byte server cookie"
        );
    }

    /// Section 05: two coalesced/in-flight requesters for the same
    /// backend query, presenting different client cookies, must each
    /// receive their own distinct, correctly-computed COOKIE option --
    /// never a shared/replayed one. Builds on the same coalesced-follower
    /// harness pattern as `resolve_coalesced_edns_follower_behind_non_edns_leader_keeps_its_own_opt`.
    #[tokio::test]
    async fn resolve_coalesced_miss_gives_each_requester_a_distinct_cookie() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 0,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let response = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![a_record("example.com", 60)],
            Vec::new(),
            Vec::new(),
            true,
        );
        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
            response.clone(),
            response,
        ));
        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport.clone(),
        ));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let cookie_secret = Arc::new(CookieSecret::generate());
        let service = Arc::new(
            resolve_service_with_recursive_cache(backend, cache, events, metrics.clone(), 1232)
                .with_cookie_secret(cookie_secret),
        );

        let cookie_a = [0x11u8; 8];
        let cookie_b = [0x22u8; 8];
        let mut option_a = vec![0u8, 10, 0, 8];
        option_a.extend_from_slice(&cookie_a);
        let mut option_b = vec![0u8, 10, 0, 8];
        option_b.extend_from_slice(&cookie_b);
        let leader_query = a_query_with_edns_options(0x1111, "example.com", 1232, false, &option_a);
        let follower_query =
            a_query_with_edns_options(0x2222, "example.com", 1232, false, &option_b);

        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        leader_query,
                    ))
                    .await
            })
        };
        transport.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        follower_query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );

        transport.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        let opt_options = |bytes: &[u8]| -> Vec<u8> {
            let message = Message::parse(bytes).unwrap();
            let opt = message
                .additionals
                .iter()
                .find(|record| matches!(record.record, RecordData::OPT(_)))
                .expect("Cookie-bearing requester must get an OPT record back")
                .clone();
            let RecordData::OPT(edns) = opt.record else {
                unreachable!();
            };
            edns.options
        };
        let options_leader = opt_options(&leader.response_bytes);
        let options_follower = opt_options(&follower.response_bytes);

        assert_eq!(
            &options_leader[4..12],
            &cookie_a,
            "leader's response must echo its own client cookie, not the follower's"
        );
        assert_eq!(
            &options_follower[4..12],
            &cookie_b,
            "follower's response must echo its own client cookie, not the leader's"
        );
        assert_ne!(
            &options_leader[12..28],
            &options_follower[12..28],
            "each requester must get its own freshly-computed server cookie, \
             never a shared/replayed one"
        );
    }

    /// Section 05: `recursive_synthesis_reused_own_framing` must never
    /// report reused framing when either side carries a well-formed client
    /// cookie, even when the echoed question and DO bit otherwise match --
    /// a server cookie is time-dependent (RFC 9018 §4.4) and must never be
    /// replayed from whichever request originally synthesized the shared
    /// response.
    #[test]
    fn recursive_synthesis_reused_own_framing_returns_false_when_cookie_present() {
        let mut cookie_option = vec![0u8, 10, 0, 8];
        cookie_option.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let cookie_bytes =
            a_query_with_edns_options(0x1111, "example.com", 1232, false, &cookie_option);
        let no_cookie_bytes = a_query_with_edns(0x1111, "example.com", 1232, false);

        let cookie_message = Message::parse_owned(cookie_bytes).unwrap();
        let no_cookie_message = Message::parse_owned(no_cookie_bytes).unwrap();

        let decoded = DecodedQuery::new(cookie_message.clone()).unwrap();
        let synthesis = RecursiveSynthesisContext {
            original_query: no_cookie_message.clone(),
            original_question: decoded.question.clone(),
            final_question: decoded.question.clone(),
        };
        assert!(
            !recursive_synthesis_reused_own_framing(&decoded, &synthesis),
            "this requester's own cookie-bearing query must force a rebuild, even \
             though question and DO bit otherwise match"
        );

        // Symmetric case: this requester carries no cookie, but the
        // request that originally synthesized the shared response did.
        let decoded_no_cookie = DecodedQuery::new(no_cookie_message).unwrap();
        let synthesis_original_had_cookie = RecursiveSynthesisContext {
            original_query: cookie_message,
            original_question: decoded_no_cookie.question.clone(),
            final_question: decoded_no_cookie.question.clone(),
        };
        assert!(
            !recursive_synthesis_reused_own_framing(
                &decoded_no_cookie,
                &synthesis_original_had_cookie
            ),
            "a cookie on the synthesizing request alone must also force a rebuild"
        );

        // Regression: no cookie on either side, question and DO bit match
        // -- framing is genuinely reused, same as before this section.
        let synthesis_no_cookie = RecursiveSynthesisContext {
            original_query: decoded_no_cookie.message.clone(),
            original_question: decoded_no_cookie.question.clone(),
            final_question: decoded_no_cookie.question.clone(),
        };
        assert!(
            recursive_synthesis_reused_own_framing(&decoded_no_cookie, &synthesis_no_cookie),
            "regression: matching non-cookie framing must still be reported reused"
        );
    }

    /// Regression test for both independent Codex adversarial reviews'
    /// shared finding: `exceeds_unfiltered` is computed once, early, from
    /// the shared/leader-framed `response_bytes` -- *before* the DO=false
    /// "nothing to filter" fast path rebuilds this requester's own
    /// question/OPT framing via `rebuild_recursive_response_with_own_framing`.
    /// Reuses the exact leader/follower shape of
    /// `resolve_coalesced_edns_follower_behind_non_edns_leader_keeps_its_own_opt`
    /// above (non-EDNS leader, EDNS DO=false follower, no DNSSEC-only
    /// material so `filtering_would_change_response` is false and this
    /// really does land in the DO=false fast path), but with a
    /// `configured_max_udp_payload_size` chosen so the leader-framed bytes
    /// (no OPT at all) fit under it while appending the follower's own
    /// 11-byte OPT record tips the rebuilt response over: the leader's 13
    /// A-record response is 237 bytes with no OPT, comfortably under the
    /// 240-byte limit here (`exceeds_unfiltered` false), but 237 + 11 = 248
    /// bytes once the follower's own OPT is appended -- over the limit.
    /// Before the fix, the rebuilt-but-oversized bytes were shipped
    /// straight to the wire with TC=0, an RFC 6891 §6.2.3/§7 + RFC 1035
    /// §4.1.1 violation; the follower must instead receive a genuinely
    /// truncated (TC=1) response.
    #[tokio::test]
    async fn resolve_coalesced_edns_follower_do_false_fast_path_truncates_when_own_opt_overflows_limit()
     {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 0,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        // 13 A records, no DNSSEC-type records at all (so a DO=false
        // filter pass is proven to be a no-op regardless of who runs it):
        // header (12) + question (17) + 13 * 16-byte answers = 237 bytes
        // with no OPT record.
        let answers = (0..13)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let response = response_message_for_question(
            question,
            ResponseCode::NoError,
            answers,
            Vec::new(),
            Vec::new(),
            true,
        );
        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
            response.clone(),
            response,
        ));
        const CONFIGURED_MAX_UDP_PAYLOAD_SIZE: usize = 240;
        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: CONFIGURED_MAX_UDP_PAYLOAD_SIZE,
            },
            transport.clone(),
        ));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend,
            cache,
            events,
            metrics.clone(),
            CONFIGURED_MAX_UDP_PAYLOAD_SIZE,
        ));

        // Leader: no EDNS at all -- no OPT record in its own request, so
        // the shared response it synthesizes has none either.
        let leader_query = a_query(0x1111, "example.com");
        // Follower: same name/type/class (coalesces onto the leader's
        // single in-flight fetch), but its own request *does* carry EDNS
        // (DO=false) -- its own rebuilt OPT record is what tips the
        // response over the limit.
        let follower_query = a_query_with_edns(
            0x2222,
            "example.com",
            CONFIGURED_MAX_UDP_PAYLOAD_SIZE as u16,
            false,
        );

        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        leader_query,
                    ))
                    .await
            })
        };
        transport.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        follower_query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );

        transport.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        let leader_message = Message::parse(&leader.response_bytes).unwrap();
        assert!(
            !leader_message.header.tc(),
            "sanity check: the leader-framed (no-OPT) response must fit comfortably \
             under the configured limit and not truncate"
        );
        assert!(
            leader.response_bytes.len() <= CONFIGURED_MAX_UDP_PAYLOAD_SIZE,
            "sanity check: leader-framed bytes ({}) must actually fit under the \
             configured limit ({}) for this test to exercise the intended gap",
            leader.response_bytes.len(),
            CONFIGURED_MAX_UDP_PAYLOAD_SIZE
        );

        let follower_message = Message::parse(&follower.response_bytes).unwrap();
        assert!(
            follower_message.header.tc(),
            "the follower's own OPT record grows the rebuilt response past its own \
             UDP payload limit even though the leader-framed bytes fit -- it must \
             receive a truncated (TC=1) response, not an oversized TC=0 one \
             (found: {} bytes, limit {})",
            follower.response_bytes.len(),
            CONFIGURED_MAX_UDP_PAYLOAD_SIZE
        );
        assert!(
            follower.response_bytes.len() <= CONFIGURED_MAX_UDP_PAYLOAD_SIZE,
            "a truncated response must itself still fit under the payload limit"
        );
        assert!(
            follower_message.answers.is_empty(),
            "a truncated response carries no answer records"
        );
        let follower_opt = follower_message
            .additionals
            .iter()
            .find(|record| matches!(record.record, RecordData::OPT(_)))
            .expect(
                "the follower advertised EDNS itself and must still get an OPT \
                 record back on its truncated response",
            );
        let RecordData::OPT(follower_edns) = &follower_opt.record else {
            unreachable!();
        };
        assert!(
            !follower_edns.dnssec_ok,
            "the follower's own request set DO=0"
        );
    }

    /// The inverse of the test above, and a regression test for the same
    /// shared finding from both independent Codex adversarial reviews, on
    /// the other side of the bug: in the no-op-filter fast path, when
    /// `exceeds_unfiltered` (measured against the leader-framed bytes) is
    /// true, the code used to truncate immediately without ever checking
    /// `recursive_synthesis_reused_own_framing` first. A coalesced
    /// follower's own framing can be *smaller* than the leader's -- not
    /// just larger, as in the test above -- e.g. a non-EDNS follower behind
    /// an EDNS leader, where the leader-framed bytes (OPT included) exceed
    /// the limit purely because of the leader's own ~11-byte OPT record,
    /// but the follower-framed rebuild (no OPT at all) genuinely fits. The
    /// bug sent that follower an unnecessary TC=1, forcing an avoidable TCP
    /// retry, even though a fitting UDP response was achievable.
    ///
    /// Reuses the exact leader/follower record shape as
    /// `resolve_coalesced_edns_follower_do_false_fast_path_truncates_when_own_opt_overflows_limit`
    /// above (13 A records, no DNSSEC-only material, so
    /// `filtering_would_change_response` is false and this lands in the
    /// no-op-filter fast path, not the content-filtering branch): 237 bytes
    /// with no OPT, 248 bytes with the leader's own 11-byte OPT record
    /// appended. With the same 240-byte `configured_max_udp_payload_size`,
    /// the leader-framed (with-OPT) bytes exceed the limit while the
    /// follower-framed (no-OPT) bytes fit comfortably under it.
    #[tokio::test]
    async fn resolve_coalesced_non_edns_follower_do_false_fast_path_fits_when_leader_opt_overflows_limit()
     {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 0,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        // 13 A records, no DNSSEC-type records at all (so a DO=false
        // filter pass is proven to be a no-op regardless of who runs it):
        // header (12) + question (17) + 13 * 16-byte answers = 237 bytes
        // with no OPT record, 248 bytes with one.
        let answers = (0..13)
            .map(|_| a_record("example.com", 60))
            .collect::<Vec<_>>();
        let response = response_message_for_question(
            question,
            ResponseCode::NoError,
            answers,
            Vec::new(),
            Vec::new(),
            true,
        );
        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
            response.clone(),
            response,
        ));
        const CONFIGURED_MAX_UDP_PAYLOAD_SIZE: usize = 240;
        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: CONFIGURED_MAX_UDP_PAYLOAD_SIZE,
            },
            transport.clone(),
        ));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend,
            cache,
            events,
            metrics.clone(),
            CONFIGURED_MAX_UDP_PAYLOAD_SIZE,
        ));

        // Leader: EDNS, DO=false -- its own OPT record is what's baked
        // into the shared response and is what tips the leader-framed
        // bytes over the limit.
        let leader_query = a_query_with_edns(
            0x1111,
            "example.com",
            CONFIGURED_MAX_UDP_PAYLOAD_SIZE as u16,
            false,
        );
        // Follower: same name/type/class (coalesces onto the leader's
        // single in-flight fetch), but its own request carries no EDNS at
        // all -- its own rebuilt (OPT-less) framing is what genuinely fits
        // under the limit.
        let follower_query = a_query(0x2222, "example.com");

        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        leader_query,
                    ))
                    .await
            })
        };
        transport.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        follower_query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );

        transport.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        let leader_message = Message::parse(&leader.response_bytes).unwrap();
        assert!(
            leader_message
                .additionals
                .iter()
                .any(|record| matches!(record.record, RecordData::OPT(_)))
                || leader_message.header.tc(),
            "sanity check: the leader's own request carried EDNS, so its own \
             (oversized) response must either carry an OPT record or have \
             been truncated"
        );
        assert!(
            leader_message.header.tc(),
            "sanity check: the leader-framed (with-OPT) bytes must actually \
             exceed the configured limit for this test to exercise the \
             intended gap"
        );

        let follower_message = Message::parse(&follower.response_bytes).unwrap();
        assert!(
            !follower_message.header.tc(),
            "the follower's own (OPT-less) framing genuinely fits under the \
             configured limit even though the leader-framed bytes (OPT \
             included) don't -- it must receive a non-truncated (TC=0) \
             response, not an unnecessary TC=1 (found: {} bytes, limit {})",
            follower.response_bytes.len(),
            CONFIGURED_MAX_UDP_PAYLOAD_SIZE
        );
        assert!(
            follower.response_bytes.len() <= CONFIGURED_MAX_UDP_PAYLOAD_SIZE,
            "sanity check: the follower's response must actually fit under \
             the configured limit ({}) for the TC=0 assertion above to mean \
             anything (found: {})",
            CONFIGURED_MAX_UDP_PAYLOAD_SIZE,
            follower.response_bytes.len()
        );
        assert_eq!(
            follower_message.answers.len(),
            13,
            "the follower must receive the full, non-truncated 13-record \
             answer set"
        );
        assert!(
            !follower_message
                .additionals
                .iter()
                .any(|record| matches!(record.record, RecordData::OPT(_))),
            "the follower's own request carried no EDNS -- it must not get \
             an unsolicited OPT record just because the leader's \
             synthesizing query had one"
        );
    }

    /// Regression test for the performance-focused Codex adversarial
    /// review's finding: `rebuild_recursive_response_with_own_framing`
    /// must only run when this requester's own framing has actually been
    /// detected to differ from whichever request synthesized the shared
    /// response -- not unconditionally on every non-truncated
    /// recursive-synthesis response. This is the overwhelmingly common
    /// case: a single, non-coalesced DO=true recursive resolve, where
    /// `decoded` IS the request that synthesized `response_message` by
    /// construction, so the rebuild would just reproduce the same bytes.
    #[tokio::test]
    async fn resolve_single_recursive_do_true_request_skips_own_framing_rebuild() {
        reset_rebuild_recursive_response_with_own_framing_calls();

        let question = QuestionKey::new("example.com", 1, 1);
        let answers = vec![
            a_record("example.com", 60),
            rrsig_record("example.com", 60, A_RECORD_TYPE),
        ];
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 1232, true),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(!response.header.tc());
        assert_eq!(
            rebuild_recursive_response_with_own_framing_call_count(),
            0,
            "a single, non-coalesced request's own framing already matches what \
             synthesized the response -- the expensive rebuild must be skipped \
             entirely, not run unconditionally on every DO=true recursive response"
        );
    }

    /// Companion to the DO=true test above, covering the DO=false
    /// "nothing to filter" fast path instead: a single, non-coalesced
    /// DO=false recursive resolve whose response has nothing DNSSEC-only
    /// for a filter pass to remove must also skip the rebuild entirely.
    #[tokio::test]
    async fn resolve_single_recursive_do_false_request_skips_own_framing_rebuild() {
        reset_rebuild_recursive_response_with_own_framing_calls();

        let question = QuestionKey::new("example.com", 1, 1);
        let answers = vec![a_record("example.com", 60)];
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question_with_id(
                0xbeef,
                question,
                ResponseCode::NoError,
                answers,
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend = Arc::new(recursive_backend(transport));
        let service = ResolveQuery::with_cache_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            BackendSnapshot::new(
                backend,
                ResolutionMode::Recursive,
                7,
                BackendHealth::Healthy,
                Some("mode:recursive;generation:7".to_string()),
            ),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(RecordingMetrics::default()),
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1234, "example.com", 1232, false),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert!(!response.header.tc());
        assert!(!response_contains_rrsig(&outcome.response_bytes));
        assert_eq!(
            rebuild_recursive_response_with_own_framing_call_count(),
            0,
            "a single, non-coalesced DO=false request's own framing already matches \
             what synthesized the response -- the expensive rebuild must be skipped \
             entirely, not run unconditionally on every DO=false no-op-filter \
             recursive response"
        );
    }

    fn response_contains_rrsig(bytes: &[u8]) -> bool {
        let message = Message::parse(bytes).unwrap();
        message
            .answers
            .iter()
            .any(|record| matches!(record.record, RecordData::RRSIG { .. }))
    }

    /// Regression test for the recursive-mode `MissKey` coalescing fix:
    /// since the always-fetch-DNSSEC change in `resolve_one_hop`, the
    /// recursive backend queries upstream authorities with
    /// `dnssec_ok = true` unconditionally, so a DO=false and a DO=true
    /// request for the same name/type/class now do *identical* backend
    /// work and must coalesce onto a single in-flight fetch (`probe_cache`
    /// canonicalizes the DO dimension of `MissKey` to `true` for
    /// `ResolutionMode::Recursive`) -- unlike before that change, when
    /// keeping them separate was necessary because backend behavior really
    /// did differ by DO. This test also covers
    /// `prepare_backend_result`'s client-facing filter: the DO=false
    /// requester's own response must still have RRSIGs trimmed out even
    /// though the single shared fetch came back DNSSEC-complete, while the
    /// DO=true requester keeps them. And once fetched, RRSIGs must
    /// actually be stored (`build_rrset_entry`) rather than discarded, so
    /// a later DO=true hit is served from cache with no further backend
    /// fetch.
    #[tokio::test]
    async fn resolve_coalesces_concurrent_recursive_do_false_and_do_true_misses() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let response_without_do = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            vec![a_record("example.com", 60)],
            Vec::new(),
            Vec::new(),
            true,
        );
        let response_with_do = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![
                a_record("example.com", 60),
                rrsig_record("example.com", 60, A_RECORD_TYPE),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );
        let transport = Arc::new(DnssecAwareBlockingAuthorityTransport::new(
            response_without_do,
            response_with_do,
        ));
        let backend: Arc<dyn ResolutionBackend> = Arc::new(RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec!["198.51.100.53:53".parse().unwrap()],
                }],
                per_authority_timeout: Duration::from_millis(500),
                per_query_deadline: Duration::from_secs(2),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport.clone(),
        ));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend,
            cache,
            events,
            metrics.clone(),
            1232,
        ));

        let do_false_query = a_query_with_edns(0x1111, "example.com", 1232, false);
        let do_true_query = a_query_with_edns(0x2222, "example.com", 1232, true);

        let first = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        do_false_query,
                    ))
                    .await
            })
        };
        transport.wait_for_requests(1).await;

        let second = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        do_true_query,
                    ))
                    .await
            })
        };
        // The DO=true request must coalesce onto the DO=false request's
        // in-flight leader rather than issuing its own backend fetch, so
        // the transport must see no new request here.
        tokio::task::yield_now().await;
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "DO=false and DO=true misses must coalesce onto one backend fetch \
             in recursive mode, since backend behavior no longer depends on \
             either requester's own DO flag"
        );

        transport.release.notify_waiters();
        let first = first.await.unwrap();
        let second = second.await.unwrap();

        let requests = transport.requests.lock().unwrap().clone();
        assert_eq!(
            requests.len(),
            1,
            "DO=false and DO=true misses must coalesce onto one backend fetch"
        );
        // Upstream is always asked for DNSSEC material now, independent of
        // either requester's own DO flag -- see `resolve_one_hop`.
        assert!(requests.iter().all(|&(_, _, dnssec_ok)| dnssec_ok));

        assert!(
            !response_contains_rrsig(&first.response_bytes),
            "DO=false requester must not receive RRSIGs, even though the \
             shared backend fetch came back DNSSEC-complete -- \
             prepare_backend_result must filter the client-facing copy"
        );
        assert!(
            response_contains_rrsig(&second.response_bytes),
            "DO=true requester must receive the RRSIGs the backend returned"
        );

        // A subsequent DO=true query for the same name must be served from
        // the cache entry the coalesced fetch just populated, still
        // carrying RRSIGs, with no further backend fetch.
        let third = service
            .resolve(ResolveRequest::new(
                "192.0.2.12".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x3333, "example.com", 1232, true),
            ))
            .await;
        assert_eq!(third.decision.kind, ResolveDecisionKind::CacheHit);
        assert!(response_contains_rrsig(&third.response_bytes));
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "a cache hit must not trigger a new backend fetch"
        );
    }

    /// Forward-mode counterpart to
    /// `resolve_coalesces_concurrent_recursive_do_false_and_do_true_misses`:
    /// `ResolutionMode::Forward` was not touched by the always-fetch-DNSSEC
    /// change (that change is recursive-only, in `resolve_one_hop`) and
    /// still relays the client's own raw wire bytes -- including its DO
    /// flag -- verbatim to whatever it forwards to. A DO=false and a
    /// DO=true request for the same name/type/class can therefore still
    /// get genuinely different backend bytes, so `probe_cache` must keep
    /// the real per-requester `dnssec_ok` in `MissKey` for forward mode and
    /// these misses must NOT coalesce.
    #[tokio::test]
    async fn resolve_does_not_coalesce_concurrent_forward_do_false_and_do_true_misses() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xaaaa, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_cache(
            upstream.clone(),
            cache,
            events,
            metrics.clone(),
            1232,
        ));

        let do_false_query = a_query_with_edns(0x1111, "example.com", 1232, false);
        let do_true_query = a_query_with_edns(0x2222, "example.com", 1232, true);

        let first = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        do_false_query,
                    ))
                    .await
            })
        };
        upstream.wait_for_requests(1).await;

        let second = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        do_true_query,
                    ))
                    .await
            })
        };
        // If the DO=true request had incorrectly coalesced onto the
        // DO=false request's in-flight leader, it would never reach the
        // upstream at all, and this would time out.
        upstream.wait_for_requests(2).await;

        upstream.release.notify_waiters();
        let first = first.await.unwrap();
        let second = second.await.unwrap();

        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            2,
            "forward-mode DO=false and DO=true misses must not coalesce onto \
             one backend fetch"
        );
        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(second.decision.kind, ResolveDecisionKind::Allowed);
    }

    /// Regression test for the recursive-backend DO-independent-fetch
    /// change (the actual behavior change this whole rework buys): a
    /// DO=false request's *miss* must still populate a `dnssec_complete:
    /// true` entry, since upstream is now always asked for DNSSEC material
    /// regardless of the requester's own DO flag (`resolve_one_hop`) --
    /// while that DO=false requester's *own* response bytes must still have
    /// the RRSIGs trimmed out (`prepare_backend_result`'s client-facing
    /// filter). A later, sequential (not concurrent -- this exercises
    /// `lookup_chain`'s cache-hit path, not single-flight coalescing)
    /// DO=true request for the exact same name/type/class must then hit
    /// that entry immediately, with the RRSIGs the first (DO=false)
    /// client's fetch already captured, and no further backend fetch --
    /// unlike before this change, where a DO=false-driven entry was
    /// genuinely dnssec-incomplete and a DO=true reader had to pay for its
    /// own dedicated refetch.
    #[tokio::test]
    async fn resolve_sequential_do_true_after_do_false_store_hits_immediately_with_rrsigs() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let response_with_rrsig = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![
                a_record("example.com", 60),
                rrsig_record("example.com", 60, A_RECORD_TYPE),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(response_with_rrsig)]));
        let backend: Arc<dyn ResolutionBackend> =
            Arc::new(recursive_backend(Arc::clone(&transport)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend, cache, events, metrics, 1232,
        ));

        // First: a DO=false request. Upstream is asked for DNSSEC material
        // regardless (dnssec_ok=true on the wire to the authority), and the
        // response genuinely carries RRSIGs -- but this requester didn't
        // ask for them, so its own response bytes must not carry them.
        let first = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1111, "example.com", 1232, false),
            ))
            .await;
        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert!(
            !response_contains_rrsig(&first.response_bytes),
            "DO=false requester must not receive RRSIGs, even though its own \
             fetch was DNSSEC-complete"
        );
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "the DO=false request must have gone to the backend (a cache miss)"
        );
        assert!(
            requests_include_dnssec_ok(&transport, true),
            "the fetch must have asked upstream for DNSSEC material regardless \
             of the requester's own DO flag"
        );

        // Second: a DO=true request, strictly sequential (fully awaited
        // after the first completed) — so this cannot be exercising
        // single-flight coalescing, only the cache-hit path
        // (`lookup_chain`). It must now be served immediately from the
        // entry the DO=false request's fetch already populated -- no
        // second backend fetch, and no dedicated refetch.
        let second = service
            .resolve(ResolveRequest::new(
                "192.0.2.11".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x2222, "example.com", 1232, true),
            ))
            .await;

        assert_eq!(second.decision.kind, ResolveDecisionKind::CacheHit);
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            1,
            "a DO=true request must be served from the DO=false request's \
             dnssec-complete entry; it must not trigger a further backend fetch"
        );
        assert!(
            response_contains_rrsig(&second.response_bytes),
            "the DO=true requester must receive the RRSIGs the first \
             (DO=false) client's fetch already captured"
        );
    }

    fn requests_include_dnssec_ok(transport: &ScriptedAuthorityTransport, dnssec_ok: bool) -> bool {
        transport
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|&(_, _, requested_dnssec_ok)| requested_dnssec_ok == dnssec_ok)
    }

    /// Regression test for `cname_chain_records`' changed DO gate: a
    /// DO=false client resolving through a CNAME must still have the
    /// covering RRSIG for the CNAME hop captured into cache storage,
    /// independent of its own DO flag -- even though that same client's
    /// own immediate response omits it. A later DO=true reader for the
    /// exact same (pre-CNAME-walk) name must then be served that RRSIG
    /// from cache, with no further backend fetch.
    #[tokio::test]
    async fn resolve_do_false_cname_chain_captures_covering_rrsig_for_do_true_hit() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let alias = QuestionKey::new("alias.example.com", A_RECORD_TYPE, 1);
        let target = QuestionKey::new("target.example.com", A_RECORD_TYPE, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                alias.clone(),
                ResponseCode::NoError,
                vec![
                    cname_record("alias.example.com", 60, "target.example.com"),
                    rrsig_record("alias.example.com", 60, CNAME_RECORD_TYPE),
                ],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                target,
                ResponseCode::NoError,
                vec![a_record("target.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend: Arc<dyn ResolutionBackend> =
            Arc::new(recursive_backend(Arc::clone(&transport)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend, cache, events, metrics, 1232,
        ));

        let first = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1111, "alias.example.com", 1232, false),
            ))
            .await;
        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert!(
            !response_contains_rrsig(&first.response_bytes),
            "DO=false requester must not receive the CNAME hop's RRSIG"
        );
        assert_eq!(transport.requests.lock().unwrap().len(), 2);

        let second = service
            .resolve(ResolveRequest::new(
                "192.0.2.11".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x2222, "alias.example.com", 1232, true),
            ))
            .await;
        assert_eq!(second.decision.kind, ResolveDecisionKind::CacheHit);
        assert_eq!(
            transport.requests.lock().unwrap().len(),
            2,
            "the DO=true reader must be served from cache -- no further backend fetch"
        );
        assert!(
            response_contains_rrsig(&second.response_bytes),
            "the DO=true requester must receive the CNAME hop's RRSIG that the \
             DO=false requester's fetch already captured"
        );
    }

    /// Regression test for the OPT-drop gap the plan review caught:
    /// `recursive_response_record_supported` never matches
    /// `RecordData::OPT` at all -- it was never meant to decide OPT's
    /// fate, since the mirrored client OPT record is appended separately
    /// (`mirrored_client_opt_record`). `prepare_backend_result`'s filter
    /// step must replicate that append after filtering, or a DO=false
    /// client's filtered miss response would silently lose its OPT record
    /// (breaking EDNS echo -- UDP payload size negotiation, etc.).
    #[tokio::test]
    async fn resolve_do_false_miss_response_retains_opt_record_after_filtering() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([Ok(
            response_message_for_question(
                question,
                ResponseCode::NoError,
                vec![
                    a_record("example.com", 60),
                    rrsig_record("example.com", 60, A_RECORD_TYPE),
                ],
                Vec::new(),
                Vec::new(),
                true,
            ),
        )]));
        let backend: Arc<dyn ResolutionBackend> =
            Arc::new(recursive_backend(Arc::clone(&transport)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend, cache, events, metrics, 1232,
        ));

        let response = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1111, "example.com", 1232, false),
            ))
            .await;

        assert_eq!(response.decision.kind, ResolveDecisionKind::Allowed);
        assert!(!response_contains_rrsig(&response.response_bytes));
        let message = Message::parse(&response.response_bytes).unwrap();
        let opt = message
            .additionals
            .iter()
            .find(|record| matches!(record.record, RecordData::OPT(_)))
            .expect("filtered DO=false response must still carry an OPT record");
        let RecordData::OPT(edns) = &opt.record else {
            unreachable!();
        };
        assert_eq!(edns.udp_payload_size, 1232);
        assert!(!edns.dnssec_ok);
    }

    /// Regression test for the `questions`/`final_question` gap the plan
    /// review caught: `prepare_backend_result`'s filter step must filter
    /// against the terminal-CNAME-aware `(original_question,
    /// final_question)` pair `synthesize_recursive_cname_response` computed
    /// internally -- *not* `ResolutionResponse::final_question`, which is
    /// derived from the already-synthesized message and (since that
    /// message's own question section is just the original query's
    /// question) is actually the same value as the *original* question,
    /// not the terminal post-CNAME one. A DO=false direct query for a
    /// DNSSEC-type record that resolves through a CNAME must still keep
    /// the terminal DNSKEY answer -- it's the record the client explicitly
    /// asked for, just surfacing under the post-CNAME name.
    #[tokio::test]
    async fn resolve_do_false_dnssec_type_query_through_cname_filters_by_terminal_question() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let alias = QuestionKey::new("alias.example.com", DNSKEY_RECORD_TYPE, 1);
        let target = QuestionKey::new("target.example.com", DNSKEY_RECORD_TYPE, 1);
        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                alias.clone(),
                ResponseCode::NoError,
                vec![cname_record("alias.example.com", 60, "target.example.com")],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                target,
                ResponseCode::NoError,
                vec![dnskey_record("target.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend: Arc<dyn ResolutionBackend> =
            Arc::new(recursive_backend(Arc::clone(&transport)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = Arc::new(resolve_service_with_recursive_cache(
            backend, cache, events, metrics, 1232,
        ));

        let response = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                query_with_edns(
                    0x1111,
                    "alias.example.com",
                    DNSKEY_RECORD_TYPE,
                    1,
                    1232,
                    false,
                ),
            ))
            .await;

        assert_eq!(response.decision.kind, ResolveDecisionKind::Allowed);
        let message = Message::parse(&response.response_bytes).unwrap();
        assert_eq!(message.answers.len(), 2, "CNAME hop plus terminal DNSKEY");
        assert_eq!(message.answers[0].rtype, CNAME_RECORD_TYPE);
        assert!(
            matches!(message.answers[1].record, RecordData::DNSKEY { .. }),
            "the terminal DNSKEY the client explicitly asked for (just under \
             the post-CNAME name) must survive filtering, even though this \
             requester's DO flag is false"
        );
    }

    /// Forward-mode miss responses must be entirely unaffected by the
    /// recursive-only client-facing filter step: `prepare_backend_result`
    /// gates it on `backend_mode == ResolutionMode::Recursive`, since the
    /// forwarding backend relays client wire bytes verbatim with no EDNS
    /// construction of its own and has no `recursive_synthesis` context to
    /// filter with.
    #[tokio::test]
    async fn resolve_forward_mode_do_false_miss_response_is_not_filtered() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
        let response_message = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![
                a_record("example.com", 60),
                rrsig_record("example.com", 60, A_RECORD_TYPE),
            ],
            Vec::new(),
            Vec::new(),
            true,
        );
        let upstream = Arc::new(StaticUpstream::new(Ok(
            ResolutionResponse::forwarded_message(
                response_message.original_bytes.to_vec(),
                response_message,
                SystemTime::UNIX_EPOCH,
                0,
                "test-forwarder",
            ),
        )));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        let response = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns(0x1111, "example.com", 1232, false),
            ))
            .await;

        assert_eq!(response.decision.kind, ResolveDecisionKind::Allowed);
        assert!(
            response_contains_rrsig(&response.response_bytes),
            "forwarding-backend responses must pass through unfiltered even \
             for a DO=false requester -- the recursive-only filter step must \
             not fire for ResolutionMode::Forward"
        );
    }

    #[tokio::test]
    async fn resolve_blocks_coalesced_cache_hit_with_malicious_cname_target() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let question = QuestionKey::new("alias.example", A_RECORD_TYPE, 1);
        let response_message = response_message_for_question(
            question,
            ResponseCode::NoError,
            vec![
                cname_record("alias.example", 60, "target.malicious.example"),
                a_record("target.malicious.example", 60),
            ],
            Vec::new(),
            Vec::new(),
            false,
        );
        let upstream = Arc::new(BlockingUpstream::new(Ok(
            ResolutionResponse::forwarded_message(
                response_message.original_bytes.to_vec(),
                response_message,
                SystemTime::UNIX_EPOCH,
                0,
                "test-forwarder",
            ),
        )));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let policy = Arc::new(ClientScopedResponsePolicy {
            client_ip: "192.0.2.11".parse().unwrap(),
            domain: DomainSelector::subtree("malicious.example").unwrap(),
            rule_id: "malware-feed".to_string(),
        });
        let service = Arc::new(ResolveQuery::with_cache_and_policy(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache,
            policy,
            Arc::new(NoopLocalDnsEntries),
            CacheTtlPolicy::default(),
            upstream.clone(),
            Arc::new(ConfiguredResponseFactory::default()),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            metrics.clone(),
        ));
        let first = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        a_query(0x1111, "alias.example"),
                    ))
                    .await
            })
        };
        upstream.wait_for_requests(1).await;
        let second = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        a_query(0x2222, "alias.example"),
                    ))
                    .await
            })
        };

        tokio::task::yield_now().await;
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        upstream.release.notify_waiters();
        let first = first.await.unwrap();
        let second = second.await.unwrap();

        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(
            second.decision.kind,
            ResolveDecisionKind::Blocked(PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("malware-feed".to_string()),
            })
        );
        assert_eq!(
            response_code_from_wire(&second.response_bytes),
            Some(ResponseCode::Refused as u16)
        );
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 2);
            assert_eq!(
                recorded_events[1].terminal_outcome,
                QueryEventOutcome::Blocked(BlockReason::MaliciousDomain)
            );
            assert_eq!(
                recorded_events[1].cache_result,
                Some(QueryEventCacheResult::Hit)
            );
        }
        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
        assert_eq!(metrics.count(ResolverMetric::QueryBlocked), 1);
        assert_eq!(metrics.count(ResolverMetric::QueryAllowed), 1);
    }

    // `single_flight_leader_drop_wakes_followers_and_clears_key` (old flat
    // `SingleFlightMisses`/`SingleFlightTicket`/`SingleFlightLeader`,
    // removed by this section) is superseded by section-04's own
    // `cache::singleflight` test suite, which already covers leader-drop
    // cancellation and follower wakeup against the sharded replacement.

    #[tokio::test]
    async fn resolve_stores_upstream_response_as_decomposed_rrset_entry() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xbeef, "example.com", 45),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
        let request_time = SystemTime::UNIX_EPOCH + Duration::from_secs(123);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                request_time,
                a_query(0x4444, "example.com"),
            ))
            .await;

        assert_eq!(&outcome.response_bytes[0..2], &[0x44, 0x44]);
        let stores = cache.stores.lock().unwrap();
        assert_eq!(stores.len(), 1);
        let (decomposed, _epoch) = &stores[0];
        assert_eq!(decomposed.positive.len(), 1);
        let (name, qtype, qclass, entry) = &decomposed.positive[0];
        assert_eq!(name, "example.com");
        assert_eq!(*qtype, A_RECORD_TYPE);
        assert_eq!(*qclass, 1);
        assert_eq!(entry.response_code, ResponseCode::NoError);
        assert_eq!(entry.minimum_ttl, Duration::from_secs(45));
        assert_eq!(entry.stored_at, request_time);
        assert!(decomposed.negative.is_none());
        drop(stores);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
    }

    /// Regression test: the backend response's own AA bit must be captured
    /// onto the stored `RRsetEntry` (`build_rrset_entry`), not silently
    /// dropped -- this is what lets a later cache-hit response
    /// (`assemble_response`) reproduce AA instead of always claiming AA=0.
    #[tokio::test]
    async fn resolve_stores_upstream_response_authoritative_bit_on_decomposed_entry() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(set_response_aa(
            a_response_with_answer(0xbeef, "example.com", 45),
            true,
        )))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

        service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x4444, "example.com"),
            ))
            .await;

        let stores = cache.stores.lock().unwrap();
        assert_eq!(stores.len(), 1);
        let (decomposed, _epoch) = &stores[0];
        let (_, _, _, entry) = &decomposed.positive[0];
        assert!(
            entry.authoritative,
            "an AA=1 backend response must be stored with authoritative: true"
        );
    }

    /// Regression test for RFC 1035 §4.1.1: AA describes *this resolver's*
    /// own authority over the zone, not the upstream authority server's.
    /// For a `ResolutionMode::Recursive` backend, the fetched response's
    /// AA=1 describes the upstream authority, not rdns -- rdns is never
    /// itself authoritative while recursing, so the stored entry (and every
    /// later recursive cache hit assembled from it) must always be
    /// `authoritative: false`, regardless of the upstream's own AA bit.
    /// Contrast with `resolve_stores_upstream_response_authoritative_bit_on_decomposed_entry`
    /// above, which covers the forwarding backend (a transparent proxy)
    /// legitimately preserving a real AA=1 from its own backend.
    #[tokio::test]
    async fn resolve_recursive_backend_never_stores_upstreams_authoritative_bit() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(set_response_aa(
            a_response_with_answer(0xbeef, "example.com", 45),
            true,
        )))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_recursive_cache(
            upstream,
            cache.clone(),
            events,
            metrics.clone(),
            1232,
        );

        service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x4444, "example.com"),
            ))
            .await;

        let stores = cache.stores.lock().unwrap();
        assert_eq!(stores.len(), 1);
        let (decomposed, _epoch) = &stores[0];
        let (_, _, _, entry) = &decomposed.positive[0];
        assert!(
            !entry.authoritative,
            "a recursive backend's AA=1 upstream response must still be stored with \
             authoritative: false -- rdns is never itself authoritative while recursing"
        );
    }

    #[tokio::test]
    async fn resolve_records_negative_cache_store_metrics() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            nxdomain_response_with_soa(0xabcd, "example.com", 30, 120),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0xabcd, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let stores = cache.stores.lock().unwrap();
        assert_eq!(stores.len(), 1);
        let (decomposed, _epoch) = &stores[0];
        assert!(decomposed.positive.is_empty());
        let (name, key, entry) = decomposed
            .negative
            .as_ref()
            .expect("negative store expected");
        assert_eq!(name, "example.com");
        assert_eq!(key.qtype, None);
        assert_eq!(key.qclass, 1);
        assert_eq!(entry.kind, NegativeCacheKind::NxDomain);
        assert_eq!(
            entry.expires_at.duration_since(entry.stored_at).unwrap(),
            Duration::from_secs(30)
        );
        drop(stores);
        assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheNegativeStore), 1);
    }

    #[tokio::test]
    async fn resolve_honors_backend_do_not_cache_directive() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let mut response = upstream_response(a_response_with_answer(0x6666, "example.com", 60));
        response.cache_directive =
            ResolutionCacheDirective::DoNotCache(ResolutionNoCacheReason::BackendPolicy);
        let upstream = Arc::new(StaticUpstream::new(Ok(response)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x6666, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert!(cache.stores.lock().unwrap().is_empty());
        assert_eq!(metrics.count(ResolverMetric::CacheStoreSkipped), 1);
    }

    #[tokio::test]
    async fn resolve_passes_backend_generation_to_backend_request() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1234, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = ResolveQuery::with_cache_and_backend_generation(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            upstream.clone(),
            99,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            metrics,
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let requests = upstream.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].backend_generation, 99);
    }

    #[tokio::test]
    async fn resolve_uses_latest_backend_handle_snapshot() {
        let first_backend = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1234, "example.com", 60),
        ))));
        let second_backend = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1234, "example.com", 60),
        ))));
        let handle = BackendHandle::new(BackendSnapshot::forwarding(first_backend.clone(), 1));
        let metrics = Arc::new(RecordingMetrics::default());
        let service = ResolveQuery::with_cache_and_backend_handle(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(NoopDnsCache),
            CacheTtlPolicy::default(),
            handle.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            metrics.clone(),
        );
        assert_eq!(metrics.backend_statuses.lock().unwrap().len(), 1);

        service.publish_backend_snapshot(BackendSnapshot::new(
            second_backend.clone(),
            ResolutionMode::Forward,
            2,
            BackendHealth::Degraded,
            Some("mode:forward;generation:2".to_string()),
        ));
        assert_eq!(metrics.backend_statuses.lock().unwrap().len(), 2);
        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1234, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert!(first_backend.requests.lock().unwrap().is_empty());
        let requests = second_backend.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].backend_generation, 2);
        let statuses = metrics.backend_statuses.lock().unwrap();
        assert_eq!(statuses.len(), 3);
        assert_eq!(statuses[2].generation, 2);
    }

    // Regression test for the string-namespace -> u64-epoch cache-identity
    // refactor: two independently-*constructed* `BackendSnapshot`s (never
    // linked by a `publish_reload`) both start at the fresh-construction
    // baseline `cache_epoch: 0` regardless of their `generation` field --
    // unlike the old descriptive-string namespace, a bare epoch carries no
    // content-derived uniqueness of its own. That's fine in production,
    // where there is always exactly one long-lived `ResolveQuery` and
    // "backend generation changed" is only ever observed through
    // `publish_reload`/`publish_backend_snapshot`, both of which bump the
    // epoch relative to the *previous* published snapshot. So this test
    // exercises that real mechanism -- one service, reloaded from
    // generation 1 to generation 2 -- rather than two from-scratch services
    // sharing a cache, which was never how cache identity is actually
    // established.
    #[tokio::test]
    async fn backend_generation_separates_cache_entries() {
        let first_backend = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1111, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = ResolveQuery::with_cache_and_backend_generation(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::new(ShardedDnsCache::new(&CacheConfig {
                max_entries: 16,
                shard_count: Some(1),
                ..CacheConfig::default()
            })),
            CacheTtlPolicy::default(),
            first_backend.clone(),
            1,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            metrics.clone(),
        );

        let first = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1111, "example.com"),
            ))
            .await;
        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(first_backend.requests.lock().unwrap().len(), 1);

        let second_backend = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x2222, "example.com", 60),
        ))));
        // Reloading to generation 2 bumps the cache epoch (the descriptive
        // fingerprint differs by generation), so the entry warmed above
        // under generation 1 must not be served to this query -- proving a
        // real backend-generation reload actually separates cache entries
        // end-to-end through `resolve()`. `publish_reload` runs its sweep
        // synchronously before returning here, so this alone doesn't
        // isolate lookup-time epoch rejection from sweep-based removal --
        // `resolve_from_cache_rejects_stale_epoch_independent_of_sweep`
        // (`cache::assemble`'s tests) covers that property directly,
        // against a hand-seeded shard a sweep never touched.
        service.publish_reload(
            BackendSnapshot::forwarding(second_backend.clone(), 2),
            Arc::new(NoopLocalDnsEntries),
        );

        let second = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x2222, "example.com"),
            ))
            .await;

        assert_eq!(second.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(second_backend.requests.lock().unwrap().len(), 1);
    }

    /// `backend_generation_separates_cache_entries` (above) only proves two
    /// generations' entries land under different namespaces and so never
    /// collide as *lookups* — it never proves `publish_reload`'s
    /// namespace-sweep call (wired in section-07) actually runs and
    /// removes the stale entry, versus just leaving it as orphaned, never
    /// pruned capacity. This test seeds a real `ShardedDnsCache` under
    /// generation 1's namespace, reloads to generation 2, and asserts the
    /// domain is actually gone afterward, not merely unreachable.
    #[tokio::test]
    async fn backend_reload_sweep_invalidates_stale_generation_entries() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1111, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = ResolveQuery::with_cache_and_backend_generation(
            Arc::new(StandardProtocolCodec::new(1232)),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            CacheTtlPolicy::default(),
            upstream.clone(),
            1,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            metrics,
        );

        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1111, "example.com"),
            ))
            .await;
        assert_eq!(
            cache.domain_count(),
            1,
            "warming resolve should have stored one domain under generation 1's namespace"
        );

        let new_backend = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let new_snapshot = BackendSnapshot::forwarding(new_backend, 2);
        service.publish_reload(new_snapshot, Arc::new(NoopLocalDnsEntries));

        assert_eq!(
            cache.domain_count(),
            0,
            "publish_reload's namespace sweep should have removed the generation-1 entry, \
             not just left it unreachable"
        );
    }

    #[tokio::test]
    async fn resolve_rejects_invalid_backend_response_bytes() {
        for response in [
            vec![0x12],
            a_response_with_answer(0x5555, "other.example", 60),
            multi_question_a_response_with_answer(0x5555, "example.com", 60),
        ] {
            let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
            let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(response))));
            let events = Arc::new(RecordingEvents::default());
            let metrics = Arc::new(RecordingMetrics::default());
            let service =
                resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

            let outcome = service
                .resolve(ResolveRequest::new(
                    "192.0.2.10".parse().unwrap(),
                    SystemTime::UNIX_EPOCH,
                    a_query(0x5555, "example.com"),
                ))
                .await;

            assert_eq!(outcome.decision.kind, ResolveDecisionKind::BackendFailure);
            assert!(cache.stores.lock().unwrap().is_empty());
            assert_eq!(metrics.count(ResolverMetric::CacheStoreSkipped), 0);
            assert_eq!(metrics.count(ResolverMetric::UpstreamSuccess), 0);
            assert_eq!(metrics.count(ResolverMetric::UpstreamFailure), 1);
        }
    }

    #[tokio::test]
    async fn resolve_rejects_backend_response_when_metadata_and_bytes_drift() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let mut response = upstream_response(a_response_with_answer(0x5555, "example.com", 60));
        response.bytes = a_response_with_answer(0x5555, "other.example", 60).into();
        let upstream = Arc::new(StaticUpstream::new(Ok(response)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x5555, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::BackendFailure);
        assert!(cache.stores.lock().unwrap().is_empty());
        assert_eq!(metrics.count(ResolverMetric::CacheStoreSkipped), 0);
        assert_eq!(metrics.count(ResolverMetric::UpstreamSuccess), 0);
        assert_eq!(metrics.count(ResolverMetric::UpstreamFailure), 1);
    }

    #[tokio::test]
    async fn resolve_caches_response_when_question_differs_only_by_case() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x5555, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x5555, "Example.COM"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        let stores = cache.stores.lock().unwrap();
        assert_eq!(stores.len(), 1);
        let (decomposed, _epoch) = &stores[0];
        assert_eq!(decomposed.positive[0].0, "example.com");
        assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheStoreSkipped), 0);
    }

    // `resolve_does_not_store_after_cache_bypass_or_unavailable` (old flat
    // `CacheLookup::Bypass`/`CacheLookup::Unavailable`, removed by this
    // section) is superseded by `resolve_bypasses_cache_for_unsupported_edns_options`
    // below, which already exercises the real bypass path (`cache_supported`
    // returning false, not a canned lookup-result variant) and asserts the
    // same "no lookup, no store" invariant.

    #[tokio::test]
    async fn resolve_bypasses_cache_for_unsupported_edns_options() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x7777, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
        let edns_nsid = [0u8, 3, 0, 2, 0xaa, 0xbb]; // option code 3 (NSID), length 2

        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns_options(0x7777, "example.com", 1232, false, &edns_nsid),
            ))
            .await;

        assert!(cache.lookups.lock().unwrap().is_empty());
        assert!(cache.stores.lock().unwrap().is_empty());
        assert_eq!(metrics.count(ResolverMetric::CacheBypass), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
    }

    #[tokio::test]
    async fn resolve_admits_well_formed_cookie_only_query_to_cache() {
        let now = SystemTime::UNIX_EPOCH;
        let record = a_record("example.com", 60);
        let entry = seed_rrset_entry(&record, Duration::from_secs(60), now, 0);
        let resolved = cache::ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry.into())],
            refresh_hints: Vec::new(),
        };
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
        let cookie_option = [
            0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option),
            ))
            .await;

        assert!(!cache.lookups.lock().unwrap().is_empty());
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheBypass), 0);
    }

    #[tokio::test]
    async fn resolve_bypasses_cache_for_cookie_combined_with_other_option() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x7777, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
        // A well-formed COOKIE option (code 10, len 8) immediately followed
        // by an NSID option (code 3, len 2) in the same options blob.
        let mut options = vec![
            0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        options.extend_from_slice(&[0u8, 3, 0, 2, 0xaa, 0xbb]);

        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns_options(0x7777, "example.com", 1232, false, &options),
            ))
            .await;

        assert!(cache.lookups.lock().unwrap().is_empty());
        assert!(cache.stores.lock().unwrap().is_empty());
        assert_eq!(metrics.count(ResolverMetric::CacheBypass), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
    }

    #[tokio::test]
    async fn resolve_cache_lookup_key_ignores_client_cookie_bytes() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x7777, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

        let cookie_a = [
            0u8, 10, 0, 8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        ];
        let cookie_b = [
            0u8, 10, 0, 8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        ];

        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_a),
            ))
            .await;
        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.11".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_b),
            ))
            .await;

        let lookups = cache.lookups.lock().unwrap();
        assert_eq!(lookups.len(), 2);
        assert_eq!(lookups[0], lookups[1]); // identical (qname, qtype, qclass) despite different client cookies
    }

    #[tokio::test]
    async fn resolve_cache_hit_response_carries_cookie_option_for_cookie_bearing_query() {
        let now = SystemTime::UNIX_EPOCH;
        let record = a_record("example.com", 60);
        let entry = seed_rrset_entry(&record, Duration::from_secs(60), now, 0);
        let resolved = cache::ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry.into())],
            refresh_hints: Vec::new(),
        };
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);
        let client_cookie = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut cookie_option = vec![0u8, 10, 0, 8];
        cookie_option.extend_from_slice(&client_cookie);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option),
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        let opt = response
            .additionals
            .iter()
            .find(|record| matches!(record.record, RecordData::OPT(_)))
            .expect("cache-hit response to a Cookie-bearing query must carry an OPT record");
        let RecordData::OPT(edns) = &opt.record else {
            unreachable!();
        };
        let echoed_client_cookie = crate::protocol::edns_cookie::parse_cookie_option(&edns.options)
            .expect("OPT options must decode to a well-formed COOKIE option");
        assert_eq!(echoed_client_cookie, client_cookie);
        assert_eq!(
            edns.options.len(),
            4 + 8 + 16,
            "COOKIE option TLV must carry the 8-byte client cookie plus a 16-byte server cookie"
        );
    }

    #[tokio::test]
    async fn resolve_shared_cache_hit_gives_each_requester_a_distinct_cookie() {
        let now = SystemTime::UNIX_EPOCH;
        let record = a_record("example.com", 60);
        let entry = seed_rrset_entry(&record, Duration::from_secs(60), now, 0);
        let resolved = cache::ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry.into())],
            refresh_hints: Vec::new(),
        };
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        let cookie_a = [0x11u8; 8];
        let cookie_b = [0x22u8; 8];
        let mut option_a = vec![0u8, 10, 0, 8];
        option_a.extend_from_slice(&cookie_a);
        let mut option_b = vec![0u8, 10, 0, 8];
        option_b.extend_from_slice(&cookie_b);

        let outcome_a = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                now,
                a_query_with_edns_options(0x7777, "example.com", 1232, false, &option_a),
            ))
            .await;
        let outcome_b = service
            .resolve(ResolveRequest::new(
                "192.0.2.11".parse().unwrap(),
                now,
                a_query_with_edns_options(0x8888, "example.com", 1232, false, &option_b),
            ))
            .await;

        let message_a = Message::parse(&outcome_a.response_bytes).unwrap();
        let message_b = Message::parse(&outcome_b.response_bytes).unwrap();
        assert_eq!(
            message_a.answers, message_b.answers,
            "both requesters share the same cached answer data"
        );

        let opt_options = |message: &Message| -> Vec<u8> {
            let opt = message
                .additionals
                .iter()
                .find(|record| matches!(record.record, RecordData::OPT(_)))
                .expect("cache-hit response must carry an OPT record");
            let RecordData::OPT(edns) = &opt.record else {
                unreachable!();
            };
            edns.options.clone()
        };
        let options_a = opt_options(&message_a);
        let options_b = opt_options(&message_b);

        assert_eq!(
            &options_a[4..12],
            &cookie_a,
            "response A must echo requester A's own client cookie"
        );
        assert_eq!(
            &options_b[4..12],
            &cookie_b,
            "response B must echo requester B's own client cookie"
        );
        assert_ne!(
            &options_a[12..28],
            &options_b[12..28],
            "each requester must get its own freshly-computed server cookie, \
             never a shared/replayed one"
        );
    }

    /// PR review finding: `cache_supported()` admits Cookie-only queries
    /// regardless of backend mode, but section-05's cookie-aware OPT
    /// rebuild only ever ran for `ResolutionMode::Recursive` responses.
    /// This is the forward-mode counterpart of
    /// `resolve_recursive_miss_response_carries_cookie_option_for_cookie_bearing_query`:
    /// a single, non-coalesced forward-mode miss for a Cookie-bearing query
    /// must get its own rdns-computed server cookie, not silently pass the
    /// upstream forwarder's raw (cookie-less, in this fixture) response
    /// straight through.
    #[tokio::test]
    async fn resolve_forward_miss_response_carries_own_cookie_option_for_cookie_bearing_query() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x7777, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let cookie_secret = Arc::new(CookieSecret::generate());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232)
            .with_cookie_secret(cookie_secret);

        let client_cookie = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut cookie_option = vec![0u8, 10, 0, 8];
        cookie_option.extend_from_slice(&client_cookie);
        let query = a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                query,
            ))
            .await;

        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(
            response.answers.len(),
            1,
            "the upstream's real answer content must be preserved verbatim"
        );
        let opt = response
            .additionals
            .iter()
            .find(|record| matches!(record.record, RecordData::OPT(_)))
            .expect(
                "forward-mode miss response to a Cookie-bearing query must carry an OPT record",
            );
        let RecordData::OPT(edns) = &opt.record else {
            unreachable!();
        };
        let echoed_client_cookie = crate::protocol::edns_cookie::parse_cookie_option(&edns.options)
            .expect("OPT options must decode to a well-formed COOKIE option");
        assert_eq!(echoed_client_cookie, client_cookie);
        assert_eq!(
            edns.options.len(),
            4 + 8 + 16,
            "COOKIE option TLV must carry the 8-byte client cookie plus a 16-byte server cookie"
        );
    }

    /// PR review finding, coalesced case: `MissKey` coalesces on
    /// name/type/class/namespace/DO only, never on cookie bytes or client
    /// IP -- so when the leader's forwarded response doesn't end up stored
    /// (forcing every `RecordingCache` lookup to `Miss` here, including the
    /// follower's post-coalesce re-probe), `resolve_coalesced_follower`
    /// falls back to reusing the leader's raw backend result. Before the
    /// fix, the follower would have received the *leader's* echoed client
    /// cookie back -- an RFC 7873 §5.2 violation. Two coalesced requesters
    /// with distinct client cookies must each get their own correctly
    /// -echoed cookie.
    #[tokio::test]
    async fn resolve_coalesced_forward_miss_gives_each_requester_a_distinct_cookie() {
        let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
        let upstream = Arc::new(BlockingUpstream::new(Ok(upstream_response(
            a_response_with_answer(0xaaaa, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let cookie_secret = Arc::new(CookieSecret::generate());
        let service = Arc::new(
            resolve_service_with_cache(upstream.clone(), cache, events, metrics.clone(), 1232)
                .with_cookie_secret(cookie_secret),
        );

        let cookie_a = [0x11u8; 8];
        let cookie_b = [0x22u8; 8];
        let mut option_a = vec![0u8, 10, 0, 8];
        option_a.extend_from_slice(&cookie_a);
        let mut option_b = vec![0u8, 10, 0, 8];
        option_b.extend_from_slice(&cookie_b);
        let leader_query = a_query_with_edns_options(0x1111, "example.com", 1232, false, &option_a);
        let follower_query =
            a_query_with_edns_options(0x2222, "example.com", 1232, false, &option_b);

        let leader = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.10".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        leader_query,
                    ))
                    .await
            })
        };
        upstream.wait_for_requests(1).await;

        let follower = {
            let service = Arc::clone(&service);
            tokio::spawn(async move {
                service
                    .resolve(ResolveRequest::new(
                        "192.0.2.11".parse().unwrap(),
                        SystemTime::UNIX_EPOCH,
                        follower_query,
                    ))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            upstream.requests.lock().unwrap().len(),
            1,
            "the follower must coalesce onto the leader's single in-flight fetch"
        );

        upstream.release.notify_waiters();
        let leader = leader.await.unwrap();
        let follower = follower.await.unwrap();

        assert_eq!(metrics.count(ResolverMetric::CacheCoalescedMiss), 1);

        let opt_options = |bytes: &[u8]| -> Vec<u8> {
            let message = Message::parse(bytes).unwrap();
            let opt = message
                .additionals
                .iter()
                .find(|record| matches!(record.record, RecordData::OPT(_)))
                .expect("Cookie-bearing requester must get an OPT record back")
                .clone();
            let RecordData::OPT(edns) = opt.record else {
                unreachable!();
            };
            edns.options
        };
        let options_leader = opt_options(&leader.response_bytes);
        let options_follower = opt_options(&follower.response_bytes);

        assert_eq!(
            &options_leader[4..12],
            &cookie_a,
            "leader's response must echo its own client cookie, not the follower's"
        );
        assert_eq!(
            &options_follower[4..12],
            &cookie_b,
            "follower's response must echo its own client cookie, not the leader's"
        );
        assert_ne!(
            &options_leader[12..28],
            &options_follower[12..28],
            "each requester must get its own freshly-computed server cookie, \
             never a shared/replayed one"
        );
    }

    #[tokio::test]
    async fn resolve_bypasses_cache_for_unsupported_edns_flags_and_version() {
        for request in [
            a_query_with_edns_details(0x7777, "example.com", 1232, false, 0, 1, &[]),
            a_query_with_edns_flags(0x7777, "example.com", 1232, false, 0, 0, 0x4000, &[]),
        ] {
            let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
            let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
                a_response_with_answer(0x7777, "example.com", 60),
            ))));
            let events = Arc::new(RecordingEvents::default());
            let metrics = Arc::new(RecordingMetrics::default());
            let service =
                resolve_service_with_cache(upstream, cache.clone(), events, metrics, 1232);

            let _ = service
                .resolve(ResolveRequest::new(
                    "192.0.2.10".parse().unwrap(),
                    SystemTime::UNIX_EPOCH,
                    request,
                ))
                .await;

            assert!(cache.lookups.lock().unwrap().is_empty());
            assert!(cache.stores.lock().unwrap().is_empty());
        }
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
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(
                recorded_events[0].terminal_outcome,
                QueryEventOutcome::ProtocolError(ResponseCode::FormErr)
            );
            assert_eq!(
                recorded_events[0].response_code,
                Some(ResponseCode::FormErr as u16)
            );
            assert_eq!(recorded_events[0].cache_result, None);
        }
        assert!(
            metrics
                .increments
                .lock()
                .unwrap()
                .contains(&ResolverMetric::ProtocolError)
        );
    }

    /// Regression test for the protocol-error path (FORMERR/NOTIMP)
    /// dropping EDNS OPT and CD for a query that `Message::parse` can fully
    /// parse but that fails standard-query validation for an unrelated
    /// reason (here: an unsupported opcode). Previously
    /// `decode_or_protocol_error` discarded the parsed request entirely on
    /// any decode failure, so this produced a NOTIMP with ARCOUNT=0 and
    /// CD=0 even though the query carried EDNS+CD -- the same RFC 6891
    /// §6.1.1 / RFC 4035 §3.2.2 violation fixed elsewhere in this codebase
    /// for SERVFAIL/blocked/TCP-oversized-response fallbacks.
    #[tokio::test]
    async fn resolve_protocol_error_for_unsupported_opcode_preserves_requester_opt_and_cd() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        // `resolve_service` configures `StandardProtocolCodec::new(1232)`,
        // so the resolver's own configured UDP payload size is 1232 --
        // distinct from the 4096 this query advertises, proving the OPT in
        // the response reflects the resolver's size, not a mirror of the
        // requester's.
        let service = resolve_service(upstream.clone(), events.clone(), metrics.clone());

        let mut request =
            a_query_with_edns_and_checking_disabled(0x9abc, "example.com", 4096, false);
        // Set OPCODE (bits 11-14 of the flags word) to 1 (IQUERY), an
        // unsupported opcode. The wire format is otherwise entirely
        // well-formed, so `Message::parse` still succeeds even though
        // `validate_standard_query_header` rejects it.
        let flags = u16::from_be_bytes([request[2], request[3]]) | 0x0800;
        request[2..4].copy_from_slice(&flags.to_be_bytes());

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                request,
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::ProtocolError(ResponseCode::NotImp)
        );
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.id, 0x9abc);
        assert_eq!(response.header.r_code(), ResponseCode::NotImp as u8);
        assert_eq!(response.questions.len(), 1);
        assert!(
            response.header.cd(),
            "CD must be copied from the request per RFC 4035 §3.2.2"
        );
        let opt_records: Vec<_> = response
            .additionals
            .iter()
            .filter_map(|record| match &record.record {
                RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .collect();
        assert_eq!(
            opt_records.len(),
            1,
            "an EDNS requester must get exactly one OPT record back per RFC 6891 §6.1.1"
        );
        assert_eq!(
            opt_records[0].udp_payload_size, 1232,
            "the OPT record must advertise this resolver's own configured UDP payload size, not the requester's"
        );
        assert!(upstream.requests.lock().unwrap().is_empty());
    }

    /// End-to-end regression test for RFC 6891 §6.1.3 BADVERS: a query
    /// advertising an EDNS version rdns doesn't support (rdns implements
    /// version 0 only) must never reach the backend, and the response must
    /// carry the 12-bit extended RCODE 16 (split across the header's RCODE
    /// nibble and the OPT record's extended-RCODE byte) with CD still
    /// copied and the OPT record still present, mirroring the same
    /// EDNS/CD-preservation behavior already covered for NOTIMP above.
    #[tokio::test]
    async fn resolve_protocol_error_for_unsupported_edns_version_returns_badvers() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream.clone(), events.clone(), metrics.clone());

        let request = a_query_with_edns_details(0x9abd, "example.com", 4096, true, 0, 7, &[]);
        let flags = u16::from_be_bytes([request[2], request[3]]) | 0x0010; // CD=1
        let mut request = request;
        request[2..4].copy_from_slice(&flags.to_be_bytes());

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                request,
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::ProtocolError(ResponseCode::FormErr),
            "response_code() buckets BADVERS as FormErr for metrics purposes -- see its doc comment"
        );
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.id, 0x9abd);
        assert_eq!(response.questions.len(), 1);
        assert!(
            response.header.cd(),
            "CD must be copied from the request per RFC 4035 §3.2.2"
        );
        let opt = response
            .additionals
            .iter()
            .find_map(|record| match &record.record {
                RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .expect("an EDNS requester must get exactly one OPT record back per RFC 6891 §6.1.1");
        let combined_extended_rcode =
            (u16::from(opt.extended_rcode) << 4) | u16::from(response.header.r_code());
        assert_eq!(combined_extended_rcode, 16, "16 == BADVERS");
        assert_eq!(
            opt.version, 0,
            "the response OPT must advertise the version rdns actually supports"
        );
        assert_eq!(
            opt.udp_payload_size, 1232,
            "the OPT record must advertise this resolver's own configured UDP payload size, not the requester's"
        );
        assert!(upstream.requests.lock().unwrap().is_empty());
    }

    /// RFC 1035 §4.1.1: RD=0 asks rdns not to pursue the query on the
    /// client's behalf. rdns has no authoritative-only mode with
    /// delegation data to hand back as a referral, so it implements this
    /// as "cache-only" -- matching how a public recursive resolver like
    /// 1.1.1.1 treats RD=0 (confirmed by hand: `dig +norecurse` gets
    /// NOERROR for an already-cached name but SERVFAIL for a cold one).
    /// A cache miss under RD=0 must be refused with SERVFAIL rather than
    /// triggering a fresh backend fetch. The cache-*hit* side of this is
    /// already covered by `resolve_rewrites_rd_flag_for_current_request_on_cache_hit`
    /// above; the in-flight-coalescing edge case is covered by
    /// `rd_zero_follower_is_refused_even_while_leaders_fetch_is_in_flight`
    /// below.
    #[tokio::test]
    async fn rd_zero_query_is_refused_on_a_cache_miss() {
        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
            ..CacheConfig::default()
        }));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream.clone(), cache, events, metrics.clone(), 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_without_rd(0xbeef, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::RecursionRefused);
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.id, 0xbeef);
        assert!(!response.header.rd(), "RD=0 on the query must echo RD=0");
        assert_eq!(response.header.r_code(), ResponseCode::ServFail as u8);
        assert!(
            response.answers.is_empty(),
            "a refused RD=0 query must not carry an answer"
        );
        assert!(
            upstream.requests.lock().unwrap().is_empty(),
            "RD=0 on a cache miss must not trigger a fresh backend fetch"
        );
        assert_eq!(metrics.count(ResolverMetric::RecursionRefused), 1);
        assert_eq!(
            metrics.duration_count(ResolverMetric::CacheMissQueryDuration),
            0,
            "a refused RD=0 query never performs a real backend miss/fetch, so its latency \
             must not land in the cache-miss/backend-round-trip latency bucket"
        );
    }

    /// Regression test for the recovery path (see
    /// `recovery_tolerates_duplicate_opt_and_recovers_first_ones_dnssec_ok`
    /// in `protocol::tests` for the unit-level version): a query with CD=1
    /// and *two* OPT records is itself a distinct FORMERR condition (RFC
    /// 6891 §6.1.1 -- `ar_count > 1` fails header validation), but its
    /// header and question are still perfectly well-formed. Recovering
    /// context for the FORMERR response by re-running a full parse of the
    /// body would itself fail here (a full parse correctly rejects more
    /// than one OPT record), which previously meant this shape degraded
    /// all the way to a header-only response -- losing both the CD echo
    /// and the mandatory responder OPT record. The response must still
    /// copy CD (RFC 4035 §3.2.2) and carry exactly one responder OPT
    /// record (RFC 6891 §6.1.1).
    #[tokio::test]
    async fn resolve_protocol_error_for_duplicate_opt_preserves_cd_and_single_responder_opt() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream.clone(), events.clone(), metrics.clone());

        let mut request =
            a_query_with_edns_and_checking_disabled(0x9abc, "example.com", 4096, false);
        // Append a second OPT record and bump ar_count to 2 -- the query is
        // now malformed (RFC 6891 §6.1.1 allows at most one OPT record),
        // but the header and question up to this point remain perfectly
        // parseable.
        request.push(0);
        request.extend_from_slice(&41u16.to_be_bytes()); // type = OPT
        request.extend_from_slice(&512u16.to_be_bytes()); // udp payload size
        request.extend_from_slice(&0u32.to_be_bytes()); // extended rcode/version/flags
        request.extend_from_slice(&0u16.to_be_bytes()); // rdlength = 0
        request[10..12].copy_from_slice(&2u16.to_be_bytes());

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                request,
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::ProtocolError(ResponseCode::FormErr)
        );
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.id, 0x9abc);
        assert_eq!(response.header.r_code(), ResponseCode::FormErr as u8);
        assert_eq!(response.questions.len(), 1);
        assert!(
            response.header.cd(),
            "CD must be copied from the request per RFC 4035 §3.2.2 even for a duplicate-OPT query"
        );
        let opt_records: Vec<_> = response
            .additionals
            .iter()
            .filter_map(|record| match &record.record {
                RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .collect();
        assert_eq!(
            opt_records.len(),
            1,
            "the response must carry exactly one responder OPT record per RFC 6891 §6.1.1"
        );
        assert_eq!(
            opt_records[0].udp_payload_size, 1232,
            "the OPT record must advertise this resolver's own configured UDP payload size"
        );
        assert!(upstream.requests.lock().unwrap().is_empty());
    }

    /// Regression test for the recovery path (see
    /// `recovery_skips_extra_questions_before_scanning_for_opt` in
    /// `protocol::tests` for the unit-level version): a query with two
    /// questions is itself a distinct FORMERR condition (RFC 6891 §6.1.1 --
    /// `validate_standard_query_header` requires exactly one question, so
    /// `qd_count == 2` fails with `InvalidQuestionCount`), but its header
    /// and first question are still perfectly well-formed, and a
    /// legitimate OPT record follows both questions. Recovery keeps only
    /// the first question, but must skip over the *second* one before
    /// scanning for EDNS context -- otherwise it scans into the second
    /// question's own bytes instead of the OPT record that follows it,
    /// losing both the CD echo and the mandatory responder OPT record.
    #[tokio::test]
    async fn resolve_protocol_error_for_two_questions_preserves_cd_and_single_responder_opt() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream.clone(), events.clone(), metrics.clone());

        let mut request =
            a_query_with_edns_and_checking_disabled(0x9abc, "example.com", 4096, false);
        // `a_query_with_edns_and_checking_disabled` builds header + one
        // question + one OPT record (ar_count already 1). Splice a second
        // question in between the first question and the OPT record, and
        // bump qd_count to 2 -- the query is now malformed, but everything
        // up through the OPT record remains perfectly parseable.
        let first_question_len = {
            let mut encoded = Vec::new();
            for label in "example.com".split('.') {
                encoded.push(label.len() as u8);
                encoded.extend_from_slice(label.as_bytes());
            }
            encoded.push(0);
            encoded.len() + 4 // + qtype + qclass
        };
        let mut second_question = Vec::new();
        for label in "example.net".split('.') {
            second_question.push(label.len() as u8);
            second_question.extend_from_slice(label.as_bytes());
        }
        second_question.push(0);
        second_question.extend_from_slice(&1u16.to_be_bytes()); // qtype = A
        second_question.extend_from_slice(&1u16.to_be_bytes()); // qclass = IN
        let splice_at = 12 + first_question_len;
        request.splice(splice_at..splice_at, second_question);
        request[4..6].copy_from_slice(&2u16.to_be_bytes()); // qd_count = 2

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                request,
            ))
            .await;

        assert_eq!(
            outcome.decision.kind,
            ResolveDecisionKind::ProtocolError(ResponseCode::FormErr)
        );
        let response = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(response.header.id, 0x9abc);
        assert_eq!(response.header.r_code(), ResponseCode::FormErr as u8);
        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.questions[0].qname, "example.com");
        assert!(
            response.header.cd(),
            "CD must be copied from the request per RFC 4035 §3.2.2 even for a two-question query"
        );
        let opt_records: Vec<_> = response
            .additionals
            .iter()
            .filter_map(|record| match &record.record {
                RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .collect();
        assert_eq!(
            opt_records.len(),
            1,
            "the response must still carry exactly one responder OPT record per RFC 6891 §6.1.1"
        );
        assert_eq!(
            opt_records[0].udp_payload_size, 1232,
            "the OPT record must advertise this resolver's own configured UDP payload size"
        );
        assert!(upstream.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn resolve_maps_backend_failure_to_servfail() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service(upstream, events.clone(), metrics.clone());

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
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::BackendFailure);
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(
                recorded_events[0].terminal_outcome,
                QueryEventOutcome::BackendFailure
            );
            assert_eq!(
                recorded_events[0].response_code,
                Some(ResponseCode::ServFail as u16)
            );
            assert_eq!(
                recorded_events[0].cache_result,
                Some(QueryEventCacheResult::Miss)
            );
        }
        assert!(
            metrics
                .increments
                .lock()
                .unwrap()
                .contains(&ResolverMetric::UpstreamFailure)
        );
    }

    #[tokio::test]
    async fn resolve_maps_no_backends_to_servfail() {
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::NoBackendsAvailable)));
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
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::BackendFailure);
        assert!(
            metrics
                .increments
                .lock()
                .unwrap()
                .contains(&ResolverMetric::UpstreamFailure)
        );
    }

    #[test]
    fn zone_suffixes_walks_from_full_name_to_tld() {
        let suffixes: Vec<&str> = zone_suffixes("www.example.com").collect();
        assert_eq!(suffixes, vec!["www.example.com", "example.com", "com"]);
    }

    #[test]
    fn delegation_cache_hits_on_matching_suffix_and_misses_otherwise() {
        let cache = DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY);
        let endpoints = vec!["203.0.113.10:53".parse().unwrap()];
        cache.insert("example.com".to_string(), 1, endpoints.clone(), 300);

        assert_eq!(
            cache.lookup("www.example.com", 1),
            Some(("example.com".to_string(), endpoints.clone()))
        );
        assert_eq!(
            cache.lookup("example.com", 1),
            Some(("example.com".to_string(), endpoints))
        );
        assert_eq!(cache.lookup("other.org", 1), None);
    }

    #[test]
    fn delegation_cache_does_not_leak_across_dns_classes() {
        let cache = DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY);
        let endpoints = vec!["203.0.113.10:53".parse().unwrap()];
        // Learned from a CHAOS (class 3) referral.
        cache.insert("example.com".to_string(), 3, endpoints, 300);

        // An IN (class 1) query for the same owner name must not reuse it.
        assert_eq!(cache.lookup("example.com", 1), None);
    }

    #[test]
    fn delegation_cache_does_not_store_zero_ttl_entries() {
        let cache = DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY);
        cache.insert(
            "example.com".to_string(),
            1,
            vec!["203.0.113.10:53".parse().unwrap()],
            0,
        );
        assert_eq!(cache.lookup("example.com", 1), None);
    }

    #[tokio::test(start_paused = true)]
    async fn delegation_cache_treats_expired_entry_as_miss() {
        let cache = DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY);
        cache.insert(
            "example.com".to_string(),
            1,
            vec!["203.0.113.10:53".parse().unwrap()],
            1,
        );
        tokio::time::advance(Duration::from_millis(1100)).await;
        assert_eq!(cache.lookup("example.com", 1), None);
    }

    #[test]
    fn delegation_cache_evicts_oldest_entry_once_over_capacity() {
        let cache = DelegationCache::new(2);
        let endpoints = vec!["203.0.113.10:53".parse().unwrap()];
        cache.insert("first.example".to_string(), 1, endpoints.clone(), 300);
        cache.insert("second.example".to_string(), 1, endpoints.clone(), 300);
        assert_eq!(cache.len(), 2);

        // Inserting a third distinct entry over a capacity of 2 must evict
        // the oldest one (first.example) rather than growing unbounded.
        cache.insert("third.example".to_string(), 1, endpoints.clone(), 300);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.lookup("first.example", 1), None);
        assert_eq!(
            cache.lookup("second.example", 1),
            Some(("second.example".to_string(), endpoints.clone()))
        );
        assert_eq!(
            cache.lookup("third.example", 1),
            Some(("third.example".to_string(), endpoints))
        );
    }

    #[test]
    fn delegation_cache_repeated_refresh_does_not_grow_insertion_order_unbounded() {
        let cache = DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY);
        let endpoints = vec!["203.0.113.10:53".parse().unwrap()];

        // Refreshing the same live delegation many times (e.g. repeated
        // referrals for names under one already-cached zone) must not leave
        // stale duplicate slots behind in the FIFO eviction order without
        // bound -- that would bypass the capacity cap even while
        // entries.len() stays 1. Each refresh strands the previous slot
        // with a stale sequence, and the next insert's `purge_front` pops
        // it, so the queue oscillates between 1 and 2 slots instead of
        // being deduped to exactly 1 by an O(capacity) scan per insert.
        for _ in 0..1000 {
            cache.insert("example.com".to_string(), 1, endpoints.clone(), 300);
        }

        assert_eq!(cache.len(), 1);
        assert!(
            cache.insertion_order_len() <= 2,
            "expected at most one live and one just-stranded slot, got {}",
            cache.insertion_order_len()
        );
    }

    // Regression test for the empty-inner-map leak in lookup's lazy expiry
    // removal (PR #149 review): removing a qclass's last entry must drop
    // the outer qclass key too, matching `remove_entry`'s invariant, so
    // distinct qclasses can't accumulate empty maps.
    #[tokio::test(start_paused = true)]
    async fn delegation_cache_lookup_lazy_removal_drops_emptied_qclass_map() {
        let cache = DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY);
        let endpoints = vec!["203.0.113.10:53".parse::<SocketAddr>().unwrap()];
        const CHAOS_QCLASS: u16 = 3;
        cache.insert("chaos.example".to_string(), CHAOS_QCLASS, endpoints, 1);
        assert_eq!(cache.qclass_key_count(), 1);

        tokio::time::advance(Duration::from_millis(1100)).await;
        assert!(cache.lookup("chaos.example", CHAOS_QCLASS).is_none());

        assert_eq!(
            cache.qclass_key_count(),
            0,
            "lazy expiry removal of a qclass's last entry must drop the outer qclass key"
        );
    }

    // Regression test for the stale-slot wrong-victim eviction bug: a zone
    // cut that expires, is lazily removed by lookup(), and is then
    // re-learned leaves its old FIFO slot behind with a stale sequence. An
    // over-capacity eviction popping that stale slot must not delete the
    // freshly re-learned live entry -- it must skip the stale slot and
    // evict the genuinely oldest live entry instead.
    #[tokio::test(start_paused = true)]
    async fn delegation_cache_eviction_skips_stale_slots_of_relearned_zones() {
        let cache = DelegationCache::new(2);
        let endpoints = vec!["203.0.113.10:53".parse::<SocketAddr>().unwrap()];

        // churn.example's slot lands at the FIFO front, stable.example's
        // behind it.
        cache.insert("churn.example".to_string(), 1, endpoints.clone(), 1);
        cache.insert("stable.example".to_string(), 1, endpoints.clone(), 300);

        // churn.example expires and is lazily removed by a lookup, leaving
        // its front slot stale.
        tokio::time::advance(Duration::from_millis(1100)).await;
        assert!(cache.lookup("churn.example", 1).is_none());
        assert_eq!(cache.len(), 1);

        // Re-learn churn.example fresh, then push the cache over capacity.
        cache.insert("churn.example".to_string(), 1, endpoints.clone(), 300);
        cache.insert("newcomer.example".to_string(), 1, endpoints, 300);

        // FIFO says stable.example (the oldest live entry) is the victim;
        // the just-re-learned churn.example must survive even though its
        // stale slot predated stable.example's.
        assert_eq!(cache.len(), 2);
        assert!(
            cache.lookup("churn.example", 1).is_some(),
            "freshly re-learned zone cut must not be evicted through its stale slot"
        );
        assert!(cache.lookup("stable.example", 1).is_none());
        assert!(cache.lookup("newcomer.example", 1).is_some());
    }

    // Regression test for unbounded insertion_order growth while under
    // capacity: a long-TTL entry at the FIFO front blocks `purge_front`,
    // and a short-TTL zone churning through expire -> lazy lookup removal
    // -> re-learn strands one stale slot per cycle. The queue-length
    // compaction trigger must keep the slot queue bounded even though the
    // live entry count never approaches capacity (so over-capacity
    // eviction never runs).
    #[tokio::test(start_paused = true)]
    async fn delegation_cache_slot_queue_stays_bounded_under_churn_below_capacity() {
        let max_entries = 4;
        let cache = DelegationCache::new(max_entries);
        let endpoints = vec!["203.0.113.10:53".parse::<SocketAddr>().unwrap()];

        cache.insert(
            "front-blocker.example".to_string(),
            1,
            endpoints.clone(),
            86_400,
        );
        for _ in 0..100 {
            cache.insert("churn.example".to_string(), 1, endpoints.clone(), 1);
            tokio::time::advance(Duration::from_millis(1100)).await;
            assert!(cache.lookup("churn.example", 1).is_none());
        }

        assert!(
            cache.insertion_order_len() <= 2 * max_entries + 1,
            "slot queue must stay bounded by the compaction trigger, got {}",
            cache.insertion_order_len()
        );
        assert!(cache.lookup("front-blocker.example", 1).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn delegation_cache_purges_expired_entries_on_insert() {
        let cache = DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY);
        let endpoints = vec!["203.0.113.10:53".parse().unwrap()];
        cache.insert("expiring.example".to_string(), 1, endpoints.clone(), 1);
        assert_eq!(cache.len(), 1);

        tokio::time::advance(Duration::from_millis(1100)).await;

        // A later insert opportunistically purges the now-expired entry
        // instead of only relying on a lookup that happens to hit it.
        cache.insert("other.example".to_string(), 1, endpoints, 300);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn delegation_cache_caps_excessive_referral_ttl() {
        let cache = DelegationCache::new(DEFAULT_DELEGATION_CACHE_CAPACITY);
        let endpoints = vec!["203.0.113.10:53".parse().unwrap()];
        // A hostile or misconfigured authority returns a huge TTL; it must be
        // clamped rather than pinning this delegation for years.
        cache.insert("example.com".to_string(), 1, endpoints, u32::MAX);

        let remaining = cache
            .ttl_remaining_secs("example.com", 1)
            .expect("entry should be cached");
        assert!(
            remaining <= u64::from(DELEGATION_CACHE_MAX_TTL_SECONDS),
            "expected remaining TTL to be capped at {DELEGATION_CACHE_MAX_TTL_SECONDS}s, got {remaining}s"
        );
        // Sanity: the cap actually kicked in rather than happening to be
        // small for some unrelated reason.
        assert!(remaining > u64::from(DELEGATION_CACHE_MAX_TTL_SECONDS) - 5);
    }

    #[test]
    fn referral_authorities_bounds_ttl_by_shorter_of_ns_and_glue() {
        let question = QuestionKey::new("www.example.com", 1, 1);
        let message = response_message_for_question(
            question.clone(),
            ResponseCode::NoError,
            Vec::new(),
            vec![ns_record("example.com", 300, "ns1.example.com")],
            vec![glue_a_record(
                "ns1.example.com",
                60,
                "203.0.113.10".parse().unwrap(),
            )],
            false,
        );
        let referral = referral_authorities(&message, &question).unwrap();
        assert_eq!(referral.min_ttl, 60);
    }

    #[tokio::test]
    async fn recursive_backend_does_not_reuse_delegation_cache_across_dns_classes() {
        // qclass 3 is CHAOS; the test helpers (ns_record/glue_a_record/a_record)
        // hardcode rclass 1 (IN), so the referral/answer records are built by
        // hand here with rclass 3 to exercise the non-IN path.
        let chaos_question = QuestionKey::new("example.com", 1, 3);
        let chaos_ns_record = Record {
            name: "example.com".to_string(),
            rtype: 2,
            rclass: 3,
            ttl: 300,
            record: RecordData::NS("ns1.example.com".to_string()),
        };
        let chaos_glue_record = Record {
            name: "ns1.example.com".to_string(),
            rtype: 1,
            rclass: 3,
            ttl: 300,
            record: RecordData::A("203.0.113.10".parse().unwrap()),
        };
        let chaos_answer_record = Record {
            name: "example.com".to_string(),
            rtype: 1,
            rclass: 3,
            ttl: 60,
            record: RecordData::A("192.0.2.10".parse().unwrap()),
        };

        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                chaos_question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![chaos_ns_record],
                vec![chaos_glue_record],
                false,
            )),
            Ok(response_message_for_question(
                chaos_question.clone(),
                ResponseCode::NoError,
                vec![chaos_answer_record],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        backend
            .resolve(recursive_request_from_bytes(query(
                0x1234,
                "example.com",
                1,
                3,
            )))
            .await
            .unwrap();

        // Delegation learned under CHAOS (class 3) must stay scoped to class 3.
        assert!(backend.delegation_cache.lookup("example.com", 3).is_some());
        // An IN (class 1) query for the same owner name must not reuse it.
        assert_eq!(backend.delegation_cache.lookup("example.com", 1), None);
    }

    #[tokio::test]
    async fn recursive_backend_reuses_delegation_cache_for_repeat_zone() {
        let first_question = QuestionKey::new("www.example.com", 1, 1);
        let second_question = QuestionKey::new("other.example.com", 1, 1);
        let ns1: SocketAddr = "203.0.113.10:53".parse().unwrap();

        let transport = Arc::new(ScriptedAuthorityTransport::new([
            Ok(response_message_for_question(
                first_question.clone(),
                ResponseCode::NoError,
                Vec::new(),
                vec![ns_record("example.com", 300, "ns1.example.com")],
                vec![glue_a_record(
                    "ns1.example.com",
                    300,
                    "203.0.113.10".parse().unwrap(),
                )],
                false,
            )),
            Ok(response_message_for_question(
                first_question.clone(),
                ResponseCode::NoError,
                vec![a_record("www.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
            Ok(response_message_for_question(
                second_question.clone(),
                ResponseCode::NoError,
                vec![a_record("other.example.com", 60)],
                Vec::new(),
                Vec::new(),
                true,
            )),
        ]));
        let backend = recursive_backend(transport.clone());

        backend
            .resolve(recursive_request("www.example.com"))
            .await
            .unwrap();
        backend
            .resolve(recursive_request("other.example.com"))
            .await
            .unwrap();

        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        // Second top-level query reuses the cached example.com delegation and
        // skips straight to ns1, never re-querying the root hint.
        assert_eq!(requests[2].0, ns1);
    }

    struct DelayedAuthorityTransport {
        responses: HashMap<SocketAddr, (Duration, Result<Message, ResolutionBackendError>)>,
        requests: Mutex<Vec<SocketAddr>>,
    }

    impl DelayedAuthorityTransport {
        fn new(
            responses: HashMap<SocketAddr, (Duration, Result<Message, ResolutionBackendError>)>,
        ) -> Self {
            Self {
                responses,
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl RecursiveAuthorityTransport for DelayedAuthorityTransport {
        fn query<'a>(
            &'a self,
            authority: SocketAddr,
            _question: QuestionKey,
            _dnssec_ok: bool,
            _timeout: Duration,
        ) -> BoxFuture<'a, Result<RecursiveAuthorityResponse, ResolutionBackendError>> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(authority);
                let (delay, result) = self
                    .responses
                    .get(&authority)
                    .expect("unexpected authority queried");
                time::sleep(*delay).await;
                match result {
                    Ok(message) => RecursiveAuthorityResponse::new(
                        message.original_bytes.to_vec(),
                        message.clone(),
                    ),
                    Err(error) => Err(error.clone()),
                }
            })
        }
    }

    #[tokio::test]
    async fn race_within_delegation_set_prefers_fastest_authority() {
        let question = QuestionKey::new("example.com", 1, 1);
        let slow: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let fast: SocketAddr = "198.51.100.2:53".parse().unwrap();

        let mut responses = HashMap::new();
        responses.insert(
            slow,
            (
                Duration::from_secs(5),
                Ok(response_message_for_question(
                    question.clone(),
                    ResponseCode::NoError,
                    vec![a_record("example.com", 60)],
                    Vec::new(),
                    Vec::new(),
                    true,
                )),
            ),
        );
        responses.insert(
            fast,
            (
                Duration::from_millis(10),
                Ok(response_message_for_question(
                    question.clone(),
                    ResponseCode::NoError,
                    vec![a_record("example.com", 60)],
                    Vec::new(),
                    Vec::new(),
                    true,
                )),
            ),
        );

        let transport = Arc::new(DelayedAuthorityTransport::new(responses));
        let backend = RecursiveResolutionBackend::new(
            RecursiveResolverConfig {
                root_hints: vec![RecursiveRootHint {
                    name: "a.root-servers.example".to_string(),
                    endpoints: vec![slow, fast],
                }],
                per_authority_timeout: Duration::from_secs(2),
                per_query_deadline: Duration::from_secs(3),
                max_recursion_depth: 8,
                max_cname_restarts: 4,
                configured_max_udp_payload_size: 1232,
            },
            transport.clone(),
        );

        let started = Instant::now();
        let response = backend
            .resolve(recursive_request("example.com"))
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(response.answers().len(), 1);
        assert!(
            elapsed < Duration::from_secs(1),
            "expected the fast authority to win the race, took {elapsed:?}"
        );
        // Both authorities were queried concurrently rather than serially
        // (a serial fallback would have paid the slow authority's full
        // per_authority_timeout before ever trying the fast one).
        assert_eq!(transport.requests.lock().unwrap().len(), 2);
    }
}
