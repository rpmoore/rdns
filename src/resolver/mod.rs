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

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use tokio::sync::{mpsc, Notify};
use tokio::time::{self, Instant};

use crate::protocol::{
    age_response_ttls, build_formerr_response, build_refused_response, build_servfail_response,
    cap_response_ttls, message_question_wire, rewrite_response_id, rewrite_response_request_fields,
    Message, QueryValidationError, Record, RecordData, ResponseCode,
};

const EDNS_DO_FLAG: u16 = 0x8000;
const MAX_FAILURE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const CNAME_RECORD_TYPE: u16 = 5;
const LRU_COMPACTION_MULTIPLIER: usize = 4;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedAt(pub SystemTime);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObservedSourceEndpoint {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub transport: Option<QueryTransport>,
    pub listener: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryTransport {
    Udp,
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
    pub bytes: Vec<u8>,
}

impl ResolveRequest {
    pub fn new(client_ip: IpAddr, received_at: SystemTime, bytes: Vec<u8>) -> Self {
        Self {
            client_ip,
            observed_source: ObservedSourceEndpoint::ip(client_ip),
            received_at: ReceivedAt(received_at),
            bytes,
        }
    }

    pub fn new_with_observed_source(
        observed_source: impl Into<ObservedSourceEndpoint>,
        received_at: SystemTime,
        bytes: Vec<u8>,
    ) -> Self {
        let observed_source = observed_source.into();
        Self {
            client_ip: observed_source.ip,
            observed_source,
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
    pub recursion_desired: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub dnssec_ok: bool,
    pub edns_udp_payload_size: Option<u16>,
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub question: QuestionKey,
    pub question_wire: Vec<u8>,
    pub features: QueryFeatures,
    pub cache_namespace: Option<String>,
    pub effective_udp_payload_size: usize,
}

impl CacheKey {
    pub fn new(
        question: QuestionKey,
        question_wire: Vec<u8>,
        features: QueryFeatures,
        cache_namespace: Option<String>,
        effective_udp_payload_size: usize,
    ) -> Self {
        Self {
            question,
            question_wire,
            features,
            cache_namespace,
            effective_udp_payload_size,
        }
    }

    pub fn from_query(
        query: &DecodedQuery,
        cache_namespace: Option<String>,
        configured_max_udp_payload_size: usize,
    ) -> Self {
        Self::new(
            query.question.clone(),
            query.question_wire.to_vec(),
            query.features.clone(),
            cache_namespace,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    LocalRule,
    MaliciousDomain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    Hit(CachedResponse),
    Miss,
    Expired,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheStore {
    pub key: CacheKey,
    pub response_template: Vec<u8>,
    pub response_code: ResponseCode,
    pub minimum_ttl: Duration,
    pub negative_cache: Option<NegativeCacheMetadata>,
    pub stored_at: SystemTime,
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

fn has_requested_answer_for(message: &Message, question: &QuestionKey) -> bool {
    message.answers.iter().any(|record| {
        QuestionKey::new(&record.name, record.rtype, record.rclass) == *question
            && !matches!(record.record, RecordData::RRSIG { .. })
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

fn cname_chain_records(message: &Message, cname_record: &Record, dnssec_ok: bool) -> Vec<Record> {
    let mut records = vec![cname_record.clone()];
    if dnssec_ok {
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
    }
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
}

fn referral_authorities(message: &Message, question: &QuestionKey) -> Option<ReferralAuthorities> {
    let owner = message
        .authorities
        .iter()
        .filter_map(|record| {
            if !matches!(record.record, RecordData::NS(_)) {
                return None;
            }
            let owner = normalize_question_name(&record.name);
            if is_delegation_owner_for_question(&owner, &question.qname) {
                Some(owner)
            } else {
                None
            }
        })
        .max_by_key(|owner| owner.len())?;
    let names: HashSet<_> = message
        .authorities
        .iter()
        .filter_map(|record| match &record.record {
            RecordData::NS(name)
                if normalize_question_name(&record.name) == owner
                    && is_delegation_owner_for_question(&owner, name) =>
            {
                Some(normalize_question_name(name))
            }
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return None;
    }

    let endpoints = message
        .additionals
        .iter()
        .filter_map(|record| {
            if !names.contains(&normalize_question_name(&record.name)) {
                return None;
            }
            match record.record {
                RecordData::A(address) => Some(SocketAddr::new(IpAddr::V4(address), 53)),
                RecordData::AAAA(address) => Some(SocketAddr::new(IpAddr::V6(address), 53)),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    if endpoints.is_empty() {
        return None;
    }
    Some(ReferralAuthorities { owner, endpoints })
}

fn has_delegation_for_question(message: &Message, question: &QuestionKey) -> bool {
    message.authorities.iter().any(|record| {
        matches!(record.record, RecordData::NS(_))
            && is_delegation_owner_for_question(&record.name, &question.qname)
    })
}

fn is_delegation_owner_for_question(owner: &str, qname: &str) -> bool {
    let owner = normalize_question_name(owner);
    let qname = normalize_question_name(qname);
    owner.is_empty() || qname == owner || qname.ends_with(&format!(".{owner}"))
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

fn synthesize_recursive_cname_response(
    original_query: &Message,
    cname_chain: &[Record],
    final_response: &Message,
) -> Result<Message, ResolutionBackendError> {
    let dnssec_ok = original_query
        .edns
        .as_ref()
        .map(|edns| edns.dnssec_ok)
        .unwrap_or(false);
    let mut answers = cname_chain.to_vec();
    answers.extend(
        final_response
            .answers
            .iter()
            .filter(|record| recursive_response_record_supported(record, dnssec_ok))
            .cloned(),
    );
    let authorities = final_response
        .authorities
        .iter()
        .filter(|record| recursive_response_record_supported(record, dnssec_ok))
        .cloned()
        .collect::<Vec<_>>();
    let additionals = final_response
        .additionals
        .iter()
        .filter(|record| recursive_response_record_supported(record, dnssec_ok))
        .cloned()
        .collect::<Vec<_>>();
    let bytes = serialize_recursive_response(
        original_query,
        response_code(final_response).unwrap_or(ResponseCode::ServFail),
        final_response.header.aa(),
        &answers,
        &authorities,
        &additionals,
    )?;
    Message::parse_owned(bytes).map_err(|_| ResolutionBackendError::MalformedResponse)
}

fn recursive_response_record_supported(record: &Record, dnssec_ok: bool) -> bool {
    match record.record {
        RecordData::A(_)
        | RecordData::AAAA(_)
        | RecordData::CNAME(_)
        | RecordData::NS(_)
        | RecordData::SOA { .. } => true,
        RecordData::DNSKEY { .. }
        | RecordData::DS { .. }
        | RecordData::NSEC { .. }
        | RecordData::NSEC3 { .. }
        | RecordData::NSEC3PARAM { .. }
        | RecordData::RRSIG { .. } => dnssec_ok,
        RecordData::Unknown { rtype, .. } => dnssec_ok || !is_dnssec_record_type(rtype),
        _ => false,
    }
}

fn is_dnssec_record_type(rtype: u16) -> bool {
    matches!(rtype, 43 | 46 | 47 | 48 | 50 | 51 | 59 | 60 | 32769)
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
    write_dns_u16(&mut bytes, flags);
    write_dns_u16(&mut bytes, 1);
    write_dns_u16(&mut bytes, answers.len() as u16);
    write_dns_u16(&mut bytes, authorities.len() as u16);
    write_dns_u16(&mut bytes, additionals.len() as u16);
    write_dns_question(&mut bytes, &question.qname, question.qtype, question.qclass);
    for record in answers {
        write_dns_record(&mut bytes, record)?;
    }
    for record in authorities {
        write_dns_record(&mut bytes, record)?;
    }
    for record in additionals {
        write_dns_record(&mut bytes, record)?;
    }
    Ok(bytes)
}

fn write_dns_question(bytes: &mut Vec<u8>, name: &str, qtype: u16, qclass: u16) {
    write_dns_name(bytes, name);
    write_dns_u16(bytes, qtype);
    write_dns_u16(bytes, qclass);
}

fn write_dns_record(bytes: &mut Vec<u8>, record: &Record) -> Result<(), ResolutionBackendError> {
    write_dns_name(bytes, &record.name);
    write_dns_u16(bytes, record.rtype);
    write_dns_u16(bytes, record.rclass);
    write_dns_u32(bytes, record.ttl);
    let rdlength_index = bytes.len();
    write_dns_u16(bytes, 0);
    let rdata_start = bytes.len();
    match &record.record {
        RecordData::A(address) => bytes.extend_from_slice(&address.octets()),
        RecordData::AAAA(address) => bytes.extend_from_slice(&address.octets()),
        RecordData::CNAME(name) | RecordData::NS(name) => write_dns_name(bytes, name),
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
            write_dns_name(bytes, mname);
            write_dns_name(bytes, rname);
            write_dns_u32(bytes, *serial);
            write_dns_u32(bytes, *refresh);
            write_dns_u32(bytes, *retry);
            write_dns_u32(bytes, *expire);
            write_dns_u32(bytes, *minimum);
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

fn apply_ttl_bounds(ttl: Duration, min_ttl: Option<Duration>, max_ttl: Duration) -> Duration {
    let capped = ttl.min(max_ttl);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionResponse {
    pub bytes: Vec<u8>,
    pub received_at: SystemTime,
    response_message: Option<Message>,
    pub response_code: Option<ResponseCode>,
    pub final_question: Option<QuestionKey>,
    pub canonical_chain: Vec<String>,
    pub negative_cache: Option<NegativeCacheMetadata>,
    pub source_credibility: SourceCredibility,
    pub backend_provenance: BackendProvenance,
    pub cache_directive: ResolutionCacheDirective,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolutionMode {
    Forward,
    Recursive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealth {
    Healthy,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub cache_namespace: Option<String>,
    pub root_hints: Option<BackendRootHintsStatus>,
}

impl BackendSnapshot {
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
        bytes: Vec<u8>,
        received_at: SystemTime,
        backend_generation: u64,
        backend_name: impl Into<String>,
    ) -> Self {
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
        bytes: Vec<u8>,
        response_message: Message,
        received_at: SystemTime,
        backend_generation: u64,
        backend_name: impl Into<String>,
    ) -> Self {
        let backend_name = backend_name.into();
        if response_message.original_bytes.as_ref() != bytes.as_slice() {
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
        bytes: Vec<u8>,
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
        }
    }

    fn unparsed_forwarded_bytes(
        bytes: Vec<u8>,
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
        }
    }

    pub(crate) fn recursive_response(
        original_query: &DecodedQuery,
        authority_response: RecursiveAuthorityResponse,
        cname_chain: &[Record],
        received_at: SystemTime,
        backend_generation: u64,
        authority: SocketAddr,
    ) -> Result<Self, ResolutionBackendError> {
        let response_message = synthesize_recursive_cname_response(
            &original_query.message,
            cname_chain,
            &authority_response.message,
        )?;
        let bytes = response_message.original_bytes.to_vec();
        let response_code = response_code(&response_message);
        let final_question = QuestionKey::from_message(&response_message);
        let canonical_chain = canonical_chain_from_response(&response_message);
        let negative_cache = negative_ttl(&response_message);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveDecisionKind {
    Allowed,
    Blocked(BlockReason),
    CacheHit,
    CacheMiss,
    ProtocolError(ResponseCode),
    BackendFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveDecision {
    pub client_ip: IpAddr,
    pub question: Option<QuestionKey>,
    pub kind: ResolveDecisionKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEventV1 {
    pub schema_version: u8,
    pub sequence: u64,
    pub timestamp: SystemTime,
    pub observed_source: ObservedSourceEndpoint,
    pub original_question_name: Option<String>,
    pub normalized_question: Option<QuestionKey>,
    pub qtype: Option<u16>,
    pub qclass: Option<u16>,
    pub terminal_outcome: QueryEventOutcome,
    pub response_code: Option<u16>,
    pub cache_result: Option<QueryEventCacheResult>,
    pub backend: Option<QueryEventBackend>,
    pub latency: Option<Duration>,
    pub advisory_findings: Vec<QueryEventClassifierFinding>,
}

impl QueryEventV1 {
    pub const SCHEMA_VERSION: u8 = 2;

    pub fn from_decision(
        sequence: u64,
        timestamp: SystemTime,
        decision: &ResolveDecision,
        response_code: Option<u16>,
        cache_result: Option<QueryEventCacheResult>,
        latency: Option<Duration>,
    ) -> Self {
        Self::from_decision_context(
            sequence,
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
            timestamp,
            observed_source,
            original_question_name,
            qtype: normalized_question.as_ref().map(|question| question.qtype),
            qclass: normalized_question.as_ref().map(|question| question.qclass),
            normalized_question,
            terminal_outcome: QueryEventOutcome::from_decision_kind(&decision.kind),
            response_code,
            cache_result,
            backend: None,
            latency,
            advisory_findings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryEventOutcome {
    AllowedFromBackend,
    AllowedFromCache,
    Blocked(BlockReason),
    ProtocolError(ResponseCode),
    BackendFailure,
}

impl QueryEventOutcome {
    fn from_decision_kind(kind: &ResolveDecisionKind) -> Self {
        match kind {
            ResolveDecisionKind::Allowed => Self::AllowedFromBackend,
            ResolveDecisionKind::Blocked(reason) => Self::Blocked(reason.clone()),
            ResolveDecisionKind::CacheHit => Self::AllowedFromCache,
            ResolveDecisionKind::CacheMiss => Self::AllowedFromBackend,
            ResolveDecisionKind::ProtocolError(code) => Self::ProtocolError(*code),
            ResolveDecisionKind::BackendFailure => Self::BackendFailure,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryEventCacheResult {
    Hit,
    Miss,
    Expired,
    Bypass,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEventClassifierFinding {
    pub classifier_version: String,
    pub config_generation: u64,
    pub reason: QueryEventClassifierReason,
    pub severity: QueryEventClassifierSeverity,
    pub score: u8,
    pub evaluated_window: QueryEventClassifierWindow,
    pub details: Vec<QueryEventClassifierDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryEventClassifierReason {
    NxdomainBurst,
    ServfailBurst,
    HighEntropyName,
    RepeatedTxtLookup,
    RareDomain,
    NewDomain,
    SuspiciousSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryEventClassifierSeverity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryEventClassifierWindow {
    pub started_at: SystemTime,
    pub ended_at: SystemTime,
    pub retained_event_count: usize,
    pub incomplete_reasons: Vec<QueryEventClassifierWindowIncompleteReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryEventClassifierWindowIncompleteReason {
    ColdStart,
    RetentionEviction,
    SampledEvents,
    DroppedEvents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    key: Option<CacheKey>,
    hit: Option<Vec<u8>>,
    store_allowed: bool,
    event_cache_result: Option<QueryEventCacheResult>,
}

pub struct ResolveQuery {
    protocol: Arc<dyn ProtocolCodec>,
    cache: Arc<dyn DnsCache>,
    ttl_policy: CacheTtlPolicy,
    miss_coalescer: Arc<SingleFlightMisses>,
    backend: BackendHandle,
    responses: Arc<dyn ResponseFactory>,
    clock: Arc<dyn Clock>,
    events: Arc<dyn QueryEventSink>,
    event_sequence: AtomicU64,
    metrics: Arc<dyn MetricsSink>,
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
        cache: Arc<dyn DnsCache>,
        ttl_policy: CacheTtlPolicy,
        backend: Arc<dyn ResolutionBackend>,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        let snapshot = BackendSnapshot::forwarding(backend, 0);
        Self::with_cache_and_backend_snapshot(
            protocol, cache, ttl_policy, snapshot, responses, clock, events, metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_and_backend_snapshot(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DnsCache>,
        ttl_policy: CacheTtlPolicy,
        backend_snapshot: BackendSnapshot,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        metrics.record_backend_status(&backend_snapshot.status());
        Self {
            protocol,
            cache,
            ttl_policy,
            miss_coalescer: Arc::new(SingleFlightMisses::default()),
            backend: BackendHandle::new(backend_snapshot),
            responses,
            clock,
            events,
            event_sequence: AtomicU64::new(0),
            metrics,
        }
    }

    pub fn backend_status(&self) -> BackendStatus {
        self.backend.status()
    }

    pub fn publish_backend_snapshot(&self, snapshot: BackendSnapshot) {
        let status = snapshot.status();
        self.backend.publish(snapshot);
        self.metrics.record_backend_status(&status);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_and_backend_handle(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DnsCache>,
        ttl_policy: CacheTtlPolicy,
        backend_handle: BackendHandle,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        metrics.record_backend_status(&backend_handle.status());
        Self {
            protocol,
            cache,
            ttl_policy,
            miss_coalescer: Arc::new(SingleFlightMisses::default()),
            backend: backend_handle,
            responses,
            clock,
            events,
            event_sequence: AtomicU64::new(0),
            metrics,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_cache_and_backend_generation(
        protocol: Arc<dyn ProtocolCodec>,
        cache: Arc<dyn DnsCache>,
        ttl_policy: CacheTtlPolicy,
        backend: Arc<dyn ResolutionBackend>,
        backend_generation: u64,
        responses: Arc<dyn ResponseFactory>,
        clock: Arc<dyn Clock>,
        events: Arc<dyn QueryEventSink>,
        metrics: Arc<dyn MetricsSink>,
    ) -> Self {
        let snapshot = BackendSnapshot::forwarding(backend, backend_generation);
        Self::with_cache_and_backend_snapshot(
            protocol, cache, ttl_policy, snapshot, responses, clock, events, metrics,
        )
    }

    pub async fn resolve(&self, mut request: ResolveRequest) -> ResolveOutcome {
        self.metrics.increment(ResolverMetric::QueryReceived);
        let started_at = self.clock.now();
        let backend_snapshot = self.backend.current();
        let request_id = request_id_from_wire(&request.bytes);
        let request_bytes = std::mem::take(&mut request.bytes);

        let decoded = match self.protocol.decode_query_owned(request_bytes) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.metrics.increment(ResolverMetric::ProtocolError);
                let decision = ResolveDecision {
                    client_ip: request.client_ip,
                    question: None,
                    kind: ResolveDecisionKind::ProtocolError(error.response_code()),
                };
                let response_bytes = self.responses.protocol_error(request_id, &error);
                return self
                    .finish(
                        started_at,
                        &request,
                        None,
                        decision,
                        response_bytes,
                        None,
                        Some(QueryEventBackend::from_snapshot(&backend_snapshot)),
                    )
                    .await;
            }
        };

        self.metrics.increment(ResolverMetric::QueryAllowed);
        let question = decoded.question.clone();

        let mut cache_probe = self
            .probe_cache(&backend_snapshot, &request, &decoded)
            .await;
        if let Some(response_bytes) = cache_probe.hit {
            let decision = ResolveDecision {
                client_ip: request.client_ip,
                question: Some(question),
                kind: ResolveDecisionKind::CacheHit,
            };
            return self
                .finish(
                    started_at,
                    &request,
                    decoded_original_question_name(&decoded),
                    decision,
                    response_bytes,
                    cache_probe.event_cache_result,
                    Some(QueryEventBackend::from_snapshot(&backend_snapshot)),
                )
                .await;
        }

        if let (Some(cache_key), true) = (cache_probe.key.take(), cache_probe.store_allowed) {
            return self
                .resolve_coalesced_miss(
                    &backend_snapshot,
                    started_at,
                    &request,
                    &decoded,
                    question,
                    cache_key,
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
            cache_probe.key,
            false,
            cache_probe.event_cache_result,
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
        cache_key: CacheKey,
        event_cache_result: Option<QueryEventCacheResult>,
    ) -> ResolveOutcome {
        match self.miss_coalescer.begin(cache_key.clone()) {
            SingleFlightTicket::Leader { key, flight } => {
                let guard = SingleFlightLeader::new(Arc::clone(&self.miss_coalescer), key, flight);
                let backend_result = self.resolve_backend(backend_snapshot, decoded).await;
                let (decision, response_bytes) = self
                    .prepare_backend_result(
                        request,
                        decoded,
                        question,
                        Some(cache_key),
                        true,
                        backend_result.clone(),
                    )
                    .await;
                guard.complete(backend_result);
                self.finish(
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
            SingleFlightTicket::Follower { flight } => {
                self.metrics.increment(ResolverMetric::CacheCoalescedMiss);
                let backend_result = flight.wait().await;
                if let Some(response_bytes) = self
                    .cache_hit_after_coalesced_miss(request, decoded, &cache_key)
                    .await
                {
                    let decision = ResolveDecision {
                        client_ip: request.client_ip,
                        question: Some(question),
                        kind: ResolveDecisionKind::CacheHit,
                    };
                    return self
                        .finish(
                            started_at,
                            request,
                            decoded_original_question_name(decoded),
                            decision,
                            response_bytes,
                            Some(QueryEventCacheResult::Hit),
                            Some(QueryEventBackend::from_snapshot(backend_snapshot)),
                        )
                        .await;
                }
                self.finish_backend_result(
                    backend_snapshot,
                    started_at,
                    request,
                    decoded,
                    question,
                    Some(cache_key),
                    false,
                    event_cache_result,
                    backend_result,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_backend_and_finish(
        &self,
        backend_snapshot: &BackendSnapshot,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        cache_key: Option<CacheKey>,
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
            cache_key,
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
        backend_snapshot
            .backend
            .resolve(ResolutionRequest {
                query: decoded.clone(),
                backend_generation: backend_snapshot.generation,
            })
            .await
    }

    async fn probe_cache(
        &self,
        backend_snapshot: &BackendSnapshot,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
    ) -> CacheProbe {
        if !cache_supported(decoded) {
            self.metrics.increment(ResolverMetric::CacheBypass);
            self.metrics.increment(ResolverMetric::CacheMiss);
            return CacheProbe {
                key: None,
                hit: None,
                store_allowed: false,
                event_cache_result: Some(QueryEventCacheResult::Bypass),
            };
        }

        let key = CacheKey::from_query(
            decoded,
            backend_snapshot.cache_namespace.clone(),
            self.protocol.configured_max_udp_payload_size(),
        );
        let lookup = self
            .cache
            .lookup(&CacheLookupRequest {
                key: key.clone(),
                received_at: request.received_at.0,
            })
            .await;
        let mut probe = CacheProbe {
            key: Some(key),
            hit: None,
            store_allowed: matches!(lookup, CacheLookup::Miss | CacheLookup::Expired),
            event_cache_result: Some(QueryEventCacheResult::Miss),
        };

        match lookup {
            CacheLookup::Hit(cached) => match self.serialize_cache_hit(decoded, &cached, request) {
                Ok(response_bytes) => {
                    probe.event_cache_result = Some(QueryEventCacheResult::Hit);
                    probe.hit = Some(response_bytes);
                }
                Err(_) => {
                    self.metrics.increment(ResolverMetric::CacheMiss);
                    probe.store_allowed = true;
                    probe.event_cache_result = Some(QueryEventCacheResult::Miss);
                }
            },
            CacheLookup::Miss => {
                self.metrics.increment(ResolverMetric::CacheMiss);
                probe.event_cache_result = Some(QueryEventCacheResult::Miss);
            }
            CacheLookup::Expired => {
                self.metrics.increment(ResolverMetric::CacheExpired);
                self.metrics.increment(ResolverMetric::CacheMiss);
                probe.event_cache_result = Some(QueryEventCacheResult::Expired);
            }
            CacheLookup::Bypass(_) => {
                self.metrics.increment(ResolverMetric::CacheBypass);
                self.metrics.increment(ResolverMetric::CacheMiss);
                probe.event_cache_result = Some(QueryEventCacheResult::Bypass);
            }
            CacheLookup::Unavailable => {
                self.metrics.increment(ResolverMetric::CacheUnavailable);
                self.metrics.increment(ResolverMetric::CacheMiss);
                probe.event_cache_result = Some(QueryEventCacheResult::Unavailable);
            }
        }

        probe
    }

    async fn cache_hit_after_coalesced_miss(
        &self,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        cache_key: &CacheKey,
    ) -> Option<Vec<u8>> {
        let lookup = self
            .cache
            .lookup(&CacheLookupRequest {
                key: cache_key.clone(),
                received_at: request.received_at.0,
            })
            .await;
        let CacheLookup::Hit(cached) = lookup else {
            return None;
        };
        self.serialize_cache_hit(decoded, &cached, request).ok()
    }

    fn serialize_cache_hit(
        &self,
        decoded: &DecodedQuery,
        cached: &CachedResponse,
        request: &ResolveRequest,
    ) -> crate::protocol::Result<Vec<u8>> {
        if cached.expires_at <= request.received_at.0 {
            self.metrics.increment(ResolverMetric::CacheExpired);
        }
        let response_bytes =
            self.protocol
                .serialize_cached_response(decoded, cached, request.received_at.0)?;
        self.metrics.increment(ResolverMetric::CacheHit);
        if cached.negative_cache.is_some() {
            self.metrics.increment(ResolverMetric::CacheNegativeHit);
        }
        if response_is_truncated(&response_bytes) {
            self.metrics
                .increment(ResolverMetric::CacheResponseTruncated);
        }
        Ok(response_bytes)
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_backend_result(
        &self,
        backend_snapshot: &BackendSnapshot,
        started_at: SystemTime,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        cache_key: Option<CacheKey>,
        cache_store_allowed: bool,
        event_cache_result: Option<QueryEventCacheResult>,
        backend_result: Result<ResolutionResponse, ResolutionBackendError>,
    ) -> ResolveOutcome {
        let (decision, response_bytes) = self
            .prepare_backend_result(
                request,
                decoded,
                question,
                cache_key,
                cache_store_allowed,
                backend_result,
            )
            .await;
        self.finish(
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

    async fn prepare_backend_result(
        &self,
        request: &ResolveRequest,
        decoded: &DecodedQuery,
        question: QuestionKey,
        cache_key: Option<CacheKey>,
        cache_store_allowed: bool,
        backend_result: Result<ResolutionResponse, ResolutionBackendError>,
    ) -> (ResolveDecision, Vec<u8>) {
        let Ok(mut response) = backend_result else {
            return self.backend_failure_response(request, decoded, question);
        };

        let Some(response_message) = validate_backend_response(&mut response, decoded) else {
            return self.backend_failure_response(request, decoded, question);
        };

        self.metrics.increment(ResolverMetric::UpstreamSuccess);
        let mut response_bytes = response.bytes;
        if self
            .protocol
            .rewrite_response_id(&mut response_bytes, decoded.message.header.id)
            .is_err()
        {
            return self.backend_failure_response(request, decoded, decoded.question.clone());
        }

        if let (true, Some(cache_key)) = (cache_store_allowed, cache_key) {
            if response.cache_directive.is_cacheable() {
                self.store_cache_response(
                    cache_key,
                    response_bytes.clone(),
                    &response_message,
                    decoded,
                    request,
                )
                .await;
            } else {
                self.metrics.increment(ResolverMetric::CacheStoreSkipped);
            }
        }

        let decision = ResolveDecision {
            client_ip: request.client_ip,
            question: Some(question),
            kind: ResolveDecisionKind::Allowed,
        };
        (decision, response_bytes)
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
        let response_bytes = self.responses.servfail(Some(decoded));
        (decision, response_bytes)
    }

    async fn store_cache_response(
        &self,
        cache_key: CacheKey,
        response_bytes: Vec<u8>,
        response: &Message,
        decoded: &DecodedQuery,
        request: &ResolveRequest,
    ) {
        if let Some(store) = self.cache_store_for_response(
            cache_key,
            response_bytes,
            response,
            decoded,
            request.received_at.0,
        ) {
            if store.negative_cache.is_some() {
                self.metrics.increment(ResolverMetric::CacheNegativeStore);
            }
            self.metrics.increment(ResolverMetric::CacheStore);
            self.cache.store(store).await;
        } else {
            self.metrics.increment(ResolverMetric::CacheStoreSkipped);
        }
    }

    fn cache_store_for_response(
        &self,
        key: CacheKey,
        mut response_template: Vec<u8>,
        response: &Message,
        query: &DecodedQuery,
        stored_at: SystemTime,
    ) -> Option<CacheStore> {
        if !response.header.qr()
            || response.questions.len() != 1
            || query.message.questions.len() != 1
            || QuestionKey::from_message(response)? != query.question
        {
            return None;
        }
        let response_code = response_code(response)?;
        let (ttl, negative_cache) = self.ttl_policy.ttl_for_response(response)?;
        self.protocol
            .rewrite_response_id(&mut response_template, 0)
            .ok()?;
        Some(CacheStore {
            key,
            response_template,
            response_code,
            minimum_ttl: ttl,
            negative_cache,
            stored_at,
            ttl,
        })
    }

    async fn finish(
        &self,
        started_at: SystemTime,
        request: &ResolveRequest,
        original_question_name: Option<String>,
        decision: ResolveDecision,
        response_bytes: Vec<u8>,
        cache_result: Option<QueryEventCacheResult>,
        backend: Option<QueryEventBackend>,
    ) -> ResolveOutcome {
        let finished_at = self.clock.now();
        let latency = finished_at.duration_since(started_at).ok();
        let mut event = QueryEventV1::from_decision_context(
            self.event_sequence.fetch_add(1, Ordering::Relaxed),
            finished_at,
            request.observed_source.clone(),
            original_question_name,
            &decision,
            response_code_from_wire(&response_bytes),
            cache_result,
            latency,
        );
        event.backend = backend;
        self.record_query_event(event);
        self.metrics.record_backend_status(&self.backend.status());
        if let Some(duration) = latency {
            self.metrics
                .observe_duration(ResolverMetric::QueryDuration, duration);
        }
        ResolveOutcome {
            response_bytes,
            decision,
        }
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

#[derive(Default)]
struct SingleFlightMisses {
    flights: Mutex<HashMap<CacheKey, Arc<InFlightMiss>>>,
}

enum SingleFlightTicket {
    Leader {
        key: CacheKey,
        flight: Arc<InFlightMiss>,
    },
    Follower {
        flight: Arc<InFlightMiss>,
    },
}

struct InFlightMiss {
    result: Mutex<Option<Result<ResolutionResponse, ResolutionBackendError>>>,
    notify: Notify,
}

struct SingleFlightLeader {
    coalescer: Arc<SingleFlightMisses>,
    key: CacheKey,
    flight: Arc<InFlightMiss>,
    completed: bool,
}

impl SingleFlightMisses {
    fn begin(&self, key: CacheKey) -> SingleFlightTicket {
        let mut flights = self.flights.lock().unwrap();
        if let Some(flight) = flights.get(&key) {
            return SingleFlightTicket::Follower {
                flight: Arc::clone(flight),
            };
        }
        let flight = Arc::new(InFlightMiss {
            result: Mutex::new(None),
            notify: Notify::new(),
        });
        flights.insert(key.clone(), Arc::clone(&flight));
        SingleFlightTicket::Leader { key, flight }
    }

    fn finish(
        &self,
        key: &CacheKey,
        flight: &Arc<InFlightMiss>,
        result: Result<ResolutionResponse, ResolutionBackendError>,
    ) {
        *flight.result.lock().unwrap() = Some(result);
        let mut flights = self.flights.lock().unwrap();
        if flights
            .get(key)
            .map(|current| Arc::ptr_eq(current, flight))
            .unwrap_or(false)
        {
            flights.remove(key);
        }
        drop(flights);
        flight.notify.notify_waiters();
    }
}

impl SingleFlightLeader {
    fn new(coalescer: Arc<SingleFlightMisses>, key: CacheKey, flight: Arc<InFlightMiss>) -> Self {
        Self {
            coalescer,
            key,
            flight,
            completed: false,
        }
    }

    fn complete(mut self, result: Result<ResolutionResponse, ResolutionBackendError>) {
        self.coalescer.finish(&self.key, &self.flight, result);
        self.completed = true;
    }
}

impl Drop for SingleFlightLeader {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.coalescer.finish(
            &self.key,
            &self.flight,
            Err(ResolutionBackendError::Transport(
                "single-flight leader cancelled".to_string(),
            )),
        );
    }
}

impl InFlightMiss {
    async fn wait(&self) -> Result<ResolutionResponse, ResolutionBackendError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            if let Some(result) = self.result.lock().unwrap().clone() {
                return result;
            }
            notified.await;
        }
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
        "mode:{};backend-generation:{backend_generation}",
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

fn validate_backend_response(
    response: &mut ResolutionResponse,
    query: &DecodedQuery,
) -> Option<Message> {
    if let Some(message) = response.response_message.take() {
        validate_backend_response_message(&message, query)?;
        if message.original_bytes.as_ref() != response.bytes.as_slice() {
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

fn cache_supported(query: &DecodedQuery) -> bool {
    query
        .message
        .edns
        .as_ref()
        .map(|edns| {
            edns.extended_rcode == 0
                && edns.version == 0
                && (edns.flags & !EDNS_DO_FLAG) == 0
                && edns.options.is_empty()
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

    fn decode_query_owned(&self, bytes: Vec<u8>) -> Result<DecodedQuery, QueryValidationError> {
        let message = Message::parse_standard_query_owned(bytes)?;
        DecodedQuery::new(message).ok_or(QueryValidationError::InvalidQuestionCount { count: 0 })
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

    fn serialize_cached_response(
        &self,
        query: &DecodedQuery,
        cached: &CachedResponse,
        now: SystemTime,
    ) -> crate::protocol::Result<Vec<u8>> {
        let mut response = cached.response_template.clone();
        if cached.expires_at <= now {
            return Err(crate::protocol::DnsParseError::MalformedRecord);
        }
        rewrite_response_request_fields(&mut response, &query.message)?;
        if let Ok(age) = now.duration_since(cached.stored_at) {
            age_response_ttls(&mut response, age)?;
        }
        let remaining_ttl = cached
            .expires_at
            .duration_since(now)
            .map_err(|_| crate::protocol::DnsParseError::MalformedRecord)?;
        cap_response_ttls(&mut response, remaining_ttl)?;
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

    fn decode_query_owned(&self, bytes: Vec<u8>) -> Result<DecodedQuery, QueryValidationError> {
        self.decode_query(&bytes)
    }

    fn configured_max_udp_payload_size(&self) -> usize;

    fn rewrite_response_id(
        &self,
        response_bytes: &mut [u8],
        request_id: u16,
    ) -> crate::protocol::Result<()>;

    fn serialize_cached_response(
        &self,
        query: &DecodedQuery,
        cached: &CachedResponse,
        now: SystemTime,
    ) -> crate::protocol::Result<Vec<u8>>;
}

pub trait PolicyEvaluator: Send + Sync {
    fn evaluate(&self, client_ip: IpAddr, question: &QuestionKey) -> PolicyDecision;
}

pub trait DnsCache: Send + Sync {
    fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup>;

    fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()>;
}

pub struct NoopDnsCache;

impl DnsCache for NoopDnsCache {
    fn lookup<'a>(&'a self, _request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> {
        Box::pin(async { CacheLookup::Miss })
    }

    fn store<'a>(&'a self, _entry: CacheStore) -> BoxFuture<'a, ()> {
        Box::pin(async {})
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

    pub fn remove_expired(&self, now: SystemTime) {
        let mut state = self.state.lock().unwrap();
        state.remove_expired(now);
        state.compact_lru();
    }

    #[cfg(test)]
    fn lru_len(&self) -> usize {
        self.state.lock().unwrap().lru.len()
    }

    fn lookup_now(&self, request: &CacheLookupRequest) -> CacheLookup {
        let mut state = self.state.lock().unwrap();
        if state
            .entries
            .get(&request.key)
            .map(|entry| entry.response.expires_at <= request.received_at)
            .unwrap_or(false)
        {
            state.entries.remove(&request.key);
            state.maybe_compact_lru(self.max_entries);
            return CacheLookup::Expired;
        }

        let Some(existing) = state.entries.get(&request.key) else {
            return CacheLookup::Miss;
        };

        let response = existing.response.clone();
        let sequence = state.next_sequence();
        if let Some(existing) = state.entries.get_mut(&request.key) {
            existing.sequence = sequence;
        }
        state.lru.push_back((request.key.clone(), sequence));
        state.maybe_compact_lru(self.max_entries);
        CacheLookup::Hit(response)
    }

    fn store_now(&self, entry: CacheStore) {
        let mut state = self.state.lock().unwrap();
        if self.max_entries == 0 {
            state.entries.clear();
            state.lru.clear();
            return;
        }

        let now = entry.stored_at;
        let expires_at = now.checked_add(entry.ttl).unwrap_or(SystemTime::UNIX_EPOCH);
        if expires_at <= now {
            state.entries.remove(&entry.key);
            state.maybe_compact_lru(self.max_entries);
            return;
        }
        if state.entries.len() >= self.max_entries {
            state.remove_expired(now);
            state.compact_lru();
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
        state.maybe_compact_lru(self.max_entries);
    }
}

impl InMemoryDnsCacheState {
    fn next_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        sequence
    }

    fn compact_lru(&mut self) {
        self.lru.retain(|(key, sequence)| {
            self.entries
                .get(key)
                .map(|entry| entry.sequence == *sequence)
                .unwrap_or(false)
        });
    }

    fn remove_expired(&mut self, now: SystemTime) {
        self.entries
            .retain(|_, entry| entry.response.expires_at > now);
    }

    fn maybe_compact_lru(&mut self, max_entries: usize) {
        if self.lru.len() > lru_compaction_threshold(max_entries) {
            self.compact_lru();
        }
    }

    fn evict_to_bound(&mut self, max_entries: usize) {
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

fn lru_compaction_threshold(max_entries: usize) -> usize {
    max_entries
        .saturating_mul(LRU_COMPACTION_MULTIPLIER)
        .max(max_entries.saturating_add(1))
}

impl DnsCache for InMemoryDnsCache {
    fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> {
        Box::pin(async move { self.lookup_now(request) })
    }

    fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.store_now(entry);
        })
    }
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
}

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

pub struct RecursiveResolutionBackend {
    config: RecursiveResolverConfig,
    transport: Arc<dyn RecursiveAuthorityTransport>,
    metrics: Option<Arc<dyn MetricsSink>>,
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

        let mut question = request.query.question.clone();
        let mut authorities = self.root_authorities();
        let mut seen_referrals = HashSet::new();
        let mut seen_cnames = HashSet::from([question.qname.clone()]);
        let mut cname_chain = Vec::new();
        let mut cname_restarts = 0u8;
        let query_deadline = Instant::now() + self.config.per_query_deadline;

        for _ in 0..self.config.max_recursion_depth {
            if authorities.is_empty() {
                self.increment_metric(ResolverMetric::RecursiveLimitHit);
                return Err(ResolutionBackendError::NoBackendsAvailable);
            }
            let mut last_error = None;
            let mut next_authorities = None;

            for authority in authorities.iter().copied() {
                let Some(remaining) = query_deadline.checked_duration_since(Instant::now()) else {
                    self.increment_metric(ResolverMetric::RecursiveAuthorityTimeout);
                    return Err(ResolutionBackendError::Timeout);
                };
                if remaining.is_zero() {
                    self.increment_metric(ResolverMetric::RecursiveAuthorityTimeout);
                    return Err(ResolutionBackendError::Timeout);
                }
                let attempt_timeout = remaining.min(self.config.per_authority_timeout);
                self.increment_metric(ResolverMetric::RecursiveAuthorityAttempt);
                let response = match time::timeout(
                    attempt_timeout,
                    self.transport.query(
                        authority,
                        question.clone(),
                        request.query.features.dnssec_ok,
                        attempt_timeout,
                    ),
                )
                .await
                {
                    Ok(Ok(response)) => response,
                    Ok(Err(error)) => {
                        if error == ResolutionBackendError::Timeout {
                            self.increment_metric(ResolverMetric::RecursiveAuthorityTimeout);
                        } else {
                            self.increment_metric(ResolverMetric::RecursiveAuthorityError);
                        }
                        last_error = Some(error);
                        continue;
                    }
                    Err(_) => {
                        self.increment_metric(ResolverMetric::RecursiveAuthorityTimeout);
                        last_error = Some(ResolutionBackendError::Timeout);
                        continue;
                    }
                };
                let message = &response.message;
                if let Some(error) = authority_response_error(message, &question) {
                    self.increment_metric(ResolverMetric::RecursiveAuthorityError);
                    last_error = Some(error);
                    continue;
                }

                if (message.header.aa() && has_requested_answer_for(message, &question))
                    || is_negative_answer(message)
                {
                    return Ok(ResolutionResponse::recursive_response(
                        &request.query,
                        response,
                        &cname_chain,
                        SystemTime::now(),
                        request.backend_generation,
                        authority,
                    )?);
                }

                if message.header.aa() {
                    if let Some(cname_record) = cname_record_for(message, &question) {
                        let RecordData::CNAME(cname_target) = &cname_record.record else {
                            unreachable!();
                        };
                        let target_question =
                            QuestionKey::new(cname_target, question.qtype, question.qclass);
                        if has_requested_answer_for(message, &target_question) {
                            return Ok(ResolutionResponse::recursive_response(
                                &request.query,
                                response,
                                &cname_chain,
                                SystemTime::now(),
                                request.backend_generation,
                                authority,
                            )?);
                        }
                        let next_name = normalize_question_name(cname_target);
                        if cname_restarts >= self.config.max_cname_restarts
                            || !seen_cnames.insert(next_name)
                        {
                            self.increment_metric(ResolverMetric::RecursiveLimitHit);
                            return Err(ResolutionBackendError::NoBackendsAvailable);
                        }
                        cname_chain.extend(cname_chain_records(
                            message,
                            cname_record,
                            request.query.features.dnssec_ok,
                        ));
                        cname_restarts = cname_restarts.saturating_add(1);
                        question = QuestionKey::new(cname_target, question.qtype, question.qclass);
                        seen_referrals.clear();
                        next_authorities = Some(self.root_authorities());
                        break;
                    }
                }

                let Some(referral) = referral_authorities(message, &question) else {
                    if has_delegation_for_question(message, &question) {
                        self.increment_metric(ResolverMetric::RecursiveBailiwickReject);
                    } else {
                        self.increment_metric(ResolverMetric::RecursiveLameDelegation);
                    }
                    last_error = Some(ResolutionBackendError::NoBackendsAvailable);
                    continue;
                };
                let referral_key = referral
                    .endpoints
                    .iter()
                    .map(SocketAddr::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let referral_key = format!("{}|{referral_key}", referral.owner);
                if !seen_referrals.insert(referral_key) {
                    self.increment_metric(ResolverMetric::RecursiveReferralLoop);
                    return Err(ResolutionBackendError::NoBackendsAvailable);
                }
                next_authorities = Some(referral.endpoints);
                break;
            }

            if let Some(next) = next_authorities {
                authorities = next;
            } else if let Some(error) = last_error {
                return Err(error);
            } else {
                return Err(ResolutionBackendError::NoBackendsAvailable);
            }
        }

        self.increment_metric(ResolverMetric::RecursiveLimitHit);
        Err(ResolutionBackendError::Timeout)
    }

    fn root_authorities(&self) -> Vec<SocketAddr> {
        self.config
            .root_hints
            .iter()
            .flat_map(|hint| hint.endpoints.iter().copied())
            .collect()
    }
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

pub trait ResponseFactory: Send + Sync {
    fn protocol_error(&self, request_id: Option<u16>, error: &QueryValidationError) -> Vec<u8>;

    fn blocked(&self, query: &DecodedQuery, block: &PolicyBlock) -> Vec<u8>;

    fn servfail(&self, query: Option<&DecodedQuery>) -> Vec<u8>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
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
    ProtocolError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc as std_mpsc;
    use std::sync::Mutex;
    use std::thread;

    use crate::protocol::{
        build_a_block_response, question_wire, EdnsInfo, Header, Question, Record,
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

    fn a_query_without_rd(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        bytes[2..4].copy_from_slice(&0u16.to_be_bytes());
        bytes
    }

    fn a_query_with_checking_disabled(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]) | 0x0010;
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        bytes
    }

    fn a_query_with_authenticated_data(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]) | 0x0020;
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
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
        a_query_with_edns_options(id, name, udp_payload_size, dnssec_ok, &[])
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
        QueryEventV1::from_decision(0, SystemTime::UNIX_EPOCH, &decision, None, None, None)
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
            SystemTime::UNIX_EPOCH,
            source.into(),
            Some("Example.COM.".to_string()),
            &decision,
            Some(ResponseCode::NoError as u16),
            Some(QueryEventCacheResult::Miss),
            Some(Duration::from_millis(1)),
        );

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
        assert!(finding_reasons(&classifier, &at_nxdomain[2], &at_nxdomain)
            .contains(&QueryEventClassifierReason::NxdomainBurst));

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
        assert!(finding_reasons(&classifier, &at_servfail[1], &at_servfail)
            .contains(&QueryEventClassifierReason::ServfailBurst));

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

        assert!(!finding_reasons(&classifier, &below_txt[1], &below_txt)
            .contains(&QueryEventClassifierReason::RepeatedTxtLookup));
        assert!(finding_reasons(&classifier, &at_txt[2], &at_txt)
            .contains(&QueryEventClassifierReason::RepeatedTxtLookup));

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
        assert!(txt_finding
            .evaluated_window
            .incomplete_reasons
            .contains(&QueryEventClassifierWindowIncompleteReason::ColdStart));
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
        assert!(txt_finding
            .evaluated_window
            .incomplete_reasons
            .contains(&QueryEventClassifierWindowIncompleteReason::RetentionEviction));
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
        assert!(second_event
            .advisory_findings
            .iter()
            .any(|finding| finding.reason == QueryEventClassifierReason::RepeatedTxtLookup));
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

        assert!(event
            .advisory_findings
            .iter()
            .any(|finding| finding.reason == QueryEventClassifierReason::NewDomain));
        assert!(!event
            .advisory_findings
            .iter()
            .any(|finding| finding.reason == QueryEventClassifierReason::RareDomain));
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
        assert!(finding
            .evaluated_window
            .incomplete_reasons
            .contains(&QueryEventClassifierWindowIncompleteReason::RetentionEviction));
        let retained = store.recent_events();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].sequence, 2);
    }

    #[derive(Default)]
    struct RecordingMetrics {
        increments: Mutex<Vec<ResolverMetric>>,
        durations: Mutex<Vec<(ResolverMetric, Duration)>>,
        backend_statuses: Mutex<Vec<BackendStatus>>,
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

        fn decode_query_owned(&self, bytes: Vec<u8>) -> Result<DecodedQuery, QueryValidationError> {
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

        fn serialize_cached_response(
            &self,
            query: &DecodedQuery,
            cached: &CachedResponse,
            now: SystemTime,
        ) -> crate::protocol::Result<Vec<u8>> {
            StandardProtocolCodec::new(1232).serialize_cached_response(query, cached, now)
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
        lookup: Mutex<CacheLookup>,
        lookups: Mutex<Vec<CacheLookupRequest>>,
        stores: Mutex<Vec<CacheStore>>,
    }

    impl RecordingCache {
        fn with_lookup(lookup: CacheLookup) -> Self {
            Self {
                lookup: Mutex::new(lookup),
                lookups: Mutex::new(Vec::new()),
                stores: Mutex::new(Vec::new()),
            }
        }
    }

    impl DnsCache for RecordingCache {
        fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> {
            Box::pin(async move {
                self.lookups.lock().unwrap().push(request.clone());
                self.lookup.lock().unwrap().clone()
            })
        }

        fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.stores.lock().unwrap().push(entry);
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

    fn resolve_service_with_cache(
        upstream: Arc<dyn ResolutionBackend>,
        cache: Arc<dyn DnsCache>,
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

    fn a_response_with_answer(id: u16, name: &str, ttl: u32) -> Vec<u8> {
        let query = Message::parse_standard_query(&a_query(id, name)).unwrap();
        build_a_block_response(&query, "192.0.2.10".parse().unwrap(), ttl)
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
        assert_eq!(
            transport.requests.lock().unwrap().as_slice(),
            &[("198.51.100.53:53".parse().unwrap(), question, false)]
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

        let message = response.response_message.as_ref().unwrap();
        assert_eq!(message.answers.len(), 1);
        assert!(message.additionals.is_empty());
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
        let requests = transport.requests.lock().unwrap();
        assert_eq!(
            requests.as_slice(),
            &[("198.51.100.53:53".parse().unwrap(), question, true)]
        );
    }

    #[tokio::test]
    async fn recursive_backend_filters_raw_dnssec_records_without_do() {
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
        assert_eq!(
            without_do.response_message.as_ref().unwrap().answers.len(),
            1
        );

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
        assert!(!message.header.ad());
        assert!(!message.header.cd());
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
        assert_eq!(requests[1], (referred, question, false));
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
        assert_eq!(requests[1], (shared_authority, question.clone(), false));
        assert_eq!(requests[2], (shared_authority, question, false));
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
        assert_eq!(requests[0].1, first);
        assert!(!requests[0].2);
        assert_eq!(requests[1].1, second);
        assert!(!requests[1].2);
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
        assert_eq!(requests[0].1, first);
        assert!(!requests[0].2);
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
        assert!(metrics
            .durations
            .lock()
            .unwrap()
            .iter()
            .any(|(metric, _)| *metric == ResolverMetric::RecursiveQueryDuration));
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
        assert_eq!(requests[1], (second_authority, question, false));
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
        assert_eq!(requests[1], (second_authority, question, false));
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
        assert_eq!(requests[1], (referral_authority, alias, false));
        assert_eq!(requests[3], (referral_authority, target, false));
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
                Some("mode:recursive;backend-generation:7".to_string()),
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
                cache_namespace: Some("mode:recursive;backend-generation:7".to_string()),
                dnssec_validation: DnssecValidationStatus::Disabled,
            })
        );
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
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::QueryEventAccepted));
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
            .decode_query_owned(query_bytes)
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

    #[test]
    fn cache_store_keeps_explicit_key_and_ttl() {
        let question = QuestionKey::new("example.com", 28, 1);
        let entry = CacheStore {
            key: CacheKey::new(
                question,
                question_wire(&aaaa_query(0x1000, "example.com"))
                    .unwrap()
                    .to_vec(),
                QueryFeatures {
                    recursion_desired: true,
                    authenticated_data: false,
                    checking_disabled: false,
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
            stored_at: SystemTime::UNIX_EPOCH,
            ttl: Duration::from_secs(60),
        };

        assert_eq!(entry.key.question.qname, "example.com");
        assert_eq!(entry.key.cache_namespace.as_deref(), Some("primary"));
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
            question_wire(&a_query(0x1000, name)).unwrap().to_vec(),
            QueryFeatures {
                recursion_desired: true,
                authenticated_data: false,
                checking_disabled: false,
                dnssec_ok: false,
                edns_udp_payload_size: None,
            },
            Some("primary".to_string()),
            512,
        )
    }

    fn cache_store_at(key: CacheKey, ttl: Duration, stored_at: SystemTime) -> CacheStore {
        CacheStore {
            key,
            response_template: vec![0x12, 0x34, 0x81, 0x80],
            response_code: ResponseCode::NoError,
            minimum_ttl: ttl,
            negative_cache: None,
            stored_at,
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
        let original_query = Message::parse_owned(a_query(id, &question.qname)).unwrap();
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
            timestamp,
            &decision,
            Some(ResponseCode::NoError as u16),
            Some(QueryEventCacheResult::Hit),
            Some(Duration::from_millis(12)),
        );

        assert_eq!(event.schema_version, QueryEventV1::SCHEMA_VERSION);
        assert_eq!(event.sequence, 7);
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
    fn in_memory_cache_returns_unexpired_entry() {
        let cache = InMemoryDnsCache::new(16);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let key = cache_key("example.com");

        cache.store_now(cache_store_at(key.clone(), Duration::from_secs(30), now));

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
        let other = cache_key("other.example");

        cache.store_now(cache_store_at(key.clone(), Duration::from_secs(30), now));
        cache.store_now(cache_store_at(other.clone(), Duration::from_secs(20), now));

        let lookup = cache.lookup_now(&CacheLookupRequest {
            key,
            received_at: now + Duration::from_secs(30),
        });

        assert_eq!(lookup, CacheLookup::Expired);
        assert_eq!(cache.len(), 1);
        let other_lookup = cache.lookup_now(&CacheLookupRequest {
            key: other,
            received_at: now + Duration::from_secs(30),
        });
        assert_eq!(other_lookup, CacheLookup::Expired);
        assert!(cache.is_empty());
    }

    #[test]
    fn in_memory_cache_evicts_least_recently_used_entry_when_bounded() {
        let cache = InMemoryDnsCache::new(2);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let first = cache_key("first.example");
        let second = cache_key("second.example");
        let third = cache_key("third.example");
        cache.store_now(cache_store_at(first.clone(), Duration::from_secs(60), now));
        cache.store_now(cache_store_at(second.clone(), Duration::from_secs(60), now));
        assert!(matches!(
            cache.lookup_now(&CacheLookupRequest {
                key: first.clone(),
                received_at: now
            }),
            CacheLookup::Hit(_)
        ));

        cache.store_now(cache_store_at(third.clone(), Duration::from_secs(60), now));

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
    fn in_memory_cache_prunes_expired_entries_before_eviction() {
        let cache = InMemoryDnsCache::new(2);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let later = now + Duration::from_secs(10);
        let first = cache_key("first.example");
        let expired = cache_key("expired.example");
        let third = cache_key("third.example");
        cache.store_now(cache_store_at(first.clone(), Duration::from_secs(60), now));
        cache.store_now(cache_store_at(expired.clone(), Duration::from_secs(5), now));

        cache.store_now(cache_store_at(
            third.clone(),
            Duration::from_secs(60),
            later,
        ));

        assert_eq!(cache.len(), 2);
        assert!(matches!(
            cache.lookup_now(&CacheLookupRequest {
                key: first,
                received_at: later
            }),
            CacheLookup::Hit(_)
        ));
        assert_eq!(
            cache.lookup_now(&CacheLookupRequest {
                key: expired,
                received_at: later
            }),
            CacheLookup::Miss
        );
        assert!(matches!(
            cache.lookup_now(&CacheLookupRequest {
                key: third,
                received_at: later
            }),
            CacheLookup::Hit(_)
        ));
    }

    #[test]
    fn in_memory_cache_zero_capacity_stores_nothing() {
        let cache = InMemoryDnsCache::new(0);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let key = cache_key("example.com");

        cache.store_now(cache_store_at(key.clone(), Duration::from_secs(30), now));

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
    fn in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits() {
        let cache = InMemoryDnsCache::new(2);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let key = cache_key("example.com");
        cache.store_now(cache_store_at(key.clone(), Duration::from_secs(60), now));

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
        assert!(cache.lru_len() <= lru_compaction_threshold(2));
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
                recursion_desired: true,
                authenticated_data: false,
                checking_disabled: false,
                dnssec_ok: true,
                edns_udp_payload_size: Some(4096),
            }
        );
        assert_eq!(key.cache_namespace.as_deref(), Some("primary"));
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

    #[test]
    fn cache_key_separates_exact_wire_question_casing_for_templates() {
        let codec = StandardProtocolCodec::new(1232);
        let lower = codec.decode_query(&a_query(0x1000, "example.com")).unwrap();
        let mixed = codec.decode_query(&a_query(0x1000, "Example.COM")).unwrap();

        assert_eq!(lower.question, mixed.question);
        assert_ne!(
            CacheKey::from_query(&lower, None, 1232),
            CacheKey::from_query(&mixed, None, 1232)
        );
    }

    #[test]
    fn cache_key_separates_recursion_desired_header_flag() {
        let codec = StandardProtocolCodec::new(1232);
        let recursive = codec.decode_query(&a_query(0x1000, "example.com")).unwrap();
        let non_recursive = codec
            .decode_query(&a_query_without_rd(0x1000, "example.com"))
            .unwrap();

        assert_ne!(
            CacheKey::from_query(&recursive, None, 1232),
            CacheKey::from_query(&non_recursive, None, 1232)
        );
    }

    #[test]
    fn cache_key_separates_dnssec_request_flags() {
        let codec = StandardProtocolCodec::new(1232);
        let base = codec.decode_query(&a_query(0x1000, "example.com")).unwrap();
        let ad = codec
            .decode_query(&a_query_with_authenticated_data(0x1000, "example.com"))
            .unwrap();
        let cd = codec
            .decode_query(&a_query_with_checking_disabled(0x1000, "example.com"))
            .unwrap();
        let do_query = codec
            .decode_query(&a_query_with_edns(0x1000, "example.com", 1232, true))
            .unwrap();

        let base_key = CacheKey::from_query(&base, None, 1232);
        assert_ne!(base_key, CacheKey::from_query(&ad, None, 1232));
        assert_ne!(base_key, CacheKey::from_query(&cd, None, 1232));
        assert_ne!(base_key, CacheKey::from_query(&do_query, None, 1232));
        assert!(
            CacheKey::from_query(&ad, None, 1232)
                .features
                .authenticated_data
        );
        assert!(
            CacheKey::from_query(&cd, None, 1232)
                .features
                .checking_disabled
        );
        assert!(
            CacheKey::from_query(&do_query, None, 1232)
                .features
                .dnssec_ok
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
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::UpstreamSuccess));
    }

    #[tokio::test]
    async fn resolve_returns_cached_template_with_current_request_id() {
        let cache = Arc::new(InMemoryDnsCache::new(16));
        let cached_query = StandardProtocolCodec::new(1232)
            .decode_query(&a_query(0xaaaa, "example.com"))
            .unwrap();
        cache.store_now(CacheStore {
            key: CacheKey::from_query(
                &cached_query,
                backend_cache_namespace(ResolutionMode::Forward, 0),
                1232,
            ),
            response_template: a_response_with_answer(0, "example.com", 60),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            negative_cache: Some(negative_metadata(
                "example.com",
                "example.com",
                1,
                1,
                NegativeCacheKind::NoData,
                Duration::from_secs(60),
            )),
            stored_at: SystemTime::UNIX_EPOCH,
            ttl: Duration::from_secs(60),
        });
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
                SystemTime::UNIX_EPOCH,
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
        assert_eq!(metrics.count(ResolverMetric::CacheNegativeHit), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 0);
    }

    #[tokio::test]
    async fn resolve_rewrites_cached_response_rd_flag_for_current_request() {
        let cache = Arc::new(InMemoryDnsCache::new(16));
        let cached_query = StandardProtocolCodec::new(1232)
            .decode_query(&a_query_without_rd(0xaaaa, "example.com"))
            .unwrap();
        cache.store_now(CacheStore {
            key: CacheKey::from_query(
                &cached_query,
                backend_cache_namespace(ResolutionMode::Forward, 0),
                1232,
            ),
            response_template: a_response_with_answer(0, "example.com", 60),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            negative_cache: None,
            stored_at: SystemTime::UNIX_EPOCH,
            ttl: Duration::from_secs(60),
        });
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_without_rd(0x2222, "example.com"),
            ))
            .await;

        assert_eq!(&outcome.response_bytes[0..2], &[0x22, 0x22]);
        assert_eq!(outcome.response_bytes[2] & 0x01, 0);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
    }

    #[tokio::test]
    async fn resolve_ages_cached_response_ttls_for_current_request_time() {
        let cache = Arc::new(InMemoryDnsCache::new(16));
        let cached_query = StandardProtocolCodec::new(1232)
            .decode_query(&a_query(0xaaaa, "example.com"))
            .unwrap();
        cache.store_now(CacheStore {
            key: CacheKey::from_query(
                &cached_query,
                backend_cache_namespace(ResolutionMode::Forward, 0),
                1232,
            ),
            response_template: a_response_with_answer(0, "example.com", 60),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            negative_cache: None,
            stored_at: SystemTime::UNIX_EPOCH,
            ttl: Duration::from_secs(60),
        });
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(25),
                a_query(0x2222, "example.com"),
            ))
            .await;

        let parsed = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(parsed.answers[0].ttl, 35);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
    }

    #[tokio::test]
    async fn resolve_caps_cached_response_ttls_to_remaining_cache_lifetime() {
        let cache = Arc::new(InMemoryDnsCache::new(16));
        let cached_query = StandardProtocolCodec::new(1232)
            .decode_query(&a_query(0xaaaa, "example.com"))
            .unwrap();
        cache.store_now(CacheStore {
            key: CacheKey::from_query(
                &cached_query,
                backend_cache_namespace(ResolutionMode::Forward, 0),
                1232,
            ),
            response_template: a_response_with_answer(0, "example.com", 3600),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            negative_cache: None,
            stored_at: SystemTime::UNIX_EPOCH,
            ttl: Duration::from_secs(60),
        });
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(25),
                a_query(0x2222, "example.com"),
            ))
            .await;

        let parsed = Message::parse(&outcome.response_bytes).unwrap();
        assert_eq!(parsed.answers[0].ttl, 35);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
    }

    #[tokio::test]
    async fn resolve_truncates_oversized_cached_response_for_current_request() {
        let mut oversized_response = a_response_with_answer(0, "example.com", 60);
        oversized_response.extend(std::iter::repeat_n(0, 700));
        let cached = CachedResponse {
            response_template: oversized_response,
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            negative_cache: None,
            stored_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(60),
        };
        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Hit(cached)));
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream.clone(), cache, events, metrics.clone(), 512);

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x3333, "example.com"),
            ))
            .await;

        assert_eq!(&outcome.response_bytes[0..2], &[0x33, 0x33]);
        assert_ne!(outcome.response_bytes[2] & 0x02, 0);
        assert_eq!(outcome.response_bytes.len(), 12);
        assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
        assert!(upstream.requests.lock().unwrap().is_empty());
        assert_eq!(metrics.count(ResolverMetric::CacheResponseTruncated), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
    }

    #[tokio::test]
    async fn resolve_treats_expired_cache_backend_hit_as_miss() {
        let cached = CachedResponse {
            response_template: a_response_with_answer(0, "example.com", 60),
            response_code: ResponseCode::NoError,
            minimum_ttl: Duration::from_secs(60),
            negative_cache: None,
            stored_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(30),
        };
        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Hit(cached)));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x8888, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service = resolve_service_with_cache(
            upstream.clone(),
            cache.clone(),
            events,
            metrics.clone(),
            1232,
        );

        let outcome = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH + Duration::from_secs(31),
                a_query(0x8888, "example.com"),
            ))
            .await;

        assert_eq!(outcome.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(upstream.requests.lock().unwrap().len(), 1);
        assert_eq!(cache.stores.lock().unwrap().len(), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheExpired), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
    }

    #[tokio::test]
    async fn resolve_coalesces_duplicate_cache_misses() {
        let cache = Arc::new(InMemoryDnsCache::new(16));
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
    }

    #[tokio::test]
    async fn single_flight_leader_drop_wakes_followers_and_clears_key() {
        let coalescer = Arc::new(SingleFlightMisses::default());
        let key = cache_key("example.com");
        let SingleFlightTicket::Leader { key, flight } = coalescer.begin(key.clone()) else {
            panic!("first miss should lead the flight");
        };
        let guard = SingleFlightLeader::new(Arc::clone(&coalescer), key.clone(), flight);
        let SingleFlightTicket::Follower { flight } = coalescer.begin(key.clone()) else {
            panic!("duplicate miss should follow the flight");
        };

        drop(guard);

        let result = tokio::time::timeout(Duration::from_secs(1), flight.wait())
            .await
            .expect("follower should wake after leader cancellation");
        assert!(matches!(result, Err(UpstreamError::Transport(_))));
        let SingleFlightTicket::Leader { key, flight } = coalescer.begin(key) else {
            panic!("cancelled flight should be removed");
        };
        SingleFlightLeader::new(Arc::clone(&coalescer), key, flight)
            .complete(Err(UpstreamError::Timeout));
    }

    #[tokio::test]
    async fn resolve_stores_upstream_response_as_neutral_id_template() {
        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
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
        assert_eq!(&stores[0].response_template[0..2], &[0, 0]);
        assert_eq!(stores[0].response_code, ResponseCode::NoError);
        assert_eq!(stores[0].ttl, Duration::from_secs(45));
        assert_eq!(stores[0].stored_at, request_time);
        assert_eq!(
            stores[0].key.question,
            QuestionKey::new("example.com", 1, 1)
        );
        drop(stores);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
    }

    #[tokio::test]
    async fn resolve_records_negative_cache_store_metrics() {
        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
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
        assert_eq!(stores[0].response_code, ResponseCode::NxDomain);
        assert_eq!(
            stores[0].negative_cache,
            Some(negative_metadata(
                "example.com",
                "example.com",
                1,
                1,
                NegativeCacheKind::NxDomain,
                Duration::from_secs(30)
            ))
        );
        drop(stores);
        assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheNegativeStore), 1);
    }

    #[tokio::test]
    async fn resolve_honors_backend_do_not_cache_directive() {
        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
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
            Some("mode:forward;backend-generation:2".to_string()),
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

    #[tokio::test]
    async fn backend_generation_separates_cache_entries() {
        let cache = Arc::new(InMemoryDnsCache::new(16));
        let first_backend = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x1111, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let first_service = ResolveQuery::with_cache_and_backend_generation(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache.clone(),
            CacheTtlPolicy::default(),
            first_backend.clone(),
            1,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events.clone(),
            metrics.clone(),
        );
        let second_backend = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x2222, "example.com", 60),
        ))));
        let second_service = ResolveQuery::with_cache_and_backend_generation(
            Arc::new(StandardProtocolCodec::new(1232)),
            cache,
            CacheTtlPolicy::default(),
            second_backend.clone(),
            2,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            metrics,
        );

        let first = first_service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x1111, "example.com"),
            ))
            .await;
        let second = second_service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query(0x2222, "example.com"),
            ))
            .await;

        assert_eq!(first.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(second.decision.kind, ResolveDecisionKind::Allowed);
        assert_eq!(first_backend.requests.lock().unwrap().len(), 1);
        assert_eq!(second_backend.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn resolve_rejects_invalid_backend_response_bytes() {
        for response in [
            vec![0x12],
            a_response_with_answer(0x5555, "other.example", 60),
            multi_question_a_response_with_answer(0x5555, "example.com", 60),
        ] {
            let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
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
        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
        let mut response = upstream_response(a_response_with_answer(0x5555, "example.com", 60));
        response.bytes = a_response_with_answer(0x5555, "other.example", 60);
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
        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
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
        assert_eq!(
            stores[0].key.question,
            QuestionKey::new("example.com", 1, 1)
        );
        assert_eq!(metrics.count(ResolverMetric::CacheStore), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheStoreSkipped), 0);
    }

    #[tokio::test]
    async fn resolve_does_not_store_after_cache_bypass_or_unavailable() {
        for (lookup, metric) in [
            (
                CacheLookup::Bypass(CacheBypassReason::UnsupportedQueryFeature),
                ResolverMetric::CacheBypass,
            ),
            (CacheLookup::Unavailable, ResolverMetric::CacheUnavailable),
        ] {
            let cache = Arc::new(RecordingCache::with_lookup(lookup));
            let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
                a_response_with_answer(0x6666, "example.com", 60),
            ))));
            let events = Arc::new(RecordingEvents::default());
            let metrics = Arc::new(RecordingMetrics::default());
            let service =
                resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

            let _ = service
                .resolve(ResolveRequest::new(
                    "192.0.2.10".parse().unwrap(),
                    SystemTime::UNIX_EPOCH,
                    a_query(0x6666, "example.com"),
                ))
                .await;

            assert!(cache.stores.lock().unwrap().is_empty());
            assert_eq!(metrics.count(metric), 1);
            assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
        }
    }

    #[tokio::test]
    async fn resolve_bypasses_cache_for_unsupported_edns_options() {
        let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            a_response_with_answer(0x7777, "example.com", 60),
        ))));
        let events = Arc::new(RecordingEvents::default());
        let metrics = Arc::new(RecordingMetrics::default());
        let service =
            resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
        let edns_cookie = [0u8, 10, 0, 2, 0xaa, 0xbb];

        let _ = service
            .resolve(ResolveRequest::new(
                "192.0.2.10".parse().unwrap(),
                SystemTime::UNIX_EPOCH,
                a_query_with_edns_options(0x7777, "example.com", 1232, false, &edns_cookie),
            ))
            .await;

        assert!(cache.lookups.lock().unwrap().is_empty());
        assert!(cache.stores.lock().unwrap().is_empty());
        assert_eq!(metrics.count(ResolverMetric::CacheBypass), 1);
        assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
    }

    #[tokio::test]
    async fn resolve_bypasses_cache_for_unsupported_edns_flags_and_version() {
        for request in [
            a_query_with_edns_details(0x7777, "example.com", 1232, false, 0, 1, &[]),
            a_query_with_edns_flags(0x7777, "example.com", 1232, false, 0, 0, 0x4000, &[]),
        ] {
            let cache = Arc::new(RecordingCache::with_lookup(CacheLookup::Miss));
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
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::ProtocolError));
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
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::UpstreamFailure));
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
        assert!(metrics
            .increments
            .lock()
            .unwrap()
            .contains(&ResolverMetric::UpstreamFailure));
    }
}
