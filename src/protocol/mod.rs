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

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::str;
use std::time::Duration;

use bytes::Bytes;
use serde::Serialize;

pub(crate) mod edns_cookie;

pub(crate) const DNS_HEADER_LEN: usize = 12;
pub const DNS_DEFAULT_UDP_PAYLOAD_SIZE: usize = 512;
const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;
const OPT_RECORD_TYPE: u16 = 41;
const TXT_RECORD_TYPE: u16 = 16;
const EDNS_DO_FLAG: u16 = 0x8000;

pub type Result<T> = std::result::Result<T, DnsParseError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsParseError {
    Truncated,
    InvalidLabel,
    InvalidNamePointer,
    PointerLoop,
    UnsupportedOpcode,
    InvalidQuestionCount,
    InvalidUtf8Label,
    UnexpectedEof,
    MalformedRecord,
    MessageTooShort,
    TcpFrameTooLarge { size: usize, max_size: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryValidationError {
    Parse(DnsParseError),
    UnsupportedOpcode {
        opcode: u8,
    },
    InvalidQuestionCount {
        count: u16,
    },
    UnexpectedSectionRecords {
        answers: u16,
        authorities: u16,
        additionals: u16,
    },
    InvalidEdns,
    NotQuery,
    /// RFC 6891 §6.1.3: rdns implements EDNS version 0 only. A query
    /// advertising any other version must be answered BADVERS (extended
    /// RCODE 16), not treated as a generic FORMERR -- see
    /// `build_badvers_response`.
    UnsupportedEdnsVersion {
        version: u8,
    },
}

impl From<DnsParseError> for QueryValidationError {
    fn from(value: DnsParseError) -> Self {
        Self::Parse(value)
    }
}

/// A `QueryValidationError` from
/// `Message::parse_standard_query_owned_with_recovery`, paired with the
/// `Message` recovered on a best-effort basis (see that method's docs for
/// when recovery does and doesn't succeed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDecodeFailure {
    pub error: QueryValidationError,
    pub recovered_message: Option<Box<Message>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

impl ResponseCode {
    fn as_u8(self) -> u8 {
        self as u8
    }
}

impl QueryValidationError {
    /// Coarse classifier used for metrics/event bucketing
    /// (`ResolveDecisionKind::ProtocolError`) -- `ResponseCode` only models
    /// the header's 4-bit RCODE field, so it cannot represent BADVERS
    /// (extended RCODE 16, split across the header's RCODE nibble and the
    /// OPT record's extended-RCODE byte). `UnsupportedEdnsVersion` is
    /// bucketed here as `FormErr` for that reason; the actual wire response
    /// is still correctly BADVERS -- see
    /// `resolver::BasicResponseFactory::protocol_error`, which special-cases
    /// this variant before ever consulting `response_code()`, and
    /// `build_badvers_response`.
    pub fn response_code(&self) -> ResponseCode {
        match self {
            Self::UnsupportedOpcode { .. } => ResponseCode::NotImp,
            Self::Parse(_)
            | Self::InvalidQuestionCount { .. }
            | Self::UnexpectedSectionRecords { .. }
            | Self::InvalidEdns
            | Self::NotQuery
            | Self::UnsupportedEdnsVersion { .. } => ResponseCode::FormErr,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFrameDecodeStatus {
    Complete {
        message_len: usize,
        required_total_len: usize,
    },
    NeedMore {
        required_total_len: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub original_bytes: Bytes,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub edns: Option<EdnsInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl Header {
    pub fn qr(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    pub fn opcode(&self) -> u8 {
        ((self.flags & 0x7800) >> 11) as u8
    }

    pub fn aa(&self) -> bool {
        (self.flags & 0x0400) != 0
    }

    pub fn tc(&self) -> bool {
        (self.flags & 0x0200) != 0
    }

    pub fn rd(&self) -> bool {
        (self.flags & 0x0100) != 0
    }

    pub fn ra(&self) -> bool {
        (self.flags & 0x0080) != 0
    }

    pub fn ad(&self) -> bool {
        (self.flags & 0x0020) != 0
    }

    pub fn cd(&self) -> bool {
        (self.flags & 0x0010) != 0
    }

    pub fn r_code(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsInfo {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub flags: u16,
    pub dnssec_ok: bool,
    pub options: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
    MX {
        preference: u16,
        exchange: String,
    },
    CERT {
        cert_type: u16,
        key_tag: u16,
        algorithm: u8,
        cert: Vec<u8>,
    },
    CNAME(String),
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    NSEC {
        next_domain: String,
        type_bit_maps: Vec<u8>,
    },
    NSEC3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt_length: u8,
        salt: Vec<u8>,
        hash_length: u8,
        next_domain: String,
        type_bit_maps: Vec<u8>,
    },
    NSEC3PARAM {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt_length: u8,
        salt: Vec<u8>,
    },
    NS(String),
    PTR(String),
    RP {
        mboxdname: String,
        txtdname: String,
    },
    RRSIG {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: Vec<u8>,
    },
    SOA {
        ttl: u32,
        rname: String,
        mname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    TXT(String),
    OPT(EdnsInfo),
    Unknown {
        rtype: u16,
        bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub record: RecordData,
}

impl Message {
    pub fn parse(dns_message: &[u8]) -> Result<Self> {
        let parts = Self::parse_parts(dns_message)?;
        Ok(Self::from_parts(Bytes::copy_from_slice(dns_message), parts))
    }

    /// Accepts anything cheaply convertible to `Bytes` -- notably `Vec<u8>`
    /// (an O(1) move of the vec's existing allocation, not a copy) and
    /// `Bytes` itself (an O(1) refcount bump when the caller already holds
    /// a `Bytes`, e.g. because it also needs to retain a cheap-clone
    /// handle to the same wire bytes for some other purpose).
    pub fn parse_owned(dns_message: impl Into<Bytes>) -> Result<Self> {
        let dns_message = dns_message.into();
        let parts = Self::parse_parts(&dns_message)?;
        Ok(Self::from_parts(dns_message, parts))
    }

    fn parse_parts(dns_message: &[u8]) -> Result<MessageParts> {
        let header = parse_header(dns_message)?;
        let mut offset = DNS_HEADER_LEN;
        let mut context = ParseContext::default();

        let questions = parse_questions(dns_message, &mut offset, header.qd_count, &mut context)?;
        let answers = parse_records(dns_message, &mut offset, header.an_count, &mut context)?;
        let authorities = parse_records(dns_message, &mut offset, header.ns_count, &mut context)?;
        let additionals = parse_records(dns_message, &mut offset, header.ar_count, &mut context)?;
        let edns = extract_edns_info(&additionals)?;

        Ok(MessageParts {
            header,
            questions,
            answers,
            authorities,
            additionals,
            edns,
        })
    }

    fn from_parts(original_bytes: Bytes, parts: MessageParts) -> Self {
        Self {
            header: parts.header,
            original_bytes,
            questions: parts.questions,
            answers: parts.answers,
            authorities: parts.authorities,
            additionals: parts.additionals,
            edns: parts.edns,
        }
    }

    pub fn parse_standard_query(
        dns_message: &[u8],
    ) -> std::result::Result<Self, QueryValidationError> {
        let header = parse_header(dns_message)?;
        validate_standard_query_header(&header)?;
        let message = Self::parse(dns_message)?;
        validate_standard_query_body(&message)?;
        Ok(message)
    }

    pub fn parse_standard_query_owned(
        dns_message: impl Into<Bytes>,
    ) -> std::result::Result<Self, QueryValidationError> {
        let dns_message = dns_message.into();
        let header = parse_header(&dns_message)?;
        validate_standard_query_header(&header)?;
        let message = Self::parse_owned(dns_message)?;
        validate_standard_query_body(&message)?;
        Ok(message)
    }

    /// Same acceptance criteria as `parse_standard_query_owned`, but on
    /// failure also makes a best-effort attempt to recover enough of the
    /// `Message` for an EDNS/CD-aware protocol-error response (RFC 6891
    /// §6.1.1 requires an OPT record in response to any EDNS query; RFC
    /// 4035 §3.2.2 requires CD to be copied from query to response).
    ///
    /// When `parse_header` itself fails, recovery yields `None` -- the
    /// wire format is too malformed to have any header, let alone a
    /// question/OPT/CD, to recover. When only
    /// `validate_standard_query_header` fails (e.g. an unsupported opcode,
    /// or more questions/records than a standard query allows),
    /// `recover_query_context` always returns `Some`: the header itself
    /// (id/flags, including CD) is always usable by that point, and the
    /// question/EDNS context is recovered on a strictly bounded budget --
    /// see that function's docs -- independent of, and specifically
    /// distrusting, the header's own section counts, since a query that
    /// already failed header validation cannot be trusted to bound how
    /// much work recovering it costs.
    ///
    /// This exists as a separate method (rather than changing
    /// `parse_standard_query_owned` itself) so every existing caller and
    /// test asserting on `Result<Self, QueryValidationError>` is unaffected
    /// -- recovery is purely additive, and (unlike eagerly cloning or
    /// unconditionally parsing on every call) only costs anything on this
    /// already-rare error path, not on every decoded query.
    pub fn parse_standard_query_owned_with_recovery(
        dns_message: impl Into<Bytes>,
    ) -> std::result::Result<Self, QueryDecodeFailure> {
        let dns_message = dns_message.into();
        let header = match parse_header(&dns_message) {
            Ok(header) => header,
            Err(error) => {
                return Err(QueryDecodeFailure {
                    error: error.into(),
                    recovered_message: None,
                });
            }
        };
        if let Err(error) = validate_standard_query_header(&header) {
            // A full `Self::parse` here would trust the header's own
            // (by definition, at this point, already-invalid) section
            // counts to bound how much of the packet it walks and
            // allocates -- letting a crafted `an_count`/`ns_count`/
            // `ar_count` turn every header-validation failure into a
            // full-parse-and-allocate pass, which is exactly the cost the
            // pre-recovery code avoided by bailing out after the 12-byte
            // header check alone. `recover_query_context` recovers the
            // same question/EDNS/CD context on a strictly bounded budget
            // instead, and (unlike `Self::parse`) tolerates a duplicate
            // OPT record rather than discarding everything recovered.
            let recovered_message = Some(Box::new(recover_query_context(dns_message, &header)));
            return Err(QueryDecodeFailure {
                error,
                recovered_message,
            });
        }
        // `validate_standard_query_header` only checks `ar_count <= 1`, not
        // what that one additional record's *type* is -- a crafted query
        // can pass header validation with a single additional record that
        // isn't actually OPT (e.g. a large unknown/DNSSEC-style RDATA).
        // Without this check, that shape would fall straight through to
        // the full `Self::parse_owned` below, which fully materializes the
        // record (including a `to_vec()` copy for unknown-type RDATA) only
        // for `validate_standard_query_body` to reject it afterwards for
        // not being OPT -- reintroducing, via a different validation-
        // ordering gap, the same "malformed packet forces expensive parse
        // work" cost the header-validation-failure branch above already
        // closed off. `recovery_additional_is_opt` answers "is this worth
        // a full parse" with the same lightweight, non-allocating
        // technique `recovery_skip_record` uses, so a non-OPT additional
        // is rejected here without ever calling `parse_record_data`. A
        // precheck parse error is deliberately *not* treated as
        // conclusive: it means the packet is malformed in a way the full
        // parse will also hit early (before the expensive RDATA copy), so
        // falling through and letting `Self::parse_owned` produce the
        // authoritative error is both correct and still cheap.
        if header.ar_count == 1 && recovery_additional_is_opt(&dns_message, &header) == Ok(false) {
            let recovered_message = Some(Box::new(recover_query_context(dns_message, &header)));
            return Err(QueryDecodeFailure {
                error: QueryValidationError::InvalidEdns,
                recovered_message,
            });
        }
        // By this point `parse_header` and `validate_standard_query_header`
        // have both already succeeded, so the 12-byte header -- including
        // the CD bit (RFC 4035 §3.2.2 requires CD to be copied from query
        // to response) -- was read successfully even if the body below
        // fails to parse (e.g. a malformed question, or a malformed
        // additional-section record body `recovery_additional_is_opt`'s
        // cheap precheck didn't catch). `dns_message.clone()` is an O(1)
        // `Bytes` refcount bump, not a copy, so retaining a handle to it
        // here to drive `recover_query_context` on this error path costs
        // nothing on the (overwhelmingly common) success path.
        let message = match Self::parse_owned(dns_message.clone()) {
            Ok(message) => message,
            Err(error) => {
                let recovered_message = Some(Box::new(recover_query_context(dns_message, &header)));
                return Err(QueryDecodeFailure {
                    error: error.into(),
                    recovered_message,
                });
            }
        };
        if let Err(error) = validate_standard_query_body(&message) {
            return Err(QueryDecodeFailure {
                error,
                recovered_message: Some(Box::new(message)),
            });
        }
        Ok(message)
    }

    pub fn validate_standard_query(&self) -> std::result::Result<(), QueryValidationError> {
        validate_standard_query_header(&self.header)?;
        validate_standard_query_body(self)
    }

    pub fn effective_udp_payload_size(&self, configured_max: usize) -> usize {
        let advertised = self
            .edns
            .as_ref()
            .map(|edns| edns.udp_payload_size as usize)
            .unwrap_or(DNS_DEFAULT_UDP_PAYLOAD_SIZE);
        advertised
            .max(DNS_DEFAULT_UDP_PAYLOAD_SIZE)
            .min(configured_max)
    }

    pub fn response_exceeds_udp_payload(&self, response_len: usize, configured_max: usize) -> bool {
        response_len > self.effective_udp_payload_size(configured_max)
    }
}

struct MessageParts {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    edns: Option<EdnsInfo>,
}

pub fn build_formerr_response(request_id: u16) -> Vec<u8> {
    build_header_only_response(request_id, false, ResponseCode::FormErr)
}

/// Builds an `rcode`-coded error response for `request_id`, using
/// `request`'s question/EDNS/CD context when available (RFC 6891 §6.1.1
/// requires an OPT record in response to any EDNS query; RFC 4035 §3.2.2
/// requires CD to be copied from query to response) and falling back to a
/// header-only response (keyed on `request_id`) only when no parsed
/// `request` could be recovered at all -- i.e. the packet's wire format
/// itself couldn't be parsed, so there's no question/OPT/CD to mirror.
/// Shared by every generic error-response builder that can be asked to
/// build any of several response codes for the same request shape (SERVFAIL
/// today, and protocol errors like FORMERR/NOTIMP).
pub fn build_question_aware_error_response(
    request: Option<&Message>,
    request_id: Option<u16>,
    rcode: ResponseCode,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    match request {
        Some(request) => {
            build_question_response(request, rcode, &[], configured_max_udp_payload_size)
        }
        None => build_header_only_response(request_id.unwrap_or(0), false, rcode),
    }
}

pub fn build_servfail_response(
    request: Option<&Message>,
    request_id: Option<u16>,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    build_question_aware_error_response(
        request,
        request_id,
        ResponseCode::ServFail,
        configured_max_udp_payload_size,
    )
}

pub fn build_refused_response(
    request: &Message,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    build_question_response(
        request,
        ResponseCode::Refused,
        &[],
        configured_max_udp_payload_size,
    )
}

pub fn build_nxdomain_response(
    request: &Message,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    build_question_response(
        request,
        ResponseCode::NxDomain,
        &[],
        configured_max_udp_payload_size,
    )
}

pub fn build_nodata_response(request: &Message, configured_max_udp_payload_size: usize) -> Vec<u8> {
    build_question_response(
        request,
        ResponseCode::NoError,
        &[],
        configured_max_udp_payload_size,
    )
}

/// Builds a BADVERS response (RFC 6891 §6.1.3: extended RCODE 16) for an
/// EDNS query advertising a version rdns doesn't support (rdns implements
/// version 0 only). The header's own RCODE nibble stays `NoError` (0) --
/// "16" only exists once that nibble and the OPT record's extended-RCODE
/// byte are combined, per §6.1.3's 12-bit extended-RCODE encoding -- and
/// the response OPT record advertises version 0, telling the client the
/// version rdns actually supports (RFC 6891 §6.1.3: "the version of EDNS
/// which the resolver supports"). Always carries an OPT record: this
/// response only ever exists because `request` had one --
/// `QueryValidationError::UnsupportedEdnsVersion` can't be produced by a
/// non-EDNS query in the first place. Doesn't reuse
/// `build_question_response` (used by every other generic error/policy
/// response) since that always zeroes the OPT's extended-RCODE byte.
pub fn build_badvers_response(
    request: &Message,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    let question_count = u16::from(!request.questions.is_empty());
    let dnssec_ok = request.edns.as_ref().is_some_and(|edns| edns.dnssec_ok);
    let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
    let opt = build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 1, Vec::new());

    write_message_header(
        &mut response,
        request.header.id,
        request.header.rd(),
        false, // truncated
        false, // synthetic local response, never authoritative
        false, // authenticated_data
        request.header.cd(),
        ResponseCode::NoError,
        question_count,
        0,
        0,
        1,
    );

    if let Some(question) = request.questions.first() {
        let mut compressor = NameCompressor::new();
        write_question(&mut response, &mut compressor, question);
    }
    write_opt_record(&mut response, &opt);

    response
}

pub fn build_a_block_response(
    request: &Message,
    ipv4: Ipv4Addr,
    ttl: u32,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    build_a_answers_response(request, &[ipv4], ttl, configured_max_udp_payload_size)
}

pub fn build_aaaa_block_response(
    request: &Message,
    ipv6: Ipv6Addr,
    ttl: u32,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    build_aaaa_answers_response(request, &[ipv6], ttl, configured_max_udp_payload_size)
}

pub fn build_a_answers_response(
    request: &Message,
    ipv4: &[Ipv4Addr],
    ttl: u32,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    let answers: Vec<_> = ipv4
        .iter()
        .copied()
        .map(|address| AddressAnswer::A { address, ttl })
        .collect();
    build_question_response(
        request,
        ResponseCode::NoError,
        &answers,
        configured_max_udp_payload_size,
    )
}

pub fn build_aaaa_answers_response(
    request: &Message,
    ipv6: &[Ipv6Addr],
    ttl: u32,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    let answers: Vec<_> = ipv6
        .iter()
        .copied()
        .map(|address| AddressAnswer::Aaaa { address, ttl })
        .collect();
    build_question_response(
        request,
        ResponseCode::NoError,
        &answers,
        configured_max_udp_payload_size,
    )
}

/// Builds a single-answer TXT response, echoing the question's own class
/// onto the answer record (CHAOS-class questions get a CHAOS-class
/// answer). Used for synthetic CHAOS-class replies (e.g. `version.bind.`)
/// -- unlike `build_a_answers_response`/`build_aaaa_answers_response`,
/// which go through `AddressAnswer`/`write_sinkhole_answer` since those
/// only ever answer in the question's IN class, this goes through the
/// generic `write_record` path because the answer class isn't fixed to IN.
pub fn build_txt_answer_response(
    request: &Message,
    text: &str,
    ttl: u32,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    let question_count = u16::from(!request.questions.is_empty());
    let opt = message_edns_opt_record(request, configured_max_udp_payload_size);
    write_message_header(
        &mut response,
        request.header.id,
        request.header.rd(),
        false,
        false, // synthetic local response, never authoritative
        false,
        request.header.cd(),
        ResponseCode::NoError,
        question_count,
        question_count,
        0,
        u16::from(opt.is_some()),
    );

    if let Some(question) = request.questions.first() {
        let mut compressor = NameCompressor::new();
        write_question(&mut response, &mut compressor, question);
        write_record(
            &mut response,
            &mut compressor,
            &question.qname,
            TXT_RECORD_TYPE,
            question.qclass,
            ttl,
            &RecordData::TXT(text.to_string()),
        );
    }
    if let Some(opt) = &opt {
        write_opt_record(&mut response, opt);
    }

    response
}

pub fn rewrite_response_id(response_bytes: &mut [u8], request_id: u16) -> Result<()> {
    if response_bytes.len() < 2 {
        return Err(DnsParseError::MessageTooShort);
    }
    response_bytes[0..2].copy_from_slice(&request_id.to_be_bytes());
    Ok(())
}

/// Rewrites a raw wire response's transaction ID, RD bit, and CD bit to
/// match `request`'s own — used when a shared/reused backend response
/// (e.g. a single-flight follower falling back to its leader's raw fetch
/// result) is being handed back to a requester whose own request fields may
/// differ from whatever request originally produced these bytes.
/// `MissKey` (`resolver::cache::singleflight`) coalesces on
/// name/type/class/namespace/DO only, not RD or CD, so both must be
/// rewritten here per requester rather than trusting the shared bytes'
/// own flags. Per RFC 4035 §3.2.2, a security-aware recursive name server
/// MUST copy the query's CD bit into the response, so leaving it as
/// whichever coalesced requester's fetch happened to set it would be a
/// spec violation for every other requester sharing that fetch.
pub fn rewrite_response_request_fields(response_bytes: &mut [u8], request: &Message) -> Result<()> {
    rewrite_response_id(response_bytes, request.header.id)?;
    if response_bytes.len() < 4 {
        return Err(DnsParseError::MessageTooShort);
    }

    let mut flags = u16::from_be_bytes([response_bytes[2], response_bytes[3]]);
    if request.header.rd() {
        flags |= 0x0100;
    } else {
        flags &= !0x0100;
    }
    if request.header.cd() {
        flags |= 0x0010;
    } else {
        flags &= !0x0010;
    }
    response_bytes[2..4].copy_from_slice(&flags.to_be_bytes());
    Ok(())
}

pub fn age_response_ttls(response_bytes: &mut [u8], age: Duration) -> Result<()> {
    let header = parse_header(response_bytes)?;
    let age_secs = age.as_secs().min(u64::from(u32::MAX)) as u32;
    let mut offset = DNS_HEADER_LEN;
    skip_questions(response_bytes, &mut offset, header.qd_count)?;
    adjust_record_ttls(response_bytes, &mut offset, header.an_count, age_secs, None)?;
    adjust_record_ttls(response_bytes, &mut offset, header.ns_count, age_secs, None)?;
    adjust_record_ttls(response_bytes, &mut offset, header.ar_count, age_secs, None)?;
    Ok(())
}

pub fn cap_response_ttls(response_bytes: &mut [u8], max_ttl: Duration) -> Result<()> {
    let header = parse_header(response_bytes)?;
    let max_ttl_secs = max_ttl.as_secs().min(u64::from(u32::MAX)) as u32;
    let mut offset = DNS_HEADER_LEN;
    skip_questions(response_bytes, &mut offset, header.qd_count)?;
    adjust_record_ttls(
        response_bytes,
        &mut offset,
        header.an_count,
        0,
        Some(max_ttl_secs),
    )?;
    adjust_record_ttls(
        response_bytes,
        &mut offset,
        header.ns_count,
        0,
        Some(max_ttl_secs),
    )?;
    adjust_record_ttls(
        response_bytes,
        &mut offset,
        header.ar_count,
        0,
        Some(max_ttl_secs),
    )?;
    Ok(())
}

pub fn question_wire(dns_message: &[u8]) -> Result<Bytes> {
    let range = question_wire_range(dns_message)?;
    Ok(Bytes::copy_from_slice(&dns_message[range]))
}

pub fn message_question_wire(message: &Message) -> Result<Bytes> {
    let range = question_wire_range(&message.original_bytes)?;
    Ok(message.original_bytes.slice(range))
}

fn question_wire_range(dns_message: &[u8]) -> Result<Range<usize>> {
    let header = parse_header(dns_message)?;
    if header.qd_count != 1 {
        return Err(DnsParseError::InvalidQuestionCount);
    }
    let mut offset = DNS_HEADER_LEN;
    let start = offset;
    skip_questions(dns_message, &mut offset, 1)?;
    Ok(start..offset)
}

pub fn first_question(dns_message: &[u8]) -> Result<Question> {
    let header = parse_header(dns_message)?;
    if header.qd_count != 1 {
        return Err(DnsParseError::InvalidQuestionCount);
    }
    let mut offset = DNS_HEADER_LEN;
    let mut context = ParseContext::default();
    parse_question(dns_message, &mut offset, &mut context)
}

pub fn encode_tcp_frame(message: &[u8], max_size: usize) -> Result<Vec<u8>> {
    validate_tcp_message_size(message.len(), max_size)?;
    let mut frame = Vec::with_capacity(message.len() + 2);
    write_u16(&mut frame, message.len() as u16);
    frame.extend_from_slice(message);
    Ok(frame)
}

pub fn decode_tcp_frame(frame: &[u8], max_size: usize) -> Result<TcpFrameDecodeStatus> {
    if frame.len() < 2 {
        return Ok(TcpFrameDecodeStatus::NeedMore {
            required_total_len: 2,
        });
    }

    let message_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    validate_tcp_message_size(message_len, max_size)?;
    let consumed_len = message_len + 2;
    if frame.len() < consumed_len {
        return Ok(TcpFrameDecodeStatus::NeedMore {
            required_total_len: consumed_len,
        });
    }

    Ok(TcpFrameDecodeStatus::Complete {
        message_len,
        required_total_len: consumed_len,
    })
}

pub fn tcp_frame_payload(frame: &[u8], max_size: usize) -> Result<Option<&[u8]>> {
    match decode_tcp_frame(frame, max_size)? {
        TcpFrameDecodeStatus::Complete {
            required_total_len, ..
        } => Ok(Some(&frame[2..required_total_len])),
        TcpFrameDecodeStatus::NeedMore { .. } => Ok(None),
    }
}

fn validate_tcp_message_size(size: usize, max_size: usize) -> Result<()> {
    if size > u16::MAX as usize || size > max_size {
        return Err(DnsParseError::TcpFrameTooLarge { size, max_size });
    }
    Ok(())
}

enum AddressAnswer {
    A { address: Ipv4Addr, ttl: u32 },
    Aaaa { address: Ipv6Addr, ttl: u32 },
}

fn build_header_only_response(
    request_id: u16,
    recursion_desired: bool,
    rcode: ResponseCode,
) -> Vec<u8> {
    let mut response = Vec::new();
    write_response_header(
        &mut response,
        request_id,
        recursion_desired,
        false,
        rcode,
        0,
        0,
    );
    response
}

/// Builds a header + question (+ optional answers) response for `request`,
/// used by every generic failure/policy-block builder in this module
/// (SERVFAIL, REFUSED, NXDOMAIN, NODATA, sinkhole A/AAAA answers). Per RFC
/// 6891 §6.1.1 a compliant responder MUST include an OPT record in any
/// response to a query that itself carried one, and per RFC 4035 §3.2.2 the
/// CD bit MUST be copied from query to response -- both are derived
/// directly from `request` (which already carries `edns` and `header.cd()`)
/// rather than threaded in separately, since every caller already has the
/// full request `Message` in hand. `configured_max_udp_payload_size` is
/// this responder's own UDP payload size (RFC 6891 §6.1.1: the OPT record
/// on a *response* describes the sender's -- i.e. this resolver's -- own
/// size, never an echo of the requester's advertised size).
fn build_question_response(
    request: &Message,
    rcode: ResponseCode,
    answers: &[AddressAnswer],
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    let mut response = Vec::new();
    let question_count = u16::from(!request.questions.is_empty());
    let opt = message_edns_opt_record(request, configured_max_udp_payload_size);
    write_message_header(
        &mut response,
        request.header.id,
        request.header.rd(),
        false,
        false, // synthetic local response, never authoritative
        false,
        request.header.cd(),
        rcode,
        question_count,
        answers.len() as u16,
        0,
        u16::from(opt.is_some()),
    );

    if let Some(question) = request.questions.first() {
        let mut compressor = NameCompressor::new();
        write_question(&mut response, &mut compressor, question);
        for answer in answers {
            write_sinkhole_answer(&mut response, &mut compressor, question, answer);
        }
    }
    if let Some(opt) = &opt {
        write_opt_record(&mut response, opt);
    }

    response
}

fn write_response_header(
    out: &mut Vec<u8>,
    id: u16,
    recursion_desired: bool,
    truncated: bool,
    rcode: ResponseCode,
    question_count: u16,
    answer_count: u16,
) {
    write_u16(out, id);
    let mut flags = 0x8000;
    if recursion_desired {
        flags |= 0x0100;
    }
    if truncated {
        flags |= 0x0200;
    }
    flags |= 0x0080;
    flags |= rcode.as_u8() as u16;
    write_u16(out, flags);
    write_u16(out, question_count);
    write_u16(out, answer_count);
    write_u16(out, 0);
    write_u16(out, 0);
}

fn write_question(out: &mut Vec<u8>, compressor: &mut NameCompressor, question: &Question) {
    compressor.write_name(out, &question.qname);
    write_u16(out, question.qtype);
    write_u16(out, question.qclass);
}

fn write_sinkhole_answer(
    out: &mut Vec<u8>,
    compressor: &mut NameCompressor,
    question: &Question,
    answer: &AddressAnswer,
) {
    match answer {
        AddressAnswer::A { address, ttl } => {
            compressor.write_name(out, &question.qname);
            write_u16(out, 1);
            write_u16(out, question.qclass);
            write_u32(out, *ttl);
            write_u16(out, 4);
            out.extend_from_slice(&address.octets());
        }
        AddressAnswer::Aaaa { address, ttl } => {
            compressor.write_name(out, &question.qname);
            write_u16(out, 28);
            write_u16(out, question.qclass);
            write_u32(out, *ttl);
            write_u16(out, 16);
            out.extend_from_slice(&address.octets());
        }
    }
}

/// Writes DNS domain names using compression pointers (RFC 1035 §4.1.4):
/// a name that repeats a suffix already written earlier in the same message
/// is replaced with a 2-byte pointer back to that earlier occurrence.
pub(crate) struct NameCompressor {
    offsets: HashMap<String, u16>,
}

impl NameCompressor {
    pub(crate) fn new() -> Self {
        Self {
            offsets: HashMap::new(),
        }
    }

    pub(crate) fn write_name(&mut self, out: &mut Vec<u8>, name: &str) {
        let name = name.trim_end_matches('.');
        if name.is_empty() {
            out.push(0);
            return;
        }
        // Lowercase once and slice suffixes out of it by byte offset, rather
        // than rejoining + relowercasing the remaining labels on every
        // iteration (which was O(n^2) in label count).
        let lower = name.to_ascii_lowercase();
        let mut offset = 0usize;
        while offset < name.len() {
            let label_end = name[offset..]
                .find('.')
                .map(|i| offset + i)
                .unwrap_or(name.len());
            let label = &name[offset..label_end];
            let suffix = &lower[offset..];
            if let Some(&ptr) = self.offsets.get(suffix) {
                out.extend_from_slice(&(0xC000u16 | ptr).to_be_bytes());
                return;
            }
            if out.len() <= 0x3FFF {
                self.offsets.insert(suffix.to_string(), out.len() as u16);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
            offset = label_end + 1;
        }
        out.push(0);
    }
}

pub(crate) fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Writes a DNS message header with full control over every section count
/// and the AD bit — unlike `write_response_header` (which always zeroes
/// the authority/additional counts and never sets AD), this is used by
/// `resolver::cache::assemble` (section-06) to build responses carrying an
/// authority-section SOA (negative results) and/or an AD bit computed from
/// DNSSEC validation state.
///
/// `checking_disabled` copies the query's CD bit onto the response, per
/// RFC 4035 §3.2.2 ("a security-aware recursive name server MUST copy the
/// CD bit from a query to the corresponding response").
///
/// `authoritative` sets the AA bit — it must reflect the *original backend
/// response's* own AA bit (see `RRsetEntry::authoritative`/
/// `NegativeEntry::authoritative`) whenever this header is describing a
/// cached copy of that answer; it is not something this resolver can claim
/// on its own behalf. `RA` (recursion available) stays hardcoded true,
/// since this resolver always performs recursion.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_message_header(
    out: &mut Vec<u8>,
    id: u16,
    recursion_desired: bool,
    truncated: bool,
    authoritative: bool,
    authenticated_data: bool,
    checking_disabled: bool,
    rcode: ResponseCode,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
) {
    write_u16(out, id);
    let mut flags = 0x8000; // QR = 1 (response)
    if recursion_desired {
        flags |= 0x0100;
    }
    if truncated {
        flags |= 0x0200;
    }
    if authoritative {
        flags |= 0x0400; // AA
    }
    flags |= 0x0080; // RA = 1
    if authenticated_data {
        flags |= 0x0020;
    }
    if checking_disabled {
        flags |= 0x0010;
    }
    flags |= rcode.as_u8() as u16;
    write_u16(out, flags);
    write_u16(out, question_count);
    write_u16(out, answer_count);
    write_u16(out, authority_count);
    write_u16(out, additional_count);
}

/// Builds a truncated (TC=1) response: header + question + a mirrored OPT
/// record (when `opt` is `Some`), no answer/authority section and no other
/// additional records. Per RFC 6891 §7, a compliant truncated response to
/// an EDNS requester must still carry the question and a responder OPT
/// record; per RFC 4035 §3.2.2, CD must still be copied.
///
/// Shared by `resolver::cache::assemble::finish_with_truncation_check`
/// (`QueryFeatures`-sourced, cache-hit serve time) and
/// `resolver::truncated_response_for_query` (`Message`-sourced, recursive
/// backend miss and local-entry paths) so both truncation call sites build
/// from the same primitives (`write_message_header` + `write_opt_record`)
/// and can't drift out of RFC compliance independently of each other again.
///
/// `authoritative` is threaded straight to `write_message_header`'s AA bit
/// — see that function's doc comment for the contract.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_truncated_wire_response(
    request_id: u16,
    recursion_desired: bool,
    authoritative: bool,
    checking_disabled: bool,
    response_code: ResponseCode,
    question_wire: &[u8],
    opt: Option<&Record>,
) -> Vec<u8> {
    let mut response = Vec::new();
    write_message_header(
        &mut response,
        request_id,
        recursion_desired,
        true,
        authoritative,
        false,
        checking_disabled,
        response_code,
        1,
        0,
        0,
        u16::from(opt.is_some()),
    );
    response.extend_from_slice(question_wire);
    if let Some(opt) = opt {
        write_opt_record(&mut response, opt);
    }
    response
}

fn write_name_uncompressed(out: &mut Vec<u8>, name: &str) {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return;
    }
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            hex.get(i..i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect()
}

/// Builds a per-transaction OPT record mirroring a requester's own EDNS
/// UDP payload size and DO flag, with the extended RCODE/version zeroed
/// and no options — used to echo a requester's EDNS presence back onto a
/// response. Per RFC 6891 §6.1.1, a compliant responder MUST include an
/// OPT record in any response to a query that itself carried one; per
/// RFC 6891 §7, even a minimal truncated response must still carry
/// header + question + OPT.
///
/// Shared by `resolver::mirrored_client_opt_record` (sourced from a
/// parsed `Message`, used on the recursive-miss path) and
/// `resolver::cache::assemble` (sourced from `QueryFeatures`, which has no
/// `Message` to read from at cache-hit serve time) so both build the exact
/// same OPT shape rather than duplicating this construction.
pub(crate) fn build_opt_record(udp_payload_size: u16, dnssec_ok: bool) -> Record {
    build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 0, Vec::new())
}

/// `build_opt_record`, with a pre-built `options` TLV byte vector (e.g. a
/// COOKIE option from `crate::protocol::edns_cookie::build_cookie_option`)
/// attached to the OPT record's RDATA instead of always building an
/// options-less OPT. Used by `message_edns_opt_record_with_cookie` (backing
/// `resolver::mirrored_client_opt_record_with_cookie`, the cache-miss/
/// recursive path) once a client cookie needs echoing back to the
/// requester there -- `resolver::cache::assemble::requester_opt_record`
/// (cache-hit path) attaches a cookie by building via `build_opt_record`
/// and mutating the resulting `EdnsInfo.options` field in place instead.
pub(crate) fn build_opt_record_with_options(
    udp_payload_size: u16,
    dnssec_ok: bool,
    options: Vec<u8>,
) -> Record {
    build_opt_record_with_extended_rcode(udp_payload_size, dnssec_ok, 0, options)
}

/// `build_opt_record`, with an explicit extended-RCODE byte (the upper 8
/// bits of the 12-bit extended RCODE; the header's own 4-bit RCODE field
/// carries the rest -- RFC 6891 §6.1.3) instead of always zeroing it.
/// Exists only for `build_badvers_response`, which needs extended RCODE 1
/// (BADVERS's upper byte) on its OPT record; every other response is a
/// plain success/error code that fits entirely in the header's RCODE
/// field, so `build_opt_record` keeps zeroing it by default.
fn build_opt_record_with_extended_rcode(
    udp_payload_size: u16,
    dnssec_ok: bool,
    extended_rcode: u8,
    options: Vec<u8>,
) -> Record {
    let flags = if dnssec_ok { EDNS_DO_FLAG } else { 0 };
    let ttl = (u32::from(extended_rcode) << 24) | u32::from(flags);
    Record {
        name: String::new(),
        rtype: OPT_RECORD_TYPE,
        rclass: udp_payload_size,
        ttl,
        record: RecordData::OPT(EdnsInfo {
            udp_payload_size,
            extended_rcode,
            version: 0,
            flags,
            dnssec_ok,
            options,
        }),
    }
}

/// `build_opt_record`, sourced from a parsed request `Message` rather than
/// raw `(udp_payload_size, dnssec_ok)` values -- `None` if `message` carried
/// no EDNS OPT record at all. Shared by every response builder in this
/// module that has a `&Message` in hand (`build_question_response`) and by
/// `resolver::mirrored_client_opt_record` (which delegates here), so the
/// "does this message have EDNS, and if so what does its OPT look like"
/// logic exists exactly once regardless of which side of the
/// protocol/resolver boundary is asking.
///
/// `responder_udp_payload_size` is *this resolver's own* configured/effective
/// UDP payload size, not `message`'s. Per RFC 6891 §6.1.1 the UDP payload
/// size field in an OPT RR is sender-specific: on a query it's the
/// requester's own advertised size, but on a *response* -- which is all this
/// function ever builds an OPT record for -- it must describe the
/// responder's own size. Only EDNS *presence* (whether to emit an OPT record
/// at all) and the DO flag are derived from `message`.
pub(crate) fn message_edns_opt_record(
    message: &Message,
    responder_udp_payload_size: usize,
) -> Option<Record> {
    let edns = message.edns.as_ref()?;
    let udp_payload_size = responder_udp_payload_size.min(u16::MAX as usize) as u16;
    Some(build_opt_record(udp_payload_size, edns.dnssec_ok))
}

/// `message_edns_opt_record`, plus RFC 9018 server-cookie construction: if
/// `message`'s EDNS options carry a well-formed RFC 7873 client cookie
/// (`edns_cookie::parse_cookie_option`), the returned OPT record's options
/// carry a freshly-built COOKIE option (`edns_cookie::build_server_cookie` +
/// `build_cookie_option`) echoing that client cookie back with a fresh
/// server cookie, instead of the options-less OPT `message_edns_opt_record`
/// always builds.
///
/// A separate function rather than widening `message_edns_opt_record`
/// in place: that function also backs `build_question_response` and
/// `build_txt_answer_response` (the statically-configured local-entry
/// response path), which section 05 of the EDNS-cookie plan explicitly
/// leaves untouched. Used by `resolver::mirrored_client_opt_record_with_cookie`
/// on the cache-miss/recursive path, mirroring
/// `resolver::cache::assemble::requester_opt_record` on the cache-hit path.
pub(crate) fn message_edns_opt_record_with_cookie(
    message: &Message,
    responder_udp_payload_size: usize,
    cookie_secret: &edns_cookie::CookieSecret,
    client_ip: std::net::IpAddr,
    now: std::time::SystemTime,
) -> Option<Record> {
    let edns = message.edns.as_ref()?;
    let udp_payload_size = responder_udp_payload_size.min(u16::MAX as usize) as u16;
    match edns_cookie::parse_cookie_option(&edns.options) {
        Some(client_cookie) => {
            let server_cookie =
                edns_cookie::build_server_cookie(cookie_secret, client_cookie, client_ip, now);
            let options = edns_cookie::build_cookie_option(client_cookie, server_cookie);
            Some(build_opt_record_with_options(
                udp_payload_size,
                edns.dnssec_ok,
                options,
            ))
        }
        None => Some(build_opt_record(udp_payload_size, edns.dnssec_ok)),
    }
}

/// Encodes one arbitrary resource record to wire bytes: owner name, type,
/// class, TTL, then a length-prefixed RDATA block sized to whatever
/// `rdata` actually needs. Mirrors `parse_record_data`'s match arms in
/// reverse — every `RecordData` variant that can be parsed can be written
/// back out here. Used by `resolver::cache::assemble` (section-06) to
/// serialize cached record sets fresh, per request, instead of replaying a
/// stored byte template.
///
/// Domain names in legacy RDATA fields (CNAME/NS/PTR targets, MX exchange,
/// SRV target, SOA mname/rname, RP names) are written through `compressor`
/// like any owner name — this is standard practice and always valid.
/// `RRSIG.signer_name` and `NSEC.next_domain` are written uncompressed
/// instead, per RFC 4034 §6.2's canonical-form requirement for
/// DNSSEC-relevant names.
pub(crate) fn write_record(
    out: &mut Vec<u8>,
    compressor: &mut NameCompressor,
    name: &str,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: &RecordData,
) {
    compressor.write_name(out, name);
    write_u16(out, rtype);
    write_u16(out, rclass);
    write_u32(out, ttl);
    let rdlength_pos = out.len();
    write_u16(out, 0);
    let rdata_start = out.len();
    write_rdata(out, compressor, rdata);
    let rdlength = (out.len() - rdata_start) as u16;
    out[rdlength_pos..rdlength_pos + 2].copy_from_slice(&rdlength.to_be_bytes());
}

/// Writes a single OPT record (owner name always root, so a fresh,
/// single-use compressor is fine -- there is nothing for it to compress
/// against or be compressed by). Shared by every response builder that
/// appends a mirrored/requester OPT record, so the "OPT records use their
/// own throwaway compressor" detail exists exactly once.
pub(crate) fn write_opt_record(out: &mut Vec<u8>, opt: &Record) {
    let mut compressor = NameCompressor::new();
    write_record(
        out,
        &mut compressor,
        &opt.name,
        opt.rtype,
        opt.rclass,
        opt.ttl,
        &opt.record,
    );
}

fn write_rdata(out: &mut Vec<u8>, compressor: &mut NameCompressor, rdata: &RecordData) {
    match rdata {
        RecordData::A(address) => out.extend_from_slice(&address.octets()),
        RecordData::AAAA(address) => out.extend_from_slice(&address.octets()),
        RecordData::CAA { flags, tag, value } => {
            out.push(*flags);
            out.push(tag.len() as u8);
            out.extend_from_slice(tag.as_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        RecordData::MX {
            preference,
            exchange,
        } => {
            write_u16(out, *preference);
            compressor.write_name(out, exchange);
        }
        RecordData::CERT {
            cert_type,
            key_tag,
            algorithm,
            cert,
        } => {
            write_u16(out, *cert_type);
            write_u16(out, *key_tag);
            out.push(*algorithm);
            out.extend_from_slice(cert);
        }
        RecordData::CNAME(target) => compressor.write_name(out, target),
        RecordData::DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
        } => {
            write_u16(out, *flags);
            out.push(*protocol);
            out.push(*algorithm);
            out.extend_from_slice(public_key);
        }
        RecordData::DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => {
            write_u16(out, *key_tag);
            out.push(*algorithm);
            out.push(*digest_type);
            out.extend_from_slice(digest);
        }
        RecordData::NSEC {
            next_domain,
            type_bit_maps,
        } => {
            write_name_uncompressed(out, next_domain);
            out.extend_from_slice(type_bit_maps);
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
            out.push(*hash_algorithm);
            out.push(*flags);
            write_u16(out, *iterations);
            out.push(*salt_length);
            out.extend_from_slice(salt);
            out.push(*hash_length);
            out.extend_from_slice(&from_hex(next_domain));
            out.extend_from_slice(type_bit_maps);
        }
        RecordData::NSEC3PARAM {
            hash_algorithm,
            flags,
            iterations,
            salt_length,
            salt,
        } => {
            out.push(*hash_algorithm);
            out.push(*flags);
            write_u16(out, *iterations);
            out.push(*salt_length);
            out.extend_from_slice(salt);
        }
        RecordData::NS(name) => compressor.write_name(out, name),
        RecordData::PTR(name) => compressor.write_name(out, name),
        RecordData::RP {
            mboxdname,
            txtdname,
        } => {
            compressor.write_name(out, mboxdname);
            compressor.write_name(out, txtdname);
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
            write_u16(out, *type_covered);
            out.push(*algorithm);
            out.push(*labels);
            write_u32(out, *original_ttl);
            write_u32(out, *signature_expiration);
            write_u32(out, *signature_inception);
            write_u16(out, *key_tag);
            write_name_uncompressed(out, signer_name);
            out.extend_from_slice(signature);
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
            compressor.write_name(out, mname);
            compressor.write_name(out, rname);
            write_u32(out, *serial);
            write_u32(out, *refresh);
            write_u32(out, *retry);
            write_u32(out, *expire);
            write_u32(out, *minimum);
        }
        RecordData::SRV {
            priority,
            weight,
            port,
            target,
        } => {
            write_u16(out, *priority);
            write_u16(out, *weight);
            write_u16(out, *port);
            compressor.write_name(out, target);
        }
        RecordData::TXT(text) => {
            if text.is_empty() {
                return;
            }
            for chunk in text.as_bytes().chunks(255) {
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        RecordData::OPT(info) => out.extend_from_slice(&info.options),
        RecordData::Unknown { rtype: _, bytes } => out.extend_from_slice(bytes),
    }
}

/// Bound on the header-declared `an_count`/`ns_count`/`ar_count`
/// `recover_query_context` is willing to trust before walking the packet
/// body: those counts are, by definition, already untrusted at the point
/// this is called (the header failed `validate_standard_query_header`),
/// so nothing bounds them but the packet's actual length. Generous enough
/// to cover the recoverable-but-malformed shapes this exists for (a
/// duplicate-OPT query needs `ar_count == 2`), while keeping the total
/// parse-and-allocate work here a small constant instead of proportional
/// to an attacker-chosen count.
const RECOVERY_MAX_SECTION_RECORDS: u16 = 4;

/// Bound on the number of *extra* questions (beyond the first, which is
/// the only one ever kept -- see `recover_query_context`) recovery is
/// willing to skip past in order to reach the answer section when
/// `qd_count > 1`. Without skipping those, EDNS recovery would start
/// scanning from right after the first question instead of the start of
/// the answer section, and scan into leftover question bytes for a
/// multi-question query instead of the answer/authority/additional
/// sections -- silently losing OPT/CD recovery for an otherwise
/// recoverable shape. Reuses `RECOVERY_MAX_SECTION_RECORDS`'s value: the
/// risk is the same attacker-controlled-count-turned-into-unbounded-work
/// shape, just for `qd_count` instead of `an_count`/`ns_count`/`ar_count`.
const RECOVERY_MAX_EXTRA_QUESTIONS: u16 = RECOVERY_MAX_SECTION_RECORDS;

/// Bounded, best-effort recovery of the question/CD/EDNS context needed to
/// build a compliant protocol-error response (RFC 6891 §6.1.1's mandatory
/// responder OPT record, RFC 4035 §3.2.2's CD echo) after
/// `validate_standard_query_header` has already rejected `dns_message`.
/// `header` itself is always usable (parsing it is what let the caller
/// reach this point), so the returned `Message` always at least carries
/// `header`'s id/flags -- including CD -- even when nothing past the
/// header can be recovered.
///
/// Deliberately does not fall back to the general `Self::parse`, for two
/// reasons:
///
///   - Cost: `Self::parse` would walk and allocate every answer/authority/
///     additional record using the header's own counts -- which, again,
///     are untrusted here. Before recovery existed, a
///     `validate_standard_query_header` failure bailed out after the
///     12-byte header check alone; naively reusing `Self::parse` for
///     recovery reintroduced that cost on every malformed packet reaching
///     this branch, turning a crafted large `an_count`/`ns_count`/
///     `ar_count` into a flood/amplification lever. This function bounds
///     the *number* of records/questions walked to at most
///     `RECOVERY_MAX_SECTION_RECORDS` per section and at most
///     `RECOVERY_MAX_EXTRA_QUESTIONS` extra questions, regardless of what
///     the header claims -- if any of those counts exceeds its bound, the
///     corresponding sections (and, since additionals can't be safely
///     located without first walking past the questions/answers/
///     authorities, EDNS) are skipped rather than walked, but the
///     recovered question and header (id/flags/CD) are still returned.
///     Just bounding the record *count* isn't enough on its own, though --
///     see `recovery_skip_record`'s docs for why the per-record work also
///     has to avoid the general `parse_record_data` path.
///   - Strictness: `Self::parse` rejects (via `extract_edns_info`) a
///     query with more than one OPT record, which is correct for the
///     primary decode path but means a duplicate-OPT query -- itself a
///     distinct FORMERR condition (RFC 6891 §6.1.1), yet one with a
///     perfectly parseable header and question -- recovered nothing at
///     all, losing both the mandatory responder OPT and the CD echo. This
///     function tolerates extra OPT records by using only the first one
///     found.
fn recover_query_context(dns_message: Bytes, header: &Header) -> Message {
    let mut context = ParseContext::default();
    let mut offset = DNS_HEADER_LEN;

    // At most one question is ever useful for an error response, so keep
    // at most one regardless of how many the (untrusted) header claims --
    // this bounds the cost of *keeping* a question without needing a cap
    // on `qd_count`'s value.
    let question = if header.qd_count >= 1 {
        parse_question(&dns_message, &mut offset, &mut context).ok()
    } else {
        None
    };

    // Keeping only the first question above still leaves `offset` right
    // after it -- for a malformed multi-question query (`qd_count > 1`,
    // itself a distinct FORMERR condition), the remaining declared
    // questions sit between `offset` and the start of the answer section.
    // Skip over those (bounded, since `qd_count` is attacker-controlled)
    // before scanning for EDNS context, or recovery would scan the
    // leftover question bytes instead of the answer/authority/additional
    // sections and never find a real OPT record. Any other case (no
    // question recovered, or exactly one declared) leaves `offset`
    // already correctly positioned, so defaults to proceeding.
    let positioned_for_edns_scan = if question.is_some() && header.qd_count > 1 {
        header.qd_count <= 1 + RECOVERY_MAX_EXTRA_QUESTIONS
            && skip_questions(&dns_message, &mut offset, header.qd_count - 1).is_ok()
    } else {
        true
    };

    let edns = if positioned_for_edns_scan
        && header.an_count <= RECOVERY_MAX_SECTION_RECORDS
        && header.ns_count <= RECOVERY_MAX_SECTION_RECORDS
        && header.ar_count <= RECOVERY_MAX_SECTION_RECORDS
    {
        recover_edns_info(&dns_message, offset, header)
    } else {
        None
    };

    Message::from_parts(
        dns_message,
        MessageParts {
            header: *header,
            questions: question.into_iter().collect(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns,
        },
    )
}

/// Walks the (bounded, per `recover_query_context`) answer and authority
/// sections without materializing their records, then scans the additional
/// section for the first OPT record, tolerating -- and simply ignoring --
/// a second one rather than treating it as a hard parse failure the way
/// `extract_edns_info` correctly does on the primary parse path.
///
/// Unlike the primary parse path, this never calls `parse_record_data`:
/// a record count bound (`RECOVERY_MAX_SECTION_RECORDS`) only bounds the
/// *number* of records walked, not their size, so a crafted packet with a
/// low `an_count`/`ns_count`/`ar_count` but one or two records carrying a
/// large RDATA blob (an unknown/DNSSEC/binary type near the message size
/// limit) would still force a full parse-and-allocate -- including a
/// `to_vec()` copy of the blob for `RecordData::Unknown` and similar --
/// on what's supposed to be a cheap reject-early path for a protocol
/// error. `recovery_skip_record` reads only each record's fixed-size
/// header (name/type/class/ttl/rdlength) and jumps over `rdlength` bytes
/// of RDATA without copying it, so per-record cost is a small constant
/// regardless of RDATA size; only when a record's type is OPT does this
/// extract the small, fixed-size OPT metadata (payload size, extended
/// rcode/version, flags/DO bit) -- never the OPT's own RDATA (its
/// options), which aren't needed to answer "is there EDNS, and what does
/// it say" for recovery purposes.
fn recover_edns_info(dns_message: &[u8], mut offset: usize, header: &Header) -> Option<EdnsInfo> {
    recovery_skip_records(dns_message, &mut offset, header.an_count).ok()?;
    recovery_skip_records(dns_message, &mut offset, header.ns_count).ok()?;
    recovery_find_opt_in_additionals(dns_message, &mut offset, header.ar_count).ok()?
}

/// Advances `offset` past `count` resource records without materializing
/// any of them -- see `recover_edns_info`'s docs for why this exists
/// instead of `parse_records`.
fn recovery_skip_records(dns_message: &[u8], offset: &mut usize, count: u16) -> Result<()> {
    for _ in 0..count {
        recovery_skip_record(dns_message, offset)?;
    }
    Ok(())
}

/// Advances `offset` past a single resource record's name, fixed-size
/// type/class/ttl/rdlength header, and `rdlength` bytes of RDATA, without
/// ever materializing a `RecordData` or copying the RDATA bytes. Bounds
/// checks the RDATA region against the buffer length so a truncated
/// packet is still reported as an error rather than silently under- or
/// over-skipping.
fn recovery_skip_record(dns_message: &[u8], offset: &mut usize) -> Result<()> {
    parse_domain_with_context(dns_message, offset, None)?;
    let mut reader = Reader::new(dns_message, *offset)?;
    reader.read_u16()?; // rtype
    reader.read_u16()?; // rclass
    reader.read_u32()?; // ttl
    let rdlength = reader.read_u16()? as usize;
    let rdata_offset = reader.position();
    let rdata_end = rdata_offset
        .checked_add(rdlength)
        .ok_or(DnsParseError::MalformedRecord)?;
    dns_message
        .get(rdata_offset..rdata_end)
        .ok_or(DnsParseError::UnexpectedEof)?;
    *offset = rdata_end;
    Ok(())
}

/// Returns whether `owner_start` -- the offset a record's owner name began
/// at, captured *before* the name was decoded -- is the canonical,
/// unambiguous root-domain owner-name encoding RFC 6891 §6.1.2 requires of
/// an OPT record: a single literal `0x00` root-label-length byte, never a
/// compression pointer, even one that would legitimately (per a real
/// `ParseContext`) decode to an empty name. Real OPT records are always
/// emitted with the direct, uncompressed root byte; accepting a compressed
/// encoding that merely *resolves* to empty would be a spec deviation and
/// would let this parser and any other OPT-owner check in the file
/// silently disagree about what counts as a valid OPT owner. Shared by
/// every place that needs this check -- `parse_record` (the primary,
/// general-purpose parser), `recovery_additional_is_opt` (the cheap
/// precheck), and `recovery_find_opt_in_additionals` (the recovery
/// scanner) -- so canonical-OPT-ownership detection can't drift apart
/// across them again.
fn is_canonical_root_owner(dns_message: &[u8], owner_start: usize) -> bool {
    dns_message.get(owner_start) == Some(&0)
}

/// Bounds the number of compression-pointer redirects
/// `skip_name_offset_only` will follow before reporting a pointer loop.
/// Pointing strictly backward from each pointer's own position (the same
/// check `decode_compression_pointer` enforces) doesn't by itself rule out
/// a cycle: label-walking is allowed to move the cursor forward past a
/// previously-followed pointer's address, so a crafted `pointer -> label
/// run -> pointer back to the same target` shape can still loop forever
/// (e.g. offsets `[0]=05 'A' 'A' 'A' 'A' 'A'` then `[6]=0xC0 0x00`: landing
/// on offset 6 jumps to offset 0, whose 5-byte label walks the cursor
/// right back to offset 6). A real name chains through at most a handful
/// of pointers, so a small hop cap catches that shape in bounded work
/// without `parse_domain_with_context`'s `HashSet`-based visited-offset
/// tracking.
const MAX_POINTER_HOPS: usize = 128;

/// Advances `offset` past a single DNS name -- the same span
/// `parse_domain_with_context` would consume -- without decoding any
/// label into a `String`, collecting labels into a `Vec`, or allocating a
/// `HashSet` for compression-pointer-loop tracking. Used by
/// `recovery_additional_is_opt` specifically: that precheck only needs to
/// advance past the question to reach the additional section, never the
/// decoded qname itself, and paying `parse_domain_with_context`'s
/// allocation cost here was pure waste -- `Self::parse_owned` parses the
/// exact same question again immediately afterward on the (overwhelmingly
/// common) path where the precheck passes.
///
/// This still follows compression pointers -- a compressed question name
/// is legal, if unusual -- but bounds the number of redirects it will
/// follow (`MAX_POINTER_HOPS`) instead of tracking every visited offset.
/// That's enough to guarantee termination (see `MAX_POINTER_HOPS`'s docs
/// for why a bare backward-pointing check isn't already enough on its
/// own) without the allocation. This is intentionally *not* a general
/// replacement for `parse_domain_with_context`: it doesn't validate
/// pointers against a `ParseContext` of legitimate prior name occurrences
/// (callers that need that keep using the full parser), and a chain of
/// more than `MAX_POINTER_HOPS` redirects is reported as `PointerLoop`
/// even in the (purely theoretical -- no real resolver emits this) case
/// where it would eventually have terminated on its own.
fn skip_name_offset_only(dns_message: &[u8], offset: &mut usize) -> Result<()> {
    let mut cursor = *offset;
    let mut hops = 0usize;
    let mut consumed_offset = None;
    // Mirrors `parse_domain_with_context`'s cumulative wire-format length
    // accounting exactly (same starting value, same per-label
    // `length + 1` increment, same `MAX_NAME_LEN` bound, and -- like that
    // parser -- never incremented on a compression-pointer hop). Without
    // this, an overlong name could be walked past by this cheap precheck
    // even though the authoritative full parser would reject it as
    // exceeding RFC 1035 §3.1's 255-byte limit, letting the precheck
    // consume more attacker-controlled bytes than the real parser allows.
    let mut wire_len = 1usize;

    loop {
        let length_octet = *dns_message
            .get(cursor)
            .ok_or(DnsParseError::UnexpectedEof)?;
        match length_octet & 0b1100_0000 {
            0b0000_0000 => {
                let length = length_octet as usize;
                cursor += 1;
                if length == 0 {
                    if consumed_offset.is_none() {
                        consumed_offset = Some(cursor);
                    }
                    break;
                }
                if length > MAX_LABEL_LEN {
                    return Err(DnsParseError::InvalidLabel);
                }
                let label_end = cursor
                    .checked_add(length)
                    .ok_or(DnsParseError::UnexpectedEof)?;
                if label_end > dns_message.len() {
                    return Err(DnsParseError::UnexpectedEof);
                }
                wire_len = wire_len
                    .checked_add(length + 1)
                    .ok_or(DnsParseError::InvalidLabel)?;
                if wire_len > MAX_NAME_LEN {
                    return Err(DnsParseError::InvalidLabel);
                }
                cursor = label_end;
            }
            0b1100_0000 => {
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return Err(DnsParseError::PointerLoop);
                }
                let pointer_offset =
                    decode_compression_pointer(dns_message, cursor, length_octet, None)?;
                if consumed_offset.is_none() {
                    consumed_offset = Some(cursor + 2);
                }
                cursor = pointer_offset;
            }
            _ => return Err(DnsParseError::InvalidLabel),
        }
    }

    *offset = consumed_offset.ok_or(DnsParseError::UnexpectedEof)?;
    Ok(())
}

/// Advances `offset` past `question_count` questions' names and their
/// fixed 4-byte qtype+qclass fields -- the same shape `skip_questions`
/// walks -- but using `skip_name_offset_only` instead of
/// `parse_domain_with_context` for the name portion, so this doesn't
/// allocate. Only used by `recovery_additional_is_opt`'s cheap precheck
/// below; `skip_questions` itself is untouched and every other call site
/// (e.g. the multi-question-skip recovery path) keeps using the full,
/// general-purpose domain parser.
fn recovery_skip_questions_offset_only(
    dns_message: &[u8],
    offset: &mut usize,
    question_count: u16,
) -> Result<()> {
    for _ in 0..question_count {
        skip_name_offset_only(dns_message, offset)?;
        let mut reader = Reader::new(dns_message, *offset)?;
        reader.read_u16()?; // qtype
        reader.read_u16()?; // qclass
        *offset = reader.position();
    }
    Ok(())
}

/// Cheaply determines whether a standard query's single declared
/// additional record (`header.ar_count == 1`, the only nonzero shape
/// `validate_standard_query_body` accepts) is a validly-owned OPT record,
/// without ever materializing the record's RDATA -- see
/// `parse_standard_query_owned_with_recovery`'s call site for why this
/// exists: `validate_standard_query_header` only checks `ar_count <= 1`,
/// not what that one record's *type* is, so a query with a large,
/// non-OPT additional record in that slot passes header validation and
/// would otherwise fall through to the full `Self::parse_owned` ->
/// `parse_record_data` path -- fully materializing (including a
/// `to_vec()` copy for unknown-type RDATA) a record `validate_standard_query_body`
/// was always going to reject once discovered not to be OPT. This reads
/// only the record's owner name and fixed-size type field, the same
/// lightweight, non-allocating technique `recovery_skip_record` uses, and
/// stops there -- it doesn't need `rdlength` or the RDATA bounds check
/// since the caller only needs a type answer, not a fully skipped record.
///
/// Also requires the owner name to be the canonical root encoding (see
/// `is_canonical_root_owner`), not merely a name that decodes to empty via
/// a compression pointer -- a record with `rtype == OPT_RECORD_TYPE` but a
/// non-canonical owner is treated the same as a non-OPT additional here
/// (`Ok(false)`), so it's rejected by this cheap precheck instead of
/// falling through to the full parse, consistent with how a non-OPT
/// additional is already handled.
///
/// Only called after `validate_standard_query_header` has already
/// confirmed `qd_count == 1`, `an_count == 0`, and `ns_count == 0`, so
/// this only needs to skip exactly one question to reach the additional
/// record. `header.ar_count == 1` is not a rare/malformed shape -- it's
/// the normal wire shape of *every* EDNS query, since a standard EDNS
/// request has exactly one additional record (the OPT pseudo-record) --
/// so this precheck runs on essentially every EDNS query the server sees,
/// not just the rare malformed one it was built to reject cheaply. That's
/// why the question-skip step here uses `skip_name_offset_only` /
/// `recovery_skip_questions_offset_only` instead of `skip_questions`, and
/// why the additional record's own owner name is never run through
/// `parse_domain_with_context` either: unlike the truly-rare recovery
/// paths elsewhere in this file, this one needed to be allocation-free on
/// the common case, not just bounded. The owner-name step below fast-paths
/// the canonical single-byte root encoding (the shape every real OPT
/// record's owner uses) without any name-parsing at all, and falls back to
/// the allocation-free `skip_name_offset_only` -- never the allocating
/// `parse_domain_with_context` -- for the rare non-root-owner shape, since
/// that branch only needs to know where the name ends, not decode it.
fn recovery_additional_is_opt(dns_message: &[u8], header: &Header) -> Result<bool> {
    let mut offset = DNS_HEADER_LEN;
    recovery_skip_questions_offset_only(dns_message, &mut offset, header.qd_count)?;
    let owner_start = offset;
    // The overwhelmingly common shape here -- a real OPT record -- always
    // uses the canonical, unambiguous single `0x00` root-label byte as its
    // owner (RFC 6891 §6.1.2; see `is_canonical_root_owner`'s docs). Fast-
    // path that exact byte directly instead of paying for *any* name
    // parse, allocating or not: it's a single length check, so there's
    // nothing left to skip.
    if is_canonical_root_owner(dns_message, owner_start) {
        offset += 1;
    } else {
        // A non-root owner can never pass the `is_canonical_root_owner`
        // check below no matter what type the record turns out to be, so
        // this branch only needs to skip past the name cheaply to reach
        // (and correctly step over) the record that follows -- not decode
        // or validate it. `skip_name_offset_only` (see its docs) is the
        // allocation-free equivalent of `parse_domain_with_context` for
        // exactly that "skip, don't decode" need.
        skip_name_offset_only(dns_message, &mut offset)?;
    }
    let mut reader = Reader::new(dns_message, offset)?;
    let rtype = reader.read_u16()?;
    Ok(rtype == OPT_RECORD_TYPE && is_canonical_root_owner(dns_message, owner_start))
}

/// Walks `count` additional-section records looking for the first OPT
/// record (RFC 6891 §6.1.2: owner name root, i.e. empty), extracting only
/// its fixed-size metadata -- never its RDATA (options) -- and otherwise
/// skips each record the same lightweight way as `recovery_skip_record`.
/// A record whose type happens to be OPT but whose owner name isn't the
/// canonical root encoding is simply skipped like any other record rather
/// than treated as a hard parse failure, since this is a best-effort scan,
/// not the primary parse path's strict `extract_edns_info` validation.
///
/// The "is this owner name root" check deliberately does *not* trust
/// `parse_domain_with_context`'s general notion of an "empty" name here.
/// Every record's owner name in this scan is parsed with `context: None`
/// (see `recovery_skip_record`'s docs for why -- a full `ParseContext`
/// isn't available/safe to build on this bounded, best-effort path), and
/// `decode_compression_pointer` only requires a pointer to point strictly
/// backward in the message when it has no context to check against --
/// it never confirms the pointer actually lands on a prior legitimate
/// domain-name occurrence. So a crafted OPT record whose owner name is a
/// compression pointer aimed at, say, the message header (where byte 0 is
/// frequently `0x00`, the ID's high byte) would pointer-chase to an
/// "empty" name here without the name being legitimately root-owned,
/// letting a spoofed/invalidly-compressed OPT claim be accepted by
/// recovery (RFC 1035 §4.1.4: pointers must reference a prior domain-name
/// occurrence, not arbitrary bytes). Real OPT records always use the
/// canonical, unambiguous root encoding -- a single `0x00` label-length
/// byte with no compression pointer involved at all -- so this only
/// treats a record as root-owned when that literal byte is what's at the
/// record's start, and fails EDNS recovery closed (skipping the record,
/// not aborting the scan) for anything else, including a compression
/// pointer that might otherwise legitimately resolve to root: recovery
/// has no full parse context to validate that safely.
fn recovery_find_opt_in_additionals(
    dns_message: &[u8],
    offset: &mut usize,
    count: u16,
) -> Result<Option<EdnsInfo>> {
    let mut found = None;
    for _ in 0..count {
        let owner_start = *offset;
        parse_domain_with_context(dns_message, offset, None)?;
        let mut reader = Reader::new(dns_message, *offset)?;
        let rtype = reader.read_u16()?;
        let rclass = reader.read_u16()?;
        let ttl = reader.read_u32()?;
        let rdlength = reader.read_u16()? as usize;
        let rdata_offset = reader.position();
        let rdata_end = rdata_offset
            .checked_add(rdlength)
            .ok_or(DnsParseError::MalformedRecord)?;
        dns_message
            .get(rdata_offset..rdata_end)
            .ok_or(DnsParseError::UnexpectedEof)?;
        if found.is_none()
            && rtype == OPT_RECORD_TYPE
            && is_canonical_root_owner(dns_message, owner_start)
        {
            let extended_rcode = ((ttl >> 24) & 0xff) as u8;
            let version = ((ttl >> 16) & 0xff) as u8;
            let flags = (ttl & 0xffff) as u16;
            found = Some(EdnsInfo {
                udp_payload_size: rclass,
                extended_rcode,
                version,
                flags,
                dnssec_ok: (flags & EDNS_DO_FLAG) != 0,
                options: Vec::new(),
            });
        }
        *offset = rdata_end;
    }
    Ok(found)
}

fn validate_standard_query_header(
    header: &Header,
) -> std::result::Result<(), QueryValidationError> {
    if header.qr() {
        return Err(QueryValidationError::NotQuery);
    }
    let opcode = header.opcode();
    if opcode != 0 {
        return Err(QueryValidationError::UnsupportedOpcode { opcode });
    }
    if header.qd_count != 1 {
        return Err(QueryValidationError::InvalidQuestionCount {
            count: header.qd_count,
        });
    }
    if header.an_count != 0 || header.ns_count != 0 || header.ar_count > 1 {
        return Err(QueryValidationError::UnexpectedSectionRecords {
            answers: header.an_count,
            authorities: header.ns_count,
            additionals: header.ar_count,
        });
    }
    Ok(())
}

fn validate_standard_query_body(
    message: &Message,
) -> std::result::Result<(), QueryValidationError> {
    if message.header.ar_count == 0 {
        return Ok(());
    }

    if message.additionals.len() != 1 {
        return Err(QueryValidationError::InvalidEdns);
    }

    match &message.additionals[0].record {
        RecordData::OPT(info) if info.version != 0 => {
            Err(QueryValidationError::UnsupportedEdnsVersion {
                version: info.version,
            })
        }
        RecordData::OPT(_) => Ok(()),
        _ => Err(QueryValidationError::InvalidEdns),
    }
}

fn extract_edns_info(records: &[Record]) -> Result<Option<EdnsInfo>> {
    let mut edns = None;
    for record in records {
        if let RecordData::OPT(info) = &record.record {
            if edns.is_some() {
                return Err(DnsParseError::MalformedRecord);
            }
            edns = Some(info.clone());
        }
    }
    Ok(edns)
}

#[derive(Default)]
struct ParseContext {
    valid_name_offsets: HashSet<usize>,
}

impl TryFrom<&[u8]> for Message {
    type Error = DnsParseError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], offset: usize) -> Result<Self> {
        if offset > bytes.len() {
            return Err(DnsParseError::UnexpectedEof);
        }
        Ok(Self { bytes, offset })
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn read_u8(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(DnsParseError::UnexpectedEof)?;
        self.offset += 1;
        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DnsParseError::UnexpectedEof)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(DnsParseError::UnexpectedEof)?;
        self.offset = end;
        Ok(bytes)
    }
}

fn parse_header(dns_message: &[u8]) -> Result<Header> {
    let mut reader = Reader::new(dns_message, 0)?;
    Ok(Header {
        id: reader.read_u16()?,
        flags: reader.read_u16()?,
        qd_count: reader.read_u16()?,
        an_count: reader.read_u16()?,
        ns_count: reader.read_u16()?,
        ar_count: reader.read_u16()?,
    })
}

fn parse_questions(
    dns_message: &[u8],
    offset: &mut usize,
    question_count: u16,
    context: &mut ParseContext,
) -> Result<Vec<Question>> {
    let mut questions = Vec::with_capacity(question_count as usize);
    for _ in 0..question_count {
        questions.push(parse_question(dns_message, offset, context)?);
    }
    Ok(questions)
}

fn parse_question(
    dns_message: &[u8],
    offset: &mut usize,
    context: &mut ParseContext,
) -> Result<Question> {
    let qname = parse_domain_with_context(dns_message, offset, Some(context))?;
    let mut reader = Reader::new(dns_message, *offset)?;
    let qtype = reader.read_u16()?;
    let qclass = reader.read_u16()?;
    *offset = reader.position();
    Ok(Question {
        qname,
        qtype,
        qclass,
    })
}

fn parse_records(
    dns_message: &[u8],
    offset: &mut usize,
    record_count: u16,
    context: &mut ParseContext,
) -> Result<Vec<Record>> {
    let mut records = Vec::with_capacity(record_count as usize);
    for _ in 0..record_count {
        records.push(parse_record(dns_message, offset, context)?);
    }
    Ok(records)
}

fn skip_questions(dns_message: &[u8], offset: &mut usize, question_count: u16) -> Result<()> {
    for _ in 0..question_count {
        parse_domain_with_context(dns_message, offset, None)?;
        let mut reader = Reader::new(dns_message, *offset)?;
        reader.read_u16()?;
        reader.read_u16()?;
        *offset = reader.position();
    }
    Ok(())
}

fn adjust_record_ttls(
    dns_message: &mut [u8],
    offset: &mut usize,
    record_count: u16,
    age_secs: u32,
    max_ttl_secs: Option<u32>,
) -> Result<()> {
    for _ in 0..record_count {
        parse_domain_with_context(dns_message, offset, None)?;
        let mut reader = Reader::new(dns_message, *offset)?;
        let rtype = reader.read_u16()?;
        reader.read_u16()?;
        let ttl_offset = reader.position();
        let ttl = reader.read_u32()?;
        let rdlength = reader.read_u16()? as usize;
        let rdata_end = reader
            .position()
            .checked_add(rdlength)
            .ok_or(DnsParseError::MalformedRecord)?;
        dns_message
            .get(reader.position()..rdata_end)
            .ok_or(DnsParseError::UnexpectedEof)?;
        if rtype != OPT_RECORD_TYPE {
            let mut adjusted_ttl = ttl.saturating_sub(age_secs);
            if let Some(max_ttl_secs) = max_ttl_secs {
                adjusted_ttl = adjusted_ttl.min(max_ttl_secs);
            }
            dns_message[ttl_offset..ttl_offset + 4].copy_from_slice(&adjusted_ttl.to_be_bytes());
        }
        *offset = rdata_end;
    }
    Ok(())
}

fn parse_record(
    dns_message: &[u8],
    offset: &mut usize,
    context: &mut ParseContext,
) -> Result<Record> {
    let owner_start = *offset;
    let name = parse_domain_with_context(dns_message, offset, Some(context))?;
    let mut reader = Reader::new(dns_message, *offset)?;
    let rtype = reader.read_u16()?;
    let rclass = reader.read_u16()?;
    let ttl = reader.read_u32()?;
    let rdlength = reader.read_u16()? as usize;
    // RFC 6891 §6.1.2: the OPT record's NAME field "MUST be 0 (root
    // domain)" -- the literal wire encoding, not merely a name that
    // *resolves* to empty. `name.is_empty()` alone would also accept a
    // compression pointer that legitimately (per this call's real
    // `ParseContext`) points at a prior root-label occurrence; real OPT
    // records never use compression for their owner name, so also require
    // the canonical encoding via `is_canonical_root_owner`. A record with
    // `rtype == OPT_RECORD_TYPE` but a non-canonical owner is malformed
    // EDNS, treated the same as the already-established duplicate-OPT
    // rejection on this primary parse path (not silently "no EDNS" and not
    // silently "valid EDNS").
    if rtype == OPT_RECORD_TYPE
        && !(name.is_empty() && is_canonical_root_owner(dns_message, owner_start))
    {
        return Err(DnsParseError::MalformedRecord);
    }
    let rdata_offset = reader.position();
    let rdata_end = rdata_offset
        .checked_add(rdlength)
        .ok_or(DnsParseError::MalformedRecord)?;
    dns_message
        .get(rdata_offset..rdata_end)
        .ok_or(DnsParseError::UnexpectedEof)?;

    let record = parse_record_data(
        dns_message,
        rdata_offset,
        rtype,
        rclass,
        ttl,
        rdlength,
        context,
    )?;
    *offset = rdata_end;
    Ok(Record {
        name,
        rtype,
        rclass,
        ttl,
        record,
    })
}

fn parse_record_data(
    dns_message: &[u8],
    offset: usize,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdlength: usize,
    context: &mut ParseContext,
) -> Result<RecordData> {
    let end = offset
        .checked_add(rdlength)
        .ok_or(DnsParseError::MalformedRecord)?;
    match rtype {
        1 => parse_a_record(dns_message, offset, end),
        2 => parse_name_record(dns_message, offset, end, context).map(RecordData::NS),
        5 => parse_name_record(dns_message, offset, end, context).map(RecordData::CNAME),
        6 => parse_soa_record(dns_message, offset, end, context),
        12 => parse_name_record(dns_message, offset, end, context).map(RecordData::PTR),
        15 => parse_mx_record(dns_message, offset, end, context),
        16 => parse_txt_record(dns_message, offset, end),
        17 => parse_rp_record(dns_message, offset, end, context),
        28 => parse_aaaa_record(dns_message, offset, end),
        33 => parse_srv_record(dns_message, offset, end, context),
        37 => parse_cert_record(dns_message, offset, end),
        43 => parse_ds_record(dns_message, offset, end),
        46 => parse_rrsig_record(dns_message, offset, end, context),
        47 => parse_nsec_record(dns_message, offset, end, context),
        48 => parse_dnskey_record(dns_message, offset, end),
        50 => parse_nsec3_record(dns_message, offset, end),
        51 => parse_nsec3param_record(dns_message, offset, end),
        257 => parse_caa_record(dns_message, offset, end),
        OPT_RECORD_TYPE => parse_opt_record(dns_message, offset, end, rclass, ttl),
        _ => Ok(RecordData::Unknown {
            rtype,
            bytes: dns_message[offset..end].to_vec(),
        }),
    }
}

fn parse_a_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    if end - offset != 4 {
        return Err(DnsParseError::MalformedRecord);
    }
    let bytes = &dns_message[offset..end];
    Ok(RecordData::A(Ipv4Addr::new(
        bytes[0], bytes[1], bytes[2], bytes[3],
    )))
}

fn parse_aaaa_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    if end - offset != 16 {
        return Err(DnsParseError::MalformedRecord);
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&dns_message[offset..end]);
    Ok(RecordData::AAAA(Ipv6Addr::from(octets)))
}

fn parse_name_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    context: &mut ParseContext,
) -> Result<String> {
    let mut cursor = offset;
    let name = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    if cursor != end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(name)
}

fn parse_mx_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    context: &mut ParseContext,
) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let preference = reader.read_u16()?;
    let mut cursor = reader.position();
    let exchange = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    if cursor != end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::MX {
        preference,
        exchange,
    })
}

fn parse_srv_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    context: &mut ParseContext,
) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let priority = reader.read_u16()?;
    let weight = reader.read_u16()?;
    let port = reader.read_u16()?;
    let mut cursor = reader.position();
    let target = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    if cursor != end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::SRV {
        priority,
        weight,
        port,
        target,
    })
}

fn parse_txt_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut cursor = offset;
    let mut text = String::new();
    while cursor < end {
        let len = *dns_message
            .get(cursor)
            .ok_or(DnsParseError::UnexpectedEof)? as usize;
        cursor += 1;
        let text_end = cursor
            .checked_add(len)
            .ok_or(DnsParseError::MalformedRecord)?;
        let bytes = dns_message
            .get(cursor..text_end)
            .ok_or(DnsParseError::UnexpectedEof)?;
        if text_end > end {
            return Err(DnsParseError::MalformedRecord);
        }
        text.push_str(&String::from_utf8_lossy(bytes));
        cursor = text_end;
    }
    Ok(RecordData::TXT(text))
}

fn parse_soa_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    context: &mut ParseContext,
) -> Result<RecordData> {
    let mut cursor = offset;
    let mname = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    let rname = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    let mut reader = Reader::new(dns_message, cursor)?;
    let serial = reader.read_u32()?;
    let refresh = reader.read_u32()?;
    let retry = reader.read_u32()?;
    let expire = reader.read_u32()?;
    let minimum = reader.read_u32()?;
    if reader.position() != end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::SOA {
        ttl: 0,
        rname,
        mname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    })
}

fn parse_rp_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    context: &mut ParseContext,
) -> Result<RecordData> {
    let mut cursor = offset;
    let mboxdname = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    let txtdname = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    if cursor != end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::RP {
        mboxdname,
        txtdname,
    })
}

fn parse_caa_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let flags = reader.read_u8()?;
    let tag_len = reader.read_u8()? as usize;
    let tag = reader.read_exact(tag_len)?;
    if reader.position() > end {
        return Err(DnsParseError::MalformedRecord);
    }
    let value = dns_message
        .get(reader.position()..end)
        .ok_or(DnsParseError::UnexpectedEof)?;
    Ok(RecordData::CAA {
        flags,
        tag: str::from_utf8(tag)
            .map_err(|_| DnsParseError::InvalidUtf8Label)?
            .to_string(),
        value: String::from_utf8_lossy(value).to_string(),
    })
}

fn parse_cert_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let cert_type = reader.read_u16()?;
    let key_tag = reader.read_u16()?;
    let algorithm = reader.read_u8()?;
    let cert = dns_message
        .get(reader.position()..end)
        .ok_or(DnsParseError::UnexpectedEof)?
        .to_vec();
    Ok(RecordData::CERT {
        cert_type,
        key_tag,
        algorithm,
        cert,
    })
}

fn parse_dnskey_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let flags = reader.read_u16()?;
    let protocol = reader.read_u8()?;
    let algorithm = reader.read_u8()?;
    let public_key = dns_message
        .get(reader.position()..end)
        .ok_or(DnsParseError::UnexpectedEof)?
        .to_vec();
    Ok(RecordData::DNSKEY {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

fn parse_ds_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let key_tag = reader.read_u16()?;
    let algorithm = reader.read_u8()?;
    let digest_type = reader.read_u8()?;
    let digest = dns_message
        .get(reader.position()..end)
        .ok_or(DnsParseError::UnexpectedEof)?
        .to_vec();
    Ok(RecordData::DS {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

fn parse_rrsig_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    context: &mut ParseContext,
) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let type_covered = reader.read_u16()?;
    let algorithm = reader.read_u8()?;
    let labels = reader.read_u8()?;
    let original_ttl = reader.read_u32()?;
    let signature_expiration = reader.read_u32()?;
    let signature_inception = reader.read_u32()?;
    let key_tag = reader.read_u16()?;
    let mut cursor = reader.position();
    let signer_name = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    if cursor > end {
        return Err(DnsParseError::MalformedRecord);
    }
    let signature = dns_message[cursor..end].to_vec();
    Ok(RecordData::RRSIG {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        signature_expiration,
        signature_inception,
        key_tag,
        signer_name,
        signature,
    })
}

fn parse_nsec_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    context: &mut ParseContext,
) -> Result<RecordData> {
    let mut cursor = offset;
    let next_domain = parse_domain_with_context(dns_message, &mut cursor, Some(context))?;
    if cursor > end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::NSEC {
        next_domain,
        type_bit_maps: dns_message[cursor..end].to_vec(),
    })
}

fn parse_nsec3_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let hash_algorithm = reader.read_u8()?;
    let flags = reader.read_u8()?;
    let iterations = reader.read_u16()?;
    let salt_len = reader.read_u8()? as usize;
    let salt = reader.read_exact(salt_len)?.to_vec();
    let hash_len = reader.read_u8()? as usize;
    let next_hashed_owner_name = reader.read_exact(hash_len)?;
    if reader.position() > end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::NSEC3 {
        hash_algorithm,
        flags,
        iterations,
        salt_length: salt_len as u8,
        salt,
        hash_length: hash_len as u8,
        next_domain: to_hex(next_hashed_owner_name),
        type_bit_maps: dns_message[reader.position()..end].to_vec(),
    })
}

fn parse_nsec3param_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let hash_algorithm = reader.read_u8()?;
    let flags = reader.read_u8()?;
    let iterations = reader.read_u16()?;
    let salt_length = reader.read_u8()?;
    let salt = reader.read_exact(salt_length as usize)?.to_vec();
    if reader.position() != end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::NSEC3PARAM {
        hash_algorithm,
        flags,
        iterations,
        salt_length,
        salt,
    })
}

fn parse_opt_record(
    dns_message: &[u8],
    offset: usize,
    end: usize,
    udp_payload_size: u16,
    ttl: u32,
) -> Result<RecordData> {
    let extended_rcode = ((ttl >> 24) & 0xff) as u8;
    let version = ((ttl >> 16) & 0xff) as u8;
    let flags = (ttl & 0xffff) as u16;
    let options = dns_message
        .get(offset..end)
        .ok_or(DnsParseError::UnexpectedEof)?
        .to_vec();
    validate_edns_options(&options)?;

    Ok(RecordData::OPT(EdnsInfo {
        udp_payload_size,
        extended_rcode,
        version,
        flags,
        dnssec_ok: (flags & EDNS_DO_FLAG) != 0,
        options,
    }))
}

fn validate_edns_options(options: &[u8]) -> Result<()> {
    let mut reader = Reader::new(options, 0)?;
    while reader.position() < options.len() {
        reader.read_u16()?;
        let option_len = reader.read_u16()? as usize;
        reader.read_exact(option_len)?;
    }
    Ok(())
}

#[cfg(test)]
fn parse_domain(dns_message: &[u8], offset: &mut usize) -> Result<String> {
    parse_domain_with_context(dns_message, offset, None)
}

#[cfg(test)]
thread_local! {
    // Per-thread call counter for `parse_domain_with_context`, used only to
    // prove that specific fast paths (e.g. `recovery_additional_is_opt`'s
    // canonical-root-owner check) never reach the allocating
    // general-purpose domain parser at all, not just that they're
    // bounded/cheap. Thread-local rather than a single global counter so
    // parallel test execution can't make tests interfere with each other's
    // counts.
    static PARSE_DOMAIN_WITH_CONTEXT_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_parse_domain_with_context_call_count() {
    PARSE_DOMAIN_WITH_CONTEXT_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn parse_domain_with_context_call_count() -> usize {
    PARSE_DOMAIN_WITH_CONTEXT_CALLS.with(|calls| calls.get())
}

fn parse_domain_with_context(
    dns_message: &[u8],
    offset: &mut usize,
    mut context: Option<&mut ParseContext>,
) -> Result<String> {
    #[cfg(test)]
    PARSE_DOMAIN_WITH_CONTEXT_CALLS.with(|calls| calls.set(calls.get() + 1));
    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut consumed_offset = None;
    let mut visited = HashSet::new();
    let mut wire_len = 1usize;

    loop {
        if !visited.insert(cursor) {
            return Err(DnsParseError::PointerLoop);
        }

        let length_octet = *dns_message
            .get(cursor)
            .ok_or(DnsParseError::UnexpectedEof)?;
        let length = length_octet as usize;
        match length_octet & 0b1100_0000 {
            0b0000_0000 => {
                if let Some(context) = context.as_deref_mut() {
                    context.valid_name_offsets.insert(cursor);
                }
                cursor += 1;
                if length == 0 {
                    if consumed_offset.is_none() {
                        consumed_offset = Some(cursor);
                    }
                    break;
                }
                if length > MAX_LABEL_LEN {
                    return Err(DnsParseError::InvalidLabel);
                }
                let label_end = cursor
                    .checked_add(length)
                    .ok_or(DnsParseError::UnexpectedEof)?;
                let label = dns_message
                    .get(cursor..label_end)
                    .ok_or(DnsParseError::UnexpectedEof)?;
                wire_len = wire_len
                    .checked_add(length + 1)
                    .ok_or(DnsParseError::InvalidLabel)?;
                if wire_len > MAX_NAME_LEN {
                    return Err(DnsParseError::InvalidLabel);
                }
                labels.push(
                    str::from_utf8(label)
                        .map_err(|_| DnsParseError::InvalidUtf8Label)?
                        .to_string(),
                );
                cursor = label_end;
            }
            0b1100_0000 => {
                let pointer_offset = decode_compression_pointer(
                    dns_message,
                    cursor,
                    length_octet,
                    context.as_deref(),
                )?;
                if let Some(context) = context.as_deref_mut() {
                    context.valid_name_offsets.insert(cursor);
                }
                if consumed_offset.is_none() {
                    consumed_offset = Some(cursor + 2);
                }
                cursor = pointer_offset;
            }
            _ => return Err(DnsParseError::InvalidLabel),
        }
    }

    *offset = consumed_offset.ok_or(DnsParseError::UnexpectedEof)?;
    Ok(labels.join("."))
}

fn decode_compression_pointer(
    dns_message: &[u8],
    cursor: usize,
    first_octet: u8,
    context: Option<&ParseContext>,
) -> Result<usize> {
    let second_octet = *dns_message
        .get(cursor + 1)
        .ok_or(DnsParseError::UnexpectedEof)? as usize;
    let pointer_offset = (((first_octet & 0b0011_1111) as usize) << 8) | second_octet;
    if pointer_offset >= cursor || pointer_offset >= dns_message.len() {
        return Err(DnsParseError::InvalidNamePointer);
    }
    if let Some(context) = context
        && !context.valid_name_offsets.contains(&pointer_offset)
    {
        return Err(DnsParseError::InvalidNamePointer);
    }
    Ok(pointer_offset)
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn build_record_header(out: &mut Vec<u8>, rtype: u16, rdlength: u16, ttl: u32) {
        push_u16(out, rtype);
        push_u16(out, 1);
        push_u32(out, ttl);
        push_u16(out, rdlength);
    }

    fn push_pointer(out: &mut Vec<u8>, offset: usize) {
        let pointer = 0b1100_0000 | ((offset >> 8) as u8 & 0b0011_1111);
        out.push(pointer);
        out.push((offset & 0xff) as u8);
    }

    fn push_header(out: &mut Vec<u8>, qd: u16, an: u16, ns: u16, ar: u16) {
        push_u16(out, 0x1234);
        push_u16(out, 0x0100);
        push_u16(out, qd);
        push_u16(out, an);
        push_u16(out, ns);
        push_u16(out, ar);
    }

    fn push_header_with_flags(out: &mut Vec<u8>, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) {
        push_u16(out, 0x1234);
        push_u16(out, flags);
        push_u16(out, qd);
        push_u16(out, an);
        push_u16(out, ns);
        push_u16(out, ar);
    }

    fn push_question(out: &mut Vec<u8>, name: &str, qtype: u16, qclass: u16) {
        push_name(out, name);
        push_u16(out, qtype);
        push_u16(out, qclass);
    }

    fn push_record(out: &mut Vec<u8>, name: &str, rtype: u16, ttl: u32, rdata: &[u8]) {
        push_name(out, name);
        build_record_header(out, rtype, rdata.len() as u16, ttl);
        out.extend_from_slice(rdata);
    }

    fn push_opt_record(out: &mut Vec<u8>, udp_payload_size: u16, dnssec_ok: bool, options: &[u8]) {
        push_opt_record_with_version(out, udp_payload_size, dnssec_ok, 0, options);
    }

    fn push_opt_record_with_version(
        out: &mut Vec<u8>,
        udp_payload_size: u16,
        dnssec_ok: bool,
        version: u8,
        options: &[u8],
    ) {
        out.push(0);
        push_u16(out, OPT_RECORD_TYPE);
        push_u16(out, udp_payload_size);
        let flags = if dnssec_ok { EDNS_DO_FLAG as u32 } else { 0 };
        push_u32(out, (u32::from(version) << 16) | flags);
        push_u16(out, options.len() as u16);
        out.extend_from_slice(options);
    }

    fn parse_test_record(bytes: &[u8]) -> Record {
        let mut offset = 0;
        let mut context = ParseContext::default();
        parse_record(bytes, &mut offset, &mut context).unwrap()
    }

    #[test]
    fn parse_domain_labels() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let mut offset = 0;
        let name = parse_domain(&bytes, &mut offset).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(offset, bytes.len());
    }

    #[test]
    fn parse_domain_pointer() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let pointer_offset = bytes.len();
        bytes.push(0b1100_0000);
        bytes.push(0);
        let mut offset = pointer_offset;
        let name = parse_domain(&bytes, &mut offset).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(offset, pointer_offset + 2);
    }

    #[test]
    fn parse_standard_query_accepts_one_question_query() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 0);
        push_question(&mut message, "example.com", 1, 1);

        let parsed = Message::parse_standard_query(&message).unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].qname, "example.com");
        assert!(parsed.header.rd());
    }

    #[test]
    fn parse_standard_query_owned_reuses_input_buffer() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 0);
        push_question(&mut message, "example.com", 1, 1);
        let original_ptr = message.as_ptr();

        let parsed = Message::parse_standard_query_owned(message).unwrap();

        assert_eq!(parsed.original_bytes.as_ptr(), original_ptr);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].qname, "example.com");
    }

    #[test]
    fn parse_standard_query_owned_matches_borrowed_errors() {
        let mut response_packet = Vec::new();
        push_header_with_flags(&mut response_packet, 0x8100, 1, 0, 0, 0);
        push_question(&mut response_packet, "example.com", 1, 1);

        let mut unsupported_opcode = Vec::new();
        push_header_with_flags(&mut unsupported_opcode, 0x0900, 1, 0, 0, 0);
        push_question(&mut unsupported_opcode, "example.com", 1, 1);

        let mut unexpected_answer = Vec::new();
        push_header(&mut unexpected_answer, 1, 1, 0, 0);
        push_question(&mut unexpected_answer, "example.com", 1, 1);

        let mut malformed_edns = Vec::new();
        push_header(&mut malformed_edns, 1, 0, 0, 1);
        push_question(&mut malformed_edns, "example.com", 1, 1);
        push_opt_record(&mut malformed_edns, 1232, false, &[0, 15, 0, 4, 1, 2]);

        let mut multiple_questions = Vec::new();
        push_header(&mut multiple_questions, 2, 0, 0, 0);
        push_question(&mut multiple_questions, "example.com", 1, 1);
        push_question(&mut multiple_questions, "example.net", 1, 1);

        for message in [
            response_packet,
            unsupported_opcode,
            unexpected_answer,
            malformed_edns,
            multiple_questions,
        ] {
            assert_eq!(
                Message::parse_standard_query_owned(message.clone()),
                Message::parse_standard_query(&message)
            );
        }
    }

    /// Regression test: a header-validation failure whose header also
    /// claims a large (attacker-controlled) additional-record count must
    /// not trigger unbounded parse work while recovering context for the
    /// protocol-error response. Before recovery was bounded, this shape
    /// made the recovery retry call the general `Self::parse`, which walks
    /// records using the header's own (already-untrusted) counts -- with
    /// real record bytes present that's a real parse+allocate cost paid on
    /// every such malformed packet; with too few bytes to back the claimed
    /// count (as constructed here) it fails outright and recovers nothing
    /// at all, losing even the question. Bounding recovery to
    /// `RECOVERY_MAX_SECTION_RECORDS` means a declared count beyond that
    /// bound is never walked -- regardless of whether the packet actually
    /// backs it up -- so the question is still recovered and only the
    /// EDNS/OPT context is cleanly dropped instead of recovery failing
    /// wholesale.
    #[test]
    fn recovery_skips_edns_when_section_counts_exceed_bound_but_still_recovers_question() {
        let mut message = Vec::new();
        // opcode = 1 (unsupported), RD = 1, ar_count = 5000 -- the packet
        // ends right after the question, nowhere near enough bytes to back
        // 5000 additional records.
        push_header_with_flags(&mut message, 0x0900, 1, 0, 0, 5000);
        push_question(&mut message, "example.com", 1, 1);

        let failure = Message::parse_standard_query_owned_with_recovery(message).unwrap_err();
        assert_eq!(
            failure.error,
            QueryValidationError::UnsupportedOpcode { opcode: 1 }
        );
        let recovered = failure
            .recovered_message
            .expect("the header and question should still be recovered");
        assert_eq!(recovered.questions.len(), 1);
        assert_eq!(recovered.questions[0].qname, "example.com");
        assert!(
            recovered.edns.is_none(),
            "a section count beyond the recovery bound must not be walked, even best-effort"
        );
    }

    /// Regression test: a query with two OPT records (itself a FORMERR
    /// condition per RFC 6891 §6.1.1, since `ar_count > 1` fails
    /// `validate_standard_query_header`) must still recover CD and enough
    /// EDNS context to build a compliant FORMERR-with-OPT response, even
    /// though a full `Self::parse` retry would itself fail on the
    /// duplicate OPT (`extract_edns_info` correctly rejects more than one
    /// OPT record on the primary parse path). Recovery tolerates the extra
    /// OPT record by using only the first one found.
    #[test]
    fn recovery_tolerates_duplicate_opt_and_recovers_first_ones_dnssec_ok() {
        let mut message = Vec::new();
        push_header_with_flags(&mut message, 0x0110, 1, 0, 0, 2); // RD=1, CD=1
        push_question(&mut message, "example.com", 1, 1);
        push_opt_record(&mut message, 1232, true, &[]);
        push_opt_record(&mut message, 4096, false, &[]);

        let failure = Message::parse_standard_query_owned_with_recovery(message).unwrap_err();
        assert_eq!(
            failure.error,
            QueryValidationError::UnexpectedSectionRecords {
                answers: 0,
                authorities: 0,
                additionals: 2,
            }
        );
        let recovered = failure
            .recovered_message
            .expect("a duplicate OPT record must not prevent CD/question recovery");
        assert!(
            recovered.header.cd(),
            "CD must still be recovered per RFC 4035 §3.2.2"
        );
        assert_eq!(recovered.questions.len(), 1);
        let edns = recovered
            .edns
            .expect("the first OPT record should still be recovered");
        assert!(
            edns.dnssec_ok,
            "should reflect the first OPT record's DO flag, not the second"
        );
    }

    /// Regression test: `recover_edns_info` must not run each recovered
    /// record through the general `parse_record_data` path. A record-count
    /// bound (`RECOVERY_MAX_SECTION_RECORDS`) only bounds how many records
    /// are walked, not how large any individual one's RDATA is -- a
    /// crafted packet with `an_count <= RECOVERY_MAX_SECTION_RECORDS` can
    /// still carry a large RDATA blob. Forcing that through
    /// `parse_record_data` would mean either a large `to_vec()` copy (for
    /// an unknown/blob type) or, as constructed here, a hard parse failure
    /// for a type whose RDATA doesn't match its type's expected shape (an
    /// A record's RDATA must be exactly 4 bytes; this one claims 60000).
    /// The old, `parse_records`-based implementation propagated that
    /// failure via `?` and lost EDNS/OPT recovery entirely, even though
    /// the OPT record immediately after it is perfectly well-formed. The
    /// lightweight `recovery_skip_record` only reads the record's
    /// fixed-size header (name/type/class/ttl/rdlength) to skip past it --
    /// it never looks at whether the RDATA content actually matches the
    /// type, so recovery must still find the OPT record that follows,
    /// which -- since a full parse of the oversized A record would have
    /// failed outright -- also proves the oversized RDATA was never fully
    /// parsed or copied.
    #[test]
    fn recovery_skips_oversized_non_opt_rdata_without_full_parsing_it() {
        let mut message = Vec::new();
        // opcode = 1 (unsupported), an_count = 1, ar_count = 1 -- both
        // within RECOVERY_MAX_SECTION_RECORDS.
        push_header_with_flags(&mut message, 0x0900, 1, 1, 0, 1);
        push_question(&mut message, "example.com", 1, 1);
        // An A record (rtype 1) with a 60000-byte RDATA -- nowhere near
        // the 4 bytes an A record requires, but large enough that a
        // `to_vec()` copy of it would be a real cost were one performed.
        let huge_rdata = vec![0u8; 60_000];
        push_record(&mut message, "example.com", 1, 0, &huge_rdata);
        push_opt_record(&mut message, 1232, true, &[]);

        let failure = Message::parse_standard_query_owned_with_recovery(message).unwrap_err();
        assert_eq!(
            failure.error,
            QueryValidationError::UnsupportedOpcode { opcode: 1 }
        );
        let recovered = failure
            .recovered_message
            .expect("the header and question should still be recovered");
        assert_eq!(recovered.questions.len(), 1);
        assert_eq!(recovered.questions[0].qname, "example.com");
        let edns = recovered.edns.expect(
            "the OPT record after the oversized answer record must still be recovered -- \
             proves the oversized answer record was skipped by its header alone, not fully parsed",
        );
        assert!(edns.dnssec_ok);
        assert_eq!(edns.udp_payload_size, 1232);
    }

    /// Regression test: a malformed multi-question query (`qd_count == 2`,
    /// itself a distinct FORMERR condition -- `InvalidQuestionCount`, since
    /// `validate_standard_query_header` requires exactly one question) with
    /// a well-formed OPT record after both questions must still recover
    /// that OPT record. Before the offset fix, `recover_query_context`
    /// kept only the first question but left `offset` positioned right
    /// after it, so `recover_edns_info` started scanning into the *second*
    /// question's bytes instead of skipping past it to the answer/
    /// additional sections -- losing EDNS/CD recovery for an otherwise
    /// recoverable shape.
    #[test]
    fn recovery_skips_extra_questions_before_scanning_for_opt() {
        let mut message = Vec::new();
        push_header_with_flags(&mut message, 0x0110, 2, 0, 0, 1); // RD=1, CD=1, qd=2
        push_question(&mut message, "example.com", 1, 1);
        push_question(&mut message, "example.net", 1, 1);
        push_opt_record(&mut message, 4096, true, &[]);

        let failure = Message::parse_standard_query_owned_with_recovery(message).unwrap_err();
        assert_eq!(
            failure.error,
            QueryValidationError::InvalidQuestionCount { count: 2 }
        );
        let recovered = failure
            .recovered_message
            .expect("the header and first question should still be recovered");
        assert!(
            recovered.header.cd(),
            "CD must still be recovered per RFC 4035 §3.2.2"
        );
        assert_eq!(recovered.questions.len(), 1);
        assert_eq!(recovered.questions[0].qname, "example.com");
        let edns = recovered.edns.expect(
            "the OPT record after the second question must still be recovered once the \
             second question is skipped rather than scanned into",
        );
        assert!(edns.dnssec_ok);
        assert_eq!(edns.udp_payload_size, 4096);
    }

    /// Regression test: a query whose *header* passes
    /// `validate_standard_query_header` cleanly (`qd_count == 1,
    /// an_count == 0, ns_count == 0, ar_count == 1`) but whose single
    /// declared additional record isn't actually OPT must be rejected by a
    /// cheap, type-only precheck (`recovery_additional_is_opt`) rather than
    /// falling through to the full `Self::parse_owned` -> `parse_record_data`
    /// path -- otherwise a crafted non-OPT additional with a large/unknown
    /// RDATA would force the same "malformed packet forces expensive parse
    /// work" cost the header-validation-failure recovery path was built to
    /// close off, just via a different validation-ordering gap.
    ///
    /// The additional record here declares a large `rdlength` (60000) but
    /// the packet is truncated right after the fixed-size record header --
    /// none of the claimed RDATA bytes are actually present. This makes
    /// the two code paths distinguishable by which error comes back: the
    /// precheck only reads the owner name and 2-byte type field (both
    /// present) and rejects for `InvalidEdns` without ever looking at
    /// `rdlength`; if the precheck weren't wired in, `Self::parse_owned`
    /// would instead try to bounds-check the (absent) 60000-byte RDATA
    /// region and fail with `DnsParseError::UnexpectedEof` -- a distinct
    /// error code from `InvalidEdns` even though both paths now recover the
    /// question (`Self::parse_owned` failures also recover context; see
    /// `cd_is_recovered_when_body_parse_fails_after_valid_header`).
    #[test]
    fn precheck_rejects_non_opt_additional_before_full_parse() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1); // opcode 0 (supported), ar = 1
        push_question(&mut message, "example.com", 1, 1);
        // The additional record's fixed-size header: root owner name, an
        // unknown/non-OPT type, and a large declared `rdlength` -- but no
        // backing RDATA bytes at all.
        message.push(0); // owner name: root
        push_u16(&mut message, 9999); // rtype: not OPT_RECORD_TYPE
        push_u16(&mut message, 1); // rclass
        push_u32(&mut message, 0); // ttl
        push_u16(&mut message, 60_000); // rdlength -- no bytes actually follow

        let failure = Message::parse_standard_query_owned_with_recovery(message).unwrap_err();
        assert_eq!(
            failure.error,
            QueryValidationError::InvalidEdns,
            "a non-OPT additional record must be rejected by the cheap precheck, not by a \
             full-parse bounds-check failure"
        );
        let recovered = failure.recovered_message.expect(
            "the question must still be recovered -- proves the cheap precheck path was taken \
             rather than a full-parse attempt that would have discarded it entirely",
        );
        assert_eq!(recovered.questions.len(), 1);
        assert_eq!(recovered.questions[0].qname, "example.com");
        assert!(
            recovered.edns.is_none(),
            "the single additional record isn't OPT, so no EDNS should be recovered"
        );
    }

    /// `skip_name_offset_only` (the allocation-free name-skip used by
    /// `recovery_additional_is_opt`'s precheck) must consume exactly the
    /// same span of bytes `parse_domain_with_context` -- the general,
    /// allocating parser -- would have consumed for an ordinary,
    /// uncompressed multi-label name. If these two ever disagreed on where
    /// a name ends, the precheck would misread the additional record that
    /// follows it.
    #[test]
    fn skip_name_offset_only_matches_parse_domain_with_context_for_simple_name() {
        let mut message = Vec::new();
        push_name(&mut message, "www.example.com");
        message.extend_from_slice(&[0xAB, 0xCD]); // trailing bytes past the name.

        let mut offset_a = 0;
        parse_domain_with_context(&message, &mut offset_a, None).unwrap();

        let mut offset_b = 0;
        skip_name_offset_only(&message, &mut offset_b).unwrap();

        assert_eq!(offset_a, offset_b);
    }

    /// Same equivalence check as above, but for a name that ends in a
    /// compression pointer instead of a literal root byte -- the branch
    /// `skip_name_offset_only` handles differently (bounded hop count
    /// instead of a visited-offset `HashSet`) from
    /// `parse_domain_with_context`.
    #[test]
    fn skip_name_offset_only_matches_parse_domain_with_context_for_compressed_name() {
        let mut message = Vec::new();
        push_name(&mut message, "example.com"); // occupies offsets 0..=12
        let pointer_target = message.len();
        message.extend_from_slice(b"\x03www"); // an unterminated label, only reachable via the pointer below.
        push_pointer(&mut message, 0); // "www" + pointer back to "example.com" at offset 0.
        message.extend_from_slice(&[0xAB, 0xCD]); // trailing bytes past the name.

        let mut offset_a = pointer_target;
        parse_domain_with_context(&message, &mut offset_a, None).unwrap();

        let mut offset_b = pointer_target;
        skip_name_offset_only(&message, &mut offset_b).unwrap();

        assert_eq!(offset_a, offset_b);
    }

    /// Regression test: a pointer-and-label layout that forms a cycle
    /// (offset A points to offset B, but the label at B walks the cursor
    /// forward past A again) must still terminate in bounded work instead
    /// of hanging, even though `skip_name_offset_only` doesn't track every
    /// visited offset the way `parse_domain_with_context`'s `HashSet`
    /// does. See `MAX_POINTER_HOPS`'s docs for why a bare
    /// "pointer must point strictly backward" check alone doesn't already
    /// rule this out.
    ///
    /// Since the cumulative wire-length cap was added (mirroring
    /// `parse_domain_with_context`'s `MAX_NAME_LEN` accounting), every
    /// repetition of this loop's label also grows the cumulative wire
    /// length by a fixed, nonzero amount (a compression pointer can only
    /// ever move the cursor *backward*, so any cycle's forward progress
    /// must come from re-walking at least one label each time around).
    /// With a 6-byte-per-lap loop, that means the 255-byte length cap is
    /// exceeded after roughly 43 laps -- long before `MAX_POINTER_HOPS`
    /// (128) would ever fire -- so this construction now terminates via
    /// `InvalidLabel`, not `PointerLoop`. That's still correct: the
    /// malformed cycle is still rejected in bounded work, just via the
    /// length cap instead of the hop cap this time. `MAX_POINTER_HOPS`
    /// remains as an independent backstop bound on redirect-following work
    /// regardless of which check ends up firing first for a given input.
    #[test]
    fn skip_name_offset_only_detects_pointer_loop_without_hanging() {
        // Offsets 0..=5: a 5-byte label ("AAAAA"), consuming exactly the
        // span that lands back on offset 6 when walked.
        let mut message = vec![5u8, b'A', b'A', b'A', b'A', b'A'];
        // Offsets 6..=7: a pointer back to offset 0.
        push_pointer(&mut message, 0);

        let mut offset = 6;
        let error = skip_name_offset_only(&message, &mut offset).unwrap_err();
        assert_eq!(
            error,
            DnsParseError::InvalidLabel,
            "the cumulative wire-length cap must catch this cycle -- in bounded work, without \
             hanging -- before the hop cap ever gets a chance to"
        );

        // The full, `HashSet`-tracked parser detects the same cycle far
        // sooner (after just two offset revisits) via its visited-offset
        // tracking, so it still reports `PointerLoop` rather than ever
        // approaching the length cap on this input. Both parsers correctly
        // reject the malformed cycle and both provably terminate; they just
        // use different bounding strategies and so can (as here) disagree
        // on the specific error variant.
        let mut offset = 6;
        let error = parse_domain_with_context(&message, &mut offset, None).unwrap_err();
        assert_eq!(error, DnsParseError::PointerLoop);
    }

    /// Companion regression test proving `MAX_POINTER_HOPS` itself still
    /// bounds work independently of the length cap: a long but strictly
    /// acyclic chain of distinct, always-strictly-backward-pointing
    /// redirects (never revisiting the same offset, so this is not a
    /// `PointerLoop`) that exceeds `MAX_POINTER_HOPS` redirects must still
    /// be rejected rather than followed indefinitely.
    #[test]
    fn skip_name_offset_only_bounds_a_long_acyclic_pointer_chain() {
        // Build MAX_POINTER_HOPS + 1 single-byte root names, each one
        // (other than the first) a two-byte pointer back to the previous
        // one. Every offset is visited exactly once -- this is a straight
        // line, not a cycle -- so only the hop cap (not the length cap,
        // and not a loop detector) can be what rejects it.
        let mut message = vec![0u8]; // offset 0: the bare root label.
        let mut previous_offset = 0usize;
        for _ in 0..(MAX_POINTER_HOPS + 1) {
            let this_offset = message.len();
            push_pointer(&mut message, previous_offset);
            previous_offset = this_offset;
        }

        let mut offset = previous_offset;
        let error = skip_name_offset_only(&message, &mut offset).unwrap_err();
        assert_eq!(
            error,
            DnsParseError::PointerLoop,
            "a chain with more than MAX_POINTER_HOPS redirects must be rejected even though it \
             never revisits an offset and never approaches the length cap"
        );
    }

    /// Regression test: `skip_name_offset_only` must enforce the same
    /// RFC 1035 §3.1 255-byte cumulative wire-format name-length limit
    /// (`MAX_NAME_LEN`) that `parse_domain_with_context` already enforces.
    /// Before this fix, the offset-only skipper tracked individual label
    /// lengths and buffer bounds but no *cumulative* wire length at all, so
    /// an overlong name the authoritative full parser rejects as
    /// `InvalidLabel` could still be walked past successfully by this
    /// cheap precheck -- letting it walk more attacker-controlled bytes
    /// than the real parser allows, and silently disagreeing with it about
    /// what counts as a validly-shaped name.
    #[test]
    fn skip_name_offset_only_enforces_max_name_len_like_parse_domain_with_context() {
        // Four 63-byte labels: each contributes `length + 1 == 64` wire
        // bytes, so the fourth label pushes the cumulative wire length to
        // `1 + 4 * 64 == 257`, past `MAX_NAME_LEN` (255) -- the same
        // accounting convention `parse_domain_with_context` uses (see its
        // `wire_len` tracking).
        let label = "a".repeat(63);
        let name = format!("{label}.{label}.{label}.{label}");
        let mut message = Vec::new();
        push_name(&mut message, &name);

        let mut offset_a = 0;
        let error_a = parse_domain_with_context(&message, &mut offset_a, None).unwrap_err();
        assert_eq!(error_a, DnsParseError::InvalidLabel);

        let mut offset_b = 0;
        let error_b = skip_name_offset_only(&message, &mut offset_b).unwrap_err();
        assert_eq!(
            error_b, error_a,
            "skip_name_offset_only must reject an overlong name with the same error the \
             authoritative full parser uses, at the same boundary, instead of silently \
             succeeding where parse_domain_with_context would fail"
        );
    }

    /// Regression test guarding the actual perf fix: a normal, valid EDNS
    /// query with a many-label question name near the 255-byte wire-format
    /// maximum (RFC 1035 §3.1) must still be accepted by
    /// `parse_standard_query_owned_with_recovery`. Before this fix, the
    /// `ar_count == 1` precheck (`recovery_additional_is_opt`) skipped the
    /// question with the fully allocating `skip_questions` /
    /// `parse_domain_with_context` on every such query -- correct, but
    /// wasteful, since a normal EDNS query's `ar_count` is always exactly
    /// 1 (the OPT pseudo-record), not a rare/malformed shape. This proves
    /// the new allocation-free `skip_name_offset_only` path is still
    /// correct on a large, many-label name, not just cheaper.
    #[test]
    fn recovery_precheck_accepts_valid_edns_query_with_near_max_length_question_name() {
        let label_a = "a".repeat(63);
        let label_b = "b".repeat(60);
        let name = format!("{label_a}.{label_a}.{label_a}.{label_b}");

        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1);
        push_question(&mut message, &name, 1, 1);
        push_opt_record(&mut message, 4096, true, &[]);

        let parsed = Message::parse_standard_query_owned_with_recovery(message).expect(
            "a many-label question name near the 255-byte wire-format maximum must still let \
             the allocation-free precheck correctly reach and classify the OPT additional \
             record",
        );
        assert_eq!(parsed.questions[0].qname, name);
        let edns = parsed
            .edns
            .expect("the OPT additional record must still be recognized");
        assert!(edns.dnssec_ok);
        assert_eq!(edns.udp_payload_size, 4096);
    }

    /// Companion to the near-max-length-name test above, exercising
    /// `recovery_additional_is_opt` directly (rather than through
    /// `parse_standard_query_owned_with_recovery`) with a question name
    /// that ends in a compression pointer -- `skip_name_offset_only`'s
    /// pointer-following branch, not just its plain-label branch. This is
    /// deliberately a unit-level test of the precheck rather than an
    /// end-to-end one: the strict, `ParseContext`-checked full parser
    /// (`Self::parse_owned`) can never legitimately accept a pointer in a
    /// message's very *first* name -- there's nothing prior for it to
    /// validly reference (see
    /// `recovery_rejects_opt_with_compression_pointer_owner_even_if_it_targets_a_zero_byte`
    /// for the same constraint on an OPT owner name) -- but the cheap,
    /// context-free precheck only needs to reach the additional section,
    /// not validate the pointer's legitimacy, so it must still follow it
    /// correctly.
    #[test]
    fn recovery_additional_is_opt_follows_compressed_question_name() {
        let mut message = Vec::new();
        push_u16(&mut message, 0x0000); // ID -- byte 0 is 0x00, the pointer target below.
        push_u16(&mut message, 0x0100); // flags: opcode 0 (supported), RD = 1
        push_u16(&mut message, 1); // qd_count
        push_u16(&mut message, 0); // an_count
        push_u16(&mut message, 0); // ns_count
        push_u16(&mut message, 1); // ar_count
        // Question name: a two-byte compression pointer aimed at offset 0
        // (the message's own ID high byte, deliberately 0x00) instead of a
        // literal root byte.
        push_pointer(&mut message, 0);
        push_u16(&mut message, 1); // qtype
        push_u16(&mut message, 1); // qclass
        push_opt_record(&mut message, 4096, false, &[]);

        let header = parse_header(&message).unwrap();
        let is_opt = recovery_additional_is_opt(&message, &header).unwrap();
        assert!(
            is_opt,
            "the precheck must follow the compression-pointer question name (without \
             materializing it) to correctly reach and classify the OPT additional record \
             that follows"
        );
    }

    /// Regression test guarding the perf fix on top of last round's: the
    /// canonical-root-owned OPT case (`ar_count == 1`, the normal shape of
    /// every real EDNS query) must classify correctly *and* never invoke
    /// the allocating `parse_domain_with_context` at all when reading the
    /// additional record's owner name -- not even with `context: None`.
    /// Before this fix, `recovery_additional_is_opt` still ran the
    /// additional owner through `parse_domain_with_context` on every such
    /// query even though a real OPT owner is always the single canonical
    /// `0x00` byte, so there was nothing to parse. Uses the
    /// `PARSE_DOMAIN_WITH_CONTEXT_CALLS` counter (see its docs) to prove
    /// the absence of the call directly, rather than only inferring it
    /// indirectly from timing or correctness.
    #[test]
    fn recovery_additional_is_opt_root_owner_fast_path_skips_domain_parser() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1);
        push_question(&mut message, "example.com", 1, 1);
        push_opt_record(&mut message, 4096, false, &[]);

        let header = parse_header(&message).unwrap();

        reset_parse_domain_with_context_call_count();
        let is_opt = recovery_additional_is_opt(&message, &header).unwrap();
        assert!(
            is_opt,
            "a canonical root-owned OPT additional record must still be classified as OPT"
        );
        assert_eq!(
            parse_domain_with_context_call_count(),
            0,
            "the canonical-root-owner fast path must never call the allocating domain parser"
        );
    }

    /// Companion to the fast-path test above: a non-root-owned additional
    /// record (so the fast path can't apply) must still be classified
    /// correctly by falling back to the allocation-free
    /// `skip_name_offset_only` -- and, like the fast path, must still never
    /// call the allocating `parse_domain_with_context`, since this
    /// precheck never needs the decoded name, only where it ends.
    #[test]
    fn recovery_additional_is_opt_non_root_owner_fallback_skips_domain_parser() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1);
        push_question(&mut message, "example.com", 1, 1);
        // A non-canonical, multi-label owner name on the additional
        // record, so the record can never pass the canonical-root-owner
        // check regardless of its declared type.
        push_record(
            &mut message,
            "not-root.example.com",
            OPT_RECORD_TYPE,
            0,
            &[],
        );

        let header = parse_header(&message).unwrap();

        reset_parse_domain_with_context_call_count();
        let is_opt = recovery_additional_is_opt(&message, &header).unwrap();
        assert!(
            !is_opt,
            "a non-canonical-root-owned additional record must never be classified as OPT, \
             even when its declared type is OPT_RECORD_TYPE"
        );
        assert_eq!(
            parse_domain_with_context_call_count(),
            0,
            "the non-root-owner fallback must skip the name with the allocation-free \
             skip_name_offset_only, never the allocating domain parser"
        );
    }

    /// Regression test: `recovery_find_opt_in_additionals` must only treat
    /// an additional record as root-owned (RFC 6891 §6.1.2) when its owner
    /// name uses the canonical, unambiguous single `0x00` byte encoding --
    /// never a compression pointer, even one that pointer-chases to an
    /// "empty" name. `parse_domain_with_context(.., None)` (used throughout
    /// recovery, since a full `ParseContext` isn't available on this
    /// bounded path) only requires a compression pointer to point strictly
    /// backward in the message; it never confirms the target is a
    /// legitimate prior domain-name occurrence (RFC 1035 §4.1.4). This
    /// constructs an OPT-typed additional record whose owner name is the
    /// two-byte pointer `0xC0 0x00`, aimed at message offset 0 -- which
    /// this packet's ID field is deliberately set to make `0x00`, so a
    /// naive pointer-chase would decode it as the empty (root) name and
    /// spoof RFC 6891 §6.1.2's root-owner requirement.
    #[test]
    fn recovery_rejects_opt_with_compression_pointer_owner_even_if_it_targets_a_zero_byte() {
        let mut message = Vec::new();
        push_u16(&mut message, 0x0000); // ID -- byte 0 is 0x00, the pointer target below.
        push_u16(&mut message, 0x0900); // flags: opcode = 1 (unsupported), RD = 1
        push_u16(&mut message, 1); // qd_count
        push_u16(&mut message, 0); // an_count
        push_u16(&mut message, 0); // ns_count
        push_u16(&mut message, 1); // ar_count
        push_question(&mut message, "example.com", 1, 1);
        // Additional record: owner name is a compression pointer aimed at
        // offset 0 (the message header, byte 0x00) instead of the
        // canonical uncompressed root byte real OPT records use.
        push_pointer(&mut message, 0);
        push_u16(&mut message, OPT_RECORD_TYPE);
        push_u16(&mut message, 4096); // rclass / udp payload size
        push_u32(&mut message, 0); // ttl (extended rcode/version/flags all 0)
        push_u16(&mut message, 0); // rdlength

        let failure = Message::parse_standard_query_owned_with_recovery(message).unwrap_err();
        assert_eq!(
            failure.error,
            QueryValidationError::UnsupportedOpcode { opcode: 1 }
        );
        let recovered = failure
            .recovered_message
            .expect("the header and question should still be recovered");
        assert_eq!(recovered.questions.len(), 1);
        assert_eq!(recovered.questions[0].qname, "example.com");
        assert!(
            recovered.edns.is_none(),
            "a compression-pointer-encoded owner name must never be accepted as a canonical \
             root OPT owner, even when the pointer happens to target a zero byte"
        );
    }

    /// Regression test: the *primary* (non-recovery) record parser,
    /// `parse_record`, must apply the same canonical-root-owner requirement
    /// (RFC 6891 §6.1.2) that recovery already enforces -- not just
    /// `name.is_empty()`. This constructs a query whose OPT record's owner
    /// name is a two-byte compression pointer aimed at the question's own
    /// terminating root-label byte: a *legitimate* prior root-label
    /// occurrence that `ParseContext` (built from the real, unbounded
    /// primary parse, unlike recovery's `context: None`) would happily
    /// validate as a proper backward-pointing reference, decoding to "".
    /// Before this fix, `parse_record` accepted this shape as valid EDNS
    /// because it only checked `name.is_empty()`, silently disagreeing with
    /// the newly-hardened recovery scanner about what counts as a valid OPT
    /// owner. Real OPT records are always emitted with the direct,
    /// uncompressed root byte, so even a strictly valid compression pointer
    /// must still be rejected here.
    #[test]
    fn parse_record_rejects_compression_pointer_opt_owner_even_when_context_validates_it() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1); // opcode 0 (supported), qd=1, ar=1
        push_name(&mut message, "example.com");
        // The question name's own terminating root-label byte -- a
        // legitimate prior domain-name occurrence per RFC 1035 §4.1.4,
        // which the primary parser's real `ParseContext` will register and
        // later validate a pointer against.
        let root_offset = message.len() - 1;
        push_u16(&mut message, 1); // qtype: A
        push_u16(&mut message, 1); // qclass: IN
        // The additional record's owner name: a compression pointer at the
        // question's root-label byte, instead of the canonical direct
        // `0x00` encoding real OPT records use.
        push_pointer(&mut message, root_offset);
        push_u16(&mut message, OPT_RECORD_TYPE);
        push_u16(&mut message, 4096); // rclass / udp payload size
        push_u32(&mut message, 0); // ttl: extended rcode/version/flags all 0
        push_u16(&mut message, 0); // rdlength

        let error = Message::parse(&message).unwrap_err();
        assert_eq!(
            error,
            DnsParseError::MalformedRecord,
            "a compression-pointer-encoded OPT owner name must be rejected on the primary \
             parse path even when it legitimately resolves to root via a valid ParseContext"
        );
    }

    /// Regression test: when `parse_header` and `validate_standard_query_header`
    /// both succeed -- meaning the header, including the CD bit, was read
    /// successfully -- but the subsequent `Self::parse_owned` body parse
    /// then fails for an unrelated reason (here, a malformed question the
    /// header-level checks don't inspect), `recovered_message` must not
    /// collapse to `None` and silently drop the already-readable CD bit.
    /// Per RFC 4035 §3.2.2 a security-aware recursive name server MUST copy
    /// CD from query to response; there's no reason a malformed body should
    /// cost the query its CD echo when the header was perfectly parseable.
    /// This also drives the recovered message through
    /// `build_question_aware_error_response` end-to-end to confirm the
    /// eventual FORMERR response actually carries CD=1, not just that
    /// `recovered_message` is non-`None` in isolation.
    #[test]
    fn cd_is_recovered_when_body_parse_fails_after_valid_header() {
        let mut message = Vec::new();
        push_header_with_flags(&mut message, 0x0110, 1, 0, 0, 0); // RD=1, CD=1, qd=1, no additionals
        // A single label-length octet using the reserved `0b10` top-bit
        // pattern -- neither a normal label (`0b00`) nor a compression
        // pointer (`0b11`) -- which `parse_domain_with_context` rejects
        // with `InvalidLabel`. `validate_standard_query_header` never looks
        // at question bytes, so this fails only once `Self::parse_owned`
        // actually tries to parse the question.
        message.push(0b1000_0000);

        let failure = Message::parse_standard_query_owned_with_recovery(message).unwrap_err();
        assert_eq!(
            failure.error,
            QueryValidationError::Parse(DnsParseError::InvalidLabel),
            "the malformed question must surface as the authoritative Self::parse_owned error"
        );
        let recovered = failure.recovered_message.expect(
            "the header -- including CD -- was fully readable before the body-parse failure, \
             so recovery must not collapse to None",
        );
        assert!(
            recovered.header.cd(),
            "CD must still be recovered per RFC 4035 §3.2.2 even when the body (here, the \
             question itself) could not be parsed at all"
        );
        assert!(
            recovered.questions.is_empty(),
            "the question itself was unparseable, so it correctly isn't recovered"
        );

        let configured_max_udp_payload_size = 1232;
        let response = build_question_aware_error_response(
            Some(&recovered),
            None,
            ResponseCode::FormErr,
            configured_max_udp_payload_size,
        );
        let parsed = Message::parse(&response).unwrap();
        assert!(
            parsed.header.cd(),
            "the FORMERR response actually sent to the client must still echo CD=1, even \
             though no question/OPT could be recovered"
        );
        assert_eq!(parsed.header.r_code(), ResponseCode::FormErr.as_u8());
    }

    #[test]
    fn parse_standard_query_accepts_single_edns_opt_additional() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1);
        push_question(&mut message, "example.com", 1, 1);
        push_opt_record(&mut message, 4096, true, &[0, 15, 0, 0]);

        let parsed = Message::parse_standard_query(&message).unwrap();
        assert_eq!(
            parsed.edns,
            Some(EdnsInfo {
                udp_payload_size: 4096,
                extended_rcode: 0,
                version: 0,
                flags: EDNS_DO_FLAG,
                dnssec_ok: true,
                options: vec![0, 15, 0, 0],
            })
        );
        assert_eq!(parsed.effective_udp_payload_size(1232), 1232);
        assert!(parsed.response_exceeds_udp_payload(1233, 1232));
        assert!(!parsed.response_exceeds_udp_payload(1232, 1232));
    }

    #[test]
    fn udp_payload_defaults_to_512_without_edns() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 0);
        push_question(&mut message, "example.com", 1, 1);

        let parsed = Message::parse_standard_query(&message).unwrap();
        assert_eq!(
            parsed.effective_udp_payload_size(1500),
            DNS_DEFAULT_UDP_PAYLOAD_SIZE
        );
        assert_eq!(parsed.effective_udp_payload_size(400), 400);
    }

    #[test]
    fn edns_udp_payload_below_default_is_treated_as_default() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1);
        push_question(&mut message, "example.com", 1, 1);
        push_opt_record(&mut message, 128, false, &[]);

        let parsed = Message::parse_standard_query(&message).unwrap();
        assert_eq!(
            parsed.effective_udp_payload_size(1500),
            DNS_DEFAULT_UDP_PAYLOAD_SIZE
        );
    }

    #[test]
    fn malformed_edns_option_returns_parse_error() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1);
        push_question(&mut message, "example.com", 1, 1);
        push_opt_record(&mut message, 1232, false, &[0, 15, 0, 4, 1, 2]);

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::Parse(DnsParseError::UnexpectedEof))
        );
    }

    #[test]
    fn parse_standard_query_rejects_response_packet() {
        let mut message = Vec::new();
        push_header_with_flags(&mut message, 0x8100, 1, 0, 0, 0);
        push_question(&mut message, "example.com", 1, 1);

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::NotQuery)
        );
    }

    #[test]
    fn parse_standard_query_rejects_unsupported_opcode() {
        let mut message = Vec::new();
        push_header_with_flags(&mut message, 0x0900, 1, 0, 0, 0);
        push_question(&mut message, "example.com", 1, 1);

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::UnsupportedOpcode { opcode: 1 })
        );
    }

    #[test]
    fn query_validation_errors_map_to_response_codes() {
        assert_eq!(
            QueryValidationError::UnsupportedOpcode { opcode: 1 }.response_code(),
            ResponseCode::NotImp
        );
        assert_eq!(
            QueryValidationError::InvalidQuestionCount { count: 2 }.response_code(),
            ResponseCode::FormErr
        );
        assert_eq!(
            QueryValidationError::Parse(DnsParseError::UnexpectedEof).response_code(),
            ResponseCode::FormErr
        );
    }

    #[test]
    fn parse_standard_query_rejects_zero_questions() {
        let mut message = Vec::new();
        push_header(&mut message, 0, 0, 0, 0);

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::InvalidQuestionCount { count: 0 })
        );
    }

    #[test]
    fn parse_standard_query_rejects_multiple_questions() {
        let mut message = Vec::new();
        push_header(&mut message, 2, 0, 0, 0);
        push_question(&mut message, "example.com", 1, 1);
        push_question(&mut message, "example.net", 1, 1);

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::InvalidQuestionCount { count: 2 })
        );
    }

    #[test]
    fn parse_standard_query_rejects_unexpected_section_records() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 1, 0, 0);
        push_question(&mut message, "example.com", 1, 1);

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::UnexpectedSectionRecords {
                answers: 1,
                authorities: 0,
                additionals: 0
            })
        );
    }

    #[test]
    fn parse_standard_query_rejects_multiple_additionals_before_body() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 2);
        push_question(&mut message, "example.com", 1, 1);

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::UnexpectedSectionRecords {
                answers: 0,
                authorities: 0,
                additionals: 2
            })
        );
    }

    #[test]
    fn parse_standard_query_rejects_non_edns_additional() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1);
        push_question(&mut message, "example.com", 1, 1);
        push_record(&mut message, "example.com", 1, 300, &[1, 2, 3, 4]);

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::InvalidEdns)
        );
    }

    /// RFC 6891 §6.1.3: rdns implements EDNS version 0 only. A query
    /// advertising a nonzero version must be rejected distinctly from a
    /// generic malformed-EDNS query, so the resolver layer can answer
    /// BADVERS instead of FORMERR (see `build_badvers_response` and
    /// `resolver::BasicResponseFactory::protocol_error`). The coarse
    /// `response_code()` classifier still buckets it as `FormErr` --
    /// that's a metrics/event simplification, not the actual wire
    /// behavior; see that method's doc comment.
    #[test]
    fn parse_standard_query_rejects_unsupported_edns_version() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 0, 0, 1);
        push_question(&mut message, "example.com", 1, 1);
        push_opt_record_with_version(&mut message, 1232, false, 7, &[]);

        let error = Message::parse_standard_query(&message).unwrap_err();
        assert_eq!(
            error,
            QueryValidationError::UnsupportedEdnsVersion { version: 7 }
        );
        assert_eq!(error.response_code(), ResponseCode::FormErr);
    }

    #[test]
    fn parse_standard_query_validates_shape_before_body() {
        let mut message = Vec::new();
        push_header(&mut message, 2, 0, 0, 0);
        push_name(&mut message, "example.com");

        assert_eq!(
            Message::parse_standard_query(&message),
            Err(QueryValidationError::InvalidQuestionCount { count: 2 })
        );
    }

    #[test]
    fn parse_standard_query_preserves_parse_errors() {
        assert_eq!(
            Message::parse_standard_query(&[0; 11]),
            Err(QueryValidationError::Parse(DnsParseError::UnexpectedEof))
        );
    }

    #[test]
    fn build_formerr_response_has_request_id_and_rcode() {
        let response = build_formerr_response(0xbeef);
        let parsed = Message::parse(&response).unwrap();

        assert_eq!(parsed.header.id, 0xbeef);
        assert!(parsed.header.qr());
        assert_eq!(parsed.header.r_code(), ResponseCode::FormErr.as_u8());
        assert!(parsed.questions.is_empty());
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn build_servfail_response_with_request_preserves_question_and_rd() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        request[0..2].copy_from_slice(&0xbeefu16.to_be_bytes());
        push_question(&mut request, "example.com", 1, 1);
        let request = Message::parse_standard_query(&request).unwrap();

        let response =
            Message::parse(&build_servfail_response(Some(&request), None, 1232)).unwrap();

        assert_eq!(response.header.id, 0xbeef);
        assert!(response.header.rd());
        assert_eq!(response.header.r_code(), ResponseCode::ServFail.as_u8());
        assert_eq!(response.questions[0], request.questions[0]);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn build_servfail_response_without_request_uses_supplied_id() {
        let response = build_servfail_response(None, Some(0x1234), 1232);
        let parsed = Message::parse(&response).unwrap();

        assert_eq!(parsed.header.id, 0x1234);
        assert_eq!(parsed.header.r_code(), ResponseCode::ServFail.as_u8());
        assert!(parsed.questions.is_empty());
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn build_refused_nxdomain_and_nodata_responses_include_question() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "example.com", 1, 1);
        let request = Message::parse_standard_query(&request).unwrap();

        let refused = Message::parse(&build_refused_response(&request, 1232)).unwrap();
        assert_eq!(refused.header.r_code(), ResponseCode::Refused.as_u8());
        assert_eq!(refused.questions[0], request.questions[0]);
        assert!(refused.answers.is_empty());

        let nxdomain = Message::parse(&build_nxdomain_response(&request, 1232)).unwrap();
        assert_eq!(nxdomain.header.r_code(), ResponseCode::NxDomain.as_u8());
        assert_eq!(nxdomain.questions[0], request.questions[0]);

        let nodata = Message::parse(&build_nodata_response(&request, 1232)).unwrap();
        assert_eq!(nodata.header.r_code(), ResponseCode::NoError.as_u8());
        assert!(nodata.answers.is_empty());
    }

    /// Regression test for the OPT/CD gap Codex's DNS-compliance review
    /// caught (Finding C): every generic failure/policy-block builder
    /// (SERVFAIL, REFUSED, NXDOMAIN, NODATA, sinkhole) flowed through
    /// `build_question_response`/`write_response_header`, which hardcoded
    /// ARCOUNT=0 and never copied CD -- so an EDNS+CD=1 requester got back
    /// a response with no OPT record (RFC 6891 §6.1.1) and CD silently
    /// reset to 0 (RFC 4035 §3.2.2) on every one of these response types.
    ///
    /// The request advertises a UDP payload size (1232) deliberately
    /// different from `configured_max_udp_payload_size` (700) passed to
    /// each builder below: per RFC 6891 §6.1.1 the OPT record on a
    /// *response* must describe the responder's own size, never an echo of
    /// the requester's -- if this ever regresses back to echoing 1232, this
    /// assertion catches it.
    #[test]
    fn build_question_response_family_mirrors_opt_and_cd_for_edns_requester() {
        let mut request = Vec::new();
        push_header_with_flags(&mut request, 0x0110, 1, 0, 0, 1); // RD=1, CD=1
        push_question(&mut request, "example.com", 1, 1);
        push_opt_record(&mut request, 1232, true, &[]);
        let request = Message::parse_standard_query(&request).unwrap();
        assert!(request.header.cd());
        assert!(request.edns.is_some());

        let configured_max_udp_payload_size = 700;
        let responses = [
            (
                "refused",
                build_refused_response(&request, configured_max_udp_payload_size),
            ),
            (
                "nxdomain",
                build_nxdomain_response(&request, configured_max_udp_payload_size),
            ),
            (
                "nodata",
                build_nodata_response(&request, configured_max_udp_payload_size),
            ),
            (
                "servfail",
                build_servfail_response(Some(&request), None, configured_max_udp_payload_size),
            ),
            (
                "sinkhole_a",
                build_a_block_response(
                    &request,
                    Ipv4Addr::new(10, 0, 0, 1),
                    60,
                    configured_max_udp_payload_size,
                ),
            ),
        ];

        for (label, response) in responses {
            let parsed = Message::parse(&response).unwrap();
            assert!(
                parsed.header.cd(),
                "{label}: CD must be copied from an EDNS+CD=1 request"
            );
            let opt = parsed
                .additionals
                .iter()
                .find(|record| matches!(record.record, RecordData::OPT(_)));
            let Some(Record {
                record: RecordData::OPT(edns),
                ..
            }) = opt
            else {
                panic!("{label}: expected a mirrored OPT record in the additional section");
            };
            assert_eq!(
                edns.udp_payload_size, 700,
                "{label}: OPT must advertise this responder's own UDP payload size, \
                 not echo the requester's 1232"
            );
            assert!(edns.dnssec_ok, "{label}");
            assert_eq!(
                parsed.header.ar_count, 1,
                "{label}: ARCOUNT must include the OPT"
            );
        }
    }

    #[test]
    fn build_question_response_family_omits_opt_for_non_edns_requester() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "example.com", 1, 1);
        let request = Message::parse_standard_query(&request).unwrap();
        assert!(request.edns.is_none());
        assert!(!request.header.cd());

        for response in [
            build_refused_response(&request, 1232),
            build_nxdomain_response(&request, 1232),
            build_nodata_response(&request, 1232),
        ] {
            let parsed = Message::parse(&response).unwrap();
            assert!(!parsed.header.cd());
            assert!(
                parsed.additionals.is_empty(),
                "a non-EDNS requester must not get an OPT record back"
            );
            assert_eq!(parsed.header.ar_count, 0);
        }
    }

    /// RFC 6891 §6.1.3: BADVERS is extended RCODE 16, a 12-bit value split
    /// across the header's 4-bit RCODE field (the low nibble, which must be
    /// 0 here) and the OPT record's 8-bit extended-RCODE byte (which must
    /// be 1). This asserts the *combined* value rather than either half in
    /// isolation, since checking only the header nibble (always 0) or only
    /// the OPT byte would each pass even if the split were wrong.
    #[test]
    fn build_badvers_response_encodes_extended_rcode_and_mirrors_opt_and_cd() {
        let mut request = Vec::new();
        push_header_with_flags(&mut request, 0x0110, 1, 0, 0, 1); // RD=1, CD=1
        push_question(&mut request, "example.com", 1, 1);
        push_opt_record_with_version(&mut request, 4096, true, 7, &[]);
        let request = Message::parse(&request).unwrap();
        assert!(request.header.cd());

        let configured_max_udp_payload_size = 700;
        let response = Message::parse(&build_badvers_response(
            &request,
            configured_max_udp_payload_size,
        ))
        .unwrap();

        assert_eq!(response.header.id, request.header.id);
        assert_eq!(response.questions[0], request.questions[0]);
        assert!(
            response.header.cd(),
            "CD must be copied from the request per RFC 4035 §3.2.2"
        );

        let opt = response
            .additionals
            .iter()
            .find_map(|record| match &record.record {
                RecordData::OPT(info) => Some(info),
                _ => None,
            })
            .expect("expected an OPT record in the BADVERS response");
        let combined_extended_rcode =
            (u16::from(opt.extended_rcode) << 4) | u16::from(response.header.r_code());
        assert_eq!(combined_extended_rcode, 16, "16 == BADVERS");
        assert_eq!(
            opt.version, 0,
            "the response OPT must advertise the version rdns actually supports"
        );
        assert_eq!(
            opt.udp_payload_size, 700,
            "OPT must advertise this responder's own UDP payload size, not echo the requester's 4096"
        );
        assert!(
            opt.dnssec_ok,
            "DO should still be mirrored on a BADVERS response"
        );
    }

    #[test]
    fn build_sinkhole_a_response_serializes_answer() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "blocked.example", 1, 1);
        let request = Message::parse_standard_query(&request).unwrap();

        let response = Message::parse(&build_a_block_response(
            &request,
            Ipv4Addr::new(10, 0, 0, 1),
            60,
            1232,
        ))
        .unwrap();

        assert_eq!(response.header.r_code(), ResponseCode::NoError.as_u8());
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].name, "blocked.example");
        assert_eq!(response.answers[0].ttl, 60);
        assert_eq!(
            response.answers[0].record,
            RecordData::A(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn build_sinkhole_a_response_compresses_repeated_question_name() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "blocked.example", 1, 1);
        let request = Message::parse_standard_query(&request).unwrap();

        let bytes = build_a_block_response(&request, Ipv4Addr::new(10, 0, 0, 1), 60, 1232);

        // The answer's owner name repeats the question name verbatim, so it
        // should be a 2-byte compression pointer rather than the full label
        // sequence written out again.
        let pointer_count = bytes.windows(2).filter(|w| w[0] & 0xC0 == 0xC0).count();
        assert_eq!(
            pointer_count, 1,
            "expected one compression pointer in {bytes:?}"
        );

        let response = Message::parse(&bytes).unwrap();
        assert_eq!(response.answers[0].name, "blocked.example");
    }

    #[test]
    fn build_sinkhole_aaaa_response_serializes_answer() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "blocked.example", 28, 1);
        let request = Message::parse_standard_query(&request).unwrap();
        let sinkhole = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let response =
            Message::parse(&build_aaaa_block_response(&request, sinkhole, 30, 1232)).unwrap();

        assert_eq!(response.header.r_code(), ResponseCode::NoError.as_u8());
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, 30);
        assert_eq!(response.answers[0].record, RecordData::AAAA(sinkhole));
    }

    #[test]
    fn build_truncated_wire_response_includes_question_cd_and_mirrored_opt() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "example.com", 1, 1);
        let request = Message::parse_standard_query(&request).unwrap();
        let question_wire = message_question_wire(&request).unwrap();
        let opt = build_opt_record(1232, true);

        let response = Message::parse(&build_truncated_wire_response(
            request.header.id,
            request.header.rd(),
            false,
            true,
            ResponseCode::NxDomain,
            &question_wire,
            Some(&opt),
        ))
        .unwrap();

        assert!(response.header.tc());
        assert!(response.header.cd());
        assert_eq!(response.header.r_code(), ResponseCode::NxDomain as u8);
        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.questions[0].qname, "example.com");
        assert!(response.answers.is_empty());
        assert!(
            response
                .additionals
                .iter()
                .any(|record| matches!(record.record, RecordData::OPT(_))),
            "a truncated response to an EDNS requester must still carry a mirrored OPT record \
             (RFC 6891 §7)"
        );
    }

    #[test]
    fn build_truncated_wire_response_without_opt_omits_additional_section() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "example.com", 1, 1);
        let request = Message::parse_standard_query(&request).unwrap();
        let question_wire = message_question_wire(&request).unwrap();

        let response = Message::parse(&build_truncated_wire_response(
            request.header.id,
            request.header.rd(),
            false,
            false,
            ResponseCode::NoError,
            &question_wire,
            None,
        ))
        .unwrap();

        assert!(response.header.tc());
        assert!(!response.header.cd());
        assert_eq!(response.questions.len(), 1);
        assert!(response.additionals.is_empty());
    }

    #[test]
    fn rewrite_response_id_updates_first_two_bytes() {
        let mut response = build_formerr_response(0x1111);
        rewrite_response_id(&mut response, 0x2222).unwrap();

        assert_eq!(Message::parse(&response).unwrap().header.id, 0x2222);
        assert_eq!(
            rewrite_response_id(&mut [0u8; 1], 0x3333),
            Err(DnsParseError::MessageTooShort)
        );
    }

    // Regression tests for RFC 4035 §3.2.2: `rewrite_response_request_fields`
    // must copy the *rewriting request's own* CD bit onto a shared/reused
    // backend response, not merely its RD bit -- a single-flight follower
    // falling back to its leader's raw fetch result must never inherit the
    // leader's CD bit when the two differ. Both directions are checked: a
    // CD=1 follower behind a CD=0 leader's bytes, and the reverse.

    fn request_with_flags(flags: u16) -> Message {
        let mut request = Vec::new();
        push_header_with_flags(&mut request, flags, 1, 0, 0, 0);
        push_question(&mut request, "example.com", 1, 1);
        Message::parse_standard_query(&request).unwrap()
    }

    #[test]
    fn rewrite_response_request_fields_sets_cd_when_request_has_cd_but_response_does_not() {
        // QR=1, CD=0 in the shared response bytes.
        let mut response = Vec::new();
        push_header_with_flags(&mut response, 0x8000, 1, 0, 0, 0);
        push_question(&mut response, "example.com", 1, 1);

        // The rewriting request has RD=0, CD=1 -- both differ from the
        // shared response's current flags.
        let request = request_with_flags(0x0010);

        rewrite_response_request_fields(&mut response, &request).unwrap();

        let parsed = Message::parse(&response).unwrap();
        assert!(
            parsed.header.cd(),
            "the response must carry the rewriting request's own CD=1, not the shared bytes' CD=0"
        );
        assert!(!parsed.header.rd());
        assert_eq!(parsed.header.id, request.header.id);
    }

    #[test]
    fn rewrite_response_request_fields_clears_cd_when_request_has_no_cd_but_response_does() {
        // QR=1, RD=1, CD=1 in the shared response bytes (e.g. built to
        // satisfy a leader whose own request had CD=1).
        let mut response = Vec::new();
        push_header_with_flags(&mut response, 0x8110, 1, 0, 0, 0);
        push_question(&mut response, "example.com", 1, 1);

        // The rewriting (follower) request has RD=1, CD=0.
        let request = request_with_flags(0x0100);

        rewrite_response_request_fields(&mut response, &request).unwrap();

        let parsed = Message::parse(&response).unwrap();
        assert!(
            !parsed.header.cd(),
            "the response must carry the rewriting request's own CD=0, not the shared bytes' CD=1"
        );
        assert!(parsed.header.rd());
    }

    #[test]
    fn tcp_frame_encode_prefixes_message_length() {
        let message = [1, 2, 3, 4];
        let frame = encode_tcp_frame(&message, 512).unwrap();

        assert_eq!(frame, vec![0, 4, 1, 2, 3, 4]);
    }

    #[test]
    fn tcp_frame_encode_rejects_oversized_message() {
        let message = [0u8; 5];

        assert_eq!(
            encode_tcp_frame(&message, 4),
            Err(DnsParseError::TcpFrameTooLarge {
                size: 5,
                max_size: 4
            })
        );
    }

    #[test]
    fn tcp_frame_decode_reports_needed_bytes_for_short_prefix() {
        assert_eq!(
            decode_tcp_frame(&[0], 512),
            Ok(TcpFrameDecodeStatus::NeedMore {
                required_total_len: 2
            })
        );
    }

    #[test]
    fn tcp_frame_decode_reports_needed_bytes_for_partial_payload() {
        assert_eq!(
            decode_tcp_frame(&[0, 4, 1, 2], 512),
            Ok(TcpFrameDecodeStatus::NeedMore {
                required_total_len: 6
            })
        );
    }

    #[test]
    fn tcp_frame_decode_reports_complete_frame() {
        assert_eq!(
            decode_tcp_frame(&[0, 4, 1, 2, 3, 4, 9], 512),
            Ok(TcpFrameDecodeStatus::Complete {
                message_len: 4,
                required_total_len: 6
            })
        );
    }

    #[test]
    fn tcp_frame_decode_rejects_oversized_frame() {
        assert_eq!(
            decode_tcp_frame(&[0, 5, 1, 2, 3, 4, 5], 4),
            Err(DnsParseError::TcpFrameTooLarge {
                size: 5,
                max_size: 4
            })
        );
    }

    #[test]
    fn tcp_frame_payload_returns_complete_payload_only() {
        assert_eq!(tcp_frame_payload(&[0, 3, 7, 8], 512), Ok(None));
        assert_eq!(
            tcp_frame_payload(&[0, 3, 7, 8, 9, 10], 512),
            Ok(Some(&[7, 8, 9][..]))
        );
    }

    #[test]
    fn parse_message_compression_uses_full_message_offsets() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 1, 0, 0);
        let question_name_offset = message.len();
        push_name(&mut message, "example.com");
        push_u16(&mut message, 1);
        push_u16(&mut message, 1);

        push_pointer(&mut message, question_name_offset);
        build_record_header(&mut message, 5, 2, 300);
        push_pointer(&mut message, question_name_offset);

        let parsed = Message::parse(&message).unwrap();
        assert_eq!(parsed.answers[0].name, "example.com");
        assert_eq!(
            parsed.answers[0].record,
            RecordData::CNAME("example.com".to_string())
        );
    }

    #[test]
    fn parse_message_allows_pointer_to_prior_compressed_name() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 2, 0, 0);
        let question_name_offset = message.len();
        push_name(&mut message, "example.com");
        push_u16(&mut message, 1);
        push_u16(&mut message, 1);

        let first_answer_name_offset = message.len();
        push_pointer(&mut message, question_name_offset);
        build_record_header(&mut message, 1, 4, 300);
        message.extend_from_slice(&[1, 2, 3, 4]);

        push_pointer(&mut message, first_answer_name_offset);
        build_record_header(&mut message, 1, 4, 300);
        message.extend_from_slice(&[5, 6, 7, 8]);

        let parsed = Message::parse(&message).unwrap();
        assert_eq!(parsed.answers[0].name, "example.com");
        assert_eq!(parsed.answers[1].name, "example.com");
    }

    #[test]
    fn message_rejects_pointer_to_header_bytes() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 1, 0, 0);
        push_name(&mut message, "example.com");
        push_u16(&mut message, 1);
        push_u16(&mut message, 1);

        push_pointer(&mut message, 0);
        build_record_header(&mut message, 1, 4, 300);
        message.extend_from_slice(&[1, 2, 3, 4]);

        assert_eq!(
            Message::parse(&message),
            Err(DnsParseError::InvalidNamePointer)
        );
    }

    #[test]
    fn message_rejects_pointer_to_middle_of_label() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 1, 0, 0);
        let question_name_offset = message.len();
        push_name(&mut message, "example.com");
        push_u16(&mut message, 1);
        push_u16(&mut message, 1);

        push_pointer(&mut message, question_name_offset + 1);
        build_record_header(&mut message, 1, 4, 300);
        message.extend_from_slice(&[1, 2, 3, 4]);

        assert_eq!(
            Message::parse(&message),
            Err(DnsParseError::InvalidNamePointer)
        );
    }

    #[test]
    fn domain_accepts_max_label_and_name_lengths() {
        let label63 = "a".repeat(63);
        let label61 = "b".repeat(61);
        let mut bytes = Vec::new();
        for label in [&label63, &label63, &label63, &label61] {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);

        let mut offset = 0;
        let parsed = parse_domain(&bytes, &mut offset).unwrap();
        assert_eq!(offset, bytes.len());
        assert_eq!(parsed, format!("{label63}.{label63}.{label63}.{label61}"));
    }

    #[test]
    fn domain_rejects_label_over_sixty_three_bytes() {
        let mut bytes = Vec::new();
        bytes.push(64);
        bytes.extend_from_slice(&[b'a'; 64]);
        bytes.push(0);

        let mut offset = 0;
        assert_eq!(
            parse_domain(&bytes, &mut offset),
            Err(DnsParseError::InvalidLabel)
        );
    }

    #[test]
    fn domain_rejects_name_over_two_hundred_fifty_five_bytes() {
        let label63 = [b'a'; 63];
        let mut bytes = Vec::new();
        for _ in 0..4 {
            bytes.push(63);
            bytes.extend_from_slice(&label63);
        }
        bytes.push(0);

        let mut offset = 0;
        assert_eq!(
            parse_domain(&bytes, &mut offset),
            Err(DnsParseError::InvalidLabel)
        );
    }

    #[test]
    fn parse_record_a() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        build_record_header(&mut bytes, 1, 4, 300);
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let record = parse_test_record(&bytes);
        assert_eq!(record.name, "example.com");
        assert_eq!(record.rtype, 1);
        assert_eq!(record.record, RecordData::A(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn parse_record_aaaa() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        build_record_header(&mut bytes, 28, 16, 120);
        bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let record = parse_test_record(&bytes);
        assert_eq!(
            record.record,
            RecordData::AAAA(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn parse_record_cname() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "alias.example.com");
        let mut rdata = Vec::new();
        push_name(&mut rdata, "target.example.com");
        build_record_header(&mut bytes, 5, rdata.len() as u16, 180);
        bytes.extend_from_slice(&rdata);

        let record = parse_test_record(&bytes);
        assert_eq!(
            record.record,
            RecordData::CNAME("target.example.com".to_string())
        );
    }

    #[test]
    fn parse_record_mx() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        push_u16(&mut rdata, 10);
        push_name(&mut rdata, "mail.example.com");
        build_record_header(&mut bytes, 15, rdata.len() as u16, 300);
        bytes.extend_from_slice(&rdata);

        let record = parse_test_record(&bytes);
        assert_eq!(
            record.record,
            RecordData::MX {
                preference: 10,
                exchange: "mail.example.com".to_string()
            }
        );
    }

    #[test]
    fn parse_record_srv() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "_sip._tcp.example.com");
        let mut rdata = Vec::new();
        push_u16(&mut rdata, 10);
        push_u16(&mut rdata, 5);
        push_u16(&mut rdata, 5060);
        push_name(&mut rdata, "sip.example.com");
        build_record_header(&mut bytes, 33, rdata.len() as u16, 60);
        bytes.extend_from_slice(&rdata);

        let record = parse_test_record(&bytes);
        assert_eq!(
            record.record,
            RecordData::SRV {
                priority: 10,
                weight: 5,
                port: 5060,
                target: "sip.example.com".to_string()
            }
        );
    }

    #[test]
    fn parse_record_soa() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        push_name(&mut rdata, "ns1.example.com");
        push_name(&mut rdata, "hostmaster.example.com");
        push_u32(&mut rdata, 2024022301);
        push_u32(&mut rdata, 3600);
        push_u32(&mut rdata, 600);
        push_u32(&mut rdata, 86400);
        push_u32(&mut rdata, 300);
        build_record_header(&mut bytes, 6, rdata.len() as u16, 1200);
        bytes.extend_from_slice(&rdata);

        let record = parse_test_record(&bytes);
        if let RecordData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ..
        } = record.record
        {
            assert_eq!(mname, "ns1.example.com");
            assert_eq!(rname, "hostmaster.example.com");
            assert_eq!(serial, 2024022301);
            assert_eq!(refresh, 3600);
            assert_eq!(retry, 600);
            assert_eq!(expire, 86400);
            assert_eq!(minimum, 300);
        } else {
            panic!("expected SOA record");
        }
    }

    #[test]
    fn parse_record_caa() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        rdata.push(0);
        rdata.push(5);
        rdata.extend_from_slice(b"issue");
        rdata.extend_from_slice(b"letsencrypt.org");
        build_record_header(&mut bytes, 257, rdata.len() as u16, 300);
        bytes.extend_from_slice(&rdata);

        let record = parse_test_record(&bytes);
        assert_eq!(
            record.record,
            RecordData::CAA {
                flags: 0,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string()
            }
        );
    }

    #[test]
    fn parse_record_txt() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let rdata = [5, b'h', b'e', b'l', b'l', b'o'];
        build_record_header(&mut bytes, 16, rdata.len() as u16, 300);
        bytes.extend_from_slice(&rdata);

        let record = parse_test_record(&bytes);
        assert_eq!(record.record, RecordData::TXT("hello".to_string()));
    }

    #[test]
    fn parse_record_ns_ptr_and_rp() {
        let mut ns_bytes = Vec::new();
        push_name(&mut ns_bytes, "example.com");
        let mut ns_rdata = Vec::new();
        push_name(&mut ns_rdata, "ns1.example.com");
        build_record_header(&mut ns_bytes, 2, ns_rdata.len() as u16, 300);
        ns_bytes.extend_from_slice(&ns_rdata);
        assert_eq!(
            parse_test_record(&ns_bytes).record,
            RecordData::NS("ns1.example.com".to_string())
        );

        let mut ptr_bytes = Vec::new();
        push_name(&mut ptr_bytes, "4.3.2.1.in-addr.arpa");
        let mut ptr_rdata = Vec::new();
        push_name(&mut ptr_rdata, "host.example.com");
        build_record_header(&mut ptr_bytes, 12, ptr_rdata.len() as u16, 300);
        ptr_bytes.extend_from_slice(&ptr_rdata);
        assert_eq!(
            parse_test_record(&ptr_bytes).record,
            RecordData::PTR("host.example.com".to_string())
        );

        let mut rp_bytes = Vec::new();
        push_name(&mut rp_bytes, "example.com");
        let mut rp_rdata = Vec::new();
        push_name(&mut rp_rdata, "admin.example.com");
        push_name(&mut rp_rdata, "txt.example.com");
        build_record_header(&mut rp_bytes, 17, rp_rdata.len() as u16, 300);
        rp_bytes.extend_from_slice(&rp_rdata);
        assert_eq!(
            parse_test_record(&rp_bytes).record,
            RecordData::RP {
                mboxdname: "admin.example.com".to_string(),
                txtdname: "txt.example.com".to_string()
            }
        );
    }

    #[test]
    fn parse_dnssec_related_records() {
        let mut cert_bytes = Vec::new();
        push_name(&mut cert_bytes, "example.com");
        let mut cert_rdata = Vec::new();
        push_u16(&mut cert_rdata, 1);
        push_u16(&mut cert_rdata, 42);
        cert_rdata.push(8);
        cert_rdata.extend_from_slice(&[1, 2, 3]);
        build_record_header(&mut cert_bytes, 37, cert_rdata.len() as u16, 300);
        cert_bytes.extend_from_slice(&cert_rdata);
        assert_eq!(
            parse_test_record(&cert_bytes).record,
            RecordData::CERT {
                cert_type: 1,
                key_tag: 42,
                algorithm: 8,
                cert: vec![1, 2, 3]
            }
        );

        let mut dnskey_bytes = Vec::new();
        push_name(&mut dnskey_bytes, "example.com");
        let mut dnskey_rdata = Vec::new();
        push_u16(&mut dnskey_rdata, 256);
        dnskey_rdata.push(3);
        dnskey_rdata.push(8);
        dnskey_rdata.extend_from_slice(&[4, 5, 6]);
        build_record_header(&mut dnskey_bytes, 48, dnskey_rdata.len() as u16, 300);
        dnskey_bytes.extend_from_slice(&dnskey_rdata);
        assert_eq!(
            parse_test_record(&dnskey_bytes).record,
            RecordData::DNSKEY {
                flags: 256,
                protocol: 3,
                algorithm: 8,
                public_key: vec![4, 5, 6]
            }
        );

        let mut ds_bytes = Vec::new();
        push_name(&mut ds_bytes, "example.com");
        let mut ds_rdata = Vec::new();
        push_u16(&mut ds_rdata, 12345);
        ds_rdata.push(8);
        ds_rdata.push(2);
        ds_rdata.extend_from_slice(&[9, 8, 7]);
        build_record_header(&mut ds_bytes, 43, ds_rdata.len() as u16, 300);
        ds_bytes.extend_from_slice(&ds_rdata);
        assert_eq!(
            parse_test_record(&ds_bytes).record,
            RecordData::DS {
                key_tag: 12345,
                algorithm: 8,
                digest_type: 2,
                digest: vec![9, 8, 7]
            }
        );
    }

    #[test]
    fn parse_nsec_rrsig_and_nsec3_records() {
        let mut nsec_bytes = Vec::new();
        push_name(&mut nsec_bytes, "example.com");
        let mut nsec_rdata = Vec::new();
        push_name(&mut nsec_rdata, "next.example.com");
        nsec_rdata.extend_from_slice(&[0, 1, 0x40]);
        build_record_header(&mut nsec_bytes, 47, nsec_rdata.len() as u16, 300);
        nsec_bytes.extend_from_slice(&nsec_rdata);
        assert_eq!(
            parse_test_record(&nsec_bytes).record,
            RecordData::NSEC {
                next_domain: "next.example.com".to_string(),
                type_bit_maps: vec![0, 1, 0x40]
            }
        );

        let mut rrsig_bytes = Vec::new();
        push_name(&mut rrsig_bytes, "example.com");
        let mut rrsig_rdata = Vec::new();
        push_u16(&mut rrsig_rdata, 1);
        rrsig_rdata.push(8);
        rrsig_rdata.push(2);
        push_u32(&mut rrsig_rdata, 3600);
        push_u32(&mut rrsig_rdata, 1700000000);
        push_u32(&mut rrsig_rdata, 1690000000);
        push_u16(&mut rrsig_rdata, 54321);
        push_name(&mut rrsig_rdata, "example.com");
        rrsig_rdata.extend_from_slice(&[0xaa, 0xbb]);
        build_record_header(&mut rrsig_bytes, 46, rrsig_rdata.len() as u16, 300);
        rrsig_bytes.extend_from_slice(&rrsig_rdata);
        if let RecordData::RRSIG {
            signer_name,
            signature,
            key_tag,
            ..
        } = parse_test_record(&rrsig_bytes).record
        {
            assert_eq!(signer_name, "example.com");
            assert_eq!(signature, vec![0xaa, 0xbb]);
            assert_eq!(key_tag, 54321);
        } else {
            panic!("expected RRSIG record");
        }

        let mut nsec3_bytes = Vec::new();
        push_name(&mut nsec3_bytes, "example.com");
        let nsec3_rdata = [1, 0, 0, 1, 1, 0xaa, 2, 0xbb, 0xcc, 0, 1, 0x40];
        build_record_header(&mut nsec3_bytes, 50, nsec3_rdata.len() as u16, 300);
        nsec3_bytes.extend_from_slice(&nsec3_rdata);
        assert_eq!(
            parse_test_record(&nsec3_bytes).record,
            RecordData::NSEC3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 1,
                salt_length: 1,
                salt: vec![0xaa],
                hash_length: 2,
                next_domain: "bbcc".to_string(),
                type_bit_maps: vec![0, 1, 0x40]
            }
        );
    }

    #[test]
    fn write_record_round_trips_soa_with_mname_before_rname_wire_order() {
        let rdata = RecordData::SOA {
            ttl: 0,
            rname: "hostmaster.example.com".to_string(),
            mname: "ns1.example.com".to_string(),
            serial: 2026070901,
            refresh: 7200,
            retry: 3600,
            expire: 1_209_600,
            minimum: 3600,
        };
        let mut bytes = Vec::new();
        let mut compressor = NameCompressor::new();
        write_record(
            &mut bytes,
            &mut compressor,
            "example.com",
            6,
            1,
            3600,
            &rdata,
        );

        assert_eq!(parse_test_record(&bytes).record, rdata);
    }

    #[test]
    fn write_record_round_trips_nsec3_hash_bytes_through_hex_encoding() {
        // Same fixture as `parse_nsec_rrsig_and_nsec3_records`'s NSEC3 case
        // (next_domain "bbcc" == hex(hash_length=2 bytes [0xbb, 0xcc])), but
        // driven through the writer this time to prove `from_hex` correctly
        // reverses `to_hex` rather than just checking the parser alone.
        let rdata = RecordData::NSEC3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 1,
            salt_length: 1,
            salt: vec![0xaa],
            hash_length: 2,
            next_domain: "bbcc".to_string(),
            type_bit_maps: vec![0, 1, 0x40],
        };
        let mut bytes = Vec::new();
        let mut compressor = NameCompressor::new();
        write_record(
            &mut bytes,
            &mut compressor,
            "example.com",
            50,
            1,
            300,
            &rdata,
        );

        assert_eq!(parse_test_record(&bytes).record, rdata);
    }

    #[test]
    fn write_record_round_trips_txt_longer_than_one_255_byte_chunk() {
        let text: String = "a".repeat(300);
        let rdata = RecordData::TXT(text.clone());
        let mut bytes = Vec::new();
        let mut compressor = NameCompressor::new();
        write_record(
            &mut bytes,
            &mut compressor,
            "example.com",
            16,
            1,
            300,
            &rdata,
        );

        match parse_test_record(&bytes).record {
            RecordData::TXT(parsed) => assert_eq!(parsed, text),
            other => panic!("expected TXT, got {other:?}"),
        }
    }

    #[test]
    fn build_opt_record_with_options_round_trips_cookie_option_bytes() {
        let secret = edns_cookie::CookieSecret::generate();
        let client_cookie: edns_cookie::ClientCookie = [1, 2, 3, 4, 5, 6, 7, 8];
        let client_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let server_cookie =
            edns_cookie::build_server_cookie(&secret, client_cookie, client_ip, now);
        let options = edns_cookie::build_cookie_option(client_cookie, server_cookie);

        let opt = build_opt_record_with_options(1232, true, options.clone());
        let mut bytes = Vec::new();
        write_opt_record(&mut bytes, &opt);

        let parsed = parse_test_record(&bytes);
        assert_eq!(parsed.rtype, OPT_RECORD_TYPE);
        match parsed.record {
            RecordData::OPT(info) => {
                assert_eq!(info.options, options);
                assert_eq!(info.udp_payload_size, 1232);
                assert!(info.dnssec_ok);
                assert_eq!(info.extended_rcode, 0);
                assert_eq!(info.version, 0);
            }
            other => panic!("expected OPT, got {other:?}"),
        }
    }

    #[test]
    fn parse_record_cname_compressed_target() {
        let mut message = Vec::new();
        push_name(&mut message, "example.com");
        let record_offset = message.len();
        push_name(&mut message, "alias.example.com");
        let mut rdata = Vec::new();
        push_pointer(&mut rdata, 0);
        build_record_header(&mut message, 5, rdata.len() as u16, 180);
        message.extend_from_slice(&rdata);

        let mut offset = record_offset;
        let mut context = ParseContext::default();
        context.valid_name_offsets.insert(0);
        let record = parse_record(&message, &mut offset, &mut context).unwrap();
        assert_eq!(record.record, RecordData::CNAME("example.com".to_string()));
    }

    #[test]
    fn parse_unknown_record() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        build_record_header(&mut bytes, 65_000, 3, 120);
        bytes.extend_from_slice(&[7, 8, 9]);

        let record = parse_test_record(&bytes);
        assert_eq!(
            record.record,
            RecordData::Unknown {
                rtype: 65_000,
                bytes: vec![7, 8, 9]
            }
        );
    }

    #[test]
    fn parse_message_sections() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 1, 1, 1);

        push_name(&mut message, "example.com");
        push_u16(&mut message, 1);
        push_u16(&mut message, 1);

        push_record(&mut message, "example.com", 1, 300, &[1, 2, 3, 4]);

        let mut ns_rdata = Vec::new();
        push_name(&mut ns_rdata, "ns1.example.com");
        push_record(&mut message, "example.com", 2, 300, &ns_rdata);

        push_record(
            &mut message,
            "ns1.example.com",
            28,
            300,
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );

        let parsed = Message::parse(&message).unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.authorities.len(), 1);
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.questions[0].qname, "example.com");
        assert_eq!(
            parsed.answers[0].record,
            RecordData::A(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn truncated_header_returns_error() {
        assert_eq!(Message::parse(&[0; 11]), Err(DnsParseError::UnexpectedEof));
    }

    #[test]
    fn truncated_record_returns_error() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        build_record_header(&mut bytes, 1, 4, 300);
        bytes.extend_from_slice(&[1, 2, 3]);

        let mut offset = 0;
        let mut context = ParseContext::default();
        assert_eq!(
            parse_record(&bytes, &mut offset, &mut context),
            Err(DnsParseError::UnexpectedEof)
        );
    }

    #[test]
    fn name_record_rejects_trailing_rdata() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "alias.example.com");
        let mut rdata = Vec::new();
        push_name(&mut rdata, "target.example.com");
        rdata.push(0xff);
        build_record_header(&mut bytes, 5, rdata.len() as u16, 180);
        bytes.extend_from_slice(&rdata);

        let mut offset = 0;
        let mut context = ParseContext::default();
        assert_eq!(
            parse_record(&bytes, &mut offset, &mut context),
            Err(DnsParseError::MalformedRecord)
        );
    }

    #[test]
    fn nsec3param_rejects_trailing_rdata() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let rdata = [1, 0, 0, 1, 0, 0xff];
        build_record_header(&mut bytes, 51, rdata.len() as u16, 300);
        bytes.extend_from_slice(&rdata);

        let mut offset = 0;
        let mut context = ParseContext::default();
        assert_eq!(
            parse_record(&bytes, &mut offset, &mut context),
            Err(DnsParseError::MalformedRecord)
        );
    }

    #[test]
    fn self_pointer_returns_error() {
        let bytes = [0xc0, 0x00];
        let mut offset = 0;
        assert_eq!(
            parse_domain(&bytes, &mut offset),
            Err(DnsParseError::InvalidNamePointer)
        );
    }

    #[test]
    fn backward_pointer_loop_returns_error() {
        let bytes = [1, b'a', 0xc0, 0x00];
        let mut offset = 0;
        assert_eq!(
            parse_domain(&bytes, &mut offset),
            Err(DnsParseError::PointerLoop)
        );
    }

    #[test]
    fn invalid_pointer_returns_error() {
        let bytes = [0xc0, 0xff];
        let mut offset = 0;
        assert_eq!(
            parse_domain(&bytes, &mut offset),
            Err(DnsParseError::InvalidNamePointer)
        );
    }

    #[test]
    fn forward_pointer_returns_error() {
        let bytes = [0xc0, 0x02, 0];
        let mut offset = 0;
        assert_eq!(
            parse_domain(&bytes, &mut offset),
            Err(DnsParseError::InvalidNamePointer)
        );
    }

    #[test]
    fn malformed_inputs_return_without_panicking() {
        let mut corpus = vec![
            Vec::new(),
            vec![0],
            vec![0; 11],
            vec![0xff; 64],
            vec![0x12, 0x34, 0x01, 0x00, 0, 1],
            vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x00],
            vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64],
        ];

        for len in 0..32 {
            let mut bytes = Vec::with_capacity(len);
            for value in 0..len {
                bytes.push((value * 17) as u8);
            }
            corpus.push(bytes);
        }

        for bytes in corpus {
            let result = std::panic::catch_unwind(|| Message::parse(&bytes));
            assert!(result.is_ok(), "parser panicked for bytes: {bytes:?}");
        }
    }

    #[test]
    fn malformed_fixed_length_rdata_returns_error() {
        let mut a_bytes = Vec::new();
        push_name(&mut a_bytes, "example.com");
        build_record_header(&mut a_bytes, 1, 3, 300);
        a_bytes.extend_from_slice(&[1, 2, 3]);
        let mut offset = 0;
        let mut context = ParseContext::default();
        assert_eq!(
            parse_record(&a_bytes, &mut offset, &mut context),
            Err(DnsParseError::MalformedRecord)
        );

        let mut aaaa_bytes = Vec::new();
        push_name(&mut aaaa_bytes, "example.com");
        build_record_header(&mut aaaa_bytes, 28, 15, 300);
        aaaa_bytes.extend_from_slice(&[0; 15]);
        let mut offset = 0;
        let mut context = ParseContext::default();
        assert_eq!(
            parse_record(&aaaa_bytes, &mut offset, &mut context),
            Err(DnsParseError::MalformedRecord)
        );
    }

    #[test]
    fn malformed_txt_and_caa_rdata_return_error() {
        let mut txt_bytes = Vec::new();
        push_name(&mut txt_bytes, "example.com");
        build_record_header(&mut txt_bytes, 16, 3, 300);
        txt_bytes.extend_from_slice(&[5, b'h', b'i']);
        let mut offset = 0;
        let mut context = ParseContext::default();
        assert_eq!(
            parse_record(&txt_bytes, &mut offset, &mut context),
            Err(DnsParseError::UnexpectedEof)
        );

        let mut caa_bytes = Vec::new();
        push_name(&mut caa_bytes, "example.com");
        build_record_header(&mut caa_bytes, 257, 3, 300);
        caa_bytes.extend_from_slice(&[0, 5, b'i']);
        let mut offset = 0;
        let mut context = ParseContext::default();
        assert_eq!(
            parse_record(&caa_bytes, &mut offset, &mut context),
            Err(DnsParseError::UnexpectedEof)
        );
    }

    #[test]
    fn generated_response_size_can_be_checked_against_current_request_udp_limit() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 1);
        push_question(&mut request, "blocked.example", 1, 1);
        push_opt_record(&mut request, 1232, false, &[]);
        let request = Message::parse_standard_query(&request).unwrap();

        let mut response = build_a_block_response(&request, Ipv4Addr::new(10, 0, 0, 1), 60, 1500);
        response.resize(800, 0);
        assert_eq!(request.effective_udp_payload_size(1500), 1232);
        assert!(!request.response_exceeds_udp_payload(response.len(), 1500));
        assert!(request.response_exceeds_udp_payload(response.len(), 700));
    }
}
