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

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;
use std::str;
use std::time::Duration;

use bytes::Bytes;

const DNS_HEADER_LEN: usize = 12;
pub const DNS_DEFAULT_UDP_PAYLOAD_SIZE: usize = 512;
const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;
const OPT_RECORD_TYPE: u16 = 41;
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
}

impl From<DnsParseError> for QueryValidationError {
    fn from(value: DnsParseError) -> Self {
        Self::Parse(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn response_code(&self) -> ResponseCode {
        match self {
            Self::UnsupportedOpcode { .. } => ResponseCode::NotImp,
            Self::Parse(_)
            | Self::InvalidQuestionCount { .. }
            | Self::UnexpectedSectionRecords { .. }
            | Self::InvalidEdns
            | Self::NotQuery => ResponseCode::FormErr,
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

    pub fn parse_owned(dns_message: Vec<u8>) -> Result<Self> {
        let parts = Self::parse_parts(&dns_message)?;
        Ok(Self::from_parts(Bytes::from(dns_message), parts))
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
        dns_message: Vec<u8>,
    ) -> std::result::Result<Self, QueryValidationError> {
        let header = parse_header(&dns_message)?;
        validate_standard_query_header(&header)?;
        let message = Self::parse_owned(dns_message)?;
        validate_standard_query_body(&message)?;
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

pub fn build_servfail_response(request: Option<&Message>, request_id: Option<u16>) -> Vec<u8> {
    match request {
        Some(request) => build_question_response(request, ResponseCode::ServFail, &[]),
        None => build_header_only_response(request_id.unwrap_or(0), false, ResponseCode::ServFail),
    }
}

pub fn build_refused_response(request: &Message) -> Vec<u8> {
    build_question_response(request, ResponseCode::Refused, &[])
}

pub fn build_nxdomain_response(request: &Message) -> Vec<u8> {
    build_question_response(request, ResponseCode::NxDomain, &[])
}

pub fn build_nodata_response(request: &Message) -> Vec<u8> {
    build_question_response(request, ResponseCode::NoError, &[])
}

pub fn build_a_block_response(request: &Message, ipv4: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let answer = SinkholeAnswer::A { address: ipv4, ttl };
    build_question_response(request, ResponseCode::NoError, &[answer])
}

pub fn build_aaaa_block_response(request: &Message, ipv6: Ipv6Addr, ttl: u32) -> Vec<u8> {
    let answer = SinkholeAnswer::Aaaa { address: ipv6, ttl };
    build_question_response(request, ResponseCode::NoError, &[answer])
}

pub fn build_truncated_response(request: &Message) -> Vec<u8> {
    let mut response = Vec::new();
    write_response_header(
        &mut response,
        request.header.id,
        request.header.rd(),
        true,
        ResponseCode::NoError,
        0,
        0,
    );
    response
}

pub fn rewrite_response_id(response_bytes: &mut [u8], request_id: u16) -> Result<()> {
    if response_bytes.len() < 2 {
        return Err(DnsParseError::MessageTooShort);
    }
    response_bytes[0..2].copy_from_slice(&request_id.to_be_bytes());
    Ok(())
}

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

enum SinkholeAnswer {
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

fn build_question_response(
    request: &Message,
    rcode: ResponseCode,
    answers: &[SinkholeAnswer],
) -> Vec<u8> {
    let mut response = Vec::new();
    let question_count = u16::from(!request.questions.is_empty());
    write_response_header(
        &mut response,
        request.header.id,
        request.header.rd(),
        false,
        rcode,
        question_count,
        answers.len() as u16,
    );

    if let Some(question) = request.questions.first() {
        write_question(&mut response, question);
        for answer in answers {
            write_sinkhole_answer(&mut response, question, answer);
        }
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

fn write_question(out: &mut Vec<u8>, question: &Question) {
    write_name(out, &question.qname);
    write_u16(out, question.qtype);
    write_u16(out, question.qclass);
}

fn write_sinkhole_answer(out: &mut Vec<u8>, question: &Question, answer: &SinkholeAnswer) {
    match answer {
        SinkholeAnswer::A { address, ttl } => {
            write_name(out, &question.qname);
            write_u16(out, 1);
            write_u16(out, question.qclass);
            write_u32(out, *ttl);
            write_u16(out, 4);
            out.extend_from_slice(&address.octets());
        }
        SinkholeAnswer::Aaaa { address, ttl } => {
            write_name(out, &question.qname);
            write_u16(out, 28);
            write_u16(out, question.qclass);
            write_u32(out, *ttl);
            write_u16(out, 16);
            out.extend_from_slice(&address.octets());
        }
    }
}

fn write_name(out: &mut Vec<u8>, name: &str) {
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

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
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

    match message.additionals[0].record {
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
    let name = parse_domain_with_context(dns_message, offset, Some(context))?;
    let mut reader = Reader::new(dns_message, *offset)?;
    let rtype = reader.read_u16()?;
    let rclass = reader.read_u16()?;
    let ttl = reader.read_u32()?;
    let rdlength = reader.read_u16()? as usize;
    if rtype == OPT_RECORD_TYPE && !name.is_empty() {
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
    let _hash_algorithm = reader.read_u8()?;
    let _flags = reader.read_u8()?;
    let _iterations = reader.read_u16()?;
    let salt_len = reader.read_u8()? as usize;
    reader.read_exact(salt_len)?;
    let hash_len = reader.read_u8()? as usize;
    let next_hashed_owner_name = reader.read_exact(hash_len)?;
    if reader.position() > end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::NSEC3 {
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

fn parse_domain_with_context(
    dns_message: &[u8],
    offset: &mut usize,
    mut context: Option<&mut ParseContext>,
) -> Result<String> {
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
    if let Some(context) = context {
        if !context.valid_name_offsets.contains(&pointer_offset) {
            return Err(DnsParseError::InvalidNamePointer);
        }
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
        out.push(0);
        push_u16(out, OPT_RECORD_TYPE);
        push_u16(out, udp_payload_size);
        let flags = if dnssec_ok { EDNS_DO_FLAG as u32 } else { 0 };
        push_u32(out, flags);
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

        let response = Message::parse(&build_servfail_response(Some(&request), None)).unwrap();

        assert_eq!(response.header.id, 0xbeef);
        assert!(response.header.rd());
        assert_eq!(response.header.r_code(), ResponseCode::ServFail.as_u8());
        assert_eq!(response.questions[0], request.questions[0]);
        assert!(response.answers.is_empty());
    }

    #[test]
    fn build_servfail_response_without_request_uses_supplied_id() {
        let response = build_servfail_response(None, Some(0x1234));
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

        let refused = Message::parse(&build_refused_response(&request)).unwrap();
        assert_eq!(refused.header.r_code(), ResponseCode::Refused.as_u8());
        assert_eq!(refused.questions[0], request.questions[0]);
        assert!(refused.answers.is_empty());

        let nxdomain = Message::parse(&build_nxdomain_response(&request)).unwrap();
        assert_eq!(nxdomain.header.r_code(), ResponseCode::NxDomain.as_u8());
        assert_eq!(nxdomain.questions[0], request.questions[0]);

        let nodata = Message::parse(&build_nodata_response(&request)).unwrap();
        assert_eq!(nodata.header.r_code(), ResponseCode::NoError.as_u8());
        assert!(nodata.answers.is_empty());
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
    fn build_sinkhole_aaaa_response_serializes_answer() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "blocked.example", 28, 1);
        let request = Message::parse_standard_query(&request).unwrap();
        let sinkhole = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let response = Message::parse(&build_aaaa_block_response(&request, sinkhole, 30)).unwrap();

        assert_eq!(response.header.r_code(), ResponseCode::NoError.as_u8());
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].ttl, 30);
        assert_eq!(response.answers[0].record, RecordData::AAAA(sinkhole));
    }

    #[test]
    fn build_truncated_response_sets_tc_and_omits_sections() {
        let mut request = Vec::new();
        push_header(&mut request, 1, 0, 0, 0);
        push_question(&mut request, "example.com", 1, 1);
        let request = Message::parse_standard_query(&request).unwrap();

        let response = Message::parse(&build_truncated_response(&request)).unwrap();

        assert!(response.header.tc());
        assert!(response.questions.is_empty());
        assert!(response.answers.is_empty());
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
                next_domain: "bbcc".to_string(),
                type_bit_maps: vec![0, 1, 0x40]
            }
        );
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

        let mut response = build_a_block_response(&request, Ipv4Addr::new(10, 0, 0, 1), 60);
        response.resize(800, 0);
        assert_eq!(request.effective_udp_payload_size(1500), 1232);
        assert!(!request.response_exceeds_udp_payload(response.len(), 1500));
        assert!(request.response_exceeds_udp_payload(response.len(), 700));
    }
}
