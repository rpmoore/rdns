use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

const DNS_HEADER_LEN: usize = 12;
const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;

pub type Result<T> = std::result::Result<T, DnsParseError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsParseError {
    Truncated,
    InvalidLabel,
    InvalidNamePointer,
    PointerLoop,
    InvalidUtf8Label,
    UnexpectedEof,
    MalformedRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub header: Header,
    pub original_bytes: Vec<u8>,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
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
        let header = parse_header(dns_message)?;
        let mut offset = DNS_HEADER_LEN;

        let questions = parse_questions(dns_message, &mut offset, header.qd_count)?;
        let answers = parse_records(dns_message, &mut offset, header.an_count)?;
        let authorities = parse_records(dns_message, &mut offset, header.ns_count)?;
        let additionals = parse_records(dns_message, &mut offset, header.ar_count)?;

        Ok(Self {
            header,
            original_bytes: dns_message.to_vec(),
            questions,
            answers,
            authorities,
            additionals,
        })
    }
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
) -> Result<Vec<Question>> {
    let mut questions = Vec::with_capacity(question_count as usize);
    for _ in 0..question_count {
        questions.push(parse_question(dns_message, offset)?);
    }
    Ok(questions)
}

fn parse_question(dns_message: &[u8], offset: &mut usize) -> Result<Question> {
    let qname = parse_domain(dns_message, offset)?;
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

fn parse_records(dns_message: &[u8], offset: &mut usize, record_count: u16) -> Result<Vec<Record>> {
    let mut records = Vec::with_capacity(record_count as usize);
    for _ in 0..record_count {
        records.push(parse_record(dns_message, offset)?);
    }
    Ok(records)
}

fn parse_record(dns_message: &[u8], offset: &mut usize) -> Result<Record> {
    let name = parse_domain(dns_message, offset)?;
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

    let record = parse_record_data(dns_message, rdata_offset, rtype, rdlength)?;
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
    rdlength: usize,
) -> Result<RecordData> {
    let end = offset
        .checked_add(rdlength)
        .ok_or(DnsParseError::MalformedRecord)?;
    match rtype {
        1 => parse_a_record(dns_message, offset, end),
        2 => parse_name_record(dns_message, offset, end).map(RecordData::NS),
        5 => parse_name_record(dns_message, offset, end).map(RecordData::CNAME),
        6 => parse_soa_record(dns_message, offset, end),
        12 => parse_name_record(dns_message, offset, end).map(RecordData::PTR),
        15 => parse_mx_record(dns_message, offset, end),
        16 => parse_txt_record(dns_message, offset, end),
        17 => parse_rp_record(dns_message, offset, end),
        28 => parse_aaaa_record(dns_message, offset, end),
        33 => parse_srv_record(dns_message, offset, end),
        37 => parse_cert_record(dns_message, offset, end),
        43 => parse_ds_record(dns_message, offset, end),
        46 => parse_rrsig_record(dns_message, offset, end),
        47 => parse_nsec_record(dns_message, offset, end),
        48 => parse_dnskey_record(dns_message, offset, end),
        50 => parse_nsec3_record(dns_message, offset, end),
        51 => parse_nsec3param_record(dns_message, offset, end),
        257 => parse_caa_record(dns_message, offset, end),
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

fn parse_name_record(dns_message: &[u8], offset: usize, end: usize) -> Result<String> {
    let mut cursor = offset;
    let name = parse_domain(dns_message, &mut cursor)?;
    if cursor != end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(name)
}

fn parse_mx_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let preference = reader.read_u16()?;
    let mut cursor = reader.position();
    let exchange = parse_domain(dns_message, &mut cursor)?;
    if cursor != end {
        return Err(DnsParseError::MalformedRecord);
    }
    Ok(RecordData::MX {
        preference,
        exchange,
    })
}

fn parse_srv_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let priority = reader.read_u16()?;
    let weight = reader.read_u16()?;
    let port = reader.read_u16()?;
    let mut cursor = reader.position();
    let target = parse_domain(dns_message, &mut cursor)?;
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

fn parse_soa_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut cursor = offset;
    let mname = parse_domain(dns_message, &mut cursor)?;
    let rname = parse_domain(dns_message, &mut cursor)?;
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

fn parse_rp_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut cursor = offset;
    let mboxdname = parse_domain(dns_message, &mut cursor)?;
    let txtdname = parse_domain(dns_message, &mut cursor)?;
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

fn parse_rrsig_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut reader = Reader::new(dns_message, offset)?;
    let type_covered = reader.read_u16()?;
    let algorithm = reader.read_u8()?;
    let labels = reader.read_u8()?;
    let original_ttl = reader.read_u32()?;
    let signature_expiration = reader.read_u32()?;
    let signature_inception = reader.read_u32()?;
    let key_tag = reader.read_u16()?;
    let mut cursor = reader.position();
    let signer_name = parse_domain(dns_message, &mut cursor)?;
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

fn parse_nsec_record(dns_message: &[u8], offset: usize, end: usize) -> Result<RecordData> {
    let mut cursor = offset;
    let next_domain = parse_domain(dns_message, &mut cursor)?;
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

fn parse_domain(dns_message: &[u8], offset: &mut usize) -> Result<String> {
    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut consumed_offset = None;
    let mut visited = HashSet::new();
    let mut wire_len = 1usize;

    loop {
        if !visited.insert(cursor) {
            return Err(DnsParseError::PointerLoop);
        }

        let length = *dns_message
            .get(cursor)
            .ok_or(DnsParseError::UnexpectedEof)? as usize;
        match length & 0b1100_0000 {
            0b0000_0000 => {
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
                let next = *dns_message
                    .get(cursor + 1)
                    .ok_or(DnsParseError::UnexpectedEof)? as usize;
                let pointer_offset = ((length & 0b0011_1111) << 8) | next;
                if pointer_offset >= cursor || pointer_offset >= dns_message.len() {
                    return Err(DnsParseError::InvalidNamePointer);
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

    fn push_record(out: &mut Vec<u8>, name: &str, rtype: u16, ttl: u32, rdata: &[u8]) {
        push_name(out, name);
        build_record_header(out, rtype, rdata.len() as u16, ttl);
        out.extend_from_slice(rdata);
    }

    fn parse_test_record(bytes: &[u8]) -> Record {
        let mut offset = 0;
        parse_record(bytes, &mut offset).unwrap()
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
        let record = parse_record(&message, &mut offset).unwrap();
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
        assert_eq!(
            parse_record(&bytes, &mut offset),
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
        assert_eq!(
            parse_record(&bytes, &mut offset),
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
        assert_eq!(
            parse_record(&bytes, &mut offset),
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
}
