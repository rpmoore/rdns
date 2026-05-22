use std::net::{Ipv4Addr, Ipv6Addr};


const DNS_HEADER_LEN: usize = 12;

pub struct Message<'a> {
    header : Header<'a>,
    dns_message :  &'a [u8],
    pub questions: Vec<Question>,
    pub answers: Option<Vec<Record>>,
    pub authorities: Option<Vec<Record>>,
    pub additionals: Option<Vec<Record>>,
}

pub struct Question {
    pub qname: String, //need to figure out how to parse the domain name from the dns_message and turn it into a string that is zero copied
    pub qtype: u16,
    pub qclass: u16,
}

pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CAA{flags: u8, tag: String, value: String}, // need to figure out if the tag should be an enum
    MX{preference: u16, exchange: String},
    CERT{cert_type: u16, key_tag: u16, algorithm: u8, cert: Vec<u8>},
    CNAME(String),
    DNSKEY{flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8>},
    DS{key_tag: u16, algorithm: u8, digest_type: u8, digest: Vec<u8>},
    NSEC{next_domain: String, type_bit_maps: Vec<u8>},
    NSEC3{next_domain: String, type_bit_maps: Vec<u8>},
    NSEC3PARAM{hash_algorithm: u8, flags: u8, iterations: u16, salt_length: u8, salt: Vec<u8>},
    NS(String),
    PTR(String),
    RP{mboxdname: String, txtdname: String},
    RRSIG{type_covered: u16, algorithm: u8, labels: u8, original_ttl: u32, signature_expiration: u32, signature_inception: u32, key_tag: u16, signer_name: String, signature: Vec<u8>},
    SOA{ttl: u32, rname: String, mname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32},
    SRV{priority: u16, weight: u16, port: u16, target: String},
    TXT(String),
}

pub struct Record {
    pub name: String, //same as qname
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub record: RecordData,
}

fn parse_record_data(dns_message: &[u8], offset: usize, rtype: u16, rdlength: u16) -> (RecordData, usize) {
    match rtype {
        1 => parse_a_record(dns_message, offset, rdlength),
        2 => parse_ns_record(dns_message, offset),
        5 => parse_cname_record(dns_message, offset),
        6 => parse_soa_record(dns_message, offset, rdlength),
        12 => parse_ptr_record(dns_message, offset),
        15 => parse_mx_record(dns_message, offset),
        16 => parse_txt_record(dns_message, offset, rdlength),
        17 => parse_rp_record(dns_message, offset),
        28 => parse_aaaa_record(dns_message, offset, rdlength),
        33 => parse_srv_record(dns_message, offset),
        37 => parse_cert_record(dns_message, offset, rdlength),
        43 => parse_ds_record(dns_message, offset, rdlength),
        46 => parse_rrsig_record(dns_message, offset, rdlength),
        47 => parse_nsec_record(dns_message, offset, rdlength),
        48 => parse_dnskey_record(dns_message, offset, rdlength),
        50 => parse_nsec3_record(dns_message, offset, rdlength),
        51 => parse_nsec3param_record(dns_message, offset, rdlength),
        257 => parse_caa_record(dns_message, offset, rdlength),
        _ => unimplemented!(), // For now, we can just panic for unsupported record types
    }
}

fn read_u16(dns_message: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([dns_message[offset], dns_message[offset + 1]])
}

fn read_u32(dns_message: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        dns_message[offset],
        dns_message[offset + 1],
        dns_message[offset + 2],
        dns_message[offset + 3],
    ])
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn parse_a_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let ip_bytes = &dns_message[offset..offset + 4];
    let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    (RecordData::A(ip), offset + rdlength as usize)
}

fn parse_aaaa_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let ip_bytes = &dns_message[offset..offset + 16];
    let ip = Ipv6Addr::new(
        ((ip_bytes[0] as u16) << 8) | ip_bytes[1] as u16,
        ((ip_bytes[2] as u16) << 8) | ip_bytes[3] as u16,
        ((ip_bytes[4] as u16) << 8) | ip_bytes[5] as u16,
        ((ip_bytes[6] as u16) << 8) | ip_bytes[7] as u16,
        ((ip_bytes[8] as u16) << 8) | ip_bytes[9] as u16,
        ((ip_bytes[10] as u16) << 8) | ip_bytes[11] as u16,
        ((ip_bytes[12] as u16) << 8) | ip_bytes[13] as u16,
        ((ip_bytes[14] as u16) << 8) | ip_bytes[15] as u16,
    );
    (RecordData::AAAA(ip), offset + rdlength as usize)
}

fn parse_cname_record(dns_message: &[u8], offset: usize) -> (RecordData, usize) {
    let (name, new_offset) = parse_domain(dns_message, offset);
    (RecordData::CNAME(name), new_offset)
}

fn parse_ns_record(dns_message: &[u8], offset: usize) -> (RecordData, usize) {
    let (name, new_offset) = parse_domain(dns_message, offset);
    (RecordData::NS(name), new_offset)
}

fn parse_ptr_record(dns_message: &[u8], offset: usize) -> (RecordData, usize) {
    let (name, new_offset) = parse_domain(dns_message, offset);
    (RecordData::PTR(name), new_offset)
}

fn parse_mx_record(dns_message: &[u8], offset: usize) -> (RecordData, usize) {
    let preference = read_u16(dns_message, offset);
    let (exchange, new_offset) = parse_domain(dns_message, offset + 2);
    (
        RecordData::MX {
            preference,
            exchange,
        },
        new_offset,
    )
}

fn parse_srv_record(dns_message: &[u8], offset: usize) -> (RecordData, usize) {
    let priority = read_u16(dns_message, offset);
    let weight = read_u16(dns_message, offset + 2);
    let port = read_u16(dns_message, offset + 4);
    let (target, new_offset) = parse_domain(dns_message, offset + 6);
    (
        RecordData::SRV {
            priority,
            weight,
            port,
            target,
        },
        new_offset,
    )
}

fn parse_txt_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let end = offset + rdlength as usize;
    let mut cursor = offset;
    let mut text = String::new();
    while cursor < end {
        let len = dns_message[cursor] as usize;
        cursor += 1;
        let bytes = &dns_message[cursor..cursor + len];
        cursor += len;
        text.push_str(&String::from_utf8_lossy(bytes));
    }
    (RecordData::TXT(text), end)
}

fn parse_soa_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let (mname, mname_offset) = parse_domain(dns_message, offset);
    let (rname, rname_offset) = parse_domain(dns_message, mname_offset);
    let serial = read_u32(dns_message, rname_offset);
    let refresh = read_u32(dns_message, rname_offset + 4);
    let retry = read_u32(dns_message, rname_offset + 8);
    let expire = read_u32(dns_message, rname_offset + 12);
    let minimum = read_u32(dns_message, rname_offset + 16);
    (
        RecordData::SOA {
            ttl: 0,
            rname,
            mname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        },
        offset + rdlength as usize,
    )
}

fn parse_rp_record(dns_message: &[u8], offset: usize) -> (RecordData, usize) {
    let (mboxdname, mbox_offset) = parse_domain(dns_message, offset);
    let (txtdname, new_offset) = parse_domain(dns_message, mbox_offset);
    (
        RecordData::RP {
            mboxdname,
            txtdname,
        },
        new_offset,
    )
}

fn parse_caa_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let end = offset + rdlength as usize;
    let flags = dns_message[offset];
    let tag_len = dns_message[offset + 1] as usize;
    let tag_start = offset + 2;
    let tag_end = tag_start + tag_len;
    let tag = std::str::from_utf8(&dns_message[tag_start..tag_end]).unwrap().to_string();
    let value = String::from_utf8_lossy(&dns_message[tag_end..end]).to_string();
    (
        RecordData::CAA {
            flags,
            tag,
            value,
        },
        end,
    )
}

fn parse_cert_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let cert_type = read_u16(dns_message, offset);
    let key_tag = read_u16(dns_message, offset + 2);
    let algorithm = dns_message[offset + 4];
    let cert = dns_message[offset + 5..offset + rdlength as usize].to_vec();
    (
        RecordData::CERT {
            cert_type,
            key_tag,
            algorithm,
            cert,
        },
        offset + rdlength as usize,
    )
}

fn parse_dnskey_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let flags = read_u16(dns_message, offset);
    let protocol = dns_message[offset + 2];
    let algorithm = dns_message[offset + 3];
    let public_key = dns_message[offset + 4..offset + rdlength as usize].to_vec();
    (
        RecordData::DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
        },
        offset + rdlength as usize,
    )
}

fn parse_ds_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let key_tag = read_u16(dns_message, offset);
    let algorithm = dns_message[offset + 2];
    let digest_type = dns_message[offset + 3];
    let digest = dns_message[offset + 4..offset + rdlength as usize].to_vec();
    (
        RecordData::DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
        },
        offset + rdlength as usize,
    )
}

fn parse_rrsig_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let end = offset + rdlength as usize;
    let type_covered = read_u16(dns_message, offset);
    let algorithm = dns_message[offset + 2];
    let labels = dns_message[offset + 3];
    let original_ttl = read_u32(dns_message, offset + 4);
    let signature_expiration = read_u32(dns_message, offset + 8);
    let signature_inception = read_u32(dns_message, offset + 12);
    let key_tag = read_u16(dns_message, offset + 16);
    let (signer_name, signer_offset) = parse_domain(dns_message, offset + 18);
    let signature = dns_message[signer_offset..end].to_vec();
    (
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
        },
        end,
    )
}

fn parse_nsec_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let end = offset + rdlength as usize;
    let (next_domain, next_offset) = parse_domain(dns_message, offset);
    let type_bit_maps = dns_message[next_offset..end].to_vec();
    (
        RecordData::NSEC {
            next_domain,
            type_bit_maps,
        },
        end,
    )
}

fn parse_nsec3_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let end = offset + rdlength as usize;
    let mut cursor = offset;
    let _hash_algorithm = dns_message[cursor];
    cursor += 1;
    let _flags = dns_message[cursor];
    cursor += 1;
    let _iterations = read_u16(dns_message, cursor);
    cursor += 2;
    let salt_length = dns_message[cursor] as usize;
    cursor += 1 + salt_length;
    let hash_length = dns_message[cursor] as usize;
    cursor += 1;
    let next_hashed_owner_name = &dns_message[cursor..cursor + hash_length];
    cursor += hash_length;
    let type_bit_maps = dns_message[cursor..end].to_vec();
    (
        RecordData::NSEC3 {
            next_domain: to_hex(next_hashed_owner_name),
            type_bit_maps,
        },
        end,
    )
}

fn parse_nsec3param_record(dns_message: &[u8], offset: usize, rdlength: u16) -> (RecordData, usize) {
    let hash_algorithm = dns_message[offset];
    let flags = dns_message[offset + 1];
    let iterations = read_u16(dns_message, offset + 2);
    let salt_length = dns_message[offset + 4];
    let salt_start = offset + 5;
    let salt_end = salt_start + salt_length as usize;
    let salt = dns_message[salt_start..salt_end].to_vec();
    (
        RecordData::NSEC3PARAM {
            hash_algorithm,
            flags,
            iterations,
            salt_length,
            salt,
        },
        offset + rdlength as usize,
    )
}

impl <'a> Message<'a> {
    pub fn new(dns_message : &'a [u8]) -> Self {

        let header = Header { dns_header: &dns_message[0..DNS_HEADER_LEN] };

        // parse all the questions
        let (questions, questions_len) = parse_questions(&dns_message[DNS_HEADER_LEN..], header.qd_count());
        let mut offset = DNS_HEADER_LEN + questions_len;

        // parse all the answers
        let (answers, answers_len) = parse_records(&dns_message[offset..], header.an_count());
        offset += answers_len;

        // parse all the authorities
        let (authorities, authorities_len) = parse_records(&dns_message[offset..], header.ns_count());
        offset += authorities_len;

        // parse all the additionals
        let (additionals, _) = parse_records(&dns_message[offset..], header.ar_count());

        Message {
            header,
            dns_message,
            questions,
            answers: if answers.is_empty() { None } else { Some(answers) },
            authorities: if authorities.is_empty() { None } else { Some(authorities) },
            additionals: if additionals.is_empty() { None } else { Some(additionals) },
        }
        // will probably want to parse the dns_message to extract the questions and answers
    }


}

struct Header<'a> {
    dns_header: &'a [u8],
}

impl <'a> Header <'a> {
    pub fn id(&self) -> u16 {
        let id_bytes = &self.dns_header[0..2];
        u16::from_be_bytes([id_bytes[0], id_bytes[1]])
    }

    pub fn qr(&self) -> bool {
        let flags_byte = self.dns_header[2];
        (flags_byte & 0b1000_0000) != 0
    }

    pub fn opcode(&self) -> u8 {
        let flags_byte = self.dns_header[2];
        (flags_byte & 0b0111_1000) >> 3
    }

    pub fn aa(&self) -> bool {
        let flags_byte = self.dns_header[2];
        (flags_byte & 0b0000_0100) != 0
    }

    pub fn tc(&self) -> bool {
        let flags_byte = self.dns_header[2];
        (flags_byte & 0b0000_0010) != 0
    }

    pub fn rd(&self) -> bool {
        let flags_byte = self.dns_header[2];
        (flags_byte & 0b0000_0001) != 0
    }

    pub fn ra(&self) -> bool {
        let flags_byte = self.dns_header[3];
        (flags_byte & 0b1000_0000) != 0
    }

    pub fn r_code(&self) -> u8 {
        let flags_byte = self.dns_header[3];
        flags_byte & 0b0000_1111
    }

    pub fn qd_count(&self) -> u16 {
        let qd_count_bytes = &self.dns_header[4..6];
        u16::from_be_bytes([qd_count_bytes[0], qd_count_bytes[1]])
    }

    pub fn an_count(&self) -> u16 {
        let an_count_bytes = &self.dns_header[6..8];
        u16::from_be_bytes([an_count_bytes[0], an_count_bytes[1]])
    }

    pub fn ns_count(&self) -> u16 {
        let ns_count_bytes = &self.dns_header[8..10];
        u16::from_be_bytes([ns_count_bytes[0], ns_count_bytes[1]])
    }

    pub fn ar_count(&self) -> u16 {
        let ar_count_bytes = &self.dns_header[10..12];
        u16::from_be_bytes([ar_count_bytes[0], ar_count_bytes[1]])
    }
}

fn parse_questions(dns_message: &[u8], question_count: u16) -> (Vec<Question>, usize) {
    let mut questions = Vec::new();
    let mut offset = 0;
    for _ in 0..question_count {
        let (question, new_offset) = parse_question(dns_message, offset);
        questions.push(question);
        offset = new_offset;
    }
    (questions, offset)
}

fn parse_question(dns_message: &[u8], offset: usize) -> (Question, usize) {
    let (qname, new_offset) = parse_domain(dns_message, offset);
    let qtype_bytes = &dns_message[new_offset..new_offset + 2];
    let qclass_bytes = &dns_message[new_offset + 2..new_offset + 4];
    let qtype = u16::from_be_bytes([qtype_bytes[0], qtype_bytes[1]]);
    let qclass = u16::from_be_bytes([qclass_bytes[0], qclass_bytes[1]]);
    (
        Question {
            qname,
            qtype,
            qclass,
        },
        new_offset + 4, // Move past the qtype and qclass
    )
}
fn parse_records(dns_message: &[u8], record_count: u16) -> (Vec<Record>, usize) {
    let mut records = Vec::new();
    let mut offset = 0;
    for _ in 0..record_count {
        let (record, new_offset) = parse_record(dns_message, offset);
        records.push(record);
        offset = new_offset;
    }
    (records, offset)
}

fn parse_record(dns_message: &[u8], offset: usize) -> (Record, usize) {
    let (qname, new_offset) = parse_domain(dns_message, offset);
    let rtype = read_u16(dns_message, new_offset);
    let rclass = read_u16(dns_message, new_offset + 2);
    let ttl = read_u32(dns_message, new_offset + 4);
    let rdlength = read_u16(dns_message, new_offset + 8);
    let rdata_offset = new_offset + 10;
    let (record, record_offset) = parse_record_data(dns_message, rdata_offset, rtype, rdlength);
    (
        Record {
            name: qname,
            rtype,
            rclass,
            ttl,
            record,
        },
        record_offset,
    )
}

fn parse_domain(dns_message: &[u8], offset: usize) -> (String, usize) {
    let mut domain = String::new();
    let mut current_offset = offset;
    loop {
        let length = dns_message[current_offset] as usize;
        if length == 0 {
            current_offset += 1;
            break;
        }
        if (length & 0b1100_0000) == 0b1100_0000 {
            // This is a pointer
            let pointer_offset = ((length & 0b0011_1111) as usize) << 8 | dns_message[current_offset + 1] as usize;
            let (pointer_domain, _) = parse_domain(dns_message, pointer_offset);
            domain.push_str(&pointer_domain);
            current_offset += 2; // Move past the pointer
            break;
        } else {
            // This is a label
            let label = std::str::from_utf8(&dns_message[current_offset + 1..current_offset + 1 + length]).unwrap();
            domain.push_str(label);
            domain.push('.');
            current_offset += length + 1; // Move past the label
        }
    }
    if domain.ends_with('.') {
        domain.pop(); // Remove the trailing dot
    }
    (domain, current_offset)
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
        push_u16(out, 1); // IN
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

    #[test]
    fn parse_domain_labels() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let (name, offset) = parse_domain(&bytes, 0);
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
        let (name, offset) = parse_domain(&bytes, pointer_offset);
        assert_eq!(name, "example.com");
        assert_eq!(offset, pointer_offset + 2);
    }

    #[test]
    fn parse_domain_label_plus_pointer() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let pointer_offset = bytes.len();
        bytes.push(3);
        bytes.extend_from_slice(b"www");
        push_pointer(&mut bytes, 0);
        let (name, offset) = parse_domain(&bytes, pointer_offset);
        assert_eq!(name, "www.example.com");
        assert_eq!(offset, bytes.len());
    }

    #[test]
    fn parse_record_a() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        build_record_header(&mut bytes, 1, 4, 300);
        bytes.extend_from_slice(&[1, 2, 3, 4]);

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        assert_eq!(record.name, "example.com");
        assert_eq!(record.rtype, 1);
        if let RecordData::A(addr) = record.record {
            assert_eq!(addr, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected A record");
        }
    }

    #[test]
    fn parse_record_aaaa() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        build_record_header(&mut bytes, 28, 16, 120);
        bytes.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ]);

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::AAAA(addr) = record.record {
            assert_eq!(addr, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        } else {
            panic!("expected AAAA record");
        }
    }

    #[test]
    fn parse_record_cname() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "alias.example.com");
        let mut rdata = Vec::new();
        push_name(&mut rdata, "target.example.com");
        build_record_header(&mut bytes, 5, rdata.len() as u16, 180);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::CNAME(name) = record.record {
            assert_eq!(name, "target.example.com");
        } else {
            panic!("expected CNAME record");
        }
    }

    #[test]
    fn parse_record_cname_compressed_target() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let cname_offset = bytes.len();
        push_name(&mut bytes, "alias.example.com");
        let mut rdata = Vec::new();
        push_pointer(&mut rdata, 0);
        build_record_header(&mut bytes, 5, rdata.len() as u16, 180);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, cname_offset);
        assert_eq!(offset, bytes.len());
        if let RecordData::CNAME(name) = record.record {
            assert_eq!(name, "example.com");
        } else {
            panic!("expected CNAME record");
        }
    }

    #[test]
    fn parse_record_ns() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        push_name(&mut rdata, "ns1.example.com");
        build_record_header(&mut bytes, 2, rdata.len() as u16, 180);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::NS(name) = record.record {
            assert_eq!(name, "ns1.example.com");
        } else {
            panic!("expected NS record");
        }
    }

    #[test]
    fn parse_record_ptr() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "4.3.2.1.in-addr.arpa");
        let mut rdata = Vec::new();
        push_name(&mut rdata, "host.example.com");
        build_record_header(&mut bytes, 12, rdata.len() as u16, 300);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::PTR(name) = record.record {
            assert_eq!(name, "host.example.com");
        } else {
            panic!("expected PTR record");
        }
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

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::SRV { priority, weight, port, target } = record.record {
            assert_eq!(priority, 10);
            assert_eq!(weight, 5);
            assert_eq!(port, 5060);
            assert_eq!(target, "sip.example.com");
        } else {
            panic!("expected SRV record");
        }
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

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::SOA { mname, rname, serial, refresh, retry, expire, minimum, .. } = record.record {
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

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::CAA { flags, tag, value } = record.record {
            assert_eq!(flags, 0);
            assert_eq!(tag, "issue");
            assert_eq!(value, "letsencrypt.org");
        } else {
            panic!("expected CAA record");
        }
    }

    #[test]
    fn parse_record_dnskey() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        push_u16(&mut rdata, 256);
        rdata.push(3);
        rdata.push(8);
        rdata.extend_from_slice(&[1, 2, 3, 4, 5]);
        build_record_header(&mut bytes, 48, rdata.len() as u16, 3600);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::DNSKEY { flags, protocol, algorithm, public_key } = record.record {
            assert_eq!(flags, 256);
            assert_eq!(protocol, 3);
            assert_eq!(algorithm, 8);
            assert_eq!(public_key, vec![1, 2, 3, 4, 5]);
        } else {
            panic!("expected DNSKEY record");
        }
    }

    #[test]
    fn parse_record_ds() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        push_u16(&mut rdata, 12345);
        rdata.push(8);
        rdata.push(2);
        rdata.extend_from_slice(&[9, 8, 7, 6]);
        build_record_header(&mut bytes, 43, rdata.len() as u16, 3600);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::DS { key_tag, algorithm, digest_type, digest } = record.record {
            assert_eq!(key_tag, 12345);
            assert_eq!(algorithm, 8);
            assert_eq!(digest_type, 2);
            assert_eq!(digest, vec![9, 8, 7, 6]);
        } else {
            panic!("expected DS record");
        }
    }

    #[test]
    fn parse_record_rrsig() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        push_u16(&mut rdata, 1);
        rdata.push(8);
        rdata.push(2);
        push_u32(&mut rdata, 3600);
        push_u32(&mut rdata, 1700000000);
        push_u32(&mut rdata, 1690000000);
        push_u16(&mut rdata, 54321);
        push_name(&mut rdata, "example.com");
        rdata.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        build_record_header(&mut bytes, 46, rdata.len() as u16, 3600);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, 0);
        assert_eq!(offset, bytes.len());
        if let RecordData::RRSIG { type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag, signer_name, signature } = record.record {
            assert_eq!(type_covered, 1);
            assert_eq!(algorithm, 8);
            assert_eq!(labels, 2);
            assert_eq!(original_ttl, 3600);
            assert_eq!(signature_expiration, 1700000000);
            assert_eq!(signature_inception, 1690000000);
            assert_eq!(key_tag, 54321);
            assert_eq!(signer_name, "example.com");
            assert_eq!(signature, vec![0xaa, 0xbb, 0xcc]);
        } else {
            panic!("expected RRSIG record");
        }
    }

    #[test]
    fn parse_record_rrsig_compressed_signer() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let record_offset = bytes.len();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        push_u16(&mut rdata, 1);
        rdata.push(8);
        rdata.push(2);
        push_u32(&mut rdata, 3600);
        push_u32(&mut rdata, 1700000000);
        push_u32(&mut rdata, 1690000000);
        push_u16(&mut rdata, 54321);
        push_pointer(&mut rdata, 0);
        rdata.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        build_record_header(&mut bytes, 46, rdata.len() as u16, 3600);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, record_offset);
        assert_eq!(offset, bytes.len());
        if let RecordData::RRSIG { signer_name, signature, .. } = record.record {
            assert_eq!(signer_name, "example.com");
            assert_eq!(signature, vec![0xde, 0xad, 0xbe, 0xef]);
        } else {
            panic!("expected RRSIG record");
        }
    }

    #[test]
    fn parse_record_rrsig_empty_signature() {
        let mut bytes = Vec::new();
        push_name(&mut bytes, "example.com");
        let record_offset = bytes.len();
        push_name(&mut bytes, "example.com");
        let mut rdata = Vec::new();
        push_u16(&mut rdata, 1);
        rdata.push(8);
        rdata.push(1);
        push_u32(&mut rdata, 3600);
        push_u32(&mut rdata, 1700000000);
        push_u32(&mut rdata, 1690000000);
        push_u16(&mut rdata, 1);
        push_pointer(&mut rdata, 0);
        build_record_header(&mut bytes, 46, rdata.len() as u16, 3600);
        bytes.extend_from_slice(&rdata);

        let (record, offset) = parse_record(&bytes, record_offset);
        assert_eq!(offset, bytes.len());
        if let RecordData::RRSIG { signature, signer_name, .. } = record.record {
            assert_eq!(signer_name, "example.com");
            assert!(signature.is_empty());
        } else {
            panic!("expected RRSIG record");
        }
    }

    #[test]
    fn parse_message_sections() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 1, 1, 1);

        push_name(&mut message, "example.com");
        push_u16(&mut message, 1);
        push_u16(&mut message, 1);

        let a_rdata = [1, 2, 3, 4];
        push_record(&mut message, "example.com", 1, 300, &a_rdata);

        let mut ns_rdata = Vec::new();
        push_name(&mut ns_rdata, "ns1.example.com");
        push_record(&mut message, "example.com", 2, 300, &ns_rdata);

        let aaaa_rdata = [
            0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        push_record(&mut message, "ns1.example.com", 28, 300, &aaaa_rdata);

        let parsed = Message::new(&message);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.as_ref().unwrap().len(), 1);
        assert_eq!(parsed.authorities.as_ref().unwrap().len(), 1);
        assert_eq!(parsed.additionals.as_ref().unwrap().len(), 1);

        assert_eq!(parsed.questions[0].qname, "example.com");
        assert_eq!(parsed.questions[0].qtype, 1);

        if let RecordData::A(addr) = &parsed.answers.as_ref().unwrap()[0].record {
            assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected A answer");
        }

        if let RecordData::NS(name) = &parsed.authorities.as_ref().unwrap()[0].record {
            assert_eq!(name, "ns1.example.com");
        } else {
            panic!("expected NS authority");
        }

        if let RecordData::AAAA(addr) = &parsed.additionals.as_ref().unwrap()[0].record {
            assert_eq!(*addr, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        } else {
            panic!("expected AAAA additional");
        }
    }

    #[test]
    fn parse_message_multiple_records() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 2, 2, 2);

        push_name(&mut message, "example.com");
        push_u16(&mut message, 1);
        push_u16(&mut message, 1);

        let a_rdata = [1, 2, 3, 4];
        push_record(&mut message, "example.com", 1, 300, &a_rdata);

        let aaaa_rdata = [
            0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        push_record(&mut message, "example.com", 28, 300, &aaaa_rdata);

        let mut ns_rdata = Vec::new();
        push_name(&mut ns_rdata, "ns1.example.com");
        push_record(&mut message, "example.com", 2, 300, &ns_rdata);

        let mut ns2_rdata = Vec::new();
        push_name(&mut ns2_rdata, "ns2.example.com");
        push_record(&mut message, "example.com", 2, 300, &ns2_rdata);

        let mx_rdata = {
            let mut rdata = Vec::new();
            push_u16(&mut rdata, 10);
            push_name(&mut rdata, "mail.example.com");
            rdata
        };
        push_record(&mut message, "example.com", 15, 300, &mx_rdata);

        let a2_rdata = [5, 6, 7, 8];
        push_record(&mut message, "mail.example.com", 1, 300, &a2_rdata);

        let parsed = Message::new(&message);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.as_ref().unwrap().len(), 2);
        assert_eq!(parsed.authorities.as_ref().unwrap().len(), 2);
        assert_eq!(parsed.additionals.as_ref().unwrap().len(), 2);

        let answers = parsed.answers.as_ref().unwrap();
        if let RecordData::A(addr) = &answers[0].record {
            assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected A answer");
        }
        if let RecordData::AAAA(addr) = &answers[1].record {
            assert_eq!(*addr, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        } else {
            panic!("expected AAAA answer");
        }

        let authorities = parsed.authorities.as_ref().unwrap();
        if let RecordData::NS(name) = &authorities[0].record {
            assert_eq!(name, "ns1.example.com");
        } else {
            panic!("expected NS authority");
        }
        if let RecordData::NS(name) = &authorities[1].record {
            assert_eq!(name, "ns2.example.com");
        } else {
            panic!("expected NS authority");
        }

        let additionals = parsed.additionals.as_ref().unwrap();
        if let RecordData::MX { preference, exchange } = &additionals[0].record {
            assert_eq!(*preference, 10);
            assert_eq!(exchange, "mail.example.com");
        } else {
            panic!("expected MX additional");
        }
        if let RecordData::A(addr) = &additionals[1].record {
            assert_eq!(*addr, Ipv4Addr::new(5, 6, 7, 8));
        } else {
            panic!("expected A additional");
        }
    }

    #[test]
    fn parse_message_with_compressed_names() {
        let mut message = Vec::new();
        push_header(&mut message, 1, 2, 0, 0);

        push_name(&mut message, "example.com");
        push_u16(&mut message, 1);
        push_u16(&mut message, 1);

        let a_rdata = [1, 2, 3, 4];
        push_record(&mut message, "example.com", 1, 300, &a_rdata);

        let mut cname_rdata = Vec::new();
        // Pointer offsets are relative to the current records slice in this parser.
        push_pointer(&mut cname_rdata, 0);
        push_name(&mut message, "alias.example.com");
        build_record_header(&mut message, 5, cname_rdata.len() as u16, 300);
        message.extend_from_slice(&cname_rdata);

        let parsed = Message::new(&message);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.answers.as_ref().unwrap().len(), 2);

        let answers = parsed.answers.as_ref().unwrap();
        if let RecordData::A(addr) = &answers[0].record {
            assert_eq!(*addr, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected A answer");
        }

        if let RecordData::CNAME(name) = &answers[1].record {
            assert_eq!(name, "example.com");
        } else {
            panic!("expected CNAME answer");
        }
    }
}
