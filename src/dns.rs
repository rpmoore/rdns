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
        1 => { // A record
            let ip_bytes = &dns_message[offset..offset + 4];
            let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            (RecordData::A(ip), offset + 4)
        },
        28 => { // AAAA record
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
            (RecordData::AAAA(ip), offset + 16)
        },
        _ => unimplemented!(), // For now, we can just panic for unsupported record types
    }
}

impl <'a> Message<'a> {
    pub fn new(dns_message : &'a [u8]) -> Self {

        let header = Header { dns_header: &dns_message[0..DNS_HEADER_LEN] };

        // parse all the questions
        let (questions, offset) = parse_questions(&dns_message[DNS_HEADER_LEN..], header.qd_count());

        // parse all the answers

        // parse all the authorities

        // parse all the additionals

        Message { dns_message }
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
    let rtype_bytes = &dns_message[new_offset..new_offset + 2];
    let rclass_bytes = &dns_message[new_offset + 2..new_offset + 4];
    let ttl_bytes = &dns_message[new_offset + 4..new_offset + 8];
    let rdlength_bytes = &dns_message[new_offset + 8..new_offset + 10];
}

fn parse_domain(dns_message: &[u8], offset: usize) -> (String, usize) {
    let mut domain = String::new();
    let mut current_offset = offset;
    loop {
        let length = dns_message[current_offset] as usize;
        if length == 0 {
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
