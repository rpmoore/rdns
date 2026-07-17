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

//! Offline, config.toml-driven DNS protocol-conformance suite. Each test
//! maps to a specific documented resolver requirement (cited in its own
//! comment) and runs against a real rdns instance built from literal TOML
//! text via `RuntimeConfig::from_toml_str` -- no network access, so this
//! suite is safe to run in CI. Live/network coverage against real
//! well-known domains lives in `tests/e2e_upstream_live.rs`.

#[path = "support/mod.rs"]
mod support;

use rdns::protocol::RecordData;
use std::time::Duration;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Number of A records `BULK_NAME` carries -- enough that its full answer
/// (roughly `43 + BULK_COUNT * 16` bytes: fixed header/question/OPT
/// overhead plus one compressed-name A record each) sits comfortably
/// between the legacy 512-byte default and this fixture's configured
/// 1232-byte max, so it can prove both the truncate-under-512 behavior and
/// the negotiated-min-with-configured-max behavior.
const BULK_COUNT: usize = 35;
const BULK_NAME: &str = "bulk-a.rdns.test";

fn bulk_ipv4_array() -> String {
    let addresses: Vec<String> = (1..=BULK_COUNT)
        .map(|n| format!("\"203.0.113.{n}\""))
        .collect();
    format!("[{}]", addresses.join(", "))
}

fn forward_toml(upstream_port: u16) -> String {
    format!(
        r#"
per_query_deadline_ms = 2000
max_udp_payload_size = 1232

[[upstreams]]
name = "fake"
endpoint = "127.0.0.1:{upstream_port}"
protocol = "udp"
enabled = true
priority = 10
timeout_ms = 500

[[local_dns_entries]]
name = "known-a.rdns.test"
ipv4 = ["203.0.113.10"]
ttl = 300
enabled = true
public_address_acknowledged = true

[[local_dns_entries]]
name = "{BULK_NAME}"
ipv4 = {bulk_ips}
ttl = 300
enabled = true
public_address_acknowledged = true

[[local_dns_entries]]
name = "{DISABLED_NAME}"
ipv4 = ["203.0.113.20"]
ttl = 300
enabled = false
public_address_acknowledged = true
"#,
        bulk_ips = bulk_ipv4_array()
    )
}

const DISABLED_NAME: &str = "disabled.rdns.test";

// RFC 1035 §4.1.1: a well-formed standard query for a name rdns knows
// about must return NOERROR with at least one answer, echoing the
// request's own transaction ID. RA is also pinned down here: rdns offers
// recursive/forwarding service unconditionally, so every response --
// success included -- must advertise that via RA=1, not just leave it
// unset by omission.
#[tokio::test]
async fn query_for_local_entry_returns_noerror_with_answer() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x1234, "known-a.rdns.test", 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x1234);
    assert!(message.header.qr());
    assert!(message.header.ra());
    assert_eq!(message.header.r_code(), NOERROR);
    assert!(!message.answers.is_empty());

    server.shutdown().await;
}

// BIND's classic operator-fingerprint query (`dig version.bind chaos txt`):
// when `[chaos]` is enabled, rdns answers it directly with the configured
// string -- via `spawn_silent_upstream` (never responds), so this also
// proves the query never reaches the backend.
#[tokio::test]
async fn version_bind_chaos_query_returns_configured_string_when_enabled() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let mut toml = forward_toml(upstream_addr.port());
    toml.push_str(
        r#"
[chaos]
enabled = true
version_bind = "rdns-e2e-test"
"#,
    );
    let server = start_forward_server(&toml).await;

    let request = RawQueryBuilder::new(0x4001, "version.bind", 16)
        .qclass(3)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x4001);
    assert_eq!(message.header.r_code(), NOERROR);
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].rclass, 3);
    assert_eq!(
        message.answers[0].record,
        RecordData::TXT("rdns-e2e-test".to_string())
    );

    server.shutdown().await;
}

// On by default: an unconfigured rdns (no `[chaos]` table at all) must
// already answer `version.bind. CH TXT` with "rdns" -- via
// `spawn_silent_upstream` (never responds), proving the query never
// reaches the backend.
#[tokio::test]
async fn version_bind_chaos_query_answers_rdns_by_default() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x4002, "version.bind", 16)
        .qclass(3)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x4002);
    assert_eq!(message.header.r_code(), NOERROR);
    assert_eq!(message.answers.len(), 1);
    assert_eq!(message.answers[0].rclass, 3);
    assert_eq!(
        message.answers[0].record,
        RecordData::TXT("rdns".to_string())
    );

    server.shutdown().await;
}

// `[chaos].enabled = false` must opt back out to normal resolution (query
// forwarded upstream, not answered directly). Uses
// `spawn_silent_upstream`'s `JoinHandle` (resolves once the fake upstream
// actually receives bytes) rather than waiting for a full round trip/
// SERVFAIL timeout, so this stays fast and doesn't depend on
// `per_query_deadline_ms`.
#[tokio::test]
async fn version_bind_chaos_query_forwards_upstream_when_explicitly_disabled() {
    let (upstream_addr, upstream_task) = spawn_silent_upstream().await;
    let mut toml = forward_toml(upstream_addr.port());
    toml.push_str(
        r#"
[chaos]
enabled = false
"#,
    );
    let server = start_forward_server(&toml).await;

    let request = RawQueryBuilder::new(0x4003, "version.bind", 16)
        .qclass(3)
        .build();
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp test client");
    client
        .send_to(&request, server.udp_addr)
        .await
        .expect("send udp query");

    let received = tokio::time::timeout(Duration::from_secs(2), upstream_task)
        .await
        .expect(
            "chaos.enabled = false must forward version.bind upstream like any other query, \
             not get intercepted before reaching the backend",
        )
        .expect("fake upstream task panicked");
    assert!(!received.is_empty());

    server.shutdown().await;
}

// RFC 1035 §4.1.1: RD is copied from query to response, nothing more --
// but rdns *does* gate on it (see the two tests below for the cache-miss
// and cache-hit cases). Local entries are the exception: they're
// statically configured, always-available data, not "new work" a
// recursive/forwarding resolver would do on the client's behalf, so RD=0
// still gets served here exactly like RD=1 would.
#[tokio::test]
async fn rd_zero_still_serves_a_local_entry() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x1235, "known-a.rdns.test", 1)
        .rd(false)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x1235);
    assert!(!message.header.rd(), "RD=0 on the query must echo RD=0");
    assert!(message.header.ra());
    assert_eq!(message.header.r_code(), NOERROR);
    assert!(
        !message.answers.is_empty(),
        "a local entry is data rdns already has, not new work -- RD=0 must still get it"
    );

    server.shutdown().await;
}

// RFC 1035 §4.1.1: rdns has no authoritative-only mode with delegation
// data to hand back as a referral, so RD=0 is implemented as "cache-only"
// -- matching how a public recursive resolver like 1.1.1.1 treats RD=0
// (confirmed by hand: `dig +norecurse` gets NOERROR for an already-cached
// name but SERVFAIL for a cold one). A name that isn't a local entry and
// isn't already cached must be refused with SERVFAIL under RD=0, not
// forwarded to answer it with fresh backend work.
#[tokio::test]
async fn rd_zero_query_is_refused_on_a_cache_miss() {
    let (upstream_addr, upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x1236, "never-queried.rdns.test", 1)
        .rd(false)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x1236);
    assert!(!message.header.rd(), "RD=0 on the query must echo RD=0");
    assert_eq!(message.header.r_code(), SERVFAIL);
    assert!(message.answers.is_empty());

    // The fake upstream never receives a query at all: refusing RD=0 on a
    // miss must happen before any backend fetch is attempted.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), upstream_task)
            .await
            .is_err(),
        "the fake upstream must never have been queried"
    );

    server.shutdown().await;
}

// The other half of the cache-only split above -- once a name is already
// cached, RD=0 must serve it -- can't be exercised through this offline
// harness: `start_forward_server` wires forward-mode e2e servers to
// `NoopDnsCache` (every non-local-entry query is a permanent miss by
// construction here), so there's no way to warm a real cache entry through
// this path. That side is instead covered at the resolver-unit level by
// `resolve_rewrites_rd_flag_for_current_request_on_cache_hit` and
// `rd_zero_query_is_refused_on_a_cache_miss` in `src/resolver/mod.rs`,
// which seed a real `ShardedDnsCache` directly.

// RFC 1035 §4.1.1: opcodes other than QUERY (0) are not supported by rdns
// and must be rejected with NOTIMP, not silently answered or dropped.
#[tokio::test]
async fn unsupported_opcode_returns_notimp() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x2222, "known-a.rdns.test", 1)
        .opcode(1) // IQUERY
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x2222);
    assert_eq!(message.header.r_code(), NOTIMP);

    server.shutdown().await;
}

// RFC 1035 §4.1.1: QR distinguishes queries from responses. A packet with
// QR=1 arriving at the server is not a query at all and must be rejected
// (FORMERR), never answered as if it were one.
#[tokio::test]
async fn response_shaped_query_qr_bit_set_returns_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x3333, "known-a.rdns.test", 1)
        .qr(true)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x3333);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// RFC 1035 §4.1.1 describes QDCOUNT as "usually 1"; rdns only supports the
// single-question convention essentially every deployed resolver uses, so
// QDCOUNT=0 is rejected as FORMERR rather than treated as "answer nothing".
#[tokio::test]
async fn zero_questions_returns_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x4444, "known-a.rdns.test", 1)
        .qdcount(0)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x4444);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// RFC 1035 §4.1.1: QDCOUNT>1 is likewise rejected -- rdns only supports the
// single-question convention essentially every deployed resolver uses.
#[tokio::test]
async fn multiple_questions_returns_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x5555, "known-a.rdns.test", 1)
        .qdcount(2)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x5555);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// RFC 1035 §4.1.1: a query carries no answer/authority records of its own.
// A client sending ANCOUNT>0 on a query is malformed and must be rejected
// as FORMERR rather than have its bogus answer section trusted or ignored.
#[tokio::test]
async fn nonzero_answer_count_in_query_returns_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x6666, "known-a.rdns.test", 1)
        .answer_count(1)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x6666);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

/// Raw 12-byte DNS header, for the handful of malformed-body tests below
/// that need full control over the bytes following it (`RawQueryBuilder`
/// only ever emits well-formed bodies).
fn header_bytes(
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&qdcount.to_be_bytes());
    bytes.extend_from_slice(&ancount.to_be_bytes());
    bytes.extend_from_slice(&nscount.to_be_bytes());
    bytes.extend_from_slice(&arcount.to_be_bytes());
    bytes
}

const RD_FLAG: u16 = 0x0100;
const CD_FLAG: u16 = 0x0010;

// RFC 1035 §4.1.1 / §4.1.2: a packet too short to even contain a DNS header
// can't be parsed at all. rdns still recovers the transaction ID directly
// off the wire's first two bytes (independent of full header parsing) and
// echoes it on the resulting FORMERR, rather than dropping the datagram or
// replying with ID=0.
#[tokio::test]
async fn garbage_shorter_than_a_dns_header_still_echoes_id_with_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = vec![0x77, 0x77, 0x00, 0x00];
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x7777);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// RFC 1035 §4.1.4: a name compression pointer must point strictly backward
// to an earlier, already-valid position -- a pointer that resolves back to
// itself (or otherwise loops) must be rejected as malformed rather than
// hang or crash the parser.
#[tokio::test]
async fn compression_pointer_loop_returns_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut request = header_bytes(0x8888, RD_FLAG, 1, 0, 0, 0);
    // Question starts at offset 12; this pointer (0xC0 0x0C = offset 12)
    // points at itself.
    request.extend_from_slice(&[0xc0, 0x0c]);
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x8888);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// The malformed-body tests above all go over UDP, but body validation
// (`Message::parse_standard_query`) runs on the same parsed bytes
// regardless of transport -- TCP only adds a length-prefix framing layer
// on top (`serve_tcp_connection`). Rather than duplicating every UDP
// malformed-body case over TCP (pure redundant coverage of the identical
// validation code), this one representative case proves the two layers
// actually compose: a malformed body inside a validly length-prefixed TCP
// frame still gets a correctly-framed FORMERR response back, not a hang,
// a reset connection, or an unframed reply.
#[tokio::test]
async fn compression_pointer_loop_returns_formerr_over_tcp() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut request = header_bytes(0x8889, RD_FLAG, 1, 0, 0, 0);
    request.extend_from_slice(&[0xc0, 0x0c]);
    let response = send_tcp(server.tcp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x8889);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// RFC 1035 §4.1.2: a label length octet's top two bits must be `00`
// (ordinary label) or `11` (compression pointer) -- `10`/`01` are reserved
// and must be rejected rather than interpreted as a label length.
#[tokio::test]
async fn invalid_label_length_returns_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut request = header_bytes(0x9999, RD_FLAG, 1, 0, 0, 0);
    request.push(0b1000_0000); // reserved length-octet pattern
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x9999);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// rdns caps a standard query at one additional record total (not just one
// OPT -- RFC 6891 §6.1.1 only mandates uniqueness *of the OPT record*, it
// doesn't forbid other additional-section RRs like TSIG/SIG(0) that rdns
// doesn't implement). Two records here -- both OPT, so RFC 6891 alone
// would already require FORMERR for the duplicate -- must be rejected.
#[tokio::test]
async fn more_than_one_additional_record_returns_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut request = header_bytes(0xaaaa, RD_FLAG, 1, 0, 0, 2);
    for label in "known-a.rdns.test".split('.') {
        request.push(label.len() as u8);
        request.extend_from_slice(label.as_bytes());
    }
    request.push(0);
    request.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    request.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    for _ in 0..2 {
        request.push(0); // OPT owner name: root
        request.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        request.extend_from_slice(&1232u16.to_be_bytes()); // CLASS = udp payload size
        request.extend_from_slice(&0u32.to_be_bytes()); // ext rcode/version/flags
        request.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    }
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0xaaaa);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// rdns implements no additional-section RR type other than OPT (no
// TSIG/SIG(0) support) -- this is an rdns scope limit, not something RFC
// 6891 itself mandates. A non-OPT record in the query's one allowed
// additional-record slot is therefore rejected as FORMERR rather than
// silently ignored or passed through.
#[tokio::test]
async fn non_opt_single_additional_record_returns_formerr() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut request = header_bytes(0xbbbb, RD_FLAG, 1, 0, 0, 1);
    for label in "known-a.rdns.test".split('.') {
        request.push(label.len() as u8);
        request.extend_from_slice(label.as_bytes());
    }
    request.push(0);
    request.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    request.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    request.push(0); // owner name: root
    request.extend_from_slice(&16u16.to_be_bytes()); // TYPE = TXT, not OPT
    request.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    request.extend_from_slice(&0u32.to_be_bytes()); // TTL
    request.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0xbbbb);
    assert_eq!(message.header.r_code(), FORMERR);

    server.shutdown().await;
}

// RFC 6891 §6.1.1 (responder OPT is mandatory for an EDNS query) and
// RFC 4035 §3.2.2 (CD must be copied query -> response): even when the
// *body* fails to parse (here: an EDNS option inside the OPT record's own
// RDATA that declares a length longer than its RDATA), rdns's bounded
// recovery path still recognizes the header, question, OPT presence and
// CD bit, and the resulting FORMERR still carries an OPT record and the
// query's own CD bit rather than silently dropping EDNS/CD context on the
// error path.
#[tokio::test]
async fn formerr_response_still_carries_opt_and_cd_when_recoverable() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut request = header_bytes(0xcccc, RD_FLAG | CD_FLAG, 1, 0, 0, 1);
    for label in "known-a.rdns.test".split('.') {
        request.push(label.len() as u8);
        request.extend_from_slice(label.as_bytes());
    }
    request.push(0);
    request.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    request.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    request.push(0); // OPT owner name: root
    request.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    request.extend_from_slice(&1232u16.to_be_bytes()); // CLASS = udp payload size
    request.extend_from_slice(&0u32.to_be_bytes()); // ext rcode/version/flags
    request.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    request.extend_from_slice(&10u16.to_be_bytes()); // option code
    request.extend_from_slice(&255u16.to_be_bytes()); // option length: bogus, longer than the RDATA actually holds
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0xcccc);
    assert_eq!(message.header.r_code(), FORMERR);
    assert!(
        opt_record(&message).is_some(),
        "expected a recovered OPT record on the FORMERR response"
    );
    assert!(
        message.header.cd(),
        "expected the query's CD bit to be mirrored onto the FORMERR response"
    );

    server.shutdown().await;
}

// RFC 6891 §6.1.1: a non-EDNS query gets a non-EDNS response -- rdns must
// not invent an OPT record the requester never asked for.
#[tokio::test]
async fn query_without_edns_gets_no_opt_in_response() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x1001, "known-a.rdns.test", 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert!(opt_record(&message).is_none());

    server.shutdown().await;
}

// RFC 6891 §6.1.1: an EDNS query must get an OPT record back, and that
// record's UDP payload size describes *this resolver's own* configured
// size (1232 in the fixture), not an echo of whatever the requester
// advertised (4096 here) -- the OPT payload-size field is sender-specific.
#[tokio::test]
async fn query_with_edns_gets_opt_echoed_with_responder_payload_size() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x1002, "known-a.rdns.test", 1)
        .edns(4096, false)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    let opt = opt_record(&message).expect("expected an OPT record in the response");
    match &opt.record {
        RecordData::OPT(info) => assert_eq!(info.udp_payload_size, 1232),
        other => panic!("expected RecordData::OPT, got {other:?}"),
    }

    server.shutdown().await;
}

// RFC 6891 §6.2.3: the effective UDP payload size a resolver uses to
// decide whether to truncate is `max(advertised, 512).min(configured_max)`
// (`Message::effective_udp_payload_size`). An advertised size *above* the
// configured max (4096 here, against a 1232 max) must be capped down to
// the configured max, not honored outright; an advertised size *below*
// the legacy default (300) must be floored up to 512, not honored either.
// `BULK_NAME`'s answer is sized to fall strictly between those two values,
// so it's truncated in the floored-up case but not in the capped-down one.
#[tokio::test]
async fn udp_payload_size_is_negotiated_between_advertised_and_configured_max() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request_above_max = RawQueryBuilder::new(0x1003, BULK_NAME, 1)
        .edns(4096, false)
        .build();
    let response_above_max = send_udp(server.udp_addr, &request_above_max).await;
    let message_above_max = parse_response(&response_above_max);
    assert_eq!(message_above_max.header.r_code(), NOERROR);
    assert!(
        !message_above_max.header.tc(),
        "advertised size above the configured max should be capped to the configured max, not truncate"
    );
    assert_eq!(message_above_max.answers.len(), BULK_COUNT);

    let request_below_default = RawQueryBuilder::new(0x1004, BULK_NAME, 1)
        .edns(300, false)
        .build();
    let response_below_default = send_udp(server.udp_addr, &request_below_default).await;
    let message_below_default = parse_response(&response_below_default);
    assert!(
        message_below_default.header.tc(),
        "advertised size below the legacy default should be floored to 512, which is too small for the bulk answer"
    );
    assert!(message_below_default.answers.is_empty());

    server.shutdown().await;
}

// RFC 6891 §6.2.3 / RFC 1035 §4.2.1: a UDP response too large for the
// negotiated payload size must be truncated (TC=1) rather than sent
// oversized or silently dropped. rdns's specific truncation strategy is
// all-or-nothing (empty answer section) rather than filling in as many
// complete RRs as fit -- the RFCs permit either, so `answers.is_empty()`
// below pins down rdns's chosen strategy, not a spec mandate.
#[tokio::test]
async fn oversized_answer_is_truncated_over_udp() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    // No EDNS at all -> legacy 512-byte default, too small for BULK_COUNT
    // answers.
    let request = RawQueryBuilder::new(0x1005, BULK_NAME, 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert!(message.header.tc());
    assert!(message.answers.is_empty());

    server.shutdown().await;
}

// RFC 1035 §4.2.2 / RFC 7766: a TC=1 UDP response is a promise that the
// same query answered over TCP will fit. rdns's own TCP listener must
// return the full, untruncated answer for the identical query.
#[tokio::test]
async fn truncated_response_client_retries_over_tcp_and_gets_full_answer() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x1006, BULK_NAME, 1).build();
    let response = send_tcp(server.tcp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert!(!message.header.tc());
    assert_eq!(message.answers.len(), BULK_COUNT);

    server.shutdown().await;
}

// RFC 6891 §6.1.3: rdns implements EDNS version 0 only. A query
// advertising any other version must get BADVERS back -- extended RCODE
// 16, a 12-bit value split across the header's 4-bit RCODE field (which
// must be 0) and the OPT record's extended-RCODE byte (which must be 1) --
// never a normal answer, and never routed to the backend.
#[tokio::test]
async fn nonzero_edns_version_returns_badvers() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut request = header_bytes(0x1007, RD_FLAG, 1, 0, 0, 1);
    for label in "known-a.rdns.test".split('.') {
        request.push(label.len() as u8);
        request.extend_from_slice(label.as_bytes());
    }
    request.push(0);
    request.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    request.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    request.push(0); // OPT owner name: root
    request.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    request.extend_from_slice(&1232u16.to_be_bytes()); // CLASS = udp payload size
    // ext rcode(8)=0 | version(8)=7 | flags(16)=0 -- EDNS version 7, not 0.
    request.extend_from_slice(&0x0007_0000u32.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH

    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x1007);
    assert!(
        message.answers.is_empty(),
        "BADVERS must not carry an answer"
    );

    let opt = opt_record(&message).expect("expected an OPT record on a BADVERS response");
    let RecordData::OPT(info) = &opt.record else {
        unreachable!("opt_record only ever returns OPT records");
    };
    let combined_extended_rcode =
        (u16::from(info.extended_rcode) << 4) | u16::from(message.header.r_code());
    assert_eq!(combined_extended_rcode, 16, "16 == BADVERS");
    assert_eq!(
        info.version, 0,
        "the response OPT must advertise the version rdns actually supports"
    );

    server.shutdown().await;
}

const SIGNED_NAME: &str = "signed.rdns.test";

fn recursive_toml(root_hint_addr: std::net::SocketAddr) -> String {
    format!(
        r#"
per_query_deadline_ms = 2000
max_udp_payload_size = 1232

[resolution]
mode = "recursive"
generation = 0

[resolution.recursive]
root_hints = "custom"
root_hints_version = "e2e-fixture"
per_authority_timeout_ms = 500

[[resolution.recursive.root_hints_entries]]
name = "fake-root."
endpoints = ["{root_hint_addr}"]
"#
    )
}

/// A directly-answering, `AA=1` response for `name` carrying both an A
/// record and an RRSIG covering it -- `evaluate_authority_response`
/// accepts any `AA=1` answer matching the queried question as terminal
/// (no referral needed), so this fake "root hint" can stand in for a full
/// root -> TLD -> authority chain for testing purposes.
fn signed_authority_response(id: u16, name: &str, ip: [u8; 4]) -> Vec<u8> {
    const AA_QR_RA_FLAGS: u16 = 0x8480; // QR=1, AA=1, RA=1
    let mut bytes = header_bytes(id, AA_QR_RA_FLAGS, 1, 2, 0, 0);
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    bytes.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    // Answer 1: A record.
    bytes.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to question
    bytes.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    bytes.extend_from_slice(&300u32.to_be_bytes()); // TTL
    bytes.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    bytes.extend_from_slice(&ip);

    // Answer 2: RRSIG covering the A record. Signature/timing fields are
    // fixture placeholders -- rdns performs no cryptographic validation
    // today (`DnssecValidationMode::Disabled`), so only the record's
    // presence/absence in the client-facing response is under test here.
    bytes.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to question
    bytes.extend_from_slice(&46u16.to_be_bytes()); // TYPE RRSIG
    bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    bytes.extend_from_slice(&300u32.to_be_bytes()); // TTL
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&1u16.to_be_bytes()); // type covered: A
    rdata.push(8); // algorithm: RSASHA256
    rdata.push(2); // labels
    rdata.extend_from_slice(&300u32.to_be_bytes()); // original ttl
    rdata.extend_from_slice(&2_000_000_000u32.to_be_bytes()); // signature expiration
    rdata.extend_from_slice(&1_000_000_000u32.to_be_bytes()); // signature inception
    rdata.extend_from_slice(&12345u16.to_be_bytes()); // key tag
    for label in "rdns.test".split('.') {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0); // signer name (uncompressed)
    rdata.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // fixture signature bytes
    bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    bytes.extend_from_slice(&rdata);

    bytes
}

fn has_rrsig(message: &rdns::protocol::Message) -> bool {
    message
        .answers
        .iter()
        .any(|record| matches!(record.record, RecordData::RRSIG { .. }))
}

// RFC 4035 §3.2.1 / §4.5: DNSSEC RRs (here, RRSIG) are only included in a
// response when the requester's own DO bit asked for them. rdns's
// recursive backend always fetches DNSSEC material from authorities
// regardless of the client's DO flag (RFC 6840 §5.9), but must filter it
// back out at response-assembly time for a DO=0 client.
#[tokio::test]
async fn do_bit_zero_filters_dnssec_rrs() {
    let (root_hint_addr, _root_hint_task) = spawn_canned_authority(move |id| {
        signed_authority_response(id, SIGNED_NAME, [203, 0, 113, 50])
    })
    .await;
    let server = start_recursive_server_from_toml(&recursive_toml(root_hint_addr)).await;

    let request = RawQueryBuilder::new(0x2001, SIGNED_NAME, 1)
        .edns(1232, false)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert!(
        !message.answers.is_empty(),
        "expected the A record to remain"
    );
    assert!(!has_rrsig(&message), "DO=0 must not receive the RRSIG");

    server.shutdown().await;
}

#[tokio::test]
async fn do_bit_one_preserves_dnssec_rrs() {
    let (root_hint_addr, _root_hint_task) = spawn_canned_authority(move |id| {
        signed_authority_response(id, SIGNED_NAME, [203, 0, 113, 51])
    })
    .await;
    let server = start_recursive_server_from_toml(&recursive_toml(root_hint_addr)).await;

    let request = RawQueryBuilder::new(0x2002, SIGNED_NAME, 1)
        .edns(1232, true)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert!(has_rrsig(&message), "DO=1 must receive the RRSIG");

    server.shutdown().await;
}

// RFC 4035 §3.2.2: a security-aware resolver MUST copy the query's CD bit
// onto the response, regardless of its own value.
#[tokio::test]
async fn cd_bit_is_copied_from_query_regardless_of_value() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    for cd in [false, true] {
        let request = RawQueryBuilder::new(0x2003, "known-a.rdns.test", 1)
            .cd(cd)
            .build();
        let response = send_udp(server.udp_addr, &request).await;
        let message = parse_response(&response);
        assert_eq!(
            message.header.cd(),
            cd,
            "CD={cd} was not mirrored onto the response"
        );
    }

    server.shutdown().await;
}

// RFC 4035 §3.2.3: AD must only be set when the responder itself performed
// DNSSEC validation and found the data authentic. rdns's
// `DnssecValidationMode` is `Disabled` (no chain-of-trust validation is
// implemented at all -- see docs/plans/dns_gaps.md), so AD must never be
// set on any response it sends, regardless of query shape. This is a
// standing regression guard: setting AD=1 with no validation behind it
// would be a false compliance claim.
#[tokio::test]
async fn ad_bit_is_never_set_on_any_response() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let plain = RawQueryBuilder::new(0x2004, "known-a.rdns.test", 1).build();
    let plain_response = parse_response(&send_udp(server.udp_addr, &plain).await);
    assert!(!plain_response.header.ad());

    let do_query = RawQueryBuilder::new(0x2005, "known-a.rdns.test", 1)
        .edns(1232, true)
        .build();
    let do_response = parse_response(&send_udp(server.udp_addr, &do_query).await);
    assert!(!do_response.header.ad());

    let malformed = RawQueryBuilder::new(0x2006, "known-a.rdns.test", 1)
        .opcode(1)
        .build();
    let malformed_response = parse_response(&send_udp(server.udp_addr, &malformed).await);
    assert_eq!(malformed_response.header.r_code(), NOTIMP);
    assert!(!malformed_response.header.ad());

    server.shutdown().await;
}

/// An NXDOMAIN response carrying a SOA record in the AUTHORITY section
/// (RFC 2308 §2.2: the SOA's MINIMUM field lets a negative-caching
/// resolver derive a negative-cache TTL for the name).
fn nxdomain_with_soa_response(id: u16, name: &str) -> Vec<u8> {
    const QR_RA_NXDOMAIN_FLAGS: u16 = 0x8183; // QR=1, RA=1, RCODE=3 (NXDOMAIN)
    let mut bytes = header_bytes(id, QR_RA_NXDOMAIN_FLAGS, 1, 0, 1, 0);
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    bytes.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    // Authority: SOA for the parent zone.
    for label in "rdns.test".split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&6u16.to_be_bytes()); // TYPE SOA
    bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    bytes.extend_from_slice(&300u32.to_be_bytes()); // TTL
    let mut rdata = Vec::new();
    for label in ["ns1", "rdns", "test"] {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0); // mname
    for label in ["hostmaster", "rdns", "test"] {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0); // rname
    rdata.extend_from_slice(&1u32.to_be_bytes()); // serial
    rdata.extend_from_slice(&3600u32.to_be_bytes()); // refresh
    rdata.extend_from_slice(&600u32.to_be_bytes()); // retry
    rdata.extend_from_slice(&86400u32.to_be_bytes()); // expire
    rdata.extend_from_slice(&300u32.to_be_bytes()); // minimum
    bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&rdata);

    bytes
}

// RFC 1035 §3.7 / RFC 2308 §2.2: a name the resolver has no local record
// for and that upstream reports as nonexistent must be passed back to the
// client as NXDOMAIN, with the SOA record upstream provided for negative
// caching preserved.
#[tokio::test]
async fn name_not_in_local_entries_falls_through_to_upstream_nxdomain() {
    let (upstream_addr, _upstream_task) =
        spawn_canned_upstream(|id| nxdomain_with_soa_response(id, "nowhere.rdns.test")).await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x3001, "nowhere.rdns.test", 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NXDOMAIN);
    assert!(message.answers.is_empty());
    assert!(
        message
            .authorities
            .iter()
            .any(|record| matches!(record.record, RecordData::SOA { .. })),
        "expected the upstream's SOA to be preserved for negative caching"
    );

    server.shutdown().await;
}

// RFC 2308 §2.2 (NODATA): a name that exists but has no record of the
// queried type returns NOERROR with an empty answer section, not NXDOMAIN
// and not SERVFAIL. `known-a.rdns.test` is a local entry with only an A
// record configured; querying it for AAAA must be answered locally as
// NODATA without ever reaching the upstream.
#[tokio::test]
async fn known_name_wrong_qtype_returns_noerror_nodata() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x3002, "known-a.rdns.test", 28).build(); // AAAA
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert!(message.answers.is_empty());

    server.shutdown().await;
}

// A backend that never answers within the configured per-upstream timeout
// (`timeout_ms` in this fixture's `[[upstreams]]`, parsed from real TOML)
// must fail the query as SERVFAIL rather than hang the client forever.
#[tokio::test]
async fn upstream_timeout_maps_to_servfail_via_toml_configured_timeout() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x3003, "slow.rdns.test", 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x3003);
    assert_eq!(message.header.r_code(), SERVFAIL);

    server.shutdown().await;
}

// `enabled = false` on a `[[local_dns_entries]]` fixture must mean the
// entry is never served locally -- the query falls through to the
// backend like any other unknown name, rather than being answered (or
// blocked) locally.
#[tokio::test]
async fn disabled_local_entry_is_not_served_locally() {
    let (upstream_addr, _upstream_task) =
        spawn_canned_upstream(|id| a_response_from_upstream(id, DISABLED_NAME, [198, 51, 100, 77]))
            .await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x3004, DISABLED_NAME, 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert_eq!(message.answers.len(), 1);
    match &message.answers[0].record {
        RecordData::A(address) => assert_eq!(*address, std::net::Ipv4Addr::new(198, 51, 100, 77)),
        other => panic!("expected an A record from upstream, got {other:?}"),
    }

    server.shutdown().await;
}

fn a_response_from_upstream(id: u16, name: &str, ip: [u8; 4]) -> Vec<u8> {
    const QR_RA_FLAGS: u16 = 0x8180; // QR=1, RA=1
    let mut bytes = header_bytes(id, QR_RA_FLAGS, 1, 1, 0, 0);
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    bytes.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    bytes.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to question
    bytes.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    bytes.extend_from_slice(&300u32.to_be_bytes()); // TTL
    bytes.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    bytes.extend_from_slice(&ip);
    bytes
}

// RFC 1035 §4.2.2 / RFC 7766: a client may query rdns directly over TCP,
// length-prefixed, and get a well-formed, correctly-framed answer back.
#[tokio::test]
async fn tcp_query_response_round_trip_with_length_prefix() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let request = RawQueryBuilder::new(0x4001, "known-a.rdns.test", 1).build();
    let response = send_tcp(server.tcp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x4001);
    assert_eq!(message.header.r_code(), NOERROR);
    assert!(!message.answers.is_empty());

    server.shutdown().await;
}

// RFC 1035 §4.2.2: a TCP length prefix declaring fewer bytes than a DNS
// header can hold (12) can never be a real query. rdns closes the
// connection rather than waiting for a body that would never complete a
// valid message.
#[tokio::test]
async fn tcp_frame_shorter_than_dns_header_closes_connection() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut stream = TcpStream::connect(server.tcp_addr)
        .await
        .expect("connect tcp test client");
    stream
        .write_all(&5u16.to_be_bytes()) // declares a 5-byte message: too short for a header
        .await
        .expect("write short length prefix");

    let mut buf = [0u8; 1];
    let read_result = stream.read(&mut buf).await;
    assert!(
        matches!(read_result, Ok(0)) || read_result.is_err(),
        "expected the connection to close rather than yield a response, got {read_result:?}"
    );

    server.shutdown().await;
}

// A persistent TCP connection may carry more than one query in sequence
// (RFC 1035 §4.2.2 makes TCP a stream, not one-query-per-connection);
// rdns must keep matching each response to its own request's transaction
// ID rather than confusing them.
#[tokio::test]
async fn sequential_queries_on_one_tcp_connection_get_correctly_matched_responses() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut stream = TcpStream::connect(server.tcp_addr)
        .await
        .expect("connect tcp test client");

    let first_request = RawQueryBuilder::new(0x4002, "known-a.rdns.test", 1).build();
    send_tcp_query(&mut stream, &first_request).await;
    let first_response = parse_response(&read_tcp_response(&mut stream).await);
    assert_eq!(first_response.header.id, 0x4002);
    assert_eq!(first_response.header.r_code(), NOERROR);

    let second_request = RawQueryBuilder::new(0x4003, BULK_NAME, 1).build();
    send_tcp_query(&mut stream, &second_request).await;
    let second_response = parse_response(&read_tcp_response(&mut stream).await);
    assert_eq!(second_response.header.id, 0x4003);
    assert_eq!(second_response.header.r_code(), NOERROR);
    assert_eq!(second_response.answers.len(), BULK_COUNT);

    server.shutdown().await;
}

// RFC 7766 §6.2.1.1: a DNS server must accept pipelined TCP queries -- it
// must not require reading a response before the client is allowed to
// write its next query. Both queries are written back-to-back here, before
// either response is read (unlike the sequential test above, which reads
// each response before sending the next request), and rdns must still
// answer both, correctly matched by transaction ID.
#[tokio::test]
async fn pipelined_tcp_queries_get_correctly_matched_responses() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;

    let mut stream = TcpStream::connect(server.tcp_addr)
        .await
        .expect("connect tcp test client");

    let first_request = RawQueryBuilder::new(0x4004, "known-a.rdns.test", 1).build();
    let second_request = RawQueryBuilder::new(0x4005, BULK_NAME, 1).build();
    send_tcp_query(&mut stream, &first_request).await;
    send_tcp_query(&mut stream, &second_request).await;

    let first_response = parse_response(&read_tcp_response(&mut stream).await);
    let second_response = parse_response(&read_tcp_response(&mut stream).await);

    assert_eq!(first_response.header.id, 0x4004);
    assert_eq!(first_response.header.r_code(), NOERROR);
    assert_eq!(second_response.header.id, 0x4005);
    assert_eq!(second_response.header.r_code(), NOERROR);
    assert_eq!(second_response.answers.len(), BULK_COUNT);

    server.shutdown().await;
}

// The TCP pipelining test above proves rdns doesn't deadlock on pipelined
// writes, but a single TCP connection is still served strictly one query
// at a time (`serve_tcp_connection`'s read -> resolve -> write loop) --
// that's *not* concurrent answering. UDP is: `UdpDnsServer::serve_until`
// spawns one task per received datagram, so independent queries can
// complete out of arrival order. Proof: `SLOW_NAME` falls through to a
// fake upstream that deliberately stalls before replying; `known-a.rdns
// .test` is answered locally with no upstream round trip at all. Both are
// sent back-to-back on one client socket -- if UDP handling were
// serialized like a single TCP connection, the fast query's answer would
// be stuck behind the slow one's multi-hundred-millisecond upstream delay.
// It isn't.
#[tokio::test]
async fn independent_udp_queries_are_answered_concurrently() {
    const SLOW_NAME: &str = "delayed.rdns.test";
    const UPSTREAM_DELAY: Duration = Duration::from_millis(300);

    let upstream_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind delayed fake upstream");
    let upstream_addr = upstream_socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (_len, source) = upstream_socket
            .recv_from(&mut buf)
            .await
            .expect("delayed upstream recv");
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        tokio::time::sleep(UPSTREAM_DELAY).await;
        let response = a_response_from_upstream(id, SLOW_NAME, [203, 0, 113, 30]);
        upstream_socket
            .send_to(&response, source)
            .await
            .expect("delayed upstream send");
    });

    let server = start_forward_server(&forward_toml(upstream_addr.port())).await;
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind test client");

    let slow_request = RawQueryBuilder::new(0x7001, SLOW_NAME, 1).build();
    let fast_request = RawQueryBuilder::new(0x7002, "known-a.rdns.test", 1).build();
    client
        .send_to(&slow_request, server.udp_addr)
        .await
        .expect("send slow query");
    client
        .send_to(&fast_request, server.udp_addr)
        .await
        .expect("send fast query");

    // The property under test is ordering, not a specific latency: a
    // generous overall timeout guards against a genuine hang without
    // making the assertion flaky under CI scheduling jitter (see below for
    // why ordering alone is a sufficient proof of concurrency).
    let mut buf = [0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("timed out waiting for either response")
        .expect("recv fast query answer");
    let first_response = parse_response(&buf[..len]);
    assert_eq!(
        first_response.header.id, 0x7002,
        "the fast query must be answered before the slow one, not stuck behind it"
    );

    let (len, _) = client
        .recv_from(&mut buf)
        .await
        .expect("recv slow query answer");
    let second_response = parse_response(&buf[..len]);
    assert_eq!(second_response.header.id, 0x7001);

    server.shutdown().await;
}

// The production UDP intake path (`UdpDnsServer::bind_configured`, the
// wiring `main.rs` uses) binds several `SO_REUSEPORT` sockets per
// configured address on Linux, each with its own serve loop, and the
// kernel picks which socket receives each datagram. Every other test in
// this suite drives a single hand-bound socket (`UdpDnsServer::new`), so
// this is the one test covering that multi-socket wiring end to end: a
// query must be answered no matter which socket the kernel routes it to,
// and all sockets must serve from the same shared cache. The canned
// upstream answers exactly one request and then goes away, so the first
// query is the only backend fetch permitted -- if any later query missed
// the shared cache (e.g. per-socket cache state), it would fall through
// to the dead upstream and come back SERVFAIL instead of an answer. Each
// query uses a fresh client socket so its source port (an input to the
// kernel's SO_REUSEPORT flow hash) varies, spreading queries across the
// bound sockets.
#[tokio::test]
async fn multi_socket_udp_listener_answers_from_shared_cache_on_every_socket() {
    const MULTI_NAME: &str = "multi-socket.rdns.test";
    let (upstream_addr, _upstream_task) =
        spawn_canned_upstream(|id| a_response_from_upstream(id, MULTI_NAME, [198, 51, 100, 42]))
            .await;
    let server = start_forward_server_multi_socket(&forward_toml(upstream_addr.port())).await;

    for i in 0..20u16 {
        let id = 0x6100 + i;
        let request = RawQueryBuilder::new(id, MULTI_NAME, 1).build();
        let response = send_udp(server.udp_addr, &request).await;
        let message = parse_response(&response);
        assert_eq!(message.header.id, id);
        assert_eq!(
            message.header.r_code(),
            NOERROR,
            "query {i} must succeed (first from the upstream, the rest from the shared cache)"
        );
        assert_eq!(
            message.answers.len(),
            1,
            "query {i} must carry the cached answer"
        );
        match &message.answers[0].record {
            RecordData::A(address) => {
                assert_eq!(*address, std::net::Ipv4Addr::new(198, 51, 100, 42));
            }
            other => panic!("expected the cached A record, got {other:?}"),
        }
    }

    server.shutdown().await;
}

const ZONE_ROOT: &str = "zone.rdns.test";
const ZONE_HOST: &str = "www.zone.rdns.test";

fn zone_file_source() -> String {
    format!(
        r#"$ORIGIN {ZONE_ROOT}.
@ 300 IN SOA ns1.{ZONE_ROOT}. hostmaster.{ZONE_ROOT}. 1 3600 600 86400 300
@ 300 IN NS ns1.{ZONE_ROOT}.
www 300 IN A 203.0.113.88
"#
    )
}

// `[[local_zones]]` (a BIND-style zone file, additive to
// `[[local_dns_entries]]`) is a real, independent configuration source --
// its records must be served the same as an inline local entry would be.
#[tokio::test]
async fn local_zone_file_records_are_served() {
    let (upstream_addr, _upstream_task) = spawn_silent_upstream().await;
    let server = support::start_forward_server_with_zone_file(
        &forward_toml(upstream_addr.port()),
        ZONE_ROOT,
        &zone_file_source(),
    )
    .await;

    let request = RawQueryBuilder::new(0x4004, ZONE_HOST, 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert_eq!(message.answers.len(), 1);
    match &message.answers[0].record {
        RecordData::A(address) => assert_eq!(*address, std::net::Ipv4Addr::new(203, 0, 113, 88)),
        other => panic!("expected an A record from the zone file, got {other:?}"),
    }

    server.shutdown().await;
}
