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

//! Network-dependent DNS protocol-conformance suite: real recursive
//! resolution against real root/TLD/authority servers and well-known
//! domains. Every test is `#[ignore]`d (same convention as
//! `tests/live_dns.rs`/`tests/recursive_perf.rs`) since it needs outbound
//! UDP/TCP DNS access; run explicitly with
//! `cargo test --test e2e_upstream_live -- --ignored`.
//!
//! Deliberately small: this suite's job is confidence that the protocol
//! rules `tests/e2e_config_toml.rs` already pins down against a
//! synthetic fixture also hold against real, independently-operated DNS
//! infrastructure -- not to add new protocol-rule coverage, which all
//! lives in the offline suite.

#[path = "support/mod.rs"]
mod support;

use rdns::config::{RecursiveResolutionConfig, ResolutionConfig, RuntimeConfig};
use rdns::protocol::RecordData;
use support::*;

async fn recursive_config() -> RuntimeConfig {
    let recursive = RecursiveResolutionConfig::bundled("e2e-live-test");
    let port = free_loopback_port().await;
    RuntimeConfig::new_with_resolution(
        vec![format!("127.0.0.1:{port}").parse().unwrap()],
        ResolutionConfig::recursive(0, recursive),
        Vec::new(),
        std::time::Duration::from_secs(5),
        1232,
    )
    .unwrap()
}

// A well-known, long-lived domain must resolve to a real A record via
// full root -> TLD -> authority recursion. RFC 1034 §5.3.3 / RFC 1035
// §4.1.2: the answer must actually correspond to the question asked --
// same owner name, same type -- not merely be "some non-empty answer
// section".
#[tokio::test]
#[ignore = "requires outbound UDP/TCP DNS access to public root/TLD/authority servers"]
async fn resolves_a_record_for_well_known_domain_recursively() {
    let server = start_recursive_server(recursive_config().await).await;

    let request = RawQueryBuilder::new(0x5001, "example.com", 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x5001);
    assert!(message.header.qr());
    assert_eq!(message.header.r_code(), NOERROR);
    assert!(!message.answers.is_empty());
    assert!(
        message
            .answers
            .iter()
            .all(|record| record.rtype == 1 && record.name.eq_ignore_ascii_case("example.com")),
        "every answer RR must be an A record owned by the queried name, got {:?}",
        message.answers
    );

    server.shutdown().await;
}

// A name that is very unlikely to ever exist under a real, currently
// delegated TLD must resolve to NXDOMAIN through real recursion, not
// SERVFAIL or a false positive answer. RFC 2308 §2.2 / §5: an NXDOMAIN
// response must carry the covering zone's SOA in the authority section so
// the negative result is cacheable with a well-defined TTL -- rcode alone
// doesn't prove that.
#[tokio::test]
#[ignore = "requires outbound UDP/TCP DNS access to public root/TLD/authority servers"]
async fn nxdomain_for_nonexistent_name_under_a_real_tld() {
    let server = start_recursive_server(recursive_config().await).await;

    // A random, never-registered second-level domain under `.com` (not a
    // subdomain of a real registered domain, which could have a wildcard
    // record) -- effectively guaranteed NXDOMAIN.
    let request =
        RawQueryBuilder::new(0x5002, "rdns-e2e-conformance-suite-9f3a7c1d.com", 1).build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x5002);
    assert_eq!(message.header.r_code(), NXDOMAIN);
    assert!(message.answers.is_empty(), "NXDOMAIN must carry no answers");
    assert!(
        message
            .authorities
            .iter()
            .any(|record| matches!(record.record, RecordData::SOA { .. })),
        "NXDOMAIN must carry the covering zone's SOA in authority for negative caching, got {:?}",
        message.authorities
    );

    server.shutdown().await;
}

// RFC 4035 §3.2.1 / §4.5, confirmed against a real DNSSEC-signed zone
// (cloudflare.com) rather than only the synthetic fixture in
// tests/e2e_config_toml.rs: RRSIG is only handed back when the client's
// own DO bit asked for it.
#[tokio::test]
#[ignore = "requires outbound UDP/TCP DNS access to public root/TLD/authority servers"]
async fn dnssec_signed_domain_returns_rrsig_when_do_bit_set() {
    let server = start_recursive_server(recursive_config().await).await;

    let request = RawQueryBuilder::new(0x5003, "cloudflare.com", 1)
        .edns(1232, true)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert!(
        message
            .answers
            .iter()
            .any(|record| matches!(record.record, RecordData::RRSIG { .. })),
        "expected an RRSIG in a DO=1 answer from a DNSSEC-signed real zone"
    );

    server.shutdown().await;
}

#[tokio::test]
#[ignore = "requires outbound UDP/TCP DNS access to public root/TLD/authority servers"]
async fn dnssec_signed_domain_omits_rrsig_when_do_bit_unset() {
    let server = start_recursive_server(recursive_config().await).await;

    let request = RawQueryBuilder::new(0x5004, "cloudflare.com", 1)
        .edns(1232, false)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.r_code(), NOERROR);
    assert!(
        !message
            .answers
            .iter()
            .any(|record| matches!(record.record, RecordData::RRSIG { .. })),
        "DO=0 must not receive the RRSIG, even from a real signed zone"
    );

    server.shutdown().await;
}

// RFC 4035 §3.2.3, confirmed against real recursion: rdns performs no
// DNSSEC chain-of-trust validation (`DnssecValidationMode::Disabled`), so
// AD must never be set, even for a genuinely signed real-world zone.
#[tokio::test]
#[ignore = "requires outbound UDP/TCP DNS access to public root/TLD/authority servers"]
async fn ad_bit_never_set_even_for_a_real_dnssec_signed_domain() {
    let server = start_recursive_server(recursive_config().await).await;

    let request = RawQueryBuilder::new(0x5005, "cloudflare.com", 1)
        .edns(1232, true)
        .build();
    let response = send_udp(server.udp_addr, &request).await;
    let message = parse_response(&response);

    assert!(!message.header.ad());

    server.shutdown().await;
}

// RFC 1035 §4.2.2 / RFC 7766: rdns's own TCP listener must serve a
// complete, correctly-framed answer for a real recursive resolution, not
// just the UDP path exercised by the tests above.
#[tokio::test]
#[ignore = "requires outbound UDP/TCP DNS access to public root/TLD/authority servers"]
async fn tcp_round_trip_against_real_recursive_resolution() {
    let server = start_recursive_server(recursive_config().await).await;

    let request = RawQueryBuilder::new(0x5006, "example.com", 1).build();
    let response = send_tcp(server.tcp_addr, &request).await;
    let message = parse_response(&response);

    assert_eq!(message.header.id, 0x5006);
    assert_eq!(message.header.r_code(), NOERROR);
    assert!(!message.answers.is_empty());

    server.shutdown().await;
}
