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

//! CNAME-chain walking (`resolve_from_cache`) and serve-time wire response
//! assembly (`assemble_response`/`assemble_negative_response`). Cache
//! entries store raw record data, not a pre-built wire template — every
//! hit assembles the response fresh, per request, using the requester's
//! own question wire bytes (casing) and advertised EDNS bufsize
//! (truncation), neither of which are cache-key dimensions anymore.
//!
//! Storing a backend response into the cache (`store_response`) and
//! wiring this into `DomainDnsCache` are section-07's job — this section
//! only produces the read side.

#![allow(dead_code)]

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use crate::protocol::{NameCompressor, ResponseCode, write_message_header, write_record};
use crate::resolver::QueryFeatures;

use super::ShardedDnsCache;
use super::entry::{DnssecState, NegativeEntry, RRsetEntry};
use super::shard::HopResult;

const CNAME_RECORD_TYPE: u16 = 5;

/// Zero or more CNAME hops followed by the terminal `RRsetEntry` matching
/// the original qtype — or, if qtype == CNAME itself, exactly one hop (the
/// CNAME's own entry, no further walking past it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAnswer {
    pub(crate) chain: Vec<(String, RRsetEntry)>, // (owner name, entry), in walk order
}

/// A negative result (NXDOMAIN or NODATA), plus whatever CNAME hops were
/// walked before reaching it — a chain ending in NXDOMAIN/NODATA must
/// still include those hops in the assembled response's answer section.
///
/// `terminal_name` is the name the negative entry was actually found
/// under (the original qname if `chain` is empty, otherwise the last
/// hop's CNAME target) — the *covered* name, which is not necessarily the
/// SOA zone apex. Not part of the plan's literal `ResolvedNegative`
/// listing, but kept for parity with `ResolvedAnswer`'s chain (whose
/// per-hop owner names are always explicit) and for tests/diagnostics that
/// want to know what name a negative result covers.
///
/// This field is *not* used for the authority-section SOA owner — that
/// must be `negative.soa_owner` (the zone apex), which can differ from
/// this covered name whenever the NXDOMAIN/NODATA is below the zone apex
/// (e.g. covered name `nx.sub.example.com`, SOA owner `example.com`); see
/// `NegativeEntry::soa_owner`'s doc comment and `write_negative_authority`'s
/// call site below. Using `terminal_name` for the SOA owner was the bug
/// this field split fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNegative {
    pub(crate) chain: Vec<(String, RRsetEntry)>,
    pub(crate) terminal_name: String,
    pub(crate) negative: NegativeEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainLookup {
    /// Every name in the chain was found, unexpired, in the current
    /// namespace.
    Answered(ResolvedAnswer),
    /// Whole-name NXDOMAIN at some point in the chain.
    NxDomain(ResolvedNegative),
    /// NODATA for the queried type at the terminal name.
    NoData(ResolvedNegative),
    /// Any name in the chain missed, expired, or was stale-namespace —
    /// caller must fall back to backend resolution.
    Miss,
}

/// Walks a (possibly empty) CNAME chain starting at `qname`, doing one
/// independent per-shard lookup per name in the chain, up to
/// `max_chain_depth` hops.
///
/// `max_chain_depth` is an intentional, documented deviation from the
/// plan's literal listed signature `(cache, qname, qtype, qclass,
/// current_namespace, now)`: the plan says to reuse
/// `RecursiveResolverConfig.max_cname_restarts` "rather than introducing
/// a second, possibly-inconsistent bound", but that field lives on a type
/// `cache/` has no access to and isn't part of `CacheConfig`. The caller
/// (section-07's `probe_cache`) passes `max_cname_restarts` through here
/// explicitly instead.
///
/// Never holds more than one shard's lock at a time: each hop acquires,
/// clones, and releases its shard's lock (via `Shard::lookup_hop`) before
/// the next hop begins.
pub(crate) fn resolve_from_cache(
    cache: &ShardedDnsCache,
    qname: &str,
    qtype: u16,
    qclass: u16,
    current_namespace: &str,
    max_chain_depth: u8,
    now: SystemTime,
) -> ChainLookup {
    let mut current = crate::resolver::normalize_question_name(qname);
    let mut chain: Vec<(String, RRsetEntry)> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();

    loop {
        if chain.len() as u8 >= max_chain_depth || visited.contains(&current) {
            return ChainLookup::Miss;
        }
        visited.insert(current.clone());

        let shard = cache.shard_for(&current);
        match shard.lookup_hop(&current, qtype, qclass, current_namespace, now) {
            HopResult::Answer(entry) => {
                chain.push((current, entry));
                return ChainLookup::Answered(ResolvedAnswer { chain });
            }
            HopResult::CnameHop(entry, target) => {
                chain.push((current, entry));
                current = crate::resolver::normalize_question_name(&target);
            }
            HopResult::NoData(negative) => {
                return ChainLookup::NoData(ResolvedNegative {
                    chain,
                    terminal_name: current,
                    negative,
                });
            }
            HopResult::NxDomain(negative) => {
                return ChainLookup::NxDomain(ResolvedNegative {
                    chain,
                    terminal_name: current,
                    negative,
                });
            }
            HopResult::Miss => return ChainLookup::Miss,
        }
    }
}

/// Ages `ttl_at_store` by elapsed time since `stored_at`, capped by
/// remaining time to `expires_at` — computed directly in Rust before any
/// wire bytes are written (rather than reusing
/// `age_response_ttls`/`cap_response_ttls` against an assembled buffer),
/// since a CNAME chain can combine records from multiple `RRsetEntry`s
/// with different `stored_at` values, which a single scalar `age` applied
/// to a whole buffer can't represent correctly.
fn compute_wire_ttl(
    ttl_at_store: u32,
    stored_at: SystemTime,
    expires_at: SystemTime,
    now: SystemTime,
) -> u32 {
    let elapsed_secs = now
        .duration_since(stored_at)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let aged = ttl_at_store.saturating_sub(elapsed_secs.min(u64::from(u32::MAX)) as u32);
    let remaining_secs = expires_at
        .duration_since(now)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    aged.min(remaining_secs.min(u64::from(u32::MAX)) as u32)
}

fn chain_answer_count(chain: &[(String, RRsetEntry)], dnssec_ok: bool) -> u16 {
    chain
        .iter()
        .map(|(_, entry)| {
            let mut count = entry.records.len();
            if dnssec_ok {
                count += entry.rrsigs.len();
            }
            count
        })
        .sum::<usize>() as u16
}

fn write_rrset(
    out: &mut Vec<u8>,
    compressor: &mut NameCompressor,
    name: &str,
    entry: &RRsetEntry,
    dnssec_ok: bool,
    now: SystemTime,
) {
    for record in &entry.records {
        let ttl = compute_wire_ttl(record.ttl_at_store, entry.stored_at, entry.expires_at, now);
        write_record(
            out,
            compressor,
            name,
            record.rtype,
            record.rclass,
            ttl,
            &record.rdata,
        );
    }
    if dnssec_ok {
        for rrsig in &entry.rrsigs {
            let ttl = compute_wire_ttl(rrsig.ttl_at_store, entry.stored_at, entry.expires_at, now);
            write_record(
                out,
                compressor,
                name,
                rrsig.rtype,
                rrsig.rclass,
                ttl,
                &rrsig.rdata,
            );
        }
    }
}

fn write_negative_authority(
    out: &mut Vec<u8>,
    compressor: &mut NameCompressor,
    owner: &str,
    negative: &NegativeEntry,
    dnssec_ok: bool,
    now: SystemTime,
) {
    let soa_ttl = compute_wire_ttl(
        negative.soa_record.ttl_at_store,
        negative.stored_at,
        negative.expires_at,
        now,
    );
    write_record(
        out,
        compressor,
        owner,
        negative.soa_record.rtype,
        negative.soa_record.rclass,
        soa_ttl,
        &negative.soa_record.rdata,
    );
    if dnssec_ok {
        if let Some(rrsig) = &negative.soa_rrsig {
            let ttl = compute_wire_ttl(
                rrsig.ttl_at_store,
                negative.stored_at,
                negative.expires_at,
                now,
            );
            write_record(
                out,
                compressor,
                owner,
                rrsig.rtype,
                rrsig.rclass,
                ttl,
                &rrsig.rdata,
            );
        }
        for proof in &negative.proof_records {
            let ttl = compute_wire_ttl(
                proof.ttl_at_store,
                negative.stored_at,
                negative.expires_at,
                now,
            );
            write_record(
                out,
                compressor,
                owner,
                proof.rtype,
                proof.rclass,
                ttl,
                &proof.rdata,
            );
        }
    }
}

fn negative_authority_count(negative: &NegativeEntry, dnssec_ok: bool) -> u16 {
    let mut count = 1u16; // SOA
    if dnssec_ok {
        if negative.soa_rrsig.is_some() {
            count += 1;
        }
        count += negative.proof_records.len() as u16;
    }
    count
}

/// SERVFAIL per RFC 6840 §5.9: if `checking_disabled` is false and any
/// relevant chain entry is `Bogus`, serve SERVFAIL instead of the cached
/// data (checked across every hop, not just the terminal one).
fn dnssec_servfail_check(chain: &[(String, RRsetEntry)], features: &QueryFeatures) -> bool {
    if features.checking_disabled {
        return false;
    }
    chain
        .iter()
        .any(|(_, entry)| matches!(entry.dnssec_state, DnssecState::Bogus(_)))
}

/// AD bit set only if every relevant chain entry is `Secure` and the
/// requester set DO or AD. `Unvalidated`/`Insecure` never produce AD=1.
/// An empty chain never produces AD=1 either — there's nothing to have
/// validated (relevant for `ResolvedNegative`, whose own `NegativeEntry`
/// carries no `dnssec_state` of its own to check; see `ResolvedNegative`'s
/// doc comment).
fn dnssec_ad_bit(chain: &[(String, RRsetEntry)], features: &QueryFeatures) -> bool {
    if !(features.dnssec_ok || features.authenticated_data) {
        return false;
    }
    !chain.is_empty()
        && chain
            .iter()
            .all(|(_, entry)| entry.dnssec_state == DnssecState::Secure)
}

fn build_servfail(
    request_id: u16,
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
) -> Vec<u8> {
    let mut response = Vec::new();
    write_message_header(
        &mut response,
        request_id,
        requester_features.recursion_desired,
        false,
        false,
        ResponseCode::ServFail,
        1,
        0,
        0,
        0,
    );
    response.extend_from_slice(requester_question_wire);
    response
}

/// Returns `response` unchanged unless `allow_udp_truncation` is set and
/// `response` exceeds the requester's effective UDP payload size (derived
/// from `requester_features.edns_udp_payload_size`, mirroring
/// `Message::effective_udp_payload_size`'s bounds-clamping), in which case
/// a truncated response is returned instead: header + question section
/// (per the plan's "header + question only, TC bit set"), TC bit set, no
/// answer/authority/additional records, `response_code` preserved from
/// the caller (an earlier draft hardcoded `NoError` here, which would
/// have silently turned a truncated NXDOMAIN/NODATA into a false
/// NOERROR). `configured_max_udp_payload_size` is the server-side
/// ceiling — an intentional, documented deviation from the plan's literal
/// `assemble_response` signature, needed for the same reason
/// `resolve_from_cache`'s `max_chain_depth` is: `assemble_response` has no
/// `Message`/`DecodedQuery` to pull it from, only raw question wire bytes
/// and `QueryFeatures`.
fn finish_with_truncation_check(
    response: Vec<u8>,
    request_id: u16,
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
    response_code: ResponseCode,
    allow_udp_truncation: bool,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    if !allow_udp_truncation {
        return response;
    }
    let advertised = requester_features
        .edns_udp_payload_size
        .map(|size| size as usize)
        .unwrap_or(crate::protocol::DNS_DEFAULT_UDP_PAYLOAD_SIZE);
    let effective = advertised
        .max(crate::protocol::DNS_DEFAULT_UDP_PAYLOAD_SIZE)
        .min(configured_max_udp_payload_size);
    if response.len() <= effective {
        return response;
    }
    let mut truncated = Vec::new();
    write_message_header(
        &mut truncated,
        request_id,
        requester_features.recursion_desired,
        true,
        false,
        response_code,
        1,
        0,
        0,
        0,
    );
    truncated.extend_from_slice(requester_question_wire);
    truncated
}

/// Builds a complete wire response from a `ChainLookup::Answered` result,
/// using the requester's own question wire bytes for name casing
/// (interview Q9) and advertised EDNS bufsize for truncation (interview
/// Q13). `request_id` is an intentional, documented deviation from the
/// plan's literal signature — `QueryFeatures` carries no transaction ID,
/// so it must be threaded through explicitly (mirrors the
/// `configured_max_udp_payload_size` deviation above).
pub(crate) fn assemble_response(
    request_id: u16,
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
    resolved: &ResolvedAnswer,
    now: SystemTime,
    allow_udp_truncation: bool,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    if dnssec_servfail_check(&resolved.chain, requester_features) {
        return build_servfail(request_id, requester_question_wire, requester_features);
    }

    let dnssec_ok = requester_features.dnssec_ok;
    let ad = dnssec_ad_bit(&resolved.chain, requester_features);
    let an_count = chain_answer_count(&resolved.chain, dnssec_ok);

    let mut response = Vec::new();
    write_message_header(
        &mut response,
        request_id,
        requester_features.recursion_desired,
        false,
        ad,
        ResponseCode::NoError,
        1,
        an_count,
        0,
        0,
    );
    response.extend_from_slice(requester_question_wire);

    let mut compressor = NameCompressor::new();
    for (name, entry) in &resolved.chain {
        write_rrset(&mut response, &mut compressor, name, entry, dnssec_ok, now);
    }

    finish_with_truncation_check(
        response,
        request_id,
        requester_question_wire,
        requester_features,
        ResponseCode::NoError,
        allow_udp_truncation,
        configured_max_udp_payload_size,
    )
}

/// Builds a complete wire response from a `ChainLookup::NxDomain`/`NoData`
/// result: any CNAME chain records in the answer section, followed by
/// `negative.soa_record` (+ `soa_rrsig`/`proof_records` if DO is set) in
/// the authority section. `response_code` should be `ResponseCode::NxDomain`
/// or `ResponseCode::NoError` per which `ChainLookup` variant produced
/// `resolved`. Same `request_id`/`configured_max_udp_payload_size`
/// deviations as `assemble_response`, for the same reasons.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_negative_response(
    request_id: u16,
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
    resolved: &ResolvedNegative,
    response_code: ResponseCode,
    now: SystemTime,
    allow_udp_truncation: bool,
    configured_max_udp_payload_size: usize,
) -> Vec<u8> {
    if dnssec_servfail_check(&resolved.chain, requester_features) {
        return build_servfail(request_id, requester_question_wire, requester_features);
    }

    let dnssec_ok = requester_features.dnssec_ok;
    let ad = dnssec_ad_bit(&resolved.chain, requester_features);
    let an_count = chain_answer_count(&resolved.chain, dnssec_ok);
    let ns_count = negative_authority_count(&resolved.negative, dnssec_ok);

    let mut response = Vec::new();
    write_message_header(
        &mut response,
        request_id,
        requester_features.recursion_desired,
        false,
        ad,
        response_code,
        1,
        an_count,
        ns_count,
        0,
    );
    response.extend_from_slice(requester_question_wire);

    let mut compressor = NameCompressor::new();
    for (name, entry) in &resolved.chain {
        write_rrset(&mut response, &mut compressor, name, entry, dnssec_ok, now);
    }
    write_negative_authority(
        &mut response,
        &mut compressor,
        &resolved.negative.soa_owner,
        &resolved.negative,
        dnssec_ok,
        now,
    );

    finish_with_truncation_check(
        response,
        request_id,
        requester_question_wire,
        requester_features,
        response_code,
        allow_udp_truncation,
        configured_max_udp_payload_size,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CacheConfig;
    use crate::protocol::{Message, RecordData, write_u16};
    use crate::resolver::NegativeCacheKind;
    use crate::resolver::cache::entry::{NegativeKey, StoredRecord};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    const IN_QCLASS: u16 = 1;
    const A_QTYPE: u16 = 1;

    fn question_wire(qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut compressor = NameCompressor::new();
        let mut wire = Vec::new();
        compressor.write_name(&mut wire, qname);
        write_u16(&mut wire, qtype);
        write_u16(&mut wire, qclass);
        wire
    }

    fn features(dnssec_ok: bool) -> QueryFeatures {
        QueryFeatures {
            recursion_desired: true,
            authenticated_data: false,
            checking_disabled: false,
            dnssec_ok,
            edns_udp_payload_size: None,
        }
    }

    fn a_record(ttl: u32, octet: u8) -> StoredRecord {
        StoredRecord {
            rtype: A_QTYPE,
            rclass: IN_QCLASS,
            ttl_at_store: ttl,
            rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, octet)),
        }
    }

    fn rrset_entry(
        records: Vec<StoredRecord>,
        minimum_ttl: Duration,
        now: SystemTime,
    ) -> RRsetEntry {
        RRsetEntry {
            records,
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl,
            stored_at: now,
            expires_at: now + minimum_ttl,
            dnssec_state: DnssecState::Unvalidated,
            cache_namespace: "ns-1".to_string(),
        }
    }

    fn cache_with_shard_count(shard_count: usize) -> ShardedDnsCache {
        ShardedDnsCache::new(&CacheConfig {
            max_entries: 1_000,
            shard_count: Some(shard_count),
        })
    }

    #[test]
    fn assemble_response_ages_each_record_ttl_independently() {
        let now = SystemTime::now();
        let stored_at = now - Duration::from_secs(100);
        let mut entry = rrset_entry(
            vec![a_record(600, 1), a_record(120, 2)],
            Duration::from_secs(600),
            stored_at,
        );
        entry.expires_at = stored_at + Duration::from_secs(600);
        let resolved = ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
        let parsed = Message::parse(&response).unwrap();

        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.answers[0].ttl, 500); // 600 - 100 elapsed
        assert_eq!(parsed.answers[1].ttl, 20); // 120 - 100 elapsed
    }

    #[test]
    fn assemble_response_caps_ttl_to_remaining_entry_lifetime() {
        let now = SystemTime::now();
        let stored_at = now - Duration::from_secs(590);
        let mut entry = rrset_entry(vec![a_record(600, 1)], Duration::from_secs(600), stored_at);
        entry.expires_at = stored_at + Duration::from_secs(600); // expires in 10s
        let resolved = ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
        let parsed = Message::parse(&response).unwrap();

        // Aged TTL would be 10s, remaining lifetime is also 10s: capped, not
        // exceeded.
        assert_eq!(parsed.answers[0].ttl, 10);
    }

    #[test]
    fn assemble_response_echoes_requesters_own_casing() {
        let now = SystemTime::now();
        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        let resolved = ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry)],
        };

        let lower_wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
        let mixed_wire = question_wire("Example.COM", A_QTYPE, IN_QCLASS);

        let lower_response = assemble_response(
            1,
            &lower_wire,
            &features(false),
            &resolved,
            now,
            false,
            4096,
        );
        let mixed_response = assemble_response(
            1,
            &mixed_wire,
            &features(false),
            &resolved,
            now,
            false,
            4096,
        );

        let lower_parsed = Message::parse(&lower_response).unwrap();
        let mixed_parsed = Message::parse(&mixed_response).unwrap();

        assert_eq!(lower_parsed.questions[0].qname, "example.com");
        assert_eq!(mixed_parsed.questions[0].qname, "Example.COM");
    }

    #[test]
    fn assemble_response_truncates_per_requesters_own_bufsize() {
        let now = SystemTime::now();
        let records: Vec<StoredRecord> = (0..40u8).map(|i| a_record(300, i)).collect();
        let entry = rrset_entry(records, Duration::from_secs(300), now);
        let resolved = ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let mut udp_features = features(false);
        udp_features.edns_udp_payload_size = Some(512);
        let udp_response = assemble_response(1, &wire, &udp_features, &resolved, now, true, 4096);
        let udp_parsed = Message::parse(&udp_response).unwrap();
        assert!(udp_parsed.header.tc());
        assert_eq!(udp_parsed.answers.len(), 0);
        assert_eq!(
            udp_parsed.questions.len(),
            1,
            "truncated response still carries the question section"
        );
        assert_eq!(udp_parsed.questions[0].qname, "example.com");

        // TCP-sourced queries pass allow_udp_truncation = false: full
        // response regardless of size.
        let tcp_response = assemble_response(1, &wire, &udp_features, &resolved, now, false, 4096);
        let tcp_parsed = Message::parse(&tcp_response).unwrap();
        assert!(!tcp_parsed.header.tc());
        assert_eq!(tcp_parsed.answers.len(), 40);
    }

    #[test]
    fn assemble_response_includes_rrsigs_only_when_requester_sets_do() {
        let now = SystemTime::now();
        let mut entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        entry.rrsigs = vec![StoredRecord {
            rtype: 46, // RRSIG
            rclass: IN_QCLASS,
            ttl_at_store: 300,
            rdata: RecordData::RRSIG {
                type_covered: A_QTYPE,
                algorithm: 8,
                labels: 2,
                original_ttl: 300,
                signature_expiration: 2_000_000_000,
                signature_inception: 1_900_000_000,
                key_tag: 12345,
                signer_name: "example.com".to_string(),
                signature: vec![0xab, 0xcd],
            },
        }];
        let resolved = ResolvedAnswer {
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let without_do = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
        let with_do = assemble_response(1, &wire, &features(true), &resolved, now, false, 4096);

        assert_eq!(Message::parse(&without_do).unwrap().answers.len(), 1);
        assert_eq!(Message::parse(&with_do).unwrap().answers.len(), 2);
    }

    #[test]
    fn assemble_response_sets_ad_only_when_secure_and_requested() {
        let now = SystemTime::now();
        let mut secure_entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        secure_entry.dnssec_state = DnssecState::Secure;
        let resolved = ResolvedAnswer {
            chain: vec![("example.com".to_string(), secure_entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let mut do_features = features(true);
        let with_do = assemble_response(1, &wire, &do_features, &resolved, now, false, 4096);
        assert!(Message::parse(&with_do).unwrap().header.ad());

        do_features.dnssec_ok = false;
        let without_do_or_ad =
            assemble_response(1, &wire, &do_features, &resolved, now, false, 4096);
        assert!(!Message::parse(&without_do_or_ad).unwrap().header.ad());

        // Unvalidated never produces AD=1 regardless of requester flags.
        let mut unvalidated_entry =
            rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        unvalidated_entry.dnssec_state = DnssecState::Unvalidated;
        let unvalidated_resolved = ResolvedAnswer {
            chain: vec![("example.com".to_string(), unvalidated_entry)],
        };
        let unvalidated_response = assemble_response(
            1,
            &wire,
            &features(true),
            &unvalidated_resolved,
            now,
            false,
            4096,
        );
        assert!(!Message::parse(&unvalidated_response).unwrap().header.ad());
    }

    #[test]
    fn assemble_response_servfails_on_bogus_when_checking_enabled() {
        let now = SystemTime::now();
        let mut bogus_entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        bogus_entry.dnssec_state = DnssecState::Bogus("signature verification failed".to_string());
        let resolved = ResolvedAnswer {
            chain: vec![("example.com".to_string(), bogus_entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let checking_enabled = features(false);
        let servfail_response =
            assemble_response(1, &wire, &checking_enabled, &resolved, now, false, 4096);
        let servfail_parsed = Message::parse(&servfail_response).unwrap();
        assert_eq!(
            servfail_parsed.header.r_code(),
            ResponseCode::ServFail as u8
        );
        assert_eq!(servfail_parsed.answers.len(), 0);

        let mut checking_disabled = features(false);
        checking_disabled.checking_disabled = true;
        let served_response =
            assemble_response(1, &wire, &checking_disabled, &resolved, now, false, 4096);
        let served_parsed = Message::parse(&served_response).unwrap();
        assert_eq!(served_parsed.header.r_code(), ResponseCode::NoError as u8);
        assert_eq!(served_parsed.answers.len(), 1);
    }

    fn soa_record(ttl: u32) -> StoredRecord {
        StoredRecord {
            rtype: 6, // SOA
            rclass: IN_QCLASS,
            ttl_at_store: ttl,
            rdata: RecordData::SOA {
                ttl: 0,
                rname: "hostmaster.example.com".to_string(),
                mname: "ns1.example.com".to_string(),
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: ttl,
            },
        }
    }

    fn negative_entry(
        now: SystemTime,
        ttl: u32,
        soa_rrsig: Option<StoredRecord>,
        proof_records: Vec<StoredRecord>,
    ) -> NegativeEntry {
        negative_entry_with_owner(now, ttl, soa_rrsig, proof_records, "example.com")
    }

    fn negative_entry_with_owner(
        now: SystemTime,
        ttl: u32,
        soa_rrsig: Option<StoredRecord>,
        proof_records: Vec<StoredRecord>,
        soa_owner: &str,
    ) -> NegativeEntry {
        NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: soa_owner.to_string(),
            soa_record: soa_record(ttl),
            soa_rrsig,
            proof_records,
            stored_at: now,
            expires_at: now + Duration::from_secs(ttl as u64),
            cache_namespace: "ns-1".to_string(),
        }
    }

    #[test]
    fn assemble_negative_response_writes_soa_in_authority_with_requested_response_code() {
        let now = SystemTime::now();
        let negative = negative_entry(now, 3600, None, Vec::new());
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: "nx.example.com".to_string(),
            negative,
        };
        let wire = question_wire("nx.example.com", A_QTYPE, IN_QCLASS);

        let nxdomain_response = assemble_negative_response(
            1,
            &wire,
            &features(false),
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
        );
        let parsed = Message::parse(&nxdomain_response).unwrap();
        assert_eq!(parsed.header.r_code(), ResponseCode::NxDomain as u8);
        assert_eq!(parsed.answers.len(), 0);
        assert_eq!(parsed.authorities.len(), 1);
        assert_eq!(parsed.authorities[0].rtype, 6);

        let nodata_response = assemble_negative_response(
            1,
            &wire,
            &features(false),
            &resolved,
            ResponseCode::NoError,
            now,
            false,
            4096,
        );
        assert_eq!(
            Message::parse(&nodata_response).unwrap().header.r_code(),
            ResponseCode::NoError as u8
        );
    }

    // Regression test for the negative-cache SOA-owner bug: the SOA in the
    // authority section must be written under the zone apex
    // (`negative.soa_owner`), not under the covered/queried name
    // (`resolved.terminal_name`). These differ whenever the NXDOMAIN is
    // below the zone apex — e.g. querying `nx.sub.example.com`, covered by
    // a SOA owned by `example.com`.
    #[test]
    fn assemble_negative_response_writes_soa_under_zone_apex_not_covered_name() {
        let now = SystemTime::now();
        let covered_name = "nx.sub.example.com";
        let soa_owner = "example.com";
        let negative = negative_entry_with_owner(now, 3600, None, Vec::new(), soa_owner);
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: covered_name.to_string(),
            negative,
        };
        let wire = question_wire(covered_name, A_QTYPE, IN_QCLASS);

        let response = assemble_negative_response(
            1,
            &wire,
            &features(false),
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
        );
        let parsed = Message::parse(&response).unwrap();

        assert_eq!(parsed.authorities.len(), 1);
        assert_eq!(parsed.authorities[0].rtype, 6); // SOA
        assert_eq!(
            parsed.authorities[0].name, soa_owner,
            "authority-section SOA must be owned by the zone apex, not the covered name"
        );
        assert_ne!(
            parsed.authorities[0].name, covered_name,
            "SOA owner must not be the covered/queried name when it differs from the zone apex"
        );
    }

    #[test]
    fn assemble_negative_response_includes_cname_chain_and_dnssec_proof_only_when_do() {
        let now = SystemTime::now();
        let cname_entry = rrset_entry(
            vec![StoredRecord {
                rtype: CNAME_RECORD_TYPE,
                rclass: IN_QCLASS,
                ttl_at_store: 300,
                rdata: RecordData::CNAME("target.example.com".to_string()),
            }],
            Duration::from_secs(300),
            now,
        );
        let soa_rrsig = StoredRecord {
            rtype: 46, // RRSIG
            rclass: IN_QCLASS,
            ttl_at_store: 3600,
            rdata: RecordData::RRSIG {
                type_covered: 6,
                algorithm: 8,
                labels: 2,
                original_ttl: 3600,
                signature_expiration: 2_000_000_000,
                signature_inception: 1_900_000_000,
                key_tag: 1,
                signer_name: "example.com".to_string(),
                signature: vec![0xaa],
            },
        };
        let proof = StoredRecord {
            rtype: 47, // NSEC
            rclass: IN_QCLASS,
            ttl_at_store: 3600,
            rdata: RecordData::NSEC {
                next_domain: "zzz.example.com".to_string(),
                type_bit_maps: vec![0, 1],
            },
        };
        let negative = negative_entry(now, 3600, Some(soa_rrsig), vec![proof]);
        let resolved = ResolvedNegative {
            chain: vec![("target.example.com".to_string(), cname_entry)],
            terminal_name: "target.example.com".to_string(),
            negative,
        };
        let wire = question_wire("target.example.com", A_QTYPE, IN_QCLASS);

        let without_do = assemble_negative_response(
            1,
            &wire,
            &features(false),
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
        );
        let without_do_parsed = Message::parse(&without_do).unwrap();
        assert_eq!(
            without_do_parsed.answers.len(),
            1,
            "CNAME hop still included"
        );
        assert_eq!(
            without_do_parsed.authorities.len(),
            1,
            "SOA only, no rrsig/proof without DO"
        );

        let with_do = assemble_negative_response(
            1,
            &wire,
            &features(true),
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
        );
        let with_do_parsed = Message::parse(&with_do).unwrap();
        assert_eq!(with_do_parsed.answers.len(), 1);
        assert_eq!(
            with_do_parsed.authorities.len(),
            3,
            "SOA + soa_rrsig + proof record with DO"
        );
    }

    #[test]
    fn assemble_negative_response_truncates_while_preserving_response_code_and_question() {
        let now = SystemTime::now();
        let big_proof_records: Vec<StoredRecord> = (0..40u16)
            .map(|i| StoredRecord {
                rtype: 999,
                rclass: IN_QCLASS,
                ttl_at_store: 3600,
                rdata: RecordData::Unknown {
                    rtype: 999,
                    bytes: vec![i as u8; 20],
                },
            })
            .collect();
        let negative = negative_entry(now, 3600, None, big_proof_records);
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: "nx.example.com".to_string(),
            negative,
        };
        let wire = question_wire("nx.example.com", A_QTYPE, IN_QCLASS);
        let mut do_features = features(true);
        do_features.edns_udp_payload_size = Some(512);

        let response = assemble_negative_response(
            1,
            &wire,
            &do_features,
            &resolved,
            ResponseCode::NxDomain,
            now,
            true,
            4096,
        );
        let parsed = Message::parse(&response).unwrap();

        assert!(parsed.header.tc());
        assert_eq!(
            parsed.header.r_code(),
            ResponseCode::NxDomain as u8,
            "truncation must not silently downgrade the response code to NOERROR"
        );
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.authorities.len(), 0);
    }

    #[test]
    fn resolve_from_cache_finds_nodata_before_nxdomain_when_both_keys_present() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        let domain = "both-negative-keys.example.com";

        let nodata = negative_entry(now, 3600, None, Vec::new());
        cache.shard_for(domain).store_negative(
            domain,
            NegativeKey {
                qtype: Some(A_QTYPE),
                qclass: IN_QCLASS,
            },
            nodata,
        );
        let nxdomain = negative_entry(now, 3600, None, Vec::new());
        cache.shard_for(domain).store_negative(
            domain,
            NegativeKey {
                qtype: None,
                qclass: IN_QCLASS,
            },
            nxdomain,
        );

        let result = resolve_from_cache(&cache, domain, A_QTYPE, IN_QCLASS, "ns-1", 8, now);

        assert!(
            matches!(result, ChainLookup::NoData(_)),
            "NODATA for the queried type must be preferred over whole-name NXDOMAIN, got {result:?}"
        );
    }

    #[test]
    fn resolve_from_cache_respects_max_chain_depth_on_a_non_cyclical_chain() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        // a -> b -> c -> d, none repeated, but max_chain_depth caps the walk
        // before it reaches the terminal answer.
        let hops = [
            ("a.example.com", "b.example.com"),
            ("b.example.com", "c.example.com"),
            ("c.example.com", "d.example.com"),
        ];
        for (name, target) in hops {
            let entry = rrset_entry(
                vec![StoredRecord {
                    rtype: CNAME_RECORD_TYPE,
                    rclass: IN_QCLASS,
                    ttl_at_store: 300,
                    rdata: RecordData::CNAME(target.to_string()),
                }],
                Duration::from_secs(300),
                now,
            );
            cache
                .shard_for(name)
                .store_positive(name, (CNAME_RECORD_TYPE, IN_QCLASS), entry);
        }
        let terminal = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        cache.shard_for("d.example.com").store_positive(
            "d.example.com",
            (A_QTYPE, IN_QCLASS),
            terminal,
        );

        // With enough depth, the walk reaches the terminal answer.
        let answered =
            resolve_from_cache(&cache, "a.example.com", A_QTYPE, IN_QCLASS, "ns-1", 8, now);
        assert!(matches!(answered, ChainLookup::Answered(_)));

        // With too little depth (2 hops allowed, but 3 are needed to reach
        // "d"), the walk must give up rather than loop or return a partial
        // answer — and this chain never revisits a name, so this exercises
        // the depth bound itself, not the visited-set cycle guard.
        let too_shallow =
            resolve_from_cache(&cache, "a.example.com", A_QTYPE, IN_QCLASS, "ns-1", 2, now);
        assert_eq!(too_shallow, ChainLookup::Miss);
    }

    #[test]
    fn resolve_from_cache_treats_expired_entry_as_miss() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        let stored_at = now - Duration::from_secs(600);
        let mut entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), stored_at);
        entry.expires_at = stored_at + Duration::from_secs(300); // expired 300s ago
        cache.shard_for("expired.example.com").store_positive(
            "expired.example.com",
            (A_QTYPE, IN_QCLASS),
            entry,
        );

        let result = resolve_from_cache(
            &cache,
            "expired.example.com",
            A_QTYPE,
            IN_QCLASS,
            "ns-1",
            8,
            now,
        );

        assert_eq!(result, ChainLookup::Miss);
    }

    #[test]
    fn resolve_from_cache_returns_negative_result_with_accumulated_cname_chain() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        let mut cname_entry = rrset_entry(
            vec![StoredRecord {
                rtype: CNAME_RECORD_TYPE,
                rclass: IN_QCLASS,
                ttl_at_store: 300,
                rdata: RecordData::CNAME("target.example.com".to_string()),
            }],
            Duration::from_secs(300),
            now,
        );
        cname_entry.cache_namespace = "ns-1".to_string();
        cache.shard_for("alias.example.com").store_positive(
            "alias.example.com",
            (CNAME_RECORD_TYPE, IN_QCLASS),
            cname_entry,
        );

        let negative = NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: StoredRecord {
                rtype: 6,
                rclass: IN_QCLASS,
                ttl_at_store: 3600,
                rdata: RecordData::SOA {
                    ttl: 0,
                    rname: "hostmaster.example.com".to_string(),
                    mname: "ns1.example.com".to_string(),
                    serial: 1,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1_209_600,
                    minimum: 3600,
                },
            },
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
        };
        let neg_key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        cache.shard_for("target.example.com").store_negative(
            "target.example.com",
            neg_key,
            negative,
        );

        let result = resolve_from_cache(
            &cache,
            "alias.example.com",
            A_QTYPE,
            IN_QCLASS,
            "ns-1",
            8,
            now,
        );

        match result {
            ChainLookup::NxDomain(resolved) => {
                assert_eq!(resolved.chain.len(), 1);
                assert_eq!(resolved.chain[0].0, "alias.example.com");
                assert_eq!(resolved.terminal_name, "target.example.com");
            }
            other => panic!("expected NxDomain with accumulated chain, got {other:?}"),
        }
    }

    #[test]
    fn resolve_from_cache_respects_max_cname_restarts_bound() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        // A cyclical CNAME chain: a -> b -> a.
        for (name, target) in [
            ("a.example.com", "b.example.com"),
            ("b.example.com", "a.example.com"),
        ] {
            let entry = rrset_entry(
                vec![StoredRecord {
                    rtype: CNAME_RECORD_TYPE,
                    rclass: IN_QCLASS,
                    ttl_at_store: 300,
                    rdata: RecordData::CNAME(target.to_string()),
                }],
                Duration::from_secs(300),
                now,
            );
            cache
                .shard_for(name)
                .store_positive(name, (CNAME_RECORD_TYPE, IN_QCLASS), entry);
        }

        let result =
            resolve_from_cache(&cache, "a.example.com", A_QTYPE, IN_QCLASS, "ns-1", 8, now);

        assert_eq!(result, ChainLookup::Miss);
    }

    #[test]
    fn resolve_from_cache_returns_miss_on_any_missing_chain_hop() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();

        let result = resolve_from_cache(
            &cache,
            "never-stored.example.com",
            A_QTYPE,
            IN_QCLASS,
            "ns-1",
            8,
            now,
        );

        assert_eq!(result, ChainLookup::Miss);
    }

    #[test]
    fn resolve_from_cache_rejects_stale_namespace_independent_of_sweep() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        // Entry is unexpired but stored under a namespace that no longer
        // matches "current" — must be treated as a miss without requiring
        // section-05's sweep to have run.
        cache.shard_for("stale-ns.example.com").store_positive(
            "stale-ns.example.com",
            (A_QTYPE, IN_QCLASS),
            entry,
        );

        let result = resolve_from_cache(
            &cache,
            "stale-ns.example.com",
            A_QTYPE,
            IN_QCLASS,
            "current-ns",
            8,
            now,
        );

        assert_eq!(result, ChainLookup::Miss);
    }

    #[test]
    fn resolve_from_cache_follows_cname_chain_across_shards() {
        // Use enough shards, and distinct enough names, that the queried
        // name and its CNAME target are very likely to land in different
        // shards; assert the walk still finds the terminal answer (proving
        // per-hop lock acquire/release rather than a single held lock that
        // would only work within one shard).
        let cache = cache_with_shard_count(8);
        let now = SystemTime::now();

        let mut cname_entry = rrset_entry(
            vec![StoredRecord {
                rtype: CNAME_RECORD_TYPE,
                rclass: IN_QCLASS,
                ttl_at_store: 300,
                rdata: RecordData::CNAME("cname-target.example.net".to_string()),
            }],
            Duration::from_secs(300),
            now,
        );
        cname_entry.cache_namespace = "ns-1".to_string();
        cache.shard_for("cname-source.example.com").store_positive(
            "cname-source.example.com",
            (CNAME_RECORD_TYPE, IN_QCLASS),
            cname_entry,
        );

        let terminal_entry = rrset_entry(vec![a_record(300, 7)], Duration::from_secs(300), now);
        cache.shard_for("cname-target.example.net").store_positive(
            "cname-target.example.net",
            (A_QTYPE, IN_QCLASS),
            terminal_entry,
        );

        let result = resolve_from_cache(
            &cache,
            "cname-source.example.com",
            A_QTYPE,
            IN_QCLASS,
            "ns-1",
            8,
            now,
        );

        match result {
            ChainLookup::Answered(resolved) => {
                assert_eq!(resolved.chain.len(), 2);
                assert_eq!(resolved.chain[0].0, "cname-source.example.com");
                assert_eq!(resolved.chain[1].0, "cname-target.example.net");
            }
            other => panic!("expected Answered chain across shards, got {other:?}"),
        }
    }

    #[test]
    fn resolve_from_cache_never_holds_two_shard_locks_at_once() {
        // While one thread holds shard A's lock mid-scan (simulated via
        // Shard::hold_lock_for_test), a lookup against a domain in a
        // *different* shard must not be blocked — proving
        // resolve_from_cache releases each hop's lock before acquiring the
        // next, rather than holding one lock for the whole walk.
        let cache = std::sync::Arc::new(cache_with_shard_count(2));
        let now = SystemTime::now();

        // Find one domain per shard.
        let mut domain_shard_0 = None;
        let mut domain_shard_1 = None;
        for i in 0..1000 {
            let candidate = format!("host-{i}.example.com");
            let shard_ptr = cache.shard_for(&candidate) as *const _;
            let shard_0_ptr = cache.shard_for("shard-0-anchor") as *const _;
            if domain_shard_0.is_none() && std::ptr::eq(shard_ptr, shard_0_ptr) {
                domain_shard_0 = Some(candidate.clone());
            }
            if domain_shard_1.is_none() && !std::ptr::eq(shard_ptr, shard_0_ptr) {
                domain_shard_1 = Some(candidate.clone());
            }
            if domain_shard_0.is_some() && domain_shard_1.is_some() {
                break;
            }
        }
        let domain_a = domain_shard_0.expect("expected a domain hashing to shard 0");
        let domain_b = domain_shard_1.expect("expected a domain hashing to a different shard");

        let entry_b = rrset_entry(vec![a_record(300, 9)], Duration::from_secs(300), now);
        cache
            .shard_for(&domain_b)
            .store_positive(&domain_b, (A_QTYPE, IN_QCLASS), entry_b);

        let cache_for_thread = std::sync::Arc::clone(&cache);
        let domain_a_for_thread = domain_a.clone();
        let handle = std::thread::spawn(move || {
            cache_for_thread
                .shard_for(&domain_a_for_thread)
                .hold_lock_for_test(Duration::from_millis(200));
        });
        std::thread::sleep(Duration::from_millis(50));

        let start = std::time::Instant::now();
        let result = resolve_from_cache(&cache, &domain_b, A_QTYPE, IN_QCLASS, "ns-1", 8, now);
        let elapsed = start.elapsed();

        handle.join().unwrap();

        assert!(matches!(result, ChainLookup::Answered(_)));
        assert!(
            elapsed < Duration::from_millis(150),
            "lookup against a different shard should not wait on shard A's held lock, took {elapsed:?}"
        );
    }
}
