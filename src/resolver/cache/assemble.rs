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
//! `DomainDnsCache` are implemented in `mod.rs`, which calls
//! `resolve_from_cache` from this module for the read side — that wiring
//! landed in section-07, so it's no longer scaffolding-only. The
//! `#[allow(dead_code)]` below is for `CNAME_RECORD_TYPE`, which this
//! module's own tests use but production code doesn't reference directly
//! (production goes through `shard.rs`'s copy).

#![allow(dead_code)]

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::config::RefreshConfig;
use crate::protocol::edns_cookie::{CookieSecret, build_cookie_option, build_server_cookie};
use crate::protocol::{
    NameCompressor, Record, RecordData, ResponseCode, build_truncated_wire_response,
    write_message_header, write_opt_record, write_record,
};
use crate::resolver::QueryFeatures;

use super::ShardedDnsCache;
use super::entry::{DnssecState, NegativeEntry, RRsetEntry};
use super::shard::HopResult;

const CNAME_RECORD_TYPE: u16 = 5;

/// One cache hop's signal that it currently qualifies for a background
/// refresh (all three of `wants_refresh`'s gates hold: eligibility floor,
/// lead window, popularity hot-threshold — see
/// `docs/knowledge/resolver/caching/auto-refresh.md`).
/// `qtype`/`qclass` identify the specific record set at `domain` that
/// should be refetched — for an intermediate CNAME hop this is
/// `(CNAME_RECORD_TYPE, qclass)`, never the original query's qtype, since
/// the CNAME record set at that hop's domain is what's actually near
/// expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefreshHint {
    pub(crate) domain: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
}

/// Zero or more CNAME hops followed by the terminal `RRsetEntry` matching
/// the original qtype — or, if qtype == CNAME itself, exactly one hop (the
/// CNAME's own entry, no further walking past it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAnswer {
    pub(crate) chain: Vec<(String, RRsetEntry)>, // (owner name, entry), in walk order
    /// One hint per hop in `chain` that independently wants a refresh —
    /// not just the terminal hop. A CNAME record is itself a positive
    /// RRset with its own independent expiry, so an intermediate hop can
    /// need a refresh even while the terminal hop stays fresh (and vice
    /// versa); collecting a hint per qualifying hop is what a caller
    /// (`ResolveQuery::probe_cache`, section-04) enqueues jobs from.
    pub(crate) refresh_hints: Vec<RefreshHint>,
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
/// current_epoch, now)`: the plan says to reuse
/// `RecursiveResolverConfig.max_cname_restarts` "rather than introducing
/// a second, possibly-inconsistent bound", but that field lives on a type
/// `cache/` has no access to and isn't part of `CacheConfig`. The caller
/// (section-07's `probe_cache`) passes `max_cname_restarts` through here
/// explicitly instead.
///
/// Never holds more than one shard's lock at a time: each hop acquires,
/// clones, and releases its shard's lock (via `Shard::lookup_hop`) before
/// the next hop begins.
///
/// `dnssec_ok` is the *reading* requester's own DO flag, threaded through
/// to every hop's `Shard::lookup_hop` call so a DO=true walk never gets
/// stuck on (or silently serves from) an entry whose DNSSEC material isn't
/// confirmed complete — see `Shard::lookup_hop`'s doc comment for the full
/// contract.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_from_cache(
    cache: &ShardedDnsCache,
    qname: &str,
    qtype: u16,
    qclass: u16,
    dnssec_ok: bool,
    current_epoch: u64,
    max_chain_depth: u8,
    now: SystemTime,
    refresh_config: &RefreshConfig,
) -> ChainLookup {
    let mut current = crate::resolver::normalize_question_name(qname);
    let mut chain: Vec<(String, RRsetEntry)> = Vec::new();
    let mut refresh_hints: Vec<RefreshHint> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();

    loop {
        // `chain.len()` here is the number of CNAME hops already followed
        // (not counting the not-yet-looked-up `current` name), so a chain
        // that has used exactly `max_chain_depth` CNAME restarts must still
        // be allowed one more lookup at `current` to reach its terminal
        // answer — hence `>`, not `>=`. `max_chain_depth` restarts means up
        // to that many hops succeed before giving up, not
        // `max_chain_depth - 1`.
        //
        // Compared without narrowing `chain.len()` (a `usize`) down to
        // `u8` first: casting first would wrap a chain that reaches exactly
        // 256 hops back to 0, silently defeating this guard for any
        // `max_chain_depth` the wrapped value still compares less than
        // (e.g. `max_chain_depth` near 255) until a cycle or genuine miss
        // happens to end the walk some other way.
        if chain.len() > usize::from(max_chain_depth) || visited.contains(&current) {
            return ChainLookup::Miss;
        }
        visited.insert(current.clone());

        let shard = cache.shard_for(&current);
        match shard.lookup_hop(
            &current,
            qtype,
            qclass,
            dnssec_ok,
            current_epoch,
            now,
            refresh_config,
        ) {
            HopResult::Answer(entry, wants_refresh) => {
                if wants_refresh {
                    refresh_hints.push(RefreshHint {
                        domain: current.clone(),
                        qtype,
                        qclass,
                    });
                }
                chain.push((current, entry));
                return ChainLookup::Answered(ResolvedAnswer {
                    chain,
                    refresh_hints,
                });
            }
            HopResult::CnameHop(entry, target, wants_refresh) => {
                if wants_refresh {
                    // This hop's own record type is CNAME, not the
                    // original query's qtype — a refresh job for this hop
                    // must refetch the CNAME record set at `current`, not
                    // whatever type was originally queried.
                    refresh_hints.push(RefreshHint {
                        domain: current.clone(),
                        qtype: CNAME_RECORD_TYPE,
                        qclass,
                    });
                }
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

/// Whether every hop in `chain` was itself sourced from an authoritative
/// backend answer (`RRsetEntry::authoritative`) — vacuously `true` for an
/// empty chain, since `assemble_negative_response` combines this with the
/// terminal `NegativeEntry`'s own `authoritative` bit, and a negative
/// result with zero CNAME hops must not have its AA bit forced false just
/// because `chain` happened to be empty.
fn chain_authoritative(chain: &[(String, RRsetEntry)]) -> bool {
    chain.iter().all(|(_, entry)| entry.authoritative)
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

/// Wire TTL for records served from an expired (stale-served) entry —
/// RFC 8767 §4: "The TTL to set on stale records... 30 seconds is
/// RECOMMENDED", long enough for the client to use the answer, short
/// enough that it re-asks soon after the background refresh lands.
pub(crate) const STALE_WIRE_TTL_SECS: u32 = 30;

fn write_rrset(
    out: &mut Vec<u8>,
    compressor: &mut NameCompressor,
    name: &str,
    entry: &RRsetEntry,
    dnssec_ok: bool,
    now: SystemTime,
) {
    // An expired entry can only reach response assembly when the lookup
    // admitted it as an RFC 8767 stale serve (`Shard::lookup_hop` — every
    // other expired candidate is evicted or filtered there, and lookup and
    // assembly share the same `now`, the request's received timestamp), so
    // this check *is* the staleness signal — no separate flag threads
    // through `ResolvedAnswer`. `compute_wire_ttl` would yield 0 for every
    // such record; 0 is legal but makes busy clients hammer the resolver
    // during the refresh window.
    let stale = entry.expires_at <= now;
    let wire_ttl = |ttl_at_store| {
        if stale {
            STALE_WIRE_TTL_SECS
        } else {
            compute_wire_ttl(ttl_at_store, entry.stored_at, entry.expires_at, now)
        }
    };
    for record in &entry.records {
        write_record(
            out,
            compressor,
            name,
            record.rtype,
            record.rclass,
            wire_ttl(record.ttl_at_store),
            &record.rdata,
        );
    }
    if dnssec_ok {
        for rrsig in &entry.rrsigs {
            write_record(
                out,
                compressor,
                name,
                rrsig.rtype,
                rrsig.rclass,
                wire_ttl(rrsig.ttl_at_store),
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
        for (proof_owner, proof) in &negative.proof_records {
            let ttl = compute_wire_ttl(
                proof.ttl_at_store,
                negative.stored_at,
                negative.expires_at,
                now,
            );
            write_record(
                out,
                compressor,
                proof_owner,
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
/// data (checked across every hop, not just the terminal one). Used for
/// `ResolvedAnswer`, whose chain is the complete set of entries backing the
/// response. For `ResolvedNegative`, whose terminal result is a
/// `NegativeEntry` not part of `chain`, see `negative_dnssec_servfail_check`
/// below instead — using this function alone for a negative result would
/// only ever inspect its CNAME hops, never the terminal NXDOMAIN/NODATA
/// entry's own `dnssec_state`.
fn dnssec_servfail_check(chain: &[(String, RRsetEntry)], features: &QueryFeatures) -> bool {
    if features.checking_disabled {
        return false;
    }
    chain
        .iter()
        .any(|(_, entry)| matches!(entry.dnssec_state, DnssecState::Bogus(_)))
}

/// `dnssec_servfail_check`'s sibling for `ResolvedNegative` results (mirrors
/// `negative_dnssec_ad_bit`'s relationship to `dnssec_ad_bit`): forces
/// SERVFAIL per RFC 6840 §5.9 when `checking_disabled` is false and either a
/// CNAME hop in `chain` *or* the terminal `negative` entry's own
/// `dnssec_state` is `Bogus`. Without this, a `NegativeEntry` marked
/// `Bogus` would be served as an ordinary NXDOMAIN/NODATA to a CD=0
/// requester instead of SERVFAIL — the same RFC 6840 §5.9 protection
/// `dnssec_servfail_check` already gives positive chains, just missing on
/// the negative-result path. `checking_disabled = true` (CD=1) still
/// overrides this and serves the cached data as-is, same as the positive
/// path — a CD=1 requester has explicitly asked to see potentially-bogus
/// data itself.
fn negative_dnssec_servfail_check(
    chain: &[(String, RRsetEntry)],
    negative: &NegativeEntry,
    features: &QueryFeatures,
) -> bool {
    if features.checking_disabled {
        return false;
    }
    matches!(negative.dnssec_state, DnssecState::Bogus(_))
        || chain
            .iter()
            .any(|(_, entry)| matches!(entry.dnssec_state, DnssecState::Bogus(_)))
}

/// AD bit set only if every relevant chain entry is `Secure` and the
/// requester set DO or AD. `Unvalidated`/`Insecure` never produce AD=1.
/// An empty chain never produces AD=1 either — there's nothing to have
/// validated. Used for `ResolvedAnswer`, whose chain always ends in the
/// terminal `RRsetEntry` itself (see `resolve_from_cache`), so the chain
/// alone is the complete set of entries to check. For `ResolvedNegative`,
/// whose terminal result is a `NegativeEntry` (with its own `dnssec_state`,
/// not part of `chain`), see `negative_dnssec_ad_bit` below instead.
fn dnssec_ad_bit(chain: &[(String, RRsetEntry)], features: &QueryFeatures) -> bool {
    if !(features.dnssec_ok || features.authenticated_data) {
        return false;
    }
    !chain.is_empty()
        && chain
            .iter()
            .all(|(_, entry)| entry.dnssec_state == DnssecState::Secure)
}

/// `dnssec_ad_bit`'s sibling for `ResolvedNegative` results: AD=1 only if
/// every CNAME hop in `chain` is `Secure` *and* the terminal `negative`
/// entry's own `dnssec_state` is `Secure`. Unlike `dnssec_ad_bit`, an empty
/// `chain` does not by itself prevent AD=1 here — a negative result with no
/// CNAME hops at all (the common case) still has `negative` itself to
/// validate, so the "nothing to have validated" rule that empty-guards
/// `dnssec_ad_bit` doesn't apply.
fn negative_dnssec_ad_bit(
    chain: &[(String, RRsetEntry)],
    negative: &NegativeEntry,
    features: &QueryFeatures,
) -> bool {
    if !(features.dnssec_ok || features.authenticated_data) {
        return false;
    }
    negative.dnssec_state == DnssecState::Secure
        && chain
            .iter()
            .all(|(_, entry)| entry.dnssec_state == DnssecState::Secure)
}

/// Builds the per-transaction OPT record to append to a response's
/// additional section, mirroring the requester's own DO flag but *this
/// resolver's own* UDP payload size — `None` if the requester's original
/// query carried no EDNS OPT record at all
/// (`requester_features.edns_udp_payload_size` is only ever `Some` when the
/// query had one; see `QueryFeatures::from_message`). Per RFC 6891 §6.1.1,
/// a compliant responder MUST include an OPT record in any response to a
/// query that itself contained one, and the UDP payload size field on that
/// OPT record is sender-specific: on a *response* it must describe the
/// responder's own size, never an echo of the requester's advertised size
/// (`requester_features.edns_udp_payload_size` only decides *presence*
/// here, matching `crate::protocol::message_edns_opt_record`).
///
/// Shares `crate::protocol::build_opt_record`'s construction with
/// `resolver::mirrored_client_opt_record`, which builds the same shape
/// from a parsed `Message` on the recursive-miss path — this module only
/// has `QueryFeatures`, not a `Message`, at cache-hit serve time.
fn requester_opt_record(
    requester_features: &QueryFeatures,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Option<Record> {
    requester_features.edns_udp_payload_size?;
    let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
    let mut opt = crate::protocol::build_opt_record(udp_payload_size, requester_features.dnssec_ok);
    if let Some(client_cookie) = requester_features.client_cookie {
        let server_cookie = build_server_cookie(cookie_secret, client_cookie, client_ip, now);
        if let RecordData::OPT(ref mut edns) = opt.record {
            edns.options = build_cookie_option(client_cookie, server_cookie);
        }
    }
    Some(opt)
}

#[allow(clippy::too_many_arguments)]
fn build_servfail(
    request_id: u16,
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Vec<u8> {
    let opt = requester_opt_record(
        requester_features,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    );
    let mut response = Vec::new();
    write_message_header(
        &mut response,
        request_id,
        requester_features.recursion_desired,
        false,
        false, // SERVFAIL carries no validated answer data to be authoritative about
        false,
        requester_features.checking_disabled,
        ResponseCode::ServFail,
        1,
        0,
        0,
        u16::from(opt.is_some()),
    );
    response.extend_from_slice(requester_question_wire);
    if let Some(opt) = &opt {
        write_opt_record(&mut response, opt);
    }
    response
}

/// Returns `response` unchanged unless `allow_udp_truncation` is set and
/// `response` exceeds the requester's effective UDP payload size (derived
/// from `requester_features.edns_udp_payload_size`, mirroring
/// `Message::effective_udp_payload_size`'s bounds-clamping), in which case
/// a truncated response is returned instead: header + question section
/// (per the plan's "header + question only, TC bit set"), TC bit set, no
/// answer/authority records, `response_code` preserved from the caller
/// (an earlier draft hardcoded `NoError` here, which would have silently
/// turned a truncated NXDOMAIN/NODATA into a false NOERROR).
/// `configured_max_udp_payload_size` is the server-side ceiling — an
/// intentional, documented deviation from the plan's literal
/// `assemble_response` signature, needed for the same reason
/// `resolve_from_cache`'s `max_chain_depth` is: `assemble_response` has no
/// `Message`/`DecodedQuery` to pull it from, only raw question wire bytes
/// and `QueryFeatures`.
///
/// Per RFC 6891 §7, even this minimal truncated response must still carry
/// an OPT record if the requester's original query had one — so the
/// additional section is not unconditionally empty; it holds exactly the
/// mirrored OPT record when the requester used EDNS, nothing otherwise.
///
/// `authoritative` is the same AA bit the untruncated response would have
/// carried (see `chain_authoritative`/`RRsetEntry::authoritative`) — a
/// truncated response is still describing the same underlying answer, so
/// its AA bit must agree with what the full response would have said.
#[allow(clippy::too_many_arguments)]
fn finish_with_truncation_check(
    response: Vec<u8>,
    request_id: u16,
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
    response_code: ResponseCode,
    authoritative: bool,
    allow_udp_truncation: bool,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
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
    let opt = requester_opt_record(
        requester_features,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    );
    build_truncated_wire_response(
        request_id,
        requester_features.recursion_desired,
        authoritative,
        requester_features.checking_disabled,
        response_code,
        requester_question_wire,
        opt.as_ref(),
    )
}

/// Builds a complete wire response from a `ChainLookup::Answered` result,
/// using the requester's own question wire bytes for name casing
/// (interview Q9) and advertised EDNS bufsize for truncation (interview
/// Q13). `request_id` is an intentional, documented deviation from the
/// plan's literal signature — `QueryFeatures` carries no transaction ID,
/// so it must be threaded through explicitly (mirrors the
/// `configured_max_udp_payload_size` deviation above).
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_response(
    request_id: u16,
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
    resolved: &ResolvedAnswer,
    now: SystemTime,
    allow_udp_truncation: bool,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
) -> Vec<u8> {
    if dnssec_servfail_check(&resolved.chain, requester_features) {
        return build_servfail(
            request_id,
            requester_question_wire,
            requester_features,
            configured_max_udp_payload_size,
            cookie_secret,
            client_ip,
            now,
        );
    }

    let dnssec_ok = requester_features.dnssec_ok;
    let ad = dnssec_ad_bit(&resolved.chain, requester_features);
    let authoritative = chain_authoritative(&resolved.chain);
    let an_count = chain_answer_count(&resolved.chain, dnssec_ok);
    let opt = requester_opt_record(
        requester_features,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    );

    let mut response = Vec::new();
    write_message_header(
        &mut response,
        request_id,
        requester_features.recursion_desired,
        false,
        authoritative,
        ad,
        requester_features.checking_disabled,
        ResponseCode::NoError,
        1,
        an_count,
        0,
        u16::from(opt.is_some()),
    );
    response.extend_from_slice(requester_question_wire);

    let mut compressor = NameCompressor::new();
    for (name, entry) in &resolved.chain {
        write_rrset(&mut response, &mut compressor, name, entry, dnssec_ok, now);
    }
    if let Some(opt) = &opt {
        write_opt_record(&mut response, opt);
    }

    finish_with_truncation_check(
        response,
        request_id,
        requester_question_wire,
        requester_features,
        ResponseCode::NoError,
        authoritative,
        allow_udp_truncation,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
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
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
) -> Vec<u8> {
    if negative_dnssec_servfail_check(&resolved.chain, &resolved.negative, requester_features) {
        return build_servfail(
            request_id,
            requester_question_wire,
            requester_features,
            configured_max_udp_payload_size,
            cookie_secret,
            client_ip,
            now,
        );
    }

    let dnssec_ok = requester_features.dnssec_ok;
    let ad = negative_dnssec_ad_bit(&resolved.chain, &resolved.negative, requester_features);
    let authoritative = chain_authoritative(&resolved.chain) && resolved.negative.authoritative;
    let an_count = chain_answer_count(&resolved.chain, dnssec_ok);
    let ns_count = negative_authority_count(&resolved.negative, dnssec_ok);
    let opt = requester_opt_record(
        requester_features,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    );

    let mut response = Vec::new();
    write_message_header(
        &mut response,
        request_id,
        requester_features.recursion_desired,
        false,
        authoritative,
        ad,
        requester_features.checking_disabled,
        response_code,
        1,
        an_count,
        ns_count,
        u16::from(opt.is_some()),
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
    if let Some(opt) = &opt {
        write_opt_record(&mut response, opt);
    }

    finish_with_truncation_check(
        response,
        request_id,
        requester_question_wire,
        requester_features,
        response_code,
        authoritative,
        allow_udp_truncation,
        configured_max_udp_payload_size,
        cookie_secret,
        client_ip,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CacheConfig;
    use crate::protocol::edns_cookie::ClientCookie;
    use crate::protocol::{Message, RecordData, write_u16};
    use crate::resolver::NegativeCacheKind;
    use crate::resolver::cache::entry::{NegativeKey, StoredRecord};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    const IN_QCLASS: u16 = 1;
    const A_QTYPE: u16 = 1;

    fn test_cookie_secret() -> CookieSecret {
        CookieSecret::generate()
    }

    fn test_client_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
    }

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
            client_cookie: None,
        }
    }

    fn features_with_cookie(client_cookie: ClientCookie) -> QueryFeatures {
        QueryFeatures {
            recursion_desired: true,
            authenticated_data: false,
            checking_disabled: false,
            dnssec_ok: false,
            edns_udp_payload_size: Some(1232),
            client_cookie: Some(client_cookie),
        }
    }

    fn features_with_edns_no_cookie() -> QueryFeatures {
        QueryFeatures {
            recursion_desired: true,
            authenticated_data: false,
            checking_disabled: false,
            dnssec_ok: false,
            edns_udp_payload_size: Some(1232),
            client_cookie: None,
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
            cache_epoch: 1,
            dnssec_complete: true,
            authoritative: false,
        }
    }

    fn cache_with_shard_count(shard_count: usize) -> ShardedDnsCache {
        ShardedDnsCache::new(&CacheConfig {
            max_entries: 1_000,
            shard_count: Some(shard_count),
            ..CacheConfig::default()
        })
    }

    /// `cache_with_shard_count` with RFC 8767 serve-stale off, for tests
    /// pinning the original expired-means-miss lookup behavior.
    fn cache_without_serve_stale(shard_count: usize) -> ShardedDnsCache {
        ShardedDnsCache::new(&CacheConfig {
            max_entries: 1_000,
            shard_count: Some(shard_count),
            serve_stale_enabled: false,
            ..CacheConfig::default()
        })
    }

    #[test]
    fn requester_opt_record_attaches_server_cookie_when_client_cookie_present() {
        let client_cookie: ClientCookie = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let features = features_with_cookie(client_cookie);
        let secret = test_cookie_secret();
        let client_ip = test_client_ip();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let record = requester_opt_record(&features, 4096, &secret, client_ip, now)
            .expect("edns_udp_payload_size is set, so a record must be returned");

        let RecordData::OPT(edns) = &record.record else {
            panic!("expected an OPT record");
        };
        assert_eq!(
            &edns.options[0..2],
            &10u16.to_be_bytes(),
            "COOKIE option code"
        );
        assert_eq!(&edns.options[2..4], &24u16.to_be_bytes(), "length: 8 + 16");
        assert_eq!(&edns.options[4..12], &client_cookie);
        let expected_server_cookie = build_server_cookie(&secret, client_cookie, client_ip, now);
        assert_eq!(&edns.options[12..28], &expected_server_cookie);
    }

    /// Regression test: a non-Cookie request's OPT record must stay
    /// byte-for-byte identical to pre-cookie-support behavior (empty
    /// options), same as `assemble_response_includes_opt_record_when_requester_used_edns`
    /// pins at a higher level.
    #[test]
    fn requester_opt_record_omits_options_when_no_client_cookie() {
        let features = features_with_edns_no_cookie();
        let secret = test_cookie_secret();
        let client_ip = test_client_ip();
        let now = SystemTime::UNIX_EPOCH;

        let record = requester_opt_record(&features, 4096, &secret, client_ip, now)
            .expect("edns_udp_payload_size is set, so a record must be returned");

        let RecordData::OPT(edns) = &record.record else {
            panic!("expected an OPT record");
        };
        assert!(edns.options.is_empty());
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
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let response = assemble_response(
            1,
            &wire,
            &features(false),
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
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
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let response = assemble_response(
            1,
            &wire,
            &features(false),
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let parsed = Message::parse(&response).unwrap();

        // Aged TTL would be 10s, remaining lifetime is also 10s: capped, not
        // exceeded.
        assert_eq!(parsed.answers[0].ttl, 10);
    }

    #[test]
    fn compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime() {
        // Origin TTL is 0 - a record that "should" expire almost
        // immediately by its own TTL.
        let now = SystemTime::now();
        let stored_at = now - Duration::from_secs(5);
        // The 30s `minimum_ttl` here simulates a min_positive_ttl floor
        // extending this entry's actual cache lifetime (`expires_at`) far
        // past what the origin TTL of 0 implies.
        let entry = rrset_entry(
            vec![a_record(0, 1)], // ttl_at_store = 0
            Duration::from_secs(30),
            stored_at,
        );
        let resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let response = assemble_response(
            1,
            &wire,
            &features(false),
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let parsed = Message::parse(&response).unwrap();

        // Even though the entry is still servable for ~25 more seconds
        // (floored expires_at), the wire TTL must reflect the record's own
        // origin TTL of 0, aged - never the entry's floor-extended remaining
        // lifetime.
        assert_eq!(parsed.answers[0].ttl, 0);
    }

    #[test]
    fn assemble_response_echoes_requesters_own_casing() {
        let now = SystemTime::now();
        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        let resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
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
            &test_cookie_secret(),
            test_client_ip(),
        );
        let mixed_response = assemble_response(
            1,
            &mixed_wire,
            &features(false),
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
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
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let mut udp_features = features(false);
        udp_features.edns_udp_payload_size = Some(512);
        let udp_response = assemble_response(
            1,
            &wire,
            &udp_features,
            &resolved,
            now,
            true,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
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
        let tcp_response = assemble_response(
            1,
            &wire,
            &udp_features,
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let tcp_parsed = Message::parse(&tcp_response).unwrap();
        assert!(!tcp_parsed.header.tc());
        assert_eq!(tcp_parsed.answers.len(), 40);
    }

    // Regression test for RFC 6891 §6.1.1: a compliant responder MUST
    // include an OPT record in any response to a query that itself
    // carried one. Before this fix, `assemble_response` always wrote
    // ARCOUNT=0 and never emitted an OPT record, regardless of the
    // requester's own EDNS usage.
    //
    // The requester advertises 4096 while `configured_max_udp_payload_size`
    // (700) is deliberately different: per RFC 6891 §6.1.1 the OPT record
    // on a *response* must describe the responder's own size, never an
    // echo of the requester's -- using the same value for both here would
    // let a regression back to echoing the requester's size pass silently.
    #[test]
    fn assemble_response_includes_opt_record_when_requester_used_edns() {
        let now = SystemTime::now();
        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        let resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let mut edns_features = features(false);
        edns_features.edns_udp_payload_size = Some(4096);

        let response = assemble_response(
            1,
            &wire,
            &edns_features,
            &resolved,
            now,
            false,
            700,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let parsed = Message::parse(&response).unwrap();

        assert_eq!(
            parsed.header.ar_count, 1,
            "ARCOUNT must account for the mirrored OPT record"
        );
        let edns = parsed
            .edns
            .expect("response must carry an OPT record when the requester's query had one");
        assert_eq!(
            edns.udp_payload_size, 700,
            "OPT must advertise this resolver's own configured UDP payload size (700), \
             not echo the requester's 4096"
        );
        assert!(!edns.dnssec_ok);

        // A requester with no EDNS at all must not get an OPT record back.
        let no_edns_response = assemble_response(
            1,
            &wire,
            &features(false),
            &resolved,
            now,
            false,
            700,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let no_edns_parsed = Message::parse(&no_edns_response).unwrap();
        assert_eq!(no_edns_parsed.header.ar_count, 0);
        assert!(no_edns_parsed.edns.is_none());
    }

    /// `write_opt_record`/`write_rdata` (`src/protocol/mod.rs`) already
    /// serialize whatever bytes sit in `EdnsInfo.options` onto the wire
    /// unconditionally -- there's no separate "wire encoder" gate to wait
    /// on. That means `requester_opt_record` attaching a COOKIE option is
    /// already live, externally observable wire behavior as of this
    /// section, not inert in-memory plumbing deferred to a later section.
    /// This test proves the option actually round-trips through
    /// `write_opt_record` -> `Message::parse` intact, not just that the
    /// in-memory `Record` looks right (`requester_opt_record_attaches_server_cookie_when_client_cookie_present`
    /// above only checks the latter).
    #[test]
    fn assemble_response_serializes_server_cookie_option_on_wire_for_cookie_bearing_query() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        let resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
        let client_cookie: ClientCookie = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let secret = test_cookie_secret();
        let client_ip = test_client_ip();

        let response = assemble_response(
            1,
            &wire,
            &features_with_cookie(client_cookie),
            &resolved,
            now,
            false,
            4096,
            &secret,
            client_ip,
        );
        let parsed = Message::parse(&response).unwrap();

        let edns = parsed
            .edns
            .expect("response must carry an OPT record for a cookie-bearing requester");
        assert_eq!(
            &edns.options[0..2],
            &10u16.to_be_bytes(),
            "COOKIE option code"
        );
        assert_eq!(&edns.options[2..4], &24u16.to_be_bytes(), "length: 8 + 16");
        assert_eq!(&edns.options[4..12], &client_cookie);
        let expected_server_cookie = build_server_cookie(&secret, client_cookie, client_ip, now);
        assert_eq!(&edns.options[12..28], &expected_server_cookie);
    }

    // Regression test: a cache-hit response must preserve the *original
    // backend response's* own AA bit (`RRsetEntry::authoritative`), not
    // always claim AA=0. Before this fix, `write_message_header` never set
    // AA at all, so a cached copy of an authoritative answer was silently
    // downgraded to AA=0 on every subsequent cache hit.
    #[test]
    fn assemble_response_preserves_authoritative_bit_from_stored_entry() {
        let now = SystemTime::now();
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let mut authoritative_entry =
            rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        authoritative_entry.authoritative = true;
        let authoritative_resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), authoritative_entry)],
        };
        let aa_response = assemble_response(
            1,
            &wire,
            &features(false),
            &authoritative_resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            Message::parse(&aa_response).unwrap().header.aa(),
            "a cached entry stored from an AA=1 backend response must be served back as AA=1"
        );

        let mut non_authoritative_entry =
            rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        non_authoritative_entry.authoritative = false;
        let non_authoritative_resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), non_authoritative_entry)],
        };
        let no_aa_response = assemble_response(
            1,
            &wire,
            &features(false),
            &non_authoritative_resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            !Message::parse(&no_aa_response).unwrap().header.aa(),
            "a cached entry stored from an AA=0 backend response must stay AA=0"
        );

        // A CNAME chain must only be reported AA=1 if every hop (not just
        // the terminal entry) came from an authoritative backend response.
        let mut authoritative_cname = rrset_entry(
            vec![StoredRecord {
                rtype: CNAME_RECORD_TYPE,
                rclass: IN_QCLASS,
                ttl_at_store: 300,
                rdata: RecordData::CNAME("target.example.com".to_string()),
            }],
            Duration::from_secs(300),
            now,
        );
        authoritative_cname.authoritative = true;
        let mut non_authoritative_terminal =
            rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        non_authoritative_terminal.authoritative = false;
        let mixed_resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![
                ("alias.example.com".to_string(), authoritative_cname),
                ("target.example.com".to_string(), non_authoritative_terminal),
            ],
        };
        let mixed_wire = question_wire("alias.example.com", A_QTYPE, IN_QCLASS);
        let mixed_response = assemble_response(
            1,
            &mixed_wire,
            &features(false),
            &mixed_resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            !Message::parse(&mixed_response).unwrap().header.aa(),
            "AA=1 requires every hop in the chain to be authoritative, not just the terminal one"
        );
    }

    // Regression test for RFC 4035 §3.2.2: a security-aware recursive name
    // server MUST copy the CD (checking disabled) bit from the query to
    // the response. Before this fix, `write_message_header` had no CD
    // parameter at all.
    #[test]
    fn assemble_response_copies_cd_bit_from_requester() {
        let now = SystemTime::now();
        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        let resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let mut cd_features = features(false);
        cd_features.checking_disabled = true;
        let cd_response = assemble_response(
            1,
            &wire,
            &cd_features,
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            Message::parse(&cd_response).unwrap().header.cd(),
            "CD=1 on the query must produce CD=1 on the response"
        );

        let no_cd_response = assemble_response(
            1,
            &wire,
            &features(false),
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            !Message::parse(&no_cd_response).unwrap().header.cd(),
            "CD=0 on the query must produce CD=0 on the response"
        );
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
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let without_do = assemble_response(
            1,
            &wire,
            &features(false),
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let with_do = assemble_response(
            1,
            &wire,
            &features(true),
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );

        assert_eq!(Message::parse(&without_do).unwrap().answers.len(), 1);
        assert_eq!(Message::parse(&with_do).unwrap().answers.len(), 2);
    }

    #[test]
    fn assemble_response_sets_ad_only_when_secure_and_requested() {
        let now = SystemTime::now();
        let mut secure_entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        secure_entry.dnssec_state = DnssecState::Secure;
        let resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), secure_entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let mut do_features = features(true);
        let with_do = assemble_response(
            1,
            &wire,
            &do_features,
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(Message::parse(&with_do).unwrap().header.ad());

        do_features.dnssec_ok = false;
        let without_do_or_ad = assemble_response(
            1,
            &wire,
            &do_features,
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(!Message::parse(&without_do_or_ad).unwrap().header.ad());

        // Unvalidated never produces AD=1 regardless of requester flags.
        let mut unvalidated_entry =
            rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        unvalidated_entry.dnssec_state = DnssecState::Unvalidated;
        let unvalidated_resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
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
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(!Message::parse(&unvalidated_response).unwrap().header.ad());
    }

    #[test]
    fn assemble_response_servfails_on_bogus_when_checking_enabled() {
        let now = SystemTime::now();
        let mut bogus_entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        bogus_entry.dnssec_state = DnssecState::Bogus("signature verification failed".to_string());
        let resolved = ResolvedAnswer {
            refresh_hints: Vec::new(),
            chain: vec![("example.com".to_string(), bogus_entry)],
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let checking_enabled = features(false);
        let servfail_response = assemble_response(
            1,
            &wire,
            &checking_enabled,
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let servfail_parsed = Message::parse(&servfail_response).unwrap();
        assert_eq!(
            servfail_parsed.header.r_code(),
            ResponseCode::ServFail as u8
        );
        assert_eq!(servfail_parsed.answers.len(), 0);

        let mut checking_disabled = features(false);
        checking_disabled.checking_disabled = true;
        let served_response = assemble_response(
            1,
            &wire,
            &checking_disabled,
            &resolved,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
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
        proof_records: Vec<(String, StoredRecord)>,
    ) -> NegativeEntry {
        negative_entry_with_owner(now, ttl, soa_rrsig, proof_records, "example.com")
    }

    fn negative_entry_with_owner(
        now: SystemTime,
        ttl: u32,
        soa_rrsig: Option<StoredRecord>,
        proof_records: Vec<(String, StoredRecord)>,
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
            cache_epoch: 1,
            dnssec_complete: true,
            dnssec_state: DnssecState::Unvalidated,
            authoritative: false,
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
            &test_cookie_secret(),
            test_client_ip(),
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
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert_eq!(
            Message::parse(&nodata_response).unwrap().header.r_code(),
            ResponseCode::NoError as u8
        );
    }

    // Regression tests for RFC 6840 §5.9: a `NegativeEntry` whose own
    // `dnssec_state` is `Bogus` must be served as SERVFAIL, not as an
    // ordinary NXDOMAIN/NODATA, when the requester's CD bit is 0 -- mirrors
    // `assemble_response_servfails_on_bogus_when_checking_enabled`'s
    // coverage for positive chains, which `dnssec_servfail_check` already
    // handled; `negative_dnssec_servfail_check` is the negative-result
    // sibling this test locks in. A CD=1 requester still gets the cached
    // data served normally, same as the positive-chain case.
    #[test]
    fn assemble_negative_response_servfails_on_bogus_nxdomain_when_checking_enabled() {
        let now = SystemTime::now();
        let mut bogus_negative = negative_entry(now, 3600, None, Vec::new());
        bogus_negative.dnssec_state =
            DnssecState::Bogus("signature verification failed".to_string());
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: "nx.example.com".to_string(),
            negative: bogus_negative,
        };
        let wire = question_wire("nx.example.com", A_QTYPE, IN_QCLASS);

        let checking_enabled = features(false);
        let servfail_response = assemble_negative_response(
            1,
            &wire,
            &checking_enabled,
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let servfail_parsed = Message::parse(&servfail_response).unwrap();
        assert_eq!(
            servfail_parsed.header.r_code(),
            ResponseCode::ServFail as u8,
            "a Bogus NegativeEntry must be served as SERVFAIL when CD=0"
        );
        assert_eq!(servfail_parsed.authorities.len(), 0);

        let mut checking_disabled = features(false);
        checking_disabled.checking_disabled = true;
        let served_response = assemble_negative_response(
            1,
            &wire,
            &checking_disabled,
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let served_parsed = Message::parse(&served_response).unwrap();
        assert_eq!(
            served_parsed.header.r_code(),
            ResponseCode::NxDomain as u8,
            "CD=1 must still serve the cached NXDOMAIN despite the Bogus state"
        );
        assert_eq!(served_parsed.authorities.len(), 1);
    }

    #[test]
    fn assemble_negative_response_servfails_on_bogus_nodata_when_checking_enabled() {
        let now = SystemTime::now();
        let mut bogus_negative = negative_entry(now, 3600, None, Vec::new());
        bogus_negative.kind = NegativeCacheKind::NoData;
        bogus_negative.dnssec_state =
            DnssecState::Bogus("signature verification failed".to_string());
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: "example.com".to_string(),
            negative: bogus_negative,
        };
        let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

        let checking_enabled = features(false);
        let servfail_response = assemble_negative_response(
            1,
            &wire,
            &checking_enabled,
            &resolved,
            ResponseCode::NoError,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let servfail_parsed = Message::parse(&servfail_response).unwrap();
        assert_eq!(
            servfail_parsed.header.r_code(),
            ResponseCode::ServFail as u8,
            "a Bogus NegativeEntry must be served as SERVFAIL when CD=0, even for NODATA"
        );
        assert_eq!(servfail_parsed.authorities.len(), 0);

        let mut checking_disabled = features(false);
        checking_disabled.checking_disabled = true;
        let served_response = assemble_negative_response(
            1,
            &wire,
            &checking_disabled,
            &resolved,
            ResponseCode::NoError,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let served_parsed = Message::parse(&served_response).unwrap();
        assert_eq!(
            served_parsed.header.r_code(),
            ResponseCode::NoError as u8,
            "CD=1 must still serve the cached NODATA despite the Bogus state"
        );
        assert_eq!(served_parsed.authorities.len(), 1);
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
            &test_cookie_secret(),
            test_client_ip(),
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

    // Regression test for the negative-cache proof-record-owner bug: NSEC/
    // NSEC3 proof records (and their RRSIGs) are frequently owned by names
    // other than both the covered/queried name and the SOA zone apex (they
    // bracket the queried name with adjacent existing names in the zone).
    // Each must be written in the authority section under its own
    // preserved owner, not blanket-assigned to `negative.soa_owner`.
    #[test]
    fn assemble_negative_response_preserves_each_proof_records_own_owner() {
        let now = SystemTime::now();
        let covered_name = "nx.example.com";
        let soa_owner = "example.com";
        let nsec_owner_before = "adjacent-before.example.com";
        let nsec_owner_after = "zzz-adjacent-after.example.com";

        let proof_before = StoredRecord {
            rtype: 47, // NSEC
            rclass: IN_QCLASS,
            ttl_at_store: 3600,
            rdata: RecordData::NSEC {
                next_domain: "nx.example.com".to_string(),
                type_bit_maps: vec![0, 1],
            },
        };
        let proof_before_rrsig = StoredRecord {
            rtype: 46, // RRSIG
            rclass: IN_QCLASS,
            ttl_at_store: 3600,
            rdata: RecordData::RRSIG {
                type_covered: 47,
                algorithm: 8,
                labels: 3,
                original_ttl: 3600,
                signature_expiration: 2_000_000_000,
                signature_inception: 1_900_000_000,
                key_tag: 2,
                signer_name: soa_owner.to_string(),
                signature: vec![0xbb],
            },
        };
        let proof_after = StoredRecord {
            rtype: 47, // NSEC
            rclass: IN_QCLASS,
            ttl_at_store: 3600,
            rdata: RecordData::NSEC {
                next_domain: "example.com".to_string(),
                type_bit_maps: vec![0, 1],
            },
        };

        let negative = negative_entry_with_owner(
            now,
            3600,
            None,
            vec![
                (nsec_owner_before.to_string(), proof_before),
                (nsec_owner_before.to_string(), proof_before_rrsig),
                (nsec_owner_after.to_string(), proof_after),
            ],
            soa_owner,
        );
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: covered_name.to_string(),
            negative,
        };
        let wire = question_wire(covered_name, A_QTYPE, IN_QCLASS);

        let response = assemble_negative_response(
            1,
            &wire,
            &features(true),
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let parsed = Message::parse(&response).unwrap();

        // SOA + 2 NSEC proofs + 1 RRSIG = 4 authority records.
        assert_eq!(parsed.authorities.len(), 4);
        assert_eq!(parsed.authorities[0].name, soa_owner, "SOA under zone apex");

        let nsec_records: Vec<_> = parsed
            .authorities
            .iter()
            .filter(|record| record.rtype == 47)
            .collect();
        assert_eq!(nsec_records.len(), 2);
        assert!(
            nsec_records
                .iter()
                .any(|record| record.name == nsec_owner_before),
            "expected an NSEC record preserved under its own owner {nsec_owner_before}, got {:?}",
            parsed.authorities
        );
        assert!(
            nsec_records
                .iter()
                .any(|record| record.name == nsec_owner_after),
            "expected an NSEC record preserved under its own owner {nsec_owner_after}, got {:?}",
            parsed.authorities
        );
        assert!(
            nsec_records.iter().all(|record| record.name != soa_owner),
            "NSEC proof records must not be rewritten to the SOA zone apex"
        );
        assert!(
            nsec_records
                .iter()
                .all(|record| record.name != covered_name),
            "NSEC proof records must not be rewritten to the covered/queried name"
        );

        let rrsig_record = parsed
            .authorities
            .iter()
            .find(|record| record.rtype == 46)
            .expect("expected the proof RRSIG in the authority section");
        assert_eq!(
            rrsig_record.name, nsec_owner_before,
            "proof RRSIG must be preserved under the same owner as the NSEC it covers"
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
        let negative = negative_entry(
            now,
            3600,
            Some(soa_rrsig),
            vec![("proof-owner.example.com".to_string(), proof)],
        );
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
            &test_cookie_secret(),
            test_client_ip(),
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
            &test_cookie_secret(),
            test_client_ip(),
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
        let big_proof_records: Vec<(String, StoredRecord)> = (0..40u16)
            .map(|i| {
                (
                    "proof-owner.example.com".to_string(),
                    StoredRecord {
                        rtype: 999,
                        rclass: IN_QCLASS,
                        ttl_at_store: 3600,
                        rdata: RecordData::Unknown {
                            rtype: 999,
                            bytes: vec![i as u8; 20],
                        },
                    },
                )
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
            &test_cookie_secret(),
            test_client_ip(),
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
        // Regression test for RFC 6891 §7: even a minimal truncated
        // response must still carry an OPT record for an EDNS requester.
        assert_eq!(
            parsed.header.ar_count, 1,
            "minimal truncated response must still carry the requester's OPT record"
        );
        assert!(
            parsed.edns.is_some(),
            "truncated response for an EDNS requester must include OPT"
        );
    }

    // Regression test for RFC 6891 §6.1.1 on the negative-response path:
    // `assemble_negative_response` must also mirror the requester's OPT
    // record, with ARCOUNT accounting for it alongside the authority
    // section's SOA (+ optional RRSIG/proof records).
    #[test]
    fn assemble_negative_response_includes_opt_record_when_requester_used_edns() {
        let now = SystemTime::now();
        let negative = negative_entry(now, 3600, None, Vec::new());
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: "nx.example.com".to_string(),
            negative,
        };
        let wire = question_wire("nx.example.com", A_QTYPE, IN_QCLASS);

        let mut edns_features = features(false);
        edns_features.edns_udp_payload_size = Some(4096);

        let response = assemble_negative_response(
            1,
            &wire,
            &edns_features,
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            700,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let parsed = Message::parse(&response).unwrap();

        assert_eq!(parsed.authorities.len(), 1, "SOA still present");
        assert_eq!(
            parsed.header.ar_count, 1,
            "ARCOUNT must account for the mirrored OPT record"
        );
        let edns = parsed
            .edns
            .expect("negative cache-hit response must carry OPT when the requester used EDNS");
        assert_eq!(
            edns.udp_payload_size, 700,
            "OPT must advertise this resolver's own configured UDP payload size (700), \
             not echo the requester's 4096"
        );

        let no_edns_response = assemble_negative_response(
            1,
            &wire,
            &features(false),
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        let no_edns_parsed = Message::parse(&no_edns_response).unwrap();
        assert_eq!(no_edns_parsed.header.ar_count, 0);
        assert!(no_edns_parsed.edns.is_none());
    }

    // Regression test for RFC 4035 §3.2.2 on the negative-response path.
    #[test]
    fn assemble_negative_response_copies_cd_bit_from_requester() {
        let now = SystemTime::now();
        let negative = negative_entry(now, 3600, None, Vec::new());
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: "nx.example.com".to_string(),
            negative,
        };
        let wire = question_wire("nx.example.com", A_QTYPE, IN_QCLASS);

        let mut cd_features = features(false);
        cd_features.checking_disabled = true;
        let cd_response = assemble_negative_response(
            1,
            &wire,
            &cd_features,
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            Message::parse(&cd_response).unwrap().header.cd(),
            "CD=1 on the query must produce CD=1 on the negative response"
        );

        let no_cd_response = assemble_negative_response(
            1,
            &wire,
            &features(false),
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            !Message::parse(&no_cd_response).unwrap().header.cd(),
            "CD=0 on the query must produce CD=0 on the negative response"
        );
    }

    #[test]
    fn assemble_negative_response_sets_ad_only_when_negative_entry_secure_and_requested() {
        let now = SystemTime::now();

        // A secure negative entry, no CNAME chain: AD=1 with DO, AD=0
        // without DO/AD, mirroring the positive-side
        // `assemble_response_sets_ad_only_when_secure_and_requested` test.
        let mut secure_negative = negative_entry(now, 3600, None, Vec::new());
        secure_negative.dnssec_state = DnssecState::Secure;
        let resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: "nx.example.com".to_string(),
            negative: secure_negative,
        };
        let wire = question_wire("nx.example.com", A_QTYPE, IN_QCLASS);

        let mut do_features = features(true);
        let with_do = assemble_negative_response(
            1,
            &wire,
            &do_features,
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            Message::parse(&with_do).unwrap().header.ad(),
            "a Secure negative entry must produce AD=1 when the requester set DO"
        );

        do_features.dnssec_ok = false;
        let without_do_or_ad = assemble_negative_response(
            1,
            &wire,
            &do_features,
            &resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            !Message::parse(&without_do_or_ad).unwrap().header.ad(),
            "AD must stay 0 when the requester set neither DO nor AD"
        );

        // Unvalidated never produces AD=1, same as the positive side.
        let unvalidated_negative = negative_entry(now, 3600, None, Vec::new());
        let unvalidated_resolved = ResolvedNegative {
            chain: Vec::new(),
            terminal_name: "nx.example.com".to_string(),
            negative: unvalidated_negative,
        };
        let unvalidated_response = assemble_negative_response(
            1,
            &wire,
            &features(true),
            &unvalidated_resolved,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            !Message::parse(&unvalidated_response).unwrap().header.ad(),
            "an Unvalidated negative entry must never produce AD=1"
        );

        // A secure negative entry preceded by a CNAME chain: AD=1 requires
        // every chain hop to also be Secure, not just the terminal negative
        // entry.
        let mut secure_cname = rrset_entry(
            vec![StoredRecord {
                rtype: CNAME_RECORD_TYPE,
                rclass: IN_QCLASS,
                ttl_at_store: 300,
                rdata: RecordData::CNAME("target.example.com".to_string()),
            }],
            Duration::from_secs(300),
            now,
        );
        secure_cname.dnssec_state = DnssecState::Secure;
        let mut secure_negative_with_chain = negative_entry(now, 3600, None, Vec::new());
        secure_negative_with_chain.dnssec_state = DnssecState::Secure;
        let resolved_with_secure_chain = ResolvedNegative {
            chain: vec![("alias.example.com".to_string(), secure_cname)],
            terminal_name: "target.example.com".to_string(),
            negative: secure_negative_with_chain,
        };
        let chain_wire = question_wire("alias.example.com", A_QTYPE, IN_QCLASS);
        let secure_chain_response = assemble_negative_response(
            1,
            &chain_wire,
            &features(true),
            &resolved_with_secure_chain,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            Message::parse(&secure_chain_response).unwrap().header.ad(),
            "AD=1 requires every CNAME hop to be Secure too, and here they all are"
        );

        let mut unvalidated_cname = rrset_entry(
            vec![StoredRecord {
                rtype: CNAME_RECORD_TYPE,
                rclass: IN_QCLASS,
                ttl_at_store: 300,
                rdata: RecordData::CNAME("target.example.com".to_string()),
            }],
            Duration::from_secs(300),
            now,
        );
        unvalidated_cname.dnssec_state = DnssecState::Unvalidated;
        let mut secure_negative_after_unvalidated_hop = negative_entry(now, 3600, None, Vec::new());
        secure_negative_after_unvalidated_hop.dnssec_state = DnssecState::Secure;
        let resolved_with_unvalidated_hop = ResolvedNegative {
            chain: vec![("alias.example.com".to_string(), unvalidated_cname)],
            terminal_name: "target.example.com".to_string(),
            negative: secure_negative_after_unvalidated_hop,
        };
        let mixed_response = assemble_negative_response(
            1,
            &chain_wire,
            &features(true),
            &resolved_with_unvalidated_hop,
            ResponseCode::NxDomain,
            now,
            false,
            4096,
            &test_cookie_secret(),
            test_client_ip(),
        );
        assert!(
            !Message::parse(&mixed_response).unwrap().header.ad(),
            "an Unvalidated CNAME hop must prevent AD=1 even when the terminal negative entry \
             is Secure"
        );
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

        let result = resolve_from_cache(
            &cache,
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

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
        let answered = resolve_from_cache(
            &cache,
            "a.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );
        assert!(matches!(answered, ChainLookup::Answered(_)));

        // With too little depth (2 hops allowed, but 3 are needed to reach
        // "d"), the walk must give up rather than loop or return a partial
        // answer — and this chain never revisits a name, so this exercises
        // the depth bound itself, not the visited-set cycle guard.
        let too_shallow = resolve_from_cache(
            &cache,
            "a.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            2,
            now,
            &RefreshConfig::default(),
        );
        assert_eq!(too_shallow, ChainLookup::Miss);
    }

    #[test]
    fn resolve_from_cache_allows_terminal_hop_at_exact_max_chain_depth_boundary() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        // a -> b -> c -> d (3 CNAME restarts), terminal answer at "d".
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

        // A chain using exactly 3 CNAME restarts must succeed when
        // max_chain_depth is exactly 3 — "up to max_chain_depth restarts"
        // must mean the boundary itself is allowed, not
        // max_chain_depth - 1.
        let exact_boundary = resolve_from_cache(
            &cache,
            "a.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            3,
            now,
            &RefreshConfig::default(),
        );
        match exact_boundary {
            ChainLookup::Answered(resolved) => {
                assert_eq!(resolved.chain.len(), 4, "3 CNAME hops + terminal answer");
            }
            other => {
                panic!("expected Answered at the exact max_chain_depth boundary, got {other:?}")
            }
        }

        // A chain needing 4 CNAME restarts (one more than max_chain_depth)
        // must still fail — a distinct chain, so no intermediate hop has a
        // shortcut direct answer that would mask the depth bound.
        let hops_of_four = [
            ("p.example.com", "q.example.com"),
            ("q.example.com", "r.example.com"),
            ("r.example.com", "s.example.com"),
            ("s.example.com", "t.example.com"),
        ];
        for (name, target) in hops_of_four {
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
        let terminal_t = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        cache.shard_for("t.example.com").store_positive(
            "t.example.com",
            (A_QTYPE, IN_QCLASS),
            terminal_t,
        );
        let four_restarts_at_boundary = resolve_from_cache(
            &cache,
            "p.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            3,
            now,
            &RefreshConfig::default(),
        );
        assert_eq!(
            four_restarts_at_boundary,
            ChainLookup::Miss,
            "a chain needing max_chain_depth + 1 restarts must still fail"
        );
    }

    /// Regression test: the depth guard used to compare
    /// `chain.len() as u8 > max_chain_depth`, narrowing `chain.len()` (a
    /// `usize`) down to `u8` *before* comparing. With `max_chain_depth`
    /// near 255 and a chain reaching exactly 256 hops, `256 as u8` wraps
    /// around to `0`, and `0 > 255` is false -- so the old guard would
    /// silently let the walk continue right at the one point it should
    /// have stopped, defeating the configured cap. This chain needs
    /// exactly 256 CNAME restarts to reach its terminal answer, one more
    /// than `max_chain_depth = 255` allows: the walk must give up with
    /// `Miss`, not wrap around and serve the terminal answer anyway.
    #[test]
    fn resolve_from_cache_depth_guard_does_not_wrap_at_256_hops() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        const HOP_COUNT: usize = 256;
        let names: Vec<String> = (0..=HOP_COUNT)
            .map(|i| format!("h{i}.example.com"))
            .collect();
        for window in names.windows(2) {
            let (name, target) = (&window[0], &window[1]);
            let entry = rrset_entry(
                vec![StoredRecord {
                    rtype: CNAME_RECORD_TYPE,
                    rclass: IN_QCLASS,
                    ttl_at_store: 300,
                    rdata: RecordData::CNAME(target.clone()),
                }],
                Duration::from_secs(300),
                now,
            );
            cache
                .shard_for(name)
                .store_positive(name, (CNAME_RECORD_TYPE, IN_QCLASS), entry);
        }
        let terminal_name = names.last().unwrap();
        let terminal = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        cache.shard_for(terminal_name).store_positive(
            terminal_name,
            (A_QTYPE, IN_QCLASS),
            terminal,
        );

        let result = resolve_from_cache(
            &cache,
            &names[0],
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            255, // max_chain_depth: one less than the 256 restarts this chain needs
            now,
            &RefreshConfig::default(),
        );

        assert_eq!(
            result,
            ChainLookup::Miss,
            "a chain needing exactly 256 restarts must still fail max_chain_depth = 255, \
             not silently succeed because 256 wrapped to 0 under a narrowing u8 cast"
        );
    }

    #[test]
    fn resolve_from_cache_treats_expired_entry_as_miss() {
        // Serve-stale disabled: expired entries are evicted at read time,
        // the original behavior. The stale-serving counterpart is
        // `resolve_from_cache_serves_expired_entry_stale_within_window`.
        let cache = cache_without_serve_stale(1);
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
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        assert_eq!(result, ChainLookup::Miss);
    }

    #[test]
    fn resolve_from_cache_serves_expired_entry_stale_within_window() {
        // Default config: serve-stale on, one-day window. An entry expired
        // 300s ago is answered stale, with an *unconditional* refresh hint
        // (no popularity gate — stale data was served, refetch is
        // mandatory), even though its domain has no popularity bucket.
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        let stored_at = now - Duration::from_secs(600);
        let mut entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), stored_at);
        entry.expires_at = stored_at + Duration::from_secs(300); // expired 300s ago
        cache.shard_for("stale.example.com").store_positive(
            "stale.example.com",
            (A_QTYPE, IN_QCLASS),
            entry.clone(),
        );

        let result = resolve_from_cache(
            &cache,
            "stale.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        assert_eq!(
            result,
            ChainLookup::Answered(ResolvedAnswer {
                chain: vec![("stale.example.com".to_string(), entry)],
                refresh_hints: vec![RefreshHint {
                    domain: "stale.example.com".to_string(),
                    qtype: A_QTYPE,
                    qclass: IN_QCLASS,
                }],
            })
        );
    }

    #[test]
    fn resolve_from_cache_treats_expired_entry_beyond_stale_window_as_miss() {
        // Even with serve-stale on, an entry expired longer ago than
        // `max_stale` is a genuine miss — and is evicted at read time,
        // same as the serve-stale-disabled path.
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        let window = CacheConfig::default().max_stale;
        let stored_at = now - window - Duration::from_secs(600);
        let mut entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), stored_at);
        entry.expires_at = stored_at + Duration::from_secs(300);
        cache.shard_for("ancient.example.com").store_positive(
            "ancient.example.com",
            (A_QTYPE, IN_QCLASS),
            entry,
        );

        let result = resolve_from_cache(
            &cache,
            "ancient.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        assert_eq!(result, ChainLookup::Miss);
        assert!(
            !cache
                .shard_for("ancient.example.com")
                .contains_positive("ancient.example.com", (A_QTYPE, IN_QCLASS)),
            "beyond-window expired entry should be evicted at read time"
        );
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
        cname_entry.cache_epoch = 1;
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
            cache_epoch: 1,
            dnssec_complete: true,
            dnssec_state: DnssecState::Unvalidated,
            authoritative: false,
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
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
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

        let result = resolve_from_cache(
            &cache,
            "a.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

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
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        assert_eq!(result, ChainLookup::Miss);
    }

    #[test]
    fn resolve_from_cache_rejects_stale_epoch_independent_of_sweep() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
        // Entry is unexpired but stored under an epoch (1, from
        // `rrset_entry`) that no longer matches the current epoch (2) —
        // must be treated as a miss without requiring section-05's sweep to
        // have run.
        cache.shard_for("stale-epoch.example.com").store_positive(
            "stale-epoch.example.com",
            (A_QTYPE, IN_QCLASS),
            entry,
        );

        let result = resolve_from_cache(
            &cache,
            "stale-epoch.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            2,
            8,
            now,
            &RefreshConfig::default(),
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
        cname_entry.cache_epoch = 1;
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
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
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
        let result = resolve_from_cache(
            &cache,
            &domain_b,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );
        let elapsed = start.elapsed();

        handle.join().unwrap();

        assert!(matches!(result, ChainLookup::Answered(_)));
        assert!(
            elapsed < Duration::from_millis(150),
            "lookup against a different shard should not wait on shard A's held lock, took {elapsed:?}"
        );
    }

    // `RefreshHint`/multi-hop plumbing tests: section-04-chainlookup-plumbing.
    // `RefreshConfig::default()`: bucket_capacity=10, hot_threshold_fraction=0.5
    // (hot_threshold=5), lead_ratio=0.10, min_lead=5s, eligibility_floor=15s.

    /// Builds a two-hop chain: `source` (CNAME) -> `target` (A), both with
    /// `minimum_ttl = 300s`. `source_remaining`/`target_remaining` control
    /// each hop's remaining TTL independently (via a post-construction
    /// `expires_at` override), so a test can put either or both hops inside
    /// the default lead window (<= 30s) independently of the other.
    fn store_cname_chain(
        cache: &ShardedDnsCache,
        source: &str,
        target: &str,
        now: SystemTime,
        source_remaining: Duration,
        target_remaining: Duration,
    ) {
        let mut cname_entry = rrset_entry(
            vec![StoredRecord {
                rtype: CNAME_RECORD_TYPE,
                rclass: IN_QCLASS,
                ttl_at_store: 300,
                rdata: RecordData::CNAME(target.to_string()),
            }],
            Duration::from_secs(300),
            now,
        );
        cname_entry.expires_at = now + source_remaining;
        cache
            .shard_for(source)
            .store_positive(source, (CNAME_RECORD_TYPE, IN_QCLASS), cname_entry);

        let mut terminal_entry = rrset_entry(vec![a_record(300, 7)], Duration::from_secs(300), now);
        terminal_entry.expires_at = now + target_remaining;
        cache
            .shard_for(target)
            .store_positive(target, (A_QTYPE, IN_QCLASS), terminal_entry);
    }

    /// Directly queries `domain` at `qtype` (bypassing chain-following)
    /// `hit_count` times, so only `domain`'s own popularity bucket
    /// increments — its chain-mate's popularity is left untouched. Used to
    /// selectively make one hop "hot" (`RefreshConfig::default()`'s
    /// `hot_threshold` is 5) without warming the other hop in the same
    /// chain.
    fn warm_popularity(
        cache: &ShardedDnsCache,
        domain: &str,
        qtype: u16,
        now: SystemTime,
        hits: u32,
    ) {
        for _ in 0..hits {
            resolve_from_cache(
                cache,
                domain,
                qtype,
                IN_QCLASS,
                false,
                1,
                8,
                now,
                &RefreshConfig::default(),
            );
        }
    }

    #[test]
    fn chain_lookup_no_qualifying_hops_empty_hints() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        // Both hops fresh (300s remaining, outside the 30s lead window) and
        // neither ever queried before now (cold, level 0) -- neither
        // qualifies.
        store_cname_chain(
            &cache,
            "source.example.com",
            "target.example.com",
            now,
            Duration::from_secs(300),
            Duration::from_secs(300),
        );

        let result = resolve_from_cache(
            &cache,
            "source.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        match result {
            ChainLookup::Answered(resolved) => {
                assert!(resolved.refresh_hints.is_empty());
            }
            other => panic!("expected Answered, got {other:?}"),
        }
    }

    #[test]
    fn chain_lookup_intermediate_hop_only() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        // Source (CNAME) near expiry; target (terminal A) fresh.
        store_cname_chain(
            &cache,
            "source.example.com",
            "target.example.com",
            now,
            Duration::from_secs(20),  // inside the 30s lead window
            Duration::from_secs(300), // outside
        );
        // Warm only the source's popularity above the hot threshold (5).
        warm_popularity(&cache, "source.example.com", CNAME_RECORD_TYPE, now, 5);

        let result = resolve_from_cache(
            &cache,
            "source.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        match result {
            ChainLookup::Answered(resolved) => {
                assert_eq!(
                    resolved.refresh_hints,
                    vec![RefreshHint {
                        domain: "source.example.com".to_string(),
                        qtype: CNAME_RECORD_TYPE,
                        qclass: IN_QCLASS,
                    }],
                    "only the intermediate CNAME hop should produce a hint, not the fresh terminal hop"
                );
            }
            other => panic!("expected Answered, got {other:?}"),
        }
    }

    #[test]
    fn chain_lookup_terminal_hop_only() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        // Source (CNAME) fresh; target (terminal A) near expiry.
        store_cname_chain(
            &cache,
            "source.example.com",
            "target.example.com",
            now,
            Duration::from_secs(300), // outside the lead window
            Duration::from_secs(20),  // inside
        );
        // Warm only the target's popularity above the hot threshold (5).
        warm_popularity(&cache, "target.example.com", A_QTYPE, now, 5);

        let result = resolve_from_cache(
            &cache,
            "source.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        match result {
            ChainLookup::Answered(resolved) => {
                assert_eq!(
                    resolved.refresh_hints,
                    vec![RefreshHint {
                        domain: "target.example.com".to_string(),
                        qtype: A_QTYPE,
                        qclass: IN_QCLASS,
                    }],
                    "only the terminal hop should produce a hint, not the fresh intermediate hop"
                );
            }
            other => panic!("expected Answered, got {other:?}"),
        }
    }

    #[test]
    fn chain_lookup_multi_hop_all_qualifying_hops_produce_hints() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        // Both hops near expiry.
        store_cname_chain(
            &cache,
            "source.example.com",
            "target.example.com",
            now,
            Duration::from_secs(20),
            Duration::from_secs(20),
        );
        // Warm both hops' popularity above the hot threshold (5) --
        // directly, so each domain's own bucket (not the other's) reaches 5.
        warm_popularity(&cache, "source.example.com", CNAME_RECORD_TYPE, now, 5);
        warm_popularity(&cache, "target.example.com", A_QTYPE, now, 5);

        let result = resolve_from_cache(
            &cache,
            "source.example.com",
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        match result {
            ChainLookup::Answered(resolved) => {
                assert_eq!(
                    resolved.refresh_hints,
                    vec![
                        RefreshHint {
                            domain: "source.example.com".to_string(),
                            qtype: CNAME_RECORD_TYPE,
                            qclass: IN_QCLASS,
                        },
                        RefreshHint {
                            domain: "target.example.com".to_string(),
                            qtype: A_QTYPE,
                            qclass: IN_QCLASS,
                        },
                    ],
                    "every qualifying hop must produce its own hint, not just the terminal one \
                     (this is the regression test for the terminal-only bug found during plan review)"
                );
            }
            other => panic!("expected Answered, got {other:?}"),
        }
    }

    #[test]
    fn chain_lookup_no_data_never_carries_hint() {
        let cache = cache_with_shard_count(1);
        let now = SystemTime::now();
        let domain = "nodata.example.com";
        let key = NegativeKey {
            qtype: Some(A_QTYPE),
            qclass: IN_QCLASS,
        };
        let negative = NegativeEntry {
            kind: crate::resolver::NegativeCacheKind::NoData,
            soa_owner: "example.com".to_string(),
            soa_record: a_record(3600, 1),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_epoch: 1,
            dnssec_complete: true,
            dnssec_state: DnssecState::Unvalidated,
            authoritative: false,
        };
        cache
            .shard_for(domain)
            .store_negative(domain, key, negative);

        let result = resolve_from_cache(
            &cache,
            domain,
            A_QTYPE,
            IN_QCLASS,
            false,
            1,
            8,
            now,
            &RefreshConfig::default(),
        );

        // `ChainLookup::NoData` wraps `ResolvedNegative`, which structurally
        // has no `refresh_hints` field at all -- there is nothing to assert
        // beyond confirming the variant itself, which this match already
        // does at compile time (a hint field on `ResolvedNegative` would be
        // a compile error to access here, since it doesn't exist).
        assert!(matches!(result, ChainLookup::NoData(_)));
    }
}
