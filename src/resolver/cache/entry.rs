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

//! Pure data types for one shard's cached content: the positive-cache
//! shape (`RRsetEntry`, `StoredRecord`, `DnssecState`, `DomainRecordSets`)
//! and the negative-cache shape (`NegativeEntry`, `NegativeKey`,
//! `DomainNegativeEntries`). No locking, shard combination, or LRU wiring
//! lives here — that's section-03 (`cache::shard`, `cache::lru`).

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::protocol::{RecordData, ResponseCode};
use crate::resolver::NegativeCacheKind;

/// All cached record sets for one owner name, across every qtype/qclass
/// queried for it. This is the "many DNS record sets per domain" shape.
/// Lives inside a shard's positive-cache map (built in section-03), keyed
/// by normalized domain name — this type itself has no knowledge of which
/// shard or map it lives in.
#[derive(Debug, Clone, Default)]
pub(crate) struct DomainRecordSets {
    pub(crate) record_sets: HashMap<(u16, u16), RRsetEntry>, // (qtype, qclass) -> entry
}

/// One cached RRset: the answer data for exactly one (name, qtype, qclass),
/// stored once regardless of how many different requesters' flag
/// combinations end up served from it (casing, EDNS bufsize, and DNSSEC
/// flags are no longer key dimensions — see the wider rework's serve-time
/// assembly design, implemented in section-06, not this section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RRsetEntry {
    pub records: Vec<StoredRecord>,
    pub rrsigs: Vec<StoredRecord>, // empty if none were fetched/cached
    // Almost always NoError; kept for parity with today's CachedResponse shape.
    pub response_code: ResponseCode,
    pub minimum_ttl: Duration,
    pub stored_at: SystemTime,
    pub expires_at: SystemTime,
    pub dnssec_state: DnssecState,
    // Namespace is no longer part of the lookup key, so it must be stored
    // per entry instead.
    pub cache_namespace: String,
    /// Whether `rrsigs` reflects a *confirmed* DNSSEC state, i.e. this
    /// entry was populated from a backend response fetched with the
    /// *storing* request's own DO (`dnssec_ok`) flag set. Recursive
    /// resolution forwards each requester's own DO flag upstream, so a
    /// DO=false-driven fetch's empty `rrsigs` means "never asked" — not
    /// "confirmed no RRSIGs exist". A DO=true reader must never be served
    /// from an entry with `dnssec_complete == false`: doing so would
    /// silently serve an answer that looks validated-empty but was simply
    /// never checked, for that entry's full remaining TTL (see
    /// `Shard::lookup_hop`'s DO-aware filtering, which enforces this at
    /// cache-hit time). A DO=false reader may be served regardless of this
    /// flag, since DO=false readers never need/emit RRSIGs anyway.
    pub dnssec_complete: bool,
    /// The backend response's own AA (Authoritative Answer) bit, captured
    /// at store time (`build_rrset_entry`) so a later cache-hit response
    /// can reproduce it instead of always serving AA=0. A cached copy of an
    /// authoritative answer is still describing an authoritative answer —
    /// serving it back as AA=0 would be a real semantic change for clients
    /// that check this bit (see `assemble::assemble_response`'s header
    /// write).
    pub authoritative: bool,
}

/// A single stored resource record, minus anything request-specific
/// (original casing, transaction id, etc. — those are applied at serve
/// time by section-06's assembly logic, not stored here). Reuses the
/// existing `RecordData` type from `src/protocol`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    pub rtype: u16,
    pub rclass: u16,
    pub ttl_at_store: u32,
    pub rdata: RecordData,
}

/// Mirrors RFC 6840 §3.1's "BAD cache" concept and Unbound/BIND-style
/// internal validation-state tracking. Every entry starts and stays
/// `Unvalidated` until real DNSSEC validation is implemented (out of scope
/// for this whole rework) — this enum exists purely so the data model
/// doesn't need reshaping again when that work happens later.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnssecState {
    #[default]
    Unvalidated,
    // Not constructed anywhere yet — real DNSSEC validation is out of
    // scope for this whole rework; these variants exist so the data
    // model doesn't need reshaping again when that work happens later.
    #[allow(dead_code)]
    Insecure,
    #[allow(dead_code)]
    Secure,
    #[allow(dead_code)]
    Bogus(String), // reason, for diagnostics; short negative-style TTL applies
}

/// All negative-cache entries for one owner name. Lives inside a shard's
/// negative-cache map (built in section-03), keyed by normalized domain
/// name — same normalization as `DomainRecordSets`, same domain-name
/// string, but a structurally separate map.
#[derive(Debug, Clone, Default)]
pub(crate) struct DomainNegativeEntries {
    pub(crate) entries: HashMap<NegativeKey, NegativeEntry>,
}

/// `qtype: None` represents a whole-name NXDOMAIN (RFC 2308) — the name
/// itself doesn't exist, independent of any specific qtype. `qtype:
/// Some(t)` represents NODATA for that specific type at an existing name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NegativeKey {
    pub(crate) qtype: Option<u16>,
    pub(crate) qclass: u16,
}

/// One negative-cache result (NXDOMAIN or NODATA) for a domain, keyed by
/// `NegativeKey` inside `DomainNegativeEntries`. Unlike today's
/// `NegativeCacheMetadata`, this stores the full covering SOA record so a
/// servable authority section can be rebuilt from `soa_record` alone —
/// except for the owner name, which `soa_record` (a bare `StoredRecord`)
/// has no field for, hence `soa_owner` below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeEntry {
    pub(crate) kind: NegativeCacheKind, // reuse existing enum: NxDomain | NoData
    /// The owner name of the covering SOA record (the zone apex, e.g.
    /// `example.com`) — distinct from the name this entry is stored/looked
    /// up under (the *covered* name, e.g. `nx.sub.example.com`, whenever
    /// the NXDOMAIN/NODATA is below the zone apex). The authority-section
    /// SOA in a servable negative response must be written under this
    /// name, not the covered name — using the covered name here was the
    /// bug this field fixes (see `assemble::write_negative_authority`'s
    /// call site).
    pub(crate) soa_owner: String,
    /// The covering SOA record itself (RDATA, TTL) — needed to rebuild the
    /// authority section of a servable negative response, not just to
    /// derive negative TTL. `soa_minimum_ttl` (today's
    /// `NegativeCacheMetadata` shape) is not duplicated here since it's
    /// derivable from `soa_record` alone.
    pub(crate) soa_record: StoredRecord,
    /// RRSIG covering `soa_record`, if DNSSEC data was fetched. None until
    /// real validation exists (mirrors `DnssecState::Unvalidated` on the
    /// positive side).
    pub(crate) soa_rrsig: Option<StoredRecord>,
    /// NSEC/NSEC3 (+ their RRSIGs) proving the negative result, if
    /// fetched, paired with each record's own owner name. Unlike
    /// `RRsetEntry`'s records (whose owner is always the domain the entry
    /// is stored under), NSEC/NSEC3 proof records are frequently owned by
    /// names *other than* the covered/queried name or the SOA zone apex
    /// (e.g. an NSEC bracketing the queried name with the adjacent
    /// existing name in the zone) — `StoredRecord` itself carries no owner
    /// field, so it must be paired here instead of written blanket-style
    /// under `soa_owner` at assemble time (`assemble::write_negative_authority`'s
    /// call site).
    pub(crate) proof_records: Vec<(String, StoredRecord)>,
    pub(crate) stored_at: SystemTime,
    pub(crate) expires_at: SystemTime,
    pub(crate) cache_namespace: String,
    /// Same DO-completeness contract as `RRsetEntry::dnssec_complete`,
    /// applied to `soa_rrsig`/`proof_records`: `true` only when this entry
    /// was populated from a backend response fetched with the storing
    /// request's own DO flag set, so empty/absent DNSSEC material means
    /// "confirmed absent" rather than "never asked". A DO=true reader must
    /// never be served from a negative entry with `dnssec_complete ==
    /// false`. Note this flag alone is *not* sufficient to gate a DO=true
    /// hit — it says nothing about whether the individually-TTLed records
    /// it vouches for (`soa_rrsig`, `proof_records`) are still within
    /// their own TTL as of read time; see `dnssec_proof_material_fresh`
    /// for that complementary check.
    pub(crate) dnssec_complete: bool,
    /// Mirrors `RRsetEntry::dnssec_state`: the validation state of this
    /// negative result (NXDOMAIN/NODATA), starting and staying
    /// `Unvalidated` until real DNSSEC validation is implemented. Wired
    /// into AD-bit computation the same way as the positive side (see
    /// `assemble::dnssec_ad_bit`'s call sites for `ResolvedNegative`).
    pub(crate) dnssec_state: DnssecState,
    /// The backend response's own AA (Authoritative Answer) bit, captured
    /// at store time (`build_negative_entry`) — same contract as
    /// `RRsetEntry::authoritative`.
    pub(crate) authoritative: bool,
}

impl NegativeEntry {
    /// Whether every DNSSEC-relevant record stored in this entry — the SOA
    /// record itself, `soa_rrsig` (if present), and each `proof_records`
    /// entry — still has positive remaining TTL as of `now`, computed from
    /// that specific record's own `ttl_at_store` aged by elapsed time since
    /// `stored_at`. This is deliberately independent of `expires_at`, which
    /// is derived solely from the covering SOA's negative-caching TTL/
    /// minimum (RFC 2308) and says nothing about how long the SOA's RRSIG
    /// or any NSEC/NSEC3 proof record individually remains valid — those
    /// can (and often do) carry a materially shorter TTL than the negative
    /// TTL they're bundled with.
    ///
    /// `dnssec_complete` (this type's other DNSSEC gate) answers a
    /// different question — "was this entry's DNSSEC material ever
    /// confirmed at all" — and stays `true` for this entry's entire
    /// `expires_at` lifetime once set. Without this method, a DO=true
    /// reader arriving after an individual proof record's own TTL elapsed
    /// (but before the overall negative TTL elapsed) would still pass the
    /// `dnssec_complete` gate and be served that record aged to wire TTL 0
    /// by `compute_wire_ttl` — stale material silently masquerading as
    /// fresh. Callers must check both: `dnssec_complete` for "was this
    /// asked for", this method for "is what was returned still usable".
    /// Only meaningful for DO=true cache-hit gating (see
    /// `Shard::lookup_hop`'s doc comment) — a DO=false reader neither
    /// needs nor emits any of this material, so it is unaffected either
    /// way, mirroring `dnssec_complete`'s own DO=false carve-out.
    pub(crate) fn dnssec_proof_material_fresh(&self, now: SystemTime) -> bool {
        let record_fresh =
            |ttl_at_store: u32| self.stored_at + Duration::from_secs(u64::from(ttl_at_store)) > now;
        if !record_fresh(self.soa_record.ttl_at_store) {
            return false;
        }
        if let Some(rrsig) = &self.soa_rrsig
            && !record_fresh(rrsig.ttl_at_store)
        {
            return false;
        }
        self.proof_records
            .iter()
            .all(|(_, record)| record_fresh(record.ttl_at_store))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const IN_QCLASS: u16 = 1;
    const A_QTYPE: u16 = 1;
    const AAAA_QTYPE: u16 = 28;

    fn stored_record(ttl: u32) -> StoredRecord {
        StoredRecord {
            rtype: A_QTYPE,
            rclass: IN_QCLASS,
            ttl_at_store: ttl,
            rdata: RecordData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    fn rrset_entry(records: Vec<StoredRecord>, minimum_ttl: Duration) -> RRsetEntry {
        let now = SystemTime::now();
        RRsetEntry {
            records,
            rrsigs: Vec::new(),
            response_code: ResponseCode::NoError,
            minimum_ttl,
            stored_at: now,
            expires_at: now + minimum_ttl,
            dnssec_state: DnssecState::default(),
            cache_namespace: "ns-1".to_string(),
            dnssec_complete: true,
            authoritative: false,
        }
    }

    #[test]
    fn rrset_entry_stores_multiple_qtypes_under_one_domain() {
        let mut domain = DomainRecordSets::default();
        let a_entry = rrset_entry(vec![stored_record(300)], Duration::from_secs(300));
        let aaaa_entry = rrset_entry(vec![stored_record(120)], Duration::from_secs(120));

        domain
            .record_sets
            .insert((A_QTYPE, IN_QCLASS), a_entry.clone());
        domain
            .record_sets
            .insert((AAAA_QTYPE, IN_QCLASS), aaaa_entry.clone());

        assert_eq!(
            domain.record_sets.get(&(A_QTYPE, IN_QCLASS)),
            Some(&a_entry)
        );
        assert_eq!(
            domain.record_sets.get(&(AAAA_QTYPE, IN_QCLASS)),
            Some(&aaaa_entry)
        );
        assert_eq!(domain.record_sets.len(), 2);
    }

    #[test]
    fn rrset_entry_dnssec_state_defaults_to_unvalidated() {
        let entry = rrset_entry(vec![stored_record(300)], Duration::from_secs(300));
        assert_eq!(entry.dnssec_state, DnssecState::Unvalidated);
    }

    #[test]
    fn stored_record_preserves_original_ttl_independent_of_entry_minimum_ttl() {
        let records = vec![stored_record(600), stored_record(120)];
        let entry = rrset_entry(records, Duration::from_secs(120));

        assert_eq!(entry.records[0].ttl_at_store, 600);
        assert_eq!(entry.records[1].ttl_at_store, 120);
        assert_eq!(entry.minimum_ttl, Duration::from_secs(120));
    }

    #[test]
    fn negative_entry_stores_soa_record_for_response_reconstruction() {
        let now = SystemTime::now();
        let soa_record = StoredRecord {
            rtype: 6, // SOA
            rclass: IN_QCLASS,
            ttl_at_store: 3600,
            rdata: RecordData::SOA {
                ttl: 3600,
                rname: "hostmaster.example.com".to_string(),
                mname: "ns1.example.com".to_string(),
                serial: 2026070901,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum: 3600,
            },
        };
        let entry = NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: soa_record.clone(),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
            dnssec_complete: true,
            dnssec_state: DnssecState::default(),
            authoritative: false,
        };

        assert_eq!(entry.soa_record, soa_record);
        assert_eq!(entry.soa_record.ttl_at_store, 3600);
        match &entry.soa_record.rdata {
            RecordData::SOA {
                mname,
                rname,
                serial,
                ..
            } => {
                assert_eq!(mname, "ns1.example.com");
                assert_eq!(rname, "hostmaster.example.com");
                assert_eq!(*serial, 2026070901);
            }
            other => panic!("expected SOA rdata, got {other:?}"),
        }
    }

    #[test]
    fn negative_key_distinguishes_nxdomain_from_nodata_by_qtype_option() {
        let now = SystemTime::now();
        let soa_record = stored_record(3600);
        let negative_entry = |kind: NegativeCacheKind| NegativeEntry {
            kind,
            soa_owner: "example.com".to_string(),
            soa_record: soa_record.clone(),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
            dnssec_complete: true,
            dnssec_state: DnssecState::default(),
            authoritative: false,
        };

        let mut domain = DomainNegativeEntries::default();
        let nxdomain_key = NegativeKey {
            qtype: None,
            qclass: IN_QCLASS,
        };
        let nodata_key = NegativeKey {
            qtype: Some(AAAA_QTYPE),
            qclass: IN_QCLASS,
        };

        domain.entries.insert(
            nxdomain_key.clone(),
            negative_entry(NegativeCacheKind::NxDomain),
        );
        domain.entries.insert(
            nodata_key.clone(),
            negative_entry(NegativeCacheKind::NoData),
        );

        assert_eq!(domain.entries.len(), 2);
        assert_eq!(
            domain.entries.get(&nxdomain_key).map(|e| e.kind),
            Some(NegativeCacheKind::NxDomain)
        );
        assert_eq!(
            domain.entries.get(&nodata_key).map(|e| e.kind),
            Some(NegativeCacheKind::NoData)
        );
    }

    #[test]
    fn negative_entry_soa_rrsig_and_proof_records_default_empty_without_dnssec() {
        let now = SystemTime::now();
        let entry = NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: stored_record(3600),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
            dnssec_complete: true,
            dnssec_state: DnssecState::default(),
            authoritative: false,
        };

        assert_eq!(entry.soa_rrsig, None);
        assert_eq!(entry.proof_records, Vec::new());
    }

    #[test]
    fn rrset_entry_dnssec_complete_defaults_false_for_do_false_populated_entries() {
        // Regression test for the stale-DO-false-entry bug: an entry
        // populated by a DO=false-driven fetch must be constructible with
        // `dnssec_complete: false` (meaning "never asked", not "confirmed
        // no RRSIGs") so a later DO=true reader can distinguish it from a
        // DO=true-confirmed entry with genuinely empty `rrsigs`.
        let mut entry = rrset_entry(vec![stored_record(300)], Duration::from_secs(300));
        entry.dnssec_complete = false;

        assert!(entry.rrsigs.is_empty());
        assert!(
            !entry.dnssec_complete,
            "a DO=false-populated entry must not report its DNSSEC state as confirmed"
        );
    }

    #[test]
    fn negative_entry_dnssec_complete_defaults_false_for_do_false_populated_entries() {
        let now = SystemTime::now();
        let entry = NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: stored_record(3600),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
            dnssec_complete: false,
            dnssec_state: DnssecState::default(),
            authoritative: false,
        };

        assert!(
            !entry.dnssec_complete,
            "a DO=false-populated negative entry must not report its DNSSEC state as confirmed"
        );
    }

    #[test]
    fn negative_entry_dnssec_state_defaults_to_unvalidated() {
        let now = SystemTime::now();
        let entry = NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: stored_record(3600),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
            dnssec_complete: true,
            dnssec_state: DnssecState::default(),
            authoritative: false,
        };

        assert_eq!(entry.dnssec_state, DnssecState::Unvalidated);
    }

    // Regression tests for the negative-entry DNSSEC-proof-TTL bug:
    // `dnssec_proof_material_fresh` must independently bound usability by
    // each stored DNSSEC-relevant record's own TTL, not just the entry's
    // SOA-derived overall `expires_at`.

    fn negative_entry_with_dnssec(
        stored_at: SystemTime,
        overall_ttl: Duration,
        soa_ttl: u32,
        soa_rrsig_ttl: Option<u32>,
        proof_ttls: Vec<u32>,
    ) -> NegativeEntry {
        NegativeEntry {
            kind: NegativeCacheKind::NxDomain,
            soa_owner: "example.com".to_string(),
            soa_record: stored_record(soa_ttl),
            soa_rrsig: soa_rrsig_ttl.map(stored_record),
            proof_records: proof_ttls
                .into_iter()
                .map(|ttl| ("proof.example.com".to_string(), stored_record(ttl)))
                .collect(),
            stored_at,
            expires_at: stored_at + overall_ttl,
            cache_namespace: "ns-1".to_string(),
            dnssec_complete: true,
            dnssec_state: DnssecState::default(),
            authoritative: false,
        }
    }

    #[test]
    fn dnssec_proof_material_fresh_true_when_every_record_still_within_its_own_ttl() {
        let stored_at = SystemTime::now() - Duration::from_secs(100);
        let entry = negative_entry_with_dnssec(
            stored_at,
            Duration::from_secs(3600),
            3600,
            Some(3600),
            vec![3600, 3600],
        );

        assert!(entry.dnssec_proof_material_fresh(SystemTime::now()));
    }

    #[test]
    fn dnssec_proof_material_fresh_false_once_a_proof_records_own_ttl_elapses() {
        // Overall SOA-derived negative TTL is a full hour, but one NSEC
        // proof record's own TTL is only 300s. 301s after storage, the
        // overall entry is still unexpired (`expires_at` unaffected), but
        // the proof record itself is stale and must not be reported fresh.
        let stored_at = SystemTime::now() - Duration::from_secs(301);
        let entry = negative_entry_with_dnssec(
            stored_at,
            Duration::from_secs(3600),
            3600,
            Some(3600),
            vec![300],
        );

        assert!(
            entry.expires_at > SystemTime::now(),
            "overall negative TTL must still be unexpired for this test to be meaningful"
        );
        assert!(!entry.dnssec_proof_material_fresh(SystemTime::now()));
    }

    #[test]
    fn dnssec_proof_material_fresh_false_once_soa_rrsig_ttl_elapses() {
        let stored_at = SystemTime::now() - Duration::from_secs(301);
        let entry = negative_entry_with_dnssec(
            stored_at,
            Duration::from_secs(3600),
            3600,
            Some(300),
            Vec::new(),
        );

        assert!(!entry.dnssec_proof_material_fresh(SystemTime::now()));
    }

    #[test]
    fn dnssec_proof_material_fresh_false_once_soa_records_own_ttl_elapses() {
        let stored_at = SystemTime::now() - Duration::from_secs(301);
        let entry =
            negative_entry_with_dnssec(stored_at, Duration::from_secs(3600), 300, None, Vec::new());

        assert!(!entry.dnssec_proof_material_fresh(SystemTime::now()));
    }

    #[test]
    fn dnssec_proof_material_fresh_true_with_no_dnssec_material_present() {
        let stored_at = SystemTime::now() - Duration::from_secs(301);
        let entry = negative_entry_with_dnssec(
            stored_at,
            Duration::from_secs(3600),
            3600,
            None,
            Vec::new(),
        );

        assert!(entry.dnssec_proof_material_fresh(SystemTime::now()));
    }
}
