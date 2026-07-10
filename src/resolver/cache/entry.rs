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
//!
//! These types have no non-test callers yet (section-03 wraps them in
//! shard state); `#[allow(dead_code)]` below is transient and should be
//! removed once section-03 adds real callers, mirroring the same pattern
//! used for `shard_index` in section-01.

#![allow(dead_code)]

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
pub(crate) struct RRsetEntry {
    pub(crate) records: Vec<StoredRecord>,
    pub(crate) rrsigs: Vec<StoredRecord>, // empty if none were fetched/cached
    // Almost always NoError; kept for parity with today's CachedResponse shape.
    pub(crate) response_code: ResponseCode,
    pub(crate) minimum_ttl: Duration,
    pub(crate) stored_at: SystemTime,
    pub(crate) expires_at: SystemTime,
    pub(crate) dnssec_state: DnssecState,
    // Namespace is no longer part of the lookup key, so it must be stored
    // per entry instead.
    pub(crate) cache_namespace: String,
}

/// A single stored resource record, minus anything request-specific
/// (original casing, transaction id, etc. — those are applied at serve
/// time by section-06's assembly logic, not stored here). Reuses the
/// existing `RecordData` type from `src/protocol`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredRecord {
    pub(crate) rtype: u16,
    pub(crate) rclass: u16,
    pub(crate) ttl_at_store: u32,
    pub(crate) rdata: RecordData,
}

/// Mirrors RFC 6840 §3.1's "BAD cache" concept and Unbound/BIND-style
/// internal validation-state tracking. Every entry starts and stays
/// `Unvalidated` until real DNSSEC validation is implemented (out of scope
/// for this whole rework) — this enum exists purely so the data model
/// doesn't need reshaping again when that work happens later.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum DnssecState {
    #[default]
    Unvalidated,
    Insecure,
    Secure,
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
pub(crate) struct NegativeKey {
    pub(crate) qtype: Option<u16>,
    pub(crate) qclass: u16,
}

/// One negative-cache result (NXDOMAIN or NODATA) for a domain, keyed by
/// `NegativeKey` inside `DomainNegativeEntries`. Unlike today's
/// `NegativeCacheMetadata`, this stores the full covering SOA record so a
/// servable authority section can be rebuilt from `soa_record` alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NegativeEntry {
    pub(crate) kind: NegativeCacheKind, // reuse existing enum: NxDomain | NoData
    /// The covering SOA record itself (owner, RDATA, TTL) — needed to
    /// rebuild the authority section of a servable negative response, not
    /// just to derive negative TTL. `soa_owner`/`soa_minimum_ttl` as
    /// separate scalar fields (today's `NegativeCacheMetadata` shape) are
    /// redundant once the full record is stored; derive them from this
    /// instead of duplicating.
    pub(crate) soa_record: StoredRecord,
    /// RRSIG covering `soa_record`, if DNSSEC data was fetched. None until
    /// real validation exists (mirrors `DnssecState::Unvalidated` on the
    /// positive side).
    pub(crate) soa_rrsig: Option<StoredRecord>,
    /// NSEC/NSEC3 (+ their RRSIGs) proving the negative result, if
    /// fetched. Empty today (no DNSSEC validation is implemented) — the
    /// field exists so RFC 8198 aggressive negative caching doesn't
    /// require another reshape later.
    pub(crate) proof_records: Vec<StoredRecord>,
    pub(crate) stored_at: SystemTime,
    pub(crate) expires_at: SystemTime,
    pub(crate) cache_namespace: String,
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
            soa_record: soa_record.clone(),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
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
            soa_record: soa_record.clone(),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
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
            soa_record: stored_record(3600),
            soa_rrsig: None,
            proof_records: Vec::new(),
            stored_at: now,
            expires_at: now + Duration::from_secs(3600),
            cache_namespace: "ns-1".to_string(),
        };

        assert_eq!(entry.soa_rrsig, None);
        assert_eq!(entry.proof_records, Vec::new());
    }
}
