# Code Review: section-02-data-model

Reviewer: `deep-implement:code-reviewer` subagent

## Summary

Overall the implementation matches the plan's type shapes closely and
stays in scope (only `src/resolver/cache/entry.rs` is touched; no
locking/shard/LRU logic leaked in). All 6 required tests are present.
Field names/types line up with the plan: `DomainRecordSets.record_sets:
HashMap<(u16,u16), RRsetEntry>`; `RRsetEntry` has
records/rrsigs/response_code/minimum_ttl/stored_at/expires_at/dnssec_state/cache_namespace;
`StoredRecord` has rtype/rclass/ttl_at_store/rdata; `NegativeKey` derives
`Debug, Clone, PartialEq, Eq, Hash` (correct for `HashMap` key use,
verified against `DomainNegativeEntries::entries`); `NegativeEntry` has
kind/soa_record/soa_rrsig/proof_records/stored_at/expires_at/cache_namespace.
Reused types (`RecordData`, `ResponseCode`, `NegativeCacheKind`) are
imported rather than redefined, per plan. No scope-creep: no
`HashMap<String, DomainRecordSets>` shard-level wiring, no locking, no
LRU, no `PositiveShardState`/`NegativeShardState` introduced.

## Findings

- **HIGH — real gap, not an acceptable simplification**:
  `negative_entry_stores_soa_record_for_response_reconstruction` built its
  `soa_record` as `StoredRecord { rtype: 6 /* SOA */, ...,
  rdata: RecordData::A(...) /* placeholder RDATA */ }`. `RecordData`
  already has a fully-defined `SOA { ttl, rname, mname, serial, refresh,
  retry, expire, minimum }` variant (`src/protocol/mod.rs:258`), so there
  was no reason to fake it with `RecordData::A`. The mismatched
  `rtype: 6` + `RecordData::A` pairing is a value that could never occur
  from real DNS data, and defeated the test's stated purpose (proving the
  new `NegativeEntry` can rebuild a full authority-section SOA record from
  `soa_record` alone).
- **MEDIUM**: `negative_entry_soa_rrsig_and_proof_records_default_empty_without_dnssec`
  is tautological as originally written — it manually constructs the
  entry with `soa_rrsig: None, proof_records: Vec::new()` and then asserts
  those same fields, with no `Default` impl or constructor in the path
  (unlike `rrset_entry_dnssec_state_defaults_to_unvalidated`, which
  exercises `DnssecState::default()`). Considered during interview; no
  code change made (see disposition below).
- **LOW**: comment alignment on `RRsetEntry.response_code`/`cache_namespace`
  inconsistent with sibling fields.
- **LOW**: `NegativeEntry` had no top-level `///` doc comment, unlike every
  other struct/enum in the file.

## Test quality

All 6 required tests present and correctly named/scoped apart from the
HIGH/MEDIUM findings above.

## Style/idiom

Rustfmt-clean; visibility (`pub(crate)`) matches plan guidance; derive
traits sound given upstream `RecordData`/`ResponseCode`/`NegativeCacheKind`
already implement the needed traits.
