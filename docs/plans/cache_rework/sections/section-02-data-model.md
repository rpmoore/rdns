# Section 02: Cache Data Model (Positive and Negative Entry Types)

## Objective

Define the pure data types that represent one shard's cached content: the
positive-cache entry shape (`RRsetEntry`, `StoredRecord`, `DnssecState`,
`DomainRecordSets`) and the negative-cache entry shape (`NegativeEntry`,
`NegativeKey`, `DomainNegativeEntries`). This section produces **data types
only** — no locking, no shard combination, no LRU wiring, no eviction logic.
Those live in section-03 (`cache/shard.rs`, `cache/lru.rs`), which depends on
the types defined here.

## Dependencies

- **section-01-foundation** must be complete first: the `src/resolver/cache/`
  module skeleton (including an empty `entry.rs`) and `CacheConfig` already
  exist. This section does not need `shard_index` or `CacheConfig` directly,
  but the module must already compile as an empty skeleton before this
  section adds real types to it.
- This section **blocks section-03-shard-and-lru**, which combines
  `DomainRecordSets`/`DomainNegativeEntries` into per-shard state
  (`PositiveShardState`, `NegativeShardState`) behind a lock, plus the LRU
  and eviction loop. Do not implement `PositiveShardState`/
  `NegativeShardState` here — those belong to section-03's `cache/shard.rs`
  per the module layout below.

## Background

This is a from-scratch redesign of the DNS answer cache currently living in
`src/resolver/mod.rs` (`InMemoryDnsCache`). The rework moves from a single
flat `CacheKey`-indexed cache to **domain-first**, sharded storage: each
shard holds, per normalized owner name, a set of positive record sets
(one per `(qtype, qclass)`) and a separate set of negative-cache entries.
This section defines the data shapes for "what one domain's cached data
looks like" — the types that section-03 will later store inside
`HashMap<String, DomainRecordSets>` / `HashMap<String, DomainNegativeEntries>`
per shard.

Two design decisions from the wider plan matter directly for this section's
types:

- **Positive and negative results are never folded into one structure.**
  Negative answers (NXDOMAIN/NODATA) get their own per-domain map, separate
  from `DomainRecordSets`, so "no data of this type" and "this type's data"
  can never be confused, and a positive `RRsetEntry` for one qtype
  coexisting with a negative result for a different qtype on the same name
  is representationally natural, not a special case.
- **`cache_namespace` moves from being part of the lookup key to being
  stored data on every entry.** The new key is just the domain name (plus,
  within a domain, `(qtype, qclass)` or `NegativeKey`) — no namespace
  component. Each `RRsetEntry` and `NegativeEntry` therefore carries its own
  `cache_namespace: String` field so a later namespace sweep (implemented in
  section-05, not this section) can identify and remove stale entries. This
  section only needs to include the field; no sweep logic belongs here.

## File to create

`src/resolver/cache/entry.rs` — per the module layout established in
section-01:

```
src/resolver/cache/
  mod.rs           # (section-01) ShardedDnsCache, trait impl, public API
  shard.rs         # (section-03) Shard, ShardState, PositiveShardState,
                    #   NegativeShardState, eviction loop
  lru.rs           # (section-03) ShardLru
  entry.rs         # (THIS SECTION) RRsetEntry, StoredRecord, DnssecState,
                    #   NegativeEntry, NegativeKey, DomainRecordSets,
                    #   DomainNegativeEntries
  singleflight.rs  # (section-04)
  assemble.rs       # (section-06)
  namespace.rs       # (section-05)
```

All types in this section go in `cache/entry.rs`, with a `#[cfg(test)] mod
tests` block at the bottom containing the tests listed below, per this
codebase's existing convention (one test module per file, descriptive
snake_case test names).

## Reused existing types (do not redefine)

- `RecordData` — the existing resource-record-data enum (variants like `A`,
  `AAAA`, `CNAME`, `MX`, `TXT`, `OPT`, etc.), defined at
  `src/protocol/mod.rs:189`. Import it (`crate::protocol::RecordData` or
  whatever the crate's existing import path is) rather than creating a new
  record-data representation.
- `ResponseCode` — defined at `src/protocol/mod.rs:73`. Reuse directly for
  `RRsetEntry.response_code`.
- `NegativeCacheKind` (`NxDomain | NoData`) — defined at
  `src/resolver/mod.rs:601`. Reuse directly for `NegativeEntry.kind`; do not
  define a new enum with the same two variants.
- `normalize_question_name` — defined at `src/resolver/mod.rs:189`. This is
  the existing lowercase-and-strip-trailing-dot normalization used for
  `QuestionKey` today. Any code in this section that documents how domain
  names are expected to be normalized (e.g. in doc comments) should
  reference reusing this function rather than describing a new
  normalization scheme — actual call sites that invoke it are section-03's
  concern (map keys), not this section's (this section defines value types,
  not the maps they live in).

## Tests first

Write these in `src/resolver/cache/entry.rs`'s `#[cfg(test)] mod tests`
block before implementing the types. These are prose stubs — implement the
actual `#[test]` functions; the descriptions below state exactly what each
must assert.

### Positive cache data model

- `rrset_entry_stores_multiple_qtypes_under_one_domain` — construct a
  `DomainRecordSets` and insert two distinct `RRsetEntry` values (e.g. one
  keyed `(A_QTYPE, IN_QCLASS)`, one keyed `(AAAA_QTYPE, IN_QCLASS)`) into
  `record_sets`. Assert both are retrievable independently afterward and
  that inserting the second did not evict or overwrite the first.
- `rrset_entry_dnssec_state_defaults_to_unvalidated` — construct an
  `RRsetEntry` via whatever minimal constructor/builder this section adds
  (a plain struct literal is acceptable if no constructor function is
  needed) without performing any DNSSEC validation, and assert
  `dnssec_state == DnssecState::Unvalidated`. This matches the current
  codebase having no DNSSEC validation mode other than disabled.
- `stored_record_preserves_original_ttl_independent_of_entry_minimum_ttl` —
  build an `RRsetEntry` from two or more `StoredRecord`s with *different*
  individual TTLs (different `ttl_at_store` values), plus an entry-level
  `minimum_ttl` that is the minimum across them. Assert each
  `StoredRecord.ttl_at_store` still holds its own original, distinct value
  — it must not have been collapsed to `minimum_ttl`. (`minimum_ttl` is used
  only for entry-level expiry, computed elsewhere; this test just confirms
  the two fields don't get conflated in the data model itself.)

### Negative cache data model

- `negative_entry_stores_soa_record_for_response_reconstruction` — construct
  a `NegativeEntry` and assert it retains a full `soa_record: StoredRecord`
  (owner name, RDATA, TTL all present/inspectable), not just derived scalar
  fields. This is a deliberate shape decision: unlike today's
  `NegativeCacheMetadata` (which stores only `soa_owner: String` and
  `soa_minimum_ttl: Duration`), the new `NegativeEntry` must be able to
  rebuild a full authority-section SOA record from `soa_record` alone.
- `negative_key_distinguishes_nxdomain_from_nodata_by_qtype_option` —
  construct a `DomainNegativeEntries` and insert two `NegativeEntry` values
  under `NegativeKey { qtype: None, qclass: IN }` (whole-name NXDOMAIN) and
  `NegativeKey { qtype: Some(t), qclass: IN }` (NODATA for type `t`) for the
  same domain. Assert both keys coexist as independent map entries and
  neither overwrites the other.
- `negative_entry_soa_rrsig_and_proof_records_default_empty_without_dnssec`
  — construct a `NegativeEntry` representing a result with no DNSSEC data
  fetched, and assert `soa_rrsig == None` and `proof_records == vec![]` (or
  equivalent empty-collection assertion). Mirrors the positive-side
  default-`Unvalidated` test: the negative shape must also default cleanly
  to "no DNSSEC" without special-case handling.

## Implementation: data types

### Positive cache entry types

```rust
/// All cached record sets for one owner name, across every qtype/qclass
/// queried for it. This is the "many DNS record sets per domain" shape.
/// Lives inside a shard's positive-cache map (built in section-03), keyed
/// by normalized domain name — this type itself has no knowledge of which
/// shard or map it lives in.
struct DomainRecordSets {
    record_sets: HashMap<(u16, u16), RRsetEntry>, // (qtype, qclass) -> entry
}

/// One cached RRset: the answer data for exactly one (name, qtype, qclass),
/// stored once regardless of how many different requesters' flag
/// combinations end up served from it (casing, EDNS bufsize, and DNSSEC
/// flags are no longer key dimensions — see the wider rework's serve-time
/// assembly design, implemented in section-06, not this section).
struct RRsetEntry {
    records: Vec<StoredRecord>,
    rrsigs: Vec<StoredRecord>,       // empty if none were fetched/cached
    response_code: ResponseCode,     // almost always NoError; kept for parity
                                      // with today's CachedResponse shape
    minimum_ttl: Duration,
    stored_at: SystemTime,
    expires_at: SystemTime,
    dnssec_state: DnssecState,
    cache_namespace: String,         // namespace is no longer part of the
                                      // lookup key, so it must be stored
                                      // per entry instead (see Background)
}

/// A single stored resource record, minus anything request-specific
/// (original casing, transaction id, etc. — those are applied at serve
/// time by section-06's assembly logic, not stored here). Reuses the
/// existing `RecordData` type from `src/protocol`.
struct StoredRecord {
    rtype: u16,
    rclass: u16,
    ttl_at_store: u32,
    rdata: RecordData,
}

/// Mirrors RFC 6840 §3.1's "BAD cache" concept and Unbound/BIND-style
/// internal validation-state tracking. Every entry starts and stays
/// `Unvalidated` until real DNSSEC validation is implemented (out of scope
/// for this whole rework) — this enum exists purely so the data model
/// doesn't need reshaping again when that work happens later.
enum DnssecState {
    Unvalidated,
    Insecure,
    Secure,
    Bogus(String), // reason, for diagnostics; short negative-style TTL applies
}
```

### Negative cache entry types

```rust
/// All negative-cache entries for one owner name. Lives inside a shard's
/// negative-cache map (built in section-03), keyed by normalized domain
/// name — same normalization as `DomainRecordSets`, same domain-name
/// string, but a structurally separate map (see "Why separate" below).
struct DomainNegativeEntries {
    entries: HashMap<NegativeKey, NegativeEntry>,
}

/// `qtype: None` represents a whole-name NXDOMAIN (RFC 2308) — the name
/// itself doesn't exist, independent of any specific qtype. `qtype:
/// Some(t)` represents NODATA for that specific type at an existing name.
#[derive(PartialEq, Eq, Hash, Clone)]
struct NegativeKey {
    qtype: Option<u16>,
    qclass: u16,
}

struct NegativeEntry {
    kind: NegativeCacheKind,   // reuse existing enum: NxDomain | NoData
                                // (src/resolver/mod.rs:601)
    /// The covering SOA record itself (owner, RDATA, TTL) — needed to
    /// rebuild the authority section of a servable negative response, not
    /// just to derive negative TTL. `soa_owner`/`soa_minimum_ttl` as
    /// separate scalar fields (today's NegativeCacheMetadata shape) are
    /// redundant once the full record is stored; derive them from this
    /// instead of duplicating.
    soa_record: StoredRecord,
    /// RRSIG covering `soa_record`, if DNSSEC data was fetched. None until
    /// real validation exists (mirrors DnssecState::Unvalidated on the
    /// positive side).
    soa_rrsig: Option<StoredRecord>,
    /// NSEC/NSEC3 (+ their RRSIGs) proving the negative result, if
    /// fetched. Empty today (no DNSSEC validation is implemented) — the
    /// field exists so RFC 8198 aggressive negative caching doesn't
    /// require another reshape later.
    proof_records: Vec<StoredRecord>,
    stored_at: SystemTime,
    expires_at: SystemTime,
    cache_namespace: String,
}
```

**Reconciling with the wider spec's `(name, qtype-or-ANY, SOA-owner)`
phrasing**: that phrasing (carried over from research on other resolvers'
negative-cache designs) is not an instruction to make SOA owner part of the
lookup key. Keeping SOA owner as *stored data* on `NegativeEntry` rather
than a key component is deliberate: there is exactly one active negative
result per `(name, qtype)` at a time — whichever SOA currently covers it —
matching how `NegativeCacheMetadata.soa_owner` is already treated as data,
not a key, in the current implementation (`src/resolver/mod.rs:591-598`).
Making it a key component would allow multiple simultaneous,
potentially-conflicting negative proofs for the same `(name, qtype)`, which
is not desired.

### Why positive and negative entries are separate maps but share a domain key

Both `DomainRecordSets` and `DomainNegativeEntries` are keyed by the same
normalized domain name string. This section only defines the two value
types; section-03 is responsible for actually placing both under one
shard's lock and one LRU/eviction unit. The reasoning that drives this
section's shape (so the types line up correctly with section-03's later
combination) is: a single domain's cache-recency and capacity accounting
must account for *all* cached data about it — positive and negative — as
one eviction unit (capacity counts **domains**, not individual record
sets). Splitting positive and negative into separate maps keeps
negative-cache semantics clean (no ambiguity between "no data of this type"
and "this type's data") without splitting the recency/capacity accounting
that section-03 will build on top of these types. A domain with only a
negative entry (no positive record sets at all) must still be a fully valid,
independently constructible `DomainNegativeEntries` — do not make any part
of this section's types assume a `DomainRecordSets` must also exist for the
same domain.

## Notes for the implementer

- Do not add any locking, `HashMap<String, DomainRecordSets>`-at-the-shard-
  level wiring, or LRU touch calls in this section — those are section-03's
  `PositiveShardState`/`NegativeShardState`/`Shard` types in `cache/shard.rs`
  and `cache/lru.rs`, which will wrap the types defined here.
- Only add constructors/builders for these types if they're needed to make
  the tests above pass cleanly (e.g., a small `RRsetEntry::new(...)` helper
  is fine if it avoids repetitive struct-literal boilerplate in tests, but
  is not required — plain struct literals in tests are acceptable).
- Derive whatever standard traits (`Debug`, `Clone`, `PartialEq`, `Eq`,
  `Hash` where applicable) are needed for the tests to construct, compare,
  and use these types as `HashMap` keys/values; `NegativeKey` in particular
  must derive `Eq + Hash` since it's used as a `HashMap` key inside
  `DomainNegativeEntries`.
- Keep all types `pub(crate)` or module-private as appropriate to
  `src/resolver/cache` — none of these types need to be part of the crate's
  public API surface; only the trait defined in section-07
  (`DomainDnsCache`) and its request/response shapes need to cross the
  `resolver::cache` module boundary.

## Relevant file paths

- `src/resolver/cache/entry.rs` — created/filled in by this section (types
  + tests).
- `src/protocol/mod.rs:189` — existing `RecordData` enum, reused.
- `src/protocol/mod.rs:73` — existing `ResponseCode` enum, reused.
- `src/resolver/mod.rs:601` — existing `NegativeCacheKind` enum, reused.
- `src/resolver/mod.rs:189` — existing `normalize_question_name` function,
  referenced for documentation purposes (actual call sites are section-03's
  concern).
- `src/resolver/mod.rs:580-598` — existing `CachedResponse`/
  `NegativeCacheMetadata` shapes this section's types replace conceptually
  (not literally reused).