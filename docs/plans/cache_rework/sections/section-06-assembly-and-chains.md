## Section 06: Response assembly at serve time, and CNAME chain walking

### Dependencies

- **section-01-foundation**: the module skeleton
  (`src/resolver/cache/{mod,shard,lru,entry,singleflight,assemble,namespace}.rs`
  must already exist and compile) and the `shard_index(domain: &str,
  shard_count: usize) -> usize` hash-routing utility. This section reuses
  `shard_index` unchanged — do not re-derive hashing logic here.
- **section-02-data-model**: `RRsetEntry`, `StoredRecord`, `DnssecState`,
  `NegativeEntry`, `NegativeKey`, `DomainRecordSets`,
  `DomainNegativeEntries` — this section reads and clones these types, it
  does not modify their shape. In particular this section relies on every
  `RRsetEntry`/`NegativeEntry` carrying its own `cache_namespace: String`,
  `stored_at: SystemTime`, and `expires_at: SystemTime`.
- **section-03-shard-and-lru**: `Shard`/`ShardState` (one `Mutex` per
  shard, combining `PositiveShardState`, `NegativeShardState`, and
  `ShardLru` behind that single lock) and `ShardLru::touch`. This section
  is the first consumer of `Shard` that reads across the positive and
  negative maps for a single lookup.

This section does **not** depend on section-04 (single-flight) or
section-05 (namespace sweep) — it is parallelizable with section-05, per
`sections/index.md`. It performs its own inline namespace check on read
(see below); it does not call `sweep_stale_namespace`.

### Out of scope for this section (belongs elsewhere)

- **Storing** a backend response into the cache (`cache_store_for_response`,
  the CNAME-hop-plus-terminal-negative combined store) is
  section-07-call-site-migration's job (plan §9). This section's tests
  construct `Shard`/`ShardState` by hand (as section-05's tests do)
  rather than by calling a store function that doesn't exist yet.
  Concretely, the TDD stub `store_response_persists_cname_hop_and_terminal_negative_together`
  (listed under `claude-plan-tdd.md`'s "§7.1" heading) is **not** part of
  this section's test list below — it exercises the store path, which
  this section does not implement.
- Implementing the `DomainDnsCache` trait (`lookup_chain`, `store_response`,
  `sweep_stale_namespace`, `domain_count`, `capacity`) is section-07's job.
  This section only needs to produce the `ShardedDnsCache` container type
  and the free functions (`resolve_from_cache`, `assemble_response`) that
  section-07's trait impl will later call into.
- §7.2 of `claude-plan.md` ("Prefetch: reserved hook point") is
  **documentation-only** — reproduced verbatim-in-spirit below for
  completeness, but there is no code, config, or test to write for it in
  this section or any other.

**File to create/extend:** `src/resolver/cache/assemble.rs` (module
skeleton already exists from section-01) and `src/resolver/cache/mod.rs`
(add the `ShardedDnsCache` struct — see below; the rest of `mod.rs`, e.g.
the `DomainDnsCache` trait impl, is section-07's job).

---

### Background

#### Why response assembly moves to serve time at all

Per interview Q8/Q9/Q13 (`claude-plan.md` §7), cache entries stop storing
pre-built wire response templates and start storing raw record data
(`RRsetEntry.records: Vec<StoredRecord>`, `NegativeEntry.soa_record`,
etc. — section-02). Every cache hit now assembles the wire response fresh,
per request, instead of replaying a stored byte template
(`serialize_cached_response`, `mod.rs:4228-4256` today). The TTL-aging,
transaction-ID-rewriting, and truncation-decision logic already run per-hit
today; what's new is that record-to-wire serialization also becomes
per-hit instead of happening once at store time. This is required because
the cache key no longer includes question wire casing or EDNS bufsize
(those became per-request inputs to assembly instead of key dimensions),
so a single stored `RRsetEntry` must be able to serve many differently-cased,
differently-sized requests correctly.

#### TTL handling — two levels that must not be conflated

Today's `age_response_ttls` (`src/protocol/mod.rs:472-481`) ages every
record in a cached response *individually* by wall-clock elapsed time
since it was stored — it does not collapse all records to one shared TTL.
Separately, `RRsetEntry.minimum_ttl`/`expires_at` (the minimum TTL across
the RRset) governs only when the *whole entry* expires from the cache, not
what TTL each record reports on the wire.

`assemble_response` must preserve this split: age each `StoredRecord`'s
own `ttl_at_store` (section-02) independently by elapsed time since the
owning `RRsetEntry`'s `stored_at`, capped at each record's own remaining
lifetime. Do **not** substitute the entry-level `minimum_ttl` for every
record's wire TTL — that would be observably wrong for an RRset whose
records were originally cached with different TTLs (this is exactly what
`stored_record_preserves_original_ttl_independent_of_entry_minimum_ttl`,
section-02, exists to make possible).

Two free functions already exist in `src/protocol/mod.rs` and encode this
exact per-record age/cap algorithm against wire bytes:

```rust
pub fn age_response_ttls(response_bytes: &mut [u8], age: Duration) -> Result<()>
pub fn cap_response_ttls(response_bytes: &mut [u8], max_ttl: Duration) -> Result<()>
```

They currently operate on an already-serialized response buffer (used by
`serialize_cached_response` at `mod.rs:4228-4256`, after cloning a stored
template). Since assembly under this rework builds the wire response fresh
from `StoredRecord.ttl_at_store` values rather than replaying a template,
you have a choice, and it's the implementer's call: (a) write each
record's already-aged-and-capped TTL directly during serialization
(computing `elapsed = now.saturating_duration_since(entry.stored_at)`,
`aged = ttl_at_store.saturating_sub(elapsed)`, `capped =
aged.min(entry.expires_at.duration_since(now))` per record before writing
its wire bytes), or (b) serialize with the raw `ttl_at_store` values first
and then reuse `age_response_ttls`/`cap_response_ttls` unchanged against
the assembled buffer, mirroring today's call sequence in
`serialize_cached_response`. Option (b) has the advantage of reusing
already-tested code verbatim; be aware if a CNAME chain response combines
records from **multiple** `RRsetEntry`s with different `stored_at`
values (a multi-hop chain), a single scalar `age` passed to
`age_response_ttls` for the whole buffer is only correct if you pick one
`age`/`max_ttl` — which is wrong across hops with different `stored_at`.
If you take approach (b), you cannot call it once for the whole assembled
message; you'd need to either normalize all hops to a single reference
`stored_at` before serializing (incorrect) or call the aging step
per-hop's byte range (fragile). **Recommendation**: use approach (a) —
compute the final per-record TTL value in Rust before writing any wire
bytes, one record at a time, driven by that record's own owning
`RRsetEntry`. This sidesteps the multi-`stored_at` chain problem entirely
and is simpler to reason about than slicing a byte buffer by hop.

#### DNSSEC-relevant assembly rules (RFC 6840, `claude-research.md` B.3)

Now that AD/CD/DO are per-request `QueryFeatures` inputs to assembly
rather than cache-key dimensions, `assemble_response` must apply these
rules itself, per relevant `RRsetEntry`/`NegativeEntry` in the resolved
chain:

- Include RRSIGs (`RRsetEntry.rrsigs`, `NegativeEntry.soa_rrsig`/
  `proof_records`) in the response only if the requester's `dnssec_ok`
  (`QueryFeatures.dnssec_ok`, i.e. EDNS DO bit) is set.
- Set the response's AD bit only if **every** relevant entry's
  `dnssec_state` is `DnssecState::Secure` **and** the requester set DO or
  AD (`QueryFeatures.authenticated_data`). `Unvalidated`/`Insecure` never
  produce AD=1 regardless of requester flags.
- If `checking_disabled` (`QueryFeatures.checking_disabled`, CD bit) is
  `false` and any relevant entry's `dnssec_state` is `Bogus(_)`, serve
  SERVFAIL instead of the cached data. If CD is `true`, serve the cached
  data regardless of validation state.

Since no DNSSEC validation logic exists yet (out of scope for this
rework — every entry is `DnssecState::Unvalidated` at store time per
section-02), the `Secure`/`Bogus` branches of this logic are currently
unreachable in production but **must** still be implemented and tested
directly against hand-constructed `RRsetEntry`/`NegativeEntry` values with
those states set, exactly as the TDD tests below require. This is
shape-readiness for future DNSSEC validation work, not dead code to skip.

#### The generic wire-record encoder does not exist yet — new work required

`src/protocol/mod.rs` today has no generic "encode arbitrary `RecordData`
to wire bytes" function. What exists:
- A full **parser** (`Message::parse`, `parse_records`, etc.) going wire
  bytes → `Record`/`RecordData`.
- Narrow, single-purpose **writers** for specific response shapes:
  `build_question_response`/`write_sinkhole_answer` only handle
  `AddressAnswer::{A, Aaaa}` (used for block/sinkhole responses);
  `build_servfail_response`, `build_nxdomain_response`,
  `build_nodata_response`, `build_truncated_response` build header/question-only
  skeletons with no answer records.
- A `pub(crate) struct NameCompressor` (`src/protocol/mod.rs:701`) with a
  `write_name` method implementing RFC 1035 §4.1.4 compression pointers —
  this **is** crate-visible and reusable from `resolver::cache::assemble`.
  `write_u16`/`write_u32`/`write_response_header` (`src/protocol/mod.rs:640-664,
  745-752`) are currently module-private (not `pub(crate)`) — widen their
  visibility (or add crate-visible wrappers) as needed; this is a small,
  mechanical change, not a design decision.

None of the existing writers handle the full `RecordData` enum (CNAME, MX,
TXT, NS, SOA, RRSIG, NSEC/NSEC3, DNSKEY, DS, CAA, CERT, SRV, RP,
NSEC3PARAM, PTR, Unknown — `src/protocol/mod.rs:189-280`). `assemble_response`
needs to serialize whichever of these are actually present in a
`StoredRecord.rdata`/`NegativeEntry.soa_record`/`proof_records`, so this
section's implementation must add a generic encoder — e.g. a function
shaped like `pub(crate) fn write_record(out: &mut Vec<u8>, compressor:
&mut NameCompressor, name: &str, rtype: u16, rclass: u16, ttl: u32, rdata:
&RecordData)` in `src/protocol/mod.rs`, mirroring the existing parser's
`RecordData` match arms in reverse (encode instead of decode). This is
real, non-trivial new code — call it out explicitly in your TODO list, do
not assume it can be assembled purely from existing helpers.

---

### `ShardedDnsCache`: the top-level container (new in this section)

Per section-03's forward reference: "Wiring `Shard` into a top-level
`ShardedDnsCache` type that owns `Vec<Shard>` and routes via `shard_index`
happens in later sections (section-06 for lookup/assembly, section-07 for
the trait implementation and call-site migration)." This section creates
that type (in `src/resolver/cache/mod.rs`) and the read-side operations
on it. Section-07 later adds `impl DomainDnsCache for ShardedDnsCache`
(wrapping `resolve_from_cache`/`assemble_response` and adding
`store_response`) — do not implement that trait here.

```rust
pub struct ShardedDnsCache {
    shards: Vec<Shard>,
}

impl ShardedDnsCache {
    /// Builds one Shard per `config.shard_count` (or the section-01
    /// default if None), splitting `config.max_entries` across them using
    /// the exact remainder-distributed formula from section-01/plan §8:
    /// shard i's capacity = max_entries / shard_count, plus one extra if
    /// i < max_entries % shard_count. Does not recompute or duplicate that
    /// formula's derivation — call whatever section-01 exposes for it.
    pub fn new(config: &CacheConfig) -> Self { ... }

    /// Routes to the one shard responsible for `domain`, via
    /// `shard_index` (section-01). Kept private/crate-visible — external
    /// callers (section-07's trait impl, tests) go through
    /// `resolve_from_cache`, not this directly, except where a section-06
    /// test needs to reach into a specific shard to set up fixture state.
    fn shard_for(&self, domain: &str) -> &Shard { ... }
}
```

---

### `resolve_from_cache` / `ChainLookup`: CNAME chain walking

This is the one place where decomposing the flat cache into per-(name,
type) RRsets adds real complexity the old design didn't have: a query
answered via a CNAME chain today caches (and replays) one flat template
covering the whole chain. Under this design, each name in the chain is a
separate `DomainRecordSets` lookup — plausibly in a **different shard**
than the one the original query name hashed to. This decomposition is a
net win, not just added complexity: a CNAME target's own record set
becomes independently reusable by any other query that names it directly.

```rust
/// Walks a (possibly empty) CNAME chain starting at `qname`, doing one
/// independent per-shard lookup per name in the chain, up to a bounded
/// depth.
///
/// NOTE ON SIGNATURE: `claude-plan.md` §7.1 lists this function's params
/// as `(cache, qname, qtype, qclass, current_namespace, now)` and says to
/// reuse `max_cname_restarts` (`RecursiveResolverConfig.max_cname_restarts`,
/// `mod.rs:5520`) as the chain-depth bound "rather than introducing a
/// second, possibly-inconsistent one" — but that field lives on
/// `RecursiveResolverConfig`, not on anything `cache/` already has access
/// to, and isn't part of `CacheConfig` (section-01). The plan's listed
/// signature is therefore incomplete: add an explicit depth-bound
/// parameter (e.g. `max_chain_depth: u8`) and have the caller (ultimately
/// `probe_cache` in section-07) pass `RecursiveResolverConfig.max_cname_restarts`
/// through. This is an intentional, documented deviation from the plan's
/// literal listed signature, not an oversight to "fix" back to the
/// original.
fn resolve_from_cache(
    cache: &ShardedDnsCache,
    qname: &str,
    qtype: u16,
    qclass: u16,
    current_namespace: &str,
    max_chain_depth: u8,
    now: SystemTime,
) -> ChainLookup { ... }

enum ChainLookup {
    /// Every name in the chain was found, unexpired, in the current
    /// namespace.
    Answered(ResolvedAnswer),
    /// Whole-name NXDOMAIN at some point in the chain.
    NxDomain(ResolvedNegative),
    /// NODATA for the queried type at the terminal name.
    NoData(ResolvedNegative),
    /// Any name in the chain missed, expired, or was stale-namespace —
    /// caller must fall back to backend resolution. (No partial-chain
    /// caching of a backend re-fetch — that's a store-side concern, not
    /// this function's.)
    Miss,
}
```

**`ResolvedAnswer`/`ResolvedNegative` shape (implementer's call on exact
fields — this is the minimum `assemble_response` needs):**

```rust
/// Zero or more CNAME hops followed by the terminal RRsetEntry matching
/// the original qtype — or, if qtype == CNAME itself, exactly one hop
/// (the CNAME's own RRsetEntry, no further walking past it).
struct ResolvedAnswer {
    chain: Vec<(String, RRsetEntry)>, // (owner name, entry), in walk order
}

/// NOTE: `claude-plan.md` §7.1 shows `NxDomain(NegativeEntry)` /
/// `NoData(NegativeEntry)` — a bare NegativeEntry with no chain context.
/// That's insufficient: a CNAME chain ending in NXDOMAIN/NODATA must
/// still include the CNAME record(s) walked along the way in the
/// assembled response's answer section (this is existing, preserved
/// behavior — see `ttl_policy_preserves_negative_metadata_for_nxdomain_with_cname_answer`
/// and `ttl_policy_preserves_negative_metadata_for_nodata_with_cname_answer`,
/// migrated in section-08). Carry the accumulated chain alongside the
/// terminal negative entry:
struct ResolvedNegative {
    /// CNAME hops walked before reaching the negative result. Empty if
    /// the queried name itself was directly NXDOMAIN/NODATA.
    chain: Vec<(String, RRsetEntry)>,
    negative: NegativeEntry,
}
```

**Algorithm, per hop, starting at `current = normalize_question_name(qname)`:**

1. If `chain.len() as u8 >= max_chain_depth`, or `current` is already in a
   `visited: HashSet<String>` set tracked for this call, return
   `ChainLookup::Miss` — do not loop indefinitely. Cyclical cached data
   shouldn't be storable (the backend already prevents storing a cycle),
   but cache entries are long-lived and independently expirable, so treat
   the visited-set check as a cache-layer invariant, not just an inherited
   guarantee from the store side.
2. Acquire `cache.shard_for(&current)`'s lock (via whatever locking API
   section-03's `Shard` exposes).
3. Look up `current` in `PositiveShardState.domains`. If a
   `DomainRecordSets.record_sets` entry exists for `(qtype, qclass)`,
   unexpired (`entry.expires_at > now`) **and**
   `entry.cache_namespace == current_namespace`: clone it, push
   `(current.clone(), entry)` onto `chain`, release the lock, and return
   `ChainLookup::Answered(ResolvedAnswer { chain })`.
4. Else, if `qtype != CNAME_RECORD_TYPE` and a `(CNAME_RECORD_TYPE, qclass)`
   entry exists, unexpired and namespace-matching: clone it, push
   `(current.clone(), entry)` onto `chain`, extract the CNAME target from
   its `StoredRecord.rdata` (`RecordData::CNAME(target)`), release the
   lock, set `current = normalize_question_name(&target)`, mark it
   visited, and continue the loop (go to step 1).
5. Else, check `NegativeShardState.domains` for `current`: first try
   `NegativeKey { qtype: Some(qtype), qclass }` (NODATA for the queried
   type), then `NegativeKey { qtype: None, qclass }` (whole-name
   NXDOMAIN). If either is present, unexpired, and namespace-matching:
   clone it, release the lock, and return `ChainLookup::NoData(ResolvedNegative
   { chain, negative })` or `ChainLookup::NxDomain(ResolvedNegative {
   chain, negative })` respectively.
6. Else (nothing found, or found but expired or stale-namespace): release
   the lock and return `ChainLookup::Miss`.

**The inline namespace check in steps 3-5 is required, not optional** —
this is separate from, and in addition to, the bulk `sweep_stale_namespace`
sweep (section-05). The sweep is a background cleanup pass run once per
reload; it does not guarantee zero stale-namespace entries exist between
reloads and its own sweep pass completing. `resolve_from_cache` must
independently reject stale-namespace matches on every lookup so a request
arriving in that window doesn't get served data from before the last
reload.

**Lock discipline (required, not optional): never hold more than one
shard's lock at a time while walking.** For each hop: acquire that name's
shard lock, clone whatever `RRsetEntry`/`NegativeEntry` data is needed,
release the lock, *then* move to the next name (steps 2-6 above already
reflect this — the lock scope should end before step 1 of the next
iteration begins). Holding a lock across hops risks deadlock (two chains
crossing shards in opposite order) or self-deadlock (a later hop hashing
back to an already-held shard).

**Touch the LRU on every hop that finds live data**, not just the
terminal name — each `Shard` visited along the chain should have its
`ShardLru::touch` called for `current` while still holding that shard's
lock in steps 3-5 (a cache hit on an intermediate CNAME hop is still a
hit for that hop's own domain, and should count as recency for it).

---

### `assemble_response`

```rust
/// Builds a complete wire response from a resolved chain/negative lookup
/// (from resolve_from_cache above), using the *requester's own* question
/// wire bytes for name casing (interview Q9) and the *requester's own*
/// advertised EDNS bufsize for truncation (interview Q13) — both of which
/// are no longer cache-key dimensions, just per-response-assembly inputs.
fn assemble_response(
    requester_question_wire: &[u8],
    requester_features: &QueryFeatures,
    resolved: &ResolvedAnswer,
    now: SystemTime,
    allow_udp_truncation: bool,
) -> Vec<u8> { ... }
```

Equivalent functions (or overloads/variants — implementer's call) are
needed for the `ChainLookup::NxDomain`/`NoData` (`ResolvedNegative`)
cases, producing NXDOMAIN/NODATA responses with the accumulated CNAME
chain in the answer section and `NegativeEntry.soa_record` (+
`soa_rrsig` if DO is set) in the authority section. Whether this is one
function with a `ChainLookup`-shaped input or several small functions per
variant is not prescribed — match whatever composes most naturally with
the DNSSEC rules and TTL logic above, which apply identically regardless
of which `ChainLookup` variant produced the input.

**Required behavior, consolidated from the background section above:**

1. Build the response header (ID/flags come from the requester's own
   query — `rewrite_response_id`/RD-flag-mirroring logic already exists
   in `src/protocol/mod.rs`'s `rewrite_response_request_fields` and can be
   reused/adapted) and question section (using `requester_question_wire`
   directly for exact casing preservation — this is the whole point of Q9).
2. For each `(name, RRsetEntry)` in the chain, and the terminal answer (if
   `Answered`): write one wire record per `StoredRecord` in
   `entry.records`, with a TTL computed per the aging/capping rule above
   (aged by elapsed time since `entry.stored_at`, capped by remaining time
   to `entry.expires_at`). Include `entry.rrsigs` only if
   `requester_features.dnssec_ok`.
3. For negative results: after any CNAME chain records, write
   `negative.soa_record` (aged/capped the same way, using
   `negative.stored_at`/`expires_at`) into the authority section, plus
   `negative.soa_rrsig` and `negative.proof_records` if
   `requester_features.dnssec_ok`. Set the response code to `NXDOMAIN` or
   `NOERROR` (NODATA) per which `ChainLookup` variant produced this call.
4. Apply the DNSSEC AD-bit and Bogus/SERVFAIL rules from the background
   section, checked across every entry in the chain (not just the
   terminal one — an intermediate CNAME hop with `Bogus` state should also
   trigger SERVFAIL when CD is false).
5. If `allow_udp_truncation` and the assembled response exceeds the
   requester's effective UDP payload size (derived from
   `requester_features.edns_udp_payload_size`, mirroring
   `Message::effective_udp_payload_size`'s existing bounds-clamping logic
   at `src/protocol/mod.rs:360-369`), return a truncated response instead
   (`build_truncated_response`-equivalent: header + question only, TC bit
   set, no answer/authority/additional records) rather than the full
   assembled bytes.

### §7.2 — Prefetch: reserved hook point (documentation only, no code)

Recorded here for completeness; **do not write any code, config, or tests
for this** — it is out of scope for this rework entirely (raised in plan
review as a capability worth checking for, not one of the three original
goals):

- `RRsetEntry.stored_at`/`expires_at`/`minimum_ttl` already carry
  everything needed to decide "this record set is close to expiring" — no
  new field is required just to detect the condition.
- The sharded single-flight structure (section-04) is the correct
  primitive to dedupe a future prefetch trigger: a future implementation
  would call the same `begin()`/`finish()` path a normal miss uses,
  keyed by the same `(name, qtype, qclass)`.
- The one invariant a future prefetch implementation must respect:
  **never trigger the background refetch while still holding the shard
  lock** — the trigger check (comparing `now` to `expires_at`) happens
  inside a lookup's existing critical section, but the actual upstream I/O
  must start only after that lock is released.

---

### Tests to write first

Write these in `src/resolver/cache/assemble.rs`'s `#[cfg(test)] mod tests`
block, against hand-constructed `ShardedDnsCache`/`Shard` state (insert
`RRsetEntry`/`NegativeEntry` values directly into shard maps via whatever
section-03 exposes for test setup — no store-path function is available
yet, per "out of scope" above).

**Response assembly (`claude-plan-tdd.md` §7):**

- `assemble_response_ages_each_record_ttl_independently` — build an
  `RRsetEntry` from records with different original TTLs, assemble after
  simulated elapsed time, assert each record's wire TTL reflects its
  *own* aging, not a shared/collapsed value.
- `assemble_response_caps_ttl_to_remaining_entry_lifetime` — assembled
  TTLs never exceed what's left of the entry's `expires_at`.
- `assemble_response_echoes_requesters_own_casing` — two lookups for the
  same normalized domain with different requester-supplied casing
  (`example.com` vs `Example.COM`) both hit the *same* underlying
  `RRsetEntry`, and each assembled response echoes back its own
  requester's casing.
- `assemble_response_truncates_per_requesters_own_bufsize` — one shared
  `RRsetEntry` assembled for two requesters advertising different EDNS
  bufsizes/transports (UDP vs TCP) produces correctly truncated vs. full
  responses per requester, from the same stored data.
- `assemble_response_includes_rrsigs_only_when_requester_sets_do` — an
  `RRsetEntry` with non-empty `rrsigs`: assembled response includes them
  when `dnssec_ok == true`, omits them when `false`.
- `assemble_response_sets_ad_only_when_secure_and_requested` — an entry
  with `dnssec_state == Secure` produces AD=1 only when the requester set
  DO or AD; `Unvalidated`/`Insecure` never produce AD=1 regardless of
  requester flags.
- `assemble_response_servfails_on_bogus_when_checking_enabled` — an entry
  with `dnssec_state == Bogus(_)` and requester `checking_disabled ==
  false` yields SERVFAIL instead of the cached data; the same entry with
  `checking_disabled == true` serves the cached data normally.
- `resolve_from_cache_treats_expired_entry_as_miss` — a lookup against an
  `RRsetEntry`/`NegativeEntry` whose `expires_at <= now` returns
  `ChainLookup::Miss`, not stale data.

**CNAME chain walking (`claude-plan-tdd.md` §7.1):**

- `resolve_from_cache_follows_cname_chain_across_shards` — construct a
  chain where the queried name and the CNAME target hash to different
  shards; assert the walk correctly acquires/releases each shard's lock
  in turn (verifiable via not deadlocking under a concurrent test, or via
  an instrumented lock-count assertion) and returns the terminal answer.
- `resolve_from_cache_never_holds_two_shard_locks_at_once` — concurrency
  test: while one thread holds a shard lock mid-chain-walk (simulated
  delay), a second thread's unrelated lookup against a *different* domain
  in that same shard is not blocked once the first thread's per-hop
  critical section ends — i.e., the lock is released between hops, not
  held for the whole walk.
- `resolve_from_cache_respects_max_cname_restarts_bound` — a
  pathologically long (or cyclical) cached CNAME chain returns
  `ChainLookup::Miss` once `max_chain_depth` hops have been walked,
  rather than looping indefinitely.
- `resolve_from_cache_returns_miss_on_any_missing_chain_hop` — if any
  name in the chain is absent, expired, or under a stale namespace, the
  whole chain lookup returns `ChainLookup::Miss` (caller falls back to
  backend resolution) rather than a partial answer.
- (Recommended, not in the original TDD list but implied by the
  `ResolvedNegative` shape change documented above) a test asserting that
  a CNAME chain ending in NXDOMAIN/NODATA returns a `ResolvedNegative`
  whose `chain` field contains every CNAME hop walked before the
  terminal negative entry, so `assemble_response` can include them in the
  answer section.
- (Recommended) a test asserting the inline namespace check: an
  `RRsetEntry`/`NegativeEntry` present and unexpired but stored under a
  namespace different from `current_namespace` passed to
  `resolve_from_cache` is treated as a miss, independent of whether
  `sweep_stale_namespace` (section-05) has run.

### File paths touched by this section

- `src/resolver/cache/assemble.rs` — `resolve_from_cache`, `ChainLookup`,
  `ResolvedAnswer`, `ResolvedNegative`, `assemble_response`, and their
  unit tests (new content in a file whose skeleton section-01 already
  created).
- `src/resolver/cache/mod.rs` — add the `ShardedDnsCache` struct
  (`shards: Vec<Shard>`, `new`, `shard_for`) only; do **not** add the
  `DomainDnsCache` trait impl here (section-07).
- `src/protocol/mod.rs` — add the generic wire-record encoder (e.g.
  `write_record`, covering every `RecordData` variant) and widen
  visibility of `write_u16`/`write_u32`/`write_response_header` (or add
  crate-visible wrappers) as needed for `assemble.rs` to use them. This
  is new code, not a modification of existing encoder logic (none
  general-purpose exists today).

No other files are touched by this section. `resolve_from_cache`'s
`max_chain_depth: u8` parameter is threaded through by its caller in
section-07 (`probe_cache`), which is where
`RecursiveResolverConfig.max_cname_restarts` actually lives — this
section does not read that config type directly.

## Implementation notes (actual vs. planned)

- **Files**: as planned — `src/resolver/cache/assemble.rs` (new content),
  `src/resolver/cache/mod.rs` (`ShardedDnsCache` only), `src/protocol/mod.rs`
  (generic encoder). One addition not in the plan's file list:
  `src/resolver/cache/shard.rs` gained a `Shard::lookup_hop` method +
  `HopResult` enum, for the same structural reason section-05 already
  added `Shard::sweep_stale_namespace` — `Shard`'s internal state is
  private to its own module, and `cache::assemble` is a sibling module
  (not a descendant), so it cannot reach `Shard`'s fields directly.
  `write_response_header` (existing) was left untouched rather than
  widened, since it always zeroes authority/additional counts and has no
  AD-bit control — a new `write_message_header` was added alongside it
  instead of changing its signature and disturbing its existing callers.
- **Signature deviations** (all intentional, all because the plan's listed
  inputs don't carry the needed value): `resolve_from_cache` takes an
  explicit `max_chain_depth: u8` (plan already calls this one out itself).
  `assemble_response`/`assemble_negative_response` additionally take an
  explicit `request_id: u16` (`QueryFeatures` has no transaction ID field)
  and `configured_max_udp_payload_size: usize` (no `Message`/`DecodedQuery`
  is passed in to derive the server-side UDP ceiling from).
  `ResolvedNegative` gained a `terminal_name: String` field not in the
  plan's literal struct listing: `NegativeEntry` has no owner-name field of
  its own (mirrors how `RRsetEntry`'s owner name comes from the chain
  tuple, not the entry itself), so `assemble_negative_response` needs to
  know what name to write the authority-section SOA under. This uses the
  terminal *queried* name as the SOA owner, not necessarily the true zone
  apex (which this cache model has no field to track) — the same
  simplification the model already applies to positive-side owner names.
- **DNSSEC AD-bit/Bogus checks on negative results** are evaluated across
  `ResolvedNegative.chain` (the CNAME hops, which carry `dnssec_state` via
  their `RRsetEntry`) but not against the terminal `NegativeEntry` itself,
  since section-02's `NegativeEntry` has no `dnssec_state` field. An empty
  chain (direct NXDOMAIN/NODATA, no CNAME hops) never produces AD=1.
- **No compression-pointer back-reference into the copied question
  section**: `requester_question_wire` is appended raw after the header;
  the `NameCompressor` used for the answer/authority sections starts fresh
  and only compresses among themselves. Produces valid but not
  maximally-compact wire output — an accepted simplification, not
  revisited.
- **Truncated-response shape — code review + user decision**: review
  found the first draft hardcoded `ResponseCode::NoError` on truncation
  regardless of the real response code (would have silently turned a
  truncated NXDOMAIN/NODATA into a false NOERROR — fixed) and omitted the
  question section, matching the codebase's pre-existing
  `build_truncated_response` but contradicting this plan's own "header +
  question only" text. Asked the user; they chose to follow the plan's
  literal text. Truncated responses from this path now carry: header
  (TC=1, real response code preserved) + question section, matching the
  plan exactly — intentionally diverging from `build_truncated_response`,
  which is untouched and still header-only for its own (non-cache)
  callers.
- **Tests**: all tests from the plan's list implemented, plus 8 added
  during code review: 3 `assemble_negative_response` tests (no prior
  coverage existed for the negative path at all), 3 wire-encoder
  round-trip tests in `protocol/mod.rs` (SOA field order, NSEC3 hex
  round-trip, TXT >255-byte chunking — the plan called the encoder "real,
  non-trivial new code" needing its own test attention), a
  NODATA-vs-NXDOMAIN priority test, and a non-cyclical depth-exceeded test
  (the existing cyclical-chain test only exercised the visited-set guard,
  not the `max_chain_depth` bound itself). Final count: 19 tests in
  `assemble.rs` (14 planned/adapted + 5 added) + 3 in `protocol/mod.rs`,
  full suite at 461 (up from 453 after section-05).