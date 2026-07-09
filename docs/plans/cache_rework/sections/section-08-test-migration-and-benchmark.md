# section-08-test-migration-and-benchmark: Migrating the ~16 existing cache tests and adding the concurrency benchmark

## Dependencies

- **section-07-call-site-migration** must be fully complete: the
  `DomainDnsCache` trait, `ShardedDnsCache`, `DecomposedResponse`,
  `ChainLookup`/`ResolvedAnswer`/`ResolvedNegative`, `assemble_response`,
  `sweep_stale_namespace`, and every rewritten call site
  (`probe_cache`, `cache_store_for_response`, `resolve_coalesced_*`,
  `main.rs`, `RuntimeConfig.cache`, `tests/recursive_perf.rs`'s
  `resolver_with_cache` helper) must already compile and have their own
  tests passing.
- Transitively depends on every other section (01-06), since this section
  is what finally makes `src/resolver/mod.rs`'s big `#[cfg(test)] mod
  tests` block compile and pass again as a whole.

This is the **last** section. Per `sections/index.md`'s dependency graph,
nothing depends on it.

## Scope

Section-07 explicitly left `src/resolver/mod.rs` in a state where its own
new code compiles and passes, but the pre-existing `#[cfg(test)] mod
tests` block does not fully compile, because:

1. It still contains the entire legacy `InMemoryDnsCache` cache
   implementation (production code, not test code — section-07 was
   explicitly told not to delete it) plus roughly a dozen tests written
   directly against it and against the now-deleted `CacheKey` type.
2. Two test doubles shared across dozens of unrelated tests —
   `RecordingCache` (implements the now-deleted `DnsCache` trait) and
   `OwnedOnlyProtocolCodec` (overrides the now-deleted
   `ProtocolCodec::serialize_cached_response`) — no longer compile.
3. A double-digit number of resolve()-level integration tests construct
   `Arc::new(InMemoryDnsCache::new(N))` or
   `Arc::new(RecordingCache::with_lookup(CacheLookup::Miss))` as plumbing
   to exercise unrelated behavior (malicious-domain blocking, backend
   generation, TCP/UDP sharing, etc.) and need a mechanical construction
   swap even though their actual test logic is untouched by this rework.

This section's job, in order:

1. **Delete the legacy `InMemoryDnsCache` implementation** (production
   code) and its own dedicated unit tests — their behavioral intent is
   already covered by sections 01/02/03/05/06's own unit tests.
2. **Fix the two shared test doubles** (`RecordingCache`,
   `OwnedOnlyProtocolCodec`) so every test that uses them compiles again.
3. **Mechanically migrate** every remaining `InMemoryDnsCache::new(...)`
   / `RecordingCache::with_lookup(CacheLookup::...)` call site that isn't
   itself a cache-semantics test (malicious-CNAME blocking,
   TCP/UDP-sharing, backend-generation-via-real-cache, etc.) to the new
   constructors — these tests' *assertions* don't change, only their
   setup plumbing.
4. **Rewrite, for real behavioral coverage**, the resolve()-level
   integration tests that exercise TTL aging/capping, truncation,
   expired-as-miss, and request coalescing through the new assembly path
   — these were *not* already written by section-07 (section-07 only
   wrote the request-id/RD-flag/malicious-CNAME/namespace-sweep/metrics
   ones; see the disposition table below for exactly which ones remain).
5. **Add the new concurrency benchmark** (`claude-plan-tdd.md` §11),
   closing G8 from `docs/caching.md` (no test/benchmark today exercises
   the cache under real concurrent load).

When this section is done, `cargo test --locked` must pass on the whole
crate, and `just bench` must still run (with the new concurrency
benchmark added alongside or in place of the existing
`tests/recursive_perf.rs` benchmark).

## Background: what plan §11 says to do, restated precisely

`claude-plan.md` §11 groups the ~16 existing cache-related tests
(`claude-research.md` A.4) into three buckets. Read this before touching
anything — the actual test count in the current codebase is closer to
~23 once you include every `InMemoryDnsCache`/`CacheKey`-touching test,
not just the ones plan §11 names individually; the extra ones follow the
same disposition logic even though they aren't named verbatim in the plan
text.

- **Rewrite for the new shape, same intent**: eviction-order, expiry,
  zero-capacity-behavior tests, and resolve-level integration tests
  (cached-template reuse, TTL aging, malicious-CNAME blocking on both
  direct and coalesced-miss paths, request coalescing itself,
  `backend_generation_separates_cache_entries` — becomes a
  namespace-sweep test — plus the truncation and expired-as-miss tests,
  which "directly exercise serve-time assembly/expiry mechanics this
  rework changes, though not the observable contract").
- **Delete, deliberately**: `cache_key_from_query_includes_supported_semantics`
  and `cache_key_separates_exact_wire_question_casing_for_templates`
  assert exactly the key-fragmentation behavior this rework removes
  (casing, EDNS bufsize, and folding `QueryFeatures` into the lookup key
  all go away). Replace with tests asserting the *opposite*.
- **`in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits`** — tests a
  ghost-token compaction mechanism that no longer exists at all; replaced
  by section-03's `lru_touch_moves_domain_to_most_recent_without_leaving_stale_positions`.

## Part 1 — Delete the legacy `InMemoryDnsCache` (production code)

`InMemoryDnsCache` is **not** test code — it's the concrete cache type
`main.rs` used to construct before section-07 rewired it to
`ShardedDnsCache`. Section-07 deleted the `DnsCache` trait it implements
(`mod.rs:4435-4451` in the pre-rework file) but was told to leave
`InMemoryDnsCache` itself alone, so as of section-07 landing,
`impl DnsCache for InMemoryDnsCache` no longer compiles (its trait is
gone) — this is the "expected transitional state" section-07 documented.
This section fixes it by deleting, not by porting:

- `pub struct InMemoryDnsCache { max_entries, state }`,
  `struct InMemoryDnsCacheState { entries, lru, next_sequence }`,
  `struct InMemoryDnsCacheEntry { response, sequence }` (originally
  `mod.rs:5322-5337`).
- `impl InMemoryDnsCache { new, len, is_empty, capacity, remove_expired,
  lru_len, lookup_now, store_now }` (originally `mod.rs:5339-5437`).
- `impl InMemoryDnsCacheState { next_sequence, compact_lru,
  remove_expired, maybe_compact_lru, evict_to_bound }` (originally
  `mod.rs:5439-5481`).
- `fn lru_compaction_threshold(max_entries: usize) -> usize` (originally
  `mod.rs:5483-5487`) and the `const LRU_COMPACTION_MULTIPLIER: usize = 4;`
  it uses (originally `mod.rs:59`) — confirm via grep that nothing else
  references either before deleting; as of this writing, nothing does.
- `impl DnsCache for InMemoryDnsCache { lookup, store }` (originally
  `mod.rs:5489-5499`).

**Do not touch anything after this block** — `DelegationCache` and its
supporting types (`DelegationEntry`, `DelegationCacheState`,
`delegation_cache_key`, `zone_suffixes`, etc.) begin immediately after
`InMemoryDnsCache` in the file and are explicitly out of scope for this
entire rework (`claude-plan.md`'s "out of scope" list). Delete exactly
the `InMemoryDnsCache`-related block and stop.

Also delete the two now-dead test helper functions that only exist to
build `CacheKey`/`CacheStore` values for `InMemoryDnsCache`'s own tests:
`fn cache_key(name: &str) -> CacheKey` and
`fn cache_store_at(key: CacheKey, ttl: Duration, stored_at: SystemTime)
-> CacheStore` (originally `mod.rs:11013`, `mod.rs:11028`, inside the
test module) — once their last caller (below) is deleted, these become
dead code too.

## Part 2 — Fix the two shared test doubles

### `RecordingCache` (originally `mod.rs:8351-8380`)

Used by **~22 call sites** across the test module — most just want a
cache that always misses (`RecordingCache::with_lookup(CacheLookup::Miss)`)
as inert plumbing for tests about something else entirely (backend
selection, policy blocking, metrics, malicious-domain handling); a
handful actually inspect what got looked up or stored.

```rust
// Before (deleted along with the old DnsCache trait)
struct RecordingCache {
    lookup: Mutex<CacheLookup>,
    lookups: Mutex<Vec<CacheLookupRequest>>,
    stores: Mutex<Vec<CacheStore>>,
}
impl DnsCache for RecordingCache {
    fn lookup<'a>(&'a self, request: &'a CacheLookupRequest) -> BoxFuture<'a, CacheLookup> { ... }
    fn store<'a>(&'a self, entry: CacheStore) -> BoxFuture<'a, ()> { ... }
}
```

Rewrite it against the new trait:

```rust
struct RecordingCache {
    chain_lookup: Mutex<ChainLookup>,
    lookups: Mutex<Vec<(String, u16, u16)>>,       // (qname, qtype, qclass) actually looked up
    stores: Mutex<Vec<DecomposedResponse>>,
}

impl RecordingCache {
    fn with_lookup(chain_lookup: ChainLookup) -> Self {
        Self {
            chain_lookup: Mutex::new(chain_lookup),
            lookups: Mutex::new(Vec::new()),
            stores: Mutex::new(Vec::new()),
        }
    }
}

impl DomainDnsCache for RecordingCache {
    fn lookup_chain(&self, qname: &str, qtype: u16, qclass: u16, _namespace: &str, _now: SystemTime) -> ChainLookup {
        self.lookups.lock().unwrap().push((qname.to_string(), qtype, qclass));
        self.chain_lookup.lock().unwrap().clone()
    }
    fn store_response(&self, decomposed: DecomposedResponse, _namespace: &str) {
        self.stores.lock().unwrap().push(decomposed);
    }
    fn sweep_stale_namespace(&self, _current_namespace: &str) {}
    fn domain_count(&self) -> usize { 0 }
    fn capacity(&self) -> usize { 0 }
}
```

`ChainLookup` needs `#[derive(Clone)]` (or a hand-rolled `Clone` impl) for
`with_lookup`'s stored value to be re-returned on every call — check
whether section-06 already derived `Clone` on it and on
`ResolvedAnswer`/`ResolvedNegative`/`RRsetEntry`/`NegativeEntry`; if not,
add it there rather than working around its absence here (this is exactly
the kind of small missing-derive gap section-06 would have hit first if
its own tests needed cloning `ChainLookup`, so check before assuming it's
missing).

Mechanical rename at every call site: `RecordingCache::with_lookup(CacheLookup::Miss)`
becomes `RecordingCache::with_lookup(ChainLookup::Miss)` — a pure
find-and-replace for the ~20 call sites that only ever construct `Miss`.
`.stores.lock().unwrap().len()`/`.is_empty()` assertions (most of the
remaining call sites) need no further changes beyond the type rename.

The handful of call sites that construct `CacheLookup::Hit(cached)` from
a hand-built `CachedResponse` (two of them — see the disposition table's
`resolve_truncates_oversized_cached_response_for_current_request` and
`resolve_treats_expired_cache_backend_hit_as_miss` entries below) need
real rewrites, not renames, since there's no more flat
`response_template` byte blob to hand-build — they must construct a
`ChainLookup::Answered(ResolvedAnswer { chain: vec![(name, RRsetEntry {
.. })] })` (or `ChainLookup::NxDomain`/`NoData(ResolvedNegative { .. })`
for negative cases) with real record data instead. These two are handled
explicitly in Part 4 below, not as a mechanical rename.

The handful of call sites that inspect `stores[0].<field>` in detail
(`resolve_stores_upstream_response_as_neutral_id_template`,
`resolve_records_negative_cache_store_metrics`, and any other test
asserting on stored fields — grep for `stores\[0\]` and
`stores.lock()` followed by field access, not just `.len()`/`.is_empty()`)
need their assertions rewritten against `DecomposedResponse`'s shape
(`positive: Vec<(String, u16, u16, RRsetEntry)>`, `negative: Option<(String,
NegativeEntry)>`) instead of `CacheStore`'s (`key.question`,
`response_template`, `response_code`, `ttl`, `negative_cache`). For
example, `resolve_stores_upstream_response_as_neutral_id_template`'s
`assert_eq!(stores[0].key.question, QuestionKey::new("example.com", 1, 1))`
becomes an assertion on `stores[0].positive[0].0 == "example.com"` (and
`.1`/`.2` for qtype/qclass); its `assert_eq!(&stores[0].response_template[0..2],
&[0, 0])` (proving the stored template has a neutral transaction ID) has
no equivalent to port forward — the whole point of assembly moving to
serve time is that nothing byte-level is stored anymore, so drop that
specific assertion and instead assert on the *record data* actually
present in `stores[0].positive[0].3.records`. `resolve_records_negative_cache_store_metrics`'s
`stores[0].response_code`/`stores[0].negative_cache` assertions become
assertions against `stores[0].negative.as_ref().unwrap().1` (the stored
`NegativeEntry`)'s `kind`/`soa_record` fields.

### `OwnedOnlyProtocolCodec` (originally `mod.rs:8156-8214`)

Section-07 removed `serialize_cached_response` from the `ProtocolCodec`
trait. If section-07 didn't already delete the corresponding
`fn serialize_cached_response(...)` override on this test double (it was
left as an optional judgment call for section-07), delete it here — it's
a pure `impl ProtocolCodec for OwnedOnlyProtocolCodec` block trimming one
now-nonexistent trait method, no other change needed. Everything else on
this double (`decode_query`/`decode_query_owned`/
`configured_max_udp_payload_size`/`rewrite_response_id` tracking) is
unaffected by this rework and needs no changes.

## Part 3 — Test disposition table

All line numbers are from the pre-rework `src/resolver/mod.rs` (they will
have shifted by the time this section starts, since sections 01-07 make
their own edits first — use them to *locate* the tests via search, not as
literal offsets).

### Cluster A: dedicated `InMemoryDnsCache`/`CacheKey` unit tests (`mod.rs:12076-12352`)

All of these construct `InMemoryDnsCache` directly or call
`CacheKey::from_query` directly — both types no longer exist after Part
1/section-07. **Delete every test in this cluster**; none are rewritten
in `mod.rs` because their intent is already covered by lower-level unit
tests in sections 01-06's own files:

| Test | Superseded by |
|---|---|
| `cache_capacity_returns_configured_max_entries` | `cache_config_*` tests (section-01) plus every resolve-level test that constructs `ShardedDnsCache` from a `CacheConfig` |
| `in_memory_cache_returns_unexpired_entry` | `resolve_from_cache`'s own unit tests (section-06) plus resolve-level cache-hit tests |
| `in_memory_cache_expires_entries_on_lookup` | `resolve_from_cache_treats_expired_entry_as_miss` (section-06) + this section's `resolve_treats_expired_cache_backend_hit_as_miss` rewrite (Part 4) |
| `in_memory_cache_evicts_least_recently_used_entry_when_bounded` | `lru_peek_oldest_returns_least_recently_touched_domain`, `evicting_a_domain_removes_both_positive_and_negative_data` (section-03) |
| `in_memory_cache_prunes_expired_entries_before_eviction` | section-03's eviction-loop tests (the new `ShardLru`/`Shard` design has no separate "prune expired before evicting" pass to test — eviction is O(log n) LRU-oldest-first, and expiry is checked independently on lookup, per section-06's inline namespace/expiry check) |
| `in_memory_cache_zero_capacity_stores_nothing` | `cache_config_zero_max_entries_gives_every_shard_zero_capacity` (section-01) |
| `in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits` | `lru_touch_moves_domain_to_most_recent_without_leaving_stale_positions` (section-03) — the ghost-token mechanism this test exercised no longer exists |
| `cache_key_from_query_includes_supported_semantics` | deleted deliberately (see below) |
| `cache_key_separates_question_type_class_and_policy` | qtype/qclass separation is now structural (`DomainRecordSets.record_sets: HashMap<(u16,u16), RRsetEntry>`, tested by `rrset_entry_stores_multiple_qtypes_under_one_domain`, section-02); namespace separation is tested by section-05's sweep tests |
| `cache_key_separates_exact_wire_question_casing_for_templates` | deleted deliberately, **replaced by the opposite assertion** — see below |
| `cache_key_separates_recursion_desired_header_flag` | RD is no longer a cache-key dimension at all; nothing to test at this layer (RD-flag-on-hit correctness is `resolve_rewrites_rd_flag_for_current_request_on_cache_hit`, already written by section-07) |
| `cache_key_separates_dnssec_request_flags` | AD/CD/DO are no longer cache-key dimensions; their effect on assembly is covered by `assemble_response_includes_rrsigs_only_when_requester_sets_do`, `assemble_response_sets_ad_only_when_secure_and_requested`, `assemble_response_servfails_on_bogus_when_checking_enabled` (section-06) |

**Deliberate deletions, replaced with opposite-intent tests** (per plan
§11's explicit instruction — these two assert exactly the fragmentation
behavior Q9/Q13 remove): `cache_key_from_query_includes_supported_semantics`
and `cache_key_separates_exact_wire_question_casing_for_templates` are
deleted outright. Their replacements already exist by the time this
section starts — `single_flight_requests_differing_only_in_bufsize_or_casing_still_coalesce`
(section-04) and `assemble_response_echoes_requesters_own_casing`/
`assemble_response_truncates_per_requesters_own_bufsize` (section-06)
already assert the new, opposite behavior. This section does not need to
write new tests for this — just confirm (by reading section-04's and
section-06's test files) that they exist, and delete the old assertions
from `mod.rs` without replacement in-place.

### Cluster B: `SingleFlightMisses`-direct unit test (`mod.rs:14140-14162`)

`single_flight_leader_drop_wakes_followers_and_clears_key` constructs
`SingleFlightMisses::default()` and drives `SingleFlightTicket`/
`SingleFlightLeader` directly (the pre-rework, non-sharded types) — these
are retired by section-04 in favor of `ShardedSingleFlight`. **Delete**
this test from `mod.rs`; section-04's TDD list already includes a test of
the identical name (`single_flight_leader_drop_wakes_followers_and_clears_key`)
written directly against `ShardedSingleFlight` in
`cache/singleflight.rs` — confirm it exists there rather than writing a
new one here.

### Cluster C: resolve()-level integration tests already handled by section-07

These were already rewritten (new names, new bodies) as part of
section-07's own "tests to write first," per that section's `## Tests to
write first`. **Do not rewrite them again here** — just delete their
pre-rework counterparts from `mod.rs` if section-07 didn't already
replace them in place, and confirm the new versions exist and pass:

| Old test (deleted) | New test (already written by section-07) |
|---|---|
| `resolve_returns_cached_template_with_current_request_id` | `resolve_returns_assembled_response_for_current_request_id` |
| `resolve_rewrites_cached_response_rd_flag_for_current_request` | `resolve_rewrites_rd_flag_for_current_request_on_cache_hit` |
| `resolve_blocks_cached_response_with_malicious_cname_target` | same name, new body |
| `resolve_blocks_coalesced_cache_hit_with_malicious_cname_target` | same name, new body |
| `backend_generation_separates_cache_entries` | `backend_reload_sweep_invalidates_stale_generation_entries` |
| (n/a — new metrics coverage) | `open_telemetry_cache_gauges_report_approximate_domain_count` |
| (n/a — `tests/recursive_perf.rs` fix) | `recursive_perf_bench_constructs_sharded_cache` |

### Cluster D: resolve()-level integration tests this section must rewrite

These are named in `claude-plan.md` §11's "rewrite, same intent" list but
were **not** part of section-07's list — this section writes their
replacements (same test names are fine; only the setup/plumbing and,
where noted, the assertion shape change):

- `resolve_ages_cached_response_ttls_for_current_request_time`
- `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime`
- `resolve_truncates_oversized_cached_response_for_current_request`
- `resolve_treats_expired_cache_backend_hit_as_miss`
- `resolve_coalesces_duplicate_cache_misses`

See Part 4 below for what changes in each.

### Cluster E: mechanical-only migrations (no behavioral change)

Every other test that constructs `Arc::new(InMemoryDnsCache::new(N))` or
`Arc::new(RecordingCache::with_lookup(CacheLookup::Miss))` purely as inert
plumbing (malicious-domain-policy tests unrelated to the two already
covered above, backend-selection tests, metrics-recording tests,
TCP/UDP-cache-sharing tests like `resolve_shares_cache_entry_between_udp_and_tcp_queries`,
etc.) needs only the constructor swapped:

```rust
// Before
Arc::new(InMemoryDnsCache::new(16))
// After
Arc::new(ShardedDnsCache::new(&CacheConfig { max_entries: 16, shard_count: None }))
```

```rust
// Before
Arc::new(RecordingCache::with_lookup(CacheLookup::Miss))
// After
Arc::new(RecordingCache::with_lookup(ChainLookup::Miss))
```

Grep for `InMemoryDnsCache::new(` and `CacheLookup::Miss` across the test
module to find every remaining site; none of them need their assertions
touched — only the construction line. `resolve_service_with_cache`'s own
parameter type (`cache: Arc<dyn DnsCache>` → `Arc<dyn DomainDnsCache>`,
originally `mod.rs:8397-8414`) should already have been updated by
section-07 (it's listed among that section's "wide, shallow diff"
signature changes) — if it wasn't, fix it here; every call site
threading a cache through this helper depends on its parameter type
matching.

## Part 4 — Rewriting Cluster D's tests

All five reuse the existing `resolve_service_with_cache` helper and a
**real** `ShardedDnsCache` (not `RecordingCache`) so the test exercises
the actual store-then-hit path through `cache_store_for_response` →
`resolve_from_cache` → `assemble_response`, the same pattern the
pre-rework tests used via `InMemoryDnsCache::new(16)` + `store_now`, or
via two live `resolve()` calls (miss-then-populate, then hit).

- **`resolve_ages_cached_response_ttls_for_current_request_time`** and
  **`resolve_caps_cached_response_ttls_to_remaining_cache_lifetime`**:
  the pre-rework versions pre-populated the cache directly via
  `cache.store_now(CacheStore { key: CacheKey::from_query(...), .. })`
  (bypassing a live store) then issued one `resolve()` call at a later
  simulated time and asserted the returned answer's wire TTL. Since
  `store_now`/`CacheKey` no longer exist, prefer replacing the
  direct-store step with a real warming `resolve()` call against a
  `StaticUpstream`/`ScriptedAuthorityTransport` returning the desired
  answer at `stored_at`, followed by the assertion `resolve()` call at
  the later time — this is simpler than hand-building a `DecomposedResponse`
  and exercises the real store path as a side benefit. Assert on the
  parsed response's `answers[0].ttl`, exactly as the original tests did.
- **`resolve_truncates_oversized_cached_response_for_current_request`**:
  the pre-rework version used `RecordingCache::with_lookup(CacheLookup::Hit(cached))`
  with a hand-built oversized `CachedResponse`. Rewrite using a real
  `ShardedDnsCache` warmed via one `resolve()` call against an upstream
  response containing enough records to exceed the requester's UDP
  bufsize (mirror `oversized_response`'s padding trick, or use enough
  real answer records), then a second `resolve()` call with a small
  `max_udp_payload_size` and assert the second response is truncated
  (question-only, TC bit set, `ResolveDecisionKind::CacheHit`,
  `ResolverMetric::CacheResponseTruncated` incremented) exactly as
  before. Alternatively, if constructing a `ResolvedAnswer`/`RRsetEntry`
  by hand via `RecordingCache::with_lookup(ChainLookup::Answered(...))`
  is more direct for this particular test (no need to drive it through a
  real backend), that's an acceptable equivalent — either approach
  proves the same observable contract.
- **`resolve_treats_expired_cache_backend_hit_as_miss`**: same shape as
  the truncation test — the pre-rework version mocked a `CachedResponse`
  with `expires_at` in the past via `RecordingCache`. Rewrite either via
  a real warming `resolve()` call at an early `stored_at` followed by an
  assertion `resolve()` call after `expires_at` has passed (assert the
  upstream is queried again, i.e. not served stale data — mirrors the
  original's intent precisely), or via `RecordingCache::with_lookup(ChainLookup::Miss)`-equivalent
  reasoning is not applicable here since expiry-as-miss is exactly what's
  being tested — use the real-cache warming approach.
- **`resolve_coalesces_duplicate_cache_misses`**: the pre-rework version
  drove N concurrent `resolve()` calls for the same query through a
  `RecordingCache` returning `CacheLookup::Miss` and a slow/blocking
  upstream, asserting only one upstream request was made. Rewrite with
  `ChainLookup::Miss` in place of `CacheLookup::Miss` and a real
  `ShardedSingleFlight`-backed `ResolveQuery` (i.e. just the mechanical
  rename from Cluster E, since `RecordingCache::with_lookup(ChainLookup::Miss)`
  is sufficient plumbing here — the actual coalescing logic under test
  lives in `ResolveQuery`'s `miss_coalescer`, already rewired by
  section-07). Confirm the assertion (`upstream.requests.lock().unwrap().len() == 1`
  or equivalent) still holds unchanged.

## Part 5 — New concurrency benchmark (closes G8)

Per interview Q10 and `claude-plan.md` §11 / `claude-plan-tdd.md` §11:
today, nothing exercises the cache under real concurrent load —
`tests/recursive_perf.rs` runs sequentially (`--test-threads=1`,
`#[ignore]`d) and measures end-to-end resolve latency through a scripted
backend, not raw cache throughput/contention. This section adds a new,
dedicated benchmark.

**Recommended location**: a new file, `tests/cache_concurrency_bench.rs`,
following `tests/recursive_perf.rs`'s existing conventions (`#[ignore]`d,
run via `just bench`, not part of default `cargo test`) rather than
extending `recursive_perf.rs` itself — the workload here is direct
cache lookups/stores across many threads, not full DNS resolution through
a backend, so it doesn't fit that file's `resolver_with_cache`/
`ScriptedAuthorityTransport` harness naturally.

- `concurrent_cache_access_across_shards_scales_with_thread_count` (name
  from `claude-plan-tdd.md` §11, or similarly named) — `#[ignore]`d:
  spawn multiple threads (e.g. 1, 2, 4, 8 — implementer's choice of
  sweep) issuing a mixed workload of `lookup_chain`/`store_response`
  calls against a shared `Arc<ShardedDnsCache>`, across a set of domain
  names chosen to span multiple shards (mix of names that hash to the
  same shard and names that don't — use `shard_index` directly, from
  section-01, to construct the mix deliberately rather than relying on
  chance). Measure total wall-clock time for a fixed total operation
  count at each thread count and assert throughput does not degrade
  linearly with thread count the way a single-global-mutex baseline
  would (e.g. assert wall-clock time at 8 threads is not >> wall-clock
  time at 1 thread scaled by contention, or print a table for manual
  inspection via `--nocapture` — exact pass/fail threshold is the
  implementer's call, since absolute numbers are environment-dependent;
  the important property is *not scaling linearly worse* with thread
  count, not hitting one specific number).
- **Before/after baseline**: per `claude-plan-tdd.md` §11, "a before/after
  comparison against the *old* `InMemoryDnsCache` ... is the most direct
  way to demonstrate the improvement goal 1 was for," but is explicitly
  **not required to be kept running in CI long-term**. Since Part 1 of
  this section deletes `InMemoryDnsCache` entirely (and plan §12 / Q14
  rules out dual-running old and new implementations permanently), do
  this comparison as a one-time manual step **before** deleting
  `InMemoryDnsCache`: run the new benchmark's workload against a
  temporarily-reinstated `InMemoryDnsCache` (e.g. from the commit just
  before this section's Part 1 deletion, or a scratch local branch),
  capture the numbers, and record them in the PR description / commit
  message for this section. The committed end state of this section
  contains only the new `ShardedDnsCache` benchmark, not a permanently
  dual-implementation test.
- Update the `justfile`'s `bench` recipe (`bench: cargo test --locked
  --release --test recursive_perf -- --ignored --nocapture
  --test-threads=1`) to also run the new test file — either widen it to
  `--test recursive_perf --test cache_concurrency_bench`, or add a
  second recipe (e.g. `bench-cache`) following the same pattern. Either
  is acceptable; keep `just bench`'s existing behavior for
  `recursive_perf` unchanged either way.

## File paths touched by this section

- `src/resolver/mod.rs` — deletes `InMemoryDnsCache` and its supporting
  types/impls (production code, Part 1), deletes `LRU_COMPACTION_MULTIPLIER`
  and `lru_compaction_threshold`, rewrites `RecordingCache` and
  `OwnedOnlyProtocolCodec` (Part 2), deletes Cluster A/B tests, deletes
  Cluster C's pre-rework counterparts, rewrites Cluster D's five tests,
  and does mechanical constructor swaps across Cluster E's remaining call
  sites. Deletes the `cache_key`/`cache_store_at` test helper functions.
- `tests/cache_concurrency_bench.rs` (new file) — the concurrency
  benchmark (Part 5).
- `justfile` — updates or adds a `bench`-family recipe to run the new
  benchmark file.

## Notes for the implementer

- This section is almost entirely deletion and mechanical renaming, not
  new logic — the genuinely new code (`ShardedDnsCache`,
  `assemble_response`, `resolve_from_cache`, `ShardedSingleFlight`,
  `sweep_stale_namespace`) was all written and tested in sections 01-07.
  Resist the urge to "improve" any of that code from here; this section's
  job is exclusively to get the test suite green again.
- `CacheTtlPolicy::ttl_for_response` and its own dedicated unit tests
  (`ttl_policy_preserves_negative_metadata_for_nxdomain_with_cname_answer`,
  `ttl_policy_preserves_negative_metadata_for_nodata_with_cname_answer`,
  `ttl_policy_preserves_negative_metadata_for_dnssec_signed_cname_nodata`,
  and their neighbors, `mod.rs:11577-11759` in the pre-rework file) are
  **unaffected by this entire rework** — they test `CacheTtlPolicy` and
  `NegativeCacheMetadata` directly, neither of which reference
  `CacheKey`/`CacheStore`/`CachedResponse`/`CacheLookup`/`InMemoryDnsCache`
  in any way. Leave them exactly as they are; if any of them fail to
  compile after this section's edits, that indicates an accidental
  scope overrun elsewhere in the diff, not a required change here.
- `NegativeCacheMetadata`, `negative_ttl`, `negative_covered_name`,
  `CacheTtlPolicy` itself, `QueryFeatures`, and `age_response_ttls`/
  `cap_response_ttls` (the free functions) all survive this rework
  unchanged, per plan §9.1 and section-07's own notes — do not delete or
  rename any of them while working through this section's edits.
- After Parts 1-4, run `cargo test --locked` on the whole crate before
  moving to Part 5 — get the existing suite fully green first, since the
  new benchmark is `#[ignore]`d and won't be caught by a normal `cargo
  test` run if something upstream of it is still broken.
- If, while doing Cluster E's mechanical sweep, you find a call site this
  document didn't anticipate (the exact count of `InMemoryDnsCache::new`/
  `CacheLookup::Miss` occurrences may have shifted slightly by the time
  sections 01-07 land their own edits), apply the same two patterns
  (constructor swap only, no assertion changes) rather than treating it
  as a new design decision — nothing in Cluster E requires judgment
  calls.

## Summary for the parent orchestrator

Files/paths most relevant to this task:
- `/home/rpmoore/code/rdns/docs/plans/cache_rework/sections/section-08-test-migration-and-benchmark.md` (written by this invocation)
- `/home/rpmoore/code/rdns/src/resolver/mod.rs` — the file this section edits almost exclusively (deleting `InMemoryDnsCache` at roughly `mod.rs:5322-5499` in the pre-rework file, the `#[cfg(test)] mod tests` block starting at `mod.rs:6533`, the `RecordingCache`/`OwnedOnlyProtocolCodec` doubles around `mod.rs:8156-8380`, and the ~23-test cache cluster around `mod.rs:12076-12352` plus the resolve-level integration tests scattered through `mod.rs:13700-14600`)
- `/home/rpmoore/code/rdns/tests/recursive_perf.rs` and `/home/rpmoore/code/rdns/justfile` — referenced for the new concurrency benchmark's conventions and recipe wiring
- Context read (not modified): `/home/rpmoore/code/rdns/docs/plans/cache_rework/claude-plan.md` §9-§12, `/home/rpmoore/code/rdns/docs/plans/cache_rework/claude-plan-tdd.md` §9 and §11, `/home/rpmoore/code/rdns/docs/plans/cache_rework/sections/index.md`, and the already-written `/home/rpmoore/code/rdns/docs/plans/cache_rework/sections/section-06-assembly-and-chains.md` and `section-07-call-site-migration.md` (to keep this section consistent with what they already committed to, e.g. `ChainLookup`/`ResolvedAnswer`/`ResolvedNegative` shapes and section-07's own "tests to write first" list, which this section explicitly does not duplicate)

No files outside the section-08 output were modified — this was a research-and-write task.