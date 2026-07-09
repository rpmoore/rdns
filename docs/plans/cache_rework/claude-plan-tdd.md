# TDD plan: Answer-cache rework

Companion to `claude-plan.md` — mirrors its section structure. Each
section lists the tests to write **before** implementing that section's
code. Testing context: this is an existing Rust codebase using the
built-in `#[test]` framework, one `#[cfg(test)] mod tests` block per file
(`claude-research.md` A.4), with descriptive snake_case test names stating
the behavior under test (e.g. `in_memory_cache_evicts_least_recently_used_entry_when_bounded`)
— follow that naming convention, not a comment-based one. Run via
`cargo test --locked` (CI) or `cargo test` locally; the new concurrency
benchmark follows `tests/recursive_perf.rs`'s existing pattern of an
`#[ignore]`d, `--test-threads=1` test invoked through `just bench`.

These are stubs — prose descriptions of what each test asserts, not test
code. The implementer writes the actual `#[test]` functions during
`deep-implement`.

## 3.1 Positive cache data model (`cache/entry.rs`)

- `rrset_entry_stores_multiple_qtypes_under_one_domain` — two `RRsetEntry`
  values (e.g. A and AAAA) inserted for the same domain in
  `DomainRecordSets.record_sets` coexist independently; neither insert
  evicts or overwrites the other.
- `rrset_entry_dnssec_state_defaults_to_unvalidated` — a freshly
  constructed `RRsetEntry` (via whatever constructor/store path is used)
  has `dnssec_state == DnssecState::Unvalidated` when no validation logic
  has run, matching `DnssecValidationMode::Disabled` being the only mode
  that exists (`claude-research.md` A.3).
- `stored_record_preserves_original_ttl_independent_of_entry_minimum_ttl`
  — construct an `RRsetEntry` from records with *different* individual
  TTLs; assert each `StoredRecord.ttl_at_store` still holds its own
  original value, distinct from `RRsetEntry.minimum_ttl` (the minimum
  across the set, used only for entry-level expiry per §7's TTL-handling
  clarification).

## 3.2 Negative cache data model (`cache/entry.rs`)

- `negative_entry_stores_soa_record_for_response_reconstruction` — a
  stored `NegativeEntry` retains a full `soa_record: StoredRecord` (owner
  name, RDATA, TTL), not just derived scalars — this is the fix for the
  Codex-review finding that the original shape couldn't rebuild an
  authority section.
- `negative_key_distinguishes_nxdomain_from_nodata_by_qtype_option` —
  `NegativeKey { qtype: None, .. }` (whole-name NXDOMAIN) and
  `NegativeKey { qtype: Some(t), .. }` (NODATA for type `t`) store as
  independent entries for the same domain and don't collide.
- `negative_entry_soa_rrsig_and_proof_records_default_empty_without_dnssec`
  — `soa_rrsig: None` and `proof_records: vec![]` when no DNSSEC data was
  fetched (matches disabled-DNSSEC baseline, same spirit as the
  `RRsetEntry` default-Unvalidated test above).

## 3.3 Shared shard for positive + negative (`cache/shard.rs`)

- `domain_with_only_negative_entry_still_counts_toward_shard_capacity` —
  a domain that has *only* a `NegativeEntry` (no positive record sets)
  still occupies one LRU/capacity slot in the shard, per the "capacity
  counts domains uniformly across positive and negative" decision (§3.3).
- `evicting_a_domain_removes_both_positive_and_negative_data` — when a
  domain is evicted (LRU pressure), both its `DomainRecordSets` entry (if
  present) and its `DomainNegativeEntries` entry (if present) are removed
  together, and its LRU token is cleared from `ShardLru`.

## 4. Exact per-shard LRU (`cache/lru.rs`)

- `lru_touch_moves_domain_to_most_recent_without_leaving_stale_positions`
  — touching a domain already tracked in `ShardLru.order` removes its old
  `(sequence, domain)` pair and inserts a new one; `order.len()` and
  `positions.len()` never exceed the number of distinct domains ever
  touched that are still live (the direct replacement for
  `in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits`, which tested
  the now-deleted ghost-token compaction threshold — this test instead
  asserts there is *never* more than one live position per domain, at any
  touch count).
- `lru_peek_oldest_returns_least_recently_touched_domain` — after touching
  domains in a known order, `peek_oldest()` returns the one touched least
  recently, exactly (not approximately).
- `lru_remove_clears_domain_from_both_order_and_positions` — removing a
  domain (e.g. on full eviction from the shard, or full removal by the
  namespace sweep) leaves no residual entry in either `order` or
  `positions` for it.
- `lru_touch_and_evict_cost_is_independent_of_shard_size` — property-style
  or count-based test asserting that a touch/evict does O(1) BTreeSet
  operations regardless of how many other domains are tracked (can be
  approximated by asserting a fixed, small number of tree operations via
  instrumentation, or accepted as implied by using `BTreeSet`/`HashMap`
  correctly rather than measured directly — implementer's call).

## 5. Bulk invalidation: namespace sweep (`cache/namespace.rs`)

- `sweep_removes_only_entries_from_stale_namespace` — a shard holding a
  mix of entries stored under an old namespace and entries stored under
  the current namespace: after `sweep_stale_namespace(current)`, only the
  stale ones are gone; current-namespace entries and their LRU positions
  are untouched.
- `sweep_removes_domain_entirely_when_all_its_record_sets_are_stale` — a
  domain whose *every* `RRsetEntry` (and negative entry, if present) is
  under the stale namespace is fully removed from `positive`/`negative`
  maps and from `ShardLru`, not left behind as an empty shell.
- `sweep_keeps_domain_partially_when_some_record_sets_are_current` — a
  domain with one stale-namespace `RRsetEntry` and one current-namespace
  `RRsetEntry`: after sweep, only the stale one is gone; the domain entry
  and its LRU position survive (this is the case that makes the sweep
  O(entries), not O(domains) — see the Codex-review fix in §5).
- `sweep_across_shards_does_not_require_a_shared_lock` — (concurrency
  test) sweeping multiple shards concurrently from separate tasks/threads
  completes correctly and doesn't deadlock; each shard's sweep only takes
  that shard's own lock.

## 6. Sharded single-flight (`cache/singleflight.rs`)

Existing behavioral guarantees to preserve, ported to the new
`(name, qtype, qclass)` key and per-shard structure — mirror these
directly from the current tests (`docs/caching.md` §6,
`claude-research.md` A.1):
- `single_flight_coalesces_concurrent_misses_for_same_name_and_qtype` —
  replacement for `resolve_coalesces_duplicate_cache_misses`; N concurrent
  lookups for the same `(name, qtype, qclass)` produce exactly one leader
  and N-1 followers, one upstream fetch total.
- `single_flight_requests_differing_only_in_bufsize_or_casing_still_coalesce`
  — new test validating the Q5/Q9/Q13 coarsening: two requests for the
  same name+qtype but different EDNS bufsize or casing now share one
  in-flight fetch (they wouldn't have under the old flat-key coalescing).
- `single_flight_leader_drop_wakes_followers_and_clears_key` — direct port
  of the existing test of the same name; leader task panicking/being
  cancelled still wakes followers with an error, and clears the shard's
  `flights` entry for that key.
- `single_flight_different_shards_do_not_contend` — (concurrency test)
  in-flight misses for names hashing to different shards proceed
  independently; one shard's lock being held doesn't block another
  shard's `begin()`/`finish()`.

## 7. Response assembly at serve time (`cache/assemble.rs`)

- `assemble_response_ages_each_record_ttl_independently` — replacement for
  the TTL-aging behavior of `resolve_ages_cached_response_ttls_for_current_request_time`:
  build an `RRsetEntry` from records with different original TTLs, assemble
  after simulated elapsed time, assert each record's wire TTL reflects its
  *own* aging, not a shared/collapsed value (the §7 TTL-handling fix).
- `assemble_response_caps_ttl_to_remaining_entry_lifetime` — replacement
  for `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime`;
  assembled TTLs never exceed what's left of the entry's `expires_at`.
- `assemble_response_echoes_requesters_own_casing` — two lookups for the
  same normalized domain with different requester-supplied casing
  (`example.com` vs `Example.COM`) both hit the *same* underlying
  `RRsetEntry`, and each assembled response echoes back its own
  requester's casing (replacement for the now-deleted
  `cache_key_separates_exact_wire_question_casing_for_templates`, which
  asserted the opposite of the new intended behavior).
- `assemble_response_truncates_per_requesters_own_bufsize` — replacement
  for `resolve_truncates_oversized_cached_response_for_current_request`;
  one shared `RRsetEntry` assembled for two requesters advertising
  different EDNS bufsizes/transports (UDP vs TCP) produces correctly
  truncated vs. full responses per requester, from the same stored data.
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
- `resolve_from_cache_treats_expired_entry_as_miss` — replacement for
  `resolve_treats_expired_cache_backend_hit_as_miss`; a lookup against an
  `RRsetEntry`/`NegativeEntry` whose `expires_at <= now` returns a miss
  variant, not stale data.

## 7.1 CNAME chain walking (`cache/assemble.rs`)

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
  pathologically long (or cyclical) cached CNAME chain is cut off at the
  existing `max_cname_restarts` config bound rather than looping
  indefinitely.
- `resolve_from_cache_returns_miss_on_any_missing_chain_hop` — if any name
  in the chain is absent, expired, or under a stale namespace, the whole
  chain lookup returns `ChainLookup::Miss` (caller falls back to backend
  resolution) rather than a partial answer.
- `store_response_persists_cname_hop_and_terminal_negative_together` —
  storing a backend response that is a CNAME chain ending in NODATA
  creates *both* the CNAME `RRsetEntry`/`RRsetEntry`s along the chain
  *and* a `NegativeEntry` for the terminal name (the §9/Codex-review fix
  replacing the old "or" wording) — assert both are independently
  retrievable afterward.

## 8. Configuration (`src/config`)

- `cache_config_defaults_preserve_current_max_entries` — an unconfigured
  `CacheConfig` yields `max_entries == 10_000`, matching today's
  `DEFAULT_CACHE_ENTRIES` behavior for anyone not setting it explicitly.
- `cache_config_shard_capacity_sums_exactly_to_max_entries` — for a range
  of `(max_entries, shard_count)` pairs, including non-evenly-divisible
  ones (e.g. `max_entries=10, shard_count=8`), the sum of all per-shard
  capacities equals `max_entries` exactly, not an overshoot (the Codex-
  review capacity-math fix, §8).
- `cache_config_zero_max_entries_gives_every_shard_zero_capacity` —
  `max_entries == 0` results in every shard's capacity being 0, and
  storing anything is a no-op (preserves
  `in_memory_cache_zero_capacity_stores_nothing`'s intent).
- `cache_config_shard_count_defaults_to_power_of_two_near_parallelism` —
  when `shard_count` is `None`, the computed default is a power of two,
  roughly proportional to `available_parallelism()` (exact formula per
  §8/Q11 — implementer's default, test asserts the power-of-two property
  and a sane range rather than one exact number, since parallelism is
  environment-dependent).

## 9. Call-site integration tests

These exercise the cache through the resolver's public `resolve()` path,
mirroring the existing integration tests in `claude-research.md` A.4:

- `resolve_returns_assembled_response_for_current_request_id` —
  replacement for `resolve_returns_cached_template_with_current_request_id`;
  a cache hit's assembled response carries the *current* request's
  transaction ID, not a stale/reused one.
- `resolve_rewrites_rd_flag_for_current_request_on_cache_hit` — port of
  `resolve_rewrites_cached_response_rd_flag_for_current_request` against
  the new assembly path.
- `resolve_blocks_cached_response_with_malicious_cname_target` and
  `resolve_blocks_coalesced_cache_hit_with_malicious_cname_target` — direct
  ports; malicious-CNAME-target blocking must still apply after response
  assembly moves to serve time (§9's stated invariant) — both the
  direct-hit and coalesced-miss paths.
- `backend_reload_sweep_invalidates_stale_generation_entries` —
  replacement for `backend_generation_separates_cache_entries`; after a
  simulated `publish_reload` with a changed `cache_namespace`, previously
  cached entries under the old namespace are actually gone (not just
  unreachable) — verifies `sweep_stale_namespace` is wired into the
  reload path, not just unit-tested in isolation (§5/§9).
- `open_telemetry_cache_gauges_report_approximate_domain_count` — the
  `main.rs` metrics construction (§9's `OpenTelemetryMetrics` entry)
  compiles against the new cache type and its gauge callback reads
  `domain_count()`/`capacity()` without holding a single global lock;
  assert the gauge's value is within the expected range under concurrent
  mutation (exact equality isn't guaranteed — this test should assert
  "plausible," not "exact," per the documented approximate-under-sharding
  tradeoff).
- `recursive_perf_bench_constructs_sharded_cache` — `tests/recursive_perf.rs`'s
  `resolver_with_cache` helper compiles and runs against the new cache
  type (the missed call site from the Codex review, §9).

## 11. New concurrency benchmark (closes G8)

Per interview Q10 and `claude-plan.md` §11's testing strategy — a new
test, not a port of an existing one:

- `concurrent_cache_access_across_shards_scales_with_thread_count` (or
  similarly named, `#[ignore]`d per `tests/recursive_perf.rs` convention,
  run via `just bench`) — spawn multiple threads issuing a mixed
  workload of lookups and stores across a set of domain names chosen to
  span multiple shards (some colliding, some not), measure total
  wall-clock time for a fixed operation count, and assert it does not
  degrade linearly with thread count the way a single-global-mutex
  baseline would (a before/after comparison against the *old*
  `InMemoryDnsCache`, captured once during this rework and not
  necessarily kept running in CI long-term, is the most direct way to
  demonstrate the improvement goal 1 was for).
