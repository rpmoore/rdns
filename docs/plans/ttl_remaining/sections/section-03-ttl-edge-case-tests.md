Now writing the final section content.

# section-03-ttl-edge-case-tests

## Scope

Add the two previously-uncovered TTL-remaining-on-read regression tests
identified during the cache-TTL audit (`docs/plans/ttl_remaining/claude-plan.md`
Part C):

1. **C.1** — a unit test in `src/resolver/cache/assemble.rs` proving
   `compute_wire_ttl` never lets the served (aged) TTL exceed a record's own
   origin TTL, even when the entry's `expires_at` has been extended past that
   origin TTL by a `min_positive_ttl` floor.
2. **C.2** — an e2e test in `src/resolver/mod.rs` proving the chain-wide
   `expires_at` ceiling computed when a CNAME chain is stored applies to the
   terminal record even when that terminal name is looked up *again*,
   independently, later — not just when re-resolving the whole chain.

**This section is test-only.** No production code changes. Both tests must
pass against the current, unmodified `compute_wire_ttl` / store logic — they
document and pin down existing, correct behavior, per the plan's explicit
"decision: current behavior is correct, document via test, do not change
logic" resolution for both edge cases (Q8, Q9 in the plan's interview notes).

This section has no dependencies on `section-01-knowledge-bundle-docs` or
`section-02-clock-dependency-injection` and can be implemented fully in
isolation, in parallel with them.

## Background: what `compute_wire_ttl` does (unchanged, for reference only)

`compute_wire_ttl` (`src/resolver/cache/assemble.rs:188-204`) is the single
function that computes the TTL value written onto every cache-hit answer,
RRSIG, SOA, and NSEC/NSEC3 proof record:

```rust
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
```

- `aged = ttl_at_store - elapsed_since(stored_at)` — the record's own origin
  TTL, decremented by how long it's actually been sitting in the cache.
- `remaining = expires_at - now` — how much longer the cache entry itself is
  allowed to live under this resolver's TTL policy.
- Final wire TTL = `min(aged, remaining)`.

It's called once per record from `write_rrset` (`assemble.rs:229-263`,
positive answers) and `write_negative_authority` (`assemble.rs:265-324`, SOA
+ its RRSIG + each DNSSEC proof record).

For CNAME chains, `expires_at` is computed **once per stored response**, not
per hop: `decompose_response_for_store` (`src/resolver/mod.rs:828-909`)
receives a single `ttl: Duration` (already the chain-wide minimum origin TTL,
computed once by `CacheTtlPolicy::ttl_for_response`, `mod.rs:638`) and passes
that same `ttl` value into `build_rrset_entry` (`mod.rs:1022-1047`) for
*every* hop, including the terminal one:

```rust
RRsetEntry {
    records: ...,
    rrsigs: ...,
    response_code: ResponseCode::NoError,
    minimum_ttl: ttl,
    stored_at,
    expires_at: stored_at + ttl,   // <-- same `ttl` for every hop in the chain
    ...
}
```

Each hop's own `StoredRecord::ttl_at_store` still holds its own real origin
TTL (e.g. the terminal record's 3600s) — only `expires_at` (the ceiling) is
shared chain-wide. This is intentional: see the doc comment at
`assemble.rs:181-187` (a CNAME chain combines records from multiple
`RRsetEntry`s with different `stored_at` values, so a single scalar `age`
applied to an assembled buffer can't represent it correctly — hence
per-record aging via `compute_wire_ttl`). The practical effect under test:
if a terminal record with a long origin TTL was first stored as part of a
chain whose shortest hop had a short TTL, that terminal record's
`RRsetEntry.expires_at` is capped by the *chain's* minimum, not its own TTL —
and that capped `expires_at` persists in the cache for any later, independent
lookup of that terminal name, because the terminal name's `RRsetEntry` is
stored under its own key (`(name, qtype, qclass)`) exactly like the
intermediate CNAME hop's entry is stored under its own key. There is no
separate re-derivation of `expires_at` on lookup.

## Test C.1 — zero/near-zero origin TTL vs. `min_positive_ttl` floor

**File:** `src/resolver/cache/assemble.rs` (add to the `#[cfg(test)] mod
tests` block, near the existing `assemble_response_ages_each_record_ttl_independently`
/ `assemble_response_caps_ttl_to_remaining_entry_lifetime` tests, currently at
lines 754-793).

**Invariant under test:** even when an entry's `expires_at` has been pushed
out past what a record's own origin TTL would justify (e.g. by a
`min_positive_ttl` floor configured on `CacheTtlPolicy` — not exercised
directly by this unit test, just its *effect* on the stored fixture), the
wire TTL `compute_wire_ttl` returns can never exceed what the record's own
`ttl_at_store`, aged by elapsed time, implies. `aged` from `ttl_at_store=0`
(or `1`) hits zero almost immediately and stays there — `remaining` (from the
extended `expires_at`) never gets to "win" and inflate the served TTL back
up, because the final value is `min(aged, remaining)`, and `aged` is already
the smaller side once time has elapsed even slightly.

### Fixture helpers already available in this test module

Reuse the existing helpers rather than inventing new ones:

- `fn a_record(ttl: u32, octet: u8) -> StoredRecord` (`assemble.rs:718-725`)
  — builds an `A` `StoredRecord` with the given `ttl_at_store`.
- `fn rrset_entry(records: Vec<StoredRecord>, minimum_ttl: Duration, now: SystemTime) -> RRsetEntry`
  (`assemble.rs:727-744`) — builds an `RRsetEntry` with `stored_at: now`,
  `expires_at: now + minimum_ttl`. The test will need to override
  `expires_at` after calling this helper (same pattern the existing two
  capping tests already use — they mutate `entry.expires_at` directly after
  construction).
- `fn features(dnssec_ok: bool) -> QueryFeatures` (`assemble.rs:708-716`).
- `fn question_wire(qname: &str, qtype: u16, qclass: u16) -> Vec<u8>`
  (around `assemble.rs:698-706`).
- `assemble_response(id, wire, features, resolved, now, is_udp, max_udp_payload_size) -> Vec<u8>`
  — the function under test, called via `ResolvedAnswer { chain: vec![(name, entry)] }`.
- `Message::parse(&response_bytes)` to inspect the assembled wire TTL.

### Test stub

```rust
#[test]
fn compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime() {
    // Origin TTL is 0 (or 1) — a record that "should" expire almost
    // immediately by its own TTL.
    let now = SystemTime::now();
    let stored_at = now - Duration::from_secs(5);
    let mut entry = rrset_entry(
        vec![a_record(0, 1)], // ttl_at_store = 0
        Duration::from_secs(30), // pretend min_positive_ttl floor
        stored_at,
    );
    // Simulate the min_positive_ttl floor extending this entry's actual
    // cache lifetime to 30s, far past what the origin TTL of 0 implies.
    entry.expires_at = stored_at + Duration::from_secs(30);
    let resolved = ResolvedAnswer {
        chain: vec![("example.com".to_string(), entry)],
    };
    let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);

    let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
    let parsed = Message::parse(&response).unwrap();

    // Even though the entry is still servable for ~25 more seconds
    // (floored expires_at), the wire TTL must reflect the record's own
    // origin TTL of 0, aged — never the entry's floor-extended remaining
    // lifetime.
    assert_eq!(parsed.answers[0].ttl, 0);
}
```

Adjust the exact numbers as needed, but the essential shape must hold:
`ttl_at_store` near 0, `expires_at` deliberately set later than
`stored_at + Duration::from_secs(ttl_at_store)` (simulating a floor), and the
assertion that the served TTL is `0` (or very close to it) for the entire
floored lifetime of the entry — i.e., sample at more than one `now` value
within that floored window if you want extra confidence, though a single
assertion satisfies the plan's requirement.

**Do not modify** `compute_wire_ttl` or any floor/`min_positive_ttl` logic —
this test must pass unmodified against current code.

## Test C.2 — chain-wide `expires_at` ceiling vs. per-hop origin TTL

**File:** `src/resolver/mod.rs` (add to the `#[cfg(test)] mod tests` block,
alongside `resolve_ages_cached_response_ttls_for_current_request_time` /
`resolve_caps_cached_response_ttls_to_remaining_cache_lifetime`, currently at
`mod.rs:16287-16365`).

**Invariant under test:** when a CNAME chain is stored with a short-TTL
intermediate hop and a long-TTL terminal record, the terminal record's
`RRsetEntry.expires_at` is capped to the chain-wide minimum at store time (as
described in Background above). A *second, independent* query — for the
terminal name directly, not by re-resolving the alias — must still see that
capped `expires_at`, proving the ceiling isn't something re-derived per
lookup from the terminal record's own TTL, but a persisted property of how
the entry was stored.

### Fixture helpers already available in this test module

- `fn a_record(name: &str, ttl: u32) -> Record` (`mod.rs:13280`).
- `fn cname_record(name: &str, ttl: u32, target: &str) -> Record` (`mod.rs:13338`).
- `fn seed_rrset_entry(record: &Record, ttl: Duration, now: SystemTime, epoch: u64) -> RRsetEntry`
  (`mod.rs:15897-15910`) — builds an `RRsetEntry` with `stored_at: now`,
  `expires_at: now + ttl`. **For this test, do not pass each hop's own TTL as
  the `ttl` argument** — pass the *same*, chain-wide-minimum `Duration` for
  both the intermediate and terminal hop's `seed_rrset_entry` calls (this is
  what mirrors production `decompose_response_for_store`/`build_rrset_entry`
  behavior — see Background above — where one shared `ttl` becomes every
  hop's `expires_at`, while each hop's `StoredRecord.ttl_at_store` still
  keeps its own origin TTL from the `Record` passed in).
- `fn a_query(id: u16, name: &str) -> Vec<u8>` (`mod.rs:7845-7847`).
- `fn resolve_service_with_cache(upstream, cache, events, metrics, max_udp_payload_size) -> ResolveQuery`
  (`mod.rs:9814-9831`) — wires a `ResolveQuery` with `FixedClock(SystemTime::UNIX_EPOCH)`,
  default `CacheTtlPolicy`, `StandardProtocolCodec`, `BasicResponseFactory`.
- `ShardedDnsCache::new(&CacheConfig { max_entries, shard_count })` +
  `cache.store_response(DecomposedResponse { positive: vec![...], negative: None }, epoch)`
  — same direct-population pattern the existing 16287-16365 tests and
  `resolve_blocks_cached_response_with_malicious_cname_target`
  (`mod.rs:15912-15970`, for the two-hop chain construction shape) already
  use.
- `A_RECORD_TYPE` (`mod.rs:81` area) and `CNAME_RECORD_TYPE` (`mod.rs:81`)
  constants for the `positive` tuple's rtype field.
- `StaticUpstream::new(Err(UpstreamError::Timeout))` — used by the existing
  e2e tests to guarantee any code path that isn't a cache hit fails loudly
  (confirms the assertion really exercises the cache-hit path, not an
  accidental backend fetch).
- `RecordingEvents::default()`, `RecordingMetrics::default()`.
- `Message::parse(&outcome.response_bytes)` to inspect the served TTL;
  `outcome.decision.kind == ResolveDecisionKind::CacheHit` to confirm no
  backend round trip occurred.

### Test stub

```rust
#[tokio::test]
async fn resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup() {
    let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
        max_entries: 16,
        shard_count: Some(1),
    }));
    let epoch = 0u64;
    let now = SystemTime::UNIX_EPOCH;

    // Chain-wide minimum origin TTL across the whole response is 60s (the
    // intermediate hop's TTL) — this becomes every hop's `expires_at`
    // ceiling, exactly as `decompose_response_for_store` computes it in
    // production (see Background).
    let chain_ceiling = Duration::from_secs(60);

    let cname = cname_record("alias.example.com", 60, "target.example.com");
    let terminal = a_record("target.example.com", 3600); // long origin TTL

    cache.store_response(
        DecomposedResponse {
            positive: vec![
                (
                    "alias.example.com".to_string(),
                    CNAME_RECORD_TYPE,
                    1,
                    seed_rrset_entry(&cname, chain_ceiling, now, epoch),
                ),
                (
                    "target.example.com".to_string(),
                    A_RECORD_TYPE,
                    1,
                    // Same chain-wide ceiling applied here, even though
                    // `terminal`'s own origin TTL is 3600 — mirrors
                    // production `build_rrset_entry`'s single shared `ttl`.
                    seed_rrset_entry(&terminal, chain_ceiling, now, epoch),
                ),
            ],
            negative: None,
        },
        epoch,
    );

    let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
    let events = Arc::new(RecordingEvents::default());
    let metrics = Arc::new(RecordingMetrics::default());
    let service = resolve_service_with_cache(upstream, cache, events, metrics, 1232);

    // Second, independent query: look up the terminal name directly,
    // NOT by re-resolving the alias.
    let outcome = service
        .resolve(ResolveRequest::new(
            "192.0.2.10".parse().unwrap(),
            now + Duration::from_secs(25),
            a_query(0x2222, "target.example.com"),
        ))
        .await;

    let parsed = Message::parse(&outcome.response_bytes).unwrap();
    // Aged TTL from the terminal record's own 3600s origin TTL would be
    // 3575 at t=25s — but the chain-wide ceiling (60s remaining lifetime,
    // 35s left at t=25s) must win: min(3575, 35) == 35.
    assert_eq!(parsed.answers[0].ttl, 35);
    assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
}
```

Adjust exact TTL/timing numbers as needed, but the essential shape must
hold: two hops stored as one chain with a shared (short) `expires_at`
ceiling and differing origin TTLs, followed by a *second, independent*
`resolve()` call for the terminal name alone, asserting the served TTL
reflects the chain ceiling (not the terminal record's own longer origin
TTL).

**Do not modify** `decompose_response_for_store`, `build_rrset_entry`, or
`compute_wire_ttl` — this test must pass unmodified against current code.

## Implementation Notes (actual)

Both tests were added exactly as specified, no deviations from the stubs
above beyond dropping the parenthetical "(or 1)"/"(or very close to it)"
hedges once concrete values were picked (`ttl_at_store=0`, assertion `== 0`).

- `compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime`
  added to `src/resolver/cache/assemble.rs`, immediately after
  `assemble_response_caps_ttl_to_remaining_entry_lifetime` (now ending around
  line 794), before `assemble_response_echoes_requesters_own_casing`.
- `resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup`
  added to `src/resolver/mod.rs`, immediately after
  `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime` (now ending
  around line 16365), before `resolve_truncates_oversized_cached_response_for_current_request`.

Code review (`docs/plans/ttl_remaining/implementation/code_review/section-03-review.md`)
flagged two non-blocking observations, both resolved as "no action" (see
`section-03-interview.md`):

1. The `entry.expires_at = ...` override in test C.1 is a no-op given the
   `rrset_entry` helper already sets that value — matches the same redundant
   pattern in the two pre-existing anchor tests it was modeled after.
2. Test C.2 populates the cache directly via `seed_rrset_entry`/
   `store_response` with a manually-shared `chain_ceiling`, rather than
   driving `decompose_response_for_store` end-to-end — this is the exact
   fixture pattern this section's spec prescribes, so it's in-scope, not a
   gap. A future e2e test driving a real CNAME chain response through
   `resolve()` could add full production-path coverage but is out of scope
   here.

`cargo fmt --check`, `cargo clippy --all-targets`, and `cargo test` (full
suite, 570+ lib tests plus integration suites) all pass, including both new
tests individually confirmed passing.

## Verification

Both tests are pure additions with no production code changes:

- `cargo fmt`, `cargo clippy`, `cargo test` must all pass (per `RUST.md` /
  root `AGENTS.md` gates).
- Both new tests must pass against the current, unmodified codebase (they
  assert existing behavior, not a change being introduced) — confirm each
  compiles and passes standalone (`cargo test compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime`,
  `cargo test resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup`).
- No `/security-review` needed (doc-only/test-only work per
  `docs/plans/ttl_remaining/claude-plan.md` Part D's PR-scope marker).
- No `docs/knowledge/` update is required from this section alone — the doc
  content describing these edge cases is `section-01-knowledge-bundle-docs`'s
  responsibility (`docs/plans/ttl_remaining/claude-plan.md` A.1 explicitly
  calls out "the zero/near-zero-origin-TTL-vs-floor behavior" and "the
  chain-wide-ceiling behavior" as things that section documents, referencing
  this section's tests as the now-closed evidence for them).