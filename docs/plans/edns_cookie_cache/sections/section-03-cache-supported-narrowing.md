# Section 03 — `cache_supported()` narrowing + regression test repointing

## Implementation status: complete

Implemented as planned, with one addition anticipated by this doc's own
dependency note (see "confirm the module is declared/re-exported as `pub` or
`pub(crate)`" below): `mod edns_cookie;` in `src/protocol/mod.rs` was private,
so `crate::protocol::edns_cookie::is_solely_cookie_option` was unreachable
from `src/resolver/mod.rs` despite the function itself being `pub(crate)`.
Changed the module declaration to `pub(crate) mod edns_cookie;` — no items
inside gained visibility beyond the crate, since every item in
`edns_cookie.rs` was already `pub(crate)`.

Files touched: `src/protocol/mod.rs` (1-line visibility change),
`src/resolver/mod.rs` (`cache_supported()` widening + repointed test +
4 new/repointed tests, as specced below — all in `#[cfg(test)] mod tests`
except the `cache_supported()` change itself).

Test count: 5 tests exercised (1 repointed, 4 new): `resolve_bypasses_cache_for_unsupported_edns_options`,
`resolve_admits_well_formed_cookie_only_query_to_cache`,
`resolve_bypasses_cache_for_cookie_combined_with_other_option`,
`resolve_cache_lookup_key_ignores_client_cookie_bytes`,
`resolve_bypasses_cache_for_unsupported_edns_flags_and_version` (unmodified,
confirmed still green). Full suite: 590 lib tests pass, `cargo fmt --check`
and `cargo clippy --all-targets` both clean.

Deviations from plan: none of substance. The optional store-path assertions
mentioned as "worth adding if convenient" (a stores-non-empty check on the
cookie-admits test, and a stores-equivalence check on the MissKey test) were
not added — both explicitly marked optional/non-minimum-bar in this doc, and
store-side coverage for cookie-admitted queries is exercised naturally by
later sections (04/05) that thread cookie response-building through the same
path.

## Scope and status

This section makes the resolver's cache-admission gate,
`cache_supported()` (`src/resolver/mod.rs:5508-5520`), recognize a
well-formed, solely-present RFC 7873 COOKIE EDNS option as
cache-compatible instead of unconditionally bypassing the cache the way
it does for every non-empty `edns.options` blob today. It also repoints
an existing regression test that (accidentally) used a Cookie-shaped
option as its "still unsupported" example, and adds new tests pinning
the resulting behavior: Cookie-only queries now participate in cache
lookup/store, Cookie+other-option combinations still bypass, and the
cache key/`MissKey` construction never reads EDNS option bytes at all.

This is a small, self-contained change to `src/resolver/mod.rs` only —
no other file is touched by this section. It does **not** thread the
client cookie value anywhere past the admission check (no OPT-record
building, no `QueryFeatures` changes) — that is section-04's job.

## Dependencies

- **section-02 (`src/protocol/edns_cookie.rs`)** — this section calls
  `is_solely_cookie_option(options: &[u8]) -> Option<ClientCookie>`,
  which must already exist and be unit-tested before this section
  starts. Only its behavior matters here: it returns `Some(client_cookie)`
  when the *entire* raw EDNS options byte slice is consumed by exactly
  one well-formed RFC 7873 COOKIE option (option code 10, length 8 or
  16-40 inclusive) and nothing else; it returns `None` for an empty-but-
  malformed option, a well-formed Cookie option accompanied by any other
  option (e.g. NSID), more than one COOKIE option, or a malformed length.
  This section does not need `parse_cookie_option`, `build_server_cookie`,
  or `build_cookie_option` — those are section-04/05/06's concern.

This section can run in parallel with section-04 and section-06 (both
also depend only on section-02, per the index's dependency graph).

## Background

`rdns` is a Rust DNS resolver/proxy whose answer cache currently refuses
to serve or store any query carrying *any* EDNS option
(`cache_supported()`, below). RFC 7873 DNS Cookies are attached by
default by many modern stub resolvers/`dig` invocations, so this bypass
silently defeats caching for a large fraction of real-world traffic —
that's the bug this whole plan (`docs/plans/edns_cookie_cache/claude-plan.md`)
fixes. This section is the actual cache-admission-gate change; later
sections (04-06) handle actually building and serializing a fresh
server-cookie response.

The cached *answer data* is unaffected by this section — the cache
already never stores EDNS-option bytes (see the `MissKey`-invariant test
below, which pins this explicitly). Only the *admission decision* — "is
this query's EDNS shape cache-compatible at all" — changes.

### Current state: `cache_supported()`

`src/resolver/mod.rs:5508-5520`, current code:

```rust
fn cache_supported(query: &DecodedQuery) -> bool {
    query
        .message
        .edns
        .as_ref()
        .map(|edns| {
            edns.extended_rcode == 0
                && edns.version == 0
                && (edns.flags & !EDNS_DO_FLAG) == 0
                && edns.options.is_empty()
        })
        .unwrap_or(true)
}
```

`query.message.edns` is `Option<EdnsInfo>` (`src/protocol/mod.rs:207-215`):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsInfo {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub flags: u16,
    pub dnssec_ok: bool,
    pub options: Vec<u8>,
}
```

`edns.options` is the raw, already-`validate_edns_options`-checked TLV
byte blob (populated by `parse_opt_record`,
`src/protocol/mod.rs:2617-2641` — validated for well-formed TLV
structure only, not per-option-code semantics, by
`validate_edns_options`, `protocol/mod.rs:2643-2651`).

`cache_supported()` is called from exactly one place,
`probe_cache` (`src/resolver/mod.rs:4409-4479`):

```rust
async fn probe_cache(
    &self,
    backend_snapshot: &BackendSnapshot,
    request: &ResolveRequest,
    decoded: &DecodedQuery,
) -> CacheProbe {
    if !cache_supported(decoded) {
        self.metrics.increment(ResolverMetric::CacheBypass);
        self.metrics.increment(ResolverMetric::CacheMiss);
        return CacheProbe {
            miss_key: None,
            hit: None,
            store_allowed: false,
            event_cache_result: Some(QueryEventCacheResult::Bypass),
        };
    }
    // ... cache lookup, MissKey construction (below) ...
}
```

`probe_cache` itself needs **no changes** beyond the behavior change
that flows automatically from `cache_supported()` recognizing more
cases — it already does the right thing (increments `CacheBypass`/
`CacheMiss` and skips lookup entirely) whenever `cache_supported`
returns `false`, and already does a full lookup whenever it returns
`true`.

### `MissKey` construction — why the cache is already Cookie-safe once admitted

Further down in `probe_cache` (`mod.rs:4462-4474`):

```rust
let miss_key_dnssec_ok = match backend_snapshot.mode {
    ResolutionMode::Recursive => true,
    ResolutionMode::Forward => decoded.features.dnssec_ok,
};

CacheProbe {
    miss_key: Some((
        decoded.question.qname.clone(),
        decoded.question.qtype,
        decoded.question.qclass,
        epoch,
        miss_key_dnssec_ok,
    )),
    hit,
    store_allowed,
    event_cache_result: Some(event_cache_result),
}
```

The `miss_key` tuple is `(qname, qtype, qclass, epoch, dnssec_ok)` —
nowhere does it read `decoded.message.edns.options` or any other
EDNS-option byte. Likewise, the cache lookup itself
(`self.cache.lookup_chain(...)`, `mod.rs:4433-4441`) is keyed only on
`qname`/`qtype`/`qclass`/`dnssec_ok`/`epoch`/`max_chain_depth`/`now` —
again, no option bytes. This is *why* it's safe to admit Cookie-bearing
queries into the cache at all: two requesters with different client
cookies querying the same name must land on the exact same cache
entry/miss-key, which they already do today (this invariant predates
this plan and is not being changed by it) — this section adds a test
that pins it explicitly rather than leaving it as narrative reasoning
only, per the plan-review finding that flagged this as worth confirming
directly rather than assuming.

## What to change

**File to modify:** `src/resolver/mod.rs` (production code, one
function) and its `#[cfg(test)] mod tests` block (test repointing +
three new tests).

### 1. Narrow `cache_supported()`

Change the `edns.options.is_empty()` condition to also accept a
solely-Cookie options blob:

```rust
fn cache_supported(query: &DecodedQuery) -> bool {
    query
        .message
        .edns
        .as_ref()
        .map(|edns| {
            edns.extended_rcode == 0
                && edns.version == 0
                && (edns.flags & !EDNS_DO_FLAG) == 0
                && (edns.options.is_empty()
                    || crate::protocol::edns_cookie::is_solely_cookie_option(&edns.options)
                        .is_some())
        })
        .unwrap_or(true)
}
```

(Adjust the exact module path to match wherever section-02 actually
places `edns_cookie` — the plan specifies `src/protocol/edns_cookie.rs`,
so `crate::protocol::edns_cookie::is_solely_cookie_option` should be
correct, but confirm the module is declared/re-exported as `pub` or
`pub(crate)` from `src/protocol/mod.rs` before wiring this call in.)

All other conditions (`extended_rcode == 0`, `version == 0`, no flags
beyond `EDNS_DO_FLAG`) are **unchanged** — this is a strictly additive
widening of the options-empty branch, nothing else in the function's
shape changes. This deliberately uses the stricter
`is_solely_cookie_option` (not `parse_cookie_option`, which section-04
uses for extraction) so that Goal 5 from the plan — every other
EDNS-option combination still bypasses unchanged — holds even for the
combination of a well-formed Cookie alongside some other option (e.g.
NSID).

### 2. Repoint `resolve_bypasses_cache_for_unsupported_edns_options`

Current test, `src/resolver/mod.rs:19007-19031`:

```rust
#[tokio::test]
async fn resolve_bypasses_cache_for_unsupported_edns_options() {
    let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
    let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
        a_response_with_answer(0x7777, "example.com", 60),
    ))));
    let events = Arc::new(RecordingEvents::default());
    let metrics = Arc::new(RecordingMetrics::default());
    let service =
        resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
    let edns_cookie = [0u8, 10, 0, 2, 0xaa, 0xbb];

    let _ = service
        .resolve(ResolveRequest::new(
            "192.0.2.10".parse().unwrap(),
            SystemTime::UNIX_EPOCH,
            a_query_with_edns_options(0x7777, "example.com", 1232, false, &edns_cookie),
        ))
        .await;

    assert!(cache.lookups.lock().unwrap().is_empty());
    assert!(cache.stores.lock().unwrap().is_empty());
    assert_eq!(metrics.count(ResolverMetric::CacheBypass), 1);
    assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
}
```

The `edns_cookie` local variable name is misleading (it's option code
10, i.e. actually shaped like a COOKIE option — length byte `2` here is
itself a malformed Cookie length per RFC 7873 §4, so this specific fixture
happens to still bypass post-change too, but only by accident of using
an invalid length). Per the plan, replace it with a genuinely,
unambiguously still-unsupported option code so this test's intent stays
correct and unambiguous regardless of any future Cookie-related changes:
use NSID (option code 3) with arbitrary payload bytes, e.g.:

```rust
let edns_nsid = [0u8, 3, 0, 2, 0xaa, 0xbb]; // option code 3 (NSID), length 2
```

Rename the local variable accordingly (e.g. `edns_nsid`) and keep every
other line of the test (setup, assertions) unchanged — this is a pure
fixture-content edit, not a logic change. The test continues to assert
`CacheBypass`/`CacheMiss` both incremented once and both
`cache.lookups`/`cache.stores` empty.

### 3. New test: well-formed Cookie-only query participates in cache

Add a new test function near the repointed one. Model it on the
`resolve_truncates_oversized_cached_response_for_current_request`
fixture pattern (`mod.rs:16444-16498`) for seeding a `RecordingCache`
with a `ChainLookup::Answered` hit, and on
`a_query_with_edns_flags`/`a_query_with_edns_options`
(`mod.rs:7960-8009`) for building the query wire bytes. You will need a
well-formed Cookie option's raw TLV bytes: option code 10 (2 bytes, big
endian: `0, 10`), length 8 (2 bytes: `0, 8`), then 8 arbitrary client
cookie bytes — i.e. `[0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
0x77, 0x88]` (12 bytes total: 4-byte option header + 8-byte client
cookie). A named helper (e.g. `a_query_with_cookie(id, name,
udp_payload_size, dnssec_ok, client_cookie: &[u8; 8]) -> Vec<u8>`,
built on top of `a_query_with_edns_options`) is a reasonable, optional
convenience — not required if inlining the raw bytes is simpler.

```rust
#[tokio::test]
async fn resolve_admits_well_formed_cookie_only_query_to_cache() {
    // Seed a hit so a successful lookup is observable — pattern from
    // resolve_truncates_oversized_cached_response_for_current_request
    // (mod.rs:16444-16498): build an RRsetEntry via seed_rrset_entry,
    // wrap it in cache::ResolvedAnswer, seed
    // RecordingCache::with_lookup(ChainLookup::Answered(resolved)).
    let now = SystemTime::UNIX_EPOCH;
    let record = a_record("example.com", 60);
    let entry = seed_rrset_entry(&record, Duration::from_secs(60), now, 0);
    let resolved = cache::ResolvedAnswer {
        chain: vec![("example.com".to_string(), entry)],
    };
    let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
    let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
    let events = Arc::new(RecordingEvents::default());
    let metrics = Arc::new(RecordingMetrics::default());
    let service =
        resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
    let cookie_option = [0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    let outcome = service
        .resolve(ResolveRequest::new(
            "192.0.2.10".parse().unwrap(),
            now,
            a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option),
        ))
        .await;

    assert!(!cache.lookups.lock().unwrap().is_empty());
    assert_eq!(outcome.decision.kind, ResolveDecisionKind::CacheHit);
    assert_eq!(metrics.count(ResolverMetric::CacheHit), 1);
    assert_eq!(metrics.count(ResolverMetric::CacheBypass), 0);
}
```

(Confirm the exact field/import names — `a_record`, `ResolveDecisionKind::CacheHit`,
`ResolverMetric::CacheHit`, `cache::ResolvedAnswer` — against the live
file at implementation time; this is illustrative of shape/intent, not
a drop-in-verbatim diff, per this plan's stub-over-full-code
convention.)

The core assertion is: a solely-Cookie query no longer takes the
`CacheBypass` branch — it performs a real `lookup_chain` call and,
since seeded with a hit, returns `ResolveDecisionKind::CacheHit` with
`ResolverMetric::CacheHit` incremented and `CacheBypass` at zero. A
store-path variant (seed `ChainLookup::Miss`, assert
`cache.stores.lock().unwrap()` gets a non-empty entry after a
successful upstream response) is also worth adding if convenient,
mirroring `resolve_stores_response_in_cache`-style existing tests
elsewhere in this file — but the hit-path assertion above is the
minimum bar this test must clear.

### 4. New test: Cookie + another EDNS option still bypasses

```rust
#[tokio::test]
async fn resolve_bypasses_cache_for_cookie_combined_with_other_option() {
    let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
    let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
        a_response_with_answer(0x7777, "example.com", 60),
    ))));
    let events = Arc::new(RecordingEvents::default());
    let metrics = Arc::new(RecordingMetrics::default());
    let service =
        resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);
    // A well-formed COOKIE option (code 10, len 8) immediately followed
    // by an NSID option (code 3, len 2) in the same options blob.
    let mut options = vec![0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    options.extend_from_slice(&[0u8, 3, 0, 2, 0xaa, 0xbb]);

    let _ = service
        .resolve(ResolveRequest::new(
            "192.0.2.10".parse().unwrap(),
            SystemTime::UNIX_EPOCH,
            a_query_with_edns_options(0x7777, "example.com", 1232, false, &options),
        ))
        .await;

    assert!(cache.lookups.lock().unwrap().is_empty());
    assert!(cache.stores.lock().unwrap().is_empty());
    assert_eq!(metrics.count(ResolverMetric::CacheBypass), 1);
    assert_eq!(metrics.count(ResolverMetric::CacheMiss), 1);
}
```

This is the direct regression pin for the `is_solely_cookie_option` vs.
`parse_cookie_option` divergence — it must behave identically to the
pre-this-plan "any non-empty options blob bypasses" behavior, since the
Cookie option here does not solely occupy the options blob.

### 5. Confirm `resolve_bypasses_cache_for_unsupported_edns_flags_and_version` needs no change

`mod.rs:19033-19047` (existing test) exercises non-zero extended RCODE
and a non-DO flag bit — neither involves `edns.options` at all, so
`cache_supported()`'s narrowing does not touch the code paths it
exercises. No edit is required to this test; just re-run it (as part of
`cargo test`) to confirm no incidental regression from the
`cache_supported` edit.

### 6. New test: cache lookup / `MissKey` never reads EDNS option bytes

Add a test asserting that two Cookie-bearing queries for the same qname
with *different* client cookies produce the identical cache
lookup/miss-key — i.e. the cache's admission and lookup path is
genuinely insensitive to which specific cookie bytes are present, only
to whether the query is solely-Cookie-shaped (or has no options at all).
The simplest way to observe this end-to-end through `ResolveQuery` is to
assert that `RecordingCache::lookups` records the identical
`(qname, qtype, qclass)` tuple for both queries, and that a miss-and-store
sequence run twice with different cookies still coalesces onto/matches
the same stored key shape:

```rust
#[tokio::test]
async fn resolve_cache_lookup_key_ignores_client_cookie_bytes() {
    let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Miss));
    let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
        a_response_with_answer(0x7777, "example.com", 60),
    ))));
    let events = Arc::new(RecordingEvents::default());
    let metrics = Arc::new(RecordingMetrics::default());
    let service =
        resolve_service_with_cache(upstream, cache.clone(), events, metrics.clone(), 1232);

    let cookie_a = [0u8, 10, 0, 8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
    let cookie_b = [0u8, 10, 0, 8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99];

    let _ = service
        .resolve(ResolveRequest::new(
            "192.0.2.10".parse().unwrap(),
            SystemTime::UNIX_EPOCH,
            a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_a),
        ))
        .await;
    let _ = service
        .resolve(ResolveRequest::new(
            "192.0.2.11".parse().unwrap(),
            SystemTime::UNIX_EPOCH,
            a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_b),
        ))
        .await;

    let lookups = cache.lookups.lock().unwrap();
    assert_eq!(lookups.len(), 2);
    assert_eq!(lookups[0], lookups[1]); // identical (qname, qtype, qclass) despite different client cookies
}
```

This directly pins the invariant described in Background above: the
cache's `lookup_chain`/`miss_key` never depend on option bytes, so
Cookie admission is safe to add without introducing any per-cookie
cache fragmentation.

## Tests (from `claude-plan-tdd.md` Section 3)

- Repoint `resolve_bypasses_cache_for_unsupported_edns_options` to a
  genuinely-still-unsupported option code (NSID = 3) instead of the
  currently-used Cookie-shaped (but malformed-length) bytes; confirm it
  still asserts bypass (`CacheBypass` metric, empty
  `cache.lookups`/`cache.stores`).
- New: a well-formed Cookie-only query participates in cache
  lookup/store — inverse of the above, using a `RecordingCache` seeded
  to return a hit; assert `cache.lookups`/`cache.stores` are non-empty
  and `CacheBypass` is not incremented.
- New: a query with both a well-formed Cookie option and another EDNS
  option (e.g. NSID) still bypasses the cache — confirms no regression
  for other option combinations, via `is_solely_cookie_option`.
- Confirm `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
  passes unmodified (no code change expected, re-run to confirm no
  incidental regression from the `cache_supported` edit).
- New: cache lookup/`MissKey` construction does not read EDNS option
  bytes at all — two Cookie-bearing queries for the same qname with
  different client cookies produce the identical cache lookup/key,
  pinning the cache-safety invariant this plan relies on.

## Verification for this section

Per `RUST.md`'s gates:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets`
- `cargo test` — run at minimum:
  - `resolve_bypasses_cache_for_unsupported_edns_options` (repointed)
  - the new Cookie-only-admits-to-cache test
  - the new Cookie+NSID-still-bypasses test
  - `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
    (unmodified, confirm still green)
  - the new `MissKey`-ignores-cookie-bytes test
  - full existing suite, to confirm the `cache_supported()` widening
    introduces no other regression (in particular, no change to
    `resolve_bypasses_cache_for_unsupported_edns_flags_and_version` or
    to any other EDNS-option-empty-path test that predates this plan)

Do not consider this section done until every EDNS-bypass test in
`src/resolver/mod.rs`'s `#[cfg(test)] mod tests` continues to pass
except where this section explicitly repoints or adds one — per Goal 5
of the parent plan, this is a strictly additive allowlist change, not a
loosening of any other bypass condition.