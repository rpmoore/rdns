# Section 04: ChainLookup / RefreshHint Plumbing

## Scope

This section threads the refresh-trigger signal (produced per cache hop by
section-03's changes to `Shard::lookup_hop`/`HopResult`) up through the
CNAME-chain walk in `cache::assemble::resolve_from_cache` and into
`ResolveQuery::probe_cache`, where it becomes a non-blocking channel enqueue.

It does **not** implement the worker pool that consumes the enqueued jobs
(that's section-05), and does **not** implement the actual refetch/store logic
a worker performs (that's section-06). This section's job ends at "a
qualifying cache hit produces a `RefreshJob` and it either lands in the
channel or gets counted as dropped."

Files touched:
- `src/resolver/cache/assemble.rs` (`ChainLookup`, `ResolvedAnswer`,
  `resolve_from_cache`, new `RefreshHint` type)
- `src/resolver/cache/mod.rs` (re-export of `RefreshHint`, if not already
  covered by the existing `pub use assemble::{...}` block)
- `src/resolver/mod.rs` (`ResolveQuery`, `probe_cache`, `evaluate_cache_lookup`,
  new `RefreshJob` type, new `refresh_sender` field + setter)

## Dependencies on other sections (reference only)

- **section-01 (`PopularityBucket`)**: not touched directly by this section;
  already wired into `ShardState`/`lookup_hop` by the time this section lands.
- **section-02 (`RefreshConfig`)**: not touched directly here either.
- **section-03 (trigger formula)**: this section's hard dependency. By the
  time this section is implemented, `HopResult` (defined in
  `src/resolver/cache/shard.rs`) must already carry a per-hop boolean
  alongside each live positive/CNAME-hop entry, indicating whether that
  specific hop currently satisfies all three gates (eligibility floor, lead
  window, popularity hot-threshold) from `claude-plan.md` §3.1:
  - `HopResult::Answer(RRsetEntry, bool)` — bool = wants-refresh
  - `HopResult::CnameHop(RRsetEntry, String, bool)` — bool = wants-refresh
  - `HopResult::NoData`/`HopResult::NxDomain`/`HopResult::Miss` are
    **unchanged** — negative results never carry a refresh signal (v1 scope
    is positive-entries-only).

  If section-03 lands with a different shape (e.g. the bool named
  differently, or exposed via a method instead of a tuple field), adjust the
  match arms below accordingly — the important contract is only "each
  positive/CNAME hop result carries its own independent
  eligible-for-refresh bool," not the exact field name.
- **section-05 (worker pool + metrics)**: this section assumes
  `ResolverMetric::RefreshTriggered` and `ResolverMetric::RefreshQueueFull`
  already exist as enum variants with working `MetricsSink` impls by the time
  this section is implemented (per the section manifest's suggested execution
  order, section-05 lands in parallel with section-03, both before this
  section). This section does **not** define those metric variants — only
  calls `self.metrics.increment(...)` on them.
- **section-06**: consumes the `RefreshJob`s this section enqueues via the
  channel; out of scope here.

## Background: current code shape

`ChainLookup` today (`src/resolver/cache/assemble.rs:83-95`) has four
variants, no room for a side signal:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainLookup {
    Answered(ResolvedAnswer),
    NxDomain(ResolvedNegative),
    NoData(ResolvedNegative),
    Miss,
}
```

`ResolvedAnswer` (`assemble.rs:52-55`):

```rust
pub struct ResolvedAnswer {
    pub(crate) chain: Vec<(String, RRsetEntry)>, // (owner name, entry), in walk order
}
```

`resolve_from_cache` (`assemble.rs:120-181`) walks the chain, once per shard
per name, via `Shard::lookup_hop`:

```rust
pub(crate) fn resolve_from_cache(
    cache: &ShardedDnsCache,
    qname: &str,
    qtype: u16,
    qclass: u16,
    dnssec_ok: bool,
    current_epoch: u64,
    max_chain_depth: u8,
    now: SystemTime,
) -> ChainLookup {
    let mut current = crate::resolver::normalize_question_name(qname);
    let mut chain: Vec<(String, RRsetEntry)> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();

    loop {
        if chain.len() > usize::from(max_chain_depth) || visited.contains(&current) {
            return ChainLookup::Miss;
        }
        visited.insert(current.clone());

        let shard = cache.shard_for(&current);
        match shard.lookup_hop(&current, qtype, qclass, dnssec_ok, current_epoch, now) {
            HopResult::Answer(entry) => {
                chain.push((current, entry));
                return ChainLookup::Answered(ResolvedAnswer { chain });
            }
            HopResult::CnameHop(entry, target) => {
                chain.push((current, entry));
                current = crate::resolver::normalize_question_name(&target);
            }
            HopResult::NoData(negative) => { /* ... unchanged ... */ }
            HopResult::NxDomain(negative) => { /* ... unchanged ... */ }
            HopResult::Miss => return ChainLookup::Miss,
        }
    }
}
```

`cache/mod.rs` re-exports the relevant types (`cache/mod.rs:32-36`):

```rust
pub use assemble::ChainLookup;
pub use assemble::{
    ResolvedAnswer, ResolvedNegative, assemble_negative_response, assemble_response,
};
```

`ResolveQuery::probe_cache` (`src/resolver/mod.rs:4656-4726`) calls
`self.cache.lookup_chain(...)` then hands the `ChainLookup` to
`evaluate_cache_lookup`:

```rust
let lookup = self.cache.lookup_chain(
    &decoded.question.qname,
    decoded.question.qtype,
    decoded.question.qclass,
    decoded.features.dnssec_ok,
    epoch,
    self.max_chain_depth,
    request.received_at.0,
);
let (store_allowed, hit, event_cache_result) =
    self.evaluate_cache_lookup(lookup, decoded, request);
```

`evaluate_cache_lookup` (`resolver/mod.rs:4741-4778`) consumes `lookup` by
value and matches on it, returning a 3-tuple `(bool, Option<Vec<u8>>,
QueryEventCacheResult)`:

```rust
fn evaluate_cache_lookup(
    &self,
    lookup: ChainLookup,
    decoded: &DecodedQuery,
    request: &ResolveRequest,
) -> (bool, Option<Vec<u8>>, QueryEventCacheResult) {
    match lookup {
        ChainLookup::Answered(resolved) => {
            let response_bytes = self.serialize_cache_hit_answer(decoded, &resolved, request);
            self.record_cache_hit_metrics(&response_bytes, false);
            (false, Some(response_bytes), QueryEventCacheResult::Hit)
        }
        // ... NxDomain / NoData / Miss unchanged ...
    }
}
```

`ResolveQuery` itself (`resolver/mod.rs:3552-3594`) is a plain struct with
fields like `max_chain_depth`, `chaos`, `cookie_secret` that ship with a
default value on every `with_cache*` constructor and get overridden
post-construction via setter methods (`with_max_chain_depth`,
`with_chaos_config`, `with_cookie_secret`, `with_single_flight_shard_count` —
see `resolver/mod.rs:3847-3882`). This section follows that exact pattern for
the new refresh-job sender.

## Tests first

Write these before wiring the code changes below. All are `#[test]`
(plain, in-memory) unless noted.

### `ChainLookup` plumbing tests (`cache/assemble.rs`, corresponds to
`claude-plan-tdd.md` §3.2)

- `chain_lookup_answered_carries_hints_for_qualifying_hops`: a chain with
  exactly one qualifying hop (its `HopResult` bool is `true`) produces
  exactly one `RefreshHint` in `ChainLookup::Answered`'s `refresh_hints`.
- `chain_lookup_multi_hop_all_qualifying_hops_produce_hints`: a multi-hop
  CNAME chain where more than one hop's `HopResult` bool is `true` produces
  one hint per qualifying hop, not just the terminal one.
- `chain_lookup_intermediate_hop_only`: only an intermediate CNAME hop's bool
  is `true` (terminal record's bool is `false`, e.g. because it's fresh) —
  a hint is still produced for that intermediate hop. This is the regression
  test for the "terminal-hop-only" bug found during plan review: an earlier
  draft only checked the terminal hop, which would let an intermediate CNAME
  record expire uncaught even while the terminal record stays fresh.
- `chain_lookup_terminal_hop_only`: only the terminal hop's bool is `true` —
  unaffected by the multi-hop change, still produces exactly one hint.
- `chain_lookup_no_data_never_carries_hint`: `ChainLookup::NoData`'s inner
  `ResolvedNegative` has no `refresh_hints` field/slot at all — a structural
  guarantee (there is nothing to assert at runtime beyond "this compiles and
  `ResolvedNegative` has no such field"; consider a doc-comment-level note
  plus a test that constructs a `NoData` result and confirms no hints are
  observable anywhere in the returned `ChainLookup`).
- `chain_lookup_no_qualifying_hops_empty_hints`: a chain where every hop's
  bool is `false` produces `ChainLookup::Answered` with an empty
  `refresh_hints` vec, not a miss or error.
- Regression test that each hint's `qtype` matches *that hop's own* record
  type, not the originally-queried qtype: a CNAME hop's hint must have
  `qtype = CNAME_RECORD_TYPE` (5), while the terminal hop's hint has the
  actual queried `qtype`. (Not explicitly named in `claude-plan-tdd.md`, but
  required for `chain_lookup_multi_hop_all_qualifying_hops_produce_hints`
  and `chain_lookup_intermediate_hop_only` to be meaningful — see
  "Implementation" below for why this matters.)

### Job enqueue tests (`resolver/mod.rs`, corresponds to
`claude-plan-tdd.md` §4.1 — `#[tokio::test]`, since these exercise a real
`tokio::sync::mpsc` channel)

- `enqueue_try_send_succeeds_under_capacity`: a hint under channel capacity
  is enqueued successfully as a `RefreshJob`, `RefreshTriggered` increments.
- `enqueue_drops_and_counts_on_full_channel`: a full channel causes
  `try_send` to fail; the job is dropped (not blocked, not retried, no
  panic); `RefreshQueueFull` increments instead of `RefreshTriggered`.
- `enqueue_per_hint_independent`: given multiple hints from one lookup (a
  multi-hop hot chain), one hint hitting a full channel does not prevent the
  other hints from being independently enqueued/dropped on their own merits.

## Implementation

### 1. `RefreshHint` (new type, `cache/assemble.rs`)

```rust
/// One cache hop's signal that it currently qualifies for a background
/// refresh (all three gates in claude-plan.md §3.1 hold: eligibility floor,
/// lead window, popularity hot-threshold). `qtype`/`qclass` identify the
/// specific record set at `domain` that should be refetched — for an
/// intermediate CNAME hop this is `(CNAME_RECORD_TYPE, qclass)`, never the
/// original query's qtype, since the CNAME record set at that hop's domain
/// is what's actually near expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefreshHint {
    pub(crate) domain: String,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
}
```

### 2. Extend `ResolvedAnswer`, not `ChainLookup`'s shape

Add a `refresh_hints: Vec<RefreshHint>` field directly to `ResolvedAnswer`,
rather than converting `ChainLookup::Answered` into a struct-like variant
(`claude-plan.md`'s pseudocode shows the field on the variant itself, but the
actual code already wraps a struct: `Answered(ResolvedAnswer)`). Adding the
field to `ResolvedAnswer` keeps every existing
`ChainLookup::Answered(resolved)` call site compiling with no shape change,
and naturally guarantees `NoData`/`NxDomain` (which use `ResolvedNegative`,
a different struct) can never carry a hint — there's no field to add it to.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAnswer {
    pub(crate) chain: Vec<(String, RRsetEntry)>,
    pub(crate) refresh_hints: Vec<RefreshHint>,
}
```

Every existing test/production construction of `ResolvedAnswer { chain: ...
}` (several in `assemble.rs`'s own `#[cfg(test)] mod tests`, e.g. around
lines 897, 993, 1034, etc.) needs the new field added — `Vec::new()` for
tests that don't care about refresh behavior.

### 3. Thread hints through `resolve_from_cache`'s loop

Accumulate a `Vec<RefreshHint>` across the whole walk (not just the terminal
hop), pushing one entry per qualifying `Answer`/`CnameHop` result:

```rust
let mut chain: Vec<(String, RRsetEntry)> = Vec::new();
let mut refresh_hints: Vec<RefreshHint> = Vec::new();
let mut visited: HashSet<String> = HashSet::new();

loop {
    // ... unchanged depth/cycle guard ...

    let shard = cache.shard_for(&current);
    match shard.lookup_hop(&current, qtype, qclass, dnssec_ok, current_epoch, now) {
        HopResult::Answer(entry, wants_refresh) => {
            if wants_refresh {
                refresh_hints.push(RefreshHint {
                    domain: current.clone(),
                    qtype,
                    qclass,
                });
            }
            chain.push((current, entry));
            return ChainLookup::Answered(ResolvedAnswer { chain, refresh_hints });
        }
        HopResult::CnameHop(entry, target, wants_refresh) => {
            if wants_refresh {
                refresh_hints.push(RefreshHint {
                    domain: current.clone(),
                    qtype: CNAME_RECORD_TYPE, // this hop's own record type, not the original qtype
                    qclass,
                });
            }
            chain.push((current, entry));
            current = crate::resolver::normalize_question_name(&target);
        }
        HopResult::NoData(negative) => { /* unchanged — no hint */
            return ChainLookup::NoData(ResolvedNegative { chain, terminal_name: current, negative });
        }
        HopResult::NxDomain(negative) => { /* unchanged — no hint */
            return ChainLookup::NxDomain(ResolvedNegative { chain, terminal_name: current, negative });
        }
        HopResult::Miss => return ChainLookup::Miss,
    }
}
```

Note the qtype distinction is load-bearing: reusing the outer `qtype`
parameter for a `CnameHop` hint would produce a `RefreshJob` that later tries
to refetch, say, an `A` record at a domain that only ever had a `CNAME`
there — a wasted/incorrect fetch. Each hint must describe the record type
actually stored (and near-expiry) at that hop's own domain.

### 4. Re-export `RefreshHint` from `cache/mod.rs`

Add `RefreshHint` to the existing re-export line so `resolver/mod.rs` can
name it without reaching into `cache::assemble` directly:

```rust
pub use assemble::{
    RefreshHint, ResolvedAnswer, ResolvedNegative, assemble_negative_response, assemble_response,
};
```

### 5. `RefreshJob` (new type, `resolver/mod.rs`, per `claude-plan.md` §4.1)

```rust
/// One background refresh attempt: a domain/qtype/qclass to refetch and
/// re-store before its cached entry actually expires. Built from a
/// `RefreshHint` at enqueue time (`ResolveQuery::probe_cache`); consumed by
/// the worker pool (section-05) and processed by `process_job` (section-06).
struct RefreshJob {
    domain: String,
    qtype: u16,
    qclass: u16,
}
```

### 6. `ResolveQuery`'s new `refresh_sender` field + setter

Add a field following the exact "default value + post-construction setter"
pattern already used for `max_chain_depth`/`chaos`/`cookie_secret`
(`resolver/mod.rs:3552-3594`, `3847-3882`):

```rust
pub struct ResolveQuery {
    // ... existing fields ...
    // Non-blocking enqueue point for background refresh jobs (§4.1). Every
    // constructor defaults this to a sender whose paired receiver has
    // already been dropped, so any accidental enqueue in an existing test
    // (none currently trigger refresh, since none configure a hot
    // popularity bucket) simply counts as a dropped job
    // (`ResolverMetric::RefreshQueueFull`) rather than panicking or
    // blocking. `main.rs` (section-05/07) overrides this via
    // `with_refresh_sender` once the real worker pool's channel exists.
    refresh_sender: tokio::sync::mpsc::Sender<RefreshJob>,
}
```

Default construction (inside `with_cache_policy_and_backend_snapshot` and any
sibling builder that directly constructs `Self { ... }`, e.g.
`with_cache_policy_and_backend_handle`):

```rust
let (refresh_sender, _dropped_receiver) = tokio::sync::mpsc::channel(1);
Self {
    // ... existing fields ...
    refresh_sender,
}
```

New setter, alongside `with_max_chain_depth`/`with_chaos_config` etc.:

```rust
pub fn with_refresh_sender(mut self, sender: tokio::sync::mpsc::Sender<RefreshJob>) -> Self {
    self.refresh_sender = sender;
    self
}
```

(`RefreshJob` is currently private to `resolver/mod.rs`; if section-05's
worker-pool wiring in `main.rs` needs to construct the channel with this
type, promote `RefreshJob` to `pub(crate)` at that point — not required by
this section alone, since this section's own tests can exercise the setter
from within `resolver::mod`'s own `#[cfg(test)] mod tests`.)

### 7. `evaluate_cache_lookup` returns hints too

Extend the return tuple with a fourth element, `Vec<RefreshHint>` — empty
for every arm except `Answered`, which clones `resolved.refresh_hints` before
`resolved` is consumed by `serialize_cache_hit_answer`:

```rust
fn evaluate_cache_lookup(
    &self,
    lookup: ChainLookup,
    decoded: &DecodedQuery,
    request: &ResolveRequest,
) -> (bool, Option<Vec<u8>>, QueryEventCacheResult, Vec<RefreshHint>) {
    match lookup {
        ChainLookup::Answered(resolved) => {
            let refresh_hints = resolved.refresh_hints.clone();
            let response_bytes = self.serialize_cache_hit_answer(decoded, &resolved, request);
            self.record_cache_hit_metrics(&response_bytes, false);
            (false, Some(response_bytes), QueryEventCacheResult::Hit, refresh_hints)
        }
        ChainLookup::NxDomain(resolved) => {
            // ... unchanged body ...
            (false, Some(response_bytes), QueryEventCacheResult::Hit, Vec::new())
        }
        ChainLookup::NoData(resolved) => {
            // ... unchanged body ...
            (false, Some(response_bytes), QueryEventCacheResult::Hit, Vec::new())
        }
        ChainLookup::Miss => {
            self.metrics.increment(ResolverMetric::CacheMiss);
            (true, None, QueryEventCacheResult::Miss, Vec::new())
        }
    }
}
```

### 8. `probe_cache` enqueues jobs after evaluating the lookup

```rust
let (store_allowed, hit, event_cache_result, refresh_hints) =
    self.evaluate_cache_lookup(lookup, decoded, request);

for hint in refresh_hints {
    self.enqueue_refresh_job(hint);
}
```

New helper, near `probe_cache`/`evaluate_cache_lookup`:

```rust
/// Non-blocking, best-effort enqueue: a full (or closed, e.g. no worker
/// pool wired up yet) channel counts as a dropped trigger
/// (`RefreshQueueFull`), never blocks, never panics. Applies independently
/// per hint — one drop from a multi-hop chain doesn't affect the others,
/// each already enqueued in its own `for` loop iteration above.
fn enqueue_refresh_job(&self, hint: RefreshHint) {
    let job = RefreshJob {
        domain: hint.domain,
        qtype: hint.qtype,
        qclass: hint.qclass,
    };
    match self.refresh_sender.try_send(job) {
        Ok(()) => self.metrics.increment(ResolverMetric::RefreshTriggered),
        Err(_) => self.metrics.increment(ResolverMetric::RefreshQueueFull),
    }
}
```

`try_send`'s `Err` covers both `TrySendError::Full` (channel at capacity) and
`TrySendError::Closed` (no receiver, e.g. in tests using the default
dropped-receiver sender) — both are treated identically as "dropped," per
the plan's best-effort-by-design framing (`claude-plan.md` §4.1): a dropped
trigger has no correctness impact, the entry just expires normally and the
next real query gets an ordinary reactive miss.

### 9. Fix existing `HopResult` match sites broken by section-03's field addition

Two existing tests in `src/resolver/cache/shard.rs` match `HopResult::Answer`
with a single wildcard (`shard.rs:759`, `shard.rs:780`:
`matches!(result, HopResult::Answer(_))`) — once the variant becomes a
2-tuple (`Answer(RRsetEntry, bool)`), these need `HopResult::Answer(..)`
instead. This is expected to already be handled by section-03 (since it's
the section that changes `HopResult`'s shape), but verify it compiles as
part of this section's own work before writing new tests against it.

## Gates

Standard gates before this section is considered done (per `RUST.md`):
`cargo fmt`, `cargo clippy`, `cargo test`. Given the number of existing
`ResolvedAnswer`/`ChainLookup`/`evaluate_cache_lookup` call sites this touches
across `assemble.rs`'s own test module and `resolver/mod.rs`'s (very large)
test module, expect several dozen existing tests to need a one-line update
(new `refresh_hints: Vec::new()` field, or an extra `Vec::new()`/ignored
tuple element) rather than a logic change.

## Implementation Notes (post-implementation)

**Major deviation from plan — a cross-section integration gap had to be
resolved first.** Section-03's plan (already implemented, committed) left
`Shard::lookup_hop`'s signature and `HopResult` untouched, keeping
`wants_refresh()` fully standalone/unwired — but this section's own plan
assumed `HopResult::Answer`/`CnameHop` already carried a per-hop bool
computed inside `lookup_hop` (where the lock + popularity bucket + config
are actually available). These two section plans were written by
non-communicating parallel planning passes and directly contradicted each
other. Additionally, this section's plan assumed
`ResolverMetric::RefreshTriggered`/`RefreshQueueFull` already existed (from
section-05), but sections are implemented in strict manifest order
(01→02→03→04→...), so section-05 hadn't landed either.

**User was asked and explicitly chose "do the full fix now"** over a
lighter-weight workaround. What that added, beyond this section's literal
plan text:
- Extended `HopResult::Answer(RRsetEntry, bool)`/`CnameHop(RRsetEntry, String, bool)`,
  with the bool computed via `wants_refresh()` inside `lookup_hop` itself
  (added `ShardState::record_hit_and_check_refresh` to share this logic
  between both branches, per code review — see below).
- Threaded `&RefreshConfig` into `Shard::lookup_hop`, `resolve_from_cache`,
  the `DomainDnsCache::lookup_chain` trait (`ShardedDnsCache` impl, 3
  test-mock impls, and the production `NoopDnsCache` impl), replacing
  section-01's placeholder `DEFAULT_POPULARITY_*` constants with real
  config-sourced values.
- Added `refresh_config: RefreshConfig` field + `with_refresh_config` setter
  to `ResolveQuery` (mirrors the existing `max_chain_depth`/`chaos`/
  `cookie_secret` post-construction-override pattern).
- Pulled forward `ResolverMetric::RefreshTriggered`/`RefreshQueueFull` (2 of
  section-05's planned 4 variants) plus `OpenTelemetryMetrics` counter
  fields/match arms in `main.rs` — section-04's own enqueue path needs them
  to compile. Confirmed by code review this won't cause section-05 rework
  (`ResolverMetric` and `OpenTelemetryMetrics::increment` are both
  exhaustive matches, so the compiler forces the remaining 2 variants'
  arms when section-05 adds them).

**This section's actual literal scope**, once the above was in place, matches
the plan: `RefreshHint` type, `ResolvedAnswer.refresh_hints: Vec<RefreshHint>`
field (not a variant-level field — `ChainLookup::Answered` already wraps a
struct), multi-hop hint accumulation in `resolve_from_cache`'s walk (every
qualifying hop gets its own hint, not just the terminal one — the plan's
core point), `RefreshJob`/`refresh_sender` field+setter, `enqueue_refresh_job`,
`evaluate_cache_lookup` returning hints, `probe_cache` enqueuing per hint.

**Code review found and fixed a real bug**: the single-flight *follower*
path (`cache_hit_after_coalesced_miss`) called `lookup_chain` correctly but
never read `resolved.refresh_hints` — silently dropping them on exactly the
concurrent/hot-domain scenario this feature targets. Fixed to enqueue the
same way `probe_cache` does, with two new end-to-end regression tests
(`resolve_cache_hit_with_refresh_hint_enqueues_a_job`,
`cache_hit_after_coalesced_miss_enqueues_refresh_hints`).

**Other review fixes**: deduplicated `lookup_hop`'s copy-pasted
popularity+trigger logic into `ShardState::record_hit_and_check_refresh`;
replaced `evaluate_cache_lookup`'s positional 4-tuple return with a named
`CacheLookupEvaluation` struct (matching this file's existing `CacheProbe`
convention); documented `wants_refresh`'s read-after-write semantics (a hit
counts toward its own hot-threshold check, not just subsequent ones).

**Known interim state, not a defect**: `main.rs` doesn't call
`with_refresh_config`/`with_refresh_sender` yet (that's section-07's job),
so as of this commit `RefreshConfig::default()` (enabled=true) runs full
popularity tracking on every production cache hit with no worker-pool
consumer yet and no operator kill switch at the `main.rs` layer. Expected
given strict manifest-order implementation.

**Test coverage**: 11 new tests beyond the plan's original list — 6
`ChainLookup`/multi-hop tests in `assemble.rs` (using a `warm_popularity`
helper that queries a hop directly, bypassing chain-following, to
selectively raise only that hop's popularity — works because popularity is
keyed per-domain, not per-(domain,qtype)), 3 `#[tokio::test]` enqueue tests
in `resolver/mod.rs`, plus the 2 end-to-end regression tests above.

All of `RUST.md`'s gates pass: `cargo fmt`, `cargo clippy --all-targets`
(warning-free, including a new `#[allow(clippy::too_many_arguments)]` on
`lookup_hop`), `cargo test` (full suite, 652 lib tests passing).