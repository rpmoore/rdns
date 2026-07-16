Now I have everything needed to write the section.

## Section content

# section-01-popularity-bucket: Popularity Tracking (Leaky Bucket)

## Scope and dependencies

This section is standalone — it touches only `src/resolver/cache/shard.rs`
and has no dependencies on any other section. It blocks `section-03-trigger-formula`,
which will later read `PopularityBucket::is_hot()` and thread real `RefreshConfig`
values into the wiring this section adds. `RefreshConfig` (from `section-02-refresh-config`)
does **not** exist yet at this point — this section uses hardcoded placeholder
constants for the leak rate / hit increment / bucket capacity, matching the plan's
confirmed defaults. Section-03 will later replace those placeholder constants with
values threaded from `RefreshConfig` when it changes `lookup_hop`'s call sites — that
signature change is out of scope here.

## Background context

`rdns` is a Rust DNS resolver. Its cache (`src/resolver/cache/`) is sharded: each
`Shard` (`src/resolver/cache/shard.rs`) owns one lock guarding a `ShardState`, which
today holds three fields:

```rust
#[derive(Debug, Default)]
struct ShardState {
    positive: PositiveShardState,
    negative: NegativeShardState,
    lru: ShardLru,
}
```

`ShardLru` (`src/resolver/cache/lru.rs`) tracks per-domain recency with `touch`/`remove`/`peek_oldest`,
used for capacity-based eviction. A domain "counts" toward shard capacity if it has any
live positive or negative data; `ShardState::evict_domain` and
`ShardState::drop_lru_if_domain_now_empty` are the exact two places today where a domain's
LRU token is removed:

```rust
impl ShardState {
    /// Removes `domain` from both the positive and negative maps
    /// (unconditionally...) and clears its LRU position.
    fn evict_domain(&mut self, domain: &str) {
        self.positive.domains.remove(domain);
        self.negative.domains.remove(domain);
        self.lru.remove(domain);
    }

    fn drop_lru_if_domain_now_empty(&mut self, domain: &str) {
        if !self.positive.domains.contains_key(domain)
            && !self.negative.domains.contains_key(domain)
        {
            self.lru.remove(domain);
        }
    }
}
```

`Shard::lookup_hop` (`shard.rs:405-463`) is the single entry point for one hop of a
cache lookup. It probes, in order: a positive answer, a CNAME hop, a NODATA negative
entry, an NXDOMAIN negative entry — returning `HopResult::{Answer, CnameHop, NoData,
NxDomain, Miss}`. On every one of the first four (live-hit) branches it calls
`state.lru.touch(domain)` to bump recency. There are exactly **four** such call sites
today, at `shard.rs:426`, `436`, `448`, `459`:

```rust
pub(crate) fn lookup_hop(
    &self,
    domain: &str,
    qtype: u16,
    qclass: u16,
    dnssec_ok: bool,
    current_epoch: u64,
    now: SystemTime,
) -> HopResult {
    let mut state = self.state.lock().unwrap();
    let answer_key = (qtype, qclass);

    if let Some(entry) =
        state.take_live_positive(domain, answer_key, dnssec_ok, current_epoch, now)
    {
        state.lru.touch(domain);                              // <-- site 1 (line 426)
        return HopResult::Answer(entry);
    }

    if qtype != CNAME_RECORD_TYPE {
        let cname_key = (CNAME_RECORD_TYPE, qclass);
        if let Some((entry, target)) =
            state.take_live_cname_hop(domain, cname_key, dnssec_ok, current_epoch, now)
        {
            state.lru.touch(domain);                          // <-- site 2 (line 436)
            return HopResult::CnameHop(entry, target);
        }
    }

    let nodata_key = NegativeKey { qtype: Some(qtype), qclass };
    if let Some(entry) =
        state.take_live_negative(domain, &nodata_key, dnssec_ok, current_epoch, now)
    {
        state.lru.touch(domain);                              // <-- site 3 (line 448)
        return HopResult::NoData(entry);
    }

    let nxdomain_key = NegativeKey { qtype: None, qclass };
    if let Some(entry) =
        state.take_live_negative(domain, &nxdomain_key, dnssec_ok, current_epoch, now)
    {
        state.lru.touch(domain);                              // <-- site 4 (line 459)
        return HopResult::NxDomain(entry);
    }

    HopResult::Miss
}
```

`now: SystemTime` is already an explicit parameter threaded through this module —
`lookup_hop` and its helpers take it directly rather than via an injected clock trait.
There *is* a `Clock`/`SystemClock`/`FixedClock` abstraction, but it lives one layer up
in `src/resolver/mod.rs` and is not used inside `cache::shard`. **Do not introduce a
`Clock` trait here.** Tests fake time the same way existing shard tests do: by
constructing explicit `SystemTime` offsets (`now - Duration::from_secs(...)` /
`now + Duration::from_secs(...)`), not via a mock clock object.

Existing test fixture conventions in this file's `#[cfg(test)] mod tests` (`shard.rs:561+`)
that this section's tests should follow:

```rust
const IN_QCLASS: u16 = 1;
const A_QTYPE: u16 = 1;

fn stored_record() -> StoredRecord { /* ... */ }
fn rrset_entry() -> RRsetEntry { /* ... */ }   // uses SystemTime::now() + Duration offsets
fn negative_entry() -> NegativeEntry { /* ... */ }
```

Tests use `Shard::new(capacity)`, `shard.store_positive(...)`, `shard.touch(...)`, and
`#[cfg(test)]`-gated inspection helpers already on `Shard` such as `domain_count()`
(not test-gated — used in production too), and `contains_positive`, `contains_negative`,
`has_any_data` (all `#[cfg(test)] pub(crate) fn`, `shard.rs:514-538`). This section adds
one more such test-only accessor for popularity level (see below).

## What to build

### 1. `LeakRate` type

Add a small plain-data type representing "drain `units` per `per` elapsed time" (e.g.
the confirmed default of 1 unit per 60 seconds):

```rust
/// Leak rate for a `PopularityBucket`: drains `units` worth of level per
/// `per` elapsed real time. Defined here (cache layer), not in `config`,
/// because the leaky-bucket concept itself belongs to the cache; a later
/// section's `RefreshConfig` (`src/config/mod.rs`) references this same
/// type by name for its `leak_rate` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LeakRate {
    pub(crate) units: u32,
    pub(crate) per: Duration,
}
```

### 2. `PopularityBucket` struct

A small plain-data struct: an integer `level` and `last_drained: SystemTime`.

```rust
/// Per-domain leaky-bucket popularity tracker. Created the first time a
/// domain is stored (mirroring `ShardLru`'s own on-first-store creation),
/// drained-then-incremented on every subsequent lookup hit, and removed
/// at exactly the two points a domain's `ShardLru` token is removed today
/// (`ShardState::evict_domain`, `ShardState::drop_lru_if_domain_now_empty`)
/// — this keeps popularity state from ever drifting out of sync with which
/// domains still have cached data: when a domain's data is gone, its
/// popularity state is gone in the same operation.
///
/// Granularity is per-domain (qname only), not per-`(qname, qtype, qclass)`
/// — matching `ShardLru`'s own granularity. A query for any record type
/// under a domain raises that domain's popularity.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PopularityBucket {
    level: u32,
    last_drained: SystemTime,
}

impl PopularityBucket {
    /// A fresh bucket for a domain seen for the first time: zero level,
    /// drained as of `now`.
    fn new(now: SystemTime) -> Self {
        Self { level: 0, last_drained: now }
    }

    /// Drains the bucket by elapsed time since `last_drained`, then adds
    /// `hit_increment`, saturating at `capacity`. Uses integer arithmetic
    /// throughout (no floats) to avoid long-uptime rounding drift.
    ///
    /// `now` must be >= `last_drained` under normal operation; a `now`
    /// that appears to go backward (clock adjustment) is treated as zero
    /// elapsed time rather than panicking or underflowing — `last_drained`
    /// is never moved backward.
    ///
    /// Truncation-bias avoidance (a known pitfall, must be covered by a
    /// unit test): converting elapsed time to leaked units naively
    /// (`elapsed * leak_rate.units / leak_rate.per`, discarding the
    /// remainder, then setting `last_drained = now`) silently biases the
    /// drain low whenever elapsed time is repeatedly smaller than one full
    /// drain unit — a domain drained in many small steps ends up with a
    /// higher level than one drained in one big step covering the same
    /// total elapsed time. Avoid this by only ever advancing
    /// `last_drained` by the exact amount of time actually "spent" on the
    /// whole leaked units applied this call (i.e. `last_drained +=
    /// leaked_units * per / units`), leaving any leftover sub-unit elapsed
    /// time still pending against `last_drained` for the next call to
    /// pick up — never simply resetting `last_drained = now`.
    fn drain_and_increment(
        &mut self,
        now: SystemTime,
        leak_rate: LeakRate,
        hit_increment: u32,
        capacity: u32,
    ) {
        todo!()
    }

    /// True if `level >= hot_threshold` (an absolute count derived
    /// elsewhere from `RefreshConfig::hot_threshold_fraction *
    /// bucket_capacity` — this method just takes the precomputed
    /// absolute threshold).
    fn is_hot(&self, hot_threshold: u32) -> bool {
        self.level >= hot_threshold
    }
}
```

### 3. `ShardState.popularity` field

Add a fourth field to `ShardState`, at the same level as `lru`:

```rust
#[derive(Debug, Default)]
struct ShardState {
    positive: PositiveShardState,
    negative: NegativeShardState,
    lru: ShardLru,
    popularity: HashMap<String, PopularityBucket>,
}
```

### 4. Removal wiring

Update the two existing removal points to also drop the domain's `PopularityBucket`:

```rust
fn evict_domain(&mut self, domain: &str) {
    self.positive.domains.remove(domain);
    self.negative.domains.remove(domain);
    self.lru.remove(domain);
    self.popularity.remove(domain);
}

fn drop_lru_if_domain_now_empty(&mut self, domain: &str) {
    if !self.positive.domains.contains_key(domain)
        && !self.negative.domains.contains_key(domain)
    {
        self.lru.remove(domain);
        self.popularity.remove(domain);
    }
}
```

Note: `sweep_stale_namespace` (`shard.rs:471-512`) also removes a domain's LRU token
for emptied domains, but does so via a direct `state.lru.remove(&domain)` call rather
than through `drop_lru_if_domain_now_empty`. Per the plan, only the two functions above
are in scope for popularity cleanup in this section — leave `sweep_stale_namespace`
untouched. (This is a pre-existing characteristic of the plan as documented, not
something to "fix" here.)

**Accepted tradeoff — eviction under shard capacity pressure**: a domain repeatedly
evicted from a shard at capacity loses its `PopularityBucket` each time and must rebuild
popularity from scratch afterward. This is the same tradeoff the LRU itself already has
under capacity pressure — not something this feature introduces or needs to special-case.

**Scope note — DNSSEC record shapes**: no new handling is needed for RRSIG-only or other
DNSSEC-specific entry shapes; this section only concerns whatever `take_live_positive`/
`take_live_cname_hop` already return as a live positive entry.

### 5. Increment wiring: `record_popularity_hit` helper + the 4 call sites

Add a private `ShardState` helper that performs the drain-then-increment, gated on an
explicit `enabled: bool` parameter (a placeholder until section-03 threads the real
`RefreshConfig::enabled` value through `lookup_hop`'s signature — out of scope here):

```rust
impl ShardState {
    /// Drains-then-increments `domain`'s popularity bucket, allocating it
    /// on first hit. A complete no-op — the bucket is never allocated at
    /// all, not merely "left untouched" — when `enabled` is false.
    fn record_popularity_hit(
        &mut self,
        domain: &str,
        now: SystemTime,
        enabled: bool,
        leak_rate: LeakRate,
        hit_increment: u32,
        bucket_capacity: u32,
    ) {
        if !enabled {
            return;
        }
        self.popularity
            .entry(domain.to_string())
            .or_insert_with(|| PopularityBucket::new(now))
            .drain_and_increment(now, leak_rate, hit_increment, bucket_capacity);
    }
}
```

Wire a call to this helper into `lookup_hop` immediately alongside each of the 4
existing `state.lru.touch(domain)` call sites (lines 426, 436, 448, 459), using
placeholder module-level constants matching the plan's confirmed `RefreshConfig`
defaults (§5 of `claude-plan.md`: `bucket_capacity = 10`, `leak_rate = 1 unit / 60s`,
`hit_increment = 1`) and `enabled = true` — these placeholders get replaced by real
`RefreshConfig`-sourced values when section-03 changes `lookup_hop`'s signature:

```rust
const DEFAULT_POPULARITY_LEAK_RATE: LeakRate = LeakRate {
    units: 1,
    per: Duration::from_secs(60),
};
const DEFAULT_POPULARITY_HIT_INCREMENT: u32 = 1;
const DEFAULT_POPULARITY_BUCKET_CAPACITY: u32 = 10;
```

Example for site 1 (the other three follow the identical pattern):

```rust
if let Some(entry) =
    state.take_live_positive(domain, answer_key, dnssec_ok, current_epoch, now)
{
    state.lru.touch(domain);
    state.record_popularity_hit(
        domain,
        now,
        true,
        DEFAULT_POPULARITY_LEAK_RATE,
        DEFAULT_POPULARITY_HIT_INCREMENT,
        DEFAULT_POPULARITY_BUCKET_CAPACITY,
    );
    return HopResult::Answer(entry);
}
```

### 6. Test-only inspection accessor

Following the existing `#[cfg(test)] pub(crate) fn` pattern for `contains_positive`/
`contains_negative`/`has_any_data` (`shard.rs:514-538`), add one for popularity so tests
can inspect bucket state without reaching into `ShardState` internals directly:

```rust
#[cfg(test)]
pub(crate) fn popularity_level(&self, domain: &str) -> Option<u32> {
    self.state.lock().unwrap().popularity.get(domain).map(PopularityBucket::level)
}
```

(Add a small `#[cfg(test)] fn level(&self) -> u32 { self.level }` accessor on
`PopularityBucket` to support this, or expose the field as `pub(crate)` within the
module — either is fine, follow whichever is more idiomatic given `#[allow(dead_code)]`
already covers this file per its module doc comment.)

## Tests to write first

Add these to the existing `#[cfg(test)] mod tests` block in `shard.rs` (`shard.rs:561+`),
reusing the existing `rrset_entry()`/`stored_record()`/`negative_entry()` fixtures and
explicit `now: SystemTime` offset style already used throughout this file. Per this
repo's TDD convention, these are `#[test]` (plain, no `#[tokio::test]` needed — pure
in-memory struct logic, no async):

- `popularity_bucket_drains_by_elapsed_time`: level decreases proportionally to elapsed
  time since `last_drained`, using explicit `now` offsets.
- `popularity_bucket_increments_on_hit`: a hit adds `hit_increment` after draining.
- `popularity_bucket_saturates_at_capacity`: level never exceeds `bucket_capacity`
  regardless of hit burst size.
- `popularity_bucket_drain_no_truncation_bias`: advancing the clock in many small
  sub-unit-of-drain steps produces the same cumulative drain as one large step covering
  the same total elapsed time (the integer-truncation pitfall described in the
  `drain_and_increment` doc comment above).
- `popularity_bucket_treats_backward_clock_as_zero_elapsed`: a `now` earlier than
  `last_drained` doesn't underflow or panic (and doesn't move `last_drained` backward).
- `popularity_cleared_on_evict_domain`: `ShardState::evict_domain` removes the domain's
  `PopularityBucket` alongside its LRU entry.
- `popularity_cleared_on_drop_lru_if_domain_now_empty`: same, via the other removal
  path (e.g. removing the domain's last positive/negative entry without a full shard
  eviction).
- `popularity_not_allocated_when_disabled`: calling `record_popularity_hit` with
  `enabled = false` creates no `PopularityBucket` entry at all — assert via
  `popularity_level(domain).is_none()`, not merely that the level is unchanged.
- `is_hot_reflects_configured_threshold`: `is_hot()` returns true only at/above the
  configured `hot_threshold`, boundary-tested at exactly the threshold (e.g. level ==
  threshold is hot, level == threshold - 1 is not).

Also add (or extend an existing) test exercising `lookup_hop` end-to-end to confirm the
wiring itself: a lookup hit at any of the four branches (`Answer`, `CnameHop`, `NoData`,
`NxDomain`) causes the domain's `popularity_level` to go from `None` to `Some(1)` (or to
increment on a second hit), matching the existing style of tests like
`eviction_removes_least_recently_used_domain_while_touched_ones_survive` that build a
`Shard`, perform operations, then assert via the test-only accessors.

## Verification

Before considering this section done, per `RUST.md`: `cargo fmt`, `cargo clippy`,
`cargo test` (scoped at minimum to `cargo test --lib resolver::cache::shard` while
iterating, full `cargo test` before calling it complete).

---

**File touched:** `src/resolver/cache/shard.rs` only.

**Relevant file/line anchors from current code** (for locating insertion points):
- `ShardState` definition: `shard.rs:72-77`
- `ShardState::evict_domain`: `shard.rs:84`
- `ShardState::drop_lru_if_domain_now_empty`: `shard.rs:144`
- `Shard::lookup_hop` and its 4 `lru.touch` call sites: `shard.rs:405-463` (touch calls
  at lines 426, 436, 448, 459)
- Existing `#[cfg(test)]` inspection helpers to mirror: `contains_positive`,
  `contains_negative`, `has_any_data`, `shard.rs:514-538`
- Existing test fixtures to reuse: `stored_record()`, `rrset_entry()`,
  `negative_entry()`, `shard.rs:572-612`

## Implementation Notes (post-implementation)

Implemented as planned: `LeakRate`, `PopularityBucket` (with `drain_and_increment`/
`is_hot`/`level`), `ShardState.popularity` field, removal wiring in `evict_domain`/
`drop_lru_if_domain_now_empty`, `record_popularity_hit` helper, all 4 `lookup_hop`
call sites, `popularity_level` test accessor — all in `src/resolver/cache/shard.rs`,
no other files touched for the code itself.

**Deviations from plan, from code review:**
- `drain_and_increment`'s elapsed-to-leaked-units conversion uses
  `u32::try_from(...).unwrap_or(u32::MAX)` instead of a bare `as u32` cast, to
  saturate instead of silently wrapping if the computed value could ever exceed
  `u32::MAX` (only reachable once section-03 threads arbitrary `RefreshConfig`
  leak rates through; not exercisable with today's fixed placeholder constants,
  but fixed now while the function is fresh).
- `PopularityBucket`'s doc comment no longer claims popularity state is
  unconditionally "gone in the same operation" a domain's data is gone — it now
  names the two removal points precisely and notes `sweep_stale_namespace`
  doesn't go through either of them, so a bucket can outlive a domain's data via
  that one path. This is an accepted gap (matches the plan's explicit "leave
  `sweep_stale_namespace` untouched" scope), just documented accurately instead
  of overclaimed.
- Added a short "Popularity tracking" section to
  `docs/knowledge/resolver/caching/answer-cache.md` (Structure block + a new
  section after "Eviction"), since this is the first user-visible mention of
  the new field per `AGENTS.md`'s Knowledge Bundle requirement. Kept brief —
  the full auto-refresh design doc lands in section-07.

**Follow-up deviation (from section-02's implementation):** `LeakRate` was
originally defined here as `pub(crate) struct LeakRate` in `shard.rs`, as
planned. When section-02 implemented `RefreshConfig`, it discovered its own
plan text independently specified a second, conflicting `pub struct
LeakRate` in `config::mod` — the two section plans, written by
non-communicating parallel subagents, each assumed the other side would
reference their definition. Resolved in section-02's diff: `LeakRate` now
lives once, as `pub struct LeakRate` in `config::mod` (required since it
must be `pub` to appear on `RefreshConfig`'s public field), and this file
imports it via `use crate::config::LeakRate;` instead of defining its own
copy. See `section-02-refresh-config.md`'s Implementation Notes for the full
rationale. Everything else in this section (`PopularityBucket`, the
`ShardState.popularity` field, removal wiring, `record_popularity_hit`,
the 4 `lookup_hop` call sites) is unaffected — only `LeakRate`'s definition
site moved.

**Test coverage: 32 tests in `shard.rs`'s test module** (up from the plan's
minimum ask of one end-to-end wiring test). Beyond the 9 listed in the original
plan, code review prompted 4 more: `lookup_hop_cname_hop_hit_increments_popularity_level`,
`lookup_hop_nodata_hit_increments_popularity_level`,
`lookup_hop_nxdomain_hit_increments_popularity_level` (covering the 3 call sites
the plan's single wiring test didn't reach), and
`popularity_bucket_drain_with_non_unit_leak_rate` (covering the
`leak_rate.units != 1` case the original fixture-based tests never exercised).

All of `RUST.md`'s gates pass: `cargo fmt`, `cargo clippy --all-targets`
(warning-free), `cargo test` (full suite, 619 lib tests passing).

**Second follow-up deviation (from section-04's implementation):** the
`DEFAULT_POPULARITY_LEAK_RATE`/`DEFAULT_POPULARITY_HIT_INCREMENT`/
`DEFAULT_POPULARITY_BUCKET_CAPACITY` placeholder constants described above
were removed. Section-04, forced to resolve a section-03 integration gap,
threaded a real `&RefreshConfig` into `lookup_hop`'s signature — exactly the
replacement this section's own doc comment anticipated ("these placeholders
get replaced by real `RefreshConfig`-sourced values when section-03 changes
`lookup_hop`'s signature" — it ended up being section-04, not section-03,
that did this). `record_popularity_hit`'s call sites now read
`refresh_config.enabled`/`.leak_rate`/`.hit_increment`/`.bucket_capacity`
directly. See `section-04-chainlookup-plumbing.md`'s Implementation Notes
for the full rationale.