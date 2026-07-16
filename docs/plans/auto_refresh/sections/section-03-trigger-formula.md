Now I have enough context. Let me produce the section content.

---

# Section 03: Refresh Trigger Formula

## Purpose

This section adds the pure, side-effect-free arithmetic that decides whether a live cache entry currently "wants" a proactive background refresh. It sits conceptually alongside — but does not replace or modify — the existing `entry.expires_at <= now` expiry check already performed by `Shard::lookup_hop`'s live-entry probes (`take_live_positive`/`take_live_cname_hop`, `src/resolver/cache/shard.rs:163-231`).

This section only adds the pure trigger-formula function (and its unit tests) to `src/resolver/cache/shard.rs`. It does **not** wire that function into `ChainLookup`/`resolve_from_cache`/`probe_cache` — that plumbing is section-04's job, which depends on this section's function being available to call during its hop walk.

## File(s) touched

- `src/resolver/cache/shard.rs` (new pure function + unit tests, added near the existing `take_live_positive`/`take_live_cname_hop` methods)

## Dependencies

- **section-01-popularity-bucket**: provides `PopularityBucket` (with `level: u32`, `last_drained: SystemTime`) and its `is_hot(&self, hot_threshold: u32) -> bool` method, both living in `src/resolver/cache/shard.rs`. This section calls `is_hot` but does not modify `PopularityBucket` itself.
- **section-02-refresh-config**: provides `RefreshConfig` (in `src/config/mod.rs`) with the fields `hot_threshold_fraction: f32`, `lead_ratio: f32`, `min_lead: Duration`, `eligibility_floor: Duration`, and `bucket_capacity: u32`. This section reads those fields but does not modify `RefreshConfig` itself. Add `use crate::config::RefreshConfig;` to `shard.rs`.

Both dependencies must already be merged/implemented before this section starts (per the dependency graph in `docs/plans/auto_refresh/sections/index.md`, section-03 depends on section-01 and section-02, and is parallelizable against section-05).

## Background: what data is already available

`RRsetEntry` (`src/resolver/cache/entry.rs:43-80`) stores, among other fields:

```rust
pub struct RRsetEntry {
    pub records: Vec<StoredRecord>,
    pub rrsigs: Vec<StoredRecord>,
    pub response_code: ResponseCode,
    pub minimum_ttl: Duration,   // the TTL the entry was stored with — "original TTL"
    pub stored_at: SystemTime,
    pub expires_at: SystemTime, // == stored_at + minimum_ttl at store time
    pub dnssec_state: DnssecState,
    pub cache_epoch: u64,
    pub dnssec_complete: bool,
    pub authoritative: bool,
}
```

- **"Original TTL"** (as used in the trigger formula) is `entry.minimum_ttl` — the TTL value the entry was stored with, confirmed by `stored_record_preserves_original_ttl_independent_of_entry_minimum_ttl` (`entry.rs:306`) and by `rrset_entry`'s test helper computing `expires_at: now + minimum_ttl` (`entry.rs:267`). This is *not* the remaining TTL.
- **"Remaining TTL"** is derived at call time: `entry.expires_at.duration_since(now)` (or equivalent saturating arithmetic — never panic or underflow if `now` happens to be at or past `expires_at`; treat that case as zero remaining TTL, since the live-entry probes only call this on entries that already passed their own `expires_at <= now` liveness check).

`Shard::lookup_hop` (`shard.rs:405-463`) and its live-entry probes already take `now: SystemTime` as an explicit parameter (not an injected clock trait — this module intentionally does not use the `Clock`/`SystemClock`/`FixedClock` abstraction that exists one layer up in `src/resolver/mod.rs`). Tests fake time the same way existing shard tests do: explicit offsets like `now - Duration::from_secs(...)`, not a mock clock object.

## Tests first

Add these as `#[test]` functions in `shard.rs`'s existing `#[cfg(test)] mod tests` block (plain `#[test]`, no `#[tokio::test]` needed — this is pure in-memory arithmetic). Use small fixture helpers matching the module's existing style (e.g. a helper that builds a `RefreshConfig` with known values, and a helper that builds a `PopularityBucket` at a given level). Write these tests *before* implementing the trigger function, per the TDD companion plan.

From `claude-plan-tdd.md` §3.1:

- `trigger_requires_eligibility_floor`: an entry with original TTL (`minimum_ttl`) below `eligibility_floor` never signals a refresh, regardless of remaining TTL or popularity — even if it's both hot and deep inside what would otherwise be the lead window.
- `trigger_fires_within_lead_window`: an eligible, hot entry with `remaining_ttl <= max(original_ttl * lead_ratio, min_lead)` signals refresh; an entry just outside that window (all else equal) does not.
- `trigger_requires_hot_popularity`: an eligible, in-lead-window entry whose domain's bucket is not hot (`is_hot()` false) does not signal refresh.
- `trigger_boundary_at_exact_lead_window_edge`: exact-equality case at the lead-window `<=` boundary — `remaining_ttl` exactly equal to `max(original_ttl * lead_ratio, min_lead)` must fire (the formula is `<=`, not `<`).
- `trigger_boundary_at_exact_eligibility_floor`: exact-equality case where `original_ttl == eligibility_floor` exactly — this must still count as eligible (the formula is `>=`, not `>`).

Additional cases worth covering explicitly to pin down behavior not spelled out as a named test but implied by the formula and by this function needing to be usable safely from section-04's hop walk:

- A domain with no `PopularityBucket` at all (never hit, or evicted) is treated as not hot — never signals refresh, regardless of the other two gates. (This matters because section-04's hop walk will need to call this for hops whose domain might not be in the popularity map at all, e.g. a domain that was just now stored for the first time.)
- `min_lead` dominates when `original_ttl * lead_ratio` is smaller than `min_lead` (e.g. a short-but-still-eligible TTL), and vice versa when `original_ttl * lead_ratio` is larger — both directions of the `max(...)` should be exercised so the test suite doesn't accidentally pass with the `max` silently swapped for `min` or one branch hardcoded.

## Implementation

Add a pure, standalone function to `src/resolver/cache/shard.rs`, placed near `take_live_positive`/`take_live_cname_hop` (it is conceptually their sibling check, even though it is not called from inside them in this section — section-04 wires the call site). Mark it `pub(crate)` so `cache::assemble` (section-04) can call it directly:

```rust
/// Pure trigger-formula check (plan §3.1). Given a live entry's own TTL
/// data, the domain's current popularity bucket (if any — a domain that
/// has never been hit, or whose bucket was evicted alongside its LRU
/// entry, has no bucket and is therefore never hot), and refresh-config
/// thresholds, decides whether the entry currently "wants" a proactive
/// background refresh.
///
/// This does not mutate anything, perform any I/O, or take any lock
/// beyond what the caller already holds — it is a pure function of data
/// the live-entry probes (`take_live_positive`/`take_live_cname_hop`)
/// already have in hand. It also does not change what those probes
/// return as the *served* answer; it only decides whether to *additionally*
/// signal "this entry wants a refresh" (consumed by section-04's
/// `ChainLookup`/`RefreshHint` plumbing).
///
/// All three independent gates must hold for this to return `true`:
/// 1. **Eligibility floor**: `original_ttl >= config.eligibility_floor`.
///    Entries below this floor are never refresh-eligible regardless of
///    remaining TTL or popularity — this exists to avoid refresh thrash on
///    very-short-TTL records.
/// 2. **Lead window**: `remaining_ttl <= max(original_ttl * config.lead_ratio,
///    config.min_lead)`.
/// 3. **Popularity**: the domain's bucket, if present, is hot at the
///    threshold derived from `config.hot_threshold_fraction *
///    config.bucket_capacity` (rounded to a `u32`); a missing bucket
///    (`None`) is never hot.
pub(crate) fn wants_refresh(
    original_ttl: Duration,
    remaining_ttl: Duration,
    bucket: Option<&PopularityBucket>,
    config: &RefreshConfig,
) -> bool {
    todo!()
}
```

Implementation notes for the function body:

- **Eligibility gate**: `original_ttl >= config.eligibility_floor`. Short-circuit `false` immediately if this fails — no need to evaluate the other two gates (though evaluating them anyway would still be correct, since all three must hold; short-circuiting is just cheaper and clearer to read).
- **Lead-window gate**: compute `lead = max(original_ttl.mul_f32(config.lead_ratio), config.min_lead)` — use `Duration::mul_f32` (or an equivalent that keeps this in integer-friendly `Duration` arithmetic; avoid converting to raw floats and back where a `Duration` API already does the job) — then check `remaining_ttl <= lead`.
- **Popularity gate**: derive `hot_threshold` from `config.hot_threshold_fraction * config.bucket_capacity as f32`, rounded to `u32` (document the rounding choice — e.g. round-to-nearest — in a comment, since this is the one place fractional-to-absolute-count conversion happens), then call `bucket.is_some_and(|b| b.is_hot(hot_threshold))`.
- Combine all three with `&&`; return the combined boolean directly — no early return needed once the three sub-expressions are computed, but short-circuiting on the eligibility gate first is a reasonable, cheap optimization worth keeping since it's also the simplest gate to evaluate.

`Duration` arithmetic throughout — no floats leak into the final boolean comparison beyond the one `hot_threshold` derivation and the one `lead_ratio` multiply, both of which are inherent to how the config expresses these as fractions (per section-02's `RefreshConfig` shape: `hot_threshold_fraction: f32`, `lead_ratio: f32`).

## Non-goals for this section

- Does not touch `ChainLookup`, `resolve_from_cache`, or `probe_cache` — that is section-04.
- Does not modify `take_live_positive`, `take_live_cname_hop`, or `lookup_hop`'s signatures or return types.
- Does not modify `PopularityBucket` or `RefreshConfig` themselves (those are section-01/section-02's surfaces respectively) — this section only consumes them.
- Does not add any new `ResolverMetric` variants (that's section-05) or perform any enqueue (section-04/section-05).

## Verification

Standard gates before this section is considered done (per `RUST.md`): `cargo fmt`, `cargo clippy`, `cargo test` — specifically the new `trigger_*` unit tests in `src/resolver/cache/shard.rs` passing, plus no regression in the existing `lookup_hop_*` test suite in the same file (this section adds a new function alongside them; it does not change their behavior).

---

Relevant file paths:
- `/home/rpmoore/code/rdns/src/resolver/cache/shard.rs` (implementation target for this section)
- `/home/rpmoore/code/rdns/src/resolver/cache/entry.rs` (background reference only — `RRsetEntry`/`minimum_ttl`/`expires_at`, not modified by this section)
- `/home/rpmoore/code/rdns/src/config/mod.rs` (background reference only — `RefreshConfig`, provided by section-02, not modified by this section)
- Output written to `/home/rpmoore/code/rdns/docs/plans/auto_refresh/sections/section-03-trigger-formula.md`

## Implementation Notes (post-implementation)

Implemented as planned: `wants_refresh(original_ttl, remaining_ttl, bucket,
config) -> bool` added to `src/resolver/cache/shard.rs`, placed right after
`impl ShardState`'s `take_live_negative`, `pub(crate)` visibility, exact
three-gate formula (eligibility floor `>=`, lead window `<=` via
`max(original_ttl.mul_f32(lead_ratio), min_lead)`, popularity via rounded
`hot_threshold_fraction * bucket_capacity`). Deliberately unwired — no calls
from `lookup_hop`/`ChainLookup`/`probe_cache` yet (section-04's job).

**Test coverage: 16 `trigger_*` tests** (up from the plan's 7 named + 2
additional cases). Code review prompted 2 more, both fixing/expanding
existing coverage rather than testing new behavior:
- `trigger_boundary_at_exact_lead_window_edge` was rewritten to use
  `lead_ratio = 0.25` (exactly representable in f32, unlike the default
  `0.10`) so the `<=`-vs-`<` boundary assertion is actually meaningful — the
  original version's `remaining_ttl = 30s` passed regardless of which
  operator was used, since `300s * 0.10` doesn't compute to exactly 30s in
  f32 floating point.
- Added `trigger_hot_threshold_fraction_zero_makes_any_existing_bucket_hot`
  and `trigger_hot_threshold_fraction_one_requires_bucket_at_full_capacity`,
  covering `hot_threshold_fraction`'s valid extremes (0.0 disables the
  popularity gate entirely; 1.0 requires the bucket at exactly
  `bucket_capacity`) — both reachable via `RefreshConfig::validate`'s
  inclusive `0.0..=1.0` range and previously untested.

All of `RUST.md`'s gates pass: `cargo fmt`, `cargo clippy --all-targets`
(warning-free), `cargo test` (full suite, 642 lib tests passing).