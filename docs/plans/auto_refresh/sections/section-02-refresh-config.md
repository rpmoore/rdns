# section-02-refresh-config: `RefreshConfig` and its raw/TOML plumbing

## Dependencies

None. This section is standalone and can be implemented in parallel with
`section-01-popularity-bucket`. It touches only `src/config/mod.rs`.

**Downstream note (informational only, not part of this section's scope):**
`section-01-popularity-bucket`'s `PopularityBucket::drain_and_increment` and
`section-03-trigger-formula`'s eligibility/lead-window/hot-threshold logic both
read the types defined here (`RefreshConfig`, `LeakRate`) once those later
sections are implemented. Nothing in *this* section needs to know about
`PopularityBucket` or the trigger formula — it only needs to produce a
config struct whose shape those later sections can consume.

## Background

`rdns`'s runtime configuration lives in `src/config/mod.rs`. `RuntimeConfig` is
the top-level struct; it's built either programmatically (`RuntimeConfig::new`,
`RuntimeConfig::development_default`) or parsed from TOML via
`RawRuntimeConfig` → `TryFrom<RawRuntimeConfig> for RuntimeConfig` (raw shadow
struct pattern used throughout this file so that TOML deserialization and
validation stay separate from the trusted, already-validated runtime type).

`CacheConfig` (`src/config/mod.rs:341-445`) is the exact template to follow for
`RefreshConfig`: a small `Copy` struct with a `Default` impl, a `RawCacheConfig`
shadow struct with per-field `#[serde(default = "...")]` and
`#[serde(deny_unknown_fields)]`, a `try_into_cache_config` conversion method,
and a `validate()` method wired into `RuntimeConfig::validate()`.

This section adds a new `RefreshConfig` section following that same
three-piece shape, giving the auto-refresh feature (implemented in later
sections) its tunables: bucket capacity/leak rate/hit increment (popularity
bucket), hot-threshold fraction, lead-window ratio/floor, eligibility floor,
and worker pool sizing (worker count, channel capacity), plus the master
`enabled` flag.

## Tests first

Add these to the existing `#[cfg(test)] mod tests` block in
`src/config/mod.rs` (it already contains `CacheConfig`'s equivalent tests —
follow their exact style: build TOML via a `valid_toml()` helper plus
`.push_str(...)` for section overrides, call `RuntimeConfig::from_toml_str`,
assert on the parsed struct or the returned `ConfigError`).

Write these tests before writing the implementation code below (prose intent
only — the implementer writes the actual assertions):

- `refresh_config_defaults_match_spec`: `RefreshConfig::default()` produces
  every value in the defaults table below exactly (`enabled: true`,
  `bucket_capacity: 10`, `leak_rate` equivalent to 1 unit/60s,
  `hit_increment: 1`, `hot_threshold_fraction: 0.5`, `lead_ratio: 0.10`,
  `min_lead: 5s`, `eligibility_floor: 15s`, `worker_count: 4`,
  `channel_capacity: 256`).
- `refresh_config_defaults_when_absent`: parsing TOML with no `[refresh]`
  table at all produces `RefreshConfig::default()` (mirrors
  `cache_config_defaults_when_absent`, `config/mod.rs:2535`).
- `refresh_config_explicit_override`: a `[refresh]` TOML section overriding a
  subset of fields produces the overridden values, with the rest still
  defaulted (mirrors `cache_config_explicit_override`, `config/mod.rs:2541`,
  and TDD's `raw_refresh_config_deserializes_with_partial_toml`).
- `raw_refresh_config_rejects_unknown_fields`: an unrecognized key inside
  `[refresh]` fails parsing due to `#[serde(deny_unknown_fields)]` (mirrors
  existing `deny_unknown_fields` tests elsewhere in this file for other Raw
  structs).
- `refresh_config_validate_rejects_out_of_range_hot_threshold`:
  `hot_threshold_fraction` outside `0.0..=1.0` (e.g. `1.5` or `-0.1`) fails
  `RuntimeConfig::from_toml_str` with the new `ConfigError` variant for this
  case.
- `refresh_config_validate_rejects_zero_worker_count`: `worker_count = 0`
  fails validation.
- `refresh_config_validate_rejects_zero_channel_capacity`: `channel_capacity
  = 0` fails validation.
- `refresh_config_validate_accepts_default`: `RefreshConfig::default()` passes
  `validate()` (mirrors `cache_config_validate_accepts_default`,
  `config/mod.rs:2707`).

Note: TDD's `refresh_config_disabled_skips_worker_spawn` and
`e2e_disabled_feature_is_true_no_op` (worker spawn / popularity allocation
behavior when `enabled = false`) belong to later sections
(`section-05-worker-pool-metrics`, `section-01-popularity-bucket`,
`section-07-integration`) since they exercise code this section doesn't
touch. This section is only responsible for the `enabled: bool` field
existing, defaulting to `true`, and round-tripping correctly through TOML.

## Implementation

All changes are in `src/config/mod.rs`.

### 1. `LeakRate` type

Introduce a small `Copy` type expressing "how much popularity-bucket level
drains per unit of elapsed time," as whole `units` per `per` duration (e.g.
`units: 1, per: Duration::from_secs(60)` for "1 unit per 60 seconds"). This
keeps the value representable without floats, matching
`section-01-popularity-bucket`'s integer-arithmetic requirement for drain
calculations:

```rust
/// Popularity-bucket leak rate: `units` drained per `per` elapsed duration.
/// Deliberately not a float ratio — downstream drain-rate arithmetic
/// (`PopularityBucket::drain_and_increment`, owned by
/// `cache::shard`) needs to stay in integer arithmetic to avoid long-uptime
/// rounding drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeakRate {
    pub units: u32,
    pub per: Duration,
}
```

### 2. `RefreshConfig` struct

Add alongside `CacheConfig`:

```rust
/// Configuration for the auto-refresh (proactive TTL-refresh) feature.
///
/// `enabled = false` makes the entire feature a no-op: no `PopularityBucket`
/// is ever allocated, no worker tasks are spawned, no refresh signal is ever
/// produced (enforced by later sections that read this flag at their own
/// call sites — this struct only carries the flag).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RefreshConfig {
    pub enabled: bool,
    pub bucket_capacity: u32,
    pub leak_rate: LeakRate,
    pub hit_increment: u32,
    /// Fraction of `bucket_capacity` a domain's popularity level must reach
    /// or exceed to be considered "hot." Must be in `0.0..=1.0`.
    pub hot_threshold_fraction: f32,
    /// Fraction of a record's original TTL used as the refresh lead window
    /// (`remaining_ttl <= max(original_ttl * lead_ratio, min_lead)`).
    pub lead_ratio: f32,
    pub min_lead: Duration,
    /// Minimum original TTL for a record to be refresh-eligible at all.
    pub eligibility_floor: Duration,
    pub worker_count: usize,
    pub channel_capacity: usize,
}
```

**Correction to the source plan's derive list:** `claude-plan.md` §5 shows this
struct deriving `Eq` alongside `PartialEq`. That does not compile: `f32` (used
by `hot_threshold_fraction` and `lead_ratio`) does not implement `Eq` (its
`PartialEq` is not reflexive because of `NaN`), so `#[derive(Eq)]` on a struct
containing an `f32` field fails to compile. Derive only
`Debug, Clone, Copy, PartialEq` here — `assert_eq!` in tests only requires
`PartialEq` + `Debug`, so this doesn't affect the test style shown above.

**Ripple effect on two existing types — required, not optional:**
`RuntimeConfig` (`src/config/mod.rs:29-42`) currently derives
`Debug, Clone, PartialEq, Eq` and gains a new `pub refresh: RefreshConfig`
field (below). Since `RefreshConfig` isn't `Eq`, `RuntimeConfig`'s derive must
drop `Eq` too (keep `PartialEq`). Confirmed by inspection that nothing in this
codebase requires `RuntimeConfig: Eq` (no `HashSet<RuntimeConfig>` or similar
usage) — only `PartialEq`+`Debug` for test assertions, which is unaffected.
Apply this one-line derive-list edit to `RuntimeConfig` as part of this
section's diff.

### 3. Defaults

```rust
impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bucket_capacity: 10,
            leak_rate: LeakRate {
                units: 1,
                per: Duration::from_secs(60),
            },
            hit_increment: 1,
            hot_threshold_fraction: 0.5,
            lead_ratio: 0.10,
            min_lead: Duration::from_secs(5),
            eligibility_floor: Duration::from_secs(15),
            worker_count: 4,
            channel_capacity: 256,
        }
    }
}
```

| Field | Default |
|---|---|
| `enabled` | `true` |
| `bucket_capacity` | `10` |
| `leak_rate` | 1 unit / 60s |
| `hit_increment` | `1` |
| `hot_threshold_fraction` | `0.5` |
| `lead_ratio` | `0.10` |
| `min_lead` | `5s` |
| `eligibility_floor` | `15s` |
| `worker_count` | `4` |
| `channel_capacity` | `256` |

Confirmed during interview as a deliberate, conservative default-on choice
(see `claude-plan.md` §5's "Why default-on is justified" note) — do not change
`enabled`'s default to `false` without checking that rationale; it isn't this
section's call to revisit.

### 4. `validate()`

```rust
impl RefreshConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(0.0..=1.0).contains(&self.hot_threshold_fraction) {
            return Err(ConfigError::InvalidRefreshHotThresholdFraction {
                value: self.hot_threshold_fraction,
            });
        }
        if self.worker_count == 0 {
            return Err(ConfigError::InvalidRefreshWorkerCount {
                value: self.worker_count,
            });
        }
        if self.channel_capacity == 0 {
            return Err(ConfigError::InvalidRefreshChannelCapacity {
                value: self.channel_capacity,
            });
        }
        Ok(())
    }
}
```

Wire into `RuntimeConfig::validate()` (`src/config/mod.rs:123-211`) the same
way `self.cache.validate()?;` is called today — add `self.refresh.validate()?;`
right after (or near) that line.

### 5. New `ConfigError` variants

Add to the `ConfigError` enum (`src/config/mod.rs:1226-1341`):

```rust
InvalidRefreshHotThresholdFraction { value: f32 },
InvalidRefreshWorkerCount { value: usize },
InvalidRefreshChannelCapacity { value: usize },
```

**Same derive issue as above applies here too:** `ConfigError`
(`src/config/mod.rs:1225`) currently derives
`Debug, Clone, PartialEq, Eq`. Adding an `f32` field
(`InvalidRefreshHotThresholdFraction { value: f32 }`) means `Eq` must be
dropped from `ConfigError`'s derive list as well, for the identical reason.
Confirmed by inspection that nothing in this file or elsewhere requires
`ConfigError: Eq` — every existing use is `assert_eq!(error, ConfigError::...)`
in tests, which needs only `PartialEq` + `Debug`. `ConfigError` has no
`Display`/`std::error::Error` impl in this file today (checked by search — it
is a plain `Debug`-only, structurally-compared error type), so there is no
exhaustive-`match` `Display` arm to update elsewhere; the enum variants
themselves are the only place needing new arms.

### 6. `RawRefreshConfig` shadow struct

Follow `RawCacheConfig`'s pattern exactly (`src/config/mod.rs:1390-1410`):
per-field `#[serde(default = "...")]`, `Duration` fields represented as
millisecond `u64`s in the raw struct (matching `per_query_deadline_ms`,
`timeout_ms`, `per_authority_timeout_ms` elsewhere in this file), converted to
`Duration` in the `try_into_*` method:

```rust
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRefreshConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_refresh_bucket_capacity")]
    bucket_capacity: u32,
    #[serde(default = "default_refresh_leak_rate_units")]
    leak_rate_units: u32,
    #[serde(default = "default_refresh_leak_rate_per_ms")]
    leak_rate_per_ms: u64,
    #[serde(default = "default_refresh_hit_increment")]
    hit_increment: u32,
    #[serde(default = "default_refresh_hot_threshold_fraction")]
    hot_threshold_fraction: f32,
    #[serde(default = "default_refresh_lead_ratio")]
    lead_ratio: f32,
    #[serde(default = "default_refresh_min_lead_ms")]
    min_lead_ms: u64,
    #[serde(default = "default_refresh_eligibility_floor_ms")]
    eligibility_floor_ms: u64,
    #[serde(default = "default_refresh_worker_count")]
    worker_count: usize,
    #[serde(default = "default_refresh_channel_capacity")]
    channel_capacity: usize,
}

impl RawRefreshConfig {
    fn try_into_refresh_config(self) -> Result<RefreshConfig, ConfigError> {
        Ok(RefreshConfig {
            enabled: self.enabled,
            bucket_capacity: self.bucket_capacity,
            leak_rate: LeakRate {
                units: self.leak_rate_units,
                per: Duration::from_millis(self.leak_rate_per_ms),
            },
            hit_increment: self.hit_increment,
            hot_threshold_fraction: self.hot_threshold_fraction,
            lead_ratio: self.lead_ratio,
            min_lead: Duration::from_millis(self.min_lead_ms),
            eligibility_floor: Duration::from_millis(self.eligibility_floor_ms),
            worker_count: self.worker_count,
            channel_capacity: self.channel_capacity,
        })
    }
}
```

`default_true` already exists (`src/config/mod.rs:1667`, reused by
`RawMetricsConfig`/`RawChaosConfig`) — reuse it rather than adding a new
identical helper. Add the ten `default_refresh_*` free functions, each
sourcing its value from `RefreshConfig::default()` (mirroring
`default_cache_max_entries() -> usize { CacheConfig::default().max_entries }`,
`src/config/mod.rs:1399-1401`), so the raw-struct defaults and the
`Default for RefreshConfig` impl can never drift apart:

```rust
fn default_refresh_bucket_capacity() -> u32 {
    RefreshConfig::default().bucket_capacity
}
fn default_refresh_leak_rate_units() -> u32 {
    RefreshConfig::default().leak_rate.units
}
fn default_refresh_leak_rate_per_ms() -> u64 {
    RefreshConfig::default().leak_rate.per.as_millis() as u64
}
fn default_refresh_hit_increment() -> u32 {
    RefreshConfig::default().hit_increment
}
fn default_refresh_hot_threshold_fraction() -> f32 {
    RefreshConfig::default().hot_threshold_fraction
}
fn default_refresh_lead_ratio() -> f32 {
    RefreshConfig::default().lead_ratio
}
fn default_refresh_min_lead_ms() -> u64 {
    RefreshConfig::default().min_lead.as_millis() as u64
}
fn default_refresh_eligibility_floor_ms() -> u64 {
    RefreshConfig::default().eligibility_floor.as_millis() as u64
}
fn default_refresh_worker_count() -> usize {
    RefreshConfig::default().worker_count
}
fn default_refresh_channel_capacity() -> usize {
    RefreshConfig::default().channel_capacity
}
```

### 7. Wiring into `RuntimeConfig` and `RawRuntimeConfig`

Add the field to `RuntimeConfig` (`src/config/mod.rs:29-42`):

```rust
pub struct RuntimeConfig {
    // ...existing fields...
    pub cache: CacheConfig,
    pub chaos: ChaosConfig,
    pub refresh: RefreshConfig,
}
```

(Placement within the struct doesn't matter; append after `chaos` to match the
plan's ordering in `claude-plan.md` §5, or place it however the existing file
groups related config — not load-bearing.)

Update every existing `RuntimeConfig` struct literal in this file to include
`refresh: RefreshConfig::default()`:
- `RuntimeConfig::new_with_resolution` (`src/config/mod.rs:71-87`)
- `RuntimeConfig::development_default` (`src/config/mod.rs:89-113`)

Add to `RawRuntimeConfig` (`src/config/mod.rs:1343-1365`):

```rust
struct RawRuntimeConfig {
    // ...existing fields...
    #[serde(default)]
    chaos: Option<RawChaosConfig>,
    #[serde(default)]
    refresh: Option<RawRefreshConfig>,
}
```

Update `impl TryFrom<RawRuntimeConfig> for RuntimeConfig`
(`src/config/mod.rs:1696-1757`) to parse it the same way `cache`/`chaos` are
parsed:

```rust
let refresh = raw
    .refresh
    .map(RawRefreshConfig::try_into_refresh_config)
    .transpose()?
    .unwrap_or_default();
```

and include `refresh,` in the `RuntimeConfig { ... }` literal built at the end
of that function, alongside `cache,` and `chaos,`.

### Summary of all edits in this section

All within `src/config/mod.rs`:

1. New `LeakRate` struct (`Debug, Clone, Copy, PartialEq, Eq`).
2. New `RefreshConfig` struct (`Debug, Clone, Copy, PartialEq` — **not** `Eq`,
   correcting the source plan) + its `Default` impl.
3. `RefreshConfig::validate()`.
4. Three new `ConfigError` variants; drop `Eq` from `ConfigError`'s derive
   list (keep `PartialEq`).
5. Drop `Eq` from `RuntimeConfig`'s derive list (keep `PartialEq`) — required
   because it now embeds a non-`Eq` `RefreshConfig`.
6. New `RawRefreshConfig` shadow struct + `try_into_refresh_config` + ten
   `default_refresh_*` helper functions.
7. New `refresh: RefreshConfig` field on `RuntimeConfig`; new
   `refresh: Option<RawRefreshConfig>` field on `RawRuntimeConfig`; wiring in
   `TryFrom<RawRuntimeConfig>`, `RuntimeConfig::validate()`,
   `RuntimeConfig::new_with_resolution`, and
   `RuntimeConfig::development_default`.

### Verification

Standard gates before this section is considered done: `cargo fmt`, `cargo
clippy`, `cargo test` (per `RUST.md`) — run scoped to `src/config/mod.rs`'s
test module at minimum, full suite before merging since the `RuntimeConfig`
struct-literal changes touch every existing config-construction call site in
this file.

## Implementation Notes (post-implementation)

**Deviation from plan — `LeakRate` placement.** Section-01
(`section-01-popularity-bucket`, implemented first) had already defined its
own `pub(crate) struct LeakRate` inside `src/resolver/cache/shard.rs`,
independently of this section's plan text specifying a *second*,
conflicting `pub struct LeakRate` inside `config::mod` — two parallel
planning subagents each assumed the other side would reference their
definition. Resolved during implementation: `LeakRate` is defined **once**,
as `pub struct LeakRate` in `config::mod` (as this section's plan specifies)
— required because it must be `pub`, not `pub(crate)`, to appear on
`RefreshConfig`'s public field (`RefreshConfig` is used by `main.rs`, a
separate binary crate). `src/resolver/cache/shard.rs` was updated to
`use crate::config::LeakRate;` instead of keeping its own duplicate
definition. Confirmed by code review as the only workable direction:
`resolver::cache`/`resolver::cache::shard` are private modules, so `config`
could never reach a type defined there regardless of the item's own
visibility, and keeping two separate types with a manual conversion was
rejected as reintroducing the exact drift risk section-01's own doc comment
warned against.

**Deviation from plan — expanded `validate()`.** The plan's `validate()`
covered only `hot_threshold_fraction`, `worker_count`, and
`channel_capacity`. Code review flagged the remaining fields
(`lead_ratio`, `bucket_capacity`, `hit_increment`, `leak_rate.units`/`.per`)
as unguarded; user chose to expand validation now rather than defer to
section-03. Added `InvalidRefreshLeadRatio`, `InvalidRefreshBucketCapacity`,
`InvalidRefreshHitIncrement`, and `InvalidRefreshLeakRate` (covers both
`units == 0` and `per.is_zero()`) `ConfigError` variants, plus their checks
and 5 corresponding tests.

**Test coverage**: 20 tests added to `config::tests` (up from the plan's 8
listed) — `refresh_config_explicit_override` was expanded to override and
assert all 10 `RefreshConfig` fields (matching `cache_config_explicit_override`'s
100%-field-coverage style, per code review), plus the 5 new validation
rejection tests above.

All of `RUST.md`'s gates pass: `cargo fmt`, `cargo clippy --all-targets`
(warning-free), `cargo test` (full suite, 632 lib tests passing).