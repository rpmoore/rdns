Now I have complete grounding. Writing the section content.

---

# section-05-dnssec-status-metrics

## Scope

Plan reference: `claude-plan.md` §A7 ("Status, mode, and metrics").

This section makes the DNSSEC feature **observable**: it adds the `Enabled`
variant to the existing (currently `Disabled`-only) `DnssecValidationMode` /
`DnssecValidationStatus` enums, flips the config default to `Enabled`, updates
every existing match arm/label producer the compiler and the plan both call
out, and adds a new labeled per-outcome counter
(`dnssec_validation_results_total`) that is the *only* operator-visible way to
tell "validation ran and came back inconclusive" (`Indeterminate`) apart from
"validation never ran at all" (mode disabled, or the query never reached the
recursive validation path) — both of those collapse to the same
`DnssecState::Unvalidated` on the cache entry itself, so the counter is load
bearing for anyone trying to debug a DNSSEC rollout.

This section does **not** touch validator logic, entry construction, TTL
capping, or CD-bit gating — those are section-04's job and are assumed
already landed and working before this section starts (see Dependencies).

## Dependencies

- **section-04-dnssec-entry-wiring** must be complete first. This section
  assumes:
  - The section-03 validator function is already called, unconditionally, at
    the `ResolutionMode::Recursive` branch of `build_rrset_entry`
    (`src/resolver/mod.rs:1039-1064`) and `build_negative_entry`
    (`:1080-1120`), with its `DnssecState` result stored on the entry
    (replacing the old `Default::default()`).
  - `ResolutionMode::Forward` never reaches that call site.
  - CD-bit gating and serve-stale/Bogus exclusion are already correct and
    tested; not touched here.
- Everything in this section builds on code that exists **today**, before
  Track A starts, confirmed by direct inspection (line numbers below are
  current, not projected):
  - `src/config/mod.rs:1107-1118` — `DnssecValidationMode` enum +
    `cache_namespace_label()`.
  - `src/config/mod.rs:733`, `741`, `763` — where `dnssec_validation` lives
    on `RecursiveResolutionConfig` and its constructors.
  - `src/config/mod.rs:1905-1916` — TOML parsing of the `dnssec_validation`
    string, including the `None` (unspecified) branch that currently
    defaults to `Disabled`.
  - `src/config/mod.rs:258-280` (`backend_cache_namespace()`) — folds
    `dnssec_validation.cache_namespace_label()` into the recursive-mode
    cache-namespace fingerprint string, which feeds the cache-epoch bump
    logic documented in `docs/knowledge/resolver/caching/cache-epoch.md`.
  - `src/resolver/mod.rs:2417-2420` — `DnssecValidationStatus` enum.
  - `src/resolver/mod.rs:2499-2516` — `BackendSnapshot::new` currently
    **hardcodes** `dnssec_validation: DnssecValidationStatus::Disabled`
    unconditionally; there is no builder to override it (contrast with
    `with_root_hints_status` at `:2518`, which follows the correct pattern
    for this kind of post-construction override).
  - `src/main.rs:751-807` — `build_forward_backend_snapshot` /
    `build_recursive_backend_snapshot`, both of which call
    `BackendSnapshot::new(...)` and never set a DNSSEC status today.
  - `src/main.rs:868-929` — `OpenTelemetryMetrics` struct fields, including
    `dnssec_validation_disabled: Gauge<u64>` at `:916`.
  - `src/main.rs:1239-1298` — `record_backend_status`,
    `backend_status_attributes`, and `dnssec_validation_label`.
  - `src/resolver/mod.rs:8928-8971` — `MetricsSink` trait (`increment`,
    `observe_duration`, `record_backend_status` with a no-op default,
    `increment_with_source`/`observe_duration_with_source` with
    delegate-to-unlabeled defaults) and `NoopMetricsSink`.
  - `src/resolver/mod.rs:10693-10735` — the `RecordingMetrics` test double
    used throughout `resolver/mod.rs`'s test module, which implements
    `MetricsSink` and records everything into `Mutex<Vec<...>>` fields for
    assertions.

## Background: current state of the affected enums/functions

`DnssecValidationMode` (config-level) and `DnssecValidationStatus`
(runtime-status-level) both currently have exactly one variant:

```rust
// src/config/mod.rs:1107-1118
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecValidationMode {
    Disabled,
}

impl DnssecValidationMode {
    fn cache_namespace_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
        }
    }
}
```

```rust
// src/resolver/mod.rs:2417-2420
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DnssecValidationStatus {
    Disabled,
}
```

TOML parsing today defaults an unspecified `dnssec_validation` key to
`Disabled`:

```rust
// src/config/mod.rs:1905-1916 (inside try_into_recursive_resolution_config)
let dnssec_validation = match self.dnssec_validation.as_deref() {
    None | Some("disabled") => DnssecValidationMode::Disabled,
    Some(other) => {
        return Err(ConfigError::InvalidTomlConfig {
            message: format!("unknown dnssec_validation mode: {other}"),
        });
    }
};
```

An existing round-trip test pins this default and **must be updated** as
part of this section (it is not a new test, it's a regression the on-by-default
decision deliberately causes):

```rust
// src/config/mod.rs:3790-3819, toml_config_round_trip_loads_bundled_recursive_resolution
// ...
assert_eq!(recursive.dnssec_validation, DnssecValidationMode::Disabled); // must become Enabled
```

The status-reporting side (`main.rs`) reads `BackendStatus.dnssec_validation`
which is `DnssecValidationStatus`, not the config-level `DnssecValidationMode`
— these are two separate enums with the same shape by design (mirrors how
`ResolutionMode`/`ResolverResolutionMode` are similarly duplicated across the
config/resolver boundary elsewhere in this codebase):

```rust
// src/main.rs:1239-1298
fn record_backend_status(&self, status: &BackendStatus) {
    let attributes = backend_status_attributes(status);
    self.backend_generation.record(status.generation, &attributes);
    self.dnssec_validation_disabled.record(
        u64::from(status.dnssec_validation == DnssecValidationStatus::Disabled),
        &attributes,
    );
    // ...
}

fn backend_status_attributes(status: &BackendStatus) -> Vec<KeyValue> {
    let mut attributes = vec![
        KeyValue::new("mode", resolver_mode_label(status.mode)),
        KeyValue::new("health", backend_health_label(status.health)),
        KeyValue::new("dnssec_validation", dnssec_validation_label(status.dnssec_validation)),
    ];
    // ...
}

fn dnssec_validation_label(status: DnssecValidationStatus) -> &'static str {
    match status {
        DnssecValidationStatus::Disabled => "disabled",
    }
}
```

**Important gap found during grounding, in scope for this section**:
`BackendSnapshot::new` (`src/resolver/mod.rs:2499-2516`) unconditionally sets
`dnssec_validation: DnssecValidationStatus::Disabled`, and neither
`build_forward_backend_snapshot` nor `build_recursive_backend_snapshot`
(`src/main.rs:746-807`) ever overrides it. Without fixing this, the new
`Enabled` variant would be structurally valid but *never actually produced* by
the running resolver — the gauge/label would permanently read "disabled" in
production regardless of config. This section must close that loop, following
the existing `with_root_hints_status` builder pattern (`resolver/mod.rs:2518`)
rather than adding a new constructor parameter (keeps `BackendSnapshot::new`'s
signature stable for its many existing call sites).

## Tests first

Write these before making the corresponding code change; each should fail
against current (pre-section-05) code and pass once its matching change lands.

### Config mode (`src/config/mod.rs`)

1. `DnssecValidationMode::Enabled` and `::Disabled` each produce a **distinct**
   `cache_namespace_label()` output (compiler forces the match-arm update
   once `Enabled` exists; this test proves the *values* differ, not just that
   it compiles) — e.g. assert `Enabled` maps to `"enabled"` and `Disabled` to
   `"disabled"`, and that the two differ.
2. Config defaults to `DnssecValidationMode::Enabled` when the TOML
   `dnssec_validation` key is unspecified (matches the on-by-default
   decision) — update the existing
   `toml_config_round_trip_loads_bundled_recursive_resolution` test's
   assertion from `Disabled` to `Enabled` (config/mod.rs:3817), and add a
   companion test that an explicit `dnssec_validation = "disabled"` still
   parses to `Disabled` (no regression to the explicit opt-out path), and
   `dnssec_validation = "enabled"` explicitly parses to `Enabled`.
3. An unknown `dnssec_validation` string (anything other than
   `"enabled"`/`"disabled"`) still produces `ConfigError::InvalidTomlConfig`
   (no-regression check on the existing malformed-input branch).

### Status/label/gauge (`src/main.rs`)

4. `dnssec_validation_label` returns `"enabled"` for
   `DnssecValidationStatus::Enabled` and `"disabled"` for `::Disabled` (new
   direct unit test — none exists today for this function).
5. `record_backend_status`'s `dnssec_validation_disabled` gauge records `0`
   for a `BackendStatus` with `dnssec_validation: Enabled` and `1` for
   `Disabled` (construct a `BackendStatus` directly and call
   `record_backend_status` against a test `OpenTelemetryMetrics`, or exercise
   it through whatever the existing metrics test harness for gauges already
   does).
6. `build_recursive_backend_snapshot` produces a `BackendSnapshot` whose
   `dnssec_validation` status reflects `RecursiveResolutionConfig.dnssec_validation`
   from the runtime config (`Enabled` in → `DnssecValidationStatus::Enabled`
   out, `Disabled` in → `Disabled` out) — this is the test that closes the
   "gap found during grounding" above; it should fail against current code
   (which always produces `Disabled`) and pass once `BackendSnapshot` gets a
   `with_dnssec_validation_status` builder wired into `main.rs`.
7. `build_forward_backend_snapshot` always produces
   `DnssecValidationStatus::Disabled` regardless of any config value (Forward
   mode has no DNSSEC validation concept per A5's scope — no-regression
   check that Forward mode's status stays inert).

### Outcome counter (`src/resolver/mod.rs` + `src/main.rs`)

8. The new outcome counter increments exactly once per validated query, with
   the correct outcome label, for each of `Secure`/`Insecure`/`Bogus`/
   `Indeterminate` — drive this through the section-04 call site with a
   `RecordingMetrics`-style test double (mirroring
   `resolver/mod.rs:10693-10735`'s existing pattern) and assert on the
   recorded outcome value, not just that some counter incremented.
9. The counter's "validation never attempted" case is distinguishable from
   `Indeterminate` in at least these two scenarios, each producing a value
   different from all four `ValidationState`-derived outcomes and from each
   other's… no — different from `Indeterminate` specifically (both
   "mode disabled" and "never reached the recursive path" may share one
   `NotAttempted`-style bucket, but neither may share `Indeterminate`'s
   bucket):
   - `DnssecValidationMode::Disabled` — recursive resolution runs, entry
     construction happens, but the validator is not invoked at all.
   - A query that never reaches the recursive validation path at all (e.g.
     `ResolutionMode::Forward`) — assert no `Indeterminate` count is ever
     produced for Forward-mode traffic.
10. A `RecordingMetrics`-based test asserting `record_dnssec_validation_outcome`
    (or equivalent) is *not* called at all for `ResolutionMode::Forward`
    queries (Forward mode has no DNSSEC concept — silence, not a `NotAttempted`
    label, is the expected signal there; only the `DnssecValidationMode::Disabled`-in-Recursive-mode
    case gets an explicit `NotAttempted` label).

## Implementation

### 1. `DnssecValidationMode` (`src/config/mod.rs:1107-1118`)

Add the `Enabled` variant and update `cache_namespace_label()`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecValidationMode {
    Disabled,
    Enabled,
}

impl DnssecValidationMode {
    fn cache_namespace_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
        }
    }
}
```

This is a compiler-forced change (no wildcard arm exists today) — the
compiler will flag every other match on this enum. Update those non-test call
sites too if any exist beyond `cache_namespace_label` (grep confirms today
there are none besides that function and equality checks in tests).

Since `DnssecValidationMode::cache_namespace_label()` feeds
`Config::backend_cache_namespace()` (`config/mod.rs:258-280`), which feeds the
cache-epoch bump logic (`docs/knowledge/resolver/caching/cache-epoch.md`),
flipping the default from `Disabled` to `Enabled` **intentionally bumps the
cache namespace on upgrade** for every existing Recursive-mode deployment —
call this out explicitly in the PR description as a deliberate, one-time
cache invalidation on upgrade, not a regression (per the plan's guidance).

### 2. Default to `Enabled` (`src/config/mod.rs:1905-1916`)

```rust
let dnssec_validation = match self.dnssec_validation.as_deref() {
    None | Some("enabled") => DnssecValidationMode::Enabled,
    Some("disabled") => DnssecValidationMode::Disabled,
    Some(other) => {
        return Err(ConfigError::InvalidTomlConfig {
            message: format!("unknown dnssec_validation mode: {other}"),
        });
    }
};
```

`RecursiveResolutionConfig::bundled()` (`config/mod.rs:763`) still hardcodes
`DnssecValidationMode::Disabled` at construction, but this value is always
immediately overwritten by `config.dnssec_validation = dnssec_validation;` at
`config/mod.rs:1953` regardless of which root-hints branch (`bundled`/
`custom`) was taken — no change needed there, just confirm this overwrite
still fires for both branches (it already does today).

### 3. `DnssecValidationStatus` (`src/resolver/mod.rs:2417-2420`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DnssecValidationStatus {
    Disabled,
    Enabled,
}
```

### 4. Close the `BackendSnapshot` wiring gap

Add a builder to `BackendSnapshot`, mirroring `with_root_hints_status`
(`resolver/mod.rs:2518-2521`):

```rust
// near resolver/mod.rs:2518
pub fn with_dnssec_validation_status(mut self, status: DnssecValidationStatus) -> Self {
    self.dnssec_validation = status;
    self
}
```

Update `main.rs`'s two `BackendSnapshot::new(...)` call sites
(`build_forward_backend_snapshot` at `:746-758`,
`build_recursive_backend_snapshot` at `:760-807`):

- `build_forward_backend_snapshot`: no change to the produced status — stays
  `DnssecValidationStatus::Disabled` (the default `BackendSnapshot::new`
  already sets), since Forward mode has no DNSSEC concept per A5's scope.
  Add a small comment noting this is intentional, not an oversight, so a
  future reader doesn't "fix" it into `Enabled`.
- `build_recursive_backend_snapshot`: after constructing the snapshot, chain
  `.with_dnssec_validation_status(...)` with a value derived from
  `recursive.dnssec_validation` (the `DnssecValidationMode` read out of
  `RuntimeConfig`), via a small mapping:

```rust
fn dnssec_validation_status_for_mode(mode: DnssecValidationMode) -> DnssecValidationStatus {
    match mode {
        DnssecValidationMode::Disabled => DnssecValidationStatus::Disabled,
        DnssecValidationMode::Enabled => DnssecValidationStatus::Enabled,
    }
}
```

placed near `root_hints_source_label` (`main.rs:809`), following that
function's style (private free function, not a method on either enum, since
`config::DnssecValidationMode` and `resolver::DnssecValidationStatus` are
deliberately kept as separate types across the config/resolver boundary).

### 5. Label/gauge producers (`src/main.rs:1239-1298`)

```rust
fn dnssec_validation_label(status: DnssecValidationStatus) -> &'static str {
    match status {
        DnssecValidationStatus::Disabled => "disabled",
        DnssecValidationStatus::Enabled => "enabled",
    }
}
```

`record_backend_status`'s `dnssec_validation_disabled` gauge line
(`:1243-1246`) already reads correctly against the new variant with no code
change (`status.dnssec_validation == DnssecValidationStatus::Disabled`
naturally evaluates to `0` for `Enabled`) — this is covered by test #5 above
as a no-regression + new-variant check, not a code change.

### 6. New outcome counter

Add a small outcome enum near `DnssecValidationStatus`
(`resolver/mod.rs:2417-2420`), distinct from it — per the spec's explicit
decision, this is *not* a richer mode/status enum, it's metrics-only:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecValidationOutcome {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
    /// Validation did not run for this query: either
    /// `DnssecValidationMode::Disabled`, or the query never reached the
    /// recursive validation path at all. Distinct from `Indeterminate`
    /// (validation ran and came back inconclusive) — collapsing the two
    /// would make it impossible for an operator to tell "DNSSEC is off" from
    /// "DNSSEC is on and confused."
    NotAttempted,
}
```

Add a corresponding `MetricsSink` trait method with a no-op default, mirroring
`record_backend_status`'s shape (`resolver/mod.rs:8933`):

```rust
pub trait MetricsSink: Send + Sync {
    // ...existing methods...
    fn record_dnssec_validation_outcome(&self, _outcome: DnssecValidationOutcome) {}
}
```

Implement it on `OpenTelemetryMetrics` (`main.rs`), adding a new field next to
`dnssec_validation_disabled: Gauge<u64>` (`main.rs:916`):

```rust
dnssec_validation_results_total: Counter<u64>,
// ...
dnssec_validation_results_total: meter.u64_counter("dnssec_validation_results_total").build(),
```

```rust
fn record_dnssec_validation_outcome(&self, outcome: DnssecValidationOutcome) {
    let label = dnssec_outcome_label(outcome);
    self.dnssec_validation_results_total
        .add(1, &[KeyValue::new("outcome", label)]);
}

fn dnssec_outcome_label(outcome: DnssecValidationOutcome) -> &'static str {
    match outcome {
        DnssecValidationOutcome::Secure => "secure",
        DnssecValidationOutcome::Insecure => "insecure",
        DnssecValidationOutcome::Bogus => "bogus",
        DnssecValidationOutcome::Indeterminate => "indeterminate",
        DnssecValidationOutcome::NotAttempted => "not_attempted",
    }
}
```

This follows the `backend_status_attributes` construction pattern
(`main.rs:1256-1275`) the plan explicitly calls out — a single labeled
`Counter<u64>` with one attribute, not five separate counters.

Add `NoopMetrics` (`main.rs:868-874`) and `NoopMetricsSink`
(`resolver/mod.rs:8965-8971`) — no code change needed, both rely on the
trait's no-op default. Add `RecordingMetrics`
(`resolver/mod.rs:10693-10735`) support for tests:

```rust
#[derive(Default)]
struct RecordingMetrics {
    // ...existing fields...
    dnssec_outcomes: Mutex<Vec<DnssecValidationOutcome>>,
}

impl MetricsSink for RecordingMetrics {
    // ...existing methods...
    fn record_dnssec_validation_outcome(&self, outcome: DnssecValidationOutcome) {
        self.dnssec_outcomes.lock().unwrap().push(outcome);
    }
}
```

### 7. Wire the increment call into section-04's call site

At the point in `build_rrset_entry`/`build_negative_entry`'s
`ResolutionMode::Recursive` branch where section 04 already calls the section-03
validator and maps its result onto `DnssecState`, thread the config's
`DnssecValidationMode` through and call
`metrics.record_dnssec_validation_outcome(...)` immediately after:

- `DnssecValidationMode::Disabled` → skip calling the validator entirely
  (entry's `dnssec_state` stays `DnssecState::Unvalidated`, matching current
  pre-Track-A behavior for anyone who opts out), and record
  `DnssecValidationOutcome::NotAttempted`.
- `DnssecValidationMode::Enabled` → call the validator as section 04 already
  does, map `DnssecState::Secure`/`Insecure`/`Bogus(_)` to the matching
  `DnssecValidationOutcome` variant 1:1, and map the case where the validator
  returned `ValidationState::Indeterminate` (collapsed to
  `DnssecState::Unvalidated` per A4) to `DnssecValidationOutcome::Indeterminate`
  — **not** `NotAttempted`. This requires section 04's validation call to
  expose, alongside the stored `DnssecState`, a separate signal that
  distinguishes "ran, came back Indeterminate" from "didn't run" (per A4's own
  TDD note: "assert the mapping function or its caller exposes both the
  `DnssecState` and a separate 'ran but inconclusive' marker, not just the
  collapsed state"). If section 04 landed this signal as, e.g., an `Option`
  wrapper or a second return value, this section's job is only to consume it
  and pick the right `DnssecValidationOutcome`, not to invent the signal
  itself.

`ResolutionMode::Forward` never reaches this call site (per A5's scope), so no
`record_dnssec_validation_outcome` call happens for Forward-mode traffic at
all — silence, not an explicit `NotAttempted` emission per query (test #10
above pins this; emitting on every Forward query would be needlessly noisy
for a mode that structurally never validates).

## Verification

- `cargo fmt`, `cargo clippy --all-targets --all-features -D warnings`,
  `cargo test` must all pass per `RUST.md`'s standard gates before this
  section is considered done — this is a metrics/config-surface change, not
  test-only or doc-only, so the `verify` skill should be run against the
  affected flow (config loading + resolver status/metrics reporting) before
  reporting done.
- Since this section changes a default (`DnssecValidationMode` → `Enabled`)
  and a cache-namespace fingerprint, double check no other existing test
  besides `toml_config_round_trip_loads_bundled_recursive_resolution`
  (`config/mod.rs:3817`) silently asserts the old `Disabled` default from an
  *unspecified* TOML key — the many other `DnssecValidationMode::Disabled`
  occurrences in `config/mod.rs` (lines ~2395, 2432, 2561, 2581, 2710, 2722,
  2741, 2754, 2778, 2791) are explicit constructor arguments in test fixtures
  unrelated to default-resolution and should be left alone unless a given
  test specifically exercises the "no config value present" path.

## As implemented

Landed materially as planned, plus two deviations the plan didn't
anticipate and one code-review fix. Full detail in
`docs/plans/sec_work/implementation/code_review/section-05-interview.md`.

**Deviation 1 — name collision resolved by renaming the internal
struct, not the new enum.** The plan's proposed public enum name
`DnssecValidationOutcome` collided with an existing `pub(crate) struct
DnssecValidationOutcome` in `resolver/dnssec_validation.rs` (the
`{state, validation_state}` pair `validate_for_store` already consumed
from section-04). Renamed the existing struct to `ValidationRunOutcome`
(all usages: `dnssec_validation.rs`, the `pub(crate) use` re-export in
`resolver/mod.rs`, and the doc comment in `resolver/cache/entry.rs`)
rather than picking a different name for the new metrics enum, since
the plan's name is the more natural fit for the metrics-facing type and
the struct's usages were fully internal to the crate.

**Deviation 2 — main.rs trust-anchor wiring, not in the plan's literal
scope but required for the section's goal to actually work.**
Grounding surfaced that `main.rs` never called
`ResolveQuery::with_trust_anchors` at all (a deliberate gap left by
section-04, with a comment saying section-05 was where it'd get wired
live). Without closing this gap, flipping `DnssecValidationMode`'s
default to `Enabled` would only be cosmetic — the status gauge/label
would say "enabled" while `validate_for_store` never actually ran the
DS/DNSKEY chase (`self.trust_anchors` stays `None` forever). Added
`trust_anchors_to_wire_in(&config) -> io::Result<Option<Vec<String>>>`
in `main.rs`, called from `main()`: returns `Some(anchors)` only when
`RecursiveResolutionConfig::dnssec_validation == Enabled`, otherwise
`None` (covers both `Disabled` and `ResolutionMode::Forward`, which has
no `[resolution.recursive]` section at all). `None` leaves
`ResolveQuery.trust_anchors` at its default, which is the actual kill
switch `validate_for_store` already checks. No change was needed to the
two `validate_for_store` call sites (`resolver/mod.rs`, the refresh-job
path and the main resolve path) — both already call it unconditionally
for `ResolutionMode::Recursive`; the mode-driven skip happens inside
`validate_for_store` via the trust-anchors-`None` check, not via a
separate `DnssecValidationMode` field threaded onto the resolver.

**Code-review fix — parse-failure metric label.** Originally both
"no trust anchors configured" and "trust anchors configured but fail to
parse" recorded `DnssecValidationOutcome::NotAttempted`. Review flagged
that the parse-failure case is a live misconfiguration (mode `Enabled`,
anchors corrupt) that would be invisible in metrics if bucketed with
the benign opt-out case. Changed that branch to record `Bogus` instead
— fail-closed, matching `validate_response`'s own convention for chase
timeouts/transport errors.

**Files touched:** `src/config/mod.rs`, `src/resolver/mod.rs`,
`src/resolver/dnssec_validation.rs`, `src/resolver/cache/entry.rs`,
`src/main.rs`, plus two `docs/knowledge/resolver/caching/` concept docs
(`serve-stale.md`, `answer-cache.md`) that described the pre-section-05
"validation unreachable in production" state and were now stale.

**Tests added:** 3 config round-trip tests (explicit `enabled`/
`disabled`/unknown-value rejection) + 1 `cache_namespace_label` unit
test in `config/mod.rs`; in `resolver/mod.rs`: `dnssec_outcome_metric`
exhaustiveness test, `Secure`/`Bogus`(tampered-signature)/`Bogus`
(parse-failure)/`NotAttempted` outcome tests via `validate_for_store`,
a Forward-mode silence assertion added to the existing
`resolve_forward_mode_never_invokes_dnssec_validator` test; in
`main.rs`: label/gauge/counter tests, `build_recursive_backend_snapshot`
/`build_forward_backend_snapshot` status tests, and
`trust_anchors_to_wire_in` tests for all three gating branches
(disabled, forward mode, enabled). All gates green: `cargo fmt`,
`cargo clippy --all-targets --all-features -D warnings`, `cargo test`
(737 lib + 39 bin tests passing).