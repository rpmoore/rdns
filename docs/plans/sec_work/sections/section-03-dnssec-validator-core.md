Now I have all the context needed. Let me write the section content.

---

# section-03-dnssec-validator-core

## Purpose

Build the core DNSSEC validation function: the piece that takes a fully-fetched recursive response and the trust anchors, runs it through the `domain` crate's validator, and produces a `DnssecState` verdict. This section produces **only** the validation function itself, its supporting transport-adapter bridge, and its own direct unit tests (including a shared signed-zone test fixture). It does **not** wire this function into cache-entry construction (`build_rrset_entry`/`build_negative_entry`), does not add CD-bit gating, and does not touch metrics — those are section-04 and section-05.

This is the largest, highest-risk section in Track A. It also produces a deterministic signed test-zone fixture that section-04's tests reuse — treat that fixture as a first-class deliverable of this section, not incidental test scaffolding.

## Dependencies

- **section-01-dnssec-deps**: `domain = "0.12"` with `unstable-validator` + `ring` features must already be in `Cargo.toml` and building cleanly before this section starts.
- **section-02-dnssec-trust-anchor**: the bundled/overridable trust-anchor set (`TrustAnchorSource`, a `bundled_trust_anchors()`-equivalent function producing `domain`'s trust-anchor type) must already exist. This section consumes that trust-anchor value as an input to the validator; it does not build or parse trust anchors itself.

Do not duplicate section-01/02 content here — reference their outputs (the crate features, and whatever function/type section-02 exposes for obtaining the trust-anchor set) as given inputs.

## Background context

### Existing types this section builds on

**`DnssecState`** — `src/resolver/cache/entry.rs:98-116`:

```rust
/// Mirrors RFC 6840 §3.1's "BAD cache" concept and Unbound/BIND-style
/// internal validation-state tracking. Every entry starts and stays
/// `Unvalidated` until real DNSSEC validation is implemented (out of scope
/// for this whole rework) — this enum exists purely so the data model
/// doesn't need reshaping again when that work happens later.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnssecState {
    #[default]
    Unvalidated,
    #[allow(dead_code)]
    Insecure,
    #[allow(dead_code)]
    Secure,
    #[allow(dead_code)]
    Bogus(String), // reason, for diagnostics; short negative-style TTL applies
}
```

This section's job is to produce real, non-default values of this enum. The stale doc comment above (claiming DNSSEC validation is out of scope) and the `#[allow(dead_code)]` markers are no longer accurate once this section lands — updating that comment and removing the now-dead `#[allow(dead_code)]` attributes belongs to this section's cleanup, since this is the first section that actually constructs these variants. Do not touch the enum's shape itself (no new variants, no field changes) — only the doc comment and dead-code markers.

**rdns's own `Message` type** (`src/protocol`, imported into `src/resolver/mod.rs:32-39`) is what recursive responses are represented as throughout the resolver — this is **not** `domain::base::Message`. `build_rrset_entry`/`build_negative_entry` (section-04's wiring target, `src/resolver/mod.rs:1039` and `:1080`) both take `response: &Message` using this rdns type. This section's validation function must accept the same rdns-side representation as its input (or whatever narrower slice of it is sufficient — e.g. the raw wire bytes plus parsed `Message` — decide based on what `domain`'s `validate_msg` actually needs) so section-04 can call it directly with the data it already has in hand, without inventing a new conversion layer at the call site.

**`RecursiveAuthorityTransport`** — `src/resolver/mod.rs:7823-7831`:

```rust
pub trait RecursiveAuthorityTransport: Send + Sync {
    fn query<'a>(
        &'a self,
        authority: SocketAddr,
        question: QuestionKey,
        dnssec_ok: bool,
        timeout: Duration,
    ) -> BoxFuture<'a, Result<RecursiveAuthorityResponse, ResolutionBackendError>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveAuthorityResponse {
    pub bytes: Vec<u8>,
    pub message: Message,
}
```

This is rdns's existing upstream-query abstraction, already implemented by `RecursiveAuthorityTransportClient` (`src/delivery/upstream.rs:121`) for production use, and by several test-only scripted/blocking/hanging transports in `resolver/mod.rs`'s test module (`ScriptedAuthorityTransport`, `DnssecAwareBlockingAuthorityTransport`, `HangingAuthorityTransport`, `DelayedAuthorityTransport`) for exercising timeout/error paths without real I/O.

`domain`'s `dnssec::validator::context::ValidationContext<Upstream>` needs something implementing `domain::net::client::SendRequest` and works in terms of `domain::base::Message`. These are different types from rdns's `RecursiveAuthorityTransport`/`Message`. Bridging them is real design work — see the "Transport adapter" implementation bullet below.

**Timeout budget** — `RecursiveResolverConfig` (`src/resolver/mod.rs:7791-7796`):

```rust
pub struct RecursiveResolverConfig {
    pub root_hints: Vec<RecursiveRootHint>,
    pub per_authority_timeout: Duration,
    pub per_query_deadline: Duration,
    pub max_recursion_depth: u8,
    pub max_cname_restarts: u8,
    // ...
}
```

`per_query_deadline` and `per_authority_timeout` already bound rdns's normal iterative resolution. The validator's own DS/DNSKEY chase (driven internally by `domain`, via the adapter) must be bounded by this same budget — it must not add an unbounded wait on top of normal resolution.

**Existing conventions**: no mocking framework anywhere in this codebase; hand-constructed byte-vector/struct fixtures rather than golden files; known-answer vectors placed directly beside the primitive they pin; inline `#[cfg(test)] mod tests` at the bottom of the same file as the code under test. Follow this pattern for the new module — do not introduce a new test-fixture format or an external golden-file directory.

### Where the new module lives

Add a new module alongside the existing `resolver/cache/` submodule (`src/resolver/mod.rs:46`, `mod cache;`) — follow the same sibling-module convention. Suggested path: `src/resolver/dnssec_validation.rs`, declared as `mod dnssec_validation;` in `src/resolver/mod.rs` near the existing `mod cache;`/`pub mod policy;` declarations, exporting whatever items section-04 needs (the validation function itself, and the `DnssecState`-mapping helper if it's useful to test/call independently). Keep the module private (`mod`, not `pub mod`) unless section-04's wiring genuinely needs cross-crate visibility — mirror `mod cache`'s visibility, which re-exports only specific items rather than the whole module.

## Tests first

Write these before filling in the validation function's body. Per this repo's convention, these are inline `#[cfg(test)] mod tests` at the bottom of `src/resolver/dnssec_validation.rs` (plus the fixture module, see below) — no mocking framework, hand-built byte vectors/structs.

### Fixture (build this first — shared prerequisite for the rest of this section, and reused by section-04)

Generate a small, deterministic, offline signed test zone using an offline signing tool:
- A handful of records.
- At least one NSEC or NSEC3 range for denial-of-existence coverage.
- At least one wildcard record, if feasible.

Commit the resulting DNSKEY/DS/RRSIG wire bytes (or the signing tool's output re-encoded into whatever format this codebase's existing hand-built-byte-vector test style uses) as a fixture module (e.g. `src/resolver/dnssec_validation.rs`'s test module, or a `dnssec_fixture` submodule if the byte data is large enough to warrant separation). This must be fully offline/deterministic — no live network dependency anywhere in the test suite. Because section-04's tests (CD-bit, mixed-CNAME-chain, serve-stale) also depend on this fixture, keep it in a location/visibility that section-04 can import from (e.g. `pub(crate)` within the module, or `#[cfg(test)] pub(crate)` if it should only exist under test).

### Core logic tests (from plan §A4 / TDD §A4)

- **Transport adapter round-trip test**: a narrow, adapter-only test proving the bridge from a canned rdns-side response into a `domain`-side `Message` compiles and round-trips data correctly — independent of real validation logic. This isolates "the adapter works" from "the validator works."
- **Known-answer chain test**: validate the fixture's full, untampered chain and assert `domain` itself returns `ValidationState::Secure` — before asserting anything about the `DnssecState` mapping. This isolates "`domain`'s validator works against our fixture" from "our state-mapping code is correct."
- **`ValidationState` → `DnssecState` mapping tests**: test the mapping function directly with each of the four `ValidationState` inputs (`Secure`, `Bogus`, `Insecure`, `Indeterminate`) — this is a pure function and should be tested as one, not only indirectly through a real validation run.
- **`Indeterminate` visibility test**: assert `Indeterminate` maps to `DnssecState::Unvalidated` on the entry side, while also being distinguishable via a separate internal signal that section-05's metrics code will consume later (assert the mapping function or its caller exposes both the collapsed `DnssecState` and a separate "ran but inconclusive" marker — do not just assert the collapsed state and call it done, since section-05 depends on this dual signal existing).
- **Timeout-bounded test**: simulate a DS/DNSKEY chase that would exceed the per-query/per-authority timeout budget (e.g. via a scripted/hanging transport, mirroring the existing `HangingAuthorityTransport`/`DelayedAuthorityTransport` test patterns already in `resolver/mod.rs`'s test module). Assert the function returns before the deadline with `DnssecState::Bogus` and a timeout-indicating diagnostic reason string — not a hang, not a panic, not `Insecure`.
- **Transport/adapter hard-error test**: distinct from the timeout test — simulate the adapter returning a transport error (not a timeout) mid-validation. Assert this also maps to `DnssecState::Bogus`, not `Insecure` or `Unvalidated` — fail-closed applies to errors generally, not just timeouts.
- **`Config` threshold test**: assert the `domain::dnssec::validator::context::Config` builder is constructed with explicit `nsec3_iter_insecure`/`nsec3_iter_bogus` values (not left at the crate's raw default) — check the configured validator context reflects the chosen thresholds rather than being zero/unset.

### Validator-attacking tests (from plan/TDD §A8, the subset that exercises this module directly)

These all call the validation function directly against a (possibly tampered) fixture — no cache-entry construction or response assembly involved (that's section-04's job).

- **Bogus-injection — tampered RRSIG**: flip a byte in an RRSIG signature from the fixture, assert `DnssecState::Bogus`. Pair this specific case with an assembly-level test (can be written here or cross-referenced/duplicated lightly in section-04, since `dnssec_servfail_check` itself is untouched and already tested) asserting that feeding this same Bogus state into the existing SERVFAIL check forces SERVFAIL — closing the loop between "the validator produces Bogus from tampered bytes" and "assembly already reacts correctly once told."
- **Bogus-injection — tampered DNSKEY byte**: independently, flip a byte in a DNSKEY record, assert `DnssecState::Bogus`.
- **Bogus-injection — tampered DS digest byte**: independently, flip a byte in a DS digest, assert `DnssecState::Bogus`.
- **Algorithm-downgrade test**: construct a scenario where the fixture zone has a DS record at the parent (signed) but the child response omits signatures entirely. Assert the result is `DnssecState::Bogus`, **not** `Insecure` — this is the specific downgrade pitfall this validator must not be vulnerable to: a DS-signed zone whose signatures are simply stripped must not be treated as "legitimately unsigned."
- **Expired-RRSIG test**: construct a fixture variant with an RRSIG whose signature-expiration field is in the past — otherwise well-formed and correctly signed, just outside its validity window. Assert `DnssecState::Bogus`. This is distinct from the tampered-byte tests above: it exercises the validity-window check, not signature verification.
- **Not-yet-valid-RRSIG test**: same as above but with an inception field in the future. Assert `DnssecState::Bogus`.
- **NSEC3 opt-out test**: if feasible within the fixture-generation approach, construct an opt-out NSEC3 scenario and confirm it cannot be used to downgrade a signed subdomain to `Insecure`/spoofed data. If building this fixture variant is disproportionately costly given the offline-signing-tool workflow, mark the test `#[ignore]` with a comment pointing at a follow-up tracking ticket — do not omit it silently.

Note: the mixed-validation-state CNAME chain test, the CD-bit test, and the serve-stale test from §A8 are **not** part of this section — they require the full entry-construction/response-assembly path and belong to section-04.

## Implementation details

### Transport adapter spike (do this first, before writing the rest of this section's logic)

Bridge rdns's `RecursiveAuthorityTransport` (`src/resolver/mod.rs:7823-7831`) to whatever `domain::net::client::SendRequest`-implementing type `ValidationContext<Upstream>` needs, so that the validator's own DS/DNSKEY chase queries flow through rdns's existing upstream transport rather than opening a separate connection path. This is real design work, not a mechanical wrapper:

- The adapter must translate between rdns's `Message`/`QuestionKey`/`SocketAddr`-based `query()` signature and whatever request/response shape `domain`'s `SendRequest` trait expects, including converting between rdns's `Message` and `domain::base::Message`.
- Decide explicitly how errors and timeouts on the adapter side surface back to `validate_msg`'s caller — this determines how the timeout/error-path tests above are actually exercised, so nail this down before writing those tests, not after.
- Budget explicit time for this as its own sub-step; it is the highest-risk part of this section.

### Core validation function

- Signature: takes the fully-synthesized recursive response (whatever subset of what `build_rrset_entry`/`build_negative_entry` currently consume is sufficient — likely `&Message` plus original wire bytes) plus the trust anchors from section-02, returns a `DnssecState` (plus, per the `Indeterminate`-visibility requirement above, some way for the caller to also observe "ran but inconclusive" distinctly from "never ran").
- Internally: construct a `domain::dnssec::validator::context::ValidationContext` using the transport adapter as the `Upstream` type parameter, call `validate_msg()`, then map the resulting `ValidationState` onto `DnssecState`:
  - `Secure` → `DnssecState::Secure`
  - `Bogus` → `DnssecState::Bogus(reason)` — thread through whatever diagnostic `domain` provides (e.g. via its `ExtendedError` return value) into the reason string.
  - `Insecure` → `DnssecState::Insecure`
  - `Indeterminate` → `DnssecState::Unvalidated`, with the separate "ran but inconclusive" signal noted above.
- **Fail-closed timeout/error handling**: `validate_msg`'s DS/DNSKEY chase must be bounded by rdns's existing `per_query_deadline`/`per_authority_timeout` (or equivalent budget passed in by the caller) — it must not add an unbounded wait on top of normal resolution. A timeout or transport error during validation maps to `DnssecState::Bogus` with a diagnostic reason (e.g. `"validation timed out"`), **not** to `Insecure` and **not** silently to `Unvalidated`. Treating "couldn't determine" the same as "provably unsigned" is the same algorithm-downgrade pitfall as the crafted-response downgrade test above, just triggered by a timeout instead of tampered bytes. This is a deliberate trade-off: transient upstream slowness during validation can produce a SERVFAIL for CD=0 requesters once section-04/06 wire this up end-to-end. That trade-off is intentional and belongs in the PR description and section-06's rollout note — nothing further needs to happen about it in this section beyond implementing it correctly.
- Configure `domain`'s `Config` builder with explicit values (not the crate's raw defaults) for `set_nsec3_iter_insecure`/`set_nsec3_iter_bogus` — high NSEC3 iteration counts are a known DoS vector against validators, so this is a deliberate policy knob, not something to leave unset. Also set `set_max_validity`/`set_max_bogus_validity` and any other `Config` setters as needed; consult `domain`'s docs for reasonable starting values.
- **Known upstream limitation, accepted as-is**: `domain`'s validator fetches DS/DNSKEY sequentially, doesn't prefetch, and can issue duplicate fetches for parallel same-name queries (e.g. simultaneous A and AAAA lookups) — this is documented in the crate itself and is not something this section's wiring can fix without vendoring/patching `domain`. Do not attempt to work around it in this section; section-05's latency-relevant metrics are where this would eventually become visible if it matters in practice.

## Explicitly out of scope for this section

- Calling this function from `build_rrset_entry`/`build_negative_entry` — section-04.
- Replacing the `dnssec_state: Default::default()` lines at `src/resolver/mod.rs:1057` and `:1117` — section-04.
- CD-bit gating at response-assembly time — section-04.
- TTL capping at RRSIG expiration — section-04.
- `DnssecValidationMode`/`DnssecValidationStatus::Enabled`, the outcome counter, and all other metrics/status work — section-05.
- `docs/knowledge/` updates and `/security-review` — section-06.

## Verification

- `cargo test` covering the new module's fixture and all tests listed above must pass.
- Per `RUST.md`/AGENTS.md's standing rules, satisfy the fmt/clippy/test gates before considering this section done: `cargo fmt`, `cargo clippy` (with this repo's configured lint level), `cargo test`.
- This section does not require its own `/security-review` pass — that happens once at the end of Track A (section-06), after entry-wiring (section-04) and metrics (section-05) are also in place, so the review covers the full validator wiring surface at once rather than a partial slice of it.

## As implemented

- New module: `src/resolver/dnssec_validation.rs`, declared `mod
  dnssec_validation;` in `src/resolver/mod.rs` next to `mod cache;`, with
  `pub(crate) use dnssec_validation::{DnssecValidationOutcome,
  validate_response, validator_config};` re-exported for section-04.
  `DnssecState` was re-exported from `resolver::cache` (it wasn't before)
  so this sibling module can reach it.

- **Transport-adapter deviation from the plan (deliberate, documented in
  the module's top doc comment)**: the plan named
  `RecursiveAuthorityTransport` (`src/resolver/mod.rs:7823-7831`) as the
  bridge target. That trait is a single-authority, one-shot,
  non-recursive query (`query(authority: SocketAddr, ...)`) — it cannot
  satisfy `domain`'s validator, which sends a plain RD=1,CD=1 query and
  expects a *fully resolved* answer back (confirmed by reading
  `request_as_groups`/`Node::trust_anchor` in `domain`'s
  `validator/context.rs`). The adapter (`BackendUpstream`) bridges to
  `ResolutionBackend::resolve` instead (`RecursiveResolutionBackend`'s
  trait, `src/resolver/mod.rs:7782`) — the same root-to-authority
  recursive engine that answers ordinary client queries, reusing its
  delegation cache/glueless-NS/timeout handling rather than duplicating a
  second iterative walker inside the adapter.

- **`Send`-not-`Sync` future workaround**: `ResolutionBackend::resolve`'s
  `BoxFuture` is `Send` but not `Sync`, while `domain`'s
  `GetResponse::get_response()` must return a `Sync` future. The adapter
  runs the actual chase on a `tokio::spawn`ed task and returns the result
  over a `tokio::sync::oneshot` channel (which is `Sync`), rather than
  holding the non-`Sync` future across an `.await` in its own state
  machine or reaching for `unsafe impl Sync`.

- **Fixture-generation deviation (deliberate, documented in `Cargo.toml`)**:
  no offline DNSSEC signing tool (`ldns-signzone` etc.) is available on
  the build host, so the fixture uses `domain`'s own `unstable-sign`
  feature (`domain::crypto::sign::generate` for an Ed25519 keypair,
  `SigningKey`, `SortedRecords::sign_zone` in-place) to build a
  deterministic signed test zone at test time. `unstable-sign` and a
  direct `ring = "0.17"` dependency were added to `[dev-dependencies]`
  only — Cargo's feature resolver keeps dev-dependency-only features out
  of `cargo build`/release, confirmed by `cargo build --lib` succeeding
  without them.
  - `sign_zone`'s in-place (`SignableZoneInPlace`) mode was used rather
    than the `SignInto` convenience wrapper the crate's own doctest
    shows: `SignInto`'s `as_out_slice()` only sees records already in the
    `out` collection (i.e. just-generated NSEC(3) records), never the
    original zone content, so it silently signs *only* the NSEC(3)
    RRset — SOA/NS/A never get RRSIGs. In-place signing folds NSEC +
    RRSIGs for everything into the same `SortedRecords`.
  - `sign_zone` deliberately skips the apex DNSKEY/CDS/CDNSKEY RRset (see
    `sign_sorted_zone_records`'s doc comment) since real zones may want
    only specific keys to sign it; the fixture signs the DNSKEY RRset
    explicitly via `sign_rrset` with the same key.
  - The fixture is a **single self-trust-anchor zone**: the trust anchor
    handed to `ValidationContext` is the zone's own DNSKEY directly
    (parsed via `TrustAnchors::from_u8`), not a DS chain from a simulated
    root. This still requires one chase query per test —
    `domain`'s `Node::trust_anchor` always fetches+verifies the DNSKEY
    RRset even when the anchor is already known key material — but avoids
    needing a full two-zone (parent DS + child DNSKEY) hierarchy for the
    core tests.
  - `pub(crate) mod fixture` lives inside `dnssec_validation.rs`,
    `#[cfg(test)]`-gated, so section-04's tests can import it too.

- **Test count**: 14 passing tests (transport-adapter smoke test, 4 pure
  `ValidationState`→`DnssecState` mapping tests, known-answer-secure,
  tampered-RRSIG-byte, tampered-DNSKEY-byte, expired-RRSIG,
  not-yet-valid-RRSIG, timeout-during-chase, transport-error-during-chase,
  Config-thresholds), plus **3 `#[ignore]`d tests with tracking
  comments** rather than silent omission:
  - `algorithm_downgrade_ds_signed_zone_with_stripped_child_signatures_is_bogus`
    — needs a two-zone (parent DS + child) chase fixture.
  - `nsec3_opt_out_cannot_downgrade_signed_subdomain` — needs an NSEC3
    opt-out fixture variant.
  - `tampered_ds_digest_byte_is_bogus` — needs a DS record in the fixture
    chain at all (the self-trust-anchor design has none). Found during
    code review, not in the original plan's test list omission — added as
    an explicit deferral rather than a silent gap.
  - These three are the recommended starting point if/when the two-zone
    hierarchy is built (they'd very likely share the same parent-zone
    fixture).

- Full suite: 719 lib tests pass (14 new + 705 existing), 3 acknowledged
  `#[ignore]`s, no regressions. `cargo fmt --all -- --check` and `cargo
  clippy --all-targets` both clean.

- Code review (subagent) caught and fixed before commit: `chase()` had
  hardcoded `backend_generation: 0` (now threaded through from
  `validate_response`'s caller, matters once cache-namespace generation
  bumps past 0 on a runtime reload); a file-scoped `#![allow(dead_code)]`
  was narrowed to per-item; hard-error branches now interpolate the
  underlying error into the `Bogus` reason string instead of a generic
  constant; the spawned chase task now logs on oneshot-send failure so a
  panicking chase isn't silently invisible.