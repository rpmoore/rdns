# section-02-dnssec-trust-anchor

## Dependencies

- **Depends on:** `section-01-dnssec-deps` (must land first — this section
  needs `domain = "0.12"` with the `unstable-validator` and `ring` features
  enabled in `Cargo.toml`, since `domain::dnssec::validator::anchor::TrustAnchors`
  only exists under those features).
- **Blocks:** `section-03-dnssec-validator-core` (the validator core needs a
  trust-anchor set to construct `ValidationContext` with).
- **Parallelizable with:** `section-08-badcookie-detection` (different
  track, disjoint files).

## Scope

This section covers plan `claude-plan.md` §A2 (trust anchor bundling) and
§A3 (CI staleness check for the bundled anchor). It does **not** touch the
validator itself (§A4, section-03), config mode/status enums for DNSSEC
(§A7, section-05), or `docs/knowledge/` updates (§C1, section-06).

Everything here lives in `src/config/mod.rs` (config plumbing, mirroring
the existing root-hints pattern), a new bundled data file, and a new,
separate GitHub Actions workflow — no resolver-runtime code changes.

---

## Background: the pattern being mirrored

`rdns` already has an identical bundled-vs-static-override pattern for root
hints, and this section replicates it for DNSSEC trust anchors:

- `RootHintsSource` enum (`src/config/mod.rs:864-868`):
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum RootHintsSource {
      Bundled,
      Static(Vec<RootHintConfig>),
  }
  ```
  with a `cache_namespace_label()` method (`:870-877`) returning `"bundled"`
  or `"static"`.
- `BUNDLED_NAMED_ROOT: &str = include_str!("named.root")` (`:933`) and
  `bundled_root_hints()` (`:935-938`), which parses that compile-time-embedded
  file and panics on parse failure (a bundled asset that fails to parse is a
  build-time bug, not a runtime condition to recover from).
- `RecursiveResolutionConfig` (`:726-735`) holds `root_hints_source:
  RootHintsSource` and a `load_root_hints()` method (`:768-773`) that
  dispatches on the enum.
- `RecursiveResolutionConfig::validate()` (`:775-816`) calls
  `load_root_hints()` and rejects an empty result with
  `ConfigError::MissingRootHints` (`:780-782`).
- TOML wiring: `RawRecursiveResolutionConfig` (`:1868-1887`) has a
  `root_hints: String` field (`"bundled"` / `"custom"`) plus a
  `#[serde(default)] root_hints_entries: Vec<RawRootHintConfig>`, and
  `try_into_recursive_resolution_config()` (`:1905-1960`) matches on the
  string to build either `RecursiveResolutionConfig::bundled(...)` or
  `RecursiveResolutionConfig::new(...)` with the parsed entries
  (`:1937-1952`). `RawRootHintConfig` (`:1963-1979`) is the per-entry TOML
  shape with its own `try_into_root_hint_config()` conversion.

Build the trust-anchor equivalent of every piece above: bundled file +
`include_str!`, `TrustAnchorSource` enum with `Bundled`/`Static(...)`
variants and a `cache_namespace_label()`, a field + loader method on
`RecursiveResolutionConfig`, validation, and the matching `Raw*` TOML
deserialization plumbing.

## Background: `domain`'s `TrustAnchors` API (confirmed against crate source)

Checked directly against `domain-0.12.2`'s
`src/dnssec/validator/anchor.rs` (available locally under
`~/.cargo/registry/src/index.crates.io-*/domain-0.12.2/`), so this is
confirmed API shape, not a guess:

```rust
pub struct TrustAnchors(Vec<TrustAnchor>);

impl TrustAnchors {
    pub fn empty() -> Self;
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self, Error>;
    pub fn from_u8(str: &[u8]) -> Result<Self, Error>;
    pub fn add_u8(&mut self, str: &[u8]) -> Result<(), Error>;
    // `find()` is `pub(crate)` — not usable from rdns.
}
```

Key findings that affect how this section's tests must be written:

- The **input format is zonefile format** (the same format
  `domain::zonefile::inplace::Zonefile` parses elsewhere), containing `DS`
  or `DNSKEY` resource records — **not** BIND's separate
  `trust-anchors { ... }` config-block syntax and not a bespoke rdns
  format. A minimal valid file looks like:
  ```
  . IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8
  . IN DS 38696 8 2 <KSK-2024 SHA-256 digest, fetch the real value from IANA — see below>
  ```
  Use `TrustAnchors::from_u8()` (byte-string input, matches
  `include_str!`'s output type after an `.as_bytes()` call) rather than
  `from_reader()`, mirroring `bundled_root_hints()`'s
  parse-embedded-string-at-runtime pattern.
- **`TrustAnchor` (the per-anchor record group) is `pub(crate)` inside
  `domain`.** There is no public way to iterate a `TrustAnchors` value's
  contents, read back key tags, or otherwise introspect what got parsed
  from outside the `domain` crate. This means the tdd-plan's literal
  ask — "the parsed anchor set contains exactly two entries with key tags
  20326 and 38696" — **cannot** be asserted by inspecting a `TrustAnchors`
  value after parsing. Write that test instead against the **source text**
  (parse the committed `root-anchor.txt` file's `DS` lines directly with a
  small local helper — e.g. split each non-comment line and read the
  key-tag field, the same way you'd assert on any other bundled text
  asset) and treat `TrustAnchors::from_u8()` succeeding without error as
  the separate "the format `domain` expects is what we produced" test.
  Don't conflate the two assertions into one test that silently only
  covers the parse-succeeds case.
- **Do not fabricate the actual DS digest bytes.** The KSK-2017 (tag
  20326) digest above is the long-published, stable IANA root anchor and
  safe to hardcode. The KSK-2024 (tag 38696) digest must be sourced from
  IANA's authoritative `root-anchors.xml`
  (`https://data.iana.org/root-anchors/root-anchors.xml`) at
  implementation time and copied verbatim — getting a trust-anchor digest
  wrong is a security-relevant correctness bug (either it never validates
  anything once KSK-2024 activates, or worse, someone "fixes" a validation
  failure later by loosening the check instead of noticing the digest is
  wrong). Confirm the exact digest algorithm field too (`2` = SHA-256 is
  what both current root KSKs publish) before writing the file.

## Existing `ConfigError` pattern to extend

`ConfigError` (`src/config/mod.rs:1460` onward, `#[derive(Debug, Clone,
PartialEq)]` — not `Eq`, because one existing variant carries an `f32`)
already has root-hints-specific variants to mirror:
```rust
MissingRecursiveResolutionConfig,
InvalidRootHintsVersion,
MissingRootHints,
InvalidRootHintName,
MissingRootHintEndpoints,
InvalidRootHintEndpoint { endpoint: SocketAddr },
```
Add trust-anchor equivalents, e.g. `MissingTrustAnchors` (empty
`Static(...)` override or a bundled file that somehow parses to nothing)
and `InvalidTrustAnchorEntry { .. }` (a malformed static-override zone-file
line) — follow whatever shape fits the chosen `TrustAnchorSource::Static`
payload type (see below). Generic TOML-level errors (unknown
`trust_anchor` string, wrong field type) should reuse the existing
`ConfigError::InvalidTomlConfig { message }` variant used throughout
`Raw*::try_into_*` conversions (see `:1861-1863`, `:1911-1915`,
`:1947-1951` for the pattern).

## CI precedent: what's already there and what's different about A3

`.github/workflows/ci.yml` already has a `bundled-data-freshness` job
(runs on every PR) that shells out to `make check-bundled-data-freshness`
→ `scripts/check-bundled-data-freshness.sh`. That script does a **byte-diff**
against upstream (`named.root`, `tlds-alpha-by-domain.txt`) and fails the
PR on any drift. **Do not add the trust-anchor check to this job or this
script** — the plan is explicit that the trust-anchor staleness check must
be a *separate, scheduled* workflow that alerts rather than blocks PRs
(IANA endpoint flakiness must not block unrelated work), and it needs CMS
signature verification, not a plain diff, since drift here (a missing or
expiring digest) is a different kind of finding from "upstream text
changed." Reuse `check-bundled-data-freshness.sh`'s *style* (bash,
`set -euo pipefail`, `curl` with `--fail --silent --show-error --retry`)
for the new script, but keep it a distinct file, distinct `make` target,
and distinct workflow.

---

## Tests first

Write these before implementing — extracted from `claude-plan-tdd.md`
§A2/§A3:

1. **`bundled_trust_anchors()` parses without error at startup.** Mirrors
   `bundled_root_hints()`'s panic-on-malformed-bundled-asset pattern: call
   the loader, assert it succeeds (or, if following the panic-on-load
   convention, assert the function is called during a smoke/startup test
   without panicking).

2. **The bundled anchor *source text* contains exactly two DS entries with
   key tags 20326 and 38696.** As established above, assert this against
   the raw `root-anchor.txt` content (parse the zonefile-format lines
   yourself in the test, reading each `DS` record's key-tag field), not
   against `TrustAnchors`'s internals (which are inaccessible). Separately,
   assert `TrustAnchors::from_u8()` on that same text returns `Ok(_)`.

3. **`TrustAnchorSource::Static(...)` config override is honored instead
   of the bundled set when present.** Mirror
   `toml_config_round_trip_loads_custom_recursive_root_hints`
   (`src/config/mod.rs:3821-3863`): build a TOML config with a
   `trust_anchor = "static"` (or equivalent) key plus inline anchor
   entries, load it via `RuntimeConfig::from_toml_str`, and assert the
   resulting `RecursiveResolutionConfig`'s trust-anchor field is
   `TrustAnchorSource::Static(...)` with the expected content — not
   `Bundled`.

4. **Malformed/empty static-override config is rejected at config
   validation time.** Mirror
   `toml_config_rejects_custom_recursive_root_hints_with_no_entries`
   (`:3865-3883`): a `trust_anchor = "static"` config with zero entries
   (or, separately, a malformed zone-file line if the chosen `Static`
   payload is raw text) must fail `RuntimeConfig::from_toml_str` with the
   new `MissingTrustAnchors` (or equivalent) `ConfigError` variant, not
   silently proceed with zero anchors.

5. **A3 verification (not a `cargo test`)**: document, as prose in this
   section's implementation (e.g. a comment in the new script or a note in
   the PR description), the manual verification step: run the new
   staleness-check script locally against a deliberately modified copy of
   the bundled anchor file (delete one digest, or backdate a
   `validUntil`), confirm it reports drift/staleness. This won't show up
   in `cargo test` output — call that out explicitly so a reviewer doesn't
   go looking for it there.

---

## Implementation

### 1. Bundled trust-anchor data file

- New file: `src/config/root-anchor.txt` (sibling to the existing
  `src/config/named.root`), containing **both** current root zone trust
  anchors in zonefile format:
  - KSK-2017, key tag **20326** (currently active signer).
  - KSK-2024, key tag **38696** (standby, becomes active 2026-10-11 — sign
    date already past "today" as of this plan's writing, so by the time
    this section is implemented it may already be closer to or past
    activation; that doesn't change what needs bundling — both anchors
    stay bundled either way since RFC 5011-style automated rollover is
    explicitly out of scope).
  - Format: `DS` (or `DNSKEY`) resource records, zonefile syntax, parseable
    by `domain::dnssec::validator::anchor::TrustAnchors::from_u8()`. Source
    the exact current digests from
    `https://data.iana.org/root-anchors/root-anchors.xml` at
    implementation time — do not hand-copy from memory or from a
    secondary source.
  - Add a doc comment at the top of the file (mirroring the one above
    `BUNDLED_NAMED_ROOT` at `src/config/mod.rs:928-932`) stating where it
    came from, that it requires **manual** refresh on future root KSK
    rollovers (no RFC 5011 automation), and pointing at the A3 staleness
    workflow as the mechanism that will flag when a refresh is needed.

### 2. `TrustAnchorSource` enum and config wiring (`src/config/mod.rs`)

- Add, near `RootHintsSource` (`:864-877`):
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum TrustAnchorSource {
      Bundled,
      Static(Vec<String>), // one zonefile-format DS/DNSKEY line per entry
  }

  impl TrustAnchorSource {
      fn cache_namespace_label(&self) -> &'static str {
          match self {
              Self::Bundled => "bundled",
              Self::Static(_) => "static",
          }
      }
  }
  ```
  (The exact `Static` payload type is a judgment call — `Vec<String>` of
  raw zone-file lines is the simplest thing that round-trips through TOML
  arrays the same way `root_hints_entries` does; a richer per-field struct
  like `RootHintConfig` is unnecessary here since a DS/DNSKEY record line
  has no natural rdns-specific substructure the way a root hint's
  name+endpoints pair does.)
- Add `const BUNDLED_ROOT_ANCHOR: &str = include_str!("root-anchor.txt");`
  and a `bundled_trust_anchors()` function mirroring `bundled_root_hints()`
  (`:935-938`) — parse-and-panic-on-malformed-bundled-asset, since a
  broken bundled file is a build-time bug.
- Add a `trust_anchor_source: TrustAnchorSource` field to
  `RecursiveResolutionConfig` (`:726-735`), plus a `load_trust_anchors()`
  method mirroring `load_root_hints()` (`:768-773`) that dispatches on the
  enum and returns `Result<TrustAnchors, ConfigError>` (or an intermediate
  `Vec<String>`/raw-bytes representation if constructing `TrustAnchors`
  itself doesn't belong in `config` — keep `domain`-crate types out of
  `config` if that violates the existing layering; check whether
  `RootHintConfig` keeps any `domain`-crate types before deciding, and if
  not, keep this loader returning rdns-owned types too, with the
  `TrustAnchors::from_u8()` conversion happening at the point section-03's
  validator actually consumes it).
- Update `RecursiveResolutionConfig::new()` and `::bundled()`
  (`:737-766`) constructors to set a sensible default
  `trust_anchor_source` (`Bundled` for `::bundled()`; for `::new()`,
  decide by symmetry with how it currently defaults `root_hints_source` —
  likely also `Bundled` unless a caller explicitly overrides it via a new
  builder-style setter, since `::new()`'s existing root-hints parameter is
  explicit but a trust-anchor override should be rarer and default-on).
- Update `RecursiveResolutionConfig::validate()` (`:775-816`) to call
  `load_trust_anchors()` and reject an empty/failed result with the new
  `ConfigError::MissingTrustAnchors` variant, mirroring the existing
  `MissingRootHints` check at `:780-782`.
- Add the corresponding `ConfigError` variants (see the "Existing
  `ConfigError` pattern" section above).

### 3. TOML deserialization plumbing

- Add a `trust_anchor: Option<String>` (default `"bundled"` when absent,
  matching the on-by-default posture the rest of this plan uses elsewhere)
  and `#[serde(default)] trust_anchor_entries: Vec<String>` field to
  `RawRecursiveResolutionConfig` (`:1868-1887`).
- In `RawRecursiveResolutionConfig::try_into_recursive_resolution_config()`
  (`:1905-1960`), add a match arm alongside the existing `root_hints`
  match (`:1937-1952`) that builds `TrustAnchorSource::Bundled` or
  `TrustAnchorSource::Static(entries)` from the new fields, erroring via
  `ConfigError::InvalidTomlConfig` on an unrecognized string, same pattern
  as the existing `root_hints`/`dnssec_validation`/`dname_handling`
  handling in that same function.
- Set the new field on the constructed `RecursiveResolutionConfig` before
  returning, same as the existing `config.dnssec_validation = ...` /
  `config.dname_handling = ...` assignments at `:1953-1954`.

### 4. CI staleness workflow (§A3)

- New workflow file, e.g. `.github/workflows/dnssec-anchor-staleness.yml`:
  - Trigger: `on: schedule` (weekly cron, e.g. `cron: '0 6 * * 1'`) plus
    `workflow_dispatch` for manual runs — explicitly **not** `pull_request`
    or `push`, so it never blocks unrelated PRs.
  - Job steps: checkout, fetch
    `https://data.iana.org/root-anchors/root-anchors.xml`,
    `root-anchors.p7s`, and `icannbundle.pem` from IANA, verify the CMS
    signature over the XML using the ICANN bundle certificate (RFC 9718),
    parse each `KeyDigest`'s `validFrom`/`validUntil`, and alert if either:
    (a) the currently-bundled digest set is missing a digest inside its
    valid window, or (b) any bundled digest's `validUntil` has passed or
    is within **60 days** of passing.
  - Treat a fetch/CMS-verification failure as a **distinct** alert
    ("couldn't confirm freshness") from an actual staleness finding
    ("anchor is stale") — don't merge the two into one alert message.
  - New script, e.g. `scripts/check-trust-anchor-staleness.sh` (or a small
    Python script, following `iana-org/get-trust-anchor`'s reference
    approach for the fetch step — note that script itself does **not** do
    CMS verification, so that part must be added, not borrowed).
  - New `make` target, e.g. `check-trust-anchor-staleness`, invoked from
    the workflow, consistent with how `check-bundled-data-freshness` is
    invoked from its job.
  - Alerting mechanism: match whatever this repo's other scheduled/alert
    workflows already use (check `.github/workflows/` for any existing
    non-blocking alert pattern — e.g. GitHub issue creation, Slack/webhook,
    or simply a failed scheduled-run notification via GitHub's own
    scheduled-workflow-failure emails) rather than inventing a new
    notification channel if one already exists in this repo.

---

## File paths touched

- `src/config/root-anchor.txt` (new — bundled trust-anchor data)
- `src/config/mod.rs` (modified — `TrustAnchorSource` enum,
  `bundled_trust_anchors()`, `RecursiveResolutionConfig` field/methods,
  `ConfigError` variants, `Raw*` TOML plumbing, plus new `#[cfg(test)]`
  tests per "Tests first" above)
- `.github/workflows/dnssec-anchor-staleness.yml` (new)
- `scripts/check-trust-anchor-staleness.sh` (new, or `.py` — match
  whichever the implementer judges cleaner for CMS verification; Python
  has more mature CMS/PKCS7 library support than bash+openssl one-liners,
  so consider deviating from the existing bash-script convention here if
  that materially simplifies the CMS check)
- `Makefile` (modified — new `check-trust-anchor-staleness` target)

## Notes for the implementer

- Do not wire `TrustAnchorSource` into `authority_config_hash()`'s
  cache-namespace hash (`:818-861`) as part of this section unless a
  clear need shows up — that hash currently only namespaces on root-hints
  and a handful of other fields; whether the trust-anchor source should
  also namespace the cache is a judgment call for section-03/04 (the
  validator wiring) to make once it's clear what changing the trust
  anchor set actually invalidates, not something to guess at here.
- Keep this section's diff behavior-inert for anything outside `config`
  parsing/validation — nothing in the resolver/cache path reads
  `trust_anchor_source` yet (that's section-03's job). `cargo test` for
  this section should be scoped to `src/config/mod.rs`'s test module.
- Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D
  warnings`, and `cargo test` (per `RUST.md`'s gates) before considering
  this section done, same as any other Rust change in this repo.

## As implemented

- KSK-2017 (tag 20326) and KSK-2024 (tag 38696) digests in
  `src/config/root-anchor.txt` were fetched live from
  `https://data.iana.org/root-anchors/root-anchors.xml` at implementation
  time (2026-07-18) and copied verbatim.
- `TrustAnchorSource::cache_namespace_label()` was added (matching the
  plan) but currently has no caller, since it isn't wired into
  `authority_config_hash()` yet per this section's own deferral note —
  marked `#[allow(dead_code)]` with a one-line reason to satisfy the
  `cargo clippy --all-targets` gate until section-03/04 wires it in.
- `scripts/check-trust-anchor-staleness.sh` was written in bash (not
  Python) using `openssl smime -verify` for the CMS check — IANA's own
  documented verification recipe — and grep/sed/tr for XML field
  extraction rather than a real parser. Chosen over a Python rewrite after
  review: this is a non-blocking weekly scheduled check, not a PR gate, so
  a parse hiccup from IANA reformatting means one missed scheduled run,
  not broken CI.
- The plan's A3 manual-verification step (run the script against a
  deliberately corrupted bundled file and confirm it flags drift) was
  performed during implementation: a corrupted digest was correctly
  flagged as "does not match IANA's published digest", and a deleted
  entry was correctly flagged as "bundle is missing an anchor". Documented
  in the script's header comment since this doesn't show up in `cargo
  test` output.
- Test count: 5 new `#[cfg(test)]` tests in `src/config/mod.rs`
  (`bundled_trust_anchors_parses_without_error`,
  `bundled_root_anchor_source_text_has_the_expected_key_tags`,
  `recursive_config_toml_honors_static_trust_anchor_override`,
  `recursive_config_toml_rejects_empty_static_trust_anchor_override`,
  `recursive_config_toml_rejects_malformed_static_trust_anchor_entry`),
  all passing; full suite (706 tests) passes with no regressions.