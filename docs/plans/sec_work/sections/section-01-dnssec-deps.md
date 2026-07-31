I have enough context now. Let me write the section content.

---

## section-01-dnssec-deps.md

# Section 01: DNSSEC Dependency and Feature Setup

## Summary

Pure foundation step for Track A (DNSSEC validation). Bumps the `domain` crate dependency to `0.12` with the `unstable-validator` and `ring` feature flags added, and confirms the crate still builds and the existing test suite passes unchanged. **No new logic, no behavior change.** Nothing downstream in Track A (section-02, section-03) can start until this lands, since they depend on the validator API and crypto backend these features enable.

This corresponds to plan section **A1** in `claude-plan.md`.

## Dependencies

None — this is the first section in Track A and has no prerequisites. It can run in parallel with section-07 (Track B's first section), since the two tracks touch disjoint files.

## Background

`rdns` is a Rust DNS resolver/proxy. It already fetches DNSKEY/DS/RRSIG material for every recursive query and the cache/response layer already fully consumes a `DnssecState` verdict (SERVFAIL-on-Bogus, AD-bit-on-Secure), but nothing currently produces that verdict — every entry sits at `Unvalidated` forever. Track A closes that gap by adding a real validation pass, built on the `domain` crate's `dnssec::validator` module rather than hand-rolling DNSSEC validation.

The `domain` crate's validator API had a breaking reorganization in `0.11.0`; that boundary is now behind the version this plan targets, so pinning the major.minor floor explicitly at `0.12` avoids accidentally re-crossing it in the future via an unconstrained bump.

## Current state

`Cargo.toml` currently has:

```toml
domain = { version = "0.12.1", default-features = false, features = ["zonefile", "bytes", "std", "siphasher"] }
```

`Cargo.lock` already resolves this to `0.12.2` transitively — the version constraint itself doesn't need to move much, but the feature list does.

## Implementation

File to modify: `/home/rpmoore/code/rdns/Cargo.toml`

1. Update the `domain` dependency line to explicitly pin the major.minor floor at `0.12` (e.g. `version = "0.12"` or keep an explicit `"0.12.1"` lower bound — either is acceptable as long as it doesn't silently allow crossing into a future `0.13` that might reorganize the validator API again; use judgment based on what's idiomatic elsewhere in this `Cargo.toml`, which uses bare major-version specifiers like `"1"` for most other deps).
2. Add two new feature flags to the `domain` dependency's `features` list, alongside the existing `["zonefile", "bytes", "std", "siphasher"]`:
   - `unstable-validator` — enables `domain`'s DNSSEC validator module (`domain::dnssec::validator`), which section-03 will build on.
   - `ring` — the pure-Rust crypto backend used for signature verification, chosen over `openssl` per the plan's decided scope (avoids adding an OpenSSL system-dependency to the build).
3. Add a `Cargo.toml` comment near the `domain` dependency line (or plan to note this in the PR description — either satisfies the plan, but a comment directly on the line is more durable) stating that `unstable-validator` transitively pulls in two new dependencies:
   - `moka` (a caching crate, used internally by the validator)
   - `unstable-client-transport` (a `domain` feature providing the client-transport types the validator needs)

   This is expected and accepted, not a mistake to "fix" later in review. This step has no *runtime* behavior change on its own, but it does expand rdns's build and supply-chain surface — call that out explicitly in the PR description, not just as an inert dependency bump.

4. Run `cargo build` and `cargo test` with the new feature flags enabled, before writing any validator code. This isolates dependency/build issues from logic issues that section-02/section-03 will introduce. Do not write any new `.rs` files or modify any other source file in this section — it is a dependency-only change.

## Tests

This section has no new unit tests to write (no new logic exists yet). Instead, verify via build/suite commands — these are the acceptance checks for the section, run manually (or via CI), not `#[test]` functions to add to the codebase:

- **Build check**: `cargo build` succeeds with the `unstable-validator` and `ring` features enabled and no other code changes. This confirms the feature flags alone don't break compilation before any validator code exists.
- **Full suite check**: the existing full test suite (`cargo test`) still passes unchanged with the new features enabled. This confirms there is no accidental behavior change from the dependency bump alone — a pure feature-flag/version change should never alter existing test outcomes.

No new unit tests belong in this section beyond these two build/suite verifications.

## Verification gates

Per this repo's standing rules (`RUST.md`), before considering this section done:

- `cargo fmt --all -- --check` (Cargo.toml formatting is not affected by `cargo fmt`, but run this anyway per the standing gate since it's required before any Rust change is reported done)
- `cargo clippy --all-targets` — should show no new warnings; a feature-only dependency bump should not introduce clippy findings, but confirm since the new features may expose additional code paths that clippy now lints (e.g. if `unstable-validator` types leak into anything, though at this stage nothing in rdns's own code references them yet)
- `cargo test` — full suite, as described above

## Acceptance criteria

- `Cargo.toml`'s `domain` dependency includes `unstable-validator` and `ring` in its feature list, with the major.minor floor pinned at `0.12`.
- A comment (in `Cargo.toml` or the PR description) documents the `moka`/`unstable-client-transport` transitive dependency expansion.
- `cargo build` succeeds.
- `cargo test` passes with no behavior change (i.e., the same tests pass/fail as before this change — none should newly fail, and no new tests are expected to exist yet).
- No files other than `Cargo.toml` (and `Cargo.lock`, updated automatically by `cargo build`/`cargo test`) are modified in this section.