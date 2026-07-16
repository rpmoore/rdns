# Section 01 Code Review Interview

## Reviewer finding: Cargo.lock dependency edges look hand-authored

**Reviewer claim:** `rand 0.10.2` depending directly on `chacha20` (rather than
via a `rand_chacha` crate), and `chacha20`/`getrandom` depending on
`rand_core`, don't match the reviewer's expectations for how these crates
relate, suggesting the lock file was hand-edited rather than produced by a
real `cargo build`.

**Resolution: false alarm, verified against ground truth, no action taken.**

The Cargo.lock in this diff was produced by an actual `cargo build` run
against the live crates.io registry (see build output: `Locking 7 packages to
latest Rust 1.96.1 compatible versions`, `Adding chacha20 v0.10.1`, `Adding
getrandom v0.4.3`, `Adding rand v0.10.2`, `Adding rand_core v0.10.1`, `Adding
siphasher v1.0.3`, `Adding r-efi v6.0.0`, `Adding cpufeatures v0.3.0`). No
manual editing occurred.

Re-inspected the resulting `Cargo.lock` directly:
- `rand 0.10.2` deps: `chacha20`, `getrandom`, `rand_core` — current `rand`
  0.10.x does use the `chacha20` crate directly for its ChaCha RNG backend
  (a restructuring vs. older `rand` versions that used a separate
  `rand_chacha` crate; there is no `rand_chacha` package anywhere in this
  lock file, confirming it's not present as a leftover/duplicate).
- `chacha20 0.10.1` deps: `cfg-if`, `cpufeatures`, `rand_core` — `chacha20`
  implements `rand_core`'s `RngCore` trait behind a feature, hence the edge.
- `getrandom 0.4.3` deps: `cfg-if`, `libc`, `r-efi`, `rand_core` — recent
  `getrandom` versions implement `rand_core::TryRngCore`, hence the edge.
- `rand_core 0.10.1` itself has **zero** dependencies — it's a small,
  trait-only crate, so multiple leaf crates depending on it to implement its
  traits is not circular and not surprising.

Reviewer's priors (rand_chacha-based backend, no rand_core reverse edges)
reflect older `rand`/RustCrypto ecosystem shapes and don't hold for the
current registry state as of this implementation (`rand` 0.10.2, `chacha20`
0.10.1, `getrandom` 0.4.3). No lock file changes made as a result of this
finding.

## Secondary notes (auto-resolved, no action needed)

- **Rand version rationale not recorded in a comment:** plan asked to check
  crates.io at implementation time. Confirmed via `cargo search rand` that
  `0.10.2` is current stable; `rand = "0.10"` is the correct current pin. No
  code comment added — version rationale belongs in this review transcript,
  not as an inline `Cargo.toml` comment (no existing convention in this file
  for per-dependency comments).
- **Duplicate-version-bloat check is moot:** since `domain`'s own `rand`
  feature was correctly left disabled (per plan), `domain` does not pull in
  `rand` transitively at all — confirmed via `cargo tree -i rand` showing
  only `rdns` as a direct consumer. Nothing to collide with; the plan's
  stated concern doesn't apply to this diff. No action needed.

## Verification re-confirmed

- `cargo build`: success.
- `cargo fmt --all -- --check`: no-op, exit 0.
- `cargo clippy --all-targets`: clean, exit 0.
- `cargo test`: all passing (38 + 8 + 4 in respective suites, rest correctly
  `ignored` for requiring network access).
- `cargo tree -i rand`: only `rdns` depends on it directly; no duplicate
  major versions introduced.
