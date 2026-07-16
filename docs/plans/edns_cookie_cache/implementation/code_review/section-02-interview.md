# Section 02 Code Review Interview

## Finding 1: `rand::rng().fill_bytes(...)` won't compile — false alarm

**Reviewer claim:** `fill_bytes` is on `RngCore`, not `Rng`; importing only
`use rand::Rng;` wouldn't bring it into scope, so this should fail with
E0599.

**Resolution: false alarm, verified — no action taken.** This exact code
was already built, clippy-checked, and exercised by tests before the
review ran (`cargo build`, `cargo clippy --all-targets`, `cargo test
edns_cookie` all passed cleanly). Re-confirmed by reading `rand_core`
0.10.1's source directly: `fill_bytes` is declared on the `Rng` trait
itself (`rand_core::Rng` at `lib.rs:49-62`), and `RngCore` (`lib.rs:257`)
is just an empty marker trait (`pub trait RngCore: Rng {}`) kept for
naming continuity. `rand`'s re-export (`pub use rand_core::{..., Rng,
...}`) is exactly what's imported. Reviewer's claim reflects the
pre-0.9 `rand` trait split (where `RngCore` did carry `fill_bytes`
independently of `Rng`), which no longer holds in 0.10.x. No changes made.

## Finding 2: `build_server_cookie` byte reassembly not pinned to a known-good absolute value

**Resolution: auto-fixed.** Added
`build_server_cookie_matches_rfc_9018_appendix_a1_vector`, using the exact
fixed secret/client-cookie/timestamp/client-IP quadruple from RFC 9018
Appendix A.1 (also used by `domain`'s own cookie.rs test suite) and
asserting the full 16-byte output byte-for-byte. This closes the gap the
reviewer identified: the existing tests checked layout shape and
IP-sensitivity but never pinned the manual
`version()/reserved()/timestamp()/hash()` byte reassembly against a
published correct value. Test passes.

## Finding 3: no truncated/malformed-TLV-header regression test

**Resolution: auto-fixed.** Added
`parse_cookie_option_rejects_truncated_tlv_bytes`, covering both a
dangling option header (fewer than 4 bytes remaining) and a declared
option length that overruns the remaining buffer — the two guard clauses
in `locate_cookie_option` (`options.len() - cursor < 4` and `data_end >
options.len()`) that were previously exercised only incidentally. Confirms
no panic on adversarial/truncated wire input. Test passes.

## Finding 4: `is_solely_cookie_option` malformed/absent/duplicate cases collapsed into one test function

**Resolution: let go (nitpick).** Not incorrect, just a minor structural
divergence from the plan's enumerated one-test-per-case list; all three
cases are still asserted. No action taken.

## Verification re-confirmed after fixes

- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets`: clean, no new warnings.
- `cargo test edns_cookie`: 16/16 passing (up from 14, +2 new regression
  tests).
- `cargo test` (full suite): 587 passing (up from 585), 0 failed.
