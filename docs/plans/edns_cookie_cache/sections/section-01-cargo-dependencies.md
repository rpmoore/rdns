Now I have a good sense of the format used for these sections. Let me write the content for section 1.

The section content:

# Section 01 — Cargo Dependency Changes

## Scope and status

This section makes a single, narrowly-scoped dependency change: enable
`domain`'s `siphasher` Cargo feature (already-present dependency) and add
`rand` as a new small direct dependency. **No behavior change** — no
production Rust code in `src/` is touched by this section. It exists to
unblock section-02's `edns_cookie.rs` module, which needs both
`domain::base::opt::cookie::{Cookie, ClientCookie, ServerCookie,
StandardServerCookie}` (unlocked by `siphasher`) and a CSPRNG for
generating the resolver's one process-lifetime cookie secret (`rand`,
used directly by rdns's own code, not via `domain`'s re-export).

## Dependencies

None — this is the first section in the plan, has no prerequisites, and
can be done in parallel with nothing else since everything else in the
plan (starting with section-02) depends on it.

## Background

`rdns` is a Rust DNS resolver/proxy. This plan (see the parent
`docs/plans/edns_cookie_cache/claude-plan.md` for full context) teaches
the resolver to recognize a well-formed RFC 7873 DNS Cookie EDNS option
as cache-compatible, and to attach a fresh RFC 9018 server cookie to
every response. The server-cookie construction (RFC 9018 §4.4: 1-byte
Version + 3-byte Reserved + 4-byte big-endian timestamp + 8-byte
SipHash-2-4 output serialized **little-endian**) is already implemented,
RFC-9018-test-vector-verified, and actively maintained inside the
`domain` crate — which is already a direct dependency of this project —
behind two optional Cargo features that are not currently enabled:

- `siphasher` — unlocks `domain::base::opt::cookie::{Cookie,
  ClientCookie, ServerCookie, StandardServerCookie}`, in particular
  `StandardServerCookie::calculate`, which takes a raw `secret: &[u8;
  16]` argument. Enabling this feature lets rdns call directly into that
  API without ever importing the `siphasher` crate itself — `siphasher`
  remains purely an internal implementation detail of `domain`.
- `rand` — **does not** give rdns's own code a usable public API for
  generating random bytes. It only unlocks `domain`'s *internal* use of
  `rand` inside its own middleware (e.g. `CookiesMiddlewareSvc`). It does
  not need to be enabled for this plan's purposes and should **not** be
  enabled on the `domain` dependency as a substitute for adding `rand`
  directly (see next point) — this was an explicit correction made
  during plan review, called out here so the implementer doesn't
  mistakenly think enabling `domain`'s `rand` feature is sufficient.

Generating `CookieSecret`'s random startup bytes (implemented in
section-02, not this section) requires `rand` as **rdns's own small,
direct dependency**. This is a genuine, if minimal, new dependency. Per
`RUST.md:20`: *"Add dependencies conservatively. A new crate should
improve correctness, reduce real complexity, or match an established
project pattern."* Rolling a bespoke PRNG for a security-relevant secret
(the process's one cookie-signing key) is exactly the kind of thing
`rand` exists to avoid getting wrong, so this satisfies that bar.

Net dependency picture after this section: one small new direct
dependency (`rand`), one feature-flag change on an already-present
dependency (`domain`'s `siphasher`), and **zero new hashing/crypto
crates** — `domain` already ships a complete, tested cookie
implementation; this section only turns on the Cargo features needed to
reach it.

## Current state (for reference — do not copy verbatim into the diff without re-reading the live file first)

`Cargo.toml` (repo root) currently contains:

```toml
[package]
name = "rdns"
version = "0.1.6"
edition = "2024"
rust-version = "1.96.1"
license = "Apache-2.0"

[dependencies]
bytes = "1"
domain = { version = "0.12.1", default-features = false, features = ["zonefile", "bytes", "std"] }
http-body-util = "0.1"
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
idna = "1"
opentelemetry = { version = "0.32.0", default-features = false, features = ["metrics"] }
opentelemetry-prometheus = "0.32"
opentelemetry_sdk = { version = "0.32.1", default-features = false, features = ["metrics"] }
prometheus = "0.14"
serde = { version = "1", features = ["derive"] }
serde_json = "1.0.150"
socket2 = "0.6"
tokio = { version = "1.28.2", features = ["full"] }
toml = "1.1"
tracing = "0.1.44"
tracing-subscriber = { version = "0.3.23", features = ["json", "env-filter"] }

[dev-dependencies]
tokio = { version = "1.28.2", features = ["test-util"] }
```

Re-read the live file before editing, in case it has drifted since this
section was written (dependency versions, entry ordering, etc.).

## What to change

**File to modify:** `Cargo.toml`

1. Change the `domain` dependency line's `features` list from
   `["zonefile", "bytes", "std"]` to also include `"siphasher"`:

```toml
domain = { version = "0.12.1", default-features = false, features = ["zonefile", "bytes", "std", "siphasher"] }
```

   Do **not** add `domain`'s `"rand"` feature — it is not needed (see
   Background above) and would be a no-op for rdns's own code.

2. Add `rand` as a new entry in `[dependencies]` (keep the list
   alphabetically ordered, matching this file's existing convention —
   `rand` sorts between `prometheus` and `serde`). Pick a version
   constraint consistent with this project's existing style (a bare
   major-version string, e.g. `rand = "0.8"` — check
   [crates.io](https://crates.io/crates/rand) at implementation time for
   the current stable major version actually compatible with `domain
   0.12.1`'s own `rand` usage, since a mismatched major version between
   rdns's direct `rand` dependency and whatever `domain` might pull in
   transitively could cause duplicate-version bloat in `cargo tree` —
   this is exactly what the verification step below checks for).

No other file changes are part of this section. In particular:
- No changes to `src/` — this section adds zero new Rust modules,
  functions, or types. `src/protocol/edns_cookie.rs` (which will
  actually use `rand` and `domain`'s cookie types) is section-02's
  responsibility, not this one.
- No changes to `Cargo.lock` beyond what `cargo build`/`cargo update`
  produces automatically as a result of the `Cargo.toml` edit — don't
  hand-edit `Cargo.lock`.

## Tests (from `claude-plan-tdd.md` Section 1)

This section has no unit tests — it is a pure dependency/build-config
change. Verification is build-level and manual, not `#[test]`-based:

- **Test: `cargo build` succeeds** after adding `rand` as a direct
  dependency and enabling `domain`'s `siphasher` feature. This is a
  build-passes check, not a unit test — verify via running the full
  build (and `cargo test` running at all post-change, i.e. the existing
  test suite still compiles and passes with the new `Cargo.toml`, even
  though no test code yet exercises the new dependencies).
- **Test: `cargo tree` inspection** confirms no unexpected heavy
  transitive dependencies were pulled in by `rand`. This is a manual
  verification step, not an automated test — run `cargo tree -i rand`
  and `cargo tree` (full tree diff before/after) and read the output;
  there is nothing to assert programmatically here, just confirm the
  new transitive dependency set looks reasonable (small, no surprise
  duplicate major-version copies of crates already in the tree, no
  unexpectedly large crates pulled in).

## Verification for this section

Per `RUST.md`'s gates:

- `cargo fmt --all -- --check` (should be a no-op — this section doesn't
  touch any `.rs` file).
- `cargo clippy --all-targets` (should be unaffected — no new code).
- `cargo build` — must succeed with the new `Cargo.toml`.
- `cargo test` — full existing suite must still compile and pass
  unchanged (no test yet exercises `rand` or `domain`'s `siphasher`
  feature; that begins in section-02).
- `cargo tree` review as described above — manual read, not scripted.

Do not proceed to section-02 until `cargo build` succeeds cleanly with
both the `siphasher` feature enabled on `domain` and `rand` present as a
direct dependency — section-02's module (`src/protocol/edns_cookie.rs`)
imports both.

## Implementation record

Implemented as planned, no deviations:

- `Cargo.toml`: `domain`'s `features` list gained `"siphasher"` (position
  unchanged, alphabetical dependency ordering preserved); `rand = "0.10"`
  added between `prometheus` and `serde`. `rand` 0.10.2 was current stable
  on crates.io at implementation time.
- `Cargo.lock` updated by `cargo build` (not hand-edited): added
  `chacha20 0.10.1`, `cpufeatures 0.3.0`, `getrandom 0.4.3`, `r-efi 6.0.0`,
  `rand 0.10.2`, `rand_core 0.10.1`, `siphasher 1.0.3`.
- Verification: `cargo fmt --all -- --check` (no-op), `cargo clippy
  --all-targets` (clean), `cargo build` (success), `cargo test` (all
  passing, network-dependent tests correctly `ignored`), `cargo tree -i
  rand` (only `rdns` depends on it directly — no duplicate-version bloat;
  `domain`'s own `rand` feature correctly left disabled per plan, so it
  doesn't pull `rand` in transitively at all).
- Code review raised a concern that the `Cargo.lock` dependency edges
  (`rand`→`chacha20`, `chacha20`/`getrandom`→`rand_core`) looked
  hand-authored rather than registry-resolved. Verified against the actual
  lock file and build output: this is real current-registry shape (`rand`
  0.10.x uses `chacha20` directly instead of the older `rand_chacha` crate;
  `chacha20`/`getrandom` implement `rand_core`'s traits). No changes made;
  see `implementation/code_review/section-01-interview.md` for the full
  verification trail.