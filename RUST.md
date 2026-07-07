# RUST.md

Rust-specific engineering standards for this crate. See `AGENTS.md` for repo-wide workflow, tooling, and logging expectations — this file only covers language- and toolchain-level rules.

## Formatting & Linting

- Run `cargo fmt --all` before finalizing any Rust change, no exceptions.
- Run `cargo fmt --all -- --check` as the last step before reporting a change done or handing off a diff for review/commit, and re-run it again if you edit a file afterward (e.g. to fix a clippy or test failure). Do not rely on CI to catch drift — a format error reaching CI is a process failure, not just a CI failure.
- Run `cargo clippy --all-targets` before finishing. This repo's baseline is warning-free; a new warning must be fixed or explicitly justified with an `#[allow(...)]` plus a one-line reason, not left unaddressed.
- Run `cargo test` for behavior changes. Narrow tests are fine while iterating, but prefer the full suite before finishing.

## Code Standards

- Prefer clear domain types over primitive-heavy APIs and loosely structured tuples.
- Keep public APIs small and intentional. Expose only what other modules or tests need.
- Use `Result<T, E>` with meaningful error types for recoverable failures.
- Avoid `unwrap` and `expect` in production code unless the invariant is local and obvious.
- Keep async I/O at the edges. Put parsing, validation, transformation, and policy decisions in synchronous helpers where practical.
- Preserve existing copyright and license headers in Rust source files.
- Add dependencies conservatively. A new crate should improve correctness, reduce real complexity, or match an established project pattern.
- Prefer deterministic tests. Avoid sleeps, wall-clock dependence, and real network access unless the test is intentionally integration-level.
- Avoid unnecessary data copying; prefer borrowing or sharing buffers when possible.
