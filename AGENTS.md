# AGENTS.md

Guidance for Codex and other coding agents working in this repository.

## Project Context

`rdns` is a Rust DNS resolver/proxy. It uses Tokio for async networking, keeps DNS protocol logic in explicit domain modules, and uses traits at important boundaries so resolver behavior can be tested without real network I/O.

## Rust Code Standards

- Run `cargo fmt` before finalizing Rust changes.
- Run `cargo test` for behavior changes. Narrow tests are fine while iterating, but prefer the full suite before finishing.
- Prefer clear domain types over primitive-heavy APIs and loosely structured tuples.
- Keep public APIs small and intentional. Expose only what other modules or tests need.
- Use `Result<T, E>` with meaningful error types for recoverable failures.
- Avoid `unwrap` and `expect` in production code unless the invariant is local and obvious.
- Keep async I/O at the edges. Put parsing, validation, transformation, and policy decisions in synchronous helpers where practical.
- Preserve existing copyright and license headers in Rust source files.
- Add dependencies conservatively. A new crate should improve correctness, reduce real complexity, or match an established project pattern.
- Prefer deterministic tests. Avoid sleeps, wall-clock dependence, and real network access unless the test is intentionally integration-level.

## Software Development Practices

- Write small, testable functions with one clear responsibility.
- Separate concerns by layer:
  - `config` owns runtime settings and validation.
  - `delivery` owns socket, listener, and upstream transport I/O.
  - `protocol` owns DNS wire-format parsing, validation, and encoding.
  - `resolver` owns resolution decisions, cache behavior, policy, metrics, and events.
- Keep orchestration code thin. Move decision logic into helpers or domain services that can be unit tested directly.
- Preserve boundaries between pure logic, I/O, metrics, and logging/event emission.
- Prefer injected dependencies for clocks, sinks, resolvers, ID generators, and other side effects when testability matters.
- Add tests at the lowest useful level. Parser edge cases belong near parser code; resolver behavior belongs near resolver code; socket behavior belongs near delivery code.
- Keep functions short enough to scan. If a function mixes validation, transformation, I/O, metrics, and error handling, split it.
- Name functions by behavior and outcome rather than implementation detail.
- Do not rewrite unrelated code for style alone.

## Change Workflow

- Inspect existing module patterns before editing.
- Keep edits scoped to the requested behavior.
- When adding behavior, add or update tests that would fail without the change.
- When fixing a bug, include a regression test whenever practical.
- When working on a step in `docs/steps.md` that links to a GitHub issue, update that issue's status as work progresses. Leave a concise progress comment when starting or materially changing scope, and close the issue only after the step's acceptance criteria and verification are complete.
- After changes, summarize what changed and which verification commands were run.

## Directory Summary Instructions

Do not use this root `AGENTS.md` to store a full summary of the current codebase. Instead, future agents should summarize code close to the directory being described.

- Before searching through a directory for context, inspect that directory's local `AGENTS.md` if one exists. Use it to understand the directory's responsibilities, boundaries, and testing expectations before reading or searching broader code.
- Do not update a directory-local `AGENTS.md` after every change. Add or update one only when a change makes the existing summary stale or when new context would materially help future agents understand that directory.
- Each directory-local summary must describe what that directory contains at a high level.
- Keep each directory summary under 200 lines.
- Summaries should explain responsibilities, important module boundaries, and testing expectations.
- Summaries should avoid listing every function or restating implementation details that are obvious from filenames.
- Update a directory summary when the directory's responsibilities change, new major modules are added, or old responsibilities move elsewhere.
