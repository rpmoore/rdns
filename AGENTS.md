# AGENTS.md

Guidance for Codex and other coding agents working in this repository.

## Project Context

`rdns` is a Rust DNS resolver/proxy. It uses Tokio for async networking, keeps DNS protocol logic in explicit domain modules, and uses traits at important boundaries so resolver behavior can be tested without real network I/O.

## Automatic Triggers

These run without being asked, no explicit request needed:

- Plan drafted → adversarial-review the plan before presenting it (Change Workflow).
- Diff ready to commit → adversarial-review the diff before committing (Change Workflow).
- Nontrivial code change done → run `verify` skill before reporting done (Change Workflow).
- PR touches auth/untrusted-input/network code → run `/security-review` before opening PR (Change Workflow).
- PR feedback reviewed → mark resolved or state why not (Change Workflow).
- Code change complete → log entry to Obsidian daily note, if available (Change Logging).

## Caveman Tooling

- For read-only code location ("where is X defined", "map this directory"), delegate to `cavecrew-investigator` instead of exploring inline — output is context-compressed.
- For bounded 1–2 file mechanical edits (typo fixes, renames, format-preserving tweaks), delegate to `cavecrew-builder`. Do not route new features, new files, or cross-file refactors through it.
- For diff/PR review output, use `cavecrew-reviewer` or `/caveman-review` for compressed, severity-tagged one-line findings instead of prose review.
- For commit messages, use `/caveman-commit` to keep them terse and Conventional-Commits formatted.
- Keep cavecrew delegation scoped to narrow, mechanical work only — multi-file refactors, new features, and architecture decisions stay in the main agent.

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
- Avoid unnecessary data copying; prefer borrowing or sharing buffers when possible.

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
- Before committing substantive code or documentation changes, run `/codex:adversarial-review` on the intended diff to challenge the implementation approach, design choices, and assumptions. Address actionable feedback before committing, or document why feedback is not being acted on. If feedback fixes materially change the diff, run one follow-up adversarial review on the updated diff before committing.
- When working on a step in `docs/steps.md` that links to a GitHub issue, update that issue's status as work progresses. Leave a concise progress comment when starting or materially changing scope, and close the issue only after the step's acceptance criteria and verification are complete.
- When reviewing GitHub PR feedback, always mark the feedback as resolved when the feedback has been addressed, or state why the comment was not addressed.
- After drafting an implementation plan (Plan mode or `/deep-plan`) and before presenting it for approval, auto-run `/codex:adversarial-review` on the plan itself. Address feedback or state why not, same as diff review.
- After nontrivial code changes and before reporting the task done, auto-run the `verify` skill against the affected flow. Skip for test-only or doc-only diffs.
- Before opening a PR that touches auth, parsing of untrusted input, or network-facing code, auto-run `/security-review`.
- After changes, summarize what changed and which verification commands were run.

## Change Logging

After code changes are complete, write one summary of what changed and why to Obsidian's daily note, under a heading/section for `rdns_change_log`, if an `mcp__obsidian__*` tool is available in the session. Daily notes for this project live under the vault directory `rdns_change_log/` (e.g. `rdns_change_log/2026-07-03.md`), not at the vault root — get the current daily note's path with `mcp__obsidian__periodic_note_get_path` (period `daily`) rather than guessing a root-level `YYYY-MM-DD.md` path. Use `mcp__obsidian__vault_patch` targeting the `rdns_change_log` heading (or `vault_append` if no daily note structure exists yet). Do not log per-step; one entry per logical change is enough.

Keep entries compact: terse phrasing, no filler, drop restating obvious context (file paths/diffs are already in git). Entry must stay skimmable and cheap to reload into context later — aim for a few lines, not paragraphs.

If no `mcp__obsidian__*` tool is available, skip Obsidian logging and instead summarize what changed and why in the PR description or final response.

## Directory Summary Instructions

Do not use this root `AGENTS.md` to store a full summary of the current codebase. Instead, future agents should summarize code close to the directory being described.

- Before searching through a directory for context, inspect that directory's local `AGENTS.md` if one exists. Use it to understand the directory's responsibilities, boundaries, and testing expectations before reading or searching broader code.
- Do not update a directory-local `AGENTS.md` after every change. Add or update one only when a change makes the existing summary stale or when new context would materially help future agents understand that directory.
- Each directory-local summary must describe what that directory contains at a high level.
- Keep each directory summary under 200 lines.
- Summaries should explain responsibilities, important module boundaries, and testing expectations.
- Summaries should avoid listing every function or restating implementation details that are obvious from filenames.
- Update a directory summary when the directory's responsibilities change, new major modules are added, or old responsibilities move elsewhere.
