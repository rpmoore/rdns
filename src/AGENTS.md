# AGENTS.md

High-level summary for `src`.

## Responsibility

This directory contains the crate's public module tree and executable entry point.

- `lib.rs` exposes the library modules used by the binary and tests.
- `main.rs` assembles runtime configuration, resolver dependencies, UDP listeners, query event handling, and metrics for the executable.
- Subdirectories own the main architectural layers: configuration, network delivery, DNS protocol handling, and resolver domain logic.

## Boundaries

- Keep application wiring in `main.rs` thin. Move reusable behavior into library modules.
- Do not put DNS parsing, cache policy, or socket transport details directly in top-level files unless they are only wiring concerns.
- Prefer module-level APIs that make ownership and side effects explicit.

## Testing Expectations

- Most behavior should be tested in the specific module that owns it.
- Add top-level tests only when the behavior spans multiple modules and cannot be tested cleanly at a lower level.
- Avoid requiring real network access for unit tests.
