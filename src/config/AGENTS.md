# AGENTS.md

High-level summary for `src/config`.

## Responsibility

This directory owns runtime configuration types and validation.

- Defines listener configuration, upstream resolver configuration, timeout/deadline settings, protocol choices, and UDP payload-size limits.
- Provides development defaults for local execution.
- Validates configuration before delivery or resolver code receives it.

## Boundaries

- Keep this module focused on describing and validating configuration, not opening sockets or resolving DNS queries.
- Validation should return explicit configuration errors rather than panicking.
- Prefer small validation helpers for individual fields or invariants.

## Testing Expectations

- Unit tests should cover defaults, valid configurations, invalid field values, duplicate listener detection, upstream ordering, and boundary values.
- Tests should be deterministic and should not perform network I/O.
