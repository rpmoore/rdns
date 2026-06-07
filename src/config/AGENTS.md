# AGENTS.md

High-level summary for `src/config`.

## Responsibility

This directory owns runtime configuration types, resolution-mode settings, and validation.

- Defines listener configuration, forward upstream configuration, recursive resolver configuration, timeout/deadline settings, protocol choices, root hints, DNSSEC mode flags, and UDP payload-size limits.
- Provides development defaults for local forwarding execution and bundled/static recursive root-hints configuration.
- Validates configuration before delivery or resolver code receives it.
- Produces backend cache namespace labels from resolution generation, enabled UDP forward upstreams, recursive root hints, and DNSSEC mode.

## Boundaries

- Keep this module focused on describing and validating configuration, not opening sockets or resolving DNS queries.
- Forward mode requires at least one enabled UDP upstream because the forwarding backend uses UDP upstream configuration.
- Recursive mode owns root-hints and recursive-limit validation and does not require forward upstreams.
- Validation should return explicit configuration errors rather than panicking.
- Prefer small validation helpers for individual fields or invariants.

## Testing Expectations

- Unit tests should cover defaults, valid configurations, invalid field values, duplicate listener detection, upstream ordering, resolution modes, cache namespaces, recursive root hints, recursive limits, and boundary values.
- Tests should be deterministic and should not perform network I/O.
