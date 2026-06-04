# AGENTS.md

High-level summary for `src/protocol`.

## Responsibility

This directory owns DNS protocol parsing, validation, and wire-format helpers.

- Defines DNS message, header, question, record, EDNS, response-code, and parse-error domain types.
- Parses UDP DNS messages and TCP DNS frames.
- Validates supported query shape and DNS semantics.
- Builds protocol-level responses and rewrites byte-level request/response fields.
- Handles TTL aging/capping, question extraction, EDNS behavior, compression pointers, and record parsing.

## Boundaries

- Keep this module deterministic and byte-oriented.
- Do not perform socket I/O, cache lookups, upstream selection, metrics emission, or policy decisions here.
- Prefer small parser helpers with explicit offsets and clear error returns.
- Treat malformed or truncated packets as recoverable parse errors.

## Testing Expectations

- Unit tests should cover valid messages, malformed input, truncation, compression pointers, EDNS, TCP framing, response construction, TTL rewriting, and supported record types.
- Keep tests table-driven where it improves coverage without hiding important byte-level details.
- Tests should not use network I/O or wall-clock timing except for deterministic duration values.
