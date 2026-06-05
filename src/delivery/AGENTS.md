# AGENTS.md

High-level summary for `src/delivery`.

## Responsibility

This directory owns network transport for DNS traffic.

- `dns.rs` handles UDP listener binding, datagram receive/send loops, request concurrency limits, shutdown, and dispatch into resolver logic. It passes observed UDP source context into resolver requests so query events can retain source IP, source port, transport, and listener address.
- `upstream.rs` handles outbound forwarding DNS transport, recursive authority transport, transaction ID generation, UDP/TCP exchange behavior, timeout handling, upstream health state, retry timing, TCP fallback on truncation, and response/source validation.
- `mod.rs` exposes delivery submodules.

## Boundaries

- Keep socket, transport, timeout, and shutdown concerns here.
- Do not place DNS wire-format parsing rules here except where needed to validate transport responses through protocol helpers.
- Do not place resolver policy, cache decisions, or metrics semantics here; call resolver abstractions instead.
- Recursive authority transport should only choose allowed transports, bound EDNS payloads to configuration, validate authority responses against the requested question, and report transport fallback metrics.
- Inject or isolate side effects where tests need fake sockets, fake upstreams, or deterministic IDs.

## Testing Expectations

- Unit tests should cover listener lifecycle, datagram handling, observed source endpoint and listener context propagation, concurrency limits, shutdown behavior, upstream failover/degraded state, timeout behavior, TCP framing paths, recursive authority UDP/TCP paths, truncation fallback, and response source/question validation.
- Prefer Tokio tests with local loopback sockets or fakes.
- Avoid depending on external DNS servers or real internet access.
