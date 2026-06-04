# AGENTS.md

High-level summary for `src/delivery`.

## Responsibility

This directory owns network transport for DNS traffic.

- `dns.rs` handles UDP listener binding, datagram receive/send loops, request concurrency limits, shutdown, and dispatch into resolver logic.
- `upstream.rs` handles outbound upstream DNS transport, transaction ID generation, UDP/TCP exchange behavior, timeout handling, upstream health state, retry timing, and response/source validation.
- `mod.rs` exposes delivery submodules.

## Boundaries

- Keep socket, transport, timeout, and shutdown concerns here.
- Do not place DNS wire-format parsing rules here except where needed to validate transport responses through protocol helpers.
- Do not place resolver policy, cache decisions, or metrics semantics here; call resolver abstractions instead.
- Inject or isolate side effects where tests need fake sockets, fake upstreams, or deterministic IDs.

## Testing Expectations

- Unit tests should cover listener lifecycle, datagram handling, concurrency limits, shutdown behavior, upstream failover/degraded state, timeout behavior, TCP framing paths, and response source validation.
- Prefer Tokio tests with local loopback sockets or fakes.
- Avoid depending on external DNS servers or real internet access.
