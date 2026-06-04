# AGENTS.md

High-level summary for `src/resolver`.

## Responsibility

This directory owns core resolver domain behavior.

- Defines resolver requests and outcomes, decoded queries, cache keys, cache lookup/store types, TTL policy, policy decisions, event sinks, query event storage, metrics sinks, upstream abstractions, protocol codec abstractions, and response factory behavior.
- Implements in-memory DNS caching, query event retention/indexing, cache TTL decisions, negative caching metadata, cache bypass rules, request coalescing, upstream orchestration, and protocol error handling.
- Coordinates protocol helpers, cache behavior, upstream resolver traits, clocks, metrics, observed source context, full DNS response code capture, and event recording.

## Boundaries

- Keep resolution decisions and observable outcomes here.
- Do not manage listener sockets or outbound socket details here; use delivery-layer implementations behind traits.
- Keep pure policy/cache decision helpers separated from async orchestration where practical.
- Prefer dependency injection for clocks, caches, upstream resolvers, protocol codecs, event sinks, and metrics sinks.

## Testing Expectations

- Unit tests should cover cache key generation, cache lookup/store behavior, TTL policy, negative caching, cache bypass, request coalescing, protocol error responses, upstream success/failure paths, metrics increments, query event storage/indexing, observed source context, full response code capture, and event recording.
- Prefer fake clocks, fake upstreams, fake sinks, and deterministic byte fixtures.
- Add regression tests for resolver bugs because this layer coordinates most user-visible behavior.
