# Resolver And Cache Domain

## Responsibility

The resolver domain coordinates lookup behavior. It receives a parsed query and client context, applies policy, checks cache, forwards allowed misses to upstream resolvers, stores cacheable responses, and returns DNS response bytes.

It should not parse blocklist files, render UI, perform direct database queries, or own low-level socket code.

## Application Service

Introduce a `ResolveQuery` service.

Inputs:

- Client IP address.
- Raw DNS request bytes.
- Receive timestamp.

Injected ports:

- `ProtocolCodec`
- `PolicyEvaluator`
- `DnsCache`
- `UpstreamResolver`
- `ResponseFactory`
- `Clock`
- `QueryEventSink`
- `MetricsSink`

Output:

- DNS response bytes.
- Query decision metadata for logging and metrics.

## Flow

1. Parse the request.
2. If parsing fails, return a protocol error response where possible.
3. Convert the question to a normalized `QuestionKey`.
4. Evaluate policy for the client and domain.
5. Return the configured blocked response if policy denies the lookup.
6. Check cache for an allowed query.
7. On hit, rewrite the transaction ID and return cached bytes.
8. On miss, forward to an upstream resolver.
9. Validate that the upstream response matches the request question and ID.
10. Cache cacheable responses with an expiry based on DNS TTLs and local caps.
11. Emit query event and metrics.

## Cache Design

Start with an in-memory TTL cache.

Cache key:

- Normalized domain name.
- Query type.
- Query class.
- DNSSEC checking/disabled flags when those are supported.
- EDNS-relevant behavior when EDNS is supported.
- Upstream policy variant if configuration can produce different answers.
- Effective client UDP response size when cached serialization can differ by request size.

Cache value:

- Canonical response template or RRset data that can be serialized with the current request ID.
- Response code.
- Minimum answer TTL.
- Stored time.
- Expiry time.
- Negative-cache metadata for NXDOMAIN/NODATA when available.

Do not blindly replay raw upstream packets. If raw bytes are cached for performance, the cache layer must store them as response templates and the protocol layer must rewrite the transaction ID and any request-dependent fields safely before returning them.

Cached responses must be serialized for the current request context. Re-check transaction ID, request flags that affect response semantics, and UDP size/truncation behavior before returning a cache hit.

TTL policy:

- Use the minimum TTL across answer records for positive responses.
- Cap very large TTLs with a configurable max TTL.
- Optionally raise very small TTLs with a conservative min TTL only if configured.
- Support negative caching using SOA-derived TTL from authority records per RFC 2308.
- Never cache malformed upstream responses.
- Avoid caching responses for unsupported or ambiguous query shapes.
- Bypass cache for query features the resolver does not understand yet.
- Do not cache upstream timeouts.
- Cache `SERVFAIL` only if an explicit short failure-cache setting is enabled.

Poisoning boundaries:

- Validate that an upstream response was received from the upstream endpoint selected for that query.
- Generate an independent upstream transaction ID and map it back to the client request instead of reusing the client ID blindly.
- Validate upstream response ID, question name, question type, and question class before accepting it.
- Do not promote unrelated authority or additional-section records into reusable cache entries unless bailiwick and record ownership rules are explicitly implemented.
- For the first cache implementation, cache only an exact-question response template or exact-question RRsets. Do not use additional records to answer different future questions.

Concurrency:

- The cache must be safe under concurrent requests.
- Add single-flight behavior so many simultaneous misses for the same key share one upstream request.
- Keep cache lock scope small; do not hold locks during upstream network I/O.

## Upstream Resolution

Support configurable upstream resolvers:

- UDP upstreams first.
- TCP fallback for truncated UDP responses.
- Per-upstream timeout.
- Retry policy with bounded attempts.
- Health state based on recent failures.
- Circuit-breaker behavior for repeatedly failing upstreams.
- Selection strategy: ordered failover initially, weighted/round-robin later.

Do not begin with DNS-over-HTTPS or DNS-over-TLS unless explicitly added as a later feature. Plain UDP/TCP is enough for the first local resolver milestone.

Initial upstream strategy:

- Try enabled upstreams in priority order.
- Use one attempt per upstream per query before returning `SERVFAIL`.
- Apply a per-query overall deadline so failover cannot hang the client.
- Use a fresh randomized upstream DNS transaction ID per upstream attempt.
- Validate the upstream source address and transaction ID before accepting a response.
- Mark upstreams degraded after consecutive timeout/malformed-response failures.
- Recover degraded upstreams after a successful probe or successful real query.
- Do not race all upstreams in parallel in the first implementation; it adds load and complicates deterministic tests.

## Failure Behavior

Define deterministic responses:

- All upstreams timeout: `SERVFAIL`.
- Upstream returns malformed response: try next upstream, then `SERVFAIL`.
- Upstream response question mismatch: reject response and try next upstream.
- Upstream returns `NXDOMAIN`: return it and negative-cache according to TTL policy.
- Cache entry expired: treat as miss.
- Cache is unavailable: continue with upstream lookup and emit degraded metric.

## Concern: `ResolveQuery` Size

`ResolveQuery` is an orchestration service, not a place for all behavior. It should delegate to narrow ports:

- `PolicyEvaluator` for allow/block decisions.
- `DnsCache` for cache lookup/store.
- `UpstreamResolver` for forwarding and failover.
- `ResponseFactory` for DNS response construction choices.
- `QueryEventSink` for logging.
- `MetricsSink` for counters and timings.

This keeps the central request flow readable without turning it into the implementation of every subsystem.

## Tests

Unit tests:

- Cache key normalization.
- TTL calculation.
- Positive cache hit and miss.
- Negative cache behavior.
- Cache expiry.
- Policy denial short-circuits cache/upstream.
- Single-flight duplicate miss behavior.

Integration tests:

- Fake UDP upstream returns known responses.
- Truncated UDP response triggers TCP fallback.
- Multiple upstream failover.
- Concurrent query load does not panic or hold locks during I/O.
- Unsupported query features bypass cache.
- Cached response uses the current client request ID.
- Upstream replies from the wrong endpoint or transaction ID are rejected.
- Additional-section records are not reused to answer unrelated questions before bailiwick support exists.
- Cached responses respect the current client's UDP response size.
