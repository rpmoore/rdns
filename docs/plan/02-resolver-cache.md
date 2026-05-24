# Resolver And Cache Domain

## Responsibility

The resolver domain coordinates lookup behavior. It receives a parsed query and client context, applies policy, checks cache, resolves allowed misses through a configured resolution backend, stores cacheable responses, and returns DNS response bytes.

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
- `ResolutionBackend`
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
8. On miss, call the configured `ResolutionBackend`.
9. The backend either forwards to configured upstream recursive resolvers or performs local iterative recursion.
10. Validate that the backend response matches the request question and ID.
11. Cache cacheable responses with an expiry based on DNS TTLs and local caps.
12. Emit metrics and a structured query event through a non-blocking sink.

## Query Event Pipeline

Every client query should produce one terminal query event, whether it is answered from cache, answered by a backend, blocked by policy, rejected by protocol validation, or failed locally. This event stream is the source for per-source review, suspicious lookup triage, query history, and durable query logging.

The resolver hot path must not perform storage work or wait for event-processing capacity. `QueryEventSink` should be best-effort and non-blocking, such as `try_record(event) -> QueryEventRecordResult`, or otherwise guarantee that `record` enqueues without waiting for downstream storage. Overflow behavior must be explicit:

- disabled logging;
- drop newest;
- drop oldest;
- sample;
- accept.

Metrics must distinguish accepted, dropped, sampled, and disabled events by reason. DNS responses must continue even when event storage, classification, or later SQLite persistence is slow or unavailable.

Start with a minimal stable `QueryEventV1` that is available after Phase 3:

- schema version;
- monotonic sequence number for stable ordering;
- timestamp;
- observed source endpoint: source IP, optional source port, transport, and listener address;
- optional later `ClientIdentitySnapshot` with identity strategy and generation;
- original and normalized question name;
- qtype and qclass;
- terminal outcome: `answered`, `blocked`, `protocol_error`, `backend_failure`, or `dropped_before_resolution`;
- local DNS response code when one is returned;
- cache result: miss, hit, bypass, expired, unavailable, or not-applicable;
- latency;
- advisory classifier findings.

Do not overload one field with resolver outcome, DNS response code, policy decision, backend result, and classifier conclusions. Later phases can attach optional extension structs:

- `BackendMetadata` for resolution mode, generation, upstream or authority metadata, and backend result.
- `PolicyMetadata` for explicit deny rules and response mode.
- `BlocklistMetadata` for known-bad source and generation attribution.
- `ResponseInspectionMetadata` for CNAME chains and answer owner names.
- `ClassifierFindings` for suspicious lookup reasons.

Source review should use "observed source" terminology until client identity enrichment exists. Source IP is not always a stable machine identity because DHCP churn, NAT, IPv6 privacy addresses, containers, and forwarding resolvers can blur it.

## Suspicious Lookup Classification

Suspicious lookup classification is advisory. It must not block DNS unless a separate policy decision explicitly blocks the lookup.

Initial classifier behavior can run against the bounded in-memory event stream and flag explainable patterns such as:

- explicit policy deny events once policy exists;
- known-bad domain events once blocklist policy exists;
- unusual NXDOMAIN or SERVFAIL bursts by observed source;
- high-entropy or DGA-like names;
- repeated TXT lookups by source;
- rare or newly observed domains within the retained event window;
- configured suspicious TLDs or domain selectors.

Each finding should include classifier name/version, config generation, reason code, severity or score, evaluated window, and structured details. Baseline-dependent findings must say they are based on the retained window and may be incomplete after restart, retention eviction, sampling, or dropped events.

## In-Memory Review Model

Before SQLite and the authenticated admin API exist, keep query review as internal application read-model ports backed by bounded in-memory state. Do not expose real query-history UI/API access before admin authentication and authorization exist.

Initial read models:

- recent events;
- suspicious events;
- per-observed-source event history;
- per-observed-source suspicious summary;
- domain lookup history;
- top suspicious observed sources and domains.

The in-memory model must define maximum retained events, maximum indexed sources/domains, retention duration if configured, ordering by timestamp plus sequence number, and whether summaries are exact or approximate when events are dropped or sampled.

## Cache Design

Start with an in-memory TTL cache.

Cache key:

- Cache namespace derived from resolution backend mode and generation.
- Normalized domain name.
- Query type.
- Query class.
- DNSSEC checking/disabled flags when those are supported.
- DNSSEC validation mode.
- EDNS-relevant behavior when EDNS is supported.
- Upstream policy variant if configuration can produce different answers.
- Upstream set hash, root-hints version, or other backend inputs that can change answer semantics.
- Effective client UDP response size when cached serialization can differ by request size.

The cache namespace must change, or the affected caches must be flushed, when resolution mode, upstream set, root hints, DNSSEC validation mode, or other answer-affecting backend settings change. Forward-mode response templates, recursive final response templates, and recursion-internal caches must not be reused across incompatible backend generations.

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

## Resolution Strategy

Allowed cache misses should be resolved through one injected port, not through branches in DNS delivery code or in callers of `ResolveQuery`.

Port shape:

- `ResolutionBackend` receives an `ResolutionRequest` containing the decoded query, original request metadata needed for validation, client-independent request features, and the active runtime snapshot generation.
- `ResolutionBackend` returns a structured `ResolutionResponse`, not just final DNS bytes. It should include response code, final question, answer RRsets, authority/additional RRsets classified by trust, canonical CNAME/DNAME chain, negative proof metadata, source credibility, backend provenance, backend mode/generation, timing, and explicit cache directives.
- Protocol serialization should happen after policy and cache decisions so `ResolveQuery` does not cache or policy-check records without provenance.
- The existing forwarding implementation becomes `ForwardingResolutionBackend`.
- Local recursion is implemented as `RecursiveResolutionBackend`.
- A startup/reload factory builds exactly one active backend from runtime configuration and injects it into `ResolveQuery`.
- Milestone 5 must introduce a lightweight `BackendSnapshot` or `BackendHandle` even before durable SQLite settings exist. The active handle must atomically pair runtime settings generation, `ResolutionBackend`, backend health state, and cache namespace so queries, logs, status, and cache lookups observe one coherent backend generation.

Configuration shape:

- `resolution.mode = "forward"` uses configured upstream recursive resolvers.
- `resolution.mode = "recursive"` uses local iterative recursion.
- Forward mode requires at least one enabled upstream resolver.
- Recursive mode requires root hints, bounded recursion depth, bounded CNAME restart count, per-query deadline, per-authority timeout, and allowed outbound transports.
- Mixed or fallback behavior should be explicit if added later, for example `recursive_with_forward_fallback`; do not silently fall back between modes because that makes policy, privacy, and debugging ambiguous.

`ResolveQuery`, UDP/TCP listeners, policy, query logging, and admin APIs should treat the selected backend as opaque except for structured metadata used in events, health, and metrics.

## Forwarding Resolution

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

## Recursive Resolution

Recursive mode should perform iterative DNS resolution locally instead of forwarding the client question to another recursive resolver.

Core responsibilities:

- Load and validate root hints at startup and on config reload.
- Query root servers, TLD servers, and authoritative servers iteratively until an answer, negative answer, referral failure, or configured limit is reached.
- Select authoritative servers deterministically with bounded retry/failover across addresses.
- Resolve in-bailiwick glue and address records needed to contact delegated name servers.
- Enforce bailiwick rules before trusting referral glue or additional-section data.
- Track CNAME restarts with explicit loop and depth limits. DNAME should be deferred initially with conservative `SERVFAIL` or cache-bypass behavior unless DNAME synthesis, loop detection, and cache rules are implemented and tested.
- Use fresh transaction IDs for each authority attempt and validate response source endpoint, transaction ID, response shape, and question before accepting a packet.
- Retry truncated UDP authority responses over TCP when TCP is allowed; otherwise return a documented conservative failure. Apply EDNS payload bounds, per-attempt timeout, and per-query deadline to both UDP and TCP authority queries.
- Return deterministic `SERVFAIL` for lame delegations, referral loops, exhausted authorities, validation failures, and deadline expiry.
- Keep recursion-internal authority, delegation, glue, and negative caches separate from the client response-template cache unless a record is safe to promote under explicit ownership and bailiwick rules.

Initial recursive mode should not claim DNSSEC validation. Unless local trust-anchor validation is implemented, responses must clear `AD`, status must report DNSSEC validation disabled, and cache keys must include DNSSEC request flags and validation mode. `DO` controls whether DNSSEC records are requested or returned when safe; `CD` must not imply local validation behavior when validation is disabled.

Recursive cache boundaries:

- Cache authoritative RRsets by owner name, type, class, TTL, source credibility, and bailiwick status.
- Cache delegation and address lookups separately from final client response templates.
- Never use out-of-bailiwick glue as authoritative data.
- Do not answer one client question from unrelated additional records unless the record passed ownership and bailiwick checks.
- Preserve the existing exact-question response-template cache for final responses when safe.
- Negative cache entries must record validated authority zone, covered name, qtype, qclass, negative kind, SOA owner, and TTL derived from `min(SOA TTL, SOA MINIMUM)` with local caps. Do not negative-cache non-authoritative responses or responses whose SOA does not match the authority zone for the covered name.

## Failure Behavior

Define deterministic responses:

- All upstreams timeout: `SERVFAIL`.
- Upstream returns malformed response: try next upstream, then `SERVFAIL`.
- Upstream response question mismatch: reject response and try next upstream.
- Upstream returns `NXDOMAIN`: return it and negative-cache according to TTL policy.
- Recursive mode reaches depth, CNAME restart, or deadline limit: `SERVFAIL`.
- Recursive mode encounters a referral loop, lame delegation, unusable authority set, or out-of-bailiwick-only glue: `SERVFAIL`.
- Recursive mode receives authoritative `NXDOMAIN` or NODATA with SOA metadata: return it and negative-cache according to TTL policy.
- Cache entry expired: treat as miss.
- Cache is unavailable: continue with upstream lookup and emit degraded metric.

## Concern: `ResolveQuery` Size

`ResolveQuery` is an orchestration service, not a place for all behavior. It should delegate to narrow ports:

- `PolicyEvaluator` for allow/block decisions.
- `DnsCache` for cache lookup/store.
- `ResolutionBackend` for forwarding or recursive resolution.
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
- Configuration selects forwarding or recursive mode without changing `ResolveQuery` callers.
- Fake root, TLD, and authoritative servers cover recursive success, negative answers, referral loops, CNAME loops, DNAME deferral, lame delegations, out-of-bailiwick glue rejection, truncated authority responses, DNSSEC flag behavior while validation is disabled, and timeout/deadline handling.
