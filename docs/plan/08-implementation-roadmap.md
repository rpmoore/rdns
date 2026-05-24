# Implementation Roadmap

## Milestone 1: Safe DNS Protocol Core

Goal: make DNS parsing and response construction safe enough for network input.

Tasks:

- Refactor `src/dns.rs` into a `protocol` module.
- Add a checked byte reader.
- Introduce `DnsParseError`.
- Parse compression pointers against the full DNS message.
- Add pointer-loop detection.
- Add `Unknown` record support.
- Add DNS response serialization helpers.
- Keep policy choices out of protocol; expose generic response builders only.
- Add TCP frame encode/decode helpers even if the DNS TCP listener lands later.
- Add minimal EDNS parsing for UDP payload size and DNSSEC `DO` flag visibility.
- Add UDP response-size enforcement and truncated-response helpers.
- Add tests for malformed packets and serializer output.

Reviewer concern gates:

- The parser must never panic on malformed network input.
- Compression offsets must be full-message offsets, not section-slice offsets.
- Unknown record types must be preserved or skipped safely, not handled with `unimplemented!`.
- Protocol APIs must not know why a response is blocked; they only serialize requested DNS response shapes.
- Oversized UDP responses must be truncated with `TC` instead of emitted as oversized datagrams.
- EDNS features must be parsed enough that resolver/cache code can make conservative decisions.

Exit criteria:

- Arbitrary malformed packets return errors instead of panicking.
- Existing parser tests still pass or are updated to the new API.
- Basic `FORMERR`, `REFUSED`, `NXDOMAIN`, and sinkhole responses can be built.
- TCP length-prefix framing helpers have unit coverage.

## Milestone 2: DNS Server And Upstream Forwarding

Goal: accept local DNS queries and forward them to configured upstream resolvers.

Tasks:

- Add UDP listener using Tokio.
- Add TCP listener or at least TCP upstream fallback planning; full TCP server can follow after UDP.
- Implement upstream UDP client.
- Implement priority-ordered upstream failover.
- Add per-upstream timeouts and a per-query overall deadline.
- Validate upstream responses before returning them.
- Generate fresh randomized upstream transaction IDs and validate upstream source address on replies.
- Add static configuration for listen address and upstreams.
- Add graceful shutdown.

Reviewer concern gates:

- Upstream behavior must be deterministic for timeout, malformed response, question mismatch, `NXDOMAIN`, and all-upstreams-failed cases.
- Resolver forwarding must not hang beyond the configured per-query deadline.
- Truncated UDP upstream responses must either trigger TCP fallback or return a documented conservative failure until TCP fallback is implemented.
- `ResolveQuery` must delegate forwarding behavior through a backend port rather than implementing upstream I/O directly.
- Upstream responses must be accepted only when source endpoint, transaction ID, and question match the active upstream attempt.

Exit criteria:

- A local client can query the resolver and receive upstream answers.
- Upstream timeout returns `SERVFAIL`.
- Integration test covers fake upstream forwarding.
- Integration test covers upstream failover.

## Milestone 3: In-Memory Cache

Goal: cache allowed upstream responses by question key.

Tasks:

- Add `DnsCache` trait and in-memory TTL implementation.
- Calculate positive and negative TTLs.
- Store canonical response templates or RRset data; do not blindly replay raw upstream packets.
- Rewrite response IDs and request-dependent fields for cached responses.
- Add cache size bound and eviction policy.
- Add single-flight miss handling.
- Add cache metrics.
- Keep cache poisoning boundaries explicit: do not use unrelated additional records for other questions until bailiwick rules are implemented.

Reviewer concern gates:

- Cache keys must include normalized name, qtype, qclass, and supported request features that affect response semantics.
- Unsupported DNSSEC/EDNS/query features must bypass cache until explicitly supported.
- Positive TTL must derive from answer TTLs, and negative TTL must derive from SOA metadata.
- Upstream timeouts must not be cached. `SERVFAIL` caching requires an explicit short failure-cache setting.
- Cached responses must be reserialized for the current client's UDP size and request context.

Exit criteria:

- Repeated query receives a cached answer without contacting upstream.
- Expired entries are not returned.
- Concurrent duplicate misses produce one upstream request.
- Cached response uses the current request transaction ID.

## Milestone 4: Query Event Pipeline And In-Memory Review Model

Goal: record every client query terminal outcome through a non-blocking event pipeline and provide bounded in-memory source-centric review models for suspicious lookup investigation.

Tasks:

- Define a minimal stable `QueryEventV1` schema with schema version, sequence number, timestamp, observed source endpoint, original and normalized question, qtype/qclass, terminal outcome, local DNS response code, cache result, latency, and advisory classifier findings.
- Split event taxonomy into separate fields for terminal outcome, DNS response code, policy decision, cache result, backend result, and classifier findings so allowed, blocked, failed, and suspicious-but-allowed events are not conflated.
- Change or wrap `QueryEventSink` so recording is best-effort and non-blocking on the DNS hot path.
- Add bounded event ingestion with explicit overflow behavior: disabled, drop newest, drop oldest, sample, or accept.
- Add metrics for accepted, dropped, sampled, and disabled query events by reason.
- Add a bounded in-memory query-event store and source-centric read models for recent events, suspicious events, per-observed-source history, per-source suspicious summary, domain history, and top suspicious observed sources/domains.
- Model source as an observed endpoint, not a guaranteed machine identity; support optional later `ClientIdentitySnapshot`.
- Add an advisory `SuspiciousLookupClassifier` port with explainable, versioned findings and initial non-blocking heuristics over retained in-memory events.
- Keep real query-history API/UI access out of this milestone except for tests or local-only diagnostics; authenticated admin access is added later.

Reviewer concern gates:

- Query event recording must never block DNS responses on queue capacity, storage, classification, or read-model updates.
- The event schema must avoid null-heavy future fields; backend, policy, blocklist, response-inspection, and richer classifier data should be optional extension structs added by later milestones.
- Source review must use observed source endpoint terminology until a real client identity snapshot exists.
- Suspicious classifier findings must be advisory and explainable, with classifier version, config generation, reason, severity/score, evaluated window, and structured details.
- Query-event retention and read-model bounds must be explicit.
- Event logs are sensitive and must not be exposed through unauthenticated UI/API routes.

Exit criteria:

- Every client query terminal outcome emits a `QueryEventV1` or increments a dropped/disabled metric.
- A slow or failing event processor/store does not delay DNS responses.
- In-memory read models can return recent events, suspicious events, and per-observed-source history within configured bounds.
- Classifier tests cover reason details, threshold boundaries, cold start, dropped/sampled events, and advisory suspicious-but-allowed events.
- Tests cover disabled logging, overflow behavior, retention eviction, source filtering, schema versioning, processor failure isolation, and dropped-event summary indicators.

## Milestone 5: Configurable Resolution Strategy And Recursive Resolver

Goal: allow configuration to choose between forwarding cache misses to upstream recursive resolvers or performing local iterative recursive resolution.

Tasks:

- Rename or generalize the `UpstreamResolver` port to a `ResolutionBackend` that returns the same response shape to `ResolveQuery` regardless of strategy.
- Add runtime configuration for `resolution.mode = forward | recursive`.
- Add an atomic `BackendSnapshot` or `BackendHandle` that pairs runtime settings generation, selected backend, backend health state, and cache namespace before durable config reload exists.
- Move the current upstream-forwarding implementation behind `ForwardingResolutionBackend`.
- Add a backend factory that validates the active runtime snapshot and injects the selected backend into `ResolveQuery`.
- Add backend cache namespaces so forward-mode, recursive-mode, and changed backend configurations cannot reuse incompatible cached responses.
- Add root-hints configuration and validation for recursive mode.
- Implement `RecursiveResolutionBackend` with iterative root-to-authority lookup, bounded depth, bounded CNAME restarts, per-authority timeouts, deterministic authority failover, and explicit `SERVFAIL` failure modes. Defer DNAME with conservative failure unless DNAME synthesis and loop/cache rules are implemented.
- Add bailiwick validation before trusting referral glue or additional-section records.
- Add recursive authority transport validation: fresh transaction ID per attempt, source endpoint/question validation, EDNS payload bounds, UDP truncation-to-TCP fallback, per-attempt timeout, and per-query deadline.
- Clear `AD` and report DNSSEC validation disabled until local trust-anchor validation exists; include DNSSEC flags and validation mode in cache keys.
- Make backend responses structured enough for safe policy and cache decisions: RRset provenance, credibility, canonical chain, negative metadata, source credibility, and explicit cache directives.
- Add recursion-internal RRset, delegation, glue, and negative caches without weakening the existing exact-question response-template cache.
- Add backend-mode metadata to query events, status, health checks, and metrics.

Reviewer concern gates:

- `ResolveQuery` and DNS delivery adapters must not branch on forward versus recursive mode.
- Runtime settings generation, selected backend, backend health, and cache namespace must be atomically consistent for each query.
- Forward mode must preserve the existing upstream validation, timeout, failover, TCP fallback, and cache behavior.
- Recursive mode must enforce bounded recursion depth, bounded CNAME restarts, query deadlines, and deterministic failure behavior.
- Recursive mode must not trust out-of-bailiwick glue or promote unrelated additional records into reusable answers.
- Recursive mode must validate authoritative transport responses and retry truncated UDP responses over TCP when allowed.
- DNSSEC validation must not be implied unless trust-anchor validation is explicitly implemented.
- Configuration reload must build and validate the new backend before publishing it.

Exit criteria:

- A config-only mode switch selects forward or recursive resolution without changing DNS listener or `ResolveQuery` calling code.
- Cache entries are isolated by backend namespace or flushed on answer-affecting backend changes.
- Forward-mode integration tests still pass unchanged except for renamed port types.
- Recursive-mode integration tests resolve through fake root, TLD, and authoritative servers.
- Recursive-mode tests cover referral loops, CNAME loops, DNAME deferral, lame delegations, out-of-bailiwick glue rejection, truncated authoritative responses, DNSSEC flag handling while validation is disabled, timeout/deadline handling, and negative answers.
- Status and query events identify which backend handled a query.

## Milestone 6: Local Policy Blocking

Goal: block configured clients from resolving configured domains.

Tasks:

- Add domain normalization and selector model.
- Add client selector model for exact IP and CIDR.
- Add `ClientIdentity` and `PolicyEngine`.
- Add blocked response mode configuration.
- Add response-aware known-malicious checks for CNAME targets and answer owner names.
- Add static or file-backed rule loading before SQLite if needed for fast iteration.

Reviewer concern gates:

- Domain matching must use canonical lowercase ASCII/Punycode names without trailing dots.
- Selectors must distinguish exact-domain and subtree-domain matching; suffix bugs such as matching `badexample.com` for `example.com` must be tested.
- Source IP must be modeled as an initial client identity strategy, not assumed to be the only future identity.
- Block response mode must be explicit for local rules and known-malicious blocks.
- Known-malicious policy must define how CNAME targets in upstream responses are handled.

Exit criteria:

- A configured client/domain rule blocks matching queries.
- Non-matching clients and domains are allowed.
- Policy decisions include reason codes.
- Block response mode is visible in config and covered by tests.

## Milestone 7: SQLite Persistence And Runtime Config

Goal: make upstreams, settings, and rules durable.

Tasks:

- Add SQLite dependency and migration runner.
- Implement repositories for settings, upstreams, and rules.
- Add immutable runtime config snapshot.
- Add atomic config reload.
- Add query-event persistence with retention.
- Persist query-event schema version, observed source endpoint, terminal outcome taxonomy, cache/backend/policy metadata extensions when available, and classifier findings.
- Add SQLite async strategy: `sqlx` pool or `rusqlite` behind `spawn_blocking` or a dedicated DB task.
- Add indices and maintenance hooks for query events, observed-source history, suspicious summaries, and blocklist tables.
- Add bounded asynchronous query-event writing with explicit drop/sampling metrics.
- Enforce configuration invariants before publishing runtime snapshots.

Reviewer concern gates:

- DNS hot path must not perform direct database reads.
- Admin writes must commit before publishing a new `Arc<RuntimeConfig>` or `Arc<PolicySnapshot>`.
- Query-event and blocklist storage must have retention limits.
- Durable query logging must preserve the non-blocking event pipeline contract and surface dropped/sampled indicators to query-review consumers.
- Migration or required settings load failure must prevent DNS listener startup unless degraded startup is explicitly configured.
- Slow or unavailable SQLite query logging must not block DNS responses.
- Invalid settings must not be persisted or published as active snapshots.

Exit criteria:

- Restart preserves upstreams and rules.
- Admin/application services can update settings transactionally.
- Queries continue during config reload.
- Retention cleanup keeps configured limits.

## Milestone 8: External Blocklist Ingestion

Goal: ingest known-malicious-domain lists and block matches.

Tasks:

- Add blocklist source model and repositories.
- Add HTTP fetcher adapter.
- Parse common domain-list and hosts-file formats.
- Normalize, dedupe, and stage domains into generations.
- Activate new generations atomically.
- Swap in-memory policy snapshot after activation.
- Add manual refresh service and scheduled refresh job.
- Add source guardrails and previous-good rollback behavior.
- Add blocklist URL scheme, redirect, timeout, and local-address safety controls.

Reviewer concern gates:

- Fetching, parsing, staging, activation, rollback, and scheduling must stay out of request-time policy evaluation.
- Source updates must enforce max bytes, max domains, parse-error thresholds, and suspicious-delta checks.
- Failed or suspicious updates must keep the previous active generation.
- Snapshot swap must happen only after durable activation commits.
- Fetcher safety must prevent blocklist sources from reading local files or unexpected internal resources by default.

Exit criteria:

- Configured source can be refreshed.
- Previous active blocklist remains active if refresh fails.
- Matching malicious domains are blocked with source attribution.
- Guardrail failures are visible to the admin API/UI.

## Milestone 9: Admin API

Goal: provide an authenticated API for resolver administration.

Tasks:

- Add HTTP server.
- Add first-run setup, authentication, and session handling.
- Add CSRF protection for browser mutating requests.
- Implement settings, resolution mode, upstreams, rules, blocklist sources, refresh, status, query-events, suspicious-event, and source-detail endpoints.
- Add validation and error response model.

Reviewer concern gates:

- Admin server must bind to loopback by default.
- First-run setup must be required before admin mutation endpoints are usable.
- Passwords must be hashed; sessions must expire.
- Mutating browser requests must require CSRF protection.
- No unauthenticated mutation endpoint is allowed.
- No unauthenticated query-history, suspicious-lookup, source-detail, or export endpoint is allowed.
- API validation must prevent changes that would break runtime invariants, such as deleting the last forward-mode upstream, enabling recursive mode without valid root hints, or enabling sinkhole mode without sinkhole addresses.

Exit criteria:

- Admin can manage resolution mode, upstreams, rules, settings, and blocklist sources through API calls.
- Admin can review suspicious lookup findings and retained query history by observed source through authenticated API calls.
- Mutating calls require authentication and CSRF protection.
- API tests cover validation and reload behavior.
- First-run setup and unauthenticated mutation rejection are tested.

## Milestone 10: Admin UI

Goal: provide a usable browser interface for the admin API.

Tasks:

- Build static UI served by the admin server.
- Add screens for status, resolution mode, upstreams, rules, blocklists, query events, suspicious lookup review, observed-source detail, and settings.
- Add forms with client-side validation matching server validation where practical.
- Add status indicators for upstreams and blocklist freshness.

Reviewer concern gates:

- UI must expose the operational implications of IP-based client identity.
- UI must show block response mode and reason codes for blocked queries.
- UI must make suspicious lookup review source-centric, distinguish advisory findings from policy blocks, and show classifier reasons, severity, evaluated windows, and dropped/sampled indicators.
- UI must show blocklist guardrail failures and previous-good status.
- UI must not imply settings are active until the API confirms persistence and snapshot reload.

Exit criteria:

- Admin can complete core configuration tasks without direct database or config-file edits.
- UI shows why recent queries were blocked or allowed.
- UI lets an authenticated administrator view all retained requests by observed source and quickly identify suspicious sources/domains.
- UI smoke test loads primary screens.

## Milestone 11: TCP And Operational Hardening

Goal: prepare for always-on LAN use.

Tasks:

- Add DNS TCP listener.
- Add TCP connection limits and read/write timeouts.
- Add parser fuzzing.
- Add stress tests for concurrent DNS queries.
- Add retention cleanup job.
- Add structured logging and metrics summary.
- Add packaging or service installation notes.
- Add port-53 deployment guidance for capabilities or socket activation.
- Review default bind addresses and security posture.

Reviewer concern gates:

- DNS TCP listener must enforce length-prefix framing, max message size, connection limits, and read/write timeouts.
- Observability must distinguish cache latency, upstream latency, policy blocks, parse errors, DB failures, ingestion failures, and admin mutations.
- Fuzz and stress tests must cover parser robustness and concurrent snapshot/cache access.
- Production deployment docs must avoid requiring the whole resolver to run as root just to bind port 53.

Exit criteria:

- Resolver survives malformed packet fuzzing without panics.
- Operational status is visible in the admin UI/API.
- Defaults are safe for a local network deployment.
