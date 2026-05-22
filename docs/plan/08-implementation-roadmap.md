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
- `ResolveQuery` must delegate upstream behavior through an `UpstreamResolver` or `UpstreamDnsClient` port.
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

## Milestone 4: Local Policy Blocking

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

## Milestone 5: SQLite Persistence And Runtime Config

Goal: make upstreams, settings, and rules durable.

Tasks:

- Add SQLite dependency and migration runner.
- Implement repositories for settings, upstreams, and rules.
- Add immutable runtime config snapshot.
- Add atomic config reload.
- Add query-event persistence with retention.
- Add SQLite async strategy: `sqlx` pool or `rusqlite` behind `spawn_blocking` or a dedicated DB task.
- Add indices and maintenance hooks for query events and blocklist tables.
- Add bounded asynchronous query-event writing with explicit drop/sampling metrics.
- Enforce configuration invariants before publishing runtime snapshots.

Reviewer concern gates:

- DNS hot path must not perform direct database reads.
- Admin writes must commit before publishing a new `Arc<RuntimeConfig>` or `Arc<PolicySnapshot>`.
- Query-event and blocklist storage must have retention limits.
- Migration or required settings load failure must prevent DNS listener startup unless degraded startup is explicitly configured.
- Slow or unavailable SQLite query logging must not block DNS responses.
- Invalid settings must not be persisted or published as active snapshots.

Exit criteria:

- Restart preserves upstreams and rules.
- Admin/application services can update settings transactionally.
- Queries continue during config reload.
- Retention cleanup keeps configured limits.

## Milestone 6: External Blocklist Ingestion

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

## Milestone 7: Admin API

Goal: provide an authenticated API for resolver administration.

Tasks:

- Add HTTP server.
- Add first-run setup, authentication, and session handling.
- Add CSRF protection for browser mutating requests.
- Implement settings, upstreams, rules, blocklist sources, refresh, status, and query-events endpoints.
- Add validation and error response model.

Reviewer concern gates:

- Admin server must bind to loopback by default.
- First-run setup must be required before admin mutation endpoints are usable.
- Passwords must be hashed; sessions must expire.
- Mutating browser requests must require CSRF protection.
- No unauthenticated mutation endpoint is allowed.
- API validation must prevent changes that would break runtime invariants, such as deleting the last upstream or enabling sinkhole mode without sinkhole addresses.

Exit criteria:

- Admin can manage upstreams, rules, settings, and blocklist sources through API calls.
- Mutating calls require authentication and CSRF protection.
- API tests cover validation and reload behavior.
- First-run setup and unauthenticated mutation rejection are tested.

## Milestone 8: Admin UI

Goal: provide a usable browser interface for the admin API.

Tasks:

- Build static UI served by the admin server.
- Add screens for status, upstreams, rules, blocklists, query events, and settings.
- Add forms with client-side validation matching server validation where practical.
- Add status indicators for upstreams and blocklist freshness.

Reviewer concern gates:

- UI must expose the operational implications of IP-based client identity.
- UI must show block response mode and reason codes for blocked queries.
- UI must show blocklist guardrail failures and previous-good status.
- UI must not imply settings are active until the API confirms persistence and snapshot reload.

Exit criteria:

- Admin can complete core configuration tasks without direct database or config-file edits.
- UI shows why recent queries were blocked or allowed.
- UI smoke test loads primary screens.

## Milestone 9: TCP And Operational Hardening

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
