# Reviewer Concerns And Revisions

## Purpose

This file records how the independent architecture review concerns should be addressed in the implementation plan. The concerns are not separate work from the plan; they change the architecture, sequencing, and acceptance criteria.

## Concern Response Matrix

| Concern | Plan Decision | Primary Files | Roadmap Placement |
| --- | --- | --- | --- |
| Cached DNS responses can leak stale transaction IDs or mishandle request flags. | Cache canonical response templates or RRset data, not blindly replayed upstream packets. Rewrite IDs and request-dependent fields through protocol helpers. Bypass cache for unsupported query features. | `02-resolver-cache.md`, `01-dns-protocol.md` | Milestone 3 |
| Resolution mode must not leak into callers. | Select forward versus recursive behavior through runtime configuration and inject one `ResolutionBackend` into `ResolveQuery`; DNS delivery adapters and callers must not branch on strategy. | `02-resolver-cache.md`, `05-persistence-config.md`, `08-implementation-roadmap.md` | Milestone 5 |
| Resolution backend state can diverge from config, status, and cache state. | Introduce an atomic `BackendSnapshot` or `BackendHandle` that pairs runtime settings generation, selected backend, backend health, and cache namespace. | `02-resolver-cache.md`, `05-persistence-config.md`, `08-implementation-roadmap.md` | Milestone 5 |
| Cache entries can leak across incompatible resolution modes or backend settings. | Include backend cache namespace in reusable cache keys, derived from mode/generation and answer-affecting settings, or flush affected caches on mode, upstream, root-hints, or DNSSEC changes. | `02-resolver-cache.md`, `05-persistence-config.md` | Milestone 5 |
| Backend responses need provenance for safe cache and policy decisions. | Return structured `ResolutionResponse` data with RRset credibility, bailiwick/trust classification, canonical chain, negative metadata, backend provenance, and explicit cache directives; serialize after policy/cache decisions. | `02-resolver-cache.md` | Milestone 5 |
| Recursive transport can be spoofed or truncated. | For authority queries, use fresh transaction IDs, validate source endpoint and question, apply EDNS payload bounds, retry truncated UDP over TCP when allowed, and enforce per-attempt/per-query deadlines. | `02-resolver-cache.md`, `07-operations-testing.md` | Milestone 5 |
| DNSSEC flags can mislead clients while validation is disabled. | Clear `AD` unless local trust-anchor validation is implemented, define `DO`/`CD` behavior, include DNSSEC flags and validation mode in cache keys, and expose validation-disabled status. | `02-resolver-cache.md`, `05-persistence-config.md`, `07-operations-testing.md` | Milestone 5 |
| Query logging can block or expose sensitive client behavior if designed like normal storage. | Emit one non-blocking bounded query event per terminal DNS outcome; keep early review models in memory only; expose real query history only behind authenticated admin APIs. | `02-resolver-cache.md`, `06-admin-api-ui.md`, `07-operations-testing.md` | Milestone 4 |
| Suspicious lookup flags can be misleading without explainability and identity caveats. | Treat classifier findings as advisory, versioned, windowed, and explainable; model source as an observed endpoint until client identity enrichment exists. | `02-resolver-cache.md`, `03-policy-blocking.md`, `06-admin-api-ui.md` | Milestone 4 |
| Block behavior is underspecified. | Make block response mode first-class config with `REFUSED`, `NXDOMAIN`, `NODATA`, and `Sinkhole` modes. Track separate defaults for local rules and malicious-domain blocks. Log reason codes independent of DNS response bytes. | `03-policy-blocking.md`, `01-dns-protocol.md`, `06-admin-api-ui.md` | Milestone 6 |
| Client identity cannot remain an implicit source-IP assumption. | Introduce `ClientIdentity` as a policy concept. Start with source IP and CIDR selectors, but leave room for labels, groups, DHCP/static-reservation imports, and future identity providers. | `03-policy-blocking.md`, `06-admin-api-ui.md` | Milestone 6 |
| Upstream behavior needs deterministic timeout, retry, and failover semantics. | Use priority-ordered failover first. Add per-upstream timeout, per-query deadline, bounded attempts, degraded health state, recovery probes, and TCP fallback on truncation. | `02-resolver-cache.md`, `07-operations-testing.md` | Milestone 2 |
| Runtime config and policy updates can race with DNS queries. | Use immutable `Arc<RuntimeConfig>` and `Arc<PolicySnapshot>` snapshots. Publish new snapshots only after durable transactions commit. Existing queries may finish on old snapshots. | `05-persistence-config.md`, `04-blocklist-ingestion.md` | Milestones 7 and 8 |
| SQLite-backed logs and blocklists can grow without bound. | Add retention settings, max query-event rows, max retained blocklist generations, maintenance cleanup, indices, and vacuum/optimize strategy. | `05-persistence-config.md`, `07-operations-testing.md` | Milestone 7 |
| Blocklist ingestion needs its own lifecycle. | Split ingestion into its own domain file. Treat fetching, parsing, guardrails, staging, activation, rollback, and scheduling separately from request-time policy. | `04-blocklist-ingestion.md` | Milestone 8 |
| Protocol module could absorb policy decisions. | Keep protocol limited to parsing, validation, serialization, TCP framing, and generic response builders. Resolver/policy chooses which response to build. | `01-dns-protocol.md`, `02-resolver-cache.md` | Milestone 1 |
| `ResolveQuery` could become a god service. | Keep it as orchestration only. Inject `PolicyEvaluator`, `DnsCache`, `ResolutionBackend`, `ResponseFactory`, `QueryEventSink`, `MetricsSink`, and `Clock`. | `02-resolver-cache.md`, `07-operations-testing.md` | Milestones 2 through 6 |
| Admin UI/API security needs bootstrap and exposure rules. | Default admin bind to loopback. Require first-run setup token/password flow, password hashing, session expiry, CSRF protection, login rate limiting, and no unauthenticated mutation endpoints. | `06-admin-api-ui.md` | Milestone 9 |
| Tests need deterministic time, network, and storage seams. | Define testability ports for `Clock`, `Scheduler`, `HttpFetcher`, `UpstreamDnsClient`, `AuthorityDnsClient`/`DnsTransport`, `RootHintsProvider`, `AuthoritySelector`, `TransactionIdGenerator`, repositories, query events, and metrics. Use fake upstreams, fake authority hierarchies, and temp SQLite databases in integration tests. | `07-operations-testing.md`, `02-resolver-cache.md`, `05-persistence-config.md` | All milestones |
| DNS TCP behavior is protocol-specific. | Add TCP length-prefix framing, max message size, read/write timeouts, connection limits, idle close, and UDP truncation fallback. | `01-dns-protocol.md`, `02-resolver-cache.md` | Milestones 2 and 11 |
| External blocklists can be bad, compromised, or too large. | Add source guardrails: max bytes, max domains, parse-error thresholds, suspicious-delta detection, previous-good retention, dry-run stats, and rollback. | `04-blocklist-ingestion.md`, `05-persistence-config.md` | Milestone 8 |
| Domain normalization must be precise. | Canonicalize to lowercase ASCII/Punycode without trailing dot. Use explicit exact and subtree selectors. Test suffix edge cases. | `03-policy-blocking.md`, `04-blocklist-ingestion.md` | Milestones 6 and 8 |
| SQLite can block Tokio runtime threads. | Choose either `sqlx` with SQLite pooling or `rusqlite` isolated through `spawn_blocking` or a dedicated DB task. Hide the choice behind repository traits. | `05-persistence-config.md` | Milestone 7 |
| Observability needs concrete signals. | Track query counts, latency, cache hit/miss, block reason, backend mode, upstream/authority health, blocklist update results, active policy generation, active rule counts, and admin mutations. | `07-operations-testing.md`, `06-admin-api-ui.md` | Milestones 2 through 11 |
| Roadmap should reflect prerequisites. | Keep protocol safety first, then UDP forwarding, cache, query-event pipeline, configurable resolution strategy and recursion, local policy, persistence, blocklist ingestion, admin API, UI, and TCP/operational hardening. | `08-implementation-roadmap.md` | Whole roadmap |

## Second Review Additions

| Concern | Plan Decision | Primary Files | Roadmap Placement |
| --- | --- | --- | --- |
| EDNS and UDP response size can make cached or generated responses invalid for the current client. | Parse minimal EDNS data, expose unsupported features to resolver/cache decisions, clamp UDP payload sizes, and return truncated responses when needed. | `01-dns-protocol.md`, `02-resolver-cache.md` | Milestones 1 and 3 |
| Upstream forwarding can be spoofed or confused if it reuses client IDs or accepts mismatched replies. | Generate fresh upstream transaction IDs, validate source endpoint and response ID, and map replies back to the original client request. | `02-resolver-cache.md`, `07-operations-testing.md` | Milestone 2 |
| Cache poisoning risk remains if unrelated additional records are reused. | Cache exact-question templates or RRsets only until explicit bailiwick and additional-record rules are implemented. | `02-resolver-cache.md` | Milestone 3 |
| Malicious-domain blocking can be bypassed through CNAME indirection. | Check resolved CNAME targets and answer owner names against known-malicious policy before returning and caching allowed responses. | `03-policy-blocking.md` | Milestone 6 |
| Query logging can backpressure the DNS hot path when SQLite is slow. | Use bounded asynchronous event writing with explicit drop/sampling behavior and metrics. | `05-persistence-config.md`, `07-operations-testing.md` | Milestone 7 |
| Admin/config updates can persist settings that break resolver invariants. | Validate invariants before persistence and snapshot publication: resolution mode requirements, upstream availability, bind conflicts, bounded numeric settings, sinkhole completeness, and URL safety. | `05-persistence-config.md`, `06-admin-api-ui.md` | Milestones 7 and 9 |
| Blocklist URL fetching can become an SSRF or local-file access path. | Restrict schemes, timeouts, redirects, resolved local/private addresses, Unix sockets, and local-file access by default. | `04-blocklist-ingestion.md`, `07-operations-testing.md` | Milestone 8 |
| Binding DNS port 53 creates deployment and privilege risk. | Develop on high ports, document systemd socket activation or `CAP_NET_BIND_SERVICE`, and avoid requiring the whole process to run as root. | `07-operations-testing.md`, `08-implementation-roadmap.md` | Milestone 11 |

## Incorporation Strategy

Handle concerns in the milestone where the related risk first appears.

- Protocol safety is a blocker for any real network listener.
- Upstream timeout/failover semantics are a blocker for forwarding.
- Cache correctness is a blocker before returning cached responses.
- Non-blocking query-event capture is a blocker before source-centric suspicious lookup review.
- Resolution strategy selection and recursive safety are blockers before policy and persistence build on runtime configuration.
- Policy response semantics and client identity are blockers before user-managed blocking.
- Immutable snapshots are a blocker before persistence, admin edits, or blocklist activation.
- Admin bootstrap and security defaults are blockers before exposing the UI beyond localhost.

This keeps the plan practical: concerns become acceptance criteria, not a separate cleanup phase.

## Acceptance Rule

Do not mark a milestone complete if one of its mapped concerns is unresolved. If a concern is intentionally deferred, record the deferred behavior in the relevant domain file and keep the default behavior conservative.

## How To Use This During Implementation

For each milestone:

1. Read the milestone in `08-implementation-roadmap.md`.
2. Treat its reviewer concern gates as required acceptance criteria.
3. Add or update tests that prove the gate is satisfied.
4. Update the relevant domain file if implementation reveals a better design.
5. Record any intentionally deferred concern with the conservative runtime behavior that remains in place.

This prevents reviewer concerns from becoming a separate backlog that is easy to ignore. Each concern is handled at the point where implementing without it would create correctness, security, or operations risk.
