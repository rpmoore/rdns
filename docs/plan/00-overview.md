# DNS Intermediate Resolver Plan

## Current State

The repository is a Rust crate named `rdns` with phases 1 through 3 complete.

- `src/protocol/mod.rs` contains the safe DNS protocol core: checked parsing, structured parse errors, full-message compression handling, unknown-record support, EDNS visibility, UDP truncation helpers, response builders, transaction-ID rewrite helpers, and TCP framing helpers.
- `src/resolver/mod.rs` contains the `ResolveQuery` application service, resolver ports, query decision metadata, in-memory TTL cache, cache key/value modeling, positive and negative TTL policy, safe cached-response template handling, cache bypass rules, single-flight miss coalescing, and cache metrics hooks.
- `src/delivery/dns.rs` contains the Tokio UDP DNS listener adapter.
- `src/delivery/upstream.rs` contains UDP upstream forwarding, fresh upstream transaction IDs, source/ID/question validation, priority-ordered failover, per-upstream timeouts, per-query deadlines, health snapshots, and TCP fallback for truncated upstream UDP responses.
- `src/config/mod.rs` contains validated static runtime configuration for DNS listeners, upstream resolvers, timing bounds, and UDP payload limits.
- `src/main.rs` starts the configured UDP DNS server with the development default runtime configuration and graceful shutdown handling.
- `src/lib.rs` exports `config`, `delivery`, `protocol`, and `resolver`.
- `Cargo.toml` currently depends only on `tokio`.

The resolver can now accept UDP queries, forward them to configured upstreams, use TCP fallback for truncated upstream responses, cache eligible responses in memory, rewrite cached responses for the current request, and emit decision/metric hooks.

Remaining major planned areas are local policy blocking, persistent/runtime-reloadable configuration, blocklist ingestion, admin API/UI, DNS TCP listener support for clients, and operational hardening.

## Target Capabilities

The finished application should run as an intermediate DNS resolver for a local network.

- Accept DNS queries from LAN clients over UDP and later TCP.
- Cache DNS responses to reduce local lookup latency.
- Let an administrator choose whether allowed cache misses are resolved by forwarding to configured upstream recursive resolvers or by performing iterative recursive resolution locally.
- Block domains known to be malicious using configured external blocklist sources.
- Block configured client IP addresses from resolving selected domains.
- Record DNS lookup events by observed client/source so administrators can review suspicious lookup patterns and investigate possible command-and-control behavior.
- Let an administrator configure upstream resolvers such as Cloudflare, Google, or local upstreams.
- Let an administrator manage client/domain rules and blocklist sources through a UI.
- Expose operational status for cache behavior, upstream health, blocklist freshness, query decisions, suspicious lookup flags, and query-event pipeline health.

## Architectural Direction

Use a modular monolith first. The application has several clear domains, but the current project does not justify separate deployable services. Keep domain logic independent from networking, database, HTTP, and UI details so each area can be tested directly.

Recommended module shape:

- `protocol`: DNS packet parsing, validation, serialization, and response construction.
- `resolver`: request orchestration, resolution-strategy selection, cache lookup, cache population, and response decisions.
- `recursive`: iterative DNS recursion, root hints, delegation walking, authority selection, bailiwick validation, glue handling, and recursion-specific cache support.
- `events`: query-event schema, non-blocking event ingestion, in-memory review models, and advisory suspicious-lookup classification.
- `policy`: domain normalization, local rules, malicious-domain matching, and block actions.
- `blocklist`: external source fetching, parsing, normalization, deduplication, and atomic activation.
- `config`: runtime settings, upstream resolver configuration, and reload semantics.
- `persistence`: SQLite repositories for settings, rules, blocklists, events, and query logs.
- `delivery::dns`: UDP/TCP DNS server adapters.
- `delivery::admin`: HTTP API and UI asset serving.
- `observability`: structured logs, metrics, health checks, and diagnostics.

## Dependency Direction

Domain types and policies should not depend on Tokio, HTTP frameworks, SQLite, or filesystem/network clients.

The dependency direction should be:

`delivery adapters -> application services -> domain policies/models -> shared value types`

Infrastructure implementations should be injected behind traits:

- `ResolutionBackend`
- `DnsCache`
- `PolicyRepository`
- `BlocklistRepository`
- `SettingsRepository`
- `BlocklistFetcher`
- `Clock`
- `QueryEventSink`
- `QueryEventStore`
- `SuspiciousLookupClassifier`
- `MetricsSink`

## Core Runtime Flow

1. DNS listener receives a query and captures the client IP address.
2. `protocol` parses the query using checked bounds and compression validation.
3. `resolver` extracts a normalized lookup key from the question.
4. `policy` evaluates client/domain rules first, then malicious-domain blocklists.
5. If blocked, `resolver` chooses the configured block mode and asks `protocol` to serialize that response.
6. If allowed, `resolver` checks the cache.
7. On cache hit, the resolver rewrites the response transaction ID and returns it.
8. On cache miss, the resolver calls the configured `ResolutionBackend`. The backend either forwards to configured upstream resolvers or performs local iterative recursion.
9. `resolver` validates the backend response, applies response-aware policy checks, caches it according to TTL policy, and returns it.
10. The query decision is emitted as a structured event through a non-blocking sink.
11. The query-event pipeline stores a bounded review model and applies advisory suspicious-lookup classification without blocking DNS responses.

## Remaining Primary Risks

- There is no policy engine yet, so local client/domain rules and known-malicious blocklist decisions are not enforced.
- Query-event review is currently limited to the in-process decision hooks; there is no bounded review store, source-centric view, suspicious classifier, or durable query-event history yet.
- Recursive resolution is not implemented yet; the current runtime can only forward cache misses to configured upstream recursive resolvers.
- Configuration is static and in-memory; upstreams, settings, and future rules are not durable or reloadable at runtime.
- There is no persistence layer, blocklist updater, admin API, UI server, structured metrics exporter, or durable query logging.
- DNS TCP support exists for protocol framing and upstream fallback, but the resolver does not yet expose a client-facing TCP listener.
- The cache is process-local and memory-only; entries are lost on restart and are intentionally conservative around unsupported DNS semantics.

## Plan Files

- [DNS Protocol](01-dns-protocol.md)
- [Resolver And Cache](02-resolver-cache.md)
- [Policy And Blocking](03-policy-blocking.md)
- [Blocklist Ingestion](04-blocklist-ingestion.md)
- [Persistence And Configuration](05-persistence-config.md)
- [Admin API And UI](06-admin-api-ui.md)
- [Operations And Testing](07-operations-testing.md)
- [Implementation Roadmap](08-implementation-roadmap.md)
- [Reviewer Concerns And Revisions](09-reviewer-concerns.md)

## Independent Review Concerns Folded Into The Plan

An independent review called out these concerns, which are incorporated in the domain files:

- Cache entries must not replay raw upstream packets with stale transaction IDs or unsupported request flags.
- Block response behavior must be explicit because `REFUSED`, `NXDOMAIN`, `NODATA`, and sinkhole answers have different client and caching effects.
- Client identity should be modeled separately from transport source IP so future DHCP, labels, groups, and IPv6 behavior can be added without rewriting resolver policy.
- Upstream timeout, retry, failover, health, and TCP fallback behavior must be deterministic.
- Resolution mode must be selected through configuration and hidden behind a resolver backend port so DNS delivery adapters and `ResolveQuery` do not branch on forwarding versus recursion.
- Runtime settings and policy data need immutable snapshots so DNS queries never observe partially updated configuration or blocklists.
- Query-event logging must be non-blocking, bounded, privacy-aware, and source-centric so it can support compromised-host investigation without making DNS availability depend on logging storage.
- Blocklist ingestion deserves its own workflow because fetching, parsing, validation, rollback, scheduling, and activation are separate from request-time policy.
- Admin UI defaults must be secure: no unauthenticated mutation endpoints and no public bind by default.

See [Reviewer Concerns And Revisions](09-reviewer-concerns.md) for the full concern-to-plan mapping.
