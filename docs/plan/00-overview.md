# DNS Intermediate Resolver Plan

## Current State

The repository is a small Rust crate named `rdns`.

- `src/dns.rs` contains a DNS wire-message parser with tests for domain-name parsing, common record types, and message sections.
- `src/main.rs` is only a placeholder that constructs a 12-byte message.
- `src/lib.rs` only exports the `dns` module.
- `Cargo.toml` currently depends only on `tokio`.

There is no resolver runtime yet: no UDP/TCP listener, upstream forwarding, response serializer, cache, policy engine, persistence layer, blocklist updater, admin API, UI server, configuration loader, metrics, or query logging.

## Target Capabilities

The finished application should run as an intermediate DNS resolver for a local network.

- Accept DNS queries from LAN clients over UDP and later TCP.
- Cache upstream DNS responses to reduce local lookup latency.
- Block domains known to be malicious using configured external blocklist sources.
- Block configured client IP addresses from resolving selected domains.
- Let an administrator configure upstream resolvers such as Cloudflare, Google, or local upstreams.
- Let an administrator manage client/domain rules and blocklist sources through a UI.
- Expose operational status for cache behavior, upstream health, blocklist freshness, and query decisions.

## Architectural Direction

Use a modular monolith first. The application has several clear domains, but the current project does not justify separate deployable services. Keep domain logic independent from networking, database, HTTP, and UI details so each area can be tested directly.

Recommended module shape:

- `protocol`: DNS packet parsing, validation, serialization, and response construction.
- `resolver`: request orchestration, upstream selection, cache lookup, cache population, and response decisions.
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

- `UpstreamResolver`
- `DnsCache`
- `PolicyRepository`
- `BlocklistRepository`
- `SettingsRepository`
- `BlocklistFetcher`
- `Clock`
- `QueryEventSink`
- `MetricsSink`

## Core Runtime Flow

1. DNS listener receives a query and captures the client IP address.
2. `protocol` parses the query using checked bounds and compression validation.
3. `resolver` extracts a normalized lookup key from the question.
4. `policy` evaluates client/domain rules first, then malicious-domain blocklists.
5. If blocked, `resolver` chooses the configured block mode and asks `protocol` to serialize that response.
6. If allowed, `resolver` checks the cache.
7. On cache hit, the resolver rewrites the response transaction ID and returns it.
8. On cache miss, the resolver forwards to an upstream resolver, validates the response, caches it according to TTL policy, and returns it.
9. The query decision is logged asynchronously.

## Primary Risks In The Existing Code

- Parser functions use unchecked indexing and `unwrap`, so malformed packets can panic the resolver.
- Unsupported record types call `unimplemented!`, which is not acceptable for network input.
- DNS compression pointers are currently parsed against the slice passed into section parsing, but DNS compression offsets are relative to the full DNS message.
- There is no response serializer or way to safely rewrite transaction IDs for cached responses.
- The parser has no explicit error type, making protocol failures hard to map to DNS response codes.
- No runtime boundary exists between parsing, policy, caching, forwarding, and persistence.

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
- Runtime settings and policy data need immutable snapshots so DNS queries never observe partially updated configuration or blocklists.
- Blocklist ingestion deserves its own workflow because fetching, parsing, validation, rollback, scheduling, and activation are separate from request-time policy.
- Admin UI defaults must be secure: no unauthenticated mutation endpoints and no public bind by default.

See [Reviewer Concerns And Revisions](09-reviewer-concerns.md) for the full concern-to-plan mapping.
