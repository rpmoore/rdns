# DNS Intermediate Resolver Plan

## Current State

The repository is a Rust crate named `rdns` with phases 1 through 6 complete,
plus an MVP wiring pass that makes the binary actually runnable and
configurable ahead of Phase 7's SQLite persistence layer (see "MVP Wiring"
below).

- `src/protocol/mod.rs` contains the safe DNS protocol core: checked parsing, structured parse errors, full-message compression handling, unknown-record support, EDNS visibility, UDP truncation helpers, response builders, transaction-ID rewrite helpers, and TCP framing helpers.
- `src/resolver/mod.rs` contains the `ResolveQuery` application service, resolver ports, query decision metadata, in-memory TTL cache, cache key/value modeling, positive and negative TTL policy, safe cached-response template handling, cache bypass rules, single-flight miss coalescing, cache metrics hooks, the generalized `ResolutionBackend` port (`ForwardingResolutionBackend`/`RecursiveResolutionBackend` behind a hot-swappable `BackendHandle`/`BackendSnapshot`), local policy/deny-rule evaluation, and a hot-swappable local DNS entry lookup (`LocalDnsEntriesHandle`) answered ahead of cache/backend.
- `src/delivery/dns.rs` contains the Tokio UDP DNS listener adapter.
- `src/delivery/upstream.rs` contains UDP upstream forwarding, fresh upstream transaction IDs, source/ID/question validation, priority-ordered failover, per-upstream timeouts, per-query deadlines, health snapshots, TCP fallback for truncated upstream UDP responses, and the recursive-mode authority transport client.
- `src/config/mod.rs` contains validated runtime configuration for DNS listeners, upstream resolvers, resolution mode (forward or recursive, including recursive root hints/timeouts/transports/DNSSEC-validation-mode/DNAME-handling), local DNS entries, and UDP payload limits — loadable from a TOML file (`RuntimeConfig::from_toml_str`) as well as constructed in-process. Bundled recursive-mode root hints are parsed at compile time from a committed IANA zone file (`src/config/named.root`) via `parse_named_root`, not hand-maintained.
- `src/main.rs` loads `RuntimeConfig` from a file (`RDNS_CONFIG` env var, or `./config.toml`, falling back to loopback development defaults), starts the configured UDP DNS server with real local DNS entries and policy wired in, watches `SIGHUP` to validate-and-hot-swap resolution mode/upstreams/local entries without a restart, and shuts down gracefully.
- `src/lib.rs` exports `config`, `delivery`, `protocol`, and `resolver`.
- `Cargo.toml` depends on `tokio`, plus `serde`/`toml` for config file loading.

The resolver can now accept UDP queries, evaluate local deny-rule policy and local DNS entries before touching cache/backend, forward to configured upstreams or perform local iterative recursion (administrator's choice, reloadable live), use TCP fallback for truncated upstream responses, cache eligible responses in memory, rewrite cached responses for the current request, and emit decision/metric hooks.

Remaining major planned areas are external blocklist ingestion, SQLite persistence (settings/rules/blocklists/query-events currently live in a TOML file plus in-memory state, not a database), admin API/UI, DNS TCP listener support for clients, and further operational hardening (see `docs/steps.md` Phase 7 onward).

### MVP Wiring (bridging Phase 6 domain logic into a runnable server)

Phase 6 (PR #99) added local policy and local-DNS-entry *domain logic* to
`ResolveQuery`, but nothing wired it into the actual binary yet — `main.rs`
still hardcoded a single upstream and `NoopLocalDnsEntries`, and there was
no way to configure anything without recompiling. A follow-up MVP pass
(branch `make_mvp`, off post-merge `main`) closed that gap ahead of Phase
7's SQLite work, since a file-based config was enough to make the server
actually useful:

- TOML config file loading (`RuntimeConfig::from_toml_str`), covering
  listen addresses, resolution mode (forward and recursive), upstreams,
  and local DNS entries, with `#[serde(deny_unknown_fields)]` so a typo'd
  or unsupported key fails closed instead of being silently ignored.
- `SIGHUP`-triggered reload: re-read and fully re-validate the config file,
  and only on success hot-swap resolution mode/upstreams (`BackendSnapshot`)
  and local DNS entries (`LocalDnsEntriesHandle`) — never a partial apply,
  and `dns_listen` intentionally stays restart-only (rebinding sockets is
  out of scope for a data reload).
- Recursive-mode root hints parsed from a real, committed IANA zone file
  (`src/config/named.root`) instead of a hardcoded list.
- `validate_listen_address` relaxed to allow privileged ports (still
  rejects port `0`), so the server can bind `:53` for real LAN use (with
  root or `setcap cap_net_bind_service`).

This is an interim mechanism, not a replacement for Phase 7: it satisfies
[Persistence And Configuration](05-persistence-config.md#configuration-reload)'s
validate-before-publish/atomic-snapshot intent using a config file and
`Arc<RwLock<Arc<T>>>` handles instead of SQLite-backed repositories and an
admin API. Phase 7 should extend or replace this reload path, not
re-derive it from scratch.

## Target Capabilities

The finished application should run as an intermediate DNS resolver for a local network.

- Accept DNS queries from LAN clients over UDP and later TCP.
- Cache DNS responses to reduce local lookup latency.
- Let an administrator choose whether allowed cache misses are resolved by forwarding to configured upstream recursive resolvers or by performing iterative recursive resolution locally.
- Block domains known to be malicious using configured external blocklist sources.
- Block configured client IP addresses from resolving selected domains.
- Let an administrator define exact local DNS entries, such as `dev1.local`, that return configured target IP addresses without contacting upstream resolvers; targets are typically LAN addresses, while public/routable targets require explicit acknowledgement and guardrails.
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
- `policy`: domain normalization, local rules, malicious-domain matching, local DNS entry lookup, and block actions.
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
6. If allowed, `resolver` checks exact local DNS entries and returns a generated local answer when one matches.
7. If there is no matching local entry, `resolver` checks the cache.
8. On cache hit, the resolver rewrites the response transaction ID and returns it.
9. On cache miss, the resolver calls the configured `ResolutionBackend`. The backend either forwards to configured upstream resolvers or performs local iterative recursion.
10. `resolver` validates the backend response, applies response-aware policy checks, caches it according to TTL policy, and returns it.
11. The query decision is emitted as a structured event through a non-blocking sink.
12. The query-event pipeline stores a bounded review model and applies advisory suspicious-lookup classification without blocking DNS responses.

## Remaining Primary Risks

- There is a local deny-rule policy engine and local DNS entry model (Phase 6), but no known-malicious blocklist ingestion yet — blocklist-sourced blocking decisions are not enforced.
- Query-event review is currently limited to the in-process decision hooks and bounded in-memory store; there is no durable (SQLite-backed) query-event history yet, so history and suspicious-lookup findings do not survive a restart.
- Configuration (resolution mode, upstreams, local DNS entries) is file-based and hot-reloadable via `SIGHUP` (see "MVP Wiring" above), but not durable/queryable SQL storage, and there is no admin API/UI to change it at runtime without editing the file.
- There is no persistence layer, blocklist updater, admin API, UI server, structured metrics exporter (beyond the existing OpenTelemetry OTLP hook), or durable query logging.
- DNS TCP support exists for protocol framing and upstream fallback, but the resolver does not yet expose a client-facing TCP listener.
- Forwarding upstreams only ever send queries over UDP; a `protocol = "tcp"` upstream entry validates but is silently excluded from the active forwarding set (`ordered_enabled_udp_upstreams`), so a TCP-only upstream list fails closed with no enabled upstream rather than actually querying over TCP.
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
- Local DNS entries need explicit precedence, cache invalidation, `.local` conflict warnings, and generated-answer guardrails so host overrides do not accidentally bypass policy or produce stale answers.
- Query-event logging must be non-blocking, bounded, privacy-aware, and source-centric so it can support compromised-host investigation without making DNS availability depend on logging storage.
- Blocklist ingestion deserves its own workflow because fetching, parsing, validation, rollback, scheduling, and activation are separate from request-time policy.
- Admin UI defaults must be secure: no unauthenticated mutation endpoints and no public bind by default.

See [Reviewer Concerns And Revisions](09-reviewer-concerns.md) for the full concern-to-plan mapping.
