# Persistence And Configuration Domain

## Responsibility

Persistence stores durable administrator intent and operational history. Configuration exposes validated runtime settings to resolver services.

The domain and application layers should depend on repository traits, not SQLite or file formats directly.

## Storage Choice

Use SQLite for the first implementation.

Reasons:

- Simple local deployment.
- Transactional updates for rules and blocklist activation.
- Good fit for an appliance-style local resolver.
- Easy backup and inspection.

Use migrations from the beginning so schema changes stay controlled.

## Proposed Tables

`settings`

- `key`
- `value_json`
- `updated_at`

Resolution-mode settings should include:

- `resolution.mode`: `forward` or `recursive`.
- `resolution.forward.upstream_policy`: ordered failover initially.
- `resolution.recursive.root_hints_source`: bundled, file, or database-managed root hints.
- `resolution.recursive.max_depth`
- `resolution.recursive.max_cname_restarts`
- `resolution.recursive.per_authority_timeout_ms`
- `resolution.recursive.allowed_transports`
- `resolution.recursive.dnssec_validation_mode`: initially `disabled` unless trust-anchor validation is implemented.
- `resolution.recursive.dname_policy`: initially `defer` unless DNAME synthesis and cache rules are implemented.
- `resolution.cache_namespace_generation`

`upstream_resolvers`

- `id`
- `name`
- `address`
- `port`
- `protocol`
- `enabled`
- `priority`
- `timeout_ms`
- `created_at`
- `updated_at`

`client_domain_rules`

- `id`
- `client_selector_type`
- `client_selector_value`
- `domain_selector_type`
- `domain_selector_value`
- `action`
- `enabled`
- `description`
- `created_at`
- `updated_at`

`local_dns_entries`

- `id`
- `domain`
- `enabled`
- `ttl_seconds`
- `description`
- `target_acknowledgements_json`
- `created_at`
- `updated_at`
- Constraints:
  - `PRIMARY KEY (id)`
  - `domain NOT NULL`, stored as canonical lowercase ASCII/Punycode without trailing dot
  - `enabled NOT NULL`
  - Unique index on `lower(domain)` for exact-name v1 behavior, so SQLite cannot persist case variants such as `Dev1.Local` and `dev1.local` as separate entries

`local_dns_entry_addresses`

- `entry_id`
- `address_family`
- `address`
- `created_at`
- Constraints:
  - `entry_id NOT NULL`
  - `address_family NOT NULL`
  - `address NOT NULL`
  - `FOREIGN KEY (entry_id) REFERENCES local_dns_entries(id) ON DELETE CASCADE`
  - `UNIQUE (entry_id, address_family, address)`
  - SQLite connections must enable `PRAGMA foreign_keys = ON` so cascade deletes are enforced.

`blocklist_sources`

- `id`
- `name`
- `url`
- `format`
- `enabled`
- `last_status`
- `last_started_at`
- `last_finished_at`
- `last_error`
- `etag`
- `last_modified`
- `created_at`
- `updated_at`

`blocklist_generations`

- `id`
- `source_id`
- `status`
- `domain_count`
- `content_hash`
- `started_at`
- `finished_at`
- `error`

`blocklist_domains`

- `generation_id`
- `domain`
- `selector_type`

`active_blocklist_generations`

- `source_id`
- `generation_id`
- `activated_at`

`query_events`

- `id`
- `schema_version`
- `sequence`
- `timestamp`
- `observed_source_ip`
- `observed_source_port`
- `transport`
- `listener`
- `client_ip`
- `client_identity_id`
- `client_identity_labels_json`
- `client_identity_generation`
- `domain`
- `original_domain`
- `qtype`
- `qclass`
- `terminal_outcome`
- `local_response_code`
- `decision`
- `reason`
- `backend_mode`
- `backend_generation`
- `upstream_id`
- `cache_status`
- `classifier_findings_json`
- `latency_ms`
- `sampled`
- `dropped_before_store`

Suggested indices:

- `client_domain_rules(enabled, client_selector_type, client_selector_value)`
- `client_domain_rules(enabled, domain_selector_type, domain_selector_value)`
- Unique exact-name index on `lower(local_dns_entries.domain)`, plus lookup support for enabled entries by canonical domain.
- `local_dns_entry_addresses(entry_id, address_family)`
- `blocklist_domains(domain)`
- `active_blocklist_generations(source_id)`
- `query_events(timestamp)`
- `query_events(client_ip, timestamp)`
- `query_events(observed_source_ip, timestamp)`
- `query_events(observed_source_ip, sampled, timestamp)`
- `query_events(domain, timestamp)`
- `query_events(terminal_outcome, timestamp)`

If classifier findings are stored separately later, add indices for suspicious findings by source, reason, severity, and timestamp. Until then, keep `classifier_findings_json` compact and query summaries through maintained read models rather than full JSON scans.

## Repository Ports

- `SettingsRepository`
- `UpstreamRepository`
- `RuleRepository`
- `LocalDnsEntryRepository`
- `BlocklistRepository`
- `QueryEventRepository`

Keep repository methods shaped around use cases, not generic table access.

Examples:

- `load_resolver_settings()`
- `replace_upstreams(upstreams)`
- `replace_resolution_mode(settings)`
- `load_root_hints()`
- `load_local_dns_entries()`
- `replace_local_dns_entries(entries)`
- `publish_backend_snapshot(snapshot)`
- `load_policy_snapshot()`
- `activate_blocklist_generation(source_id, generation_id)`
- `append_query_events(events)`

## Configuration Reload

Runtime configuration should be snapshot-based.

- Validate admin changes before saving.
- Persist changes transactionally.
- Build a new immutable runtime snapshot.
- Swap the active snapshot atomically.
- Existing queries may finish with the old snapshot.
- New queries use the new snapshot.

This avoids partially applied settings while keeping DNS request handling fast.

Implementation shape:

- Use `Arc<RuntimeConfig>` for resolver settings.
- Use an atomic `Arc<BackendSnapshot>` or equivalent handle for resolution backend, backend health state, and cache namespace.
- Use `Arc<PolicySnapshot>` for local rules and active blocklist domains.
- Use an immutable local DNS entry snapshot, or include local entries in the policy snapshot, so exact local answers are generation-tracked and hot-path lookups never read the database.
- Publish new snapshots only after database transactions commit.
- Include a generation/version number in snapshots for logs and debugging.
- Avoid direct database reads on the DNS hot path.

Configuration validation must enforce invariants before a snapshot can be published:

- In `forward` mode, at least one enabled upstream resolver is required unless degraded/no-upstream mode is explicitly configured.
- In `recursive` mode, root hints must be present and valid, recursion limits must be bounded, and outbound transport/timeouts must be configured.
- Resolution mode changes must build the new `ResolutionBackend` successfully before publishing the runtime snapshot.
- Resolution mode, upstream-set, root-hints, DNSSEC-validation, and other answer-affecting setting changes must advance the cache namespace or explicitly flush affected response-template and recursive-internal caches.
- `recursive` mode with DNSSEC validation disabled must clear `AD` and report validation-disabled status; enabling validation requires trust-anchor configuration and validation tests.
- DNAME handling must remain conservative until DNAME synthesis, loop detection, and cache safety are implemented.
- DNS listen addresses and admin listen addresses must be valid and must not conflict.
- Upstream timeout, per-query deadline, cache size, TTL caps, and retention settings must be within bounded ranges.
- Sinkhole addresses must be configured before `Sinkhole` block mode can be enabled.
- IPv4 and IPv6 settings should be validated separately so an IPv4-only sinkhole is not used for AAAA responses.
- Local DNS entries must use valid normalized exact domain names, bounded TTLs, and address-family-correct IP values.
- Local DNS entries under `.local` are allowed only with warning metadata surfaced to the administrator because of mDNS conflicts.
- Local DNS entries that target public/routable addresses require explicit acknowledgement; private/LAN targets are the safe default.
- Local DNS entry changes must advance an answer-affecting generation or flush affected exact-question cache entries before the new snapshot becomes active.
- Blocklist source URLs must pass fetcher safety validation before being saved as enabled.

## Blocklist Update Transactions

Blocklist updates should be idempotent and recoverable.

Flow:

1. Mark source update as started.
2. Fetch content through a fetcher adapter.
3. Parse and normalize domains into a staging generation.
4. Store generation rows transactionally.
5. Activate the new generation in one transaction.
6. Rebuild and swap the in-memory policy snapshot.
7. Mark source status with counts and timestamps.

If fetching or parsing fails, keep the previous active generation.

## Retention

Add retention controls early:

- Query-event retention days.
- Query-event maximum row count.
- Query-event maximum retained sources/domains in summary tables.
- Maximum blocklist generations retained per source.
- Optional cache size limit.
- Maintenance task for deleting expired operational data.
- SQLite vacuum/optimize strategy after large blocklist churn.

Without retention, a busy LAN can grow the SQLite database indefinitely.

## Query Event Backpressure

Query logging must not block DNS responses when SQLite is slow or unavailable.

- Send query events through a bounded asynchronous queue or dedicated writer task.
- Define overflow behavior: drop newest, drop oldest, or sample, and emit metrics for dropped events.
- Preserve the non-blocking hot-path contract introduced by the in-memory event pipeline; SQLite writes must consume from the event processor, not from `ResolveQuery` directly.
- Keep enough synchronous metadata for resolver metrics even if durable query logging is disabled or backpressured.
- Admin UI query history should show when logs are sampled or dropped so operators do not mistake it for complete history.
- Suspicious classifier findings persisted with events must include classifier version, config generation, reason, severity/score, evaluated window, and structured details.

## SQLite Async Strategy

Choose the SQLite access model deliberately.

Options:

- `sqlx` with SQLite pool and migrations.
- `rusqlite` isolated behind `spawn_blocking` or a dedicated database task.

Do not perform blocking SQLite work on Tokio async worker threads. Repository traits should hide this choice from application services.

SQLite foreign-key enforcement must be enabled for every database connection, for example with `PRAGMA foreign_keys = ON` or the equivalent pool/ORM setting. The `local_dns_entry_addresses.entry_id` cascade and duplicate-address constraints rely on that enforcement to avoid orphaned rows after entry deletion.

## Startup And Migration Failure

Startup behavior must be explicit:

- If migrations fail, do not start the DNS listener.
- If settings cannot load, do not start the DNS listener.
- If blocklist policy cannot load but local rules and upstreams can load, start only if configured to allow degraded startup.
- Emit health status explaining degraded startup state.
- Never start with an empty policy snapshot due to a silent blocklist load error.

## Tests

- Migration tests from empty database.
- Repository integration tests using temporary SQLite databases.
- Atomic rule update and reload tests.
- Resolution-mode validation and reload tests for forward and recursive settings.
- Failed blocklist update keeps prior active generation.
- Query-event retention cleanup.
- Concurrent readers during config reload.
- Migration failure prevents listener startup.
- Retention cleanup keeps configured limits.
- Invalid configuration cannot be persisted or published as a runtime snapshot.
- Slow or unavailable query-event persistence does not block DNS responses.
