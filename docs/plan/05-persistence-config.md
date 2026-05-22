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
- `timestamp`
- `client_ip`
- `domain`
- `qtype`
- `decision`
- `reason`
- `upstream_id`
- `cache_status`
- `latency_ms`

Suggested indices:

- `client_domain_rules(enabled, client_selector_type, client_selector_value)`
- `client_domain_rules(enabled, domain_selector_type, domain_selector_value)`
- `blocklist_domains(domain)`
- `active_blocklist_generations(source_id)`
- `query_events(timestamp)`
- `query_events(client_ip, timestamp)`
- `query_events(domain, timestamp)`

## Repository Ports

- `SettingsRepository`
- `UpstreamRepository`
- `RuleRepository`
- `BlocklistRepository`
- `QueryEventRepository`

Keep repository methods shaped around use cases, not generic table access.

Examples:

- `load_resolver_settings()`
- `replace_upstreams(upstreams)`
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
- Use `Arc<PolicySnapshot>` for local rules and active blocklist domains.
- Publish new snapshots only after database transactions commit.
- Include a generation/version number in snapshots for logs and debugging.
- Avoid direct database reads on the DNS hot path.

Configuration validation must enforce invariants before a snapshot can be published:

- At least one enabled upstream resolver is required unless degraded/no-upstream mode is explicitly configured.
- DNS listen addresses and admin listen addresses must be valid and must not conflict.
- Upstream timeout, per-query deadline, cache size, TTL caps, and retention settings must be within bounded ranges.
- Sinkhole addresses must be configured before `Sinkhole` block mode can be enabled.
- IPv4 and IPv6 settings should be validated separately so an IPv4-only sinkhole is not used for AAAA responses.
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
- Maximum blocklist generations retained per source.
- Optional cache size limit.
- Maintenance task for deleting expired operational data.
- SQLite vacuum/optimize strategy after large blocklist churn.

Without retention, a busy LAN can grow the SQLite database indefinitely.

## Query Event Backpressure

Query logging must not block DNS responses when SQLite is slow or unavailable.

- Send query events through a bounded asynchronous queue or dedicated writer task.
- Define overflow behavior: drop newest, drop oldest, or sample, and emit metrics for dropped events.
- Keep enough synchronous metadata for resolver metrics even if durable query logging is disabled or backpressured.
- Admin UI query history should show when logs are sampled or dropped so operators do not mistake it for complete history.

## SQLite Async Strategy

Choose the SQLite access model deliberately.

Options:

- `sqlx` with SQLite pool and migrations.
- `rusqlite` isolated behind `spawn_blocking` or a dedicated database task.

Do not perform blocking SQLite work on Tokio async worker threads. Repository traits should hide this choice from application services.

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
- Failed blocklist update keeps prior active generation.
- Query-event retention cleanup.
- Concurrent readers during config reload.
- Migration failure prevents listener startup.
- Retention cleanup keeps configured limits.
- Invalid configuration cannot be persisted or published as a runtime snapshot.
- Slow or unavailable query-event persistence does not block DNS responses.
