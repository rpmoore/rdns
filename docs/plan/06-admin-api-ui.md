# Admin API And UI Domain

## Responsibility

The admin surface lets an operator configure and inspect the resolver. It should call application services, not manipulate resolver internals or database tables directly.

## API Scope

Initial endpoints:

- `GET /api/status`
- `GET /api/settings`
- `PUT /api/settings`
- `GET /api/upstreams`
- `POST /api/upstreams`
- `PUT /api/upstreams/{id}`
- `DELETE /api/upstreams/{id}`
- `GET /api/rules`
- `POST /api/rules`
- `PUT /api/rules/{id}`
- `DELETE /api/rules/{id}`
- `GET /api/local-dns-entries`
- `POST /api/local-dns-entries`
- `PUT /api/local-dns-entries/{id}`
- `DELETE /api/local-dns-entries/{id}`
- `GET /api/blocklist-sources`
- `POST /api/blocklist-sources`
- `PUT /api/blocklist-sources/{id}`
- `DELETE /api/blocklist-sources/{id}`
- `POST /api/blocklist-sources/{id}/refresh`
- `GET /api/query-events`
- `GET /api/query-events/suspicious`
- `GET /api/query-events/sources`
- `GET /api/query-events/sources/{source_id}`
- `GET /api/metrics/summary`

Use typed request/response structs and validate at the API boundary before invoking application services.

For local DNS entries, `POST` creates a full `LocalDnsEntry` resource and `PUT /api/local-dns-entries/{id}` replaces the full resource, including `domain`, `enabled`, `ttl_seconds`, `addresses`, `description`, and required warning acknowledgements. Enable and disable flows use the same `PUT` endpoint by changing the `enabled` boolean; no partial `PATCH` or dedicated enable/disable endpoint is required in the first API version. Responses should return the saved resource plus validation or warning metadata so the UI can show whether `.local` and public-address acknowledgements were required.

API validation must preserve runtime invariants:

- Do not allow deleting or disabling the last usable upstream while `forward` mode is active unless a documented degraded mode is enabled.
- Do not allow enabling `recursive` mode unless root hints and recursion bounds are valid.
- Show resolution-mode changes as pending until persistence, backend construction, and snapshot reload all succeed.
- Show DNSSEC validation status explicitly; while validation is disabled, the UI must not imply recursive mode validates DNSSEC.
- Show cache namespace/generation changes or cache flushes caused by resolution-mode, upstream, root-hints, or DNSSEC-setting changes.
- Do not allow unsafe listen-address changes without successful persistence and snapshot reload.
- Do not allow `Sinkhole` mode without valid sinkhole addresses for the affected query families.
- Validate local DNS entry names, TTLs, address families, `.local` warning acknowledgements, and public-address acknowledgements before persistence.
- Show local DNS entry changes as pending until persistence, cache invalidation or namespace advancement, and snapshot reload succeed.
- Validate blocklist source URLs with the same safety rules used by the fetcher.
- Return typed validation errors that the UI can display without implying the change was applied.
- Query-event and suspicious-lookup APIs must require authentication and should audit export/copy actions because DNS history is sensitive.

## Authentication And Safety

Even on a local network, the admin UI controls security policy and DNS routing.

Minimum requirements:

- Require authentication before any admin action.
- Provide a first-run password or setup-token flow.
- Store password hashes, not plaintext passwords.
- Use secure session cookies.
- Expire sessions.
- Protect mutating browser requests from CSRF.
- Bind admin server to a configured interface, defaulting to loopback until explicitly configured.
- Rate-limit login attempts.
- Log admin changes in an audit-friendly form.
- Expose no unauthenticated mutation endpoints.

Bootstrap requirement:

- On first run, generate or require an admin setup token.
- The UI should force initial credential creation before exposing settings.
- The setup token must become invalid after first successful setup.
- If the administrator chooses to bind the UI to a LAN address, require an explicit config change.

## UI Screens

`Status`

- Resolver health.
- Active resolution mode.
- Active backend generation/cache namespace.
- Listening addresses.
- Upstream health.
- Recursive root-hint status and recent authority failure summary when recursive mode is active.
- Recursive DNSSEC validation status.
- Cache hit rate.
- Blocklist freshness.
- Recent query decisions.
- Query-event pipeline health, dropped/sampled event counts, and current suspicious source count.

`Upstreams`

- Add, edit, enable, disable, reorder upstream resolvers.
- Validate IP/host, port, protocol, timeout.
- Test upstream reachability.
- Make clear that upstreams are used by forward mode and not by pure recursive mode.

`Resolution`

- Choose `forward` or `recursive` mode.
- Configure forward-mode upstream behavior.
- Configure recursive root hints, recursion limits, and authority timeouts.
- Validate the new backend before applying it as active.

`Rules`

- Add, edit, enable, disable client/domain deny rules.
- Support exact IP and CIDR selectors.
- Support exact and subtree domain selectors.
- Show match examples so administrators can verify intent.

`Local DNS`

- Add, edit, enable, disable, and delete exact local DNS entries.
- Support `A` and `AAAA` address lists with TTL and description fields.
- Show generated-answer behavior clearly, including that local entries are evaluated after deny/blocklist policy and before cache/upstream resolution.
- Warn when an entry uses `.local` because mDNS behavior may prevent some clients from querying this resolver.
- Warn and require explicit acknowledgement before saving public/routable target addresses.
- Show match examples and the resulting `NODATA` behavior when a known local name is queried for an unconfigured address family.

`Blocklists`

- Add, edit, enable, disable external blocklist sources.
- Trigger refresh.
- Show last update status, domain count, and error message.
- Show active generation timestamp.

`Queries`

- Search recent query events.
- Filter by observed source, domain, terminal outcome, DNS response code, policy decision, cache status, suspicious flag/reason, qtype, and time.
- Show why a query was blocked or allowed.
- Distinguish `AllowedFromBackend` from `AllowedFromCache`.
- Show dropped/sampled indicators so operators understand when summaries are incomplete.

`Suspicious Lookups`

- Show suspicious events grouped by observed source.
- Show classifier reason, severity/score, evaluated window, classifier version, and whether the finding was advisory or policy-blocked.
- Link from a suspicious finding to the source detail and surrounding query timeline.
- Make clear that observed source IP may not be a stable machine identity until client identity labels are configured.

`Source Detail`

- Show all retained requests for one observed source.
- Show suspicious timeline, top queried domains, blocked/allowed breakdown, qtype distribution, NXDOMAIN/SERVFAIL bursts, repeated TXT lookups, and known-bad/blocklist attribution when available.
- Show any `ClientIdentitySnapshot` labels and generation when policy identity support exists.

`Settings`

- DNS listen addresses.
- Admin listen address.
- Resolution mode.
- Cache TTL caps and size.
- Block response mode.
- Local DNS entry defaults, including default TTL and public-address acknowledgement policy.
- Query-log retention.
- Query-event logging mode, overflow behavior, in-memory retention limits, classifier enablement, and classifier thresholds.

## Delivery Implementation

Recommended Rust direction:

- Use an HTTP framework such as `axum` for API and static UI serving.
- Use server-rendered HTML or a small static frontend first.
- Avoid a large frontend toolchain until the API/domain behavior is stable.

The UI can start as static HTML/CSS/JavaScript served by the Rust admin server. Keep the API stable enough that a richer UI can replace it later.

## Tests

- API validation tests.
- Auth and CSRF tests.
- Settings update reload test.
- Query-event filtering and source-detail authorization tests.
- Local DNS entry API validation, warning acknowledgement, reload, and cache-invalidation tests.
- Suspicious lookup API tests for advisory findings, dropped/sampled indicators, and export audit logging.
- Blocklist refresh endpoint starts an update without blocking the HTTP request indefinitely.
- UI smoke test for loading the primary screens.
- First-run setup cannot be skipped.
- Unauthenticated mutation attempts are rejected.
