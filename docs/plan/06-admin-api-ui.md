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
- `GET /api/blocklist-sources`
- `POST /api/blocklist-sources`
- `PUT /api/blocklist-sources/{id}`
- `DELETE /api/blocklist-sources/{id}`
- `POST /api/blocklist-sources/{id}/refresh`
- `GET /api/query-events`
- `GET /api/metrics/summary`

Use typed request/response structs and validate at the API boundary before invoking application services.

API validation must preserve runtime invariants:

- Do not allow deleting or disabling the last usable upstream unless a documented degraded mode is enabled.
- Do not allow unsafe listen-address changes without successful persistence and snapshot reload.
- Do not allow `Sinkhole` mode without valid sinkhole addresses for the affected query families.
- Validate blocklist source URLs with the same safety rules used by the fetcher.
- Return typed validation errors that the UI can display without implying the change was applied.

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
- Listening addresses.
- Upstream health.
- Cache hit rate.
- Blocklist freshness.
- Recent query decisions.

`Upstreams`

- Add, edit, enable, disable, reorder upstream resolvers.
- Validate IP/host, port, protocol, timeout.
- Test upstream reachability.

`Rules`

- Add, edit, enable, disable client/domain deny rules.
- Support exact IP and CIDR selectors.
- Support exact and subtree domain selectors.
- Show match examples so administrators can verify intent.

`Blocklists`

- Add, edit, enable, disable external blocklist sources.
- Trigger refresh.
- Show last update status, domain count, and error message.
- Show active generation timestamp.

`Queries`

- Search recent query events.
- Filter by client, domain, decision, cache status, and time.
- Show why a query was blocked or allowed.

`Settings`

- DNS listen addresses.
- Admin listen address.
- Cache TTL caps and size.
- Block response mode.
- Query-log retention.

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
- Blocklist refresh endpoint starts an update without blocking the HTTP request indefinitely.
- UI smoke test for loading the primary screens.
- First-run setup cannot be skipped.
- Unauthenticated mutation attempts are rejected.
