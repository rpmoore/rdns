# Operations And Testing Domain

## Runtime Concerns

The resolver will sit on the critical path for local network name resolution. Operational behavior should be explicit from the first usable milestone.

## Logging

Use structured logs.

Important events:

- Server startup and shutdown.
- DNS listener bind failures.
- Upstream timeout and recovery.
- Blocklist update start, success, failure, and activation.
- Admin configuration changes.
- Cache pressure and evictions.

Query logging should be configurable because DNS logs can contain sensitive browsing metadata.

## Metrics

Track:

- Total queries.
- Query latency.
- Cache hits and misses.
- Blocked queries by reason.
- Upstream requests, failures, and latency.
- Blocklist source freshness and domain counts.
- Active policy generation.
- DNS parse errors by type.
- Active rule count.
- Active blocklist domain count.
- Admin mutations by action type.
- Query log sampling/drop counts if sampling is enabled.

Expose metrics through the admin API first. Prometheus-format export can be added later if needed.

## Health Checks

Admin status should distinguish:

- DNS listener running.
- Admin listener running.
- At least one upstream resolver healthy.
- SQLite reachable.
- Policy snapshot loaded.
- Blocklist sources fresh or stale.

## Security Considerations

- Never panic on network input.
- Validate packet sizes and reject malformed DNS messages.
- Respect UDP response size limits and return truncated responses instead of oversized datagrams.
- Bound upstream timeouts and retries.
- Randomize upstream transaction IDs and validate upstream response source addresses.
- Bound cache size.
- Bound blocklist source size and parse time.
- Do not let arbitrary blocklist URLs read local files, local sockets, or unexpected internal network resources by default.
- Do not expose the admin UI publicly by default.
- Protect admin sessions and mutating API requests.
- Treat query logs as sensitive data.

## Test Strategy

Unit tests:

- DNS parsing and serialization.
- Domain normalization.
- Policy matching.
- Cache TTL and expiry.
- Blocklist parsers.
- Config validation.

Integration tests:

- Resolver with fake UDP/TCP upstreams.
- SQLite repositories and migrations.
- API endpoints with test state.
- Blocklist refresh with fake HTTP source.
- Config reload while queries are in flight.
- Deterministic scheduled refresh using fake `Clock` and `Scheduler`.
- Query logging under a slow or unavailable event writer.
- Blocklist fetcher rejects unsafe schemes, excessive redirects, and local/private-address targets by default.
- EDNS UDP-size behavior and truncated-response behavior.

End-to-end tests:

- Start resolver on high local ports.
- Send DNS queries using raw UDP test client.
- Verify cache hit after first upstream response.
- Verify local rule blocking.
- Verify external blocklist blocking after refresh.
- Verify admin API changes upstream configuration.

Fuzz and robustness:

- Fuzz DNS parser.
- Fuzz blocklist parser with malformed lines.
- Stress concurrent queries for cache and snapshot races.

## Testability Ports

Add explicit traits so failure and timing behavior can be tested deterministically:

- `Clock`
- `Scheduler`
- `HttpFetcher`
- `UpstreamDnsClient`
- `SettingsRepository`
- `RuleRepository`
- `BlocklistRepository`
- `QueryEventSink`
- `MetricsSink`

## Developer Tooling

Recommended commands once implementation grows:

- `cargo test`
- `cargo clippy --all-targets --all-features`
- `cargo fmt --check`
- Parser fuzz target through `cargo fuzz`

## Deployment Notes

Running on standard DNS port 53 usually requires elevated privileges or platform-specific capability setup.

- Develop and test on high local ports by default.
- Document Linux options such as systemd socket activation or `CAP_NET_BIND_SERVICE`.
- Avoid running the whole process as root when a narrower binding capability or socket activation is available.
- Make default listen addresses explicit for DNS and admin separately.
- Include firewall/router guidance only as deployment documentation, not resolver core logic.

## Milestone Acceptance Checks

Each milestone should include:

- Passing unit tests.
- At least one integration test for changed behavior.
- No panics from malformed network input.
- Clear config defaults.
- Documentation update when behavior changes.
