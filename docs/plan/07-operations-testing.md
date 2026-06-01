# Operations And Testing Domain

## Runtime Concerns

The resolver will sit on the critical path for local network name resolution. Operational behavior should be explicit from the first usable milestone.

## Performance Budgets

Define and version explicit throughput and latency budgets before query-event pipeline rollout so later milestones can prove no DNS hot-path regressions.

Track at least:

- End-to-end DNS query latency percentiles (p50, p95, p99) under representative steady-state and burst load profiles.
- Throughput targets under representative steady-state and burst load profiles.
- Query-event pipeline enqueue latency, queue wait time, and drop/sampled-rate budgets under expected and overload conditions.

## Logging

Use structured logs.

Important events:

- Server startup and shutdown.
- DNS listener bind failures.
- Upstream timeout and recovery.
- Blocklist update start, success, failure, and activation.
- Admin configuration changes.
- Cache pressure and evictions.
- Query-event pipeline overflow, sampling, disabled logging, and processor failures.
- Suspicious lookup classifier threshold/config changes.

Query logging should be configurable because DNS logs can contain sensitive browsing metadata.

## Metrics

Track:

- Total queries.
- Query latency.
- Cache hits and misses.
- Blocked queries by reason.
- Upstream requests, failures, and latency.
- Active backend mode and generation.
- Recursive query count and latency.
- Recursive authority attempts, timeouts, lame delegations, referral loops, and bailiwick rejections.
- Recursive TCP fallback attempts and failures.
- Recursive depth-limit and CNAME/DNAME restart-limit hits.
- Negative-cache hits and stores.
- Root-hints source, age, and load status.
- DNSSEC validation status.
- Blocklist source freshness and domain counts.
- Active policy generation.
- DNS parse errors by type.
- Active rule count.
- Active local DNS entry count.
- Active blocklist domain count.
- Admin mutations by action type.
- Query log sampling/drop counts if sampling is enabled.
- Query-event pipeline queue depth and processor errors.
- Query-event pipeline queue wait latency.
- Query-event pipeline stage latency (enqueue, classify, store, read-model update).
- Suspicious lookup findings by reason and severity.
- Suspicious observed source count.

Expose metrics through the admin API first. Prometheus-format export can be added later if needed.

## Health Checks

Admin status should distinguish:

- DNS listener running.
- Admin listener running.
- Active resolution backend healthy.
- At least one upstream resolver healthy when forward mode is active.
- Root hints and recent authority health when recursive mode is active.
- DNSSEC validation disabled or validating status.
- SQLite reachable.
- Policy snapshot loaded.
- Blocklist sources fresh or stale.

## Security Considerations

- Never panic on network input.
- Validate packet sizes and reject malformed DNS messages.
- Respect UDP response size limits and return truncated responses instead of oversized datagrams.
- Bound upstream timeouts and retries.
- Randomize upstream transaction IDs and validate upstream response source addresses.
- Bound recursive depth, CNAME restarts, authority retries, and referral handling.
- Enforce bailiwick rules before trusting recursive referral glue.
- Randomize recursive authority transaction IDs, validate authority response source and question, and retry truncated UDP authority responses over TCP when allowed.
- Clear `AD` unless local DNSSEC trust-anchor validation is implemented.
- Bound cache size.
- Bound blocklist source size and parse time.
- Do not let arbitrary blocklist URLs read local files, local sockets, or unexpected internal network resources by default.
- Do not expose the admin UI publicly by default.
- Protect admin sessions and mutating API requests.
- Treat query logs as sensitive data.
- Do not expose query-event history, source detail, suspicious lookup findings, or exports without authenticated admin access.
- Make observed-source identity limitations visible in query-review views.
- Warn administrators that `.local` entries may conflict with mDNS and may not be queried through this resolver by all clients.
- Require explicit acknowledgement before local DNS entries point at public/routable addresses.

## Test Strategy

Unit tests:

- DNS parsing and serialization.
- Domain normalization.
- Policy matching.
- Cache TTL and expiry.
- Blocklist parsers.
- Config validation.
- Local DNS entry validation, exact matching, generated `NODATA`, and policy precedence.

Integration tests:

- Resolver with fake UDP/TCP upstreams.
- Recursive resolver with fake root, TLD, and authoritative servers.
- Recursive transport tests for truncated authoritative answers/referrals, source mismatch, ID mismatch, question mismatch, and deadline handling.
- Recursive cache namespace tests across mode, upstream-set, root-hints, and DNSSEC-validation changes.
- SQLite repositories and migrations.
- API endpoints with test state.
- Blocklist refresh with fake HTTP source.
- Config reload while queries are in flight.
- Deterministic scheduled refresh using fake `Clock` and `Scheduler`.
- Query logging under a slow or unavailable event writer.
- Query-event hot-path tests proving slow processors/stores do not delay DNS responses.
- In-memory query-review tests for per-observed-source history, suspicious summaries, retention eviction, ordering by timestamp plus sequence, disabled logging, and overflow indicators.
- Suspicious classifier tests for versioned findings, threshold boundaries, cold starts, retained-window limitations, sampled/dropped events, and advisory suspicious-but-allowed events.
- Performance-gate tests that compare current DNS hot-path latency/throughput against recorded Milestone 2/3 baselines.
- Event-pipeline load tests for representative steady-state throughput, burst pressure, slow/failing processors, and high-cardinality source/domain patterns.
- Blocklist fetcher rejects unsafe schemes, excessive redirects, and local/private-address targets by default.
- EDNS UDP-size behavior and truncated-response behavior.
- DNSSEC `AD`, `DO`, and `CD` behavior while validation is disabled.

End-to-end tests:

- Start resolver on high local ports.
- Send DNS queries using raw UDP test client.
- Verify cache hit after first upstream response.
- Verify local rule blocking.
- Verify local DNS entry answers for allowed `A`/`AAAA` queries and no backend request is made.
- Verify external blocklist blocking after refresh.
- Verify admin API changes upstream configuration.
- Verify authenticated query review can find suspicious lookups and source history without exposing data unauthenticated.

Fuzz and robustness:

- Fuzz DNS parser.
- Fuzz blocklist parser with malformed lines.
- Stress concurrent queries for cache and snapshot races.
- Stress query-event ingestion, classifier processing, and read-model updates under high query volume.
- Stress backend snapshot swaps and cache namespace changes while queries are in flight.

## Testability Ports

Add explicit traits so failure and timing behavior can be tested deterministically:

- `Clock`
- `Scheduler`
- `HttpFetcher`
- `UpstreamDnsClient`
- `AuthorityDnsClient` or `DnsTransport`
- `RootHintsProvider`
- `AuthoritySelector`
- `TransactionIdGenerator`
- `RecursionCache`
- `SettingsRepository`
- `RuleRepository`
- `LocalDnsEntryRepository`
- `BlocklistRepository`
- `QueryEventSink`
- `QueryEventStore`
- `QueryEventReadModel`
- `SuspiciousLookupClassifier`
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
