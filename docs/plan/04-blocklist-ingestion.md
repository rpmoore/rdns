# Blocklist Ingestion Domain

## Responsibility

Blocklist ingestion turns external domain lists into validated, normalized, immutable policy snapshots.

It should not run during request-time DNS policy evaluation, build DNS responses, or directly mutate the active in-memory policy set while parsing.

## Inputs

- Configured source URL.
- Source format.
- Optional HTTP cache metadata such as ETag and Last-Modified.
- Current active generation.
- Update limits and guardrails.

Supported initial formats:

- Plain domain per line.
- Hosts-file style entries such as `0.0.0.0 bad.example`.
- Comment lines beginning with `#`.

Later formats can be added behind parser traits.

## Update Flow

1. Load enabled blocklist sources.
2. Acquire a per-source update lock so the same source is not refreshed twice concurrently.
3. Fetch source content through an `HttpFetcher` adapter.
4. Enforce maximum byte size before parsing.
5. Parse source lines into raw domain candidates.
6. Normalize and validate domains using the policy domain's canonical representation.
7. Track parse errors and reject the generation if error thresholds are exceeded.
8. Dedupe domains.
9. Store the result as a new inactive generation.
10. Compare generation stats against the previous active generation.
11. Activate the new generation transactionally if guardrails pass.
12. Rebuild and atomically swap the in-memory policy snapshot.
13. Mark source update status.

If any step fails, retain the previous active generation.

## Guardrails

External blocklists can fail or become hostile. Add guardrails before activation:

- Maximum download size.
- Maximum domain count.
- Maximum parse-error ratio.
- Minimum domain count for sources that previously had a healthy non-empty list.
- Suspicious-delta detection when a source suddenly removes or adds most domains.
- Per-source enable/disable.
- Dry-run stats shown in the admin UI before manual activation if a guardrail fails.
- Retain at least one previous-good generation.
- Idempotent update runs based on source metadata or content hash.

Fetcher safety requirements:

- Allow only explicit `http` and `https` schemes.
- Reject `file`, `ftp`, shell-command, and other non-HTTP schemes.
- Apply connection and total request timeouts.
- Resolve and validate the target address before connecting.
- Reject loopback, link-local, multicast, private network, and Unix-socket targets by default unless the administrator explicitly enables local sources.
- Limit redirects and re-validate the final URL and resolved target address after each redirect.
- Do not let blocklist fetching access local files or Unix sockets.

## Atomic Activation

Ingestion writes durable data first, then publishes runtime state.

- Store the new generation in SQLite in a transaction.
- Activate the generation by updating `active_blocklist_generations` in the same transaction.
- Build a new `PolicySnapshot` from active generations.
- Publish it with an atomic `Arc<PolicySnapshot>` swap.

Queries in flight can finish using the old snapshot. New queries use the new snapshot.

## Scheduling

Start with manual refresh through the admin API. Add scheduled refresh after manual refresh is reliable.

Scheduling requirements:

- Inject a `Scheduler` or clock abstraction for deterministic tests.
- Add jitter so all installations do not refresh at the same instant.
- Bound concurrent source refreshes.
- Report last successful update separately from last attempted update.

## Tests

- Plain domain-list parser.
- Hosts-file parser.
- Comment and blank-line handling.
- Domain normalization and invalid domain rejection.
- Max-size and max-domain guardrails.
- Unsafe source URLs, disallowed schemes, excessive redirects, and local/private-address targets are rejected by default.
- Suspicious empty update keeps previous generation.
- Failed fetch keeps previous generation.
- Atomic activation swaps the policy snapshot only after commit.
- Two concurrent refreshes for one source do not interleave.
- Unsafe source URLs, disallowed schemes, excessive redirects, and local-address redirects are rejected by default.
