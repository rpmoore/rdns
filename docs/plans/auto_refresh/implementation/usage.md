# Usage Guide: Auto-Refresh Popular Domains Before TTL Expiry

## Quick Start

Ships **enabled by default** — no config change needed to use it. To tune or
disable it, add a `[refresh]` table to your `config.toml`:

```toml
[refresh]
enabled = true              # default: true. Set false to fully disable
                             # (no popularity tracking, no worker pool spawned).
bucket_capacity = 10        # default: 10. Max popularity level per domain.
leak_rate_units = 1         # default: 1. Leaked units...
leak_rate_per_ms = 60000    # default: 60000 (60s). ...per this many ms.
hit_increment = 1           # default: 1. Level added per cache hit.
hot_threshold_fraction = 0.5 # default: 0.5. Fraction of bucket_capacity
                             # that counts as "hot" (rounds to nearest u32).
lead_ratio = 0.10           # default: 0.10. Refresh window = max(
                             #   original_ttl * lead_ratio, min_lead).
min_lead_ms = 5000          # default: 5000 (5s).
eligibility_floor_ms = 15000 # default: 15000 (15s). Entries with a smaller
                             # original TTL are never refresh-eligible.
worker_count = 4            # default: 4. Background worker tasks.
channel_capacity = 256      # default: 256. Bounded job queue depth.
```

All fields are optional and independently defaulted — a `[refresh]` table
with just `enabled = false` is valid and disables the whole feature.

## What it does

A DNS answer normally sits in the cache until `expires_at` passes, then the
next lookup pays a full backend round trip. This feature tracks per-domain
popularity (an integer leaky bucket, incremented on every cache hit) and,
for domains that are both **popular** ("hot": bucket level over
`hot_threshold_fraction * bucket_capacity`) and **near expiry** (inside the
`lead_ratio`/`min_lead` window), enqueues a background job that refetches
the answer from the upstream backend and stores it — before any real client
sees a miss.

- **Eligibility floor** (`eligibility_floor_ms`): entries with an original
  TTL below this are never refresh-eligible at all — prevents refresh
  thrash on very-short-TTL records.
- **No client-facing latency impact**: refresh happens entirely in the
  background worker pool; a query that triggers a refresh hint is still
  answered from cache with normal cache-hit latency.
- **Best-effort**: a failed refresh (timeout, backend error, an uncacheable
  response) simply leaves the stale entry to expire and fall back to
  ordinary reactive-miss behavior — no retry.

## Verifying it's working

Four Prometheus counters are exposed on the metrics endpoint
(`config.metrics.listen`, when `config.metrics.enabled = true`):

- `refresh_triggered_total` — a refresh job was successfully enqueued.
- `refresh_queue_full_total` — a hint was dropped because the worker
  queue (`channel_capacity`) was full; harmless, the entry just expires
  normally.
- `refresh_succeeded_total` — a background refresh completed and stored.
- `refresh_failed_total` — a background refresh attempt failed (any
  reason: eligibility recheck miss, fetch error, uncacheable response).

```bash
curl -s http://<metrics-listen-addr>/metrics | grep refresh_
```

To disable and confirm it's a true no-op, set `enabled = false` and restart:
no `PopularityBucket` is ever allocated and no worker tasks are spawned —
verified by `refresh_workers_not_spawned_when_disabled` (`src/main.rs`) and
`section-01`/`section-03`'s no-op tests at the popularity/trigger level.

## Example Output

```
$ curl -s http://127.0.0.1:9090/metrics | grep refresh_
# HELP refresh_triggered_total ...
refresh_triggered_total 42
refresh_queue_full_total 0
refresh_succeeded_total 40
refresh_failed_total 2
```

## API Reference (internal, for anyone extending this feature)

- `rdns::config::RefreshConfig` (`src/config/mod.rs:480`) — the validated
  runtime config struct; `RuntimeConfig::refresh: RefreshConfig`.
- `rdns::resolver::RefreshJob` (`src/resolver/mod.rs:3575`) — one enqueued
  refresh unit: `(domain, qtype, qclass)`.
- `rdns::resolver::spawn_refresh_worker_pool` (`src/resolver/mod.rs:3593`) —
  spawns the fixed worker pool; called from `main.rs` gated on
  `config.refresh.enabled`.
- `ResolverMetric::RefreshTriggered` / `RefreshQueueFull` /
  `RefreshSucceeded` / `RefreshFailed` (`src/resolver/mod.rs:8624-8639`).

Full behavioral documentation, including the trigger formula, the
`ChainLookup`/multi-hop hint invariant, and the epoch-recheck-before-fetch
design: `docs/knowledge/resolver/caching/auto-refresh.md`. Design history
and rejected alternatives: `docs/plans/auto_refresh/`.
