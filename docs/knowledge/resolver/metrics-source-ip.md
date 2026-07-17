---
type: System
title: Per-Query Metrics and the source_ip Label
description: >
          Which resolver metrics carry a source_ip label identifying the
          requesting client, how the label flows from ResolveRequest to
          the Prometheus exposition, and why some metric families are
          deliberately unlabeled.
resource: src/resolver/mod.rs
tags: [dns, resolver, metrics, observability, prometheus]
timestamp: 2026-07-17T00:00:00Z
---

Per-client-query metrics are labeled with the requesting client's source
IP (`source_ip`), so operators can attribute traffic, blocks, cache
behavior, and latency to where queries come from. The label value is
`ResolveRequest::client_ip` (`src/resolver/mod.rs:174`) — the transport
peer address the delivery layer captured, not anything read from the
query payload.

# The sink contract

`MetricsSink` (`src/resolver/mod.rs:8924`) has two emission tiers:

* `increment` / `observe_duration` — unlabeled, used for metrics emitted
  from background or shared work.
* `increment_with_source` / `observe_duration_with_source`
  (`src/resolver/mod.rs:8943`) — per-query variants carrying the client
  IP. Both have default impls that discard the IP and delegate to the
  unlabeled methods, so sinks that don't label by source (the Noop
  sinks, test recorders) need no changes.

**Invariant: each metric family is consistently labeled or consistently
not.** The resolver calls the `*_with_source` variant for every emission
of a labeled family and the plain variant for every emission of an
unlabeled one — never a mix, so a Prometheus family never has some
series with `source_ip` and some without.

# Which families are labeled

Labeled (every emission has a real client request in scope):
`QueryReceived`, `QueryAllowed`, `QueryBlocked`, `ProtocolError`,
`RecursionRefused`, `CacheHit`, `CacheNegativeHit`, `CacheStaleHit`,
`CacheResponseTruncated`, `CacheMiss`, `CacheBypass`,
`CacheCoalescedMiss`, `UpstreamSuccess`, `UpstreamFailure`, and the
duration histograms `QueryDuration`, `CacheHitQueryDuration`,
`CacheMissQueryDuration` (emitted in `finish`,
`src/resolver/mod.rs:6143`). Cache-hit counters funnel through
`record_cache_hit_metrics`, which takes the client IP as a parameter
(`src/resolver/mod.rs:5407`).

Unlabeled, deliberately:

* `CacheStore` / `CacheNegativeStore` / `CacheStoreSkipped` —
  `store_cache_response` (`src/resolver/mod.rs:6073`) is shared with the
  auto-refresh worker, which calls it with a synthetic request whose
  client IP is `0.0.0.0` (`src/resolver/mod.rs:4006`). Labeling would
  either split the family or attribute refresh stores to a fake client.
* `RefreshTriggered` / `RefreshQueueFull` / `RefreshSucceeded` /
  `RefreshFailed` — background cache maintenance, not client actions,
  even though a client's hit is what enqueues the job.
* `QueryEventAccepted`..`QueryEventSampled` — event-queue accounting.
* `Recursive*` metrics and `RecursiveQueryDuration` — emitted deep in
  `RecursiveResolutionBackend` (`src/resolver/mod.rs:8161`), which has
  no client context (and one recursion can serve coalesced queries from
  several clients).
* Gauges (`backend_generation`, `cache_size`, …) — process state.

# The Prometheus sink

`OpenTelemetryMetrics` in `src/main.rs` maps each `ResolverMetric` to
its instrument via `counter_for`/`histogram_for` (`src/main.rs:1050`);
the labeled variants attach `source_ip_attributes`
(`src/main.rs:1125`), producing series like
`query_received_total{source_ip="192.168.1.50"}`.

# Cardinality caveat

One time series per distinct client IP per labeled metric, and source
addresses of UDP queries are spoofable — so exposure to untrusted /
internet-scale client populations can grow the registry without bound.
Accepted for rdns's target deployment (LAN-scale resolver with a known
client population); revisit (hash, allowlist, or top-N the label) if
that changes.

# Tests

* `per_query_metrics_carry_client_source_ip` (resolver tests) — resolves
  a query and asserts the per-query metrics arrive via the labeled path
  with the client's IP, and never with any other IP.
* `open_telemetry_source_variants_label_series_by_source_ip` (main.rs
  tests) — asserts the Prometheus registry splits series by `source_ip`
  for counters and histograms.
