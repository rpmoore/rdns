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
`CacheCoalescedMiss`, and the duration histograms `QueryDuration`,
`CacheHitQueryDuration`, `CacheMissQueryDuration` (emitted in `finish`,
`src/resolver/mod.rs:6143`). Cache-hit counters funnel through
`record_cache_hit_metrics`, which takes the client IP as a parameter
(`src/resolver/mod.rs:5407`).

Unlabeled, deliberately:

* `UpstreamSuccess` / `UpstreamFailure` — single-flight coalescing runs
  one backend fetch for concurrent same-key misses, and only the
  race-winning leader's request reaches the increment in
  `prepare_backend_result`; labeling would attribute a shared fetch to
  an arbitrary client (flagged by Codex review on PR #150).
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
its instrument via `counter_for`/`histogram_for`; the labeled variants
fetch their attribute set from `SourceIpLabels`, producing series like
`query_received_total{source_ip="192.168.1.50"}`.

`SourceIpLabels` interns one `Arc`-backed attribute set per distinct
client IP, so the hot path formats an IP once and every later emission
is a refcount bump, not an allocation (per-request allocation concern
from Codex review on PR #150).

# Cardinality bounds

Two guards keep spoofable UDP source addresses from growing the
registry without bound (Codex review, PR #150):

* `[metrics].source_ip_labels = false` (`MetricsConfig`,
  `src/config/mod.rs`) disables the label entirely — per-query
  emissions fold into the unlabeled series. Default `true`.
* `MAX_SOURCE_IP_SERIES` (1024, `src/main.rs`): once that many distinct
  IPs are interned, further IPs share a single `source_ip="other"`
  series and are never inserted into the cache.

Operators exposing rdns beyond a bounded LAN client population should
disable the label or accept the capped worst case (~1025 series per
labeled family).

# Tests

* `per_query_metrics_carry_client_source_ip` (resolver tests) — resolves
  a query and asserts the per-query metrics arrive via the labeled path
  with the client's IP, and never with any other IP.
* `open_telemetry_source_variants_label_series_by_source_ip` (main.rs
  tests) — asserts the Prometheus registry splits series by `source_ip`
  for counters and histograms.
* `source_ip_labels_cap_distinct_ips_and_reuse_interned_attributes` and
  `source_ip_labels_disabled_emits_unlabeled_series` (main.rs tests) —
  pin the cardinality cap/overflow behavior and the config off-switch.
* `metrics_config_source_ip_labels_defaults_on_and_can_be_disabled`
  (config tests) — pins the `[metrics].source_ip_labels` default.
