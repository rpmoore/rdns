# Auto-Refresh Popular Domains Before TTL Expiry — Synthesized Spec

This document combines the initial spec (`spec.md`), codebase/web research
(`claude-research.md`), and interview decisions (`claude-interview.md`) into a
single, complete specification for the implementation plan.

## Context

`rdns`'s cache (`src/resolver/cache/`) is a passive, pull-based sharded cache:
entries sit until their `expires_at` (`RRsetEntry`/`NegativeEntry`, `src/resolver/cache/entry.rs`)
passes, then the next lookup for that name finds nothing and pays a full backend
round trip before anything is re-cached (`Shard::lookup_hop`, `src/resolver/cache/shard.rs:405`).
For domains queried repeatedly, that round trip repeats every TTL cycle, on the
client's own dime — the miss becomes visible latency for whoever happens to ask
right after expiry.

The ask: keep genuinely popular domains "hot" by refreshing them from the backend
proactively, at or just before TTL expiry, without maintaining a fixed popular-domain
list (query patterns drift over time) and without adding meaningful overhead or lock
contention to the query hot path.

**Scope for v1 (decided during interview): positive answers only.** `NegativeEntry`
(cached NXDOMAIN/NODATA) near-expiry does not trigger refresh — refreshing a hot
NXDOMAIN just reconfirms it's still NXDOMAIN, lower value than a real answer, and
keeps v1 scope simpler. This can be revisited later without touching the positive
path's design.

## Research: refresh-trigger strategies considered

Four strategies were evaluated against this codebase's existing sharded-lock cache
(one `Mutex` per `Shard`, already taken on every lookup for LRU bookkeeping —
`ShardState`/`Shard::lookup_hop`, `src/resolver/cache/shard.rs:73,405`):

1. **Periodic full-cache scan.** Rejected: cost scales with total cache size, not
   actual popular-domain count.
2. **Background timer wheel** (min-heap of `(expires_at, domain, qtype, qclass)`).
   Rejected: a second data structure that must stay in sync with every insert,
   eviction, and expiry the cache already tracks via `ShardLru`.
3. **Lazy refresh-on-read ("stale-while-revalidate")** — detect "near expiry + hot"
   at the exact point a real query already takes the shard lock, serve the still-valid
   entry immediately, kick a background refetch. Matches Unbound's/BIND's "prefetch
   popular near-expiry names" and CDN stale-while-revalidate behavior.
4. **Dedicated refresh queue/worker** — the actual backend refetch runs off a bounded
   worker pool via a channel, fully decoupled from the request path.

**Recommendation: (3) + (4) combined**, confirmed by research into real-world
precedent (Unbound `prefetch`, BIND9 `prefetch trigger/eligibility`, RFC 5861
`stale-while-revalidate`) — see Design §2 for how those inform the exact trigger
formula.

## Design

### 1. Popularity tracking: per-domain leaky bucket, inside the existing shard lock

Add a per-domain leaky-bucket counter (integer level + last-drained `SystemTime`)
alongside `ShardLru`'s existing `HashMap<String, u64>` position index, as a new
field on `ShardState` (`src/resolver/cache/shard.rs:73`) — same map lifecycle as
the LRU token: created when a domain is first stored, drained lazily on each touch,
removed via the same `drop_lru_if_domain_now_empty`/`evict_domain` paths that
already clear LRU state (`src/resolver/cache/shard.rs:84,144`, confirmed by
research as the two exact places a domain fully disappears from a shard).

Granularity: **per-domain (qname only)**, matching `ShardLru`'s own granularity.

**Drain-then-increment formula** (confirmed against leaky-bucket research —
use integer/fixed-point arithmetic, not floats, to avoid long-uptime rounding
drift; take `now: SystemTime` as an explicit parameter, matching this codebase's
existing cache-layer convention — no new `Clock` trait needed inside `cache::shard`,
since one doesn't exist there today and the resolver-layer `Clock` trait,
`src/resolver/mod.rs:8065-8079`, isn't threaded into cache lookups):

```
elapsed = now.duration_since(last_drained)   // saturating; clock non-monotonicity guarded
leaked  = elapsed_as_leak_units * leak_rate
level   = level.saturating_sub(leaked)
level   = level.saturating_add(hit_increment)
last_drained = now
is_hot = level >= hot_threshold
```

Increment happens inside `Shard::lookup_hop`'s existing lock section, at the same
4 call sites `state.lru.touch(domain)` already runs on a hit
(`src/resolver/cache/shard.rs:426,436,448,459`).

### 2. Trigger: detected at read time, alongside the existing expiry check

`Shard::lookup_hop`'s live-entry probes (`take_live_positive`/`take_live_cname_hop`,
`src/resolver/cache/shard.rs:163-268`) already compute `entry.expires_at <= now` per
lookup. Extend that check: an entry that is live but within a configurable *refresh
lead window* of expiry, **and** whose domain's popularity bucket is hot, **and**
whose *original* TTL clears an eligibility floor, is served normally (unchanged
response) but the lookup additionally signals "this entry wants a refresh."

**Trigger formula** (refined from research: BIND uses a pure floor + separate
eligibility gate on original TTL; Unbound uses a pure ratio; RFC 5861 uses a fixed
window — this design combines a lead-ratio/floor with a distinct eligibility gate,
which research flagged as a reasonable synthesis not exactly matching any single
real system but avoiding BIND's documented "prefetch thrash on short-TTL records"
failure mode):

- Eligible at all only if `original_ttl >= eligibility_floor` (default 15s) — records
  with shorter original TTLs are never marked hot-refreshable, full stop.
- If eligible, triggers when `remaining_ttl <= max(original_ttl * lead_ratio, min_lead)`
  (defaults 10% / 5s) **and** the domain's bucket is hot (`level >= hot_threshold`,
  default 50% of `bucket_capacity`).

**Signal path (resolved during interview — this was an open gap in the initial
spec):** `ResolveQuery::probe_cache` (`src/resolver/mod.rs:4656`) does not call
`Shard::lookup_hop` directly. It calls `self.cache.lookup_chain(...)`
(`DomainDnsCache` trait, `cache/mod.rs:120-129`), which for `ShardedDnsCache`
delegates to `assemble::resolve_from_cache` (`cache/mod.rs:151-172`), which walks
`Shard::lookup_hop` per CNAME hop. `ChainLookup` (`cache/assemble.rs:84-95`) — today
`Answered`/`NxDomain`/`NoData`/`Miss` — must be extended: add a refresh-hint payload
(e.g. `Option<RefreshHint { domain, qtype, qclass }>`, or equivalent) to the
`Answered`/`NoData`-shaped variants that can carry a live positive entry, threaded
through `resolve_from_cache` unchanged in the CNAME-hop-walking logic (only the
terminal hop's hint, if any, propagates), so `probe_cache` receives it alongside the
existing answer/miss data and turns it into the non-blocking enqueue described below.

Re-trigger suppression: no new bookkeeping. The worker re-validates the entry is
still in the lead window immediately before fetching; the actual backend call
always goes through `ShardedSingleFlight`, so duplicate triggers from a burst
collapse to at most one backend fetch. Once a refresh succeeds, `expires_at` moves
forward and the entry falls outside the lead window — self-limiting, same as the
popularity bucket.

### 3. Execution: bounded worker pool, reusing the existing single-flight and store paths

New background task(s), spawned in `main.rs` alongside `spawn_sighup_reload_task`
(`src/main.rs:579`) — the first periodic non-reload background task in the
codebase. **Shutdown (resolved during interview): matches the existing precedent
exactly** — no internal `select!`/shutdown channel; the worker-pool tasks loop
forever reading the job channel and get `.abort()`'d externally at teardown, same
as `sighup_task.abort(); let _ = sighup_task.await;` (`main.rs:301-302`).

- Hot-path trigger (§2) does a non-blocking `try_send` of a small refresh job
  (`domain`, `qtype`, `qclass` — DO flag is not carried, see below) onto a bounded
  `tokio::sync::mpsc` channel. Full channel ⇒ drop the job (best-effort by design;
  a dropped trigger just means normal reactive-miss behavior at true expiry).
- **Worker pool implementation (decided directly, no new dependency per RUST.md
  "add dependencies conservatively"):** a single bounded `mpsc::channel`, its
  `Receiver` wrapped in `Arc<tokio::sync::Mutex<Receiver<Job>>>` shared across
  `worker_count` (default 4) worker loops, each doing
  `let job = { let mut rx = receiver.lock().await; rx.recv().await };` — no new
  external crate (e.g. `async-channel`) needed.
- Each job: re-check the entry is still within the lead window (cheap shard-lock
  probe), then perform the backend refetch and re-store.
- The refetch **must** go through `ShardedSingleFlight`'s existing `MissKey`
  machinery (`src/resolver/cache/singleflight.rs:73`,
  `(qname, qtype, qclass, epoch, dnssec_ok)`) — this is what makes a refresh-in-flight
  coalesce for free with a real client request missing the same key.
- **DNSSEC DO flag (resolved during interview — deviates from the initial spec's
  "preserve whatever DO-fetched state produced the entry" wording):** the refresh
  worker always fetches with `dnssec_ok = true`, regardless of the original entry's
  `RRsetEntry::dnssec_complete` state. A refresh always upgrades the entry to a
  DNSSEC-complete fetch going forward.
- Building the outgoing query requires a new small production helper to construct
  a synthetic `Message`/`DecodedQuery` from `(domain, qtype, qclass, dnssec_ok=true)`
  — research confirmed no such production helper exists today (only test-only
  `query`/`query_with_edns` helpers inside `#[cfg(test)] mod tests`,
  `src/resolver/mod.rs:8154+`).
- Storing the result reuses `ResolveQuery::resolve_backend` (`src/resolver/mod.rs:4575`)
  and the existing decompose/store pipeline (`cache_store_for_response`/
  `store_cache_response`, `src/resolver/mod.rs:5400,5434`) — bypassing
  `prepare_backend_result`'s policy/local-entries/chaos layers entirely (confirmed
  by research: those layers don't apply to and aren't reusable for a
  server-internal refresh). A minimal `ResolveRequest` is fabricated just to carry
  `received_at` for the store call. Epoch sourced from `BackendHandle::current()`
  (`src/resolver/mod.rs:2562`) once per refresh attempt (not read twice, to avoid
  tearing across a mid-refresh reload) — same discipline every other store path
  already follows per `cache-epoch.md`.

**Failure handling (resolved during interview):** on a failed refetch (timeout,
SERVFAIL, NXDOMAIN, transport error) — no retry. Log `RefreshFailed`, leave the
stale entry alone; it expires normally and the next real query gets a standard
reactive miss. No backoff/suppression bookkeeping is introduced.

Worker count and channel capacity are configurable (defaults below).

### 4. Configuration

New `RefreshConfig` struct in `src/config/mod.rs`, following `CacheConfig`'s exact
three-piece shape (`src/config/mod.rs:341` as the pattern): real struct + `Default`
impl + `Raw*` shadow struct (`#[derive(Deserialize)] #[serde(deny_unknown_fields)]`,
per-field `#[serde(default = "...")]`) + `try_into_refresh_config` conversion +
`Option<RawRefreshConfig>` field on `RawRuntimeConfig`, wired into
`RuntimeConfig::validate()` the same way `self.cache.validate()?` is today.

**Fields and confirmed defaults** (interview round 3 — exact numbers may still be
tuned during TDD/implementation, but this is the agreed starting point):

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Ships default-on; disable switch required for operators who want to opt out |
| `bucket_capacity` | `10` | Leaky bucket max level |
| `leak_rate` | `1` per 60s | Drains ~1 hit/minute of idle time |
| `hit_increment` | `1` | Amount added per cache hit |
| `hot_threshold` | 50% of `bucket_capacity` | Level at/above which a domain is "hot" |
| `lead_ratio` | 10% of original TTL | Refresh lead window, ratio component |
| `min_lead` | `5` seconds | Refresh lead window, floor component |
| `eligibility_floor` | `15` seconds original TTL | Below this, a domain is never hot-refreshable |
| `worker_count` | `4` | Fixed worker pool size |
| `channel_capacity` | `256` | Bounded mpsc channel depth |

This is new always-running behavior touching the cache hot path — defaults favor
"barely noticeable" over "aggressive."

### 5. Metrics

New `ResolverMetric` variants (`src/resolver/mod.rs:8110-8151`) following existing
naming style: `RefreshTriggered`, `RefreshQueueFull` (or `RefreshDropped`),
`RefreshSucceeded`, `RefreshFailed`.

**Important, confirmed by research:** `OpenTelemetryMetrics::increment`
(`src/main.rs:963`) is an exhaustive match over `ResolverMetric` — adding these
variants requires new match arms there plus new counter fields on
`OpenTelemetryMetrics`, not just the enum addition. `NoopMetricsSink`
(`src/resolver/mod.rs:8104`) and other `MetricsSink` impls (test-only
`RecordingMetrics` in `resolver/mod.rs:9793` and `delivery/upstream.rs:1080`) also
need updating for exhaustiveness.

## Non-goals

- No fixed/configured list of "popular domains" anywhere — popularity is entirely
  derived from the leaky bucket's live state.
- No change to reactive (on-miss) cache behavior — purely additive; disabling it
  (or a dropped/failed refresh) leaves today's behavior fully intact.
- No new locking primitive — reuses the existing per-shard `Mutex` and
  `ShardedSingleFlight`.
- No refresh of `NegativeEntry` (NXDOMAIN/NODATA) in v1 — positive answers only
  (interview decision).
- DNSSEC validation semantics: refresh always fetches DO=true going forward
  (interview decision — supersedes the initial spec's "preserve original DO state"
  framing).

## Critical files / modules

- `src/resolver/cache/shard.rs` — `ShardState`/`Shard::lookup_hop`: popularity
  bucket storage + drain/increment, refresh-trigger detection.
- `src/resolver/cache/lru.rs` — reference for the per-domain map lifecycle pattern.
- `src/resolver/cache/assemble.rs` — `ChainLookup` (`:84-95`) needs a new
  refresh-hint payload; `resolve_from_cache` (`:151-172`) threads it through.
- `src/resolver/cache/singleflight.rs` — `ShardedSingleFlight`/`MissKey`: reused
  unchanged for refresh-fetch dedup.
- `src/resolver/mod.rs` — `ResolveQuery::probe_cache` (~4656) consumes the trigger
  signal and enqueues; `resolve_backend` (4575), `cache_store_for_response`/
  `store_cache_response` (5400/5434), `BackendHandle::current` (2562) reused for
  fetch+store; new `ResolverMetric` variants (~8111); new synthetic-query-building
  helper (no existing production equivalent — nearest precedent is the test-only
  `query`/`query_with_edns` helpers at `:8168+`).
- `src/main.rs` — `spawn_sighup_reload_task` (579) is the exact shape/shutdown
  pattern (`.abort()`-based, no internal select) the new refresh-worker task(s)
  follow; `OpenTelemetryMetrics::increment` (963) needs new match arms.
- `src/config/mod.rs` — `CacheConfig` (341) is the three-piece pattern
  (struct/Default/Raw shadow/try_into/validate wiring) for `RefreshConfig`.
- `docs/knowledge/resolver/caching/` — `sharding.md`, `cache-epoch.md`,
  `answer-cache.md` to extend once implemented, per `AGENTS.md`'s Knowledge Bundle
  requirement; none currently mention popularity/refresh/leaky-bucket.

## Verification

- Unit tests near the popularity/trigger logic (`cache::shard`) — using explicit
  `now: SystemTime` parameters (matching existing convention, no new `Clock` trait):
  bucket fills/drains correctly (including sub-unit-of-drain elapsed-time steps to
  catch integer truncation), trigger fires only once eligibility floor + lead
  window + hot-threshold all hold, and clears when a domain is evicted.
- `ChainLookup` refresh-hint plumbing tests: a hint set at the terminal hop of a
  CNAME chain propagates correctly to `probe_cache`; non-terminal hops don't leak
  a hint incorrectly.
- Resolver-level tests (`resolver::mod` style, fake upstream/backend via
  `StaticUpstream`/`ScriptedAuthorityTransport`) proving: a triggered refresh
  updates the cache entry's `expires_at` without a client-visible cache miss; a
  dropped (channel-full) trigger leaves existing reactive-miss behavior intact; a
  refresh in flight coalesces with a concurrent real client miss for the same key
  via `ShardedSingleFlight`; a failed refresh leaves the stale entry untouched and
  is not retried.
- Worker pool tests: `catch_unwind`-style panic isolation per job so one bad job
  doesn't kill a worker loop iteration-to-iteration (research-flagged gotcha for
  inline-in-loop job execution vs. Tokio's per-spawned-task isolation).
- End-to-end: run the resolver against a fake backend that logs query timestamps
  for a domain queried steadily above the hot threshold; observe backend re-queries
  landing near each TTL boundary rather than a client-visible miss, and confirm a
  domain that stops being queried stops getting refreshed after its bucket drains.
- `cargo fmt`/`cargo clippy`/`cargo test` gates per `RUST.md`, run before
  considering any implementation step done.
