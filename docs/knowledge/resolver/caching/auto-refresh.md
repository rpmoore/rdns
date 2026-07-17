---
type: Mechanism
title: Auto-Refresh Popular Domains Before TTL Expiry
description: >
          Proactively refetches popular, near-expiry cache entries in the
          background so a real client query never sees the reactive miss;
          popularity tracking, the trigger formula, and the worker pool
          that executes the refetch.
resource: src/resolver/cache/shard.rs
tags: [cache, dns, resolver, refresh, popularity, worker-pool]
timestamp: 2026-07-16T00:00:00Z
---

The [answer-cache](answer-cache.md) is purely reactive by default: an entry
sits until `expires_at` passes, then the next lookup pays a full backend
round trip. This feature keeps genuinely popular domains "hot" by
refreshing them from the backend just before they expire, without any
fixed or configured list of "popular domains" — popularity is entirely
derived from live, self-decaying state that rides along with the cache's
existing per-domain lifecycle. Ships enabled by default
(`RefreshConfig::enabled`, default `true`); design history and rejected
alternatives: `docs/plans/auto_refresh/`.

# Popularity tracking: per-domain leaky bucket

`PopularityBucket` (`src/resolver/cache/shard.rs:59-124`) is an integer
leaky-bucket counter — `level: u32` + `last_drained: SystemTime` — stored in
a new `ShardState.popularity: HashMap<String, PopularityBucket>` field
(`shard.rs:169,170`), at the same level as `ShardLru`. It's
drained-then-incremented (`PopularityBucket::drain_and_increment`,
`shard.rs:92-111`) on every cache hit, at the same 4 call sites
`state.lru.touch(domain)` already runs inside `Shard::lookup_hop`
(`shard.rs:798,819` for the `Answer`/`CnameHop` branches, via the
shared `ShardState::record_hit_and_check_refresh` helper, `shard.rs:217-240`;
`NoData`/`NxDomain` branches still call `record_popularity_hit` directly,
`shard.rs:188-215`, since negative entries never produce a refresh signal —
see below). Granularity is per-domain (qname only), matching `ShardLru`'s
own granularity — any query for the domain, any record type, raises its
popularity.

Drain arithmetic is integer-only (no floats) to avoid long-uptime rounding
drift, and advances `last_drained` by only the exact time "spent" on
whole leaked units — never resets to `now` — so draining in many small
steps can't systematically under-drain relative to one large step covering
the same elapsed time.

**Lifecycle**: a bucket is created on first hit and removed at exactly the
same two points a domain's `ShardLru` token is removed —
`ShardState::evict_domain` (`shard.rs:178`) and
`ShardState::drop_lru_if_domain_now_empty` (`shard.rs:336`) — so popularity
state can never outlive a domain's cached data through either of those
paths. Accepted gap: `sweep_stale_namespace` clears a domain's LRU token
directly without going through either function, so a bucket can currently
outlive its domain's data when cleared by a namespace sweep instead — the
same tradeoff the LRU itself already has under that path, not something
this feature special-cases.

When `RefreshConfig::enabled` is `false`, the increment call is skipped
entirely at the call site — no `PopularityBucket` is ever allocated, not
merely left untouched.

# Trigger formula: three independent gates

`wants_refresh` (`src/resolver/cache/shard.rs:603-619`) is a pure function
(no I/O, no lock beyond what the caller already holds) checked alongside
the existing `entry.expires_at <= now` liveness check, deciding whether a
live entry should *additionally* signal "this wants a refresh" without
changing what's actually served. All three gates must hold:

1. **Eligibility floor**: `original_ttl >= config.eligibility_floor`
   (default 15s) — entries below this floor are never refresh-eligible at
   all, regardless of remaining TTL or popularity, avoiding refresh thrash
   on very-short-TTL records.
2. **Lead window**: `remaining_ttl <= max(original_ttl * config.lead_ratio,
   config.min_lead)` (defaults 10% / 5s).
3. **Popularity**: the domain's bucket, if present, is hot — `level >=
   hot_threshold`, where `hot_threshold = round(hot_threshold_fraction *
   bucket_capacity)` (default 20% of capacity 10, i.e. 2, against a default
   leak of 1 per 5 minutes — two queries landing within ~5 minutes make a
   domain hot; the original 5-of-10 threshold against a 1-per-minute leak
   required a sustained >1 query/min, which client-side stub caches made
   nearly unreachable, and live counters showed the trigger firing
   approximately never — pinned by
   `shipped_defaults_let_a_two_minute_interval_domain_reach_hot`,
   `src/resolver/cache/shard.rs`). A missing bucket is never hot.

Exception: a hop served under [serve-stale](serve-stale.md) signals a
refresh *unconditionally*, bypassing all three gates
(`ShardState::record_hit_and_check_refresh_maybe_stale`) — stale data was
just served, so the refetch is mandatory, not a popularity-gated
optimization.

Callers pass the bucket *after* recording the current hit
(`ShardState::record_hit_and_check_refresh`, `shard.rs:217-240`), so a
hit's own increment counts toward its own hot-threshold determination —
deterministic (both happen under the same lock, back-to-back), not a race.
**Known feedback-loop caveat**: the auto-refresh worker's own eligibility
recheck (see below) reuses this exact same code path, and therefore also
counts as a hit — a refresh cycle can contribute its own "traffic" toward
staying hot, independent of real client demand. For a domain whose lead
window recurs faster than its bucket's leak rate, this could theoretically
sustain refreshing indefinitely after real demand stops. Not fixed
(the alternative is a side-effect-free recheck path, which would duplicate
`lookup_chain`'s logic) — flagged for anyone debugging why a domain keeps
refreshing after traffic apparently stopped.

`RefreshConfig` (`src/config/mod.rs:480-506`) carries all of these
thresholds plus `worker_count`/`channel_capacity`, following
`CacheConfig`'s three-piece pattern (real struct + `Default` + `RawRefreshConfig`
shadow struct + `validate()`, wired into `RuntimeConfig::validate()`).
`LeakRate` (`config/mod.rs:463-467`) — `units` drained per `per` elapsed
duration — is defined in `config`, not `cache::shard`, specifically because
it must be `pub` to appear on `RefreshConfig`'s public field; `cache::shard`
imports it rather than defining its own copy.

# Signal path: `ChainLookup` and multi-hop hints

`RefreshHint { domain, qtype, qclass }` (`src/resolver/cache/assemble.rs:59-70`)
is one hop's signal that it currently qualifies. `ChainLookup::Answered`
carries `refresh_hints: Vec<RefreshHint>` (`assemble.rs:77`) — **every**
qualifying positive hop in a CNAME chain gets its own hint during
`resolve_from_cache`'s walk (`assemble.rs:147-...`), not just the terminal
hop. This is a load-bearing invariant, not an implementation detail: a
CNAME record is itself a positive RRset with its own independent expiry, so
an intermediate hop can need a refresh even while the terminal hop stays
fresh (and vice versa) — an earlier draft that only checked the terminal
hop was a real bug caught during plan review. A CNAME hop's hint carries
`qtype = CNAME_RECORD_TYPE`, never the original query's qtype, since the
CNAME record set at that hop's domain — not whatever type was originally
queried — is what's actually near expiry.

`ChainLookup::NoData` never carries a hint at all (no field to add one to)
— v1 scope is positive-entries-only; NODATA/NXDOMAIN are negative entries
and never trigger refresh.

`ResolveQuery::probe_cache` and the singleflight-follower path
`cache_hit_after_coalesced_miss` (`src/resolver/mod.rs`) both read
`refresh_hints` off the `ChainLookup` result, but deliberately don't enqueue
them directly — they carry the hints forward instead (`CacheProbe.refresh_hints`,
`CoalescedFollowerHit.refresh_hints`) so the caller enqueues only once the hit
is genuinely admitted. `finish_cache_hit` enqueues (via `enqueue_refresh_job`,
`resolver/mod.rs:5339-...`) only if the response-block policy doesn't block
the hit *and* the query's `recursion_desired` flag is set; `resolve_coalesced_follower`
enqueues only if the block-policy check passes (its `recursion_desired` is
already guaranteed `true` by control flow — a real miss coalescing only
happens past the RD=0 refusal check). Review found the original, simpler
design (enqueue directly inside `probe_cache`/`cache_hit_after_coalesced_miss`)
could trigger a real background backend fetch for a query the rest of the
pipeline hadn't admitted yet: an RD=0 cache-only query, or a hit about to be
rejected by response policy. `enqueue_refresh_job` itself
(`resolver/mod.rs:5339-...`) is unchanged — a non-blocking `try_send` onto the
worker pool's channel. `RefreshTriggered`/`RefreshQueueFull` metrics
(`resolver/mod.rs:8748,8753`) record success/drop; a dropped trigger has no
correctness impact, the entry just expires normally.

# Worker pool: bounded channel, per-job panic isolation

`spawn_refresh_worker_pool` (`src/resolver/mod.rs:3606-3620`) spawns a fixed
pool of `RefreshConfig.worker_count` tasks sharing one bounded
`tokio::sync::mpsc::Receiver<RefreshJob>`, wrapped in
`Arc<tokio::sync::Mutex<_>>` since `Receiver` is single-consumer — this
serializes only the dequeue point (one worker parks on `recv()` at a time),
not job *execution*. Each dequeued job (`refresh_worker_loop`,
`resolver/mod.rs:3646-3672`) is spawned as its own `tokio::spawn`ed task,
and the worker `.await`s that task's `JoinHandle` before dequeuing the
next job: a panic in one job fails only its own `JoinHandle` (inspected via
`JoinError::is_panic()` and logged via `tracing::error!`), never the worker
loop itself — deliberately not `futures::FutureExt::catch_unwind`, since
this codebase adds dependencies conservatively and already has no
`futures` crate dependency.

**Shutdown has no internal signal** — `main.rs` holds the pool's
`JoinHandle`s and `.abort()`s them at teardown (`main.rs:324-327`),
mirroring `spawn_sighup_reload_task`'s existing convention exactly: no
`select!`, no shutdown channel, the loops just run until aborted from
outside. Aborting the outer loop task while a job's inner spawned task is
in flight only cancels the *outer* future by itself — review found this
could leave the inner job task detached, still holding its own
`Arc<ResolveQuery>` clone, which could prevent `drop(resolver)` from
happening and hang shutdown's `event_drain.await`. Fixed via `AbortOnDrop`
(`resolver/mod.rs:3676-3682`): `refresh_worker_loop` holds an `AbortHandle`
for the just-spawned inner job task in a guard tied to its own stack frame,
so aborting the outer task drops that guard too — wherever the outer
future happened to be parked, including mid-`handle.await` — which reliably
requests cancellation of the inner job task as well.

`main.rs` creates the channel *before* building the resolver
(`main.rs:132`), threads the sender in via `.with_refresh_config(...)` /
`.with_refresh_sender(...)` on the `ResolveQuery` builder chain, and gates
both the sender wiring and the pool spawn on `config.refresh.enabled`
(`main.rs:152-173`): when disabled, no worker tasks are spawned at all —
not merely idle ones.

# Job processing: epoch-first recheck, DO=true fetch, store-before-complete

`process_refresh_job` (`resolver/mod.rs:3807-...`) does, per dequeued job:

1. **Capture epoch once**: `BackendHandle::current()` is read exactly once
   at the top and reused for every subsequent step — never re-read
   mid-job, the same discipline every other store path in this codebase
   follows (see [cache-epoch](cache-epoch.md)).
2. **Re-check eligibility** by calling the same `lookup_chain` path a real
   query uses, with the captured epoch and `dnssec_ok = false` (not
   `true` — see below), confirming the re-probed hints still contain this
   exact `(domain, qtype, qclass)`. A stale epoch from a reload that
   happened while the job sat in the channel surfaces here as an ordinary
   miss, since `lookup_hop` already treats an epoch mismatch as invisible —
   no separate epoch check is needed.
3. **Fetch via `ShardedSingleFlight`** (`MissKey = (domain, qtype, qclass,
   epoch, dnssec_ok=true)`) using a `build_refresh_query` production helper
   (`resolver/mod.rs:3752-...`) to build a synthetic outbound query. Fetches
   always use `dnssec_ok = true` — a refresh always upgrades to a
   DNSSEC-complete fetch, regardless of the original entry's own DNSSEC
   state. The query's EDNS UDP payload size is the operator's own
   `configured_max_udp_payload_size()` (not a fixed constant — review found
   a hard-coded 1232 bytes could truncate/fail a large DNSSEC refresh
   response for an operator who configured a bigger buffer, since only
   `ResolutionMode::Recursive` backend calls get their EDNS size rewritten
   downstream by `resolve_backend`; `ResolutionMode::Forward` sends whatever
   `build_refresh_query` encoded, verbatim). **Coalescing caveat**: because
   `MissKey` includes `dnssec_ok`, this only coalesces with a concurrent
   client request that itself has `dnssec_ok = true` — a DO=false client
   miss for the same key becomes its own independent singleflight `Leader`,
   paying its own round trip. No correctness impact, just narrower
   coalescing than "any concurrent miss."
4. **Store before completing the singleflight flight** via
   `store_cache_response`, deliberately bypassing `prepare_backend_result`'s
   policy-block, response-rewrite, and chaos-injection layers (none apply to
   a server-internal refresh) — but *does* check
   `ResolutionCacheDirective::is_cacheable()` first, same as
   `prepare_backend_result` does, so a backend-declared "do not cache this"
   signal is still honored. If this job is the singleflight `Leader`,
   `SingleFlightLeader::complete` — which wakes any waiting follower — is
   called *after* the store, not before, on every exit path (cacheable
   success, `DoNotCache`, invalid response, or fetch error). Review found
   the original leader-completes-then-stores ordering (matching the naive
   reading of `resolve_backend`'s result) could wake a follower before this
   job's own store landed; the follower re-probes the cache immediately on
   waking (`cache_hit_after_coalesced_miss`), and could still see the stale
   entry, miss, and fall back to this job's raw synthetic backend result —
   which in forward mode only has its ID/RD/CD rewritten for the real
   client, not reframed with that client's own question/OPT. Storing first
   mirrors `resolve_coalesced_leader`'s own store-then-complete ordering.
5. **No retry on any failure** (timeout, backend error, an uncacheable or
   unparseable response) — the stale entry is simply left untouched and
   falls back to ordinary reactive-miss behavior at its real expiry.
   Best-effort by design, naturally bounded by the worker pool's fixed
   size and channel capacity, not a backoff mechanism.

Why the recheck uses `dnssec_ok = false` while the fetch always uses
`true`: `Shard::take_live_positive`/`take_live_cname_hop` treat any entry
with `dnssec_complete = false` as invisible to a `dnssec_ok = true` reader.
Since the recheck's only job is confirming "still live, in-window, hot" —
independent of DNSSEC completeness — using `true` there would permanently
exclude every domain whose cached answer originated from a DO=false query,
silently defeating refresh for that entire class of domain forever.

# Metrics

`ResolverMetric::RefreshTriggered`/`RefreshQueueFull`/`RefreshSucceeded`/
`RefreshFailed` (`resolver/mod.rs:8748-8758`), following existing
`CacheHit`/`CacheMiss`-style naming. `OpenTelemetryMetrics` in `main.rs`
exposes each as its own Prometheus counter (`refresh_triggered_total`,
etc.) — `ResolverMetric` and `OpenTelemetryMetrics::increment` are both
exhaustive matches, so new variants force new counter wiring at compile
time.

# See also

- [answer-cache](answer-cache.md) — the base cache structure this feature extends.
- [sharding](sharding.md) — popularity is tracked per-shard, per-domain, at the same routing
  granularity as everything else in the cache.
- [cache-epoch](cache-epoch.md) — the epoch-recheck-before-fetch step depends directly on this
  invalidation mechanism.
