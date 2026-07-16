# Implementation Plan: Auto-Refresh Popular Domains Before TTL Expiry

## 1. Overview

`rdns` is a Rust DNS resolver whose cache (`src/resolver/cache/`) is purely
reactive: an entry sits until its `expires_at` passes, and the *next* query for
that name pays a full backend round trip before anything is re-cached. For a
domain queried continuously, this means every single TTL cycle re-pays that
round trip as visible client latency.

This plan adds proactive refresh: when a domain is popular ("hot") and one of
its cached answers is close to expiring, the resolver kicks off a background
refetch that updates the cache *before* the entry actually expires, so a real
client query never sees the miss. Popularity is tracked with a per-domain leaky
bucket that lives and dies with the cache's existing per-domain bookkeeping — no
fixed list of "popular domains," no second data structure to keep in sync.

The feature touches four areas of the codebase:

1. **Cache layer** (`src/resolver/cache/`): popularity tracking and refresh-eligibility
   detection, added to code that already runs on every cache lookup.
2. **Cache-to-resolver boundary** (`src/resolver/cache/assemble.rs`): a new way for
   the cache to tell the resolver "this entry wants a refresh," since today's
   return type has no room for that.
3. **Resolver layer** (`src/resolver/mod.rs`): turning that signal into a
   non-blocking enqueue, and a new background worker pool that performs the
   actual refetch and cache update.
4. **Config and observability** (`src/config/mod.rs`, `ResolverMetric`): a new
   config section and new metrics so operators can tune and monitor the feature.

Ships enabled by default, with a config flag to disable it entirely. All
tunables are operator-overridable.

## 2. Popularity Tracking (Leaky Bucket)

### 2.1 Where it lives

`ShardState` (`src/resolver/cache/shard.rs:73`) currently holds three fields:
`positive`, `negative`, and `lru: ShardLru`. Add a fourth field, a new
per-domain popularity map, living at the same level as `lru`:

```rust
struct ShardState {
    positive: PositiveShardState,
    negative: NegativeShardState,
    lru: ShardLru,
    popularity: HashMap<String, PopularityBucket>,
}
```

`PopularityBucket` is a small plain-data struct: an integer `level` and a
`last_drained: SystemTime`. It is created the first time a domain is stored
(mirroring how `ShardLru`'s position index is created on first store), drained
and incremented on every subsequent lookup hit, and removed at exactly the two
points where a domain's LRU entry is already removed today:
`ShardState::drop_lru_if_domain_now_empty` (`shard.rs:144`) and
`ShardState::evict_domain` (`shard.rs:84`). This reuse of the LRU's own removal
points is what keeps the popularity map from ever drifting out of sync with
which domains actually still have cached data — when a domain's data is gone,
its popularity state is gone in the same operation, not a separate cleanup pass.

Granularity is per-domain (qname only), not per-`(qname, qtype, qclass)` —
matching `ShardLru`'s own granularity. A query for any record type under a
domain raises that domain's popularity; the refresh trigger (§3) still acts on
whichever specific `RRsetEntry` is actually near expiry.

### 2.2 Drain-then-increment

The update on each hit is a pure arithmetic operation, no I/O, no allocation for
domains already tracked:

```rust
impl PopularityBucket {
    /// Drains the bucket by elapsed time since last_drained, then adds one hit.
    /// Uses integer arithmetic throughout (no floats) to avoid long-uptime
    /// rounding drift. `now` must be >= last_drained under normal operation;
    /// a `now` that appears to go backward (clock adjustment) is treated as
    /// zero elapsed time rather than panicking or underflowing.
    fn drain_and_increment(&mut self, now: SystemTime, leak_rate: LeakRate, hit_increment: u32, capacity: u32);

    /// True if level >= hot_threshold (an absolute count derived from
    /// RefreshConfig::hot_threshold_fraction * bucket_capacity).
    fn is_hot(&self, hot_threshold: u32) -> bool;
}
```

`now: SystemTime` is an explicit parameter, matching the existing convention in
this module (`Shard::lookup_hop` and its helpers already take `now: SystemTime`
explicitly rather than relying on an injected clock trait). Do **not** introduce
a `Clock` trait into `cache::shard` — one exists already, but one layer up in
`src/resolver/mod.rs` (`Clock`/`SystemClock`/`FixedClock`), and is not threaded
into cache lookups today. Tests fake time the same way existing shard tests do:
constructing timestamps as explicit offsets (`now - Duration::from_secs(...)`),
not via a mock clock object.

`leak_rate` expresses "how much level drains per unit of elapsed time" — e.g.
the confirmed default of 1 unit per 60 seconds. Implement the elapsed-time-to-
leaked-units conversion so a very small elapsed time (smaller than one drain
unit) doesn't silently truncate to zero drain forever; accumulate fractional
drain progress in a way that integer division can't systematically bias low
(this was flagged directly by research as a known pitfall — cover it with a
unit test that advances the clock in many small sub-unit steps and confirms the
cumulative drain matches one large step of the same total elapsed time).

Wiring: the increment happens inside `Shard::lookup_hop`'s existing lock section,
at the same 4 call sites where `state.lru.touch(domain)` already runs today on a
hit (`shard.rs:426, 436, 448, 459`) — add `state.popularity.entry(domain...).or_insert_with(...).drain_and_increment(...)` immediately alongside each of those.

**Accepted tradeoff — eviction under shard capacity pressure**: a domain
repeatedly evicted from a shard at capacity loses its `PopularityBucket` each
time (§2.1's reuse of the LRU's own removal points means popularity and LRU
state disappear together) and must rebuild popularity from scratch afterward.
This is the same tradeoff the LRU itself already has under capacity pressure —
not something auto-refresh introduces or needs to special-case. An operator who
sees this in practice should increase `max_entries`/shard capacity, not expect
this feature to compensate for an undersized cache.

**Scope note — DNSSEC record shapes**: refresh only concerns whatever
`lookup_hop`'s existing `take_live_positive`/`take_live_cname_hop` probes
already return as a live positive entry — no new handling is needed for
RRSIG-only or other DNSSEC-specific entry shapes beyond what's already cached
there today.

## 3. Refresh Trigger Detection

### 3.1 Eligibility and lead-window formula

Extend the same live-entry probes that already compute `entry.expires_at <= now`
(`take_live_positive`/`take_live_cname_hop`, `shard.rs:163-268`) with a second,
independent check that does not change the returned answer — it only decides
whether to *also* signal "this entry wants a refresh":

1. **Eligibility gate**: the entry's *original* TTL (the TTL value it was stored
   with, not the remaining TTL) must be `>= eligibility_floor` (default 15s).
   Entries below this are never marked hot-refreshable, regardless of popularity
   or how close to expiry they are. This exists specifically to avoid refresh
   thrash on very-short-TTL records — without it, a short-TTL record combined
   with a floor-dominated lead time could mean "always inside the refresh
   window," triggering on nearly every hit.
2. **Lead window**: only entries eligible per (1) are checked against
   `remaining_ttl <= max(original_ttl * lead_ratio, min_lead)` (defaults 10% /
   5s).
3. **Popularity gate**: the domain's `PopularityBucket::is_hot()` must be true.

All three must hold for the signal to fire. This logic is a pure function of
already-available data (the entry's stored TTL/expiry, `now`, and the domain's
bucket level) — no new I/O, no new lock beyond the one already held.

### 3.2 Signal path: extending `ChainLookup`

This is the one piece of the original design that doesn't work as initially
described, found during research: `ResolveQuery::probe_cache`
(`src/resolver/mod.rs:4656`) does not call `Shard::lookup_hop` directly. The
actual call chain is `probe_cache` → `DomainDnsCache::lookup_chain`
(`cache/mod.rs:120`) → `assemble::resolve_from_cache` (`cache/mod.rs:151`) →
`Shard::lookup_hop`, once per CNAME hop. The return type in between,
`ChainLookup` (`cache/assemble.rs:84-95`), today has exactly four variants —
`Answered`, `NxDomain`, `NoData`, `Miss` — with no slot for a side signal.

Add a refresh-hint payload to the variant that represents a live, servable
*positive* answer only. **`NoData` never carries a hint** — in this codebase,
NODATA is stored as a `NegativeEntry`, the same family as NXDOMAIN, and v1 scope
is positive-entries-only (§ interview decision); adding a hint there would
silently contradict that scope:

```rust
pub(crate) struct RefreshHint {
    pub domain: String,
    pub qtype: u16,
    pub qclass: u16,
}

pub(crate) enum ChainLookup {
    Answered { /* existing fields */ refresh_hints: Vec<RefreshHint> },
    NxDomain { /* existing fields */ },
    NoData { /* existing fields, no hint */ },
    Miss,
}
```

**Every positive hop matters, not just the terminal one.** A CNAME record is
itself a positive RRset with its own `expires_at`, stored under its own domain
(e.g. `foo.com` CNAME → `bar.com`, with `bar.com`'s A record as the terminal
hop) — each hop already gets its own popularity increment via `lru.touch`
today, and each has an independent expiry. An earlier version of this plan only
propagated the terminal hop's hint, which would let an intermediate CNAME
record expire uncaught even while the terminal record stays fresh, causing a
visible miss on the *chain* despite the "refresh" appearing to be working.
Fixed design: `resolve_from_cache` collects a hint for *every* hop in the chain
that independently satisfies the eligibility/lead-window/hot checks (§3.1), not
just the last one, and returns them as `refresh_hints: Vec<RefreshHint>` (in
practice usually 0 or 1 entries, occasionally more for a multi-hop hot chain).
`probe_cache` reads this list off the `ChainLookup` result and enqueues one job
per hint (§4.1) — multiple jobs from a single lookup are expected and fine, each
independently subject to the same channel-full-drop behavior.

### 3.3 Re-trigger suppression

No new bookkeeping structure. The worker (§4) re-validates the entry is still
within the lead window immediately before fetching — a job that sat in the
queue during a burst and became stale gets skipped. The actual backend call
always goes through `ShardedSingleFlight`, so duplicate triggers from multiple
queries in the same lead window collapse to at most one backend fetch by
construction. Once a refresh succeeds, `expires_at` moves forward and the entry
falls outside the lead window on the next check — this alone is what stops
further triggers, no explicit "already triggered" flag needed.

## 4. Refresh Execution: Worker Pool

### 4.1 Job enqueue (hot path)

When `probe_cache` sees one or more `refresh_hints` (§3.2 — a single lookup can
produce more than one, for a multi-hop hot CNAME chain), it does a non-blocking
`try_send` per hint onto a bounded `tokio::sync::mpsc::Sender<RefreshJob>`:

```rust
struct RefreshJob {
    domain: String,
    qtype: u16,
    qclass: u16,
}
```

If the channel is full, `try_send` returns immediately with an error; the job is
simply dropped (increment `RefreshQueueFull` metric, see §6) — this is
best-effort by design. A dropped trigger has no correctness impact: the entry
just expires normally and the next real query gets an ordinary reactive miss.
This applies independently per hint, so a multi-hop chain under channel
pressure may get some hops refreshed and others dropped — each hop's outcome is
independent, matching the "best-effort per entry" theme throughout this design.

### 4.2 Worker pool shape

A fixed pool of `worker_count` (default 4) tokio tasks share one bounded
channel. Because `tokio::sync::mpsc::Receiver` is single-consumer, and this plan
avoids adding a new external dependency (per this repo's "add dependencies
conservatively" policy, and since a pure-tokio solution is sufficient), the
`Receiver` is wrapped in `Arc<tokio::sync::Mutex<mpsc::Receiver<RefreshJob>>>`
shared across the `worker_count` loops. This serializes the *dispatch* point
(only one worker parks on `recv()` at a time) but not job *execution* (each
dequeued job runs in its own spawned task, §4.2 below) — an accepted, deliberate
tradeoff given the small fixed pool size; not worth a new dependency (e.g.
`async-channel`'s true MPMC receiver) to remove. Each loop does roughly:

```
loop {
    let job = { let mut rx = receiver.lock().await; rx.recv().await };
    match job {
        Some(job) => {
            let handle = tokio::spawn(process_job(job, /* shared deps */));
            if let Err(join_err) = handle.await {
                // join_err.is_panic() -> log + metric; task panicked, worker continues
            }
        }
        None => break,  // channel closed
    }
}
```

**Panic isolation without a new dependency**: rather than wrapping job
execution in `futures::FutureExt::catch_unwind` (the initial draft's approach —
rejected because this project has no `futures` dependency today, and adding one
just for this would contradict the same "add dependencies conservatively"
reasoning already used to avoid `async-channel`), each worker loop iteration
`tokio::spawn`s the single dequeued job as its own task and awaits that task's
`JoinHandle` before dequeuing the next one. This is simpler than `catch_unwind`
and uses a mechanism this codebase and Tokio already provide natively: a panic
inside `process_job` only fails that one `JoinHandle` (inspect via
`JoinError::is_panic()`), never the worker loop itself, and total concurrency
stays bounded at `worker_count` because a worker never starts job N+1 until job
N's spawned task has finished (successfully or not).

**Shutdown**: matches this codebase's one existing background-task precedent
(`spawn_sighup_reload_task`, `main.rs:579`) exactly — no internal shutdown
`select!`, no shutdown channel. The worker loops run until aborted; at teardown,
`serve_until_shutdown` (`main.rs:209-311`) holds the `JoinHandle`s and calls
`.abort()` on each the same way it already does for the SIGHUP task.

### 4.3 Job processing

For each dequeued job:

1. **Capture epoch first**: read `BackendHandle::current()`
   (`src/resolver/mod.rs:2562`) once, before anything else in this job, and use
   this same snapshot for every subsequent step (never re-read mid-attempt, to
   avoid tearing across a mid-refresh config reload — same discipline every
   other store path in this codebase already follows).
2. **Re-check eligibility against that epoch**: a cheap shard-lock probe
   confirming the entry (a) is still within the lead window, and (b) still
   carries the epoch just captured in step 1. Ordering matters here: a job that
   sat in the channel across a reload could otherwise look "eligible" purely by
   `expires_at` while actually referring to an entry that's already invisible
   under the new epoch (per `cache-epoch.md`, `lookup_hop` itself treats an
   epoch mismatch as a miss) — checking epoch match as part of this recheck, not
   after, is what catches that. A mismatch aborts the job with no further
   action (no metric beyond what step-5-style "no-op" bookkeeping already
   covers).
3. **Fetch via singleflight**: call `ShardedSingleFlight::begin` with the same
   `MissKey` shape production code already uses — `(qname, qtype, qclass,
   cache_epoch, dnssec_ok)`, with `dnssec_ok` always `true` for refresh jobs
   (decided during interview — a refresh always upgrades an entry to a
   DNSSEC-complete fetch, regardless of how the entry being replaced was
   originally fetched).
   - On `Leader`: build the synthetic query (below), call
     `ResolveQuery::resolve_backend`, then `leader.complete(result)`.
   - On `Follower`: `flight.wait().await`.
   - **Coalescing caveat (correcting an overclaim in the initial draft):**
     because `MissKey` includes `dnssec_ok` and refresh jobs always set it
     `true`, this only coalesces with a concurrent *client* request that is
     itself asking with `dnssec_ok = true`. A DO=false client miss landing
     during an in-flight DO=true refresh does **not** coalesce — it becomes its
     own independent `Leader` and pays its own backend round trip. This has no
     correctness impact (both fetches complete and store correctly; the
     DO=false client just doesn't get the "free" latency win this time), but the
     plan's earlier wording ("coalesces for free... and vice versa") overstated
     this — it holds only for same-`dnssec_ok` traffic.
4. **Build the synthetic query**: there is currently no production helper that
   builds a `Message`/`DecodedQuery` from bare `(qname, qtype, qclass,
   dnssec_ok)` — only test-only equivalents exist
   (`query`/`query_with_edns` inside `#[cfg(test)] mod tests`,
   `src/resolver/mod.rs:8154+`). Add one:

   ```rust
   /// Builds a minimal outbound DecodedQuery for a synthetic, server-internal
   /// refresh fetch — not a client-originated query.
   fn build_refresh_query(domain: &str, qtype: u16, qclass: u16, dnssec_ok: bool) -> DecodedQuery;
   ```

5. **Store the result**: on success, call `cache_store_for_response`/
   `store_cache_response` (`src/resolver/mod.rs:5400,5434`) directly —
   deliberately bypassing `prepare_backend_result`'s policy-block checks,
   response rewriting, and chaos-injection layers, none of which apply to a
   server-internal refresh. A minimal `ResolveRequest` is fabricated purely to
   carry a `received_at` timestamp for the store call (the only field of
   `ResolveRequest` that `store_cache_response` actually reads).
6. **On failure** (timeout, SERVFAIL, NXDOMAIN, transport error): no retry.
   Increment `RefreshFailed` and stop — the stale entry is left untouched, and
   the domain simply falls back to normal reactive-miss behavior once it
   actually expires. No backoff or suppression bookkeeping is introduced for
   repeated failures; this keeps the worker path simple and matches the
   "best-effort, no correctness impact on drop/failure" theme running through
   the whole design. **On sustained hot traffic against a failing backend**,
   this can mean repeated failed attempts for the same domain within one lead
   window (each hit re-triggers, since only a *successful* refresh moves
   `expires_at` forward and exits the window) — this is bounded naturally by
   the fixed worker pool size and channel capacity (§4.1/§4.2 already cap total
   concurrent/queued attempts), not by a new backoff mechanism. This was an
   explicit, twice-confirmed scope decision (interview Q3), not an oversight.
7. **On success**: increment `RefreshSucceeded`; the store call naturally moves
   `expires_at` forward, which is what removes the entry from the lead window
   and stops further triggers.

### 4.4 Spawning

The worker task(s) are spawned in `src/main.rs` alongside
`spawn_sighup_reload_task` (`main.rs:579`), following that function's exact
shape: accept an `Arc<ResolveQuery>` (cloned at the call site the same way the
SIGHUP task's `Arc` is), `tokio::spawn` each worker loop, return the
`JoinHandle`s to the caller for later `.abort()`.

## 5. Configuration

Add `RefreshConfig` to `src/config/mod.rs`, following `CacheConfig`'s existing
three-piece shape (`CacheConfig`, `config/mod.rs:341`, is the template):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshConfig {
    pub enabled: bool,
    pub bucket_capacity: u32,
    pub leak_rate: LeakRate,       // e.g. units-per-duration
    pub hit_increment: u32,
    pub hot_threshold_fraction: f32,   // fraction of bucket_capacity
    pub lead_ratio: f32,               // fraction of original TTL
    pub min_lead: Duration,
    pub eligibility_floor: Duration,    // minimum original TTL to be eligible at all
    pub worker_count: usize,
    pub channel_capacity: usize,
}
```

Defaults (confirmed during interview — conservative starting point, may be
tuned further during TDD):

| Field | Default |
|---|---|
| `enabled` | `true` |
| `bucket_capacity` | `10` |
| `leak_rate` | 1 unit / 60s |
| `hit_increment` | `1` |
| `hot_threshold_fraction` | `0.5` |
| `lead_ratio` | `0.10` |
| `min_lead` | `5s` |
| `eligibility_floor` | `15s` |
| `worker_count` | `4` |
| `channel_capacity` | `256` |

Follow `CacheConfig`'s exact deserialization pattern: a `RawRefreshConfig` shadow
struct (`#[derive(Deserialize)] #[serde(deny_unknown_fields)]`, per-field
`#[serde(default = "...")]`), a `try_into_refresh_config(self) -> Result<RefreshConfig, ConfigError>`
conversion, an `Option<RawRefreshConfig>` field on `RawRuntimeConfig` defaulted
via `.unwrap_or_default()` at parse time, and a `validate()` method wired into
`RuntimeConfig::validate()` the same way `self.cache.validate()?` is today.
`validate()` should reject nonsensical combinations (e.g. `hot_threshold_fraction`
outside `0.0..=1.0`, zero `worker_count`, zero `channel_capacity`).

`enabled = false` should make the entire feature a no-op: when disabled, the
popularity-increment call at each `lru.touch` call site is skipped entirely
behind the config check — no `PopularityBucket` is ever allocated (not merely
"untracked"), no worker tasks are spawned, no signal is ever produced. This is
the operator opt-out required by the spec.

**Why default-on is justified despite comparable systems defaulting off**:
Unbound's equivalent feature (`prefetch`) ships off by default, citing ~10%
added traffic — a fair comparison point raised during review. That figure comes
from Unbound's mechanism being a blanket ratio-only trigger applied to *every*
cached record regardless of popularity. This design's qualifying set is
structurally much smaller: an entry must clear the eligibility floor, the
lead-window formula, *and* the popularity threshold — three independent gates,
none of which Unbound's mechanism has except the ratio. Total added backend
load is further hard-capped by the fixed worker pool (`worker_count`) regardless
of how many entries qualify in a given instant. Given that, and that the
default-on choice itself was confirmed twice with the user (initial spec and
interview round 3), it stands — but operators who still want it off have a
single `enabled = false` switch.

## 6. Metrics

Add to `ResolverMetric` (`src/resolver/mod.rs:8110-8151`), matching existing
naming style (`CacheHit`/`CacheMiss`/...):

- `RefreshTriggered` — a hot, near-expiry entry was seen and a job was enqueued.
- `RefreshQueueFull` — a trigger fired but the channel was full; job dropped.
- `RefreshSucceeded` — a worker's refetch completed and the entry was re-stored.
- `RefreshFailed` — a worker's refetch failed for any reason.

**Every `MetricsSink` implementation that exhaustively matches `ResolverMetric`
needs new arms, not just the enum**: `OpenTelemetryMetrics::increment`
(`src/main.rs:963`, confirmed exhaustive by inspection) needs four new match
arms plus four new counter fields; `NoopMetricsSink`
(`src/resolver/mod.rs:8104`) needs the new variants to compile (it likely
ignores the value, but check); test-only `RecordingMetrics` impls
(`src/resolver/mod.rs:9793`, `src/delivery/upstream.rs:1080`) need updating so
existing tests keep compiling.

## 7. Documentation

Per this repo's Knowledge Bundle requirement (`AGENTS.md`), update
`docs/knowledge/resolver/caching/` once implemented. None of the existing docs
(`sharding.md`, `cache-epoch.md`, `answer-cache.md`) currently mention
popularity tracking, refresh workers, or leaky buckets. Add either a new
`docs/knowledge/resolver/caching/auto-refresh.md` concept doc (recommended,
given this introduces real new invariants: bucket lifecycle, trigger formula,
worker-pool shutdown semantics) or a `## Auto-refresh` section on
`answer-cache.md` if it turns out to be small enough — follow existing doc
structure (frontmatter with `type`/`title`/`description`/`resource`/`tags`,
`file:line`-grounded claims), and link it from `docs/knowledge/resolver/caching/index.md`.

## 8. Testing Strategy

- **Popularity bucket unit tests** (near `cache::shard`): fills/drains correctly
  under explicit `now: SystemTime` steps, including many small sub-unit-of-drain
  steps to catch integer-truncation bias; clears when a domain is evicted via
  both `evict_domain` and `drop_lru_if_domain_now_empty`.
- **Trigger-formula unit tests**: fires only when all three gates hold
  (eligibility floor, lead window, hot threshold) and not when any one is
  missing; boundary cases at exactly the lead-window edge and exactly the
  eligibility floor.
- **`ChainLookup` plumbing tests**: every qualifying positive hop in a multi-hop
  CNAME chain produces its own hint (not just the terminal one) — including the
  case where only an intermediate CNAME hop is near-expiry+hot while the
  terminal record is fresh, and the reverse; `NoData` never carries a hint.
- **Resolver-level tests** (`resolver::mod` style, `StaticUpstream`/
  `ScriptedAuthorityTransport` fakes): a triggered refresh updates
  `expires_at` with no client-visible miss; a dropped (channel-full) trigger
  preserves today's reactive-miss behavior exactly; a refresh in flight
  coalesces with a concurrent real client miss on the same key **when both
  share the same `dnssec_ok` value** (explicit test with both sides DO=true);
  and an explicit negative case proving a DO=false client miss does **not**
  coalesce with an in-flight DO=true refresh (both complete independently,
  both store correctly); a failed refresh leaves the stale entry untouched and
  is never retried; a refresh job that sits across a `cache_epoch` bump (config
  reload mid-flight) aborts cleanly at the epoch-recheck step (§4.3) rather
  than storing under a stale epoch.
- **Invariant test for bypassing `prepare_backend_result`**: a refresh-stored
  entry for a given backend response is structurally equivalent (same TTL
  computation, same RRset decomposition) to what the normal client-miss path
  would store for the identical response — proving the skipped policy/rewrite/
  chaos layers don't leave the stored entry in an inconsistent shape.
- **Worker pool tests**: a panicking job doesn't stop the worker loop from
  processing subsequent jobs (verified via the per-job `tokio::spawn` +
  `JoinHandle`/`JoinError::is_panic()` pattern in §4.2, not `catch_unwind`).
- **Config tests**: `RefreshConfig` defaults match the table in §5;
  `validate()` rejects out-of-range values; `enabled = false` produces no
  worker spawn and no `PopularityBucket` allocation at all (not just "untracked").
- **End-to-end**: a fake backend logging query timestamps for a domain queried
  steadily above the hot threshold shows backend re-queries landing near each
  TTL boundary rather than as a client-visible miss; a domain that stops being
  queried stops getting refreshed once its bucket drains below threshold.
- Standard gates before any step is considered done: `cargo fmt`, `cargo
  clippy`, `cargo test` (per `RUST.md`).

## 9. Suggested Implementation Order

1. `PopularityBucket` + `ShardState` field + drain/increment wiring + unit
   tests (self-contained, no cross-module dependency).
2. `RefreshConfig` (config struct, Raw shadow, validation), with config tests —
   moved ahead of trigger-formula logic since that logic reads these
   thresholds directly; building config first avoids rework.
3. Trigger-formula logic (eligibility/lead-window/hot check) as a pure function
   near the existing expiry check in `lookup_hop`, with unit tests, now backed
   by real `RefreshConfig` values from step 2.
4. `ChainLookup`/`RefreshHint` plumbing through `resolve_from_cache`
   (multi-hop-aware — every qualifying positive hop, not just the terminal
   one), with plumbing tests.
5. `RefreshJob`/channel + worker pool skeleton (spawn shape, per-job
   `tokio::spawn`+`JoinHandle` panic isolation per §4.2) + metrics variants and
   all `MetricsSink` impl updates — metrics land here, alongside the skeleton,
   rather than after step 6, since the fetch/store logic in step 6 needs to
   call them directly rather than being retrofitted later. Jobs can no-op
   initially.
6. Synthetic query builder + epoch-first eligibility recheck + singleflight-
   based fetch + store wiring inside a worker job, with resolver-level tests
   (including the epoch-race and DO=true/false coalescing tests from §8).
7. `main.rs` wiring: spawn worker pool alongside SIGHUP task, threaded through
   `enabled` config flag.
8. Knowledge doc updates.
9. End-to-end verification pass.

This order keeps each step independently testable and defers the riskiest,
most cross-cutting piece (worker job's fetch+store logic) until the simpler
supporting pieces (bucket, trigger, config, plumbing) are already in place and
tested.
