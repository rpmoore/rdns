# section-04-singleflight

## Summary

Implement the sharded request-coalescing (single-flight) structure that
replaces today's single global-mutex `SingleFlightMisses`. This closes the
second global mutex identified in `docs/caching.md` §6 (the first being the
cache's own lock, addressed by section-03). The new structure keys
in-flight misses by `(name, qtype, qclass)` instead of the full flat
`CacheKey`, and shards its internal map the same way the cache itself is
sharded (hash of the domain name), reusing the `shard_index` utility from
section-01.

This section is **independently testable** — it has no dependency on the
cache data model (section-02/03) or on response assembly (section-06). It
only needs `shard_index`/`CacheConfig` (or an equivalent shard-count
integer) from **section-01-foundation**. It is *not* wired into
`probe_cache`/`resolve_coalesced_*` in this section — that mechanical
rewiring happens in **section-07-call-site-migration**, which depends on
this section (along with section-05 and section-06) being complete first.

## Background: what exists today

The current implementation lives in `src/resolver/mod.rs` and must be
ported (not reinvented) into the new sharded, coarser-keyed shape. Read
this before writing the new code — the leader/follower/notify semantics
below carry over **unchanged in behavior**; only the key type and the
single-map-becomes-many-per-shard-maps aspects change.

Current shape (`src/resolver/mod.rs:3826-3931`):

```rust
#[derive(Default)]
struct SingleFlightMisses {
    flights: Mutex<HashMap<CacheKey, Arc<InFlightMiss>>>,
}

enum SingleFlightTicket {
    Leader {
        key: CacheKey,
        flight: Arc<InFlightMiss>,
    },
    Follower {
        flight: Arc<InFlightMiss>,
    },
}

struct InFlightMiss {
    result: Mutex<Option<Result<ResolutionResponse, ResolutionBackendError>>>,
    notify: Notify,
}

struct SingleFlightLeader {
    coalescer: Arc<SingleFlightMisses>,
    key: CacheKey,
    flight: Arc<InFlightMiss>,
    completed: bool,
}

impl SingleFlightMisses {
    fn begin(&self, key: CacheKey) -> SingleFlightTicket {
        let mut flights = self.flights.lock().unwrap();
        if let Some(flight) = flights.get(&key) {
            return SingleFlightTicket::Follower {
                flight: Arc::clone(flight),
            };
        }
        let flight = Arc::new(InFlightMiss {
            result: Mutex::new(None),
            notify: Notify::new(),
        });
        flights.insert(key.clone(), Arc::clone(&flight));
        SingleFlightTicket::Leader { key, flight }
    }

    fn finish(
        &self,
        key: &CacheKey,
        flight: &Arc<InFlightMiss>,
        result: Result<ResolutionResponse, ResolutionBackendError>,
    ) {
        *flight.result.lock().unwrap() = Some(result);
        let mut flights = self.flights.lock().unwrap();
        if flights
            .get(key)
            .map(|current| Arc::ptr_eq(current, flight))
            .unwrap_or(false)
        {
            flights.remove(key);
        }
        drop(flights);
        flight.notify.notify_waiters();
    }
}

impl SingleFlightLeader {
    fn new(coalescer: Arc<SingleFlightMisses>, key: CacheKey, flight: Arc<InFlightMiss>) -> Self {
        Self {
            coalescer,
            key,
            flight,
            completed: false,
        }
    }

    fn complete(mut self, result: Result<ResolutionResponse, ResolutionBackendError>) {
        self.coalescer.finish(&self.key, &self.flight, result);
        self.completed = true;
    }
}

impl Drop for SingleFlightLeader {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.coalescer.finish(
            &self.key,
            &self.flight,
            Err(ResolutionBackendError::Transport(
                "single-flight leader cancelled".to_string(),
            )),
        );
    }
}

impl InFlightMiss {
    async fn wait(&self) -> Result<ResolutionResponse, ResolutionBackendError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            if let Some(result) = self.result.lock().unwrap().clone() {
                return result;
            }
            notified.await;
        }
    }
}
```

Key semantics to preserve exactly:

- `begin(key)` returns `Leader` (and registers the flight) if no in-flight
  miss exists for `key`; otherwise returns `Follower` cloning the existing
  `Arc<InFlightMiss>`.
- `finish(key, flight, result)` stores the result, removes the map entry
  **only if it still points at this exact `flight`** (an `Arc::ptr_eq`
  check — guards against a stale removal if a newer flight has since
  replaced this key), then wakes all waiters via `notify_waiters()`.
- `SingleFlightLeader` is a guard: calling `.complete(result)` finishes
  normally; if it's dropped without `.complete()` being called (panic,
  early return, cancellation), `Drop` calls `finish()` with a synthetic
  `ResolutionBackendError::Transport("single-flight leader cancelled")` so
  followers never hang forever.
- `InFlightMiss::wait()` loops: register interest in `notify` *before*
  checking the result (to avoid a missed-wakeup race), return the cloned
  result once set, otherwise wait for a notification and re-check.

Existing tests that exercise this today (`src/resolver/mod.rs` around
line 14141-14161) construct a `SingleFlightMisses::default()`, call
`begin(key)` twice (once expecting `Leader`, once expecting `Follower`),
and exercise `SingleFlightLeader`/`Drop` behavior directly — use the same
pattern for the new sharded structure's tests, just routed through
`ShardedSingleFlight` instead of a bare `SingleFlightMisses`.

`ResolutionResponse` and `ResolutionBackendError` are defined in
`src/resolver/mod.rs` (around lines 1507 and 1521 respectively) and are
`pub`; the new module can reference them via
`crate::resolver::{ResolutionResponse, ResolutionBackendError}` (adjust
per actual crate path conventions already used elsewhere in
`src/resolver/cache/`).

## Dependencies

- **section-01-foundation**: provides `shard_index(domain: &str,
  shard_count: usize) -> usize` (the shared hash-routing utility — reuse
  it, do not write a second hashing scheme for single-flight) and the
  module skeleton file `src/resolver/cache/singleflight.rs` (currently
  empty/stubbed). Also provides `CacheConfig`/shard-count plumbing if this
  section needs to accept a shard count at construction time; a plain
  `usize` parameter is sufficient if `CacheConfig` isn't convenient to
  depend on directly — the important part is that whatever shard count is
  chosen for the cache is the same shard count used to construct
  `ShardedSingleFlight`, so the two structures agree on which shard a
  given domain routes to (this wiring/guarantee is section-07's job at the
  call site; this section just needs to accept a shard count as a
  constructor argument).

This section does **not** depend on section-02 (data model) or section-03
(shard/LRU) — it has no knowledge of cached record data, only of
in-flight-miss bookkeeping keyed by `(name, qtype, qclass)`.

## File to create

`src/resolver/cache/singleflight.rs` — new module (skeleton file already
created by section-01; this section fills it in). Per the module layout
in the plan: "mostly moved verbatim from `mod.rs`" — port the
leader/follower/notify logic essentially unchanged, only changing the key
type and adding the shard-routing layer around it.

## Design

### Key change: `CacheKey` → `(String, u16, u16)`

Per interview decision Q5 (plan §6), coalescing granularity moves from
today's full-`CacheKey` (which bakes in exact wire casing and EDNS
bufsize, per `docs/caching.md`) to just `(name, qtype, qclass)`. This is a
direct consequence of casing/bufsize no longer being cache-key dimensions
at all (plan §7, sections 06/07's concern) — coalescing should key on
exactly what the *cache* now keys on for the purposes of "is this the same
query," which is coarser than before. Two requests for the same name+type
that differ only in casing or EDNS bufsize must now coalesce into one
upstream fetch, where previously they would not have.

The domain-name component of the key is assumed **already normalized** by
the caller (lowercased, trailing dot stripped — the same normalization
`QuestionKey`/the cache's `PositiveShardState` uses) before it reaches
`ShardedSingleFlight::begin`. This module does not perform normalization
itself; it is purely a keyed coalescing structure over whatever string key
it's given. (Section-07 is responsible for normalizing before calling in,
matching how the cache's own domain map expects normalized names.)

### Sharded structure

```rust
/// Sharded replacement for today's single-mutex `SingleFlightMisses`.
/// Shard count and routing must match the cache's own sharding so that,
/// in principle, in-flight-miss bookkeeping for a domain and its cached
/// data end up in "parallel" shards — though this structure's lock is
/// intentionally kept separate from the cache shard's lock (see "Why a
/// separate structure" below), so this parallelism is about avoiding
/// unnecessary contention, not about sharing a lock.
pub(crate) struct ShardedSingleFlight {
    shards: Vec<SingleFlightShard>,
}

struct SingleFlightShard {
    flights: Mutex<HashMap<(String, u16, u16), Arc<InFlightMiss>>>,
}

impl ShardedSingleFlight {
    /// `shard_count` must be > 0; construct with the same shard count the
    /// sharded cache itself uses (not enforced here — the caller's
    /// responsibility, per section-07's wiring).
    pub(crate) fn new(shard_count: usize) -> Self { ... }

    /// Routes to `shard_index(&key.0, self.shards.len())` (reusing
    /// section-01's utility) and delegates to that shard's `begin`.
    pub(crate) fn begin(&self, key: (String, u16, u16)) -> SingleFlightTicket { ... }

    /// Routes the same way `begin` does; called by `SingleFlightLeader`'s
    /// `complete`/`Drop` path.
    fn finish(
        &self,
        key: &(String, u16, u16),
        flight: &Arc<InFlightMiss>,
        result: Result<ResolutionResponse, ResolutionBackendError>,
    ) { ... }
}
```

`SingleFlightShard::begin`/`finish` carry the exact same body as today's
`SingleFlightMisses::begin`/`finish` shown above, just with `CacheKey`
replaced by `(String, u16, u16)` and operating on one shard's `flights`
map instead of the single global one.

`InFlightMiss`, `SingleFlightTicket`, and `SingleFlightLeader` keep the
same shape as today (shown above), with `SingleFlightTicket::Leader.key`
and `SingleFlightLeader.key` changing type from `CacheKey` to `(String,
u16, u16)`, and `SingleFlightLeader.coalescer` changing type from
`Arc<SingleFlightMisses>` to `Arc<ShardedSingleFlight>`.

### Why a separate structure from the cache shard's lock

Per plan §6's explicit design note: **do not** merge single-flight
tracking into `ShardState`'s lock (the structure section-03 builds).
Keeping them separate:

- preserves today's separation of concerns — cache storage and in-flight
  miss tracking are independently testable today (two separate mutexes
  per `docs/caching.md` §6), and should stay that way;
- avoids widening the cache-shard critical section to include
  single-flight bookkeeping, which would reintroduce exactly the kind of
  unrelated-work-under-one-lock problem this whole rework exists to
  remove.

This means `ShardedSingleFlight` has its own `shard_count` shards, each
with their own `Mutex`, entirely independent of the cache's own shard
locks — even though, in practice, section-07 will likely construct both
with the same shard count for conceptual symmetry.

## Tests first

Write these before implementing. Place them in a `#[cfg(test)] mod tests`
block in `src/resolver/cache/singleflight.rs`. These are prose stubs —
write the actual `#[test]` functions; names below are required, bodies are
not fully specified.

- **`single_flight_coalesces_concurrent_misses_for_same_name_and_qtype`**
  — replacement for the existing `resolve_coalesces_duplicate_cache_misses`
  test's intent. Spawn N concurrent calls to `ShardedSingleFlight::begin`
  with the *same* `(name, qtype, qclass)` key; assert exactly one returns
  `SingleFlightTicket::Leader` and the remaining N-1 return
  `SingleFlightTicket::Follower`, all sharing the same underlying
  `Arc<InFlightMiss>`. After the leader completes (`SingleFlightLeader::
  complete`), every follower's `InFlightMiss::wait()` resolves to that same
  result.

- **`single_flight_requests_differing_only_in_bufsize_or_casing_still_coalesce`**
  — new test validating the Q5/Q9/Q13 coarsening described above: two
  `begin()` calls for the same normalized name + qtype/qclass — as if
  derived from two requests that differed only in EDNS bufsize or original
  wire casing (this module doesn't see those fields at all, since the key
  is just `(String, u16, u16)`) — produce one `Leader` and one `Follower`
  sharing one flight, i.e. they coalesce. This test is really asserting
  "the key type itself no longer has room for those dimensions," so
  constructing two `begin()` calls with identical `(String, u16, u16)`
  values and asserting coalescence is sufficient; there's no bufsize/casing
  field to vary in this module's own key type.

- **`single_flight_leader_drop_wakes_followers_and_clears_key`** — direct
  port of the existing test of the same name (verify a test of this exact
  name exists today, e.g. near `src/resolver/mod.rs:14141-14161`, and use
  it as the reference for behavior, not literal code). Register a leader
  and at least one follower for the same key; drop the `SingleFlightLeader`
  guard *without* calling `.complete()` (simulating a panicked/cancelled
  leader task); assert the follower's `wait()` resolves to an `Err(
  ResolutionBackendError::Transport(_))` result, and that the shard's
  `flights` map no longer contains an entry for that key afterward (i.e.
  a fresh `begin()` for the same key afterward returns `Leader`, not
  `Follower`).

- **`single_flight_different_shards_do_not_contend`** — concurrency test:
  construct a `ShardedSingleFlight` with multiple shards, pick two domain
  names known to hash to different shards (via `shard_index`), hold one
  shard's flight open (leader not yet completed) on a background
  task/thread, and assert that `begin()`/`finish()` for the other domain's
  key on the other shard proceeds without blocking — e.g. by asserting it
  completes within a short timeout while the first shard's leader is still
  pending. This is the direct verification that per-shard locking actually
  decorrelates unrelated domains' coalescing, closing the second global
  mutex from `docs/caching.md` §6.

## Implementation notes

- Port the leader-drop-wakes-followers `Drop` impl and the missed-wakeup-
  safe `wait()` loop (register `notify.notified()` before checking the
  result, per the current code) unmodified in structure — these are
  subtle correctness properties (this is literally what the ported test
  above verifies) and should not be "improved" or restructured during the
  port.
- `finish`'s `Arc::ptr_eq` guard before removing the map entry must be
  preserved — it protects against removing a *newer* flight that has since
  replaced this key in the shard's map (can happen if a leader's `finish`
  runs unusually late relative to a subsequent `begin`/`finish` cycle for
  the same key).
- Use `shard_index` from section-01 for routing in `begin`/`finish` —
  do not reimplement hashing here. If section-01's `shard_index` signature
  needs a `shard_count: usize` argument, pass `self.shards.len()`.
- Keep `ShardedSingleFlight`, `SingleFlightShard`, `InFlightMiss`,
  `SingleFlightTicket`, and `SingleFlightLeader` all `pub(crate)` (or
  narrower, per whatever visibility convention section-01's module
  skeleton establishes) — none of this needs to be part of the crate's
  public API; only `resolver::cache` (and eventually `resolver::mod` via
  re-export, per section-07) needs to reach these types.
- This section does not touch `src/resolver/mod.rs` at all — the old
  `SingleFlightMisses`/`InFlightMiss`/`SingleFlightTicket`/
  `SingleFlightLeader` definitions there, and their call sites in
  `resolve_coalesced_miss`/`resolve_coalesced_leader`/
  `resolve_coalesced_follower`, stay untouched until section-07 rewires
  them to call into `resolver::cache::singleflight` instead. Leaving both
  the old and new single-flight implementations compiling side-by-side
  until section-07 is expected and fine.