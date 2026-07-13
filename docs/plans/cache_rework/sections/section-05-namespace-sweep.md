# section-05-namespace-sweep: Bulk invalidation via explicit namespace sweep

## Dependencies

This section depends on **section-03-shard-and-lru** already existing:
specifically `Shard`/`ShardState` (combining `PositiveShardState` and
`NegativeShardState` behind one lock per shard) and `ShardLru` (with
`touch`, `remove`, `peek_oldest`). This section does not redefine those
types — it only adds a new function, `sweep_stale_namespace`, that walks
them.

This section also depends on section-02-data-model's `DomainRecordSets`
(`record_sets: HashMap<(u16, u16), RRsetEntry>`) and
`DomainNegativeEntries` (`entries: HashMap<NegativeKey, NegativeEntry>`),
and on both `RRsetEntry` and `NegativeEntry` having a `cache_namespace:
String` field.

This section does **not** wire the sweep into the SIGHUP reload path
(`Config::backend_cache_namespace` / `main.rs`'s `resolver.publish_reload(...)`
call, or the `DomainDnsCache::sweep_stale_namespace` trait method) — that
wiring is section-07-call-site-migration's job. This section is
implementable and fully testable in isolation against hand-constructed
shard state.

**File to create:** `src/resolver/cache/namespace.rs` (per the module
layout in `claude-plan.md` §10).

## Background

### Why an explicit sweep is needed at all

Today (`docs/caching.md` §2), `cache_namespace` is baked directly into the
flat `CacheKey`. When a SIGHUP reload changes the namespace (any
backend-affecting config change recomputes it), every old entry becomes
instantly unreachable "for free" — the lookup key itself changes, so old
entries are simply never matched again. The cost of this trick is orphaned
capacity sitting in the cache until eviction or expiry eventually reclaims
it (this is gaps G4/G5 from `docs/caching.md`).

Under this rework, the cache key is just the domain name — there is no
namespace component left in the key (see section-01/section-02 for the
new key shape) — so the "key changes, old entries become unreachable"
trick no longer applies. Every `RRsetEntry` and `NegativeEntry` instead
*stores* its own `cache_namespace: String` value (set at store time), and
this section's job is to actively walk the cache and remove anything
whose stored `cache_namespace` no longer matches the current one.

### When it runs

Once, after a new `BackendSnapshot` is published — the same SIGHUP-reload
trigger point that recomputes `cache_namespace` today (see
`main.rs`'s `resolver.publish_reload(...)` call and
`Config::backend_cache_namespace` in `src/config/mod.rs`). It is not
called on the request path and not called per-lookup. (Wiring this trigger
is section-07's responsibility; this section only needs to make the sweep
function itself correct and independently testable.)

### Why this is the one deliberate O(n) operation in the whole design

Every other cache operation in this rework (touch, evict, chain lookup) is
O(log n) or better *per shard* (section-03, section-04, section-06). The
namespace sweep is the sole exception, by design: it must inspect every
cached record set and every negative entry individually, because a single
domain can hold record sets stored at different times — some possibly
still current, some stale — and only a full per-entry check can tell them
apart. Here "n" is the total number of cached *entries* (RRsets +
negative entries) across all shards, not the number of domains. This
matches the spec's goal 2 target: the design has exactly one intentional
O(n) operation, and it only runs once per reload, not once per request.

### Lock discipline: no global lock across shards

Each shard's sweep takes **that shard's own lock** for the duration of
its own scan only. Sweeping shard 0 does not require holding shard 1's
lock, or any single lock shared across all shards. This means a
reload-triggered sweep does not reintroduce the single-lock contention
this whole rework exists to remove — concurrent requests hitting shards
that have already been swept, or haven't yet been swept, proceed
normally. Whether shards are swept sequentially or concurrently
(e.g. one thread/task per shard) is an implementation detail left to the
implementer; concurrent is preferable since shards are already
independent, but sequential is acceptable if it simplifies the initial
implementation — neither choice affects correctness, only wall-clock time
of the sweep itself.

## Function to implement

```rust
/// Called once, after a new BackendSnapshot is published (the same
/// SIGHUP-reload trigger point that recomputes cache_namespace today —
/// see main.rs's resolver.publish_reload(...) call and
/// Config::backend_cache_namespace in src/config/mod.rs). Walks every
/// shard and every record-set/negative-entry within each domain, removing
/// any entry whose stored cache_namespace no longer matches. A domain that
/// loses all of its record sets and its negative entry is also removed
/// from that shard's LRU.
///
/// This is the one deliberate O(n) operation in the design — n is the
/// total number of cached *entries* (RRsets + negative entries) across
/// all shards, not the number of domains: a domain can hold many record
/// sets, and the sweep must inspect each one's stored namespace
/// individually (they may have been cached at different times, some
/// possibly still current). It runs once per reload, not once per
/// request, and pays the cost immediately instead of leaving orphaned
/// capacity behind.
fn sweep_stale_namespace(cache: &ShardedDnsCache, current_namespace: &str) { ... }
```

`ShardedDnsCache` here is whatever top-level container section-03
establishes holding all shards (e.g. a `Vec<Shard>` or similar) — the
exact field/method names for accessing an individual shard's lock and
state are section-03's implementation choice; this function needs to
iterate all shards and, for each one, take that shard's lock for the
duration of its own scan (not a shared/global lock).

### Algorithm, per shard

For each shard, while holding only that shard's lock:

1. **Positive side**: for each domain in `PositiveShardState.domains`,
   for each `(qtype, qclass) -> RRsetEntry` in that domain's
   `DomainRecordSets.record_sets`, remove the entry if
   `entry.cache_namespace != current_namespace`. If this empties the
   domain's `record_sets` map, remove the domain from
   `PositiveShardState.domains` entirely (don't leave an empty-shell
   `DomainRecordSets` behind).
2. **Negative side**: identical treatment for
   `NegativeShardState.domains` — for each domain, for each
   `NegativeKey -> NegativeEntry` in `DomainNegativeEntries.entries`,
   remove the entry if its `cache_namespace` doesn't match; remove the
   domain from `NegativeShardState.domains` if this empties its
   `entries` map.
3. **LRU cleanup**: for any domain that, after steps 1-2, has *no*
   remaining entry in either `PositiveShardState.domains` or
   `NegativeShardState.domains`, call `ShardLru::remove` for that
   domain so no stale LRU token is left behind (mirrors the eviction
   path in section-03: a domain's LRU token exists iff it has data in
   at least one of the two maps).
4. A domain with data remaining in *either* map after the sweep (e.g.
   one current-namespace `RRsetEntry` survives alongside a removed
   stale one) keeps its LRU position untouched — the sweep only removes
   LRU tokens for domains that end up with **zero** remaining entries of
   either kind.

## Tests to write first

All of these belong in `cache/namespace.rs`'s `#[cfg(test)] mod tests`
block, built directly against section-03's `Shard`/`ShardState` and
section-02's entry types with hand-constructed state (no resolver/backend
involved):

- **`sweep_removes_only_entries_from_stale_namespace`** — set up a shard
  holding a mix of entries stored under an old namespace and entries
  stored under the current namespace. After
  `sweep_stale_namespace(cache, current_namespace)`, assert only the
  stale-namespace entries are gone; current-namespace entries, and their
  LRU positions, are untouched.

- **`sweep_removes_domain_entirely_when_all_its_record_sets_are_stale`** —
  a domain whose *every* `RRsetEntry` (and negative entry, if it has one)
  is under the stale namespace. After the sweep, assert the domain is
  fully removed from both `PositiveShardState.domains` and
  `NegativeShardState.domains` (not left behind as an empty shell with an
  empty `record_sets`/`entries` map), and is removed from `ShardLru` too.

- **`sweep_keeps_domain_partially_when_some_record_sets_are_current`** —
  a domain with one stale-namespace `RRsetEntry` and one
  current-namespace `RRsetEntry` (e.g. an A record cached under the old
  namespace, an AAAA record cached under the current one). After the
  sweep, assert only the stale `RRsetEntry` is gone; the domain entry
  itself and its `ShardLru` position survive. This is the case that makes
  the sweep genuinely O(entries) rather than O(domains) — a domain can't
  be judged stale or current as a single unit, each record set must be
  checked individually.

- **`sweep_across_shards_does_not_require_a_shared_lock`** —
  concurrency test: sweep multiple shards concurrently from separate
  threads/tasks (each calling into the per-shard portion of the sweep, or
  the whole `sweep_stale_namespace` call itself if shards are swept
  concurrently internally) and assert it completes correctly without
  deadlocking. Each shard's sweep should only ever take that shard's own
  lock — verify this either by running the sweep alongside concurrent,
  unrelated lookups against *other* shards and confirming those aren't
  blocked, or by structural inspection if the implementation makes shard
  independence obvious (e.g. no lock is held across the loop over
  shards).

Also worth covering directly (not explicitly named in the TDD stub list
but implied by the algorithm above, and cheap to add while writing these):
a domain with only a negative entry (no positive record sets) that goes
stale is removed the same way a positive-only domain is — exercises the
same "capacity/LRU counts domains uniformly across positive and negative"
invariant from section-03 in the sweep's own removal path, not just in
eviction.

## Notes for the implementer

- Do not special-case "domain has only a negative entry" or "domain has
  only positive entries" differently in the sweep logic — the same
  "check each entry's namespace individually, then remove the domain if
  both maps end up empty" algorithm applies uniformly regardless of
  which combination of positive/negative data a domain started with.
- This function's return type/error handling is not prescribed — plan
  says `fn sweep_stale_namespace(cache: &ShardedDnsCache, current_namespace: &str)`
  with no return value; that's a reasonable signature to implement
  literally, but returning a count of removed entries (for logging/metrics
  in section-07's wiring, if useful) is a reasonable deviation if it helps
  testing (e.g. asserting "N entries removed" directly rather than only
  asserting "these specific entries are gone").
- Do not implement or reference the reload-trigger wiring
  (`Config::backend_cache_namespace`, `main.rs`'s `publish_reload`, or the
  `DomainDnsCache::sweep_stale_namespace` trait method) in this section —
  those exist in section-07-call-site-migration and will call this
  function once it exists.

## Implementation notes (actual vs. planned)

- **Files**: `src/resolver/cache/namespace.rs` (new content, as planned)
  plus a small addition to `src/resolver/cache/shard.rs` — not originally
  listed as touched by this section, but required: `Shard`'s internal
  state (`ShardState`, `PositiveShardState`, `NegativeShardState`) is
  private to the `shard` module, and `namespace` is a sibling module, not
  a descendant, so it cannot reach into `Shard`'s fields directly. Added
  `Shard::sweep_stale_namespace(&self, current_namespace: &str) -> usize`
  (the actual per-shard scan-and-remove logic, encapsulated where the
  private state already lives) and widened three existing `#[cfg(test)]`
  helpers (`contains_positive`, `contains_negative`, `has_any_data`) from
  private to `pub(crate)` so this section's tests can use them. `namespace::sweep_stale_namespace`
  itself is a thin aggregator: `shards.iter().map(|s| s.sweep_stale_namespace(...)).sum()`.
- **Signature deviation**: takes `shards: &[Shard]` instead of the plan's
  literal `cache: &ShardedDnsCache`. `ShardedDnsCache` is section-06's
  deliverable (built in parallel with this section from the same
  section-03 dependency, per `index.md`'s dependency graph) and does not
  exist at this section's implementation time. Section-07 will call this
  as `sweep_stale_namespace(&cache.shards, ...)` once `ShardedDnsCache`
  exists. Also returns `usize` (entries removed) rather than `()`, per the
  plan's own explicitly-sanctioned deviation for testability/metrics.
- **Test-only additions surfaced by review**: `ShardLru::order_for_test()`
  (`lru.rs`) and `Shard::lru_order_for_test()`/`Shard::hold_lock_for_test()`
  (`shard.rs`), all `#[cfg(test)]`-gated, added so tests could assert
  relative LRU-recency ordering (not just presence/absence) and force real
  cross-shard lock contention respectively.
- **Tests**: all tests from the plan's list implemented, plus one not
  originally listed — `sweep_stale_namespace_walks_every_shard_in_the_slice`
  — added during code review after the reviewer noted every other test
  exercised the sweep against a single-shard slice only, leaving the
  multi-shard aggregation loop itself unverified. Final count: 6 tests in
  `namespace.rs` (5 planned + 1 added), full suite at 439 (up from 438
  after section-04).