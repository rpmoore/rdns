## Section 03: Shard state and exact per-shard LRU

### Scope

This section implements the core per-shard storage structure for the
sharded DNS cache: the exact O(log n) LRU (`ShardLru`) and the combined
`Shard`/`ShardState` type that holds one shard's positive cache, negative
cache, and LRU behind a single lock, plus the eviction loop that keeps all
three in sync when a shard reaches capacity.

This is the heart of goals 1 and 2 from the rework: goal 1 (per-shard
locking instead of one global mutex) is realized by `Shard` owning exactly
one lock covering all of a shard's state; goal 2 (exact, non-amortized LRU
with no periodic O(n) compaction) is realized by `ShardLru`.

### Dependencies

- **section-01-foundation**: module skeleton
  (`src/resolver/cache/{mod,shard,lru,entry,singleflight,assemble,namespace}.rs`
  must already exist and compile), the `shard_index(domain, shard_count)
  -> usize` hashing utility, and `CacheConfig` including the exact
  remainder-distributed per-shard capacity split (each shard's capacity is
  `max_entries / shard_count` plus one extra if `shard_index < max_entries
  % shard_count`). This section consumes that per-shard capacity number to
  decide when to evict; it does not recompute it.
- **section-02-data-model**: `RRsetEntry`, `StoredRecord`, `DnssecState`,
  `NegativeEntry`, `NegativeKey`, `DomainRecordSets`,
  `DomainNegativeEntries` (the pure data types this section's maps store).
  This section does not add or change those types — it wraps them in
  shard-level containers and wires them to the LRU.

This section is a dependency for **section-05-namespace-sweep** and
**section-06-assembly-and-chains**, both of which walk/lock the `Shard`
structure defined here. Do not start on those sections' logic here —
this section stops at "a shard with working touch/evict," nothing about
namespace matching or response assembly.

### Background: why one lock per shard covers three things at once

Per the overall design (`claude-plan.md` §2), all data for a given domain
— its positive record sets, its negative-cache entries, and its LRU
recency token — must live in exactly one shard and be mutated together,
atomically, under that shard's single lock. This is not an incidental
implementation choice: capacity is counted **per domain**, uniformly
across positive and negative data (interview Q6), so eviction must be able
to remove a domain's positive map entry, its negative map entry, and its
LRU position as one atomic unit. If these three lived behind separate
locks, a reader could observe a domain present in the LRU but already gone
from the maps (or vice versa) — splitting the maps is fine (keeps negative
semantics clean, per §3.3 of the plan), splitting the *locks* is not.

### Data model recap (from section-02, referenced not redefined here)

```rust
struct PositiveShardState {
    domains: HashMap<String, DomainRecordSets>,
}

struct NegativeShardState {
    domains: HashMap<String, DomainNegativeEntries>,
}
```

`DomainRecordSets` holds a `HashMap<(u16, u16), RRsetEntry>` keyed by
`(qtype, qclass)`; `DomainNegativeEntries` holds a `HashMap<NegativeKey,
NegativeEntry>`. Both are defined in section-02 — this section only adds
the `domains: HashMap<String, _>` layer plus the shared lock and LRU
around them.

## Implementation

### File: `src/resolver/cache/lru.rs`

Exact per-shard LRU, replacing the current ghost-token `VecDeque` design.
Per interview Q1/Q2, this gives O(log n) average-case touch/evict, no
periodic full-scan compaction, and exact (not approximate) ordering within
the shard.

```rust
/// Ordered by (sequence, domain) so the numerically smallest entry is
/// always the least-recently-touched domain in this shard.
struct ShardLru {
    order: BTreeSet<(u64, String)>,
    /// Reverse index: domain -> its current sequence number, so a touch
    /// can find and remove its old position in `order` in O(log n) instead
    /// of scanning.
    positions: HashMap<String, u64>,
    next_sequence: u64,
}

impl ShardLru {
    /// Records that `domain` was just accessed (hit or store). Removes its
    /// old `(sequence, domain)` pair from `order` (O(log n)) if present,
    /// assigns a fresh sequence, and reinserts (O(log n)). Unlike today's
    /// ghost-token design, there is never more than one entry per domain
    /// in `order` — no compaction pass is ever needed.
    fn touch(&mut self, domain: &str) { ... }

    /// Removes `domain` from LRU tracking entirely (used when a domain's
    /// last record set/negative entry is deleted, whether by eviction,
    /// expiry, or the namespace sweep in section-05).
    fn remove(&mut self, domain: &str) { ... }

    /// Returns the least-recently-touched domain without removing it, for
    /// the eviction loop to consult.
    fn peek_oldest(&self) -> Option<&str> { ... }
}
```

Notes for the implementer:
- `touch` must look up any existing sequence for `domain` in `positions`
  first, remove the corresponding `(old_sequence, domain.to_string())`
  pair from `order` if found, then insert the new pair and update
  `positions`. This is what guarantees "never more than one entry per
  domain in `order`."
- `next_sequence` only ever increases; wraparound is not a practical
  concern at `u64` size for this use case and does not need handling.
- `peek_oldest` returns `order.iter().next()`'s domain (the string half of
  the smallest `(u64, String)` tuple), not the whole tuple.

### File: `src/resolver/cache/shard.rs`

`Shard` combines `PositiveShardState`, `NegativeShardState`, and
`ShardLru` behind one lock (`std::sync::Mutex` or equivalent — match
whatever the rest of the codebase's sharded structures use; this is the
implementer's call, not prescribed by the plan). Exact type/field names
are the implementer's call; the required shape is:

```rust
struct Shard {
    state: Mutex<ShardState>,
    capacity: usize, // this shard's share of max_entries, from CacheConfig (section-01)
}

struct ShardState {
    positive: PositiveShardState,
    negative: NegativeShardState,
    lru: ShardLru,
}
```

All three fields of `ShardState` are mutated together under the one
`Mutex` lock — no separate locking for the LRU vs. the maps.

**Eviction loop.** On store, when a shard's domain count reaches its
`capacity` (the exact remainder-distributed per-shard capacity from
`CacheConfig`, section-01 — not a naive `ceil(max_entries / shard_count)`
which would overshoot the configured total), evict before/as part of
inserting the new domain:

1. Call `lru.peek_oldest()` to find the least-recently-touched domain.
2. Remove that domain from `positive.domains` (if present) and from
   `negative.domains` (if present) — both, unconditionally, since
   capacity counts a domain once regardless of whether it holds positive
   data, negative data, or both (interview Q6, plan §3.3).
3. Call `lru.remove()` for that domain, clearing its LRU position.

This is O(log n) per evicted domain (the LRU removal), with the map
removals being O(1) average case. There is no scenario in normal
operation (bounded eviction, single-domain touch) that costs more than
O(log n) total. The **only** O(n) operation in the whole cache design is
the namespace sweep (section-05) — this eviction loop must not
accidentally introduce another one (e.g. by scanning the maps to find the
oldest domain instead of using `ShardLru`).

**Domain count for capacity checks**: a domain "counts" toward capacity
if it has an entry in `positive.domains` OR `negative.domains` (OR both —
still counts once). The simplest correct implementation is to check the
LRU's `positions.len()` (which tracks exactly the set of domains with any
live data in this shard, since `touch` is called whenever either map
gains a domain and `remove` is called whenever a domain loses its last
entry in both maps) rather than separately unioning the two maps' key
sets on every store.

**Zero-capacity behavior**: when `capacity == 0` (from `max_entries == 0`
in `CacheConfig`, section-01), storing anything must be a no-op — this
preserves the existing invariant from `mod.rs:12213`
(`in_memory_cache_zero_capacity_stores_nothing`, migrated in
section-08). Do not attempt to insert-then-immediately-evict in this
case; skip the insert entirely when `capacity == 0`.

## Tests to write first

Write these against `src/resolver/cache/lru.rs` and
`src/resolver/cache/shard.rs`, in a `#[cfg(test)] mod tests` block in each
file, before implementing the corresponding logic. These are prose
descriptions of intent — write the actual `#[test]` functions using
descriptive snake_case names as shown (or equivalent), following the
existing codebase convention of one `#[cfg(test)] mod tests` block per
file.

### `cache/lru.rs`

- `lru_touch_moves_domain_to_most_recent_without_leaving_stale_positions`
  — touching a domain already tracked in `ShardLru.order` removes its old
  `(sequence, domain)` pair and inserts a new one; `order.len()` and
  `positions.len()` never exceed the number of distinct domains ever
  touched that are still live. (This is the direct replacement for the
  now-deleted `in_memory_cache_bounds_stale_lru_tokens_on_repeated_hits`
  ghost-token-compaction test — assert there is *never* more than one live
  position per domain, at any touch count, rather than testing a
  compaction threshold that no longer exists.)
- `lru_peek_oldest_returns_least_recently_touched_domain` — after touching
  domains in a known order, `peek_oldest()` returns the one touched least
  recently, exactly (not approximately).
- `lru_remove_clears_domain_from_both_order_and_positions` — removing a
  domain (e.g. on full eviction from the shard, or full removal by the
  namespace sweep) leaves no residual entry in either `order` or
  `positions` for it.
- `lru_touch_and_evict_cost_is_independent_of_shard_size` — property-style
  or count-based test asserting that a touch/evict does O(1) BTreeSet
  operations regardless of how many other domains are tracked (can be
  approximated by asserting a fixed, small number of tree operations via
  instrumentation, or accepted as implied by using `BTreeSet`/`HashMap`
  correctly rather than measured directly — implementer's call).

### `cache/shard.rs`

- `domain_with_only_negative_entry_still_counts_toward_shard_capacity` —
  a domain that has *only* a `NegativeEntry` (no positive record sets)
  still occupies one LRU/capacity slot in the shard, per the "capacity
  counts domains uniformly across positive and negative" decision.
- `evicting_a_domain_removes_both_positive_and_negative_data` — when a
  domain is evicted under LRU pressure, both its `DomainRecordSets` entry
  (if present) and its `DomainNegativeEntries` entry (if present) are
  removed together, and its LRU token is cleared from `ShardLru`.
- (Recommended, not in the original TDD list but implied by the plan's
  zero-capacity invariant) a test asserting that with `capacity == 0`, a
  store is a no-op: the domain never appears in either map or in the LRU
  afterward.
- (Recommended) an eviction-order test analogous to today's
  `in_memory_cache_evicts_least_recently_used_entry_when_bounded`: fill a
  shard to its capacity, touch (via lookup) all but one domain, store one
  more domain, and assert the untouched (least-recently-used) domain is
  the one evicted, while the touched ones survive.

## Implementation notes (actual vs. planned)

Implemented as specified: `ShardLru` (`BTreeSet<(u64, String)>` +
`HashMap<String, u64>` reverse index) in `cache/lru.rs`, and
`Shard`/`ShardState` (`PositiveShardState`/`NegativeShardState`/`ShardLru`
behind one `std::sync::Mutex`) plus the eviction loop in `cache/shard.rs`.
Public `Shard` API: `new(capacity)`, `store_positive`, `store_negative`,
`touch` (simulates a cache-hit LRU bump without mutating data —
implementer's naming choice, not prescribed by the plan), `domain_count`.

One deviation from the plan's literal code sketch, landed during code
review: `ShardLru` gained a `contains(&self, domain: &str) -> bool`
method, and `ShardState::domain_is_tracked` now calls it instead of
independently unioning `positive.domains`/`negative.domains` key
presence. The plan's own background section already recommends
consulting the LRU as the single source of truth for "is this domain
live" rather than re-deriving it from the maps (see "Domain count for
capacity checks" above) — this fix makes the code match that stated
intent instead of duplicating the check.

Three tests were added beyond the plan's listed minimum, all covering
gaps identified during code review:
`adding_a_second_qtype_to_an_existing_domain_never_evicts_at_full_capacity`
(the highest-risk untested branch of `make_room_for` — an already-tracked
domain gaining a new record set at full shard capacity must not trigger
eviction), `touching_only_the_negative_side_of_a_dual_entry_domain_keeps_it_recently_used`
(confirms capacity/recency is tracked per-domain, not per-map, per §3.3's
uniform-counting rule), and `touch_on_untracked_domain_is_a_no_op`.

Final test count: 4 in `src/resolver/cache/lru.rs`, 7 in
`src/resolver/cache/shard.rs` (4 from the plan's minimum + 3 added during
review). File paths match the plan exactly — no locking/namespace/assembly
logic leaked into this section, and no files outside
`lru.rs`/`shard.rs`/`entry.rs` (the last only for a transient
`#[allow(dead_code)]` narrowing, described in section-02's own doc
update) were touched.

## File paths touched by this section

- `src/resolver/cache/lru.rs` — `ShardLru` and its unit tests (new content
  in a file whose skeleton section-01 already created).
- `src/resolver/cache/shard.rs` — `Shard`, `ShardState`, the eviction loop,
  and their unit tests (new content in a file whose skeleton section-01
  already created).

No other files are touched by this section. Wiring `Shard` into a
top-level `ShardedDnsCache` type that owns `Vec<Shard>` and routes via
`shard_index` happens in later sections (section-06 for
lookup/assembly, section-07 for the trait implementation and call-site
migration) — do not build that top-level type here; this section's scope
ends at one working, independently-lockable `Shard`.