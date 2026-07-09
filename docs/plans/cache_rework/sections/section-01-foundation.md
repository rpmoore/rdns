# section-01-foundation: Module skeleton, shard-routing hash, and `CacheConfig`

## Dependencies

None — this is the first section, with no prerequisites. Every other
section (`section-02` through `section-08`) depends on this one either
directly or transitively, per `docs/plans/cache_rework/sections/index.md`'s
dependency graph. Do not wait on anything else before starting this
section.

## Scope of this section

This section only has to compile and pass its own config/hashing unit
tests. **No cache storage/lookup/eviction logic is written here** — that
starts in `section-02-data-model` and `section-03-shard-and-lru`. This
section produces exactly three things:

1. The new `src/resolver/cache/` module skeleton (empty/near-empty files
   that later sections fill in).
2. `shard_index(domain, shard_count) -> usize`, the hash-routing utility
   both the cache shards (`section-03`) and the single-flight shards
   (`section-04`) will use to route a domain name to a shard.
3. `CacheConfig`, including the exact remainder-distributed per-shard
   capacity split and the default-shard-count formula.

## Background context

This is part of a from-scratch redesign of the DNS answer cache
currently living in `src/resolver/mod.rs` (`InMemoryDnsCache` and
`SingleFlightMisses`, documented in full in `docs/caching.md`). The
motivating problems (documented in `docs/caching.md` §6-8) are: a single
global mutex serializing all cache access, an LRU implementation that
periodically costs O(n) to compact, and a cache key that's finer-grained
than necessary (bakes in exact wire casing, EDNS bufsize, and DNSSEC
flags).

The fix being built out across this section and the ones that follow is:
**N independently-locked shards**, selected by hashing the normalized
owner (domain) name. All data for a given domain — its positive record
sets, its negative-cache entries, and its LRU recency token — will live
in exactly one shard, so a single domain's cache operations never need to
coordinate across shards. This section provides the hashing primitive
that decides which shard a domain belongs to, and the configuration type
that decides how many shards there are and how big each one's capacity
is.

```
                    hash(domain_name) % shard_count
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         ┌─────────┐    ┌─────────┐    ┌─────────┐
         │ Shard 0 │    │ Shard 1 │ …  │Shard N-1│
         │ (own    │    │ (own    │    │ (own    │
         │  lock)  │    │  lock)  │    │  lock)  │
         └─────────┘    └─────────┘    └─────────┘
```

## Part 1 — Module skeleton

Create the new module directory `src/resolver/cache/` with the following
files (mirrors `claude-plan.md` §10's suggested layout):

```
src/resolver/
  mod.rs                  # unchanged responsibilities minus cache internals;
                           # gains `mod cache;` declaration
  cache/
    mod.rs                 # ShardedDnsCache, DnsCache trait impl, public API
                            # (this section: just shard_index + re-exports)
    shard.rs                # Shard, ShardState, PositiveShardState,
                             # NegativeShardState, eviction loop (section-03)
    lru.rs                   # ShardLru (BTreeSet + HashMap side-index, §4)
                              # (section-03)
    entry.rs                  # RRsetEntry, StoredRecord, DnssecState,
                               # NegativeEntry, NegativeKey (section-02)
    singleflight.rs             # ShardedSingleFlight, InFlightMiss,
                                 # SingleFlightTicket/Leader (section-04)
    assemble.rs                  # assemble_response, resolve_from_cache,
                                  # ChainLookup (section-06)
    namespace.rs                  # sweep_stale_namespace (section-05)
```

For this section:

- `shard.rs`, `lru.rs`, `entry.rs`, `singleflight.rs`, `assemble.rs`,
  `namespace.rs` are created as near-empty placeholder files — just the
  standard license header (see below) and, optionally, a one-line doc
  comment noting which later section owns the file's contents (e.g. `//!
  Positive/negative shard state — filled in by section-03.`). They must
  exist and be declared as modules so the crate compiles, but contain no
  logic yet.
- `cache/mod.rs` declares all six submodules (`mod shard;`, `mod lru;`,
  `mod entry;`, `mod singleflight;`, `mod assemble;`, `mod namespace;`)
  and hosts `shard_index` (Part 2 below).
- `src/resolver/mod.rs` gains a `mod cache;` declaration (place it near
  the existing `pub mod policy;` line, around line 40). Visibility of
  `cache` itself (`mod` vs `pub(crate) mod`) is the implementer's call —
  `mod cache;` (private) is sufficient for this section since nothing
  outside `resolver` needs it yet; widen it in `section-07` when
  call-site migration needs to reach `cache::ShardedDnsCache` from
  outside `resolver::mod`.

**License header requirement**: every new `.rs` file in this repo must
start with the standard Apache-2.0 header (enforced by the `reuse lint`
CI check). Copy it verbatim from an existing file, e.g.
`src/resolver/mod.rs`'s first 13 lines:

```rust
// Copyright 2026 Ryan Moore
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
```

Apply this to all seven new files (`cache/mod.rs` plus the six
submodule stubs).

## Part 2 — `shard_index` hash-routing utility

Location: `src/resolver/cache/mod.rs`.

```rust
/// Routes a domain name to a shard index in `[0, shard_count)`. Shared by
/// the cache shards (`cache::shard`, section-03) and the single-flight
/// shards (`cache::singleflight`, section-04) — both structures shard
/// purely by domain name, so a single hashing implementation keeps their
/// routing behavior identical and avoids duplicated hashing logic.
///
/// `domain` is expected to already be normalized (lowercased, trailing
/// dot stripped — the same normalization `normalize_question_name`
/// applies in `resolver::mod`) by the caller; this function does not
/// normalize internally, so two differently-cased spellings of the same
/// domain will only route to the same shard if the caller normalizes
/// first. Every call site added in later sections normalizes before
/// calling this.
///
/// `shard_count` is expected to be at least 1 in real use (see
/// `CacheConfig::resolved_shard_count`, Part 3); `shard_count == 0` is
/// handled defensively (returns 0) rather than panicking, since this is a
/// cheap routing function, not a place to enforce config invariants.
pub(crate) fn shard_index(domain: &str, shard_count: usize) -> usize {
    // Use a deterministic (not randomly-seeded) hasher — routing must be
    // stable across repeated calls within the same process run.
    // `std::collections::hash_map::DefaultHasher` is deterministic
    // (fixed keys), unlike `HashMap`'s default `RandomState`. Hash the
    // already-normalized `domain` string and reduce mod `shard_count`.
    ...
}
```

Implementation notes for the stub above:
- Use `std::collections::hash_map::DefaultHasher` + `std::hash::{Hash,
  Hasher}` (deterministic within a process — unlike `RandomState`,
  `DefaultHasher::new()` uses fixed keys), hash the `domain: &str`, then
  reduce `hasher.finish() % shard_count as u64` cast to `usize`. Guard
  `shard_count == 0` before the modulo to avoid a divide-by-zero panic.
- This function currently has no non-test callers (section-03 and
  section-04 add them). To keep `cargo clippy --all-targets --all-features
  -D warnings` clean in the interim, either accept a temporary
  `#[allow(dead_code)]` on the function (remove it once section-03 or
  section-04 adds a real caller) or leave it and note the expected
  transient warning in the PR description — implementer's call, but do
  not silently leave the build red.

## Part 3 — `CacheConfig`

Location: `src/config/mod.rs` (the same file `RuntimeConfig`,
`MetricsConfig`, `ResolutionConfig`, etc. already live in — this is a
single-file config module today, not a directory of submodules). Add
`CacheConfig` as a new public struct in that file, near
`RuntimeConfig`/`MetricsConfig`.

**Important**: this section defines the `CacheConfig` type and its
methods only. Wiring `RuntimeConfig.cache: CacheConfig` through the
struct field, the `RawRuntimeConfig`/TOML deserialization path, and
`main.rs`'s cache construction is **`section-07-call-site-migration`'s
job**, not this section's. Do not touch `RuntimeConfig`,
`RawRuntimeConfig`, or `main.rs` in this section.

```rust
pub struct CacheConfig {
    /// Total domain-count capacity across the whole cache (capacity
    /// counts domains, not individual record sets — a domain with
    /// multiple cached qtypes still occupies one slot). Replaces the
    /// current `main.rs` `DEFAULT_CACHE_ENTRIES` constant. Default:
    /// 10_000, preserving today's behavior for anyone not setting this
    /// explicitly.
    pub max_entries: usize,
    /// Number of shards. `None` means "pick a sensible default" — a
    /// power of two near `available_parallelism()`, following the
    /// DashMap/RocksDB convention of roughly 4x parallelism.
    pub shard_count: Option<usize>,
}
```

Required methods (exact names/signatures are the implementer's call, but
must cover this behavior — later sections will call whatever you name
them, so pick something you're willing to commit to):

- `resolved_shard_count(&self) -> usize` — returns `shard_count` if
  `Some`, else computes the default: `available_parallelism()` (via
  `std::thread::available_parallelism()`, falling back to `1` if it
  returns `Err`) times 4, rounded up to the nearest power of two (e.g.
  via `usize::next_power_of_two`).
- A per-shard capacity function, e.g. `shard_capacity(&self, index:
  usize, shard_count: usize) -> usize` (or a `shard_capacities(&self,
  shard_count: usize) -> Vec<usize>` returning the whole distribution —
  implementer's call). **Per-shard capacity must sum exactly to
  `max_entries`, not merely approximate it.** Naively giving every shard
  `ceil(max_entries / shard_count)` overshoots the configured total —
  e.g. `max_entries=10, shard_count=8` gives each shard capacity 2, an
  effective ceiling of 16, silently violating the configured bound.
  Instead, distribute the remainder explicitly: shard `i`'s capacity is
  `max_entries / shard_count` (integer division), plus one extra if `i <
  max_entries % shard_count`. This sums to exactly `max_entries` for any
  `shard_count`, and correctly gives every shard capacity 0 (preserving
  the existing "zero capacity stores nothing" invariant,
  `mod.rs:12213`) when `max_entries == 0`.
- `impl Default for CacheConfig` — `max_entries: 10_000, shard_count:
  None`.

Both `CacheConfig` and its methods should be `pub` (not `pub(crate)`),
since `src/config` is a `pub mod` and this type is genuinely public
config surface — this also means it won't trip `dead_code` lints even
before `section-07` wires it into `RuntimeConfig`.

## Tests (write first)

### `shard_index` tests — `src/resolver/cache/mod.rs`, `#[cfg(test)] mod tests`

No literal stubs for `shard_index` exist in `claude-plan-tdd.md` (it only
covers `CacheConfig`, below) — the manifest (`sections/index.md`) calls
for `shard_index` to have its own unit tests as this section's "hashing
unit tests." Write these, following the repo's descriptive-snake-case
naming convention:

- `shard_index_is_deterministic_for_same_input` — calling
  `shard_index(domain, shard_count)` twice with the same arguments
  returns the same result both times.
- `shard_index_stays_within_bounds` — for a range of `shard_count` values
  including non-powers-of-two (e.g. 1, 2, 8, 17), every returned index is
  `< shard_count` for a variety of domain strings.
- `shard_index_distributes_distinct_domains_across_shards` — hashing a
  reasonably large set of distinct domain-name strings with a fixed
  `shard_count > 1` produces more than one distinct shard index (sanity
  check that the hash isn't degenerate, e.g. everything collapsing to
  shard 0).

### `CacheConfig` tests — `src/config/mod.rs`, existing `#[cfg(test)] mod
tests` block (starts around line 1606)

Directly from `claude-plan-tdd.md` §8:

- `cache_config_defaults_preserve_current_max_entries` — an unconfigured
  `CacheConfig` (i.e. `CacheConfig::default()`) yields `max_entries ==
  10_000`, matching today's `DEFAULT_CACHE_ENTRIES` behavior for anyone
  not setting it explicitly.
- `cache_config_shard_capacity_sums_exactly_to_max_entries` — for a range
  of `(max_entries, shard_count)` pairs, including non-evenly-divisible
  ones (e.g. `max_entries=10, shard_count=8`), the sum of all per-shard
  capacities (i.e. `sum(shard_capacity(i, shard_count) for i in
  0..shard_count)`) equals `max_entries` exactly, not an overshoot.
- `cache_config_zero_max_entries_gives_every_shard_zero_capacity` —
  `max_entries == 0` results in every shard's capacity being 0 (this
  section only tests the capacity function returns 0 for every index;
  the "storing anything is a no-op" behavior itself is section-03's
  concern once shard storage exists).
- `cache_config_shard_count_defaults_to_power_of_two_near_parallelism` —
  when `shard_count` is `None`, `resolved_shard_count()` returns a power
  of two (assert via `n.is_power_of_two()` or equivalent), and the value
  is in a sane range relative to `available_parallelism()` (e.g. between
  `available_parallelism` and `available_parallelism * 8`, since the
  exact formula is 4x rounded up to the next power of two) — assert the
  power-of-two property and a sane range rather than one exact number,
  since parallelism is environment-dependent.

## Definition of done

- `src/resolver/cache/{mod,shard,lru,entry,singleflight,assemble,namespace}.rs`
  all exist with correct license headers; `cache/mod.rs` declares all six
  submodules.
- `src/resolver/mod.rs` has a `mod cache;` declaration.
- `shard_index` is implemented in `cache/mod.rs` with its three unit
  tests passing.
- `CacheConfig` (struct + `resolved_shard_count` + per-shard capacity
  method + `Default` impl) is implemented in `src/config/mod.rs` with its
  four unit tests passing.
- `RuntimeConfig` is **not** modified in this section.
- `cargo test --locked` passes.
- `cargo build`/`cargo check` compiles cleanly (accounting for the
  documented transient `dead_code` consideration on `shard_index` until
  later sections add real callers).

## Notes for the implementer

- Do not implement `ShardedDnsCache`, `Shard`, `ShardState`, `ShardLru`,
  `RRsetEntry`, `NegativeEntry`, or any single-flight types in this
  section — those belong to `section-02-data-model`,
  `section-03-shard-and-lru`, and `section-04-singleflight` respectively.
  This section's only job is the module scaffolding, the hash-routing
  primitive, and the config type those sections will build on.
- `normalize_question_name` (defined in `src/resolver/mod.rs:189`, `fn
  normalize_question_name(name: &str) -> String { name.trim_end_matches('.').to_ascii_lowercase()
  }`) already exists and is what later sections will use to normalize a
  domain before calling `shard_index`. It's a private `fn` in
  `resolver::mod` — since `cache` is a descendant module of `resolver`,
  code in `cache::*` can call it directly (`super::normalize_question_name`
  or `crate::resolver::normalize_question_name`) without changing its
  visibility. You don't need it for this section's own tests (which pass
  already-normalized literal strings), but don't accidentally re-derive
  normalization logic elsewhere — later sections should reuse this
  function.

## Relevant file paths

- `/home/rpmoore/code/rdns/src/resolver/mod.rs` (add `mod cache;`
  declaration; existing `normalize_question_name` at line 189 for later
  sections' reference)
- `/home/rpmoore/code/rdns/src/resolver/cache/mod.rs` (new — `shard_index`
  + submodule declarations)
- `/home/rpmoore/code/rdns/src/resolver/cache/shard.rs` (new — stub)
- `/home/rpmoore/code/rdns/src/resolver/cache/lru.rs` (new — stub)
- `/home/rpmoore/code/rdns/src/resolver/cache/entry.rs` (new — stub)
- `/home/rpmoore/code/rdns/src/resolver/cache/singleflight.rs` (new — stub)
- `/home/rpmoore/code/rdns/src/resolver/cache/assemble.rs` (new — stub)
- `/home/rpmoore/code/rdns/src/resolver/cache/namespace.rs` (new — stub)
- `/home/rpmoore/code/rdns/src/config/mod.rs` (add `CacheConfig` struct +
  methods + tests; existing `RuntimeConfig` at line 30, existing test
  module starting around line 1606 — do not modify `RuntimeConfig` or
  `RawRuntimeConfig` in this section)
- `/home/rpmoore/code/rdns/src/main.rs` (reference only — `DEFAULT_CACHE_ENTRIES`
  at line 46 is what `CacheConfig::max_entries`'s default replaces; not
  modified until `section-07`)