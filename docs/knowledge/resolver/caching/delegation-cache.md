---
type: Mechanism
title: Delegation Cache
description: >
          Recursive mode's zone-cut cache: learned NS/glue endpoints keyed
          by (qclass, owner), with lazy expiry and sequence-stamped FIFO
          eviction.
resource: src/resolver/mod.rs
tags: [cache, dns, resolver, recursive, delegation, eviction]
timestamp: 2026-07-17T00:00:00Z
---

Recursive resolution's private cache of learned zone cuts — "queries at
or below `example.com` can start at these authority endpoints" — so a
walk for `a.example.com` doesn't re-traverse root → TLD when a referral
for `example.com` was already learned. Entirely separate from the
[answer cache](answer-cache.md): it stores authority *endpoints*
(`Vec<SocketAddr>`), not answers, is not sharded, and does not
participate in [cache-epoch](cache-epoch.md) invalidation.

# Structure

`DelegationCache` (`src/resolver/mod.rs:7951`) is one `Mutex` over
`DelegationCacheState` (`src/resolver/mod.rs:7836`):

- `entries: HashMap<qclass, HashMap<owner, DelegationEntry>>` — two-level
  so `lookup` can probe each zone suffix with a borrowed `&str` (no
  per-suffix key allocation; the outer map is almost always just IN).
- `insertion_order: VecDeque<(qclass, owner, sequence)>` — FIFO eviction
  order, deliberately *not* deduped on insert.
- `DelegationEntry` (`src/resolver/mod.rs:7808`) carries `endpoints`,
  `expires_at`, and a `sequence` stamped at insert time.

`lookup` (`src/resolver/mod.rs:8000`) is a longest-suffix match
(`www.example.com` → `example.com` → `com`), scoped by qclass.

# Invariants

- **Capacity**: at most `DEFAULT_DELEGATION_CACHE_CAPACITY` (4096,
  `src/resolver/mod.rs:7827`) live entries; exceeded → FIFO eviction of
  the oldest *live* entries (`evict`, `src/resolver/mod.rs:7917`).
- **TTL ceiling**: learned delegations are trusted at most
  `DELEGATION_CACHE_MAX_TTL_SECONDS` (24h, `src/resolver/mod.rs:7833`)
  regardless of the NS/glue TTL an authority returned.
- **Sequence-guarded eviction**: every insert stamps a fresh `sequence`
  onto the entry and pushes a matching slot. A slot whose sequence no
  longer matches the live entry (the entry expired, was lazily removed,
  or was replaced by a refresh) is *stale* and is never allowed to evict
  the live entry — it is skipped in `evict`'s pop loop, popped by
  `purge_front` (`src/resolver/mod.rs:7889`) when it surfaces at the
  front, and reclaimed in bulk by `compact`
  (`src/resolver/mod.rs:7940`). Without this guard, FIFO eviction
  through a stranded slot would delete a just-refreshed live delegation
  (the wrong-victim bug the sequence field exists to prevent; regression
  test `delegation_cache_eviction_skips_stale_slots_of_relearned_zones`).

# Expiry and cleanup (three cooperating paths, one policy)

Expired entries are removed **lazily**, never by a per-insert full scan
(the old shape — an O(capacity) scan on every referral store — is what
this design replaced):

1. `lookup` drops an expired entry it encounters (its slot goes stale).
2. `insert` runs `purge_front`: pops stale/expired slots off the FIFO
   front only — amortized O(1) (test
   `delegation_cache_purges_expired_entries_on_insert`).
3. Over capacity, `evict` does the full expiry purge, FIFO-evicts live
   entries, then compacts the slot queue.

Because refreshes strand old slots rather than deduping them, the slot
queue can outgrow the entry count; `insert` triggers `compact` once the
queue passes `2 * max_entries`, keeping queue growth amortized-O(1)
bounded even while the entry count sits below capacity (regression test
`delegation_cache_slot_queue_stays_bounded_under_churn_below_capacity`).

Consequence of laziness: an expired entry may linger in `entries` until
one of the three paths reaches it. That is memory-only slack bounded by
capacity — `lookup` never *serves* an expired entry.
