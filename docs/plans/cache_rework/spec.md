# Spec: Answer-cache rework — locking, LRU, and key structure

## Source

Ground truth for current behavior: `docs/caching.md` (snapshot as of
2026-07-09, covers `InMemoryDnsCache` in `src/resolver/mod.rs`). Read that
document in full before proposing changes — it documents the existing
`CacheKey`, `CachedResponse`, TTL policy, concurrency model, and eviction
behavior, plus a numbered list of concurrency/perf gaps (G1-G12) derived
from code inspection.

## Goals (user-stated, raw)

1. **Reduce lock scope to increase concurrency.** Today `InMemoryDnsCache`
   guards its entire state (`entries: HashMap`, `lru: VecDeque`,
   `next_sequence`) with one `std::sync::Mutex` (§6 of caching.md) — every
   lookup and store for every key, regardless of collision, serializes
   through this single lock (G2). Separately, `SingleFlightMisses` has its
   own single global mutex (also §6). The goal is to shrink what's covered
   by any one lock (sharding by key hash, splitting independent pieces of
   state, or similar) so unrelated concurrent requests stop contending.

2. **Real LRU, not an approximation.** Today eviction order is
   "approximately least-recently-used" via an append-only ghost-token
   `VecDeque` that requires periodic O(n) `retain` compaction (§7 of
   caching.md, and G1/G6 — the O(n) scan is the single biggest bottleneck
   identified in the current doc). The user's target complexity:
   - Worst case O(n) is acceptable **only** for the case where all items
     have been invalidated at once (e.g. a namespace-wide invalidation
     sweep — bulk removal is inherently O(k) in the number removed).
   - **Average-case O(log n)** for removal/touch operations otherwise —
     this points away from an O(1) intrusive-linked-list LRU and toward an
     ordered structure (e.g., a `BTreeSet`/`BTreeMap` keyed by recency
     sequence, or equivalent) that supports O(log n) reposition without
     unbounded ghost-token accumulation.
   - Confirm this complexity target is deliberate (vs. simply wanting exact
     LRU semantics with whatever complexity a standard exact-LRU structure
     gives) during the interview — an intrusive doubly-linked-list + hashmap
     gives exact LRU with O(1) touch/evict, which satisfies "real LRU"
     without matching the stated O(log n) figure. Surface the tradeoff
     explicitly rather than assuming.

3. **Cache key redesign.** The user believes the current key structure is
   wrong. Current `CacheKey` (§2 of caching.md) is a flat struct combining
   `QuestionKey` (name+qtype+qclass), exact question wire bytes, per-query
   `QueryFeatures` (RD/AD/CD/DO flags, EDNS bufsize), and an opaque
   `cache_namespace` string — meaning **one cache entry per (name, qtype,
   flags-combination, namespace)**, not one entry per name. The user's
   intuition: the key should be **the domain name**, pointing to **many DNS
   record sets** underneath (presumably keyed further by qtype/qclass, and
   by whatever DNSSEC-relevant dimensions actually affect the wire bytes —
   e.g. DO flag, validated-vs-unvalidated RRSIGs). Explicitly called out:
   *"thinking about how DNSSEC will need to behave"* — the new key/storage
   shape needs to accommodate DNSSEC record sets (RRSIGs, NSEC/NSEC3,
   validated state) without falling back to one-entry-per-flag-combination
   for names that support DNSSEC. This needs real design work during
   planning: what "many DNS record sets" means structurally (nested map?
   separate qtype dimension?), what stays per-request-derived vs.
   per-domain-cached, and how this interacts with the existing
   `question_wire`-preserves-casing behavior and `cache_namespace`
   invalidation lever (§2 of caching.md) — both of which may need to be
   rethought under a domain-first key.

## Explicit non-goals / scope note

- The delegation cache (`DelegationCache`, last section of caching.md) is a
  **separate** cache with its own lock and eviction policy. Not in scope
  unless the interview surfaces a reason to touch it.
- No specific performance targets (throughput numbers, latency SLOs) were
  given yet — clarify during interview whether any exist, or whether
  "increase concurrency" / "real LRU" are the only success criteria.

## Known constraints from current implementation (do not relitigate without reason)

- Correctness invariants that any redesign must preserve: TTL/expiry policy
  (§4), cache bypass conditions (§5), single-flight miss coalescing
  semantics (§6), and the fact that one stored entry currently serves both
  UDP and TCP requesters via post-hoc truncation at serve time (§3) — a
  domain-keyed redesign must decide whether this still holds per record-set
  entry.
- `cache_namespace` is the current bulk-invalidation lever (backend-affecting
  config changes, SIGHUP reload) — G4/G5 in caching.md describe the
  stampede/orphan-capacity costs this causes today. Any redesign should
  state how bulk invalidation is expected to behave under the new key
  structure, since goal 2's "O(n) only when everything is invalidated" case
  is explicitly about this scenario.
