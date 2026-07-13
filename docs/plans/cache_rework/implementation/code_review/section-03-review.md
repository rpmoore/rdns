# Code Review: section-03-shard-and-lru

Reviewer: `deep-implement:code-reviewer` subagent

## Summary

Overall the implementation is correct and matches the plan closely:
single-lock atomicity, exact LRU semantics, unconditional dual-map
eviction, and the zero-capacity no-op invariant all check out under
careful trace-through. No crash/deadlock/data-race bugs found. Findings
below are mostly test-coverage gaps and a maintainability nit.

**HIGH**: none found.

## Findings

- **MEDIUM — test coverage gap**: the early-return path in
  `make_room_for` ("adding a second qtype/negative-key to an
  already-tracked domain must never trigger eviction, even when the
  shard is exactly at capacity") had zero direct test coverage — exactly
  the off-by-one-prone branch the plan calls out.
- **MEDIUM — test coverage gap**: no test for "touch only the negative
  side of a domain that has both positive and negative entries, confirm
  the domain still counts as recently used" (plan's
  capacity-counts-domains-uniformly rationale, §3.3).
- **MEDIUM — maintainability nit**: `ShardState::domain_is_tracked`
  re-derived domain presence via
  `positive.domains.contains_key(domain) || negative.domains.contains_key(domain)`,
  duplicating the notion of "is this domain live" that `ShardLru`
  already encodes via `positions`. The plan itself recommends consulting
  the LRU's position count rather than re-deriving from the maps.
  `ShardLru` had no `contains(domain)` accessor, so `shard.rs`
  reimplemented the check via two HashMap lookups instead of one.
  Functionally correct today (both were kept in lockstep), but two
  parallel definitions of "domain set" that could silently drift on a
  future edit.
- **LOW**: `ShardLru::touch` allocates up to three owned `String`s per
  call on the already-tracked path; not a correctness issue given O(log
  n)/O(1) either way. Not changed — out of scope for what the plan asked
  for.
- **LOW — test coverage gap**: no test directly exercises `Shard::touch()`
  on a domain with no live data to confirm it's a true no-op.

## Scope check

Confirmed only `src/resolver/cache/{lru.rs,shard.rs,entry.rs}` were
touched, matching the plan's file list exactly; no namespace-sweep
(section-05) or assembly (section-06) logic leaked in; `Shard`/`ShardLru`
correctly stop at store/touch/evict primitives with no top-level
`ShardedDnsCache` type and no capacity-computation logic (correctly
deferred to section-01/07). The `entry.rs` changes exactly match the
described minor diff. `.lock().unwrap()` usage matches the existing
codebase convention.
