# Integration notes: Codex review → claude-plan.md

Review: `reviews/iteration-1-codex.md` (Codex CLI, via `codex:codex-rescue`
subagent — used per explicit user request instead of the default
Opus-subagent review path, since Codex was available in this environment).

## Integrated (plan updated)

1. **Namespace-sweep complexity was misstated (§5).** The plan said the
   sweep is O(n), n = domains. Since namespace is stored per `RRsetEntry`/
   `NegativeEntry` and a domain can hold many of each, the sweep must
   inspect every entry, not just every domain. **Fixed**: reworded §5 to
   say n = total cached record-sets + negative entries across the cache.
   Still a one-time, invalidation-only cost — the goal-2 target ("O(n)
   only on full invalidation") is unaffected, only the definition of `n`
   was wrong.

2. **Per-shard capacity rounding could exceed configured `max_entries`
   (§8).** `ceil(max_entries / shard_count)` per shard, summed across
   shards, can exceed the configured total (concrete example from review:
   `max_entries=10, shard_count=8` → per-shard cap 2 → true ceiling 16).
   **Fixed**: replaced with an exact remainder-distributed split (`shard i
   capacity = max_entries / shard_count`, plus one extra for the first
   `max_entries % shard_count` shards) so the sum is exactly
   `max_entries`, including the `max_entries == 0` case (every shard gets
   0, preserving the existing "stores nothing" invariant tested at
   `mod.rs:12213`).

3. **`NegativeEntry` couldn't reconstruct a servable negative response
   (§3.2).** The original shape stored only kind/soa_owner/soa_minimum_ttl/
   times — not enough to rebuild the authority-section SOA record the
   current implementation replays from its stored template
   (`docs/caching.md` §3, `mod.rs:4228`). **Fixed**: added a stored SOA
   `StoredRecord`, an optional SOA RRSIG (DNSSEC-shape-readiness, matching
   the positive-side `DnssecState` treatment), and an (empty-today) list of
   NSEC/NSEC3 proof records — the last one directly serves the
   DNSSEC-readiness goal the research doc flagged as missing on the
   negative side (`claude-research.md` B.3's RFC 8198 discussion).

4. **CNAME-chain + terminal-negative storage was ambiguous ("or") (§7.1,
   §9).** The plan said a backend response is stored as "RRsetEntry per
   chain, **or** NegativeEntry for NXDOMAIN/NODATA," which doesn't cover
   the CNAME-chain-ending-in-NODATA case the current TTL logic explicitly
   handles (`mod.rs:663-674`, `negative_covered_name` walking the chain,
   `mod.rs:780-796`). **Fixed**: reworded to "and, additionally" — every
   CNAME hop in the chain is always stored as its own positive
   `RRsetEntry`; a negative terminal result *additionally* stores a
   `NegativeEntry` for the terminal (covered) name. These aren't
   mutually exclusive.

5. **Missing test/call-site references (§9, §11).** Codex found two
   existing resolve-level tests not in the original migration list
   (`resolve_truncates_oversized_cached_response_for_current_request`,
   `mod.rs:13888`; `resolve_treats_expired_cache_backend_hit_as_miss`,
   `mod.rs:13924`) and one missed cache-construction call site
   (`tests/recursive_perf.rs:141-148`, `resolver_with_cache` helper).
   **Fixed**: added all three to §9/§11.

6. **No explicit lock-discipline rule for cross-shard CNAME walking
   (§7.1).** The plan implied "one shard lock at a time" but never said so
   outright — a real deadlock/ordering risk if an implementer instead held
   a lock across hops. **Fixed**: added an explicit rule (never hold more
   than one shard lock at a time during chain walk; clone needed data and
   drop the guard before the next hop) and pointed at the existing
   `max_cname_restarts` config bound (`mod.rs:5520`, enforced at
   `mod.rs:6000`) as the chain-depth limit to reuse, rather than inventing
   a second, possibly-inconsistent one.

7. **`DnsCache` trait replacement was left implicit (§9).** The plan
   referenced `resolve_from_cache`/`assemble_response` without ever
   defining the trait boundary that replaces today's flat
   `lookup`/`store`. **Fixed**: added an explicit new trait sketch (method
   signatures only) to §9 so the TDD stage and implementer have a concrete
   interface to target instead of inferring one.

## Considered, not changed

- **`NegativeKey` "should" include SOA owner, per `claude-spec.md`'s
  `(name, qtype-or-ANY, SOA-owner)` phrasing.** Codex flagged this as a
  plan/spec inconsistency. On inspection, treating SOA owner as part of
  the lookup key (rather than a stored value on the entry) would allow
  multiple simultaneous, potentially-conflicting negative proofs for the
  same (name, qtype) — that's not desirable; there should be exactly one
  active negative result per (name, qtype) at a time, whichever SOA
  currently covers it, matching how `NegativeCacheMetadata.soa_owner` is
  already treated as *data*, not a key component, in the current
  implementation (`mod.rs:591-598`). Kept `NegativeKey` as
  `(qtype, qclass)` with `soa_owner` staying a stored value on
  `NegativeEntry` (now `soa_record`, see item 3) — this matches existing
  code, not a regression. The spec's research-derived phrasing was a loose
  paraphrase of PowerDNS's design, not a hard resolved decision to key on
  SOA owner; noting the reconciliation here rather than treating it as an
  unresolved conflict.
- **Per-shard-map data-model-sized work vs. LRU-sized work distinction
  (§4).** Codex's observation that store/sweep cost is proportional to
  records-per-domain, not just LRU-depth, is correct but was already
  implicit in the "sweep = O(total entries)" fix (item 1) — no separate
  plan change needed beyond that.
