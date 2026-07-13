# Interview: answer-cache rework

Conducted 2026-07-09, informed by `docs/caching.md` and `claude-research.md`.

## Q1: LRU exactness scope

Sharding (goal 1) naturally gives per-shard eviction order, not one global
LRU order — RocksDB/Unbound/PowerDNS all accept this. Does "real LRU" mean
exact within each shard (matches industry practice), or must eviction
order be exact across the whole cache?

**A:** Exact per-shard. Each shard has its own exact O(log n) LRU order.
Global order is only approximate across shards — matches RocksDB/Unbound/
PowerDNS practice.

## Q2: Build custom vs. adopt moka

moka gives sharded/lock-free storage + built-in single-flight coalescing
for free, but its eviction is TinyLFU-based, not a literal O(log n)
BTree-backed exact LRU. Adopt it (relaxing the exact-O(log n) LRU ask), or
build custom to hit the stated complexity target exactly?

**A:** Build custom. Hand-rolled sharded cache + BTreeSet/HashMap LRU per
shard, to hit the stated O(log n)/O(n)-only-on-full-invalidation target
exactly, even though it's more code to own.

## Q3: DNSSEC scope

DNSSEC support today is a stub (only `DnssecValidationMode::Disabled`
exists — no validation logic anywhere). Should this rework make the cache
shape DNSSEC-ready (store RRSIGs + a validation-state enum per RRset, per
RFC 4035/6840) without implementing actual signature validation, or is
validation itself in scope too?

**A:** Cache shape ready, no validation. Store RRSIGs alongside RRsets
with an Unvalidated/Insecure/Secure/Bogus state field. Actual crypto
validation is separate future work.

## Q4: Bulk invalidation mechanism

Today `cache_namespace` changes make all old entries instantly
unreachable (still occupy slots until evicted/expired — G4/G5 orphan-
capacity cost). Under the new domain-first key, keep this same
"instant-unreachable, lazy reclaim" trick, or move to an explicit sweep
that actively removes entries (matches the stated "O(n) only when
everything invalidated" language more literally)?

**A:** Explicit active sweep. A namespace/generation change walks and
removes affected entries directly — O(n) cost paid once, immediately, no
orphan slots lingering afterward.

## Q5: Single-flight coalescing granularity

Single-flight is currently keyed identically to the cache (full
question+features). Under the new domain-first/nested key, should
coalescing stay at that same fine granularity, or move to coarser
per-(name,type) granularity?

**A:** Coarsen to per-(name,type). Two requests for the same name+qtype
but different EDNS bufsize/flags share one upstream fetch — fewer upstream
round-trips; more complexity in reconciling per-request response assembly
(expected, given Q9's serve-time-assembly answer, which is what makes this
tractable).

## Q6: Capacity counting unit

Nested record-set storage means one domain entry now holds multiple
qtype/qclass record sets plus (later) DNSSEC state. Should `max_entries`
(capacity bound, currently 10,000, hardcoded, G10) count domains, or
individual record-sets/RRsets?

**A:** Count domains. One popular domain with many record types counts as
1 slot toward the bound — simpler mental model, accepted tradeoff that
memory per domain becomes variable/unbounded-by-count-alone (no separate
byte-size bound is in scope, per Q7).

## Q7: G10/G11 scope

`docs/caching.md` flags G10 (capacity hardcoded, not configurable) and
G11 (no byte-size bound, only entry-count). Is fixing either of these in
scope, or strictly out of scope?

**A:** Make capacity configurable (G10) only — wire `max_entries`/
shard-count through `src/config` since capacity semantics are already
being touched for the new counting unit. G11 (byte-size bound) stays out
of scope.

## Q8: Response assembly model

Today one cache entry stores a fully pre-built wire response template
reused as-is per hit. A domain-first RRset-keyed cache implies storing
raw RRdata once per (name,type) and re-assembling the wire response per
request instead. Confirm this shift to per-request response assembly at
serve time?

**A:** Yes. Matches the DNSSEC serve-time design from research (DO/AD/CD
decided per request) and is required for the new key shape anyway.

## Q9: Casing as a key dimension

`cache_key_separates_exact_wire_question_casing_for_templates` — today,
`example.com` vs. `Example.COM` get separate entries because the whole
response template is reused byte-for-byte. Once response assembly happens
per-request from stored RRdata, does casing still need to fragment
anything?

**A:** Share one entry, apply casing at assembly. Store RRset once per
normalized name; each response echoes back the requester's own casing at
assembly time from their own wire bytes. Removes a key-fragmentation
dimension entirely.

## Q10: Concurrency benchmark

G8: no test/benchmark exercises the cache under concurrent load today.
Given this rework's whole point is concurrency, should the plan include
adding a real concurrent-load benchmark/stress test?

**A:** Yes. A new concurrency benchmark is needed to prove the
sharding/lock-scoping actually reduces contention vs. the old
single-mutex design — otherwise goal 1 is unverified.

## Q11: Shard count

Any target shard count, or should the plan pick one?

**A:** Let the plan decide — pick a sensible default (e.g. power-of-two
near `available_parallelism`), informed by research (DashMap/RocksDB
convention of ~4x parallelism); can be tuned later.

## Q12: Negative caching structure

Research recommends storing negative-cache entries per (name,
qtype-or-ANY, SOA-owner) separately from positive RRsets (PowerDNS
NegCache / Unbound design). Adopt that split, or keep negative answers
folded into the same per-(name,type) entry structure as positive ones?

**A:** Separate negative-cache structure. Matches PowerDNS/Unbound design
— cleaner separation, avoids conflating "no data of this type" with "this
type's data."

## Q13: EDNS bufsize as a key dimension

The raw advertised EDNS UDP bufsize currently fragments the cache key on
purpose (deliberately kept per `docs/plans/cache_key.md`). Under
response-assembly-at-serve-time, does bufsize still need to fragment
anything, or can it also collapse into serve-time-only like casing did?

**A:** Collapse to serve-time-only. One shared entry regardless of
advertised bufsize; truncation applied fresh per request at assembly time
— consistent with the casing decision (Q9), removes another key
dimension.

## Q14: Rollout strategy

Is this rework a straight in-place rewrite of `InMemoryDnsCache` (no
feature flag, no dual-running old/new), or does it need to coexist
with/be toggleable against the current implementation during rollout?

**A:** Straight rewrite, no flag. Replace `InMemoryDnsCache` and
`SingleFlightMisses` in place. Matches project norms (no backwards-compat
shims unless asked).

## Summary of decisions carried into the plan

- **Architecture**: custom sharded cache (not moka), each shard = its own
  lock + own exact O(log n) LRU (BTreeSet<(seq,key)> + HashMap side-index)
  + own portion of the domain→{type→RRset} map. Global eviction order is
  only approximate across shards (per-shard exact).
- **Key**: domain name (normalized) → nested map of {qtype/qclass →
  positive RRset entry}, with a **separate** negative-cache structure
  keyed by (name, qtype-or-ANY, SOA-owner). Casing and raw EDNS bufsize
  are dropped from the key entirely — both become serve-time response-
  assembly concerns.
- **DNSSEC**: each positive RRset entry carries raw RRSIG(s) (if any) and
  a validation-state enum (`Unvalidated | Insecure | Secure | Bogus`).
  DO/AD/CD handling moves to serve-time response assembly, per RFC
  4035/6840. No signature validation logic is implemented in this project
  — the state enum exists but nothing sets it beyond `Unvalidated` yet
  (or whatever default matches `DnssecValidationMode::Disabled` today).
- **Single-flight**: coarsened to per-(name, qtype) — collapsing the
  casing/bufsize dimensions from the cache key naturally coarsens
  coalescing too.
- **Bulk invalidation**: namespace/generation changes trigger an explicit
  active sweep (not instant-unreachable + lazy reclaim) — this is the
  source of the "O(n), but only on full invalidation" behavior in goal 2.
- **Capacity**: `max_entries` counts **domains**, not individual RRsets.
  Made configurable via `src/config` (G10 fixed). Byte-size bound (G11)
  stays out of scope.
- **Testing**: existing ~16 cache-related tests need review/rewrite for
  the new shape; add a new multi-threaded concurrency benchmark/stress
  test (closes G8) proving sharding reduces contention.
- **Rollout**: straight in-place rewrite, no feature flag, no dual-running.
