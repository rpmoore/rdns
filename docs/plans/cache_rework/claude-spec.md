# Spec: Answer-cache rework — locking, LRU, and key structure

Synthesizes `spec.md` (raw user request), `claude-research.md` (codebase +
web research), and `claude-interview.md` (14 Q&A resolving every open
design question). This is the spec the implementation plan is built from.

## Source

Ground truth for current behavior: `docs/caching.md` (snapshot as of
2026-07-09, covers `InMemoryDnsCache` in `src/resolver/mod.rs`). All
section/line references below (`§N`, `mod.rs:NNNN`) point into that doc or
the file it describes unless stated otherwise.

## What exists today (baseline)

- `InMemoryDnsCache` — one `std::sync::Mutex<InMemoryDnsCacheState>`
  guarding a `HashMap<CacheKey, InMemoryDnsCacheEntry>` plus an
  append-only ghost-token `VecDeque<(CacheKey, u64)>` LRU approximation
  requiring periodic O(n) compaction (`docs/caching.md` §6-7).
- `SingleFlightMisses` — a second, independent global
  `Mutex<HashMap<CacheKey, Arc<InFlightMiss>>>` for request coalescing
  (§6).
- `CacheKey` is flat: `QuestionKey` (name+qtype+qclass) + exact question
  wire bytes (preserves requester casing) + `QueryFeatures` (RD/AD/CD/DO,
  raw EDNS bufsize) + `cache_namespace` (§2) — meaning one entry per exact
  (name, qtype, flags-combination, namespace) tuple, not one entry per
  name.
- `CachedResponse` stores a fully pre-built wire response template,
  reused byte-for-byte per hit with only transaction ID/TTL rewritten (§3).
- DNSSEC is a stub: `DnssecValidationMode::Disabled` is the only variant;
  no validation logic exists anywhere (research finding A.3).
- Known gaps from `docs/caching.md` §8-9: G1 (O(n) scan on every store once
  at capacity — the single biggest bottleneck), G2 (no sharding — one lock
  domain for the whole keyspace), G4/G5 (reload causes a full-cache-cold
  stampede, orphaned entries linger), G6 (hits also pay lock-held cloning +
  periodic O(n) compaction), G8 (no concurrency test/benchmark exists),
  G10 (capacity hardcoded, not configurable), G11 (no byte-size bound).

## Goals

1. **Reduce lock scope to increase concurrency.** Replace the single
   global cache-state mutex and the single global single-flight mutex with
   a **sharded** design: N shards, each independently locked, holding its
   own portion of the keyspace. Unrelated concurrent requests (different
   shards) must not contend.

2. **Real per-shard exact LRU**, not the current ghost-token
   approximation. Target complexity: **O(log n) average-case per touch/
   removal**, **O(n) worst case reserved for the bulk-invalidation-sweep
   case only** (§ Bulk invalidation below) — not for normal operation.
   This rules out the O(1) intrusive-linked-list design in favor of an
   ordered structure (`BTreeSet<(sequence, key)>` + `HashMap<key,
   sequence>` side-index per shard, per research B.2) that gives exact LRU
   with no ghost tokens and no periodic compaction pass.

3. **Domain-first cache key.** Replace the flat `CacheKey` with a
   hierarchical structure: **domain name → {qtype/qclass → RRset entry}**,
   matching how production resolvers (PowerDNS, Unbound) structure their
   caches (research B.3) rather than one entry per exact query. This
   structurally accommodates DNSSEC: each RRset entry carries its raw
   RRSIG(s) and a validation-state field, per RFC 4035 §4.5 ("cache each
   response as a single atomic entry containing the RRset and its DNSSEC
   RRs").

## Design decisions (resolved in interview)

- **Sharding vs. exact global LRU (Q1)**: exact LRU is per-shard only.
  Global eviction order across the whole cache is approximate (a shard can
  evict a "warmer" entry than another shard's coldest) — this is the
  accepted industry tradeoff (RocksDB, Unbound, PowerDNS all do this); it
  is not a design gap, it's inherent to sharding and explicitly accepted
  here.
- **Custom implementation, not `moka` (Q2)**: build a hand-rolled sharded
  cache rather than adopting the `moka` crate. `moka` would give sharded/
  lock-free storage and built-in single-flight coalescing "for free," but
  its TinyLFU eviction doesn't hit the literal stated O(log n)/O(n)-only-
  on-full-invalidation complexity target — that target was explicit and
  wins over adopting a library.
- **DNSSEC: cache-shape-ready, not implementing validation (Q3)**: each
  RRset entry gets a validation-state enum (`Unvalidated | Insecure |
  Secure | Bogus(reason)`, per research B.3 and RFC 6840 §3.1's "BAD
  cache" concept) and stores raw RRSIG(s) alongside RRdata. No signature-
  verification logic is written in this project — entries stay
  `Unvalidated` (or equivalent) since `DnssecValidationMode::Disabled` is
  the only mode that exists today. The shape must not need revisiting when
  validation is eventually implemented.
- **Bulk invalidation: explicit active sweep (Q4)**: unlike today's
  `cache_namespace`-based "instant unreachable, reclaimed lazily by
  eviction/expiry" trick (§2, G4/G5), a namespace/generation change under
  the new design **actively walks and removes** affected entries at the
  time of the change. This is deliberately where the design's O(n) worst
  case lives — paid once, immediately, per invalidation event, with no
  orphan-capacity cost lingering afterward (closes G5).
- **Single-flight coalescing: per-(name, qtype) (Q5)**: coarsened from
  today's full-(question, features) granularity. This is a direct
  consequence of dropping casing and EDNS-bufsize from the key (Q9, Q13)
  — two requests differing only in those dimensions now naturally share
  one upstream fetch.
- **Capacity unit: domains (Q6)**: `max_entries` counts distinct cached
  **domain names**, not individual RRsets. A domain with many cached
  record types (A, AAAA, MX, TXT, RRSIG-bearing entries, etc.) still
  counts as 1 toward the bound. Accepted tradeoff: per-domain memory is
  now variable/unbounded by count alone (no byte-size bound is in scope —
  see G11 below).
- **G10 fixed, G11 not (Q7)**: capacity (and shard count) become
  configurable via `src/config` instead of the current `main.rs`-hardcoded
  `DEFAULT_CACHE_ENTRIES = 10_000`. A byte-size/memory ceiling (G11) is
  explicitly out of scope for this rework.
- **Response assembly moves to serve time (Q8)**: cache entries store raw
  RRdata (and RRSIGs), not pre-built wire templates. Every cache hit
  assembles the wire response fresh per request — this is what makes
  DO/AD/CD-dependent serving (RFC 6840 §5.8-5.9, research B.3) and the key
  simplifications below possible without one-entry-per-flag-combination.
- **Casing collapses to serve-time (Q9)**: the current
  `question_wire`-preserves-casing behavior (§2,
  `cache_key_separates_exact_wire_question_casing_for_templates`) is
  dropped as a key dimension. One RRset entry is shared regardless of
  requester casing; the response is assembled using the *requester's own*
  wire bytes for the name at serve time.
- **Concurrency benchmark required (Q10)**: this rework must add a real
  multi-threaded, contention-focused benchmark/stress test proving the
  sharded design measurably reduces contention vs. the old single-mutex
  design under concurrent load — this directly closes G8 (no such test
  exists today) and is the only way to verify goal 1 was actually
  achieved, not just structurally plausible.
- **Shard count: plan's discretion (Q11)**: no user-specified number; pick
  a sensible default informed by research B.1 (power-of-two, roughly
  proportional to `available_parallelism`, DashMap/RocksDB convention of
  ~4x parallelism as a starting point), configurable per Q7.
- **Negative caching: separate structure (Q12)**: NXDOMAIN/NODATA answers
  get their own cache structure — keyed by (name, qtype-or-ANY, SOA-owner)
  — distinct from the positive per-(name, qtype) RRset entries, per
  PowerDNS `NegCache`/Unbound design (research B.3). Do not fold negative
  answers into the same entry structure as positive ones.
- **EDNS bufsize collapses to serve-time (Q13)**: unlike the prior
  deliberate decision to keep raw advertised EDNS bufsize in the key (see
  `docs/plans/cache_key.md`, §2 of caching.md), this rework reverses that:
  bufsize also becomes a serve-time-only concern once response assembly
  happens per-request. One shared RRset entry serves all bufsize/DO/CD/AD/
  casing variants; truncation and DNSSEC-record-inclusion are decided
  fresh per response.
- **Straight in-place rewrite (Q14)**: no feature flag, no dual-running
  old and new cache implementations. Replace `InMemoryDnsCache` and
  `SingleFlightMisses` directly.

## Non-goals

- The delegation cache (`DelegationCache`) is untouched — separate lock,
  separate eviction policy, not part of this rework.
- No specific throughput/latency SLO was given; success criteria are the
  stated complexity targets (goal 2) and a demonstrated reduction in lock
  contention under the new concurrency benchmark (Q10), not a numeric
  target.
- Byte-size/memory bound (G11) — out of scope, entry-count-by-domain
  (Q6/Q7) remains the only capacity dimension.
- Actual DNSSEC signature validation — cache shape only (Q3); no crypto
  verification logic.

## Correctness invariants that must survive the rewrite

From `docs/caching.md` and the existing ~16 cache-touching tests
(research A.4) — these encode current behavior/guarantees that the new
design must preserve or deliberately supersede (and the plan must say
which, for each):

- TTL/expiry policy (§4): positive-TTL bounds (`apply_ttl_bounds`),
  RFC 2308 negative-TTL derivation from SOA, SERVFAIL caching opt-in with
  a hard cap.
- Cache bypass conditions (§5): EDNS with nonzero extended rcode/version/
  non-DO flags/any option, non-cacheable response codes, `DoNotCache`
  directive, zero-TTL results, `max_entries == 0`, policy-block-on-store.
- Single-flight semantics: still exactly one upstream fetch per leader,
  followers still get a real cache-lookup-shaped result (not a raw clone
  of leader bytes) unless the leader's result was non-cacheable — now at
  per-(name,qtype) granularity (Q5) instead of per full flat key.
- Malicious-CNAME-target blocking on cache hits (both direct and
  coalesced-miss paths) must still apply after response assembly moves to
  serve time (Q8).
- The one non-trait caller (`OpenTelemetryMetrics` in `main.rs:842-863`,
  calling `cache.len()`/`cache.capacity()` directly on the concrete type,
  research A.1) needs an updated concrete-type surface for a sharded
  cache — decide in the plan whether `len()` becomes an approximate
  cross-shard sum and whether that's acceptable for a gauge.
