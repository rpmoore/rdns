# Codex Review

**Reviewer:** codex-rescue subagent (GPT-5.1-Codex via Codex CLI)
**Generated:** 2026-07-09

---

## 1. Summary verdict

Ready with fixes, not ready as-is. The sharded `BTreeSet + HashMap` LRU direction is sound for exact per-shard recency, but the plan has blocking gaps in negative-response storage, DNSSEC-proof readiness, namespace sweep complexity accounting, and migration/test completeness. A competent engineer could implement the broad architecture, but would need further design decisions before safely rewriting cache storage and response assembly.

## 2. Correctness/soundness issues

- **§5 understates invalidation complexity.** The plan says the namespace sweep is `O(n)` where `n = total cached domains` (claude-plan.md:253), but namespace is stored per `RRsetEntry` and `NegativeEntry` (claude-plan.md:110, claude-plan.md:170). Since capacity counts domains and a domain may hold unbounded qtypes/RRsets (claude-spec.md:99), a correct sweep must inspect all per-domain RRsets/negative entries, not just domains. Concrete failure mode: a single hot domain with many cached RRsets makes invalidation `O(total RRsets + negative entries)`, so the stated complexity bound is inaccurate.

- **§8 can violate the configured total capacity.** The plan defines `max_entries` as total domain-count capacity (claude-plan.md:400) but divides by shard count "rounded up" for each shard (claude-plan.md:409). Concrete failure mode: `max_entries=10`, `shard_count=8` gives per-shard capacity 2, allowing 16 domains. `max_entries < shard_count` is worse, and zero-capacity behavior must preserve the existing "stores nothing" invariant tested in source (mod.rs:12213). The plan needs either distributed remainder capacities or an explicit "capacity is approximate under sharding" decision.

- **§4's normal-operation `O(log n)` claim is mostly sound for LRU touch/evict, but only for domain-level operations.** The proposed `BTreeSet<(sequence, domain)> + HashMap<domain, sequence>` matches the researched `O(log n)` touch mechanism (claude-research.md:206, claude-plan.md:192). No ghost-token compaction remains. The hidden caveat is that stores and sweeps now operate over variable-size per-domain maps, so the plan should distinguish `O(log domains_per_shard)` LRU work from `O(records/RRsets in the response or domain)` data-model work.

## 3. Completeness gaps

- **§3.2 / §7 cannot reconstruct negative cached responses.** Current cache stores the full response template, including authority/additional sections, and replays it with ID/TTL/truncation changes (docs/caching.md:116, mod.rs:4228). The proposed `NegativeEntry` stores only kind, SOA owner, SOA minimum TTL, times, and namespace (claude-plan.md:164). Concrete failure mode: an NXDOMAIN/NODATA cache hit cannot rebuild the SOA authority record or any proof records, even though negative TTL derivation currently depends on SOA coverage (docs/caching.md:155, mod.rs:746) and the served cached response today is the original template.

- **§7.1 / §9 do not fully specify CNAME+negative storage.** Existing TTL logic treats CNAME chains ending in NODATA as negative-cacheable and walks to the terminal covered name (mod.rs:663, mod.rs:780). §9 says store "one `RRsetEntry` per answer/CNAME chain, or one `NegativeEntry` for NXDOMAIN/NODATA" (claude-plan.md:431). Concrete failure mode: for `qname CNAME target` plus terminal NODATA, the cache must store the CNAME RRset and the terminal negative entry together; "or" leaves implementers unsure whether to preserve the chain on a negative hit.

- **§11 misses existing cache tests found in source.** The plan follows research A.4's list (claude-research.md:116), but actual source has additional cache-hit behavior tests not named in §11, including oversized cached-response truncation (mod.rs:13888) and treating an expired backend cache hit as a miss (mod.rs:13924). These are directly affected by serve-time assembly and expiry handling and should be explicitly migrated.

- **§9 omits `tests/recursive_perf.rs` construction.** Research notes `tests/recursive_perf.rs:144` builds `InMemoryDnsCache` (claude-research.md:140), and the source confirms it (recursive_perf.rs:141). §9 lists `main.rs` metrics/construction but not this test/perf call site (claude-plan.md:443).

## 4. Internal consistency issues

- **§3.2 contradicts the spec's negative-cache key.** The spec says negative entries are keyed by `(name, qtype-or-ANY, SOA-owner)` (claude-spec.md:130). The plan's `NegativeKey` includes only `qtype` and `qclass`, with `soa_owner` stored as a value (claude-plan.md:156, claude-plan.md:166). Concrete failure mode: two negative proofs for the same name/qtype/class but different covering SOA owner cannot coexist or be distinguished.

- **§8 contradicts its own "total capacity" wording via rounded-up shard capacity.** Same mechanism as above: total `max_entries` (claude-plan.md:400) is not actually enforced if every shard gets `ceil(max_entries / shard_count)` (claude-plan.md:409).

## 5. DNSSEC readiness assessment

Positive `RRsetEntry` is directionally compatible: it stores RRdata, raw RRSIG records, and a validation state (claude-plan.md:101), matching the research recommendation to store per `(owner,type,class)` with RRSIGs and validation state (claude-research.md:288).

The negative side is not DNSSEC-shape-ready. Research explicitly calls out NSEC/NSEC3 proof material and separate reusable negative proof caching (claude-research.md:281), but §3.2 stores no SOA record data, SOA RRSIG, NSEC/NSEC3 records, or proof linkage (claude-plan.md:164). That likely forces another data-model reshape before real negative validation or aggressive negative caching can be added.

## 6. CNAME chain handling / cross-shard locking assessment

Deadlock risk is low if §7.1 is implemented as one shard lock at a time: lookup current name, clone the needed RRset/CNAME target, release the guard, then move to the next name. The plan says "one independent per-shard lookup per name" (claude-plan.md:349), which implies that model, but it should state the lock rule explicitly.

Ordering risk: if an implementation holds shard A while looking up shard B, CNAME chains can deadlock under concurrent opposite chains or self-deadlock when a later hop hashes to the same shard. The plan should add: never hold more than one shard lock during chain walking; clone/copy records before the next hop; track seen names; use the existing recursive CNAME restart limit. Source has `max_cname_restarts` and loop detection in the recursive backend (mod.rs:5519, mod.rs:6000).

## 7. Migration completeness assessment (§9 vs research A.1/A.3)

§9 covers the main flat-key call sites from research A.3: `probe_cache`, `cache_store_for_response`, `SingleFlightMisses`, `serialize_cached_response`, metrics, and namespace computation (claude-plan.md:426; research list at claude-research.md:99). It also accounts for the concrete metrics bypass of the trait noted in A.1 (claude-research.md:41, main.rs:842).

Not complete: it omits `tests/recursive_perf.rs` construction, and it leaves the `DnsCache` trait/API shape vague despite the current trait being flat `CacheLookupRequest`/`CacheStore` based (mod.rs:4435). §10 says "equivalent request/response shapes" stay/re-exported (claude-plan.md:487), but §9's `probe_cache` bypasses flat lookup via `resolve_from_cache`. The plan should define the new cache interface boundary clearly.

## 8. Open questions / blockers

- What exact data must `NegativeEntry` store to rebuild NXDOMAIN/NODATA responses: full SOA record, authority-section records, SOA RRSIG, NSEC/NSEC3 proofs, original response code, and/or a negative "message fragment"?

- For CNAME+NODATA, does storing a backend response create both CNAME `RRsetEntry` records and a terminal `NegativeEntry` in one operation?

- Is global `max_entries` strict or approximate under sharding? If strict, define shard capacity distribution rather than rounded-up equal capacity.

- What is the new `DnsCache` public API? The existing trait is shaped around flat `CacheKey` lookup/store; the plan needs a concrete replacement before TDD stubs are written.

- During CNAME cache walking, what exact lock discipline is required? The plan should mandate one lock at a time and existing `max_cname_restarts`/seen-name loop protection.
