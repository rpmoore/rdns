# Section 01 — Knowledge-Bundle Docs (Documentation-Only, PR 1 / Part A)

## Implementation status: DONE

Implemented as planned, with two adjustments made during code review:

- The new content lives under one `# Wire-TTL aging on read` heading as
  plain prose paragraphs (matching this doc's existing style), not as
  bold inline lead-ins per sub-topic as originally drafted below — the
  review flagged the bold-lead-in convention as inconsistent with the
  rest of `docs/knowledge/`.
- References to section 03's two new regression tests are phrased as
  "covered by a regression test ... (see `docs/plans/ttl_remaining/`
  section 03)" rather than asserting the tests already exist, since
  section 03 had not landed yet at the time section 01 was committed
  (sections are independently committable per this index's dependency
  graph).

Both files (`docs/knowledge/resolver/caching/answer-cache.md`,
`docs/caching.md`) were edited exactly as scoped; the `grep -rl
'docs/caching.md' .` check was re-run post-edit and confirmed all 18
inbound references remain under `docs/plans/**`.

## Scope and status

This section is **doc-only**. It corresponds to Part A of
`docs/plans/ttl_remaining/claude-plan.md` and has no test requirements —
per `claude-plan-tdd.md`'s Part A entry: *"Doc-only change. No tests
apply; verification is human/reviewer read-through of
`docs/knowledge/resolver/caching/answer-cache.md` and the retired
`docs/caching.md` for accuracy, plus confirming (via grep, not a test)
that no live non-`docs/plans/` link to `docs/caching.md` breaks."*

No production code changes. This section is fully independent of
sections 02 (Clock DI) and 03 (TTL edge-case tests) — it touches only
markdown files, they touch only Rust source/tests. All three can proceed
in parallel.

## Background: what is already correct in the code (nothing here changes it)

`compute_wire_ttl` (`src/resolver/cache/assemble.rs:188-204`) is the
single function that computes the TTL value written onto every cache-hit
answer, RRSIG, SOA, and NSEC/NSEC3 proof record. Its current
implementation (unchanged by this section — quoted here only so the docs
you write accurately describe it):

```rust
/// Ages `ttl_at_store` by elapsed time since `stored_at`, capped by
/// remaining time to `expires_at` — computed directly in Rust before any
/// wire bytes are written (rather than reusing
/// `age_response_ttls`/`cap_response_ttls` against an assembled buffer),
/// since a CNAME chain can combine records from multiple `RRsetEntry`s
/// with different `stored_at` values, which a single scalar `age` applied
/// to a whole buffer can't represent correctly.
fn compute_wire_ttl(
    ttl_at_store: u32,
    stored_at: SystemTime,
    expires_at: SystemTime,
    now: SystemTime,
) -> u32 {
    let elapsed_secs = now
        .duration_since(stored_at)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let aged = ttl_at_store.saturating_sub(elapsed_secs.min(u64::from(u32::MAX)) as u32);
    let remaining_secs = expires_at
        .duration_since(now)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    aged.min(remaining_secs.min(u64::from(u32::MAX)) as u32)
}
```

Its logic, in prose:

- `aged = ttl_at_store - elapsed_since(stored_at)` — the record's own
  origin TTL, decremented by how long it has actually been sitting in the
  cache.
- `remaining = expires_at - now` — how much longer the cache entry itself
  is allowed to live under this resolver's TTL policy.
- Final wire TTL = `min(aged, remaining)`.

It is called once per record, independently, from `write_rrset`
(`assemble.rs:229-263`, positive answers) and `write_negative_authority`
(`assemble.rs:265-324`, SOA + its RRSIG + each DNSSEC proof record). Both
UDP and TCP responses go through the same `assemble_response` /
`assemble_negative_response` path (`assemble.rs:546`, `:615`) — there is
exactly one wire-TTL-aging code path in this codebase, already shared by
every transport. Read-time expiry (`Shard::lookup_hop`,
`src/resolver/cache/shard.rs:405-463`) deletes any entry already past
`expires_at` at lookup time, so an expired entry is never served at all.

This section does not change any of the above. It documents it, notes
the two previously-uncovered edge cases now covered by section 03's
regression tests, and records why the cache is invisible today for
EDNS-Cookie-bearing clients (Part E, out of scope for this section split
— see "Note on Part E" below).

## Task A.1 — Update `docs/knowledge/resolver/caching/answer-cache.md`

**File to modify:** `docs/knowledge/resolver/caching/answer-cache.md`

Current content (read in full before editing — this is the file's
complete existing text, reproduced here so you don't need to open it
separately):

```markdown
---
type: System
title: DNS Answer Cache
description: Sharded, in-memory cache of backend/upstream DNS answers, keyed by domain name.
resource: src/resolver/cache/mod.rs
tags: [cache, dns, resolver]
timestamp: 2026-07-13T00:00:00Z
---

Caches responses obtained from actual backend resolution — forwarding or
recursive — so a repeated query for the same name doesn't re-do that
work until TTL expiry or [invalidation](cache-epoch.md). It does **not**
cache manually-loaded data (BIND zone files, `[[local_dns_entries]]`);
see [local-dns-entries](local-dns-entries.md) for why that's a separate
structure entirely.

# Structure

```text
ShardedDnsCache { shards: Vec<Shard> }
Shard { state: Mutex<ShardState>, capacity: usize }
ShardState {
    // DomainRecordSets: HashMap<(qtype, qclass), RRsetEntry>
    positive: HashMap<domain, DomainRecordSets>,
    negative: HashMap<domain, DomainNegativeEntries>,
    lru: ShardLru,
}
```

One domain name's positive records, negative (NXDOMAIN/NODATA) entries,
and LRU recency token all live in the same shard, mutated together under
that shard's single `Mutex`. See [sharding](sharding.md) for how a
domain is routed to a shard and why this grouping matters for
concurrency.

# What's stored per entry

`RRsetEntry` (positive) and `NegativeEntry` (negative),
`src/resolver/cache/entry.rs`:

| Field | Purpose |
|---|---|
| `records` / `soa_record` + proof records | The actual RRset or negative-cache proof material. |
| `stored_at` / `expires_at` | TTL bookkeeping — `expires_at` is checked on every lookup and read-time expiry deletes the entry immediately (not just filters it out), see `Shard::lookup_hop`. |
| `dnssec_state` | RFC 6840 §3.1 validation state; stays `Unvalidated` until real DNSSEC validation exists — orthogonal to everything else in this document. |
| `dnssec_complete` | Whether this entry was populated by a fetch that actually requested DNSSEC material (DO=1). A DO=1 reader must never be served an entry where this is `false`, even if TTL-valid — see `Shard::lookup_hop`'s DO-aware filtering. |
| `authoritative` | The backend response's own AA bit, replayed on a cache hit. |
| `cache_epoch` | Cache-identity tag, compared for equality at lookup/sweep time. See [cache-epoch](cache-epoch.md) for the whole mechanism — this field is the one piece of it that lives on the entry itself. |

Unlike an earlier design, no per-entry data is keyed by the *requester's*
casing, EDNS bufsize, or flags — one entry serves every requester for
that `(domain, qtype, qclass)`; request-specific details are applied at
serve time (`cache::assemble`).

# Concurrency model, in one sentence

Every lookup and every store takes exactly one shard's `Mutex`, for the
duration of one domain-name operation only — never a global lock, never
held across an `.await`, never held across more than one hop of a
CNAME-chain walk (`Shard::lookup_hop`'s doc comment: "takes and releases
this shard's lock for the duration of this one hop only"). Concurrent
requests for different domains that hash to different shards never
contend with each other at all.

# Eviction

Per-shard LRU (`cache::lru::ShardLru`), evicted **by domain**, not by
individual record set — evicting a domain removes its positive entries,
negative entries, and LRU token together (`ShardState::evict_domain`).
Capacity is domain-count-based, configured via `CacheConfig.max_entries`,
split across shards by `CacheConfig::shard_capacity` (see
[sharding](sharding.md)).

# See also

- [cache-epoch](cache-epoch.md) — how a SIGHUP reload invalidates entries here.
- [sharding](sharding.md) — how domains route to shards, and what else shares this routing scheme.
- [local-dns-entries](local-dns-entries.md) — the separate, non-cached structure for manually-loaded
  answers.
```

### What to add

Add a new section (a natural placement is directly after "What's stored
per entry", since that section's `stored_at`/`expires_at` row is exactly
what today just says "TTL bookkeeping" and nothing more — expand on it
there, or add a new top-level `# Wire-TTL aging on read` section
immediately following it; either placement is fine as long as it sits
near that table). The new section must cover, as concrete documented
facts (not "open questions" — these are all settled, already-implemented
behaviors):

1. **Remaining-time-to-expiry, not raw origin TTL.** Cache-hit responses
   serve **remaining time to expiry** as their wire TTL, computed
   per-record by `compute_wire_ttl` (`src/resolver/cache/assemble.rs:188-204`),
   never the raw origin TTL that was stored. Cite RFC 1035 §3.2.1 as the
   conformance basis (a resolver replaying a cached RR must decrement the
   TTL by elapsed time, not repeat the original value forever).

2. **The two inputs and why `min`.** Explain `aged` (from the record's
   own origin TTL, `ttl_at_store`, decremented by elapsed time since
   `stored_at`) and `remaining` (from the entry's policy-bounded
   `expires_at` ceiling), and that the final wire value is `min(aged,
   remaining)` — whichever constraint is tighter wins.

3. **The chain-wide `expires_at` ceiling.** A CNAME chain's `expires_at`
   is computed **once**, as the minimum origin TTL across every record in
   the response, and applied identically to every hop including the
   terminal record — so a long-TTL terminal record looked up again later,
   *on its own*, is still capped by whatever chain it was first stored as
   part of. Reference the doc comment at `assemble.rs:181-187` (quoted
   above) for the design rationale: a CNAME chain combines records from
   multiple `RRsetEntry`s with different `stored_at` values, so a single
   scalar age applied to an assembled buffer can't represent it correctly
   — hence per-record aging computed directly in Rust rather than reused
   from a buffer-level `age_response_ttls`/`cap_response_ttls` helper.
   State this as a documented, tested edge case (section 03 of this
   implementation adds
   `resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup`
   covering exactly this).

4. **Negative-cache dual-aging distinction.** `write_negative_authority`'s
   per-record `compute_wire_ttl` calls (`assemble.rs:265-324` —
   wire-TTL aging, i.e. what gets sent on the wire for the SOA, its
   RRSIG, and each DNSSEC proof record) are a **different computation**
   from `NegativeEntry::dnssec_proof_material_fresh`
   (`src/resolver/cache/entry.rs:224-238` — servability gating, i.e.
   whether a DO=1 reader may be served this entry *at all*). Quote or
   paraphrase the existing doc comment on `dnssec_proof_material_fresh`
   (entry.rs:210-223): without this second check, a DO=true reader
   arriving after an individual proof record's own TTL elapsed (but
   before the overall negative TTL elapsed) would still pass the
   `dnssec_complete` gate and be served that record aged to wire TTL 0 by
   `compute_wire_ttl` — stale material silently masquerading as fresh.
   State plainly in the doc: these are two intentional, non-redundant
   mechanisms operating over the same stored fields, not a duplicate
   check.

5. **Zero/near-zero-origin-TTL-vs-floor behavior**, as a documented,
   tested edge case (section 03 adds
   `compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime`
   in `assemble.rs`): even when a `min_positive_ttl` floor extends an
   entry's actual cache lifetime (`expires_at`) well past what the
   record's own origin TTL alone would justify, `compute_wire_ttl`'s
   `aged` term still comes from the record's own `ttl_at_store` — so the
   served wire TTL correctly goes to (and stays at) 0 once the origin TTL
   has elapsed, even though the entry itself is still servable under the
   floor. State this as settled, tested behavior, not an open question.

6. **Backend-round-trip-latency freshness overstatement (one line).** A
   cache entry's `stored_at` is set from the *client request's* received
   timestamp, not the backend answer's arrival timestamp, so a cached
   entry's apparent remaining TTL is understated by roughly one backend
   round trip. Note this as pre-existing, low-severity, and **not fixed**
   by this plan — purely a documentation note.

7. **Forward-reference to Part E (do not implement here).** Add one line
   stating that this doc will need a follow-up edit, after a *separate,
   later* PR (Part E of `claude-plan.md`, the EDNS-Cookie cache
   allowlist) lands, noting that EDNS-Cookie-bearing queries become
   cache-compatible at that point (today they bypass the cache entirely
   — see `cache_supported`, `src/resolver/mod.rs:5508-5520`). Do **not**
   write that follow-up edit now; Part E is an unimplemented scoping
   document (see `claude-plan.md` E.6 and `claude-plan-tdd.md`'s
   section-split note) and is explicitly excluded from this section
   split. This section only needs the forward-reference sentence marking
   where that future edit belongs.

Keep the doc's existing style: terse, `file:line`-grounded claims,
consistent with the rest of `docs/knowledge/` (see the reproduced file
above for tone/format — short prose paragraphs, a table where a table
already exists, backtick-quoted function/file references, RFC citations
inline).

Update the file's YAML frontmatter `timestamp` field to reflect the date
this edit lands (the existing value is `2026-07-13T00:00:00Z`; use the
actual date of this change).

No other file in `docs/knowledge/` needs updating for this section — the
`docs/knowledge/resolver/caching/index.md` entry for `answer-cache.md`
already exists and its one-line description ("What the sharded DNS
answer cache stores, and its concurrency model") remains accurate; do
not add a new concept doc, this is an edit to an existing one.

## Task A.2 — Retire `docs/caching.md`

**File to modify:** `docs/caching.md`

### Why

This file describes a `CachedResponse { response_template: Vec<u8>, ... }`
type and a `serialize_cached_response` function that **no longer exist
anywhere in `src/`**. It predates the `cache_rework` effort that
introduced the current `RRsetEntry`/`ShardedDnsCache`/
`assemble_response`/`compute_wire_ttl` design and was never updated to
match. The only remaining mentions of the old names in source are code
comments/test names inside `src/resolver/mod.rs` around lines 12748 and
12809 (e.g. `/// exercises \`serialize_cached_response\`'s own truncation
check` and `// Second TCP query: cache hit, served through
\`serialize_cached_response\`.`) — these are stale comment/test-naming
artifacts referencing the old design, not live code; they do not block
this doc retirement and are out of scope to fix here (they're comments,
not behavior).

### Before editing: confirm no live non-plans references

Before replacing this file's content, grep the repo for every inbound
reference to `docs/caching.md` to confirm which are historical (safe to
leave pointing at a retired file) versus a live documentation link that
would need updating instead:

```
grep -rl 'docs/caching.md' .
```

As of this writing, every reference found is under `docs/plans/**`
(specifically: `docs/plans/cache_rework/spec.md`,
`docs/plans/cache_rework/claude-interview.md`,
`docs/plans/cache_rework/claude-plan-tdd.md`,
`docs/plans/cache_rework/claude-plan.md`,
`docs/plans/cache_rework/claude-research.md`,
`docs/plans/cache_rework/claude-spec.md`,
`docs/plans/cache_rework/claude-integration-notes.md`,
`docs/plans/cache_rework/reviews/iteration-1-codex.md`, and several
`docs/plans/cache_rework/sections/*.md` files, plus this
`ttl_remaining` plan's own docs) — all of these cite `docs/caching.md`
as historical context describing the pre-rework state *at the time those
planning docs were written*, and are fine to leave pointing at a
retired/archived file. **Re-run this grep at implementation time** in
case something has changed since this section was written, and if any
non-`docs/plans/**` live documentation link turns up, update that link
instead of assuming it's safe to leave.

### What to write

Replace `docs/caching.md`'s content with a short pointer stating:

- It is superseded by `docs/knowledge/resolver/caching/` (link to that
  directory's `index.md`) for current, accurate behavior.
- `docs/plans/cache_rework/` has the design history this file used to
  describe (the effort that replaced the `CachedResponse`/
  `serialize_cached_response` design this file documented with the
  current `RRsetEntry`/`ShardedDnsCache` design).

Do **not** delete the file outright — deleting it would break the
relative links from the historical planning docs enumerated above. Do
**not** rewrite it to match the current design in detail; that would
duplicate `docs/knowledge/resolver/caching/answer-cache.md` and the
other docs in that directory, creating two sources of truth. This is a
retirement/pointer, not a rewrite.

A minimal shape for the replacement content (adapt wording, don't copy
verbatim):

```markdown
# DNS Resolver Caching — Retired

This document described caching as implemented before the `cache_rework`
effort (a `CachedResponse`/`serialize_cached_response`-based design that
no longer exists in `src/`). It is retired and kept only so historical
links from `docs/plans/cache_rework/**` continue to resolve.

For current, accurate caching behavior, see
[docs/knowledge/resolver/caching/](knowledge/resolver/caching/index.md).

For the design history of the transition away from what this file used
to describe, see `docs/plans/cache_rework/`.
```

(Adjust the relative link path to `docs/knowledge/resolver/caching/index.md`
based on this file's actual location at `docs/caching.md` relative to
`docs/knowledge/`.)

## Verification for this section

- No `cargo fmt`/`cargo clippy`/`cargo test` gate applies — doc-only, per
  `claude-plan-tdd.md` Part A and `claude-plan.md`'s "Verification
  expectations": *"Part A: doc-only, no test/build gate beyond normal
  review."*
- Verify by human read-through of both edited files for accuracy against
  the current code (the `compute_wire_ttl`/`assemble.rs`/`entry.rs`
  references quoted above should still match the live source when you
  make the edit — re-check line numbers if the surrounding code has
  drifted since this section was written).
- Re-run the `grep -rl 'docs/caching.md' .` check described in A.2 after
  editing, to confirm no live non-`docs/plans/**` link was missed or
  broken.
- No new or changed `#[test]` functions are part of this section.

## Dependencies

None. This section does not depend on section-02 (Clock DI) or
section-03 (TTL edge-case tests) landing first, and nothing in those
sections depends on this one. All three can be implemented in any order
or in parallel.

## Note on Part E (out of scope for this section)

`claude-plan.md` Part E (EDNS-Cookie cache allowlist) is explicitly
**excluded** from this section split — it is a scoping document pending
a dedicated follow-up `/deep-plan` session, not implementation-ready
(see `claude-plan.md` E.6 and `claude-plan-tdd.md`'s section-split
note). This section's only obligation regarding Part E is item 7 above:
a single forward-reference sentence in `answer-cache.md` noting that a
future edit will be needed once Part E lands. Do not attempt to describe
Part E's design in the knowledge doc, and do not implement any of Part
E's behavior as part of this section.