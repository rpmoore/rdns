---
type: System
title: DNS Answer Cache
description: Sharded, in-memory cache of backend/upstream DNS answers, keyed by domain name.
resource: src/resolver/cache/mod.rs
tags: [cache, dns, resolver]
timestamp: 2026-07-15T00:00:00Z
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
    // DomainRecordSets: HashMap<(qtype, qclass), Arc<RRsetEntry>>
    positive: HashMap<domain, DomainRecordSets>,
    // DomainNegativeEntries: HashMap<NegativeKey, Arc<NegativeEntry>>
    negative: HashMap<domain, DomainNegativeEntries>,
    lru: ShardLru,
    popularity: HashMap<domain, PopularityBucket>,
}
```

Entries are stored as `Arc<RRsetEntry>`/`Arc<NegativeEntry>`
(`src/resolver/cache/entry.rs:34-40,118-122`): a cache hit hands the
entry out of `Shard::lookup_hop` as an `Arc` clone — a refcount bump
under the shard lock, not a deep copy of the records — and everything
downstream (`ChainLookup`'s chains, response assembly) reads it
immutably through the `Arc`.

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
| `stored_at` / `expires_at` | TTL bookkeeping — `expires_at` is checked on every lookup; an expired entry is served stale (within the [serve-stale](serve-stale.md) window, positive entries only), kept-but-missed (in-window but DO-filtered for *this* reader — a DO=true reader vs. `dnssec_complete == false` misses while the entry stays for DO=false readers), or deleted immediately at read time (not just filtered out), see `Shard::lookup_hop`/`stale_servability`. |
| `dnssec_state` | RFC 6840 §3.1 validation state, computed by `ResolveQuery::validate_for_store` for `ResolutionMode::Recursive` fetches (`Unvalidated`/`Insecure`/`Secure`/`Bogus`) — `Bogus` entries are additionally excluded from [serve-stale](serve-stale.md) eligibility. Currently `Unvalidated` in practice regardless of mode: `main.rs` doesn't wire trust anchors into production yet, pending a config-level enable gate (`DnssecValidationMode`, still `Disabled`-only) — otherwise orthogonal to everything else in this document. |
| `dnssec_complete` | Whether this entry was populated by a fetch that actually requested DNSSEC material (DO=1). A DO=1 reader must never be served an entry where this is `false`, even if TTL-valid — see `Shard::lookup_hop`'s DO-aware filtering. |
| `authoritative` | The backend response's own AA bit, replayed on a cache hit. |
| `cache_epoch` | Cache-identity tag, compared for equality at lookup/sweep time. See [cache-epoch](cache-epoch.md) for the whole mechanism — this field is the one piece of it that lives on the entry itself. |

Unlike an earlier design, no per-entry data is keyed by the *requester's*
casing, EDNS bufsize, or flags — one entry serves every requester for
that `(domain, qtype, qclass)`; request-specific details are applied at
serve time (`cache::assemble`).

# Wire-TTL aging on read

Cache-hit responses serve **remaining time to expiry** as their wire
TTL, computed per-record by `compute_wire_ttl`
(`src/resolver/cache/assemble.rs:245-261`), never the raw origin TTL
that was stored — per RFC 1035 §3.2.1, a resolver replaying a cached RR
must decrement the TTL by elapsed time, not repeat the original value
forever. It is called once per record, independently, from
`write_rrset` (`assemble.rs:295-343`, positive answers) and
`write_negative_authority` (`assemble.rs:345-404`, SOA + its RRSIG +
each DNSSEC proof record). Both UDP and TCP responses go through the
same `assemble_response`/`assemble_negative_response` path
(`assemble.rs:653`, `:736`) — one wire-TTL-aging code path, shared by
every transport.

`compute_wire_ttl` combines two independently-bounded quantities and
takes the tighter of the two:

- `aged = ttl_at_store - elapsed_since(stored_at)` — the record's own
  origin TTL, decremented by how long it has actually been sitting in
  the cache.
- `remaining = expires_at - now` — how much longer the cache entry
  itself is allowed to live under this resolver's TTL policy.
- Final wire value = `min(aged, remaining)`.

**Chain-wide `expires_at` ceiling.** A CNAME chain's `expires_at` is
computed once, as the minimum origin TTL across every record in the
response, and applied identically to every hop including the terminal
record — so a long-TTL terminal record looked up again later, on its
own, is still capped by whatever chain it was first stored as part of.
Per the doc comment at `assemble.rs:238-244`: a CNAME chain combines
records from multiple `RRsetEntry`s with different `stored_at` values,
so a single scalar age applied to an assembled buffer can't represent
it correctly — hence per-record aging computed directly in Rust rather
than reused from a buffer-level `age_response_ttls`/`cap_response_ttls`
helper. This edge case is covered by a regression test,
`resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup`
in `src/resolver/mod.rs:16380-16442` (see `docs/plans/ttl_remaining/` section 03).

`CacheTtlPolicy`'s bounds are operator-configurable since the
serve-stale/TTL-config change: `[cache] max_positive_ttl_secs`,
`min_positive_ttl_secs`, `max_negative_ttl_secs`, `min_negative_ttl_secs`
(`RawCacheConfig`, `src/config/mod.rs`; wired in `main.rs`,
`cache_ttl_policy_from_config`). Ceilings are capped at 30 days
(`MAX_CACHE_TTL_CEILING`) so a fat-fingered value can't overflow
`stored_at + ttl` at store time; `failure_ttl` is deliberately *not*
exposed — the sharded cache has no stored shape for a SERVFAIL, so the
knob would be inert (see the comment in `cache_ttl_policy_from_config`).
Every `[cache]` field is startup-only: a SIGHUP reload ignores changes
here. Defaults are pinned to `CacheTtlPolicy::default()` by
`cache_config_default_ttls_match_cache_ttl_policy_default` (`src/main.rs`).

An origin TTL of exactly 0 is exempt from both floors
(`apply_ttl_bounds`, `src/resolver/mod.rs`): RFC 1035 §3.2.1 / RFC 2308
§5 define TTL 0 as "this transaction only", so a floor must not lift it
into a cacheable lifetime — the entry stores already-expired and the
first lookup evicts it (pinned by
`ttl_policy_floor_does_not_lift_zero_origin_ttl`).

Even when a `min_positive_ttl` floor extends an entry's actual cache
lifetime (`expires_at`) well past what the record's own origin TTL
alone would justify, `compute_wire_ttl`'s `aged` term still comes from
the record's own `ttl_at_store` — so the served wire TTL correctly goes
to (and stays at) 0 once the origin TTL has elapsed, even though the
entry itself is still servable under the floor. Covered by a regression
test, `compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime`
in `src/resolver/cache/assemble.rs:1042-1068` (see `docs/plans/ttl_remaining/` section 03).

`write_negative_authority`'s per-record `compute_wire_ttl` calls
(`assemble.rs:345-404` — wire-TTL aging, what gets sent on the wire for
the SOA, its RRSIG, and each DNSSEC proof record) are a different
computation from `NegativeEntry::dnssec_proof_material_fresh`
(`src/resolver/cache/entry.rs:229-243` — servability gating, whether a
DO=1 reader may be served this entry at all). Without the latter check,
a DO=true reader arriving after an individual proof record's own TTL
elapsed (but before the overall negative TTL elapsed) would still pass
the `dnssec_complete` gate and be served that record aged to wire TTL 0
by `compute_wire_ttl` — stale material silently masquerading as fresh.
These are two intentional, non-redundant mechanisms operating over the
same stored fields, not a duplicate check.

Separately: a cache entry's `stored_at` is set from the client
request's received timestamp, not the backend answer's arrival
timestamp, so a cached entry's apparent remaining TTL is understated by
roughly one backend round trip — pre-existing, low-severity, not fixed
by this plan.

# EDNS Cookie interaction: per-request OPT, never cached

RFC 7873 COOKIE-bearing queries (EDNS option code 10) are cache-compatible,
provided the COOKIE option is the *only* EDNS option present:
`cache_supported` (`src/resolver/mod.rs:5670-5684`) admits a query whose
`edns.options` is either empty or passes
`edns_cookie::is_solely_cookie_option` (`src/protocol/edns_cookie.rs:144`) —
the strict predicate requiring the entire options blob to be exactly one
well-formed COOKIE option. A query carrying a Cookie *and* any other EDNS
option (e.g. NSID) still bypasses the cache exactly as before this change.
All other admission conditions (extended RCODE 0, EDNS version 0, no flags
beyond DO) are unchanged.

**Cache key never depends on cookie bytes.** Two Cookie-bearing queries for
the same `(qname, qtype, qclass)` with *different* client cookies produce an
identical lookup/`MissKey` — pinned by
`resolve_cache_lookup_key_ignores_client_cookie_bytes`
(`src/resolver/mod.rs:19621`). This is what makes "one shared cached
answer, one freshly-built OPT record per requester" (below) safe to state as
a hard guarantee rather than an incidental detail.

**The OPT pseudo-record — including any COOKIE option in it — is never
part of what's stored in or read from `RRsetEntry`/`NegativeEntry`.** It is
always rebuilt fresh per request, on both paths:

- Cache-hit: `requester_opt_record` (`src/resolver/cache/assemble.rs:517`),
  called from all four response builders in that file.
- Cache-miss/recursive: `mirrored_client_opt_record_with_cookie`
  (`src/resolver/mod.rs:1667`), threaded through
  `rebuild_recursive_response_with_own_framing`,
  `truncated_response_for_query`, and every OPT-attaching branch of
  `prepare_backend_result`. The plain, cookie-unaware
  `mirrored_client_opt_record` (`mod.rs:1642`) still backs the one call site
  that has no single requester's client IP to compute a cookie against
  (`synthesize_recursive_cname_response`, building the shared/coalescable
  backend response) and `local_entry_response`'s statically-configured local
  entries (out of scope for cookie-echoing entirely).

Both paths compute the cookie the same way — `parse_cookie_option` extracts
the client cookie, `build_server_cookie` computes a fresh RFC 9018 server
cookie from a process-lifetime `CookieSecret`, the requester's own client
IP, and the injected `Clock` (never `SystemTime::now()` directly), and
`build_cookie_option` serializes the TLV — but attach it to the wire
differently: the cache-hit path builds a plain OPT via `build_opt_record`
and then mutates the resulting `EdnsInfo.options` field in place
(`assemble.rs:524-531`), while the cache-miss path builds the options bytes
first and passes them straight into `build_opt_record_with_options`
(`src/protocol/mod.rs:1261`, called from `message_edns_opt_record_with_cookie`
at `protocol/mod.rs:1354`). Both `build_opt_record` and
`build_opt_record_with_options` delegate to the same private constructor,
`build_opt_record_with_extended_rcode` (`protocol/mod.rs:1276-1298`), so
the two paths still end up on identical wire framing outside of `options`.
Two requesters sharing one cached answer (or one coalesced in-flight
backend fetch), each
presenting a different client cookie, get their own distinct,
correctly-computed COOKIE option in their own response — the *answer data*
is shared, the OPT record never is. This is the same "request-specific
details are applied at serve time" pattern already described above in
"What's stored per entry" (casing/bufsize/flags) and in "Wire-TTL aging on
read" — cookies are just another instance of it, not an exception.

**Security trade-off — read this before assuming any anti-spoofing
protection exists.** This resolver never validates an incoming *server*
cookie's hash or timestamp window, never generates BADCOOKIE (RCODE 23), and
never rejects a query for cookie-related reasons — every query is processed
normally and every response gets a freshly-computed, valid server cookie,
unconditionally. This is one of RFC 7873's own compliant behaviors (§5.2.3/
§5.2.4 branch 3: "process the request and provide a normal response"), not a
corner cut — but it means this implementation gains **no**
anti-off-path-spoofing value from DNS Cookies. That protection comes from
the incoming-cookie validation/rejection path this implementation
deliberately does not build — see the module doc comment at
`src/protocol/edns_cookie.rs:15-21` ("never validates an incoming server
cookie's hash or timestamp") and `parse_cookie_option`
(`src/protocol/edns_cookie.rs:113-131`, whose own doc comment repeats the
same non-goal at the one function that actually reads an incoming cookie);
the full non-goals list (no BADCOOKIE, no server-cookie verification, no
secret rotation) is in
`docs/plans/edns_cookie_cache/claude-plan.md`. If you're checking whether
rdns has DNS Cookie *protection*: no — it has Cookie *echo/interop* only.

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
[sharding](sharding.md)). Internally the LRU keys its `order` BTreeSet
and `positions` reverse index on one shared `Arc<str>` per domain
(`src/resolver/cache/lru.rs:29-48`), so the per-hit `touch` is two
O(log n) BTreeSet operations plus refcount bumps with no `String`
allocations.

# Popularity tracking and auto-refresh

Each domain also has an optional `PopularityBucket` (`ShardState.popularity`,
`src/resolver/cache/shard.rs:59,170`) feeding a proactive-refresh feature that
refetches popular, near-expiry entries before a client would ever see the
miss. Full design, invariants, and file:line references:
see [auto-refresh](auto-refresh.md).

# See also

- [cache-epoch](cache-epoch.md) — how a SIGHUP reload invalidates entries here.
- [sharding](sharding.md) — how domains route to shards, and what else shares this routing scheme.
- [local-dns-entries](local-dns-entries.md) — the separate, non-cached structure for manually-loaded
  answers.
- [auto-refresh](auto-refresh.md) — proactive cache refresh for popular domains nearing TTL expiry,
  built on top of this cache's LRU/eviction lifecycle.
