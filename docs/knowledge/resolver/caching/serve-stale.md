---
type: Mechanism
title: Serve-Stale (RFC 8767)
description: >
          Expired-but-recently-cached positive answers are served
          immediately with a short fixed wire TTL while an unconditional
          background refresh refetches them, instead of costing the client
          an inline backend round trip.
resource: src/resolver/cache/shard.rs
tags: [cache, dns, resolver, serve-stale, rfc8767, refresh]
timestamp: 2026-07-16T00:00:00Z
---

Before this feature, `Shard::lookup_hop` evicted every expired entry at
read time and the client paid a full backend round trip (~95ms observed
vs ~24µs for a hit). With serve-stale, a positive entry that expired
within the configured window is served immediately — with a fixed short
wire TTL — and a background refresh is signaled unconditionally, so a
subsequent query typically gets fresh data (the refresh is asynchronous
and best-effort: it can be delayed, coalesced, dropped on a full
channel, or fail, in which case later queries keep being served stale
until one succeeds or the window ends). This is RFC 8767 behavior, and the primary
lever for keeping average-case latency low for domains whose TTL is
shorter than their query interval (which always missed before, and which
the [auto-refresh](auto-refresh.md) popularity gate structurally could
not rescue — popularity only accrues on hits).

Ships enabled by default: `CacheConfig::serve_stale_enabled = true`,
window `max_stale` = 1 day (`src/config/mod.rs`, `CacheConfig::default`).
TOML: `[cache] serve_stale_enabled` / `max_stale_secs`, the latter
validated to `(0, 7 days]` (`MAX_CACHE_STALE_WINDOW`) only while the
feature is on. `RuntimeConfig::validate` rejects
`serve_stale_enabled = true` with `[refresh] enabled = false`
(`ConfigError::ServeStaleRequiresRefresh`): the background refetch runs
on the auto-refresh worker pool, and serving stale without any way to
refresh would hand clients the same aging answer until the window ran
out. Exception: `max_entries = 0` (caching disabled) skips this check —
a zero-capacity cache can never retain an entry, so no-cache/no-refresh
configs remain valid.

# Admission: `stale_servability`

The window lives on each `Shard` (`stale_window: Option<Duration>`,
`None` = disabled), fixed at construction from `CacheConfig` — startup
only, like shard count. When a lookup probe finds a positive entry with
`expires_at <= now`, `stale_servability` (`src/resolver/cache/shard.rs`)
decides one of three outcomes:

- **`Servable`** — same `cache_epoch`, nonzero origin TTL, within
  `expires_at + window`, and passing the same DO-completeness filter a
  live hit gets. Cloned out and served; the entry *stays cached*.
- **`KeepButMiss`** — within the window but the reader is DO=true and
  the entry is `dnssec_complete = false`: a miss for this caller, but
  the entry survives, since a DO=false reader may still be stale-served
  from it (mirroring the live-path DO filter, which is also not grounds
  for eviction).
- **`Evict`** — serve-stale disabled, beyond the window, stamped with a
  stale epoch, `dnssec_state` is `Bogus` (checked first, ahead of the
  window/TTL checks below — a known-tampered response must never be
  served regardless of window or TTL state), or carrying any
  record/RRSIG whose *origin* TTL (`StoredRecord::ttl_at_store`) was 0
  (RFC 1035: TTL 0 means "this transaction only"). The TTL-0 check is
  per record, not `entry.minimum_ttl`: with a `min_positive_ttl` floor
  configured, `minimum_ttl` is the policy-bounded lifetime and is
  nonzero even for origin-TTL-0 records (PR #142 review finding).
  Non-Bogus evictions are removed at read time, byte-for-byte the
  original pre-serve-stale behavior.

Epoch equality is required even for stale service: RFC 8767 staleness is
about *time*, never about resurrecting answers a config change already
invalidated (see [cache-epoch](cache-epoch.md)).

**Negative entries are never stale-served** (v1 scope): RFC 8767 §5
flags stale negative answers — NXDOMAIN especially — as the harmful
case, so `take_live_negative` keeps the original evict-at-read behavior
unconditionally.

# Refresh signal: unconditional, no popularity gate

A stale serve sets the hop's `wants_refresh` signal to `true` directly
(`ShardState::record_hit_and_check_refresh_maybe_stale`,
`src/resolver/cache/shard.rs`), bypassing `wants_refresh`'s three-gate
formula entirely — stale data was just served, so refetching is
mandatory (RFC 8767 §4), not a popularity-gated optimization. The stale
hit still records a popularity hit (it is real client demand). From
there the signal rides the existing [auto-refresh](auto-refresh.md)
plumbing unchanged: `RefreshHint` → `CacheProbe.refresh_hints` →
`enqueue_refresh_job` → worker pool → singleflight-coalesced refetch →
re-store. `process_refresh_job`'s eligibility recheck passes naturally
for a stale job (the re-probe sees the same stale entry, whose hint is
unconditional), and duplicate jobs for the same name self-cancel at that
recheck once the first refresh lands (the entry is then live and outside
the lead window, so no hint is present).

Accepted gap: a stale CNAME hop walked on the way to a *negative*
terminal serves stale but never refreshes — `ResolvedNegative` carries
no `refresh_hints` field, so hints accumulated before the negative
terminal are dropped. Rare shape (CNAME chain into NXDOMAIN/NODATA) and
self-limiting: the hop ages out of the window and becomes a real miss.

# Wire TTL: fixed 30s, derived staleness

Records from a stale entry are written with
`STALE_WIRE_TTL_SECS = 30` (`src/resolver/cache/assemble.rs`,
RFC 8767 §4's recommended value) instead of `compute_wire_ttl`'s aged
value (which would be 0). No staleness flag threads through
`ResolvedAnswer`: an expired entry can only reach response assembly when
the lookup admitted it as a stale serve, and lookup, assembly, and
metrics classification all share one `now` (the request's received
timestamp), so `entry.expires_at <= now` *is* the staleness signal in
all three places (`write_rrset`, `chain_contains_stale` in
`src/resolver/mod.rs`). A mixed chain (live CNAME hop, stale terminal or
vice versa) ages each hop independently — live hops serve normal aged
TTLs, stale hops serve 30s.

DNSSEC note: stale RRSIGs are served as stored; signature validity
windows are absolute timestamps unaffected by TTL, so a validating
client fails closed on genuinely lapsed signatures exactly as RFC 8767
anticipates. `dnssec_state` is stamped by `ResolveQuery::validate_for_store`
(real DNSSEC validation exists as of the DNSSEC entry-wiring work) but is
currently unreachable in production — `main.rs` doesn't wire trust
anchors in yet, pending a config-level enable/disable gate
(`DnssecValidationMode`, still `Disabled`-only) — so every stored entry
is still `Unvalidated` in practice, and the `dnssec_ad_bit` AD=1 path
stays unreachable for cached entries, stale or live, until that gate
lands. Once real verdicts flow: `Bogus` entries are excluded from
serve-stale outright (see the `Evict` bullet above), so the "stale
signature that later turns out tampered" case can't be served past
expiry either way. `Secure`/`Insecure` entries' existing serve-stale
behavior is unaffected by that exclusion. Entry TTL is separately capped
at the earliest RRSIG expiration at store time
(`cap_expires_at_to_rrsig_expiration`, `src/resolver/mod.rs`), so a
`Secure` entry's `expires_at` (and thus its stale window) already
reflects signature validity — no additional inception/expiration
revalidation is needed at stale-serve time beyond what capping already
guarantees.

Refresh attempt rate under upstream failure: a failed refresh leaves the
stale entry in place, so each subsequent client query for that name
re-enqueues one refresh attempt. That backend attempt rate is bounded by
the client's own query rate for the name — identical to what the same
queries would have cost as inline misses before serve-stale existed —
and concurrent attempts still coalesce via singleflight. A per-key
refresh cooldown (RFC 8767 §5 suggests ~30s between failed-resolution
retries) is deliberately deferred until measured need.

# Observability

- `ResolverMetric::CacheStaleHit` → `cache_stale_hit_total` (main.rs):
  incremented *in addition to* `cache_hit_total`, the same
  subdivision pattern as `cache_negative_hit_total`.
- Query events record `QueryEventCacheResult::Stale` instead of `Hit`
  (including on the singleflight-follower path, which carries the
  re-probe's result through `CoalescedFollowerHit.event_cache_result`);
  `QueryEventV1::SCHEMA_VERSION` bumped 5 → 6 for the new enum value.
- Latency histograms count a stale serve as a cache hit
  (`CacheHitQueryDuration`) — answered from memory, backend deferred.

# Interaction with capacity

Stale entries keep occupying their domain's capacity slot for up to the
window, and a stale hit touches LRU recency like any hit — under
capacity pressure, a stale-but-demanded domain outlives an untouched
live one, which is the intended demand-driven ordering.

Pinning tests: `lookup_hop_serves_stale_positive_within_window_with_unconditional_refresh`
and siblings (`src/resolver/cache/shard.rs`),
`resolve_from_cache_serves_expired_entry_stale_within_window` /
`_beyond_stale_window_as_miss` (`src/resolver/cache/assemble.rs`), and
the end-to-end cycle
`resolve_serves_stale_hit_then_background_refresh_restores_freshness`
(`src/resolver/mod.rs`).
