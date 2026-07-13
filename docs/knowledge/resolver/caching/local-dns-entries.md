---
type: System
title: Local DNS Entries
description: Manually-loaded DNS data (BIND zone files, config TOML), and why it's not in the answer cache at all.
resource: src/resolver/mod.rs
tags: [cache, dns, resolver, local-entries]
timestamp: 2026-07-13T00:00:00Z
---

Manually-loaded DNS data — BIND zone files, `[[local_dns_entries]]` in
the config TOML — never enters the [sharded answer cache](answer-cache.md)
at all. It's a completely separate structure with its own, much simpler
invalidation story: an atomic pointer swap, no per-entry tagging, no
sweep, no [epoch](cache-epoch.md).

# Structure

`LocalDnsEntriesHandle` (`src/resolver/mod.rs:2332`), backed by a
`LocalDnsEntries` trait implementation swapped wholesale on reload —
there's no `RRsetEntry`/`NegativeEntry` involved, no shard, no TTL
expiry loop. `publish_reload` replaces the whole thing in one atomic
write, under the same `reload_gate` section as the backend snapshot.

# Where it's checked

`ResolveQuery::resolve` calls `try_local_lookup`
(`src/resolver/mod.rs:3829`) **before** `probe_cache`
(`src/resolver/mod.rs:4200`) — a local match short-circuits the request
entirely; the sharded answer cache is never consulted for it, and a
local answer is never stored there either.

# Why this matters for the epoch mechanism

[cache-epoch](cache-epoch.md) exists purely to invalidate
backend/upstream-derived answers — the only thing actually stored in the
sharded cache. Local entries don't need it: they're checked first, from
a structure that's already fully replaced on every reload, so there's
nothing stale to invalidate by the time a request would fall through to
the epoch-gated cache.

# The one edge case this creates

Local entry changes never touch `cache_epoch` — correct for the local
answers themselves, but it means removing a local entry can surface a
stale cached *backend* answer: if a name was resolved and cached before
a local entry for it existed, then that local entry is later removed,
`try_local_lookup` stops shadowing the name and the next query falls
through to `probe_cache` — which may still hold the old, unexpired
backend-cache entry from before the local override existed. Removing a
local entry can un-shadow an old cached answer rather than guarantee a
fresh lookup for that name.

# See also

- [answer-cache](answer-cache.md) — the structure this document is contrasted with.
- [cache-epoch](cache-epoch.md) — the invalidation mechanism that only applies to the other structure.
