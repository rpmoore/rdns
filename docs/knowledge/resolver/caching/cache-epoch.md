---
type: Mechanism
title: Cache-Identity Epoch
description: How a SIGHUP reload invalidates the whole answer cache instantly, without a stop-the-world lock.
resource: src/resolver/mod.rs
tags: [cache, dns, resolver, epoch, invalidation, sighup]
timestamp: 2026-07-13T00:00:00Z
---

Every [answer-cache](answer-cache.md) entry carries a `cache_epoch: u64`.
A reload that actually changes resolution-affecting config bumps a
single global counter; every entry stamped with an older epoch becomes
an instant miss to every future lookup, with no scan, no per-entry
tagging pass, and no lock held over the whole cache.

# What triggers a bump

`Config::backend_cache_namespace()` (`src/config/mod.rs:223`) builds a
descriptive fingerprint string once per reload — **not** stored per
entry, only used to decide whether to bump:

- Forward mode: `mode:forward;generation:{n};upstreams:{hash}` — the
  hash covers name/endpoint/protocol/priority/timeout of every enabled
  UDP upstream.
- Recursive mode: `mode:recursive;generation:{n};root-hints:{version};dnssec:{label};authorities:{hash}`.
- `generation` is an operator-set integer (`ResolutionConfig::generation`)
  — bumping it by itself is the manual "flush everything" lever, with no
  other config change required.

`next_cache_epoch` (`src/resolver/mod.rs:2290`) compares this reload's
fingerprint against the previous one:

```rust
fn next_cache_epoch(previous: &BackendSnapshot, new_snapshot: &BackendSnapshot) -> u64 {
    if previous.cache_namespace == new_snapshot.cache_namespace {
        previous.cache_epoch
    } else {
        previous.cache_epoch.wrapping_add(1)
    }
}
```

A reload that changes something the fingerprint doesn't cover (logging
config, metrics, `RuntimeConfig::per_query_deadline` — see caveat below)
leaves the fingerprint identical, so the epoch does **not** bump and the
entire cache stays warm.

**The bump is whole-cache, not partial.** There is one global epoch
counter, compared for equality against every entry regardless of domain,
qtype, or which specific upstream/setting actually changed. There is no
per-domain or per-upstream granularity — any resolution-affecting change
invalidates everything. This was true of the pre-epoch string-namespace
design too; this mechanism didn't change that scope, only how cheaply
it's checked.

# Where the epoch lives

`BackendSnapshot.cache_epoch` (`src/resolver/mod.rs:2229`), published
together with the backend `Arc` and the descriptive `cache_namespace`
string under the same `reload_gate` write section — never read or
mutated independently of the snapshot it belongs to. This matters: if
the epoch were a free-standing `AtomicU64`, a request could pair an old
backend with a new epoch (or vice versa) depending on read timing. Tying
it to `BackendSnapshot` makes backend-and-epoch tearing structurally
impossible.

# The two publishers

Both go through `next_cache_epoch`, so neither can accidentally roll the
epoch backwards or diverge from the other's rule:

- **`publish_reload`** (`src/resolver/mod.rs:3521`) — the SIGHUP path.
  Swaps backend + local entries atomically under `reload_gate`, computes
  the new epoch, then — **only if the epoch actually changed** — runs
  `cache.sweep_stale_namespace(new_epoch)` *after* releasing
  `reload_gate`. Skipping the sweep on an unrelated reload is a real
  optimization over the old string-namespace design, which swept
  unconditionally on every reload.
- **`publish_backend_snapshot`** (`src/resolver/mod.rs:3466`) — a
  backend-only publisher (health-check-driven failover, tests). Applies
  the same epoch math, but never sweeps — stale entries are still
  instantly invisible at lookup time; sweeping just gets deferred to
  whenever `publish_reload` next runs.

# What "instant invalidation" actually means

The sweep is pure memory reclamation, not what makes stale entries
unreachable. `Shard::lookup_hop` (`src/resolver/cache/shard.rs:405`)
checks `entry.cache_epoch == current_epoch` on every single lookup — the
moment a new `BackendSnapshot` is published, every entry under the old
epoch fails that check for every subsequent lookup, even though it may
still physically occupy a slot for a while. The sweep just reclaims that
memory in bulk later; it is never a prerequisite for correctness.

`sweep_stale_namespace` (`src/resolver/cache/namespace.rs`, per-shard
logic in `src/resolver/cache/shard.rs:472`) is an O(n) walk across every
shard's positive/negative maps, retaining only entries whose
`cache_epoch` matches. It runs with each shard's own lock, one shard at a
time — never a single lock over the whole cache — and, per
`publish_reload`'s doc comment, runs after `reload_gate` is released so
it can't stall concurrent `resolve()` calls for its duration.

# Per-request pinning: why in-flight requests don't tear

`ResolveQuery::resolve` (`src/resolver/mod.rs:3649`) captures its
`backend_snapshot` **once**, at the top of the request, under
`reload_gate`'s read side (`:3652-3658`), and carries that same snapshot
— mode, generation, and epoch together — through the entire request,
including any store it does at the end. This wasn't introduced for the
epoch specifically; it's the pre-existing pattern that already kept
`mode`/`generation` from tearing mid-request.

Consequence: a request already in flight when a reload happens keeps
using its captured (now-old) epoch to completion — its lookups still
match old-epoch entries, and if it stores a fresh answer, that answer is
stamped with the *old* epoch too. That store is not wrong, just wasted:
it's instantly invisible to anyone else once the new epoch is live,
since their own `self.backend.current()` call already returns the bumped
snapshot. A request that captures its snapshot *after* the reload
publishes sees the new epoch immediately and treats every old-epoch
entry as a miss.

There is no draining, barrier, or "wait for old-epoch readers to
finish" — in-flight requests simply run to completion on their own (DNS
resolves are short-lived), each internally consistent with whatever
snapshot it started with.

# The miss-coalescing path also keys on epoch

`MissKey` (`src/resolver/cache/singleflight.rs:73`):
`(qname, qtype, qclass, cache_epoch, dnssec_ok)`. Epoch **must** be part
of this key — otherwise a request that misses just after a reload could
coalesce onto an in-flight fetch that started before the reload, and get
served a stale-generation response resolved under the old epoch.

# Why not just swap in a brand-new empty cache instead?

Both approaches make every old entry an instant miss; the difference is
in the machinery, not client-visible behavior. Epoch tagging was chosen
because:

- The cache object itself (`ResolveQuery.cache: Arc<dyn DomainDnsCache>`,
  `src/resolver/mod.rs:3289`) is fixed for the process's lifetime — only
  `backend` and `local_entries` are behind a swappable, `reload_gate`-guarded
  pointer. Making the cache swappable too would add a lock on every
  single lookup, permanently, to support something that happens rarely
  (an actual generation bump).
- Reclaiming old entries costs the same O(n) either way — dropping a
  whole old cache still has to free every entry. The sweep does that
  work under the shard locks lookups/stores already use, and skips
  entirely when nothing changed; a whole-cache swap would need the same
  skip-if-unchanged logic to avoid needlessly cold-starting on harmless
  reloads.
- A request that grabbed a reference to an old, wholesale-swapped cache
  before the swap would keep storing into a structure nobody will ever
  read from again. Epoch-tagged stores into the one shared structure are
  at least reusable if their epoch happens to still be current.

# Caveats (pre-existing, not introduced by this mechanism)

- `RuntimeConfig::per_query_deadline` is not part of the fingerprint —
  a SIGHUP that only changes it can change whether a query now times out
  to SERVFAIL, without bumping the epoch. Answers cached under the old
  deadline remain addressable.
- Local DNS entry changes never touch the epoch at all — see
  [local-dns-entries](local-dns-entries.md) for why, and for the one
  surfaced edge case (removing a local entry can un-shadow an old cached
  backend answer rather than guarantee a fresh lookup).
- Invalidating cached *positive* answers on an upstream-set change is a
  conservative operational choice, not something plain DNS TTL semantics
  strictly requires — but it's intentional, load-bearing for
  split-horizon/filtering setups, and unchanged by this mechanism.
- A request that captured the previous, epoch-changing snapshot can still
  be in flight when that reload's sweep runs, and store an old-epoch entry
  *after* the sweep already passed. Not a correctness issue (an epoch
  mismatch is still an unconditional miss at lookup time), but a run of
  subsequent same-namespace reloads won't sweep it away either — only the
  next actual epoch-changing reload's sweep will, since it removes anything
  not matching its new epoch. Until then it sits invisible, occupying one
  domain slot, reclaimed eventually by ordinary LRU pressure.
- Two independently-constructed `BackendSnapshot`s (e.g. via
  `BackendSnapshot::new` directly, never linked through one
  `ResolverHandle`'s `publish_reload`/`publish_backend_snapshot`) both
  start at `cache_epoch: 0` — safe only because production always has
  exactly one long-lived `ResolverHandle` observing backend changes
  relative to its own previous snapshot. Sharing one `ShardedDnsCache`
  across two independently-built snapshots would collide at epoch 0
  regardless of `generation`; see
  `backend_generation_separates_cache_entries` in `resolver/mod.rs`.

# See also

- [answer-cache](answer-cache.md) — where `cache_epoch` lives on the entry.
- [sharding](sharding.md) — the sweep walks shards one lock at a time; this is where that structure is described.
