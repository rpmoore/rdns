# Bundle Update Log

## 2026-08-10
* **Creation**: Added the `delivery/` area and documented the
  [DNS TCP listener](delivery/tcp-listener.md) — connection limits, framing,
  timeouts, oversized-response fallback, and shutdown — while reconciling
  Milestone 11 of the roadmap against open GitHub issues and the code.

## 2026-07-13
* **Initialization**: Created the bundle root and `resolver/` area.
* **Creation**: Documented the sharded answer cache — [overview](resolver/caching/answer-cache.md),
  [cache-identity epoch](resolver/caching/cache-epoch.md),
  [sharding](resolver/caching/sharding.md),
  and the [local DNS entries boundary](resolver/caching/local-dns-entries.md).
