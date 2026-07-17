# Caching

* [answer-cache](answer-cache.md) - What the sharded DNS answer cache stores, and its concurrency
  model.
* [cache-epoch](cache-epoch.md) - How a SIGHUP reload invalidates the cache instantly, without a
  stop-the-world clear.
* [sharding](sharding.md) - How the cache is split into independently-locked shards, and what
  does/doesn't share that sharding scheme.
* [local-dns-entries](local-dns-entries.md) - Why manually-loaded DNS data is not in this cache at
  all, and what that means for reload invalidation.
* [auto-refresh](auto-refresh.md) - Proactive cache refresh for popular domains nearing TTL expiry:
  popularity tracking, the trigger formula, and the background worker pool.
* [serve-stale](serve-stale.md) - RFC 8767: expired-but-recently-cached positive answers served
  immediately (30s wire TTL) with an unconditional background refresh.
* [delegation-cache](delegation-cache.md) - Recursive mode's zone-cut cache (learned NS/glue
  endpoints): lazy expiry, sequence-stamped FIFO eviction, bounded slot queue.
