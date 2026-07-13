# Caching

* [answer-cache](answer-cache.md) - What the sharded DNS answer cache stores, and its concurrency model.
* [cache-epoch](cache-epoch.md) - How a SIGHUP reload invalidates the cache instantly, without a stop-the-world clear.
* [sharding](sharding.md) - How the cache is split into independently-locked shards, and what does/doesn't share that sharding scheme.
* [local-dns-entries](local-dns-entries.md) - Why manually-loaded DNS data is not in this cache at all, and what that means for reload invalidation.
