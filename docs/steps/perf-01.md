# Performance 01 Remediation Steps

Source review: [`docs/review/perf-01.md`](../review/perf-01.md)

## Scope

Resolve the performance bottlenecks that can be fixed without weakening DNS
correctness or cache-poisoning defenses:

1. Decouple UDP receive from request resolution for a single listener.
2. Move query-event recording off the response critical path.
3. Enable the in-memory TTL cache in the binary's default resolver wiring.
4. Use degraded upstream health to avoid repeatedly starting with failing
   upstreams.
5. Remove eager whole-cache expiry scans from normal cache lookup/store paths.

Do not implement UDP upstream socket pooling in this pass. The current
fresh-ephemeral-socket behavior is expensive but preserves source-port entropy.
Document the tradeoff and leave pooling for a later design that explicitly
maintains RFC 5452 entropy.

Do not replace the upstream health mutex with atomics. The review marks it as
negligible and the current critical section is small.

## Step 1: Concurrent UDP Listener Handling

Files:

- `src/delivery/dns.rs`
- `tests/forwarding.rs`

Implementation:

1. Change `UdpDnsServer` to store `Arc<UdpSocket>` so the receive loop can share
   the socket with response tasks.
2. Add a bounded in-flight request limit using `tokio::sync::Semaphore`.
   Start with a conservative default constant in `delivery::dns` rather than
   changing public configuration.
3. Acquire an owned semaphore permit before `recv_from`, inside a
   shutdown-aware `tokio::select!`. This applies socket/kernel backpressure when
   saturated and avoids receiving a datagram before the server can process it.
4. After a datagram is received, spawn a task that owns the permit, calls the
   resolver, and sends the response. All task captures must be owned or
   `'static` (`Arc<UdpSocket>`, `Arc<ResolveQuery>`, copied sizes, and owned
   request bytes).
5. Track spawned tasks in a `JoinSet`. Poll the `JoinSet` while serving so
   completed task results do not accumulate and task failures are surfaced
   promptly.
6. During graceful shutdown, stop accepting new datagrams and drain in-flight
   tasks according to the same task-result error policy.

Tests:

1. Add a UDP server test with a deliberately delayed resolver response. Send two
   queries from separate clients and assert the second response is not blocked
   behind the first.
2. Add a shutdown-with-in-flight test that verifies the selected drain behavior.
3. Keep existing forwarding and graceful-shutdown tests passing.

## Step 2: Non-Blocking Query Event Recording

Files:

- `src/resolver/mod.rs`
- `src/main.rs`

Implementation:

1. Add a `ChannelQueryEventSink` wrapper that owns a bounded
   `tokio::sync::mpsc::Sender<ResolveDecision>`.
2. Make `record` use `try_send` and return immediately. Dropping newest events
   on a full channel is acceptable for this pass because blocking would
   reintroduce request-path latency.
3. Add a spawned drain task in `main.rs` that receives decisions and forwards
   them to `StdoutEvents`.
4. Keep the existing `QueryEventSink` trait shape so resolver tests and custom
   sinks do not need a wide refactor.
5. Add a small test proving `ChannelQueryEventSink::record` returns promptly
   when the channel is full.
6. Give the drain task an explicit shutdown contract. Either drop all sender
   clones before awaiting it, or intentionally abandon it and document why
   flushing is not part of binary shutdown.

Tests:

1. Unit-test accepted and dropped channel behavior.
2. Existing resolver tests should remain valid because direct test sinks still
   implement `QueryEventSink`.

## Step 3: Enable Default TTL Cache In The Binary

Files:

- `src/main.rs`
- `src/resolver/mod.rs`

Implementation:

1. Add a named default cache capacity constant, initially `10_000` entries.
2. Wire `main.rs` through `ResolveQuery::with_cache` using
   `InMemoryDnsCache::new(DEFAULT_CACHE_ENTRIES)` and
   `CacheTtlPolicy::default()`.
3. Leave `ResolveQuery::new` as a no-cache constructor to preserve test and
   library compatibility unless all call sites clearly expect the production
   default.

Tests:

1. Add or adjust a binary wiring test only if the codebase already has a
   practical seam for it.
2. Rely on existing resolver cache tests for cache correctness.

## Step 4: Health-Aware Upstream Ordering

Files:

- `src/delivery/upstream.rs`
- `tests/forwarding.rs`

Implementation:

1. Keep the configured priority order for healthy upstreams.
2. For each request, build an attempt order where non-degraded upstreams come
   first and degraded upstreams are moved to the back.
3. Preserve original upstream indices when marking success or failure; the
   reordered attempt position must never be used as the health index.
4. Continue trying degraded upstreams if all healthy upstreams fail or no
   healthy upstreams remain. A degraded upstream only recovers after it is
   actually attempted successfully; this pass does not add background probes or
   hedged recovery.
5. Preserve the existing per-query deadline and per-upstream timeout behavior.

Tests:

1. Add a unit test that marks the primary degraded after repeated timeout or
   malformed-response failures, then verifies the next resolution attempts the
   secondary first.
2. Add a recovery test showing a degraded upstream can be marked healthy again
   after it is later attempted and succeeds.
3. Add a test showing a degraded primary does not recover merely because a
   healthy secondary succeeds.

## Step 5: Lazy Cache Expiry And LRU Cleanup

Files:

- `src/resolver/mod.rs`

Implementation:

1. Remove eager `remove_expired` scans from every `lookup_now` and `store_now`.
2. On lookup, check only the requested key. If it is expired, remove that key
   and return `CacheLookup::Expired`.
3. On store, remove or ignore only the key being stored if the new entry is
   immediately expired.
4. Keep LRU metadata bounded. Prefer an occasional threshold-triggered
   compaction over a full scan on every access unless a proper O(1) LRU
   structure is introduced.
5. Add a maintenance method for tests or future background cleanup, but do not
   spawn a cache maintenance task in this pass unless it is needed to preserve
   size bounds.

Tests:

1. Update expiry tests so looking up one expired key does not require scanning
   and removing unrelated expired keys.
2. Keep LRU eviction tests proving fresh entries remain bounded.
3. Keep zero-capacity behavior unchanged.
4. Add a test that repeated hits cannot grow LRU metadata without bound under
   the selected cleanup strategy.

## Step 6: Upstream Socket Pooling Deferred

Files:

- `docs/steps/perf-01.md`

Implementation:

1. Leave `resolve_attempt` binding a fresh ephemeral UDP socket per query.
2. Record in this plan that pooling needs a separate design for randomized
   source-port entropy, pool sizing, lifecycle, and contention.

Tests:

1. No code tests in this pass.

## Verification

Run:

```sh
cargo fmt
cargo test
```

Optional manual/perf checks after tests pass:

1. Compare two concurrent client queries against a delayed fake upstream to
   confirm responses can complete independently.
2. Exercise repeated primary-upstream timeouts and verify later requests start
   with the healthy secondary until the primary recovers.
