# rdns Performance Bottleneck Analysis

Context: rdns is currently configured as a home-lab/personal DNS proxy
(`development_default()` hardcodes `127.0.0.1:5300`, no cache, stdout logging).
This tempers some severity ratings, but the architectural limits matter if the
codebase evolves toward higher QPS use.

---

## Finding 1 — Sequential Request Processing ⚠️ HIGH

**Location:** `delivery/dns.rs`, `serve_until` / `handle_next_datagram`

**Problem:** The server loop is `recv_from → resolver.resolve().await → send_to`.
It awaits the full resolver pipeline — including upstream network I/O — before
reading the next datagram. With a single listen address, this caps concurrent
in-flight requests (L) at 1.

**Little's Law impact:** L = λW. To serve λ = 1000 QPS at W = 50 ms average
upstream RTT, you need L = 50. The current design delivers L = 1 per server
instance. For a cache-miss-heavy workload with a 500 ms upstream timeout,
worst-case throughput per listener is ~2 QPS.

**Solution:** Spawn each request as a separate Tokio task so receive and
processing are decoupled:

```rust
let resolver = Arc::clone(&self.resolver);
let socket = Arc::clone(&self.socket); // or use a channel back to sender
tokio::spawn(async move { /* handle_datagram */ });
```

**Tradeoffs:**

- Unbounded task spawning under overload requires a `tokio::sync::Semaphore` to
  cap in-flight concurrency and implement backpressure.
- Shutdown bookkeeping becomes more complex (need a `JoinSet` inside the server
  loop).
- `UdpSocket` must be wrapped in `Arc` since it is shared across tasks for
  `send_to`.
- On Linux, `SO_REUSEPORT` already allows multiple `UdpDnsServer` instances to
  share a port, but the current config rejects duplicate listen addresses, so
  in-process parallelism for a single address requires this task-spawn approach.

---

## Finding 2 — O(n) Cache Operations Under a Global Mutex ⚠️ MEDIUM

**Location:** `resolver/mod.rs`, `InMemoryDnsCache` / `InMemoryDnsCacheState`

**Problem:** `lookup_now` and `store_now` each hold a `std::sync::Mutex` while
executing:

- `remove_expired`: full `HashMap::retain` scan — O(n) on the entire cache,
  every access.
- `compact_lru`: full `VecDeque::retain` scan — O(n) on the LRU queue, every
  access.

Under concurrency, all Tokio worker threads can pile up on this single lock
during cache scans.

**Clarification from reviewer:** The mutex is not held across `.await` points,
so the "blocking async" framing is overstated. The real problem is the O(n) work
done while holding the lock. Also: switching to `tokio::sync::RwLock` is not a
good fix because cache hits mutate LRU state (they are effectively writes), and
Tokio locks are often slower than `std::sync::Mutex` for short CPU-bound
critical sections.

**Solutions:**

- Replace the `VecDeque` ghost-entry LRU with a proper O(1) doubly-linked LRU
  (e.g. the [`lru` crate](https://docs.rs/lru)), reducing eviction to O(1).
- Replace eager `remove_expired` scans with lazy per-entry TTL checks at lookup
  time, plus a background task for periodic eviction.
- For higher concurrency, consider a sharded design (e.g. N mutexes each
  covering 1/N of the keyspace) to reduce lock contention.

**Tradeoffs:**

- Adding the `lru` crate introduces a dependency.
- Lazy expiry allows stale entries to occupy slots longer.
- Sharding increases code complexity.

---

## Finding 3 — Ephemeral UDP Socket Per Upstream Query ⚠️ MEDIUM

**Location:** `delivery/upstream.rs`, `resolve_attempt`

**Problem:** A brand-new UDP socket is created (`socket` + `bind` syscalls),
used for one query, then dropped — on every upstream call. This is measurable
overhead at scale.

**Important tradeoff from reviewer:** Reusing sockets across queries reduces
source-port entropy, which is a defense against DNS cache poisoning (RFC 5452).
Fresh ephemeral sockets are expensive but correct. Any pooling solution must
maintain randomized source ports per query.

**Solutions:**

- If pooling is used, keep a sufficiently large, rotating set of bound sockets and
  choose among them randomly; a small per-worker pool reduces source-port entropy
  to the pool size and should be treated as a security tradeoff.
- Transaction-ID-based multiplexing on a shared socket amortizes syscalls, but it
  does not preserve source-port randomization because all queries share one local
  port; pair it with multiple bound sockets if RFC 5452 entropy is required.

**Tradeoffs:** Socket pooling adds lifecycle complexity. A shared socket becomes
a single contention point unless carefully sharded.

---

## Finding 4 — Synchronous Logging on the Request Critical Path ⚠️ MEDIUM

**Location:** `main.rs`, `StdoutEvents::record`; `resolver/mod.rs`, `finish()`

**Problem:** `finish()` unconditionally awaits `self.events.record(decision.clone())`.
In the default binary, this calls `println!`, which acquires a process-wide
mutex and performs synchronous I/O — on every resolved query, on the critical
path before the response is returned.

**Reviewer clarification:** The deeper issue is architectural: the event sink is
awaited on the request path by design. Even replacing `println!` with
`tokio::io::stdout()` does not fully fix this — a slow event sink always adds to
tail latency.

**Solution:** Decouple event recording from the response path using a
`tokio::sync::mpsc` channel. The resolver enqueues events and immediately
continues; a dedicated task drains the channel and writes to the sink.

**Tradeoffs:**

- The channel must be bounded to avoid unbounded queue growth; a full channel
  must either drop events (lossy) or block the sender (which re-introduces
  latency).
- Events may be recorded slightly out of order relative to response delivery.

---

## Finding 5 — Cache Disabled by Default ⚠️ MEDIUM

**Location:** `resolver/mod.rs`, `ResolveQuery::new`; `main.rs`

**Problem:** `ResolveQuery::new()` uses `NoopDnsCache`. Every query goes to the
upstream regardless of whether the same name was just resolved. With no caching,
average W equals upstream RTT on every query — and Little's Law requires
proportionally more concurrency to achieve a given throughput.

**Reviewer correction:** "Single-flight coalescing is entirely wasted" is
inaccurate — `SingleFlightMisses` still coalesces duplicate in-flight misses
even with `NoopDnsCache`. The loss is the TTL-based hit rate that would otherwise
absorb repeated queries for the same name.

**Solution:** Default `ResolveQuery::new()` (or the binary's wiring in `main.rs`)
to `InMemoryDnsCache` with a reasonable bound (e.g., 10,000 entries). Cache hits
skip the upstream entirely, collapsing W to near-zero for hot names and
dramatically improving throughput.

**Tradeoffs:**

- Increased baseline memory usage.
- Stale entries served until TTL expiry.
- Adds cache invalidation considerations for correctness-sensitive deployments.

---

## Finding 6 — Sequential Upstream Failover ⚠️ MEDIUM

**Location:** `delivery/upstream.rs`, `resolve_with_failover`

**Problem:** When multiple upstreams are configured, failover is strictly
sequential. Upstream 1 must fully time out before upstream 2 is tried. With a
500 ms primary timeout, total failover latency is 500 ms + secondary RTT.

**Additional issue from reviewer:** The degraded health flag is recorded but
never used to change routing order. Even after repeated failures, the resolver
still starts with the failing upstream, wasting its timeout on every subsequent
query.

**Solutions:**

- Use the degraded flag to skip degraded upstreams (or move them to the back of
  the priority order) until they recover.
- "Happy eyeballs" / hedged requests: after a short delay (e.g., 100 ms), start
  a parallel query to the next upstream and use whichever responds first.

**Tradeoffs:**

- Hedged requests increase upstream load; a hedge delay needs tuning.
- Parallel fanout to all upstreams is simple but wasteful.
- Health-based routing requires a recovery probe mechanism to un-mark upstreams
  as degraded.

---

## Finding 7 — Health Tracking Mutex (INFO / Negligible)

**Location:** `delivery/upstream.rs`, `mark_success` / `mark_failure`

The reviewer assessed this as noise. The `Mutex` is held only briefly (no I/O,
no O(n) work), and switching to atomics would not meaningfully improve latency
while weakening snapshot consistency. **Recommendation: skip this change.**

---

## Priority Summary

| # | Finding | Severity | Impact |
|---|---------|----------|--------|
| 1 | Sequential request processing | HIGH | Throughput cap (L=1 per listener) |
| 4 | Event sink on request critical path | MEDIUM | Latency / tail latency |
| 5 | No cache by default | MEDIUM | Every query hits upstream (W = full RTT) |
| 6 | Sequential failover + degraded flag unused | MEDIUM | Failover latency |
| 2 | O(n) cache ops under global mutex | MEDIUM | Lock contention at scale |
| 3 | Ephemeral socket per upstream query | MEDIUM | Syscall overhead (mind port entropy) |
| — | Health mutex vs atomics | INFO | Negligible; skip |

If only one change is made, **Finding 1** (spawning requests as tasks) has the
largest impact: it allows Little's Law to work in your favour by enabling L to
grow proportionally with λ × W.
