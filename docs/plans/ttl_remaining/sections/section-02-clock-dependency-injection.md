# Section 02: Clock Dependency Injection

## Implementation status: DONE

Implemented as planned, with one correction made during code review to
tests 2/3 ("Tests first" list below):

- The plan's items 2/3 called for unit tests asserting the exact
  `ResolveRequest.received_at` value via `QueryEventV1`. Investigation
  during review found `QueryEventV1.timestamp` is populated from the
  *resolver's own* internal clock (`self.clock.now()` at query-finish
  time, `mod.rs:5176`) — a separate `Clock` instance from the one
  threaded through the transport in this section — not from
  `request.received_at.0`. Asserting against it would have exercised the
  wrong clock and could pass or fail for reasons unrelated to this
  section's actual wiring.
- Fixed by testing the transport's clock the same way
  `tests/clock_injection.rs` (item 4) does, but scoped per-transport at
  the unit level: `handle_datagram_uses_injected_clock_for_cache_ttl_aging`
  (UDP) and `serve_tcp_connection_uses_injected_clock_for_cache_ttl_aging`
  (TCP), both added in `src/delivery/dns.rs`'s test module. Each wires a
  real `ShardedDnsCache` (not `NoopDnsCache`) and a new `AdvanceableClock`
  test fixture (atomic-backed, mutable in place — a fourth `Clock` shape
  beyond the three precedents listed below, needed because the test must
  advance time between two live queries) shared between the resolver and
  the transport, sends two live queries, and asserts the served wire TTL
  ages by exactly the clock's advance — provable only if the transport
  reads the injected clock, not `SystemTime::now()`.
- This also gives the TCP path its own regression coverage: the
  `tests/clock_injection.rs` e2e test (item 4) only drives UDP.

All files list below was implemented as scoped; `cargo fmt`/`clippy`/
`test` all pass (569 lib tests, up from 567 pre-section).

## Dependencies

None. This section is independent of section-01 (documentation) and
section-03 (new regression tests) — it touches only `src/delivery/dns.rs`,
`src/main.rs`, and their existing test/call sites. It can be implemented in
parallel with the other two sections.

## Background

`rdns` is a Rust DNS resolver/proxy (Tokio async). This repo already has a
`Clock` dependency-injection trait:

```rust
// src/resolver/mod.rs:7758-7760
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}
```

It is already used, but only for query-duration metrics (`started_at`/
`finished_at`, read at `mod.rs:3739` and `:5176` via `self.clock.now()`
inside `ResolveQuery`). `ResolveQuery` (`mod.rs:3341`) already holds a
`clock: Arc<dyn Clock>` field, constructed once in `src/main.rs:129-148` as
`Arc::new(SystemClock)` (the `SystemClock` unit struct and its `Clock` impl
live at `main.rs:740-746`):

```rust
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
```

and passed into `ResolveQuery::with_cache_policy_and_backend_snapshot`
(`main.rs:129-148`, currently `Arc::new(SystemClock)` inline at line 138).

The value that actually seeds TTL aging — `ReceivedAt(SystemTime)`
(`mod.rs:93`), which becomes `request.received_at.0` and flows into both
`store_cache_response`'s `stored_at` (`mod.rs:5095-5119`) and every
cache-lookup path — is **not** sourced from this `Clock`. It comes from two
raw `SystemTime::now()` calls at the transport edge:

- `src/delivery/dns.rs:262` — inside `handle_datagram`, feeding
  `ResolveRequest::new_with_observed_source`, UDP path.
- `src/delivery/dns.rs:620` — inside `serve_tcp_connection`, same
  constructor call, TCP path.

Current code at those two sites (for exact context):

```rust
// dns.rs:252-270, handle_datagram
async fn handle_datagram(
    socket: Arc<UdpSocket>,
    resolver: Arc<ResolveQuery>,
    listener: Option<SocketAddr>,
    datagram: ReceivedDatagram,
) -> io::Result<()> {
    let _permit = datagram.permit;
    let outcome = resolver
        .resolve(ResolveRequest::new_with_observed_source(
            ObservedSourceEndpoint::udp(datagram.source, listener),
            SystemTime::now(),
            datagram.request_bytes,
        ))
        .await;
    socket
        .send_to(&outcome.response_bytes, datagram.source)
        .await
        .map(|_| ())
}
```

```rust
// dns.rs:553-623, serve_tcp_connection (relevant excerpt)
async fn serve_tcp_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    listener: SocketAddr,
    resolver: Arc<ResolveQuery>,
) -> io::Result<()> {
    loop {
        // ... read length-prefixed message ...
        let outcome = resolver
            .resolve(ResolveRequest::new_with_observed_source(
                ObservedSourceEndpoint::tcp(peer_addr, Some(listener)),
                SystemTime::now(),
                message,
            ))
            .await;
        // ...
    }
}
```

Two other raw `SystemTime::now()` sites exist nearby but are confirmed
**out of scope for this section**: `src/delivery/upstream.rs:296,640` and
`src/resolver/mod.rs:7244,7266` (inside `evaluate_authority_response`) feed
a different struct field (`ResolutionResponse::received_at`, populated by
`forwarded_bytes`/`forwarded_message`/`recursive_response` constructors)
that is never read by anything — only `request.received_at.0` (the
client-request timestamp) reaches the cache. Confirmed by grep: all 5 uses
of `request.received_at.0` are at `mod.rs:4440, 4555, 4574, 4595, 5107`.
Do not touch `upstream.rs:296,640` or `mod.rs:7244,7266`.

This is a **pure refactor**: `SystemClock::now()` wraps `SystemTime::now()`
identically, so production timing behavior must be unchanged. The goal is
only to make `now` injectable for tests, not to change what value is used
in production.

## Goal

`handle_datagram` and `serve_tcp_connection` obtain `now` from an injected
`Arc<dyn Clock>` instead of calling `SystemTime::now()` directly, so tests
can inject a fake clock and drive the whole receive → cache-store →
cache-read pipeline deterministically.

## Tests first

Write/verify these before or alongside touching `UdpDnsServer`/
`TcpDnsServer`/`main.rs` (per this repo's TDD convention, `RUST.md`'s
fmt/clippy/test gates apply once each is filled in):

1. **Compile-level check (not a runtime assertion):** every constructor of
   `UdpDnsServer`/`TcpDnsServer` compiles with a new `clock: Arc<dyn Clock>`
   parameter, and every existing call site (list in "Call sites to update"
   below, including `tests/forwarding.rs`, `tests/support/mod.rs`, and the
   in-module `src/delivery/dns.rs` tests) is updated to pass one. `cargo
   build` and `cargo test` must both succeed after these updates — this is
   the acceptance bar for this check, not a new `#[test]` function.

2. **`handle_datagram` uses the injected clock** — a test that constructs
   the UDP path with an injected `FixedClock` holding a known `SystemTime`
   and asserts the resulting `ResolveRequest`'s `received_at` matches that
   fixed value **exactly** (not just "close to now"). Place this alongside
   `dns.rs`'s existing in-module UDP tests, following the existing
   `FixedClock(SystemTime)` pattern already at `dns.rs:755-761` (see
   "FixedClock precedent" below).

3. **Same assertion for `serve_tcp_connection`** (TCP path) — mirror test
   2 but drive it through the TCP constructor/connection path instead.

4. **New file under `tests/`** — a live, end-to-end black-box test named
   something like `clock_injection_ages_cache_hit_ttl_end_to_end`. Write
   this test **first**; it should fail against the *current*
   raw-`SystemTime::now()` code (there is no way to inject a fixed time
   yet) and pass once this section's wiring lands. It must:
   - Construct a `UdpDnsServer` (following whatever `tests/forwarding.rs`
     already sets up for its own black-box resolver tests: see
     `resolver_from_config`/`run_server`/`send_query` helpers at
     `tests/forwarding.rs:96-136`) with an injected `FixedClock`
     (unit-struct style, per `tests/forwarding.rs:30-36`'s precedent)
     wired through the new `clock` parameter.
   - Send a request that causes a cache store.
   - Advance the injected clock — construct a second `FixedClock` instance
     with a later `SystemTime`, or introduce a mutable-clock variant if
     that's cleaner given `Clock`'s immutable `&self` signature. Decide
     during implementation whether a `Cell<SystemTime>`-backed fake clock
     is needed to represent time advancing *within* one test, since every
     existing `FixedClock` variant in this repo is single-value and
     doesn't mutate (see the three existing shapes below — none of them
     support advancing time in place).
   - Send a second request for the same query and assert the served TTL
     has aged by the expected amount, driven entirely through the live
     transport path (socket → `handle_datagram` → resolver → cache →
     `assemble_response`) rather than by hand-constructing `now`/
     `stored_at` values as the existing unit/e2e tests do.
   - This closes a real coverage gap: every existing test in this codebase
     constructs `now`/`stored_at` by hand; none drives the actual
     transport-to-cache pipeline with an injected clock end-to-end.

### FixedClock precedent to follow

Do not invent a fourth shape. This repo already has three slightly
different `FixedClock` patterns in tests — pick whichever fits the file a
given new test lands in:

- `src/resolver/mod.rs:7999-8005`: `struct FixedClock(SystemTime)`, returns
  the stored value.
- `src/delivery/dns.rs:755-761`: same shape, local to that test module:
  ```rust
  struct FixedClock(SystemTime);

  impl Clock for FixedClock {
      fn now(&self) -> SystemTime {
          self.0
      }
  }
  ```
- `tests/forwarding.rs:30-36`: `struct FixedClock;` (unit struct), always
  returns `SystemTime::UNIX_EPOCH`, imported via `rdns::resolver::Clock`
  and passed through the public API — a true black-box injection, not a
  `#[cfg(test)]`-internal fixture:
  ```rust
  struct FixedClock;

  impl Clock for FixedClock {
      fn now(&self) -> SystemTime {
          SystemTime::UNIX_EPOCH
      }
  }
  ```

For the new B.4/section-02 e2e test (item 4 above), use the unit-struct,
black-box style (`tests/forwarding.rs`'s), since the new test lives under
`tests/` and must exercise the public API only.

## Implementation

### Files to modify

- `src/delivery/dns.rs`
- `src/main.rs`
- `tests/forwarding.rs`
- `tests/support/mod.rs`
- New file under `tests/` (e.g. `tests/clock_injection.rs`) for the e2e
  test.

### `UdpDnsServer` changes (`src/delivery/dns.rs`)

Current struct and constructors (`dns.rs:117-170`):

```rust
pub struct UdpDnsServer {
    socket: Arc<UdpSocket>,
    resolver: Arc<ResolveQuery>,
    listener: Option<SocketAddr>,
    max_request_size: usize,
    max_in_flight_requests: usize,
}

impl UdpDnsServer {
    pub fn new(socket: UdpSocket, resolver: Arc<ResolveQuery>, max_request_size: usize) -> Self { ... }

    pub fn with_max_in_flight_requests(
        socket: UdpSocket,
        resolver: Arc<ResolveQuery>,
        max_request_size: usize,
        max_in_flight_requests: usize,
    ) -> Self { ... }

    pub async fn bind(
        address: SocketAddr,
        resolver: Arc<ResolveQuery>,
        max_request_size: usize,
    ) -> io::Result<Self> { ... }

    pub async fn bind_configured(
        config: &RuntimeConfig,
        resolver: Arc<ResolveQuery>,
    ) -> io::Result<Vec<Self>> { ... }
}
```

Changes:

- `UdpDnsServer` (`dns.rs:117-123`) gains a `clock: Arc<dyn Clock>` field
  alongside its existing `socket`/`resolver`/`listener`/`max_request_size`/
  `max_in_flight_requests` fields.
- Every public constructor that currently takes `resolver: Arc<ResolveQuery>`
  gains a parallel `clock: Arc<dyn Clock>` parameter, threaded the same way
  `resolver` already is, down to the lowest-level constructor
  (`with_max_in_flight_requests`). This includes `new`, `bind`, and
  `bind_configured`.
- `spawn_datagram_task` (`dns.rs:238-243`) clones `self.clock` the same way
  it already clones `self.resolver`, and passes it into `handle_datagram`.
- `handle_datagram` (`dns.rs:252-270`) takes a new `clock: Arc<dyn Clock>`
  parameter and calls `clock.now()` instead of `SystemTime::now()` at
  line 262.
- Add `use crate::resolver::Clock;` to `dns.rs`'s import block (currently
  `use crate::resolver::{ObservedSourceEndpoint, ResolveQuery, ResolveRequest};`
  at `dns.rs:31`) so `Clock` is in scope.

### `TcpDnsServer` changes (`src/delivery/dns.rs`)

Current struct and constructors (`dns.rs:285-376`, `456-474`, `553-623`):

```rust
pub struct TcpDnsServer {
    listener: TcpListener,
    resolver: Arc<ResolveQuery>,
    local_addr: SocketAddr,
    max_connections: usize,
    max_connections_per_ip: usize,
    shutdown_grace_period: Duration,
}

impl TcpDnsServer {
    pub async fn bind(address: SocketAddr, resolver: Arc<ResolveQuery>) -> io::Result<Self> { ... }

    pub async fn bind_with_max_connections(
        address: SocketAddr,
        resolver: Arc<ResolveQuery>,
        max_connections: usize,
    ) -> io::Result<Self> { ... }

    async fn bind_with_options(
        address: SocketAddr,
        resolver: Arc<ResolveQuery>,
        max_connections: usize,
        max_connections_per_ip: usize,
        shutdown_grace_period: Duration,
    ) -> io::Result<Self> { ... }

    pub async fn bind_configured(
        config: &RuntimeConfig,
        resolver: Arc<ResolveQuery>,
    ) -> io::Result<Vec<Self>> { ... }

    fn spawn_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        permit: OwnedSemaphorePermit,
        per_ip_guard: PerIpConnectionGuard,
        tasks: &mut JoinSet<()>,
    ) { ... }
}
```

Changes:

- `TcpDnsServer` (`dns.rs:285-292`) gains the same `clock: Arc<dyn Clock>`
  field alongside its existing fields.
- Every public constructor gains a parallel `clock: Arc<dyn Clock>`
  parameter, threaded down to the lowest-level private constructor
  (`bind_with_options`). This includes `bind`, `bind_with_max_connections`,
  and `bind_configured`.
- `spawn_connection` (`dns.rs:456`) clones `self.clock` the same way it
  already clones `self.resolver`, and passes it into `serve_tcp_connection`.
- `serve_tcp_connection` (`dns.rs:553`) takes a new `clock: Arc<dyn Clock>`
  parameter and calls `clock.now()` instead of `SystemTime::now()` at
  line 620.

### `src/main.rs` wiring

At `main.rs:129-161`:

- Bind a single `let clock: Arc<dyn Clock> = Arc::new(SystemClock);` before
  constructing the resolver.
- Pass `Arc::clone(&clock)` into the resolver constructor
  (`ResolveQuery::with_cache_policy_and_backend_snapshot`), replacing the
  inline `Arc::new(SystemClock)` currently at line 138.
- Pass another `Arc::clone(&clock)` into both
  `UdpDnsServer::bind_configured` and `TcpDnsServer::bind_configured` calls
  (`main.rs:153` and `:161`).

This ensures production wiring uses one shared clock instance across the
resolver and both transports, matching this repo's existing
dependency-injection convention (`src/resolver/AGENTS.md:19`: "Prefer
dependency injection for clocks, caches, upstream resolvers..."). `Clock`
is already imported in `main.rs` (`main.rs:32-34`,
`use rdns::resolver::{... Clock, ...};`), and the `SystemClock` unit struct
already exists at `main.rs:740-746` — no new type needs to be introduced in
`main.rs`, just reused for both wiring points.

### Call sites to update (compile-breakage list — update all, don't wait for compiler errors)

Confirmed against the current tree; every one of these needs a `clock`
argument added once the new parameter lands:

- `tests/forwarding.rs:107` — `UdpDnsServer::new` call at line 116 (inside
  `run_server`). This file already defines its own `FixedClock` unit struct
  at `tests/forwarding.rs:30-36` and already constructs
  `Arc::new(FixedClock)` for the resolver at line 101
  (`resolver_from_config`) — pass the same `Arc<FixedClock>` (or a fresh
  clone/instance, since it's a unit struct) into the new `UdpDnsServer`
  parameter too, so transport and resolver share one clock in this test
  harness the same way production does.
- `tests/support/mod.rs:137` — `UdpDnsServer::new` at line 141,
  `TcpDnsServer::bind_configured` at line 156 (inside `spawn_servers`).
  This file already defines a `pub struct SystemClock` at
  `tests/support/mod.rs:59-65` (identical shape to `main.rs`'s) — thread an
  `Arc<SystemClock>` (or accept one as a parameter to `spawn_servers` if
  callers need to inject their own) through both constructor calls.
- `src/delivery/dns.rs:880` — `UdpDnsServer::bind` at line 886.
- `src/delivery/dns.rs:940` — `UdpDnsServer::bind_configured` at line 961.
- `src/delivery/dns.rs:1596` and `:1644` —
  `UdpDnsServer::with_max_in_flight_requests` at lines 1608 and 1656.
- `src/delivery/dns.rs:990` — `TcpDnsServer::bind` at line 995 (and other
  later TCP tests using the same constructor).
- `src/delivery/dns.rs:1078` and `:1199` — `TcpDnsServer::bind_configured`
  at lines 1098 and 1208.
- `src/delivery/dns.rs:1136` and `:1527` — private
  `TcpDnsServer::bind_with_options` at lines 1142 and 1533.
- `src/delivery/dns.rs:1505` — `TcpDnsServer::bind_with_max_connections` at
  line 1513.

All in-module `dns.rs` test call sites already have a `FixedClock(SystemTime)`
pattern available at `dns.rs:755-761` — reuse it for these, rather than
inventing a new fixture shape per call site.

## Non-goals for this section

- No production timing-behavior change: `SystemClock::now()` still wraps
  `SystemTime::now()` identically.
- Do not touch `src/delivery/upstream.rs:296,640` or
  `src/resolver/mod.rs:7244,7266` — these feed
  `ResolutionResponse::received_at`, which is never read by the cache path
  (confirmed by grep; only `request.received_at.0` reaches the cache).
- No new configuration surface, no changes to `CacheTtlPolicy` defaults.
- This section does not touch `docs/knowledge/` (that's section-01) or add
  the C.1/C.2 TTL edge-case regression tests (that's section-03).

## Verification expectations

`cargo fmt`, `cargo clippy`, and `cargo test` must all pass. The new
end-to-end test (item 4 above) and the two `FixedClock`-based unit tests
(items 2-3) must fail against the pre-change code (raw `SystemTime::now()`
can't be overridden) and pass once this section's wiring lands — standard
TDD expectation per `AGENTS.md`. Per `claude-plan.md` Part D, this is a
low-risk pure refactor: it needs the usual fmt/clippy/test verification but
not a `/security-review` pass on its own merits.