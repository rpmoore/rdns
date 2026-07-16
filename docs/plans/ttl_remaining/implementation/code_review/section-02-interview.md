# Section 02 code review — interview/decisions

Reviewer verdict: core Clock DI threading correct and complete (all
constructors, both raw `SystemTime::now()` call sites replaced, main.rs
shares one clock instance, no scope creep). One real gap found:

**Real gap — missing path-specific unit-level regression tests (auto-fixed,
required a design correction, not just an addition).** The plan's items 2/3
called for unit tests asserting the exact `ResolveRequest.received_at`
value against an injected `FixedClock`. First attempt used
`QueryEventV1.timestamp` as a proxy for `received_at` — investigation
during the fix showed this field is actually populated from the
*resolver's own* `self.clock.now()` (`mod.rs:5176`, `finished_at`), a
separate clock instance from the transport's, not from
`request.received_at.0`. That version passed for the wrong reason (masked
by resolver's own clock happening to match in some paths) and failed
outright once resolver and transport clocks diverged in the corrected
test. Fixed: replaced both broken tests with
`handle_datagram_uses_injected_clock_for_cache_ttl_aging` (UDP) and
`serve_tcp_connection_uses_injected_clock_for_cache_ttl_aging` (TCP) —
each wires a real `ShardedDnsCache` + `AdvanceableClock` shared between
resolver and transport, sends two live queries, and asserts the served
wire TTL ages by exactly the clock's advance (100 -> 60), which can only
be explained by `handle_datagram`/`serve_tcp_connection` reading the
injected clock (real wall-clock elapsed time between two fast async
calls is microseconds, not 40 seconds). This also directly addresses the
reviewer's second observation — the single e2e test
(`tests/clock_injection.rs`) only exercised the UDP path; these two new
unit tests give the TCP path equivalent, independent coverage.

Both new tests pass; full suite green (569 lib tests, up from 567).

Not acted on (correctly non-blocking per reviewer, no fix needed):
- `Ordering::SeqCst` on `AdvanceableClock`'s `AtomicU64` is stronger than
  needed for a single-threaded test body — acceptable, not a bug.
- `resolve_service`'s own `FixedClock(UNIX_EPOCH)` for the resolver in
  *other*, pre-existing in-module tests diverges slightly from
  `tests/forwarding.rs`'s shared-Arc pattern — cosmetic only, not touched.

No open items requiring user input.
