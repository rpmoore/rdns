# TDD Plan: TTL-remaining audit, Clock DI, EDNS-Cookie cache allowlist

Companion to `claude-plan.md` — mirrors its section structure. For each
implementation section, lists the tests to write **before** implementing,
per this repo's existing Rust `#[test]` conventions (see
`claude-research.md` for the testing-pattern research: `FixedClock`
precedent, e2e tests co-located in `mod.rs`, unit tests co-located in
`assemble.rs`/`entry.rs`, black-box tests in `tests/*.rs`). Stubs only —
no test bodies. `cargo fmt` / `cargo clippy` / `cargo test` gates from
`RUST.md` apply once each stub is filled in.

## Part A — Documentation

Doc-only change. No tests apply; verification is human/reviewer read-through
of `docs/knowledge/resolver/caching/answer-cache.md` and the retired
`docs/caching.md` for accuracy, plus confirming (via grep, not a test) that
no live non-`docs/plans/` link to `docs/caching.md` breaks.

## Part B — Clock dependency injection

Write these before touching `UdpDnsServer`/`TcpDnsServer`/`main.rs`:

- **Stub:** `UdpDnsServer`/`TcpDnsServer` construction compiles with a new
  `clock: Arc<dyn Clock>` parameter threaded through every constructor
  listed in `claude-plan.md` Part B.2 (this is a compile-level check, not
  a runtime assertion — the "test" here is that `cargo test` and `cargo
  build` succeed after updating every enumerated call site, including the
  ones in `tests/forwarding.rs`, `tests/support/mod.rs`, and the in-module
  `src/delivery/dns.rs` test call sites).
- **Stub:** `handle_datagram` uses the injected `clock.now()` instead of
  `SystemTime::now()` — verify by injecting a `FixedClock` with a
  known `SystemTime` and asserting the resulting `ResolveRequest`'s
  `received_at` matches that fixed value exactly (not just "close to
  now").
- **Stub:** same assertion for `serve_tcp_connection` (TCP path).
- **Stub (B.4, new file under `tests/`):**
  `clock_injection_ages_cache_hit_ttl_end_to_end` (or similar name) —
  drives a real request through the live UDP transport with an injected
  fake clock, stores a response, advances the fake clock, sends a second
  request for the same query, and asserts the served wire TTL reflects
  the advanced time — exercising the full transport → `ReceivedAt` →
  cache store/read pipeline, not hand-constructed `now`/`stored_at`
  values. Write this test first; it should fail against the *current*
  raw-`SystemTime::now()` code (can't inject a fixed time), and pass once
  Part B's wiring lands. Decide during writing whether the injected fake
  clock needs interior mutability (e.g. a `Cell<SystemTime>`-backed
  variant) to represent time advancing mid-test, since the existing
  `FixedClock` variants are single-value.

## Part C — Edge-case regression tests

These tests ARE the deliverable for this part — write them first, confirm
they pass against current (unchanged) `compute_wire_ttl`/store logic (this
part doesn't change production code, only adds tests), and keep them
green.

- **Stub (C.1):**
  `compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime`
  in `src/resolver/cache/assemble.rs` (near the existing
  `assemble_response_ages_each_record_ttl_independently` /
  `assemble_response_caps_ttl_to_remaining_entry_lifetime` tests,
  `assemble.rs:754-793`) — record with `ttl_at_store` near 0, entry
  `expires_at` extended by a `min_positive_ttl` floor past what the origin
  TTL alone implies; assert served wire TTL stays at (or near) 0 for the
  whole floored lifetime.
- **Stub (C.2):** a new e2e test near
  `resolve_ages_cached_response_ttls_for_current_request_time` /
  `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime`
  (`mod.rs:16287-16365`) — store a CNAME chain with a short-TTL
  intermediate hop and long-TTL terminal record, then issue a second,
  independent query for the terminal name directly; assert its served
  wire TTL is still capped to the chain-wide minimum, not its own origin
  TTL. Name it to state the invariant, e.g.
  `resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup`.

## Part D — Section/PR boundary marker

No tests; this is a planning/sequencing marker only.

## Part E — EDNS-Cookie cache allowlist

**Not TDD-ready.** Per `claude-plan.md` E.6 ("Known gaps"), this part is a
scoping document, not an implementation-ready section — several design
decisions (EDNS-option representation, which response paths need Cookie
echo, malformed-Cookie FORMERR policy, secret configurability, SipHash
crate choice, incoming-cookie-validation policy, multi-Cookie-option
policy) are unresolved. Writing concrete test stubs now would encode
assumptions a follow-up `/deep-plan` session hasn't yet made. Once that
follow-up session resolves E.6's open items, it should produce its own
`claude-plan-tdd.md`-equivalent for the Cookie feature specifically,
covering (at minimum, per `claude-plan.md` E.5's already-identified test
list): server-cookie determinism/per-requester-binding, `cache_supported`
Cookie-only vs. Cookie-plus-other-conditions cases, the two existing
EDNS-bypass regression tests continuing to pass unmodified, and an
end-to-end two-requester test proving no cookie material leaks across a
shared cache entry.

## Section-split note

Given Part E is not implementation-ready, the upcoming section split
(step 18) should produce sections only for Parts A-D (PR 1's scope). Part
E stays in `claude-plan.md`/this file as the scoping record for the
follow-up planning session — it should not be forced into a section file
for `/deep-implement` to pick up.
