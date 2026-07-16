# Implementation Plan: TTL-remaining audit, Clock DI, EDNS-Cookie cache allowlist

## Reader orientation

`rdns` is a Rust DNS resolver/proxy (Tokio async). This plan covers three
related but separable pieces of work discovered/decided during an audit of
its DNS-cache TTL-serving behavior:

1. Confirming and documenting that cache-hit responses already serve
   **remaining time to expiry** as their wire TTL (RFC 1035 §3.2.1
   conformant), not the raw origin TTL — this is already implemented and
   correct; the work here is closing documentation gaps and adding missing
   regression tests around edge cases.
2. Routing the timestamp that drives TTL aging through this repo's
   existing `Clock` dependency-injection trait instead of two raw
   `SystemTime::now()` call sites — a pure refactor, no behavior change.
3. A finding that the cache is effectively bypassed for any client that
   attaches an EDNS Cookie option (RFC 7873) — which modern `dig` and many
   stub resolvers do by default — silently defeating (1) above in real
   deployments. This plan implements a fix: allow Cookie-bearing queries to
   use the cache, while still computing a fresh, correct, per-requester
   COOKIE option on every response.

Per an explicit sequencing decision (see "PR sequencing" below), (1) and
(2) ship together as one lower-risk PR; (3) ships as its own, later,
security-reviewed PR. This plan describes both, organized so the section
split naturally follows that PR boundary.

**No code in this plan should be copy-pasted verbatim.** Signatures and
field lists are given to pin down shape and naming; bodies are the
implementer's job.

---

## Background: what's already correct (no changes here)

`compute_wire_ttl` (`src/resolver/cache/assemble.rs:188-204`) is the single
function that computes the TTL value written onto every cache-hit answer,
RRSIG, SOA, and NSEC/NSEC3 proof record. Its logic:

- `aged = ttl_at_store - elapsed_since(stored_at)` — the record's own
  origin TTL, decremented by how long it's actually been sitting in the
  cache.
- `remaining = expires_at - now` — how much longer the cache entry itself
  is allowed to live under this resolver's TTL policy.
- Final wire TTL = `min(aged, remaining)`.

It's called once per record, independently, from `write_rrset`
(`assemble.rs:229-263`, positive answers) and `write_negative_authority`
(`assemble.rs:265-324`, SOA + its RRSIG + each DNSSEC proof record). Both
UDP and TCP responses go through the same `assemble_response` /
`assemble_negative_response` path (`assemble.rs:546`, `:615`) — there is
exactly one wire-TTL-aging code path in this codebase, already shared by
every transport. Read-time expiry (`Shard::lookup_hop`,
`src/resolver/cache/shard.rs:405-463`) deletes any entry already past
`expires_at` at lookup time, so an expired entry is never served at all.

This plan does not change any of the above. It documents it, tests two
previously-uncovered edge cases around it, and fixes why it's invisible
for Cookie-bearing clients today.

---

## Part A — Documentation (PR 1)

### A.1 Update `docs/knowledge/resolver/caching/answer-cache.md`

This file currently documents `stored_at`/`expires_at` as generic "TTL
bookkeeping" (line 44) and never mentions `compute_wire_ttl` or
remaining-TTL-on-read at all. Add a section (near the existing
`stored_at`/`expires_at` table entry) that explains:

- Cache-hit responses serve **remaining time to expiry**, computed
  per-record by `compute_wire_ttl` (`assemble.rs:188-204`), not the raw
  origin TTL — cite RFC 1035 §3.2.1 as the conformance basis.
- The two inputs it combines (`aged` from the record's own origin TTL,
  `remaining` from the entry's policy-bounded `expires_at`) and why the
  final value is `min` of the two.
- The chain-wide `expires_at` ceiling: a CNAME chain's `expires_at` is
  computed once, as the minimum origin TTL across every record in the
  response, and applied identically to every hop including the terminal
  record — so a long-TTL terminal record looked up again later, on its
  own, is still capped by whatever chain it was first stored as part of.
  Reference the doc comment at `assemble.rs:181-187` for the design
  rationale (a CNAME chain combines records from multiple `RRsetEntry`s
  with different `stored_at` values, so a single scalar age over an
  assembled buffer can't represent it — hence per-record aging).
- The negative-cache dual-aging distinction: `write_negative_authority`'s
  per-record `compute_wire_ttl` calls (wire-TTL aging, what gets sent) are
  a different computation from `NegativeEntry::dnssec_proof_material_fresh`
  (`entry.rs:224-238`, servability gating — whether a DO=1 reader may be
  served this entry at all). State plainly that these are two intentional,
  non-redundant mechanisms over the same stored fields.
- The zero/near-zero-origin-TTL-vs-floor behavior (see A.3 below) and the
  chain-wide-ceiling behavior (this section) as documented, tested edge
  cases — not open questions.
- One line noting the backend-round-trip-latency freshness overstatement:
  a cache entry's `stored_at` is set from the *client request's* received
  timestamp, not the backend answer's arrival timestamp, so a cached
  entry's apparent remaining TTL is understated by roughly one backend
  round trip. Pre-existing, low-severity, not fixed by this plan.
- After PR 2 lands (Cookie allowlist), this doc also needs one line
  stating that EDNS-Cookie-bearing queries are now cache-compatible
  (previously bypassed cache entirely). Note this as a follow-up edit
  tied to Part E, not part of Part A's PR.

### A.2 Retire `docs/caching.md`

This file describes a `CachedResponse { response_template: Vec<u8>, ... }`
type and a `serialize_cached_response` function that no longer exist
anywhere in `src/` (confirmed by grep — the only two remaining mentions,
`src/resolver/mod.rs:12659,12720`, are comments/test-name references to the
old name). It predates the `cache_rework` effort that introduced
`RRsetEntry`/`ShardedDnsCache`/`assemble_response`/`compute_wire_ttl` and
was never updated.

`docs/plans/cache_rework/*` cites `docs/caching.md` extensively as
historical context (describing pre-rework state at the time those planning
docs were written) — those citations are fine as history and must keep
resolving. Before editing/removing `docs/caching.md`, grep the repo for
all inbound references to confirm which are historical (`docs/plans/**`,
fine to leave pointing at a retired/archived file) versus any live
documentation link outside `docs/plans/` (would need updating instead).

Retirement approach: replace `docs/caching.md`'s content with a short
pointer stating it's superseded by `docs/knowledge/resolver/caching/`
for current behavior, and that `docs/plans/cache_rework/` has the design
history it used to describe — rather than deleting the file outright,
since deleting would break any relative links from the historical planning
docs. Do not rewrite it to match current design; that duplicates
`docs/knowledge/`.

---

## Part B — Clock dependency injection (PR 1)

### B.1 Current state

This repo's `Clock` trait (`pub trait Clock: Send + Sync { fn now(&self) ->
SystemTime; }`, `src/resolver/mod.rs:7758-7760`) already exists and is
already used — but only for query-duration metrics (`started_at`/
`finished_at`, read at `mod.rs:3739` and `:5176` via `self.clock.now()`
inside `ResolveQuery`). `ResolveQuery` (`mod.rs:3341`) already holds a
`clock: Arc<dyn Clock>` field, constructed once in `src/main.rs:129-148` as
`Arc::new(SystemClock)` (the `SystemClock` unit struct and its `Clock` impl
live at `main.rs:740-746`) and passed into
`ResolveQuery::with_cache_policy_and_backend_snapshot`.

The value that actually seeds TTL aging — `ReceivedAt(SystemTime)`
(`mod.rs:93`), which becomes `request.received_at.0` and flows into both
`store_cache_response`'s `stored_at` (`mod.rs:5095-5119`) and every
cache-lookup path — is **not** sourced from this `Clock`. It comes from two
raw `SystemTime::now()` calls at the transport edge:
`src/delivery/dns.rs:262` (inside `handle_datagram`, feeding
`ResolveRequest::new_with_observed_source`) and `:620` (inside
`serve_tcp_connection`, same constructor call, TCP path).

Two other raw `SystemTime::now()` sites exist nearby but are confirmed
**out of scope**: `src/delivery/upstream.rs:296,640` and
`src/resolver/mod.rs:7244,7266` (inside `evaluate_authority_response`) feed
a different struct field (`ResolutionResponse::received_at`, populated by
`forwarded_bytes`/`forwarded_message`/`recursive_response` constructors)
that is never read by anything — only `request.received_at.0` (the
client-request timestamp) reaches the cache. Confirmed by grep: all 5 uses
of `request.received_at.0` are at `mod.rs:4440, 4555, 4574, 4595, 5107`.
Leave these two sites untouched.

### B.2 What changes

Goal: `handle_datagram` and `serve_tcp_connection` obtain `now` from an
injected `Arc<dyn Clock>` instead of calling `SystemTime::now()` directly,
so tests can inject a fake clock and drive the whole receive → cache-store
→ cache-read pipeline deterministically.

Concretely:

- `UdpDnsServer` (`src/delivery/dns.rs:117-123`) gains a `clock: Arc<dyn
  Clock>` field alongside its existing `socket`/`resolver`/`listener`/
  `max_request_size`/`max_in_flight_requests` fields.
- `TcpDnsServer` (`dns.rs:285-292`) gains the same `clock: Arc<dyn Clock>`
  field alongside its existing fields.
- Every public constructor that currently takes `resolver: Arc<ResolveQuery>`
  gains a parallel `clock: Arc<dyn Clock>` parameter, threaded the same way
  `resolver` already is, down to the lowest-level constructor
  (`UdpDnsServer::with_max_in_flight_requests`, `TcpDnsServer::bind_with_options`).
  This includes the `bind`, `bind_with_max_connections`/
  `with_max_in_flight_requests`, and `bind_configured` levels for both
  servers.
- `spawn_datagram_task` (`dns.rs:238-243`) clones `self.clock` the same way
  it already clones `self.resolver`, and passes it into `handle_datagram`.
  `handle_datagram` (`dns.rs:252-270`) takes a new `clock: Arc<dyn Clock>`
  parameter and calls `clock.now()` instead of `SystemTime::now()` at line
  262.
- The TCP equivalent (`spawn_connection`, `dns.rs:456`, and
  `serve_tcp_connection`, `dns.rs:553`) gets the same treatment: `clock`
  threaded through, `clock.now()` replacing `SystemTime::now()` at line 620.
- `src/main.rs:129-161`: bind a single `let clock: Arc<dyn Clock> =
  Arc::new(SystemClock);` before constructing the resolver, pass
  `Arc::clone(&clock)` into the resolver constructor (replacing the
  inline `Arc::new(SystemClock)` at line 138), and pass another
  `Arc::clone(&clock)` into both `UdpDnsServer::bind_configured` and
  `TcpDnsServer::bind_configured` calls (`main.rs:153,161`). This ensures
  production wiring uses one shared clock instance across the resolver and
  both transports, matching this repo's existing dependency-injection
  convention (`src/resolver/AGENTS.md:19`: "Prefer dependency injection for
  clocks, caches, upstream resolvers...").

This is a pure refactor: `SystemClock::now()` wraps `SystemTime::now()`
identically, so production timing behavior is unchanged. Every existing
call site and test that constructs a `UdpDnsServer`/`TcpDnsServer` directly
(not via `main.rs`) will need a `clock` argument added. Confirmed (verified
against current tree) call sites that will fail to compile once the new
parameter is added — the implementer should update all of these, not
discover them via compiler errors:

- `tests/forwarding.rs:107` — `UdpDnsServer::new` call at line 116.
- `tests/support/mod.rs:137` — `UdpDnsServer::new` at line 141,
  `TcpDnsServer::bind_configured` at line 156.
- `src/delivery/dns.rs:880` — `UdpDnsServer::bind` at line 886.
- `src/delivery/dns.rs:940` — `UdpDnsServer::bind_configured` at line 961.
- `src/delivery/dns.rs:1596` and `:1644` — `UdpDnsServer::with_max_in_flight_requests`
  at lines 1608 and 1656.
- `src/delivery/dns.rs:990` — `TcpDnsServer::bind` at line 995 (and other
  later TCP tests using the same constructor).
- `src/delivery/dns.rs:1078` and `:1199` — `TcpDnsServer::bind_configured`
  at lines 1098 and 1208.
- `src/delivery/dns.rs:1136` and `:1527` — private `TcpDnsServer::bind_with_options`
  at lines 1142 and 1533.
- `src/delivery/dns.rs:1505` — `TcpDnsServer::bind_with_max_connections` at
  line 1513.

### B.3 Test-only clock precedent to follow

This repo already has a `FixedClock` pattern used in tests, in three
places with slightly different shapes:

- `mod.rs:7999-8005`: `struct FixedClock(SystemTime)`, returns the stored
  value.
- `src/delivery/dns.rs:755-761`: same shape, local to that test module.
- `tests/forwarding.rs:30-36`: `struct FixedClock;` (unit struct), always
  returns `SystemTime::UNIX_EPOCH`, imported via `rdns::resolver::Clock`
  and passed through the public API — i.e. a true black-box injection, not
  a `#[cfg(test)]`-internal fixture.

New tests added by this plan (B.4 below) should use whichever `FixedClock`
shape already exists in the file they're added to, rather than inventing a
fourth variant.

### B.4 New test: live end-to-end Clock injection

Per interview decision, add a **new file under `tests/`** (matching
`tests/forwarding.rs`'s black-box style, not the in-module `mod.rs` e2e
tests). This test should:

- Construct a `UdpDnsServer` (or minimal equivalent harness, following
  whatever `tests/forwarding.rs` already sets up for its own black-box
  resolver tests) with an injected `FixedClock` (unit-struct style, per
  `tests/forwarding.rs:30-36`'s precedent) wired through the new `clock`
  parameter from B.2.
  - Send a request that causes a cache store.
  - Advance the injected clock (construct a second `FixedClock` instance
    with a later `SystemTime`, or use whatever mutable-clock pattern is
    cleanest given `Clock`'s immutable `&self` signature — decide during
    implementation whether a `Cell<SystemTime>`-backed fake clock is
    needed to represent time advancing within one test, since the existing
    `FixedClock` variants are single-value and don't mutate).
  - Send a second request for the same query and assert the served TTL
    has aged by the expected amount, driven entirely through the live
    transport path (socket → `handle_datagram` → resolver → cache →
    `assemble_response`) rather than by hand-constructing `now`/
    `stored_at` values as the existing unit/e2e tests do.
- This closes the gap noted in `plan.md`'s Current State point 8: existing
  tests all construct `now`/`stored_at` by hand; none drive the actual
  transport-to-cache pipeline with an injected clock.

---

## Part C — Edge-case regression tests (PR 1)

Both tests below are pure additions — no production behavior changes.

### C.1 Zero/near-zero origin TTL vs. `min_positive_ttl` floor

Decision (interview Q8): current behavior is correct, document via test,
do not change `compute_wire_ttl` or the floor logic.

Add a unit test near
`assemble_response_ages_each_record_ttl_independently`/
`assemble_response_caps_ttl_to_remaining_entry_lifetime`
(`src/resolver/cache/assemble.rs:754-793`) that:

- Constructs an `RRsetEntry` with a record whose `ttl_at_store` is `0`
  (or `1`), but whose `expires_at` reflects a `min_positive_ttl` floor
  (e.g. 30s) having raised the entry's actual cache lifetime past what the
  origin TTL alone would justify — mirror however the existing capping
  tests construct their `stored_at`/`expires_at` fixtures.
- Asserts the wire TTL returned by `compute_wire_ttl` is `0` (or very
  close to it) for the entire floored lifetime — i.e., `aged` never
  exceeds what the record's own origin TTL implies, even though the entry
  itself is still servable.
- Name it to state the invariant directly, e.g.
  `compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime`.

### C.2 Chain-wide `expires_at` ceiling vs. per-hop origin TTL

Decision (interview Q9): document + add a dedicated regression test.

Add a test (placement: alongside the existing `resolve_ages_cached_response_ttls_for_current_request_time`
/ `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime` e2e tests,
now at `mod.rs:16287-16365`, since this is a store-then-serve interaction
across a real CNAME chain, not a single-`RRsetEntry` unit case) that:

- Stores a response containing a CNAME chain where one intermediate hop
  has a short origin TTL (e.g. 60s) and the terminal record has a much
  longer origin TTL (e.g. 3600s) — matching the exact scenario described in
  `plan.md`'s Current State point 2.
- Immediately after store, issues a **second, independent query** for the
  terminal record's own name directly (not by re-resolving the chain) and
  asserts its served wire TTL is still capped to the chain-wide minimum
  (~60s), not the terminal record's own 3600s origin TTL — proving the
  ceiling from the original chain's store operation persists even for
  unrelated later lookups of the terminal name.
- This is the first test to exercise this specific
  stored-via-chain / looked-up-standalone interaction; existing tests only
  cover a single record's own TTL being capped, not one hop's cap leaking
  onto another hop looked up independently later.

---

## Part D — Section/PR boundary marker

Everything above (Parts A-C) is PR 1: documentation, Clock DI, two new
regression tests. No behavior change to what gets sent on the wire, no
security-sensitive code paths touched, no new dependency on untrusted-input
parsing decisions. Per `RUST.md`/`AGENTS.md` gates, this PR needs the usual
fmt/clippy/test verification but not a `/security-review` pass on its own
merits.

Part E below is a **separate, later PR** — implement, review, and land it
independently. Do not merge Part E's work into the same PR as A-C.

---

## Part E — EDNS-Cookie cache allowlist (PR 2, security-sensitive)

**This part requires a `/security-review` pass before landing**, per root
`AGENTS.md`'s "PR touches auth/untrusted-input/network code" trigger — RFC
7873 cookies are an anti-spoofing mechanism, and this change makes EDNS
option parsing feed a caching decision plus introduces server-secret
generation and cryptographic comparison on the query path.

**Status after Codex review (see `claude-integration-notes.md`): this Part
is a scoping document, not an implementation-ready section.** The design's
core idea (cache the answer, regenerate the Cookie option per requester) is
sound, but tracing the actual response-construction code revealed more
call sites and open RFC-conformance decisions than originally scoped — see
E.6, "Known gaps." Send Part E to a dedicated follow-up `/deep-plan`
session before implementing it.

### E.1 Current bypass behavior (unchanged for everything except Cookie)

`cache_supported` (`src/resolver/mod.rs:5508-5520`) returns `false` — full
cache bypass, no lookup, no store — whenever a query's EDNS record has a
non-zero extended RCODE, non-zero version, any flag other than DO set, or
**any non-empty `edns.options`**. `probe_cache` (`mod.rs:4409-4424`)
short-circuits on this, incrementing `CacheBypass` + `CacheMiss` metrics
and routing straight to the backend.

Two existing tests pin this down and **must not regress** for any
non-Cookie case: `resolve_bypasses_cache_for_unsupported_edns_options`
(`mod.rs:18930-18954`) and
`resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
(`mod.rs:18956+`). After this change, only a query carrying *solely* a
well-formed EDNS Cookie option (option code 10) — no other options, no
other disqualifying flags/version/RCODE — should become cache-compatible;
every other case these tests cover must still bypass exactly as today.

### E.2 What "cache-compatible" means here

The cached *answer* (RRset data) does not depend on the requester's
cookie. What must never be cached or replayed verbatim is the **OPT
record's COOKIE option value**, because RFC 7873 §4.2 defines the server
cookie as a function of the requesting client's source IP and client
cookie — a value that is, by construction, different for every requester.
(RFC 9018, which updates RFC 7873, mandates the specific algorithm:
`SipHash-2-4(Client Cookie | Version | Reserved | Timestamp | Client-IP,
Server Secret)` producing a 16-byte server cookie; the older example
algorithms in RFC 7873 Appendix B are explicitly superseded.)

So: cache the answer, regenerate the COOKIE option fresh on every
response — cache hit or cache miss alike.

**Correction from Codex review:** an earlier draft of this plan pointed to
`filter_response_for_requester` (`mod.rs:1480-1507`) as "the" per-requester
rewrite seam to reuse for Cookie-option attachment. That function's own doc
comment says it explicitly does not touch the OPT record, and tracing its
only call site (`mod.rs:4940`, inside `prepare_backend_result`) shows the
actual OPT reattachment happens a few lines later, at `mod.rs:4960-4963`.
That is only *one* of several independent places in this codebase that
currently construct an optionless OPT record for an outgoing response.
Because this codebase does not implement DNS Cookies at all today (no
COOKIE option is ever emitted, on any path), making "every response
attaches a correct, fresh COOKIE option when the request had one" true
requires touching every one of them, not just the recursive-miss path:

- Cache-hit positive/negative responses: `assemble_response` /
  `assemble_negative_response` (`src/resolver/cache/assemble.rs:546,615`),
  which call `requester_opt_record` (`assemble.rs:437`) — currently builds
  an optionless OPT unconditionally.
- Cache-hit truncated / SERVFAIL-on-oversized responses inside cache
  assembly (`assemble.rs:449,504`) — same `requester_opt_record` path.
- Recursive-miss, filtered path: `prepare_backend_result`
  (`mod.rs:4665` area), OPT reattachment at `mod.rs:4960-4963`, right after
  `filter_response_for_requester`'s trimmed records come back.
- Recursive-miss, no-filter rebuild path: `rebuild_recursive_response_with_own_framing`
  (`mod.rs:1670-1688`), which strips OPT and appends
  `mirrored_client_opt_record`.
- Truncated responses: `truncated_response_for_query` (`mod.rs:1716-1721`),
  also via `mirrored_client_opt_record`.
- Local/refusal/policy-block/SERVFAIL/protocol-error responses: response
  factories and protocol helpers such as `BasicResponseFactory::servfail`
  (`mod.rs:5636`) and `message_edns_opt_record` (`src/protocol/mod.rs:1296`)
  — currently always emit an optionless OPT.

A follow-up planning pass for Part E (see "Known gaps," below) needs to
decide, deliberately, which of these paths are actually required to echo a
Cookie option for RFC 7873 correctness versus which can be left
optionless (e.g. does a SERVFAIL response need a valid Cookie echo? RFC
7873 doesn't clearly require it, but a real implementation should decide
explicitly rather than by omission).

Also, per Codex's review: `EdnsInfo.options` (`src/protocol/mod.rs:208`)
is currently a raw `Vec<u8>`, not a typed representation — there is no
`EdnsOption` enum/struct in this codebase today. Any Cookie-aware code
(cache-admission check, per-response Cookie attachment) needs either a new
typed EDNS-option parser at the protocol layer, or to work directly against
the raw byte encoding (RFC 7873's option is straightforward — 2-byte code,
2-byte length, then 8 or 16-40 bytes of value — so a narrow raw-byte
extractor may be simpler than a general typed-option parser). This decision
belongs to Part E's follow-up planning pass, not to this document.

### E.3 Scope decisions from the interview

- **Cookie only, not Padding.** RFC 7830 Padding (option code 12) is
  stateless/cache-key-neutral by design (arbitrary filler bytes, no
  per-requester dependency, only relevant over encrypted transport per RFC
  7830 §6) but this resolver doesn't yet serve DNS-over-TLS/DoH, so
  supporting it now would be unused code. Defer Padding support to
  whenever DoT/DoH is added; do not build a general "cache-key-neutral
  options" abstraction now if it only has one real caller.
- **Server secret: random, in-memory, generated at process startup.** Not
  persisted, not configurable. A process restart invalidates all
  outstanding server cookies for connected clients, which is not an error
  condition — it's handled by the RFC's own existing "invalid/stale server
  cookie" fallback (§5.2.4), which this plan also uses for the
  no-server-cookie-yet case (see below). No new configuration surface is
  added by this plan.
- **§5.2.3/§5.2.4 policy: always process normally, always attach a fresh,
  valid COOKIE option.** No `BADCOOKIE` (RCODE 23) path is implemented in
  this pass — every Cookie-bearing query (whether it has no server cookie
  yet, or an invalid/stale one) gets answered normally with a freshly
  computed, valid server cookie attached. This is simpler and avoids
  adding a round-trip retry path and its tests; it remains RFC-compliant
  since §5.2.3/§5.2.4 list "process the request as if it had no COOKIE
  option present, but include a COOKIE option ... in the response" as an
  explicitly allowed alternative to sending BADCOOKIE.
- **Malformed COOKIE options (wrong length — anything other than exactly
  8 bytes, or 16-40 bytes) are not made cache-compatible.**
  **Correction from Codex review:** the protocol parser today
  (`src/protocol/mod.rs:2643`) only validates generic EDNS option framing
  (code/length/value), not Cookie-specific length legality — so a
  malformed Cookie is *not* currently rejected with FORMERR anywhere,
  contrary to what an earlier draft of this plan assumed ("verify whether
  upstream already handles it" — it doesn't). RFC 7873 §5.2.2 says illegal
  Cookie lengths must get FORMERR. Deciding whether to add that
  protocol-layer validation as part of this work (making rdns's Cookie
  handling actually RFC-conformant) versus merely leaving malformed
  Cookies as cache-incompatible (a narrower, cache-admission-only fix) is
  a real scope decision for Part E's follow-up planning pass — it is
  **not** resolved by this document.
- **Anycast/multi-instance posture: single-instance only, stated as an
  explicit constraint, not a footnote.** RFC 9018 §"Security
  Considerations" states the server secret **MUST be configurable** so an
  anycast cluster's instances can share one secret and validate each
  other's cookies; a random, in-memory, per-process secret (as decided in
  the interview) does not meet that. This plan accepts that tradeoff
  explicitly for a single-instance deployment: cookies remain valid and
  regenerated correctly per the RFC's own fallback path (§5.2.4 — an
  "invalid/stale" cookie is simply treated as absent and a fresh one is
  issued, so nothing breaks for the client), but a multi-instance/anycast
  deployment of this resolver would see cookies "reset" on every request
  that lands on a different instance, giving up the DoS-amplification/
  anti-spoofing value cookies are meant to provide across such a
  deployment. If this resolver is ever deployed anycast, secret
  configurability must be revisited before relying on Cookie support for
  its security properties there.

### E.4 New/changed surface (signatures only)

- `cache_supported` (`mod.rs:5508-5520`) needs a new branch: instead of
  unconditionally requiring `edns.options.is_empty()`, it should also
  accept the case where `edns.options` contains exactly one well-formed
  Cookie option (code 10, correct length) and nothing else. Because
  `EdnsInfo.options` is a raw `Vec<u8>` today (`src/protocol/mod.rs:208`,
  not a typed option list), this predicate operates on the raw
  code/length/value encoding directly, or against whatever typed
  representation Part E's follow-up planning decides to add (see
  "Known gaps" below) — not against a `&[EdnsOption]` slice, which doesn't
  exist in this codebase. The requirement, regardless of representation,
  is that every other combination of options/flags/version/RCODE continues
  to bypass exactly as the two existing tests (E.1) assert.
- A new server-cookie computation function, following RFC 9018's
  algorithm, roughly shaped as `fn compute_server_cookie(client_cookie: [u8; 8],
  client_ip: IpAddr, timestamp: SystemTime, secret: &ServerCookieSecret) -> [u8; 8]`
  (16-byte total server cookie per RFC 9018 includes a 1-byte version +
  3-byte reserved + 4-byte timestamp + 8-byte SipHash-2-4 output — exact
  field layout is RFC 9018's, not this plan's to redesign). The timestamp
  input should come from `ResolveQuery`'s existing `clock: Arc<dyn Clock>`
  field (`mod.rs:3362`) — already available inside `ResolveQuery`, no new
  clock-threading needed if cookie generation happens there — rather than
  a new raw `SystemTime::now()` call, to keep this deterministic under
  test per this repo's DI convention. Lives wherever this codebase's other
  per-response construction helpers live — implementer's call based on
  existing module boundaries.
- A `ServerCookieSecret` (or similarly named) holder, generated once at
  startup (likely alongside where `Arc::new(SystemClock)` is constructed
  in `main.rs`, given both are "one shared instance threaded through
  request handling" concerns) and threaded into whatever construct
  ultimately calls the new cookie-computation function — mirror the
  `Clock`-threading pattern from Part B rather than inventing a new DI
  shape. Name the SipHash-2-4 implementation/crate explicitly during
  follow-up planning rather than leaving it to the implementer's
  discretion — Rust's standard-library `SipHasher` types are not
  positioned as a stable, protocol-interoperable primitive, and RFC 9018
  requires exact algorithm conformance for interop with other resolvers'
  cookie validation.
- The response-construction path needs a new branch at **every** OPT-
  building call site enumerated in E.2 above (not just the one near
  `mod.rs:4960-4963`): when the request carried a Cookie option, compute
  and attach a fresh COOKIE option instead of whatever
  `mirrored_client_opt_record`/`requester_opt_record`/`message_edns_opt_record`
  currently do for the no-Cookie case. Follow-up planning should decide,
  per call site, whether Cookie echo is actually required there (see E.2).

### E.5 Required tests (in addition to not regressing E.1's two tests)

- Unit tests for the new server-cookie computation function: deterministic
  output for a given (client cookie, client IP, secret) tuple; different
  output for different client IPs with the same client cookie and secret
  (confirms per-requester binding, the property that makes cookie caching
  safe in the first place).
- A `cache_supported`-level test: a query with *only* a well-formed Cookie
  option and nothing else now returns `true` (cache-compatible) — sibling
  to, and must coexist with, `resolve_bypasses_cache_for_unsupported_edns_options`.
- A `cache_supported`-level test: a query with a Cookie option *plus* any
  other disqualifying condition (extra option, non-DO flag, non-zero
  version) still bypasses — confirms Cookie-compatibility is narrowly
  scoped, not a general relaxation.
- An end-to-end test: two different (simulated) requesters query the same
  name with different client cookies; both get cache hits (single
  backend fetch, confirmed via existing cache-hit/miss metrics or mock
  backend call-count assertions) but each receives a COOKIE option in
  its response whose server-cookie portion is valid for *that
  requester's* client IP + client cookie — proving the shared cache entry
  never leaks one requester's cookie material to another.
- A malformed-Cookie-length test confirming such queries do not become
  cache-compatible (still bypass, per E.3's scope decision) — and, if
  follow-up planning decides to add protocol-layer FORMERR validation for
  malformed Cookies (E.3), a corresponding FORMERR test.
- A test confirming multiple COOKIE options in one query are handled per
  a decision follow-up planning must make explicitly: RFC 7873 §5.2.1
  says only the first is considered — decide whether this codebase treats
  a second COOKIE option as "ignored" (still cache-compatible) or as
  disqualifying (falls back to full bypass), and test whichever is chosen.
- If incoming server-cookie validation is implemented (i.e. the code
  distinguishes a request's existing server cookie as valid vs.
  invalid/stale for any behavioral purpose), the comparison must be
  constant-time and should have a test asserting this isn't a
  data-dependent-timing oracle on the server secret. If validation never
  changes behavior (every case is answered identically per E.3's "always
  process normally" policy), follow-up planning should say so explicitly
  and drop "cryptographic comparison" from the design rather than imply
  unvalidated input is being compared.

### E.6 Known gaps — resolve in a dedicated follow-up `/deep-plan` session

Codex's review of this plan (see `claude-integration-notes.md`) surfaced
that Part E's real implementation surface is substantially larger than "one
new branch in `cache_supported`" once the actual response-construction code
paths and EDNS-option data shape are accounted for. Rather than under-
specifying a security-sensitive feature under this session's time budget,
the following should be resolved by a **new, dedicated `/deep-plan` session
scoped only to Cookie support**, run after PR 1 (Parts A-C) lands:

1. EDNS-option representation: add a typed parser, or work against raw
   bytes (E.2).
2. Which of the ~6 response-construction call sites (E.2) actually need
   Cookie echo, versus which can stay optionless.
3. Malformed-Cookie handling: cache-admission-only fix vs. full RFC 7873
   FORMERR conformance (E.3).
4. Server-secret configurability for anycast/multi-instance deployments —
   confirm single-instance-only is an acceptable constraint for this
   resolver's actual deployment targets, or add configurability (E.3).
5. SipHash-2-4 crate/implementation choice (E.4).
6. Whether incoming server-cookie validation gates any behavior, and if
   so, constant-time comparison (E.5).
7. Multi-COOKIE-option policy (E.5).

Until that follow-up session resolves these, Part E should be treated as a
**scoping document**, not an implementation-ready section — do not hand
Part E to `/deep-implement` as-is.

---

## Non-goals (carried over from `plan.md`, unchanged)

- Real DNSSEC validation.
- Changing `CacheTtlPolicy` defaults or adding new configuration knobs.
- Redesigning the delegation cache (`DelegationCache`, `mod.rs:6738-6870`
  — confirmed out of scope: stores nameserver `SocketAddr`s for the
  resolver's own iterative routing, holds no DNS records, never
  serialized to a client, uses a monotonic `Instant` not `SystemTime`).
- A general clock-injection audit beyond the `received_at`/TTL-aging path
  (e.g. `upstream.rs`'s or `main.rs`'s other `SystemTime::now()` uses for
  transaction-ID seeding or root-hints staleness are untouched).
- RFC 7830 Padding support (deferred, see E.3).

## Verification expectations

- Part A: doc-only, no test/build gate beyond normal review.
- Parts B/C: `cargo fmt`, `cargo clippy`, `cargo test` must all pass; the
  new B.4 e2e test and C.1/C.2 regression tests must fail without their
  respective changes and pass with them (standard TDD expectation per
  `AGENTS.md`).
- Part E: same fmt/clippy/test gates, **plus** a `/security-review` pass
  before opening the PR, plus explicit confirmation that
  `resolve_bypasses_cache_for_unsupported_edns_options` and
  `resolve_bypasses_cache_for_unsupported_edns_flags_and_version` still
  pass unmodified (only a new sibling test should be added for the
  Cookie-only-compatible case, not a change to those two tests'
  assertions).
