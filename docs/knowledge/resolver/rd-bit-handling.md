---
type: System
title: RD Bit Handling (RFC 1035 §4.1.1)
description: Why RD=0 gets cache-only treatment instead of full resolution, and where that's enforced.
resource: src/resolver/mod.rs
tags: [dns, resolver, rd, rfc1035, cache]
timestamp: 2026-07-13T00:00:00Z
---

RD (Recursion Desired) is copied from query to response per RFC 1035
§4.1.1, but rdns also gates on it: RD=0 restricts a query to data rdns
*already has* — a [local entry](caching/local-dns-entries.md) or an
existing [answer-cache](caching/answer-cache.md) hit — and refuses
(SERVFAIL) rather than doing fresh backend work for anything else. This
matches how a public recursive resolver like 1.1.1.1 treats RD=0 (verified
by hand: `dig +norecurse` returns NOERROR for an already-cached name but
SERVFAIL for a cold one) — rdns has no authoritative-only mode with
delegation data to hand back as a referral, so "cache-only" is the
closest equivalent.

# Where it's enforced

`ResolveQuery::resolve` (`src/resolver/mod.rs:3702`) checks
`decoded.features.recursion_desired` in one specific spot: **after**
`try_local_lookup` and **after** the cache-hit check inside `probe_cache`
(`src/resolver/mod.rs:4313`), but **before**
`resolve_coalesced_miss`/`resolve_backend_and_finish`. A cache miss under
RD=0 is answered by `refuse_recursion` (`src/resolver/mod.rs:3961`), which
returns `ResolveDecisionKind::RecursionRefused` and a SERVFAIL built via
`self.responses.servfail`.

SERVFAIL vs. REFUSED is a deliberate choice, not the only defensible one:
some resolvers (PowerDNS's `allow-no-rd`, Unbound's `allow_snoop`) refuse
non-recursive cache-only queries with REFUSED by default. rdns follows
1.1.1.1's observed behavior (SERVFAIL) instead, since that's the concrete
reference behavior this feature was modeled on.

Concretely, RD=0 gets:

- **Served**: local entries, cache hits (positive or negative).
- **Refused (SERVFAIL)**: a cache miss that would otherwise trigger a
  fresh upstream fetch or recursive resolution — including a miss for a
  name another (RD=1) requester is *already* fetching. The gate runs
  before a query would ever register with `ShardedSingleFlight`, so an
  RD=0 query never piggybacks on someone else's in-flight coalesced fetch
  either; it's refused the same as a cold miss.

`QueryFeatures::recursion_desired` (`src/resolver/mod.rs:243`) is also
read at response-serialization time (`src/resolver/cache/assemble.rs`) to
mirror the requester's own RD bit into the response header — that's a
separate, unconditional RFC 1035 §4.1.1 requirement independent of the
gating above (every response echoes the request's RD, refused or not).

# Metrics and events

`ResolveDecisionKind::RecursionRefused` maps to
`QueryEventOutcome::RecursionRefused` for query-event logging and
`ResolverMetric::RecursionRefused` (`recursion_refused_total` counter in
`src/main.rs`'s OpenTelemetry sink) for observability — distinct from
`BackendFailure`/`UpstreamFailure`, since this is a policy refusal, not an
actual upstream error.

# See also

- [local-dns-entries](caching/local-dns-entries.md) — why local entries
  are checked first and always served regardless of RD.
- [answer-cache](caching/answer-cache.md) — the cache whose hit/miss
  status this gate keys on.
