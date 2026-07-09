# DNS Resolver Feature Gaps (beyond DNSSEC)

## Summary

This is a survey, not a fully-scoped implementation plan (contrast with
`docs/plans/cache_key.md`). It catalogs DNS features that are considered
baseline for an intermediate resolver (Unbound/BIND/Knot Resolver class)
that rdns does not yet have, excluding DNSSEC (tracked separately). For each
gap: what the feature is for, and a rough outline of what implementing it
would touch in rdns. Detailed step-by-step implementation plans for
individual features will be written later, one at a time, as their own docs.

## What rdns already has

For context, the gaps below are gaps *on top of* an already substantial
feature set:

- **Caching with RFC 2308 negative caching** — `src/resolver/mod.rs:613`
  `CacheStore`, `:624` `CacheTtlPolicy`, `:746` `negative_ttl()` derives
  NXDOMAIN/NODATA TTL from the SOA MINIMUM field.
- **True recursive resolution**, not just forwarding —
  `src/resolver/mod.rs:5703` `RecursiveResolutionBackend`, `:5798`
  `resolve_iterative` walks from root hints (`config/mod.rs:334`, bundled
  `named.root`), follows referrals, races authorities per hop. A separate
  `ForwardingResolutionBackend` (`delivery/upstream.rs:114`) covers pure
  forwarding mode.
- **TCP fallback / TC bit handling**, both directions — server-side
  truncation (`protocol/mod.rs:434`) and client-side fallback on truncated
  upstream replies (`delivery/upstream.rs`).
- **IPv6 / dual-stack** — AAAA parsing/building, in-bailiwick glue for both
  families (`resolver/mod.rs:957`, `config/mod.rs:523`).
- **CNAME chain following + loop detection** — `resolver/mod.rs:5717`
  `seen_cnames`/`cname_restarts`, bounded by `max_cname_restarts`.
- **Message compression** — `NameCompressor` (recent work on this branch).
- **Basic upstream health tracking** — `delivery/upstream.rs:137`
  `UpstreamHealth` (consecutive failures, degraded, retry_after), though
  selection is static priority order rather than RTT-adaptive (see gap #4
  below).

## Gap 1: QNAME minimization (RFC 7816)

**What it's for.** During iterative resolution, a resolver normally sends
the *full* query name to every authority server in the delegation chain,
even though each authority only needs enough of the name to decide where to
delegate next (e.g. the root only needs to see the TLD). QNAME minimization
sends only the minimal prefix necessary at each hop, so intermediate and
root/TLD servers don't observe the full names being resolved. This is
considered baseline privacy hygiene in modern resolvers — Unbound and Knot
Resolver both enable it by default.

**Rough outline.** Touches `resolve_iterative` / `resolve_one_hop` in
`src/resolver/mod.rs`. Instead of forwarding the original QNAME at each
hop, the resolver would compute the minimal label count needed relative to
the current zone cut and issue a query for that shortened name (typically
QTYPE=NS, falling back to the real QTYPE on the final label). Needs care
around non-minimizing fallback for servers that mishandle minimized queries
(RFC 7816 §3 recommends a fallback path).

**Current state.** Absent — no matches for "minimi" in `resolver/` or
`config/`.

## Gap 2: Rate limiting / Response Rate Limiting (RRL)

**What it's for.** Without RRL, a resolver (especially one doing recursive
resolution or acting as an open/semi-open forwarder) can be used as part of
a reflection/amplification DDoS, or simply overwhelmed by a single abusive
client. RRL throttles identical or similar responses to the same client
(or client subnet) within a time window, which is standard on any DNS
server that sits in a path attackers could exploit.

**Rough outline.** Would sit in the delivery layer (`src/delivery/`),
likely as a check keyed on source address (or /24 or /56 prefix) plus
response characteristics (qname/qtype, NXDOMAIN status), similar in shape
to the existing `UpstreamHealth` tracking in `delivery/upstream.rs` but
applied to inbound client traffic rather than outbound upstream queries.
Needs a decision on algorithm (token bucket vs. sliding window) and what
action to take when limited (drop vs. truncate-to-force-TCP, the common
RRL mitigation since it's harder to spoof TCP).

**Current state.** Absent — no rate-limit/RRL logic in `resolver/mod.rs`,
`delivery/dns.rs`, or `config/mod.rs`. (An unrelated future admin-UI
login-rate-limit item exists in `docs/plan/06-admin-api-ui.md:69` but does
not apply to DNS query traffic.)

## Gap 3: Cache prefetching

**What it's for.** Without prefetching, a cache entry for a popular name
goes cold the instant its TTL expires, forcing the next requester to pay
the full (possibly recursive, multi-hop) resolution latency synchronously.
Prefetching refreshes hot entries in the background shortly before they
expire, so client-facing latency stays low for frequently-queried names.

**Rough outline.** Touches `CacheStore`/`CacheTtlPolicy` in
`src/resolver/mod.rs`. Needs: a way to track query popularity or simply
"was this entry served recently," a background task that re-resolves
entries nearing expiry, and a policy for how aggressively to prefetch
(unconditional near-expiry refresh vs. popularity-gated, as Unbound does
with `prefetch-key`/`prefetch`).

**Current state.** Absent — zero matches for "prefetch" anywhere in `src/`
or `docs/`.

## Gap 4: RTT-based adaptive server selection (SLIST)

**What it's for.** When multiple upstream/authority servers are available
for a query, a resolver should prefer the one that's actually fastest and
healthiest right now, not a fixed configured order. BIND/Unbound maintain
an RTT-ranked server list per zone/upstream set and adapt as measured
latency changes, which matters both for tail latency and for routing
around a degrading (but not yet fully failed) server.

**Rough outline.** Extends the existing `UpstreamHealth` struct in
`delivery/upstream.rs:137`, which already tracks consecutive failures and
degraded/retry-after state but not latency. Would add an RTT sample (EWMA
or similar) per upstream and change `ordered_enabled_udp_upstreams`
(`delivery/upstream.rs:832`) from static-priority sort to RTT-aware sort,
likely keeping configured priority as a tiebreaker or hard override.

**Current state.** Partial — health/failure tracking exists, but selection
is static-priority ordering only, not RTT-adaptive.

## Gap 5: DoT/DoH support

**What it's for.** DNS over TLS (DoT, RFC 7858) and DNS over HTTPS (DoH,
RFC 8484) encrypt DNS traffic in transit, preventing on-path
eavesdropping/tampering. This matters both for rdns as a *listener*
(clients connecting to rdns want privacy) and as a *client* (rdns querying
upstream forwarders/authorities privately). Increasingly expected of any
resolver marketed for privacy-conscious deployments.

**Rough outline.** No TLS dependency currently exists in `Cargo.toml`
(the only `hyper` usage is a plaintext metrics endpoint,
`delivery/metrics_http.rs:39`, which explicitly notes "No TLS, no auth").
Would need a TLS crate (e.g. `rustls`), a new listener type alongside the
existing UDP/TCP ones configured via `dns_listen` (`config/mod.rs:31`,
bound in `main.rs:208/221`), and separately, TLS-wrapped upstream
connections in `delivery/upstream.rs` for DoT to forwarders. DoH would
additionally need HTTP/2 framing on top.

**Current state.** Absent — no TLS anywhere in the codebase.

## Gap 6: EDNS0 completeness (cookies, padding, NSID)

**What it's for.** EDNS0 OPT records carry several sub-options beyond the
basic UDP payload size negotiation rdns already handles:
- **DNS Cookies** (RFC 7873) — a lightweight anti-spoofing mechanism so a
  server can recognize repeat clients and reject off-path forged responses.
- **Padding** (RFC 7830) — pads queries/responses to fixed sizes, mainly
  useful over DoT/DoH to prevent traffic analysis from message length.
- **NSID** (RFC 5001) — lets a server identify itself in responses, useful
  for anycast deployment debugging.

**Rough outline.** Touches `parse_opt_record`/`validate_edns_options`
(`protocol/mod.rs:1362`, `:1388`) and `EdnsInfo` (`protocol/mod.rs:179`),
which currently stores options as a raw `Vec<u8>` passthrough. Each option
would need its own typed parse/build path and behavior: cookies need
server-side generation/validation logic, padding needs response-size
padding logic (and is most useful once Gap 5 / DoT exists), NSID needs a
configured server identifier to echo back.

**Current state.** Partial — OPT record parsing/serialization and UDP
payload size negotiation exist, but individual options are opaque
passthrough with no cookie, padding, or NSID handling.

## Gap 7: AXFR/IXFR (zone transfer)

**What it's for.** AXFR (full zone transfer, RFC 5936) and IXFR
(incremental, RFC 1995) let a secondary DNS server replicate zone data from
a primary. This is lower priority than the other gaps here — it's only
relevant if rdns takes on a secondary/authoritative role rather than
staying purely a caching/recursive resolver.

**Rough outline.** Would need a new query type (AXFR/IXFR are unusual in
using TCP-only, multi-message responses) and zone storage distinct from the
existing cache (zone data must persist independent of TTL-based eviction).
Not scoped further here since it's out of the resolver's core path.

**Current state.** Absent — no matches for "axfr"/"ixfr"/"zone transfer"
in `src/`.
