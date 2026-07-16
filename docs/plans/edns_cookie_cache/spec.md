# Spec: EDNS Cookie cache-bypass fix

## Context

`cache_supported()` (`src/resolver/mod.rs:5508-5520`) currently bypasses the
cache for ANY query carrying an EDNS option, including the RFC 7873 DNS
Cookie option — which modern `dig`/stub resolvers attach by default. This
was confirmed against a live v0.1.6 deployment: `dig`'s default query never
gets served from cache. This makes the already-landed cache-hit TTL aging
work (`docs/plans/ttl_remaining/`) invisible in most real traffic.

This spec is a follow-on to `docs/plans/ttl_remaining/plan.md`, whose Open
Question 1 laid out three options for this bypass and left the decision to
`/deep-plan:deep-plan`. That decision has since been made via stakeholder
interview (`docs/plans/ttl_remaining/claude-interview.md`, Q1/Q4/Q5/Q10/Q11)
and is **not to be re-litigated here** — this plan is about designing and
sequencing the *implementation* of that decision, not re-deciding it.

## Decided scope (already resolved, do not re-open)

- **Option (b): broader cache-key-neutral allowlist.** Permit the Cookie
  option through the cache path. Cache the answer data; do **not**
  cache/replay OPT record bytes — strip/regenerate the OPT record
  (including a fresh, correctly-computed COOKIE option) per request at
  serve time, analogous to how `filter_response_for_requester`
  (`mod.rs:4462` area) already trims DO-dependent content per requester from
  a shared cache entry.
- **Cookie only, not Padding** (RFC 7830). Padding is currently a no-op for
  this resolver (only matters over encrypted transport / DoT/DoH, which this
  resolver doesn't yet serve). Defer Padding to whenever DoT/DoH support is
  added.
- **Server cookie secret**: generate random in-memory at startup. No
  config/persistence surface added — cookie validity resetting on restart is
  acceptable per RFC (clients re-handshake automatically via the
  invalid/stale server cookie fallback path).
- **RFC 7873 §5.2.3 policy**: if client cookie present with no/invalid
  server cookie, process normally and attach a fresh valid COOKIE option —
  no BADCOOKIE (RCODE 23) round-trip in this pass.
- **Separate PR** from the already-landed docs/Clock-DI/edge-case-test PR
  (branch `fix_ttl_edns_bypass`, commits `06b4da1`/`0b834cd`/`0130240`).
- **Security-sensitive**: touches untrusted-input EDNS option parsing
  feeding a caching decision. Plan must call out mandatory
  `/security-review` before landing, and must not regress the existing
  `resolve_bypasses_cache_for_unsupported_edns_options` /
  `resolve_bypasses_cache_for_unsupported_edns_flags_and_version` tests
  (`mod.rs:18930-18954`, `18956+`) for every other (non-Cookie)
  EDNS-option/flag/version case.

## Open design questions for this planning pass

1. Is there an existing per-requester response-rewrite seam this can reuse
   (e.g. `filter_response_for_requester`, `mod.rs:4462` area), and if so,
   what does correct per-request COOKIE-option generation/validation
   (client cookie echo + server cookie compute per RFC 7873 §5.1/§5.3) look
   like at the code level — where does OPT-record stripping/regeneration
   plug into the existing response-assembly path
   (`src/resolver/cache/assemble.rs`)?
2. Where does `cache_supported()`'s EDNS-options check live relative to
   cache-key computation, and what's the minimal-diff way to carve out a
   Cookie-specific exception without touching the bypass logic for every
   other EDNS option/flag/version case?
3. What does RFC 7873 §5.1/§5.3 server-cookie computation require
   concretely (hash inputs: client cookie, client IP, secret; algorithm
   choice) and what crate/primitive in this codebase's existing dependency
   set (see `RUST.md` dependency policy) is appropriate?
4. Test strategy: unit tests for cookie generation/validation in isolation,
   plus e2e tests proving (a) a Cookie-bearing query now gets cache hits,
   (b) each response's cookie is correctly per-requester even when served
   from a shared cache entry, (c) all other EDNS-option bypass cases are
   unchanged.
5. Where exactly does `/security-review` fit in the section sequence —
   after implementation, before the final commit/PR, per this repo's
   `AGENTS.md` "PR touches auth/untrusted-input/network code" trigger.

## Non-goals

- RFC 7830 Padding support.
- BADCOOKIE (RCODE 23) retry/round-trip handling.
- Any change to `CacheTtlPolicy`, TTL aging, or the Clock-DI work (already
  landed separately).
- Redesigning `cache_supported()`'s handling of any EDNS option/flag/version
  other than Cookie.

## Source

- `docs/plans/ttl_remaining/plan.md` — original audit spec, Current State
  point 9 and Open Question 1 describe the finding and the three options.
- `docs/plans/ttl_remaining/claude-interview.md` — Q1/Q4/Q5/Q10/Q11 record
  the decision this plan implements.
- `src/resolver/mod.rs:5508-5520` — `cache_supported()`, the bypass to
  narrow.
- `src/resolver/mod.rs:4462` area — `filter_response_for_requester`, the
  existing per-requester response-rewrite seam to investigate for reuse.
- `src/resolver/mod.rs:18930-18954`, `18956+` — existing EDNS-bypass
  regression tests that must not regress for non-Cookie cases.
- `src/resolver/cache/assemble.rs` — response-assembly path where OPT
  stripping/regeneration would plug in.
- `docs/knowledge/resolver/caching/answer-cache.md` — current-behavior
  knowledge bundle, updated by the ttl_remaining work; will likely need a
  further update once Cookie is allowlisted.
