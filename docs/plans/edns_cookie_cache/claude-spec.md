# Spec: EDNS Cookie cache-bypass fix (synthesized)

## Context

`cache_supported()` (`src/resolver/mod.rs:5508-5520`) bypasses the cache for
ANY query carrying an EDNS option, including the RFC 7873 DNS Cookie option
— which modern `dig`/stub resolvers attach by default. Confirmed against a
live v0.1.6 deployment. This makes the already-landed cache-hit TTL aging
work (`docs/plans/ttl_remaining/`) invisible in most real traffic.

This is a follow-on to `docs/plans/ttl_remaining/plan.md` (Open Question 1),
whose three options were decided via stakeholder interview
(`docs/plans/ttl_remaining/claude-interview.md` Q1/Q4/Q5/Q10/Q11): **Option
(b)**, a broader cache-key-neutral allowlist. That decision is not
re-litigated here — this document plans the *implementation*.

## Decided scope

- **Allowlist Cookie (option code 10) only**, not Padding (RFC 7830, no-op
  until DoT/DoH exists).
- Cache the answer data; **never cache/replay OPT record bytes** — strip and
  regenerate the OPT record (including a fresh COOKIE option) per request at
  serve time.
- **Server cookie secret**: one random in-memory secret generated at
  startup, no config/persistence surface. Restart resets cookie validity —
  acceptable per RFC (clients re-handshake automatically).
- **RFC 7873 §5.2.3/§5.2.4 policy**: always process normally and attach a
  fresh, freshly-computed server cookie — **never validate an incoming
  server cookie's hash or timestamp** (dead code otherwise, since behavior
  doesn't branch on validity). Only the 8-byte client cookie is
  parsed/echoed.
- **No FORMERR for malformed COOKIE options** (wrong length: not 8, not
  16-40) — falls back to today's generic bypass behavior unchanged. No new
  rejection path.
- **No new metrics/events** — Cookie-bearing cache hits flow through
  existing `CacheHit`/`CacheMiss`/`CacheBypass` counters unchanged.
- **Dependency**: enable the already-present `domain` crate's `siphasher`
  and `rand` Cargo features (currently `default-features = false, features
  = ["zonefile", "bytes", "std"]`) rather than adding a new top-level crate.
  Reuse `domain::base::opt::cookie`'s RFC-9018-test-vector-verified
  `StandardServerCookie` construction as the hashing primitive.
- **Algorithm**: RFC 9018 (not RFC 7873 Appendix B, which is explicitly
  non-interoperable and "MUST NOT be used"). 16-byte server cookie =
  1-byte Version(1) + 3-byte Reserved(0) + 4-byte big-endian Timestamp +
  8-byte SipHash-2-4 output (output serialized **little-endian** — a
  documented `domain`-crate gotcha; if hand-rolled instead of calling
  `domain` directly, must be tested against RFC 9018 Appendix A vectors).
  Hash input: `client_cookie(8) | version(1) | reserved(3) | timestamp(4) |
  client_ip(4 or 16)`.
- **Module home**: new module under `src/protocol/` (e.g.
  `src/protocol/edns_cookie.rs`) — protocol owns DNS wire-format concerns
  per `AGENTS.md` layering.
- **Secret wiring**: mirror the `Clock` DI pattern from `ttl_remaining`
  (section-02). Generate once in `main.rs` at startup, wrap in an `Arc`,
  thread into `ResolveQuery` construction and down to wherever
  `assemble_response`/`requester_opt_record` needs it.
- **Security review**: mandatory `/security-review` as the final section,
  run against the complete diff before PR — per `AGENTS.md`'s
  untrusted-input/network-code trigger. Must not regress
  `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
  (orthogonal, version/flags not options) and must repoint
  `resolve_bypasses_cache_for_unsupported_edns_options` (currently uses a
  Cookie-shaped option as its "any unsupported option" example) to a
  genuinely-still-unsupported code.
- **Separate PR** from the already-landed docs/Clock-DI/edge-case-test PR
  (branch `fix_ttl_edns_bypass`, commits `06b4da1`/`0b834cd`/`0130240`).
- **Documented trade-off**: always-process-normally forfeits DNS Cookies'
  anti-off-path-spoofing value (that comes from the *rejection* path this
  plan doesn't implement). This must be stated explicitly in the
  knowledge-bundle doc output so a future reader doesn't assume DoS
  protection that isn't there — this resolver's separate source-IP
  legitimacy handling is assumed to exist elsewhere and is out of scope
  here.

## Non-goals

- RFC 7830 Padding support.
- BADCOOKIE (RCODE 23) retry/round-trip handling.
- Server-cookie secret rotation (RFC 9018 §5) — single static in-memory
  secret only.
- Any change to `CacheTtlPolicy`, TTL aging, or Clock DI (landed already).
- Any change to `cache_supported()`'s handling of EDNS options/flags/version
  other than Cookie.
- Incoming server-cookie validation (hash check, timestamp-window
  acceptance) — never implemented per Q1's decision.

## Existing seams and gaps (from codebase research)

| Concern | Seam | Gap |
|---|---|---|
| Cache bypass gate | `cache_supported()` (`mod.rs:5508-5520`), sole caller `probe_cache` (`4409-4479`) | Replace `edns.options.is_empty()` with "empty, or exactly one well-formed COOKIE option" |
| Per-option-code EDNS parsing | None — `validate_edns_options` (`protocol/mod.rs:2643-2651`) discards option_code | New COOKIE-scanning helper over `edns.options: Vec<u8>` |
| Per-request data reaching cache-hit assembly | `QueryFeatures` (`mod.rs:241-274`) → `assemble_response`/`assemble_negative_response` via `decoded.features` | Add a Cookie-carrying field, populated in `QueryFeatures::from_message` |
| Per-request OPT record at serve time | `requester_opt_record` (`assemble.rs:437-447`) | Extend to accept/emit non-empty `options`; `build_opt_record` (`protocol/mod.rs:1246-1278`) hardcodes `options: Vec::new()` today |
| Per-requester content-trimming precedent | `filter_response_for_requester` (`mod.rs:1480-1507`) | Pattern reference only — lives on the recursive-miss path, not cache-hit-serve |
| Client IP for hash input | `ResolveRequest.client_ip` (`mod.rs:167-183`) | Already available at every relevant call site |
| Crypto primitive | `domain` crate (already a dep) | Enable `siphasher`+`rand` features |
| Regression tests | `resolve_bypasses_cache_for_unsupported_edns_options` (`mod.rs:18996-19019`) uses a Cookie-shaped option as its "unsupported" example | Repoint to a still-unsupported code (e.g. NSID=3); add new inverse Cookie test |
| Test fixture layer | `a_query_with_edns_flags(...)` (`mod.rs:7975+`) | Add `a_query_with_cookie(...)` built on top of it |

## Source

- `docs/plans/ttl_remaining/plan.md` and `claude-interview.md` — origin decision.
- `src/resolver/mod.rs:5508-5520` (`cache_supported`), `4409-4479`
  (`probe_cache`), `241-274` (`QueryFeatures`), `1480-1507`
  (`filter_response_for_requester`), `18996-19047` (existing bypass tests),
  `167-183` (`ResolveRequest`), `7975+` (test query builders).
- `src/protocol/mod.rs:207-215` (`EdnsInfo`), `2617-2651` (OPT parsing/validation),
  `1246-1278` (`build_opt_record`).
- `src/resolver/cache/assemble.rs:15-28` (module doc), `437-447`
  (`requester_opt_record`).
- RFC 7873 (DNS Cookies), RFC 9018 (Interoperable DNS Server Cookies), RFC
  6891 §6.1 (OPT semantics).
- `domain` crate v0.12.1, `src/base/opt/cookie.rs` and
  `src/net/server/middleware/cookies.rs` (reference implementation).
- `RUST.md:20` (dependency-addition policy).
