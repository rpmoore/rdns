# Spec: DNSSEC validation + BADCOOKIE handling

## Context

A performance-focused review of rdns's caching and network paths (see prior
`docs/plans/` perf work) turned up two RFC-compliance gaps as a side effect,
both security-relevant rather than perf-relevant:

1. **DNSSEC validation is parsed-but-never-verified.** The data model and
   the response-assembly logic that consumes it are already built and
   tested; nothing produces a real verdict.
2. **BADCOOKIE (RFC 7873 RCODE 23) handling is a recorded, deliberate
   non-goal** from the earlier `edns_cookie_cache` work, being reopened now.

This spec is input for `/deep-plan:deep-plan` — it scopes and grounds both
gaps with concrete file:line references so the interview/research/plan
stages can proceed without re-deriving this context, but does not itself
decide implementation-level design. No code changes are part of this spec.

## Current state (grounding)

### DNSSEC — plumbing exists, verification does not

- `DnssecState` (`src/resolver/cache/entry.rs:104-115`) already has
  `Unvalidated` / `Insecure` / `Secure` / `Bogus(String)` variants. Every
  cache entry defaults to and stays `Unvalidated` today — `Secure` and
  `Bogus` are `#[allow(dead_code)]`, never constructed anywhere in the
  codebase.
- Response assembly already fully and correctly consumes `dnssec_state`:
  `dnssec_servfail_check` / `negative_dnssec_servfail_check`
  (`src/resolver/cache/assemble.rs:426-459`) force SERVFAIL when any entry
  in the chain is `Bogus`; `dnssec_ad_bit` / `negative_dnssec_ad_bit`
  (`assemble.rs:469-498`) set the AD bit only when every entry in the chain
  is `Secure`. This logic has existing test coverage. **The only missing
  piece is what actually sets the state** — there is no validator.
- `DnssecValidationStatus` (`src/resolver/mod.rs:2418-2420`) has exactly one
  variant, `Disabled`, surfaced in status/metrics output
  (`src/main.rs:1244`, `:1294-1296` → rendered as the label `"disabled"`).
- Recursive-mode resolution already always requests DNSSEC material
  internally (`dnssec_ok = true`, `src/resolver/mod.rs:1373`) — RRSIG /
  DNSKEY / DS / NSEC / NSEC3 wire parsing already exists
  (`src/protocol/mod.rs:2562` `parse_dnskey_record`, `:2579`
  `parse_ds_record`, RRSIG type-46 handling throughout `resolver/mod.rs`).
  A comment at `resolver/mod.rs:840` notes this always-fetch behavior is
  Recursive-mode only. `ResolutionMode::Forward` does not independently
  fetch or validate anything today — it passes through the upstream's own
  AD bit verbatim (`resolver/mod.rs:5291`, `:5663`:
  `ResolutionMode::Forward => decoded.features.dnssec_ok`).
- `NegativeEntry` (`src/resolver/cache/entry.rs`) already carries
  `soa_rrsig` and NSEC/NSEC3 proof records paired with their owner names —
  captured at fetch time, never verified.
- **No trust anchor exists anywhere in the codebase.** Root hints (the
  root server addresses) are bundled today via `RootHintsSource::Bundled` /
  `bundled_root_hints()` (`src/config/mod.rs:727-783`), with a
  `RootHintsSource::Static` override path for config-supplied values. A
  root zone trust anchor (DS record) has no equivalent yet, but the same
  bundled/static-override pattern is a direct precedent.
- **No signature-verification crypto exists**, but none needs to be
  hand-rolled: `domain` (already a dependency, `Cargo.toml:12`, currently
  built with `features = ["zonefile", "bytes", "std", "siphasher"]`) ships
  `dnssec::validator` and `dnssec::sign` modules gated behind its own
  `unstable-validator` feature plus a crypto-backend feature (`ring` or
  `openssl` — currently neither is enabled). Turning this on is a
  feature-flag change to an existing dependency, not a new crate — fits
  `RUST.md`'s "add dependencies conservatively" policy.
- The CD (Checking Disabled) bit is already parsed and threaded throughout
  request handling (`request.header.cd()`, `src/protocol/mod.rs`, e.g.
  lines 639, 735, 795, 972, 1114-1198) but has no connection yet to any
  "still fetch/attach signatures, skip the SERVFAIL-on-Bogus gate for this
  response" behavior — there's nothing to gate yet since nothing produces
  `Bogus`.

### BADCOOKIE — explicit prior non-goal, now being reopened

- `src/protocol/edns_cookie.rs:15-21` module doc states plainly: "This
  module never validates an incoming server cookie's hash or timestamp (no
  BADCOOKIE handling, no secret rotation) — see the parent plan's
  non-goals."
- `docs/plans/edns_cookie_cache/spec.md:36-38` recorded this as a
  deliberate, explicit deferral for that PR: "RFC 7873 §5.2.3 policy: if
  client cookie present with no/invalid server cookie, process normally and
  attach a fresh valid COOKIE option — no BADCOOKIE (RCODE 23) round-trip
  in this pass." This spec revisits that specific, previously-closed
  decision.
- `locate_cookie_option` (`src/protocol/edns_cookie.rs:75-111`) already
  parses the full COOKIE option including any 16-byte server-cookie tail
  when present, but only ever copies out the first 8 (client-cookie) bytes
  (`edns_cookie.rs:100-101`) — server-cookie bytes are located but
  discarded, never compared against what this server would have issued.
- `build_server_cookie` (`edns_cookie.rs:158-182`) already implements the
  RFC 9018 §4.4 computation (SipHash-2-4 via
  `domain::base::opt::cookie::StandardServerCookie::calculate`) and is
  unit-tested against the RFC 9018 Appendix A.1 known-answer vector
  (`edns_cookie.rs:373-400`). A BADCOOKIE check reuses this same primitive
  to recompute-and-compare an incoming server cookie.
- `CookieSecret` (`edns_cookie.rs:56-68`) is one random, CSPRNG-seeded,
  process-lifetime secret generated once at startup
  (`CookieSecret::generate()`, called once from `src/main.rs`). Sufficient
  for a same-process BADCOOKIE check as-is: a restart naturally invalidates
  all previously-issued server cookies, which RFC 7873 already treats as
  the normal "client re-handshakes" case.
- RFC 7873 §5.4 draws a transport distinction worth carrying into the
  design stage rather than resolving here: servers SHOULD respond
  BADCOOKIE to a bad/stale server cookie over UDP, but SHOULD still process
  the query normally over TCP, since TCP already provides some
  off-path-spoofing resistance on its own.

## Decided scope (do not re-litigate in /deep-plan)

- Reuse `domain`'s `unstable-validator` (+ a crypto-backend feature, `ring`
  preferred for a pure-Rust build) instead of implementing RRSIG/DS/DNSKEY
  cryptographic verification by hand.
- Reuse the existing `DnssecState` / `DnssecValidationStatus` data model as
  the validator's output shape — it is already correctly consumed by
  `assemble.rs`; do not redesign it.
- Reuse `build_server_cookie` for BADCOOKIE's recompute-and-compare step —
  do not implement a second cookie-hash code path.
- Bundle a static root-zone trust anchor the same way `bundled_root_hints()`
  bundles root server addresses, with a config-level static override
  (mirroring `RootHintsSource::Static`).
- No RFC 5011 automated trust-anchor rollover in this pass — a static,
  manually-updated bundled anchor is in scope; automated rollover is future
  work.
- No cookie-secret rotation or cross-restart persistence for BADCOOKIE — the
  existing one-secret-per-process-lifetime model is sufficient.

## Open design questions for /deep-plan's interview stage

1. **Sequencing.** DNSSEC validation and BADCOOKIE are independently
   shippable — different files, different code paths (`resolver/mod.rs`
   chain-of-trust walk vs. `protocol/edns_cookie.rs` plus an early-reject
   hook). Should this stay one `docs/plans/sec_work/` implementation
   plan/PR, or should the interview stage split it into two sequenced
   plans/PRs?
2. **DNSSEC scope boundary.** Validate only in `ResolutionMode::Recursive`
   (matches today's always-fetch behavior), or also add independent
   validation in `ResolutionMode::Forward` instead of trusting the
   upstream's AD bit as it does today?
3. **Where the chain-of-trust walk plugs in.** Per referral, alongside the
   existing delegation-cache walk, or as a separate pass over
   already-fetched DNSKEY/DS/RRSIG material immediately before
   `build_rrset_entry` / `build_negative_entry`
   (`src/resolver/mod.rs:~1045-1120`) stamp `dnssec_state` onto a cache
   entry?
4. **CD-bit semantics.** Confirm the intended RFC 4035 §3.2.2 behavior:
   when `request.header.cd()` is true, still fetch/attach signatures and
   compute `dnssec_state` (so the entry is cacheable and correct for
   *other* requesters), but skip the SERVFAIL-on-`Bogus` gate for this
   specific response — and identify exactly where that hooks into
   `dnssec_servfail_check`.
5. **Trust anchor format/source.** Bundle IANA's current root zone KSK as a
   static DS record (mirroring `bundled_root_hints()`'s bundling
   mechanism) — what update/staleness story is acceptable given no RFC
   5011 rollover automation is in scope (e.g. a version marker + CI
   staleness check, similar to whatever currently keeps root hints fresh)?
6. **BADCOOKIE transport nuance.** Confirm the RFC 7873 §5.4 UDP-vs-TCP
   handling difference, and decide where the early-reject hook belongs in
   the request pipeline (before cache lookup, alongside existing
   EDNS/cache-admission checks).
7. **Test strategy.** For DNSSEC: known-answer vectors against a real
   signed zone's DNSKEY/DS/RRSIG chain, plus Bogus-injection tests (tampered
   RRSIG bytes) proving SERVFAIL fires. For BADCOOKIE: unit tests for
   tampered/expired/wrong-secret server cookies, plus e2e assertions that a
   bad server cookie over UDP gets RCODE 23 with a freshly issued cookie
   attached.
8. **`/security-review` placement.** Per `AGENTS.md`'s "PR touches
   auth/untrusted-input/network code" trigger — both tracks verify
   attacker-controlled wire bytes and must gate on a security review before
   landing. Confirm where in the section sequence this runs for each track.

## Non-goals

- RFC 5011 automated trust-anchor rollover.
- DNSSEC signing (validation only — this resolver is not authoritative for
  signed zones).
- RFC 7830 Padding (already deferred separately in `edns_cookie_cache`).
- Cookie-secret rotation or persistence across restarts.
- Any change to `ResolutionMode::Forward`'s current AD-bit passthrough
  behavior, unless Open Question 2 above decides otherwise.

## Source

- `src/resolver/cache/entry.rs:104-115` — `DnssecState` enum.
- `src/resolver/cache/assemble.rs:426-498` — SERVFAIL-on-Bogus / AD-bit
  consumption logic.
- `src/resolver/mod.rs:840`, `:1373`, `:2418-2420`, `:5291`, `:5663`,
  `:~1045-1120` — always-fetch-DNSSEC-in-Recursive-mode behavior,
  `DnssecValidationStatus`, Forward-mode AD passthrough, entry-construction
  hook points.
- `src/protocol/mod.rs:2562`, `:2579`, `639,735,795,972,1114-1198` (CD bit)
  — DNSKEY/DS parsing, CD-bit threading.
- `src/config/mod.rs:727-783` — `RootHintsSource::Bundled`/`Static`
  pattern to mirror for a trust anchor.
- `Cargo.toml:12` — `domain` crate's current feature set.
- `src/protocol/edns_cookie.rs:15-21,56-68,75-111,100-101,158-182,373-400`
  — cookie parsing/secret/server-cookie-compute, the non-goal statement,
  and the RFC 9018 known-answer test to reuse as a validation reference.
- `src/main.rs:1244,1294-1296` — `dnssec_validation` status surfaced today.
- `docs/plans/edns_cookie_cache/spec.md:36-38` — the original recorded
  decision to defer BADCOOKIE, being reopened by this spec.
