# Synthesized Spec: DNSSEC Validation + BADCOOKIE Handling

Combines the original `spec.md`, `claude-research.md`, and
`claude-interview.md`. This is the authoritative input to
`claude-plan.md` — implementation-level decisions below are settled;
open items were closed in the interview.

## Delivery shape

**One combined plan document, two separate PRs.** Section boundaries in
`claude-plan.md` are grouped so that DNSSEC-validation sections form one
contiguous track and BADCOOKIE sections form another, each track ending
with its own `/security-review` gate before that track's PR opens.

## Track A — DNSSEC validation

### Scope
- **Recursive mode only.** `ResolutionMode::Forward` keeps passing through
  the upstream's AD bit verbatim, unchanged (`resolver/mod.rs:5291,5663`).
- Validate real chain-of-trust: DS → DNSKEY → RRSIG, using `domain`'s
  `dnssec::validator` module (feature `unstable-validator` + `ring` crypto
  backend). Pin `domain = "0.12"` (post-v0.11.0 reorg; API stable since).
- New transitive deps (`moka`, `unstable-client-transport`) from
  `unstable-validator` are accepted — document in `Cargo.toml` comment and
  the PR description, no further minimization needed.

### Architecture
- **Separate validation pass**, not inline in the referral walk. Runs
  immediately before `build_rrset_entry` / `build_negative_entry`
  (`src/resolver/mod.rs:1039-1064`, `:1080-1120`), which today hardcode
  `dnssec_state: Default::default()` at lines 1057 and 1117 — those are the
  two call sites the validator's output replaces.
- Mirrors Unbound/BIND's validator/iterator separation: the pass consumes
  already-fetched DNSKEY/DS/RRSIG material from the synthesized response
  (`synthesize_recursive_cname_response`, `:1367-1430`, always
  DNSSEC-complete since `dnssec_ok = true` is forced for every recursive
  fetch, `:1373`), and independently fetches DS/DNSKEY up the parent chain
  via `domain`'s `ValidationContext` (which issues its own queries against
  the same upstream transport) when not already cached.
- Output maps directly onto existing `DnssecState`: `domain`'s
  `ValidationState::{Secure, Insecure, Bogus, Indeterminate}` →
  `DnssecState::{Secure, Insecure, Bogus(reason), Unvalidated}` (treat
  `Indeterminate` as `Unvalidated` unless research/implementation surfaces
  a reason to distinguish it).
- No new `IterativeQueryState` fields, no changes to
  `evaluate_authority_response`/`handle_referral`/`referral_authorities`.

### CD-bit semantics
- Validation always runs and `dnssec_state` is always computed/cached,
  regardless of the request's CD bit (RFC 4035 §3.2.2, §4.7 BAD-cache
  interaction).
- CD only gates response-code enforcement: `dnssec_servfail_check`'s call
  site skips the SERVFAIL-on-Bogus behavior when the *requesting* query has
  CD=1, but the cache entry itself stays correctly stamped so other
  requesters (CD=0) get correct enforcement. Locate and thread this at the
  point `dnssec_servfail_check`/`negative_dnssec_servfail_check`
  (`assemble.rs:426-459`) are invoked from response assembly — this is the
  one behavior change needed in `assemble.rs`; the SERVFAIL/AD-bit
  functions themselves stay as-is.

### Trust anchor
- Bundle **both** KSK-2017 (key tag 20326) and KSK-2024 (key tag 38696) as
  static DS records, mirroring `RootHintsSource::Bundled`/`Static`
  (`src/config/mod.rs:864-868`, `bundled_root_hints()` at `:935` using
  `include_str!("named.root")`). New `TrustAnchorSource::Bundled/Static`
  enum, new `src/config/root-anchor.txt`-style bundled file, config-level
  static override following the same shape.
- **Grounding note**: KSK-2024 becomes the active root signer 2026-10-11;
  KSK-2017 is revoked ~2027-01-11. Bundling both now is required regardless
  of ship date to avoid the 2018-rollover failure mode (9,000+ resolvers
  went dark on a stale single-anchor bundle).
- **CI staleness check**: a scheduled CI job fetches
  `https://data.iana.org/root-anchors/root-anchors.xml` +
  `root-anchors.p7s` + `icannbundle.pem`, verifies the CMS signature,
  parses `validFrom`/`validUntil` per RFC 9718, and fails the build if the
  bundled anchor set is missing an in-window digest or a bundled digest's
  `validUntil` has passed or is imminently approaching. Reference
  implementation to adapt: `iana-org/get-trust-anchor` (fetch logic only;
  CMS verification must be added).
- No RFC 5011 automated rollover (confirmed non-goal, `domain`'s validator
  doesn't implement it either).

### Config & defaults
- `DnssecValidationMode` gets a second variant: `Enabled` (alongside
  existing `Disabled`). Same for `DnssecValidationStatus`. No richer
  per-outcome mode/status enum — Secure/Insecure/Bogus counts are metrics,
  not mode/status.
- **On by default** once shipped — this is an explicit user decision
  (deviates from the interview's suggested opt-in default). Existing
  deployments start validating and enforcing SERVFAIL-on-Bogus immediately
  on upgrade. Flag this prominently in the plan's rollout/changelog
  section since it's a behavior change on upgrade, not just a new opt-in
  feature.
- Both enum changes affect `DnssecValidationMode::cache_namespace_label()`
  (`config/mod.rs:1113-1117`), which feeds the cache-epoch namespace hash
  (`docs/knowledge/resolver/caching/cache-epoch.md:27`) — enabling
  validation by default changes the cache namespace on upgrade, which is
  expected/correct (old unvalidated entries shouldn't be reused as if
  validated) but must be called out explicitly as an intended cache
  invalidation on upgrade, not a bug.

### Metrics
- New labeled `Counter<u64>` (e.g. `dnssec_validation_results_total`) with
  an outcome label/attribute (`Secure|Insecure|Bogus|Indeterminate`),
  incremented once per validated query. Follows the existing
  `backend_status_attributes` labeling pattern (`src/main.rs:1256-1275`).
  The existing `dnssec_validation_disabled` gauge (`:916`, `:1027`) and
  `dnssec_validation_label` (`:1294-1297`) get updated match arms for the
  new `Enabled` variant (compiler-forced — no wildcard arms today).

### Testing
- **Known-answer chain test**: generate a small deterministic signed test
  zone + keys offline (tool TBD in plan — e.g. `ldns-signzone` or
  `domain`'s own signing support), commit the resulting DNSKEY/DS/RRSIG
  wire bytes as a fixture. No external network dependency in tests, full
  control over NSEC/NSEC3/wildcard edge cases.
- **Bogus-injection tests**: tamper a signature byte in the fixture,
  assert `DnssecState::Bogus` and downstream SERVFAIL via the existing
  `assemble.rs` state-injection test pattern (tests already set
  `entry.dnssec_state = DnssecState::Bogus(...)` directly at
  `assemble.rs:1499,1560,1713,1771,2274,2355,2357,2393` to exercise
  `dnssec_servfail_check`/`dnssec_ad_bit` — the new validator needs its own
  tests that *produce* the state these tests already assume, not
  duplicate the assembly-side assertions).
- **Algorithm-downgrade / NSEC3 opt-out tests**: cover the pitfalls
  research flagged — an unsigned answer from a known-signed zone must
  yield `Bogus`, not `Insecure`, unless a validated NSEC/NSEC3
  absence-of-DS proof exists; opt-out NSEC3 must not be usable to downgrade
  a signed subdomain (cf. BIND GitLab #5970 class of bug).
- **e2e**: extend the `verify` skill flow with a DNSSEC-specific probe —
  `dig +dnssec` against a signed test zone or public well-known signed
  domain, assert AD bit set / SERVFAIL on a Bogus case, alongside the
  existing miss/hit/TCP/negative-cache checks.

## Track B — BADCOOKIE handling

### Scope
- Implement RFC 7873 §5.2.1-§5.2.5's server-side decision tree exactly:
  on a client cookie with an **invalid or stale** server cookie (a
  server-cookie tail that IS present but doesn't match a recompute, or is
  malformed), **over UDP** respond BADCOOKIE (RCODE 23) with a freshly
  issued correct server cookie attached; **over TCP**, process the query
  normally regardless of cookie state (§5.2.3's TCP carve-out — "the
  server SHOULD take the authentication provided by the use of TCP into
  account and SHOULD choose (3)"). A client cookie with **no
  server-cookie tail at all** (first contact — client hasn't been issued
  one yet) is a separate case (§5.2.3's 3-way policy choice) and is
  **not** a BADCOOKIE trigger — process normally and issue a fresh cookie,
  matching existing pre-BADCOOKIE behavior and RFC 7873's requirement that
  servers "MUST, at least occasionally, respond" so clients can bootstrap.
- Correction carried from research: the operative transport-distinction
  citation is **§5.2.3/§5.2.4**, not §5.4 (§5.4 is the unrelated
  QDCOUNT=0 "querying for a server cookie" bootstrap mechanism — out of
  scope for this pass).
- Reuse `build_server_cookie` (`edns_cookie.rs:158-182`) for the
  recompute-and-compare step — no second cookie-hash code path. This
  already implements the RFC 9018 SipHash-2-4 recipe, matching what
  interoperable implementations (BIND 9.16+, Knot 2.9.0+) use.
- No new config toggle — BADCOOKIE checking is correct behavior wherever
  EDNS cookies are already accepted; always on, no new config surface.

### Wire response
- `ResponseCode` (`protocol/mod.rs:93-100`) only models RCODE 0-5 and
  cannot represent BADCOOKIE (23) any more than it could BADVERS (16).
  Replicate the `build_badvers_response` (`:609-655`) +
  `build_opt_record_with_extended_rcode` (`:1276+`) pattern: split the
  12-bit extended RCODE across the header's 4-bit nibble and the OPT
  record's extended-RCODE byte (23 = nibble 7 + byte 1).
- New `QueryValidationError`-style variant (mirroring
  `UnsupportedEdnsVersion` at `:71-73`) with its own `response_code()`
  bucketing (likely `FormErr` for metrics, matching the BADVERS precedent's
  documented rationale at `:119-127`) and a
  `BasicResponseFactory::protocol_error` special case
  (`resolver/mod.rs:6620`), replicating the BADVERS wiring end-to-end:
  parse-time detection → metrics bucket → dedicated wire builder.

### Hook point
- Extend `cache_supported` (`resolver/mod.rs:6526-6538`) or add a sibling
  check invoked from `probe_cache` (`:~5225-5250`) before the
  `cache_supported(decoded)` branch at `:5234` — this is the single
  existing EDNS-admission gate before cache lookup, already importing
  `edns_cookie::is_solely_cookie_option`.
- Recompute the expected server cookie via `build_server_cookie` for the
  incoming client cookie + request source IP, compare against the 16-byte
  server-cookie tail currently parsed-but-discarded at
  `edns_cookie.rs:100-101`.

### Testing
- Unit tests for tampered/expired/wrong-secret server cookies, following
  the existing hand-built-byte-vector pattern
  (`parse_cookie_option_rejects_malformed_lengths` /
  `_rejects_truncated_tlv_bytes` / `_rejects_duplicates` in
  `edns_cookie.rs`).
- e2e assertions: a bad server cookie over UDP gets RCODE 23 with a
  freshly issued cookie attached; the same bad cookie over TCP gets a
  normal answer (no BADCOOKIE), per the §5.2.3 TCP carve-out — this
  UDP-vs-TCP behavioral split needs an explicit e2e test pair, not just
  unit coverage, since it's a transport-conditional response-code decision.

## Cross-cutting

### `/security-review` gate
Each track's plan ends with a "security review + fix findings" section,
run once that track's code (parsing + validation/check logic + tests) is
complete, immediately before that track's PR opens. Both tracks parse
attacker-controlled wire bytes (RRSIG/DNSKEY signature bytes; server
cookie bytes), triggering AGENTS.md's auth/untrusted-input/network trigger.

### `docs/knowledge/` updates
- `docs/knowledge/resolver/caching/serve-stale.md:113-118` currently
  states DNSSEC validation doesn't exist and the AD=1 path is unreachable
  in production — **must be updated** once the validator ships (AGENTS.md
  Knowledge Bundle trigger: stale doc after code change).
- `docs/knowledge/resolver/caching/answer-cache.md:54-55`'s `dnssec_state`
  description ("stays Unvalidated until real DNSSEC validation exists")
  needs the same update.
- New concept doc needed for the DNSSEC validator itself (no existing doc
  covers it) — likely under `docs/knowledge/resolver/` given it's a
  resolver-owned policy/decision concern per AGENTS.md's layering.
- New concept doc needed for EDNS cookie handling generally (none exists
  today) if BADCOOKIE's addition is judged substantial enough to warrant
  one — use judgment per AGENTS.md ("a subsystem with real invariants...
  does" warrant a doc; a pure-addition to an existing well-tested module
  may just need the existing behavior noted inline).

### Non-goals (carried from original spec, all confirmed unchanged)
- RFC 5011 automated trust-anchor rollover.
- DNSSEC signing (validation only).
- RFC 7830 Padding (already deferred separately).
- Cookie-secret rotation or persistence across restarts.
- Any change to `ResolutionMode::Forward`'s AD-bit passthrough.
- RFC 7873 §5.4 QDCOUNT=0 server-cookie-bootstrap query type.
- Cross-instance/anycast cookie-secret sharing and its associated
  repeated-BADCOOKIE monitoring signal (noted by research as a future
  concern if rdns ever runs multiple instances sharing a secret — not in
  scope now since `CookieSecret` stays one-per-process-lifetime).
