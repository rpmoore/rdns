# Implementation Plan: DNSSEC Validation + BADCOOKIE Handling

## Overview

`rdns` is a Rust recursive/forwarding DNS resolver. Two RFC-compliance gaps
exist today, both security-relevant:

1. **DNSSEC is parsed but never verified.** The resolver already fetches
   DNSKEY/DS/RRSIG material for every recursive query, and the cache/response
   layer already fully consumes a `DnssecState` verdict (SERVFAIL-on-Bogus,
   AD-bit-on-Secure) — but nothing ever produces that verdict. Every entry
   sits at `Unvalidated` forever.
2. **BADCOOKIE (RFC 7873 RCODE 23) is a deliberate, recorded non-goal**
   from an earlier EDNS-cookie feature, being reopened now. The server
   already computes its own correct server cookie and can parse an
   incoming one, but never compares the two — a spoofed or stale server
   cookie is silently accepted.

This plan delivers both as two independently shippable, independently
reviewable tracks (Track A: DNSSEC, Track B: BADCOOKIE) sharing one planning
document but landing as two separate PRs, each gated by its own
`/security-review` before merge (both tracks parse attacker-controlled wire
bytes).

Full grounding, codebase file:line references, and web research (the
`domain` crate's validator API, real-resolver architecture precedent, IANA
root KSK rollover timeline, and the exact RFC 7873 transport rules) live in
`claude-research.md`. Design decisions and their rationale live in
`claude-interview.md`. This plan is the synthesis — read `claude-spec.md`
first if you want the compressed decision record; this document is the
step-by-step build order.

## Architectural summary

**Track A (DNSSEC)** adds one new thing to the resolver: a validation pass
that runs after a recursive query's data has been fully fetched (the
existing code already always fetches DNSSEC material in Recursive mode) and
before that data is turned into a cache entry. This pass calls into the
`domain` crate's `dnssec::validator` module — a full DNSSEC validator we do
not need to (and should not) hand-roll — feeding it the response and root
trust anchors. **Important**: `domain`'s validator does its own DS/DNSKEY
chase against the upstream as needed — the pass does not depend on rdns's
existing iterative fetch having already accumulated a full chain; it works
because the validator independently walks up from the terminal answer to
the trust anchor, not because rdns's referral walk happens to gather that
material as a side effect. It returns one of
`Secure`/`Insecure`/`Bogus`/`Indeterminate`. That verdict is translated into
rdns's existing `DnssecState` enum and stamped onto the cache entry at the
same two call sites that build every cache entry today. Nothing about cache
lookup, response assembly, or the referral/delegation walk changes — those
already correctly consume `DnssecState`, they just haven't had a real value
to consume yet.

**Track B (BADCOOKIE)** adds one new check to the existing EDNS-admission
gate that already runs before every cache lookup: recompute what this
server's server cookie *should* be for the incoming client cookie (reusing
the exact function that already computes outgoing server cookies), compare
it to what the client sent, and — over UDP only — reject with RCODE 23 and
a freshly issued cookie if the presented server cookie is invalid or stale.
A client cookie with no server cookie at all (first contact) is a distinct
case and is not rejected — see B2. Over TCP, the RFC explicitly says to
skip the invalid/stale check and process normally, since TCP already
provides some spoofing resistance on its own. This also requires teaching
the wire-response layer about RCODE 23, which today can only represent
RCODE 0-5 — the exact same problem BADVERS (RCODE 16) already solved, so
this reuses that pattern rather than inventing a new one.

**What ties them together**: both tracks handle attacker-controlled wire
bytes (signature bytes, cookie bytes) that an adversary can craft to try to
bypass validation, so both need a security review pass and both need
malformed/tampered-input tests, not just valid-input tests.

---

## Track A: DNSSEC Validation

### A1. Dependency and feature setup

Update `Cargo.toml`'s `domain` dependency:
- Bump to `domain = "0.12"` (currently pinned `"0.12.1"`; `.lock` already
  resolves `0.12.2`) — pin the major.minor floor at `0.12` explicitly since
  the validator API had a breaking reorg in `0.11.0` that is now behind us;
  staying on `0.12.x` avoids re-crossing that boundary accidentally.
- Add feature flags: `unstable-validator` and `ring` (the pure-Rust crypto
  backend — preferred per the spec's decided scope over `openssl`).
- Note in a `Cargo.toml` comment (or the PR description) that
  `unstable-validator` transitively pulls in `moka` (a caching crate) and
  `unstable-client-transport`, beyond the crypto backend — this is expected
  and accepted, not a mistake to "fix" later. This step has no *runtime*
  behavior change on its own, but it does expand rdns's build and
  supply-chain surface (two new transitive dependencies); call that out
  explicitly in the PR description rather than treating the step as
  fully inert.
- Confirm the crate still builds and existing tests pass with the new
  feature flags before writing any validator code — this isolates dependency
  issues from logic issues.

### A2. Trust anchor bundling

Add a new trust-anchor source mirroring the existing root-hints pattern
(`RootHintsSource::Bundled`/`Static` at `src/config/mod.rs:864-868`,
`bundled_root_hints()` at `:935` using `include_str!("named.root")`):

- New bundled data file (e.g. `src/config/root-anchor.txt`) containing
  **both** current root zone trust anchors: KSK-2017 (key tag 20326, the
  currently active signer) and KSK-2024 (key tag 38696, the standby that
  becomes active 2026-10-11). Format should match whatever `domain`'s
  `TrustAnchors::from_reader()`/`from_u8()` expects (BIND-style
  trust-anchor text) — confirm the exact expected format against the
  `domain` crate's docs/source before writing the file, since this is
  new-to-rdns input format, not something existing code already parses.
- New `TrustAnchorSource::Bundled | Static(Vec<...>)` enum in
  `src/config/mod.rs`, config-level static override, following the exact
  shape of `RootHintsSource`. Wire it into whatever validated config
  struct assembles resolver startup state, the same way `RootHintsSource`
  is wired today.
- Document (in the plan's PR description, not in code) that this bundled
  anchor set requires manual refresh on future root KSK rollovers — no RFC
  5011 automated rollover is in scope, matching the spec's non-goals.

### A3. CI staleness check for the bundled anchor

Add a **separate, scheduled** workflow (e.g. weekly, not part of per-PR
CI) that:
- Fetches `https://data.iana.org/root-anchors/root-anchors.xml`,
  `root-anchors.p7s`, and `icannbundle.pem` from IANA.
- Verifies the CMS signature over the XML using the ICANN bundle
  certificate (per RFC 9718's guidance — this signature check is required,
  not optional, since the XML fetch alone isn't authenticated).
- Parses each `KeyDigest`'s `validFrom`/`validUntil` attributes.
- Alerts (does not block unrelated PRs — this must not be wired into
  per-PR CI, since an IANA endpoint outage or transient fetch failure
  would otherwise block unrelated work) if: (a) the currently-bundled
  anchor set (from A2) is missing a digest that's inside its valid
  window, or (b) any bundled digest's `validUntil` has passed or is
  within **60 days** of passing.
- Treat a fetch/verification failure (endpoint down, signature doesn't
  verify) as a distinct alert from an actual staleness finding — a failed
  check is "we couldn't confirm freshness," not "the anchor is stale";
  don't conflate the two in the alert output.
- `iana-org/get-trust-anchor` (a small dependency-free Python script) is a
  useful reference for the fetch step, but does not itself do CMS
  verification — that part must be added.

### A4. Validation pass — core logic

Add a new module (suggested location: `src/resolver/dnssec_validation.rs`
or similar, alongside the existing `resolver/cache/` submodule structure —
follow whatever grouping convention `resolver/mod.rs`'s existing
sibling-module layout uses) containing:

- A function that takes the fully-synthesized recursive response (the
  same data `build_rrset_entry`/`build_negative_entry` currently consume)
  plus the trust anchors from A2, and returns a `DnssecState`.
- **Transport adapter spike (do this first, before writing the rest of
  A4)**: rdns has its own `Message`/`RecursiveAuthorityTransport` types
  (`src/resolver/mod.rs:7823-7830` and friends); `domain`'s
  `ValidationContext<Upstream>` needs `domain::base::Message` +
  something implementing `domain::net::client::SendRequest`. These are
  not the same types, and bridging them (so the validator's own
  DS/DNSKEY chase queries flow through rdns's existing upstream
  transport rather than opening a separate connection path) is real
  design work, not a mechanical wrapper — budget explicit time for this
  as its own sub-step, including how errors and timeouts on the adapter
  side surface back to `validate_msg`'s caller (see the timeout bullet
  below).
- Internally, this constructs a `domain::dnssec::validator::context::ValidationContext`
  using the A4 adapter as the `Upstream` type parameter, calls
  `validate_msg()`, and maps the resulting `ValidationState` onto
  `DnssecState`:
  - `Secure` → `DnssecState::Secure`
  - `Bogus` → `DnssecState::Bogus(reason)` (thread through whatever
    diagnostic `domain` provides, e.g. via the `ExtendedError` return value,
    into the reason string)
  - `Insecure` → `DnssecState::Insecure`
  - `Indeterminate` → `DnssecState::Unvalidated` (data-model unchanged per
    the decided scope, but see A7 — the outcome metric must distinguish
    "validation ran and was inconclusive" from "validation never ran," so
    this collapse is metrics-visible even though it's state-invisible)
- **Timeout and error handling (fail-closed)**: `validate_msg`'s DS/DNSKEY
  chase must be bounded by rdns's existing per-query/per-authority timeout
  budget (`per_query_deadline`/`per_authority_timeout` or equivalent) —
  it must not add an unbounded wait on top of normal resolution. A
  timeout or transport error during validation maps to
  `DnssecState::Bogus` with a diagnostic reason (e.g. "validation timed
  out"), **not** to `Insecure` or silently to `Unvalidated` — treating
  "couldn't determine" the same as "provably unsigned" is the same
  algorithm-downgrade pitfall covered in A8's downgrade test, just
  triggered by a timeout instead of a crafted response. This is a
  deliberate fail-closed choice: transient upstream slowness during
  validation can produce a SERVFAIL for CD=0 requesters. Call this out in
  the PR description and in C3's rollout notes, since it's a real,
  intended trade-off, not an oversight.
- Configure `domain`'s `Config` builder with sane defaults for
  `set_nsec3_iter_insecure`/`set_nsec3_iter_bogus` (high NSEC3 iteration
  counts are a known DoS vector against validators — this is a policy knob,
  not optional to leave at whatever the crate's own default is without a
  deliberate choice) and other `Config` setters as needed
  (`set_max_validity`, `set_max_bogus_validity`, etc. — consult `domain`'s
  docs for reasonable starting values).
- **Known upstream limitation, accepted as-is**: `domain`'s validator
  fetches DS/DNSKEY sequentially, doesn't prefetch, and can issue
  duplicate fetches for parallel same-name queries (e.g. simultaneous A
  and AAAA lookups) — this is documented in the crate itself, not
  something rdns's wiring can fix without vendoring/patching `domain`.
  Not solved in this pass; watch A7's latency-relevant metrics after
  rollout rather than attempting to fix it now.

### A5. Wiring the validation pass into entry construction

- Call the A4 function from the code path that leads into
  `build_rrset_entry` (`src/resolver/mod.rs:1039-1064`) and
  `build_negative_entry` (`:1080-1120`), replacing the hardcoded
  `dnssec_state: Default::default()` at lines 1057 and 1117 with the real
  computed value.
- This only applies in `ResolutionMode::Recursive` — confirm the call site
  is reached only on that path (per the scope decision: Forward mode is
  unchanged and keeps trusting the upstream's AD bit verbatim).
- Validation always runs and the result is always stored on the entry,
  independent of the current request's CD bit — CD-bit gating happens later,
  at response-assembly time (A6), not here. This matters because the cache
  entry is shared across requesters; a CD=1 requester shouldn't cause a
  CD=0 requester to get an unvalidated entry.
- **TTL capping**: an entry's effective cache TTL must be capped at the
  earliest RRSIG expiration found in its validated chain, in addition to
  whatever TTL logic already governs the entry today. Without this, a
  `Secure` entry could keep being served from cache after its signature
  has cryptographically expired, which is a correctness gap even though
  it wouldn't be caught by the existing TTL machinery (which knows nothing
  about signature validity windows).

### A6. CD-bit response gating

- Locate the call site(s) where `dnssec_servfail_check` /
  `negative_dnssec_servfail_check` (`src/resolver/cache/assemble.rs:426-459`)
  are invoked during response assembly.
- Thread the current request's CD bit (`request.header.cd()`, already
  parsed and available per the spec's grounding) into that call site so
  that when CD=1, the SERVFAIL-on-Bogus behavior is skipped for *this
  response* — the response is still built from the (possibly Bogus) cached
  data, just without forcing SERVFAIL.
- Do not modify `dnssec_servfail_check`/`negative_dnssec_servfail_check`
  themselves or `dnssec_ad_bit`/`negative_dnssec_ad_bit` — those are
  already correct and tested; only their call site needs a new CD-aware
  branch.
- **Serve-stale interaction**: a `Bogus` entry must never be served via
  serve-stale — serving a known-tampered response past its expiration
  defeats the point of validating it in the first place. `Secure` and
  `Insecure` entries are unaffected; their existing serve-stale behavior
  carries over unchanged. This needs an explicit check wherever serve-stale
  currently decides whether an expired entry is eligible to be served, and
  the rule needs to land in `docs/knowledge/resolver/caching/serve-stale.md`
  as part of C1.

### A7. Status, mode, and metrics

- Add `DnssecValidationMode::Enabled` alongside the existing `Disabled`
  variant (`src/config/mod.rs:1108-1110`). Add the mirroring
  `DnssecValidationStatus::Enabled` (`src/resolver/mod.rs:2418-2420`).
- Update `DnssecValidationMode::cache_namespace_label()`
  (`config/mod.rs:1113-1117`) to produce a distinct label for `Enabled` vs
  `Disabled` — this is required (the compiler will force a match-arm
  update since there's no wildcard arm today) and is also *desired*: it
  changes the cache-epoch namespace hash on upgrade, which correctly
  invalidates old unvalidated entries rather than silently treating them as
  validated. Call this out explicitly in the PR description as an
  intended, one-time cache invalidation on upgrade — not a regression.
- Default `DnssecValidationMode` to `Enabled` (per the on-by-default
  decision) — find wherever config defaults are assembled and set this
  explicitly rather than relying on a derive default that happens to match.
- Update `dnssec_validation_label` (`src/main.rs:1294-1297`) and the
  `dnssec_validation_disabled` gauge's producer (`record_backend_status`,
  `:1239-1246`) for the new variant.
- Add a new labeled `Counter<u64>` (e.g. `dnssec_validation_results_total`)
  with an outcome attribute (`Secure|Insecure|Bogus|Indeterminate`),
  incremented once per validated query from within or near the A4/A5 call
  site. Follow the existing `backend_status_attributes` construction
  pattern (`src/main.rs:1256-1275`) for how labels/attributes are built.
  The `Indeterminate` label must be distinguishable in this counter from
  "validation was never attempted" (e.g. mode disabled, or the query never
  reached the recursive validation path) — since both collapse to the same
  `DnssecState::Unvalidated` on the entry itself (A4), the counter is the
  only operator-visible signal that validation ran and came back
  inconclusive versus never running at all. Don't let both cases increment
  the same "not validated" bucket with no way to tell them apart.

### A8. DNSSEC testing

- **Test fixture generation**: produce a small, deterministic signed test
  zone (a handful of records, at least one NSEC or NSEC3 range for
  denial-of-existence coverage, at least one wildcard if feasible) using an
  offline signing tool, and commit the resulting DNSKEY/DS/RRSIG wire bytes
  (or the tool's output re-encoded into whatever format rdns's existing
  hand-built-byte-vector test style uses) as a fixture module. This must be
  fully offline/deterministic — no live network dependency in the test
  suite.
- **Known-answer chain test**: feed the fixture's full chain through the
  A4 validation function, assert `DnssecState::Secure`.
- **Bogus-injection tests**: take the same fixture, flip a byte in an
  RRSIG signature (or DNSKEY, or DS digest), assert the validation function
  returns `DnssecState::Bogus`. Pair at least one of these with an
  assembly-level test asserting the existing `dnssec_servfail_check`
  correctly forces SERVFAIL given that Bogus state — closing the loop the
  spec identified (assembly-side logic already tests Bogus→SERVFAIL by
  direct state injection; this test proves the *validator* actually
  produces that Bogus state from tampered bytes, not just that assembly
  reacts correctly once told).
- **Algorithm-downgrade test**: construct a scenario where a zone has a DS
  at the parent (signed) but the child response omits signatures entirely;
  assert the result is `Bogus`, not `Insecure` — this is the downgrade
  pitfall research flagged as a real, previously-exploited bug class.
- **NSEC3 opt-out test**: if feasible within the fixture-generation
  approach, construct an opt-out NSEC3 scenario and confirm it cannot be
  used to downgrade a signed subdomain to `Insecure`/spoofed. If building
  this fixture is disproportionately costly, document it as a known gap
  with a follow-up ticket rather than skipping it silently.
- **Signature validity-window tests**: distinct from the Bogus-injection
  (tampered-byte) tests above, construct fixtures with an RRSIG that is
  expired (past its signature-expiration field) and one that is not-yet-valid
  (before its inception field) — both well-formed and correctly signed,
  just outside their validity window — and assert `Bogus` for both. This
  exercises the validity-window check specifically, not signature
  verification.
- **Timeout/error-path test**: simulate a DS/DNSKEY chase timing out or the
  adapter (A4) returning a transport error mid-validation, assert the
  result is `Bogus` with a diagnostic reason, not `Insecure` or a panic —
  covering the fail-closed behavior from A4.
- **Mixed-validation-state CNAME chain test**: construct a CNAME chain
  where one link resolves to a `Secure` entry and another to `Bogus`,
  assert the chain-level verdict reflects the worst state in the chain —
  matching how `dnssec_servfail_check` already treats "any entry in the
  chain is Bogus" as SERVFAIL-triggering, confirming the validator produces
  data consistent with that existing assembly-side assumption.
- **CD-bit test**: assert that a Bogus entry with a CD=1 request does not
  trigger SERVFAIL, while the same entry with CD=0 does — covering the A6
  gating logic specifically, separate from the A4/A5 validation-production
  tests.
- **Serve-stale test**: assert an expired `Bogus` entry is not served via
  serve-stale (A6's rule), while an expired `Secure`/`Insecure` entry's
  existing serve-stale behavior is unaffected.
- **e2e**: extend the `verify` skill's manual/scripted flow with a
  DNSSEC-specific check — `dig +dnssec` against the fixture zone (served
  however the e2e harness serves other test zones) or a known-signed public
  domain, asserting the AD bit is set on success, and a SERVFAIL assertion
  for a deliberately-Bogus case if the e2e harness can inject one.

---

## Track B: BADCOOKIE Handling

### B1. Wire-level RCODE 23 support

`ResponseCode` (`src/protocol/mod.rs:93-100`) only models RCODE 0-5 (the
header's 4-bit nibble) and cannot represent extended RCODEs like BADCOOKIE
(23) or BADVERS (16). BADVERS already solved exactly this problem — Track B
replicates that pattern rather than inventing a new one:

- Add a new wire-response builder (mirroring `build_badvers_response`,
  `src/protocol/mod.rs:609-655`) that produces a BADCOOKIE response,
  splitting the 12-bit extended RCODE 23 across the header's 4-bit nibble
  (7) and the OPT record's extended-RCODE byte (1), using the existing
  `build_opt_record_with_extended_rcode` helper (`:1276+`) the same way
  BADVERS does.
- The BADCOOKIE response must attach a freshly issued, correct server
  cookie (via `build_server_cookie`) so the client can retry per RFC 7873
  §5.3.
- Add a new error variant (mirroring `QueryValidationError::UnsupportedEdnsVersion`,
  `:71-73`) representing "invalid or stale server cookie over UDP" — **not**
  "missing"; see B2 for why a missing server cookie is a separate, non-error
  case — with its own `response_code()` bucketing (follow the BADVERS
  precedent's documented rationale at `:119-127` for which coarse metrics
  bucket — likely `FormErr` — is appropriate) and a
  `BasicResponseFactory::protocol_error` special case
  (`src/resolver/mod.rs:6620`) that routes to the new BADCOOKIE builder
  instead of the generic error path.
- This same error variant also covers a cookie option that's **present but
  structurally malformed** (wrong length, truncated TLV) — a malformed
  cookie must be treated as an invalid server cookie (triggering BADCOOKIE
  over UDP), not silently treated the same as "no cookie option at all,"
  which would let a malformed-but-present cookie bypass the check entirely.

### B2. BADCOOKIE detection and transport-conditional gating

- Add the recompute-and-compare check as a new function (or extend
  `cache_supported`, `src/resolver/mod.rs:6526-6538` — pick whichever keeps
  the function single-purpose; a sibling function called from the same
  spot is likely cleaner than overloading `cache_supported`'s existing
  meaning), invoked from `probe_cache` (`:~5225-5250`) before the
  `cache_supported(decoded)` branch at `:5234`.
- **Ordering**: this check must run only *after* the existing EDNS-version
  check (which produces BADVERS) has already passed — don't let a request
  with an unsupported EDNS version reach cookie logic at all. This matches
  how `cache_supported`'s existing EDNS-admission checks are already
  sequenced.
- **Two distinct cases, do not conflate them** (this distinction was
  inconsistently described earlier in this plan's drafting — the
  resolution below is authoritative):
  1. **Client cookie present, server-cookie tail present but invalid,
     stale, or structurally malformed** (`locate_cookie_option`,
     `edns_cookie.rs:75-111`, RFC 7873 §5.2.4): recompute what this server
     would have issued for that client cookie + request source IP via
     `build_server_cookie` (`edns_cookie.rs:158-182`), and compare.
     - **Over UDP**: reject with the B1 BADCOOKIE response.
     - **Over TCP**: skip rejection, continue normal processing — RFC 7873
       §5.2.3's explicit TCP carve-out ("the server SHOULD take the
       authentication provided by the use of TCP into account and SHOULD
       choose (3)"). Make sure the transport type is available at this
       call site (confirm `probe_cache`/its callers already know
       UDP-vs-TCP, or thread it through if not).
  2. **Client cookie present, no server-cookie tail at all** (first
     contact — client hasn't been issued one yet, RFC 7873 §5.2.3): this
     is **not** an invalid-cookie case and does **not** trigger BADCOOKIE
     on either transport. RFC 7873 requires servers to "at least
     occasionally" respond so clients can bootstrap a server cookie at
     all — process normally and issue a fresh cookie, matching the
     existing, unchanged pre-BADCOOKIE behavior for this case.
- **IP normalization**: the recompute-and-compare step must reuse
  `build_server_cookie`'s existing source-address handling exactly (call
  the same function used for outgoing cookie issuance, don't re-derive
  IPv4-mapped-IPv6 or address-normalization logic separately) — this is a
  correctness-by-construction requirement, not a new design decision,
  since any divergence between how an address is normalized for issuance
  versus verification would cause spurious BADCOOKIE rejections.
- No new config toggle. This check runs unconditionally wherever EDNS
  cookies are already accepted.

### B3. BADCOOKIE testing

- **Unit tests**, following the existing hand-built-byte-vector pattern in
  `edns_cookie.rs` (`parse_cookie_option_rejects_malformed_lengths`,
  `_rejects_truncated_tlv_bytes`, `_rejects_duplicates`):
  - Tampered server cookie (valid length, wrong bytes) → BADCOOKIE over
    UDP.
  - Expired/stale server cookie (if `build_server_cookie`'s timestamp
    handling exposes an expiry concept — confirm against
    `edns_cookie.rs:158-182` before assuming this path exists) → BADCOOKIE
    over UDP.
  - Server cookie computed with the wrong secret (simulating a restart or
    a different process) → BADCOOKIE over UDP.
  - **Malformed cookie option** (wrong length, truncated TLV, but present)
    → BADCOOKIE over UDP, same as tampered — must not fall through to the
    "no cookie" path.
  - **Duplicate cookie options** in one request → confirm this is rejected
    or handled consistently with however `edns_cookie.rs`'s existing
    `_rejects_duplicates` test already governs duplicate-option handling
    generally, not specially bypassed by the new check.
  - Same scenarios over TCP → normal processing, no BADCOOKIE.
  - Client cookie with no server-cookie tail (first contact) → normal
    processing with a fresh cookie attached, not BADCOOKIE, on both
    transports.
  - **IPv4-mapped IPv6 source address** with an otherwise-valid server
    cookie → accepted identically to the equivalent plain IPv4 source,
    confirming B2's IP-normalization-reuse requirement.
  - **EDNS-version-plus-cookie interaction**: a request with both an
    unsupported EDNS version and an invalid server cookie → BADVERS, not
    BADCOOKIE, confirming B2's ordering requirement.
- **e2e**: a bad server cookie over UDP gets RCODE 23 with a freshly issued
  cookie attached (assert via raw-socket or `dig` if it exposes extended
  RCODE / cookie option inspection); the identical bad cookie over TCP gets
  a normal answer. This transport-conditional pair needs explicit e2e
  coverage, not just unit tests, since it's exactly the kind of behavior
  that's easy to get right in a unit test against the check function but
  wrong in wiring (e.g. forgetting to thread transport type through
  correctly).

---

## Cross-cutting work

### C1. `docs/knowledge/` updates

- Update `docs/knowledge/resolver/caching/serve-stale.md:113-118`, which
  currently states DNSSEC validation doesn't exist and the AD=1 path is
  unreachable in production — no longer true once Track A ships.
- Update `docs/knowledge/resolver/caching/answer-cache.md:54-55`'s
  `dnssec_state` description, which says it "stays Unvalidated until real
  DNSSEC validation exists."
- Add a new concept doc for the DNSSEC validation pass itself (module
  location, trust anchor sourcing, CD-bit interaction, `DnssecState`
  mapping) — no existing doc covers this; follow the existing
  `docs/knowledge/` frontmatter/structure conventions.
- Evaluate whether BADCOOKIE's addition to `edns_cookie.rs` warrants its
  own new concept doc or just an update to inline doc comments — use
  judgment per AGENTS.md (a subsystem with real invariants warrants a doc;
  a scoped addition to an already-tested, already-documented module may
  not need a standalone doc).

### C2. Security review gates

- **End of Track A** (after A1-A8 are complete, before Track A's PR opens):
  run `/security-review` covering the validator wiring, trust-anchor
  bundling/override path, and the CD-bit gating logic. Address findings or
  document why not, per AGENTS.md's PR-feedback-resolution rule.
- **End of Track B** (after B1-B3, before Track B's PR opens): run
  `/security-review` covering the BADCOOKIE detection/comparison logic and
  the new wire-response builder.
- Per AGENTS.md's standing rules, also run `verify` and satisfy the
  fmt/clippy/test gates from `RUST.md` before either PR is considered done,
  independent of the security review.

### C3. Rollout note

DNSSEC validation ships **on by default** — this is a deliberate,
explicit decision, reaffirmed after external plan review specifically
recommended an opt-in first release given the lack of field experience
with this validator in production. The decision stands: on-by-default,
with the expanded test suite (A8 — known-answer, Bogus-injection,
algorithm-downgrade, expired/not-yet-valid-signature, timeout/error-path,
and mixed-chain tests) treated as the mitigation instead of a staged
rollout. Existing deployments start validating and enforcing
SERVFAIL-on-Bogus immediately on upgrading past Track A's release, and
per A4's fail-closed timeout handling, transient upstream slowness during
validation can also produce SERVFAILs for CD=0 requesters — this is an
additional, related risk introduced by the on-by-default choice, not just
the Bogus-detection risk. Combined with the cache-namespace change from
A7, an upgrade will both invalidate old cache entries and begin rejecting
previously-tolerated Bogus-signed responses. This should be called out
prominently in the PR description and any release/changelog notes — it is
intended behavior per the interview, but is a meaningful behavior change
on upgrade that operators should be aware of, not a silent default flip.

---

## Suggested build order

1. **A1-A3** (dependency setup, trust anchor bundling, CI staleness check)
   — no behavior change yet, safe to land and verify independently.
2. **A4-A6** (validator core, wiring into entry construction, CD-bit
   gating) — the core DNSSEC feature. A8's fixture generation likely needs
   to happen alongside A4 (you need a test fixture to develop the validator
   against, not just to test it after the fact).
3. **A7** (status/mode/metrics) — small, mechanical, but touches the
   cache-namespace hash, so land after A4-A6 are confirmed working to avoid
   churning the namespace repeatedly during development.
4. **A8** (remaining tests not already written alongside A4) + Track A's
   `/security-review` (C2) → Track A PR.
5. **B1** (wire-level RCODE 23 support) — small, mechanical, mirrors
   existing BADVERS code exactly, low risk, good to land first within
   Track B.
6. **B2** (detection/gating logic) — the core BADCOOKIE feature.
7. **B3** (tests) + Track B's `/security-review` (C2) → Track B PR.
8. **C1** (`docs/knowledge/` updates) alongside whichever track's changes
   make the existing docs stale — likely split across both PRs rather than
   batched at the end, per AGENTS.md's Knowledge Bundle trigger ("code
   change complete → update docs/knowledge/ ... in the same change").
