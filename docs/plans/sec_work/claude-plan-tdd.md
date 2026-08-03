# TDD Companion: DNSSEC Validation + BADCOOKIE Handling

Mirrors `claude-plan.md`'s section structure. For each section, lists the
tests to write **before** implementing that section's logic. Follows this
repo's existing conventions (confirmed in `claude-research.md` §1.5):
inline `#[cfg(test)] mod tests` at the bottom of the same file as the code
under test, no mocking framework anywhere in the codebase, hand-constructed
byte-vector/struct fixtures rather than golden files, known-answer vectors
placed directly beside the primitive they pin.

These are stubs — prose descriptions of what each test asserts, not test
code. The implementer (deep-implement or a human) writes the actual
`#[test]` functions.

---

## Track A: DNSSEC Validation

### A1. Dependency and feature setup

- Test: `cargo build` succeeds with `unstable-validator` + `ring` features
  enabled and no other code changes (confirms the feature flags alone
  don't break compilation before any validator code exists).
- Test: existing full test suite still passes unchanged with the new
  features enabled (confirms no accidental behavior change from the
  dependency bump alone).

No new unit tests belong in this section beyond build/suite verification —
there's no new logic yet.

### A2. Trust anchor bundling

- Test: `bundled_root_hints()`-equivalent for trust anchors
  (`bundled_trust_anchors()` or similar) parses the committed anchor file
  without error at startup.
- Test: the parsed anchor set contains exactly two `KeyDigest`-equivalent
  entries with key tags 20326 (KSK-2017) and 38696 (KSK-2024).
- Test: `TrustAnchorSource::Static(...)` config override is honored instead
  of the bundled set when present, mirroring however
  `RootHintsSource::Static` is already tested.
- Test: malformed/empty static-override config is rejected at config
  validation time (mirror whatever `RootHintsSource` validation test
  pattern already exists for its `Static` variant).

### A3. CI staleness check for the bundled anchor

- This is a CI workflow, not application code — no `#[test]` coverage.
  Instead: a manual/documented verification step that the workflow
  correctly fails when pointed at a deliberately stale/mismatched fixture
  anchor set (e.g. run the check script locally against a modified copy of
  the bundled file with one digest removed, confirm it reports drift).
  Note this verification approach explicitly in the section's
  implementation notes since it won't show up in `cargo test`.

### A4. Validation pass — core logic

Write these before the validation function's body is filled in — the
fixture from the first bullet is a shared prerequisite for the rest of A4,
A5, and A8's fixture-dependent tests, so it should be built first even
though it also appears in A8.

- **Fixture**: generate the offline signed test zone (small zone, at least
  one NSEC or NSEC3 range, at least one wildcard if feasible) and commit
  its DNSKEY/DS/RRSIG wire bytes as a fixture module before writing any
  assertions against it.
- Test: transport adapter correctly bridges a canned rdns-side response
  into a `domain`-side `Message` that `validate_msg` can consume (a narrow
  adapter-only test, independent of real validation logic — proves the
  bridge compiles and round-trips data correctly).
- Test: validating the fixture's full, untampered chain returns
  `ValidationState::Secure` from `domain`, before asserting the
  `DnssecState` mapping (isolates "domain's validator works against our
  fixture" from "our state-mapping code is correct").
- Test: the `Secure`/`Bogus`/`Insecure`/`Indeterminate` → `DnssecState`
  mapping function, tested directly with each of the four
  `ValidationState` inputs (not requiring a real validation run — this is
  a pure mapping function and should be tested as one).
- Test: `Indeterminate` maps to `DnssecState::Unvalidated` while also
  being distinguishable via whatever internal signal A7's metrics code
  will consume (assert the mapping function or its caller exposes both the
  `DnssecState` and a separate "ran but inconclusive" marker, not just the
  collapsed state).
- Test: validation is bounded by the per-query/per-authority timeout
  budget — simulate a chase that would exceed the budget, assert the
  function returns before the deadline with `DnssecState::Bogus` and a
  timeout-indicating reason string, not a hang or a panic.
- Test: a transport/adapter error during the DS/DNSKEY chase (not a
  timeout — a hard error) also maps to `DnssecState::Bogus`, not
  `Insecure` or `Unvalidated` (fail-closed on errors generally, not just
  on timeouts specifically).
- Test: `Config` builder is constructed with explicit
  `nsec3_iter_insecure`/`nsec3_iter_bogus` values (not the crate's raw
  default) — assert the configured validator context reflects the chosen
  thresholds, e.g. by checking the values are set to what the plan
  specifies rather than left at zero/unset.

### A5. Wiring the validation pass into entry construction

- Test: `build_rrset_entry` in `ResolutionMode::Recursive` calls the A4
  validation function and stores its result in the resulting entry's
  `dnssec_state` (replaces today's implicit `Default::default()` — this
  test should fail against the current code and pass once A5 is wired).
- Test: same for `build_negative_entry`.
- Test: `ResolutionMode::Forward` does not invoke validation at all —
  confirm no call to the A4 function occurs on that path (e.g. via a call
  counter or spy in the test, consistent with however other
  path-not-taken assertions are made elsewhere in this codebase without a
  mocking framework).
- Test: a cache entry's `dnssec_state` is populated identically regardless
  of the originating request's CD bit — validate with a CD=1 request and a
  CD=0 request producing the same underlying fetch, assert both produce
  the same stored `dnssec_state` (proves A5's "always validate, always
  store" independent of A6's later gating).
- Test: effective entry TTL is capped at the earliest RRSIG expiration in
  the validated chain when that's tighter than the otherwise-computed TTL;
  and is unaffected (uses the otherwise-computed TTL) when RRSIG expiration
  is later than that TTL.

### A6. CD-bit response gating

- Test: a `Bogus` entry + CD=0 request → `dnssec_servfail_check`'s call
  site produces SERVFAIL (matches existing pre-validator test expectations
  for this function, now exercised through the new call site).
- Test: a `Bogus` entry + CD=1 request → SERVFAIL is skipped, response is
  built from the entry's data as normal.
- Test: a `Secure` entry's AD-bit behavior is unaffected by CD (existing
  `dnssec_ad_bit` behavior carries through unchanged — this is a
  no-regression check on the untouched functions).
- Test: an expired `Bogus` entry is not eligible for serve-stale (the
  serve-stale decision point rejects it regardless of otherwise-eligible
  staleness).
- Test: an expired `Secure` entry's existing serve-stale eligibility is
  unchanged by this work (no-regression check).

### A7. Status, mode, and metrics

- Test: `DnssecValidationMode::Enabled`/`Disabled` each produce a distinct
  `cache_namespace_label()` output (compiler forces the match-arm update;
  this test proves the *values* are distinct, not just that it compiles).
- Test: config defaults to `DnssecValidationMode::Enabled` when
  unspecified (matches the on-by-default decision).
- Test: `dnssec_validation_label` and the status gauge/producer emit
  correct values for both `Enabled` and `Disabled` states (no-regression
  plus new-variant coverage).
- Test: the new outcome counter increments exactly once per validated
  query, with the correct outcome label, for each of
  Secure/Insecure/Bogus/Indeterminate.
- Test: the counter's "validation never attempted" case (e.g. mode
  disabled) is distinguishable from an `Indeterminate` outcome — assert
  they produce different labels/counters, not the same bucket.

### A8. DNSSEC testing

(Most of A8's fixture-dependent tests are listed under A4 above, since the
fixture needs to exist before A4's core logic can be developed against it.
This section covers what's left: the tests that exercise the *validator as
attacker*, once the happy path already works.)

- Test: Bogus-injection — tampered RRSIG signature byte → `Bogus`, wired
  through to assembly-level SERVFAIL (an integration-style test spanning
  A4 through A6).
- Test: Bogus-injection variants — tampered DNSKEY byte, tampered DS
  digest byte — each independently → `Bogus`.
- Test: algorithm-downgrade — DS present at parent (signed zone) but child
  response has no signatures at all → `Bogus`, explicitly not `Insecure`.
- Test: NSEC3 opt-out — if the fixture supports it, an opt-out NSEC3
  response cannot downgrade a signed subdomain to `Insecure`. If not
  feasible, this test is explicitly marked `#[ignore]` with a comment
  pointing at a follow-up ticket, not silently omitted.
- Test: expired RRSIG (past signature-expiration field, otherwise valid)
  → `Bogus`.
- Test: not-yet-valid RRSIG (before inception field, otherwise valid) →
  `Bogus`.
- Test: mixed-state CNAME chain — one link `Secure`, another `Bogus` →
  chain-level verdict is `Bogus` (matches `dnssec_servfail_check`'s
  existing "any entry Bogus" semantics).
- e2e (documented in the `verify` skill flow, not `cargo test`): `dig
  +dnssec` against the fixture zone or a known-signed public domain shows
  AD=1 on success; a deliberately-Bogus case (if the e2e harness supports
  injecting one) returns SERVFAIL.

---

## Track B: BADCOOKIE Handling

### B1. Wire-level RCODE 23 support

- Test: the new BADCOOKIE response builder produces a wire response with
  RCODE nibble 7 and OPT extended-RCODE byte 1 (== 23 combined), mirroring
  however `build_badvers_response`'s equivalent split is already asserted
  in existing tests.
- Test: the BADCOOKIE response includes a freshly issued, correct server
  cookie in its OPT record (assert via `build_server_cookie` producing the
  same value independently and comparing).
- Test: the new error variant's `response_code()` bucketing produces the
  chosen metrics bucket (e.g. `FormErr`), mirroring the existing
  `UnsupportedEdnsVersion` bucketing test if one exists.
- Test: `BasicResponseFactory::protocol_error` routes the new error
  variant to the BADCOOKIE builder specifically, not the generic error
  path (a no-regression-style test proving the special case is actually
  reached, not just defined).

### B2. BADCOOKIE detection and transport-conditional gating

- Test: EDNS-version check runs and rejects (BADVERS) before cookie logic
  is reached, for a request with both an unsupported EDNS version and an
  invalid cookie — asserts ordering, not just that BADVERS eventually
  wins.
- Test: client cookie + tampered server cookie + UDP → BADCOOKIE.
- Test: client cookie + tampered server cookie + TCP → normal processing
  (no BADCOOKIE), per the §5.2.3 TCP carve-out.
- Test: client cookie + malformed (wrong-length/truncated) server-cookie
  TLV + UDP → BADCOOKIE (not silently treated as absent).
- Test: client cookie + malformed server-cookie TLV + TCP → normal
  processing.
- Test: client cookie + no server-cookie tail at all (first contact) + UDP
  → normal processing with a freshly issued cookie attached, explicitly
  **not** BADCOOKIE (this is the test that would have caught the
  spec/plan contradiction the external review flagged — write it before
  the first-contact carve-out is implemented, not after).
- Test: same first-contact case + TCP → identical normal-processing
  behavior.
- Test: server cookie recomputed with the wrong secret (simulating a
  restart) + UDP → BADCOOKIE.
- Test: IPv4-mapped IPv6 source address with an otherwise-valid server
  cookie → accepted, behaves identically to the equivalent plain IPv4
  source (proves the IP-normalization-reuse requirement — this test
  should call the exact same code path used for outgoing cookie issuance
  to derive its expected value, not a separately-written comparison).

### B3. BADCOOKIE testing

(B2's tests above already cover the core matrix; this section covers what
remains — duplicate-option handling and the e2e transport pair.)

- Test: duplicate cookie options in one request are handled consistently
  with whatever `edns_cookie.rs`'s existing `_rejects_duplicates` test
  already asserts for duplicate-option requests generally (not specially
  bypassed by the new BADCOOKIE check).
- e2e (documented in the `verify` skill flow): a bad server cookie over
  UDP gets RCODE 23 with a freshly issued cookie attached (verified via
  raw-socket response inspection or `dig`, whichever the harness already
  uses for other extended-RCODE/EDNS-option assertions); the identical bad
  cookie over TCP gets a normal answer, no BADCOOKIE.

---

## Cross-cutting

### C1. `docs/knowledge/` updates

Documentation changes — no `#[test]` coverage. Verification is a read-through
confirming the updated docs no longer contradict the shipped behavior (e.g.
`serve-stale.md` no longer claims DNSSEC validation doesn't exist).

### C2. Security review gates

Not a testing section — `/security-review` is the verification step itself
for this section, run after each track's tests above are green.

### C3. Rollout note

Not a testing section — a documentation/communication step. No code tests;
verify by confirming the PR description and changelog entry both mention
the on-by-default behavior change and the fail-closed timeout trade-off
before merge, per C3's requirements in `claude-plan.md`.
