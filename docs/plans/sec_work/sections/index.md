<!-- PROJECT_CONFIG
runtime: rust-cargo
test_command: cargo test
END_PROJECT_CONFIG -->

<!-- SECTION_MANIFEST
section-01-dnssec-deps
section-02-dnssec-trust-anchor
section-03-dnssec-validator-core
section-04-dnssec-entry-wiring
section-05-dnssec-status-metrics
section-06-dnssec-review-docs
section-07-badcookie-wire-rcode
section-08-badcookie-detection
section-09-badcookie-review-docs
END_MANIFEST -->

# Implementation Sections Index

Source plan: `../claude-plan.md`. Test stubs: `../claude-plan-tdd.md`. Nine
sections split across two independent tracks — Track A (DNSSEC,
sections 01-06) and Track B (BADCOOKIE, sections 07-09) — landing as two
separate PRs per the plan's decided delivery shape. The two tracks touch
disjoint files and have no dependency on each other, so they run in
parallel batches throughout.

## Dependency Graph

| Section | Depends On | Blocks | Parallelizable |
|---------|------------|--------|-----------------|
| section-01-dnssec-deps | - | 02, 03 | Yes (with 07) |
| section-02-dnssec-trust-anchor | 01 | 03 | Yes (with 08) |
| section-03-dnssec-validator-core | 01, 02 | 04 | Yes (with 09) |
| section-04-dnssec-entry-wiring | 03 | 05 | No |
| section-05-dnssec-status-metrics | 04 | 06 | No |
| section-06-dnssec-review-docs | 05 | - | No |
| section-07-badcookie-wire-rcode | - | 08 | Yes (with 01) |
| section-08-badcookie-detection | 07 | 09 | Yes (with 02) |
| section-09-badcookie-review-docs | 08 | - | Yes (with 03) |

## Execution Order (batches)

1. **section-01-dnssec-deps**, **section-07-badcookie-wire-rcode** (no
   dependencies, different tracks — parallel)
2. **section-02-dnssec-trust-anchor** (after 01), **section-08-badcookie-detection**
   (after 07) — parallel
3. **section-03-dnssec-validator-core** (after 01, 02),
   **section-09-badcookie-review-docs** (after 08) — parallel; Track B
   finishes here
4. **section-04-dnssec-entry-wiring** (after 03)
5. **section-05-dnssec-status-metrics** (after 04)
6. **section-06-dnssec-review-docs** (after 05) — Track A finishes here

## Section Summaries

### section-01-dnssec-deps
Plan §A1. Bump `domain` to `0.12`, add `unstable-validator` + `ring`
features, confirm the crate still builds and the existing suite passes
with no behavior change yet. Pure foundation — nothing downstream can
start without the feature flags in place.

### section-02-dnssec-trust-anchor
Plan §A2, §A3. Bundle KSK-2017 + KSK-2024 as a static trust-anchor file
mirroring `RootHintsSource::Bundled`/`Static`, add the config-level
`TrustAnchorSource` override, and add the scheduled (not per-PR-blocking)
CI staleness-check workflow against IANA's `root-anchors.xml` per RFC
9718, with a 60-day warning threshold.

### section-03-dnssec-validator-core
Plan §A4, plus the fixture-generation and validator-attacking tests from
§A8 that exercise this module directly (known-answer, Bogus-injection,
algorithm-downgrade, expired/not-yet-valid-signature, timeout/error-path).
The core validation function: transport adapter spike bridging rdns's
upstream transport to `domain`'s `SendRequest`, `ValidationContext`
construction and `validate_msg()` call, `ValidationState` →
`DnssecState` mapping (including the `Indeterminate`-visibility
requirement), fail-closed timeout/error handling, and `Config` NSEC3
iteration-count thresholds. This is the largest, highest-risk section —
it produces the deterministic signed test-zone fixture that section-04's
tests also depend on.

### section-04-dnssec-entry-wiring
Plan §A5, §A6, plus the remaining §A8 tests that need the full
entry-construction/response-assembly path wired up (CD-bit test,
mixed-state CNAME chain test, serve-stale test). Wires the section-03
validator into `build_rrset_entry`/`build_negative_entry` (Recursive mode
only), adds TTL capping at RRSIG expiration, threads CD-bit gating into
the `dnssec_servfail_check` call site without modifying that function
itself, and adds the Bogus-excluded-from-serve-stale rule.

### section-05-dnssec-status-metrics
Plan §A7. Adds `DnssecValidationMode::Enabled`/`DnssecValidationStatus::Enabled`,
updates `cache_namespace_label()` and the existing gauge/label producers
for the new variant, defaults the mode to `Enabled`, and adds the new
labeled per-outcome counter with an explicit "never attempted" vs.
`Indeterminate` distinction.

### section-06-dnssec-review-docs
Plan §C1 (DNSSEC portion), §C2 (Track A `/security-review`), §C3 (rollout
note). Closes out Track A: run `/security-review` over the full validator
wiring/trust-anchor/CD-bit surface, update
`docs/knowledge/resolver/caching/serve-stale.md` and `answer-cache.md`
(both currently document DNSSEC as unimplemented), add a new DNSSEC
validator concept doc, and write the on-by-default + fail-closed-timeout
rollout note for the PR description/changelog. This is the last section
before Track A's PR opens.

### section-07-badcookie-wire-rcode
Plan §B1. Adds RCODE 23 wire-response support mirroring
`build_badvers_response`'s extended-RCODE split, attaches a freshly
issued server cookie to the BADCOOKIE response, and adds the new
error-variant/response_code/protocol_error wiring (covering both
invalid-and-present and malformed-but-present server cookies). No
dependency on Track A — can start immediately alongside section-01.

### section-08-badcookie-detection
Plan §B2. The recompute-and-compare check wired into `probe_cache`,
running only after the existing EDNS-version check passes. Implements the
two-case split precisely (invalid/stale/malformed server cookie → UDP
BADCOOKIE / TCP normal; no server-cookie tail at all → always normal,
never BADCOOKIE) and reuses `build_server_cookie`'s IP-normalization
exactly rather than re-deriving it.

### section-09-badcookie-review-docs
Plan §B3, §C1 (BADCOOKIE portion), §C2 (Track B `/security-review`).
Closes out Track B: remaining unit tests (duplicate-cookie-option
handling) plus the transport-conditional e2e pair, `/security-review`
over the detection/comparison logic and new wire-response builder, and a
judgment call on whether BADCOOKIE's addition warrants its own
`docs/knowledge/` concept doc or an inline-comment-only update. Last
section before Track B's PR opens.
