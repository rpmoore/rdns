# Track A security review (section-06, Task 4)

Per plan §C2, `/security-review` was run over the full surface Track A
(sections 01-05) built, before Track A's PR opens:

- Validator wiring: the core validation function and its transport
  adapter bridging rdns's own `ResolutionBackend` onto `domain`'s
  `SendRequest` for the validator's DS/DNSKEY chase
  (`src/resolver/dnssec_validation.rs`).
- Trust-anchor bundling and the config-level override path
  (`TrustAnchorSource::Bundled`/`Static`, `src/config/mod.rs`).
- CD-bit gating (`dnssec_servfail_check`/`negative_dnssec_servfail_check`,
  `src/resolver/cache/assemble.rs`).
- The on-by-default status/metrics wiring, including the new
  `trust_anchors_to_wire_in` production activation path (`src/main.rs`).

Scope covered attacker-controlled wire bytes (signature bytes, key
bytes, DS/DNSKEY chase responses) per the plan's stated threat model for
this track, plus config-driven attack surface (trust-anchor source
handling, cache-namespace fingerprinting) and the CI staleness-check
script/workflow.

## Findings

### 1. Trust-anchor parse failure stored `Unvalidated` instead of `Bogus` (fixed)

`ResolveQuery::validate_for_store`'s "trust anchors configured but fail
to parse" branch recorded the `Bogus` metric outcome (added in
section-05's own code-review interview) but still returned
`DnssecState::Unvalidated` — the identical stored state as the benign
"no trust anchors configured" opt-out path. Since
`dnssec_servfail_check`/`negative_dnssec_servfail_check` and the
serve-stale Bogus-exclusion only match on `DnssecState::Bogus(_)`, a
live trust-anchor misconfiguration (anchors configured, mode `Enabled`,
but corrupt) would bypass both protections — served to CD=0 requesters
as an ordinary, un-SERVFAILed answer, with only a `tracing::warn!` log
line as the operator-visible signal, not the metric-driven signal the
section-05 commit message claimed existed for this case.

**Fix**: `src/resolver/mod.rs::validate_for_store` now returns
`DnssecState::Bogus("trust anchors failed to parse".to_string())` in
that branch, matching both the doc comment's stated intent and the
metric. Updated the corresponding test
(`validate_for_store_records_bogus_when_trust_anchors_fail_to_parse`)
to assert `matches!(dnssec_state, DnssecState::Bogus(_))`.

Not currently reachable with the shipped bundled config (config-level
`validate()` already parses each anchor entry individually before
startup), but the two validation call sites (`RecursiveResolutionConfig::
validate` vs. `TrustAnchors::from_u8` on the joined string at
`validate_for_store`) aren't provably equivalent, so this closes a real
gap rather than a theoretical one.

### 2. Trust-anchor content not hashed into the cache-namespace fingerprint (fixed)

`TrustAnchorSource::cache_namespace_label()` existed but was never
wired into `RecursiveResolutionConfig::authority_config_hash`
(`#[allow(dead_code)]`, deferred since section-02/03 "once it's clear
what changing it actually invalidates" — never revisited through
section-05). Switching trust anchors (Bundled → Static, or between two
different `Static` sets) left the cache namespace/epoch unchanged,
meaning `Secure`/`Bogus` verdicts computed under the old anchor set
would persist in cache past a trust-anchor rotation until natural TTL
expiry, rather than being invalidated immediately the way a
`dnssec_validation` mode flip or root-hints change already are.

**Fix**: `authority_config_hash` now hashes both the
`TrustAnchorSource` Bundled/Static label and the actual trust-anchor
content (each DS/DNSKEY line via `load_trust_anchors()`), mirroring how
root-hints content is already hashed in the same function. Removed the
stale `#[allow(dead_code)]`/deferral comment. Added
`recursive_cache_namespace_changes_with_trust_anchor_source`
(`src/config/mod.rs`) covering both the Bundled→Static transition and
two different Static sets.

### 3. Doc-quality findings (fixed)

- `docs/knowledge/resolver/dnssec-validation.md` cited an inaccurate
  `src/main.rs` line number for the `dnssec_validation_disabled` gauge's
  field declaration (off by ~70 lines from a stale intermediate draft).
  Corrected.
- `src/resolver/cache/entry.rs`'s `DnssecState::Bogus` inline comment
  claimed "short negative-style TTL applies" — no code implements a
  distinct short TTL for `Bogus`; the actual differentiator is
  serve-stale exclusion (`stale_servability`). Comment corrected.
- Minor prose-wrap inconsistency in `serve-stale.md`'s DNSSEC note,
  fixed.

## Not addressed (out of scope for this review)

- `domain`'s validator fetching DS/DNSKEY sequentially without
  prefetch/dedup across parallel same-name queries (e.g. simultaneous
  A/AAAA lookups) is a known, accepted upstream limitation — not a
  vulnerability, documented in the new concept doc's "Known upstream
  limitation" section, not re-litigated here.
- CI staleness-check script (`scripts/check-trust-anchor-staleness.sh`)
  and its workflow were reviewed for injection risk (IANA XML content,
  date parsing, shell quoting) and found sound — CMS/PKCS7 signature
  verification happens before any fetched content is trusted, and all
  string interpolation is quoted/regex-restricted. No changes needed.
