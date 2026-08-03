# section-06-dnssec-review-docs — code review interview

Reviewer: `deep-implement:code-reviewer` subagent, run against the
staged diff (docs + the one section-05 code fix this section's
security-review surfaced).

## Auto-fixed (no user input needed)

1. **Inaccurate file:line reference.** The new
   `docs/knowledge/resolver/dnssec-validation.md` cited `src/main.rs:1043`
   for the `dnssec_validation_disabled` gauge's field declaration —
   actually a different field's builder line. Corrected to `:973`
   (declaration) / `:1085` (builder).
2. **Stale inline comment.** `src/resolver/cache/entry.rs`'s
   `DnssecState::Bogus` variant carried a comment claiming "short
   negative-style TTL applies" — no code implements a distinct short
   TTL for `Bogus`; the actual differentiator is serve-stale exclusion.
   Corrected to describe what's actually implemented.
3. **Prose-wrap cosmetic.** Fixed an inconsistent line-wrap in
   `serve-stale.md`'s DNSSEC note paragraph introduced by section-05's
   edit.
4. **Missing security-review paper trail.** Sections 01-05 each left a
   `-review.md`/`-interview.md` pair; section-06's Task 4
   (`/security-review`) had only produced one code fix with no record
   of review scope or that it was the sole finding. Wrote
   `section-06-security-review.md` documenting scope, both real
   findings (the section-05 Bogus/Unvalidated mismatch, and the
   trust-anchor cache-namespace gap below), and what was explicitly
   checked and found sound (chase fail-closed paths, CD-bit gating,
   serve-stale, CI staleness script injection surface).

## Interviewed (user decision)

**Finding:** `TrustAnchorSource::cache_namespace_label()` existed
(`#[allow(dead_code)]`) but was never wired into
`RecursiveResolutionConfig::authority_config_hash` — deferred since
section-02/03 "once it's clear what changing it actually invalidates,"
and never revisited through section-05. Consequence: switching trust
anchors (Bundled → Static, or between two different `Static` sets)
left the cache namespace/epoch unchanged, so `Secure`/`Bogus` verdicts
computed under the old anchor set would persist in cache past a
trust-anchor rotation until natural TTL expiry — a real,
security-relevant gap the reviewer identified as squarely in-scope for
this section's own security-review task (which explicitly lists
"trust-anchor bundling and the config-level override path" as
in-scope).

**Options presented:** fix now (hash actual trust-anchor content into
`authority_config_hash`, mirroring the existing root-hints content
loop) vs. defer with an explicit, tracked rationale note.

**Decision:** Fix now. `authority_config_hash` hashes both the
`TrustAnchorSource` label and the trust-anchor content (each DS/DNSKEY
line via `load_trust_anchors()`). Removed the stale
`#[allow(dead_code)]`/deferral comment. Added
`recursive_cache_namespace_changes_with_trust_anchor_source`
(`src/config/mod.rs`) covering both the Bundled→Static transition and
two different Static sets producing distinct namespaces.

## Noted, no action taken

- The reviewer independently re-verified the section-05
  Bogus/Unvalidated fix (already applied before this section's review
  ran, as part of Task 4's own findings) was complete and introduced no
  display/consumer inconsistency — no further action.
- `domain`'s DS/DNSKEY chase lacking prefetch/dedup across parallel
  same-name queries remains a known, accepted upstream limitation
  (documented in the new concept doc) — not revisited.
