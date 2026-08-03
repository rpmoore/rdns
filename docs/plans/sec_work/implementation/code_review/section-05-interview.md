# section-05-dnssec-status-metrics — code review interview

Reviewer: `deep-implement:code-reviewer` subagent, run against the staged diff.

## Auto-fixed (no user input needed)

1. **Stale `docs/knowledge` claims.** Two concept docs
   (`docs/knowledge/resolver/caching/serve-stale.md`,
   `docs/knowledge/resolver/caching/answer-cache.md`) said DNSSEC
   validation was "currently unreachable in production" pending a
   config gate — exactly what this section adds. Updated both to
   describe the new live-by-default state.
2. **Stale `#[allow(unused_imports)]`.** The `pub(crate) use
   dnssec_validation::{...}` re-export in `resolver/mod.rs` carried a
   blanket `#[allow(unused_imports)] // wired in by section-04` that
   would have masked a real future regression. On inspection, neither
   `ValidationRunOutcome` (renamed from `DnssecValidationOutcome` this
   section, to free the name for the new metrics enum) nor
   `validator_config` were actually referenced via that re-export path
   anywhere in the crate — only `validate_response` is. Trimmed the
   re-export to just `validate_response` and dropped the `allow`
   entirely; compiles warning-free.
3. **Comment on redundant `load_trust_anchors()` call.** Reviewer
   noted `main.rs::trust_anchors_to_wire_in` re-loads anchors that
   `RecursiveResolutionConfig::validate()` already validated at config
   load, making its error branch practically dead code. Added a
   comment explaining this mirrors the file's existing
   belt-and-suspenders pattern rather than being an oversight.

## Interviewed (user decision)

**Finding:** `validate_for_store`'s "trust anchors configured but fail
to parse" branch recorded `DnssecValidationOutcome::NotAttempted` —
the same bucket as the benign "`DnssecValidationMode::Disabled`, no
anchors configured at all" case. Reviewer's objection: this is a live
misconfiguration (mode `Enabled`, anchors corrupt), and collapsing it
into the same label as routine opt-out means an operator has no
metric-driven signal it's happening — only a `tracing::warn!` log
line, which no alerting rule reliably fires off the way it does off a
counter label.

**Options presented:** relabel as `Bogus` (fail-closed, consistent
with `validate_response`'s own fail-closed convention for chase
timeouts/transport errors) vs. leave as `NotAttempted` (config-level
`validate()` already makes this path near-unreachable in practice).

**Decision:** Relabel as `Bogus`. Applied in
`resolver/mod.rs::validate_for_store`; updated comment explaining the
distinction, and renamed/updated the corresponding test
(`validate_for_store_records_bogus_when_trust_anchors_fail_to_parse`,
was `..._records_not_attempted_when_trust_anchors_fail_to_parse`).

## Noted, no action taken

- **Residual production-risk reminder** (contextual, not a new
  finding): shipping DNSSEC on-by-default with SERVFAIL-on-`Bogus` and
  no feature-flag/canary rollout beyond hand-editing
  `dnssec_validation = "disabled"` was already flagged as a
  Major(x2) risk in `docs/plans/sec_work/reviews/iteration-1-codex.md`
  §3, and accepted as a deliberate decision upstream in the plan. No
  code change from this review; restating here so it isn't lost at
  merge time.
- Rename verification (`DnssecValidationOutcome` → `ValidationRunOutcome`
  for the internal struct) and the trust-anchor kill-switch reasoning
  were both checked by the reviewer and confirmed correct — no changes
  needed.
- Config-fixture audit (the plan's own verification note about other
  `DnssecValidationMode::Disabled` occurrences in `config/mod.rs`)
  confirmed all are explicit constructor args unrelated to the
  TOML-default path — left untouched, as the plan expected.
