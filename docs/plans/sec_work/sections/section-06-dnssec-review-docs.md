Now I have all the context needed. Writing the section content.

---

# section-06-dnssec-review-docs

## Overview

This is the final section of Track A (DNSSEC validation). By the time this section starts, sections 01-05 have landed: dependencies/feature flags (01), bundled trust anchors (02), the core validator (03), entry-construction wiring with CD-bit gating and serve-stale exclusion (04), and the `Enabled`/`Disabled` status/mode/metrics work (05). This section closes the loop before Track A's PR opens: it brings `docs/knowledge/` back in sync with what's actually shipped (it currently documents DNSSEC as unimplemented, which is no longer true), runs a full `/security-review` over everything Track A built, and writes the rollout note that has to accompany the PR because DNSSEC validation ships **on by default** with fail-closed timeout behavior — both deliberate, risk-bearing decisions that need to be visible to reviewers and operators, not buried in a diff.

This section corresponds to plan `§C1` (DNSSEC portion only — the BADCOOKIE portion of `§C1` belongs to section-09), `§C2` (Track A's security review gate), and `§C3` (the rollout note) in `/home/rpmoore/code/rdns/docs/plans/sec_work/claude-plan.md`.

## Dependencies

- **section-05-dnssec-status-metrics** must be complete: this section documents the final shape of `DnssecValidationMode`/`DnssecValidationStatus`, the `dnssec_validation_results_total` counter, and the on-by-default config default, all of which section-05 produces.
- Transitively depends on sections 01-04 for the validator core, trust-anchor sourcing, entry wiring, CD-bit gating, and serve-stale exclusion — this section's docs describe all of that as already-shipped behavior.
- Nothing downstream depends on this section; it is the last step in Track A before the PR opens. Track B (sections 07-09) is fully independent and does not depend on this section or vice versa.

## No new tests

This is a documentation-and-review section — there is no new application logic and therefore no new `#[test]` coverage to write. Per `claude-plan-tdd.md`'s Cross-cutting section:

- **C1** (`docs/knowledge/` updates): "Documentation changes — no `#[test]` coverage. Verification is a read-through confirming the updated docs no longer contradict the shipped behavior (e.g. `serve-stale.md` no longer claims DNSSEC validation doesn't exist)."
- **C2** (security review gates): "Not a testing section — `/security-review` is the verification step itself for this section, run after each track's tests above are green."
- **C3** (rollout note): "Not a testing section — a documentation/communication step. No code tests; verify by confirming the PR description and changelog entry both mention the on-by-default behavior change and the fail-closed timeout trade-off before merge."

Verification for this section is entirely manual/read-through, described in each task below.

## Task 1: Update `docs/knowledge/resolver/caching/serve-stale.md`

The file currently ends with this paragraph (lines 113-122), which is now stale:

```
DNSSEC note: stale RRSIGs are served as stored; signature validity
windows are absolute timestamps unaffected by TTL, so a validating
client fails closed on genuinely lapsed signatures exactly as RFC 8767
anticipates. This resolver performs no local DNSSEC validation —
`dnssec_state` is only ever `Unvalidated` in production stores
(`build_rrset_entry`), so the `dnssec_ad_bit` AD=1 path is unreachable
for cached entries, stale or live. If local validation ever starts
assigning `Secure`, stale service must additionally revalidate RRSIG
inception/expiration before asserting AD (RFC 4035 §4.3) — flagged here
so that feature inherits the requirement.
```

Rewrite this paragraph to reflect Track A's shipped behavior:

- `dnssec_state` is now a real, computed value (`Secure`/`Insecure`/`Bogus`/`Unvalidated`) produced by the section-03 validator and stamped on entries at construction (section-04). It is no longer always `Unvalidated` in production.
- The `dnssec_ad_bit` AD=1 path is reachable now — a `Secure` entry served live or stale can carry AD=1.
- **New rule, must be documented explicitly (from plan §A6):** a `Bogus` entry must never be served via serve-stale. Serving a known-tampered response past its expiration defeats the point of validating it. This needs to be stated as an explicit invariant in the "Admission: `stale_servability`" section (or wherever the `Servable`/`KeepButMiss`/`Evict` outcomes are enumerated) — a `Bogus` entry past `expires_at` is not eligible for `Servable`/`KeepButMiss` treatment regardless of otherwise-eligible staleness; it must fall into eviction/miss handling instead.
- `Secure` and `Insecure` entries are unaffected by this change — their existing serve-stale behavior (as already documented) carries over unchanged. Say this explicitly so a reader doesn't assume the new rule applies more broadly than it does.
- Retain the still-true parts: signature validity windows are absolute timestamps unaffected by TTL, so a validating client fails closed on genuinely lapsed signatures per RFC 8767 — this reasoning was correct even before Track A and remains correct now that validation actually runs. The RFC 4035 §4.3 concern (stale service must revalidate RRSIG inception/expiration before asserting AD) — check whether section-04's TTL-capping-at-RRSIG-expiration work (plan §A5) already addresses this for the stale-serve path specifically, or whether it remains a residual gap; document whichever is actually true rather than leaving the old speculative phrasing in place.
- Cross-reference the new DNSSEC validator concept doc (Task 3 below) rather than re-explaining the validator's mechanics inline — this file's job is to describe the serve-stale-specific interaction, not to be the canonical DNSSEC doc.
- Update the file's `timestamp` frontmatter field to reflect the edit.

File: `/home/rpmoore/code/rdns/docs/knowledge/resolver/caching/serve-stale.md` (frontmatter block at lines 1-12, target paragraph at lines 113-122 as of this plan's writing — confirm exact line numbers haven't drifted before editing, since sections 01-05 may have touched other parts of the codebase but should not have touched this doc).

## Task 2: Update `docs/knowledge/resolver/caching/answer-cache.md`

The "What's stored per entry" table (around lines 50-57) has this row for `dnssec_state`:

```
| `dnssec_state` | RFC 6840 §3.1 validation state; stays `Unvalidated` until real DNSSEC validation exists — orthogonal to everything else in this document. |
```

Update this row (and only this row — the rest of the table, e.g. `dnssec_complete`, is unaffected by Track A and should not be touched unless Track A's changes actually altered its semantics, which they do not):

- Describe `dnssec_state` as the real, validator-produced verdict (`Unvalidated`/`Insecure`/`Secure`/`Bogus(reason)`) now, not a value that "stays `Unvalidated`."
- Note it is populated in `ResolutionMode::Recursive` only — `Forward` mode continues to trust the upstream's AD bit and does not run the validator (per plan §A5's scope decision). Say this explicitly since a reader relying on this table shouldn't assume `dnssec_state` is meaningful for every entry regardless of resolution mode.
- Keep this row's scope narrow — it is describing what's stored, not how it's computed or consumed; point to the new DNSSEC concept doc (Task 3) for the validator itself, and to `serve-stale.md` (Task 1) for the serve-stale-specific interaction, rather than duplicating either here.
- Update the file's `timestamp` frontmatter field to reflect the edit.

File: `/home/rpmoore/code/rdns/docs/knowledge/resolver/caching/answer-cache.md` (frontmatter at lines 1-8, target row around lines 50-57 as of this plan's writing — confirm current line numbers before editing).

## Task 3: Add a new DNSSEC validation concept doc

No existing `docs/knowledge/` doc covers the DNSSEC validator itself. Add a new concept doc following the frontmatter/structure conventions already used throughout `docs/knowledge/` (see `/home/rpmoore/code/rdns/docs/knowledge/resolver/metrics-source-ip.md` as a structural reference: YAML frontmatter with `type`, `title`, `description`, `resource`, `tags`, `timestamp`, followed by grounded prose with `file:line` references).

Suggested location: `/home/rpmoore/code/rdns/docs/knowledge/resolver/dnssec-validation.md` (sibling to `rd-bit-handling.md`, `chaos-queries.md`, `metrics-source-ip.md` — a resolver-level concept, not caching-specific, since it spans validator core, trust anchors, and response assembly). Confirm against whatever module location sections 01-05 actually used (plan suggests `src/resolver/dnssec_validation.rs` or similar) and set `resource:` to that path.

The doc must cover, grounded with real `file:line` references (fill these in from what sections 01-05 actually built — do not guess line numbers, read the landed code):

- **What it is**: a validation pass that runs after a recursive query's data is fully fetched and before it's turned into a cache entry, calling into the `domain` crate's `dnssec::validator` module (not hand-rolled).
- **Module location and entry points**: the section-03 validation function's signature/location, and the section-04 call sites in `build_rrset_entry`/`build_negative_entry`.
- **Trust anchor sourcing**: the bundled KSK-2017/KSK-2024 anchor file from section-02, the `TrustAnchorSource::Bundled`/`Static` config override, and a pointer to the separate scheduled CI staleness check (section-02's §A3 workflow) rather than duplicating its mechanics here.
- **Scope**: `ResolutionMode::Recursive` only; `Forward` mode is unchanged and trusts the upstream AD bit verbatim.
- **`ValidationState` → `DnssecState` mapping**: `Secure`→`Secure`, `Insecure`→`Insecure`, `Bogus`→`Bogus(reason)`, `Indeterminate`→`Unvalidated` — and the important asymmetry that `Indeterminate` is state-invisible (collapses to `Unvalidated` on the entry) but metrics-visible (distinguishable from "never attempted" via the section-05 outcome counter). Explain *why* this collapse is safe: the entry-level `DnssecState` enum's data model wasn't expanded for `Indeterminate` as a distinct persisted state, by design, but that doesn't mean the distinction is lost — it's just relocated to the metrics layer.
- **Fail-closed timeout/error handling**: a timeout or transport error during the DS/DNSKEY chase maps to `Bogus` with a diagnostic reason, not `Insecure` or silently to `Unvalidated`. State plainly that this is a deliberate trade-off — transient upstream slowness can produce a SERVFAIL for CD=0 requesters — and cross-reference this same point in the rollout note (Task 4) rather than only stating it once.
- **CD-bit gating**: validation always runs and is always stored regardless of the triggering request's CD bit; CD-bit gating happens later, at response-assembly time, by threading the request's CD bit into the `dnssec_servfail_check`/`negative_dnssec_servfail_check` call site (`src/resolver/cache/assemble.rs:426-459` as of this plan's writing) without modifying those functions themselves. Explain why this matters: the cache entry is shared across requesters, so a CD=1 requester must not cause a CD=0 requester to see an unvalidated/ungated entry.
- **TTL capping**: effective cache TTL is capped at the earliest RRSIG expiration in the validated chain, in addition to whatever TTL logic already governs the entry — otherwise a `Secure` entry could be served from cache after its signature has cryptographically expired.
- **Serve-stale interaction**: a `Bogus` entry is never eligible for serve-stale — cross-reference `serve-stale.md` (Task 1) rather than re-deriving the rule here.
- **Known upstream limitation, accepted as-is**: `domain`'s validator fetches DS/DNSKEY sequentially, doesn't prefetch, and can issue duplicate fetches for parallel same-name queries (e.g. simultaneous A/AAAA lookups). This is a `domain`-crate limitation, not something rdns's wiring fixes; not solved in this pass, watch the section-05 metrics for latency impact post-rollout.
- **Status/mode/metrics**: `DnssecValidationMode::Enabled`/`Disabled`, the on-by-default config default, the `cache_namespace_label()` split (which changes the cache-epoch namespace hash on upgrade — call out that this is an intended, one-time cache invalidation, not a regression), and the `dnssec_validation_results_total` counter with its outcome labels.
- **Tests**: point to the fixture module and test names from section-03/section-04/section-08 (known-answer, Bogus-injection variants, algorithm-downgrade, NSEC3 opt-out if built, signature validity-window, timeout/error-path, mixed-state CNAME chain, CD-bit, serve-stale) rather than re-describing what each test does — this doc should be a map into the test suite, not a duplicate of it.

Add an index entry for the new doc in `/home/rpmoore/code/rdns/docs/knowledge/resolver/index.md`, following the existing bullet format (see the four existing entries there for `caching/`, `rd-bit-handling.md`, `chaos-queries.md`, `metrics-source-ip.md`).

## Task 4: Run `/security-review` over Track A (plan §C2)

Run `/security-review` covering the full surface Track A built:

- The validator wiring (section-03's core validation function, the transport adapter bridging rdns's upstream transport to `domain`'s `SendRequest`).
- Trust-anchor bundling and the config-level override path (section-02).
- CD-bit gating logic (section-04's response-assembly call-site change).
- This is explicitly required because both Track A and Track B "handle attacker-controlled wire bytes (signature bytes, cookie bytes) that an adversary can craft to try to bypass validation" (plan overview) — DNSSEC signature/key/digest bytes specifically for this track.

Address findings, or document explicitly why a given finding is not being acted on, per `AGENTS.md`'s PR-feedback-resolution rule ("When reviewing GitHub PR feedback, always mark the feedback as resolved when the feedback has been addressed, or state why the comment was not addressed"). If addressing feedback materially changes the diff, run one follow-up `/codex:adversarial-review` on the updated diff before committing, per `AGENTS.md`'s standing Change Workflow rule.

Separately, per `AGENTS.md`'s standing rules (not specific to this section, but a gate this section must also satisfy before Track A's PR is considered done): run the `verify` skill and satisfy the fmt/clippy/test gates in `RUST.md`, independent of the security review.

## Task 5: Write the rollout note (plan §C3)

Write a rollout note for Track A's PR description (and any changelog entry, if the project adds one — as of this plan's writing there is no `CHANGELOG.md` in the repo root, so the PR description is the primary vehicle). The note must cover, verbatim in substance even if reworded:

- **DNSSEC validation ships on by default.** This is a deliberate, explicit decision, reaffirmed after external plan review specifically recommended an opt-in first release given the lack of field experience with this validator in production. The decision stands: on-by-default, with the expanded test suite (known-answer, Bogus-injection, algorithm-downgrade, expired/not-yet-valid-signature, timeout/error-path, and mixed-chain tests — sections 03/04/08 collectively) treated as the mitigation instead of a staged rollout.
- **Existing deployments start validating and enforcing SERVFAIL-on-Bogus immediately on upgrading** past this release. This is not a silent default flip — it's an intended, immediate behavior change operators should be aware of before upgrading.
- **Fail-closed timeout risk.** Per the validator core's fail-closed timeout handling (section-03/04), transient upstream slowness during validation can also produce SERVFAILs for CD=0 requesters. This is an additional, related risk introduced by the on-by-default choice — distinct from, and additive to, the Bogus-detection risk above. State both risks separately; don't let one subsume the other in the writeup.
- **Cache-namespace invalidation on upgrade.** Combined with the cache-namespace change from section-05 (`cache_namespace_label()`'s new `Enabled`/`Disabled` split), an upgrade will both invalidate old cache entries *and* begin rejecting previously-tolerated Bogus-signed responses at the same time. Call out that these are two distinct, simultaneous effects of the same upgrade, not one effect described twice.

This should be a self-contained paragraph or two suitable for pasting directly into the PR description — write it as such, not as a reference to "see the plan for details."

## Verification checklist for this section

- [ ] `serve-stale.md` no longer states DNSSEC validation doesn't exist; the Bogus-excluded-from-serve-stale rule is present and explicit; `Secure`/`Insecure` no-change is stated explicitly; frontmatter `timestamp` updated.
- [ ] `answer-cache.md`'s `dnssec_state` row reflects the real computed value and the `Recursive`-only scope; frontmatter `timestamp` updated.
- [ ] New DNSSEC validator concept doc exists, is grounded with real `file:line` references (not placeholders), and is linked from `docs/knowledge/resolver/index.md`.
- [ ] `/security-review` has been run over the validator wiring/trust-anchor/CD-bit surface; findings addressed or explicitly documented as not-addressed.
- [ ] `verify` skill and `RUST.md`'s fmt/clippy/test gates pass.
- [ ] Rollout note drafted, covering on-by-default, fail-closed timeout risk, and cache-namespace invalidation, ready to paste into Track A's PR description.

---

Relevant files for this section:
- `/home/rpmoore/code/rdns/docs/knowledge/resolver/caching/serve-stale.md`
- `/home/rpmoore/code/rdns/docs/knowledge/resolver/caching/answer-cache.md`
- `/home/rpmoore/code/rdns/docs/knowledge/resolver/index.md`
- New file: `/home/rpmoore/code/rdns/docs/knowledge/resolver/dnssec-validation.md` (suggested path; confirm against actual section-01/03 module location before finalizing)
- `/home/rpmoore/code/rdns/src/resolver/cache/assemble.rs` (referenced, not modified, in the new concept doc)
- `/home/rpmoore/code/rdns/src/resolver/cache/entry.rs` (`DnssecState` enum, referenced not modified)

## As implemented

Landed at the suggested path (`docs/knowledge/resolver/dnssec-validation.md`,
resolver-level sibling of `metrics-source-ip.md`, confirmed correct
against the actual module location `src/resolver/dnssec_validation.rs`).
Full detail in
`docs/plans/sec_work/implementation/code_review/section-06-{security-review,interview}.md`.

**Tasks 1-3 (docs)**: `serve-stale.md`/`answer-cache.md`'s DNSSEC
paragraphs were largely already accurate going in — section-05's own
code-review interview had already updated both away from the
"unreachable in production" framing this section's plan draft was
written against, and section-04 had already landed the explicit
`Bogus`-excluded-from-serve-stale invariant and the RFC 4035 §4.3
answer (TTL capping at RRSIG expiration already covers stale-serve
revalidation). This section's actual doc work was: bump both files'
frontmatter timestamps, add cross-references to the new concept doc,
tighten `answer-cache.md`'s wording to state the `Recursive`-only scope
explicitly, and write the new `dnssec-validation.md` concept doc itself
(grounded with real `file:line` references, verified accurate by the
code-review subagent) plus its `index.md` entry.

**Task 4 (`/security-review`)** surfaced two real, non-theoretical
findings, both fixed in this section's diff rather than deferred:
1. Section-05's trust-anchor-parse-failure branch recorded the correct
   `Bogus` metric but the wrong stored `DnssecState` (`Unvalidated`),
   bypassing SERVFAIL/serve-stale gating for a live misconfiguration.
2. `TrustAnchorSource` content/source was never hashed into the
   cache-namespace fingerprint (`authority_config_hash`), left
   unresolved since section-02/03 — rotating trust anchors didn't
   invalidate cached verdicts computed under the old anchor set. Fixed
   by hashing trust-anchor content the same way root-hints content
   already is, with a new regression test.

Neither finding was anticipated by the original plan text (which
expected this task to mostly confirm sections 01-05's existing work was
sound) — both were genuine gaps the review step was supposed to catch,
and did.

**Task 5 (rollout note)**: written to
`docs/plans/sec_work/rollout-note.md` rather than inline in this file,
since it's meant to be pasted directly into Track A's PR description —
covers all four required points (on-by-default decision, immediate
upgrade behavior change, fail-closed timeout risk stated separately
from Bogus-detection risk, cache-namespace invalidation stated as a
distinct simultaneous effect) as the plan's anti-conflation instructions
required.

**Verification**: `cargo fmt`, `cargo clippy --all-targets --all-features
-D warnings`, `cargo test` all green (738 lib + 39 bin tests, +1 new
regression test from the trust-anchor cache-namespace fix). Doc-only
Tasks 1-3 have no `#[test]` coverage per the plan's own note; Task 4's
two code fixes each carry a new/updated test.