# Code Review: Section 02 - DNSSEC Trust Anchor Bundling + Staleness CI

Config-side plumbing (`src/config/mod.rs`) faithfully mirrors the `RootHintsSource` pattern: `TrustAnchorSource` enum, `bundled_trust_anchors()`/`BUNDLED_ROOT_ANCHOR` const, `RecursiveResolutionConfig` field + `load_trust_anchors()`, `validate()` rejecting empty sets, `ConfigError::MissingTrustAnchors`/`InvalidTrustAnchorEntry`, and the `Raw*`/TOML match arm all line up with the plan. All four "Tests first" unit tests are present and correctly navigate the documented `TrustAnchor`-being-`pub(crate)` constraint (asserting key tags against source text rather than the parsed `TrustAnchors` value).

## Findings

1. **(High) Missing `cache_namespace_label()` on `TrustAnchorSource`.** The plan's Implementation section 2 explicitly specifies this method as part of "the trust-anchor equivalent of every piece" of `RootHintsSource`. The diff adds the enum but no `impl TrustAnchorSource` block. The "Notes for the implementer" section only excuses *wiring it into `authority_config_hash()`*, not omitting the method entirely.

2. **(High, security-relevant) KSK-2024 digest correctness.** The reviewer subagent had no network access to verify `683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16` against IANA. **Already verified independently during implementation**: fetched `root-anchors.xml` live from `https://data.iana.org/root-anchors/` and confirmed byte-for-byte, and separately confirmed via a full CMS-signature-verified run of `check-trust-anchor-staleness.sh` against the live file (passed with the real bundled digests). No action needed.

3. **(High) A3 manual verification undocumented.** The plan calls out that the manual "run the script against a deliberately corrupted copy and confirm it flags drift" check won't show up in `cargo test` and must be documented as prose. **This was performed** during implementation: tested against a corrupted digest (correctly flagged `does not match IANA's published digest`) and a deleted entry (correctly flagged `bundle is missing an anchor`), both with clean-file restore confirmed after. Not yet documented anywhere in the diff — needs a note.

4. **(Medium) Fragile regex/sed XML parsing in the staleness script.** Internally consistent (tested against 3 real scenarios: clean pass, corrupted digest, missing anchor) but brittle to IANA reformatting whitespace/attribute order.

5. **(Medium) Bare command substitution can abort mid-loop under `set -e`.** If `grep -oP` fails to match inside the per-record loop, the assignment's exit status aborts the script with an uncategorized error instead of the script's own `::error::`-prefixed message — still fails closed, but blurs the "couldn't confirm freshness" vs "anchor is stale" distinction the plan asks to keep separate.

6. **(Low) Redundant re-parse for the Bundled case in `validate()`** — harmless, and consistent with how `root_hint.validate()` already re-validates every entry unconditionally regardless of source.

7. **(Low) Staleness script's field-parsing is DS-specific** — fine since the bundled file is DS-only and self-consistent with the script; no action.

8. **(Low) `xargs`-as-trim idiom** in the staleness script's bundled-line parser — minor robustness nit, trivial to swap for `sed`.

## Not flagged
`docs/knowledge/` updates are out of scope per the plan (deferred to section-06). No existing scheduled/alert workflow pattern to match, so relying on GitHub's default scheduled-workflow-failure email is reasonable. `authority_config_hash()` correctly left untouched.
