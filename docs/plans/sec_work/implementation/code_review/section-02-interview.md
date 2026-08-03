# Code Review: Section 02 - DNSSEC Trust Anchor Bundling + Staleness CI

**Date:** 2026-07-18

## Discussed with user

### cache_namespace_label() omission
**Decision:** Add `cache_namespace_label()` to `TrustAnchorSource` with `#[allow(dead_code)]` and a one-line reason (unused until section-03/04 wires trust-anchor source into the cache namespace hash). Matches the plan's spec exactly while keeping the clippy gate clean.

### Regex-based XML parsing in the staleness script
**Decision:** Keep the current grep/sed/tr parsing. Already tested against 3 live scenarios (clean pass, corrupted digest, missing anchor). This is a non-blocking weekly scheduled check, not a PR gate — a parse hiccup means one missed scheduled run, not broken CI. Not worth reworking a script that's already verified working.

## Auto-fixes (applied without asking)

- **A3 manual verification undocumented.** Added a note to the staleness script's header comment and will call it out in the commit message: script was run locally against the real bundled file (clean pass) and against two deliberately corrupted copies (wrong digest → flagged; deleted entry → flagged), confirming it reports drift correctly.
- **Bare command substitution can abort mid-loop under `set -e`.** Guarded the per-record `grep -oP` extractions so a parse hiccup produces one of the script's own `::error::`-prefixed messages instead of an uncategorized abort, keeping "couldn't confirm freshness" and "anchor is stale" distinct as the plan asks.
- **`xargs`-as-trim idiom** in the bundled-file line parser swapped for an explicit `sed` trim — trivial robustness improvement, no behavior change for well-formed input.

## Let go

- KSK-2024 digest correctness — already independently verified against a live fetch of IANA's `root-anchors.xml` plus a full CMS-verified script run; not a gap.
- Redundant re-parse of the Bundled trust-anchor set inside `validate()` — consistent with how `root_hint.validate()` already re-validates every entry unconditionally regardless of source; not worth special-casing.
- Staleness script's DS-specific field parsing — self-consistent with the bundled file (DS-only); no action needed.
