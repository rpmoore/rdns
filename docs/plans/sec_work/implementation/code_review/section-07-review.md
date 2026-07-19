## Section 07 (BADCOOKIE wire-level RCODE 23) — code review

Reviewed by `deep-implement:code-reviewer` subagent against `section-07-badcookie-wire-rcode.md`'s acceptance criteria and `section-07-diff.md`.

### Findings

1. **HIGH** (src/resolver/mod.rs, `BasicResponseFactory::protocol_error`'s new `InvalidServerCookie` branch): re-derives the client cookie via `edns_cookie::parse_cookie_option`, which returns `None` for a malformed-length COOKIE option — exactly one of the two cases `InvalidServerCookie`'s doc comment says it covers. Once wired to a real caller, a malformed-but-present server cookie would silently fall through to the generic FormErr path instead of BADCOOKIE.
   - **Resolution: no code change in this section.** Confirmed against `section-08-badcookie-detection.md` (lines 119-151): section-08 explicitly calls this out as "left as a placeholder" and replaces it with `locate_cookie_for_verification`-based extraction as part of its own scope, sharing one parsing function between `probe_cache`'s new check and this special case. Fixing it here would be replaced within the next section anyway. Tightened the inline comment instead to name the known gap plainly rather than imply the extraction is always sound (see interview).

2. **HIGH** (`#[allow(clippy::too_many_arguments)]` only on the trait decl, not the two impls): verified empirically not a real gate risk — `cargo clippy --all-targets` passes clean with zero warnings on the impls. Clippy does not re-flag `too_many_arguments` on trait-method impls whose signature is fixed by the trait. No action needed.

3. **MEDIUM** (no routing test for the malformed-length cookie case): section-08's plan (test 12, line 305) already commits to adding exactly this test once the real fix lands. Adding it here against the placeholder would just be deleted/rewritten next section. No action needed.

4. **LOW** (silent fallthrough has no logging/metric): same reasoning as #1 — superseded by section-08's fix. No action needed.

### Verified correct (no changes needed)
- Manually-composed header flags in `build_badcookie_response` exactly mirror `write_message_header`'s bit layout (QR/RD/RA/CD conditional-copy, TC/AA/AD hardcoded off, RCODE nibble 7 ORed in directly).
- Combined extended-RCODE arithmetic (`(1<<4)|7 = 23`) correct; both new protocol-level tests assert the combined value, not either half in isolation.
- Server-cookie-freshness test independently recomputes `build_server_cookie` and diffs against the response's OPT options.
- `ConfiguredResponseFactory` delegation verified byte-identical for the new variant.
- Single production call site (`decode_or_protocol_error`), imports, variant/doc-comment, and `response_code()` bucketing all match the plan.
