## Section 07 — code review triage (no user interview needed)

The subagent review surfaced one substantive finding (client-cookie re-extraction in `BasicResponseFactory::protocol_error`'s `InvalidServerCookie` placeholder silently drops the malformed-cookie case) and one false positive (clippy `too_many_arguments` on the trait impls).

Both were resolved by cross-checking `section-08-badcookie-detection.md`, which already documents this exact gap as a known placeholder it fixes in its own scope (`locate_cookie_for_verification`, shared between the new `probe_cache` check and this special case). No design tradeoff needed a user decision — the plan had already made the call. Auto-fix applied: tightened the inline comment in `src/resolver/mod.rs` to name the gap plainly instead of asserting the extraction is always sound, so a reader hitting this code before section-08 lands isn't misled.

Auto-fixes applied:
1. `src/resolver/mod.rs`, `BasicResponseFactory::protocol_error`'s `InvalidServerCookie` branch: reworded the comment above the `parse_cookie_option` call to explicitly flag it as a placeholder that mishandles the malformed-length case, and point at section-08's planned fix.

No fixes deferred to the user; nothing skipped as a nitpick beyond what's already noted in `section-07-review.md`.
