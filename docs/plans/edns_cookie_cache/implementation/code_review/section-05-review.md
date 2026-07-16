# Section 05 code review: cache-miss/recursive-response OPT path gains Cookie support

Reviewed by `deep-implement:code-reviewer` subagent against
`docs/plans/edns_cookie_cache/sections/section-05-cache-miss-opt-path.md`.

## Findings

1. **`recursive_synthesis_reused_own_framing` cookie-forced-rebuild logic** — correct.
   `has_cookie` checks both `decoded.message` and `synthesis.original_query`, forcing
   `false` (never-reused) if either carries a parseable cookie, before falling through to
   the pre-existing `question_matches && opt_matches` logic for the non-cookie case.

2. **Call-site audit inside `prepare_backend_result`** — all 8 threaded call sites pass
   `&self.cookie_secret, request.client_ip, self.clock.now()` consistently; no site missed.

3. **`local_entry_response` cookie leak (SHOULD-FIX, applied)** — the widened
   `truncated_response_for_query` signature caused `local_entry_response`'s truncation
   fallback to silently gain cookie-echoing behavior that the plan explicitly scoped out,
   while its untruncated branch stayed cookie-unaware — a size-dependent behavioral flip
   for the same query type, uncovered by any test. **Fix applied**: `local_entry_response`
   now inlines a plain, cookie-unaware truncated-response build (via the untouched
   `mirrored_client_opt_record`) instead of calling the now-cookie-aware
   `truncated_response_for_query`. Added regression test
   `resolve_truncated_local_entry_response_omits_cookie_option`.

4. **`message_edns_opt_record_with_cookie` mirrors `requester_opt_record`** — correct,
   same `parse_cookie_option` → `build_server_cookie` → `build_cookie_option` sequence,
   same fallbacks. Minor stale doc comment on `build_opt_record_with_options` fixed to
   reflect that it's now wired up.

5. **Test quality** — no repeat of the blocking-transport trap from an earlier draft (fixed
   during self-testing before review: the single-resolve test now uses
   `ScriptedAuthorityTransport`, not an unreleased blocking transport). Coalesced test
   correctly releases the transport before awaiting both requesters.

6. **Separate `mirrored_client_opt_record_with_cookie` function vs. widening in place** —
   confirmed correct. The plan's own "Recommended shape" section is internally
   contradictory (widen in place, but also leave call site 1 untouched on the old
   signature); a separate function is the only way to satisfy both, and it mirrors the
   already-separate protocol-layer pattern (`message_edns_opt_record_with_cookie` next to
   `message_edns_opt_record`).

7. **Nits (not acted on)**: `self.clock.now()` called fresh at each of the 8 call sites
   rather than captured once — harmless per RFC 9018's timestamp tolerance, left as-is to
   avoid unrequested refactoring. `docs/knowledge/` update for the resolver's recursive-miss
   cookie behavior deferred to the section-07 (knowledge bundle) step, which is already a
   dedicated section in this plan.
