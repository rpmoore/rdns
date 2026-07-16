# Section 07 code review: knowledge-bundle documentation update

Reviewed by `deep-implement:code-reviewer` subagent against
`docs/plans/edns_cookie_cache/sections/section-07-knowledge-bundle-docs.md`.
Doc-only change to `docs/knowledge/resolver/caching/answer-cache.md`.

## Findings

1. **SHOULD-FIX (applied)**: the "both paths build their COOKIE option the
   same way ... written to the wire by `build_opt_record_with_options`"
   paragraph was factually wrong on two counts — (a) the cache-hit path
   (`requester_opt_record`) never calls `build_opt_record_with_options`; it
   builds a plain OPT via `build_opt_record` and mutates `EdnsInfo.options`
   in place, only the cache-miss path
   (`message_edns_opt_record_with_cookie`) calls
   `build_opt_record_with_options`; (b) the "funnel through" direction was
   backwards — both `build_opt_record` and `build_opt_record_with_options`
   delegate to `build_opt_record_with_extended_rcode`, not the reverse.
   **Fix applied**: rewrote the paragraph to correctly distinguish the two
   paths' wire-attachment mechanisms and the actual delegation direction.

2. **Verified accurate** (no issue): every other `file:line` reference and
   behavioral claim — `cache_supported` admission condition and line range,
   `is_solely_cookie_option`, the cache-key/`MissKey` independence test,
   `requester_opt_record`'s four call sites, `mirrored_client_opt_record_with_cookie`'s
   threading through `rebuild_recursive_response_with_own_framing`/
   `truncated_response_for_query`/`prepare_backend_result`, the plain
   `mirrored_client_opt_record`'s two remaining call sites, `CookieSecret`'s
   process-lifetime/no-rotation properties, and the RFC 7873/RFC 9018
   citations — all checked out exactly against current source.

3. **Security trade-off paragraph**: not softened, matches the plan's
   explicit requirement — states plainly there is no incoming-cookie
   validation, no BADCOOKIE generation, no rejection behavior, and closes
   with an unambiguous "no — it has Cookie echo/interop only."

4. **Decision not to add a new concept doc for `src/protocol/edns_cookie.rs`**:
   confirmed reasonable — no independent concurrency/invalidation/rotation
   invariant exists in that module beyond what `answer-cache.md`'s update
   already covers.

5. Style, heading placement, and OKF frontmatter: all consistent with the
   rest of the doc; no broken cross-references; the old forward-reference
   stub was fully removed, not left dangling.
