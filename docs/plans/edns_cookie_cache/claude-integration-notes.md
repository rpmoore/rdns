# Integration notes: Codex review → claude-plan.md

All 5 findings from `reviews/codex-review.md` are integrated. None rejected.

1. **Cache-predicate ambiguity (integrated)** — split into two distinct
   functions in the plan: `parse_cookie_option` (extraction, used for
   response-building) vs. a new, explicitly-named
   `is_solely_cookie_option` (the cache-admission predicate) so
   `cache_supported()`'s allowlist condition is unambiguous and
   independently testable, including the Cookie+NSID-still-bypasses case.

2. **Scope gap on cache-miss/recursive path (integrated)** — added a new
   section covering `mirrored_client_opt_record`/`message_edns_opt_record`
   (the recursive-miss OPT-rebuild path, distinct from
   `requester_opt_record`'s cache-hit path) so Goal 2 ("every response,
   cache hit or miss") is actually covered by a section, not just stated
   as a goal.

3. **Cache-safety invariant (integrated)** — added an explicit
   verification bullet: a test asserting cache lookup/`MissKey`
   construction never reads EDNS option bytes, pinning the invariant
   rather than leaving it as narrative reasoning only.

4. **Dependency correction (integrated)** — corrected the dependency
   section: `domain`'s `"rand"` feature only unlocks `domain`'s internal
   use of `rand`, not a public API rdns can call. `rand` needs to be added
   as rdns's own small direct dependency for `CookieSecret::generate()`.
   `siphasher` stays purely an internal `domain` feature (not imported
   directly by rdns) since `StandardServerCookie::calculate` is reachable
   with a raw `&[u8; 16]` secret. Updated the "zero new top-level
   dependency" framing to "one small, justified new direct dependency
   (`rand`, for CSPRNG secret generation) plus a `domain` feature-flag
   change — no new crypto/hashing crate."

5. **Test sequencing (integrated)** — added the additional existing tests
   that need review/update: `assemble.rs` OPT/truncation/negative-response
   tests and `recursive_synthesis_reused_own_framing`
   (`mod.rs:1744-1768`), which currently only compares EDNS-presence/DO-bit
   for framing reuse and needs to account for per-requester Cookie
   differences.
