# Interview transcript

## Q1: Should the resolver validate an incoming server cookie's hash/timestamp at all, given the decided policy is "always process normally + attach a fresh valid server cookie" regardless of validity?
**Answer:** Skip validation entirely. Behavior doesn't depend on incoming server-cookie validity, so validating it would be dead code. Only extract+echo the 8-byte client cookie; always compute and emit a freshly-computed server cookie.

## Q2: Where should the per-startup server-cookie secret + cookie compute/parse logic live?
**Answer:** New module under `src/protocol/` (e.g. `src/protocol/edns_cookie.rs`) — protocol owns DNS wire-format concerns per `AGENTS.md` layering. Secret generated once at startup, threaded down like `Clock`.

## Q3: Enable `domain` crate's existing `siphasher`+`rand` features (already a dependency) instead of adding a new top-level crate?
**Answer:** Yes. Zero new top-level `Cargo.toml` entries; reuses `domain::base::opt::cookie`'s RFC-9018-test-vector-verified implementation.

## Q4: Implement RFC 7873 §5.2.2 FORMERR for malformed (wrong-length) COOKIE options, or fall back to today's generic bypass?
**Answer:** Bypass cache, no FORMERR. Malformed COOKIE option is treated like any other unrecognized/malformed EDNS content today — `cache_supported()` returns false, request proceeds to backend unchanged. No new FORMERR path.

## Q5: New metric/event to distinguish "cache hit served with Cookie present" from today's plain cache-hit metric?
**Answer:** No new metric. Cookie-bearing requests flow through existing `CacheHit`/`CacheMiss`/`CacheBypass` metrics unchanged.

## Q6: How should the per-startup Cookie secret reach the code that threads it (ResolveQuery construction, main.rs wiring)? Mirror the Clock DI pattern from ttl_remaining?
**Answer:** Yes, same DI pattern as `Clock`. Generate once in `main.rs` at startup, pass as an `Arc`-wrapped secret type into `ResolveQuery` construction, thread down to wherever `assemble_response` needs it — consistent with the existing `Arc<dyn Clock>` precedent.

## Q7: Where should mandatory `/security-review` sit in the section sequence?
**Answer:** Final section, after all code lands — run `/security-review` against the full diff before PR, per `AGENTS.md`'s untrusted-input/network-code trigger.
