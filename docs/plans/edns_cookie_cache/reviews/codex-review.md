# Codex review of claude-plan.md

1. **Cache-predicate ambiguity**: `cache_supported()`'s "options empty OR
   exactly one well-formed COOKIE option consumes all the bytes" needs to
   be a crisp, explicitly-tested condition distinct from
   `parse_cookie_option`'s "extract a client cookie if present" concern — a
   query with Cookie + NSID must still bypass (Goal 5), and the plan's
   wording didn't clearly separate "extraction" from "cache-compatibility
   admission."

2. **Scope gap: only cache-hit assembly widened.** The plan named
   `requester_opt_record`'s four cache-hit callers
   (`build_servfail`, `finish_with_truncation_check`, `assemble_response`,
   `assemble_negative_response`, all in `assemble.rs`) but Goal 2 says
   "every response, cache hit or miss." The recursive-miss/coalesced path
   rebuilds requester OPT records via a *different* mechanism
   (`mirrored_client_opt_record`/`message_edns_opt_record`,
   `mod.rs:1628-1630,1685-1687,1721-1729,4960-4963,5023-5029`;
   `protocol/mod.rs:1296-1303`) that the plan didn't touch — cache misses
   would still emit option-less OPT records even for Cookie-bearing
   queries.

3. **Cache-safety reasoning holds**, but should be pinned as an explicit
   invariant/test (cache lookup/`MissKey` already excludes EDNS option
   bytes, `mod.rs:4433-4440,4467-4474`) rather than left implicit.

4. **Dependency plan needs correction**: enabling `domain`'s `"rand"`
   Cargo feature only unlocks `domain`'s *internal* use of `rand` (e.g.
   inside its middleware) — it does not give rdns's own code a public,
   importable `rand` API. To generate `CookieSecret`'s random bytes, rdns
   code needs `rand` as its own **direct** Cargo dependency (it can still
   be tiny/justified — CSPRNG secret generation — but "zero new top-level
   entries" was inaccurate for this piece). `siphasher` itself can stay
   purely an internal `domain` feature, since `StandardServerCookie::calculate`
   is reachable directly with a `&[u8; 16]` secret argument, without rdns
   needing to import `siphasher`.

5. **Test sequencing under-scoped**: beyond the two named bypass tests,
   widening `QueryFeatures`/OPT-per-requester behavior will also touch
   existing `assemble.rs` OPT/truncation/negative-response tests
   (`assemble.rs:903-938,1672-1681,1684-1727`) and
   `recursive_synthesis_reused_own_framing` (`mod.rs:1744-1768`), which
   currently only compares EDNS-presence/DO-bit and would need to account
   for per-requester Cookie differences on otherwise-shared/coalesced
   framing.
