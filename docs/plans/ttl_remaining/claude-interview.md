# Interview transcript

## Q1: Open Q1 (primary) — how resolve `cache_supported()`'s EDNS-options bypass?
**Answer:** (b) Broader cache-key-neutral allowlist. Cookie (and, in principle,
Padding) permitted through the cache path; OPT record stripped/regenerated
per request rather than replaying cached OPT bytes.

## Q2: If (c) had been chosen, would broader real-world-impact measurement be needed?
**Answer:** Document as-is (moot — (b) was chosen, not (c); no further
measurement needed for the confirmed-vs-plausible distinction already in
the spec).

## Q3: Disposition of stale `docs/caching.md`?
**Answer:** Retire it. `docs/knowledge/` is current-behavior source of truth
per root `AGENTS.md`; `docs/caching.md`'s described types/functions
(`CachedResponse`, `serialize_cached_response`) no longer exist.

## Q4: Where should the Cookie server-secret live?
**Answer:** Generate random in-memory at startup. No config/persistence
surface added; cookie validity resetting on restart is acceptable per RFC —
clients re-handshake automatically (§5.2.3/§5.2.4 fallback path handles
this as an ordinary "invalid/stale server cookie" case).

## Q5: RFC 7873 §5.2.3 policy (client cookie present, no/invalid server cookie)?
**Answer:** Process normally, attach a fresh valid COOKIE option. No
BADCOOKIE (RCODE 23) round-trip implemented — simplest correct behavior,
avoids adding a BADCOOKIE retry path/tests for this pass.

## Q6: Clock DI wiring — where does the `Arc<dyn Clock>` come from at the delivery/dns.rs layer?
**Answer:** Passed into the UDP/TCP listener/handler at construction time —
same `Arc<dyn Clock>` instance already built once at startup (`main.rs`'s
`SystemClock`), threaded through the handler structs, mirroring however the
resolver itself already receives it. Exact call-site wiring to be nailed
down during plan-writing (Open Question 2's "wiring decision," not decided
in interview).

## Q7: Test placement for the live-Clock-injection e2e case (Goal 6 / Open Q6)?
**Answer:** New file under `tests/`, matching `tests/forwarding.rs`'s
`FixedClock` precedent — true black-box integration test through the public
`Clock` trait, not colocated with the in-module `mod.rs` e2e tests.

## Q8: Open Q4 — zero/near-zero origin TTL vs `min_positive_ttl` floor: change aging behavior or keep as-is?
**Answer:** Keep as-is, add a regression test. Document as intended
semantics: never claim more remaining TTL than the record's own origin TTL
implies. Matches `compute_wire_ttl`'s per-record-truth design intent.

## Q9: Open Q5 — chain-wide `expires_at` ceiling: dedicated regression test needed, or doc mention only?
**Answer:** Doc mention + regression test. This interaction (a CNAME
chain's minimum TTL silently capping a terminal record even when looked up
directly later) was discovered mid-audit and was previously untested;
worth locking in given it's real, previously-invisible behavior.

## Q10: PR sequencing — combined or split, given Option (b) triggers mandatory `/security-review`?
**Answer:** Split. Land the lower-risk work first: knowledge-bundle
documentation, Clock DI, and the edge-case regression tests (zero-TTL
floor, chain-wide ceiling) as one PR. The Cookie-cache-allowlist
implementation (Option (b), security-sensitive) ships as a separate,
later PR with its own `/security-review` pass.

## Q11: Scope check — Cookie only, or Cookie + Padding together, for the Option (b) work?
**Answer:** Cookie only for now. Cookie is the confirmed real-world finding
(dig's default query bypasses the cache). Padding (RFC 7830) is currently a
no-op for this resolver — it only matters over encrypted transport
(DNS-over-TLS/DoH), which this resolver doesn't yet serve (UDP/TCP-53
only) — so implementing Padding support now would be unused code. Defer
Padding to whenever DoT/DoH support is added.
