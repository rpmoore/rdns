# Synthesized spec: TTL-remaining audit, EDNS-cookie cache allowlist, Clock DI

This synthesizes `plan.md` (initial input), `claude-research.md` (codebase
verification + RFC research), and `claude-interview.md` (all 6 open
questions + scope/sequencing decisions) into one complete, decided spec for
implementation planning.

## Resolved decisions (supersede `plan.md`'s "Open Questions" section)

1. **`cache_supported()` EDNS-options bypass → Option (b), Cookie-only, this pass.**
   Broaden `cache_supported()` to permit EDNS Cookie (RFC 7873, option code
   10) through the cache path. Do **not** implement Padding (RFC 7830) in
   this pass — it's currently a no-op for this resolver (UDP/TCP-53 only,
   no DoT/DoH), so it would be unused code; defer to whenever DoT/DoH
   lands. Every other EDNS-options bypass condition (non-zero extended
   RCODE, non-zero version, non-DO flags, any other option code) is
   unchanged — only the Cookie option specifically becomes cache-compatible.

   Design shape (confirmed reusable seam via codebase research):
   `filter_response_for_requester` (mod.rs:1480-1507, called from
   `prepare_backend_result` at mod.rs:4940) already builds a per-requester
   client-facing copy of a shared, always-DNSSEC-complete cached/synthesized
   response — trimming DO-dependent content per requester. Its doc comment
   explicitly notes it does not handle the OPT record; callers re-append
   `mirrored_client_opt_record` themselves. The Cookie allowlist should
   follow the same shape: cache the answer/RRset data only, never the OPT
   bytes; regenerate a fresh, correct COOKIE option on every response
   (cache hit or miss) at the same per-requester rewrite point.

   Cookie protocol behavior (RFC 7873 §5.2, hardened by RFC 9018):
   - No OPT/no COOKIE option → unaffected, existing behavior.
   - Malformed COOKIE option (wrong length: not 8, and not 16-40) → FORMERR
     (existing malformed-EDNS handling should already cover this via the
     "any non-DO flag / non-empty other options" path — verify during
     planning whether length-validation happens before or after the
     cache-bypass check).
   - Client cookie only, or client cookie + invalid/stale server cookie →
     **process normally, respond with a freshly generated valid COOKIE
     option** (client's cookie + new server cookie). No BADCOOKIE
     (RCODE 23) path implemented this pass (interview Q5).
   - Client cookie + valid server cookie → process normally, response
     includes a COOKIE option (fresh-generated, not copied verbatim from
     any cached bytes).
   - Server cookie computation: RFC 9018's mandated algorithm —
     `SipHash-2-4(Client Cookie | Version | Reserved | Timestamp |
     Client-IP, Server Secret)` → 16-byte server cookie. (RFC 7873
     Appendix B's older example algorithms are explicitly superseded/"MUST
     NOT be used" per RFC 9018.)
   - Server secret: generated randomly in-memory at process startup, not
     persisted, not configurable (interview Q4). Restart invalidates all
     outstanding server cookies for connected clients — acceptable, RFC's
     own invalid/stale-cookie fallback (§5.2.4) handles this transparently
     (client just gets a fresh cookie on its next query, no error surfaced).
   - Anycast/multi-instance note from research (RFC 7873 §6): a
     random-per-process secret means multiple resolver instances behind
     one anycast/load-balanced address would each reject each other's
     cookies as "stale," continuously falling back to §5.2.3/5.2.4
     regeneration — functionally correct (never breaks a client, per RFC
     text) but means cookies never actually "stick" across instances. Not
     a defect for a single-instance deployment; worth one line in the plan
     as a known limitation if this resolver is ever run in a multi-instance
     anycast setup.

   **Security-sensitivity:** RFC 7873 cookies are an anti-spoofing
   mechanism (untrusted-input parsing feeds a caching decision +
   cryptographic secret generation/comparison). Per root `AGENTS.md`, this
   work requires a mandatory `/security-review` pass before landing, and
   must not regress `resolve_bypasses_cache_for_unsupported_edns_options` /
   `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
   (mod.rs:18930-18954, 18956+) for every *other* EDNS-options case — only
   Cookie-shaped options should change behavior.

2. **PR/section sequencing → split (interview Q10).** This plan should
   organize work into (at minimum) two independently-shippable chunks:
   - **PR 1 (lower risk, ship first):** knowledge-bundle documentation
     (Goal 2, 4), Clock dependency-injection (Goal 3), edge-case regression
     tests (Goal 5: zero-TTL floor, chain-wide ceiling), Clock-injection
     e2e test (Goal 6), `docs/caching.md` retirement (decision 3 below).
     No behavior change to production TTL-aging logic; no security-review
     trigger on its own merits (Clock DI is a pure refactor per Risks
     section of `plan.md`).
   - **PR 2 (security-sensitive, ships separately, later):** the Cookie
     cache-allowlist (decision 1 above) — mandatory `/security-review`
     before landing, gated independently of PR 1.
   The implementation plan (`claude-plan.md`) and its TDD/section split
   should reflect this PR boundary explicitly — e.g. as a dedicated
   section (or section group) for the Cookie work, clearly separated from
   the audit/hardening sections, so `/deep-implement` can treat them as
   separate review/merge units.

3. **`docs/caching.md` → retire (interview Q3).** It describes types/
   functions (`CachedResponse`, `serialize_cached_response`) that no longer
   exist in `src/`. `docs/knowledge/` is the current-behavior source of
   truth per root `AGENTS.md`. Retiring means: remove the file (or replace
   its content with an explicit "superseded by docs/knowledge/resolver/
   caching/, see docs/plans/cache_rework/ for history" pointer — plan
   should decide which, given it has several inbound references from
   `docs/plans/cache_rework/*` that must keep working as *historical*
   citations, per `plan.md`'s Risks section). Do not break those inbound
   historical links.

4. **Zero/near-zero origin TTL vs `min_positive_ttl` floor → keep current
   behavior, add regression test (interview Q8).** Document as intended
   semantics: `compute_wire_ttl` never claims more remaining TTL than the
   record's own origin TTL implies, even when the entry is kept alive
   longer by a `min_positive_ttl` floor. New unit test needed (no existing
   coverage per `plan.md` Current State point 8) alongside
   `assemble_response_ages_each_record_ttl_independently` /
   `assemble_response_caps_ttl_to_remaining_entry_lifetime` in
   `assemble.rs`.

5. **Chain-wide `expires_at` ceiling → doc mention + dedicated regression
   test (interview Q9).** New test needed asserting: CNAME chain with a
   short-TTL intermediate hop and a long-TTL terminal record, terminal
   record's servable wire TTL is capped to the chain minimum even when
   looked up — this specific interaction (previously undocumented,
   discovered mid-audit) should have its own test, not just be implied by
   the existing capping tests (which only exercise a single-record-entry
   case, not a multi-hop chain).

6. **Clock DI wiring (interview Q6, resolves Open Question 2).** Thread
   the same `Arc<dyn Clock>` already constructed once at startup
   (`SystemClock`, `main.rs:740-746`) into the UDP/TCP listener/handler
   structs in `src/delivery/dns.rs`, replacing the two raw
   `SystemTime::now()` call sites (confirmed still at lines 262 and 620)
   that currently feed `ResolveRequest::new_with_observed_source`'s
   `received_at`. Exact struct/constructor signature changes are a
   plan-writing-time decision — verify during planning how
   `handle_datagram`/the TCP accept-loop currently receive their other
   injected dependencies (e.g. however the resolver itself already gets
   its `Clock`) and mirror that pattern, per this repo's
   `src/resolver/AGENTS.md:19` DI convention.

7. **Clock-injection e2e test placement → new file under `tests/`
   (interview Q7).** Follow `tests/forwarding.rs`'s `FixedClock` precedent
   (a true black-box test through the public `Clock` trait) rather than
   extending the in-module `mod.rs` e2e tests. Drives a real request
   through live transport → `ReceivedAt` → cache store/read with an
   injected fake `Clock`, confirming the whole pipeline is
   clock-injectable end-to-end (not just hand-constructed `now`/`stored_at`
   values in existing unit tests).

## Verified-current line references (use these, not `plan.md`'s, when
## writing the implementation plan / sections — see `claude-research.md`
## §1 for the full drift table)

- `Clock` trait: `mod.rs:7758-7760` (not 7669-7671)
- Raw `SystemTime::now()` in `evaluate_authority_response`:
  `mod.rs:7244,7266` (not 7155,7177 — those lines are unrelated code now)
- `store_cache_response`: `mod.rs:5095-5119` (not 5006-5020)
- `apply_ttl_bounds`: `mod.rs:2115-2121` (not 2105-2111)
- `decompose_response_for_store`: `mod.rs:818-930` (not 818-919)
- `resolve_ages_cached_response_ttls_for_current_request_time` /
  `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime`:
  `mod.rs:16287-16365` (not ~16042-16121)
- `FixedClock` (mod.rs): `mod.rs:7999-8005` (not 7910)
- `filter_response_for_requester`: definition `mod.rs:1480-1507`, call site
  `mod.rs:4940` (not ~4462)
- All other file:line references in `plan.md`'s Current State section
  (items 1, 3, 5, 6, 7, and most of 8) are confirmed unchanged — see
  `claude-research.md` for the full verification list.

## Everything else from `plan.md` stands as written

Context, Source, RFC conformance basis, Current State (behavioral claims —
all confirmed correct), Goals, Non-goals, and Risks sections from `plan.md`
are unchanged and should be treated as ground truth for plan-writing,
**except** where the Resolved Decisions above explicitly supersede an Open
Question. In particular:
- Goal 1's three lettered options are now resolved to (b), Cookie-only.
- Goal 3's Clock-DI approach is now resolved per decision 6 above.
- Goal 5's edge-case matrix items are now resolved per decisions 4-5 above.
- Goal 6's test placement is now resolved per decision 7 above.
- Non-goals are unchanged (still out of scope: real DNSSEC validation,
  `CacheTtlPolicy` defaults/new config knobs, delegation cache redesign,
  general clock-injection audit beyond the `received_at`/TTL-aging path).
