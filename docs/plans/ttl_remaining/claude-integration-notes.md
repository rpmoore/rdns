# Integration notes: Codex review feedback

Review performed via `codex:codex-rescue` agent (Codex CLI, direct code
read against current tree) since `/codex:review` cannot be invoked
programmatically (Skill tool blocks model-invocation for it). Full findings
preserved in conversation; this file records what changed in
`claude-plan.md` and why, and what was deliberately not changed.

## Integrated

1. **Part B: concrete call-site list added.** Codex enumerated every test/
   support constructor that calls `UdpDnsServer`/`TcpDnsServer` constructors
   and would fail to compile once a `clock` parameter is added — the
   original plan only said "grep for call sites during implementation."
   Added the full list (tests/forwarding.rs, tests/support/mod.rs, and
   ~10 in-module test call sites in `src/delivery/dns.rs`) directly to
   Part B so the TDD implementer isn't discovering compile failures
   instead of working from a complete plan.

2. **Part E: corrected the OPT-reattachment site.** The plan's claim that
   `filter_response_for_requester` (mod.rs:1480-1507) is "the" place to
   attach a fresh Cookie option was wrong — that function explicitly
   doesn't touch the OPT record; Codex traced the actual reattachment to
   mod.rs:4939, lines 4960-4963. Corrected in the plan, and expanded to
   list every other response-construction path that currently builds an
   optionless OPT record and would need Cookie-aware treatment if Cookie
   echo is genuinely required on every response (cache-hit assembly,
   cache-hit truncation, recursive-miss no-filter rebuild, truncated
   responses, local/refusal/SERVFAIL responses). The original plan
   understated this to a single seam; it's actually ~6 call sites.

3. **Part E: corrected the EDNS-options data shape.** `EdnsInfo.options`
   is currently a raw `Vec<u8>` (src/protocol/mod.rs:208), not a typed
   `Vec<EdnsOption>` — the plan's sketched
   `is_cache_compatible_edns_options(options: &[EdnsOption])` helper
   assumed a representation that doesn't exist yet. Added a note that
   Part E's real first step is deciding whether to add a typed EDNS-option
   parser/representation or work directly against the raw byte encoding.

4. **Part E: malformed-Cookie-length handling flagged as a real RFC gap,
   not just a cache-admission detail.** The protocol parser currently only
   validates EDNS option framing (code/length/value), not Cookie-specific
   length legality (src/protocol/mod.rs:2643) — so today a malformed
   Cookie doesn't get FORMERR per RFC 7873, it just isn't validated at
   all. The original plan treated this as "don't make it cache-compatible,
   verify upstream handles it" — Codex correctly points out upstream
   doesn't handle it. Added as an explicit open item for Part E's
   follow-up planning (see "Deferred" below) rather than silently
   resolving it here, since it changes protocol-layer behavior beyond the
   cache-admission question this spec was originally scoped to.

5. **Part E: added "known gaps requiring resolution" list** covering
   Codex's remaining findings that are real and substantive but require
   product/security decisions this planning session doesn't have standing
   to make unilaterally: server-secret configurability for anycast (RFC
   9018 says it MUST be configurable — the interview's "random, in-memory,
   not configurable" answer was scoped to a single-instance deployment,
   which should now be stated as an explicit constraint, not just a
   footnote), SipHash-2-4 implementation/crate choice, timestamp source
   for the RFC 9018 cookie format (should reuse `ResolveQuery.clock`, not
   introduce a third raw-clock call site), whether incoming server-cookie
   validation actually gates any behavior (if it doesn't, drop the
   "cryptographic comparison" language; if it does, comparison must be
   constant-time), and multiple-COOKIE-option handling (RFC 7873 says
   consider only the first).

## Deferred (not integrated as line-edits — recommend a follow-up planning
## pass instead)

Codex's review makes clear that Part E (the Cookie cache-allowlist) is
substantially larger in scope than "narrow one predicate in
`cache_supported()`" — it touches EDNS-option representation across the
protocol layer, at least six independent response-construction call sites,
and several RFC-compliance decisions (secret rotation/config, malformed-
length FORMERR behavior, multi-cookie handling) that weren't visible until
Codex traced the actual response-building code paths.

Rather than trying to fully re-spec Part E inline here — which would turn
this document from "plan for the whole audit effort" into "a second,
much larger spec for just the Cookie feature" — Part E is left in this
plan as a **scoping document for a dedicated follow-up `/deep-plan` session**
once PR 1 (Parts A-C) lands. This is consistent with the interview's own
PR-sequencing decision (split, Cookie ships separately and later) and
avoids under-speccing a security-sensitive feature under time pressure.
The plan has been updated to say this explicitly rather than implying
Part E as written is implementation-ready.

**Not integrated at all** (noted, not acted on): Codex's DoS-amplification
observation (no BADCOOKIE path means no anti-spoofing/amplification
mitigation value from cookies) is a restatement of a decision already made
explicitly in the interview (Q5: process normally, no BADCOOKIE path,
chosen deliberately for simplicity). Added one line to Part E acknowledging
this as a stated tradeoff rather than an oversight, but did not reopen the
interview decision.
