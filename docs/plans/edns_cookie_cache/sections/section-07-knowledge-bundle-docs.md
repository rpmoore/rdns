# Section 07: Knowledge-bundle documentation update

## Implementation notes (as built)

Implemented as planned: doc-only change to
`docs/knowledge/resolver/caching/answer-cache.md`, replacing the
forward-reference stub with a new "EDNS Cookie interaction: per-request
OPT, never cached" section (between "Wire-TTL aging on read" and
"Concurrency model, in one sentence"), covering cache-admission narrowing,
cache-key independence from cookie bytes, the OPT-never-cached invariant
across both the cache-hit and cache-miss/recursive rebuild paths, and the
security trade-off (echo/interop only, no validation/BADCOOKIE/rotation).

Code review caught one factual error before commit: the initial draft
claimed both the cache-hit and cache-miss paths write their COOKIE option
to the wire via `build_opt_record_with_options`, and that `build_opt_record`
funnels through it. Neither is true — the cache-hit path
(`requester_opt_record`) mutates a plain OPT's `EdnsInfo.options` in place;
only the cache-miss path (`message_edns_opt_record_with_cookie`) calls
`build_opt_record_with_options`; and both `build_opt_record` and
`build_opt_record_with_options` independently delegate to the same private
`build_opt_record_with_extended_rcode`, not one calling the other. Fixed
and re-verified line-by-line against current source.

No new concept doc was added for `src/protocol/edns_cookie.rs` — per the
plan's own judgment call, it's a small, self-contained module with no
independent invariant (concurrency, invalidation, secret rotation) not
already covered by the `answer-cache.md` update; review confirmed no such
invariant exists.

Verification: doc-only change, no `cargo` gates apply. Every `file:line`
reference and behavioral claim re-checked against the landed sections
02-06 code as merged (not against this plan's predictions).

## Dependencies

This section depends on **section-03-cache-supported-narrowing**,
**section-04-query-features-opt-threading**, **section-05-cache-miss-opt-path**,
and **section-06-opt-record-serialization** having landed — it documents the
actual, final behavior of all four, not the as-planned behavior. Do not start
this section until those four are merged/complete; the doc must describe what
the code actually does, confirmed by re-reading the landed diffs, not what the
plan predicted it would do. This section blocks **section-08-security-review**
(the mandatory `/security-review` pass runs against the complete diff,
including this doc update).

## Task

This is a **doc-only change** — no new tests, no source-code edits. Update
`/home/rpmoore/code/rdns/docs/knowledge/resolver/caching/answer-cache.md` (an
existing OKF-conformant concept doc, already touched by the earlier
`ttl_remaining` plan's section-01) to document:

1. The new Cookie cache-compatibility behavior (EDNS COOKIE option no longer
   unconditionally bypasses the cache).
2. The OPT-record-never-cached invariant (the OPT pseudo-record, including any
   COOKIE option, is always rebuilt fresh per request — cache hit or miss —
   never stored or replayed from the cache).
3. The explicit security trade-off: this implementation gains **none** of DNS
   Cookies' anti-off-path-spoofing value. There is no incoming-cookie
   validation, no BADCOOKIE (RCODE 23) generation, and no rejection behavior
   tied to cookie correctness. This must be written down clearly enough that
   a future reader doesn't mistake "the resolver echoes cookies" for "the
   resolver enforces anti-spoofing."

Per `AGENTS.md`'s Knowledge Bundle change-workflow trigger: "After a nontrivial
code change, before reporting the task done: check whether any concept doc
under `docs/knowledge/` describes the code just touched, and bring it up to
date in the same change... If a concept doc exists for that area and the
change made it stale... update it." This doc already exists and is already
stale by design — it contains a forward-reference stub written in anticipation
of exactly this change (see below). This section's job is to resolve that
stub into real, landed-behavior documentation.

### Where the existing doc is already stale

The file currently (as of the `ttl_remaining` work) ends its "Wire-TTL aging
on read" section with this forward-reference paragraph, which this section
must replace/resolve:

```markdown
This doc will need a follow-up edit once a separate, later PR (Part E of
`docs/plans/ttl_remaining/claude-plan.md`, the EDNS-Cookie cache
allowlist) lands, noting that EDNS-Cookie-bearing queries become
cache-compatible at that point. Today they bypass the cache entirely —
see `cache_supported`, `src/resolver/mod.rs:5508-5520`.
```

That paragraph currently sits at the end of the "Wire-TTL aging on read"
section (lines ~122-126 in the doc as it exists today), just before the
"Concurrency model" section. Replace it with real content describing the
landed Cookie behavior — do not just delete it and leave nothing, since the
Cookie/cache interaction is exactly the kind of invariant this doc exists to
record (RFC-shaped protocol behavior intersecting with cache admission).

## Background: what actually changed (to document accurately)

Read the following for the ground truth of what to document — don't
reconstruct this from memory, confirm against the landed code:

- **`cache_supported()` narrowing** (section-03): `src/resolver/mod.rs` around
  line 5508-5520. The condition changed from requiring `edns.options.is_empty()`
  to requiring `edns.options.is_empty()` **or**
  `is_solely_cookie_option(&edns.options)` returns `Some(_)`. All other
  admission conditions (extended RCODE 0, EDNS version 0, no flags beyond DO)
  are unchanged. A query with a well-formed COOKIE option *and* any other EDNS
  option (e.g. NSID) still bypasses the cache — `is_solely_cookie_option`
  requires the *entire* options blob to be exactly one COOKIE option.

- **New module** `src/protocol/edns_cookie.rs` (section-02, already landed as
  a dependency of this section but not this section's own subject): defines
  `CookieSecret`, `ClientCookie`, `parse_cookie_option` (lenient extraction —
  used for echoing a cookie on the response even when the query isn't
  cache-admissible), `is_solely_cookie_option` (the strict cache-admission
  predicate), `build_server_cookie` (RFC 9018 server-cookie construction),
  and `build_cookie_option` (TLV serialization).

- **Cache-hit OPT rebuild** (section-04): `requester_opt_record`
  (`src/resolver/cache/assemble.rs`, originally around line 437-447) now
  builds a COOKIE option into the OPT record it constructs, whenever the
  requester's query carried a client cookie — using a `CookieSecret`, the
  requester's client IP, and the injected `Clock` (never `SystemTime::now()`
  directly). This never reads from or writes into the cached entry itself —
  the cached `RRsetEntry`/`NegativeEntry` data is completely unaffected by
  cookies; only the per-request OPT pseudo-record differs.

- **Cache-miss/recursive OPT rebuild** (section-05):
  `mirrored_client_opt_record`/`message_edns_opt_record` (or a shared helper
  factored out with `requester_opt_record` — confirm which shape landed)
  gained the same treatment for the backend-forwarded/cache-miss path, so a
  fresh server cookie is attached on **every** response, not just cache hits.
  Two coalesced requesters sharing one in-flight backend query, presenting
  different client cookies, each get their own distinct COOKIE option.

- **Wire serialization** (section-06): the OPT-record wire encoder
  (`build_opt_record`/`build_opt_record_with_extended_rcode`,
  `src/protocol/mod.rs`, originally around line 1246-1278) now serializes a
  non-empty `options` byte vector into the OPT RDATA — previously this always
  hardcoded an empty options list on the write side.

- **No cache-key/`MissKey` dependency on cookie bytes**: section-03 added a
  test pinning that two Cookie-bearing queries for the same qname with
  *different* client cookies produce the identical cache lookup/key — cookie
  bytes never participate in cache identity. This is the invariant that makes
  "the OPT record is per-request, the cached answer is shared" safe to state
  as a hard guarantee, not just an implementation detail that happens to be
  true today.

## Content to write into `answer-cache.md`

Add a new section (or fold into the existing "Wire-TTL aging on read" section
if it reads more naturally as a continuation — implementer's call on exact
placement, but it should sit near the wire-serialization content since it's
another example of "per-request-assembled, never cached" behavior). The new
content must cover, in the doc's existing prose/file:line-grounded style:

1. **What changed**: EDNS COOKIE-bearing queries (RFC 7873, option code 10)
   are now cache-compatible, provided the COOKIE option is the *only* EDNS
   option present (any other option alongside a well-formed Cookie, e.g. NSID,
   still bypasses the cache exactly as before). Ground this in
   `cache_supported`'s actual post-change line range and `is_solely_cookie_option`'s
   location in `src/protocol/edns_cookie.rs`.

2. **The OPT-record-never-cached invariant**: explicitly state that the OPT
   pseudo-record — including any COOKIE option in it — is never part of what
   gets stored in or read from `RRsetEntry`/`NegativeEntry`. It is always
   rebuilt per request, on both the cache-hit path (`requester_opt_record`)
   and the cache-miss/recursive path (`mirrored_client_opt_record`/
   `message_edns_opt_record`), using a freshly-computed RFC 9018 server
   cookie each time. Two requesters hitting the same cached answer with
   different client cookies get different, correctly-computed COOKIE options
   in their respective responses — the *answer data* is shared, the OPT
   record never is. This mirrors and extends the existing "no per-entry data
   is keyed by the requester's own casing/bufsize/flags" statement already in
   this doc (see the "What's stored per entry" section) — cookies are just
   another instance of that same "request-specific details are applied at
   serve time" pattern, not an exception to it.

3. **The explicit security trade-off** (this is the most important part to
   get right — do not soften or omit it): this resolver never validates an
   incoming server cookie's hash or timestamp window, never generates
   BADCOOKIE (RCODE 23), and never rejects a query for cookie-related reasons
   — it always processes the query normally and always attaches a freshly
   computed, valid server cookie in response, unconditionally. This is one of
   RFC 7873's own explicitly compliant behaviors (§5.2.3/§5.2.4 branch 3:
   "process the request and provide a normal response"), not a bug or a
   corner cut — but it means this resolver gains **no** anti-off-path-spoofing
   protection from implementing DNS Cookies. That protection comes from the
   rejection/validation path this implementation deliberately does not build
   (see `docs/plans/edns_cookie_cache/claude-plan.md`'s Non-goals section for
   the full list: no BADCOOKIE, no incoming-cookie validation, no secret
   rotation). State this plainly enough that a future reader skimming this
   doc for "does rdns have DNS Cookie protection" gets an unambiguous "no,
   only echo/interop, not validation" answer.

4. Keep the doc's existing conventions: `file:line` grounding for every
   concrete claim, cross-references to sibling docs where relevant (e.g. this
   could reference back to itself for the wire-TTL-aging pattern, since both
   are examples of "per-request assembly, nothing cached beyond the answer
   data"), and match the terse, declarative prose style already used
   throughout the file (see the existing "Wire-TTL aging on read" and
   "Concurrency model, in one sentence" sections for tone/density reference).

## Whether any other knowledge doc needs a new entry

The plan (`claude-plan.md` Goal 6 and section-breakdown item 7) scopes this
change to a single file: `answer-cache.md`. Before finishing, use judgment per
`AGENTS.md`'s general Knowledge Bundle guidance ("If no concept doc exists yet
for that section of code, add one... a small helper doesn't need its own
concept doc; a subsystem with real invariants... does") on whether the new
`src/protocol/edns_cookie.rs` module warrants its own concept doc. Given it's
a small, self-contained parsing/construction module with no independent
concurrency or invalidation invariants of its own (its only externally-visible
behavioral consequence — cache admission and OPT-record content — is exactly
what `answer-cache.md`'s new section documents), a separate doc is likely
unnecessary; the existing `docs/knowledge/rdns-overview.md` protocol-layer
paragraph already describes EDNS handling at the appropriate level of
generality and does not need a Cookie-specific mention. Do not create a new
doc unless review of the landed code surfaces an invariant (e.g. secret
lifecycle/rotation semantics) that isn't naturally covered by the
`answer-cache.md` update.

## Verification

- No `cargo test`/`cargo fmt`/`cargo clippy` gate applies — this is a
  markdown-only change.
- Before considering this section done, re-read the final `answer-cache.md`
  content against the actual landed diffs of sections 03-06 (not against this
  plan's predictions) and confirm every file:line reference and every
  behavioral claim (cache admission condition, OPT-rebuild call sites,
  cache-key independence from cookie bytes, the no-validation/no-BADCOOKIE
  trade-off) is accurate as merged.
- This section's completion is itself a prerequisite input to
  **section-08-security-review**'s diff review — the security reviewer should
  be able to read this doc alone and get an accurate picture of the Cookie
  feature's security posture without re-deriving it from the code.