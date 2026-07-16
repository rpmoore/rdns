# Spec: TTL-remaining-time behavior audit, EDNS-cookie cache-bypass finding, and Clock dependency-injection fix

## Context

Cloudflare (1.1.1.1) and systemd-resolved report a cached DNS record's
TTL as time remaining until expiry, not the raw TTL set by the
authoritative server. RFC 1035 §3.2.1 defines TTL as "a 32 bit unsigned
integer that specifies the time interval that the resource record may be
cached before the source of the information should again be consulted" —
an intermediate resolver replaying the raw origin TTL on every cache hit
would misrepresent freshness to downstream clients/resolvers, since a
client cannot otherwise tell how long an answer has already sat in the
resolver's cache upstream of it.

**This behavior is already implemented and tested in `rdns`** —
`compute_wire_ttl` in `src/resolver/cache/assemble.rs:188-204`. This spec
is therefore an *audit-and-harden* document, not a "build remaining-TTL
support" document. It covers, per explicit scope decision (full audit,
not the narrower doc+Clock-fix-only alternative):

0. **A live-deployment finding that explains why this correct behavior is
   invisible in real traffic**, discovered mid-audit by reproducing the
   symptom directly against a running v0.1.6 instance (see Current State
   point 9): `cache_supported()` (`src/resolver/mod.rs:5508-5520`)
   disqualifies any query carrying an EDNS option — including the DNS
   Cookie option (RFC 7873) that modern `dig`/stub resolvers attach by
   default — from the cache entirely. This is tested-as-currently-coded
   behavior (`resolve_bypasses_cache_for_unsupported_edns_options`,
   `mod.rs:18930-18954`, exercises an EDNS option with code 10 — RFC 7873's
   Cookie option code — but doesn't establish that excluding Cookie
   specifically was an intentional design call, only that the bypass
   fires for it), not a regression, but its real-world reach (confirmed
   for `dig`'s default query on the one deployment tested; plausibly
   broader given Cookie-by-default is common in modern clients, but that
   extrapolation isn't independently verified) was previously
   unquantified. This is now the primary,
   highest-priority finding in this spec.
1. Documenting the already-correct baseline behavior (currently absent
   from the knowledge bundle).
2. A Clock dependency-injection gap found during the audit.
3. A full consistency/edge-case audit across every response-assembly
   path (positive, negative/SOA, DNSSEC proof material, CNAME chains),
   plus confirming TCP vs UDP share one path and delegation cache is
   correctly out of scope (not a response-assembly path at all).

Naming note: `docs/plans/` has no prior `plan.md` precedent (two flat
docs, `cache_key.md` and `dns_gaps.md`, live directly under `docs/plans/`;
the one subdirectory precedent, `cache_rework/`, uses `spec.md`/
`claude-spec.md`). `ttl_remaining/plan.md` is a reasonable new
convention, not a deviation needing correction.

## Source

- `docs/knowledge/resolver/caching/answer-cache.md` — current
  knowledge-bundle doc for this cache. Documents `stored_at`/`expires_at`
  as "TTL bookkeeping" (line 44) but never mentions `compute_wire_ttl` or
  remaining-TTL-on-read at all. **Must be updated** as part of this
  effort (see Goals).
- `docs/caching.md` — **stale, do not trust its content or line
  citations.** It describes a `CachedResponse { response_template: Vec<u8>,
  ... }` type and a `serialize_cached_response` function that no longer
  exist anywhere in `src/` (verified by grep — zero real hits; the two
  remaining mentions of `serialize_cached_response` in
  `src/resolver/mod.rs:12659,12720` are comments/test-name references to
  the old name, not a live function). Git-log timestamps confirm
  `docs/caching.md` predates the `cache_rework` effort that introduced
  `RRsetEntry`/`ShardedDnsCache`/`assemble_response`/`compute_wire_ttl`,
  and was never updated afterward. It is still referenced extensively
  from `docs/plans/cache_rework/*` — those are historical planning docs
  describing pre-rework state at the time, so those references are fine
  as history; just don't treat `docs/caching.md` as current-behavior
  ground truth here.
- `docs/plans/cache_rework/spec.md` and
  `docs/plans/cache_rework/sections/section-06-assembly-and-chains.md` —
  design rationale for why `compute_wire_ttl` is applied per-record in
  `assemble.rs` rather than as a single scalar age over an assembled
  buffer (see doc comment at `assemble.rs:181-187`: a CNAME chain
  combines records from multiple `RRsetEntry`s with different
  `stored_at` values, which one scalar age can't represent).
- `src/resolver/AGENTS.md:19,24` — this repo's clock-injection/testability
  convention, which the Clock-DI fix (Goal 2) must satisfy.
- `AGENTS.md` (root) — Knowledge Bundle process (`docs/knowledge/` is
  current behavior; `docs/plans/` is point-in-time design history).

## RFC conformance basis

- **RFC 1035 §3.2.1** — TTL definition ("time interval that the resource
  record may be cached before the source of the information should again
  be consulted"). Ground truth for why remaining-time semantics is the
  conformant behavior for an intermediate resolver.
- **RFC 2308 §3, §5** — negative-caching TTL derivation
  (`min(SOA TTL, SOA MINIMUM)`); already the norm here
  (`negative_ttl`, cited in-repo at `src/resolver/mod.rs` as
  "RFC 2308 §5"). Cited to ground the negative-cache aging discussion in
  Current State below.
- **RFC 6840 §3.1** ("BAD cache" concept) — mirrored by this codebase's
  `DnssecState` enum (`entry.rs:94-112`); relevant only as context for
  why DNSSEC state tracking exists alongside TTL aging, not as a TTL
  requirement itself.
- **RFC 6891 §6.2.3** (EDNS payload/truncation) — boundary note only:
  truncation is a separate, transport-aware decision in
  `assemble_response`'s own parameters, orthogonal to TTL aging (see
  Current State point 2 below) — cited to preempt conflating "TCP-specific
  path" concerns with TTL-aging concerns.
- **RFC 7873** (DNS Cookies) — directly relevant to the live-deployment
  finding (Current State point 9): the EDNS Cookie option this RFC
  defines is what triggers `cache_supported()`'s bypass on essentially
  every modern default-configured client. §5.1 defines the client-cookie
  round-trip contract this codebase's current all-options-bypass
  approach avoids having to implement per-cache-entry.

## Current state (baseline) — already implemented, verified by direct read

1. **Storage shape.** `RRsetEntry` (`src/resolver/cache/entry.rs:43-80`)
   holds `Vec<StoredRecord>` (`records`) and `Vec<StoredRecord>`
   (`rrsigs`), each `StoredRecord` (`entry.rs:87-92`) carrying its own raw
   **origin** `ttl_at_store: u32`, plus entry-level `stored_at: SystemTime`
   and `expires_at: SystemTime` (`entry.rs:49-50`) representing the
   **policy-bounded** cache lifetime. `NegativeEntry`
   (`entry.rs:139-196`) mirrors this: `soa_record: StoredRecord` (own
   `ttl_at_store`), optional `soa_rrsig`, `proof_records: Vec<(String,
   StoredRecord)>` (NSEC/NSEC3 + their RRSIGs, each with its own owner
   name and `ttl_at_store`), plus entry-level `stored_at`/`expires_at`
   (`entry.rs:171-172`).

2. **Store-time TTL computation** (separate concern from remaining-TTL
   serving — this determines `expires_at`, not what gets aged).
   `CacheTtlPolicy::ttl_for_response` (`src/resolver/mod.rs:602-704`)
   computes one policy-bounded TTL per store operation via
   `apply_ttl_bounds` (`mod.rs:2105-2111`: `ttl.min(max_ttl)`, then if
   `min_ttl` set, `.max(min_ttl).min(max_ttl)` — the trailing
   `.min(max_ttl)` means a misconfigured `min_positive_ttl >
   max_positive_ttl` safely resolves to `max_ttl`, never inverts; this is
   already-correct, no action needed). `expires_at = stored_at +
   policy_bounded_ttl`. **Chain-wide ceiling**: `decompose_response_for_store`
   (`mod.rs:818-919`) computes this ttl *once* per store operation (as
   `min` across every record in the response) and applies the *same*
   `expires_at` ceiling to every hop of a CNAME chain, including the
   terminal RRset — so a CNAME with 60s origin TTL and a terminal record
   with 3600s origin TTL both get `expires_at` capped to ~60s from that
   store. Each record's own `ttl_at_store` still independently preserves
   its raw origin TTL (the terminal record still stores `3600`), so
   `compute_wire_ttl`'s `aged` term is per-record-correct, but its
   `remaining` term (from the shared `expires_at`) silently caps the
   terminal record's servable life to the chain minimum — even if a later,
   unrelated query looks up that terminal name directly. This has never
   been documented anywhere; treat as an edge case requiring an explicit
   design decision (see Open Questions), not as a bug to silently fix.

3. **Serve-time aging** — the core remaining-TTL mechanism.
   `compute_wire_ttl` (`assemble.rs:188-204`):
   ```rust
   fn compute_wire_ttl(ttl_at_store: u32, stored_at: SystemTime, expires_at: SystemTime, now: SystemTime) -> u32 {
       let elapsed_secs = now.duration_since(stored_at).unwrap_or(Duration::ZERO).as_secs();
       let aged = ttl_at_store.saturating_sub(elapsed_secs.min(u64::from(u32::MAX)) as u32);
       let remaining_secs = expires_at.duration_since(now).unwrap_or(Duration::ZERO).as_secs();
       aged.min(remaining_secs.min(u64::from(u32::MAX)) as u32)
   }
   ```
   Called per-record (answer + each RRSIG independently) from
   `write_rrset` (`assemble.rs:229-263`) and `write_negative_authority`
   (`assemble.rs:265-324`, covering the SOA record, `soa_rrsig`, and each
   `proof_records` entry independently). `assemble_response` and
   `assemble_negative_response` (`assemble.rs:546`, `:615`) are the only
   two functions feeding client responses, called from
   `serialize_cache_hit_answer`/`serialize_cache_hit_negative`
   (`src/resolver/mod.rs:4461`, `:4479`) for both transports (UDP and
   TCP) — the only
   transport-conditioned parameter is a truncation-eligibility bool
   (`!request.observed_source.is_tcp()`), not a different aging path.
   **Conclusion: there is exactly one wire-TTL-aging code path, shared by
   every cache-hit response, both transports — already fully unified, not
   an open question.**

4. **Read-time expiry.** `resolve_from_cache`/`Shard::lookup_hop`
   (`assemble.rs:118-179`, `src/resolver/cache/shard.rs:405-463`) deletes
   (not just filters) any entry already past `expires_at` at lookup time.

5. **Negative-cache DNSSEC proof material — two intentionally distinct
   aging computations over the same fields, not an inconsistency:**
   - *Wire-TTL aging*: `write_negative_authority` calls
     `compute_wire_ttl(_, negative.stored_at, negative.expires_at, now)`
     independently per record (SOA, `soa_rrsig`, each proof record) —
     structurally identical to the positive-side treatment.
   - *Servability gating* (different question, different computation):
     `NegativeEntry::dnssec_proof_material_fresh` (`entry.rs:224-238`)
     is used only at `Shard::lookup_hop` time to decide whether a DO=1
     reader may be served this entry **at all**. It deliberately ignores
     `expires_at` and ages each record's own `ttl_at_store` directly from
     `stored_at`, because (per its doc comment, `entry.rs:203-208`)
     `expires_at` reflects only the negative TTL (RFC 2308) and "says
     nothing about how long the SOA's RRSIG or any NSEC/NSEC3 proof
     record individually remains valid." Present both mechanisms in any
     downstream documentation; do not conflate them as redundant.

6. **Delegation/referral cache — confirmed out of scope for wire-TTL
   aging, not an open question.** `DelegationCache`/`DelegationEntry`
   (`src/resolver/mod.rs:6738-6870`) stores nameserver `SocketAddr`s for
   the resolver's own iterative routing plus a single `expires_at:
   Instant` (monotonic clock, not `SystemTime`) — it holds no DNS
   records and is never serialized to a client. `compute_wire_ttl` does
   not apply here by construction. (`delegation_cache_does_not_store_zero_ttl_entries`
   and `delegation_cache_caps_excessive_referral_ttl`,
   `mod.rs:19242,19322`, test this cache's own TTL-bounding policy, which
   is a separate concern from wire-TTL aging.)

7. **Wire encoding.** `write_record` (`src/protocol/mod.rs:1267-1286`)
   takes an already-computed `ttl: u32` and writes it — no cache/time
   awareness at the protocol layer; every aging decision happens upstream
   in `assemble.rs`. Nothing to audit here.

8. **Existing test inventory** (what's already guarded vs. not):
   - E2E: `resolve_ages_cached_response_ttls_for_current_request_time`,
     `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime`
     (`src/resolver/mod.rs:16042-16121`) — assert a 60s-TTL record served
     25s later returns TTL 35, and an oversized 3600s-TTL record capped
     by a 60s entry lifetime also returns TTL 35.
   - Unit: `assemble_response_ages_each_record_ttl_independently`,
     `assemble_response_caps_ttl_to_remaining_entry_lifetime`
     (`assemble.rs:754-793`); `stored_record_preserves_original_ttl_independent_of_entry_minimum_ttl`
     (`entry.rs:305-313`); DNSSEC proof-material freshness tests
     (`entry.rs:523-594`).
   - **Not covered** (see edge-case matrix below): zero/near-zero origin
     TTL combined with a `min_positive_ttl` floor; the chain-wide-ceiling
     vs. terminal-origin-TTL interaction (point 2 above); a live
     request-path test that drives an injected `Clock` end-to-end rather
     than hand-constructed `now`/`stored_at` values.

9. **Live-deployment finding: `cache_supported()`'s EDNS-options check
   makes remaining-TTL aging unreachable for EDNS-Cookie-bearing
   clients.** `cache_supported` (`mod.rs:5508-5520`) returns `false` —
   bypassing the cache entirely, no lookup, no store — whenever a query
   carries EDNS with a non-zero extended RCODE/version, any flag other
   than DO, or **any non-empty `edns.options`**. `probe_cache`
   (`mod.rs:4409-4424`) short-circuits on this: `CacheBypass` +
   `CacheMiss` metrics increment, and the request always goes straight to
   the backend.

   Reproduced directly against a live v0.1.6 deployment (one
   deployment/client pair — a real-world observation, not derived purely
   from source reading):
   ```
   $ dig +qr facebook.com @<host>          # dig's default query
   ; COOKIE: 7b90e5a8f4932cfb              # EDNS Cookie option (RFC 7873), sent by default
   ...
   facebook.com. 60 IN A ...               # TTL 60, unchanged across repeated queries <60s apart

   $ dig +noedns facebook.com @<host>      # no EDNS at all -> cache_supported() == true
   facebook.com. 60 IN A ...
   facebook.com. 54 IN A ...   (5s later)
   facebook.com. 49 IN A ...   (5s later)  -- ages correctly once the bypass is avoided
   ```
   This is consistent with `compute_wire_ttl` (point 3 above) being
   correct and the `cache_supported` bypass being the cause of the
   non-aging TTL observed in this deployment. `dig` on Ubuntu 24.04
   (DiG 9.18.39) attaches an EDNS Cookie by default. Whether this
   generalizes broadly (cookie-by-default is common among modern
   BIND-derived clients) is a plausible inference from this one
   observation, not an independently confirmed measurement across
   clients — the spec should state the confirmed fact (this deployment,
   this client, this bypass) separately from the extrapolation.

   This is tested-as-currently-coded behavior — not a regression
   introduced by the cache rework — per
   `resolve_bypasses_cache_for_unsupported_edns_options`
   (`mod.rs:18930-18954`): sends a query with an EDNS option whose type
   code is 10 (RFC 7873's Cookie option code, though the test's payload,
   `[0u8, 10, 0, 2, 0xaa, 0xbb]`, is a 2-byte value shorter than a real
   client cookie's minimum 8 bytes — it exercises the *option-code-10
   bypass path*, not full Cookie-semantics validation) and asserts zero
   cache lookups, zero stores, one `CacheBypass`. This confirms the
   bypass fires for a Cookie-shaped option; it does not by itself
   establish that excluding Cookie traffic specifically was a deliberate,
   documented design decision — only that it's the current, intentional
   (as coded) behavior of the "any EDNS option bypasses" rule. A sibling
   test, `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
   (`mod.rs:18956+`), covers the non-zero-version/non-DO-flag cases of
   the same gate. Whatever the original rationale (plausibly: avoiding
   having to model per-client Cookie-echo semantics against a shared
   cache entry — RFC 7873 §5.1 requires echoing the requester's own
   client cookie plus a server-computed cookie, which a naively shared
   cached response can't safely replay for a different requester's
   cookie), it was never documented as an operational tradeoff anywhere,
   and its real-world reach beyond this one observation was not
   previously measured. See Goals and Open Questions.

## Goals

1. **(Primary)** Decide and act on the `cache_supported()` EDNS-options
   bypass (Current State point 9). Three options, laid out fully in Open
   Question 1 — (a) narrow the check to specifically allow the DNS
   Cookie option through, with correct per-requester cookie-echo; (b)
   allowlist cache-key-neutral options (Cookie, Padding) more generally
   by caching the answer data but regenerating/stripping the OPT record
   per request rather than sharing cached OPT bytes; (c) keep today's
   conservative all-options bypass but document it explicitly as an
   accepted tradeoff, with the observed real-world impact (confirmed for
   `dig`'s default query in this deployment; plausibly broader) recorded
   in `docs/knowledge/resolver/caching/answer-cache.md` so it's never
   mistaken for a bug again. This decision has security implications
   (RFC 7873 cookie validation is an anti-spoofing mechanism) and must
   not be made silently — see Open Questions and Risks.
2. Confirm and document, in the knowledge bundle, that cache-hit TTLs
   are remaining-time-to-expiry and RFC 1035 §3.2.1-conformant across
   every response-assembly path (positive, negative/SOA, DNSSEC proof
   material, CNAME chains) — stating plainly that delegation-cache is
   out of scope and TCP/UDP share one path (not open questions).
3. Route the `now`/`received_at` timestamp that drives TTL aging through
   the existing `Clock` trait/DI seam instead of raw `SystemTime::now()`
   at the transport edge, per `src/resolver/AGENTS.md:19`. Specifically:
   `trait Clock { fn now(&self) -> SystemTime; }` (`mod.rs:7669-7671`,
   prod impl `SystemClock` at `src/main.rs:739-741`) is today used only
   for query-duration metrics (`started_at`/`finished_at`,
   `mod.rs:3704,5087`) — not for the `ReceivedAt(SystemTime)`
   (`mod.rs:93`) value that seeds `now`/`stored_at` for all TTL aging,
   which instead comes from **raw** `SystemTime::now()` at exactly two
   call sites: `src/delivery/dns.rs:262` (UDP) and `:620` (TCP), both
   feeding `ResolveRequest::new_with_observed_source`. (Adjacent but
   out of scope: `src/delivery/upstream.rs:296,640` and
   `mod.rs:7155,7177` also call raw `SystemTime::now()` for their own
   `received_at` fields, but confirmed these do **not** feed
   `stored_at` — `store_cache_response` (`mod.rs:5006-5020`) always uses
   the *client request's* `received_at`, not a backend-answer timestamp.
   This means a cache entry's apparent age is understated by roughly the
   backend round-trip latency — pre-existing, minor, worth one line in
   the edge-case matrix, not part of the Clock-DI fix itself.)
4. Close documentation gaps: add `compute_wire_ttl` remaining-TTL-on-read
   coverage to `docs/knowledge/resolver/caching/answer-cache.md`; resolve
   `docs/caching.md`'s staleness (exact disposition — rewrite, retire, or
   merge — left to Open Questions below, not decided in this spec).
5. Enumerate and resolve, or explicitly hand off, this edge-case matrix:
   - Zero/near-zero origin TTL vs. `min_positive_ttl` floor: an origin
     record with TTL 0 and a configured 30s floor gets `expires_at` raised
     to `stored_at + 30s` (servable for 30s), but `compute_wire_ttl`'s
     `aged` term starts at 0 and can only shrink — wire TTL is pinned at
     0 for the whole 30s window regardless of the floor. Not covered by
     any existing test (existing tests cover large-TTL-capped-down, not
     near-zero-floored-up). Is "never claim more remaining TTL than the
     record's own origin TTL implies" the intended semantics (plausible,
     given `compute_wire_ttl`'s per-record-truth design intent), or should
     aging also respect the floor? **Decision needed downstream, not
     here.**
   - Chain-wide `expires_at` ceiling vs. per-hop origin TTL (Current
     State point 2) — same treatment: flag, don't resolve here.
   - Clock-skew / `saturating_sub` behavior — already handled safely
     (`saturating_sub` avoids underflow; `unwrap_or(Duration::ZERO)`
     handles `now < stored_at`/`now > expires_at` cases from clock
     adjustments) — document as already-correct, not a gap.
   - Backend-round-trip freshness overstatement (Goal 3's adjacent
     finding) — document as known, low-severity, pre-existing.
6. Identify missing test coverage: an integration/e2e test that drives a
   real request through the live transport → `ReceivedAt` → cache
   store/read path with an injected fake `Clock`, following this repo's
   existing `FixedClock` precedent (`mod.rs:7910`, `src/delivery/dns.rs:755`,
   `tests/forwarding.rs:30`), to confirm the whole pipeline is
   clock-injectable end to end — not just the cache-layer unit tests that
   construct `now`/`stored_at` by hand.

## Non-goals

- Real DNSSEC validation (orthogonal; `DnssecState` stays `Unvalidated`
  until that separate work happens).
- Changing `CacheTtlPolicy` defaults or adding new configuration knobs.
- Redesigning the delegation cache (confirmed out of scope, Current
  State point 6).
- A general clock-injection audit of the whole codebase — scoped to the
  `received_at`/TTL-aging path only, not e.g. `upstream.rs`'s or
  `main.rs`'s unrelated `SystemTime::now()` uses (transaction-ID seeding,
  root-hints staleness) unless the downstream plan decides otherwise.

## Open questions for `/deep-plan:deep-plan` to resolve

1. **(Primary)** Three options for `cache_supported()`'s EDNS-options
   bypass — none decided here, all handed to `/deep-plan:deep-plan`:
   - **(a) Narrow specifically for Cookie**: permit the EDNS Cookie
     option (RFC 7873) while keeping the cache. The response's cached
     *answer* data doesn't depend on the cookie, but each response's OPT
     record must still echo that specific requester's client cookie plus
     a correctly computed server cookie (RFC 7873 §5.1/§5.3) — needs a
     real design (is there an existing per-requester response-rewrite
     seam this can reuse, analogous to how `filter_response_for_requester`
     already trims DO-dependent content per requester at serve time from
     a shared cache entry, `mod.rs:4462` area?).
   - **(b) Broader allowlist**: treat any cache-key-neutral EDNS option
     (Cookie, Padding/RFC 7830) as compatible with caching by regenerating
     or stripping the OPT record per request at serve time — cache the
     answer, never the OPT bytes — rather than special-casing Cookie
     alone. More general, more implementation surface.
   - **(c) Keep the bypass, document it**: no behavior change; update
     `docs/knowledge/resolver/caching/answer-cache.md` to state plainly
     that EDNS-option-bearing queries get no caching today, so this isn't
     rediscovered as a mystery again.
   (a) and (b) are security-relevant (cookie validation is an
   anti-spoofing mechanism) — **do not implement either without a
   `/security-review` pass**, per this repo's `AGENTS.md` "PR touches
   auth/untrusted-input/network code" trigger.
2. Exact call-site/signature changes to thread `Arc<dyn Clock>` from
   wherever it's already available down to `handle_datagram`/the TCP
   handler in `src/delivery/dns.rs`, replacing the two raw
   `SystemTime::now()` calls (`dns.rs:262`, `:620`) — a wiring decision.
3. Whether `docs/caching.md`'s staleness gets fixed (rewritten to match
   current design), retired, or merged into the knowledge bundle as part
   of *this* effort, or spun out separately.
4. Whether the zero-TTL/`min_positive_ttl`-floor interaction (Goal 5)
   should change behavior, or is correct as-is and just needs a
   regression test asserting current behavior.
5. Whether the chain-wide `expires_at` ceiling (Current State point 2)
   needs a dedicated regression test and knowledge-bundle mention, given
   it was previously undocumented.
6. Test placement for the live-Clock-injection e2e case (Goal 6): new
   file under `tests/` (matching `tests/forwarding.rs`'s `FixedClock`
   precedent) vs. extending the existing in-module e2e tests in
   `src/resolver/mod.rs`.

## Risks / things to verify before landing

- **If Open Question 1 resolves toward narrowing `cache_supported()`**:
  this touches untrusted-input handling on the network-facing query path
  (EDNS option parsing feeds a caching decision) — mandatory
  `/security-review` per `AGENTS.md`, and must not regress
  `resolve_bypasses_cache_for_unsupported_edns_options` /
  `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`
  (`mod.rs:18930-18954`, `18956+`) for every *other* EDNS-options case —
  only Cookie specifically should change behavior, nothing else in that
  gate.
- Switching `received_at`'s source from raw `SystemTime::now()` to
  `Clock::now()` must not change production timing behavior —
  `SystemClock` wraps `SystemTime::now()` identically (`main.rs:739-741`),
  so this is a pure DI refactor, not a behavior change, but it touches
  every request's hot path and deserves an explicit before/after check.
- Any edge-case fix arising from Open Question 4 must not regress the
  two existing capping tests (`assemble_response_caps_ttl_to_remaining_entry_lifetime`,
  `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime`).
- `docs/caching.md` has many inbound references from
  `docs/plans/cache_rework/*` (verified via grep) — those are historical
  planning docs and should keep citing it as history; re-check before
  editing/retiring `docs/caching.md` itself so live documentation links
  (if any exist outside `docs/plans/`) aren't broken.
