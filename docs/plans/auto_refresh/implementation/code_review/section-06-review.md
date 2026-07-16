# Code Review: section-06-refresh-fetch-store

**Reviewer:** deep-implement:code-reviewer subagent
**Generated:** 2026-07-16

The biggest, most intricate section — real fetch/store logic. Confirmed the
implementer's own `dnssec_ok=false`-for-recheck fix (found via a self-authored
failing test) as correct, and found one additional high-severity bug the
plan itself didn't catch.

## Findings

1. **Confirmed correct**: the `dnssec_ok=false` recheck fix is sound —
   `take_live_positive`/`take_live_cname_hop` gate visibility on
   `!dnssec_ok || entry.dnssec_complete`, so a `true` recheck would
   permanently exclude any `dnssec_complete=false` entry. Using `false`
   only relaxes that gate, never the epoch gate, so no counter-scenario
   exists. **New finding**: the recheck's reuse of `lookup_hop` also
   unconditionally records a popularity hit and touches LRU — meaning a
   refresh cycle contributes its own hit toward staying "hot," a real,
   undocumented feedback loop for fast-refresh-cycle domains.
2. **REAL BUG**: `build_refresh_query`'s `.expect()`-based construction
   wasn't actually guaranteed well-formed — an oversized label (>255 bytes)
   would silently wrap via `as u8`, and labels 64–255 bytes would panic at
   `parse_standard_query_owned` with no `RefreshFailed` metric recorded
   (panic happens before any `increment` call).
3. **REAL BUG (most serious)**: `process_refresh_job` never checked
   `fetch_result`'s `ResolutionCacheDirective::is_cacheable()` before
   storing — `prepare_backend_result` gates its own store on exactly this;
   a refresh could force-cache a response the backend explicitly marked
   `DoNotCache`. Present in the plan's own pseudocode too, not solely an
   implementer slip, but unaddressed and untested by any of the 10 tests.
   Minor nit: unnecessary `miss_key.clone()`.
4. **Test suite gaps**: the DO=false coalescing test hand-duplicates
   Leader-branch logic inline instead of reusing shared logic (could drift
   silently); the reverse case (refresh job as Follower behind a genuine
   client Leader) is untested; `job_aborts_on_epoch_mismatch` conflates
   epoch-mismatch with physical namespace-sweep removal, so it doesn't pin
   the epoch guard specifically; `job_success_advances_expires_at_and_exits_lead_window`
   didn't actually verify the "exits lead window" half its name and the
   plan both claim.
5. **Confirmed fine**: CNAME-hop refresh jobs — `RefreshHint` for a CNAME
   hop already carries `qtype=CNAME_RECORD_TYPE`, and `process_refresh_job`/
   `build_refresh_query` consistently use whatever qtype the job carries, so
   nothing breaks structurally for a CNAME-type job.

## Triage

All real, no genuine tradeoffs needing user input — fixed directly, except
where a full fix would require re-opening cache/shard.rs signatures a third
time (documented instead, with a flag for section-07):

1. **Documented, not fixed**: added a detailed comment at the recheck call
   site explaining the feedback loop and explicitly flagging it for
   section-07's end-to-end verification to probe with a short-TTL/
   fast-refresh-cycle domain, not just a long-TTL one. Fixing it properly
   would require a side-effect-free recheck path, contradicting this
   design's deliberate choice to reuse `lookup_chain`.
2. **Fixed**: `build_refresh_query` now returns `Option<DecodedQuery>`
   (never panics), with an explicit `label.len() > 63` guard before the
   `as u8` cast (catches the truncation case directly, not just via the
   downstream parser). Caller treats `None` as `RefreshFailed`, no fetch
   attempted. Added `build_refresh_query_rejects_oversized_label` test.
3. **Fixed**: added the `cache_directive.is_cacheable()` check before
   storing, matching `prepare_backend_result`'s own gate exactly, with a
   `RefreshFailed` increment on the DoNotCache path. Removed the
   unnecessary `miss_key.clone()`.
4. **Fixed** `job_success_advances_expires_at_and_exits_lead_window` to
   actually assert `refresh_hints.is_empty()` under the *default*
   RefreshConfig post-refresh (not just the permissive config used to
   trigger the test), which genuinely exercises the "exits lead window"
   claim. **Not fixed**: the reverse-coalescing test and the epoch-guard-
   specific test were judged not worth pursuing — the reverse case requires
   either sleep-based timing (against this codebase's established
   no-sleep-for-correctness testing convention) or is architecturally
   unreachable deterministically (singleflight only activates on a genuine
   miss, but the refresh job's own recheck requires a *live* entry to
   proceed past step 2, and a live entry never reaches singleflight from a
   real client's side either) — documented this reasoning directly in a
   code comment near the store step instead, alongside the related
   "Follower also stores" redundancy behavior (intentional, harmless).
5. **Not acted on**: already correct, no change needed.
