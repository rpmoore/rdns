# Integration Notes: Codex Review → Plan Revisions

Reviewer verdict: "No-go as written." Findings below, each marked integrated or not, with reasoning.

## Integrated (plan changed)

1. **Terminal-only CNAME hint propagation is wrong (Correctness #1, Gaps #1/#2).**
   Confirmed on inspection: CNAME RRsets are stored as ordinary *positive* entries,
   not negative ones, so dropping intermediate hops from hint propagation directly
   contradicts the "positive answers only" v1 scope decision — it wasn't a
   deliberate narrowing, it was an oversight. **Fixed**: every positive hop walked
   during `resolve_from_cache` (including intermediate CNAME hops, not just the
   terminal answer) is independently checked for refresh-eligibility, and *each*
   qualifying hop produces its own hint. `probe_cache` may enqueue more than one
   job per lookup (one per qualifying hop domain). This also resolves Gaps #1 (NoData
   hint semantics) by removing the hint from `NoData` entirely — see next item.

2. **`NoData` should not carry a refresh hint at all (Gaps #1).** Per this
   codebase's existing negative-caching semantics (RFC 2308 style — confirmed by
   `docs/knowledge` research), NODATA is stored as a `NegativeEntry`, same family
   as NXDOMAIN. The v1 "positive entries only" scope decision (interview Q5)
   already excludes this; adding an optional hint to `ChainLookup::NoData` in the
   first plan draft was inconsistent with that decision. **Fixed**: only
   `ChainLookup::Answered`-shaped (positive) results carry a hint; `NoData` never
   does.

3. **Epoch must be captured before/atomically-with the eligibility recheck, not
   after (Correctness #3).** If a reload bumps `cache_epoch` between enqueue and
   processing, the old entry is effectively invisible under the new epoch (per
   `cache-epoch.md`), but the lead-window recheck alone (which only looks at
   `expires_at`) wouldn't catch that — it would look "eligible" against stale
   data. **Fixed**: the worker captures `BackendHandle::current()` first, then
   performs the eligibility recheck *using that same epoch* (the recheck now also
   confirms the entry's `cache_epoch` still matches; a mismatch is treated as "no
   longer eligible," job aborts, no metric beyond a no-op). This also directly
   produces the epoch-race test Codex flagged as missing (Testability #2).

4. **Worker-loop panic isolation via `catch_unwind` was the wrong mechanism
   (Scope #1).** Confirmed via `Cargo.toml`: this project has no `futures`
   dependency today, so `FutureExt::catch_unwind` would be a new dependency —
   contradicting the plan's own "add dependencies conservatively" rationale for
   avoiding `async-channel`. **Fixed, and simpler than the original design**: each
   worker loop iteration now does its own `tokio::spawn` for a single dequeued
   job and awaits that job's `JoinHandle` before dequeuing the next one. This
   still bounds total concurrency to `worker_count` (a worker never dequeues job
   N+1 until job N's spawned task completes), gets Tokio's native per-task panic
   isolation for free (inspect `JoinError::is_panic()`), and needs no new crate.

5. **Overclaimed singleflight coalescing needed correction, not a design change
   (Correctness #2).** `MissKey` includes `dnssec_ok`, and refresh jobs always use
   `dnssec_ok = true` (interview decision), so a concurrent *client* miss with
   `dnssec_ok = false` genuinely will not coalesce with an in-flight refresh — the
   plan's "coalesces for free" language was too broad. **Fixed**: plan now states
   this precisely (coalescing applies when the client's own query also has
   `dnssec_ok = true`; a DO=false client miss during a DO=true refresh pays its own
   independent backend round trip — no correctness issue, just narrower
   coalescing than originally described) and adds the explicit dual test
   (Testability #3).

6. **Default-on needs an explicit rollout justification (Scope #3).** Unbound
   ships its comparable feature *off* by default, citing ~10% added traffic — a
   fair challenge to this plan shipping default-on. **Addressed by adding
   rationale, not by changing the interview-confirmed default**: Unbound's 10%
   figure comes from a blanket ratio-only trigger applied to *every* cached
   record; this design additionally gates on a popularity threshold *and* an
   eligibility floor, both absent from Unbound's mechanism, so the qualifying set
   is structurally much smaller, and total added backend load is further capped
   by the fixed worker pool regardless of how many domains qualify. This
   reasoning is now stated directly in the plan rather than left implicit. The
   default-on choice itself stays as confirmed twice by the user (initial spec
   and interview round 3) — reviewer pushback here was "justify it," not
   "reverse it."

7. **Missing invariant tests for bypassing `prepare_backend_result` (Scope #4).**
   Added explicit test to §8: a refresh-stored entry must be structurally
   equivalent (TTL computation, RRset decomposition) to what the normal
   client-miss path would store for the identical backend response, modulo the
   policy/rewrite/chaos layers refresh deliberately skips.

8. **Implementation order: config before trigger logic, metrics before job
   processing (Testability #4/#5).** Reordered §9: `RefreshConfig` now precedes
   trigger-formula implementation (trigger logic reads config thresholds, so
   building config first avoids rework); metrics variants now land alongside the
   worker-pool skeleton, before the fetch/store logic needs to call them.

9. **Missing CNAME-chain, epoch-race, and DO=true/false coalescing tests
   (Testability #1/#2/#3).** All three added explicitly to §8, made possible by
   the design fixes above (per-hop hints, epoch-first ordering, precise
   coalescing claim).

## Noted as accepted tradeoffs (plan clarified, not changed)

10. **Worker receiver mutex serializes dispatch (Correctness #4).** Accepted:
    `worker_count` defaults to 4, a small fixed pool: the serialization is on the
    `.await` point of an already-idle receiver, not on job execution time, so
    contention is negligible at this scale. Not worth a new dependency
    (`async-channel`) to fix. Noted directly in the plan as a deliberate,
    bounded tradeoff.

11. **Popularity bucket allocation wording (Correctness #5).** Clarified: when
    `enabled = false`, the increment call itself is skipped at the call site
    (behind the existing config check), so no `PopularityBucket` is ever
    allocated — not just "lookups skip tracking." Wording fix only.

12. **Shard-capacity eviction storms (Gaps #3).** Accepted as a documented
    tradeoff, consistent with the design's "no separate cleanup, rides on
    existing LRU lifecycle" philosophy: a domain repeatedly evicted under memory
    pressure loses its bucket and must rebuild popularity from scratch. This is
    the same tradeoff the LRU itself already has under capacity pressure — not
    something auto-refresh should special-case. Added as an explicit non-goal
    note rather than new bookkeeping.

13. **RRSIG-only/DNSSEC-complete entries (Gaps #4).** Clarified with one
    sentence: refresh only concerns whatever `lookup_hop`'s existing
    `take_live_positive`/`take_live_cname_hop` probes already return — no new
    entry-shape handling needed beyond what's already cached there.

14. **Repeated failed-refresh attempts under sustained hot traffic (Gaps #5).**
    The "no retry, no backoff" behavior was an explicit, twice-confirmed interview
    decision (Q3, "Recommended" option chosen) — not reversed. Clarified instead:
    natural rate-limiting on repeated failures comes from the worker pool size
    and channel capacity (bounding concurrent attempts) and the lead window's
    short duration (bounding total exposure time before real expiry), not a new
    backoff mechanism. This is now stated explicitly rather than left implicit.

15. **Config surface breadth (Scope #2).** Not reduced — all ten knobs were
    explicitly walked through and confirmed with the user in interview round 3;
    breadth matches the spec's own requirement that "every knob remains
    operator-overridable."
