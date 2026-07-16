# Codex Review

**Reviewer:** Codex (via codex:codex-rescue, per user request — external_llm/opus_subagent unavailable/not chosen)
**Generated:** 2026-07-16

---

## 1. Correctness / Soundness

1. **Terminal-only CNAME refresh can still leave visible misses** — Major. Terminal-only hint propagation may let an intermediate CNAME RRset expire and break the chain even when the terminal RRset is fine.
2. **Singleflight coalescing claim is too broad with DO=true refreshes** — Major. Refresh jobs force `dnssec_ok = true`, but `MissKey` includes `dnssec_ok`, so a concurrent client miss with `dnssec_ok = false` won't coalesce as claimed.
3. **Epoch revalidation ordering is underspecified** — Major. Plan lists "re-check eligibility" before capturing `BackendHandle::current()`; should snapshot epoch first, then re-check against that same epoch.
4. **Worker receiver mutex serializes job dispatch while waiting** — Minor. `Arc<Mutex<mpsc::Receiver<RefreshJob>>>` pattern means only one worker parks on receive at a time.
5. **Popularity creation on first store not connected to disabled-mode claim** — Minor. Should state no `PopularityBucket` allocation happens on store when disabled, not just that lookups skip tracking.

## 2. Gaps / Edge Cases

1. **Terminal NoData hint semantics unclear through CNAME chains** — Major. Unclear what a `NoData` hint actually refreshes given the positive-only v1 scope.
2. **Positive-only scope conflicts with CNAME-chain maintenance** — Major. CNAME RRsets are positive entries, so excluding them from hint propagation seems inconsistent with "positive answers only" scope.
3. **Shard-capacity eviction storms only partially addressed** — Minor. A hot domain repeatedly evicted under memory pressure loses its bucket and may never re-reach threshold; not called out as an accepted tradeoff.
4. **RRSIG-only/DNSSEC-complete refresh behavior underspecified** — Minor.
5. **Failure handling may produce repeated failed refresh attempts under hot traffic** — Minor. No suppression/backoff after a failed refresh within the same lead window.

## 3. Scope / Complexity Concerns

1. **`catch_unwind` may introduce dependency/unwind-safety complexity** — Minor. Potentially conflicts with the stated no-new-dependency rationale if `futures` isn't already a dependency.
2. **Config surface broad for v1** — Minor. Ten knobs vs. the smaller surfaces of comparable systems (BIND, Unbound).
3. **Default-on deserves a rollout argument** — Major. Unbound ships prefetch off by default citing ~10% extra traffic/load; plan should justify default-on.
4. **Bypassing `prepare_backend_result` needs invariant tests** — Major. Direct-store path for refresh results skips policy-block/rewriting/chaos layers; needs explicit tests proving cacheable-answer invariants still hold.

## 4. Testability

1. **Missing test for intermediate CNAME expiry** — Major. The most questionable ChainLookup design choice (dropping intermediate hints) is untested.
2. **Missing epoch-reload race test** — Major. No test for a mid-flight `cache_epoch` bump between enqueue and processing.
3. **Missing DO=true/DO=false coalescing test** — Major. Should cover both DO=true coalescing and DO=false non-coalescing explicitly.
4. **Implementation order puts metrics too late (step 7 vs. worker logic step 6)** — Minor.
5. **Config should precede trigger wiring (step 4 vs. step 2)** — Minor. Trigger logic depends on configured thresholds, so implementing config first avoids rework.

**Overall Assessment:** No-go as written. Architecture is viable but needs revision on CNAME-hop refresh semantics, epoch snapshot/recheck ordering, the `dnssec_ok` coalescing claim, and default-on justification, plus added tests for CNAME-chain and epoch-race cases, before implementation should start.
