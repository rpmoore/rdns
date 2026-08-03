Good, enough context. Now writing the section content.

## Section 04: DNSSEC Entry Wiring and CD-Bit Gating

### Summary

Wires the section-03 validator into the actual entry-construction and response-assembly paths so `DnssecState` stops being a hardcoded `Unvalidated` default and starts reflecting a real validation verdict. Covers plan **§A5** (calling the validator from the code path that builds cache entries, plus RRSIG-expiration TTL capping) and **§A6** (CD-bit gating at response-assembly time, plus the Bogus-excluded-from-serve-stale rule), and the subset of **§A8** tests that need the full entry-construction/response-assembly path wired up: the CD-bit test, the mixed-validation-state CNAME chain test, and the serve-stale test.

This corresponds to plan sections **A5** and **A6** in `claude-plan.md`, plus the relevant part of **A8**.

**Important grounding note before starting**: this section's Current State investigation found that the CD-bit gating behavior A6 describes as new work is *already implemented and already tested* in the current codebase (`dnssec_servfail_check`/`negative_dnssec_servfail_check` already consult `requester_features.checking_disabled`, which is already sourced from `request.header.cd()`). It has simply never been exercisable end-to-end because no code path has ever produced a real `Bogus` state. Re-verify this is still true against the code you find when you start (it may have drifted since this section was written), but do not assume you need to write new CD-bit-threading code at the `assemble_response`/`assemble_negative_response` call sites — confirm first, then focus new code on what's genuinely missing: the serve-stale Bogus-exclusion rule and the RRSIG-expiration TTL cap.

### Dependencies

- **Depends on section-03-dnssec-validator-core**: this section calls the validation function section-03 produces (referred to below as "the A4 function" — plan §A4, `src/resolver/dnssec_validation.rs` or wherever section-03 lands it) and consumes its `DnssecState` output. Read section-03's actual function signature before starting — its exact shape (whether it validates once per whole response, or can be invoked per-hop/per-RRset) determines how the wiring in this section is structured; see the note under "Wiring the validator" below.
- **Depends on section-03**'s fixture module (the deterministic signed test zone) for the mixed-state CNAME chain test, if that test is written against real validator output rather than hand-constructed entries (see Tests below — both approaches are acceptable).
- **Blocks section-05-dnssec-status-metrics**: A7's outcome counter increments "from within or near the A4/A5 call site," so section-05 needs this section's call site to exist first.

### Background

`rdns` is a Rust recursive/forwarding DNS resolver. The cache/response layer already fully consumes a `DnssecState` verdict end-to-end — `dnssec_servfail_check`/`negative_dnssec_servfail_check` already force SERVFAIL on `Bogus` (respecting CD), `dnssec_ad_bit`/`negative_dnssec_ad_bit` already set AD=1 only when every entry in a chain is `Secure`, and serve-stale already has a `dnssec_complete`-based DO=true gate. None of that logic has ever run against a real verdict, though: every cache entry's `dnssec_state` field is populated via `Default::default()`, which resolves to `DnssecState::Unvalidated` (`src/resolver/cache/entry.rs:104-116`, `#[default]` on `Unvalidated`). This section is what starts producing real verdicts.

`DnssecState` (`src/resolver/cache/entry.rs:104-116`):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnssecState {
    #[default]
    Unvalidated,
    #[allow(dead_code)]
    Insecure,
    #[allow(dead_code)]
    Secure,
    #[allow(dead_code)]
    Bogus(String), // reason, for diagnostics; short negative-style TTL applies
}
```

The `#[allow(dead_code)]` attributes exist because nothing constructs these variants today outside tests. Once this section (or section-03, whichever lands the first real construction site) wires in real production code that constructs `Insecure`/`Secure`/`Bogus`, these attributes should be removed — leave them if section-03 already removed them, otherwise remove them here since this section is what makes them reachable via production code paths.

### Current state: where cache entries get their `dnssec_state`

Two functions build cache entries and both currently hardcode the default (`src/resolver/mod.rs`):

```rust
// src/resolver/mod.rs:1039-1064
fn build_rrset_entry(
    response: &Message,
    records: &[&Record],
    owner: &str,
    ttl: Duration,
    stored_at: SystemTime,
    dnssec_ok: bool,
    store_authoritative: bool,
) -> RRsetEntry {
    let rtype = records.first().map_or(0, |record| record.rtype);
    let rclass = records.first().map_or(0, |record| record.rclass);
    RRsetEntry {
        records: records.iter().copied().map(to_stored_record).collect(),
        rrsigs: matching_rrsigs(&response.answers, owner, rtype, rclass),
        response_code: ResponseCode::NoError,
        minimum_ttl: ttl,
        stored_at,
        expires_at: stored_at + ttl,
        dnssec_state: Default::default(),   // <-- line 1057, replace this
        cache_epoch: 0,
        dnssec_complete: dnssec_ok,
        authoritative: store_authoritative,
    }
}
```

```rust
// src/resolver/mod.rs:1080-1120
fn build_negative_entry(
    response: &Message,
    metadata: &NegativeCacheMetadata,
    ttl: Duration,
    stored_at: SystemTime,
    dnssec_ok: bool,
    store_authoritative: bool,
) -> NegativeEntry {
    // ... (SOA/soa_rrsig/proof_records lookups, unchanged) ...
    NegativeEntry {
        kind: metadata.kind,
        soa_owner: metadata.soa_owner.clone(),
        soa_record,
        soa_rrsig,
        proof_records,
        stored_at,
        expires_at: stored_at + ttl,
        cache_epoch: 0,
        dnssec_complete: dnssec_ok,
        dnssec_state: Default::default(),   // <-- line 1117, replace this
        authoritative: store_authoritative,
    }
}
```

Both are called from `decompose_response_for_store` (`src/resolver/mod.rs:845-947`), which walks a recursive response's CNAME chain, calling `build_rrset_entry` once per hop (lines 880 and 914) and `build_negative_entry` once for the terminal negative result (line 935) if the chain ends in NXDOMAIN/NODATA rather than a positive answer.

`decompose_response_for_store` itself is called from `cache_store_for_response` (`src/resolver/mod.rs:6111-6135`), which is called from `store_cache_response` (`:6077-6101`), which is called from `prepare_backend_result` (`:5581+`). `prepare_backend_result` is the relevant outer call site: it already has `backend_mode: ResolutionMode` as a parameter and already branches on it to decide `store_dnssec_ok`/`store_authoritative` before calling `store_cache_response` (`:5645-5693`):

```rust
// src/resolver/mod.rs:5661-5689 (existing code, for reference)
let store_dnssec_ok = match backend_mode {
    ResolutionMode::Recursive => true,
    ResolutionMode::Forward => decoded.features.dnssec_ok,
};
let store_authoritative = match backend_mode {
    ResolutionMode::Recursive => false,
    ResolutionMode::Forward => response_message.header.aa(),
};
self.store_cache_response(
    cache_epoch,
    &response_message,
    &question,
    request,
    store_dnssec_ok,
    store_authoritative,
)
.await;
```

This `backend_mode == ResolutionMode::Recursive` branch is where validation must be gated — `ResolutionMode::Forward` must never call the validator (per the scope decision: Forward mode keeps trusting the upstream's AD bit verbatim, unchanged by this whole plan).

### Wiring the validator (§A5)

1. **Thread a `DnssecState` (or however section-03 exposes its result) through the call chain** from `prepare_backend_result` down to `build_rrset_entry`/`build_negative_entry`, replacing each `dnssec_state: Default::default()` with the real value. The most direct path: add a `dnssec_state: DnssecState` parameter to `build_rrset_entry` and `build_negative_entry`, thread it through `decompose_response_for_store` (add a parameter there too), and compute it once in `prepare_backend_result` (or `store_cache_response`/`cache_store_for_response` — pick whichever keeps the async validator call closest to where it's actually awaited) by calling the A4 function only when `backend_mode == ResolutionMode::Recursive`.
2. **Forward mode never validates.** When `backend_mode == ResolutionMode::Forward`, do not call the A4 function at all — pass `DnssecState::Unvalidated` (or whatever section-03's function would return for "not attempted") straight through. This must be provable with a call-counter/spy-style test (see Tests below), not just an untested assumption, since this is a correctness-relevant scope boundary from the interview.
3. **Validation always runs and its result is always stored**, independent of the current request's CD bit. The cache entry this fetch produces is shared across every future requester of that name/type, so a CD=1 fetcher must not cause a CD=0 requester to later be served an entry that was never actually validated. CD-bit gating happens only at response-assembly time (§A6 below), never here.
4. **Mixed-state CNAME chains**: `decompose_response_for_store`'s loop (`src/resolver/mod.rs:868-925`) builds one `RRsetEntry` per CNAME hop plus a terminal entry. Whether each hop can get its own independently-computed `DnssecState`, or whether section-03's function only produces one verdict for the whole response, depends entirely on section-03's actual signature — read it before deciding how to structure this loop's validator call(s). If section-03 only exposes one verdict per response, apply it uniformly to every entry built from that response in this loop; the mixed-state CNAME chain test (see Tests below) then needs to construct two independently-labeled stored entries directly, the same way the existing `assemble_response_servfails_on_bogus_when_checking_enabled` test already does, to prove the chain-level aggregation in `dnssec_servfail_check` itself, rather than proving per-hop independent validation which may not exist as a wiring feature at all. Do not silently assume one or the other — this is a real decision point, not a mechanical detail.

### TTL capping at RRSIG expiration (§A5)

An entry's effective cache TTL must be capped at the earliest RRSIG expiration found in its validated chain, on top of whatever TTL logic already governs the entry today (`ttl_for_response`/`min_positive_ttl` floors, etc.). Without this, a `Secure` entry could keep being served from cache after its signature has cryptographically expired — the existing TTL machinery knows nothing about signature validity windows.

- RRSIG wire format (`src/protocol/mod.rs:278-288`) carries `signature_expiration: u32` — a Unix timestamp (seconds since epoch), not a duration.
- `build_rrset_entry` already computes `rrsigs: matching_rrsigs(&response.answers, owner, rtype, rclass)` (`:1052`) before setting `expires_at: stored_at + ttl` (`:1056`). Add a step that, if `rrsigs` is non-empty, finds the minimum `signature_expiration` across them, converts it to a `SystemTime` (`UNIX_EPOCH + Duration::from_secs(signature_expiration as u64)`), and caps the effective TTL/`expires_at` to whichever is earlier: `stored_at + ttl` (today's value) or the earliest RRSIG expiration time. If `rrsigs` is empty, behavior is unchanged (no RRSIGs to cap against).
- Apply the same capping to `build_negative_entry`, using `soa_rrsig` and the RRSIGs embedded in `proof_records` as the candidate set (both are `Option<StoredRecord>`/`Vec<(String, StoredRecord)>` respectively, holding `RecordData::RRSIG { .. }` when present).
- This capping is independent of whether the entry validated `Secure`, `Bogus`, or anything else — RRSIGs may be present (and thus have an expiration to cap against) even on an `Insecure`/`Bogus` entry; cap whenever RRSIGs exist, not only on `Secure` verdicts.
- Test both directions: RRSIG expiration tighter than the otherwise-computed TTL (cap applies), and RRSIG expiration later than the otherwise-computed TTL (cap is a no-op, existing TTL wins) — see Tests below.

### CD-bit response gating (§A6)

Response assembly already gates SERVFAIL-on-Bogus by CD bit. `dnssec_servfail_check`/`negative_dnssec_servfail_check` (`src/resolver/cache/assemble.rs:417-459`):

```rust
// src/resolver/cache/assemble.rs:426-433
fn dnssec_servfail_check(chain: &[(String, Arc<RRsetEntry>)], features: &QueryFeatures) -> bool {
    if features.checking_disabled {
        return false;
    }
    chain
        .iter()
        .any(|(_, entry)| matches!(entry.dnssec_state, DnssecState::Bogus(_)))
}

// src/resolver/cache/assemble.rs:447-459 (negative sibling)
fn negative_dnssec_servfail_check(
    chain: &[(String, Arc<RRsetEntry>)],
    negative: &NegativeEntry,
    features: &QueryFeatures,
) -> bool {
    if features.checking_disabled {
        return false;
    }
    matches!(negative.dnssec_state, DnssecState::Bogus(_))
        || chain
            .iter()
            .any(|(_, entry)| matches!(entry.dnssec_state, DnssecState::Bogus(_)))
}
```

`features.checking_disabled` is `QueryFeatures.checking_disabled`, already populated as `message.header.cd()` at `src/resolver/mod.rs:278` (inside `QueryFeatures::from_message`), and `assemble_response`/`assemble_negative_response` (`src/resolver/cache/assemble.rs:653-726`, `:736+`) already call these two checks first thing, passing `requester_features` straight through — `requester_features` is always derived from the current request's own `QueryFeatures::from_message`.

**Do not modify `dnssec_servfail_check`/`negative_dnssec_servfail_check`, `dnssec_ad_bit`/`negative_dnssec_ad_bit`, or their call sites in `assemble_response`/`assemble_negative_response`** — confirm (via the tests below) that this already-existing wiring correctly produces SERVFAIL on `Bogus`+CD=0 and skips it on `Bogus`+CD=1, now that §A5 makes `Bogus` reachable in practice. If your investigation finds this is no longer accurate by the time you implement (code may have drifted), then and only then make the minimal call-site change the plan originally specified: threading `request.header.cd()` into the `dnssec_servfail_check`/`negative_dnssec_servfail_check` call site without modifying the functions themselves.

### Serve-stale Bogus exclusion (§A6) — the actual new logic in this section

This part is genuinely new. A `Bogus` entry must never be served via serve-stale — serving a known-tampered response past its expiration defeats the point of validating it. `Secure` and `Insecure` entries are unaffected; their existing serve-stale behavior carries over unchanged.

Serve-stale eligibility for positive entries is decided by `stale_servability` (`src/resolver/cache/shard.rs:521-567`):

```rust
// src/resolver/cache/shard.rs:528-567 (current code)
fn stale_servability(
    entry: &RRsetEntry,
    dnssec_ok: bool,
    current_epoch: u64,
    now: SystemTime,
    stale_window: Option<Duration>,
) -> StaleServability {
    let Some(window) = stale_window else {
        return StaleServability::Evict;
    };
    if entry.cache_epoch != current_epoch {
        return StaleServability::Evict;
    }
    let has_zero_origin_ttl = entry
        .records
        .iter()
        .chain(entry.rrsigs.iter())
        .any(|record| record.ttl_at_store == 0);
    if has_zero_origin_ttl {
        return StaleServability::Evict;
    }
    let within_window = entry
        .expires_at
        .checked_add(window)
        .is_some_and(|stale_until| now < stale_until);
    if !within_window {
        return StaleServability::Evict;
    }
    if dnssec_ok && !entry.dnssec_complete {
        return StaleServability::KeepButMiss;
    }
    StaleServability::Servable
}
```

Add a `Bogus` check that returns `StaleServability::Evict` — place it early (e.g. right after the `cache_epoch` check, before the window/zero-TTL checks, since a `Bogus` entry should never be stale-servable regardless of window or TTL state):

```rust
if matches!(entry.dnssec_state, DnssecState::Bogus(_)) {
    return StaleServability::Evict;
}
```

This requires importing `DnssecState` into `src/resolver/cache/shard.rs` (not currently imported there — check the file's existing `use` block, e.g. near `use crate::resolver::cache::entry::StoredRecord;` at `:981` inside the test module, and add a module-level import alongside `RRsetEntry`'s own import).

`stale_servability` is called from both `take_live_positive` (`:350-379`) and `take_live_cname_hop` (`:396-439`), so this one change covers both the terminal positive entry and CNAME-hop entries in a chain.

**Negative entries are out of scope for this rule**: negative (NXDOMAIN/NODATA) entries are never stale-served at all today — confirmed by the existing test `lookup_hop_negative_entries_are_never_stale_served` (`src/resolver/cache/shard.rs:2175+`, "v1 scope: RFC 8767 §5 flags stale negative answers... original evict-at-read behavior even inside the stale window"). Since negative entries can never be stale-served regardless of `dnssec_state`, no change is needed for `NegativeEntry`'s serve-stale path — do not add a parallel Bogus check there; it would be dead code.

### Tests

Write these before/alongside the implementation changes above. Follow this repo's existing convention: inline `#[cfg(test)] mod tests` at the bottom of the same file as the code under test, hand-constructed struct/byte-vector fixtures, no mocking framework.

**§A5 — entry construction (in `src/resolver/mod.rs`'s existing test module):**

- `build_rrset_entry` in `ResolutionMode::Recursive` calls the A4 validation function and stores its result in the resulting entry's `dnssec_state` (replaces today's implicit `Default::default()`) — this test should fail against the current code and pass once this section's wiring lands.
- Same assertion for `build_negative_entry`.
- `ResolutionMode::Forward` does not invoke validation at all — confirm via a call-counter/spy (consistent with how other path-not-taken assertions are made elsewhere in this codebase without a mocking framework — e.g. a test-only wrapper around the A4 function that increments a counter, asserted to stay at zero for a Forward-mode fetch).
- A cache entry's `dnssec_state` is populated identically regardless of the originating request's CD bit — validate with a CD=1 request and a CD=0 request producing the same underlying fetch, assert both produce the same stored `dnssec_state` (proves "always validate, always store," independent of §A6's later gating).
- Effective entry TTL is capped at the earliest RRSIG expiration in the validated chain when that's tighter than the otherwise-computed TTL, and is unaffected (uses the otherwise-computed TTL) when RRSIG expiration is later than that TTL. Write both directions as separate cases.

**§A6 — CD-bit gating and serve-stale (in `src/resolver/cache/assemble.rs`'s and `src/resolver/cache/shard.rs`'s existing test modules):**

- A `Bogus` entry + CD=0 request → `dnssec_servfail_check`'s call site produces SERVFAIL. (Likely already covered by the existing `assemble_response_servfails_on_bogus_when_checking_enabled` test at `src/resolver/cache/assemble.rs:1557+` — confirm it still passes and covers this; extend it rather than duplicating if so.)
- A `Bogus` entry + CD=1 request → SERVFAIL is skipped, response is built from the entry's data as normal. (Same existing test likely already covers this — it constructs both a CD=0 and CD=1 assembly from the same Bogus entry.)
- A `Secure` entry's AD-bit behavior is unaffected by CD (no-regression check on `dnssec_ad_bit`, which this section does not touch).
- An expired `Bogus` entry is not eligible for serve-stale — new test against `stale_servability` (or `Shard::lookup_hop` end-to-end, matching the existing `lookup_hop_*` test style in `src/resolver/cache/shard.rs`'s test module, e.g. near `lookup_hop_serves_stale_positive_within_window_with_unconditional_refresh` at `:1958`): construct an expired, in-stale-window entry with `dnssec_state: DnssecState::Bogus(...)`, assert the lookup misses (evicted) rather than serving it stale.
- An expired `Secure` entry's existing serve-stale eligibility is unchanged (no-regression check against the existing stale-serve tests, e.g. `lookup_hop_serves_stale_positive_within_window_with_unconditional_refresh`).

**§A8 — mixed-state CNAME chain test (in `src/resolver/cache/assemble.rs`'s test module, alongside `assemble_response_servfails_on_bogus_when_checking_enabled`):**

- Construct a `ResolvedAnswer` whose `chain` has two hops: one `RRsetEntry` with `dnssec_state: DnssecState::Secure`, another with `dnssec_state: DnssecState::Bogus("...")`. Assert `assemble_response` with CD=0 returns SERVFAIL — the chain-level verdict reflects the worst state in the chain, matching `dnssec_servfail_check`'s existing `.any()` semantics (`src/resolver/cache/assemble.rs:430-432`). This is a coverage test for an existing `.any()` code path that no prior test happened to exercise with a genuine multi-hop mixed-state chain (existing tests use a single-entry chain) — it should already pass against unmodified `dnssec_servfail_check` code; if it doesn't, that's a real bug to fix, not an expected new-code failure.

### Verification gates

Per this repo's standing rules (`RUST.md`), before considering this section done:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets` — no new warnings; removing the `#[allow(dead_code)]` attributes on `DnssecState::Insecure`/`Secure`/`Bogus` (if not already removed by section-03) should not introduce new dead-code warnings once this section's code paths construct them.
- `cargo test` — full suite, including every new test listed above.
- Per AGENTS.md's automatic triggers, run the `verify` skill against the affected flow (cache-store and response-assembly paths) before reporting this section done, since this is a nontrivial code change, not test-only or doc-only.

### Acceptance criteria

- `build_rrset_entry` and `build_negative_entry` store a real, section-03-computed `DnssecState` instead of `Default::default()`, only in `ResolutionMode::Recursive`; `ResolutionMode::Forward` is provably unaffected.
- Validation always runs and its result is always stored, independent of the storing request's CD bit.
- Entry TTL is capped at the earliest RRSIG expiration among the entry's stored RRSIGs, both for positive (`build_rrset_entry`) and negative (`build_negative_entry`) entries, without regressing the otherwise-computed TTL when RRSIG expiration is later.
- CD-bit gating at response assembly is confirmed correct (either already-working, re-verified, or fixed if drifted) — a `Bogus` entry produces SERVFAIL only when CD=0; `dnssec_ad_bit`/`negative_dnssec_ad_bit` behavior is unchanged.
- `stale_servability` (`src/resolver/cache/shard.rs`) excludes `Bogus` entries from serve-stale eligibility; `Secure`/`Insecure` entries' existing serve-stale behavior is unchanged; negative entries are unaffected (they were already never stale-served).
- The mixed-state CNAME chain test passes, proving `dnssec_servfail_check`'s chain-wide `Bogus` aggregation works against a genuine multi-hop chain.
- All listed tests pass; `cargo fmt`/`cargo clippy`/`cargo test` gates are green; `verify` skill has been run.

---

Files this section creates/modifies:
- `/home/rpmoore/code/rdns/src/resolver/mod.rs` — `build_rrset_entry` (~1039-1064), `build_negative_entry` (~1080-1120), `decompose_response_for_store` (~845-947), `prepare_backend_result`/`store_cache_response`/`cache_store_for_response` call chain (~5581-6135), plus new tests.
- `/home/rpmoore/code/rdns/src/resolver/cache/assemble.rs` — no production-code changes expected (pending the re-verification above); new mixed-state CNAME chain test in the existing test module.
- `/home/rpmoore/code/rdns/src/resolver/cache/shard.rs` — `stale_servability` (~521-567), new `DnssecState` import, new serve-stale-Bogus-exclusion tests.
- `/home/rpmoore/code/rdns/src/resolver/cache/entry.rs` — remove `#[allow(dead_code)]` from `DnssecState::Insecure`/`Secure`/`Bogus` (~104-116) once this section's code constructs them, if section-03 hasn't already done so.

Relevant file paths (all absolute, for reference during review): `/home/rpmoore/code/rdns/docs/plans/sec_work/claude-plan.md` (§A5, §A6, §A8), `/home/rpmoore/code/rdns/docs/plans/sec_work/claude-plan-tdd.md` (§A5, §A6, §A8 sections), `/home/rpmoore/code/rdns/docs/plans/sec_work/sections/index.md` (manifest entry for `section-04-dnssec-entry-wiring`).

---

### Implementation notes (what was actually built)

**Files actually touched** (matches the plan's list, plus `main.rs`):
- `src/resolver/mod.rs` — `build_rrset_entry`/`build_negative_entry`/`decompose_response_for_store`/`cache_store_for_response`/`store_cache_response` all gained a `dnssec_state: DnssecState` parameter; `prepare_backend_result` computes it via a new `ResolveQuery::validate_for_store` method (gated on `backend_mode == Recursive`); a second call site in the auto-refresh job path (`process_refresh_job`, ~line 4053) got the same gate. New `cap_expires_at_to_rrsig_expiration` helper does the TTL capping for both entry builders. `ResolveQuery` gained two new fields (`trust_anchors: Option<Vec<String>>`, `dnssec_validation_deadline: Duration`) with `with_trust_anchors`/`with_dnssec_validation_deadline` builder methods, defaulting to `None`/`DEFAULT_DNSSEC_VALIDATION_DEADLINE` so every existing test and constructor is unaffected unless it opts in.
- `src/resolver/cache/shard.rs` — `stale_servability` gained the `Bogus`-exclusion check exactly as specified; `DnssecState` imported at module level.
- `src/resolver/cache/assemble.rs` — no production-code changes (re-verification confirmed the plan's grounding note: CD-bit gating was already correct). Added the mixed-state CNAME chain test plus one extra AD-bit/CD no-regression test (see Deviations).
- `src/resolver/dnssec_validation.rs` — removed the `#[allow(dead_code)]`s section-03 left for this section to clear; made `mod tests` `pub(crate)` so this section's own tests could reuse `tests::fixture` (the signed-zone fixture), matching that module's own doc comment ("`pub(crate)` so section-04's tests can reuse it") which hadn't actually been reachable until this change.
- `src/main.rs` — see Deviations below; ended up **not** wiring `with_trust_anchors` into production.
- `src/resolver/cache/entry.rs` — no change needed; section-03 had already removed the `#[allow(dead_code)]`s.

**Deviations from the plan, with rationale:**

1. **`TrustAnchors` isn't `Clone`** (discovered during implementation, not mentioned in the plan). `domain::dnssec::validator::anchor::TrustAnchors` has no `Clone` impl, and `ValidationContext::with_config` consumes one by value per validation run. Storing a parsed `TrustAnchors` on `ResolveQuery` for reuse across many `validate_for_store` calls was therefore impossible. Fixed by storing the raw zonefile-format lines (`Vec<String>`, matching `RecursiveResolutionConfig::load_trust_anchors`'s own return shape) and re-parsing via `TrustAnchors::from_u8` on every call — cheap relative to the DS/DNSKEY chase that follows it.

2. **`main.rs` does NOT call `with_trust_anchors`, contrary to the original intent of "wire it into production."** Live-verified with `dig` against a real recursive instance: wiring bundled trust anchors unconditionally (whenever `config.resolution.recursive` is `Some`) made ordinary, unsigned domains (e.g. `example.com` behind Cloudflare, no DS/DNSKEY chain) start returning SERVFAIL on cache hits and repeat negative-cache lookups. Root cause: `DnssecValidationMode` (`config/mod.rs`) currently has only a `Disabled` variant — there is no config-level opt-in/kill-switch for validation yet, so unconditional wiring made every `ResolutionMode::Recursive` fetch validate regardless of that mode, with a Bogus-leaning-in-practice verdict for undelegated data forcing `dnssec_servfail_check` to SERVFAIL any CD=0 requester. `DnssecValidationMode::Enabled` (and defaulting it on deliberately, with its own rollout notes) is explicitly section-05's job (plan §A7). Section-04 therefore lands the mechanism (`ResolveQuery::validate_for_store`, fully wired and tested against real signed-zone fixtures) but leaves it **unreachable in production** until section-05 adds the enable gate — exactly like every other `ResolveQuery` default. `main.rs` still wires `with_dnssec_validation_deadline(config.per_query_deadline)` (harmless without trust anchors) and leaves a comment at the call site explaining this for whoever implements section-05.

3. **Code-review finding, resolved via the plan's own text rather than a new decision**: `validate_for_store` runs synchronously on the triggering client's own reply path (awaited inside `prepare_backend_result`, before that request's response is returned) — a cache-miss client really does block on the DS/DNSKEY chase once trust anchors are configured. An initial doc comment on `validate_for_store` incorrectly claimed this was off the critical path; corrected during review. Per `claude-plan.md` §A4 ("Timeout and error handling (fail-closed)"), this is a **deliberate, plan-sanctioned trade-off**, not a defect to redesign away in this section — the doc comment now says so explicitly and points at watching section-05's latency metrics after rollout, matching §A7's own "not solved in this pass" framing.

4. **Extra test beyond the plan's explicit list**: `assemble_response_ad_bit_for_secure_entry_unaffected_by_cd_bit` (`assemble.rs`) — the plan's Tests section asked for this no-regression check but the diff hadn't included it in the first pass; added during code review.

5. **Extra hardening beyond the plan**: a `tracing::warn!` on trust-anchor parse failure inside `validate_for_store` (previously silently degraded to `Unvalidated` with no operator-visible signal) — added during code review as a security-relevant silent-failure fix.

**Test count**: all tests listed in the plan's Tests section were written, plus the two additions above. Full suite: 730 passing (up from 729 pre-section-04), 3 pre-existing `#[ignore]`d follow-ups (algorithm-downgrade, NSEC3 opt-out, DS-digest-tamper fixtures — tracked as section-03 follow-ups, unrelated to this section). `cargo fmt --all -- --check`, `cargo clippy --all-targets` (clean after adding `#[allow(clippy::too_many_arguments)]` to three functions whose parameter count crossed the default lint threshold, matching this codebase's existing convention), and the `verify` skill (live `dig` against a real recursive instance: cache miss/hit, TCP, `+dnssec`, repeated negative lookups, malformed-UDP FORMERR probes, 60-query concurrency burst, metrics endpoint) all passed.