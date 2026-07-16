# Section 03 Code Review

Verified both tests compile against real helper signatures (rrset_entry, a_record, seed_rrset_entry, resolve_service_with_cache, ResolveRequest::new) and hand-checked the compute_wire_ttl arithmetic for both; math is correct and neither test resamples SystemTime::now() after capturing `now`, so there's no real-clock flakiness risk despite test 1 using SystemTime::now(). No production code touched, consistent with plan's Q8/Q9 'document, don't change' resolution.

## Findings

- `src/resolver/cache/assemble.rs:808` — LOW: `entry.expires_at = stored_at + Duration::from_secs(30)` is a no-op — `rrset_entry(..., Duration::from_secs(30), stored_at)` already sets `expires_at` to exactly this value, so the override changes nothing. Matches existing convention at assemble.rs:762 and :781 (both also redundant), so not new debt. Comment slightly overstates what the line does.

- `src/resolver/mod.rs:16367-16430` — MEDIUM: test never exercises `decompose_response_for_store`/`build_rrset_entry` (the actual production code that computes/shares the chain-wide `expires_at` ceiling). Both `seed_rrset_entry` calls are handed the identical `chain_ceiling` directly by the test author — proves compute_wire_ttl doesn't re-derive expires_at per lookup, not that the chain-storage path actually produces that shared value. Matches plan's explicit prescription (direct `store_response` population, same pattern as existing 16287-16365 tests), so not a deviation from spec. Test docstring slightly overclaims coverage.

- INFO: placement and fixture reuse match plan exactly; naming convention matches siblings. fmt/clippy/test gates already run and passed (cargo fmt --check clean, clippy clean, `cargo test` 38+ passed incl. both new tests).

## Overall
No off-by-one or flakiness found. Only substantive point is the C.2 coverage gap — inherent to the plan's prescribed test-fixture approach, not an implementation deviation.
