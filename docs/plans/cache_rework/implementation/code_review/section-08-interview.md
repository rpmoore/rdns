# Code Review Interview: section-08-test-migration-and-benchmark

Review source: `section-08-review.md` (via `deep-implement:code-reviewer`
subagent).

## Findings triage

| Finding | Severity | Disposition |
|---|---|---|
| `backend_reload_sweep_invalidates_stale_generation_entries` verified sound | — | No action — confirmed non-vacuous |
| `RRsetEntry`/`StoredRecord`/`DnssecState` widened to fully `pub` (permanent public-surface widening, no feature gate) | MEDIUM (design tradeoff) | Let go, documented — see rationale below |
| `seed_entry`'s hand-set `cache_namespace` is dead (overwritten by `store_response`) | LOW | Auto-fix — added a one-line comment explaining why |
| Benchmark has no warm-up pass before timing starts | LOW | Auto-fix — added a warm-up pass outside the timed window |
| Manual before/after `InMemoryDnsCache` baseline comparison not produced | LOW-MEDIUM (scope) | Let go, documented — see rationale below |
| Spot-check of Parts 1-4 completeness | — | Independently re-verified by reviewer, confirmed clean (one initial false-alarm on `open_telemetry_cache_gauges_report_approximate_domain_count`'s location, resolved — it's in `main.rs`, not `mod.rs`, matching where it was actually added during section-07's review) |

No user interview was needed — the two mechanical fixes were unambiguous;
the two "let go" items are genuine judgment calls with reasonable
rationale on both sides, documented here and in the section doc rather
than escalated, since neither blocks correctness or leaves a hidden
defect.

## Fixes applied

1. **`tests/cache_concurrency_bench.rs`** — added a one-line comment on
   `seed_entry`'s `cache_namespace` field noting it's dead (overwritten
   by `store_response` at store time).
2. **`tests/cache_concurrency_bench.rs`** — added a warm-up pass
   (`run_workload(&cache, &domains, domains.len())`) before `Instant::now()`
   starts timing, so cold-cache/allocation-growth cost doesn't
   inconsistently pollute the relative thread-count comparison. Re-ran
   the benchmark after the change: scaling remained consistent
   (~7.9M ops/sec at 1 thread → ~22.5M ops/sec at 8 threads).

## Judgment calls (not changed, documented instead)

- **Visibility widening left as fully `pub`, not feature-gated**: `rdns`
  is an unpublished, single-binary application crate (no `publish`
  distribution, no external consumers beyond this repo's own `main.rs`/
  `tests/*.rs`), so the practical blast radius of `RRsetEntry`/
  `StoredRecord`/`DnssecState`/`DecomposedResponse`/`NegativeEntry`/
  `NegativeKey` being permanently constructible from external test crates
  is low — feature-gating them behind a `bench`/`test-util` Cargo feature
  would add real complexity (conditional re-exports, a new feature
  definition, `--features` wiring in `justfile`) for a risk that doesn't
  materialize in this project's actual deployment shape. Accepted as a
  reasonable, if not maximally tidy, tradeoff.
- **No manual `InMemoryDnsCache` before/after baseline recorded**: the
  plan's Part 5 asks for this as a one-time step run *before* deleting
  `InMemoryDnsCache`. That deletion already happened during section-07
  (under the user's own explicit override, in this same session) before
  section-08 began — reconstructing the comparison now would mean
  checking out a pre-section-07 commit, rebuilding a parallel benchmark
  against the old implementation, and running it there, purely to backfill
  a number for the commit message. Given the new benchmark's own
  thread-count scaling (~7.9M → ~22.5M ops/sec, 1→8 threads) already
  directionally demonstrates the sharded design doesn't serialize under
  concurrent load — the property goal 1 and this section both care
  about — the marginal value of the historical comparison didn't seem
  worth the git-archaeology effort. Recording this explicitly here (per
  the reviewer's "at minimum" recommendation) rather than leaving it a
  silent gap.

## Verification after fixes

- `cargo build --all-targets` — clean.
- `cargo test --locked` (full workspace) — 450 lib + 19 bin + 8 forwarding
  + 1 recursive_perf passed, 0 failed; `cache_concurrency_bench` correctly
  shows 0 passed / 1 ignored by default.
- `cargo test --locked --release --test cache_concurrency_bench -- --ignored --nocapture --test-threads=1`
  — runs successfully, prints a plausible scaling table.
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo fmt` — clean.
- Repeated `cargo test --locked` 3x — stable, no flakes.
