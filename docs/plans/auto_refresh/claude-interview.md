# Interview: Auto-Refresh Popular Domains

## Round 1

### Q1: ChainLookup signal path

Research found `probe_cache` doesn't call `lookup_hop` directly — it goes through `cache.lookup_chain -> resolve_from_cache -> lookup_hop`, and `ChainLookup` (Answered/NxDomain/NoData/Miss) has no slot for a refresh-wanted signal. How should that signal surface?

**Answer:** Extend `ChainLookup` variants — add a refresh-hint payload to `Answered`/`NoData` variants, thread through `resolve_from_cache` to `probe_cache`.

### Q2: Shutdown style

Codebase's only existing background task (SIGHUP reload) has no internal shutdown-select — loops forever, gets `.abort()`'d externally at teardown. Should the new refresh worker pool match that, or use idiomatic drop-sender shutdown?

**Answer:** Match existing `.abort()` convention — consistent with the one precedent in this codebase, no new shutdown machinery.

### Q3: Failure handling

On a failed refresh refetch (timeout, SERVFAIL, NXDOMAIN), what should happen?

**Answer:** No retry — let it expire normally. Log `RefreshFailed`, leave the stale entry alone; next real query gets a normal reactive miss at true expiry.

### Q4: Defaults approach

Concrete default numbers for the config knobs, or propose-and-confirm?

**Answer:** Propose conservative defaults grounded in Unbound/BIND research, for user to confirm.

## Round 2

### Q5: Negative entries

Should `NegativeEntry` (cached NXDOMAIN/NODATA) near-expiry also trigger refresh, or is v1 positive-answers-only?

**Answer:** Positive entries only for v1. Refreshing a hot NXDOMAIN just reconfirms it's still NXDOMAIN — lower value than a real answer, simpler scope.

### Q6: DNSSEC DO flag on refresh fetch

Spec flags as open detail: should refresh fetch DO=true always, or match the original entry's `dnssec_complete` state?

**Answer:** Always fetch DO=true, regardless of how the entry being replaced was originally fetched. (Deviates from the spec's "preserve whatever DO-fetched state produced the entry" wording — refresh always upgrades to a DNSSEC-complete fetch going forward.)

### Q7: Config naming

Confirm proposed `RefreshConfig` struct/field naming (following `CacheConfig` conventions) or provide different names?

**Answer:** Follow proposed naming: `RefreshConfig` with `enabled`/`bucket_capacity`/`leak_rate`/`hit_increment`/`hot_threshold`/`lead_ratio`/`min_lead`/`eligibility_floor`/`worker_count`/`channel_capacity`.

## Round 3

### Q8: Concrete defaults

Proposed: `enabled=true`, `bucket_capacity=10`, `leak_rate=1/60s`, `hit_increment=1`, `hot_threshold=50%` of bucket capacity, `lead_ratio=10%` of TTL, `min_lead=5s`, `eligibility_floor=15s` original TTL, `worker_count=4`, `channel_capacity=256`. Confirm or adjust?

**Answer:** Use as proposed. Exact numbers can still be tuned during TDD/implementation.

## Codebase facts established during research (not re-asked, decided directly)

- No production helper exists today to build a synthetic `Message`/`DecodedQuery` from `(qname, qtype, qclass, dnssec_ok)` — only test-only helpers (`query`/`query_with_edns` inside `#[cfg(test)] mod tests`, `resolver/mod.rs:8154+`). Plan will need a new small production helper for this.
- `OpenTelemetryMetrics::increment` (`src/main.rs:963`) is an exhaustive match over `ResolverMetric` — new refresh metric variants require new arms there and new counter fields, not just the enum addition.
- Per RUST.md ("add dependencies conservatively"), worker pool fan-out should use only `tokio::sync::mpsc` + `Arc<tokio::sync::Mutex<Receiver<Job>>>` shared across N worker loops — no new external crate (e.g. `async-channel`) needed for this.
