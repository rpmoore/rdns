Good, that's sufficient context. Now writing the section content.

---

# Section 06: Refresh Fetch + Store

## Dependencies

- **section-04-chainlookup-plumbing**: provides `RefreshHint { domain, qtype, qclass }` and threads `refresh_hints: Vec<RefreshHint>` through `ChainLookup::Answered` and `resolve_from_cache`. This section's epoch-recheck logic re-invokes the same `DomainDnsCache::lookup_chain` path that section-04 wires up.
- **section-05-worker-pool-metrics**: provides the `RefreshJob { domain: String, qtype: u16, qclass: u16 }` type, the bounded `tokio::sync::mpsc` channel, the fixed worker pool (`worker_count` fixed-size loop, `Arc<tokio::sync::Mutex<Receiver<RefreshJob>>>`, per-job `tokio::spawn` + `JoinHandle` panic isolation), the `ResolverMetric::{RefreshTriggered, RefreshQueueFull, RefreshSucceeded, RefreshFailed}` variants, and all `MetricsSink` impl updates (`OpenTelemetryMetrics`, `NoopMetricsSink`, test `RecordingMetrics` impls). Section-05's worker loop dequeues a `RefreshJob` and — per its own skeleton, initially a no-op — hands it off to whatever per-job processing function this section defines. **This section defines that function's real body.**

This section touches only `src/resolver/mod.rs`. No new files.

## Scope of this section

Implement the actual logic that runs for each dequeued `RefreshJob`:

1. Capture the current backend epoch first (before anything else in the job).
2. Re-check eligibility (lead window + epoch match) against that captured epoch.
3. Fetch the fresh answer via `ShardedSingleFlight`, with `dnssec_ok` always `true`, building a synthetic outbound query since no production helper for that exists yet.
4. Store the result directly via `cache_store_for_response`/`store_cache_response`, bypassing `prepare_backend_result`'s policy/rewrite/chaos layers.
5. Handle failure with no retry.

The entry point exposed to section-05's worker loop is a new inherent method on `ResolveQuery`:

```rust
impl ResolveQuery {
    /// Processes one dequeued `RefreshJob`: epoch-first eligibility recheck,
    /// synthetic-query fetch via singleflight, and direct cache store.
    /// Called by section-05's worker loop inside its own per-job
    /// `tokio::spawn`, so a panic in here is caught at the `JoinHandle`
    /// level by the caller, not here.
    async fn process_refresh_job(&self, job: RefreshJob) {
        // implemented by this section, see below
    }
}
```

(If section-05's skeleton already named this function differently, rename to match — the name itself isn't load-bearing, only that it is reachable from the per-job `tokio::spawn` call and has access to `&self: &ResolveQuery`.)

## Background: relevant existing code

### `ResolveQuery`'s fields (`src/resolver/mod.rs:3552-3594`)

`process_refresh_job` is an inherent method on `ResolveQuery`, so it has direct access to (relevant fields only):

```rust
pub struct ResolveQuery {
    protocol: Arc<dyn ProtocolCodec>,
    cache: Arc<dyn DomainDnsCache>,
    ttl_policy: CacheTtlPolicy,
    miss_coalescer: Arc<ShardedSingleFlight>,
    max_chain_depth: u8,
    backend: BackendHandle,
    clock: Arc<dyn Clock>,
    metrics: Arc<dyn MetricsSink>,
    // ...other fields (policy, local_entries, responses, events, chaos,
    // cookie_secret) not needed by this job path.
}
```

`self.clock.now()` (the `Clock` trait, already used elsewhere in this file, e.g. in `finish`) is the source of `now: SystemTime` for this job's eligibility recheck and store timestamp — do not use `SystemTime::now()` directly, for the same testability reasons the rest of this file avoids it.

### `BackendHandle::current()` (`src/resolver/mod.rs:2550-2568`)

```rust
#[derive(Clone)]
pub struct BackendHandle {
    snapshot: Arc<RwLock<Arc<BackendSnapshot>>>,
}

impl BackendHandle {
    pub fn current(&self) -> Arc<BackendSnapshot> { /* ... */ }
}
```

`BackendSnapshot` (`src/resolver/mod.rs:2441-2464`) — the fields this job needs:

```rust
pub struct BackendSnapshot {
    pub backend: Arc<dyn ResolutionBackend>,
    pub mode: ResolutionMode,       // Forward | Recursive
    pub generation: u64,
    pub cache_epoch: u64,
    // ...health, dnssec_validation, cache_namespace, root_hints — unused here
}
```

Read `self.backend.current()` exactly once at the top of `process_refresh_job` and reuse that one `Arc<BackendSnapshot>` for every subsequent step in the job (epoch, mode, and the actual backend call). Never re-read `self.backend.current()` mid-job — this is the same discipline every other store path in this file already follows (see `resolve_backend_and_finish`), and is what prevents a reload racing mid-refresh from tearing the epoch used for the recheck away from the epoch used for the eventual store.

### Epoch semantics (background, no new code needed here)

Per `docs/knowledge/resolver/caching/cache-epoch.md`: every cache entry carries a `cache_epoch: u64`; `DomainDnsCache::lookup_chain` treats an entry whose stored epoch doesn't match the epoch passed into the lookup as an ordinary miss — there is no separate "epoch mismatch" error variant to check for. This is exactly the mechanism the eligibility recheck (step 2 below) piggybacks on.

### `DomainDnsCache::lookup_chain` (`src/resolver/cache/mod.rs:120-129`)

```rust
pub trait DomainDnsCache: Send + Sync {
    fn lookup_chain(
        &self,
        qname: &str,
        qtype: u16,
        qclass: u16,
        dnssec_ok: bool,
        epoch: u64,
        max_chain_depth: u8,
        now: SystemTime,
    ) -> ChainLookup;
    // ...store_response, sweep_stale_namespace, domain_count, capacity
}
```

This is the *same* call `probe_cache` already makes (`src/resolver/mod.rs:4680`) and the same path section-04 wires `refresh_hints` through. Calling it again with the job's `(domain, qtype, qclass)`, `dnssec_ok = true`, the freshly captured epoch, `self.max_chain_depth`, and `self.clock.now()` gives a cheap, correct way to re-derive *both* halves of the eligibility recheck (lead-window-still-open and epoch-still-current) for free, using logic that already exists (section-03's trigger formula, threaded through by section-04) rather than duplicating it:

- If the epoch no longer matches, the underlying `lookup_hop` treats the entry as invisible and the lookup falls through to `ChainLookup::Miss` (or another non-`Answered` variant) — this **is** the epoch-mismatch abort case, with no separate check needed.
- If the lookup returns `ChainLookup::Answered { refresh_hints, .. }` but `refresh_hints` no longer contains an entry with this job's exact `(domain, qtype, qclass)`, the entry has moved out of the lead window (or is no longer hot) since the job was enqueued — abort, no fetch.
- Otherwise (the hint is still present), proceed to fetch.

This reuse is a deliberate implementation choice for this section: it keeps the epoch-then-lead-window ordering correct by construction (an epoch mismatch always shows up as *not `Answered`*, never as a stale-but-`Answered` result) instead of hand-rolling a second, parallel recheck path that could drift from section-03/04's actual trigger logic over time.

### `ShardedSingleFlight` (`src/resolver/cache/singleflight.rs`)

```rust
pub(crate) type MissKey = (String, u16, u16, u64, bool); // (qname, qtype, qclass, epoch, dnssec_ok)

pub(crate) enum SingleFlightTicket {
    Leader { key: MissKey, flight: Arc<InFlightMiss> },
    Follower { flight: Arc<InFlightMiss> },
}

pub(crate) struct SingleFlightLeader { /* ... */ }
impl SingleFlightLeader {
    pub(crate) fn complete(mut self, result: Result<ResolutionResponse, ResolutionBackendError>);
}

impl InFlightMiss {
    pub(crate) async fn wait(&self) -> Result<ResolutionResponse, ResolutionBackendError>;
}

impl ShardedSingleFlight {
    pub(crate) fn begin(&self, key: MissKey) -> SingleFlightTicket;
}
```

`self.miss_coalescer: Arc<ShardedSingleFlight>` is the exact same instance `probe_cache`'s caller path uses for real client misses. Build the `MissKey` for this job as `(job.domain.clone(), job.qtype, job.qclass, epoch, true)` — the `true` is the fixed `dnssec_ok` for all refresh jobs (decided in interview: a refresh always upgrades to a DNSSEC-complete fetch). Because `dnssec_ok` is baked into `MissKey`, this only coalesces with a concurrent *client* miss that itself has `dnssec_ok = true`; a `dnssec_ok = false` client miss for the same key becomes its own independent `Leader` (see the coalescing tests below — this is intentional, not a bug, and corrects an overstated claim in an earlier draft of this plan).

- On `SingleFlightTicket::Leader { key, flight }`: build the synthetic query (below), call `self.resolve_backend(&backend_snapshot, &synthetic_query).await` (existing private method, `src/resolver/mod.rs:4575-4595`, already used by the normal miss path — reuse it rather than duplicating its `ResolutionMode::Recursive` UDP-payload-bounding branch), then `leader.complete(result)`.
- On `SingleFlightTicket::Follower { flight }`: `flight.wait().await`.

Both branches converge on the same `Result<ResolutionResponse, ResolutionBackendError>`.

### Synthetic query builder (new production helper)

There is currently no production helper that builds a `DecodedQuery` from bare `(qname, qtype, qclass, dnssec_ok)` — only test-only equivalents exist (`query`/`query_with_edns` inside `#[cfg(test)] mod tests`, `src/resolver/mod.rs:8168,8189`, which build raw wire bytes by hand). Add a production version near those, following the same wire-byte-construction-then-parse approach (simplest correct way to get a `DecodedQuery` whose invariants — `question`, `question_wire`, `features` — are all derived consistently by `DecodedQuery::new`/`QuestionKey::from_message`/`QueryFeatures::from_message`, the exact same derivation every other decoded query goes through):

```rust
/// Builds a minimal outbound DecodedQuery for a synthetic, server-internal
/// refresh fetch — not a client-originated query. `dnssec_ok` is expected
/// to always be passed as `true` for refresh jobs (see `process_refresh_job`),
/// but the parameter is kept explicit rather than hardcoded so the function
/// itself stays a pure, independently testable builder.
fn build_refresh_query(qname: &str, qtype: u16, qclass: u16, dnssec_ok: bool) -> DecodedQuery {
    // Build a standard-query-shaped `Message` (opcode 0, qd_count 1,
    // an_count/ns_count 0, ar_count 0 or 1) with a single question for
    // (qname, qtype, qclass) and, since dnssec_ok is always true for
    // refresh jobs, a single EDNS OPT additional record with the DO flag
    // set. Parse it back through `Message::parse_standard_query` (the same
    // validation every client query goes through, per
    // `validate_standard_query_header`/`validate_standard_query_body`,
    // `src/protocol/mod.rs:2061-2106`) and hand the result to
    // `DecodedQuery::new`, mirroring `StandardProtocolCodec::decode_query`
    // (`src/resolver/mod.rs:5842-5845`) exactly.
    unimplemented!()
}
```

Relevant existing struct shapes needed to build the `Message` by hand (`src/protocol/mod.rs:144-217`):

```rust
pub struct Message {
    pub header: Header,
    pub original_bytes: Bytes,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub edns: Option<EdnsInfo>,
}
pub struct Header { pub id: u16, pub flags: u16, pub qd_count: u16, pub an_count: u16, pub ns_count: u16, pub ar_count: u16 }
pub struct Question { pub qname: String, pub qtype: u16, pub qclass: u16 }
pub struct EdnsInfo { pub udp_payload_size: u16, pub extended_rcode: u8, pub version: u8, pub flags: u16, pub dnssec_ok: bool, pub options: Vec<u8> }
```

The simplest correct implementation path (matching the existing test helpers `query`/`query_with_edns` byte-for-byte in shape) is to build raw wire bytes for a standard query with RD set, one question, and (since `dnssec_ok` is always `true` here) exactly one EDNS OPT additional record with the DO flag (`EDNS_DO_FLAG`, already defined in this module) set, then call `Message::parse_standard_query(&bytes)` followed by `DecodedQuery::new(message)`. Both of those calls already exist and are exercised by every other query path in this file; `unwrap()` is acceptable here since the bytes are constructed by this function itself and always well-formed by construction — an internal invariant violation here is a bug in `build_refresh_query`, not a runtime condition to recover from.

### `cache_store_for_response`/`store_cache_response` (`src/resolver/mod.rs:5400-5458`)

```rust
async fn store_cache_response(
    &self,
    epoch: u64,
    response: &Message,
    question: &QuestionKey,
    request: &ResolveRequest,
    dnssec_ok: bool,
    store_authoritative: bool,
) {
    if let Some(decomposed) = self.cache_store_for_response(
        response, question, request.received_at.0, dnssec_ok, store_authoritative,
    ) {
        if decomposed.negative.is_some() {
            self.metrics.increment(ResolverMetric::CacheNegativeStore);
        }
        self.metrics.increment(ResolverMetric::CacheStore);
        self.cache.store_response(decomposed, epoch);
    } else {
        self.metrics.increment(ResolverMetric::CacheStoreSkipped);
    }
}
```

`store_cache_response` only reads `request.received_at.0` off `ResolveRequest` — every other field (`client_ip`, `observed_source`, `request_id`, `bytes`) is unused by this call path. Fabricate a minimal `ResolveRequest` purely to carry that timestamp:

```rust
let synthetic_request = ResolveRequest::new(
    Ipv4Addr::UNSPECIFIED.into(),
    self.clock.now(),
    Vec::new(), // bytes: unused by store_cache_response
);
```

(`ResolveRequest::new`, `src/resolver/mod.rs:192-201`, derives `observed_source` and `request_id` automatically; both are irrelevant here since neither is read by `store_cache_response`.)

Call `self.store_cache_response(epoch, &response_message, &question, &synthetic_request, dnssec_ok, store_authoritative)` where:

- `epoch` is the captured epoch from step 1 (not re-read).
- `response_message` comes from validating the fetched `ResolutionResponse` — reuse the existing private free function `validate_backend_response(&mut response, &synthetic_query) -> Option<Message>` (`src/resolver/mod.rs:5755-5768`), the same validation `prepare_backend_result` itself calls. A `None` result (malformed/question-mismatched response) is treated the same as any other failure (step 6 below): increment `RefreshFailed`, stop.
- `question` is `synthetic_query.question.clone()` (a `QuestionKey`).
- `dnssec_ok` for the *store* call, and `store_authoritative`, must be computed with **exactly the same logic `prepare_backend_result` already uses** (`src/resolver/mod.rs:4985-5004`), so a refresh-stored entry is structurally indistinguishable from what the normal miss path would have stored for the same response (this is what the `job_store_matches_normal_miss_path_shape` invariant test checks):

  ```rust
  let store_dnssec_ok = match backend_snapshot.mode {
      ResolutionMode::Recursive => true,
      ResolutionMode::Forward => true, // refresh jobs always fetch with dnssec_ok = true
  };
  let store_authoritative = match backend_snapshot.mode {
      ResolutionMode::Recursive => false,
      ResolutionMode::Forward => response_message.header.aa(),
  };
  ```

  (Note `store_dnssec_ok` collapses to `true` in both arms for a refresh job specifically, since the synthetic query itself always sets `dnssec_ok = true` — unlike `prepare_backend_result`'s general case, which depends on the *original requester's* DO flag for `ResolutionMode::Forward`.)

Do **not** call `prepare_backend_result` itself — it also runs policy-block checks, response rewriting (`rewrite_response_request_fields`), UDP-truncation/reserialization, and chaos injection, none of which apply to a server-internal refresh fetch. Calling straight through to `cache_store_for_response`/`store_cache_response` is the deliberate, documented bypass.

### Metrics (from section-05, referenced not redefined here)

`self.metrics.increment(ResolverMetric::RefreshSucceeded)` and `self.metrics.increment(ResolverMetric::RefreshFailed)` — both variants and the `MetricsSink` impl updates are section-05's responsibility; this section only calls `increment` with them.

## Implementation: `process_refresh_job` step by step

```rust
async fn process_refresh_job(&self, job: RefreshJob) {
    // 1. Capture epoch first — reused for every subsequent step, never
    //    re-read mid-job.
    let backend_snapshot = self.backend.current();
    let epoch = backend_snapshot.cache_epoch;
    let now = self.clock.now();

    // 2. Re-check eligibility against that captured epoch (also catches an
    //    epoch mismatch from a reload that happened while this job sat in
    //    the channel — see cache-epoch.md: lookup_hop treats that as a miss).
    let recheck = self.cache.lookup_chain(
        &job.domain, job.qtype, job.qclass, /* dnssec_ok */ true,
        epoch, self.max_chain_depth, now,
    );
    let still_eligible = matches!(
        &recheck,
        ChainLookup::Answered(resolved)
            if resolved.refresh_hints.iter().any(|hint| {
                hint.domain == job.domain && hint.qtype == job.qtype && hint.qclass == job.qclass
            })
    );
    if !still_eligible {
        return; // no metric beyond what's already covered — see plan §4.3 step 2
    }

    // 3+4. Fetch via singleflight, dnssec_ok always true.
    let miss_key: MissKey = (job.domain.clone(), job.qtype, job.qclass, epoch, true);
    let synthetic_query = build_refresh_query(&job.domain, job.qtype, job.qclass, true);
    let fetch_result = match self.miss_coalescer.begin(miss_key) {
        SingleFlightTicket::Leader { key, flight } => {
            let leader = SingleFlightLeader::new(Arc::clone(&self.miss_coalescer), key, flight);
            let result = self.resolve_backend(&backend_snapshot, &synthetic_query).await;
            leader.complete(result.clone());
            result
        }
        SingleFlightTicket::Follower { flight } => flight.wait().await,
    };

    // 5/6/7. Store on success, no-retry on failure.
    match fetch_result {
        Ok(mut response) => {
            let Some(response_message) = validate_backend_response(&mut response, &synthetic_query) else {
                self.metrics.increment(ResolverMetric::RefreshFailed);
                return;
            };
            let store_authoritative = match backend_snapshot.mode {
                ResolutionMode::Recursive => false,
                ResolutionMode::Forward => response_message.header.aa(),
            };
            let synthetic_request = ResolveRequest::new(Ipv4Addr::UNSPECIFIED.into(), now, Vec::new());
            self.store_cache_response(
                epoch, &response_message, &synthetic_query.question,
                &synthetic_request, /* dnssec_ok */ true, store_authoritative,
            ).await;
            self.metrics.increment(ResolverMetric::RefreshSucceeded);
        }
        Err(_) => {
            self.metrics.increment(ResolverMetric::RefreshFailed);
            // No retry — matches plan §4.3 step 6 exactly. Stale entry left
            // untouched; the domain falls back to ordinary reactive-miss
            // behavior once it actually expires.
        }
    }
}
```

Notes on this sketch (implementer should treat exact variable plumbing above as illustrative, not literal — `RefreshJob`'s exact field names/visibility come from section-05):

- `SingleFlightLeader::new` is `pub(crate)` in `cache::singleflight` — check it's actually reachable from `resolver::mod` (it's used today via the module's existing miss path, so it should already be in scope via the `use cache::{... SingleFlightLeader ...}` import at the top of `src/resolver/mod.rs:48`).
- `leader.complete(result.clone())` requires `ResolutionResponse` to be `Clone` (it already derives `Clone`, confirmed at `src/resolver/mod.rs:2360`).
- The re-check's `ChainLookup::Answered(resolved)` destructuring assumes section-04 names the inner payload type sensibly (e.g. a struct with a `refresh_hints: Vec<RefreshHint>` field) — adjust field access to match whatever section-04 actually produces; the *behavior* (checking that this exact `(domain, qtype, qclass)` still appears in the hints for the re-probed lookup) is what matters, not the exact destructuring syntax.

## Tests first (write before implementing, from `claude-plan-tdd.md` §4.3)

All are `#[tokio::test]` per this codebase's convention for anything touching singleflight or the resolver (see intro to `claude-plan-tdd.md`: real concurrent `tokio::spawn` interleaving, `tokio::task::yield_now()` to force scheduling points where needed). Build via `ResolveQuery::with_cache(...)`/`with_cache_and_backend_snapshot(...)` with `StaticUpstream` (scripted request/response recording) or `ScriptedAuthorityTransport` (queued scripted responses) as the fake backend — both already exist in this codebase's test helpers for `resolver::mod`.

- `job_captures_epoch_before_recheck`: verifies ordering — epoch is read once (via `BackendHandle::current()`), and the eligibility recheck is evaluated against that same epoch snapshot, not a value re-read later in the job.
- `job_aborts_on_epoch_mismatch`: a job whose entry's stored `cache_epoch` no longer matches the freshly captured epoch (simulate a reload — e.g. call `publish_reload`/equivalent between enqueue and processing) aborts cleanly: no store call happens, no panic, and (per the recheck design above) this surfaces as the re-probe `lookup_chain` call returning a non-`Answered` variant.
- `job_rechecks_lead_window_before_fetch`: a job that's no longer within the lead window (e.g. the entry was already refreshed by another trigger, or time has simply progressed past the window) aborts without ever calling `resolve_backend` — assert via the fake backend's recorded-request log staying empty for that job.
- `job_fetch_uses_dnssec_ok_true_always`: build the job from an entry whose *original* stored `dnssec_ok`/`dnssec_complete` was `false`; assert the outbound synthetic query built for the backend call has `features.dnssec_ok == true` regardless (inspect via the fake backend's recorded request, or via `MissKey`'s captured `dnssec_ok` field).
- `job_coalesces_with_concurrent_do_true_client_miss`: spawn a refresh job and a concurrent real client miss for the identical `(qname, qtype, qclass)` with `dnssec_ok = true` on the client side too; assert both resolve from a single backend call (`StaticUpstream`'s recorded-request count is 1) via `Leader`/`Follower`.
- `job_does_not_coalesce_with_do_false_client_miss`: same setup, but the concurrent client miss has `dnssec_ok = false`; assert **two** independent backend calls happen (both `Leader`s), and both the refresh job and the client miss complete successfully and store correctly — the corrected-claim regression test for the earlier draft's overclaim.
- `job_store_matches_normal_miss_path_shape`: for an identical backend response, assert a refresh-triggered store (via `process_refresh_job`) produces a cache entry structurally equivalent (same TTL computation, same RRset decomposition, same `dnssec_complete`/`authoritative` flags) to what feeding the same response through the normal client-miss path (`prepare_backend_result` → `store_cache_response`) would produce. This is the test that pins down the `store_dnssec_ok`/`store_authoritative` computation shown above.
- `job_failure_no_retry_leaves_entry_untouched`: script the fake backend to fail (timeout, SERVFAIL, NXDOMAIN, or a transport error — cover at least one) for the refresh fetch; assert `RefreshFailed` increments exactly once, the stale entry's `expires_at` is unchanged after the job completes, and no second backend call happens (no retry).
- `job_success_advances_expires_at_and_exits_lead_window`: script a successful fetch; assert the entry's `expires_at` after the job completes is later than before, and a subsequent lead-window check (re-running the same trigger formula / `lookup_chain` probe) no longer signals refresh for this entry.

Additionally, add a focused unit-style test for the new helper itself:

- `build_refresh_query_always_sets_do_flag`: for both `dnssec_ok = true` and `dnssec_ok = false` inputs, assert the returned `DecodedQuery.features.dnssec_ok` matches the input parameter (the *function* is a faithful pure builder; it's the *caller*, `process_refresh_job`, that always passes `true` — keeping the builder itself parameterized is what makes this test possible and keeps the builder's own correctness decoupled from the fixed-`true` policy decision).

## Verification gates

Standard gates before this section is considered done, per `RUST.md`: `cargo fmt`, `cargo clippy`, `cargo test`. Given this section touches singleflight coalescing and epoch semantics directly, run the full `src/resolver/mod.rs` test module plus `src/resolver/cache/singleflight.rs`'s tests, not just the new tests in isolation — the coalescing tests in particular are sensitive to interactions with the *existing* client-miss singleflight tests.

---

Relevant file: `/home/rpmoore/code/rdns/src/resolver/mod.rs` (all new code — `process_refresh_job`, `build_refresh_query`, and their tests — lands here; no new files created).

I've written the section content directly (per the harness's SubagentStop hook, no separate report file needed). Key source locations consulted while drafting this section, for reference:

- `/home/rpmoore/code/rdns/src/resolver/mod.rs:3552-3594` (`ResolveQuery` fields), `2550-2568` (`BackendHandle`), `2441-2464` (`BackendSnapshot`), `4575-4595` (`resolve_backend`), `4916-5017` (`prepare_backend_result`'s store-flag logic, mirrored for the invariant test), `5400-5458` (`store_cache_response`/`cache_store_for_response`), `5755-5768` (`validate_backend_response`), `8164-8208` (test-only `query`/`query_with_edns` wire-byte builders, the template for `build_refresh_query`).
- `/home/rpmoore/code/rdns/src/resolver/cache/mod.rs:101-172` (`DomainDnsCache`/`lookup_chain`).
- `/home/rpmoore/code/rdns/src/resolver/cache/singleflight.rs:73-233` (`MissKey`, `ShardedSingleFlight`, `SingleFlightTicket`/`Leader`/`Follower`, `InFlightMiss`).
- `/home/rpmoore/code/rdns/src/protocol/mod.rs:144-217` (`Message`/`Header`/`Question`/`EdnsInfo`), `2061-2106` (standard-query validation rules `build_refresh_query`'s wire bytes must satisfy).
- `/home/rpmoore/code/rdns/docs/knowledge/resolver/caching/cache-epoch.md` (epoch-mismatch-is-a-miss semantics underpinning the recheck design).

The generated section file was written to `/home/rpmoore/code/rdns/docs/plans/auto_refresh/sections/section-06-refresh-fetch-store.md`.

## Implementation Notes (post-implementation)

Implemented as a real body inside section-05's existing `process_refresh_job`
free function (`resolver: Arc<ResolveQuery>, job: RefreshJob`) rather than as
a new inherent method, since section-05 had already defined it that shape;
the plan's sketch used `&self` but the actual signature wasn't load-bearing
per the plan's own note. `build_refresh_query` added as a new production
free function.

**Deviation from plan, found via a failing self-authored test**: the
plan's own recheck (step 2) used `dnssec_ok = true` (matching the fetch's
own DO flag). This is wrong: `take_live_positive`/`take_live_cname_hop`
treat any entry with `dnssec_complete = false` as invisible to a
`dnssec_ok = true` reader — so a `true` recheck would permanently exclude
any domain whose cached answer originated from a DO=false query, silently
defeating refresh for that whole class of domain forever. Fixed to
`dnssec_ok = false` for the recheck specifically (the actual fetch in step
3 still always uses `true`, per the confirmed interview decision) — the
recheck's only job is confirming "still live, in-window, hot," independent
of DNSSEC completeness. Caught by `job_fetch_uses_dnssec_ok_true_always`,
which failed until this fix landed.

**Code review found two further real bugs**, both fixed:
- `build_refresh_query` originally used `.expect()`-based construction that
  wasn't actually guaranteed well-formed (an oversized label could silently
  truncate via `as u8`, or panic downstream with no `RefreshFailed`
  recorded). Now returns `Option<DecodedQuery>` with an explicit
  `label.len() > 63` guard; the caller treats `None` as a clean
  `RefreshFailed`, never a panic.
- `process_refresh_job` never checked the fetched response's
  `ResolutionCacheDirective::is_cacheable()` before storing —
  `prepare_backend_result` gates its own store on exactly this, and a
  refresh could otherwise force-cache a response the backend explicitly
  marked `DoNotCache`. This gap existed in the plan's own pseudocode too.
  Fixed with the same check, incrementing `RefreshFailed` on the
  not-cacheable path.

**Documented, not fixed — flagged for section-07**: the recheck's reuse of
`lookup_hop` (a deliberate design choice, confirmed correct by research) has
a side effect: every recheck itself counts as a popularity hit and an LRU
touch, meaning a refresh cycle can contribute its own "traffic" toward
staying hot, independent of real client demand. For a domain whose lead
window recurs faster than its popularity bucket's leak rate, this could
theoretically sustain refreshing indefinitely after real demand stops —
directly relevant to the plan's own stated end-to-end requirement ("a
domain that stops being queried stops getting refreshed"). Not fixed here
since the only fix is a second, side-effect-free recheck path, which
contradicts this design's explicit choice to reuse `lookup_chain` rather
than hand-roll a parallel one. Documented in detail at the recheck call
site; **section-07's end-to-end verification should specifically test a
short-TTL/fast-refresh-cycle domain**, not just a long-TTL one, to confirm
whether this is a practical problem with the shipped defaults.

Also documented (not a bug): if this job ever runs as a singleflight
Follower (behind some other Leader — a real client miss, or another
refresh job racing the same key), it still independently calls
`store_cache_response` on the shared result — a deliberate, harmless
redundancy (last store wins, same underlying data) rather than something
worth special-casing away.

**Test coverage**: 11 tests (`claude-plan-tdd.md` §4.3's full list plus a
label-length guard test), using a `permissive_refresh_config()` helper
(`hot_threshold_fraction=0.0`, `lead_ratio=1.0`, `min_lead=0`,
`eligibility_floor=0`) to make freshly-stored test entries trivially
eligible without simulating real near-expiry timing. The two coalescing
tests directly drive a second `miss_coalescer.begin()` call from a
concurrent task (rather than a full `.resolve()` call) since a live,
non-expired entry under `FixedClock` is always a normal cache hit through
`.resolve()` and never reaches singleflight — this is also why a reverse
"refresh job as Follower behind a genuine client Leader" test isn't
included: it's only constructible via real wall-clock timing (this
codebase's tests deliberately avoid sleep-based correctness assertions), or
not at all deterministically, since singleflight only activates on a
genuine miss and the refresh job's own recheck requires a *live* entry to
even reach the fetch step.

All of `RUST.md`'s gates pass: `cargo fmt`, `cargo clippy --all-targets`
(warning-free), `cargo test` (full suite, 667 lib tests passing).