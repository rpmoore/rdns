# Remediation Plan: Catch Up Through Phase 4

## Scope
Bring the current implementation into compliance with the documented roadmap through **Phase 4 (Query Event Pipeline and In-Memory Review Model)**.

## Phase 1: Safe DNS Protocol Core
1. **No feature remediation required** based on current tests and module structure.
2. Record explicit Phase 1 compliance evidence (parser safety, compression handling, EDNS visibility, truncation behavior, TCP framing) so later phases can rely on a locked baseline.

## Phase 2: DNS Runtime and Upstream Forwarding
1. **No feature remediation required** for core forwarding behavior.
2. Record Phase 2 compliance evidence for upstream validation, timeout/deadline behavior, deterministic failover, and TCP fallback so Phase 4 event taxonomy can classify backend outcomes correctly.

## Phase 3: In-Memory Cache
1. **No feature remediation required** for core cache behavior.
2. Record Phase 3 compliance evidence for cache key semantics, TTL derivation, conservative bypass behavior, and single-flight miss handling so Phase 4 events can report accurate cache outcomes.

## Phase 4: Query Event Pipeline and In-Memory Review Model
1. Replace the current decision-only sink contract with a **structured Phase 4 event pipeline contract** centered on `QueryEventV1`.
2. Expand event taxonomy into distinct fields for terminal outcome, DNS response code, policy decision, cache result, backend result, and advisory classifier findings.
3. Implement **non-blocking event ingestion** via background task processing so DNS responses never wait on queueing, storage, classification, or read-model updates.
4. Add bounded ingestion with explicit overflow modes: disabled, drop newest, drop oldest, sample, and accept.
5. Add event-pipeline metrics for accepted, dropped, sampled, and disabled outcomes, including reason labels and overflow-mode attribution.
6. Add a bounded in-memory query-event store with explicit retention bounds (max retained events and max indexed sources/domains), timestamp+sequence ordering, and dropped/sampled summary indicators.
7. Add internal source-centric read-model ports for recent events, suspicious events, per-observed-source history, domain history, and top suspicious observed sources/domains. Keep these internal in Phase 4 and defer authenticated external API/UI exposure to later phases.
8. Add an advisory suspicious lookup classifier port with explainable/versioned findings metadata.
9. Implement initial in-memory suspicious heuristics over retained events (NXDOMAIN/SERVFAIL burst detection, repeated TXT lookups, high-entropy names, rare/new domains in retention window, suspicious TLD/domain selectors), including incomplete-baseline signaling after restart/eviction/sampling/drops.
10. Ensure all source-facing semantics use **observed source endpoint** terminology and avoid implying strong identity.
11. Add Phase 4 test coverage for event emission, non-blocking behavior under slow/failing processors, disabled logging, overflow policy behavior, retention eviction, source filtering, schema/version handling, classifier explanations, threshold boundaries, cold start behavior, and processor-failure isolation.

## Completion Gate (Phase 4 Compliant)
- Every terminal query outcome either emits a `QueryEventV1` record or increments dropped/sampled/disabled counters by reason.
- Event processing failures do not delay DNS responses.
- In-memory read models return bounded source-centric and suspicious-review data.
- Classifier output is advisory, explainable, versioned, and clearly separated from policy blocking.
