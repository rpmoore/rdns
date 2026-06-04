# Implementation Steps

This checklist turns the plan in [`docs/plan`](plan/00-overview.md) into iterative implementation work. Each step links back to the plan section it implements and should be completed with tests appropriate to the risk in that step.

## Cross-Phase Latency Requirements

Apply latency requirements in every phase, not only after Phase 4.

1. Define or reaffirm the latency and throughput budgets affected by the phase before phase completion.
2. Measure and record DNS hot-path (query processing critical path) p50/p95/p99 latency impact during phase validation, even when the phase focuses on correctness or feature wiring.
3. Add and validate latency gates for new paths introduced by the phase (for example query-event queueing, persistence, ingestion, API, or UI-backed operations).
4. Do not close a phase if measured latency regresses beyond documented budgets unless the budget update is explicitly approved and recorded.

## Phase 1: Safe DNS Protocol Core

1. Create the protocol module boundary.
   - Implements: [Architectural Direction](plan/00-overview.md#architectural-direction), [DNS Protocol Responsibility](plan/01-dns-protocol.md#responsibility), [Milestone 1](plan/08-implementation-roadmap.md#milestone-1-safe-dns-protocol-core).
   - Move the reusable pieces of `src/dns.rs` into a `protocol` module without adding resolver, policy, or I/O concerns.

2. Add checked packet reading and structured parse errors.
   - Implements: [Existing Code To Rework](plan/01-dns-protocol.md#existing-code-to-rework), [Error Model](plan/01-dns-protocol.md#domain-model), [Remaining Primary Risks](plan/00-overview.md#remaining-primary-risks).
   - Replace unchecked indexing, slicing, `unwrap`, and `unimplemented!` paths with `Result<T, DnsParseError>` and an `Unknown { rtype, bytes }` record variant.

3. Correct DNS name parsing and compression handling.
   - Implements: [Existing Code To Rework](plan/01-dns-protocol.md#existing-code-to-rework), [Query Constraints](plan/01-dns-protocol.md#query-constraints), [Reviewer Concern Matrix](plan/09-reviewer-concerns.md#concern-response-matrix).
   - Parse compression pointers against full-message offsets, detect pointer loops, reject invalid targets, and enforce DNS label and full-name limits.

4. Model supported query shapes and conservative protocol failures.
   - Implements: [Query Constraints](plan/01-dns-protocol.md#query-constraints), [Core Runtime Flow](plan/00-overview.md#core-runtime-flow).
   - Accept standard one-question recursive `QUERY` messages, reject unsupported opcodes and multi-question messages with explicit response-code behavior, and expose parse failures cleanly to resolver code.

5. Add minimal EDNS visibility and UDP-size handling.
   - Implements: [Query Constraints](plan/01-dns-protocol.md#query-constraints), [UDP Size And Truncation](plan/01-dns-protocol.md#udp-size-and-truncation), [Second Review Additions](plan/09-reviewer-concerns.md#second-review-additions).
   - Parse `OPT` enough to expose advertised UDP payload size and DNSSEC `DO`; clamp response sizes and produce truncated responses when needed.

6. Add generic response builders and ID rewrite helpers.
   - Implements: [Response Construction](plan/01-dns-protocol.md#response-construction), [Block Response Mode](plan/03-policy-blocking.md#block-response-mode), [Cache Design](plan/02-resolver-cache.md#cache-design).
   - Build `FORMERR`, `REFUSED`, `NXDOMAIN`, `NODATA`, sinkhole, and truncated responses while keeping policy reasons outside the protocol module.

7. Add TCP DNS framing helpers.
   - Implements: [TCP Framing](plan/01-dns-protocol.md#tcp-framing), [DNS TCP behavior concern](plan/09-reviewer-concerns.md#concern-response-matrix).
   - Implement length-prefix encode/decode, maximum message-size checks, and timeout-friendly framing APIs before the listener is added.

8. Lock down protocol tests and robustness fixtures.
   - Implements: [DNS Protocol Tests](plan/01-dns-protocol.md#tests), [Operations Test Strategy](plan/07-operations-testing.md#test-strategy), [Milestone 1 Exit Criteria](plan/08-implementation-roadmap.md#milestone-1-safe-dns-protocol-core).
   - Cover valid records, malformed packets, unknown records, compression failures, serializer output, EDNS behavior, UDP truncation, TCP framing, and the no-panic invariant.

## Phase 2: DNS Runtime And Upstream Forwarding

9. Introduce resolver application-service ports.
   - Implements: [Application Service](plan/02-resolver-cache.md#application-service), [Dependency Direction](plan/00-overview.md#dependency-direction), [Concern: ResolveQuery Size](plan/02-resolver-cache.md#concern-resolvequery-size).
   - Define `ProtocolCodec`, `PolicyEvaluator`, `DnsCache`, `UpstreamResolver`, `ResponseFactory`, `Clock`, `QueryEventSink`, and `MetricsSink` traits around the `ResolveQuery` orchestration flow.

10. Implement the first `ResolveQuery` flow without cache or policy complexity.
    - Implements: [Resolver Flow](plan/02-resolver-cache.md#flow), [Core Runtime Flow](plan/00-overview.md#core-runtime-flow), [Milestone 2](plan/08-implementation-roadmap.md#milestone-2-dns-server-and-upstream-forwarding).
    - Parse the request, build a normalized question key, forward allowed requests to upstream, return protocol errors where possible, and emit basic decision metadata.

11. Add static runtime configuration for DNS listen and upstreams.
    - Implements: [Forwarding Resolution](plan/02-resolver-cache.md#forwarding-resolution), [Configuration Reload](plan/05-persistence-config.md#configuration-reload), [Deployment Notes](plan/07-operations-testing.md#deployment-notes).
    - Start with validated static settings on high local ports and at least one enabled upstream.

12. Add UDP DNS listener delivery adapter.
    - Implements: [Architectural Direction](plan/00-overview.md#architectural-direction), [Milestone 2 Tasks](plan/08-implementation-roadmap.md#milestone-2-dns-server-and-upstream-forwarding), [Runtime Concerns](plan/07-operations-testing.md#runtime-concerns).
    - Use Tokio UDP I/O, pass raw request bytes and client source IP into `ResolveQuery`, and keep socket handling out of domain code.

13. Implement upstream UDP forwarding.
    - Implements: [Forwarding Resolution](plan/02-resolver-cache.md#forwarding-resolution), [Failure Behavior](plan/02-resolver-cache.md#failure-behavior), [Security Considerations](plan/07-operations-testing.md#security-considerations).
    - Generate fresh upstream transaction IDs, validate upstream source endpoint, response ID, and question match, then map the response back to the client request.

14. Add deterministic upstream failover and deadlines.
    - Implements: [Initial Forwarding Strategy](plan/02-resolver-cache.md#forwarding-resolution), [Failure Behavior](plan/02-resolver-cache.md#failure-behavior), [Upstream behavior concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Try enabled upstreams in priority order with per-upstream timeouts, a per-query deadline, bounded attempts, degraded health marking, and defined `SERVFAIL` fallback.

15. Add TCP upstream fallback for truncated UDP upstream responses.
    - Implements: [UDP Size And Truncation](plan/01-dns-protocol.md#udp-size-and-truncation), [TCP Framing](plan/01-dns-protocol.md#tcp-framing), [Milestone 2 Reviewer Gates](plan/08-implementation-roadmap.md#milestone-2-dns-server-and-upstream-forwarding).
    - Use DNS-over-TCP framing for upstream fallback when a UDP response has `TC`; if temporarily deferred, document the conservative failure behavior in the relevant plan file.

16. Add forwarding integration tests.
    - Implements: [Resolver Integration Tests](plan/02-resolver-cache.md#tests), [Operations Integration Tests](plan/07-operations-testing.md#test-strategy), [Milestone 2 Exit Criteria](plan/08-implementation-roadmap.md#milestone-2-dns-server-and-upstream-forwarding).
    - Use fake UDP/TCP upstreams to test forwarding, timeout-to-`SERVFAIL`, malformed-response rejection, source/ID mismatch rejection, failover, and graceful shutdown.

## Phase 3: In-Memory Cache

17. Define cache key and value types.
    - Implements: [Cache Design](plan/02-resolver-cache.md#cache-design), [Cache correctness concern](plan/09-reviewer-concerns.md#concern-response-matrix), [Milestone 3](plan/08-implementation-roadmap.md#milestone-3-in-memory-cache).
    - Include normalized name, qtype, qclass, supported request features, upstream policy variant where needed, and response-size-sensitive behavior.

18. Implement in-memory TTL cache with bounded size.
    - Implements: [Cache Design](plan/02-resolver-cache.md#cache-design), [Concurrency](plan/02-resolver-cache.md#cache-design), [Security Considerations](plan/07-operations-testing.md#security-considerations).
    - Add concurrent-safe lookup/store, expiry, size bound, eviction policy, and small lock scopes.

19. Implement positive and negative TTL calculation.
    - Implements: [TTL Policy](plan/02-resolver-cache.md#cache-design), [Failure Behavior](plan/02-resolver-cache.md#failure-behavior).
    - Use minimum answer TTL for positive responses, SOA-derived TTL for negative responses, local caps, and explicit rules for unsupported or failure responses.

20. Cache safe response templates only.
    - Implements: [Cache Design](plan/02-resolver-cache.md#cache-design), [Poisoning Boundaries](plan/02-resolver-cache.md#cache-design), [Second Review Additions](plan/09-reviewer-concerns.md#second-review-additions).
    - Store canonical templates or exact-question RRsets, rewrite the client transaction ID and request-dependent fields through protocol helpers, and avoid reusing unrelated additional records.

21. Add cache bypass paths for unsupported semantics.
    - Implements: [Query Constraints](plan/01-dns-protocol.md#query-constraints), [Cache Design](plan/02-resolver-cache.md#cache-design), [Milestone 3 Reviewer Gates](plan/08-implementation-roadmap.md#milestone-3-in-memory-cache).
    - Bypass cache for DNSSEC/EDNS/query features the resolver does not understand enough to cache safely.

22. Add single-flight miss handling.
    - Implements: [Concurrency](plan/02-resolver-cache.md#cache-design), [Resolver Tests](plan/02-resolver-cache.md#tests).
    - Ensure simultaneous misses for the same cache key share one upstream lookup without holding cache locks during network I/O.

23. Add cache metrics and tests.
    - Implements: [Metrics](plan/07-operations-testing.md#metrics), [Resolver Tests](plan/02-resolver-cache.md#tests), [Milestone 3 Exit Criteria](plan/08-implementation-roadmap.md#milestone-3-in-memory-cache).
    - Cover hit, miss, expiry, negative caching, unsupported-feature bypass, current request ID rewrite, response-size truncation on cached output, and duplicate-miss coalescing.

## Phase 4: Query Event Pipeline And In-Memory Review Model

24. [Define the query event schema and taxonomy](https://github.com/rpmoore/rdns/issues/18).
    - Implements: [Query Event Pipeline](plan/02-resolver-cache.md#query-event-pipeline), [Milestone 4](plan/08-implementation-roadmap.md#milestone-4-query-event-pipeline-and-in-memory-review-model).
    - Add a minimal `QueryEventV1` with schema version, sequence number, timestamp, observed source endpoint, original and normalized question, qtype/qclass, terminal outcome, local DNS response code, cache result, latency, and advisory classifier findings. Keep backend, policy, blocklist, and response-inspection data as optional later extensions.

25. [Make query-event recording non-blocking](https://github.com/rpmoore/rdns/issues/19).
    - Implements: [Query Event Pipeline](plan/02-resolver-cache.md#query-event-pipeline), [Metrics](plan/07-operations-testing.md#metrics), [Milestone 4](plan/08-implementation-roadmap.md#milestone-4-query-event-pipeline-and-in-memory-review-model).
    - Change or wrap `QueryEventSink` so the resolver hot path never waits on queue capacity, classification, storage, or read-model updates. Define disabled, drop-newest, drop-oldest, sample, and accepted outcomes with metrics.

26. [Emit one terminal event per client query](https://github.com/rpmoore/rdns/issues/20).
    - Implements: [Query Event Pipeline](plan/02-resolver-cache.md#query-event-pipeline), [Resolver Flow](plan/02-resolver-cache.md#flow).
    - Record every terminal outcome: answered from backend/upstream, answered from cache, protocol error when source is known, backend failure, and later policy/blocklist blocks. Keep `AllowedFromBackend` distinct from `AllowedFromCache`.

27. [Add bounded in-memory query-event storage](https://github.com/rpmoore/rdns/issues/21).
    - Implements: [In-Memory Review Model](plan/02-resolver-cache.md#in-memory-review-model), [Security Considerations](plan/07-operations-testing.md#security-considerations).
    - Store recent events in bounded memory with max retained events, max indexed sources/domains, optional retention duration, timestamp-plus-sequence ordering, and dropped/sampled summary indicators.

28. [Add source-centric review read models](https://github.com/rpmoore/rdns/issues/22).
    - Implements: [In-Memory Review Model](plan/02-resolver-cache.md#in-memory-review-model), [Milestone 4 Exit Criteria](plan/08-implementation-roadmap.md#milestone-4-query-event-pipeline-and-in-memory-review-model).
    - Provide internal read-model ports for recent events, suspicious events, per-observed-source history, per-source suspicious summary, domain history, and top suspicious observed sources/domains. Do not expose real UI/API access before authenticated admin APIs exist.

29. [Add advisory suspicious lookup classifier scaffolding](https://github.com/rpmoore/rdns/issues/23).
    - Implements: [Suspicious Lookup Classification](plan/02-resolver-cache.md#suspicious-lookup-classification), [Milestone 4](plan/08-implementation-roadmap.md#milestone-4-query-event-pipeline-and-in-memory-review-model).
    - Add a `SuspiciousLookupClassifier` port with explainable findings: classifier version, config generation, reason, severity/score, evaluated window, and structured details. Keep findings advisory and non-blocking.

30. [Add initial in-memory suspicious heuristics](https://github.com/rpmoore/rdns/issues/24).
    - Implements: [Suspicious Lookup Classification](plan/02-resolver-cache.md#suspicious-lookup-classification), [Test Strategy](plan/07-operations-testing.md#test-strategy).
    - Start with heuristics that only need retained events, such as NXDOMAIN/SERVFAIL bursts, high-entropy names, repeated TXT lookups, rare/new domains within the retained window, and configured suspicious TLD/domain selectors. Mark baseline-dependent findings as incomplete after restart, retention eviction, sampling, or drops.

31. [Add query-event pipeline tests](https://github.com/rpmoore/rdns/issues/25).
    - Implements: [Resolver Tests](plan/02-resolver-cache.md#tests), [Milestone 4 Exit Criteria](plan/08-implementation-roadmap.md#milestone-4-query-event-pipeline-and-in-memory-review-model).
    - Cover event emission, non-blocking behavior with slow/failing processors, disabled logging, overflow policies, retention eviction, source filtering, schema versioning, classifier explanations, threshold boundaries, cold start, dropped/sampled events, and processor failure isolation.

## Phase 5: Configurable Resolution Strategy And Recursive Resolver

32. [Generalize the resolver backend port](https://github.com/rpmoore/rdns/issues/26).
    - Implements: [Resolution Strategy](plan/02-resolver-cache.md#resolution-strategy), [Dependency Direction](plan/00-overview.md#dependency-direction), [Milestone 5](plan/08-implementation-roadmap.md#milestone-5-configurable-resolution-strategy-and-recursive-resolver).
    - Rename or wrap the current `UpstreamResolver` port as `ResolutionBackend` so `ResolveQuery` receives one opaque backend regardless of forwarding or recursive mode. Define `ResolutionResponse` as structured answer material with provenance, credibility, canonical-chain, negative-metadata, backend provenance, and explicit cache directives; serialize DNS bytes after policy/cache decisions.

33. [Add resolution-mode runtime configuration](https://github.com/rpmoore/rdns/issues/27).
    - Implements: [Resolution Strategy](plan/02-resolver-cache.md#resolution-strategy), [Configuration Reload](plan/05-persistence-config.md#configuration-reload), [Milestone 5](plan/08-implementation-roadmap.md#milestone-5-configurable-resolution-strategy-and-recursive-resolver).
    - Support `resolution.mode = forward | recursive`, validate mode-specific settings, and add an atomic `BackendSnapshot` or `BackendHandle` pairing runtime settings generation, selected backend, backend health, and cache namespace.

34. [Move forwarding behind `ForwardingResolutionBackend`](https://github.com/rpmoore/rdns/issues/28).
    - Implements: [Forwarding Resolution](plan/02-resolver-cache.md#forwarding-resolution), [Milestone 2](plan/08-implementation-roadmap.md#milestone-2-dns-server-and-upstream-forwarding).
    - Preserve the current upstream source/ID/question validation, failover, deadlines, TCP fallback, health snapshots, and cache integration while hiding the forwarding strategy behind the generalized backend port.

35. [Add backend cache namespaces](https://github.com/rpmoore/rdns/issues/29).
    - Implements: [Cache Design](plan/02-resolver-cache.md#cache-design), [Resolution Strategy](plan/02-resolver-cache.md#resolution-strategy), [Milestone 5](plan/08-implementation-roadmap.md#milestone-5-configurable-resolution-strategy-and-recursive-resolver).
    - Include backend mode/generation, upstream-set hash, root-hints version, DNSSEC validation mode, and other answer-affecting backend inputs in reusable cache keys, or flush affected caches on those changes.

36. [Add recursive root-hints and authority configuration](https://github.com/rpmoore/rdns/issues/30).
    - Implements: [Recursive Resolution](plan/02-resolver-cache.md#recursive-resolution), [Repository Ports](plan/05-persistence-config.md#repository-ports).
    - Load and validate root hints, per-authority timeout, recursion depth, CNAME restart limit, allowed outbound transports, DNSSEC validation mode, and DNAME handling policy.

37. [Implement iterative recursive lookup](https://github.com/rpmoore/rdns/issues/31).
    - Implements: [Recursive Resolution](plan/02-resolver-cache.md#recursive-resolution), [Core Runtime Flow](plan/00-overview.md#core-runtime-flow).
    - Query root, TLD, and authoritative servers iteratively with deterministic authority selection, bounded retries, deadline enforcement, CNAME loop/depth handling, conservative DNAME deferral unless fully implemented, and explicit `SERVFAIL` outcomes for loops, lame delegations, and exhausted authorities.

38. [Add recursive transport safety](https://github.com/rpmoore/rdns/issues/32).
    - Implements: [Recursive Resolution](plan/02-resolver-cache.md#recursive-resolution), [Security Considerations](plan/07-operations-testing.md#security-considerations).
    - Use fresh transaction IDs for authority attempts, validate source endpoint and question, apply EDNS payload bounds, retry truncated UDP answers/referrals over TCP when allowed, and enforce per-attempt and per-query deadlines.

39. [Add recursive bailiwick and cache boundaries](https://github.com/rpmoore/rdns/issues/33).
    - Implements: [Recursive Cache Boundaries](plan/02-resolver-cache.md#recursive-resolution), [Cache Design](plan/02-resolver-cache.md#cache-design).
    - Validate referral glue and additional records before trust, keep recursion-internal RRset/delegation/glue/negative caches distinct from final response-template caching, and reject negative caching unless SOA ownership, authority zone, covered name, qtype/qclass, and RFC 2308 TTL derivation are valid.

40. [Add DNSSEC-disabled semantics for recursive mode](https://github.com/rpmoore/rdns/issues/34).
    - Implements: [Recursive Resolution](plan/02-resolver-cache.md#recursive-resolution), [Query Constraints](plan/01-dns-protocol.md#query-constraints).
    - Clear `AD`, define `DO` and `CD` handling, include DNSSEC flags and validation mode in cache keys, and report DNSSEC validation as disabled until local trust-anchor validation is implemented.

41. [Expose backend mode in events, status, and metrics](https://github.com/rpmoore/rdns/issues/35).
    - Implements: [Metrics](plan/07-operations-testing.md#metrics), [Health Checks](plan/07-operations-testing.md#health-checks), [Admin Status UI](plan/06-admin-api-ui.md#ui-screens).
    - Record backend mode/generation, recursive query latency, authority attempts/timeouts, bailiwick rejects, lame delegations, referral loops, TCP fallback results, limit hits, negative-cache hits, root-hints age/source, and whether DNSSEC validation is disabled.

42. [Add resolution-strategy tests](https://github.com/rpmoore/rdns/issues/36).
    - Implements: [Resolver Tests](plan/02-resolver-cache.md#tests), [Milestone 5 Exit Criteria](plan/08-implementation-roadmap.md#milestone-5-configurable-resolution-strategy-and-recursive-resolver).
    - Keep existing forwarding integration tests passing through the new backend port and add fake root/TLD/authoritative recursive tests for success, negative answers, referral loops, CNAME loops, DNAME deferral, lame delegations, glue rejection, truncated authoritative answers/referrals, DNSSEC flag handling, cache namespace isolation, and timeout/deadline handling.

## Phase 6: Local Policy And Local DNS Entries

43. [Add domain normalization and selector models](https://github.com/rpmoore/rdns/issues/37).
    - Implements: [Domain Normalization](plan/03-policy-blocking.md#domain-normalization), [Domain normalization concern](plan/09-reviewer-concerns.md#concern-response-matrix), [Milestone 6](plan/08-implementation-roadmap.md#milestone-6-local-policy-and-local-dns-entries).
    - Canonicalize lowercase ASCII/Punycode names without trailing dots and model exact versus subtree selectors explicitly.

44. [Add client identity and selector models](https://github.com/rpmoore/rdns/issues/38).
    - Implements: [Client Identity](plan/03-policy-blocking.md#client-identity), [Policy Inputs](plan/03-policy-blocking.md#policy-inputs), [Client identity concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Start with `ClientIdentity::Ip` plus exact-IP and CIDR selectors while preserving a path for labels, groups, and future identity providers.

45. [Implement local deny-rule evaluation](https://github.com/rpmoore/rdns/issues/39).
    - Implements: [Local Client/Domain Rules](plan/03-policy-blocking.md#local-clientdomain-rules), [Precedence](plan/03-policy-blocking.md#precedence), [Policy Outputs](plan/03-policy-blocking.md#policy-outputs).
    - Evaluate local deny rules before cache and upstream lookup, returning reason codes and rule identifiers.

46. [Add explicit block response configuration](https://github.com/rpmoore/rdns/issues/40).
    - Implements: [Block Response Mode](plan/03-policy-blocking.md#block-response-mode), [Response Construction](plan/01-dns-protocol.md#response-construction), [Block behavior concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Support `Refused`, `NxDomain`, `NoData`, and optional `Sinkhole` modes with blocked-response TTL, cacheability settings, and family-specific sinkhole validation.

47. [Integrate policy into `ResolveQuery`](https://github.com/rpmoore/rdns/issues/41).
    - Implements: [Resolver Flow](plan/02-resolver-cache.md#flow), [Local DNS Entries](plan/02-resolver-cache.md#local-dns-entries), [Core Runtime Flow](plan/00-overview.md#core-runtime-flow), [Policy Precedence](plan/03-policy-blocking.md#precedence).
    - Short-circuit blocked requests before local entries, cache, or upstream; answer matching exact local DNS entries from structured `A`/`AAAA` data before cache/backend; log the DNS response mode separately from the policy reason.

48. [Add response-aware malicious-domain checks](https://github.com/rpmoore/rdns/issues/42).
    - Implements: [Response-Aware Policy](plan/03-policy-blocking.md#response-aware-policy), [Malicious CNAME concern](plan/09-reviewer-concerns.md#second-review-additions).
    - Inspect CNAME targets and answer owner names in upstream responses before returning and caching; block matches and avoid storing them as allowed cache entries.

49. [Add policy tests](https://github.com/rpmoore/rdns/issues/43).
    - Implements: [Policy Tests](plan/03-policy-blocking.md#tests), [Milestone 6 Exit Criteria](plan/08-implementation-roadmap.md#milestone-6-local-policy-and-local-dns-entries).
    - Cover normalization, exact/subtree matching, suffix edge cases, client selectors, local-rule precedence, local DNS entry precedence and validation, `.local` warning metadata, generated `NODATA`, reason codes, block response selection, and CNAME-based malicious blocking.

## Phase 7: SQLite Persistence And Runtime Config

50. [Choose and isolate the SQLite async strategy](https://github.com/rpmoore/rdns/issues/44).
    - Implements: [SQLite Async Strategy](plan/05-persistence-config.md#sqlite-async-strategy), [Dependency Direction](plan/00-overview.md#dependency-direction), [SQLite concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Use either `sqlx` with SQLite pooling or `rusqlite` behind `spawn_blocking` or a dedicated database task, hidden behind repository traits.

51. [Add migrations for durable tables and indices](https://github.com/rpmoore/rdns/issues/45).
    - Implements: [Storage Choice](plan/05-persistence-config.md#storage-choice), [Proposed Tables](plan/05-persistence-config.md#proposed-tables), [Retention](plan/05-persistence-config.md#retention).
    - Create settings, upstreams, rules, local DNS entries, blocklist, active generation, and query-event tables with the suggested indices.

52. [Implement settings, upstream, rule, and query-event repositories](https://github.com/rpmoore/rdns/issues/46).
    - Implements: [Repository Ports](plan/05-persistence-config.md#repository-ports), [Configuration Reload](plan/05-persistence-config.md#configuration-reload).
    - Shape repository methods around use cases such as loading resolver settings, replacing upstreams, loading policy and local DNS entry snapshots, appending query events, and querying observed-source/suspicious lookup read models.

53. [Add immutable runtime snapshots and atomic reload](https://github.com/rpmoore/rdns/issues/47).
    - Implements: [Configuration Reload](plan/05-persistence-config.md#configuration-reload), [Runtime config concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Publish `Arc<RuntimeConfig>`, `Arc<PolicySnapshot>`, and local DNS entry snapshot state only after validation and committed database transactions.

54. [Enforce configuration validation before persistence and publication](https://github.com/rpmoore/rdns/issues/48).
    - Implements: [Configuration Reload](plan/05-persistence-config.md#configuration-reload), [API Validation](plan/06-admin-api-ui.md#api-scope), [Admin/config invariant concern](plan/09-reviewer-concerns.md#second-review-additions).
    - Validate upstream availability, bind-address conflicts, bounded timeouts and TTLs, sinkhole completeness, local DNS entry names/address families/warnings, retention settings, and blocklist URL safety.

55. [Add startup migration and degraded-startup behavior](https://github.com/rpmoore/rdns/issues/49).
    - Implements: [Startup And Migration Failure](plan/05-persistence-config.md#startup-and-migration-failure), [Health Checks](plan/07-operations-testing.md#health-checks).
    - Prevent DNS listener startup when migrations or required settings fail, unless an explicit degraded mode allows a narrower startup path.

56. [Add bounded asynchronous query-event writing](https://github.com/rpmoore/rdns/issues/50).
    - Implements: [Query Event Backpressure](plan/05-persistence-config.md#query-event-backpressure), [Query logging concern](plan/09-reviewer-concerns.md#second-review-additions), [Logging](plan/07-operations-testing.md#logging).
    - Persist events from the non-blocking query-event processor, define overflow behavior, preserve dropped/sampled indicators, and emit metrics without blocking DNS responses.

57. [Add retention maintenance](https://github.com/rpmoore/rdns/issues/51).
    - Implements: [Retention](plan/05-persistence-config.md#retention), [Developer Tooling](plan/07-operations-testing.md#developer-tooling), [SQLite growth concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Enforce query-event retention, maximum rows, maximum observed-source/domain summary size, maximum blocklist generations retained per source, and database optimize/vacuum strategy after large churn.

58. [Add persistence and reload tests](https://github.com/rpmoore/rdns/issues/52).
    - Implements: [Persistence Tests](plan/05-persistence-config.md#tests), [Milestone 7 Exit Criteria](plan/08-implementation-roadmap.md#milestone-7-sqlite-persistence-and-runtime-config).
    - Cover migrations, repository behavior with temp databases, invalid config rejection, restart durability, concurrent readers during reload, startup failure, retention cleanup, and slow query-event persistence.

## Phase 8: External Blocklist Ingestion

59. [Add blocklist source and generation persistence](https://github.com/rpmoore/rdns/issues/53).
    - Implements: [Blocklist Inputs](plan/04-blocklist-ingestion.md#inputs), [Proposed Tables](plan/05-persistence-config.md#proposed-tables), [Milestone 8](plan/08-implementation-roadmap.md#milestone-8-external-blocklist-ingestion).
    - Persist source settings, update status, inactive generations, domains, and active generation pointers.

60. [Implement safe fetcher adapter](https://github.com/rpmoore/rdns/issues/54).
    - Implements: [Guardrails](plan/04-blocklist-ingestion.md#guardrails), [Fetcher SSRF concern](plan/09-reviewer-concerns.md#second-review-additions), [Security Considerations](plan/07-operations-testing.md#security-considerations).
    - Allow only explicit `http` and `https`, enforce timeouts and redirect limits, and reject local/private/link-local/multicast targets by default.

61. [Implement source parsers](https://github.com/rpmoore/rdns/issues/55).
    - Implements: [Inputs](plan/04-blocklist-ingestion.md#inputs), [Update Flow](plan/04-blocklist-ingestion.md#update-flow), [Blocklist Tests](plan/04-blocklist-ingestion.md#tests).
    - Parse plain domain lists, hosts-file style entries, comments, and blank lines into raw candidates.

62. [Normalize, dedupe, and validate staged domains](https://github.com/rpmoore/rdns/issues/56).
    - Implements: [Update Flow](plan/04-blocklist-ingestion.md#update-flow), [Domain Normalization](plan/03-policy-blocking.md#domain-normalization).
    - Reuse the policy domain's canonical domain representation and track parse errors for guardrail evaluation.

63. [Add ingestion guardrails](https://github.com/rpmoore/rdns/issues/57).
    - Implements: [Guardrails](plan/04-blocklist-ingestion.md#guardrails), [External blocklist concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Enforce maximum download size, maximum domain count, parse-error ratio, minimum count for previously healthy lists, suspicious deltas, previous-good retention, and dry-run stats.

64. [Implement transactional activation and snapshot swap](https://github.com/rpmoore/rdns/issues/58).
    - Implements: [Atomic Activation](plan/04-blocklist-ingestion.md#atomic-activation), [Blocklist Update Transactions](plan/05-persistence-config.md#blocklist-update-transactions), [Runtime config concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Store new generations durably, activate in one transaction, rebuild `PolicySnapshot`, and atomically publish it only after commit.

65. [Add manual refresh service and API-facing status model](https://github.com/rpmoore/rdns/issues/59).
    - Implements: [Update Flow](plan/04-blocklist-ingestion.md#update-flow), [API Scope](plan/06-admin-api-ui.md#api-scope), [Milestone 8 Exit Criteria](plan/08-implementation-roadmap.md#milestone-8-external-blocklist-ingestion).
    - Let an application service refresh one source without blocking request-time DNS policy evaluation and expose status, counts, and guardrail failures.

66. [Add scheduled refresh](https://github.com/rpmoore/rdns/issues/60).
    - Implements: [Scheduling](plan/04-blocklist-ingestion.md#scheduling), [Testability Ports](plan/07-operations-testing.md#testability-ports).
    - Use injected clock/scheduler abstractions, jitter, bounded concurrent refreshes, and separate last-attempted from last-successful status.

67. [Add blocklist ingestion tests](https://github.com/rpmoore/rdns/issues/61).
    - Implements: [Blocklist Tests](plan/04-blocklist-ingestion.md#tests), [Operations Test Strategy](plan/07-operations-testing.md#test-strategy).
    - Cover parsers, invalid domains, guardrails, unsafe URLs, redirects, previous-generation retention, failed fetch rollback, atomic activation, concurrent refresh locks, and deterministic scheduling.

## Phase 9: Admin API

68. [Add admin HTTP server and route structure](https://github.com/rpmoore/rdns/issues/62).
    - Implements: [Admin Responsibility](plan/06-admin-api-ui.md#responsibility), [Delivery Implementation](plan/06-admin-api-ui.md#delivery-implementation), [Milestone 9](plan/08-implementation-roadmap.md#milestone-9-admin-api).
    - Use an HTTP framework such as `axum`, serve API routes and static assets, and call application services rather than repositories directly.

69. [Implement first-run setup and authentication](https://github.com/rpmoore/rdns/issues/63).
    - Implements: [Authentication And Safety](plan/06-admin-api-ui.md#authentication-and-safety), [Admin security concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Require setup token or password bootstrap, hash stored passwords, expire sessions, rate-limit login attempts, and invalidate setup after first successful setup.

70. [Add CSRF protection and safe bind defaults](https://github.com/rpmoore/rdns/issues/64).
    - Implements: [Authentication And Safety](plan/06-admin-api-ui.md#authentication-and-safety), [API Scope](plan/06-admin-api-ui.md#api-scope).
    - Bind admin to loopback by default and require CSRF protection for mutating browser requests.

71. [Implement settings and upstream endpoints](https://github.com/rpmoore/rdns/issues/65).
    - Implements: [API Scope](plan/06-admin-api-ui.md#api-scope), [Configuration Reload](plan/05-persistence-config.md#configuration-reload), [Milestone 9 Tasks](plan/08-implementation-roadmap.md#milestone-9-admin-api).
    - Add typed request/response structs and validation that prevents deleting or disabling the last usable upstream while forward mode is active, rejects invalid recursive root-hint settings, and publishes mode changes only after backend construction succeeds.

72. [Implement rule endpoints](https://github.com/rpmoore/rdns/issues/66).
    - Implements: [API Scope](plan/06-admin-api-ui.md#api-scope), [Local Client/Domain Rules](plan/03-policy-blocking.md#local-clientdomain-rules).
    - Support create, update, delete, enable, and disable flows for IP/CIDR and exact/subtree deny rules with typed validation errors.

73. [Implement local DNS entry endpoints](https://github.com/rpmoore/rdns/issues/67).
    - Implements: [API Scope](plan/06-admin-api-ui.md#api-scope), [Local DNS UI](plan/06-admin-api-ui.md#ui-screens), [Local DNS Entries](plan/03-policy-blocking.md#local-dns-entries).
    - Support create, update, delete, enable, and disable flows for exact `A`/`AAAA` local DNS entries with TTL validation, `.local` warning metadata, public-address acknowledgement, cache invalidation, and typed validation errors.

74. [Implement blocklist source and refresh endpoints](https://github.com/rpmoore/rdns/issues/68).
    - Implements: [API Scope](plan/06-admin-api-ui.md#api-scope), [Blocklist Scheduling](plan/04-blocklist-ingestion.md#scheduling), [Manual refresh roadmap task](plan/08-implementation-roadmap.md#milestone-8-external-blocklist-ingestion).
    - Manage sources, validate URLs with fetcher safety rules, trigger refresh asynchronously, and return update status.

75. [Implement status, query-event, and metrics endpoints](https://github.com/rpmoore/rdns/issues/69).
    - Implements: [API Scope](plan/06-admin-api-ui.md#api-scope), [Metrics](plan/07-operations-testing.md#metrics), [Health Checks](plan/07-operations-testing.md#health-checks).
    - Expose resolver health, listener state, upstream health, cache summary, blocklist freshness, query history, suspicious-event filters, observed-source detail, dropped/sampled indicators, and metrics summary.

76. [Add audit-friendly admin change logging](https://github.com/rpmoore/rdns/issues/70).
    - Implements: [Authentication And Safety](plan/06-admin-api-ui.md#authentication-and-safety), [Logging](plan/07-operations-testing.md#logging), [Metrics](plan/07-operations-testing.md#metrics).
    - Record admin mutation type, actor, target, timestamp, validation outcome, and reload result.

77. [Add API security and validation tests](https://github.com/rpmoore/rdns/issues/71).
    - Implements: [Admin API Tests](plan/06-admin-api-ui.md#tests), [Milestone 9 Exit Criteria](plan/08-implementation-roadmap.md#milestone-9-admin-api).
    - Cover first-run setup, unauthenticated mutation/query-history rejection, CSRF, session expiry, invariant validation, local DNS entry validation/reload/cache invalidation, settings reload, source-detail authorization, suspicious lookup filters, export audit logging, and refresh endpoint behavior.

## Phase 10: Admin UI

78. [Add static UI shell served by the admin server](https://github.com/rpmoore/rdns/issues/72).
    - Implements: [Delivery Implementation](plan/06-admin-api-ui.md#delivery-implementation), [Milestone 10](plan/08-implementation-roadmap.md#milestone-10-admin-ui).
    - Build a small static HTML/CSS/JavaScript UI first, avoiding a large frontend toolchain until the API and domain behavior are stable.

79. [Build the status screen](https://github.com/rpmoore/rdns/issues/73).
    - Implements: [UI Screens](plan/06-admin-api-ui.md#ui-screens), [Health Checks](plan/07-operations-testing.md#health-checks), [Metrics](plan/07-operations-testing.md#metrics).
    - Show resolver health, listening addresses, upstream health, cache hit rate, blocklist freshness, recent query decisions, query-event pipeline health, and suspicious observed-source count.

80. [Build upstream management](https://github.com/rpmoore/rdns/issues/74).
    - Implements: [UI Screens](plan/06-admin-api-ui.md#ui-screens), [Forwarding Resolution](plan/02-resolver-cache.md#forwarding-resolution).
    - Add, edit, enable, disable, reorder, validate, and test upstream resolvers.

81. [Build rules management](https://github.com/rpmoore/rdns/issues/75).
    - Implements: [UI Screens](plan/06-admin-api-ui.md#ui-screens), [Client Identity](plan/03-policy-blocking.md#client-identity), [Local Client/Domain Rules](plan/03-policy-blocking.md#local-clientdomain-rules).
    - Manage exact IP/CIDR and exact/subtree deny rules, show match examples, and make IP-based identity limitations visible.

82. [Build local DNS entry management](https://github.com/rpmoore/rdns/issues/76).
    - Implements: [UI Screens](plan/06-admin-api-ui.md#ui-screens), [Local DNS Entries](plan/03-policy-blocking.md#local-dns-entries).
    - Manage exact `A`/`AAAA` local DNS entries, show `.local` and public-address warnings, show generated `NODATA` behavior, and make clear that deny/blocklist policy still runs first.

83. [Build blocklist management](https://github.com/rpmoore/rdns/issues/77).
    - Implements: [UI Screens](plan/06-admin-api-ui.md#ui-screens), [Guardrails](plan/04-blocklist-ingestion.md#guardrails), [Atomic Activation](plan/04-blocklist-ingestion.md#atomic-activation).
    - Add, edit, enable, disable, refresh sources, and show last status, active generation timestamp, domain count, guardrail failures, and previous-good state.

84. [Build query history](https://github.com/rpmoore/rdns/issues/78).
    - Implements: [UI Screens](plan/06-admin-api-ui.md#ui-screens), [Query Event Backpressure](plan/05-persistence-config.md#query-event-backpressure), [Logging](plan/07-operations-testing.md#logging).
    - Filter recent events by observed source, domain, terminal outcome, DNS response code, policy decision, cache status, suspicious reason, qtype, and time; show reason codes and sampling/drop indicators.

85. [Build suspicious lookup review and source detail](https://github.com/rpmoore/rdns/issues/79).
    - Implements: [UI Screens](plan/06-admin-api-ui.md#ui-screens), [Suspicious Lookup Classification](plan/02-resolver-cache.md#suspicious-lookup-classification), [Security Considerations](plan/07-operations-testing.md#security-considerations).
    - Group suspicious events by observed source, show classifier reason/severity/window/version, link to source timelines, show blocked/allowed breakdowns, and make observed-source identity limitations visible.

86. [Build settings management](https://github.com/rpmoore/rdns/issues/80).
    - Implements: [UI Screens](plan/06-admin-api-ui.md#ui-screens), [Configuration Reload](plan/05-persistence-config.md#configuration-reload), [Block Response Mode](plan/03-policy-blocking.md#block-response-mode).
    - Manage DNS/admin listen addresses, cache TTL and size, block response mode, sinkhole settings, and query-log retention; show settings as active only after API confirmation.

87. [Add UI smoke and validation tests](https://github.com/rpmoore/rdns/issues/81).
    - Implements: [Admin API/UI Tests](plan/06-admin-api-ui.md#tests), [Milestone 10 Exit Criteria](plan/08-implementation-roadmap.md#milestone-10-admin-ui).
    - Smoke-test primary screens, query review filters, suspicious source detail, local DNS entry forms/warnings, core forms, validation errors, unauthenticated redirects, and API-confirmed active-state updates.

## Phase 11: TCP Listener And Operational Hardening

88. [Add DNS TCP listener delivery adapter](https://github.com/rpmoore/rdns/issues/82).
    - Implements: [TCP Framing](plan/01-dns-protocol.md#tcp-framing), [Milestone 11](plan/08-implementation-roadmap.md#milestone-11-tcp-and-operational-hardening).
    - Enforce length-prefix framing, maximum message size, read/write timeouts, idle close, and configured connection limits.

89. [Share resolver flow between UDP and TCP listeners](https://github.com/rpmoore/rdns/issues/83).
    - Implements: [TCP Framing](plan/01-dns-protocol.md#tcp-framing), [Application Service](plan/02-resolver-cache.md#application-service), [Architectural Direction](plan/00-overview.md#architectural-direction).
    - Keep framing and transport concerns in delivery adapters while both transports call the same `ResolveQuery` service.

90. [Add structured logging and metrics coverage](https://github.com/rpmoore/rdns/issues/84).
    - Implements: [Logging](plan/07-operations-testing.md#logging), [Metrics](plan/07-operations-testing.md#metrics), [Observability concern](plan/09-reviewer-concerns.md#concern-response-matrix).
    - Distinguish cache latency, upstream latency, policy blocks, parse errors, DB failures, ingestion failures, admin mutations, and dropped query logs.

91. [Add health-check completeness](https://github.com/rpmoore/rdns/issues/85).
    - Implements: [Health Checks](plan/07-operations-testing.md#health-checks), [Admin Status UI](plan/06-admin-api-ui.md#ui-screens).
    - Report DNS listener state, admin listener state, upstream health, SQLite reachability, policy snapshot load status, and blocklist freshness.

92. [Add fuzzing targets](https://github.com/rpmoore/rdns/issues/86).
    - Implements: [Fuzzing](plan/01-dns-protocol.md#tests), [Fuzz And Robustness](plan/07-operations-testing.md#test-strategy), [Milestone 11 Exit Criteria](plan/08-implementation-roadmap.md#milestone-11-tcp-and-operational-hardening).
    - Fuzz DNS parser and blocklist parser with the invariant that arbitrary input returns a parsed result or structured error, never a panic.

93. [Add stress and race tests](https://github.com/rpmoore/rdns/issues/87).
    - Implements: [Fuzz And Robustness](plan/07-operations-testing.md#test-strategy), [Concurrency](plan/02-resolver-cache.md#cache-design), [Configuration Reload](plan/05-persistence-config.md#configuration-reload).
    - Stress concurrent DNS queries, cache single-flight behavior, snapshot swaps, slow event writing, blocklist activation, and config reload while queries are in flight.

94. [Add deployment and privilege documentation](https://github.com/rpmoore/rdns/issues/88).
    - Implements: [Deployment Notes](plan/07-operations-testing.md#deployment-notes), [Port 53 concern](plan/09-reviewer-concerns.md#second-review-additions), [Milestone 11 Tasks](plan/08-implementation-roadmap.md#milestone-11-tcp-and-operational-hardening).
    - Document high-port development defaults, port-53 options such as systemd socket activation or `CAP_NET_BIND_SERVICE`, and why the whole process should not run as root just to bind DNS.

95. [Review defaults and final local-network safety posture](https://github.com/rpmoore/rdns/issues/89).
    - Implements: [Security Considerations](plan/07-operations-testing.md#security-considerations), [Authentication And Safety](plan/06-admin-api-ui.md#authentication-and-safety), [Milestone Acceptance Checks](plan/07-operations-testing.md#milestone-acceptance-checks).
    - Verify safe admin bind defaults, no unauthenticated mutation endpoints, bounded packet/source/cache/log/blocklist behavior, explicit degraded modes, and clear documentation for operational tradeoffs.

## Per-Step Completion Rule

For each step:

- Add or update focused tests when behavior changes.
- Keep DNS hot-path code free of direct database and UI dependencies.
- Preserve immutable config and policy snapshot semantics once introduced.
- Update the relevant plan file if implementation discovers a better design or an intentional deferral.
- Do not mark a milestone complete until its reviewer concern gates in [Implementation Roadmap](plan/08-implementation-roadmap.md) and [Reviewer Concerns And Revisions](plan/09-reviewer-concerns.md) are satisfied.
