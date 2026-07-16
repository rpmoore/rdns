<!-- PROJECT_CONFIG
runtime: rust-cargo
test_command: cargo test
END_PROJECT_CONFIG -->

<!-- SECTION_MANIFEST
section-01-knowledge-bundle-docs
section-02-clock-dependency-injection
section-03-ttl-edge-case-tests
END_MANIFEST -->

# Implementation Sections Index

Scope: PR 1 only (`claude-plan.md` Parts A-C — documentation, Clock
dependency injection, TTL edge-case regression tests). Part E (EDNS-Cookie
cache allowlist) is intentionally excluded from this section split — per
`claude-plan.md` E.6 and `claude-plan-tdd.md`'s section-split note, it is a
scoping document pending a dedicated follow-up `/deep-plan` session, not
implementation-ready. Part D is a planning marker only (no code), not a
section.

## Dependency Graph

| Section | Depends On | Blocks | Parallelizable |
|---------|------------|--------|-----------------|
| section-01-knowledge-bundle-docs | - | - | Yes |
| section-02-clock-dependency-injection | - | - | Yes |
| section-03-ttl-edge-case-tests | - | - | Yes |

All three sections are independent: they touch disjoint files/subsystems
(knowledge-bundle markdown; `src/delivery/dns.rs` + `src/main.rs` +
existing test call sites; new unit/e2e test functions in
`src/resolver/cache/assemble.rs` + `src/resolver/mod.rs`). None depends on
another's code landing first.

## Execution Order

1. section-01-knowledge-bundle-docs, section-02-clock-dependency-injection,
   section-03-ttl-edge-case-tests — all in parallel, single batch.

## Section Summaries

### section-01-knowledge-bundle-docs
Update `docs/knowledge/resolver/caching/answer-cache.md` to document
`compute_wire_ttl` remaining-TTL-on-read behavior, the chain-wide
`expires_at` ceiling, and the negative-cache dual-aging distinction
(`claude-plan.md` Part A.1). Retire `docs/caching.md`, replacing its
content with a pointer to `docs/knowledge/` and `docs/plans/cache_rework/`
without breaking `docs/plans/cache_rework/*`'s historical inbound
references (Part A.2). Doc-only; no tests.

### section-02-clock-dependency-injection
Thread a shared `Arc<dyn Clock>` from `src/main.rs` through
`UdpDnsServer`/`TcpDnsServer` (`src/delivery/dns.rs`) to replace the two
raw `SystemTime::now()` call sites (`dns.rs:262`, `:620`) that seed
`ReceivedAt` for cache TTL aging, per `claude-plan.md` Part B. Update every
enumerated test/support call site (`tests/forwarding.rs`,
`tests/support/mod.rs`, in-module `dns.rs` tests). Add the new live
end-to-end Clock-injection test under `tests/` (Part B.4). Pure refactor —
no production timing-behavior change.

### section-03-ttl-edge-case-tests
Add the two previously-uncovered regression tests identified during the
audit (`claude-plan.md` Part C): zero/near-zero origin TTL vs.
`min_positive_ttl` floor (C.1, in `src/resolver/cache/assemble.rs`), and
the chain-wide `expires_at` ceiling applying to a terminal record looked
up independently after being stored as part of a CNAME chain (C.2, in
`src/resolver/mod.rs`). Test-only; asserts existing, unchanged behavior.
