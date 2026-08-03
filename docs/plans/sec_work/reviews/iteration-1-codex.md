# Codex Review

**Reviewer:** Codex (codex-rescue subagent, via /codex delegate)
**Generated:** 2026-07-17

---

## 1. Architecture soundness

- **Major**: plan overstates that DS/DNSKEY/RRSIG material is already
  accumulated during iteration — `synthesize_recursive_cname_response`
  doesn't carry that (`claude-spec.md:33-39`,
  `src/resolver/mod.rs:1367-1429,8116-8123`). Fix: state that post-hoc
  validation is only sound if `domain` does its own DS/DNSKEY chase.
- **Major**: `domain`'s `validate_msg` needs `domain::base::Message` +
  `domain::net::client::SendRequest`, but rdns has its own
  `Message`/`RecursiveAuthorityTransport` types (`claude-plan.md:138-143`,
  `src/resolver/mod.rs:7823-7830`). Fix: add explicit adapter/spike task
  with timeout/error translation.

## 2. CD-bit design

- No finding against the core always-validate/CD-gate design; it's
  grounded correctly.
- **Major**: mapping `Indeterminate` to `Unvalidated` risks silently
  serving unverifiable data with no operator-visible failure path
  (`claude-plan.md:151-153`).

## 3. On-by-default rollout

- **Major (x2)**: pushes back on shipping SERVFAIL-on-Bogus by default with
  no field burn-in; recommends opt-in/permissive mode for at least one
  release, plus rollout verification for cold-cache/DS-DNSKEY-fetch latency
  impact.

## 4. BADCOOKIE transport gating

- **Critical**: plan/spec/interview contradict each other on "missing
  server cookie" handling — B1/spec treat missing as BADCOOKIE-over-UDP,
  B2's first-contact carve-out conflicts (`claude-plan.md:278-280,309-317`,
  `claude-spec.md:137-144`, `claude-interview.md:76-78`).
- **Major (x3)**: malformed cookie options collapse to `None` and could
  bypass BADCOOKIE entirely; IPv4-mapped IPv6 source normalization
  unspecified before hashing; EDNS-version-vs-cookie precedence undefined.

## 5. Trust anchor CI check

- **Major**: scheduled IANA-fetch check could block unrelated CI if made a
  required gate rather than a monitor.
- **Minor**: warning threshold left undecided, weakening the safety
  mechanism.

## 6. Missing pieces

- **Critical**: validator timeout/error behavior undefined against rdns's
  existing `per_query_deadline`/`per_authority_timeout`.
- **Major (x3)**: cache TTL not tied to DNSSEC signature validity window;
  sequential/duplicate DS-DNSKEY fetch performance not addressed;
  serve-stale interaction with Secure/Bogus verdicts undecided.

## 7. Testing gaps

- **Major (x3)**: missing expired/not-yet-valid signature and
  rollover/timeout tests; missing mixed-validation-state CNAME chain
  tests; B3 missing malformed-cookie/duplicate-option/EDNS-version/
  IPv4-mapped-IPv6/cookie-echo tests.

## Other

- **Minor**: A1's dependency-feature change (`unstable-validator`) treated
  as "no behavior change" undersells supply-chain/build-surface risk.
