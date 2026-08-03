# Interview: DNSSEC Validation + BADCOOKIE Handling

Interview conducted by `/deep-plan` on `docs/plans/sec_work/spec.md`, informed
by `claude-research.md`. All answers below are the user's selections
(mostly the recommended option in each case).

## Round 1 — Architecture

### Q1. Sequencing
DNSSEC validation and BADCOOKIE are independently shippable (different
files/paths). One combined plan/PR, or split into two sequenced plans?

**Answer:** One combined plan, two PRs. Single deep-plan doc covers both
tracks with clear section boundaries; implementation still lands as two
separate PRs so each gets its own `/security-review` gate.

### Q2. DNSSEC scope boundary
Validate only in Recursive mode (matches today's always-fetch behavior), or
also add independent validation in Forward mode instead of trusting
upstream's AD bit?

**Answer:** Recursive mode only. Matches existing always-fetch-DNSSEC
behavior; Forward mode keeps passing through upstream's AD bit verbatim,
unchanged. (Confirms spec non-goal — no change to `ResolutionMode::Forward`
AD-bit passthrough.)

### Q3. Chain-of-trust hook point
Research shows Unbound/BIND run the validator as a separate pass after the
iterator finishes, not inline-per-referral-hop. Which architecture for
rdns?

**Answer:** Separate pass before entry construction (Recommended). New
validation pass runs right before `build_rrset_entry`/`build_negative_entry`
(`resolver/mod.rs:~1045-1120`), walking already-fetched DNSKEY/DS/RRSIG
material. No new referral-walk plumbing needed. Matches Unbound/BIND's
validator/iterator separation.

### Q4. New transitive dependencies
`domain`'s `unstable-validator` feature pulls in `moka` (caching crate) +
`unstable-client-transport` as new transitive deps, beyond the ring/openssl
crypto backend the spec anticipated. Acceptable under RUST.md's
conservative-dependency policy?

**Answer:** Yes, acceptable. `moka`/`unstable-client-transport` are
transitive deps of a crate already in Cargo.toml, not new direct
dependencies — document the addition in the plan and move on.

## Round 2 — Protocol semantics

### Q5. CD-bit design
Research confirms RFC 4035 §3.2.2/§4.7 pattern — always compute+cache
`dnssec_state` regardless of CD, only gate the SERVFAIL-on-Bogus response
behavior on CD at response-build time. Confirm this as the design?

**Answer:** Yes, validate always, gate response only. `dnssec_servfail_check`'s
call site skips enforcement when request CD=1, but the cache entry's
`dnssec_state` is always computed/stored so other requesters (CD=0) get
correct behavior.

### Q6. Trust anchor
Root KSK rollover is imminent (KSK-2024 active 2026-10-11, current date
2026-07-17). Bundle both KSK-2017 (tag 20326) + KSK-2024 (tag 38696) now,
plus a CI job diffing against IANA's `root-anchors.xml` per RFC 9718?

**Answer:** Yes, both anchors + CI staleness check. Avoids the
2018-rollover failure mode (9000+ resolvers went dark on stale
single-anchor bundles); CI job fetches `root-anchors.xml` on a schedule,
fails build if bundled set drifts from `validFrom`/`validUntil` window.

### Q7. BADCOOKIE transport design
Research corrects spec — real citation is RFC 7873 §5.2.3/§5.2.4 (not
§5.4). Confirm implementing exactly per spec: over TCP, SHOULD process
normally (choose option 3); over UDP, send BADCOOKIE on bad/stale server
cookie?

**Answer:** Yes, per §5.2.3/§5.2.4 exactly. UDP + bad/stale/missing server
cookie → BADCOOKIE with freshly issued cookie attached. TCP → process
normally regardless of cookie state, per the RFC's TCP carve-out.

### Q8. Security review placement
AGENTS.md requires `/security-review` before any PR touching
auth/untrusted-input/network code. Both tracks parse attacker-controlled
wire bytes. Where in the section sequence should each PR's
`/security-review` run?

**Answer:** End of each PR's sections, before merge. Last section in each
track's plan is "/security-review + fix findings" — runs once all
validator/BADCOOKIE code for that PR is written and tested, right before
the PR is opened.

## Round 3 — Testing & config

### Q9. DNSSEC test fixture source
DNSSEC known-answer test needs a real signed-zone DNSKEY/DS/RRSIG chain.
What's the source for that test fixture?

**Answer:** Generate our own test zone + keys offline. Use a tool (e.g.
`ldns-signzone` / `domain`'s own signing support) to produce a small
deterministic signed zone once, commit the resulting wire bytes as a
fixture — no external network dependency in tests, full control over edge
cases (NSEC/NSEC3/wildcards).

### Q10. Status/mode variant shape
`DnssecValidationStatus`/`DnssecValidationMode` currently have one variant
(`Disabled`). What should the new variant set look like once validation is
real?

**Answer:** Enabled + Disabled. Mode/status just reflects whether
validation is on — per-query Secure/Insecure/Bogus counts surface as
separate counters, not as the mode/status enum itself.

### Q11. Default enablement
Should DNSSEC validation be enabled by default once shipped, or opt-in
behind a config flag initially?

**Answer:** On by default. Validation runs by default once the feature
ships; existing deployments start validating and enforcing
SERVFAIL-on-Bogus immediately on upgrade. (Note: deviates from the
skill's suggested recommendation of opt-in — user's explicit choice.)

## Round 4 — Metrics & BADCOOKIE config

### Q12. Metrics shape
Per-query DNSSEC outcome metrics (Secure/Insecure/Bogus counts) — what
shape?

**Answer:** Counter per outcome, labeled. One u64 Counter (e.g.
`dnssec_validation_results_total`) with a label/attribute for
Secure|Insecure|Bogus|Indeterminate, incremented per validated query —
matches existing `backend_status_attributes` labeling pattern.

### Q13. BADCOOKIE config toggle
Should BADCOOKIE have its own config enable/disable toggle, independent of
the existing cookie support?

**Answer:** No separate toggle. BADCOOKIE checking is just correct
behavior once cookies are supported at all — always on wherever EDNS
cookies are already accepted, no new config surface.

## Interview stop rationale

All 8 open design questions from `spec.md` are now resolved (sequencing,
DNSSEC scope, chain-of-trust hook, CD-bit, trust anchor, BADCOOKIE
transport, test strategy, security-review placement), plus follow-on
questions raised by research (transitive deps, status/mode shape, default
enablement, metrics shape, BADCOOKIE config surface). User consistently
selected the grounded/recommended option except Q11 (explicit on-by-default
choice). Proceeding to spec synthesis and plan generation.
