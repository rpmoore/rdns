# Track A rollout note (DNSSEC validation) — paste into PR description

**DNSSEC validation ships on by default.** This is a deliberate,
explicit decision, reaffirmed after external plan review specifically
recommended an opt-in first release given the lack of field experience
with this validator in production. The decision stands: on-by-default,
with the expanded test suite (known-answer, Bogus-injection via
tampered RRSIG/DNSKEY bytes, expired/not-yet-valid-signature, chase
timeout/transport-error, and mixed-state CNAME chain tests across the
validator core, entry-wiring, and response-assembly layers) treated as
the mitigation instead of a staged rollout. Set
`[resolution.recursive] dnssec_validation = "disabled"` to opt out.

**Existing deployments start validating and enforcing SERVFAIL-on-Bogus
immediately on upgrading** past this release. This is not a silent
default flip — it's an intended, immediate behavior change operators
should be aware of before upgrading. A response whose DNSSEC chain
fails validation (tampered signature, broken chain of trust, or a
misconfigured/unparseable trust-anchor set) now produces a real `Bogus`
verdict, and any CD=0 requester for that name gets SERVFAIL instead of
the previously-served (unauthenticated) answer.

**Fail-closed timeout risk, additive to the Bogus-detection risk
above.** The validator's DS/DNSKEY chase is bounded by a deadline; a
timeout or transport error during that chase — including transient
upstream slowness that has nothing to do with an actual attack — maps
to `Bogus`, never silently to `Insecure` or `Unvalidated`. This means
ordinary transient network conditions during the chase can also produce
a SERVFAIL for CD=0 requesters, distinct from genuine signature
tampering. Both risks are real and independent; neither subsumes the
other.

**Cache-namespace invalidation on upgrade.** The config default flip
(`DnssecValidationMode::Disabled` → `Enabled`) changes
`cache_namespace_label()`'s output, which feeds the cache-epoch
fingerprint. An upgrade therefore both invalidates every existing
Recursive-mode cache entry *and* begins rejecting previously-tolerated
Bogus-signed responses at the same time — two distinct, simultaneous
effects of the same upgrade, not one effect described twice.

**Observability added alongside this rollout**: a
`dnssec_validation_results_total` counter (labeled `outcome` =
`secure`/`insecure`/`bogus`/`indeterminate`/`not_attempted`) and a
`dnssec_validation` label on the existing backend-status
gauge/attributes, so operators can watch validation-outcome mix and
confirm the mode actually in effect before and after upgrading. See
`docs/knowledge/resolver/dnssec-validation.md` for the full mechanism.
