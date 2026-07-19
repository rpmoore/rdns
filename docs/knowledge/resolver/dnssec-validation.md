---
type: System
title: DNSSEC Validation
description: >
          Recursive-mode responses are validated against DNSSEC signatures
          before being turned into cache entries, using the `domain`
          crate's validator; the verdict gates AD-bit assertion, serve-stale
          eligibility, and (as of the on-by-default rollout) whether a
          CD=0 requester gets SERVFAIL for a tampered or unreachable-chase
          answer.
resource: src/resolver/dnssec_validation.rs
tags: [dns, resolver, dnssec, security, validation, metrics]
timestamp: 2026-07-19T00:00:00Z
---

# What it is

A validation pass that runs after a recursive query's response is fully
fetched and before it's turned into a cache entry — it calls into the
`domain` crate's `dnssec::validator` module (not a hand-rolled
validator). `ResolutionMode::Recursive` only; `Forward` mode never runs
it and continues to trust the upstream's AD bit verbatim (see
`ResolveQuery::validate_for_store`'s doc comment,
`src/resolver/mod.rs:6234-6265`).

# Module and entry points

- `validate_response` (`src/resolver/dnssec_validation.rs:118`) is the
  core validation function: given a response, configured trust anchors,
  a backend for the validator's own DS/DNSKEY chase, and a deadline, it
  drives `domain::dnssec::validator::context::ValidationContext` and
  returns a `ValidationRunOutcome { state: DnssecState, validation_state:
  ValidationState }` — both the codebase's collapsed `DnssecState` and
  the raw `domain` verdict, since some callers (metrics, below) need to
  tell "ran, `Indeterminate`" apart from "never ran," which
  `DnssecState::Unvalidated` alone can't do.
- `ResolveQuery::validate_for_store` (`src/resolver/mod.rs:6266`) is the
  sole caller: it resolves configured trust anchors (`None` = skip
  entirely, see Status/mode below), calls `validate_response` with a
  fresh deadline derived from `self.dnssec_validation_deadline`, records
  the section-05 outcome metric (see Metrics below), and returns just
  the collapsed `DnssecState` for storage.
- Both call sites that feed `decompose_response_for_store`'s
  `dnssec_state` parameter call `validate_for_store` for
  `ResolutionMode::Recursive` and hardcode `DnssecState::Unvalidated` for
  `ResolutionMode::Forward` — the client-miss path
  (`src/resolver/mod.rs:5834`) and the refresh-worker path
  (`src/resolver/mod.rs:4092`). The stored verdict flows into
  `build_rrset_entry`/`build_negative_entry` (`src/resolver/mod.rs:1054`,
  `:1126`), stamped onto every hop of a CNAME chain and the terminal
  negative entry alike.

# Trust anchor sourcing

- Bundled root KSKs ship at compile time via `include_str!`
  (`BUNDLED_ROOT_ANCHOR`, `src/config/mod.rs:930`), parsed by
  `bundled_trust_anchors` (`:932`) into raw zonefile-format DS/DNSKEY
  lines. `TrustAnchorSource::Bundled`/`Static` (`:903`) lets an operator
  override with a static list via `[resolution.recursive]
  trust_anchor_entries`.
- A separate scheduled CI job checks the bundled anchor file for
  staleness (added alongside the bundling work) — not duplicated here,
  see that workflow directly for its mechanics.
- `RecursiveResolutionConfig::load_trust_anchors` (`src/config/mod.rs:784`)
  returns the raw lines regardless of source; `RecursiveResolutionConfig::
  validate` parses and validates each entry at config-load time, so a
  malformed static override is rejected at startup, not at first query.
- `RecursiveResolutionConfig::authority_config_hash` (`src/config/mod.rs:841`)
  hashes actual trust-anchor content (each DS/DNSKEY line) into the
  cache-namespace fingerprint, alongside the `TrustAnchorSource`
  Bundled/Static label — mirroring how root-hints content is already
  hashed. Without this, rotating trust anchors (Bundled → Static, or
  between two different `Static` sets) wouldn't bump the cache epoch,
  letting `Secure`/`Bogus` verdicts computed under the old anchor set
  persist past the rotation until natural TTL expiry — a gap this
  section's own security review found and closed.

# Status, mode, and the production kill switch

- `DnssecValidationMode` (`src/config/mod.rs:1188`, config-level) and
  `DnssecValidationStatus` (`src/resolver/mod.rs:2471`, resolver-level)
  are deliberately duplicated across the config/resolver boundary — same
  pattern as `ResolutionMode`/`ResolverResolutionMode` elsewhere in this
  codebase. Both now have `Enabled`/`Disabled` variants; **`Enabled` is
  the config default** for an unspecified `dnssec_validation` TOML key
  (`src/config/mod.rs:2000-2007`).
- The actual kill switch is whether `ResolveQuery.trust_anchors` is
  `Some` or `None` — `validate_for_store` short-circuits to
  `DnssecState::Unvalidated` (recording the `NotAttempted` metric
  outcome) whenever it's `None`, without touching the backend at all.
  `main.rs`'s `trust_anchors_to_wire_in` (`src/main.rs:852`) is the one
  place that decision takes effect in production: it loads real anchors
  and calls `ResolveQuery::with_trust_anchors` only when
  `RecursiveResolutionConfig::dnssec_validation == Enabled`, leaving the
  resolver's `None` default untouched for `Disabled` mode and for
  `ResolutionMode::Forward` (no `[resolution.recursive]` section at
  all).
- `DnssecValidationMode::cache_namespace_label()` (`:1192-1198`) feeds
  `Config::backend_cache_namespace`, which feeds the cache-epoch bump
  logic (see [cache-epoch](caching/cache-epoch.md)) — flipping the
  default from `Disabled` to `Enabled` intentionally bumps the cache
  namespace, and thus invalidates existing cache entries, on upgrade.
  This is a deliberate, one-time effect of the upgrade, not a
  regression.
- `BackendSnapshot::with_dnssec_validation_status`
  (`src/resolver/mod.rs:2598`) lets `main.rs`'s
  `build_recursive_backend_snapshot` report the real configured status;
  `build_forward_backend_snapshot` never calls it, so Forward mode's
  status always reads `Disabled` (no DNSSEC concept for that mode at
  all).

# `ValidationState` → `DnssecState` mapping

`map_validation_state` (`src/resolver/dnssec_validation.rs:87`):

| `domain`'s `ValidationState` | `DnssecState` |
|---|---|
| `Secure` | `Secure` |
| `Insecure` | `Insecure` |
| `Bogus` | `Bogus(reason)` |
| `Indeterminate` | `Unvalidated` |

The `Indeterminate` collapse is state-invisible but metrics-visible: the
entry-level `DnssecState` enum (`src/resolver/cache/entry.rs:107-113`)
was deliberately not expanded with a distinct `Indeterminate` variant —
"ran but inconclusive" and "never ran at all" both look like
`Unvalidated` on the stored entry — but the distinction isn't lost, it's
relocated to the metrics layer (see Metrics below), which is the only
place an operator can currently tell those two cases apart.

# Fail-closed timeout and error handling

A timeout or transport error during the DS/DNSKEY chase maps to `Bogus`
with a diagnostic reason (`bogus_outcome`,
`src/resolver/dnssec_validation.rs:96`), never to `Insecure` and never
silently to `Unvalidated` — pinned by
`timeout_during_chase_is_bogus_not_hang_or_insecure` and
`transport_error_during_chase_is_bogus_not_insecure_or_unvalidated`
(`:752`, `:775`). This is a deliberate trade-off, not an oversight:
transient upstream slowness during the chase can produce a SERVFAIL for
CD=0 requesters exactly as a genuinely tampered response would (see
`dnssec_servfail_check` below) — called out again in the rollout note
for the on-by-default PR, not just documented here.

Trust anchors that are configured (`ResolveQuery.trust_anchors` is
`Some`) but fail to parse as valid zonefile data hit the same
fail-closed philosophy at one layer up: `validate_for_store`
(`src/resolver/mod.rs:6279-6305`) never even reaches `validate_response`
in that case, but stores `DnssecState::Bogus(reason)` (not
`Unvalidated`) and records the `Bogus` metric outcome, not
`NotAttempted` — a live misconfiguration under an operator who believes
DNSSEC is on must not look identical, either in the stored cache state
or in metrics, to the benign `Disabled` opt-out. Storing `Bogus` here
also means this failure gets the same SERVFAIL/serve-stale-exclusion
treatment as a genuinely tampered response, not just a distinguishable
metric label.

# CD-bit gating and serve-stale interaction

Validation always runs (when reachable at all) and its result is always
stored, independent of the storing request's own CD bit — the cache
entry is shared across every future requester of that name/type. CD-bit
gating happens only at response-assembly time:
`dnssec_servfail_check`/`negative_dnssec_servfail_check`
(`src/resolver/cache/assemble.rs:426`, `:447`) force SERVFAIL for a
CD=0 requester when any hop in the chain (or the negative entry itself)
is `Bogus`, without modifying `build_rrset_entry`/`build_negative_entry`
themselves — pinned by
`assemble_response_servfails_on_bogus_when_checking_enabled`,
`assemble_response_servfails_on_mixed_state_cname_chain_with_any_bogus_hop`,
and their negative-response siblings (`src/resolver/cache/assemble.rs:1609`,
`:1663`, `:1813`, `:1870`). `dnssec_ad_bit`/`negative_dnssec_ad_bit`
(`assemble.rs:469`, `:486`) assert AD=1 only for a `Secure` chain/entry.

A `Bogus` entry is never eligible for serve-stale — see
[serve-stale](caching/serve-stale.md)'s `stale_servability` admission
rule, checked ahead of the window/TTL checks specifically so a
known-tampered response can't be served past expiry either way.

# TTL capping

Effective cache TTL is capped at the earliest RRSIG expiration among the
records/proof material being stored, via
`cap_expires_at_to_rrsig_expiration` (`src/resolver/mod.rs:1093`),
applied whenever RRSIGs are present regardless of `DnssecState` — a
`Secure` entry's `expires_at` (and thus its serve-stale window) already
reflects signature validity, so no additional inception/expiration
revalidation is needed at stale-serve time beyond what this capping
already guarantees.

# Metrics

- `dnssec_validation_disabled` (gauge, declared `src/main.rs:973`, built
  at `:1085`, recorded in `record_backend_status` at `:1304`) reports
  whether the *configured* mode is `Disabled` — a point-in-time status
  gauge, not a per-query counter.
- `dnssec_validation_results_total` (counter, `src/main.rs:1086-1088`)
  is the per-query outcome counter this validation pass feeds via
  `MetricsSink::record_dnssec_validation_outcome`
  (`src/resolver/mod.rs`, trait default no-op, implemented on
  `OpenTelemetryMetrics` at `src/main.rs:1316-1319`). Labeled `outcome`
  with one of `DnssecValidationOutcome`'s variants
  (`src/resolver/mod.rs:2483-2495`): `secure`, `insecure`, `bogus`,
  `indeterminate`, `not_attempted`. `not_attempted` covers both
  `DnssecValidationMode::Disabled` and any query that never reaches the
  recursive validation path (`Forward` mode emits no metric at all —
  silence, not an explicit `not_attempted` per query, since Forward
  structurally never validates).

# Known upstream limitation, accepted as-is

`domain`'s validator fetches DS/DNSKEY sequentially, doesn't prefetch,
and can issue duplicate chase queries for parallel same-name lookups
(e.g. simultaneous A/AAAA queries for the same domain). This is a
`domain`-crate limitation, not something rdns's wiring fixes — not
solved in this pass; watch the outcome counter and query latency after
rollout for its impact.

# Tests

- Core validator (`src/resolver/dnssec_validation.rs`):
  `known_answer_chain_validates_secure` (`:648`),
  `tampered_rrsig_signature_is_bogus` (`:668`),
  `tampered_dnskey_byte_is_bogus` (`:690`), `expired_rrsig_is_bogus`
  (`:716`), `not_yet_valid_rrsig_is_bogus` (`:734`),
  `timeout_during_chase_is_bogus_not_hang_or_insecure` (`:752`),
  `transport_error_during_chase_is_bogus_not_insecure_or_unvalidated`
  (`:775`).
- Entry wiring and TTL capping (`src/resolver/mod.rs`):
  `validate_for_store_returns_secure_for_a_known_good_signed_response`,
  `validate_for_store_records_bogus_outcome_for_a_tampered_signature`,
  `validate_for_store_returns_unvalidated_without_configured_trust_anchors`,
  `validate_for_store_records_bogus_when_trust_anchors_fail_to_parse`,
  `resolve_forward_mode_never_invokes_dnssec_validator`,
  `build_rrset_entry_caps_ttl_to_earlier_rrsig_expiration`,
  `build_negative_entry_caps_ttl_to_earlier_soa_rrsig_expiration`.
- CD-bit gating and AD assertion (`src/resolver/cache/assemble.rs`):
  `assemble_response_copies_cd_bit_from_requester`,
  `assemble_response_ad_bit_for_secure_entry_unaffected_by_cd_bit`,
  `assemble_response_servfails_on_bogus_when_checking_enabled`,
  `assemble_response_servfails_on_mixed_state_cname_chain_with_any_bogus_hop`,
  `assemble_negative_response_servfails_on_bogus_nxdomain_when_checking_enabled`,
  `assemble_negative_response_servfails_on_bogus_nodata_when_checking_enabled`.
- Config/status/metrics (`src/config/mod.rs`, `src/main.rs`):
  the `toml_config_round_trip_*_dnssec_validation_*` family,
  `dnssec_validation_label_differs_by_status`,
  `dnssec_outcome_label_covers_every_outcome`,
  `record_backend_status_dnssec_gauge_reflects_enabled_and_disabled`,
  `record_dnssec_validation_outcome_increments_labeled_counter`,
  `build_recursive_backend_snapshot_reflects_configured_dnssec_validation`,
  `build_forward_backend_snapshot_is_always_dnssec_disabled`,
  `trust_anchors_to_wire_in_*` (three branches: disabled, forward mode,
  enabled).

# See also

- [serve-stale](caching/serve-stale.md) — the `Bogus`-excluded-from-stale
  rule and the RFC 4035 §4.3 revalidation question this section's TTL
  capping answers.
- [answer-cache](caching/answer-cache.md) — `dnssec_state`'s place among
  everything else stored per cache entry.
- [cache-epoch](caching/cache-epoch.md) — the cache-namespace bump this
  feature's on-by-default default flip causes on upgrade.
