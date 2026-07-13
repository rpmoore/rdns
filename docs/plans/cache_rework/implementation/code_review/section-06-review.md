# Code Review: section-06-assembly-and-chains

Reviewer: `deep-implement:code-reviewer` subagent

## Summary

Structurally sound; the documented plan deviations (explicit `max_chain_depth`,
`request_id`, `configured_max_udp_payload_size` params; `ResolvedNegative.terminal_name`;
DNSSEC checks scoped to the chain only, not the terminal `NegativeEntry`
which has no `dnssec_state`) are all reasonable given the types actually
available. Lock discipline is correct — `Shard::lookup_hop` takes and
drops its `MutexGuard` within one call, so `resolve_from_cache` never
holds two shard locks at once. TTL aging/capping is fully saturating, no
panics. AD-bit/SERVFAIL rules match spec. `NameCompressor` reuse across
chain+authority sections is correct (real absolute buffer offsets). Scope
is clean — only the three planned files touched.

## Findings

- **HIGH**: `finish_with_truncation_check` hardcodes `ResponseCode::NoError`
  in the truncated header regardless of what `response_code` was passed to
  `assemble_negative_response`. A truncated NXDOMAIN/NODATA response
  reports NOERROR to the client instead of the real code.
- **MEDIUM (design question)**: the truncated path omits the question
  section entirely, matching the codebase's pre-existing
  `build_truncated_response` (verified by its own test asserting empty
  questions) — but this directly contradicts section-06's own plan text
  ("header + question only, TC bit set"). The plan's description of the
  existing function's behavior appears to not match reality.
- **MEDIUM**: `assemble_negative_response` (SOA/authority writer, negative
  TTL aging, proof-record/soa_rrsig inclusion, response-code selection,
  truncation) has zero direct test coverage — every existing test calls
  either `assemble_response` (positive path) or `resolve_from_cache`.
- **MEDIUM**: SOA field order, NSEC3 hex round-trip (`from_hex`), and TXT
  255-byte chunking are unverified by any test — only A and RRSIG are
  round-tripped through `Message::parse` in the new tests, despite the
  plan calling the generic encoder "real, non-trivial new code" needing
  its own test attention.
- **LOW**: `from_hex` silently drops any unparseable byte pair via
  `filter_map` rather than erroring — if `NSEC3.next_domain`'s hex string
  and `hash_length` ever diverge, this produces a wire-corrupt record with
  no error raised. Low risk in practice: the only producer of these hex
  strings is our own `to_hex`, always well-formed.
- **LOW**: `write_record`'s rdlength computation silently truncates for
  RDATA exceeding 65535 bytes — inherent to DNS's 16-bit RDLENGTH field,
  not specific to this diff.
- **LOW**: `ChainLookup::NoData` is never tested directly (only `NxDomain`
  is) — the NODATA-before-NXDOMAIN priority check in `Shard::lookup_hop`
  is untested with both negative keys populated for the same domain.
- **LOW**: `resolve_from_cache_respects_max_cname_restarts_bound` only
  exercises the cyclical/visited-set path; the `chain.len() as u8 >=
  max_chain_depth` branch on a plain non-cyclical over-length chain is
  never independently exercised.
- **LOW (note, not a defect)**: assembled responses never include an
  OPT/EDNS pseudo-record (`additional_count` always 0) — consistent with
  existing precedent (`build_question_response` does the same), not
  called out as deferred anywhere but matches the codebase's established
  pattern for synthesized responses.
- **LOW (note)**: `Shard::lookup_hop` does two separate `.get(domain)`
  lookups rather than fetching `DomainRecordSets` once — correctness
  unaffected, minor missed micro-optimization.
- **LOW (note, pre-existing)**: TXT chunking at raw 255-byte boundaries
  won't generally reproduce a multi-string TXT record's original
  character-string boundaries — inherent to `RecordData::TXT(String)`
  predating this diff.

## Scope check

Only `src/protocol/mod.rs`, `src/resolver/cache/{mod,shard,assemble}.rs`
touched, matching the plan's file list.
