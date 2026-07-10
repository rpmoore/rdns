# Code Review Interview: section-06-assembly-and-chains

Review source: `section-06-review.md` (via `deep-implement:code-reviewer`
subagent).

## Findings triage

| Finding | Severity | Disposition |
|---|---|---|
| Truncated responses hardcoded `ResponseCode::NoError` regardless of the caller's real `response_code` — a truncated NXDOMAIN/NODATA would report NOERROR | HIGH | Auto-fix — thread `response_code` through `finish_with_truncation_check` |
| Truncated responses omit the question section, matching existing `build_truncated_response` precedent but contradicting the plan's literal "header + question only" text | MEDIUM (design question) | **Asked user** — chose to follow the plan's literal text |
| `assemble_negative_response` (SOA/authority writer, negative TTL aging, proof/rrsig inclusion, response-code selection, truncation) had zero direct test coverage | MEDIUM | Auto-fix — add 3 new tests |
| SOA field order, NSEC3 hex round-trip, TXT 255-byte chunking unverified by any test | MEDIUM | Auto-fix — add 3 round-trip tests in `protocol/mod.rs` next to `write_record` |
| `from_hex` silently drops unparseable byte pairs instead of erroring | LOW | Let go — only ever fed our own `to_hex` output, always well-formed |
| `write_record`'s rdlength computation truncates for RDATA > 65535 bytes | LOW | Let go — inherent to DNS's 16-bit RDLENGTH field, not specific to this diff |
| `ChainLookup::NoData` never tested directly (only `NxDomain` is); NODATA-before-NXDOMAIN priority in `Shard::lookup_hop` untested with both keys present | LOW | Auto-fix — add a test |
| `resolve_from_cache_respects_max_cname_restarts_bound` only exercises the cyclical/visited-set path, not the plain depth-exceeded path | LOW | Auto-fix — add a test |
| Assembled responses never include an OPT/EDNS pseudo-record | LOW (note) | Let go — consistent with existing `build_question_response` precedent, not a defect |
| `Shard::lookup_hop` does two separate `.get(domain)` lookups instead of one | LOW (note) | Let go — correctness unaffected, micro-optimization only |
| TXT chunking at raw 255-byte boundaries doesn't preserve original character-string boundaries | LOW (note) | Let go — pre-existing `RecordData::TXT(String)` limitation, not introduced by this section |

## User interview

Asked the user whether truncated cache responses should include the
question section (contradicting the existing `build_truncated_response`
precedent, which the plan's own text appears to have mis-described) or
stay header-only (matching that precedent). The user chose to **follow
the plan's literal text** — truncated responses from this new
cache-assembly path now include the question section, TC bit set,
diverging intentionally from the existing (differently-scoped, non-cache)
`build_truncated_response` function, which is left untouched.

## Fixes applied

1. **Truncation response-code + question-section fix**
   (`src/resolver/cache/assemble.rs`, `finish_with_truncation_check`) —
   now takes `requester_question_wire: &[u8]` and `response_code:
   ResponseCode` parameters, appends the question section, and passes
   through the real response code instead of hardcoding `NoError`. Both
   call sites (`assemble_response`, `assemble_negative_response`) updated
   accordingly. Updated `assemble_response_truncates_per_requesters_own_bufsize`
   to assert the question section survives truncation.
2. **`assemble_negative_response` test coverage** (`assemble.rs`) — added
   `assemble_negative_response_writes_soa_in_authority_with_requested_response_code`,
   `assemble_negative_response_includes_cname_chain_and_dnssec_proof_only_when_do`,
   and `assemble_negative_response_truncates_while_preserving_response_code_and_question`
   (the last directly re-proves fix #1 end-to-end through the negative
   path with a real oversized response).
3. **Encoder round-trip tests** (`src/protocol/mod.rs`) — added
   `write_record_round_trips_soa_with_mname_before_rname_wire_order`,
   `write_record_round_trips_nsec3_hash_bytes_through_hex_encoding` (same
   fixture as the existing NSEC3 parse-only test, driven through the
   writer + `from_hex` this time), and
   `write_record_round_trips_txt_longer_than_one_255_byte_chunk`.
4. **NODATA-vs-NXDOMAIN priority test** (`assemble.rs`) — added
   `resolve_from_cache_finds_nodata_before_nxdomain_when_both_keys_present`.
5. **Depth-bound test** (`assemble.rs`) — added
   `resolve_from_cache_respects_max_chain_depth_on_a_non_cyclical_chain`,
   using a straight-line (non-cyclical) 3-hop chain to isolate the
   `chain.len() as u8 >= max_chain_depth` branch from the visited-set
   cycle guard already covered by the existing cyclical-chain test.

## Verification after fixes

- `cargo build --tests` — clean.
- `cargo test --locked -- resolver::cache::assemble` — 19/19 passed.
- `cargo test --locked -- protocol::tests::write_record` — 3/3 passed.
- `resolve_from_cache_never_holds_two_shard_locks_at_once` (timing-based)
  — run 3x consecutively after all fixes, no flakes.
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo fmt` — clean.
- `cargo test --locked` (full suite) — 461 passed, 0 failed (up from 453
  before this section's fixes; +8 net new tests).
