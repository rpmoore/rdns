## Section 08 — code review triage (no user interview needed)

The subagent review surfaced two actionable, non-controversial findings (missing explicit RFC 9018 §4.3 version check; missing end-to-end test for the IPv4-mapped-IPv6 case) and several correct-as-is items where the plan had already made the call (fully-qualified `edns_cookie` module paths, `Vec<u8>` tail field shape, re-deriving the client cookie independently in `protocol_error`). None involved a real tradeoff needing the user's input — both actionable items were auto-fixed.

Auto-fixes applied:
1. `src/protocol/edns_cookie.rs`, `server_cookie_matches`: added an explicit `version != 1` rejection ahead of the hash check, matching RFC 9018 §4.3's literal requirement (previously relied only on the version byte being folded into the hash comparison).
2. `src/resolver/mod.rs`: added `resolve_accepts_valid_cookie_from_mapped_ipv6_client`, a full `service.resolve(...)` end-to-end test for the IPv4-mapped-IPv6 case, complementing the existing unit-level `server_cookie_matches_reuses_ip_normalization_for_mapped_v6` test in `edns_cookie.rs`.

No fixes deferred to the user; the doc-comment staleness in `edns_cookie.rs`'s module doc (flagged informationally) is explicitly section-09's scope, not touched here.
