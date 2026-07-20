# Security review: Track B (BADCOOKIE) + Track A (DNSSEC), section-09 gate

Run via `/security-review` per plan §C2 and AGENTS.md's standing pre-PR
gate, covering the full branch diff (`v0.1.10_prep` vs `main`) with focus
on Track B's detection/comparison logic (section-08) and wire-response
builder (section-07), as required to close section-09.

## Result: no HIGH or MEDIUM findings above the 80% exploitability
confidence bar.

## Scope reviewed

- **Track A (DNSSEC):** `src/config/mod.rs` (trust-anchor loading/parsing),
  `src/resolver/dnssec_validation.rs` (validator wiring, fail-closed
  timeout/error handling), `src/resolver/cache/assemble.rs`/`entry.rs`/
  `shard.rs` (CD-bit gating, AD-bit gating, Bogus-entry serve-stale
  exclusion), `src/main.rs` (trust-anchor wiring, default-enable).
- **Track B (RFC 7873 DNS Cookies / BADCOOKIE):** `src/protocol/edns_cookie.rs`
  (`locate_cookie_for_verification`, `server_cookie_matches`),
  `src/protocol/mod.rs` (`build_badcookie_response`, wire-level RCODE-23
  header composition), `src/resolver/mod.rs` (`probe_cache`/
  `invalid_server_cookie` wiring, UDP-only gating).

## Findings

None met the HIGH/MEDIUM confidence bar. Specifically checked and found
sound:

- `locate_cookie_for_verification` (`src/protocol/edns_cookie.rs:158-207`)
  bounds every slice access with `declared_end.min(options.len())` before
  indexing — a truncated/malformed COOKIE TLV degrades to `Malformed`/
  `NoCookieOption`, never an out-of-bounds read or panic.
- `server_cookie_matches` (`src/protocol/edns_cookie.rs:318-352`) rejects
  any non-16-byte tail, checks the RFC 9018 version byte explicitly, and
  recomputes the hash using the *presented* cookie's own embedded
  timestamp (not "now") — correct behavior for accepting legitimately
  reused, still-fresh cookies.
- `invalid_server_cookie` (`src/resolver/mod.rs:6875-6903`) correctly gates
  BADCOOKIE rejection to UDP-only and treats `NoCookieOption`/`Duplicate`/
  `ClientOnly` as non-errors, never fabricating a false rejection.
- `build_badcookie_response` (`src/protocol/mod.rs:696-760`) composes
  header flags and the extended-RCODE-23 split correctly, and attaches a
  freshly issued, correctly computed server cookie.
- `dnssec_validation::validate_response` is fail-closed: chase timeouts,
  transport errors, and malformed input all map to `DnssecState::Bogus`,
  never `Insecure` or silently `Unvalidated`.

## Candidates considered and ruled out (low confidence, not actionable)

1. **Non-constant-time cookie-hash comparison** — lives in the `domain`
   crate (third-party, not this PR's code); DNS Cookies aren't a strict
   auth boundary and a practical remote timing attack against an 8-byte
   SipHash comparison over UDP isn't realistic. Confidence <20%.
2. **`Malformed { client_cookie: None }` short-circuits to "not
   rejected"** — code's own comments assert this is unreachable from a
   real decoded wire message (`validate_edns_options` already guarantees
   TLV-length consistency); even if reached, worst case is "treat as no
   cookie," not an auth bypass. Very low confidence.
3. **DNS Cookie replay window** — `server_cookie_matches` has no
   freshness check beyond format correctness (RFC 9018 recommends, does
   not mandate, one); only matters against an on-path attacker who can
   already observe traffic. Out of this review's scope (DoS/replay
   excluded).

No files were modified as part of this review.
