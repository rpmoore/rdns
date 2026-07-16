# Section 08: `/security-review` pass — final report

Run via the `/security-review` skill against the complete branch diff (union
of sections 01-07: `Cargo.toml`/`Cargo.lock`, `src/protocol/edns_cookie.rs`,
`src/protocol/mod.rs`, `src/resolver/mod.rs`, `src/resolver/cache/assemble.rs`,
`src/main.rs`, `docs/knowledge/resolver/caching/answer-cache.md`).

## Result: no HIGH or MEDIUM confidence vulnerabilities identified

An adversarial vulnerability-identification pass covered input validation on
the untrusted EDNS options byte blob, write-direction OPT serialization,
`CookieSecret` randomness quality, secret-leakage via Debug/logging, MAC
construction (server-cookie reversibility), and cache-key isolation from
cookie bytes. No candidate finding cleared the >80%-confidence exploitability
bar, so no false-positive-filtering pass was needed.

## Required checklist (per `section-08-security-review.md`)

### 1. No regression in any non-Cookie EDNS-bypass case

Confirmed via `cargo test --lib`: `resolve_bypasses_cache_for_unsupported_edns_options`,
`resolve_bypasses_cache_for_unsupported_edns_flags_and_version`, and
`resolve_bypasses_cache_for_cookie_combined_with_other_option` all pass on
the final combined diff (603 lib tests, 0 failed).

### 2. Malformed-Cookie-length case still bypasses safely

Confirmed by direct code inspection (see vulnerability-identification pass
above): `parse_cookie_option`/`is_solely_cookie_option`
(`src/protocol/edns_cookie.rs:75-111,129-156`) bounds-check every length
field read from the untrusted blob before use (`options.len() - cursor < 4`
guard, `checked_add` for offset arithmetic, `data_end > options.len()` guard
before slicing) — malformed lengths return `None`/fall through to existing
bypass behavior, never panic or read out of bounds. Existing tests
`parse_cookie_option_rejects_malformed_lengths`,
`parse_cookie_option_rejects_truncated_tlv_bytes`,
`is_solely_cookie_option_rejects_malformed_absent_duplicate` all pass.

### 3. `CookieSecret` never logged/exposed/serialized anywhere reachable by a client

Confirmed: `CookieSecret` (`src/protocol/edns_cookie.rs:56-68`) has no
`Debug`/`Display`/`Serialize` impl, deliberately (documented in its own doc
comment). `ResolveQuery`, which holds it, does not derive `Debug` either —
no transitive-derive path exists. `src/main.rs:130` constructs it via
`CookieSecret::generate()` and never logs it. `build_server_cookie`
delegates to `domain::base::opt::cookie::StandardServerCookie::calculate`
(keyed SipHash-2-4), not a reversible construction — the secret cannot be
derived from observing server-cookie outputs. `CookieSecret::generate()`
uses `rand`'s OS-seeded ChaCha CSPRNG (`rand = "0.10"`, pulling in
`chacha20`/`getrandom`), producing 16 bytes (128 bits), meeting RFC 9018
§4.2's SHOULD-minimum.

### 4. No cache-key or `MissKey` code path depends on cookie bytes

Confirmed: `MissKey` and `QuestionKey` (`src/resolver/mod.rs`) carry only
qname/qtype/qclass/namespace/DO — no `ClientCookie`/cookie-derived value.
`cache_supported()` uses `is_solely_cookie_option` purely as an admission
gate (yes/no), never as key material. Test
`resolve_cache_lookup_key_ignores_client_cookie_bytes` (`mod.rs:19621`)
passes on the final diff, pinning that two Cookie-bearing queries with
different client cookies produce an identical cache lookup/key.

## Additional considerations

- **Randomness quality**: confirmed appropriate (see checklist item 3).
- **Timestamp handling**: `build_server_cookie` takes `now: SystemTime` as a
  parameter from every call site (sourced from the injected `Clock`), never
  calls `SystemTime::now()` internally.
- **DoS surface**: out of scope per this review's exclusions (denial of
  service / resource exhaustion) and per the plan's own note that SipHash-2-4
  is deliberately cheap.
- **OPT write-path panics**: confirmed no panic risk — the only producer of
  the `options` vector on the write path is `build_cookie_option`'s fixed
  28-byte output, never attacker-controlled length.
- **Knowledge-bundle doc accuracy**: `docs/knowledge/resolver/caching/answer-cache.md`'s
  security-trade-off paragraph was independently fact-checked during section
  07's code review (see `implementation/code_review/section-07-review.md`)
  and confirmed not to overstate protection — it explicitly states "echo/
  interop only," no validation/BADCOOKIE/rotation.

## Verification

- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `cargo test` (full suite, lib + integration): 603 lib tests passed, all
  integration test binaries passed (non-network tests; network-dependent
  e2e tests remain `#[ignore]`d as pre-existing).

**Conclusion: ready to open the PR.**
