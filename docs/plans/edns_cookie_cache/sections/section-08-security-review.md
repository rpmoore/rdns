Now I'll write section 08 in a matching style.

---

# Section 08: `/security-review` pass (final section)

## Implementation notes (as built)

Ran the project's `/security-review` skill against the complete combined
diff of sections 01-07 (adversarial vulnerability-identification pass +
false-positive filtering). **Result: no HIGH or MEDIUM confidence
vulnerabilities identified** — the vulnerability-identification pass
returned zero candidates above the >80%-confidence threshold, so no
false-positive-filtering sub-pass was needed. Full report:
`docs/plans/edns_cookie_cache/reviews/section-08-security-review.md`.

All four required checklist items explicitly confirmed (test names and
file:line evidence in the review report):
1. No regression in non-Cookie EDNS-bypass cases.
2. Malformed-Cookie-length inputs bounds-checked, never panic/OOB.
3. `CookieSecret` never logged/exposed/serializable; adequate CSPRNG
   entropy; server-cookie MAC not reversible.
4. No cache-key/`MissKey` path depends on cookie bytes.

No actionable findings surfaced, so no fixes were needed for this section.
`cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
and `cargo test` (full suite, including integration tests) were all
re-verified clean against the final combined diff.

## Dependencies

This is the **final section** of the plan — it depends on all prior sections having landed:

- **section-01-cargo-dependencies** (`rand` direct dependency, `domain`'s `siphasher` feature)
- **section-02-edns-cookie-module** (`src/protocol/edns_cookie.rs`: `CookieSecret`, `ClientCookie`, `parse_cookie_option`, `is_solely_cookie_option`, `build_server_cookie`, `build_cookie_option`)
- **section-03-cache-supported-narrowing** (`cache_supported()` in `src/resolver/mod.rs`)
- **section-04-query-features-opt-threading** (`QueryFeatures` client-cookie field, `requester_opt_record` and its four callers in `src/resolver/cache/assemble.rs`, `CookieSecret` DI wiring from `main.rs`)
- **section-05-cache-miss-opt-path** (`mirrored_client_opt_record`/`message_edns_opt_record` cookie-aware rebuild)
- **section-06-opt-record-serialization** (OPT-record wire encoder emitting non-empty `options`)
- **section-07-knowledge-bundle-docs** (`docs/knowledge/resolver/caching/answer-cache.md` update)

It blocks nothing else — it is the last gate before the PR opens. Do not start this section until sections 01-07 are complete and `cargo test` passes on the full, combined diff; this review is meant to run against the *complete* feature diff, not an individual section's diff.

## Background: why this section exists

`AGENTS.md`'s Change Workflow section states:

> Before opening a PR that touches auth, parsing of untrusted input, or network-facing code, auto-run `/security-review`.

and, under Automatic Triggers:

> PR touches auth/untrusted-input/network code → run `/security-review` before opening PR (Change Workflow).

This feature parses untrusted network input (the raw EDNS options TLV blob from an incoming DNS query, `edns.options: Vec<u8>`) to make a caching decision, and constructs and emits a cryptographic value (the RFC 9018 server cookie, keyed by `CookieSecret`) into every DNS response. That is squarely both "parsing of untrusted input" and "network-facing code" per the trigger above — so this is a mandatory step, not an optional one, before this PR opens.

`claude-plan.md`'s Overview section states this explicitly as a plan constraint:

> This is a separate PR from the already-landed `ttl_remaining` work... It is security-sensitive (parses untrusted network input to feed a caching decision) and the final section of this plan is a mandatory `/security-review` pass before the PR opens, per `AGENTS.md`.

## Task

Run the `/security-review` command (or the equivalent adversarial security-focused review process available in your environment) against the **complete diff** for this feature — i.e. the union of sections 01 through 07's changes, not any single section in isolation. This is a review-only section: **no new source code, no new tests are written as part of this section** (per `claude-plan-tdd.md` Section 8: "No new tests — review-only"). The deliverable is a completed review with every checklist item below explicitly confirmed (not merely assumed), plus any fixes the review surfaces as necessary before the PR can open.

If the review surfaces an actionable finding, fix it as part of this section, then re-run the affected checklist item(s) (and, if the fix was non-trivial, consider a second review pass on the updated diff — mirroring the "if feedback fixes materially change the diff, run one follow-up adversarial review" convention `AGENTS.md` already establishes for plan/diff review).

## Files in scope for this review

The full diff to review spans (adjust to whatever the actual landed diff touches, per each prior section's own file list):

- `Cargo.toml` (section-01: `rand` dependency, `domain`'s `siphasher` feature)
- `src/protocol/edns_cookie.rs` (section-02: new module — this is where untrusted bytes are parsed and where the secret and hash construction live)
- `src/resolver/mod.rs` (section-03: `cache_supported()`; section-04: `QueryFeatures`; section-05: `mirrored_client_opt_record`/`message_edns_opt_record`/`recursive_synthesis_reused_own_framing`)
- `src/resolver/cache/assemble.rs` (section-04: `requester_opt_record` and its four callers — `build_servfail`, `finish_with_truncation_check`, `assemble_response`, `assemble_negative_response`)
- `src/protocol/mod.rs` (section-06: `build_opt_record`/`build_opt_record_with_extended_rcode` write-direction options serialization)
- `src/main.rs` (section-04: `CookieSecret::generate()` construction and DI wiring, mirroring `SystemClock`'s construction at `main.rs:739-741`)
- `docs/knowledge/resolver/caching/answer-cache.md` (section-07: documentation — review this too, since an inaccurate security-trade-off writeup is itself a finding worth catching here)

## Required checklist (must be explicitly confirmed, not assumed)

These four items come directly from `claude-plan.md`'s section-breakdown item 8 and `claude-plan-tdd.md`'s Section 8, and are the minimum bar for this section to be considered complete:

### 1. No regression in any non-Cookie EDNS-bypass case

Re-run the full `resolve_bypasses_cache_for_unsupported_*` test group in `src/resolver/mod.rs` (this includes the repointed `resolve_bypasses_cache_for_unsupported_edns_options` from section-03, and the unmodified `resolve_bypasses_cache_for_unsupported_edns_flags_and_version`) and confirm every one of them still asserts bypass (`CacheBypass`/`CacheMiss` incremented, `cache.lookups`/`cache.stores` empty) exactly as before this plan. Cross-check this against Goal 5 of the plan: "non-zero extended RCODE, non-zero version, unrecognized flag bits, and any other/malformed EDNS option... must continue to bypass the cache exactly as today." Also confirm the Cookie+other-option case (e.g. Cookie+NSID, section-03's `resolve_bypasses_cache_for_cookie_combined_with_other_option`) still bypasses — this is the case most likely to have been weakened by an overly-loose `is_solely_cookie_option` implementation, since it's the one place `parse_cookie_option` and `is_solely_cookie_option` must diverge.

### 2. Malformed-Cookie-length case still bypasses safely

Confirm `parse_cookie_option`/`is_solely_cookie_option` reject every malformed-length COOKIE option (lengths other than 8, or 16-40 inclusive — e.g. 9, 15, 41 bytes) by returning `None`, and that `cache_supported()` correctly falls through to its existing "any weird EDNS content bypasses the cache" behavior for those cases (this is an explicit non-goal per `claude-plan.md`: "RFC 7873 §5.2.2 FORMERR for malformed-length COOKIE options — falls back to today's generic... behavior, unchanged" — i.e. no FORMERR is generated, the query is simply treated as cache-incompatible and processed normally, matching pre-plan behavior for any non-empty, non-solely-Cookie options blob). Also confirm a truncated/short options blob (fewer bytes than the TLV header claims) cannot cause a panic, out-of-bounds slice, or integer-overflow read in `parse_cookie_option`/`is_solely_cookie_option` — this is parsing of fully untrusted, attacker-controlled bytes, so bounds-checking on every length field read is the primary thing to scrutinize here, not just the "what does a well-formed-but-wrong-length option do" case.

### 3. `CookieSecret` never logged/exposed/serialized anywhere reachable by a client

Confirm:

- `CookieSecret`'s raw secret bytes are never included in any `Debug`/`Display` output, log line, metric, or event emitted by the resolver (check any `#[derive(Debug)]` on `CookieSecret` itself — if derived, confirm no code path actually logs a `CookieSecret` value; if there's any risk, a manual `Debug` impl that redacts the bytes is preferable to a derived one that doesn't).
- The secret is used **only** as an input to `build_server_cookie`'s SipHash-2-4 keyed hash — it is never itself transmitted, never part of any wire-format byte range, and never derivable from the server-cookie output it's used to compute (this is an inherent property of a correctly-implemented keyed hash/MAC, but confirm the implementation actually delegates to `domain::base::opt::cookie::StandardServerCookie::calculate` or a straightforward `siphasher` call, rather than e.g. XORing the secret directly into output bytes or otherwise doing something that would leak key material).
- No test fixture or debug-assertion path accidentally prints the secret to test output in a way that could end up in CI logs (low severity, but worth a quick grep).

### 4. No cache-key or `MissKey` code path depends on cookie bytes

Confirm the cache lookup key (`self.cache.lookup_chain(...)` inputs, `mod.rs:4433-4441` in the pre-plan line numbering) and `MissKey` tuple construction (`mod.rs:4462-4474` in the pre-plan line numbering — `(qname, qtype, qclass, epoch, dnssec_ok)`) still contain **no** reference to `edns.options`, `ClientCookie`, or any cookie-derived value, across all of sections 03-06's changes. Re-run section-03's `resolve_cache_lookup_key_ignores_client_cookie_bytes` test (two Cookie-bearing queries for the same qname with different client cookies must produce the identical cache lookup/key) and confirm it still passes on the full, final diff. This is the load-bearing invariant that makes Goal 1 (admitting Cookie queries into the cache) safe at all — if any later section (04/05/06) accidentally threaded a cookie value into the cache-key computation itself (as opposed to only into the per-request OPT record), that would silently fragment the cache per-client-cookie, which is both a functional regression and a subtle correctness/security concern (an attacker varying their own client cookie could otherwise force excessive cache misses/cardinality against a shared cache entry).

## Additional review considerations (beyond the four required checklist items)

These aren't separately called out in the plan's checklist but are natural extensions of "security review of code parsing untrusted input and computing a cryptographic value" and worth the reviewer's attention:

- **Randomness quality of `CookieSecret::generate()`**: confirm it uses a cryptographically-suitable RNG (the `rand` crate's default `thread_rng`/`OsRng`-backed generator, not a fixed seed or a non-cryptographic PRNG) and produces at least 128 bits (16 bytes) per RFC 9018 §4.2's SHOULD. Section-02's test (`CookieSecret::generate()` produces the expected byte length, two calls produce different secrets) is a basic sanity check, not a substitute for confirming the underlying RNG choice is appropriate.
- **Timestamp handling in `build_server_cookie`**: confirm the 4-byte big-endian Unix timestamp field is derived from the injected `Clock`/`now: SystemTime` parameter (not `SystemTime::now()` called directly inside this function), consistent with the `ttl_remaining` Clock-DI convention this plan explicitly follows — this matters for testability, not for security per se, but a hardcoded or unfed clock here would be a correctness bug worth catching in the same pass.
- **Denial-of-service surface**: confirm that computing a server cookie (one SipHash-2-4 call per response) doesn't introduce a meaningfully exploitable CPU-cost asymmetry attackers could use to amplify load, given this happens on every response for every Cookie-bearing query, cache hit or miss. SipHash-2-4 is deliberately cheap and this is unlikely to be a real finding, but it's worth a one-line confirmation rather than silence.
- **No new panics on the OPT-record write path**: section-06 extends the OPT wire encoder to serialize a non-empty `options` byte vector for the first time in the write direction — confirm this can't panic or produce a malformed RDATA length field for any legal input (e.g. options vector larger than fits in the record's length encoding), even though in practice the only producer of that vector today is `build_cookie_option`'s fixed 24-byte output.
- **Knowledge-bundle doc accuracy** (cross-check against section-07's output): confirm `docs/knowledge/resolver/caching/answer-cache.md`'s security-trade-off paragraph is not just present but *accurate* — specifically that it does not overstate what this feature provides (it must not imply any anti-spoofing/BADCOOKIE/validation behavior exists). An inaccurate security doc is itself a security-review-relevant finding, since it could lead a future reader/operator to mistakenly believe this resolver has spoofing protection it does not have.

## What "done" looks like for this section

- Every item in the "Required checklist" above has an explicit, written confirmation (not a silent assumption) — e.g. as review notes or PR-description bullet points, referencing the specific test(s) re-run or code path(s) inspected for each.
- Any actionable finding from the review has either been fixed (with the corresponding checklist item re-verified afterward) or explicitly documented as intentionally not addressed, with a one-line reason — mirroring the `AGENTS.md` convention: "Address actionable feedback before committing, or document why feedback is not being acted on."
- The full test suite (`cargo test`) passes on the complete, final diff.
- `cargo fmt --all -- --check` and `cargo clippy --all-targets` are clean per `RUST.md`'s gates, run against the complete diff (not just this section's own — since this section adds no code of its own, this is really a final confirmation that sections 01-07 collectively leave the repo in this state).
- Only after all of the above is the PR opened.

## Verification for this section

- No `cargo test` additions of its own — this section's "test" is the completed review itself plus re-running the specific existing/prior-section tests called out above (the `resolve_bypasses_cache_for_unsupported_*` group, the malformed-Cookie-length cases, the `resolve_cache_lookup_key_ignores_client_cookie_bytes` invariant test) against the final, combined diff.
- `cargo fmt --all -- --check`, `cargo clippy --all-targets`, `cargo test` (full suite) — final confirmation before PR, per `RUST.md`.
- Confirm `docs/knowledge/resolver/caching/answer-cache.md` (section-07's output) is reviewed as part of this pass, not skipped as "just docs" — an inaccurate security-trade-off statement there is a real finding.
- Do not consider this section — and therefore the whole plan — done until the PR is ready to open with every required-checklist item explicitly confirmed.

---

Section content written to `/home/rpmoore/code/rdns/docs/plans/edns_cookie_cache/sections/section-08-security-review.md` (via the SubagentStop hook).

Relevant files read while preparing this section:
- `/home/rpmoore/code/rdns/docs/plans/edns_cookie_cache/sections/.prompts/section-08-security-review-prompt.md`
- `/home/rpmoore/code/rdns/docs/plans/edns_cookie_cache/sections/index.md`
- `/home/rpmoore/code/rdns/docs/plans/edns_cookie_cache/claude-plan.md`
- `/home/rpmoore/code/rdns/docs/plans/edns_cookie_cache/claude-plan-tdd.md`
- `/home/rpmoore/code/rdns/docs/plans/edns_cookie_cache/sections/section-07-knowledge-bundle-docs.md` (for style/consistency reference)
- `/home/rpmoore/code/rdns/docs/plans/edns_cookie_cache/sections/section-03-cache-supported-narrowing.md` (for style/consistency reference)
- `/home/rpmoore/code/rdns/RUST.md` (verification gates referenced)