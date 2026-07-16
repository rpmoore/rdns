# Section 04 code review interview

## Review summary
Mechanical plumbing (QueryFeatures.client_cookie, cookie_secret/client_ip
threading through assemble.rs, ResolveQuery DI, ~40 test call-site fan-out)
verified correct. Visibility split (CookieSecret/ClientCookie -> pub, rest
of edns_cookie.rs stays pub(crate)) confirmed minimal and non-leaky.

## Key finding: this section is already live, not deferred
The plan's Scope/Verification sections claim "this section introduces no
new observable end-to-end (wire-level) behavior... the wire encoder still
hardcodes empty options until section-06 lands." That's factually wrong
about the current codebase: `write_rdata`'s `RecordData::OPT` arm
(`src/protocol/mod.rs:1518`) already does
`out.extend_from_slice(&info.options)` unconditionally — there is no
separate "wire encoder gate" to wait on. The moment this diff lands,
cache-hit responses to a Cookie-bearing query emit a real RFC-9018 COOKIE
option on the wire in production, well ahead of the section-05/06 rollout
the plan assumed.

## Triage
1. **No test exercised the actual wire round-trip for the cookie case** —
   every existing cookie-related test asserted against the in-memory
   `Record`/`QueryFeatures` only. Given the behavior is live, this was a
   real coverage gap, not a nitpick. **Auto-fixed**: added
   `assemble_response_serializes_server_cookie_option_on_wire_for_cookie_bearing_query`
   (`src/resolver/cache/assemble.rs`), which calls `assemble_response`
   with a cookie-bearing `QueryFeatures`, parses the response bytes back
   with `Message::parse`, and asserts the wire-decoded EDNS options match
   the expected COOKIE TLV byte-for-byte.
2. **Stale `#![allow(dead_code)]` + comment** in `edns_cookie.rs` claiming
   the module is "intentionally unwired until later plan sections... allow
   dead_code until then" — false as of this section (every item is now
   consumed: `is_solely_cookie_option` by section-03,
   `parse_cookie_option`/`build_server_cookie`/`build_cookie_option`/
   `CookieSecret::generate` by this section). **Auto-fixed**: removed the
   allow and its comment; `cargo build` confirms zero dead-code warnings
   without it.
3. **`main.rs` moves `cookie_secret` into `.with_cookie_secret(...)`
   rather than cloning it**, and reviewer flagged that section-05's
   cache-miss path will likely need the same secret later. **Not fixed**:
   speculative — adding an `Arc::clone` for a need that doesn't exist yet
   goes against this project's "don't design for hypothetical future
   requirements" convention. Section-05 can add the clone itself when it
   actually needs a second handle.
4. **`requester_opt_record` runs twice per truncated response** (once in
   `assemble_response`, again inside `finish_with_truncation_check`), and
   cookie support adds a real SipHash computation to that duplicate call.
   **Not fixed**: pre-existing shape, not introduced by this section; pure
   micro-efficiency note, no correctness impact.
5. **Every `ResolveQuery` constructor defaults to its own independently
   generated `Arc::new(CookieSecret::generate())`**, so a future caller
   that forgets `.with_cookie_secret(...)` gets a silently-fresh
   per-instance secret rather than a compile error. **Not fixed**: this is
   the explicit setter-pattern trade-off the plan itself chose (mirroring
   `max_chain_depth`/`chaos`), not a defect introduced here.
6. Plan's File Paths section calls `src/protocol/edns_cookie.rs` a
   "read-only dependency... not modified by this section" — stale as of
   the `pub`/`pub(crate)` visibility split. Addressed in the section-04
   doc update (step 9), not here.

No user interview needed — both real action items (1, 2) were low-risk,
unambiguous improvements with no tradeoff to weigh; the rest are
explicitly out of scope or already-accepted plan trade-offs.
