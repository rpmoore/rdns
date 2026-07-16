# Section 05: Cache-miss/recursive-response OPT path gains Cookie support

## Implementation notes (as built)

Implemented substantially as planned, with one deliberate naming deviation and
one scope correction found during code review:

- **`mirrored_client_opt_record` was NOT widened in place.** A new, separate
  function `mirrored_client_opt_record_with_cookie` was added instead
  (`src/resolver/mod.rs`, next to the original), delegating to a new
  protocol-layer helper `message_edns_opt_record_with_cookie`
  (`src/protocol/mod.rs`, next to `message_edns_opt_record`). This plan's own
  "Recommended shape" section was internally contradictory: it asked to widen
  `mirrored_client_opt_record`'s signature in place, but also said call site 1
  (`synthesize_recursive_cname_response`, `mod.rs:1416`) must stay on the old,
  cookie-unaware call — that function runs inside `ResolutionResponse::recursive_response`,
  a backend-layer construction site with no single requester's client IP or
  cookie secret available (its output can be shared across coalesced
  requesters). A separate function is the only way to satisfy both
  constraints: call site 1 compiles unchanged; call sites 2-5 use the new
  cookie-aware function.
- **`recursive_synthesis_reused_own_framing`** gained the planned
  cookie-forced-rebuild condition: if either `decoded.message` or
  `synthesis.original_query` carries a well-formed client cookie
  (`edns_cookie::parse_cookie_option`), framing is never considered reused,
  regardless of whether question/DO bit otherwise match.
- **Scope correction (found in code review, not in the original plan):**
  `ResolveQuery::local_entry_response` (`mod.rs:4483+`) shares
  `truncated_response_for_query` with the recursive-miss path for its own
  UDP-payload-limit truncation fallback — a caller the plan's "five call
  sites" list never accounted for. Widening `truncated_response_for_query`'s
  signature (to thread `cookie_secret`/`client_ip`/`now`) would have silently
  made local-entry responses echo cookies *only when truncated*, while the
  untruncated branch (`build_a_answers_response` et al.) stays cookie-unaware
  by design (out of scope per this plan). Fixed by inlining a plain,
  cookie-unaware truncated-response build directly in `local_entry_response`
  (using the untouched `mirrored_client_opt_record`) instead of reusing the
  now-cookie-aware helper. Regression test:
  `resolve_truncated_local_entry_response_omits_cookie_option`.

Files touched: `src/protocol/mod.rs` (new `message_edns_opt_record_with_cookie`,
doc-comment fix on `build_opt_record_with_options`), `src/resolver/mod.rs`
(new `mirrored_client_opt_record_with_cookie`; `cookie_secret`/`client_ip`/`now`
threaded through `rebuild_recursive_response_with_own_framing`,
`truncated_response_for_query`, `enforce_udp_payload_limit_after_reserialize`,
and all 8 call sites inside `prepare_backend_result`; cookie-aware
`opt_matches` in `recursive_synthesis_reused_own_framing`; `local_entry_response`
kept cookie-unaware).

Tests added (all in `src/resolver/mod.rs`'s `#[cfg(test)] mod tests`):
- `resolve_recursive_miss_response_carries_cookie_option_for_cookie_bearing_query`
  — single, non-coalesced recursive-miss resolve with a Cookie-bearing query;
  asserts the wire response's OPT carries a correct server cookie.
- `resolve_coalesced_miss_gives_each_requester_a_distinct_cookie` — coalesced
  leader+follower with distinct client cookies/IPs; asserts each gets its own
  echoed client cookie and a distinct server cookie.
- `recursive_synthesis_reused_own_framing_returns_false_when_cookie_present` —
  direct unit test covering both directions (cookie on the requester's own
  query; cookie only on the original synthesizing query) plus a non-cookie
  regression case.
- `resolve_truncated_local_entry_response_omits_cookie_option` — regression
  test for the scope correction above.

Verification: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --lib` (603 passed, 0 failed) all green.

## Scope

Extend the resolver's **cache-miss / recursive-response** OPT-record rebuild
machinery — `mirrored_client_opt_record` and the functions that call it in
`src/resolver/mod.rs` — so that a fresh, correctly-shaped RFC 9018 server
cookie is attached to *every* miss-path response whose originating query
carried a well-formed RFC 7873 COOKIE option, mirroring what section-04 does
for the **cache-hit** path via `requester_opt_record`
(`src/resolver/cache/assemble.rs:437-447`).

This closes a gap a plan-review pass caught: `requester_opt_record` and its
four callers (`build_servfail`, `finish_with_truncation_check`,
`assemble_response`, `assemble_negative_response`, all in
`src/resolver/cache/assemble.rs`) only run on the cache-**hit** serve path.
Goal 2 of the overall plan ("compute and attach a fresh server cookie on
every response, cache hit **or miss**") is not satisfied without also
touching the separate mechanism recursive-miss and coalesced-response
handling uses to rebuild/reattach an OPT record: `mirrored_client_opt_record`
(`src/resolver/mod.rs:1625-1630`), which delegates to
`crate::protocol::message_edns_opt_record` (`src/protocol/mod.rs:1296-1303`).

## Dependencies (reference only — do not re-derive here)

- **Section 02** (`src/protocol/edns_cookie.rs`) must exist and provide:
  `ClientCookie`, `CookieSecret`, `parse_cookie_option(options: &[u8]) ->
  Option<ClientCookie>`, `build_server_cookie(secret, client_cookie,
  client_ip, now) -> [u8; 16]`, `build_cookie_option(client_cookie,
  server_cookie) -> Vec<u8>`. This section only ever uses
  `parse_cookie_option` (the permissive extractor), never
  `is_solely_cookie_option` (the stricter cache-admission predicate from
  section 03) — a cache-miss response must still echo a cookie even for a
  query that also carried some other EDNS option (e.g. NSID) and therefore
  wasn't cache-admissible.
- **Section 04** must have already landed: `QueryFeatures` gains a
  `client_cookie: Option<ClientCookie>` field (or equivalent), and — most
  importantly for this section — `ResolveQuery` gains an
  `Arc<CookieSecret>` field (call it `cookie_secret`), constructed once in
  `main.rs` alongside `SystemClock` and threaded through the same
  DI seam `Arc<dyn Clock>` already uses (`ResolveQuery`'s `clock` field,
  `src/resolver/mod.rs:3362`). `prepare_backend_result` (the method this
  section's changes live inside) is a method on `ResolveQuery`, so
  `self.cookie_secret` and `self.clock` are both already in scope there —
  no new plumbing into that method is needed, only new parameters on the
  free functions it calls.
- **Section 06** (OPT-record wire serialization) must have already landed:
  `build_opt_record`/`build_opt_record_with_extended_rcode`
  (`src/protocol/mod.rs:1246-1278`) must serialize a non-empty `options`
  byte vector for this section's tests to observe a Cookie option on
  parsed response bytes at all. Section 05 is ordered *after* section 06 in
  the dependency graph specifically so its tests can assert end-to-end on
  real wire bytes rather than only on intermediate `Record`/`EdnsInfo`
  values.

## Background: the two paths that build a miss-path OPT record

`src/resolver/mod.rs` has (today, pre-this-section):

```rust
fn mirrored_client_opt_record(
    original_query: &Message,
    configured_max_udp_payload_size: usize,
) -> Option<Record> {
    crate::protocol::message_edns_opt_record(original_query, configured_max_udp_payload_size)
}
```

Called from five places:

1. `src/resolver/mod.rs:1399`, inside `synthesize_recursive_cname_response`
   — builds the OPT baked into the initial, always-DNSSEC-complete
   recursive response (`ResolutionResponse::recursive_response`,
   `mod.rs:2544-2586`, called from `RecursiveResolutionBackend`'s
   `evaluate_authority_response`, `mod.rs:7221-7250`/`7261-7271`). **This
   call site is deliberately left unmodified by this section** — see
   "Design decision" below for why.
2. `src/resolver/mod.rs:1685`, inside `rebuild_recursive_response_with_own_framing`
   (`mod.rs:1670-1697`) — rebuilds header/question/OPT from a specific
   requester's own `decoded.message` when their framing doesn't match
   whichever request originally synthesized a shared/coalesced response.
3. `src/resolver/mod.rs:1721`, inside `truncated_response_for_query`
   (`mod.rs:1716-1731`) — builds a TC=1 response, still needs a mirrored
   OPT per RFC 6891 §7.
4. `src/resolver/mod.rs:4960-4963`, directly inside `prepare_backend_result`'s
   DO=false "filtering would actually change something" branch.
5. `src/resolver/mod.rs:5023-5029`, indirectly, via
   `rebuild_recursive_response_with_own_framing` again, in
   `prepare_backend_result`'s DO=true fast-path branch.

All four call sites that need Cookie treatment (2-5) are reachable from
`prepare_backend_result` (`mod.rs:4665`, a method on `ResolveQuery`, `&self`
in scope), which has everything needed: `self.cookie_secret`, `self.clock`,
and `request.client_ip` (`request: &ResolveRequest`, already a parameter).

## The key design decision: `recursive_synthesis_reused_own_framing` must treat a cookie-bearing message as never framing-reusable

`prepare_backend_result` has a "fast path" that trusts the already-built
`response_bytes` verbatim whenever
`recursive_synthesis_reused_own_framing(decoded, synthesis)` returns `true`
(`mod.rs:4863-4881` and `4997-5023`) — i.e. whenever this requester's own
question-echo/OPT framing already matches whatever the *original*
synthesizing request baked in. Today that function
(`mod.rs:1756-1771`) only compares the echoed question and the DO bit:

```rust
fn recursive_synthesis_reused_own_framing(
    decoded: &DecodedQuery,
    synthesis: &RecursiveSynthesisContext,
) -> bool {
    let original_query = &synthesis.original_query;
    let question_matches = decoded.message.questions.first() == original_query.questions.first();
    let opt_matches = match (decoded.message.edns.as_ref(), original_query.edns.as_ref()) {
        (None, None) => true,
        (Some(this), Some(original)) => this.dnssec_ok == original.dnssec_ok,
        _ => false,
    };
    question_matches && opt_matches
}
```

A server cookie is time-dependent (RFC 9018 §4.4 bakes in a fresh Unix
timestamp) and must never be replayed — so even in the *ordinary,
non-coalesced* case (where `synthesis.original_query` genuinely is this same
requester's own query), reusing whatever OPT got baked in at
`synthesize_recursive_cname_response` time (call site 1 above, which this
section does **not** give access to `CookieSecret`/`client_ip`) would either
omit the cookie entirely or ship a stale one. The fix: extend `opt_matches`
so that **if either `decoded.message` or `original_query` carries a
well-formed client cookie** (`parse_cookie_option` returns `Some` on its
`edns.options`), framing is never considered reused — this forces every
cookie-bearing response through `rebuild_recursive_response_with_own_framing`
(call sites 2/5), which *does* run inside `prepare_backend_result` and *does*
have `self.cookie_secret`/`self.clock`/`request.client_ip` available to pass
down.

This is exactly why call site 1 (`synthesize_recursive_cname_response`,
inside the backend-layer construction of the shared response) is left
untouched: it never needs `CookieSecret` or a client IP threaded into it at
all, because its output is never trusted as final once a cookie is in play
— the forced-rebuild path downstream always overwrites it with a
freshly-built, correctly-timestamped one.

## Recommended shape of the change (implementer's call on exact naming)

Widen `mirrored_client_opt_record` to accept the extra inputs it needs when
the message carries a client cookie:

```rust
fn mirrored_client_opt_record(
    original_query: &Message,
    configured_max_udp_payload_size: usize,
    cookie_secret: &CookieSecret,
    client_ip: IpAddr,
    now: SystemTime,
) -> Option<Record> {
    // delegates to a new protocol-layer helper, e.g.
    // `crate::protocol::message_edns_opt_record_with_cookie`, which:
    // 1. builds the base OPT exactly as `message_edns_opt_record` does today
    //    (EDNS presence + DO bit, options empty)
    // 2. if `parse_cookie_option(&edns.options)` is `Some(client_cookie)`,
    //    computes `build_server_cookie` + `build_cookie_option` and sets
    //    the result as the OPT's `options` bytes
    ...
}
```

Add the new protocol-layer helper as a **separate function** from
`message_edns_opt_record` (`src/protocol/mod.rs:1296-1303`) rather than
widening that function's own signature in place —
`message_edns_opt_record` is also called from `build_question_response`
(`protocol/mod.rs:962`, backing `build_a_answers_response`,
`build_aaaa_answers_response`, `build_nodata_response`) and
`build_txt_answer_response` (`protocol/mod.rs:717-759`, the CHAOS-class
`version.bind.`-style synthetic responses), both of which back
`ResolveQuery::local_entry_response` (`mod.rs:4364-4399`) — a **third**,
distinct resolution path (statically-configured local entries) that this
plan's architecture section and TDD test list never mention and that has no
test coverage in this section. Leaving `message_edns_opt_record` itself
untouched means those call sites need zero changes and stay byte-for-byte
identical; only the genuinely-in-scope recursive-miss/coalesced-response
call sites gain the new, cookie-aware variant.

Then thread `cookie_secret: &CookieSecret, client_ip: IpAddr, now:
SystemTime` through:

- `rebuild_recursive_response_with_own_framing` (`mod.rs:1670-1697`) — new
  parameters, passed down to its own `mirrored_client_opt_record` call
  (line 1685).
- `truncated_response_for_query` (`mod.rs:1716-1731`) — new parameters,
  passed to its `mirrored_client_opt_record` call (line 1721). Also update
  its one other caller, `enforce_udp_payload_limit_after_reserialize`
  (`mod.rs:1794-1810`), which itself needs the same three new parameters
  threaded through from *its* callers inside `prepare_backend_result`.
- The two direct calls inside `prepare_backend_result` itself
  (`mod.rs:4818-4822`, `4876-4880`, `4919-4925`, `4960-4963`, `4988-4994`,
  `5024-5029`, `5037+`) — all reachable via `self.cookie_secret`,
  `self.clock.now()`, and `request.client_ip`, already in scope on that
  method.

`recursive_synthesis_reused_own_framing` (`mod.rs:1756-1771`) gains the
extra `opt_matches` condition described above — it does not need
`CookieSecret`/`client_ip` itself, only `parse_cookie_option` from section
02, since it's answering "is a rebuild required," not building anything.

## Explicitly out of scope for this section

- `ResolveQuery::local_entry_response` and everything it calls
  (`build_a_answers_response`, `build_aaaa_answers_response`,
  `build_nodata_response`, `build_txt_answer_response`) — not mentioned in
  the plan's architecture section or this section's TDD test list. Leave
  `message_edns_opt_record` and its existing callers untouched.
- `synthesize_recursive_cname_response`'s own `mirrored_client_opt_record`
  call (`mod.rs:1399`) — deliberately left as today's plain,
  cookie-unaware call. See "Design decision" above.
- Any change to `cache_supported()`, `QueryFeatures`, or
  `requester_opt_record` — those are section 03/04's surface.

## Tests first

All new/changed tests live in `src/resolver/mod.rs`'s existing `#[cfg(test)]
mod tests` block (`mod.rs:7847+`), reusing existing fixtures: `a_query`,
`a_query_with_edns`/`a_query_with_edns_flags` (`mod.rs:7951-8009`, extend
with raw COOKIE-option TLV bytes — option code 10, 2-byte length, 8-byte
client cookie, per section 02's `build_cookie_option` shape, or hand-build
the bytes inline the same way the existing EDNS-option tests do),
`FixedClock` (`mod.rs:8011-8017`), `RecordingEvents`/`RecordingMetrics`,
`RecursiveResolutionBackend`, `DnssecAwareBlockingAuthorityTransport`, and
`resolve_service_with_recursive_cache` — the same harness already used by
the existing coalesced-follower-OPT tests at `mod.rs:17077-17195` and
neighbors (`resolve_coalesced_edns_follower_behind_non_edns_leader_keeps_its_own_opt`,
`resolve_coalesced_non_edns_follower_behind_edns_leader_gets_no_opt`, etc.).

From `claude-plan-tdd.md` §5:

- **Test**: a cache-miss (backend-forwarded) query carrying a well-formed
  Cookie option gets a response whose OPT record carries a fresh, correct
  server cookie — mirroring the cache-hit case (section 06's e2e tests) but
  exercised through the recursive-miss/`mirrored_client_opt_record` path
  instead. Concretely: a single (non-coalesced) `resolve()` call through
  `RecursiveResolutionBackend`, with the query carrying a Cookie option;
  parse the returned `response_bytes` with `Message::parse`, find the OPT
  additional record, assert its `options` bytes decode (via section 02's
  `parse_cookie_option` or a raw-byte assertion) to the same client cookie
  the query sent, with a 16-byte server cookie present.
- **Test**: two coalesced/in-flight requesters for the same backend query,
  presenting *different* client cookies, each receive their own distinct,
  correctly-computed COOKIE option in their respective responses — not a
  shared/replayed one. Build on the existing coalesced-follower harness
  pattern (`mod.rs:17077-17195`): leader and follower queries for the same
  name/type/class (so they coalesce onto one in-flight fetch,
  `transport.wait_for_requests(1)`), each carrying its own distinct 8-byte
  client cookie; after both resolve, assert each response's OPT carries
  *its own* requester's client cookie echoed back (not the other's), and
  that the two server cookies differ (different client cookie is part of
  the SipHash-2-4 input, so this follows automatically from section 02's
  `build_server_cookie` if client IPs differ too — pick distinct client
  IPs for the two requesters, as the existing coalesced tests already do,
  `"192.0.2.10"`/`"192.0.2.11"`).
- **Test**: `recursive_synthesis_reused_own_framing` (`mod.rs:1756-1771`)
  updated/extended to cover the Cookie case: confirm coalesced requesters
  with different cookies do NOT get identical reused framing where the OPT
  record is concerned, even though other framing (question echo, DO bit)
  may still be shared. This can be a focused unit test directly against
  `recursive_synthesis_reused_own_framing` (constructing a `DecodedQuery`
  and a `RecursiveSynthesisContext` whose `original_query` differs only in
  cookie bytes) asserting it now returns `false`, distinct from the
  higher-level e2e coalesced test above which proves the *end-to-end*
  behavior (distinct cookies actually reach each requester).
- Regression check (not explicitly listed but implied by "no other framing
  regresses"): a coalesced-follower test with **no** cookie on either side
  still gets `recursive_synthesis_reused_own_framing == true` when question
  and DO bit match — i.e. re-run (or reuse) one of the existing
  `resolve_coalesced_*_keeps_its_own_opt`/`gets_no_opt` tests
  (`mod.rs:17077-17195`, `17201+`) to confirm they still pass unmodified
  after the `opt_matches` change (these carry no Cookie option at all, so
  the new condition should never trigger for them).

## Verification

- `cargo fmt`, `cargo clippy`, `cargo test` (full suite) per `RUST.md` —
  pay particular attention to every existing test that touches
  `mirrored_client_opt_record`, `rebuild_recursive_response_with_own_framing`,
  `truncated_response_for_query`, or `recursive_synthesis_reused_own_framing`
  (signature changes ripple to every call site listed above; the compiler
  will catch missed ones, but confirm none of the existing
  non-Cookie coalesced/truncation tests changed behavior).
- Confirm the two e2e miss-path tests actually exercise real wire bytes
  (`Message::parse` round-trip), not just intermediate `Record`/`EdnsInfo`
  values — this is the reason this section is ordered after section 06.