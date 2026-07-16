# Research: EDNS Cookie cache-bypass fix

## Codebase research

### 1. `cache_supported()` — the bypass to narrow

`src/resolver/mod.rs:5508-5520`:

```rust
fn cache_supported(query: &DecodedQuery) -> bool {
    query
        .message
        .edns
        .as_ref()
        .map(|edns| {
            edns.extended_rcode == 0
                && edns.version == 0
                && (edns.flags & !EDNS_DO_FLAG) == 0
                && edns.options.is_empty()
        })
        .unwrap_or(true)
}
```

No EDNS → supported. EDNS present → supported only if extended RCODE=0, version=0, no flags beyond DO (`EDNS_DO_FLAG = 0x8000`), **and `edns.options.is_empty()`** — any option at all (Cookie, NSID, Padding, anything) disqualifies today.

Only caller: `probe_cache` (`mod.rs:4409-4479`), the very first check — gates cache-key computation and lookup entirely. `probe_cache` is called once from `resolve()` (`mod.rs:3793-3795`).

**Fix shape**: replace `edns.options.is_empty()` with "options is empty, or the only option present is a single well-formed COOKIE option" — nothing else about this function changes.

### 2. `filter_response_for_requester` — precedent, not the actual seam to extend

`mod.rs:1480-1507`. Trims DO-dependent content from a shared `Message` per requester on the **recursive-miss** path only (inside `prepare_backend_result`, `mod.rs:4927+`), before a fresh backend response is returned to the client. Explicitly does **not** touch the OPT record — callers re-append `mirrored_client_opt_record` themselves. This is *not* on the cache-hit-serve path.

Useful as a pattern (shared cached content + per-requester re-derivation at serve time, OPT always handled as a separate step) but the actual code seam for cache hits is different — see #4.

### 3. EDNS/OPT parsing — no per-option-code handling exists today

- `QueryFeatures` (`mod.rs:241-274`): only `recursion_desired`, `authenticated_data`, `checking_disabled`, `dnssec_ok`, `edns_udp_payload_size`. **No EDNS options data at all.**
- `EdnsInfo` (`src/protocol/mod.rs:207-215`): has `options: Vec<u8>` — the raw, undifferentiated OPT-RR RDATA TLV blob.
- `parse_opt_record` (`protocol/mod.rs:2617-2641`) copies that blob verbatim; `validate_edns_options` (`protocol/mod.rs:2643-2651`) only validates TLV framing (reads `option_code` but discards it) — no COOKIE constant, no option-code branch anywhere.
- Confirmed via grep: zero hits for `COOKIE`/`option_code` comparisons outside test data. Option code 10 is handled today only as "any option" — Cookie-specific parsing is **new code**, not a wire-up of something existing.

### 4. Response assembly — the real per-request OPT seam

`src/resolver/cache/assemble.rs` module doc (`15-28`): every cache hit assembles the response fresh per request using the requester's own question-wire bytes and EDNS bufsize — architecture already supports "some things vary per request even though the cached entry is shared."

`requester_opt_record` (`assemble.rs:437-447`):
```rust
fn requester_opt_record(requester_features: &QueryFeatures, configured_max_udp_payload_size: usize) -> Option<Record> {
    requester_features.edns_udp_payload_size?;
    let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
    Some(crate::protocol::build_opt_record(udp_payload_size, requester_features.dnssec_ok))
}
```
Gated purely on "did this requester send EDNS at all." `build_opt_record` (`protocol/mod.rs:1246-1278`) always builds `options: Vec::new()` — **no response OPT record has ever carried options before; this is new plumbing, not existing-field wiring.**

Callers: `build_servfail`, `finish_with_truncation_check`, `assemble_response`, `assemble_negative_response` — all invoked per-request from `QueryFeatures` (via `decoded.features`) at `serialize_cache_hit_answer`/`serialize_cache_hit_negative` (`mod.rs:4544-4578`).

**This is the seam**: add a Cookie-carrying field to `QueryFeatures` (populated in `QueryFeatures::from_message`, via a new option-scanning helper), thread it into `requester_opt_record`/`assemble_response`/`assemble_negative_response`, and extend `build_opt_record`/OPT-writing in `protocol/mod.rs` to actually serialize non-empty `options` bytes.

`ResolveRequest.client_ip: IpAddr` (`mod.rs:167-183`) is already available at every relevant call site — no new plumbing needed to get the client IP to the cookie-hash computation.

### 5. Existing regression tests to touch/add

- `resolve_bypasses_cache_for_unsupported_edns_options` (`mod.rs:18996-19019`) — uses a **COOKIE-shaped option** (`[0,10,0,2,0xaa,0xbb]`, code 10) as its example "unsupported option," asserting bypass. **Must be repointed** to a genuinely-still-unsupported code (e.g. NSID=3) once Cookie becomes an exception — plus a **new inverse test** added for Cookie asserting cache participation.
- `resolve_bypasses_cache_for_unsupported_edns_flags_and_version` (`mod.rs:19021-19047`) — tests version≠0 and an unrelated flag bit, both with empty options. **Orthogonal, no change needed.**

### 6. Dependency landscape — no new top-level crate needed

`Cargo.toml` has **no** hashing/crypto crate, direct or transitive (`Cargo.lock` grep for sha/hmac/siphash/ring/blake/digest/rand/getrandom: no hits). BUT: `domain` (already a dependency, `version = "0.12.1"`, currently `default-features = false, features = ["zonefile", "bytes", "std"]`) ships **`domain::base::opt::cookie`** — a complete, RFC-9018-test-vector-verified cookie implementation (`Cookie`, `ClientCookie`, `ServerCookie`, `StandardServerCookie`) behind two optional features not currently enabled:
- `siphasher` feature → unlocks `StandardServerCookie::calculate`/`check_hash`.
- `rand` feature → unlocks CSPRNG helpers (also usable for the one-time startup secret, mirroring `domain`'s own `CookiesMiddlewareSvc::with_random_secret`).

rdns's own protocol layer is hand-rolled (`EdnsInfo`/raw `Vec<u8>` TLV scanning) and doesn't use `domain`'s `Message`/`Opt` types anywhere — so the plan should keep TLV scanning in rdns's own style but call `domain`'s cookie math (or `siphasher` directly) as the hashing primitive, rather than hand-rolling SipHash. **Recommendation: enable `domain`'s `siphasher` (+ `rand`) features rather than adding a new top-level Cargo.toml entry** — satisfies `RUST.md`'s "add dependencies conservatively" bar about as well as possible (zero new top-level deps, reuses an already-vetted, already-present crate).

RUST.md:20 — "Add dependencies conservatively. A new crate should improve correctness, reduce real complexity, or match an established project pattern." Enabling existing-dependency features is the cleanest way to satisfy this.

### 7. Test fixture conventions to reuse

`a_query_with_edns_flags(id, name, udp_payload_size, dnssec_ok, extended_rcode, version, extra_flags, options) -> Vec<u8>` (`mod.rs:7975+`) is the fullest-control query builder — a new `a_query_with_cookie(...)` helper should be built on top of this same layer, constructing the option TLV (code=10, len=8 or 16-40) and passing it as `options`.

Other reusable fixtures: `RecordingEvents`, `RecordingMetrics` (`.count(metric)`), `StaticUpstream` (asserts on what actually reached "upstream"), `RecordingCache` (`.lookups`/`.stores` — the two existing bypass tests assert these stay empty; a Cookie-serves-from-cache test asserts the inverse), `resolve_service_with_cache(upstream, cache, events, metrics, max_udp_payload_size)`.

## Web research: RFC 7873/9018 implementation

### Wire format (RFC 7873 §4)
Option code 10. Two valid lengths: 8 bytes (client-cookie-only) or 16-40 bytes (client cookie [8] + server cookie [8-32]). Any other length → FORMERR (§5.2.2).

### Algorithm: use RFC 9018, not RFC 7873 Appendix B

RFC 7873 Appendix B's examples (FNV-64, or HMAC-SHA256-64-with-nonce) are **non-normative and non-interoperable** — different vendors produced incompatible formats. **RFC 9018 ("Interoperable DNS Server Cookies") fixes this and explicitly states the 7873 examples "MUST NOT be used."** Use RFC 9018 §4.4's construction:

- 16-byte server cookie = 1-byte Version (`1`) + 3-byte Reserved (`0x00 0x00 0x00`) + 4-byte Timestamp (big-endian, seconds since epoch) + 8-byte SipHash-2-4 output.
- Hash input: `Client Cookie(8) | Version(1) | Reserved(3) | Timestamp(4) | Client-IP(4 or 16)` — 20 bytes for IPv4, 32 for IPv6. Keyed by the server secret.
- §4.3: accept timestamps up to 1hr in the past, 5min in the future (replay/skew window).
- §4.2: secret ≥128 bits, CSPRNG-generated.
- §5: secret rotation procedure (out of scope here — single in-memory secret per this plan's decided scope, restart-resets-cookies being acceptable).

**Pitfall** (confirmed in `domain` crate source, `base/opt/cookie.rs:641-644`): Version/Reserved/Timestamp are big-endian, but the 8-byte SipHash-2-4 output must be serialized **little-endian** — "somewhat surprisingly." A naive full-big-endian implementation would self-validate but fail interop with every other RFC-9018 server. If hand-rolling instead of calling `domain` directly, must test against RFC 9018 Appendix A vectors.

### Cache-safety analysis

Safe, given source-IP validation is handled elsewhere (already true for this resolver, out of scope here):
- OPT/COOKIE is per-transaction metadata (RFC 6891 §6.1), never zone/cache data — as long as the cache key never includes cookie bytes, no cross-client leakage channel exists.
- The server cookie is a deterministic function of *this* request's client cookie + client IP — recomputing fresh per response (never caching/replaying it) is the only correct approach; a cached cookie would be wrong for a different requesting IP.
- RFC 7873 §5.2.1/5.2.3/5.2.4 all treat "no cookie," "client-cookie-only," and "invalid server cookie" as legitimate states a compliant server must tolerate and normally answer — none gate answer servability by design.
- Computation cost is negligible (SipHash-2-4 over ~20-32 bytes) — no perf pressure to cache cookies.

### "No BADCOOKIE round-trip" is RFC-conformant, not a corner cut

RFC 7873 §5.2.3 (client cookie only) and §5.2.4 (invalid server cookie) both explicitly list "(3) Process the request and provide a normal response" as one of three compliant server choices — not a deviation. **What it forfeits**: the entire anti-off-path-spoofing value of cookies comes from the *rejection* path (BADCOOKIE forcing a round-trip an off-path attacker can't complete). Always choosing branch (3) gives **zero** additional DoS/spoofing resistance from this mechanism — it's a pure interoperability/protocol-civility feature here, not a security control. Notably, `domain`'s own `CookiesMiddlewareSvc` has a TODO explicitly choosing the *stricter* branch (send BADCOOKIE) "err[ing] on the side of security" — i.e., the reference implementation's authors treat this as a real trade-off, not a non-issue. **This must be stated explicitly in the plan's docs/spec output** so a future reader doesn't assume DoS protection that isn't there, given the resolver's source-IP legitimacy checks are asserted (not verified in this research pass) to live elsewhere.

### Crate comparison

| Option | Verdict |
|---|---|
| `domain::base::opt::cookie` (enable `siphasher`[+`rand`] features on existing dep) | **Recommended** — zero new top-level deps, RFC-9018-test-vector-verified, actively maintained |
| `siphasher` directly | Fine fallback if avoiding `domain`'s `Parser`/`Octets` abstractions in the hand-rolled protocol layer; 0 mandatory deps |
| `hmac`+`sha2` | Unnecessary extra dependency surface; not the RFC 9018 primitive |
| `blake3`, `ring` | Not RFC-standardized for this / unnecessary build weight |
| `dns-cookie` crate | Correct target spec but low adoption (~12 recent downloads, last publish 2021) — prefer `domain`'s in-tree equivalent |

## Testing preferences

Follow this repo's existing `#[cfg(test)] mod tests` e2e conventions in `src/resolver/mod.rs` (per Codebase research #7) — no new test framework/tooling needed. Unit-level cookie hash/validate tests should include RFC 9018 Appendix A test vectors as a correctness check if hand-rolling the hash construction instead of calling `domain` directly.
