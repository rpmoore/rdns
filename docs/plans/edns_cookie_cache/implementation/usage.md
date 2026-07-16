# Usage Guide: RFC 7873/9018 DNS Cookie support

This plan added RFC 7873 (DNS Cookies) client-cookie echoing and RFC 9018
server-cookie construction to `rdns`. It is **not** a new CLI command or API
— it's a behavior change in the existing resolver: any query that carries a
well-formed EDNS COOKIE option gets a response with a fresh, correctly
-computed server cookie attached, on both the cache-hit and cache-miss
paths. Cookie-only queries are now also cache-admissible (previously any
non-empty EDNS options blob unconditionally bypassed the cache).

## Quick Start

No new configuration is required — the feature is always on. Build and run
`rdns` as usual:

```bash
cargo build --release
RDNS_CONFIG=config.toml ./target/release/rdns
```

`config.toml`'s `dns_listen` (default `["0.0.0.0:53"]`) controls where the
resolver listens; nothing Cookie-specific needs setting there. At startup,
`main.rs` constructs one process-lifetime `CookieSecret` via
`CookieSecret::generate()` and wires it into `ResolveQuery` alongside the
existing `SystemClock` (`src/main.rs:130`, `ResolveQuery::with_cookie_secret`)
— restarting the process rotates the secret (no persistence, no rotation
schedule; see the security trade-off note below).

## Example: sending a Cookie-bearing query

Using `dig` (most modern `dig` builds support `+cookie` directly):

```bash
dig @127.0.0.1 example.com A +cookie
```

Or manually with `kdig`/`dig +ednsopt` to send a raw 8-byte client cookie
(option code 10):

```bash
dig @127.0.0.1 example.com A +ednsopt=10:1122334455667788
```

## Example Output

A response to a Cookie-bearing query carries a COOKIE option in its OPT
record's `EDNS OPT PSEUDOSECTION`, echoing the 8-byte client cookie you sent
plus a fresh 16-byte server cookie:

```
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
; COOKIE: 1122334455667788 (echoed) 3af1...  (server cookie, 16 bytes, changes every query)
```

Two things to observe experimentally:

- **Same client cookie, repeated query**: the *client* cookie half stays
  whatever you sent; the *server* cookie half is freshly computed every
  response (it's never cached or replayed) — it will differ across requests
  even for an identical query, because it's a function of `(secret,
  client_cookie, client_ip, now)` and `now` changes.
- **Cookie-only queries are now cacheable**: repeat the same Cookie-bearing
  query rapidly and watch the resolver's cache-hit metrics
  (`ResolverMetric::CacheHit`) increment, whereas before this plan every
  such query would have counted as a `CacheBypass`. Adding any *other* EDNS
  option alongside the Cookie (e.g. `+nsid`) still forces a bypass — that's
  intentional (see `cache_supported()`,
  `docs/knowledge/resolver/caching/answer-cache.md`'s "EDNS Cookie
  interaction" section).

## What this feature does NOT do

Read `docs/knowledge/resolver/caching/answer-cache.md`'s "EDNS Cookie
interaction" section before relying on this for anything security-related:
this resolver **echoes and computes** cookies (RFC 7873/9018 wire-format
interop) but never **validates** an incoming server cookie's hash or
timestamp, never generates BADCOOKIE (RCODE 23), and never rejects a query
for cookie-related reasons. It provides zero anti-off-path-spoofing
protection — that would require the validation/rejection path this plan
deliberately does not build.

## API Reference (internal — not a public crate API change)

No new public CLI flags or HTTP endpoints. The touched public/crate-visible
surface:

- `rdns::resolver::CookieSecret` (re-exported from `src/protocol/edns_cookie.rs`)
  — `CookieSecret::generate()`, constructed once per process.
- `ResolveQuery::with_cookie_secret(Arc<CookieSecret>) -> Self` — the
  post-construction setter `main.rs` uses to wire the secret in, mirroring
  `with_max_chain_depth`/`with_chaos_config`.
- Everything else (`ClientCookie`, `parse_cookie_option`,
  `is_solely_cookie_option`, `build_server_cookie`, `build_cookie_option`,
  `mirrored_client_opt_record_with_cookie`, `message_edns_opt_record_with_cookie`)
  is `pub(crate)` — internal wiring, not part of the crate's external API.

## Files touched across all 8 sections

- `Cargo.toml` / `Cargo.lock` — `rand` dependency, `domain`'s `siphasher` feature.
- `src/protocol/edns_cookie.rs` — new module (parsing, cache-admission predicate, server-cookie construction).
- `src/protocol/mod.rs` — OPT record wire serialization gains an options payload; new `message_edns_opt_record_with_cookie`.
- `src/resolver/mod.rs` — `cache_supported()` narrowing, `QueryFeatures.client_cookie`, cache-miss/recursive cookie-aware OPT rebuild, `recursive_synthesis_reused_own_framing` cookie-forced-rebuild.
- `src/resolver/cache/assemble.rs` — cache-hit path cookie-aware OPT building (`requester_opt_record` and its four callers).
- `src/main.rs` — `CookieSecret::generate()` construction and DI wiring.
- `docs/knowledge/resolver/caching/answer-cache.md` — knowledge-bundle documentation of the landed behavior.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

All three are clean on the final combined diff (603 lib tests passing plus
integration test binaries; network-dependent e2e tests remain `#[ignore]`d
as pre-existing).
