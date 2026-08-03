# Usage Guide: DNSSEC validation + BADCOOKIE handling (`docs/plans/sec_work/`)

This plan shipped two independent features across 9 sections:

- **Track A** (sections 01-06): DNSSEC chain-of-trust validation, on by
  default.
- **Track B** (sections 07-09): RFC 7873 DNS Cookie BADCOOKIE (RCODE 23)
  handling.

## Track A: DNSSEC validation

### Quick start

DNSSEC validation is **on by default** as of section-05 — no config
change needed to get it. It only applies in `[resolution] mode =
"recursive"` (forward mode has no chain of trust to walk, since it
relays whatever an upstream forwarder already decided).

```toml
[resolution]
mode = "recursive"

[resolution.recursive]
root_hints = "bundled"
root_hints_version = "bundled:v1"

# Optional — defaults shown. Set to "disabled" to opt out entirely.
dnssec_validation = "enabled"
```

Trust anchors default to the bundled root KSK-2017/KSK-2024 DS records
(`src/config/root-anchor.txt`, `TrustAnchorSource::Bundled`). Override with
a static TOML list if operating an isolated/private root:

```toml
[resolution.recursive.trust_anchor_source]
type = "static"
entries = ["... DS record lines ..."]
```

### Observing it

- `dig +dnssec example.com` against a signed domain (e.g.
  `cloudflare.com`) returns RRSIGs and `ad` (Authenticated Data) when the
  chain validates.
- `dig +cd example.com` (Checking Disabled) bypasses SERVFAIL-on-Bogus
  gating for that one query — proves validation is running without it
  blocking a client that doesn't want it enforced.
- Metrics: `dnssec_validation_results_total{outcome="secure|insecure|bogus|indeterminate|not_attempted"}`
  on the `/metrics` endpoint.
- `docs/knowledge/resolver/dnssec-validation.md` documents the validator,
  trust-anchor handling, CD-bit gating, and metrics in full.

### Rollout note

`docs/plans/sec_work/rollout-note.md` covers the operational risk: this
is an on-by-default behavior change (an upgrade turns validation on with
no action needed) with a fail-closed timeout risk (a slow/unreachable
authority during the DNSSEC chase can turn what would have been a normal
answer into SERVFAIL). Read it before rolling out to a new fleet.

## Track B: BADCOOKIE (RFC 7873 DNS Cookies)

### Quick start

No config needed — BADCOOKIE detection is unconditional wherever EDNS
Cookies are already supported (echo/interop has existed since before this
plan). A UDP query presenting a tampered, stale, or structurally malformed
server-cookie tail gets RCODE 23 (BADCOOKIE) with a freshly issued
server cookie attached so the client can retry. The identical query over
TCP is processed normally (RFC 7873 §5.2.3's carve-out).

### Observing it

Craft a query with a COOKIE option (code 10) carrying an 8-byte client
cookie plus a garbage 16-byte tail:

```python
import socket, struct

def cookie_option(client_cookie, tail):
    data = client_cookie + tail
    return struct.pack(">HH", 10, len(data)) + data

client_cookie = bytes(range(1, 9))
tampered_tail = bytes([0xAA] * 16)
opt_rdata = cookie_option(client_cookie, tampered_tail)

header = struct.pack(">HHHHHH", 0x1111, 0x0100, 1, 0, 0, 1)
qname = b"\x07example\x03com\x00"
question = qname + struct.pack(">HH", 1, 1)
opt = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, len(opt_rdata)) + opt_rdata
query = header + question + opt

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(query, ("127.0.0.1", 5300))
resp, _ = s.recvfrom(4096)
ext_rcode = resp[11 - 4]  # see cookie_probe.py for the real parse
```

(The full, tested version of this probe — including response parsing and
the TCP/duplicate-option counterpart cases — lives in the section-09 verify
run; see `tests/e2e_config_toml.rs`'s `bad_server_cookie_over_udp_returns_badcookie_with_fresh_cookie`
/ `bad_server_cookie_over_tcp_returns_normal_answer` for the canonical,
maintained version.)

- Metrics: `protocol_error_total` increments on a BADCOOKIE reject (same
  bucket as other `QueryValidationError` protocol errors, RFC 7873 doesn't
  get its own counter).
- `docs/knowledge/resolver/caching/answer-cache.md`'s "Security trade-off"
  section documents the transport-conditional gating rule, the
  first-contact case, and the duplicate-COOKIE-option case in full.

## Verification run for this session

Live-probed against a running `rdns` forward-mode instance
(`cargo build` + `RDNS_CONFIG=... target/debug/rdns`), via a hand-rolled
UDP/TCP client sending raw wire bytes (`cookie_probe.py`, ad hoc — not
checked into the repo):

1. Tampered server cookie, UDP → combined extended RCODE 23, 28-byte
   COOKIE option echoing the client cookie with a fresh server cookie. ✅
2. Identical tampered cookie, TCP → NOERROR, normal answer. ✅
3. Duplicate COOKIE options, UDP → not BADCOOKIE. ✅
4. Duplicate COOKIE options, TCP → not BADCOOKIE. ✅
5. First-contact (client cookie only, no server tail), UDP → not
   BADCOOKIE, fresh server cookie attached. ✅

`/metrics` confirmed: 5 `query_received_total`, 1 `protocol_error_total`
(the UDP BADCOOKIE reject), 4 `query_allowed_total`.

## Full test suite

`cargo test` (766 lib tests + 39 e2e config-toml tests + others, all
passing), `cargo fmt --all -- --check`, `cargo clippy --all-targets` (no
warnings).

## Code review trail

Each section's diff, subagent review, and interview transcript is under
`docs/plans/sec_work/implementation/code_review/section-NN-*.md`.
Section-09 additionally has `section-09-security-review.md` (the
Track-B-focused `/security-review` run, no HIGH/MEDIUM findings).
