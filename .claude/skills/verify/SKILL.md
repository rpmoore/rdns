---
name: verify
description: Build, launch, and drive rdns end-to-end to verify a change at its DNS surface (UDP/TCP queries via dig, malformed-input probes, metrics).
---

# Verifying rdns changes end-to-end

Build: `cargo build` (debug binary at `target/debug/rdns`).

## Launch

rdns reads its config from `RDNS_CONFIG` (falls back to `./config.toml`,
then built-in loopback defaults that bind 127.0.0.1:5300). Use absolute
paths for `RDNS_CONFIG` — the binary resolves it relative to its CWD.

Minimal recursive config (needs outbound UDP/TCP DNS to root/TLD servers):

```toml
dns_listen = ["127.0.0.1:5300"]
per_query_deadline_ms = 3000
max_udp_payload_size = 1232
max_tcp_connections = 128

[metrics]
enabled = true
listen = "127.0.0.1:19090"
max_connections = 32

[resolution]
mode = "recursive"

[resolution.recursive]
root_hints = "bundled"
root_hints_version = "bundled:v1"
```

Forward mode: swap the `[resolution]` block for `mode = "forward"` plus:

```toml
[[upstreams]]
name = "cloudflare"
endpoint = "1.1.1.1:53"
protocol = "udp"
enabled = true
priority = 10
timeout_ms = 1500
```

Run: `RDNS_CONFIG=/abs/path/config.toml target/debug/rdns` (background,
capture the JSON log). Startup logs one `rdns listening on udp` line per
bound socket — on Linux expect `min(nproc, 8)` UDP sockets per address
(SO_REUSEPORT intake parallelism) plus one TCP line.

Check outbound DNS first: `dig +time=2 +tries=1 @1.1.1.1 example.com +short`.
If that fails, recursive/forward flows can't be driven — say so rather
than reporting FAIL.

## Drive

- Miss then hit: `dig @127.0.0.1 -p 5300 example.com A +stats` twice —
  second query should be ~0 msec with the TTL aged down (e.g. 300 → 299).
- TCP: same query with `+tcp`.
- Negative cache: query a nonexistent name twice; compare status/SOA
  authority against `dig @1.1.1.1` ground truth.
- DNSSEC path: `dig +dnssec` should return RRSIGs.
- Metrics: `curl -s http://127.0.0.1:19090/metrics`.

## Probes that worked

- Garbage UDP (empty / 3-byte / oversized-random payloads via a python
  socket): expect a 12-byte FORMERR (rcode 1) each, server stays up.
- Malformed TCP frame with length prefix < 12: server resets the
  connection (by design — see `serve_tcp_connection`'s header-length
  check).
- Concurrency: `seq 1 60 | xargs -P 20 -I{} dig @127.0.0.1 -p 5300 ...`
  then confirm the process count and a follow-up query still hits cache.

## Gotchas

- A previously-launched rdns that failed to read its config falls back
  to built-in defaults and silently binds 127.0.0.1:5300 — `pgrep -a rdns`
  before trusting socket counts.
- `dig` against a fresh recursive instance can take a few hundred ms on
  the first query (root → TLD → authority walk); that's normal, not a hang.
