# rdns

Small DNS server. Answers configured local names for your LAN, forwards
everything else upstream (e.g. Cloudflare) or resolves it recursively itself.

## Install

Installs the latest release binary to `/usr/local/bin/rdns` and, if you opt
in, sets up a systemd service running as a recursive resolver. **Linux
x86_64 only** — no macOS or ARM builds are published yet, so the script
exits with an error on other platforms.

```bash
curl -fsSL https://raw.githubusercontent.com/rpmoore/rdns/main/scripts/install.sh | sudo bash
```

Pass `--yes` to install and start the service without prompting, `--no-service`
to install only the binary, or `--version <tag>` to pin a specific release.
See `./scripts/install.sh --help` for details (from a repo checkout).

## Run it

```bash
cargo run
```

Startup config resolution order:

1. `RDNS_CONFIG` env var, if set — path to a TOML config file.
2. `./config.toml`, if present in the working directory.
3. Otherwise, built-in loopback dev defaults (listens on `127.0.0.1:5300`,
   forwards to `1.1.1.1:53`, no local entries).

A sample `config.toml` ships at the repo root and loads automatically. Its
`[[local_dns_entries]]` sample (`nas.lan`) is `enabled = false` out of the
box — enable it and set your own address, or add your own entries — so a
plain checkout never answers a fake record. Point at a different file:

```bash
RDNS_CONFIG=/etc/rdns/config.toml cargo run
```

Test it:

```bash
dig @127.0.0.1 -p 5300 nas.lan A        # local entry, once enabled in config.toml
dig @127.0.0.1 -p 5300 example.com A    # forwarded upstream
```

## Config file format

TOML. Top-level:

```toml
dns_listen = ["127.0.0.1:5300"]   # one or more "host:port" UDP listeners
per_query_deadline_ms = 2000       # per-query timeout budget
max_udp_payload_size = 1232        # EDNS UDP payload size advertised/accepted
```

`dns_listen` binding to port 53 (or any port `<= 1024`) is allowed by config
validation, but the OS still requires privilege to bind it — run as root or
grant the built binary the capability:

```bash
sudo setcap cap_net_bind_service=+ep target/release/rdns
```

(This only matters if you build/run the binary manually. `scripts/install.sh`'s
systemd unit grants the capability via `AmbientCapabilities` instead, so its
service doesn't need `setcap` and won't lose the capability across binary
upgrades.)

Unknown fields in the file are rejected at load time (fails closed rather
than silently ignoring a typo'd or unsupported setting).

### Upstream resolvers (forwarding)

Everything not answered by a local entry is forwarded to `[[upstreams]]`,
tried in ascending `priority` order:

```toml
[[upstreams]]
name = "cloudflare"
endpoint = "1.1.1.1:53"
protocol = "udp"
enabled = true
priority = 10
timeout_ms = 750

[[upstreams]]
name = "quad9"
endpoint = "9.9.9.9:53"
protocol = "udp"
enabled = true
priority = 20
timeout_ms = 750
```

Multiple entries give failover, not fan-out: rdns tries them in priority
order and falls through on failure/timeout. `protocol` parses `"tcp"` but
forwarding only considers `enabled` upstreams with `protocol = "udp"` —
`"tcp"`-configured upstreams are skipped entirely (an all-`"tcp"` upstream
list leaves no backend to forward to). Initial forwarding queries always go
out over UDP; rdns retries the same upstream over TCP if the UDP response
comes back truncated (`TC` bit set).

### Recursive resolution (acting as your own root-to-leaf resolver)

Instead of forwarding, rdns can walk the DNS hierarchy itself starting from
the root servers. Add a `[resolution]` section — if omitted, rdns defaults
to forward mode using `[[upstreams]]` as above.

Simplest form, using the bundled root hints:

```toml
[resolution]
mode = "recursive"

[resolution.recursive]
root_hints = "bundled"
root_hints_version = "bundled:v1"
```

`[[upstreams]]` is ignored in recursive mode — you don't need any.

Full set of tunables (all but `root_hints`/`root_hints_version` are
optional and default as shown):

```toml
[resolution]
mode = "recursive"
generation = 1              # bump to force cache namespace invalidation

[resolution.recursive]
root_hints = "bundled"              # "bundled" or "custom"
root_hints_version = "bundled:v1"   # required; any label, used for cache namespacing
per_authority_timeout_ms = 750      # timeout per upstream authority query
max_recursion_depth = 16            # referral chain depth limit
max_cname_restarts = 8              # CNAME-chase limit
allowed_transports = ["udp", "tcp"] # transports used to query authorities
dnssec_validation = "disabled"      # only "disabled" is currently supported
dname_handling = "defer"            # only "defer" is currently supported
```

To use your own root server list instead of the bundled one:

```toml
[resolution.recursive]
root_hints = "custom"
root_hints_version = "custom:v1"

[[resolution.recursive.root_hints_entries]]
name = "a.root-servers.net"
endpoints = ["198.41.0.4:53"]

[[resolution.recursive.root_hints_entries]]
name = "b.root-servers.net"
endpoints = ["199.9.14.201:53"]
```

`[resolution]`/`[[upstreams]]` reload on SIGHUP too — you can flip between
`forward` and `recursive`, or change recursive settings, without a restart.
Only `dns_listen` is restart-only, see below.

#### Updating the bundled (`root_hints = "bundled"`) root server list

The bundled list (currently all 13 root servers, IPv4 + IPv6) isn't
hand-maintained Rust — it's parsed at runtime from a committed copy of
IANA/InterNIC's root hints zone file at `src/config/named.root` (embedded
into the binary at compile time via `include_str!`), via `parse_named_root()`
in `src/config/mod.rs`. To refresh it when a root server's address changes:

```bash
curl -sS https://www.internic.net/domain/named.root -o src/config/named.root
```

Then rebuild — `parse_named_root` re-derives `bundled_root_hints()` from
the new file automatically, no other code changes needed. It reads the
standard BIND zone-file shape IANA publishes (`;`-prefixed comments,
`<name> <ttl> <type> <rdata>` data lines) and keeps only the `A`/`AAAA`
glue records, grouped by root server name in first-seen order; `NS`
records are ignored (redundant with the address records' owner names).
Bump `root_hints_version` in your config after a refresh if you want the
new file to invalidate the resolver's recursive-mode cache namespace on
next load/reload.

### Local DNS entries

Answers exact names for devices on your network, skipping upstream entirely
for those names:

```toml
[[local_dns_entries]]
name = "nas.lan"
ipv4 = ["192.168.1.10"]
ttl = 300
enabled = true
public_address_acknowledged = false

[[local_dns_entries]]
name = "printer.lan"
ipv6 = ["fd00::1"]
ttl = 300
enabled = true
public_address_acknowledged = false
```

Rules enforced at load time:
- At least one of `ipv4`/`ipv6` must be set.
- `ttl` must be between 1 and 86400 seconds (24h).
- Names must be unique (case/trailing-dot normalized).
- If an address is public/routable (not private-use, loopback, or
  link-local), you must set `public_address_acknowledged = true` or the
  config is rejected — this stops an accidental public IP in a local entry
  from being silently exposed as the "local" answer.
- `enabled = false` keeps the entry in the file but disabled — no lookup
  match, useful for keeping a device's known address around without serving
  it.
- **The entry's name cannot use a real, currently-delegated top-level
  domain as its suffix** (checked against a bundled copy of IANA's TLD
  registry — see "Local zones" below for the full explanation). `nas.lan`
  is fine; `nas.dev`/`nas.app`/`nas.io` are rejected, because those are
  real, currently-registered gTLDs — a local override should never be able
  to shadow a real public domain. If you were relying on a real TLD suffix
  for a local name, rename it to something like `.lab`, `.home`, or
  `.internal` instead.

### Local zones (BIND-style zone files)

For a larger local-network record set, or to migrate an existing BIND
setup, point rdns at a real zone file instead of (or alongside)
`[[local_dns_entries]]`:

```toml
[[local_zones]]
path = "zones/mynetwork.zone"
root_domain = "mynetwork"
public_address_acknowledged = false
enabled = true
```

- `path` is resolved relative to the directory containing the config file
  (`RDNS_CONFIG`/`./config.toml`) when relative; absolute paths are used
  as-is. With no config file loaded, a relative path resolves against the
  current working directory.
- The zone file uses standard BIND zone-file syntax (`$ORIGIN`, `$TTL`,
  `SOA`, `NS`, multi-line parenthesized records, comments, owner-name
  inheritance, etc.) — parsed with [the `domain` crate's zone-file
  scanner](https://docs.rs/domain), the same crate other Rust DNS tooling
  uses. Zone files are expected to declare their own `$ORIGIN`; rdns never
  programmatically overrides it.
- Only `A`, `AAAA`, `SOA`, and `NS` records are supported. `SOA`/`NS` are
  recognized and ignored (they're zone-management boilerplate, not
  answerable local records). Any other record type (`CNAME`, `MX`, `TXT`,
  `SRV`, DNSSEC records, etc.) or a `$INCLUDE` directive causes the whole
  config to be rejected rather than silently dropping data — this is a
  deliberate limitation, not an oversight.
- Multiple `A`/`AAAA` records under the same owner name are grouped into
  one local entry, same as listing multiple addresses in one
  `[[local_dns_entries]]` block's `ipv4`/`ipv6` arrays. If the same owner
  name has records with different TTLs, the first one seen wins for the
  whole entry (rdns has one TTL per entry, not one per address family).
- A zone file is capped at 10 MiB and 10,000 `A`/`AAAA` records; an
  oversized file is rejected rather than parsed, to bound worst-case parse
  time/memory from a misconfigured or unexpected file.
- `root_domain` is mandatory and enforced: every record's owner name in
  the zone file must be at or below it, and `root_domain` itself is
  checked with the same **not-a-registered-TLD** rule described above for
  `[[local_dns_entries]]` — a zone can never claim authority over a real
  public domain. Most of IANA's Special-Use Domain Names (RFC 6761:
  `local`, `test`, `invalid`, `example`, `onion`, `localhost`) remain legal
  choices simply because they're **not** delegated TLDs at all — `.local`
  specifically still carries the existing mDNS conflict warning.
  `home.arpa` (RFC 8375) is a narrow, explicit exception rather than an
  instance of that same rule: `arpa` itself *is* a real, delegated
  infrastructure TLD, so `home.arpa`/`*.home.arpa` are allowed only because
  they're special-cased, not because `arpa` is absent from the checked
  list — nothing else under `.arpa` is exempted.
- `public_address_acknowledged` here is **zone-wide** (BIND zone files
  have no per-record acknowledgement syntax) — set it only if you
  intentionally have a public/routable address somewhere in that zone
  file; otherwise any public/routable `A`/`AAAA` record in the file is
  rejected, same fail-closed default as inline entries.
- `enabled = false` (default `true`) skips the zone entirely, including
  never reading the file from disk — useful for keeping a zone file
  configured but temporarily out of service without needing the file to
  even exist.
- `local_zones` entries merge with `[[local_dns_entries]]`: both are
  checked for duplicate names against each other (across every zone file
  and the inline list together), and the not-a-registered-TLD rule
  applies to **both** kinds of entries, not just zone-file ones.
- Reloadable via `SIGHUP` exactly like `[[local_dns_entries]]` — see below.

#### Updating the bundled IANA TLD list

The list of real, currently-delegated top-level domains checked against
(for both `[[local_dns_entries]]` names and `[[local_zones]]`
`root_domain`s) is a committed, verbatim copy of IANA's published TLD
registry at `src/config/tlds-alpha-by-domain.txt`, embedded into the
binary at compile time. Refresh it the same way as the root hints list:

```bash
curl -sS https://data.iana.org/TLD/tlds-alpha-by-domain.txt -o src/config/tlds-alpha-by-domain.txt
```

Then rebuild — `parse_iana_tlds`/`bundled_iana_tlds()` re-derive the
checked set from the new file automatically, no other code changes
needed.

## Reloading config without a restart

Send `SIGHUP` to the running process to reload resolution mode, upstreams,
and local DNS entries (inline and zone-file-sourced) from the same config
file:

```bash
kill -HUP <pid>
```

- The file is re-read, re-parsed, and fully re-validated before anything is
  applied. A broken edit (bad TOML, invalid address, duplicate name, etc.)
  is logged and rejected in full — the server keeps serving the last-good
  config, with no fields changed from the rejected reload.
- On a successful reload, the new backend (upstreams/recursive settings)
  and new local DNS entries are published together as one atomic step: a
  query in flight during the reload sees either the fully old pair or the
  fully new pair, never one field from each.
- `[resolution]`, `[[upstreams]]`, `[[local_dns_entries]]`, and
  `[[local_zones]]` are all reloadable this way — including switching
  between `forward` and `recursive` mode. A `[[local_zones]]` file is
  re-read from disk on every reload, so editing the zone file itself and
  sending `SIGHUP` picks up the change too, without touching `config.toml`.
- `dns_listen` and `[metrics]` changes are **not** picked up on SIGHUP —
  changing DNS listen addresses/ports, or the metrics endpoint's
  address/enabled state, requires a restart.
- No effect if rdns started with no config file (built-in dev defaults) —
  there's nothing to re-read.

## Metrics (Prometheus)

> **Breaking change:** rdns used to push metrics via OpenTelemetry OTLP/gRPC
> (`OTEL_EXPORTER_OTLP_ENDPOINT`). That exporter has been removed entirely and
> replaced with a Prometheus pull endpoint. If you were scraping metrics via
> an OTLP collector, that pipeline stops receiving data after upgrading —
> point your Prometheus server at the new `/metrics` endpoint instead (there
> is no OTLP compatibility mode).

rdns exposes `GET /metrics` in Prometheus text exposition format — no TLS,
no auth. The endpoint's own reachability doubles as a liveness check: if
`/metrics` responds, the process is up.

```toml
[metrics]
enabled = true              # set false to disable the endpoint entirely
listen = "127.0.0.1:9090"   # loopback by default since there's no TLS/auth;
                             # override to e.g. "0.0.0.0:9090" for an
                             # external Prometheus server to reach it
max_connections = 32        # concurrent HTTP connection cap
```

If `[metrics]` is omitted, these are the defaults — the endpoint is on by
default. A bind failure (e.g. the port is already in use by something else
on the host) is logged and does **not** prevent rdns from starting or
serving DNS; it just runs without a metrics endpoint for that run.

`[metrics]` is **restart-only** — unlike `[resolution]`/`[[upstreams]]`/
`[[local_dns_entries]]`, changes here (including `enabled = false`) are not
picked up on `SIGHUP`. A reload log line reporting success does not mean the
metrics listener's address or enabled state changed; it keeps running with
whatever `[metrics]` config was in effect at startup until the process is
restarted.

Includes request/cache counters (`query_received_total`, `cache_hit_total`,
`cache_miss_total`, ...), latency histograms split by cache-hit vs.
cache-miss/backend path (`cache_hit_query_duration_seconds`,
`cache_miss_query_duration_seconds`), and cache size/capacity gauges
(`cache_size`, `cache_capacity`).
