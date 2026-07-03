# rdns

Small DNS server. Answers configured local names for your LAN, forwards
everything else upstream (e.g. Cloudflare) or resolves it recursively itself.

## Run it

```bash
cargo run
```

Startup config resolution order:

1. `RDNS_CONFIG` env var, if set — path to a TOML config file.
2. `./config.toml`, if present in the working directory.
3. Otherwise, built-in loopback dev defaults (listens on `127.0.0.1:5300`,
   forwards to `1.1.1.1:53`, no local entries).

A sample `config.toml` ships at the repo root and loads automatically.
Point at a different file:

```bash
RDNS_CONFIG=/etc/rdns/config.toml cargo run
```

Test it:

```bash
dig @127.0.0.1 -p 5300 nas.lan A        # local entry
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
order and falls through on failure/timeout. `protocol` only supports `"udp"`
right now — a `"tcp"` value parses but forwarding queries always go out over
UDP.

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

## Reloading config without a restart

Send `SIGHUP` to the running process to reload resolution mode, upstreams,
and local DNS entries from the same config file:

```bash
kill -HUP <pid>
```

- The file is re-read, re-parsed, and fully re-validated before anything is
  applied. A broken edit (bad TOML, invalid address, duplicate name, etc.)
  is logged and the server keeps serving the last-good config — never a
  partial apply.
- `[resolution]`, `[[upstreams]]`, and `[[local_dns_entries]]` are all
  reloadable this way — including switching between `forward` and
  `recursive` mode.
- `dns_listen` changes are **not** picked up on SIGHUP — changing listen
  addresses/ports requires a restart.
- No effect if rdns started with no config file (built-in dev defaults) —
  there's nothing to re-read.

## Metrics export note

The current OpenTelemetry OTLP metrics exporter configuration supports plaintext gRPC endpoints.
Use an `http://` endpoint in `OTEL_EXPORTER_OTLP_ENDPOINT`.

HTTPS OTLP endpoints (`https://`) are not currently supported in this configuration.
