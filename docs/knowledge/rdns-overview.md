---
type: System
title: rdns Overview
description: >
          What rdns is, its four-layer architecture, and how a query
          flows from socket to response.
resource: src/lib.rs
tags: [architecture, overview, dns, resolver, delivery, protocol, config]
timestamp: 2026-07-14T00:00:00Z
---

rdns is a single-binary DNS server (Rust, Tokio async runtime): it answers
configured local names for a LAN, then either forwards everything else to
a fixed set of upstreams (e.g. Cloudflare) or resolves it recursively
itself via the real root/TLD/authority chain — not both at once. Which
one a given deployment does is a config-time choice, not a per-query one
(`ResolutionMode`, see below).

# Module layout

`src/lib.rs:15-18` exposes exactly four top-level modules, and
`src/AGENTS.md` pins each one to a single architectural layer:

- **`config`** (`src/config/`) — runtime settings and validation. Owns
  listener addresses, forward-upstream config, recursive resolver config,
  timeouts/deadlines, root hints, DNSSEC mode flags, UDP payload-size
  limits, and cache-namespace derivation. Validates before anything else
  sees the config; forward mode requires at least one enabled UDP
  upstream, recursive mode owns root-hints/recursion-limit validation
  instead.
- **`delivery`** (`src/delivery/`) — socket and transport I/O.
  `dns.rs` is the UDP listener (bind, receive/send loop, per-request
  concurrency limits, shutdown) and the TCP listener (RFC 7766 makes TCP
  mandatory, not just a large-response fallback). On Linux,
  `UdpDnsServer::bind_configured` binds several `SO_REUSEPORT` sockets
  per configured address (`udp_sockets_per_listener`,
  `src/delivery/dns.rs:90-113`) so the kernel load-balances datagrams
  across parallel receive loops instead of funneling all intake through
  one. `upstream.rs` is
  outbound transport: forwarding to configured upstreams and querying
  recursive authorities, including transaction-ID generation, UDP/TCP
  exchange, timeouts, upstream health/retry, and TCP fallback on
  truncation.
- **`protocol`** (`src/protocol/`) — DNS wire-format parsing, validation,
  and encoding. Deterministic and byte-oriented on purpose: no socket
  I/O, no cache lookups, no policy decisions. Defines the message/header/
  question/record/EDNS types, parses UDP messages and TCP frames,
  validates query shape, and builds responses (including error responses
  like FORMERR/NOTIMP/BADVERS).
- **`resolver`** (`src/resolver/`) — resolution decisions, caching,
  policy, metrics, and event emission. This is where a decoded query
  actually gets turned into an answer: local-entry lookup, cache
  lookup/store, request coalescing (single-flight), forwarding
  orchestration, recursive iterative resolution (CNAME restarts, referral
  walking, DNSSEC/EDNS response shaping), and protocol-error handling all
  live here, behind trait boundaries (`ResolutionBackend`, `DomainDnsCache`,
  `Clock`, `MetricsSink`, `QueryEventSink`) so it's testable without real
  network I/O.

Layering is enforced by convention, not the type system: `delivery` calls
into `resolver` behind traits, `resolver` calls into `protocol` for wire
work, and `config` is consumed (read-only) by both. See each layer's own
`AGENTS.md` for what's explicitly out of bounds for it.

# The two resolution modes

`ResolutionMode` (`Forward` vs `Recursive`, surfaced in config as
`ConfigResolutionMode`) is selected once at startup/reload, not
per-query:

- **Forward** — `ForwardingResolutionBackend` (`src/main.rs:667`) proxies
  to a fixed, prioritized list of configured upstreams.
- **Recursive** — `RecursiveResolutionBackend` (`src/main.rs:702`) walks
  root → TLD → authority itself, using either bundled or configured root
  hints.

Both modes share the same request path once wrapped in a
`BackendSnapshot` (`ResolveQuery::resolve`, `src/resolver/mod.rs:3702`):
local entries, then cache, then (for `Recursive`-tagged snapshots) the
per-client DNSSEC-record filtering and RD=0 cache-only gating documented
in `resolver/rd-bit-handling.md`.

# Entry point and lifecycle

`main()` (`src/main.rs:67`) does, in order: load and validate config,
build the local-DNS-entries handle, build the resolution backend for
whichever mode is configured (`build_forward_backend_snapshot` /
`build_recursive_backend_snapshot`, `src/main.rs:660-661`), bind the UDP
listener(s) (`UdpDnsServer::bind_configured`, `src/main.rs:152`) and TCP
listener(s) (`TcpDnsServer::bind_configured`, `src/main.rs:160`), then
serve until shutdown. A SIGHUP handler
(`spawn_sighup_reload_task`, `src/main.rs:573`) re-reads the config file
and publishes a new backend/local-entries snapshot atomically, without a
stop-the-world pause — see `resolver/caching/cache-epoch.md` for how that
interacts with the answer cache.

# See also

- [resolver](resolver/) — the resolution engine: caching, recursive/
  forwarding backends, protocol handling, and the RD-bit gating this doc
  only summarizes.
- `docs/plans/` — point-in-time design history (why a decision was made,
  what alternatives were rejected). This bundle documents *current*
  behavior only; it isn't a replacement for that record, and this doc in
  particular should be updated in the same change whenever the module
  layout or startup sequence it describes actually changes.
