---
type: System
title: DNS TCP Listener
description: >
          The DNS-over-TCP listener: global and per-source-IP connection
          limits, length-prefix framing, idle timeouts, oversized-response
          fallback, and graceful shutdown.
resource: src/delivery/dns.rs
tags: [dns, delivery, tcp, rfc7766, rfc1035, timeouts, shutdown]
timestamp: 2026-08-10T00:00:00Z
---

`TcpDnsServer` (`src/delivery/dns.rs:382-585`) is a first-class DNS
listener, not a large-response fallback: RFC 7766 makes TCP mandatory, and
`main()` binds it alongside the UDP listener(s) unconditionally
(`TcpDnsServer::bind_configured`, `src/delivery/dns.rs:463-484`, called
from `src/main.rs:196`). One `TcpDnsServer` is bound per configured
address in `RuntimeConfig::dns_listen` (`src/config/mod.rs:35`).

# Connection limits

Two independent caps, both enforced before a connection is handed a
resolver-facing task:

- **Global**: `max_connections` (from `RuntimeConfig::max_tcp_connections`,
  default `DEFAULT_MAX_TCP_CONNECTIONS = 128`, `src/config/mod.rs:52`),
  enforced via a `tokio::sync::Semaphore` (`src/delivery/dns.rs:499`). The
  accept loop (`serve_until`, `src/delivery/dns.rs:494-562`) acquires a
  permit *before* calling `listener.accept()` (`src/delivery/dns.rs:519`),
  not after — so once the cap is reached, excess connections stay parked in
  the kernel's accept backlog instead of being pulled into a live,
  resource-holding `TcpStream` and then dropped. That also makes the
  select loop cancel-safe: an abandoned semaphore wait is invisible to the
  client, unlike dropping an already-`accept()`-ed stream.
- **Per-source-IP**: `max_connections_per_ip`
  (`DEFAULT_MAX_TCP_CONNECTIONS_PER_IP = 32`, `src/delivery/dns.rs:38`,
  not currently exposed via `RuntimeConfig`), enforced by
  `PerIpConnectionGuard` (`src/delivery/dns.rs:590-631`), an RAII guard
  backed by an `Arc<Mutex<HashMap<IpAddr, usize>>>` that increments on
  acquire and decrements (pruning the map entry at zero) on drop — added in
  response to PR #117 review, which found no per-IP cap existed
  (`src/delivery/dns.rs:1439-1441`). A connection that would exceed the
  per-IP cap is dropped at accept time (`src/delivery/dns.rs:536-539`),
  after the global permit was already acquired — the permit is returned to
  the semaphore when the guard/permit go out of scope.

`bind_with_options` (`src/delivery/dns.rs:418-461`) rejects
`max_connections == 0` and `max_connections_per_ip == 0` at construction
time: a zero global cap would mean every accepted connection stalls forever
waiting for a permit that's never issued, and a zero per-IP cap would insert
a permanent zero-count map entry for every distinct source IP without ever
letting a connection through — both self-inflicted DoS conditions that are
easier to reject up front than debug from the outside.

# Framing and message-size limits

Framing is 2-byte big-endian length-prefix per RFC 1035 §4.2.2, hand-read
directly off the stream in `serve_tcp_connection`
(`src/delivery/dns.rs:664-777`) rather than through the buffer-oriented
`decode_tcp_frame`/`encode_tcp_frame` helpers in `src/protocol/mod.rs:960-996`
(those helpers exist for outbound upstream/authority TCP transport,
`src/delivery/upstream.rs:29`, where the whole frame is already in memory;
the inbound listener instead reads directly off a `TcpStream` and hand-rolls
the same 2-byte prefix, so no bug results — but it is separate code, not a
shared implementation).

- `MAX_TCP_MESSAGE_SIZE = u16::MAX` (`src/delivery/dns.rs:41`) bounds both
  directions: an incoming length prefix is trusted at face value (the read
  buffer is sized to exactly that length,
  `src/delivery/dns.rs:687-700`), since the 2-byte prefix format itself
  caps it at 65535.
- A length prefix shorter than a DNS header (`DNS_HEADER_LEN` bytes) is
  rejected without reading a message body or invoking the resolver
  (`src/delivery/dns.rs:692-699`).
- On the response side, if a resolved answer exceeds
  `MAX_TCP_MESSAGE_SIZE` (only reachable if a backend itself violates the
  RFC 1035 length-prefix ceiling), the connection is not dropped — the
  query is answered with a same-transaction SERVFAIL built via
  `build_servfail_response`, preserving EDNS/CD context by re-parsing the
  request bytes only on this rare fallback path
  (`src/delivery/dns.rs:742-768`), and the connection keeps serving
  subsequent pipelined queries.
- Queries are pipelined: `serve_tcp_connection` loops, reading and
  answering one length-prefixed query after another on the same connection
  (`src/delivery/dns.rs:661-663`, tested by
  `tcp_server_answers_pipelined_queries_on_one_connection`,
  `src/delivery/dns.rs:1345`). The loop — and the connection — ends on
  any of: the client closing the connection or going idle past
  `TCP_CONNECTION_IDLE_TIMEOUT` (see Timeouts below), a length prefix
  shorter than `DNS_HEADER_LEN` (`src/delivery/dns.rs:692-699`), or an
  I/O error on the message-body read or the response write
  (`src/delivery/dns.rs:701-703,773-775`).

# Timeouts

`TCP_CONNECTION_IDLE_TIMEOUT = 30s` (`src/delivery/dns.rs:46`) wraps every
read *and* write inside `serve_tcp_connection`
(`src/delivery/dns.rs:673-676` for the length prefix,
`src/delivery/dns.rs:701-703` for the message body,
`src/delivery/dns.rs:773-775` for the response write) — the same constant
doubles as the idle-between-queries timeout and the in-flight read/write
timeout, since a stalled read or write looks identical to a stalled client
from the listener's point of view. A timeout on the initial length-prefix
read (i.e. no more queries arriving) closes the connection cleanly; a
timeout mid-message-body read or during the response write is surfaced as
an `io::Error` and closes the connection.

# Shutdown

`serve_until`'s post-shutdown drain is itself bounded
(`src/delivery/dns.rs:550-560`), unlike the UDP server's drain: a TCP
connection isn't guaranteed to finish on its own the way a UDP
datagram-handling task does, so an idle or stalled client can't hang
shutdown indefinitely. `bind_configured` derives the grace period as
`config.per_query_deadline + TCP_SHUTDOWN_GRACE_BUFFER` (250ms,
`src/delivery/dns.rs:58,469`); direct `bind`/`bind_with_max_connections`
callers get a fixed `TCP_SHUTDOWN_GRACE_PERIOD` (1s,
`src/delivery/dns.rs:51,413`). If in-flight connection tasks haven't
drained within the grace period, they're aborted
(`src/delivery/dns.rs:557-559`).

# Shared resolver flow with UDP

`serve_tcp_connection` calls the same `ResolveQuery::resolve`
(`src/resolver/mod.rs:4759`) that the UDP path uses
(`handle_datagram`, `src/delivery/dns.rs:348-368`), passing
`ObservedSourceEndpoint::tcp(peer_addr, Some(listener))`
(`src/delivery/dns.rs:731`) so query events and metrics can distinguish
transport. Only framing, connection lifecycle, and transport-level timeouts
differ between the two listeners — resolution, caching, and policy
decisions are transport-agnostic, per the layering in
[rdns-overview](../rdns-overview.md#module-layout).

# Tests

`src/delivery/dns.rs`'s TCP test module (from `src/delivery/dns.rs:1230`)
covers: basic length-prefixed request/response
(`tcp_server_answers_a_length_prefixed_query`, line 1250), pipelining
(line 1345), one-server-per-configured-address binding (line 1383),
configured `max_tcp_connections` plumbing (line 1505), per-source-IP
connection limiting (`tcp_server_enforces_per_source_ip_connection_limit`,
line 1441), oversized-response SERVFAIL fallback while keeping the
connection open (`tcp_server_answers_servfail_for_oversized_response_and_keeps_connection_open`,
line 1564), and injected-clock TTL aging through the TCP path (line 1300).

# See also

- [rdns-overview](../rdns-overview.md) - four-layer architecture and where
  `delivery` sits relative to `protocol` and `resolver`.
- `src/delivery/AGENTS.md` - directory-local summary of `src/delivery`'s
  responsibilities and testing expectations.
