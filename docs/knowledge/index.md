---
okf_version: "0.1"
---

# rdns Knowledge Bundle

* [rdns-overview](rdns-overview.md) - What rdns is, its four-layer architecture, and how a query
  flows from socket to response. Start here.
* [resolver](resolver/) - DNS resolution engine: caching, recursive/forwarding backends, protocol
  handling.
* [delivery](delivery/) - Socket and transport I/O: the DNS TCP listener's connection limits,
  framing, timeouts, and shutdown.
* [config](config/) - Runtime settings and the IANA data snapshots bundled into the binary.
