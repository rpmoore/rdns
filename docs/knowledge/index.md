---
okf_version: "0.1"
---

# rdns Knowledge Bundle

Agent- and human-readable knowledge about the `rdns` codebase: how
subsystems actually behave, not just what the code says syntactically.
Conforms to [OKF v0.1](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md).

Concepts here describe *implemented, current* behavior, grounded in
specific file/line references. They are living documents — when the
code they describe changes, the concept should be updated in the same
change, not left to drift. For point-in-time design history (why a
decision was made, what alternatives were rejected), see `docs/plans/`
instead; this bundle is not a replacement for that record.

# Areas

* [resolver](resolver/) - DNS resolution engine: caching, recursive/forwarding backends, protocol handling.
