---
type: System
title: CHAOS-class Queries (version.bind.)
description: >
          How rdns answers version.bind. CH TXT (BIND's operator-fingerprint
          query), why it's on by default, and where it's enforced.
resource: src/resolver/mod.rs
tags: [dns, resolver, chaos, config]
timestamp: 2026-07-15T00:00:00Z
---

`version.bind. CH TXT` is BIND's conventional operator-fingerprint query
(`dig version.bind chaos txt`). rdns answers it with an operator-configured
string instead of resolving it like any other query — controlled by
`[chaos]` in `config.toml`, **on by default**, answering `"rdns"`. Set
`[chaos].enabled = false` to opt out and resolve it like any other query
instead.

# Config

`ChaosConfig` (`src/config/mod.rs:318`): `enabled: bool` (default `true`)
and `version_bind: String` (default `"rdns"`), parsed from a `[chaos]` TOML
table via `RawChaosConfig` — including when the table is present but
`enabled` is omitted (`RawChaosConfig.enabled` defaults via
`default_true`, so a bare `[chaos]\nversion_bind = "..."` table stays
enabled). `RuntimeConfig::validate` rejects `enabled = true` paired with
an empty `version_bind` (`ConfigError::ChaosVersionBindEmpty`) or one
longer than `MAX_CHAOS_VERSION_BIND_LEN` -- 64 bytes
(`ConfigError::ChaosVersionBindTooLong`, `src/config/mod.rs:198-207`).

Like `[metrics]` and `max_tcp_connections`, this is **not** part of
SIGHUP hot-reload — it's read once at startup (`main.rs` calls
`ResolveQuery::with_chaos_config(config.chaos.clone())` right after
construction, mirroring `with_max_chain_depth`) and requires a restart to
change.

# Where it's enforced

`ResolveQuery::try_chaos_lookup` (`src/resolver/mod.rs:3937`) runs inside
`resolve` (`src/resolver/mod.rs:3735`) in the same before-cache/
before-backend slot as [local entries](caching/local-dns-entries.md) —
right after `try_policy_block`, before `try_local_lookup` — since a CHAOS
answer is also "data rdns already has," not new work. It matches only
when all of the following hold:

- `self.chaos.enabled` is `true`
- `question.qclass == CHAOS_CLASS` (3, `src/resolver/mod.rs:93`) — a
  `version.bind. IN TXT` query (class 1) does **not** match and falls
  through to normal resolution
- `question.qtype == TXT_RECORD_TYPE` (16)
- `question.qname == VERSION_BIND_QNAME` (`"version.bind"`,
  `src/resolver/mod.rs:98` — matched against the already-normalized,
  lowercased, trailing-dot-stripped `QuestionKey.qname`)

On a match it builds a response via `protocol::build_txt_answer_response`
(`src/protocol/mod.rs:717`) — a single TXT answer at TTL 0
(`CHAOS_ANSWER_TTL`, matching BIND's own convention of never caching this
answer), with the answer record's class echoing the question's own class
(CHAOS in, CHAOS out) rather than being hardcoded to IN like
`build_a_answers_response`/`build_aaaa_answers_response` are — the reason
this needed its own builder instead of reusing the `AddressAnswer`/
`write_sinkhole_answer` path.

# Metrics and events

`ResolveDecisionKind::ChaosAnswer` (`src/resolver/mod.rs:2651`) maps to
`QueryEventOutcome::AllowedFromLocal` for query-event logging (same
outcome bucket as a local-DNS-entry answer — a synthetic config-driven
answer, not a real "local entry," but the same "answered without
touching cache/backend" shape) and increments `ResolverMetric::QueryAllowed`,
same as `try_local_lookup`.

# See also

- [local-dns-entries](caching/local-dns-entries.md) — the analogous
  before-cache/before-backend short-circuit for A/AAAA local entries.
