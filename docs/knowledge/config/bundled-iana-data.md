---
type: System
title: Bundled IANA Data (root hints and TLD list)
description: >
          The IANA snapshots compiled into the binary, how each is parsed
          at runtime, and how CI detects real upstream drift without
          flagging IANA's per-publish version/date headers.
resource: src/config/mod.rs
tags: [config, iana, root-hints, tlds, ci, bundled-data]
timestamp: 2026-08-07T00:00:00Z
---

Two IANA-published files ship inside the binary via `include_str!`, so a
fresh install can resolve recursively and validate local-zone names with
no network fetch and no on-disk assets:

- `src/config/named.root` — InterNIC's root hints
  (`BUNDLED_NAMED_ROOT`, `src/config/mod.rs:1030`), from
  <https://www.internic.net/domain/named.root>.
- `src/config/tlds-alpha-by-domain.txt` — IANA's currently-delegated TLD
  list (`BUNDLED_IANA_TLDS`, `src/config/mod.rs:1099`), from
  <https://data.iana.org/TLD/tlds-alpha-by-domain.txt>.

A third bundled IANA asset, `src/config/root-anchor.txt`, is covered by
[dnssec-validation](../resolver/dnssec-validation.md) instead — it has its
own refresh story (manual, on KSK rollover) and its own scheduled CI job.

Neither of the two files here is parsed into a static table at build time.
Both are re-derived from the embedded text at runtime, so refreshing a
snapshot is a one-file change with no generated code to regenerate.

# Root hints

`bundled_root_hints` (`src/config/mod.rs:1032`) parses the embedded text
on every call and **panics** if it fails — a malformed bundled asset is a
build/packaging bug, not a runtime condition to recover from.

`parse_named_root` (`src/config/mod.rs:1044`) accepts the zonefile subset
InterNIC actually publishes: `;` starts a comment anywhere on a line,
lines are `<name> <ttl> [class] <type> <rdata>` (an explicit class is
accepted only when it is `IN`), and record types are matched
case-insensitively. Only `A`/`AAAA` records become hints — `NS` lines are
skipped, since the glue addresses are what the resolver needs. Addresses
are grouped into one `RootHintConfig` per owner name in first-seen order,
each endpoint at port 53, with the owner name lowercased and its trailing
dot stripped. An input yielding no `A`/`AAAA` records is an error, not an
empty hint set.

The bundled set is used only when `root_hints_source` is
`RootHintsSource::Bundled` (`src/config/mod.rs:774`); operators can
override it with `RootHintsSource::Static`, and `load_root_hints` is the
single choke point both flow through.

`root_hints_version` (`src/config/mod.rs:728`) is **not** derived from the
file's header. It is an operator-supplied opaque string (e.g.
`"bundled:v1"`) that feeds the cache namespace
(`src/config/mod.rs:272`) and is only validated as non-empty
(`ConfigError::InvalidRootHintsVersion`, `src/config/mod.rs:793`).
Refreshing `named.root` does not change it automatically.

It is not, however, the only thing that invalidates the cache on a
refresh. `authority_config_hash` (`src/config/mod.rs:841`) hashes the
*parsed* hints — every root-hint name and every endpoint — into the same
namespace, so a refresh that actually changes a root server's address or
name shifts the namespace on its own, with `root_hints_version` untouched.
The two cover different cases: the hash handles semantic changes
automatically, while `root_hints_version` is the operator's explicit
override for forcing invalidation when the parsed hints are identical.
A header-only refresh changes neither — which is the point: nothing the
resolver depends on has changed.

# TLD list

`bundled_iana_tlds` (`src/config/mod.rs:1101`) parses once into a
`OnceLock<HashSet<String>>` of lowercased TLDs, panicking on a malformed
asset for the same reason as above.

`parse_iana_tlds` (`src/config/mod.rs:1112`) is deliberately strict: a
comment is only a line whose first non-blank character is `#` (that's the
version header), every other non-blank line must be exactly one
whitespace-free token, and an empty result is an error.

A mid-line `#` is therefore never a comment, though what happens next
depends on spacing: `COM # note` is three tokens and fails the parse,
while `COM#note` is a single token and is silently accepted as the bogus
TLD `com#note`. Neither outcome is "the data is unchanged", which is why
the freshness check treats a mid-line `#` as drift rather than stripping
it.

The set has exactly one consumer: `validate_not_registered_tld`
(`src/config/mod.rs:1153`), via `is_registered_iana_tld`
(`src/config/mod.rs:1135`). It rejects a local DNS name whose rightmost
label is a real delegated TLD, so a local override can never claim
authority over a real public domain. `home.arpa` is the one explicit
exception (RFC 8375), since `arpa` itself is in the list. The other
special-use names — `test`, `invalid`, `example`, `local`, `localhost`
(RFC 6761) and `onion` (RFC 7686) — never appear in this file at all, so
they need no exception.

# Freshness checking

`scripts/check-bundled-data-freshness.sh` fetches both URLs and compares
them against the bundled copies. The `bundled-data-freshness` job in
`.github/workflows/ci.yml:101` runs it via `just
check-bundled-data-freshness` on every CI run. A fetch failure is an error
(the check never silently passes when upstream is unreachable).

Both sources rewrite a version/date header on **every** publish, whether
or not the data changed — IANA bumps `# Version 2026080700, Last Updated
...` and InterNIC bumps `; last update:` / `; related version of root
zone:`. Comparing bytes therefore failed CI, and forced a commit, on
publishes that changed nothing the parsers can see.

So the check compares bytes first and, only if they differ, compares
**normalized** output from `scripts/normalize-bundled-data.sh`:

- Byte-identical → pass.
- Normalized-identical → `::notice`, pass. The bundled copy stays as-is.
- Otherwise → `::error` plus a unified diff, exit 1.

Both normalizer runs write to files whose exit status is checked, rather
than being compared through process substitution. Bash does not propagate
a process substitution's exit status, so a normalizer that failed to run
would hand `diff` two empty streams — which compare equal, quietly
downgrading a broken check to "comment-only, pass". A normalization
failure is instead reported as an error and treated as stale.

`normalize-bundled-data.sh` takes a format mode rather than a comment
character, because each mode mirrors one parser exactly — that
correspondence is what makes "normalized output unchanged" mean "parsed
result unchanged":

- `zonefile` strips from `;` to end of line, matching `parse_named_root`.
- `tld-list` strips only whole `#`-leading lines, matching
  `parse_iana_tlds`. Stripping a mid-line `#` here would be wrong: such a
  line fails the parse, so it has to count as drift.

Both modes then collapse whitespace runs and drop blank lines, matching
the trim/`split_whitespace` both parsers do.

# Refreshing

`just update-iana-data` fetches both files and applies the same
normalized comparison before installing each one, so a header-only
republish leaves the working tree clean instead of producing a diff that
reviewers have to read and dismiss. It prints per-file status
(`updated` / `unchanged apart from comments, keeping bundled copy`).

`just update-iana-data 1` forces upstream's exact bytes in, header and
all — use it when you specifically want the newer header text.

Because the comparison is normalized in both directions, a bundled file
can sit at an older header than upstream indefinitely while still being
current in content. The header is not a staleness signal; the check is.

# See also

- [dnssec-validation](../resolver/dnssec-validation.md) — the bundled
  root KSK trust anchor, the other IANA asset, with a separate manual
  refresh path and its own scheduled staleness workflow.
