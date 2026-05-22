# Policy And Blocking Domain

## Responsibility

The policy domain decides whether a client may resolve a domain. It combines local administrator rules with known-malicious-domain data from external sources.

It should not fetch blocklists, write SQLite rows directly, parse DNS packets, or build DNS response bytes.

## Policy Inputs

- Client IP address.
- Normalized domain name.
- Query type and class.
- Current policy snapshot.
- Current resolver settings.

## Policy Outputs

- `Allow`
- `BlockLocalRule`
- `BlockKnownMalicious`
- `BlockInvalidDomain`

The output should include a reason code and rule/source identifier when available so query logs and the UI can explain decisions.

## Client Identity

Start with transport source IP because that is what the DNS listener sees reliably.

Model it as a domain concept instead of passing raw socket metadata everywhere:

- `ClientIdentity::Ip(IpAddr)`
- `ClientIdentity::Cidr(IpNet)` for configured selectors.
- Optional display labels for known clients.
- Future support for DHCP/static-reservation imports.
- Future support for groups such as `kids_devices` or `iot_devices`.

Do not put DHCP, MAC-address lookup, router integration, or VPN-specific behavior in the resolver core. Those can become identity-provider adapters later.

Known concern: IP-only policies can be wrong when DHCP leases change, IPv6 privacy addresses rotate, or another resolver forwards all traffic from one source IP. The UI should make this limitation visible when administrators create IP-based rules.

## Precedence

Recommended decision order:

1. Malformed DNS request is handled by the protocol layer before policy.
2. Local client/domain deny rules.
3. Known-malicious-domain blocklist.
4. Allow.

Local rules should take precedence because they are explicit administrator intent. If allowlist behavior is later added, define it carefully because it can bypass security blocklists.

## Response-Aware Policy

Request-time policy must check the requested domain before forwarding. The resolver should also define what happens when an allowed request returns records that point at blocked names.

Initial behavior:

- Evaluate local client/domain rules against the requested question name before cache or upstream lookup.
- Evaluate known-malicious-domain policy against the requested question name before cache or upstream lookup.
- After an upstream response, inspect CNAME chains and answer owner names that are present in the response.
- If a CNAME target or answer owner name matches a known-malicious-domain selector, return the configured known-malicious block response and do not cache that upstream response as allowed.
- Keep local client/domain rules request-name based unless a future setting explicitly applies them to response CNAME targets too.

This prevents a benign-looking domain from bypassing malicious-domain policy through a CNAME to a blocked domain, while keeping administrator local rules predictable.

## Domain Normalization

Normalize domains before any lookup:

- Lowercase ASCII names.
- Remove one trailing dot.
- Convert IDN names to ASCII/Punycode before matching.
- Reject empty labels except root handling.
- Reject labels over 63 bytes and names over 255 bytes.
- Match exact domains and configured subdomain behavior consistently.

Represent matching intent explicitly:

- `Exact("example.com")`
- `Subtree("example.com")`, matching `example.com` and `*.example.com`

Avoid ambiguous wildcard strings in the core domain model.

## Local Client/Domain Rules

Rules should include:

- Client selector: exact IP, CIDR range, or named client group.
- Domain selector: exact or subtree.
- Action: deny.
- Enabled flag.
- Optional description.
- Created/updated metadata.

Start with deny-only rules. Allow rules can be added later if there is a clear UI and precedence model.

## Known-Malicious Domain Blocklists

Blocklists should be activated as immutable snapshots.

The policy engine reads from an in-memory snapshot built from persistence:

- Exact domains.
- Subtree domains if source format supports them.
- Source IDs for explainability.
- Generation timestamp.

When blocklists update, build a new snapshot and swap it atomically. Active DNS queries should either use the old snapshot or the new snapshot, never a partially updated one.

## Block Response Mode

Make block response behavior configurable globally, with a clear default.

Options:

- `Refused`: return DNS `REFUSED`.
- `NxDomain`: return `NXDOMAIN`.
- `NoData`: return no answers for the requested type.
- `Sinkhole`: return configured A/AAAA addresses.

Default recommendation: `Refused` for clarity and low surprise. Add `Sinkhole` only when the administrator configures sinkhole IPs.

Block response settings should include:

- Default mode for local client/domain rules.
- Default mode for known-malicious-domain blocks.
- Optional blocked-response TTL.
- Optional IPv4 and IPv6 sinkhole addresses.
- Whether blocked responses are cacheable by clients.

Reason codes must be logged regardless of DNS response mode:

- `local_rule`
- `known_malicious`
- `invalid_domain`
- `admin_disabled`

Concern: `NXDOMAIN`, `REFUSED`, `NODATA`, and sinkhole responses produce different client behavior. Some clients retry aggressively on `REFUSED`, while `NXDOMAIN` can be cached. This must be an intentional administrator choice, not an implementation accident.

## Tests

Unit tests:

- Domain normalization and validation.
- Exact vs subtree matching.
- CIDR and exact-client matching.
- Local rule precedence over malicious blocklist.
- Reason codes and source IDs.
- Block response mode selection.
- Known-malicious match on upstream CNAME target blocks the response and prevents allowed caching.

Property-style tests:

- Case-insensitive matching.
- Trailing-dot equivalence.
- Subtree match does not match sibling suffixes such as `badexample.com` for `example.com`.
