# DNS Protocol Domain

## Responsibility

The DNS protocol domain owns wire-format correctness. It should parse client queries, parse upstream responses, build resolver responses, and expose protocol-level value objects to the rest of the application.

It should not decide policy, choose upstream resolvers, perform I/O, access the database, or know about the admin UI.

The protocol module may provide generic response builders, but the application layer decides when to use them. For example, protocol can build `REFUSED`, `NXDOMAIN`, `NODATA`, or synthetic A/AAAA responses; policy and resolver code decide which one represents a block.

## Existing Code To Rework

`src/dns.rs` currently parses DNS messages and many record types. Keep the useful record-modeling work, but refactor it before accepting real network traffic.

Required changes:

- Return `Result<T, DnsParseError>` instead of panicking.
- Replace all unchecked slices and `unwrap` calls with bounds-checked reads.
- Replace `unimplemented!` for unknown record types with an `Unknown { rtype, bytes }` record variant.
- Parse domain compression pointers relative to the full message, not section slices.
- Detect pointer loops and invalid pointer targets.
- Enforce DNS name limits: 63 bytes per label and 255 bytes per full name.
- Preserve enough original bytes to support cached response rewriting where appropriate.
- Add a serializer/response builder for normal responses, blocked responses, and protocol errors.

## Domain Model

Core value objects:

- `MessageId(u16)`
- `DnsName`
- `Question { name, qtype, qclass }`
- `QuestionKey { name, qtype, qclass }`
- `DnsHeader`
- `DnsMessage`
- `DnsResponse`
- `ResourceRecord`
- `RecordData`
- `ResponseCode`

Error model:

- `Truncated`
- `InvalidLabel`
- `InvalidNamePointer`
- `PointerLoop`
- `UnsupportedOpcode`
- `InvalidQuestionCount`
- `InvalidUtf8Label`
- `UnexpectedEof`
- `MalformedRecord`

## Query Constraints

Start with standard recursive queries:

- Accept opcode `QUERY`.
- Support one-question queries for resolver behavior.
- Return `FORMERR` or `NOTIMP` for unsupported opcodes and shapes.
- Preserve recursion-desired behavior where sensible.
- Reject malformed packets without panicking.
- Parse EDNS `OPT` pseudo-records enough to understand advertised UDP payload size and DNSSEC `DO` behavior, even if full EDNS support is deferred.
- If EDNS features are not fully supported, expose them to resolver/cache code so those queries can bypass cache or receive a conservative response instead of being cached incorrectly.

Multi-question DNS messages are rare and complicate cache/policy semantics. The first production milestone should reject or explicitly not implement them.

## UDP Size And Truncation

Response construction must respect the client's effective UDP response size.

- Use the DNS default UDP size when no EDNS payload size is advertised.
- Clamp advertised EDNS payload sizes to a configured maximum.
- If a response cannot fit, return a truncated UDP response with the `TC` bit instead of emitting an oversized datagram.
- Cache serialization must re-check size against the current client request; a cached template that fit one client may not fit another client's UDP size.
- Upstream truncation should trigger TCP fallback when available.

## Response Construction

The protocol layer should provide helpers for:

- `build_formerr_response(request_id)`
- `build_refused_response(request)`
- `build_nxdomain_response(request)`
- `build_nodata_response(request)`
- `build_a_block_response(request, ipv4)`
- `build_aaaa_block_response(request, ipv6)`
- `build_truncated_response(request)`
- `rewrite_response_id(response_bytes, request_id)`

Blocked-response behavior must be selected by policy/config, but byte construction belongs here.

Blocked responses must use a configured TTL when they include cacheable negative or synthetic answers. The resolver must log the policy reason separately; DNS response bytes alone are not the audit trail.

## TCP Framing

DNS over TCP uses a two-byte length prefix before each DNS message.

Requirements:

- Enforce a configurable maximum DNS TCP message size.
- Use read and write timeouts.
- Limit concurrent TCP connections.
- Close idle connections.
- Support multiple queries per connection only after the simple one-query path is stable.
- Use TCP upstream fallback when an upstream UDP response has the `TC` flag set.

The UDP and TCP delivery adapters should share the same protocol parser and resolver application service after framing is handled.

## Tests

Unit tests:

- Valid queries for A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, CAA, DNSSEC-related records.
- Unknown record passthrough.
- Truncated headers, questions, and records.
- Invalid compression pointers.
- Compression pointer loops.
- Label and full-name length limits.
- Unsupported opcode and multi-question handling.
- Response serializer round trips for blocked/error responses.
- EDNS `OPT` parsing for UDP payload size and DNSSEC `DO` visibility.
- UDP response-size truncation behavior.
- TCP length-prefix encode/decode behavior.
- Max-size and timeout behavior for TCP framing.

Integration fixtures:

- Real captured DNS query/response bytes.
- Packets from common tools such as `dig` and `nslookup`.

Fuzzing:

- Add parser fuzz tests once the checked parser API exists.
- The invariant is that arbitrary bytes must return either a parsed message or a structured parse error, never panic.
