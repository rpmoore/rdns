# Research: TTL-remaining audit, EDNS-cookie cache-bypass, Clock DI

Combines: (1) codebase verification of every file:line claim in `plan.md`'s
Current State section, (2) web research on RFC 7873 (DNS Cookies) and RFC 7830
(EDNS Padding) as background for Open Question 1.

## 1. Codebase verification (Explore subagent, direct code read)

All **behavioral/logic claims** in `plan.md` were independently confirmed
correct by reading the actual code — `compute_wire_ttl`'s aged/remaining/min
logic, `cache_supported()`'s bypass conditions, the chain-wide `expires_at`
ceiling, the DNSSEC proof-material dual-aging split, and the `FixedClock`
test precedent all match the spec's description exactly.

However, the plan was drafted against an earlier state of the tree and a
number of **line numbers have drifted** (code moved, unrelated commits
landed in between). Re-verify against current line numbers when writing the
implementation plan and section files — do not copy `plan.md`'s line numbers
verbatim:

| Item | plan.md claim | Current actual |
|---|---|---|
| `Clock` trait | mod.rs:7669-7671 | **mod.rs:7758-7760** |
| raw `SystemTime::now()` (evaluate_authority_response) | mod.rs:7155,7177 | **mod.rs:7244,7266** (old lines aren't clock calls at all) |
| `store_cache_response` | mod.rs:5006-5020 | **mod.rs:5095-5119** |
| `apply_ttl_bounds` | mod.rs:2105-2111 | **mod.rs:2115-2121** |
| `decompose_response_for_store` | mod.rs:818-919 | **mod.rs:818-930** (end was mid-body) |
| `resolve_ages_cached_response_ttls_for_current_request_time` / `resolve_caps_cached_response_ttls_to_remaining_cache_lifetime` | mod.rs ~16042-16121 | **mod.rs:16287-16365** |
| `FixedClock` (mod.rs) | mod.rs:7910 | **mod.rs:7999-8005** |
| `filter_response_for_requester` | mod.rs ~4462 | definition **mod.rs:1480-1507**, call site **mod.rs:4940** (inside `prepare_backend_result`, fn starts 4665) |

Everything else (`compute_wire_ttl` 188-204, `write_rrset` 229-263,
`write_negative_authority` 265-324, `RRsetEntry`/`StoredRecord`/`NegativeEntry`
entry.rs shapes, `cache_supported`/`probe_cache` mod.rs:5508-5520/4409-4424,
`dns.rs:262,620`, `upstream.rs:296,640`, both EDNS-bypass tests at
mod.rs:18930-18954/18956+, `src/resolver/AGENTS.md:19,24`,
`docs/knowledge/resolver/caching/answer-cache.md` line 44 gap) matched
`plan.md` exactly, current line numbers confirmed unchanged.

**New finding relevant to Open Question 1 (Cookie handling design):**
`filter_response_for_requester` (mod.rs:1480-1507) is a real, exercised
per-requester response-rewrite seam — it builds a client-facing trimmed copy
of an always-DNSSEC-complete stored/synthesized response for DO=false
requesters, called from `prepare_backend_result` (mod.rs:4940). Its doc
comment explicitly notes it does **not** handle the OPT record — callers
must re-append `mirrored_client_opt_record` themselves. This confirms the
codebase already has precedent for "one cached answer, N different
per-requester wire renderings" — the same shape needed for
per-requester COOKIE-option generation if Open Question 1 resolves toward
(a) or (b). The plan should reference this seam by name as the natural
reuse point.

**Also confirmed:** none of `upstream.rs:296,640` or `mod.rs:7244,7266`'s
raw-`SystemTime::now()` timestamps feed `store_cache_response`'s `stored_at`.
Only `request.received_at.0` (client `ResolveRequest`, struct field at
mod.rs:170) is threaded into cache store/lookup (5 use sites: mod.rs:4440,
4555, 4574, 4595, 5107). This confirms Goal 3's scope boundary and the
backend-round-trip-latency freshness-overstatement note in Current State
are both accurate as written.

## 2. RFC 7873 (DNS Cookies) — for Open Question 1

**Wire format (§4):** COOKIE option code 10. Client Cookie is a fixed 8
bytes; if a Server Cookie is present it's 8-32 bytes, so total option length
is either 8 or 16-40 bytes — any other length is malformed (FORMERR, §5.2.2).

**Server behavior (§5.2, 5 cases):**
1. No OPT/no COOKIE → treat as if COOKIE unimplemented.
2. Malformed → FORMERR.
3. Client cookie only (no server cookie) → policy choice: silently discard,
   BADCOOKIE (RCODE 23), or process normally; if it responds, it **must**
   generate a COOKIE option with the client's cookie plus a freshly
   generated server cookie.
4. Client cookie + invalid/stale server cookie → recompute expected value,
   fall back to case-3 handling on mismatch.
5. Client cookie + valid server cookie → process normally, response
   **must** include a COOKIE option (either copied from the request or
   freshly generated with a valid server cookie).

**Confirms the core design constraint driving Open Question 1:** per §4.2,
the server cookie "SHOULD consist of ... a pseudorandom function of the
request source (client) IP address, a secret quantity known only to the
server, and the request Client Cookie." §5.2.4 restates the same binding.
**A resolver cannot replay one cached OPT/COOKIE byte sequence to every
requester** — the server cookie is cryptographically bound to that specific
requester's source IP and client cookie. Any cache design that shares a
cooked answer across requesters must regenerate the COOKIE option per
response, never store it as part of the cached bytes.

RFC 9018 (updates 7873) hardens this further: it says RFC 7873 Appendix B's
example algorithms "MUST NOT be used" (too weak) and mandates
`SipHash-2-4(Client Cookie | Version | Reserved | Timestamp | Client-IP,
Server Secret)` → 16-byte server cookie. Still explicitly keyed on
client IP + client cookie — reinforces "recompute per response," not
"cache and replay."

**Prior art:** BIND ≥9.16 and Knot ≥2.9.0 implement RFC 9018's SipHash
recipe; Unbound/NSD had interop-validated proofs of concept (IETF 104
hackathon). ISC's own operational guidance confirms cookies are
per-client/per-server-instance by design — in anycast clusters, a
shared secret across instances is required specifically because the
server cookie can't be treated as a cacheable/replayable blob.

**Design implication for Options (a)/(b):** cache the RRset/answer data
only; compute and attach a fresh COOKIE option (shared secret + per-request
client IP + client cookie) on every outgoing response, cache hit or miss.
This is exactly the shape `filter_response_for_requester` already
implements for DO-trimming — same seam, different per-requester payload.

## 3. RFC 7830 (EDNS Padding) — for Open Question 1, Option (b)

Code 12. Purpose: mitigate traffic-analysis/size-correlation over encrypted
transports (DNS-over-TLS primarily; DoH by extension) — §6 explicitly says
**MUST NOT use over unencrypted transport**. For a plain UDP/TCP-53
resolver this is currently a no-op concern; only matters if/when DoT/DoH is
served.

**Confirmed cache-key-neutral, unlike Cookie:** §3/§4 specify the option's
byte content is arbitrary filler (SHOULD be 0x00, MAY be anything, receiver
ignores content) and the padding *amount* is unspecified/local-policy
("This document does not specify the actual amount of padding to be used").
Responder rule: MUST pad if query had padding, MAY pad otherwise. None of
this depends on requester identity — a resolver can add/strip/resize
Padding purely at serialization time with zero requester-specific state,
unlike Cookie's per-requester cryptographic binding.

**Design implication:** if Option (b)'s broader allowlist is chosen,
Padding is the easy case (pure serialization-time strip/regenerate, no
state) while Cookie remains the hard case (needs the per-requester
regeneration seam above). The two options are not equally complex to
support — plan should treat them separately rather than as one
"cache-key-neutral options" bucket with uniform effort.

## Sources

- RFC 7873: https://www.rfc-editor.org/rfc/rfc7873.txt / https://datatracker.ietf.org/doc/html/rfc7873
- RFC 9018: https://datatracker.ietf.org/doc/rfc9018/
- RFC 7830: https://www.rfc-editor.org/rfc/rfc7830.txt
- ISC KB (anycast cookie behavior): https://kb.isc.org/docs/dns-cookies-on-servers-in-anycast-clusters
- draft-ietf-dnsop-server-cookies-05: https://www.ietf.org/archive/id/draft-ietf-dnsop-server-cookies-05.html
