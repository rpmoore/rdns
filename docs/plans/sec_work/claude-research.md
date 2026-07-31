# Research: DNSSEC Validation + BADCOOKIE Handling

Research performed for `/deep-plan` on `docs/plans/sec_work/spec.md`. Two
subagent passes: codebase (Explore-style) and web (best practices, 2025-2026
sources). Findings below correct/extend the spec's grounding in a few places
— those are called out explicitly.

---

## Part 1 — Codebase Research

### 1.1 Project structure & conventions

Layering matches AGENTS.md's config/delivery/protocol/resolver split:
- `src/config/mod.rs` — settings + validation (`RootHintsSource`, `DnssecValidationMode`, `RecursiveResolutionConfig::validate`)
- `src/protocol/mod.rs` — wire parsing/encoding, no policy (`parse_dnskey_record`, `parse_ds_record`, `parse_rrsig_record`, response builders)
- `src/resolver/mod.rs` (23,742 lines) + `src/resolver/cache/` — resolution decisions, cache, policy, metrics, events

Policy-decision functions (`src/resolver/cache/assemble.rs:426-498`,
`dnssec_servfail_check`/`dnssec_ad_bit`) are small, free (non-method)
functions: pure `fn(&[data], &QueryFeatures) -> bool`, no I/O, doc-commented
with the RFC citation and a cross-reference to their positive/negative
sibling. This is the idiom a validator's decision functions should follow.

Entry-construction hooks: `build_rrset_entry` (`src/resolver/mod.rs:1039-1064`)
and `build_negative_entry` (`:1080-1120`) are free functions taking
already-decomposed message data plus flags, returning a built entry struct.
**Both currently hardcode `dnssec_state: Default::default()`** (line 1057
and 1117) — these are the exact two call sites a validator's output needs to
flow into.

### 1.2 Chain-of-trust / referral walk

The delegation/referral walk (`src/resolver/mod.rs:8115-8532`) is a
**separate concern from chain-of-trust validation**, not directly reusable
as-is, though it's a candidate hook point for per-zone-cut DNSSEC state
accumulation:

- `IterativeQueryState` (`:8116-8123`): `question`, `current_zone`,
  `seen_referrals`, `seen_cnames`, `cname_chain`, `cname_restarts` — no
  DNSSEC field today. Threaded through one full iterative query; natural
  place to add an accumulator if the walk is chosen as the DNSSEC hook
  point.
- `evaluate_authority_response` (`:8362-8433`, async) — per-authority-response
  dispatcher: usable-answer check, CNAME-restart check, then falls through
  to `referral_authorities` (`:1258`) / `handle_referral` (`:8486-8514`) /
  `handle_missing_referral` (`:8448-8483`, glueless delegations).
- `referral_authorities` (`:1258-1297`) extracts NS+glue per hop — walks
  *delegation*, not signatures. No DNSKEY/DS/RRSIG awareness.
- `handle_referral` (`:8486-8514`) validates zone progression and caches the
  delegation via `self.delegation_cache.insert(...)` — a chain-of-trust step
  could piggyback here, but needs its own DNSKEY-set fetches (referral
  responses don't carry DNSKEY RRsets) and its own accumulated trust state.
  **Plugging in here requires new fields on `IterativeQueryState` and new
  authority queries, not just reading existing referral data.**

Two real design options (matches spec's open question #3):
- (a) extend `IterativeQueryState`/`evaluate_authority_response` per-hop
  (validate as you descend).
- (b) a separate pass right before `build_rrset_entry`/`build_negative_entry`
  (`:1039`, `:1080`) that walks accumulated DNSKEY/DS/RRSIG material in the
  final synthesized response (`synthesize_recursive_cname_response`,
  `:1367-1430`, always DNSSEC-complete since `dnssec_ok = true` is forced
  for every recursive fetch, `:1373`).

Option (b) is structurally simpler — no new authority round-trips needed for
the terminal RRset (only for chasing DNSKEY/DS up the parent chain if not
already cached) — and matches how real resolvers do it (see §2.1 below,
validator as a post-hoc pass, not inline-per-hop).

### 1.3 Request pipeline / early-reject hooks (BADCOOKIE)

Natural hook point: **`probe_cache`** (`src/resolver/mod.rs:~5225-5250`),
which calls **`cache_supported`** (`:6526-6538`):

```rust
fn cache_supported(query: &DecodedQuery) -> bool {
    query.message.edns.as_ref().map(|edns| {
        edns.extended_rcode == 0
            && edns.version == 0
            && (edns.flags & !EDNS_DO_FLAG) == 0
            && (edns.options.is_empty()
                || crate::protocol::edns_cookie::is_solely_cookie_option(&edns.options).is_some())
    }).unwrap_or(true)
}
```

This is the single existing EDNS-admission gate before cache lookup, already
importing `edns_cookie::is_solely_cookie_option`. A BADCOOKIE check
(recompute server cookie via `build_server_cookie`, compare to the incoming
16-byte tail currently discarded at `edns_cookie.rs:100-101`) fits directly
alongside/inside this function, or as a sibling check called from
`probe_cache` before the `cache_supported(decoded)` branch at `:5234`.

**Wire-response precedent**: `build_badvers_response`
(`src/protocol/mod.rs:609-655`) is the template for any RCODE > 15 response.
`ResponseCode` (`:93-100`) only models RCODE 0-5 and **cannot represent
BADCOOKIE (23)**, same limitation it has for BADVERS (16). BADVERS solves
this via `build_opt_record_with_extended_rcode` (`:1276+`), splitting the
12-bit extended RCODE across the header's 4-bit nibble and the OPT record's
extended-RCODE byte (16 = nibble 0 + byte 1). BADCOOKIE (23 = nibble 7 +
byte 1) needs the identical split. `QueryValidationError::UnsupportedEdnsVersion`
(`:71-73`) + its `response_code()` bucketing to `FormErr` for metrics
(`:119-127`) + `BasicResponseFactory::protocol_error`'s special-case
(`src/resolver/mod.rs:6620`) is the exact wiring pattern a `BadCookie` case
should replicate: parse-time detection → coarse metrics bucket → dedicated
wire builder bypassing the generic one.

CD-bit is mechanically copied request→response everywhere a response is
built (`protocol/mod.rs:639,735,795,972` all do `request.header.cd()`
verbatim) but nothing branches on its value yet — confirms spec's claim
there's no CD-aware logic to gate against today.

### 1.4 `domain` crate usage today

Only two files import `domain` directly:
- `src/config/mod.rs:21-24` — zonefile parsing types.
- `src/protocol/edns_cookie.rs:26-27` — `domain::base::Serial`,
  `domain::base::opt::cookie::{ClientCookie, StandardServerCookie}`.

DNSKEY/DS/RRSIG parsing at `src/protocol/mod.rs:2562-2622` is **hand-rolled**,
not via `domain` — `parse_dnskey_record`, `parse_ds_record`,
`parse_rrsig_record` manually read fields via a `Reader`. This stays as-is;
validation consumes these already-parsed structs.

**Correction to spec**: resolved `domain` version is **0.12.2**
(Cargo.toml pins `"0.12.1"`). Feature graph:
`unstable-validator = ["zonefile", "unstable-client-transport", "unstable-crypto", "moka"]`
— **pulls in `moka` (a caching crate) and `unstable-client-transport` as new
transitive deps**, not just a crypto backend. The spec's framing ("a
feature-flag change to an existing dependency, not a new crate") is true for
direct `[dependencies]` but understates new transitive deps — flag explicitly
in the plan under RUST.md's "add dependencies conservatively."

`ring = ["dep:ring", "unstable-crypto-backend"]` / `openssl = [...]` exactly
as spec says.

`RootHintsSource` pattern to mirror: `src/config/mod.rs:864-868`
(`enum RootHintsSource { Bundled, Static(Vec<RootHintConfig>) }`) +
`bundled_root_hints()` (`:935`) using
`const BUNDLED_NAMED_ROOT: &str = include_str!("named.root")` (`:933`, file
at `src/config/named.root`). A trust-anchor equivalent: sibling
`src/config/root-anchor.txt`-style `include_str!` + `TrustAnchorSource::Bundled/Static`
enum following this exact shape.

### 1.5 Testing conventions

- Unit tests live inline in `#[cfg(test)] mod tests` at file bottom
  (`resolver/mod.rs:9038`, `resolver/cache/assemble.rs:822`,
  `protocol/mod.rs:2862`). `tests/` (top-level) is for e2e/integration
  (`e2e_config_toml.rs`, `e2e_upstream_live.rs`, `forwarding.rs`,
  `recursive_perf.rs`, `clock_injection.rs`, `cache_concurrency_bench.rs`,
  `tests/support/mod.rs` helpers).
- Known-answer-vector tests live beside the primitive: `edns_cookie.rs:373-400`
  hardcodes the RFC 9018 Appendix A.1 vector. A DNSSEC known-answer test
  (real signed-zone DNSKEY/DS/RRSIG chain) should follow this shape.
- **Tampered/malformed wire-bytes pattern exists today**:
  `edns_cookie.rs`'s `parse_cookie_option_rejects_malformed_lengths` /
  `_rejects_truncated_tlv_bytes` / `_rejects_duplicates` hand-construct byte
  vectors and assert rejection. A future "tampered RRSIG" test (flip a
  signature byte, assert `DnssecState::Bogus`) or "bad server cookie" test
  should mirror this — no fixture-file/golden-wire-capture infra exists;
  everything is inline byte-array construction.
- `assemble.rs` already has direct-construction test fixtures for
  `DnssecState`: tests set `entry.dnssec_state = DnssecState::Secure` /
  `Bogus(...)` directly (`assemble.rs:1499, 1560, 1713, 1771, 2274, 2355,
  2357, 2393`) to exercise `dnssec_servfail_check`/`dnssec_ad_bit` — this is
  state-injection, confirming assembly-side logic is fully tested; only the
  *producer* of `dnssec_state` is missing.
- e2e verification: `.claude/skills/verify/SKILL.md` — build via
  `cargo build`, launch via `RDNS_CONFIG=<abs path>`, drive with `dig`
  (miss/hit, TCP, negative cache, `+dnssec` for RRSIGs), probe malformed
  UDP/TCP payloads with raw sockets, check
  `curl http://127.0.0.1:19090/metrics`. No DNSSEC-specific probe documented
  yet — plan should add one (Bogus→SERVFAIL, BADCOOKIE→RCODE 23).

### 1.6 Metrics/status surfacing

`DnssecValidationStatus` (resolver-level, `src/resolver/mod.rs:2418-2420`,
one variant `Disabled`) and `DnssecValidationMode` (config-level,
`src/config/mod.rs:1108-1110`, also just `Disabled`) are **separate enums**
— not called out in spec. `DnssecValidationMode::cache_namespace_label()`
(`config/mod.rs:1113-1117`) feeds the cache-epoch namespace hash (per
`docs/knowledge/resolver/caching/cache-epoch.md:27`, format
`mode:recursive;generation:{n};root-hints:{version};dnssec:{label};authorities:{hash}`)
— **adding new `DnssecValidationMode`/`DnssecValidationStatus` variants
changes the cache namespace hash**, a real invalidation-boundary concern.

Metrics pattern (`src/main.rs`, `OpenTelemetryMetrics` struct `:876`):
`Gauge<u64>` field (`dnssec_validation_disabled`, `:916`), built via
`meter.u64_gauge(...)` (`:1027`), recorded as boolean-cast-to-u64 in
`record_backend_status` (`:1239-1246`), string label via
`dnssec_validation_label` (`:1294-1297`). Adding real states means extending
both enums, updating those match arms (compiler-forced, no wildcard arms
present), and likely replacing the boolean gauge with labeled counters
(current gauge only answers "is validation off," not "how many
Secure/Bogus"). No JSON `/status` endpoint separate from `/metrics`.

### 1.7 docs/knowledge/ bundle

- `docs/knowledge/resolver/caching/answer-cache.md:54-55` already documents
  `dnssec_state`: *"stays `Unvalidated` until real DNSSEC validation exists
  — orthogonal to everything else in this document."*
- `docs/knowledge/resolver/caching/serve-stale.md:113-118`: *"This resolver
  performs no local DNSSEC validation ... the `dnssec_ad_bit` AD=1 path is
  unreachable [in production]."* **Will go stale once a validator ships —
  update per AGENTS.md Knowledge Bundle trigger.**
- `docs/knowledge/resolver/caching/delegation-cache.md` documents
  `DelegationCache` fully — useful background for option (a) in §1.2, but
  zero DNSSEC content (caches endpoints only, never signature material).
- **No concept doc exists yet** for EDNS option handling (`edns_cookie.rs`)
  or DNSSEC validation — both need new concept docs once implemented.

---

## Part 2 — Web Research

### 2.1 `domain` crate's `unstable-validator` feature

**API surface** (from NLnetLabs/domain `main`,
https://docs.rs/domain/latest/domain/dnssec/validator/index.html):

- `domain::dnssec::validator::anchor::TrustAnchors` — `::empty()`,
  `::from_reader()`, `::from_u8()` (parses BIND-style trust-anchor text,
  e.g. a root DNSKEY RR).
- `domain::dnssec::validator::context::Config` — builder:
  `set_max_node_cache`, `set_max_nsec3_cache`, `set_max_isig_cache`,
  `set_max_usig_cache`, `set_max_validity`, `set_max_bogus_validity`,
  `set_bad_signatures`, `set_nsec3_iter_insecure`, `set_nsec3_iter_bogus`,
  `set_max_cname_dname`.
- `domain::dnssec::validator::context::ValidationContext<Upstream>` —
  `::new(ta, upstream)` or `::with_config(ta, upstream, conf)`. `Upstream`
  is any `domain::net::client` transport implementing `SendRequest` (issues
  its own DS/DNSKEY lookups against the same upstream already queried).
  Entry point:
  ```rust
  pub async fn validate_msg<'a, MsgOcts, USOcts>(
      &self,
      msg: &'a mut Message<MsgOcts>,
  ) -> Result<(ValidationState, Option<ExtendedError<Vec<u8>>>), Error>
  ```
- `ValidationState` = `Secure | Insecure | Bogus | Indeterminate` — maps
  directly onto RFC 4035 terminology and onto rdns' existing `DnssecState`.
- Only usage example is the module's rustdoc `#[no_run]` example (build
  transport, `req.set_dnssec_ok(true)`, `TrustAnchors::from_u8(...)`,
  `Config`, `ValidationContext::with_config`, `vc.validate_msg(&mut reply)`).
  **No example in `examples/`** — none of the shipped examples touch the
  validator.

**Version history / gotchas**:
- `unstable-validator` added in **v0.10.2** (2024-10-10).
- **v0.11.0** (2025-05-21) breaking reorg: `validate` → `dnssec::validator::base`,
  `validator` → `dnssec::validator`; renamed `DigestAlg→DigestAlgorithm`,
  `Nsec3HashAlg→Nsec3HashAlgorithm`, `SecAlg→SecurityAlgorithm`,
  `ZonemdAlg→ZonemdAlgorithm`; introduced `unstable-crypto`/`unstable-crypto-sign`.
- v0.12.0/0.12.1 (2026-04/05) — no validator-module breaking changes.
  **API stable since v0.11.0.** Current version: v0.12.2 (2026-07-16).
- Documented limitations (module doc "Bugs" section): no RFC 5011 rollover,
  no RFC 7958 HTTPS trust-anchor fetch, no negative trust anchors, no RFC
  9102 validation-chain generation, no EDNS(0) CHAIN, DS/DNSKEY size
  unbounded, DS/DNSKEY fetched sequentially not in parallel, no prefetching,
  duplicate DS/DNSKEY fetches on parallel same-name queries (e.g. A/AAAA).
- No published integration guidance for embedding in a third-party
  resolver — NLnetLabs' own consumer is their in-development `Cascade`
  resolver, not a tutorial.

**Recommendation**: wire directly against `ValidationContext::validate_msg`
using rdns' existing upstream transport as `Upstream`; pin `domain = "0.12"`
(post-reorg); budget for documented gaps (no RFC 5011, no HTTPS
trust-anchor fetch — both relevant to §2.3) as things rdns must supply
itself.

### 2.2 RFC 4035 CD-bit / chain-of-trust architecture

**Real-resolver architecture**: Unbound and BIND keep validator and
iterator as separate, cooperating modules/passes rather than validating
inline per referral hop.
- **Unbound**: `module-config "validator iterator"` pipeline; validator
  module runs once the iterator signals done, its own state machine
  (`VAL_INIT_STATE → VAL_FINDKEY_STATE → VAL_VALIDATE_STATE → VAL_FINISHED_STATE`)
  walks *up* the chain looking up DS/DNSKEY as needed
  (github.com/NLnetLabs/unbound `validator/validator.c`). Opportunistically
  grabs DS records while the iterator walks down delegations to avoid an
  extra round trip, but crypto/chain validation itself is a distinct pass
  after data is fetched, with state cached to avoid repetition.
- **PowerDNS Recursor**: validation added in 4.0; ships root anchor
  preconfigured.
- **BIND9**: recursor+validator co-located in one process for performance
  (shared cache, pointer-passing, DS grabbed while iterating down) but
  logically separate passes, not inline-per-hop.
- `domain`'s validator matches this model: `validate_msg()` operates on a
  completed message and re-issues its own DS/DNSKEY queries — it is a
  post-hoc validation layer, not wired into a referral walk.

**This directly supports choosing option (b) from §1.2** (separate pass
before `build_rrset_entry`/`build_negative_entry`) over inline-per-referral
validation — it matches how Unbound/BIND actually do it.

**RFC 4035 §3.2.2 CD-bit semantics — confirmed**: implementations still
compute/cache the validation result regardless of CD; CD only controls
whether SERVFAIL (Bogus) is enforced on *that specific response*. Backed by
§4.7's BAD-cache interaction: a cached-bad entry is returned from the BAD
cache if CD=1, but yields SERVFAIL if CD=0. **Design implication for rdns**:
validation state attaches to the cache entry unconditionally; CD only gates
response-code behavior at the point a client's answer is built (i.e. at
`dnssec_servfail_check`'s call site, not at validation time) — this matches
spec's open question #4 exactly and confirms the intended answer.

Recent RFC nuances:
- **RFC 8198** (aggressive NSEC/NSEC3 caching) superseded/updated by **RFC
  9077** (NSEC/NSEC3 TTL handling) — relevant if rdns later wants to
  synthesize negative answers from cached, already-validated NSEC/NSEC3
  ranges without re-querying. Not required for this pass but worth a
  non-goal callout.
- **RFC 9364** (BCP 237, obsoletes RFC 6840) is purely navigational — no new
  architecture/CD-bit guidance, just points at RFC 8624 for algorithm
  requirements.
- **RFC 7129** is explanatory (NSEC vs NSEC3 denial-of-existence mechanics),
  not normative.

**Common validator pitfalls** (cross-validated):
1. **Algorithm downgrade**: treating an unsigned answer from a known-signed
   zone as "Insecure" instead of "Bogus" opens a downgrade path — only
   allow Insecure when there's a validated NSEC/NSEC3 proof of DS absence
   at the parent.
2. **NSEC3 opt-out abuse**: opt-out NSEC3 asserts "may or may not be a
   signed delegation here"; incorrect handling lets it downgrade/spoof a
   signed subdomain. Concrete recent instance: ISC BIND GitLab issue #5970
   (`isdelegation()` consumes a sub-validation-failed NSEC3 from packed
   ncache → on-path forged Opt-Out NSEC3 downgrades a signed name to
   insecure).
3. **Algorithm/NSEC3 fallback**: a zone migrating RSASHA1→NSEC3 must also
   roll to alg 7 (RSASHA1-NSEC3-SHA1) so validators lacking NSEC3 support
   degrade to insecure, not bogus.
4. **NSEC3 iteration-count limits**: high iteration counts are a known DoS
   vector against validators — hence `domain`'s `Config` exposing separate
   `nsec3_iter_insecure`/`nsec3_iter_bogus` thresholds. rdns' plan should
   set sane defaults for these.

### 2.3 IANA root zone KSK staleness without RFC 5011

**2018 rollover lesson**: post-rollover analysis found **over 9,000
resolvers** still reporting only the old KSK months after the October 2018
rollover (~4% of ~12,000 measured validating resolvers as of Sept 2017).
ICANN's official review attributes the low-disruption outcome to heavy
pre-rollover outreach/measurement, not automated mechanisms — **static
bundled trust anchors are a demonstrated real failure mode**, not
hypothetical.

**Current grounding (fetched `root-anchors.xml` directly, 2026-07-17)**:
three `KeyDigest` entries — KSK-2010 (tag 19036, expired 2019-01-11,
historical), **KSK-2017 (tag 20326, currently active)**, **KSK-2024 (tag
38696, standby, `validFrom` 2024-07-18)**. Per ICANN's published schedule,
**KSK-2024 becomes the active signer 2026-10-11** (KSK-2017 revoked
~2027-01-11). **Given today's date, a static anchor bundled now must
include both tags or it goes dark on 2026-10-11** — this is directly
actionable for the plan's Trust Anchor section.

**CI staleness-check practice**: **RFC 9718** (Jan 2025, obsoletes RFC 7958)
is the current normative spec for `root-anchors.xml`/`.p7s`/`icannbundle.pem`
publication; defines `validFrom`/`validUntil` on each `KeyDigest` as the
staleness signal ("operators SHOULD NOT use a KeyDigest outside of the time
range given"). Recommended CI pattern: fetch `root-anchors.xml` +
`root-anchors.p7s` + `icannbundle.pem` on a schedule, verify the CMS
signature (OpenSSL), diff resulting `KeyDigest` set against rdns' bundled
anchors, fail the build if the bundled set is missing an in-window digest or
`validUntil` on a bundled digest has passed/is approaching. Reference tool:
`iana-org/get-trust-anchor` (dependency-free Python fetch script; doesn't
itself do CMS verification).

**Recommendation**: bundle both KSK-2017 (20326) and KSK-2024 (38696) now;
add a CI job (weekly) diffing against `root-anchors.xml` per RFC 9718, hard
failure if the bundled set drifts from the valid window. This addresses
spec's open question #5.

### 2.4 RFC 7873 BADCOOKIE server behavior

**Correction to spec's framing**: the UDP-vs-TCP distinction is in
**§5.2.3** ("Only a Client Cookie"), not §5.4 (confirmed by fetching RFC
7873 directly and enumerating every TCP-mentioning sentence by section).

- **§5.2.3** (client cookie present, no/absent server cookie): server policy
  picks one of (1) silently discard, (2) send BADCOOKIE, (3) process
  normally with NOERROR. Normative: *"If the request was received over TCP,
  the server SHOULD take the authentication provided by the use of TCP into
  account and SHOULD choose (3)."* — **over TCP, prefer normal processing;
  the BADCOOKIE-vs-discard tradeoff is chiefly a UDP concern.** Also:
  *"Servers MUST, at least occasionally, respond to such requests"* (to let
  clients bootstrap a server cookie at all).
- **§5.2.4** (client cookie + invalid/stale server cookie): *"The server
  SHALL process the request as if the invalid Server Cookie was not
  present"* — falls through to the same §5.2.3 decision tree, same TCP
  carve-out.
- **§5.4** is actually "Querying for a Server Cookie" (opcode QUERY,
  QDCOUNT=0 bootstrap/refresh mechanism) — a distinct mechanism from
  rejecting a normal query. Lower priority for this pass.
- **§5.3** (client-side): on BADCOOKIE with matching client cookie, retry
  using the new server cookie; if a retry using the fresh cookie still gets
  BADCOOKIE, retry over TCP. Repeated BADCOOKIE on the same cookie signals
  anycast secret-sharing inconsistency — worth a metric if rdns runs
  multiple instances sharing a secret.

**This corrects and sharpens spec's open question #6** — the plan should
cite §5.2.3/§5.2.4 (not §5.4) for the transport nuance, and implement the
discard/BADCOOKIE/process-normally decision exactly per §5.2.1-§5.2.5.

**Implementation survey**:
- **BIND9**: invalid cookie → BADCOOKIE + fresh correct server cookie,
  client retries. `require-server-cookie yes` makes cookies mandatory.
  9.11.26+ hardened client-side TCP fallback if a server stops offering
  cookies after previously offering them.
- **PowerDNS**: implements "option 2 of §5.2.3" (defaults to BADCOOKIE
  rather than silent accept) — flagged in community discussion as real
  interop friction for clients that support cookies but haven't yet
  round-tripped for a server cookie.
- **Knot DNS/Resolver**: cookie support since 1.1.0 (2016); Resolver later
  removed its cookie module (~v3.0.0) pending IETF DNSOP work, though
  `modules/cookies/cookiemonster.c` remains in tree.
- **RFC 9018 adoption**: BIND 9.16+ and Knot DNS 2.9.0+ adopted the
  mandatory SipHash-2-4 server-cookie recipe; PowerDNS/Unbound/NSD only had
  IETF-104-hackathon proof-of-concepts. **rdns already implements the RFC
  9018 recipe** (`build_server_cookie`), so this is a non-issue for rdns —
  just confirms reusing it for BADCOOKIE's compare step (per spec's decided
  scope) is the right call and matches the interoperable implementations.

**Security considerations**: DNS cookies are a lightweight
anti-spoofing/anti-amplification control — a spoofed-source UDP flood can't
complete the handshake, so cookie-validated queries can be exempted from
rate limiting while non-cookie traffic gets rate-limited harder (standard
pattern per BIND docs). Repeated BADCOOKIE on a supposedly-fresh cookie is a
concrete monitoring signal worth exposing as a metric if rdns ever runs
multiple anycast/load-balanced instances sharing a cookie secret (currently
out of scope per spec's non-goals, but worth a one-line forward-reference in
the plan).

**Recommendation**: implement server-side BADCOOKIE per §5.2.1-§5.2.5
exactly, don't skip the §5.2.3 TCP "SHOULD choose (3)" carve-out, keep using
the already-implemented RFC 9018 recipe. Treat §5.4's empty-question query
type as out of scope for this pass.

---

## Testing preferences (carried into TDD plan)

- Rust: `#[cfg(test)] mod tests` inline, standard library assertions, no
  mocking framework in use anywhere in the codebase (confirmed by
  Explore pass) — hand-constructed fixtures throughout.
- Known-answer vectors for crypto/hash primitives sit directly beside the
  primitive (see `edns_cookie.rs:373-400` pattern) — a DNSSEC validator
  needs an equivalent fixed-input/fixed-output test using a real (or
  well-known test) signed zone's DNSKEY/DS/RRSIG chain.
- Malformed/tampered-bytes tests are hand-built byte vectors + assert
  rejection/specific-state, not fixture files.
- e2e verification path is the `verify` skill (build, launch, `dig`,
  `curl /metrics`, raw-socket malformed-input probes) — no DNSSEC-specific
  probe exists yet; the plan's test-strategy section should add one.
