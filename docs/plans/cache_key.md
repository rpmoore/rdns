# Plan: Remove UDP payload size from the cache key

## Summary

`CacheKey` includes an `effective_udp_payload_size: usize` field. This plan
removes it. The concrete motivation: right now a UDP query and a TCP query
for the identical question never land in the same cache entry, because the
TCP-sourced fix (see `ObservedSourceEndpoint::is_tcp`) gives TCP queries a
dedicated `usize::MAX` size class in `probe_cache`. Removing the field lets
UDP and TCP share cache entries for the same question. It does *not* collapse
UDP-vs-UDP fragmentation across different EDNS bufsize values — the *raw*
advertised bufsize stays in the key via `QueryFeatures.edns_udp_payload_size`
(see "Out of scope" below), so two UDP queries with different raw bufsizes
still get different keys regardless of this change. As section 1 of "Why
remove it" explains, `effective_udp_payload_size` never affected UDP-vs-UDP
collisions in the first place — it only ever duplicated a partition `features`
already enforced.

## Current state

`CacheKey` (`src/resolver/mod.rs`):

```rust
pub struct CacheKey {
    pub question: QuestionKey,
    pub question_wire: Vec<u8>,
    pub features: QueryFeatures,
    pub cache_namespace: Option<String>,
    pub effective_udp_payload_size: usize,
}
```

`effective_udp_payload_size` is computed as:

```rust
pub fn effective_udp_payload_size(&self, configured_max: usize) -> usize {
    let advertised = self.edns.as_ref()
        .map(|edns| edns.udp_payload_size as usize)
        .unwrap_or(DNS_DEFAULT_UDP_PAYLOAD_SIZE); // 512
    advertised.max(DNS_DEFAULT_UDP_PAYLOAD_SIZE).min(configured_max)
}
```

`probe_cache` currently special-cases TCP to avoid the 512-byte pre-EDNS
floor (which is meaningless over TCP, RFC 6891 §6.2.3) by keying TCP queries
on `usize::MAX` instead:

```rust
let effective_payload_size = if request.observed_source.is_tcp() {
    usize::MAX
} else {
    decoded.message.effective_udp_payload_size(self.protocol.configured_max_udp_payload_size())
};
```

This means: every distinct effective UDP size class, plus one separate class
for all of TCP, gets its own cache entry for the same question/qtype/qclass —
even though (see below) the *content* stored is identical across all of them.

## Why the field exists (documented rationale, and its history)

The original design doc, `docs/plan/02-resolver-cache.md`, lists as a cache
key component:

> Effective client UDP response size when cached serialization can differ by
> request size.

That's the stated intent: cached *serialization* was expected to potentially
differ per request size, so the key was partitioned defensively along that
axis. The same doc, in the very next section, also specifies:

> Cached responses must be serialized for the current request context.
> Re-check transaction ID, request flags that affect response semantics, and
> UDP size/truncation behavior before returning a cache hit.

That second requirement is exactly what got implemented: `ProtocolCodec::serialize_cached_response`
re-derives truncation fresh, from the *current* requester's own EDNS/transport,
every time a cache entry is served — independent of which key bucket was hit.

Checking history confirms these two ideas have coexisted since the
beginning, not that one superseded the other over time:

- `53c25da` ("Define cache key construction") introduced `CacheKey` with
  `effective_udp_payload_size` from day one.
- The very next resolver commit, `cd26178` ("Cache safe DNS response
  templates"), added the per-request truncation re-check in
  `serialize_cached_response` — its own test is named
  `resolve_truncates_oversized_cached_response_for_current_request`, i.e.
  "truncate for the current request," not "truncate because of which
  cache-key class this is."

So the size-based key partitioning and the free-standing per-request
truncation check have never been in a "before/after" relationship — they
were designed together, and the key partitioning appears to have been a
defensive hedge that was never actually required once the per-request
re-check existed.

## Why remove it

1. **It's redundant even on its own terms.** `effective_udp_payload_size` is
   a pure function of `raw_advertised_bufsize` and the fixed
   `configured_max_udp_payload_size` (constant for the process's lifetime).
   `QueryFeatures.edns_udp_payload_size` (part of `CacheKey.features`
   already) stores the *raw* advertised value. Two queries with different
   raw values already get different `features`, hence different keys,
   regardless of whether their *effective* (clamped) sizes match. Two
   queries with the same raw value always compute the same effective size.
   So `effective_udp_payload_size` never changes which queries collide —
   it duplicates a partition `features` already enforces.

2. **Nothing reads it back out.** Grepping the codebase, `effective_udp_payload_size`
   is only ever written (in `CacheKey::new`/`from_query`) and compared (via
   the derived `Hash`/`Eq`) — no eviction, accounting, or serving logic reads
   the field out of a resolved cache key. It exists purely to fragment
   identity, not to carry information anything consumes.

3. **The stored value is always the full response anyway.** `store_cache_response`
   caches `response_bytes` captured *before* the truncation check runs in
   `prepare_backend_result`. Every cache entry, regardless of key, holds the
   complete, untruncated answer. Truncation is entirely a serve-time
   decision (`serialize_cached_response`'s `allow_udp_truncation` parameter,
   `local_entry_response`, `prepare_backend_result`'s own check) computed
   fresh from the *current* request's transport and EDNS state. The key
   partitioning duplicates a decision that's already made correctly and
   independently at read time.

4. **Concrete, current cost: UDP and TCP never share a cache entry.**
   This is the motivating case. A client that queries the same name first
   over UDP, then over TCP (e.g. after a truncated response, exactly the
   scenario TCP support exists for) recomputes the answer from scratch
   instead of hitting the entry UDP already populated — despite both
   transports needing the identical underlying data, just served without a
   truncation ceiling on the TCP side. More generally, every distinct raw
   EDNS bufsize a client population presents (dig, systemd-resolved,
   Windows, unbound, etc. don't all default to the same value) creates a
   fresh, duplicate cache entry for what is, byte-for-byte, the same stored
   template.

## Proposed change

1. Remove `effective_udp_payload_size` from `CacheKey` (`src/resolver/mod.rs`).
2. Drop the `configured_max_udp_payload_size` parameter from
   `CacheKey::new` and `CacheKey::from_query`.
3. Simplify `probe_cache`: remove the `is_tcp()`/`usize::MAX` branch entirely
   and go back to a single, unconditional `CacheKey::new(...)` call with no
   size argument. (The `is_tcp()` checks in `local_entry_response`,
   `prepare_backend_result`, and the `allow_udp_truncation` argument to
   `serialize_cached_response` are unaffected and stay exactly as they are —
   those are the actual truncation-correctness fix and remain necessary.)
4. Update every call site that constructs a `CacheKey` (production:
   `probe_cache` only; the rest are tests — `grep -n "CacheKey::new(\|CacheKey::from_query("`
   currently finds ~20 sites, nearly all in `#[cfg(test)]`).
5. Update/remove the tests that assert the old fragmentation:
   - `cache_key_from_query_includes_supported_semantics` — drop the
     `key.effective_udp_payload_size` assertion.
   - `cache_key_separates_question_type_class_policy_and_udp_size` — remove
     the `a_in_larger_udp` case (that's precisely the collapsed behavior);
     keep the qtype/qclass/policy-variant assertions, since those are
     unrelated and still correct.
   - Any other `CacheKey::from_query(..., <size>)` call in tests needs the
     trailing size argument dropped.
6. Add a regression test proving the motivating case: a UDP query and a
   TCP query for the same question, same EDNS bufsize, produce a cache hit
   on the second request regardless of which transport asked first (extend
   or replace `resolve_does_not_truncate_tcp_sourced_cache_hit`, which
   currently proves TCP-to-TCP hits work — extend it to prove a UDP miss
   followed by a TCP *hit*, and vice versa).

## Out of scope for this change

`QueryFeatures.edns_udp_payload_size` (the *raw* advertised bufsize, as
opposed to the clamped `effective_udp_payload_size` this plan removes) stays
in `CacheKey` for now. Reasoning:

- For the common case (e.g. `dig`), the raw advertised bufsize is the same
  whether the query arrives over UDP or TCP (dig defaults to advertising
  the same EDNS bufsize regardless of transport) — so removing only
  `effective_udp_payload_size` is already sufficient to let UDP and TCP
  share entries for typical clients. Verified by hand: `dig +tcp` still
  reports `EDNS: version: 0, flags:; udp: 1232` in its request, identical to
  its UDP default.
- `features` is a shared struct also presumably read for other purposes
  (audit/query-event surfacing, `cache_supported()` gating). Removing a
  field from it is a larger, separate surgery with more call sites to
  audit than the narrowly-scoped, provably-redundant `effective_udp_payload_size`
  field. If raw-bufsize fragmentation turns out to matter in practice after
  this change ships, it should be its own follow-up plan.

## Risks / things to verify before landing

- Confirm no other code depends on cache entries being segmented by size
  class for a reason not covered above (re-read `docs/plan/02-resolver-cache.md`
  in full for any other cache-key rationale tied to payload size before
  removing it).
- Re-run the full test suite plus the `recursive_perf` ignored benchmarks
  (real network) after the change to confirm cache hit-rate assumptions in
  those tests don't silently change in an unexpected direction.
- Double check `CacheKey`'s `Hash`/`Eq` derive still compiles cleanly with
  one fewer field, and that no serialization (e.g. metrics/cache-namespace
  logging) formats `CacheKey` in a way that assumed this field's presence.

## Expected outcome

- UDP and TCP queries for the same question converge on one cache entry
  (the concrete goal).
- Fewer, better-utilized cache entries across all EDNS bufsize variations
  seen from different client stub resolvers.
- No behavior change to what gets served to any individual client: the
  serve-time truncation logic (`allow_udp_truncation`, `is_tcp()` checks)
  already decides correctness per-request and is untouched by this plan.
