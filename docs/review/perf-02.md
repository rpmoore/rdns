# Performance Review 02: DNS Request Copy Reduction

## Purpose

Capture current opportunities to reduce memory copies while processing DNS requests, with emphasis on zero-copy or shared-buffer techniques in the Rust hot path.

## Highest-Impact Copy Hot Spots

### 1. Request bytes are copied into `Message` during parse

- File: `src/protocol/mod.rs`
- Location: `Message::parse`
- Current behavior: `original_bytes: dns_message.to_vec()`
- Impact: every parsed DNS request incurs a full-packet copy even when later stages only need borrowed access to the original wire bytes.

### 2. Question wire bytes are copied into a fresh `Vec<u8>`

- File: `src/protocol/mod.rs`
- Location: `question_wire`
- Current behavior: `Ok(dns_message[start..offset].to_vec())`
- Impact: the question section is copied again before being stored in `DecodedQuery` and `CacheKey`.

### 3. Upstream resolution clones the original query bytes per attempt

- File: `src/delivery/upstream.rs`
- Location: `resolve_attempt`
- Current behavior: `let mut upstream_query = request.query.message.original_bytes.clone();`
- Impact: each upstream attempt, including failover paths, clones the full request packet before only rewriting the transaction ID.

### 4. Upstream failover clones the full request object per retry

- File: `src/delivery/upstream.rs`
- Location: `resolve_with_failover`
- Current behavior: `self.resolve_attempt(upstream, request.clone(), attempt_timeout)`
- Impact: `UpstreamRequest` contains `DecodedQuery`, so retry/failover duplicates already-parsed request state and owned buffers.

### 5. Truncated-response question validation copies the response prefix

- File: `src/delivery/upstream.rs`
- Location: `validate_response_question_prefix`
- Current behavior: `let mut question_only = response_bytes[..question_end].to_vec();`
- Impact: the truncated response prefix is copied into a temporary buffer solely to zero counts and reparse the question.

## Additional Copy Areas Worth Revisiting

- `src/resolver/mod.rs`
  - `finish_upstream_result` clones `response_bytes` before cache storage.
  - `InFlightMiss::wait` clones the stored `Result<UpstreamResponse, UpstreamError>`, including response buffers.
- `src/protocol/mod.rs`
  - Unknown RDATA and several DNSSEC-related record parsers copy slices into owned `Vec<u8>` values.

These may be acceptable for now, but they are secondary after removing avoidable full-request and per-attempt copies from the forwarding path.

## Recommended Future Work

1. Introduce borrowed packet view types such as `MessageView<'a>` and `DecodedQueryView<'a>` so parsing and validation can borrow from `&[u8]` instead of eagerly copying request bytes.
2. Change question-wire handling to use a borrowed slice or byte range instead of allocating a new `Vec<u8>`.
3. Pass upstream requests by reference where possible so retries and failover do not clone parsed request state.
4. Replace the copied truncated-response validation path with direct parsing and comparison against the existing `response_bytes` buffer.
5. Where ownership must cross async or cache boundaries, prefer shared immutable storage such as `Arc<[u8]>` or `bytes::Bytes` over repeated `Vec<u8>` cloning.

## Suggested Implementation Order

1. Remove the `Message::parse` full-packet copy.
2. Remove the `question_wire` allocation.
3. Eliminate per-attempt upstream request cloning.
4. Eliminate temporary buffer allocation in truncated-response validation.
5. Revisit shared-buffer use in cache and single-flight response handling.
