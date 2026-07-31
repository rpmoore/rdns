# section-03 code review interview

All 5 findings are auto-fixed (correctness/hygiene, no real tradeoffs to interview on):

1. Auto-fix: add `#[ignore]`d `tampered_ds_digest_byte_is_bogus` test with tracking comment (fixture has no DS chain currently -- same deferral convention as the other two `#[ignore]`d tests), and note the gap explicitly in the section doc update.
2. Auto-fix: thread real `backend_generation: u64` through `validate_response` -> `BackendUpstream` -> `chase`, instead of hardcoded `0`. Section-04 (the caller) will supply the real value.
3. Auto-fix: replace file-scoped `#![allow(dead_code)]` with per-item `#[allow(dead_code)]` on `validator_config`, `DnssecValidationOutcome`, and `validate_response`.
4. Auto-fix: interpolate underlying error detail into the `Bogus` reason strings (`validate_msg` error, `ResolutionBackendError` variant) instead of generic constants.
5. Auto-fix: log a `tracing::warn!` when the oneshot send fails (receiver dropped) so a panicking chase task isn't silently invisible.
