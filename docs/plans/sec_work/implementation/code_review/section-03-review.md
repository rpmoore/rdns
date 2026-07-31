# section-03 code review

See subagent findings below. Triage/interview in `section-03-interview.md`.

## Review findings — section-03 DNSSEC validator core (`src/resolver/dnssec_validation.rs`)

1. (Medium-high) Required "tampered DS digest byte" test is silently missing (no `#[ignore]`/tracking comment, unlike the two legitimately-deferred tests). Structurally impossible with the current self-trust-anchor fixture (no DS anywhere in the chain). Fix: add an `#[ignore]`d test with the same tracking-comment convention, and note the gap in the section doc.

2. (Medium) `chase()` hardcodes `backend_generation: 0`. Cache namespacing is keyed by generation (`backend_cache_namespace`); once a runtime reload bumps the real generation past 0, every DS/DNSKEY chase permanently lands in the stale generation-0 bucket. Fix: thread the real `backend_generation` through `BackendUpstream`/`validate_response`.

3. (Low-medium) File-scoped `#![allow(dead_code)]` suppresses dead-code lints for the entire file, broader than intended (silently hides genuinely-unused code added later). Fix: move to per-item `#[allow(dead_code)]` on the specific unused exports.

4. (Low) Diagnostics swallowed on hard errors -- `Ok(Err(_)) => bogus_outcome("validator error")` and `chase_error` collapse all detail into generic strings. Fix: interpolate the underlying error's Display/Debug.

5. (Low) Fire-and-forget spawned chase task has no panic visibility. Fix: log on oneshot-send failure.

Confirmed non-issues: Cargo.toml dev-only scoping is correct; oneshot/spawn workaround is sound and deadline-bounded across nested chases; `flip_last_byte_of`'s single-occurrence assert is adequate; no stray debug artifacts.
