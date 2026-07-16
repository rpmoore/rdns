# Usage Guide: ttl_remaining plan

This plan closed out the wire-TTL-aging audit (`docs/plans/ttl_remaining/claude-plan.md`) in three sections. No CLI/API surface changed — this is documentation, an internal DI seam, and regression tests.

## What was built

1. **section-01** (`06b4da1`) — Knowledge-bundle docs: `docs/knowledge/resolver/caching/answer-cache.md` documents `compute_wire_ttl`'s remaining-TTL-on-read behavior, the chain-wide `expires_at` ceiling, and negative-cache dual-aging. `docs/caching.md` retired to a pointer.
2. **section-02** (`0b834cd`) — Clock dependency injection: `UdpDnsServer`/`TcpDnsServer` now take a shared `Arc<dyn Clock>` (threaded from `main.rs`) instead of calling `SystemTime::now()` directly at the two `ReceivedAt`-seeding call sites. Enables deterministic TTL-aging tests at the transport layer (`tests/clock_injection.rs`, plus UDP/TCP unit tests using `AdvanceableClock`).
3. **section-03** (`0130240`) — Two regression tests pinning down existing (unmodified) TTL edge-case behavior:
   - `compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime` (`src/resolver/cache/assemble.rs`)
   - `resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup` (`src/resolver/mod.rs`)

## Verifying the work

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test
```

To run just the new edge-case tests:

```bash
cargo test compute_wire_ttl_never_exceeds_origin_ttl_even_when_floor_extends_entry_lifetime
cargo test resolve_caps_terminal_record_ttl_to_chain_wide_ceiling_on_standalone_lookup
```

To see the clock-injection e2e test:

```bash
cargo test --test clock_injection
```

## Where to look

- Behavioral doc: `docs/knowledge/resolver/caching/answer-cache.md`
- Clock trait/seam: search `Arc<dyn Clock>` in `src/main.rs`, `src/delivery/`
- Regression tests: `src/resolver/cache/assemble.rs` and `src/resolver/mod.rs` (`#[cfg(test)] mod tests`)

## Next steps

- Branch `fix_ttl_edns_bypass` has all three section commits plus pre-existing EDNS bypass work; review full branch diff before opening/updating the PR.
- `/security-review` not required for sections 01-03 (doc/test-only, no auth/parsing/network-facing production code changed).
