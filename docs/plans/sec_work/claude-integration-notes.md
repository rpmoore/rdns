# Integration Notes: Codex Review (iteration-1)

Source: `reviews/iteration-1-codex.md`. Decisions below, applied to
`claude-plan.md`.

## Integrated

1. **Architecture soundness (Major x2)** — Integrated. The plan's phrasing
   implied DS/DNSKEY/RRSIG material is already fully accumulated by the
   time entry-construction runs, purely from the existing iterative fetch.
   That's not accurate — `domain`'s validator does its own DS/DNSKEY chase
   against the upstream; the "separate pass" design is sound *because* of
   that, not despite skipping it. Reworded A4/A5 to state this explicitly.
   Also added an explicit adapter/spike subtask to A4 for bridging rdns's
   own `Message`/`RecursiveAuthorityTransport` types to `domain`'s
   `Message`/`SendRequest` traits, including timeout/error translation —
   this was underspecified as "confirm the transport already implements or
   can be adapted," which understated the amount of real design work
   there.

2. **Indeterminate → Unvalidated visibility gap (Major)** — Integrated.
   Kept the state mapping (`Indeterminate` → `DnssecState::Unvalidated`,
   per the decided data-model non-goal of not redesigning `DnssecState`),
   but added a requirement that the new outcome counter (A7) distinguishes
   `Indeterminate` from a query that was never validated at all (e.g.
   validation not attempted vs. validation attempted and inconclusive), so
   operators have a visible signal instead of both cases looking identical
   in metrics.

3. **BADCOOKIE "missing vs. invalid/stale" contradiction (Critical)** —
   Integrated, this was a real inconsistency introduced during plan
   synthesis, not a genuine design ambiguity. The interview (Q7) and
   research only ever settled "bad/stale server cookie" as the
   BADCOOKIE-over-UDP trigger; `claude-spec.md`'s Track B summary and the
   plan's B1 section drifted to also say "or missing," which directly
   contradicted B2's first-contact carve-out. Resolved in favor of B2's
   original carve-out (matches the interview's literal wording and RFC
   7873's "servers MUST at least occasionally respond" requirement for
   bootstrapping): **a client cookie with no server-cookie tail at all
   (first contact) is not a BADCOOKIE trigger** — process normally, issue a
   fresh cookie, same as existing pre-BADCOOKIE behavior. Only an
   invalid/stale/tampered server cookie that IS present triggers BADCOOKIE
   over UDP. Fixed the wording in both `claude-spec.md` (Track B intro) and
   `claude-plan.md` (B1, B2) to say "invalid or stale" consistently, never
   "or missing."

4. **Malformed (not merely absent) cookie option bypassing the check
   (Major)** — Integrated. Added explicit handling to B2: a cookie option
   that's present but structurally malformed (wrong length, truncated
   TLV) must not silently collapse into the same code path as "no cookie
   present" (which would bypass BADCOOKIE checking entirely) — it should
   be treated as an invalid server cookie and trigger the same
   UDP-BADCOOKIE / TCP-process-normally branching as a tampered-but
   well-formed one.

5. **IPv4-mapped IPv6 source-address normalization (Major)** — Integrated
   as a verification requirement rather than new logic: `build_server_cookie`
   is already used for existing outgoing cookie issuance, so whatever
   address normalization it already does is the source of truth — B2's
   recompute-and-compare step must reuse the identical normalization path,
   not re-derive its own. Added an explicit note to confirm this by
   construction (call the same function, don't duplicate the IP handling)
   rather than as a new design decision.

6. **EDNS-version-vs-cookie precedence (Major)** — Integrated. Added
   explicit ordering to B2: the existing EDNS-version check (which produces
   BADVERS) runs first; the cookie/BADCOOKIE check only runs on requests
   that already passed EDNS-version validation. This matches how BADVERS
   and other EDNS-admission checks are already sequenced in
   `cache_supported`/`probe_cache` and avoids a request with an
   unsupported EDNS version ever reaching cookie logic.

7. **Trust-anchor CI check as a blocking gate (Major) / warning threshold
   (Minor)** — Integrated. Reworded A3: the staleness check runs as its own
   scheduled workflow (not embedded in per-PR CI), so an IANA endpoint
   outage doesn't block unrelated PRs. A fetch/verification *failure*
   (endpoint down, signature doesn't verify) logs/alerts but does not
   independently indicate anchor staleness — it's a distinct signal from an
   actual `validUntil` breach. Set the concrete warning threshold explicitly
   at 60 days before `validUntil` (previously left as "pick a threshold
   when implementing").

8. **Validator timeout/error behavior undefined (Critical)** — Integrated.
   Added an explicit subtask to A4: validation calls must be bounded by
   rdns's existing per-query/per-authority timeout budget (not an unbounded
   wait on top of normal resolution), and a timeout or transport error
   during validation must map to `DnssecState::Bogus` with a
   diagnostic reason, not silently downgrade to `Insecure` or
   `Unvalidated` — treating "couldn't determine" the same as "provably
   unsigned" (Insecure) is exactly the algorithm-downgrade pitfall
   research flagged in a different context (§2.2 of `claude-research.md`);
   the same reasoning applies to timeouts. This is a fail-closed choice and
   is called out explicitly as intentional in the plan and in rollout
   notes, since it means transient upstream slowness can produce
   SERVFAILs.

9. **Cache TTL vs. RRSIG expiration (Major)** — Integrated. Added to A5/A6:
   an entry's effective cache TTL must be capped at the earliest RRSIG
   expiration in its validated chain, in addition to whatever TTL logic
   already governs the entry — otherwise a `Secure` entry could be served
   past the point its signature is cryptographically no longer valid.

10. **Sequential/duplicate DS-DNSKEY fetch performance (Major)** —
    Integrated as a documented, accepted limitation rather than solved in
    this pass: this is an upstream limitation of `domain`'s validator
    itself (per research's §2.1 "Bugs" summary — sequential fetching, no
    prefetch, duplicate fetches on parallel same-name queries), not
    something rdns's wiring can fix without vendoring/patching `domain`.
    Added to A4 as a known-limitation note plus a recommendation to watch
    the new latency-relevant metrics (A7) post-rollout rather than
    attempting to solve it now — consistent with the plan's existing
    non-goal boundary of not hand-rolling validator internals.

11. **Serve-stale interaction with validation state (Major)** —
    Integrated. Added an explicit rule to A6: `Bogus` entries must never be
    served via serve-stale (serving a known-tampered response past
    expiration defeats the point of validation); `Secure` and `Insecure`
    stale-serving behavior is unaffected by this work. Cross-referenced
    against `docs/knowledge/resolver/caching/serve-stale.md`, which will
    need this rule added when C1's doc update happens.

12. **Testing gaps (Major x3, several sub-items)** — Integrated. Added to
    A8: expired-signature and not-yet-valid-signature test cases (distinct
    from the existing tampered-byte Bogus test — these exercise the
    validity-window check, not signature verification itself), and a
    mixed-validation-state CNAME-chain test (chain where one link is
    Secure and another is Bogus, confirming the chain-level verdict
    correctly reflects the worst state in the chain, matching how
    `dnssec_servfail_check` already treats "any entry in the chain is
    Bogus"). Added to B3: malformed-cookie-option test (distinct from
    absent-cookie), duplicate-cookie-option test, EDNS-version-plus-cookie
    interaction test (confirms ordering from integration item 6), and an
    IPv4-mapped-IPv6 source address test confirming identical behavior to
    a plain IPv4 source.

13. **A1 "no behavior change" framing (Minor)** — Integrated. Reworded to
    acknowledge the feature-flag change expands build/supply-chain surface
    (new transitive deps `moka`/`unstable-client-transport`, confirmed
    already accepted per interview Q4) even though it has no *runtime*
    behavior change on its own — the original wording overstated how inert
    this step is.

## Not integrated (with reason)

- **On-by-default rollout (Major x2)** — Not integrated. Codex recommends
  opt-in for at least one release given no field experience with the
  validator. This directly reverses an explicit, twice-confirmed user
  decision (interview Q11, and reconfirmed when this exact tension was
  raised back to the user after the review). The user's call stands: ship
  on-by-default, rely on the expanded test suite (integration items 8, 9,
  11, 12) as the mitigation rather than a slower rollout. `claude-plan.md`'s
  C3 rollout section already flags this as a deliberate, non-default-ish
  choice operators should be aware of — left as-is, not softened into an
  opt-in recommendation.
