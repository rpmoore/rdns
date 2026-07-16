diff --git a/docs/knowledge/resolver/caching/answer-cache.md b/docs/knowledge/resolver/caching/answer-cache.md
index f19854d..a335637 100644
--- a/docs/knowledge/resolver/caching/answer-cache.md
+++ b/docs/knowledge/resolver/caching/answer-cache.md
@@ -119,11 +119,74 @@ timestamp, so a cached entry's apparent remaining TTL is understated by
 roughly one backend round trip — pre-existing, low-severity, not fixed
 by this plan.
 
-This doc will need a follow-up edit once a separate, later PR (Part E of
-`docs/plans/ttl_remaining/claude-plan.md`, the EDNS-Cookie cache
-allowlist) lands, noting that EDNS-Cookie-bearing queries become
-cache-compatible at that point. Today they bypass the cache entirely —
-see `cache_supported`, `src/resolver/mod.rs:5508-5520`.
+# EDNS Cookie interaction: per-request OPT, never cached
+
+RFC 7873 COOKIE-bearing queries (EDNS option code 10) are cache-compatible,
+provided the COOKIE option is the *only* EDNS option present:
+`cache_supported` (`src/resolver/mod.rs:5670-5684`) admits a query whose
+`edns.options` is either empty or passes
+`edns_cookie::is_solely_cookie_option` (`src/protocol/edns_cookie.rs:144`) —
+the strict predicate requiring the entire options blob to be exactly one
+well-formed COOKIE option. A query carrying a Cookie *and* any other EDNS
+option (e.g. NSID) still bypasses the cache exactly as before this change.
+All other admission conditions (extended RCODE 0, EDNS version 0, no flags
+beyond DO) are unchanged.
+
+**Cache key never depends on cookie bytes.** Two Cookie-bearing queries for
+the same `(qname, qtype, qclass)` with *different* client cookies produce an
+identical lookup/`MissKey` — pinned by
+`resolve_cache_lookup_key_ignores_client_cookie_bytes`
+(`src/resolver/mod.rs:19621`). This is what makes "one shared cached
+answer, one freshly-built OPT record per requester" (below) safe to state as
+a hard guarantee rather than an incidental detail.
+
+**The OPT pseudo-record — including any COOKIE option in it — is never
+part of what's stored in or read from `RRsetEntry`/`NegativeEntry`.** It is
+always rebuilt fresh per request, on both paths:
+
+- Cache-hit: `requester_opt_record` (`src/resolver/cache/assemble.rs:439`),
+  called from all four response builders in that file.
+- Cache-miss/recursive: `mirrored_client_opt_record_with_cookie`
+  (`src/resolver/mod.rs:1667`), threaded through
+  `rebuild_recursive_response_with_own_framing`,
+  `truncated_response_for_query`, and every OPT-attaching branch of
+  `prepare_backend_result`. The plain, cookie-unaware
+  `mirrored_client_opt_record` (`mod.rs:1642`) still backs the one call site
+  that has no single requester's client IP to compute a cookie against
+  (`synthesize_recursive_cname_response`, building the shared/coalescable
+  backend response) and `local_entry_response`'s statically-configured local
+  entries (out of scope for cookie-echoing entirely).
+
+Both paths build their COOKIE option the same way: `parse_cookie_option`
+extracts the client cookie, `build_server_cookie` computes a fresh RFC 9018
+server cookie from a process-lifetime `CookieSecret`, the requester's own
+client IP, and the injected `Clock` (never `SystemTime::now()` directly), and
+`build_cookie_option` serializes the TLV — written to the wire by
+`build_opt_record_with_options` (`src/protocol/mod.rs:1261`), which
+`build_opt_record`/`build_opt_record_with_extended_rcode`
+(`protocol/mod.rs:1248-1298`) both ultimately funnel through. Two requesters
+sharing one cached answer (or one coalesced in-flight backend fetch), each
+presenting a different client cookie, get their own distinct,
+correctly-computed COOKIE option in their own response — the *answer data*
+is shared, the OPT record never is. This is the same "request-specific
+details are applied at serve time" pattern already described above in
+"What's stored per entry" (casing/bufsize/flags) and in "Wire-TTL aging on
+read" — cookies are just another instance of it, not an exception.
+
+**Security trade-off — read this before assuming any anti-spoofing
+protection exists.** This resolver never validates an incoming *server*
+cookie's hash or timestamp window, never generates BADCOOKIE (RCODE 23), and
+never rejects a query for cookie-related reasons — every query is processed
+normally and every response gets a freshly-computed, valid server cookie,
+unconditionally. This is one of RFC 7873's own compliant behaviors (§5.2.3/
+§5.2.4 branch 3: "process the request and provide a normal response"), not a
+corner cut — but it means this implementation gains **no**
+anti-off-path-spoofing value from DNS Cookies. That protection comes from
+the incoming-cookie validation/rejection path this implementation
+deliberately does not build (no BADCOOKIE, no server-cookie verification, no
+secret rotation — see `docs/plans/edns_cookie_cache/claude-plan.md`'s
+Non-goals). If you're checking whether rdns has DNS Cookie *protection*: no
+— it has Cookie *echo/interop* only.
 
 # Concurrency model, in one sentence
 
