diff --git a/src/main.rs b/src/main.rs
index cb677c1..be7a2f2 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -134,6 +134,21 @@ async fn main() -> io::Result<()> {
     let cookie_secret = Arc::new(CookieSecret::generate());
     let (refresh_tx, refresh_rx) =
         tokio::sync::mpsc::channel(refresh_channel_capacity(&config.refresh));
+    // `ResolveQuery::with_trust_anchors` is deliberately NOT called here yet.
+    // `DnssecValidationMode` (`config/mod.rs`) currently only has a
+    // `Disabled` variant -- there is no config-level way to opt into
+    // validation yet, so wiring real trust anchors in unconditionally would
+    // make every `ResolutionMode::Recursive` fetch validate regardless of
+    // that mode, with no kill switch. Confirmed against a live recursive
+    // instance: ordinary (unsigned) domains started coming back SERVFAIL,
+    // since a domain with no DS/DNSKEY chain validates as `Bogus` in some
+    // paths, not `Insecure`, and `dnssec_servfail_check` then forces
+    // SERVFAIL for any CD=0 requester -- a severe regression for the
+    // current (validation-off) default. Section-05 (`DnssecValidationMode::
+    // Enabled`, defaulted on deliberately, with its own rollout/metrics
+    // story) is where this gets wired live; until then the mechanism stays
+    // built and tested (`ResolveQuery::validate_for_store`) but unreachable
+    // in production, matching every existing `ResolveQuery` default.
     let mut resolver_builder = ResolveQuery::with_cache_policy_and_backend_snapshot(
         Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
         Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
@@ -153,7 +168,8 @@ async fn main() -> io::Result<()> {
     .with_single_flight_shard_count(cache.shard_count())
     .with_chaos_config(config.chaos.clone())
     .with_cookie_secret(cookie_secret)
-    .with_refresh_config(config.refresh);
+    .with_refresh_config(config.refresh)
+    .with_dnssec_validation_deadline(config.per_query_deadline);
     if config.refresh.enabled {
         resolver_builder = resolver_builder.with_refresh_sender(refresh_tx);
     }
diff --git a/src/resolver/cache/assemble.rs b/src/resolver/cache/assemble.rs
index 0e07be0..f3bc93c 100644
--- a/src/resolver/cache/assemble.rs
+++ b/src/resolver/cache/assemble.rs
@@ -1601,6 +1601,58 @@ mod tests {
         assert_eq!(served_parsed.answers.len(), 1);
     }
 
+    // section-04 (A8): coverage for `dnssec_servfail_check`'s existing
+    // `.any()` aggregation with a genuine multi-hop chain -- prior coverage
+    // (`assemble_response_servfails_on_bogus_when_checking_enabled` above)
+    // only ever used a single-entry chain. Proves the chain-level verdict
+    // reflects the worst state in the chain (one Secure hop, one Bogus hop
+    // -> SERVFAIL), not just that a lone Bogus entry triggers it.
+    #[test]
+    fn assemble_response_servfails_on_mixed_state_cname_chain_with_any_bogus_hop() {
+        let now = SystemTime::now();
+        let mut secure_hop = rrset_entry(
+            vec![StoredRecord {
+                rtype: CNAME_RECORD_TYPE,
+                rclass: IN_QCLASS,
+                ttl_at_store: 300,
+                rdata: RecordData::CNAME("target.example.com".to_string()),
+            }],
+            Duration::from_secs(300),
+            now,
+        );
+        secure_hop.dnssec_state = DnssecState::Secure;
+        let mut bogus_hop = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
+        bogus_hop.dnssec_state = DnssecState::Bogus("signature verification failed".to_string());
+        let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
+            chain: vec![
+                ("alias.example.com".to_string(), secure_hop.into()),
+                ("target.example.com".to_string(), bogus_hop.into()),
+            ],
+        };
+        let wire = question_wire("alias.example.com", A_QTYPE, IN_QCLASS);
+
+        let checking_enabled = features(false);
+        let response = assemble_response(
+            1,
+            &wire,
+            &checking_enabled,
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
+        let parsed = Message::parse(&response).unwrap();
+        assert_eq!(
+            parsed.header.r_code(),
+            ResponseCode::ServFail as u8,
+            "a Bogus hop anywhere in the chain must force SERVFAIL, even alongside a Secure hop"
+        );
+        assert_eq!(parsed.answers.len(), 0);
+    }
+
     fn soa_record(ttl: u32) -> StoredRecord {
         StoredRecord {
             rtype: 6, // SOA
diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index ed58c78..637037d 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -31,7 +31,7 @@ use std::sync::{Arc, Mutex};
 use std::time::{Duration, SystemTime};
 
 use super::entry::{
-    DomainNegativeEntries, DomainRecordSets, NegativeEntry, NegativeKey, RRsetEntry,
+    DnssecState, DomainNegativeEntries, DomainRecordSets, NegativeEntry, NegativeKey, RRsetEntry,
 };
 use super::lru::ShardLru;
 use crate::config::{LeakRate, RefreshConfig};
@@ -538,6 +538,14 @@ fn stale_servability(
     if entry.cache_epoch != current_epoch {
         return StaleServability::Evict;
     }
+    // A `Bogus` entry must never be served via serve-stale, regardless of
+    // window or TTL state -- serving a known-tampered response past its
+    // expiration defeats the point of validating it in the first place.
+    // Checked early, ahead of the window/zero-TTL checks below, since no
+    // other condition can make a `Bogus` entry servable.
+    if matches!(entry.dnssec_state, DnssecState::Bogus(_)) {
+        return StaleServability::Evict;
+    }
     // The TTL-0 exclusion checks each stored record's own origin TTL
     // (`ttl_at_store`), not `entry.minimum_ttl`: with a configured
     // `min_positive_ttl` floor, `minimum_ttl` is the policy-bounded cache
@@ -1984,6 +1992,66 @@ mod tests {
         );
     }
 
+    #[test]
+    fn lookup_hop_evicts_expired_bogus_entry_instead_of_serving_stale() {
+        // section-04 (A6): a `Bogus` entry must never be served via
+        // serve-stale, even within the window that would otherwise make it
+        // servable -- serving a known-tampered response past its expiration
+        // defeats the point of validating it.
+        let shard = stale_shard();
+        let domain = "bogus-stale.example.com";
+        let now = SystemTime::now();
+        let mut entry = expired_rrset_entry(now);
+        entry.dnssec_state = DnssecState::Bogus("signature verification failed".to_string());
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);
+
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
+
+        assert!(
+            matches!(result, HopResult::Miss),
+            "expected a Bogus expired entry to be evicted rather than stale-served, got {result:?}"
+        );
+        assert!(
+            !shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)),
+            "a Bogus entry excluded from serve-stale must not remain cached"
+        );
+    }
+
+    #[test]
+    fn lookup_hop_serves_stale_secure_entry_unaffected_by_bogus_exclusion() {
+        // No-regression check: `Secure`/`Insecure` entries keep today's
+        // serve-stale behavior unchanged by the new Bogus exclusion above.
+        let shard = stale_shard();
+        let domain = "secure-stale.example.com";
+        let now = SystemTime::now();
+        let mut entry = expired_rrset_entry(now);
+        entry.dnssec_state = DnssecState::Secure;
+        shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);
+
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
+
+        assert!(
+            matches!(result, HopResult::Answer(_, true)),
+            "expected a Secure expired entry to still be stale-served, got {result:?}"
+        );
+    }
+
     #[test]
     fn lookup_hop_evicts_expired_positive_beyond_stale_window() {
         let shard = stale_shard();
diff --git a/src/resolver/dnssec_validation.rs b/src/resolver/dnssec_validation.rs
index 6e764dc..defae95 100644
--- a/src/resolver/dnssec_validation.rs
+++ b/src/resolver/dnssec_validation.rs
@@ -14,9 +14,10 @@
 
 //! Core DNSSEC validation: runs a fully-synthesized recursive response
 //! through `domain`'s validator and maps the verdict onto this codebase's
-//! `DnssecState`. Does not wire into cache-entry construction, CD-bit
-//! gating, or metrics -- see `docs/plans/sec_work/sections/`
-//! section-04/05/06 for those.
+//! `DnssecState`. Wired into cache-entry construction by
+//! `ResolveQuery::validate_for_store` (`resolver/mod.rs`, section-04); CD-bit
+//! gating already existed independently (`resolver/cache/assemble.rs`) and
+//! metrics are section-05 -- see `docs/plans/sec_work/sections/` for both.
 //!
 //! The validator's own DS/DNSKEY chase queries are bridged onto
 //! `ResolutionBackend::resolve` (the same root-to-authority recursive
@@ -59,10 +60,6 @@ const MAX_BOGUS_VALIDITY: Duration = Duration::from_secs(30);
 
 /// Builds the `domain` validator `Config` with rdns's explicit policy
 /// values rather than the crate's raw defaults.
-// Not called from cache-entry construction yet -- section-04 wires
-// `validate_response` into `build_rrset_entry`/`build_negative_entry`.
-// Remove this allow once that lands.
-#[allow(dead_code)]
 pub(crate) fn validator_config() -> ValidatorConfig {
     let mut config = ValidatorConfig::new();
     config.set_nsec3_iter_insecure(NSEC3_ITER_INSECURE);
@@ -77,7 +74,6 @@ pub(crate) fn validator_config() -> ValidatorConfig {
 /// so callers that need to distinguish "ran, Indeterminate" from "never
 /// ran" (section-05's metrics) still can -- `DnssecState::Unvalidated`
 /// alone can't tell those apart.
-#[allow(dead_code)] // not constructed outside this module yet -- section-04 wires it in
 #[derive(Debug, Clone, PartialEq)]
 pub(crate) struct DnssecValidationOutcome {
     pub(crate) state: DnssecState,
@@ -119,10 +115,6 @@ fn bogus_outcome(reason: impl Into<String>) -> DnssecValidationOutcome {
 /// `ResolutionRequest` so they land in the same cache-namespace generation
 /// as the request being validated, rather than a fixed/stale one (see
 /// `backend_cache_namespace`).
-// Not called from cache-entry construction yet -- section-04 wires
-// `validate_response` into `build_rrset_entry`/`build_negative_entry`.
-// Remove this allow once that lands.
-#[allow(dead_code)]
 pub(crate) async fn validate_response(
     response: &Message,
     trust_anchors: TrustAnchors,
@@ -277,7 +269,7 @@ fn chase_error(error: ResolutionBackendError) -> ClientError {
 }
 
 #[cfg(test)]
-mod tests {
+pub(crate) mod tests {
     use super::*;
 
     #[test]
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index d1e47f9..3bc1318 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -23,6 +23,7 @@ use std::sync::{
 use std::time::{Duration, SystemTime};
 
 use bytes::Bytes;
+use domain::dnssec::validator::anchor::TrustAnchors;
 use serde::Serialize;
 use tokio::sync::mpsc;
 use tokio::task::JoinSet;
@@ -53,8 +54,8 @@ use cache::{
 // `tests/cache_concurrency_bench.rs` (section-08) — can drive
 // `DomainDnsCache::store_response` with real data, not just the read path.
 pub use cache::{
-    DecomposedResponse, DomainDnsCache, NegativeEntry, NegativeKey, RRsetEntry, ShardedDnsCache,
-    StoredRecord,
+    DecomposedResponse, DnssecState, DomainDnsCache, NegativeEntry, NegativeKey, RRsetEntry,
+    ShardedDnsCache, StoredRecord,
 };
 
 mod dnssec_validation;
@@ -77,6 +78,10 @@ const AAAA_RECORD_TYPE: u16 = 28;
 /// (`config/mod.rs`). Callers constructing from real config override this
 /// via `ResolveQuery::with_max_chain_depth`.
 const DEFAULT_MAX_CHAIN_DEPTH: u8 = 8;
+/// Default bound on `ResolveQuery::validate_for_store`'s DS/DNSKEY chase.
+/// Callers constructing from real config override this via
+/// `ResolveQuery::with_dnssec_validation_deadline`.
+const DEFAULT_DNSSEC_VALIDATION_DEADLINE: Duration = Duration::from_secs(5);
 /// Default shard count for the `ShardedSingleFlight` a `ResolveQuery`
 /// constructs itself. Matches `CacheConfig::resolved_shard_count()`'s own
 /// fallback (section-01) so a `ResolveQuery` built without an explicit
@@ -846,6 +851,7 @@ fn name_is_at_or_below(name: &str, zone: &str) -> bool {
 /// really is authoritative for the zone) may pass the response's real AA
 /// bit through. See `prepare_backend_result`'s `store_authoritative`
 /// computation, which mirrors `store_dnssec_ok`'s existing per-mode gate.
+#[allow(clippy::too_many_arguments)]
 fn decompose_response_for_store(
     response: &Message,
     question: &QuestionKey,
@@ -854,6 +860,7 @@ fn decompose_response_for_store(
     stored_at: SystemTime,
     dnssec_ok: bool,
     store_authoritative: bool,
+    dnssec_state: DnssecState,
 ) -> DecomposedResponse {
     let mut positive = Vec::new();
     let mut current_name = question.qname.clone();
@@ -889,6 +896,7 @@ fn decompose_response_for_store(
                     stored_at,
                     dnssec_ok,
                     store_authoritative,
+                    dnssec_state.clone(),
                 );
                 positive.push((current_name, question.qtype, question.qclass, entry));
                 return DecomposedResponse {
@@ -923,6 +931,7 @@ fn decompose_response_for_store(
             stored_at,
             dnssec_ok,
             store_authoritative,
+            dnssec_state.clone(),
         );
         positive.push((current_name, CNAME_RECORD_TYPE, question.qclass, entry));
         current_name = target;
@@ -943,6 +952,7 @@ fn decompose_response_for_store(
             stored_at,
             dnssec_ok,
             store_authoritative,
+            dnssec_state.clone(),
         );
         (current_name.clone(), key, entry)
     });
@@ -1040,6 +1050,7 @@ fn negative_proof_records(authorities: &[Record], qclass: u16) -> Vec<(String, S
 /// `store_authoritative` is stamped verbatim onto the produced entry's
 /// `authoritative` field — see `decompose_response_for_store`'s doc
 /// comment for why this must not simply be `response.header.aa()`.
+#[allow(clippy::too_many_arguments)]
 fn build_rrset_entry(
     response: &Message,
     records: &[&Record],
@@ -1048,17 +1059,20 @@ fn build_rrset_entry(
     stored_at: SystemTime,
     dnssec_ok: bool,
     store_authoritative: bool,
+    dnssec_state: DnssecState,
 ) -> RRsetEntry {
     let rtype = records.first().map_or(0, |record| record.rtype);
     let rclass = records.first().map_or(0, |record| record.rclass);
+    let rrsigs = matching_rrsigs(&response.answers, owner, rtype, rclass);
+    let expires_at = cap_expires_at_to_rrsig_expiration(stored_at + ttl, rrsigs.iter());
     RRsetEntry {
         records: records.iter().copied().map(to_stored_record).collect(),
-        rrsigs: matching_rrsigs(&response.answers, owner, rtype, rclass),
+        rrsigs,
         response_code: ResponseCode::NoError,
         minimum_ttl: ttl,
         stored_at,
-        expires_at: stored_at + ttl,
-        dnssec_state: Default::default(),
+        expires_at,
+        dnssec_state,
         // Overwritten by `ShardedDnsCache::store_response` at store time —
         // see that method's doc comment for why the epoch isn't set here.
         cache_epoch: 0,
@@ -1067,6 +1081,34 @@ fn build_rrset_entry(
     }
 }
 
+/// Caps `expires_at` at the earliest RRSIG `signature_expiration` among
+/// `rrsigs`, when that's tighter than `expires_at` -- a `Secure` entry must
+/// never be served from cache past its signature's cryptographic validity
+/// window, which today's TTL machinery (`ttl_for_response`/
+/// `min_positive_ttl` floors) knows nothing about. Applies whenever RRSIGs
+/// are present, independent of the entry's `DnssecState` -- an
+/// `Insecure`/`Bogus` entry may still carry RRSIGs worth capping against.
+/// A no-op when `rrsigs` is empty or every RRSIG expires later than
+/// `expires_at` already would.
+fn cap_expires_at_to_rrsig_expiration<'a>(
+    expires_at: SystemTime,
+    rrsigs: impl Iterator<Item = &'a StoredRecord>,
+) -> SystemTime {
+    let earliest_rrsig_expiration = rrsigs
+        .filter_map(|record| match &record.rdata {
+            RecordData::RRSIG {
+                signature_expiration,
+                ..
+            } => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(*signature_expiration as u64)),
+            _ => None,
+        })
+        .min();
+    match earliest_rrsig_expiration {
+        Some(rrsig_expiration) if rrsig_expiration < expires_at => rrsig_expiration,
+        _ => expires_at,
+    }
+}
+
 /// Builds the terminal `NegativeEntry` for a decomposed store. `metadata`
 /// was already computed by `negative_ttl` (via `ttl_for_response`), which
 /// only succeeds after finding a covering SOA record satisfying exactly
@@ -1088,6 +1130,7 @@ fn build_negative_entry(
     stored_at: SystemTime,
     dnssec_ok: bool,
     store_authoritative: bool,
+    dnssec_state: DnssecState,
 ) -> NegativeEntry {
     let soa_record = response
         .authorities
@@ -1108,6 +1151,12 @@ fn build_negative_entry(
     .into_iter()
     .next();
     let proof_records = negative_proof_records(&response.authorities, metadata.qclass);
+    let expires_at = cap_expires_at_to_rrsig_expiration(
+        stored_at + ttl,
+        soa_rrsig
+            .iter()
+            .chain(proof_records.iter().map(|(_, record)| record)),
+    );
     NegativeEntry {
         kind: metadata.kind,
         soa_owner: metadata.soa_owner.clone(),
@@ -1115,10 +1164,10 @@ fn build_negative_entry(
         soa_rrsig,
         proof_records,
         stored_at,
-        expires_at: stored_at + ttl,
+        expires_at,
         cache_epoch: 0,
         dnssec_complete: dnssec_ok,
-        dnssec_state: Default::default(),
+        dnssec_state,
         authoritative: store_authoritative,
     }
 }
@@ -4007,6 +4056,15 @@ async fn process_refresh_job(resolver: Arc<ResolveQuery>, job: RefreshJob) {
                 ResolutionMode::Recursive => false,
                 ResolutionMode::Forward => response_message.header.aa(),
             };
+            // Same Recursive-only validation gate as `prepare_backend_result`
+            // -- a refresh-stored entry must carry a real `DnssecState`, not
+            // silently regress to `Unvalidated`, since it's otherwise
+            // structurally indistinguishable from a normal client-miss store
+            // (see the comment on `store_authoritative` above).
+            let dnssec_state = match backend_snapshot.mode {
+                ResolutionMode::Recursive => resolver.validate_for_store(&response_message).await,
+                ResolutionMode::Forward => DnssecState::Unvalidated,
+            };
             let synthetic_request =
                 ResolveRequest::new(Ipv4Addr::UNSPECIFIED.into(), now, Vec::new());
             resolver
@@ -4017,6 +4075,7 @@ async fn process_refresh_job(resolver: Arc<ResolveQuery>, job: RefreshJob) {
                     &synthetic_request,
                     true,
                     store_authoritative,
+                    dnssec_state,
                 )
                 .await;
             resolver.metrics.increment(ResolverMetric::RefreshSucceeded);
@@ -4092,6 +4151,30 @@ pub struct ResolveQuery {
     // blocking. `main.rs` overrides this via `with_refresh_sender` once the
     // real worker pool's channel exists (section-05).
     refresh_sender: tokio::sync::mpsc::Sender<RefreshJob>,
+    // Raw zonefile-format DS/DNSKEY lines, matching
+    // `RecursiveResolutionConfig::load_trust_anchors`'s own return shape --
+    // stored as text rather than a parsed `TrustAnchors`, since `domain`'s
+    // `TrustAnchors` doesn't implement `Clone` (it's moved into a fresh
+    // `ValidationContext` per call, see `ValidationContext::with_config`),
+    // so a single parsed instance couldn't be reused across the many
+    // `validate_for_store` calls a long-lived resolver makes. Re-parsing
+    // via `TrustAnchors::from_u8` per call is cheap relative to the DS/DNSKEY
+    // chase that follows it. `None` by default -- every constructor leaves
+    // DNSSEC validation unreachable until `main.rs` calls `with_trust_anchors`
+    // with the real config-loaded set. `validate_for_store` treats `None`
+    // the same as "validation not available", storing
+    // `DnssecState::Unvalidated` -- this lets existing
+    // `ResolutionMode::Recursive` tests that don't care about DNSSEC keep
+    // passing unmodified, same as before this section. Whether validation
+    // is *policy-enabled* (`DnssecValidationMode`) is section-05's concern;
+    // this section only wires the mechanism.
+    trust_anchors: Option<Vec<String>>,
+    // Bounds the DS/DNSKEY chase `validate_for_store` performs before
+    // storing an entry -- same reasoning as `max_chain_depth`/`chaos` for
+    // why this is a post-construction override (`with_dnssec_validation_deadline`)
+    // rather than a constructor parameter. `main.rs` overrides this with a
+    // real per-query deadline once available.
+    dnssec_validation_deadline: Duration,
 }
 
 impl ResolveQuery {
@@ -4227,6 +4310,8 @@ impl ResolveQuery {
             cookie_secret: Arc::new(CookieSecret::generate()),
             refresh_config: crate::config::RefreshConfig::default(),
             refresh_sender,
+            trust_anchors: None,
+            dnssec_validation_deadline: DEFAULT_DNSSEC_VALIDATION_DEADLINE,
         }
     }
 
@@ -4364,6 +4449,29 @@ impl ResolveQuery {
         self
     }
 
+    /// Overrides the default `None` trust-anchor set (which leaves DNSSEC
+    /// validation unreachable -- `validate_for_store` treats no configured
+    /// anchors as "not available" and stores `DnssecState::Unvalidated`).
+    /// `main.rs` calls this with the real config-loaded anchors
+    /// (`RecursiveResolutionConfig::load_trust_anchors`) once available --
+    /// see `ResolveQuery.trust_anchors`'s doc comment for why this takes raw
+    /// zonefile lines rather than a parsed `TrustAnchors`, and why this is a
+    /// post-construction override rather than a parameter threaded through
+    /// every `with_cache*` constructor.
+    pub fn with_trust_anchors(mut self, trust_anchors: Vec<String>) -> Self {
+        self.trust_anchors = Some(trust_anchors);
+        self
+    }
+
+    /// Overrides the default DS/DNSKEY chase deadline
+    /// (`DEFAULT_DNSSEC_VALIDATION_DEADLINE`) set by every constructor.
+    /// `main.rs` calls this with the real per-query deadline once available
+    /// -- see `ResolveQuery.dnssec_validation_deadline`'s doc comment.
+    pub fn with_dnssec_validation_deadline(mut self, deadline: Duration) -> Self {
+        self.dnssec_validation_deadline = deadline;
+        self
+    }
+
     /// Overrides the default process-lifetime `CookieSecret` set by every
     /// constructor. `main.rs` calls this with the one real secret generated
     /// alongside `SystemClock` -- see `ResolveQuery.cookie_secret`'s doc
@@ -4464,6 +4572,8 @@ impl ResolveQuery {
             cookie_secret: Arc::new(CookieSecret::generate()),
             refresh_config: crate::config::RefreshConfig::default(),
             refresh_sender,
+            trust_anchors: None,
+            dnssec_validation_deadline: DEFAULT_DNSSEC_VALIDATION_DEADLINE,
         }
     }
 
@@ -5682,6 +5792,21 @@ impl ResolveQuery {
                     ResolutionMode::Recursive => false,
                     ResolutionMode::Forward => response_message.header.aa(),
                 };
+                // Validation always runs (when reachable at all -- see
+                // `validate_for_store`) and its result is always stored,
+                // independent of *this* request's own CD bit: the entry is
+                // shared across every future requester of this name/type, so
+                // a CD=1 fetcher must not cause a later CD=0 requester to be
+                // served an entry that was never actually validated. CD-bit
+                // gating happens only at response-assembly time
+                // (`dnssec_servfail_check`/`negative_dnssec_servfail_check`),
+                // never here. Forward mode never validates at all -- keeps
+                // trusting the upstream's AD bit verbatim, unchanged by this
+                // whole feature (see `validate_for_store`'s doc comment).
+                let dnssec_state = match backend_mode {
+                    ResolutionMode::Recursive => self.validate_for_store(&response_message).await,
+                    ResolutionMode::Forward => DnssecState::Unvalidated,
+                };
                 self.store_cache_response(
                     cache_epoch,
                     &response_message,
@@ -5689,6 +5814,7 @@ impl ResolveQuery {
                     request,
                     store_dnssec_ok,
                     store_authoritative,
+                    dnssec_state,
                 )
                 .await;
             } else {
@@ -6078,6 +6204,46 @@ impl ResolveQuery {
         (decision, response_bytes)
     }
 
+    /// Runs `response` through the DNSSEC validator (`dnssec_validation::
+    /// validate_response`) using this resolver's configured trust anchors,
+    /// or returns `DnssecState::Unvalidated` immediately if none are
+    /// configured (`self.trust_anchors` is `None` -- every constructor
+    /// defaults to this; `main.rs` sets real anchors via
+    /// `with_trust_anchors`). Only ever called for `ResolutionMode::Recursive`
+    /// (see `prepare_backend_result`'s call site) -- `ResolutionMode::Forward`
+    /// must never reach here, since it keeps trusting the upstream's AD bit
+    /// verbatim per the scope decision.
+    ///
+    /// Uses `self.backend.current()`'s own backend/generation for the
+    /// validator's own DS/DNSKEY chase queries, so they land in the same
+    /// cache namespace as the response being validated, and bounds them by
+    /// `self.dnssec_validation_deadline` -- a fresh deadline computed from
+    /// "now", not tied to the original request's own remaining budget,
+    /// since store-time validation runs after the triggering response has
+    /// already been decoded and is no longer on that request's critical
+    /// path for reply latency.
+    async fn validate_for_store(&self, response: &Message) -> DnssecState {
+        let Some(trust_anchor_lines) = self.trust_anchors.as_ref() else {
+            return DnssecState::Unvalidated;
+        };
+        let Ok(trust_anchors) = TrustAnchors::from_u8(trust_anchor_lines.join("\n").as_bytes())
+        else {
+            return DnssecState::Unvalidated;
+        };
+        let snapshot = self.backend.current();
+        let deadline = Instant::now() + self.dnssec_validation_deadline;
+        let outcome = validate_response(
+            response,
+            trust_anchors,
+            Arc::clone(&snapshot.backend),
+            snapshot.generation,
+            deadline,
+        )
+        .await;
+        outcome.state
+    }
+
+    #[allow(clippy::too_many_arguments)]
     async fn store_cache_response(
         &self,
         epoch: u64,
@@ -6086,6 +6252,7 @@ impl ResolveQuery {
         request: &ResolveRequest,
         dnssec_ok: bool,
         store_authoritative: bool,
+        dnssec_state: DnssecState,
     ) {
         if let Some(decomposed) = self.cache_store_for_response(
             response,
@@ -6093,6 +6260,7 @@ impl ResolveQuery {
             request.received_at.0,
             dnssec_ok,
             store_authoritative,
+            dnssec_state,
         ) {
             if decomposed.negative.is_some() {
                 self.metrics.increment(ResolverMetric::CacheNegativeStore);
@@ -6119,6 +6287,7 @@ impl ResolveQuery {
         stored_at: SystemTime,
         dnssec_ok: bool,
         store_authoritative: bool,
+        dnssec_state: DnssecState,
     ) -> Option<DecomposedResponse> {
         if !response.header.qr()
             || response.questions.len() != 1
@@ -6135,6 +6304,7 @@ impl ResolveQuery {
             stored_at,
             dnssec_ok,
             store_authoritative,
+            dnssec_state,
         ))
     }
 
@@ -11518,6 +11688,275 @@ mod tests {
         )
     }
 
+    /// Test-only `ResolutionBackend` keyed by `(qname, qtype)`, answering a
+    /// canned wire response -- mirrors `dnssec_validation::tests`' own
+    /// `ScriptedValidatorBackend` (private to that module, so not directly
+    /// reusable here). Tracks a call count so a spy test can prove a code
+    /// path never reaches the backend at all (e.g. Forward mode never
+    /// running the DS/DNSKEY chase).
+    struct ScriptedNameKeyedBackend {
+        responses: Mutex<Vec<(String, u16, Vec<u8>)>>,
+        call_count: AtomicU64,
+    }
+
+    impl ScriptedNameKeyedBackend {
+        fn new(responses: Vec<(String, u16, Vec<u8>)>) -> Self {
+            Self {
+                responses: Mutex::new(responses),
+                call_count: AtomicU64::new(0),
+            }
+        }
+
+        fn calls(&self) -> u64 {
+            self.call_count.load(Ordering::SeqCst)
+        }
+    }
+
+    impl ResolutionBackend for ScriptedNameKeyedBackend {
+        fn resolve<'a>(
+            &'a self,
+            request: ResolutionRequest,
+        ) -> BoxFuture<'a, Result<ResolutionResponse, ResolutionBackendError>> {
+            Box::pin(async move {
+                self.call_count.fetch_add(1, Ordering::SeqCst);
+                let question = &request.query.question;
+                let responses = self.responses.lock().unwrap();
+                let found = responses
+                    .iter()
+                    .find(|(name, qtype, _)| name == &question.qname && *qtype == question.qtype)
+                    .map(|(_, _, wire)| wire.clone());
+                match found {
+                    Some(wire) => Ok(ResolutionResponse::forwarded_bytes(
+                        wire,
+                        SystemTime::now(),
+                        0,
+                        "scripted-name-keyed-backend",
+                    )),
+                    None => Err(ResolutionBackendError::NoBackendsAvailable),
+                }
+            })
+        }
+    }
+
+    #[tokio::test]
+    async fn validate_for_store_returns_secure_for_a_known_good_signed_response() {
+        use crate::resolver::dnssec_validation::tests::fixture;
+        use domain::rdata::dnssec::Timestamp;
+
+        let now = Timestamp::now();
+        let expiration = Timestamp::from(now.into_int().wrapping_add(3600));
+        let material = fixture::build_zone("example.test.", now, expiration);
+        let backend: Arc<dyn ResolutionBackend> = Arc::new(ScriptedNameKeyedBackend::new(vec![(
+            material.apex.trim_end_matches('.').to_string(),
+            DNSKEY_RECORD_TYPE,
+            material.dnskey_response_wire.clone(),
+        )]));
+        let service = resolve_service_with_recursive_cache(
+            backend,
+            Arc::new(NoopDnsCache),
+            Arc::new(RecordingEvents::default()),
+            Arc::new(RecordingMetrics::default()),
+            1232,
+        )
+        .with_trust_anchors(vec![material.trust_anchor_line.clone()]);
+
+        let response = fixture::rdns_message(material.a_response_wire.clone());
+        let dnssec_state = service.validate_for_store(&response).await;
+
+        assert_eq!(
+            dnssec_state,
+            DnssecState::Secure,
+            "expected a real validator run against a known-good signed response to produce Secure"
+        );
+    }
+
+    #[tokio::test]
+    async fn validate_for_store_returns_unvalidated_without_configured_trust_anchors() {
+        // No `.with_trust_anchors(...)` call -- every constructor defaults
+        // to `None`, which must short-circuit to `Unvalidated` without
+        // touching the backend at all (proven by the untouched call count).
+        use crate::resolver::dnssec_validation::tests::fixture;
+        use domain::rdata::dnssec::Timestamp;
+
+        let now = Timestamp::now();
+        let expiration = Timestamp::from(now.into_int().wrapping_add(3600));
+        let material = fixture::build_zone("example.test.", now, expiration);
+        let backend = Arc::new(ScriptedNameKeyedBackend::new(vec![(
+            material.apex.trim_end_matches('.').to_string(),
+            DNSKEY_RECORD_TYPE,
+            material.dnskey_response_wire.clone(),
+        )]));
+        let service = resolve_service_with_recursive_cache(
+            Arc::clone(&backend) as Arc<dyn ResolutionBackend>,
+            Arc::new(NoopDnsCache),
+            Arc::new(RecordingEvents::default()),
+            Arc::new(RecordingMetrics::default()),
+            1232,
+        );
+
+        let response = fixture::rdns_message(material.a_response_wire.clone());
+        let dnssec_state = service.validate_for_store(&response).await;
+
+        assert_eq!(dnssec_state, DnssecState::Unvalidated);
+        assert_eq!(
+            backend.calls(),
+            0,
+            "no trust anchors configured must skip the validator entirely, never touching the backend"
+        );
+    }
+
+    #[tokio::test]
+    async fn resolve_forward_mode_never_invokes_dnssec_validator() {
+        // section-04 (A5): Forward mode must never call the validator, even
+        // when trust anchors *are* configured -- proven by a call-count spy
+        // on the backend rather than just code inspection, since the spy
+        // also catches an accidental extra chase call the way a plain
+        // "does it compile" check wouldn't.
+        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
+        let response_wire = response_message_for_question(
+            question.clone(),
+            ResponseCode::NoError,
+            vec![a_record("example.com", 60)],
+            Vec::new(),
+            Vec::new(),
+            false,
+        )
+        .original_bytes
+        .to_vec();
+        let backend = Arc::new(ScriptedNameKeyedBackend::new(vec![(
+            "example.com".to_string(),
+            A_RECORD_TYPE,
+            response_wire,
+        )]));
+        let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+            max_entries: 16,
+            shard_count: Some(1),
+            ..CacheConfig::default()
+        }));
+        let service = resolve_service_with_cache(
+            Arc::clone(&backend) as Arc<dyn ResolutionBackend>,
+            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+            Arc::new(RecordingEvents::default()),
+            Arc::new(RecordingMetrics::default()),
+            1232,
+        )
+        // Anchors configured but unparseable as real zonefile data -- if
+        // Forward mode incorrectly called the validator, this would either
+        // panic/error out or trigger an extra backend call; neither may
+        // happen since Forward mode must never reach that code at all.
+        .with_trust_anchors(vec!["not a valid zonefile trust anchor line".to_string()]);
+
+        let outcome = service
+            .resolve(ResolveRequest::new(
+                "192.0.2.10".parse().unwrap(),
+                SystemTime::UNIX_EPOCH,
+                a_query(0x1234, "example.com"),
+            ))
+            .await;
+        let parsed = Message::parse(&outcome.response_bytes).unwrap();
+        assert_eq!(parsed.header.r_code(), ResponseCode::NoError as u8);
+
+        assert_eq!(
+            backend.calls(),
+            1,
+            "expected exactly the client's own top-level fetch, no extra validator chase call"
+        );
+
+        match cache.lookup_chain(
+            "example.com",
+            A_RECORD_TYPE,
+            1,
+            false,
+            0,
+            8,
+            SystemTime::UNIX_EPOCH,
+            &RefreshConfig::default(),
+        ) {
+            ChainLookup::Answered(resolved) => {
+                assert_eq!(resolved.chain[0].1.dnssec_state, DnssecState::Unvalidated);
+            }
+            other => panic!("expected Answered after storing the fetched entry, got {other:?}"),
+        }
+    }
+
+    #[tokio::test]
+    async fn resolve_recursive_mode_stores_dnssec_state_independent_of_requesters_cd_bit() {
+        // section-04 (A5): validation always runs and its result is always
+        // stored, independent of the storing request's own CD bit -- proven
+        // here with the safe (no-trust-anchors -> Unvalidated) path across
+        // two otherwise-identical fetches that differ only in CD, each
+        // against its own fresh cache so neither serve masks the other's
+        // store.
+        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
+        let response_wire = response_message_for_question(
+            question.clone(),
+            ResponseCode::NoError,
+            vec![a_record("example.com", 60)],
+            Vec::new(),
+            Vec::new(),
+            false,
+        )
+        .original_bytes
+        .to_vec();
+
+        let mut observed_states = Vec::new();
+        for checking_disabled in [false, true] {
+            let backend = Arc::new(ScriptedNameKeyedBackend::new(vec![(
+                "example.com".to_string(),
+                A_RECORD_TYPE,
+                response_wire.clone(),
+            )]));
+            let cache = Arc::new(ShardedDnsCache::new(&CacheConfig {
+                max_entries: 16,
+                shard_count: Some(1),
+                ..CacheConfig::default()
+            }));
+            let service = resolve_service_with_recursive_cache(
+                backend,
+                Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
+                Arc::new(RecordingEvents::default()),
+                Arc::new(RecordingMetrics::default()),
+                1232,
+            );
+
+            let mut query = a_query(0x1234, "example.com");
+            if checking_disabled {
+                let flags = u16::from_be_bytes([query[2], query[3]]) | 0x0010;
+                query[2..4].copy_from_slice(&flags.to_be_bytes());
+            }
+            let outcome = service
+                .resolve(ResolveRequest::new(
+                    "192.0.2.10".parse().unwrap(),
+                    SystemTime::UNIX_EPOCH,
+                    query,
+                ))
+                .await;
+            let parsed = Message::parse(&outcome.response_bytes).unwrap();
+            assert_eq!(parsed.header.r_code(), ResponseCode::NoError as u8);
+
+            match cache.lookup_chain(
+                "example.com",
+                A_RECORD_TYPE,
+                1,
+                false,
+                0,
+                8,
+                SystemTime::UNIX_EPOCH,
+                &RefreshConfig::default(),
+            ) {
+                ChainLookup::Answered(resolved) => {
+                    observed_states.push(resolved.chain[0].1.dnssec_state.clone());
+                }
+                other => panic!("expected Answered after storing the fetched entry, got {other:?}"),
+            }
+        }
+
+        assert_eq!(
+            observed_states[0], observed_states[1],
+            "the stored dnssec_state must be identical for a CD=0 and a CD=1 fetch of the same data"
+        );
+    }
+
     fn a_response_with_answer(id: u16, name: &str, ttl: u32) -> Vec<u8> {
         let query = Message::parse_standard_query(&a_query(id, name)).unwrap();
         // `a_query` never carries EDNS, so the OPT-record-bearing branch of
@@ -15749,6 +16188,7 @@ mod tests {
             SystemTime::UNIX_EPOCH,
             true,
             true,
+            DnssecState::Unvalidated,
         );
 
         assert!(
@@ -15789,6 +16229,7 @@ mod tests {
             SystemTime::UNIX_EPOCH,
             true,
             true,
+            DnssecState::Unvalidated,
         );
 
         assert_eq!(decomposed.positive.len(), 1);
@@ -15840,6 +16281,7 @@ mod tests {
             SystemTime::UNIX_EPOCH,
             true,
             true,
+            DnssecState::Unvalidated,
         );
 
         assert_eq!(decomposed.positive.len(), 2);
@@ -15891,6 +16333,7 @@ mod tests {
             SystemTime::UNIX_EPOCH,
             true,
             true,
+            DnssecState::Unvalidated,
         );
 
         let (_, _, negative_entry) = decomposed.negative.expect("expected a negative entry");
@@ -15949,6 +16392,138 @@ mod tests {
         );
     }
 
+    fn rrsig_record_with_expiration(
+        name: &str,
+        ttl: u32,
+        type_covered: u16,
+        signature_expiration: u32,
+    ) -> Record {
+        let mut record = rrsig_record(name, ttl, type_covered);
+        if let RecordData::RRSIG {
+            signature_expiration: expiration,
+            ..
+        } = &mut record.record
+        {
+            *expiration = signature_expiration;
+        }
+        record
+    }
+
+    #[test]
+    fn build_rrset_entry_caps_ttl_to_earlier_rrsig_expiration() {
+        // section-04 (A5): a `Secure` entry must never keep being served
+        // from cache after its signature has cryptographically expired --
+        // `expires_at` must be capped at the earliest RRSIG expiration when
+        // that's tighter than the otherwise-computed TTL.
+        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
+        let ttl = Duration::from_secs(3600);
+        let response = response_message_for_question(
+            question.clone(),
+            ResponseCode::NoError,
+            vec![
+                a_record("example.com", 3600),
+                rrsig_record_with_expiration("example.com", 3600, A_RECORD_TYPE, 1800),
+            ],
+            Vec::new(),
+            Vec::new(),
+            true,
+        );
+
+        let decomposed = decompose_response_for_store(
+            &response,
+            &question,
+            ttl,
+            None,
+            SystemTime::UNIX_EPOCH,
+            true,
+            true,
+            DnssecState::Secure,
+        );
+
+        let (_, _, _, entry) = &decomposed.positive[0];
+        assert_eq!(
+            entry.expires_at,
+            SystemTime::UNIX_EPOCH + Duration::from_secs(1800),
+            "expected expires_at capped to the earlier RRSIG expiration, not the full TTL"
+        );
+    }
+
+    #[test]
+    fn build_rrset_entry_ttl_unaffected_when_rrsig_expiration_is_later() {
+        let question = QuestionKey::new("example.com", A_RECORD_TYPE, 1);
+        let ttl = Duration::from_secs(3600);
+        let response = response_message_for_question(
+            question.clone(),
+            ResponseCode::NoError,
+            vec![
+                a_record("example.com", 3600),
+                rrsig_record_with_expiration("example.com", 3600, A_RECORD_TYPE, 7200),
+            ],
+            Vec::new(),
+            Vec::new(),
+            true,
+        );
+
+        let decomposed = decompose_response_for_store(
+            &response,
+            &question,
+            ttl,
+            None,
+            SystemTime::UNIX_EPOCH,
+            true,
+            true,
+            DnssecState::Secure,
+        );
+
+        let (_, _, _, entry) = &decomposed.positive[0];
+        assert_eq!(
+            entry.expires_at,
+            SystemTime::UNIX_EPOCH + ttl,
+            "expected the otherwise-computed TTL to win when the RRSIG expires later"
+        );
+    }
+
+    #[test]
+    fn build_negative_entry_caps_ttl_to_earlier_soa_rrsig_expiration() {
+        // The SOA's `minimum` (120) governs the negative TTL
+        // (`ttl_for_response`), so the RRSIG expiration must be tighter
+        // than *that* -- not the SOA's own 3600s record TTL -- to actually
+        // exercise the cap.
+        let question = QuestionKey::new("nx.example.com", A_RECORD_TYPE, 1);
+        let response = response_message_for_question(
+            question.clone(),
+            ResponseCode::NxDomain,
+            Vec::new(),
+            vec![
+                soa_record("example.com", 3600, 120),
+                rrsig_record_with_expiration("example.com", 3600, SOA_RECORD_TYPE, 60),
+            ],
+            Vec::new(),
+            true,
+        );
+        let policy = CacheTtlPolicy::default();
+        let (ttl, negative_meta) = policy.ttl_for_response(&response).expect("cacheable");
+        assert!(negative_meta.is_some());
+
+        let decomposed = decompose_response_for_store(
+            &response,
+            &question,
+            ttl,
+            negative_meta.as_ref(),
+            SystemTime::UNIX_EPOCH,
+            true,
+            true,
+            DnssecState::Secure,
+        );
+
+        let (_, _, negative_entry) = decomposed.negative.expect("expected a negative entry");
+        assert_eq!(
+            negative_entry.expires_at,
+            SystemTime::UNIX_EPOCH + Duration::from_secs(60),
+            "expected the negative entry's expires_at capped to the SOA RRSIG's earlier expiration"
+        );
+    }
+
     #[test]
     fn ttl_policy_applies_negative_bounds_and_requires_soa() {
         let policy = CacheTtlPolicy::new(
