diff --git a/src/main.rs b/src/main.rs
index 0a986e7..7f93c05 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -839,6 +839,8 @@ struct OpenTelemetryMetrics {
     dnssec_validation_disabled: Gauge<u64>,
     protocol_error_total: Counter<u64>,
     recursion_refused_total: Counter<u64>,
+    refresh_triggered_total: Counter<u64>,
+    refresh_queue_full_total: Counter<u64>,
     query_duration_seconds: Histogram<f64>,
     recursive_query_duration_seconds: Histogram<f64>,
     cache_hit_query_duration_seconds: Histogram<f64>,
@@ -944,6 +946,8 @@ impl OpenTelemetryMetrics {
             dnssec_validation_disabled: meter.u64_gauge("dnssec_validation_disabled").build(),
             protocol_error_total: meter.u64_counter("protocol_error_total").build(),
             recursion_refused_total: meter.u64_counter("recursion_refused_total").build(),
+            refresh_triggered_total: meter.u64_counter("refresh_triggered_total").build(),
+            refresh_queue_full_total: meter.u64_counter("refresh_queue_full_total").build(),
             query_duration_seconds: meter.f64_histogram("query_duration_seconds").build(),
             recursive_query_duration_seconds: meter
                 .f64_histogram("recursive_query_duration_seconds")
@@ -1022,6 +1026,8 @@ impl MetricsSink for OpenTelemetryMetrics {
             }
             ResolverMetric::ProtocolError => self.protocol_error_total.add(1, &[]),
             ResolverMetric::RecursionRefused => self.recursion_refused_total.add(1, &[]),
+            ResolverMetric::RefreshTriggered => self.refresh_triggered_total.add(1, &[]),
+            ResolverMetric::RefreshQueueFull => self.refresh_queue_full_total.add(1, &[]),
             ResolverMetric::QueryDuration
             | ResolverMetric::RecursiveQueryDuration
             | ResolverMetric::CacheHitQueryDuration
diff --git a/src/resolver/cache/assemble.rs b/src/resolver/cache/assemble.rs
index 9d91c34..8df55b1 100644
--- a/src/resolver/cache/assemble.rs
+++ b/src/resolver/cache/assemble.rs
@@ -33,6 +33,7 @@ use std::collections::HashSet;
 use std::net::IpAddr;
 use std::time::{Duration, SystemTime};
 
+use crate::config::RefreshConfig;
 use crate::protocol::edns_cookie::{CookieSecret, build_cookie_option, build_server_cookie};
 use crate::protocol::{
     NameCompressor, Record, RecordData, ResponseCode, build_truncated_wire_response,
@@ -46,12 +47,34 @@ use super::shard::HopResult;
 
 const CNAME_RECORD_TYPE: u16 = 5;
 
+/// One cache hop's signal that it currently qualifies for a background
+/// refresh (all three gates in `docs/plans/auto_refresh/claude-plan.md`
+/// §3.1 hold: eligibility floor, lead window, popularity hot-threshold).
+/// `qtype`/`qclass` identify the specific record set at `domain` that
+/// should be refetched — for an intermediate CNAME hop this is
+/// `(CNAME_RECORD_TYPE, qclass)`, never the original query's qtype, since
+/// the CNAME record set at that hop's domain is what's actually near
+/// expiry.
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub(crate) struct RefreshHint {
+    pub(crate) domain: String,
+    pub(crate) qtype: u16,
+    pub(crate) qclass: u16,
+}
+
 /// Zero or more CNAME hops followed by the terminal `RRsetEntry` matching
 /// the original qtype — or, if qtype == CNAME itself, exactly one hop (the
 /// CNAME's own entry, no further walking past it).
 #[derive(Debug, Clone, PartialEq, Eq)]
 pub struct ResolvedAnswer {
     pub(crate) chain: Vec<(String, RRsetEntry)>, // (owner name, entry), in walk order
+    /// One hint per hop in `chain` that independently wants a refresh —
+    /// not just the terminal hop. A CNAME record is itself a positive
+    /// RRset with its own independent expiry, so an intermediate hop can
+    /// need a refresh even while the terminal hop stays fresh (and vice
+    /// versa); collecting a hint per qualifying hop is what a caller
+    /// (`ResolveQuery::probe_cache`, section-04) enqueues jobs from.
+    pub(crate) refresh_hints: Vec<RefreshHint>,
 }
 
 /// A negative result (NXDOMAIN or NODATA), plus whatever CNAME hops were
@@ -126,9 +149,11 @@ pub(crate) fn resolve_from_cache(
     current_epoch: u64,
     max_chain_depth: u8,
     now: SystemTime,
+    refresh_config: &RefreshConfig,
 ) -> ChainLookup {
     let mut current = crate::resolver::normalize_question_name(qname);
     let mut chain: Vec<(String, RRsetEntry)> = Vec::new();
+    let mut refresh_hints: Vec<RefreshHint> = Vec::new();
     let mut visited: HashSet<String> = HashSet::new();
 
     loop {
@@ -152,12 +177,41 @@ pub(crate) fn resolve_from_cache(
         visited.insert(current.clone());
 
         let shard = cache.shard_for(&current);
-        match shard.lookup_hop(&current, qtype, qclass, dnssec_ok, current_epoch, now) {
-            HopResult::Answer(entry) => {
+        match shard.lookup_hop(
+            &current,
+            qtype,
+            qclass,
+            dnssec_ok,
+            current_epoch,
+            now,
+            refresh_config,
+        ) {
+            HopResult::Answer(entry, wants_refresh) => {
+                if wants_refresh {
+                    refresh_hints.push(RefreshHint {
+                        domain: current.clone(),
+                        qtype,
+                        qclass,
+                    });
+                }
                 chain.push((current, entry));
-                return ChainLookup::Answered(ResolvedAnswer { chain });
+                return ChainLookup::Answered(ResolvedAnswer {
+                    chain,
+                    refresh_hints,
+                });
             }
-            HopResult::CnameHop(entry, target) => {
+            HopResult::CnameHop(entry, target, wants_refresh) => {
+                if wants_refresh {
+                    // This hop's own record type is CNAME, not the
+                    // original query's qtype — a refresh job for this hop
+                    // must refetch the CNAME record set at `current`, not
+                    // whatever type was originally queried.
+                    refresh_hints.push(RefreshHint {
+                        domain: current.clone(),
+                        qtype: CNAME_RECORD_TYPE,
+                        qclass,
+                    });
+                }
                 chain.push((current, entry));
                 current = crate::resolver::normalize_question_name(&target);
             }
@@ -895,6 +949,7 @@ mod tests {
         );
         entry.expires_at = stored_at + Duration::from_secs(600);
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -924,6 +979,7 @@ mod tests {
         let mut entry = rrset_entry(vec![a_record(600, 1)], Duration::from_secs(600), stored_at);
         entry.expires_at = stored_at + Duration::from_secs(600); // expires in 10s
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -961,6 +1017,7 @@ mod tests {
             stored_at,
         );
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -990,6 +1047,7 @@ mod tests {
         let now = SystemTime::now();
         let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
 
@@ -1032,6 +1090,7 @@ mod tests {
         let records: Vec<StoredRecord> = (0..40u8).map(|i| a_record(300, i)).collect();
         let entry = rrset_entry(records, Duration::from_secs(300), now);
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -1093,6 +1152,7 @@ mod tests {
         let now = SystemTime::now();
         let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -1159,6 +1219,7 @@ mod tests {
         let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
         let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -1207,6 +1268,7 @@ mod tests {
             rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         authoritative_entry.authoritative = true;
         let authoritative_resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), authoritative_entry)],
         };
         let aa_response = assemble_response(
@@ -1229,6 +1291,7 @@ mod tests {
             rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         non_authoritative_entry.authoritative = false;
         let non_authoritative_resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), non_authoritative_entry)],
         };
         let no_aa_response = assemble_response(
@@ -1264,6 +1327,7 @@ mod tests {
             rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         non_authoritative_terminal.authoritative = false;
         let mixed_resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![
                 ("alias.example.com".to_string(), authoritative_cname),
                 ("target.example.com".to_string(), non_authoritative_terminal),
@@ -1296,6 +1360,7 @@ mod tests {
         let now = SystemTime::now();
         let entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -1356,6 +1421,7 @@ mod tests {
             },
         }];
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -1393,6 +1459,7 @@ mod tests {
         let mut secure_entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         secure_entry.dnssec_state = DnssecState::Secure;
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), secure_entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -1430,6 +1497,7 @@ mod tests {
             rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         unvalidated_entry.dnssec_state = DnssecState::Unvalidated;
         let unvalidated_resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), unvalidated_entry)],
         };
         let unvalidated_response = assemble_response(
@@ -1452,6 +1520,7 @@ mod tests {
         let mut bogus_entry = rrset_entry(vec![a_record(300, 1)], Duration::from_secs(300), now);
         bogus_entry.dnssec_state = DnssecState::Bogus("signature verification failed".to_string());
         let resolved = ResolvedAnswer {
+            refresh_hints: Vec::new(),
             chain: vec![("example.com".to_string(), bogus_entry)],
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
@@ -2332,7 +2401,17 @@ mod tests {
             nxdomain,
         );
 
-        let result = resolve_from_cache(&cache, domain, A_QTYPE, IN_QCLASS, false, 1, 8, now);
+        let result = resolve_from_cache(
+            &cache,
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            8,
+            now,
+            &RefreshConfig::default(),
+        );
 
         assert!(
             matches!(result, ChainLookup::NoData(_)),
@@ -2383,6 +2462,7 @@ mod tests {
             1,
             8,
             now,
+            &RefreshConfig::default(),
         );
         assert!(matches!(answered, ChainLookup::Answered(_)));
 
@@ -2399,6 +2479,7 @@ mod tests {
             1,
             2,
             now,
+            &RefreshConfig::default(),
         );
         assert_eq!(too_shallow, ChainLookup::Miss);
     }
@@ -2448,6 +2529,7 @@ mod tests {
             1,
             3,
             now,
+            &RefreshConfig::default(),
         );
         match exact_boundary {
             ChainLookup::Answered(resolved) => {
@@ -2497,6 +2579,7 @@ mod tests {
             1,
             3,
             now,
+            &RefreshConfig::default(),
         );
         assert_eq!(
             four_restarts_at_boundary,
@@ -2548,9 +2631,15 @@ mod tests {
         );
 
         let result = resolve_from_cache(
-            &cache, &names[0], A_QTYPE, IN_QCLASS, false, 1,
+            &cache,
+            &names[0],
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
             255, // max_chain_depth: one less than the 256 restarts this chain needs
             now,
+            &RefreshConfig::default(),
         );
 
         assert_eq!(
@@ -2583,6 +2672,7 @@ mod tests {
             1,
             8,
             now,
+            &RefreshConfig::default(),
         );
 
         assert_eq!(result, ChainLookup::Miss);
@@ -2655,6 +2745,7 @@ mod tests {
             1,
             8,
             now,
+            &RefreshConfig::default(),
         );
 
         match result {
@@ -2700,6 +2791,7 @@ mod tests {
             1,
             8,
             now,
+            &RefreshConfig::default(),
         );
 
         assert_eq!(result, ChainLookup::Miss);
@@ -2719,6 +2811,7 @@ mod tests {
             1,
             8,
             now,
+            &RefreshConfig::default(),
         );
 
         assert_eq!(result, ChainLookup::Miss);
@@ -2748,6 +2841,7 @@ mod tests {
             2,
             8,
             now,
+            &RefreshConfig::default(),
         );
 
         assert_eq!(result, ChainLookup::Miss);
@@ -2796,6 +2890,7 @@ mod tests {
             1,
             8,
             now,
+            &RefreshConfig::default(),
         );
 
         match result {
@@ -2853,7 +2948,17 @@ mod tests {
         std::thread::sleep(Duration::from_millis(50));
 
         let start = std::time::Instant::now();
-        let result = resolve_from_cache(&cache, &domain_b, A_QTYPE, IN_QCLASS, false, 1, 8, now);
+        let result = resolve_from_cache(
+            &cache,
+            &domain_b,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            8,
+            now,
+            &RefreshConfig::default(),
+        );
         let elapsed = start.elapsed();
 
         handle.join().unwrap();
@@ -2864,4 +2969,295 @@ mod tests {
             "lookup against a different shard should not wait on shard A's held lock, took {elapsed:?}"
         );
     }
+
+    // `RefreshHint`/multi-hop plumbing tests: section-04-chainlookup-plumbing.
+    // `RefreshConfig::default()`: bucket_capacity=10, hot_threshold_fraction=0.5
+    // (hot_threshold=5), lead_ratio=0.10, min_lead=5s, eligibility_floor=15s.
+
+    /// Builds a two-hop chain: `source` (CNAME) -> `target` (A), both with
+    /// `minimum_ttl = 300s`. `source_remaining`/`target_remaining` control
+    /// each hop's remaining TTL independently (via a post-construction
+    /// `expires_at` override), so a test can put either or both hops inside
+    /// the default lead window (<= 30s) independently of the other.
+    fn store_cname_chain(
+        cache: &ShardedDnsCache,
+        source: &str,
+        target: &str,
+        now: SystemTime,
+        source_remaining: Duration,
+        target_remaining: Duration,
+    ) {
+        let mut cname_entry = rrset_entry(
+            vec![StoredRecord {
+                rtype: CNAME_RECORD_TYPE,
+                rclass: IN_QCLASS,
+                ttl_at_store: 300,
+                rdata: RecordData::CNAME(target.to_string()),
+            }],
+            Duration::from_secs(300),
+            now,
+        );
+        cname_entry.expires_at = now + source_remaining;
+        cache
+            .shard_for(source)
+            .store_positive(source, (CNAME_RECORD_TYPE, IN_QCLASS), cname_entry);
+
+        let mut terminal_entry = rrset_entry(vec![a_record(300, 7)], Duration::from_secs(300), now);
+        terminal_entry.expires_at = now + target_remaining;
+        cache
+            .shard_for(target)
+            .store_positive(target, (A_QTYPE, IN_QCLASS), terminal_entry);
+    }
+
+    /// Directly queries `domain` at `qtype` (bypassing chain-following)
+    /// `hit_count` times, so only `domain`'s own popularity bucket
+    /// increments — its chain-mate's popularity is left untouched. Used to
+    /// selectively make one hop "hot" (`RefreshConfig::default()`'s
+    /// `hot_threshold` is 5) without warming the other hop in the same
+    /// chain.
+    fn warm_popularity(
+        cache: &ShardedDnsCache,
+        domain: &str,
+        qtype: u16,
+        now: SystemTime,
+        hits: u32,
+    ) {
+        for _ in 0..hits {
+            resolve_from_cache(
+                cache,
+                domain,
+                qtype,
+                IN_QCLASS,
+                false,
+                1,
+                8,
+                now,
+                &RefreshConfig::default(),
+            );
+        }
+    }
+
+    #[test]
+    fn chain_lookup_no_qualifying_hops_empty_hints() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        // Both hops fresh (300s remaining, outside the 30s lead window) and
+        // neither ever queried before now (cold, level 0) -- neither
+        // qualifies.
+        store_cname_chain(
+            &cache,
+            "source.example.com",
+            "target.example.com",
+            now,
+            Duration::from_secs(300),
+            Duration::from_secs(300),
+        );
+
+        let result = resolve_from_cache(
+            &cache,
+            "source.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            8,
+            now,
+            &RefreshConfig::default(),
+        );
+
+        match result {
+            ChainLookup::Answered(resolved) => {
+                assert!(resolved.refresh_hints.is_empty());
+            }
+            other => panic!("expected Answered, got {other:?}"),
+        }
+    }
+
+    #[test]
+    fn chain_lookup_intermediate_hop_only() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        // Source (CNAME) near expiry; target (terminal A) fresh.
+        store_cname_chain(
+            &cache,
+            "source.example.com",
+            "target.example.com",
+            now,
+            Duration::from_secs(20),  // inside the 30s lead window
+            Duration::from_secs(300), // outside
+        );
+        // Warm only the source's popularity above the hot threshold (5).
+        warm_popularity(&cache, "source.example.com", CNAME_RECORD_TYPE, now, 5);
+
+        let result = resolve_from_cache(
+            &cache,
+            "source.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            8,
+            now,
+            &RefreshConfig::default(),
+        );
+
+        match result {
+            ChainLookup::Answered(resolved) => {
+                assert_eq!(
+                    resolved.refresh_hints,
+                    vec![RefreshHint {
+                        domain: "source.example.com".to_string(),
+                        qtype: CNAME_RECORD_TYPE,
+                        qclass: IN_QCLASS,
+                    }],
+                    "only the intermediate CNAME hop should produce a hint, not the fresh terminal hop"
+                );
+            }
+            other => panic!("expected Answered, got {other:?}"),
+        }
+    }
+
+    #[test]
+    fn chain_lookup_terminal_hop_only() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        // Source (CNAME) fresh; target (terminal A) near expiry.
+        store_cname_chain(
+            &cache,
+            "source.example.com",
+            "target.example.com",
+            now,
+            Duration::from_secs(300), // outside the lead window
+            Duration::from_secs(20),  // inside
+        );
+        // Warm only the target's popularity above the hot threshold (5).
+        warm_popularity(&cache, "target.example.com", A_QTYPE, now, 5);
+
+        let result = resolve_from_cache(
+            &cache,
+            "source.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            8,
+            now,
+            &RefreshConfig::default(),
+        );
+
+        match result {
+            ChainLookup::Answered(resolved) => {
+                assert_eq!(
+                    resolved.refresh_hints,
+                    vec![RefreshHint {
+                        domain: "target.example.com".to_string(),
+                        qtype: A_QTYPE,
+                        qclass: IN_QCLASS,
+                    }],
+                    "only the terminal hop should produce a hint, not the fresh intermediate hop"
+                );
+            }
+            other => panic!("expected Answered, got {other:?}"),
+        }
+    }
+
+    #[test]
+    fn chain_lookup_multi_hop_all_qualifying_hops_produce_hints() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        // Both hops near expiry.
+        store_cname_chain(
+            &cache,
+            "source.example.com",
+            "target.example.com",
+            now,
+            Duration::from_secs(20),
+            Duration::from_secs(20),
+        );
+        // Warm both hops' popularity above the hot threshold (5) --
+        // directly, so each domain's own bucket (not the other's) reaches 5.
+        warm_popularity(&cache, "source.example.com", CNAME_RECORD_TYPE, now, 5);
+        warm_popularity(&cache, "target.example.com", A_QTYPE, now, 5);
+
+        let result = resolve_from_cache(
+            &cache,
+            "source.example.com",
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            8,
+            now,
+            &RefreshConfig::default(),
+        );
+
+        match result {
+            ChainLookup::Answered(resolved) => {
+                assert_eq!(
+                    resolved.refresh_hints,
+                    vec![
+                        RefreshHint {
+                            domain: "source.example.com".to_string(),
+                            qtype: CNAME_RECORD_TYPE,
+                            qclass: IN_QCLASS,
+                        },
+                        RefreshHint {
+                            domain: "target.example.com".to_string(),
+                            qtype: A_QTYPE,
+                            qclass: IN_QCLASS,
+                        },
+                    ],
+                    "every qualifying hop must produce its own hint, not just the terminal one \
+                     (this is the regression test for the terminal-only bug found during plan review)"
+                );
+            }
+            other => panic!("expected Answered, got {other:?}"),
+        }
+    }
+
+    #[test]
+    fn chain_lookup_no_data_never_carries_hint() {
+        let cache = cache_with_shard_count(1);
+        let now = SystemTime::now();
+        let domain = "nodata.example.com";
+        let key = NegativeKey {
+            qtype: Some(A_QTYPE),
+            qclass: IN_QCLASS,
+        };
+        let negative = NegativeEntry {
+            kind: crate::resolver::NegativeCacheKind::NoData,
+            soa_owner: "example.com".to_string(),
+            soa_record: a_record(3600, 1),
+            soa_rrsig: None,
+            proof_records: Vec::new(),
+            stored_at: now,
+            expires_at: now + Duration::from_secs(3600),
+            cache_epoch: 1,
+            dnssec_complete: true,
+            dnssec_state: DnssecState::Unvalidated,
+            authoritative: false,
+        };
+        cache
+            .shard_for(domain)
+            .store_negative(domain, key, negative);
+
+        let result = resolve_from_cache(
+            &cache,
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            8,
+            now,
+            &RefreshConfig::default(),
+        );
+
+        // `ChainLookup::NoData` wraps `ResolvedNegative`, which structurally
+        // has no `refresh_hints` field at all -- there is nothing to assert
+        // beyond confirming the variant itself, which this match already
+        // does at compile time (a hint field on `ResolvedNegative` would be
+        // a compile error to access here, since it doesn't exist).
+        assert!(matches!(result, ChainLookup::NoData(_)));
+    }
 }
diff --git a/src/resolver/cache/mod.rs b/src/resolver/cache/mod.rs
index e028f51..cc0fa42 100644
--- a/src/resolver/cache/mod.rs
+++ b/src/resolver/cache/mod.rs
@@ -27,11 +27,12 @@ use std::hash::BuildHasher;
 use std::sync::OnceLock;
 use std::time::SystemTime;
 
+use crate::config::RefreshConfig;
 use shard::Shard;
 
 pub use assemble::ChainLookup;
 pub(crate) use assemble::{
-    ResolvedAnswer, ResolvedNegative, assemble_negative_response, assemble_response,
+    RefreshHint, ResolvedAnswer, ResolvedNegative, assemble_negative_response, assemble_response,
 };
 pub use entry::{NegativeEntry, NegativeKey, RRsetEntry, StoredRecord};
 pub(crate) use singleflight::{
@@ -126,6 +127,7 @@ pub trait DomainDnsCache: Send + Sync {
         epoch: u64,
         max_chain_depth: u8,
         now: SystemTime,
+        refresh_config: &RefreshConfig,
     ) -> ChainLookup;
 
     /// Replaces the old flat `store` — called once per backend response,
@@ -158,6 +160,7 @@ impl DomainDnsCache for ShardedDnsCache {
         epoch: u64,
         max_chain_depth: u8,
         now: SystemTime,
+        refresh_config: &RefreshConfig,
     ) -> ChainLookup {
         assemble::resolve_from_cache(
             self,
@@ -168,6 +171,7 @@ impl DomainDnsCache for ShardedDnsCache {
             epoch,
             max_chain_depth,
             now,
+            refresh_config,
         )
     }
 
diff --git a/src/resolver/cache/shard.rs b/src/resolver/cache/shard.rs
index 4651579..4614cf7 100644
--- a/src/resolver/cache/shard.rs
+++ b/src/resolver/cache/shard.rs
@@ -39,13 +39,6 @@ use crate::protocol::RecordData;
 
 const CNAME_RECORD_TYPE: u16 = 5;
 
-const DEFAULT_POPULARITY_LEAK_RATE: LeakRate = LeakRate {
-    units: 1,
-    per: Duration::from_secs(60),
-};
-const DEFAULT_POPULARITY_HIT_INCREMENT: u32 = 1;
-const DEFAULT_POPULARITY_BUCKET_CAPACITY: u32 = 10;
-
 /// Per-domain leaky-bucket popularity tracker. Created the first time a
 /// domain is stored (mirroring `ShardLru`'s own on-first-store creation),
 /// drained-then-incremented on every subsequent lookup hit, and removed
@@ -136,15 +129,21 @@ impl PopularityBucket {
 /// shard's lock.
 #[derive(Debug, Clone)]
 pub(crate) enum HopResult {
-    /// A record set matching the queried `(qtype, qclass)` directly.
-    Answer(RRsetEntry),
+    /// A record set matching the queried `(qtype, qclass)` directly, plus
+    /// whether this hop currently wants a proactive refresh
+    /// (`wants_refresh`, computed inside `lookup_hop` while the lock —
+    /// and this domain's popularity bucket — is already held).
+    Answer(RRsetEntry, bool),
     /// The queried type wasn't found, but a CNAME record set was — carries
-    /// the CNAME's own entry (for the response's answer section) plus the
-    /// extracted target name to continue the walk.
-    CnameHop(RRsetEntry, String),
-    /// NODATA for the queried type at this (existing) name.
+    /// the CNAME's own entry (for the response's answer section), the
+    /// extracted target name to continue the walk, and whether this hop
+    /// wants a proactive refresh.
+    CnameHop(RRsetEntry, String, bool),
+    /// NODATA for the queried type at this (existing) name. Negative
+    /// entries never carry a refresh signal (v1 scope is positive-entries
+    /// only), so there is no bool here.
     NoData(NegativeEntry),
-    /// Whole-name NXDOMAIN at this name.
+    /// Whole-name NXDOMAIN at this name. Same scope note as `NoData`.
     NxDomain(NegativeEntry),
     /// Nothing usable here: absent, expired, or stored under a stale
     /// namespace.
@@ -562,6 +561,7 @@ impl Shard {
     /// live in the *authority* section and their TTLs play no part in the
     /// SOA-minimum-derived negative TTL computation, hence this dedicated
     /// read-time check.
+    #[allow(clippy::too_many_arguments)]
     pub(crate) fn lookup_hop(
         &self,
         domain: &str,
@@ -570,6 +570,7 @@ impl Shard {
         dnssec_ok: bool,
         current_epoch: u64,
         now: SystemTime,
+        refresh_config: &RefreshConfig,
     ) -> HopResult {
         let mut state = self.state.lock().unwrap();
         let answer_key = (qtype, qclass);
@@ -587,12 +588,19 @@ impl Shard {
             state.record_popularity_hit(
                 domain,
                 now,
-                true,
-                DEFAULT_POPULARITY_LEAK_RATE,
-                DEFAULT_POPULARITY_HIT_INCREMENT,
-                DEFAULT_POPULARITY_BUCKET_CAPACITY,
+                refresh_config.enabled,
+                refresh_config.leak_rate,
+                refresh_config.hit_increment,
+                refresh_config.bucket_capacity,
             );
-            return HopResult::Answer(entry);
+            let remaining_ttl = entry.expires_at.duration_since(now).unwrap_or_default();
+            let refresh_wanted = wants_refresh(
+                entry.minimum_ttl,
+                remaining_ttl,
+                state.popularity.get(domain),
+                refresh_config,
+            );
+            return HopResult::Answer(entry, refresh_wanted);
         }
 
         if qtype != CNAME_RECORD_TYPE {
@@ -604,12 +612,19 @@ impl Shard {
                 state.record_popularity_hit(
                     domain,
                     now,
-                    true,
-                    DEFAULT_POPULARITY_LEAK_RATE,
-                    DEFAULT_POPULARITY_HIT_INCREMENT,
-                    DEFAULT_POPULARITY_BUCKET_CAPACITY,
+                    refresh_config.enabled,
+                    refresh_config.leak_rate,
+                    refresh_config.hit_increment,
+                    refresh_config.bucket_capacity,
+                );
+                let remaining_ttl = entry.expires_at.duration_since(now).unwrap_or_default();
+                let refresh_wanted = wants_refresh(
+                    entry.minimum_ttl,
+                    remaining_ttl,
+                    state.popularity.get(domain),
+                    refresh_config,
                 );
-                return HopResult::CnameHop(entry, target);
+                return HopResult::CnameHop(entry, target, refresh_wanted);
             }
         }
 
@@ -624,10 +639,10 @@ impl Shard {
             state.record_popularity_hit(
                 domain,
                 now,
-                true,
-                DEFAULT_POPULARITY_LEAK_RATE,
-                DEFAULT_POPULARITY_HIT_INCREMENT,
-                DEFAULT_POPULARITY_BUCKET_CAPACITY,
+                refresh_config.enabled,
+                refresh_config.leak_rate,
+                refresh_config.hit_increment,
+                refresh_config.bucket_capacity,
             );
             return HopResult::NoData(entry);
         }
@@ -643,10 +658,10 @@ impl Shard {
             state.record_popularity_hit(
                 domain,
                 now,
-                true,
-                DEFAULT_POPULARITY_LEAK_RATE,
-                DEFAULT_POPULARITY_HIT_INCREMENT,
-                DEFAULT_POPULARITY_BUCKET_CAPACITY,
+                refresh_config.enabled,
+                refresh_config.leak_rate,
+                refresh_config.hit_increment,
+                refresh_config.bucket_capacity,
             );
             return HopResult::NxDomain(entry);
         }
@@ -956,13 +971,29 @@ mod tests {
         shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);
         let now = SystemTime::now();
 
-        let do_false_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let do_false_result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
-            matches!(do_false_result, HopResult::Answer(_)),
+            matches!(do_false_result, HopResult::Answer(_, _)),
             "a DO=false reader may still be served from a dnssec-incomplete entry"
         );
 
-        let do_true_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
+        let do_true_result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            true,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
             matches!(do_true_result, HopResult::Miss),
             "a DO=true reader must not be served from a dnssec-incomplete entry, got {do_true_result:?}"
@@ -978,8 +1009,16 @@ mod tests {
         shard.store_positive(domain, (A_QTYPE, IN_QCLASS), entry);
         let now = SystemTime::now();
 
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
-        assert!(matches!(result, HopResult::Answer(_)));
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            true,
+            1,
+            now,
+            &test_refresh_config(),
+        );
+        assert!(matches!(result, HopResult::Answer(_, _)));
     }
 
     #[test]
@@ -997,7 +1036,15 @@ mod tests {
         shard.store_positive(domain, (CNAME_RECORD_TYPE, IN_QCLASS), entry);
         let now = SystemTime::now();
 
-        let do_true_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
+        let do_true_result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            true,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
             matches!(do_true_result, HopResult::Miss),
             "a DO=true reader must not follow a dnssec-incomplete CNAME hop, got {do_true_result:?}"
@@ -1017,10 +1064,26 @@ mod tests {
         shard.store_negative(domain, nxdomain_key, entry.clone());
         let now = SystemTime::now();
 
-        let do_false_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let do_false_result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(matches!(do_false_result, HopResult::NxDomain(_)));
 
-        let do_true_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
+        let do_true_result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            true,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
             matches!(do_true_result, HopResult::Miss),
             "a DO=true reader must not be served from a dnssec-incomplete NXDOMAIN entry, got {do_true_result:?}"
@@ -1032,7 +1095,15 @@ mod tests {
             qclass: IN_QCLASS,
         };
         shard.store_negative(domain2, nodata_key, entry);
-        let do_true_nodata = shard.lookup_hop(domain2, A_QTYPE, IN_QCLASS, true, 1, now);
+        let do_true_nodata = shard.lookup_hop(
+            domain2,
+            A_QTYPE,
+            IN_QCLASS,
+            true,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
             matches!(do_true_nodata, HopResult::Miss),
             "a DO=true reader must not be served from a dnssec-incomplete NODATA entry, got {do_true_nodata:?}"
@@ -1098,13 +1169,29 @@ mod tests {
             negative_entry_with_short_lived_proof(stored_at),
         );
 
-        let do_false_result = shard.lookup_hop(nxdomain_domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let do_false_result = shard.lookup_hop(
+            nxdomain_domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
             matches!(do_false_result, HopResult::NxDomain(_)),
             "a DO=false reader may still be served despite the stale proof record, got {do_false_result:?}"
         );
 
-        let do_true_result = shard.lookup_hop(nxdomain_domain, A_QTYPE, IN_QCLASS, true, 1, now);
+        let do_true_result = shard.lookup_hop(
+            nxdomain_domain,
+            A_QTYPE,
+            IN_QCLASS,
+            true,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
             matches!(do_true_result, HopResult::Miss),
             "a DO=true reader must not be served an NXDOMAIN entry whose proof record TTL has elapsed, got {do_true_result:?}"
@@ -1120,8 +1207,15 @@ mod tests {
             nodata_key,
             negative_entry_with_short_lived_proof(stored_at),
         );
-        let do_true_nodata_result =
-            shard.lookup_hop(nodata_domain, A_QTYPE, IN_QCLASS, true, 1, now);
+        let do_true_nodata_result = shard.lookup_hop(
+            nodata_domain,
+            A_QTYPE,
+            IN_QCLASS,
+            true,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
             matches!(do_true_nodata_result, HopResult::Miss),
             "a DO=true reader must not be served a NODATA entry whose proof record TTL has elapsed, got {do_true_nodata_result:?}"
@@ -1146,7 +1240,15 @@ mod tests {
             negative_entry_with_short_lived_proof(stored_at),
         );
 
-        let do_true_result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, true, 1, now);
+        let do_true_result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            true,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(
             matches!(do_true_result, HopResult::NxDomain(_)),
             "a DO=true reader must still be served while every stored record remains within its own TTL, got {do_true_result:?}"
@@ -1180,7 +1282,15 @@ mod tests {
         shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired_rrset_entry(now));
         assert_eq!(shard.domain_count(), 1);
 
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
 
         assert!(matches!(result, HopResult::Miss));
         assert!(
@@ -1210,7 +1320,15 @@ mod tests {
         shard.store_positive(domain, (CNAME_RECORD_TYPE, IN_QCLASS), entry);
         assert_eq!(shard.domain_count(), 1);
 
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
 
         assert!(matches!(result, HopResult::Miss));
         assert!(!shard.contains_positive(domain, (CNAME_RECORD_TYPE, IN_QCLASS)));
@@ -1230,7 +1348,15 @@ mod tests {
         shard.store_negative(domain, nodata_key.clone(), expired_negative_entry(now));
         assert_eq!(shard.domain_count(), 1);
 
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
 
         assert!(matches!(result, HopResult::Miss));
         assert!(
@@ -1253,7 +1379,15 @@ mod tests {
         shard.store_negative(domain, nxdomain_key.clone(), expired_negative_entry(now));
         assert_eq!(shard.domain_count(), 1);
 
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
 
         assert!(matches!(result, HopResult::Miss));
         assert!(!shard.contains_negative(domain, &nxdomain_key));
@@ -1275,7 +1409,15 @@ mod tests {
         shard.store_positive(domain, (AAAA_QTYPE, IN_QCLASS), rrset_entry());
         assert_eq!(shard.domain_count(), 1);
 
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
 
         assert!(matches!(result, HopResult::Miss));
         assert!(!shard.contains_positive(domain, (A_QTYPE, IN_QCLASS)));
@@ -1388,7 +1530,15 @@ mod tests {
         let domain = "popular.example.com";
         shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
         let now = SystemTime::now();
-        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert_eq!(shard.popularity_level(domain), Some(1));
 
         // Force eviction via capacity pressure.
@@ -1403,7 +1553,15 @@ mod tests {
         let domain = "solo-positive.example.com";
         shard.store_positive(domain, (A_QTYPE, IN_QCLASS), rrset_entry());
         let now = SystemTime::now();
-        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert_eq!(shard.popularity_level(domain), Some(1));
 
         // Expire the only entry and look it up again, triggering removal
@@ -1411,7 +1569,15 @@ mod tests {
         let mut expired = rrset_entry();
         expired.expires_at = now - Duration::from_secs(1);
         shard.store_positive(domain, (A_QTYPE, IN_QCLASS), expired);
-        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
 
         assert_eq!(shard.popularity_level(domain), None);
     }
@@ -1453,9 +1619,25 @@ mod tests {
         let now = SystemTime::now();
 
         assert_eq!(shard.popularity_level(domain), None);
-        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert_eq!(shard.popularity_level(domain), Some(1));
-        shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert_eq!(shard.popularity_level(domain), Some(2));
     }
 
@@ -1474,8 +1656,16 @@ mod tests {
         let now = SystemTime::now();
 
         assert_eq!(shard.popularity_level(domain), None);
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
-        assert!(matches!(result, HopResult::CnameHop(_, _)));
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
+        assert!(matches!(result, HopResult::CnameHop(_, _, _)));
         assert_eq!(shard.popularity_level(domain), Some(1));
     }
 
@@ -1493,7 +1683,15 @@ mod tests {
         let now = SystemTime::now();
 
         assert_eq!(shard.popularity_level(domain), None);
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(matches!(result, HopResult::NoData(_)));
         assert_eq!(shard.popularity_level(domain), Some(1));
     }
@@ -1510,7 +1708,15 @@ mod tests {
         let now = SystemTime::now();
 
         assert_eq!(shard.popularity_level(domain), None);
-        let result = shard.lookup_hop(domain, A_QTYPE, IN_QCLASS, false, 1, now);
+        let result = shard.lookup_hop(
+            domain,
+            A_QTYPE,
+            IN_QCLASS,
+            false,
+            1,
+            now,
+            &test_refresh_config(),
+        );
         assert!(matches!(result, HopResult::NxDomain(_)));
         assert_eq!(shard.popularity_level(domain), Some(1));
     }
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 47285b5..2dc4f71 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -3549,6 +3549,24 @@ struct CacheProbe {
     event_cache_result: Option<QueryEventCacheResult>,
 }
 
+/// One background refresh attempt: a domain/qtype/qclass to refetch and
+/// re-store before its cached entry actually expires. Built from a
+/// `RefreshHint` at enqueue time (`ResolveQuery::probe_cache`); consumed by
+/// the worker pool (section-05) and processed by job-processing logic
+/// (section-06). `pub`, not `pub(crate)`: `main.rs` is a separate binary
+/// crate and needs to name this type to construct the channel
+/// (`with_refresh_sender`) once the worker pool exists.
+///
+/// Fields are inert (never read) until section-06's job-processing logic
+/// consumes them — `#[allow(dead_code)]` until then.
+#[allow(dead_code)]
+#[derive(Debug, Clone)]
+pub struct RefreshJob {
+    domain: String,
+    qtype: u16,
+    qclass: u16,
+}
+
 pub struct ResolveQuery {
     protocol: Arc<dyn ProtocolCodec>,
     policy: Arc<dyn PolicyEvaluator>,
@@ -3591,6 +3609,23 @@ pub struct ResolveQuery {
     // every existing test call site. `main.rs` overrides it with a real,
     // process-lifetime secret once available.
     cookie_secret: Arc<CookieSecret>,
+    // Not part of any constructor's parameter list by default (defaults to
+    // `RefreshConfig::default()`) -- same reasoning as `max_chain_depth`/
+    // `chaos`/`cookie_secret` above. Threaded into every `self.cache.lookup_chain(...)`
+    // call so `Shard::lookup_hop` (via `resolve_from_cache`) can compute the
+    // auto-refresh trigger formula (`docs/plans/auto_refresh/`) with real
+    // thresholds instead of a hardcoded default. `main.rs` overrides it via
+    // `with_refresh_config` once real config is available.
+    refresh_config: crate::config::RefreshConfig,
+    // Non-blocking enqueue point for background refresh jobs
+    // (`docs/plans/auto_refresh/claude-plan.md` §4.1). Every constructor
+    // defaults this to a sender whose paired receiver has already been
+    // dropped, so any enqueue attempt in an existing test (none currently
+    // configure a hot popularity bucket) simply counts as a dropped job
+    // (`ResolverMetric::RefreshQueueFull`) rather than panicking or
+    // blocking. `main.rs` overrides this via `with_refresh_sender` once the
+    // real worker pool's channel exists (section-05).
+    refresh_sender: tokio::sync::mpsc::Sender<RefreshJob>,
 }
 
 impl ResolveQuery {
@@ -3706,6 +3741,7 @@ impl ResolveQuery {
         metrics: Arc<dyn MetricsSink>,
     ) -> Self {
         metrics.record_backend_status(&backend_snapshot.status());
+        let (refresh_sender, _dropped_refresh_receiver) = tokio::sync::mpsc::channel(1);
         Self {
             protocol,
             policy,
@@ -3723,6 +3759,8 @@ impl ResolveQuery {
             metrics,
             chaos: crate::config::ChaosConfig::default(),
             cookie_secret: Arc::new(CookieSecret::generate()),
+            refresh_config: crate::config::RefreshConfig::default(),
+            refresh_sender,
         }
     }
 
@@ -3870,6 +3908,26 @@ impl ResolveQuery {
         self
     }
 
+    /// Overrides the default `RefreshConfig` set by every constructor.
+    /// `main.rs` calls this with the real `[refresh]` config once available
+    /// -- see `ResolveQuery.refresh_config`'s doc comment for why this is a
+    /// post-construction override rather than a parameter threaded through
+    /// every `with_cache*` constructor.
+    pub fn with_refresh_config(mut self, refresh_config: crate::config::RefreshConfig) -> Self {
+        self.refresh_config = refresh_config;
+        self
+    }
+
+    /// Wires the auto-refresh job sender into this resolver. Left at its
+    /// default (a sender whose receiver has already been dropped) when
+    /// `RefreshConfig::enabled` is `false`, or before the worker pool
+    /// (section-05) exists -- see `ResolveQuery.refresh_sender`'s doc
+    /// comment.
+    pub fn with_refresh_sender(mut self, sender: tokio::sync::mpsc::Sender<RefreshJob>) -> Self {
+        self.refresh_sender = sender;
+        self
+    }
+
     /// Overrides the default `ShardedSingleFlight` shard count set by
     /// every constructor. `main.rs` calls this with the real
     /// `ShardedDnsCache`'s own `shard_count()` once both are constructed,
@@ -3920,6 +3978,7 @@ impl ResolveQuery {
         metrics: Arc<dyn MetricsSink>,
     ) -> Self {
         metrics.record_backend_status(&backend_handle.status());
+        let (refresh_sender, _dropped_refresh_receiver) = tokio::sync::mpsc::channel(1);
         Self {
             protocol,
             policy,
@@ -3937,6 +3996,8 @@ impl ResolveQuery {
             metrics,
             chaos: crate::config::ChaosConfig::default(),
             cookie_secret: Arc::new(CookieSecret::generate()),
+            refresh_config: crate::config::RefreshConfig::default(),
+            refresh_sender,
         }
     }
 
@@ -4685,9 +4746,13 @@ impl ResolveQuery {
             epoch,
             self.max_chain_depth,
             request.received_at.0,
+            &self.refresh_config,
         );
-        let (store_allowed, hit, event_cache_result) =
+        let (store_allowed, hit, event_cache_result, refresh_hints) =
             self.evaluate_cache_lookup(lookup, decoded, request);
+        for hint in refresh_hints {
+            self.enqueue_refresh_job(hint);
+        }
 
         // The DO dimension of `MissKey` only needs to distinguish backend
         // fetches that can genuinely differ. The forwarding backend still
@@ -4743,12 +4808,23 @@ impl ResolveQuery {
         lookup: ChainLookup,
         decoded: &DecodedQuery,
         request: &ResolveRequest,
-    ) -> (bool, Option<Vec<u8>>, QueryEventCacheResult) {
+    ) -> (
+        bool,
+        Option<Vec<u8>>,
+        QueryEventCacheResult,
+        Vec<cache::RefreshHint>,
+    ) {
         match lookup {
             ChainLookup::Answered(resolved) => {
+                let refresh_hints = resolved.refresh_hints.clone();
                 let response_bytes = self.serialize_cache_hit_answer(decoded, &resolved, request);
                 self.record_cache_hit_metrics(&response_bytes, false);
-                (false, Some(response_bytes), QueryEventCacheResult::Hit)
+                (
+                    false,
+                    Some(response_bytes),
+                    QueryEventCacheResult::Hit,
+                    refresh_hints,
+                )
             }
             ChainLookup::NxDomain(resolved) => {
                 let response_bytes = self.serialize_cache_hit_negative(
@@ -4758,7 +4834,12 @@ impl ResolveQuery {
                     request,
                 );
                 self.record_cache_hit_metrics(&response_bytes, true);
-                (false, Some(response_bytes), QueryEventCacheResult::Hit)
+                (
+                    false,
+                    Some(response_bytes),
+                    QueryEventCacheResult::Hit,
+                    Vec::new(),
+                )
             }
             ChainLookup::NoData(resolved) => {
                 let response_bytes = self.serialize_cache_hit_negative(
@@ -4768,15 +4849,38 @@ impl ResolveQuery {
                     request,
                 );
                 self.record_cache_hit_metrics(&response_bytes, true);
-                (false, Some(response_bytes), QueryEventCacheResult::Hit)
+                (
+                    false,
+                    Some(response_bytes),
+                    QueryEventCacheResult::Hit,
+                    Vec::new(),
+                )
             }
             ChainLookup::Miss => {
                 self.metrics.increment(ResolverMetric::CacheMiss);
-                (true, None, QueryEventCacheResult::Miss)
+                (true, None, QueryEventCacheResult::Miss, Vec::new())
             }
         }
     }
 
+    /// Non-blocking, best-effort enqueue: a full (or closed, e.g. no
+    /// worker pool wired up yet) channel counts as a dropped trigger
+    /// (`RefreshQueueFull`), never blocks, never panics. Applies
+    /// independently per hint — one drop from a multi-hop chain doesn't
+    /// affect the others, each already enqueued in its own loop iteration
+    /// by the caller.
+    fn enqueue_refresh_job(&self, hint: cache::RefreshHint) {
+        let job = RefreshJob {
+            domain: hint.domain,
+            qtype: hint.qtype,
+            qclass: hint.qclass,
+        };
+        match self.refresh_sender.try_send(job) {
+            Ok(()) => self.metrics.increment(ResolverMetric::RefreshTriggered),
+            Err(_) => self.metrics.increment(ResolverMetric::RefreshQueueFull),
+        }
+    }
+
     fn record_cache_hit_metrics(&self, response_bytes: &[u8], negative: bool) {
         self.metrics.increment(ResolverMetric::CacheHit);
         if negative {
@@ -4844,6 +4948,7 @@ impl ResolveQuery {
             epoch,
             self.max_chain_depth,
             request.received_at.0,
+            &self.refresh_config,
         );
         match lookup {
             ChainLookup::Answered(resolved) => {
@@ -6175,6 +6280,7 @@ impl DomainDnsCache for NoopDnsCache {
         _epoch: u64,
         _max_chain_depth: u8,
         _now: SystemTime,
+        _refresh_config: &crate::config::RefreshConfig,
     ) -> ChainLookup {
         ChainLookup::Miss
     }
@@ -8148,6 +8254,17 @@ pub enum ResolverMetric {
     CacheMissQueryDuration,
     ProtocolError,
     RecursionRefused,
+    /// A hot, near-expiry entry was seen and a `RefreshJob` was enqueued
+    /// (`docs/plans/auto_refresh/`). Pulled forward from section-05's
+    /// scope: needed here since section-04's enqueue path must compile,
+    /// even though the worker pool that consumes these jobs doesn't exist
+    /// yet.
+    RefreshTriggered,
+    /// A refresh trigger fired but the channel was full (or, before
+    /// section-05's worker pool exists, always — every `ResolveQuery` has
+    /// no live receiver until `main.rs` wires one up), so the job was
+    /// dropped. Best-effort by design; no correctness impact.
+    RefreshQueueFull,
 }
 
 #[cfg(test)]
@@ -9824,6 +9941,86 @@ mod tests {
         }
     }
 
+    // Job enqueue tests: section-04-chainlookup-plumbing (`claude-plan-tdd.md` §4.1).
+
+    fn resolver_for_enqueue_tests(metrics: Arc<RecordingMetrics>) -> ResolveQuery {
+        ResolveQuery::new(
+            Arc::new(StandardProtocolCodec::new(1232)),
+            Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout))),
+            Arc::new(BasicResponseFactory),
+            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
+            Arc::new(RecordingEvents::default()),
+            metrics,
+        )
+    }
+
+    fn test_refresh_hint(domain: &str) -> cache::RefreshHint {
+        cache::RefreshHint {
+            domain: domain.to_string(),
+            qtype: 1,
+            qclass: 1,
+        }
+    }
+
+    #[tokio::test]
+    async fn enqueue_try_send_succeeds_under_capacity() {
+        let metrics = Arc::new(RecordingMetrics::default());
+        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
+        let resolver = resolver_for_enqueue_tests(metrics.clone()).with_refresh_sender(sender);
+
+        resolver.enqueue_refresh_job(test_refresh_hint("hot.example.com"));
+
+        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 1);
+        assert_eq!(metrics.count(ResolverMetric::RefreshQueueFull), 0);
+        let job = receiver.try_recv().expect("job should be enqueued");
+        assert_eq!(job.domain, "hot.example.com");
+    }
+
+    #[tokio::test]
+    async fn enqueue_drops_and_counts_on_full_channel() {
+        let metrics = Arc::new(RecordingMetrics::default());
+        // Capacity 1, pre-filled, so the next try_send is guaranteed to see
+        // a full channel.
+        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
+        sender
+            .try_send(RefreshJob {
+                domain: "already-queued.example.com".to_string(),
+                qtype: 1,
+                qclass: 1,
+            })
+            .unwrap();
+        let resolver = resolver_for_enqueue_tests(metrics.clone()).with_refresh_sender(sender);
+
+        resolver.enqueue_refresh_job(test_refresh_hint("dropped.example.com"));
+
+        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 0);
+        assert_eq!(metrics.count(ResolverMetric::RefreshQueueFull), 1);
+        // The channel still only has the pre-filled job -- the dropped one
+        // never made it in, and nothing panicked or blocked.
+        let job = receiver.try_recv().expect("pre-filled job still present");
+        assert_eq!(job.domain, "already-queued.example.com");
+        assert!(receiver.try_recv().is_err());
+    }
+
+    #[tokio::test]
+    async fn enqueue_per_hint_independent() {
+        let metrics = Arc::new(RecordingMetrics::default());
+        // Capacity 1, pre-filled, so exactly one of the two hints below
+        // finds room and the other is dropped -- independently.
+        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
+        let resolver = resolver_for_enqueue_tests(metrics.clone()).with_refresh_sender(sender);
+
+        resolver.enqueue_refresh_job(test_refresh_hint("first.example.com"));
+        resolver.enqueue_refresh_job(test_refresh_hint("second.example.com"));
+
+        assert_eq!(metrics.count(ResolverMetric::RefreshTriggered), 1);
+        assert_eq!(metrics.count(ResolverMetric::RefreshQueueFull), 1);
+        let job = receiver
+            .try_recv()
+            .expect("first hint should have been enqueued");
+        assert_eq!(job.domain, "first.example.com");
+    }
+
     struct ClientScopedResponsePolicy {
         client_ip: IpAddr,
         domain: DomainSelector,
@@ -10128,6 +10325,7 @@ mod tests {
             _epoch: u64,
             _max_chain_depth: u8,
             _now: SystemTime,
+            _refresh_config: &crate::config::RefreshConfig,
         ) -> ChainLookup {
             self.lookups
                 .lock()
@@ -15907,6 +16105,7 @@ mod tests {
             _epoch: u64,
             _max_chain_depth: u8,
             _now: SystemTime,
+            _refresh_config: &crate::config::RefreshConfig,
         ) -> ChainLookup {
             ChainLookup::Miss
         }
@@ -16881,6 +17080,7 @@ mod tests {
         };
         let resolved = cache::ResolvedAnswer {
             chain: vec![("example.com".to_string(), entry)],
+            refresh_hints: Vec::new(),
         };
         let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
@@ -19704,6 +19904,7 @@ mod tests {
         let entry = seed_rrset_entry(&record, Duration::from_secs(60), now, 0);
         let resolved = cache::ResolvedAnswer {
             chain: vec![("example.com".to_string(), entry)],
+            refresh_hints: Vec::new(),
         };
         let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
@@ -19805,6 +20006,7 @@ mod tests {
         let entry = seed_rrset_entry(&record, Duration::from_secs(60), now, 0);
         let resolved = cache::ResolvedAnswer {
             chain: vec![("example.com".to_string(), entry)],
+            refresh_hints: Vec::new(),
         };
         let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
@@ -19849,6 +20051,7 @@ mod tests {
         let entry = seed_rrset_entry(&record, Duration::from_secs(60), now, 0);
         let resolved = cache::ResolvedAnswer {
             chain: vec![("example.com".to_string(), entry)],
+            refresh_hints: Vec::new(),
         };
         let cache = Arc::new(RecordingCache::with_lookup(ChainLookup::Answered(resolved)));
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
diff --git a/tests/cache_concurrency_bench.rs b/tests/cache_concurrency_bench.rs
index 7a78ad4..9bd8a52 100644
--- a/tests/cache_concurrency_bench.rs
+++ b/tests/cache_concurrency_bench.rs
@@ -33,7 +33,7 @@ use std::sync::Arc;
 use std::thread;
 use std::time::{Duration, Instant, SystemTime};
 
-use rdns::config::CacheConfig;
+use rdns::config::{CacheConfig, RefreshConfig};
 use rdns::protocol::{RecordData, ResponseCode};
 use rdns::resolver::{
     DecomposedResponse, DomainDnsCache, RRsetEntry, ShardedDnsCache, StoredRecord,
@@ -101,6 +101,7 @@ fn run_workload(cache: &ShardedDnsCache, domains: &[String], operation_count: us
                 CACHE_EPOCH,
                 MAX_CHAIN_DEPTH,
                 now,
+                &RefreshConfig::default(),
             );
         }
     }
