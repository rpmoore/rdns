diff --git a/src/main.rs b/src/main.rs
index b64eac5..0a986e7 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -31,13 +31,13 @@ use rdns::delivery::metrics_http::MetricsServer;
 use rdns::delivery::upstream::{ForwardingResolutionBackend, RecursiveAuthorityTransportClient};
 use rdns::resolver::{
     BackendHealth, BackendRootHintsStatus, BackendSnapshot, BackendStatus, BasicResponseFactory,
-    CacheTtlPolicy, ChannelQueryEventSink, Clock, DnssecValidationStatus, DomainDnsCache,
-    DomainName, InMemoryLocalDnsEntries, InMemoryQueryEventStore, InMemoryQueryEventStoreConfig,
-    InMemorySuspiciousLookupClassifier, InMemorySuspiciousLookupClassifierConfig, LocalDnsEntry,
-    MetricsSink, NoopPolicyEvaluator, QueryEventRecordResult, QueryEventSink, QueryEventV1,
-    RecursiveResolutionBackend, RecursiveResolverConfig, RecursiveRootHint,
-    ResolutionMode as ResolverResolutionMode, ResolveQuery, ResolverMetric, ShardedDnsCache,
-    StandardProtocolCodec, SystemClock,
+    CacheTtlPolicy, ChannelQueryEventSink, Clock, CookieSecret, DnssecValidationStatus,
+    DomainDnsCache, DomainName, InMemoryLocalDnsEntries, InMemoryQueryEventStore,
+    InMemoryQueryEventStoreConfig, InMemorySuspiciousLookupClassifier,
+    InMemorySuspiciousLookupClassifierConfig, LocalDnsEntry, MetricsSink, NoopPolicyEvaluator,
+    QueryEventRecordResult, QueryEventSink, QueryEventV1, RecursiveResolutionBackend,
+    RecursiveResolverConfig, RecursiveRootHint, ResolutionMode as ResolverResolutionMode,
+    ResolveQuery, ResolverMetric, ShardedDnsCache, StandardProtocolCodec, SystemClock,
 };
 use tokio::task::{JoinError, JoinSet};
 use tracing::{error, info, warn};
@@ -127,6 +127,7 @@ async fn main() -> io::Result<()> {
         .map(|recursive| recursive.max_cname_restarts)
         .unwrap_or(8);
     let clock: Arc<dyn Clock> = Arc::new(SystemClock);
+    let cookie_secret = Arc::new(CookieSecret::generate());
     let resolver = Arc::new(
         ResolveQuery::with_cache_policy_and_backend_snapshot(
             Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
@@ -145,7 +146,8 @@ async fn main() -> io::Result<()> {
         )
         .with_max_chain_depth(max_chain_depth)
         .with_single_flight_shard_count(cache.shard_count())
-        .with_chaos_config(config.chaos.clone()),
+        .with_chaos_config(config.chaos.clone())
+        .with_cookie_secret(cookie_secret),
     );
 
     let sighup_task =
diff --git a/src/protocol/edns_cookie.rs b/src/protocol/edns_cookie.rs
index 2aac046..60295c7 100644
--- a/src/protocol/edns_cookie.rs
+++ b/src/protocol/edns_cookie.rs
@@ -36,7 +36,11 @@ const COOKIE_OPTION_CODE: u16 = 10;
 
 /// The 8-byte client cookie extracted from an incoming query's COOKIE
 /// option.
-pub(crate) type ClientCookie = [u8; 8];
+///
+/// `pub`, not `pub(crate)`: it appears in `QueryFeatures.client_cookie`, a
+/// public field on a public struct, so it must be nameable from outside
+/// this crate too.
+pub type ClientCookie = [u8; 8];
 
 /// The resolver's one random, process-lifetime server-cookie secret
 /// (RFC 9018 §4.2: SHOULD be >= 128 bits). Constructed once at process
@@ -44,17 +48,24 @@ pub(crate) type ClientCookie = [u8; 8];
 /// side-effect-holding value. Held behind an `Arc<CookieSecret>` at call
 /// sites that need it, exactly like `Arc<dyn Clock>`.
 ///
+/// `pub`, not `pub(crate)`: `src/main.rs` (a separate binary crate) must
+/// construct one via `generate()` and hand it to
+/// `ResolveQuery::with_cookie_secret`, mirroring how it constructs
+/// `SystemClock` -- re-exported at `crate::resolver::CookieSecret` for that
+/// call site. Every other item in this module stays `pub(crate)`: nothing
+/// else needs to cross the crate boundary.
+///
 /// Deliberately does not derive/implement `Debug`, `Display`, or
 /// `Serialize` -- doing so would risk printing or serializing the raw
 /// secret bytes.
-pub(crate) struct CookieSecret {
+pub struct CookieSecret {
     bytes: [u8; 16],
 }
 
 impl CookieSecret {
     /// Generates a fresh, CSPRNG-backed secret. Called exactly once, in
     /// `src/main.rs`, alongside where `SystemClock` is constructed.
-    pub(crate) fn generate() -> Self {
+    pub fn generate() -> Self {
         let mut bytes = [0u8; 16];
         rand::rng().fill_bytes(&mut bytes);
         CookieSecret { bytes }
diff --git a/src/resolver/cache/assemble.rs b/src/resolver/cache/assemble.rs
index 6ed4f51..cbeb8f9 100644
--- a/src/resolver/cache/assemble.rs
+++ b/src/resolver/cache/assemble.rs
@@ -30,11 +30,13 @@
 #![allow(dead_code)]
 
 use std::collections::HashSet;
+use std::net::IpAddr;
 use std::time::{Duration, SystemTime};
 
+use crate::protocol::edns_cookie::{CookieSecret, build_cookie_option, build_server_cookie};
 use crate::protocol::{
-    NameCompressor, Record, ResponseCode, build_truncated_wire_response, write_message_header,
-    write_opt_record, write_record,
+    NameCompressor, Record, RecordData, ResponseCode, build_truncated_wire_response,
+    write_message_header, write_opt_record, write_record,
 };
 use crate::resolver::QueryFeatures;
 
@@ -437,22 +439,39 @@ fn negative_dnssec_ad_bit(
 fn requester_opt_record(
     requester_features: &QueryFeatures,
     configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
+    now: SystemTime,
 ) -> Option<Record> {
     requester_features.edns_udp_payload_size?;
     let udp_payload_size = configured_max_udp_payload_size.min(u16::MAX as usize) as u16;
-    Some(crate::protocol::build_opt_record(
-        udp_payload_size,
-        requester_features.dnssec_ok,
-    ))
+    let mut opt = crate::protocol::build_opt_record(udp_payload_size, requester_features.dnssec_ok);
+    if let Some(client_cookie) = requester_features.client_cookie {
+        let server_cookie = build_server_cookie(cookie_secret, client_cookie, client_ip, now);
+        if let RecordData::OPT(ref mut edns) = opt.record {
+            edns.options = build_cookie_option(client_cookie, server_cookie);
+        }
+    }
+    Some(opt)
 }
 
+#[allow(clippy::too_many_arguments)]
 fn build_servfail(
     request_id: u16,
     requester_question_wire: &[u8],
     requester_features: &QueryFeatures,
     configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
+    now: SystemTime,
 ) -> Vec<u8> {
-    let opt = requester_opt_record(requester_features, configured_max_udp_payload_size);
+    let opt = requester_opt_record(
+        requester_features,
+        configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
+    );
     let mut response = Vec::new();
     write_message_header(
         &mut response,
@@ -510,6 +529,9 @@ fn finish_with_truncation_check(
     authoritative: bool,
     allow_udp_truncation: bool,
     configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
+    now: SystemTime,
 ) -> Vec<u8> {
     if !allow_udp_truncation {
         return response;
@@ -524,7 +546,13 @@ fn finish_with_truncation_check(
     if response.len() <= effective {
         return response;
     }
-    let opt = requester_opt_record(requester_features, configured_max_udp_payload_size);
+    let opt = requester_opt_record(
+        requester_features,
+        configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
+    );
     build_truncated_wire_response(
         request_id,
         requester_features.recursion_desired,
@@ -543,6 +571,7 @@ fn finish_with_truncation_check(
 /// plan's literal signature — `QueryFeatures` carries no transaction ID,
 /// so it must be threaded through explicitly (mirrors the
 /// `configured_max_udp_payload_size` deviation above).
+#[allow(clippy::too_many_arguments)]
 pub(crate) fn assemble_response(
     request_id: u16,
     requester_question_wire: &[u8],
@@ -551,6 +580,8 @@ pub(crate) fn assemble_response(
     now: SystemTime,
     allow_udp_truncation: bool,
     configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
 ) -> Vec<u8> {
     if dnssec_servfail_check(&resolved.chain, requester_features) {
         return build_servfail(
@@ -558,6 +589,9 @@ pub(crate) fn assemble_response(
             requester_question_wire,
             requester_features,
             configured_max_udp_payload_size,
+            cookie_secret,
+            client_ip,
+            now,
         );
     }
 
@@ -565,7 +599,13 @@ pub(crate) fn assemble_response(
     let ad = dnssec_ad_bit(&resolved.chain, requester_features);
     let authoritative = chain_authoritative(&resolved.chain);
     let an_count = chain_answer_count(&resolved.chain, dnssec_ok);
-    let opt = requester_opt_record(requester_features, configured_max_udp_payload_size);
+    let opt = requester_opt_record(
+        requester_features,
+        configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
+    );
 
     let mut response = Vec::new();
     write_message_header(
@@ -601,6 +641,9 @@ pub(crate) fn assemble_response(
         authoritative,
         allow_udp_truncation,
         configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
     )
 }
 
@@ -621,6 +664,8 @@ pub(crate) fn assemble_negative_response(
     now: SystemTime,
     allow_udp_truncation: bool,
     configured_max_udp_payload_size: usize,
+    cookie_secret: &CookieSecret,
+    client_ip: IpAddr,
 ) -> Vec<u8> {
     if negative_dnssec_servfail_check(&resolved.chain, &resolved.negative, requester_features) {
         return build_servfail(
@@ -628,6 +673,9 @@ pub(crate) fn assemble_negative_response(
             requester_question_wire,
             requester_features,
             configured_max_udp_payload_size,
+            cookie_secret,
+            client_ip,
+            now,
         );
     }
 
@@ -636,7 +684,13 @@ pub(crate) fn assemble_negative_response(
     let authoritative = chain_authoritative(&resolved.chain) && resolved.negative.authoritative;
     let an_count = chain_answer_count(&resolved.chain, dnssec_ok);
     let ns_count = negative_authority_count(&resolved.negative, dnssec_ok);
-    let opt = requester_opt_record(requester_features, configured_max_udp_payload_size);
+    let opt = requester_opt_record(
+        requester_features,
+        configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
+    );
 
     let mut response = Vec::new();
     write_message_header(
@@ -680,6 +734,9 @@ pub(crate) fn assemble_negative_response(
         authoritative,
         allow_udp_truncation,
         configured_max_udp_payload_size,
+        cookie_secret,
+        client_ip,
+        now,
     )
 }
 
@@ -687,15 +744,24 @@ pub(crate) fn assemble_negative_response(
 mod tests {
     use super::*;
     use crate::config::CacheConfig;
+    use crate::protocol::edns_cookie::ClientCookie;
     use crate::protocol::{Message, RecordData, write_u16};
     use crate::resolver::NegativeCacheKind;
     use crate::resolver::cache::entry::{NegativeKey, StoredRecord};
-    use std::net::Ipv4Addr;
+    use std::net::{IpAddr, Ipv4Addr};
     use std::time::Duration;
 
     const IN_QCLASS: u16 = 1;
     const A_QTYPE: u16 = 1;
 
+    fn test_cookie_secret() -> CookieSecret {
+        CookieSecret::generate()
+    }
+
+    fn test_client_ip() -> IpAddr {
+        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
+    }
+
     fn question_wire(qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
         let mut compressor = NameCompressor::new();
         let mut wire = Vec::new();
@@ -712,6 +778,29 @@ mod tests {
             checking_disabled: false,
             dnssec_ok,
             edns_udp_payload_size: None,
+            client_cookie: None,
+        }
+    }
+
+    fn features_with_cookie(client_cookie: ClientCookie) -> QueryFeatures {
+        QueryFeatures {
+            recursion_desired: true,
+            authenticated_data: false,
+            checking_disabled: false,
+            dnssec_ok: false,
+            edns_udp_payload_size: Some(1232),
+            client_cookie: Some(client_cookie),
+        }
+    }
+
+    fn features_with_edns_no_cookie() -> QueryFeatures {
+        QueryFeatures {
+            recursion_desired: true,
+            authenticated_data: false,
+            checking_disabled: false,
+            dnssec_ok: false,
+            edns_udp_payload_size: Some(1232),
+            client_cookie: None,
         }
     }
 
@@ -750,6 +839,51 @@ mod tests {
         })
     }
 
+    #[test]
+    fn requester_opt_record_attaches_server_cookie_when_client_cookie_present() {
+        let client_cookie: ClientCookie = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
+        let features = features_with_cookie(client_cookie);
+        let secret = test_cookie_secret();
+        let client_ip = test_client_ip();
+        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
+
+        let record = requester_opt_record(&features, 4096, &secret, client_ip, now)
+            .expect("edns_udp_payload_size is set, so a record must be returned");
+
+        let RecordData::OPT(edns) = &record.record else {
+            panic!("expected an OPT record");
+        };
+        assert_eq!(
+            &edns.options[0..2],
+            &10u16.to_be_bytes(),
+            "COOKIE option code"
+        );
+        assert_eq!(&edns.options[2..4], &24u16.to_be_bytes(), "length: 8 + 16");
+        assert_eq!(&edns.options[4..12], &client_cookie);
+        let expected_server_cookie = build_server_cookie(&secret, client_cookie, client_ip, now);
+        assert_eq!(&edns.options[12..28], &expected_server_cookie);
+    }
+
+    /// Regression test: a non-Cookie request's OPT record must stay
+    /// byte-for-byte identical to pre-cookie-support behavior (empty
+    /// options), same as `assemble_response_includes_opt_record_when_requester_used_edns`
+    /// pins at a higher level.
+    #[test]
+    fn requester_opt_record_omits_options_when_no_client_cookie() {
+        let features = features_with_edns_no_cookie();
+        let secret = test_cookie_secret();
+        let client_ip = test_client_ip();
+        let now = SystemTime::UNIX_EPOCH;
+
+        let record = requester_opt_record(&features, 4096, &secret, client_ip, now)
+            .expect("edns_udp_payload_size is set, so a record must be returned");
+
+        let RecordData::OPT(edns) = &record.record else {
+            panic!("expected an OPT record");
+        };
+        assert!(edns.options.is_empty());
+    }
+
     #[test]
     fn assemble_response_ages_each_record_ttl_independently() {
         let now = SystemTime::now();
@@ -765,7 +899,17 @@ mod tests {
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
 
-        let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
+        let response = assemble_response(
+            1,
+            &wire,
+            &features(false),
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         let parsed = Message::parse(&response).unwrap();
 
         assert_eq!(parsed.answers.len(), 2);
@@ -784,7 +928,17 @@ mod tests {
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
 
-        let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
+        let response = assemble_response(
+            1,
+            &wire,
+            &features(false),
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         let parsed = Message::parse(&response).unwrap();
 
         // Aged TTL would be 10s, remaining lifetime is also 10s: capped, not
@@ -811,7 +965,17 @@ mod tests {
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
 
-        let response = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
+        let response = assemble_response(
+            1,
+            &wire,
+            &features(false),
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         let parsed = Message::parse(&response).unwrap();
 
         // Even though the entry is still servable for ~25 more seconds
@@ -840,6 +1004,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let mixed_response = assemble_response(
             1,
@@ -849,6 +1015,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
 
         let lower_parsed = Message::parse(&lower_response).unwrap();
@@ -870,7 +1038,17 @@ mod tests {
 
         let mut udp_features = features(false);
         udp_features.edns_udp_payload_size = Some(512);
-        let udp_response = assemble_response(1, &wire, &udp_features, &resolved, now, true, 4096);
+        let udp_response = assemble_response(
+            1,
+            &wire,
+            &udp_features,
+            &resolved,
+            now,
+            true,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         let udp_parsed = Message::parse(&udp_response).unwrap();
         assert!(udp_parsed.header.tc());
         assert_eq!(udp_parsed.answers.len(), 0);
@@ -883,7 +1061,17 @@ mod tests {
 
         // TCP-sourced queries pass allow_udp_truncation = false: full
         // response regardless of size.
-        let tcp_response = assemble_response(1, &wire, &udp_features, &resolved, now, false, 4096);
+        let tcp_response = assemble_response(
+            1,
+            &wire,
+            &udp_features,
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         let tcp_parsed = Message::parse(&tcp_response).unwrap();
         assert!(!tcp_parsed.header.tc());
         assert_eq!(tcp_parsed.answers.len(), 40);
@@ -912,7 +1100,17 @@ mod tests {
         let mut edns_features = features(false);
         edns_features.edns_udp_payload_size = Some(4096);
 
-        let response = assemble_response(1, &wire, &edns_features, &resolved, now, false, 700);
+        let response = assemble_response(
+            1,
+            &wire,
+            &edns_features,
+            &resolved,
+            now,
+            false,
+            700,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         let parsed = Message::parse(&response).unwrap();
 
         assert_eq!(
@@ -930,8 +1128,17 @@ mod tests {
         assert!(!edns.dnssec_ok);
 
         // A requester with no EDNS at all must not get an OPT record back.
-        let no_edns_response =
-            assemble_response(1, &wire, &features(false), &resolved, now, false, 700);
+        let no_edns_response = assemble_response(
+            1,
+            &wire,
+            &features(false),
+            &resolved,
+            now,
+            false,
+            700,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         let no_edns_parsed = Message::parse(&no_edns_response).unwrap();
         assert_eq!(no_edns_parsed.header.ar_count, 0);
         assert!(no_edns_parsed.edns.is_none());
@@ -961,6 +1168,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             Message::parse(&aa_response).unwrap().header.aa(),
@@ -981,6 +1190,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             !Message::parse(&no_aa_response).unwrap().header.aa(),
@@ -1018,6 +1229,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             !Message::parse(&mixed_response).unwrap().header.aa(),
@@ -1040,14 +1253,33 @@ mod tests {
 
         let mut cd_features = features(false);
         cd_features.checking_disabled = true;
-        let cd_response = assemble_response(1, &wire, &cd_features, &resolved, now, false, 4096);
+        let cd_response = assemble_response(
+            1,
+            &wire,
+            &cd_features,
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         assert!(
             Message::parse(&cd_response).unwrap().header.cd(),
             "CD=1 on the query must produce CD=1 on the response"
         );
 
-        let no_cd_response =
-            assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
+        let no_cd_response = assemble_response(
+            1,
+            &wire,
+            &features(false),
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         assert!(
             !Message::parse(&no_cd_response).unwrap().header.cd(),
             "CD=0 on the query must produce CD=0 on the response"
@@ -1079,8 +1311,28 @@ mod tests {
         };
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
 
-        let without_do = assemble_response(1, &wire, &features(false), &resolved, now, false, 4096);
-        let with_do = assemble_response(1, &wire, &features(true), &resolved, now, false, 4096);
+        let without_do = assemble_response(
+            1,
+            &wire,
+            &features(false),
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
+        let with_do = assemble_response(
+            1,
+            &wire,
+            &features(true),
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
 
         assert_eq!(Message::parse(&without_do).unwrap().answers.len(), 1);
         assert_eq!(Message::parse(&with_do).unwrap().answers.len(), 2);
@@ -1097,12 +1349,31 @@ mod tests {
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
 
         let mut do_features = features(true);
-        let with_do = assemble_response(1, &wire, &do_features, &resolved, now, false, 4096);
+        let with_do = assemble_response(
+            1,
+            &wire,
+            &do_features,
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         assert!(Message::parse(&with_do).unwrap().header.ad());
 
         do_features.dnssec_ok = false;
-        let without_do_or_ad =
-            assemble_response(1, &wire, &do_features, &resolved, now, false, 4096);
+        let without_do_or_ad = assemble_response(
+            1,
+            &wire,
+            &do_features,
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         assert!(!Message::parse(&without_do_or_ad).unwrap().header.ad());
 
         // Unvalidated never produces AD=1 regardless of requester flags.
@@ -1120,6 +1391,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(!Message::parse(&unvalidated_response).unwrap().header.ad());
     }
@@ -1135,8 +1408,17 @@ mod tests {
         let wire = question_wire("example.com", A_QTYPE, IN_QCLASS);
 
         let checking_enabled = features(false);
-        let servfail_response =
-            assemble_response(1, &wire, &checking_enabled, &resolved, now, false, 4096);
+        let servfail_response = assemble_response(
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
         let servfail_parsed = Message::parse(&servfail_response).unwrap();
         assert_eq!(
             servfail_parsed.header.r_code(),
@@ -1146,8 +1428,17 @@ mod tests {
 
         let mut checking_disabled = features(false);
         checking_disabled.checking_disabled = true;
-        let served_response =
-            assemble_response(1, &wire, &checking_disabled, &resolved, now, false, 4096);
+        let served_response = assemble_response(
+            1,
+            &wire,
+            &checking_disabled,
+            &resolved,
+            now,
+            false,
+            4096,
+            &test_cookie_secret(),
+            test_client_ip(),
+        );
         let served_parsed = Message::parse(&served_response).unwrap();
         assert_eq!(served_parsed.header.r_code(), ResponseCode::NoError as u8);
         assert_eq!(served_parsed.answers.len(), 1);
@@ -1222,6 +1513,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let parsed = Message::parse(&nxdomain_response).unwrap();
         assert_eq!(parsed.header.r_code(), ResponseCode::NxDomain as u8);
@@ -1238,6 +1531,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert_eq!(
             Message::parse(&nodata_response).unwrap().header.r_code(),
@@ -1276,6 +1571,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let servfail_parsed = Message::parse(&servfail_response).unwrap();
         assert_eq!(
@@ -1296,6 +1593,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let served_parsed = Message::parse(&served_response).unwrap();
         assert_eq!(
@@ -1330,6 +1629,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let servfail_parsed = Message::parse(&servfail_response).unwrap();
         assert_eq!(
@@ -1350,6 +1651,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let served_parsed = Message::parse(&served_response).unwrap();
         assert_eq!(
@@ -1388,6 +1691,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let parsed = Message::parse(&response).unwrap();
 
@@ -1479,6 +1784,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let parsed = Message::parse(&response).unwrap();
 
@@ -1588,6 +1895,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let without_do_parsed = Message::parse(&without_do).unwrap();
         assert_eq!(
@@ -1610,6 +1919,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let with_do_parsed = Message::parse(&with_do).unwrap();
         assert_eq!(with_do_parsed.answers.len(), 1);
@@ -1658,6 +1969,8 @@ mod tests {
             now,
             true,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let parsed = Message::parse(&response).unwrap();
 
@@ -1708,6 +2021,8 @@ mod tests {
             now,
             false,
             700,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let parsed = Message::parse(&response).unwrap();
 
@@ -1734,6 +2049,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         let no_edns_parsed = Message::parse(&no_edns_response).unwrap();
         assert_eq!(no_edns_parsed.header.ar_count, 0);
@@ -1763,6 +2080,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             Message::parse(&cd_response).unwrap().header.cd(),
@@ -1778,6 +2097,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             !Message::parse(&no_cd_response).unwrap().header.cd(),
@@ -1811,6 +2132,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             Message::parse(&with_do).unwrap().header.ad(),
@@ -1827,6 +2150,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             !Message::parse(&without_do_or_ad).unwrap().header.ad(),
@@ -1849,6 +2174,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             !Message::parse(&unvalidated_response).unwrap().header.ad(),
@@ -1886,6 +2213,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             Message::parse(&secure_chain_response).unwrap().header.ad(),
@@ -1919,6 +2248,8 @@ mod tests {
             now,
             false,
             4096,
+            &test_cookie_secret(),
+            test_client_ip(),
         );
         assert!(
             !Message::parse(&mixed_response).unwrap().header.ad(),
diff --git a/src/resolver/mod.rs b/src/resolver/mod.rs
index 56b5a06..a053ad2 100644
--- a/src/resolver/mod.rs
+++ b/src/resolver/mod.rs
@@ -28,6 +28,7 @@ use tokio::sync::mpsc;
 use tokio::task::JoinSet;
 use tokio::time::{self, Instant};
 
+use crate::protocol::edns_cookie::ClientCookie;
 use crate::protocol::{
     Message, NameCompressor, QueryDecodeFailure, QueryValidationError, Record, RecordData,
     ResponseCode, build_a_answers_response, build_a_block_response, build_aaaa_answers_response,
@@ -36,6 +37,11 @@ use crate::protocol::{
     build_servfail_response, build_txt_answer_response, message_question_wire, rewrite_response_id,
     rewrite_response_request_fields,
 };
+// Re-exported (not just used privately): `src/main.rs` is a separate
+// binary crate and must construct one via `CookieSecret::generate()` to
+// hand to `ResolveQuery::with_cookie_secret`, mirroring how it constructs
+// `SystemClock` from this same module.
+pub use crate::protocol::edns_cookie::CookieSecret;
 
 mod cache;
 use cache::{
@@ -255,6 +261,13 @@ pub struct QueryFeatures {
     pub checking_disabled: bool,
     pub dnssec_ok: bool,
     pub edns_udp_payload_size: Option<u16>,
+    /// The requester's client cookie, extracted via
+    /// `edns_cookie::parse_cookie_option` (not the stricter
+    /// `is_solely_cookie_option`, which is section-03's cache-admission-only
+    /// concern) -- a query carrying a well-formed Cookie alongside another
+    /// EDNS option still gets its cookie echoed here, even though such a
+    /// query isn't cache-admissible.
+    pub client_cookie: Option<ClientCookie>,
 }
 
 impl QueryFeatures {
@@ -269,6 +282,10 @@ impl QueryFeatures {
                 .map(|edns| edns.dnssec_ok)
                 .unwrap_or(false),
             edns_udp_payload_size: message.edns.as_ref().map(|edns| edns.udp_payload_size),
+            client_cookie: message
+                .edns
+                .as_ref()
+                .and_then(|edns| crate::protocol::edns_cookie::parse_cookie_option(&edns.options)),
         }
     }
 }
@@ -3370,6 +3387,16 @@ pub struct ResolveQuery {
     // threading yet another parameter through every `with_cache*`
     // constructor.
     chaos: crate::config::ChaosConfig,
+    // Not part of any constructor's parameter list by default (defaults to
+    // `Arc::new(CookieSecret::generate())`) -- same reasoning as
+    // `max_chain_depth`/`chaos` above: unlike `clock`, `CookieSecret` isn't
+    // a trait object the vast majority of existing tests need to
+    // substitute (they don't exercise Cookie behavior at all), so a
+    // post-construction setter (`with_cookie_secret`) avoids threading a
+    // new mandatory parameter through every `with_cache*` constructor and
+    // every existing test call site. `main.rs` overrides it with a real,
+    // process-lifetime secret once available.
+    cookie_secret: Arc<CookieSecret>,
 }
 
 impl ResolveQuery {
@@ -3501,6 +3528,7 @@ impl ResolveQuery {
             event_sequence: AtomicU64::new(0),
             metrics,
             chaos: crate::config::ChaosConfig::default(),
+            cookie_secret: Arc::new(CookieSecret::generate()),
         }
     }
 
@@ -3638,6 +3666,16 @@ impl ResolveQuery {
         self
     }
 
+    /// Overrides the default process-lifetime `CookieSecret` set by every
+    /// constructor. `main.rs` calls this with the one real secret generated
+    /// alongside `SystemClock` -- see `ResolveQuery.cookie_secret`'s doc
+    /// comment for why this is a post-construction override rather than a
+    /// parameter threaded through every `with_cache*` constructor.
+    pub fn with_cookie_secret(mut self, cookie_secret: Arc<CookieSecret>) -> Self {
+        self.cookie_secret = cookie_secret;
+        self
+    }
+
     /// Overrides the default `ShardedSingleFlight` shard count set by
     /// every constructor. `main.rs` calls this with the real
     /// `ShardedDnsCache`'s own `shard_count()` once both are constructed,
@@ -3704,6 +3742,7 @@ impl ResolveQuery {
             event_sequence: AtomicU64::new(0),
             metrics,
             chaos: crate::config::ChaosConfig::default(),
+            cookie_secret: Arc::new(CookieSecret::generate()),
         }
     }
 
@@ -4555,6 +4594,8 @@ impl ResolveQuery {
             request.received_at.0,
             !request.observed_source.is_tcp(),
             self.protocol.configured_max_udp_payload_size(),
+            &self.cookie_secret,
+            request.client_ip,
         )
     }
 
@@ -4574,6 +4615,8 @@ impl ResolveQuery {
             request.received_at.0,
             !request.observed_source.is_tcp(),
             self.protocol.configured_max_udp_payload_size(),
+            &self.cookie_secret,
+            request.client_ip,
         )
     }
 
@@ -7954,6 +7997,42 @@ mod tests {
         a_query_with_edns_options(id, name, udp_payload_size, dnssec_ok, &[])
     }
 
+    #[test]
+    fn query_features_from_message_extracts_client_cookie() {
+        let cookie_option = [
+            0u8, 10, 0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
+        ];
+        let bytes = a_query_with_edns_options(0x7777, "example.com", 1232, false, &cookie_option);
+        let message = Message::parse(&bytes).unwrap();
+
+        let features = QueryFeatures::from_message(&message);
+
+        assert_eq!(
+            features.client_cookie,
+            Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
+        );
+    }
+
+    #[test]
+    fn query_features_from_message_has_no_client_cookie_without_edns() {
+        let bytes = a_query(0x7777, "example.com");
+        let message = Message::parse(&bytes).unwrap();
+
+        let features = QueryFeatures::from_message(&message);
+
+        assert_eq!(features.client_cookie, None);
+    }
+
+    #[test]
+    fn query_features_from_message_has_no_client_cookie_when_edns_options_empty() {
+        let bytes = a_query_with_edns(0x7777, "example.com", 1232, false);
+        let message = Message::parse(&bytes).unwrap();
+
+        let features = QueryFeatures::from_message(&message);
+
+        assert_eq!(features.client_cookie, None);
+    }
+
     fn a_query_with_edns_options(
         id: u16,
         name: &str,
