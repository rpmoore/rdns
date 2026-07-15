diff --git a/src/delivery/dns.rs b/src/delivery/dns.rs
index b299272..de6401c 100644
--- a/src/delivery/dns.rs
+++ b/src/delivery/dns.rs
@@ -17,7 +17,7 @@ use std::future::Future;
 use std::io;
 use std::net::{IpAddr, SocketAddr};
 use std::sync::{Arc, Mutex};
-use std::time::{Duration, SystemTime};
+use std::time::Duration;
 
 use bytes::Bytes;
 use tokio::io::{AsyncReadExt, AsyncWriteExt};
@@ -28,7 +28,7 @@ use tokio::time;
 
 use crate::config::{DEFAULT_MAX_TCP_CONNECTIONS, RuntimeConfig};
 use crate::protocol::{DNS_HEADER_LEN, Message, build_servfail_response};
-use crate::resolver::{ObservedSourceEndpoint, ResolveQuery, ResolveRequest};
+use crate::resolver::{Clock, ObservedSourceEndpoint, ResolveQuery, ResolveRequest};
 
 const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 1024;
 /// Caps how many concurrent connections a single source IP may hold against
@@ -117,16 +117,23 @@ async fn bind_tcp_listener_socket(address: SocketAddr) -> io::Result<TcpListener
 pub struct UdpDnsServer {
     socket: Arc<UdpSocket>,
     resolver: Arc<ResolveQuery>,
+    clock: Arc<dyn Clock>,
     listener: Option<SocketAddr>,
     max_request_size: usize,
     max_in_flight_requests: usize,
 }
 
 impl UdpDnsServer {
-    pub fn new(socket: UdpSocket, resolver: Arc<ResolveQuery>, max_request_size: usize) -> Self {
+    pub fn new(
+        socket: UdpSocket,
+        resolver: Arc<ResolveQuery>,
+        clock: Arc<dyn Clock>,
+        max_request_size: usize,
+    ) -> Self {
         Self::with_max_in_flight_requests(
             socket,
             resolver,
+            clock,
             max_request_size,
             DEFAULT_MAX_IN_FLIGHT_REQUESTS,
         )
@@ -135,6 +142,7 @@ impl UdpDnsServer {
     pub fn with_max_in_flight_requests(
         socket: UdpSocket,
         resolver: Arc<ResolveQuery>,
+        clock: Arc<dyn Clock>,
         max_request_size: usize,
         max_in_flight_requests: usize,
     ) -> Self {
@@ -142,6 +150,7 @@ impl UdpDnsServer {
         Self {
             socket: Arc::new(socket),
             resolver,
+            clock,
             listener,
             max_request_size,
             max_in_flight_requests,
@@ -151,20 +160,29 @@ impl UdpDnsServer {
     pub async fn bind(
         address: SocketAddr,
         resolver: Arc<ResolveQuery>,
+        clock: Arc<dyn Clock>,
         max_request_size: usize,
     ) -> io::Result<Self> {
         let socket = bind_listener_socket(address).await?;
-        Ok(Self::new(socket, resolver, max_request_size))
+        Ok(Self::new(socket, resolver, clock, max_request_size))
     }
 
     pub async fn bind_configured(
         config: &RuntimeConfig,
         resolver: Arc<ResolveQuery>,
+        clock: Arc<dyn Clock>,
     ) -> io::Result<Vec<Self>> {
         let mut servers = Vec::with_capacity(config.dns_listen.len());
         for address in &config.dns_listen {
-            servers
-                .push(Self::bind(*address, resolver.clone(), config.max_udp_payload_size).await?);
+            servers.push(
+                Self::bind(
+                    *address,
+                    resolver.clone(),
+                    clock.clone(),
+                    config.max_udp_payload_size,
+                )
+                .await?,
+            );
         }
         Ok(servers)
     }
@@ -238,8 +256,11 @@ impl UdpDnsServer {
     fn spawn_datagram_task(&self, datagram: ReceivedDatagram, tasks: &mut JoinSet<io::Result<()>>) {
         let socket = Arc::clone(&self.socket);
         let resolver = Arc::clone(&self.resolver);
+        let clock = Arc::clone(&self.clock);
         let listener = self.listener;
-        tasks.spawn(async move { handle_datagram(socket, resolver, listener, datagram).await });
+        tasks.spawn(
+            async move { handle_datagram(socket, resolver, clock, listener, datagram).await },
+        );
     }
 }
 
@@ -252,6 +273,7 @@ struct ReceivedDatagram {
 async fn handle_datagram(
     socket: Arc<UdpSocket>,
     resolver: Arc<ResolveQuery>,
+    clock: Arc<dyn Clock>,
     listener: Option<SocketAddr>,
     datagram: ReceivedDatagram,
 ) -> io::Result<()> {
@@ -259,7 +281,7 @@ async fn handle_datagram(
     let outcome = resolver
         .resolve(ResolveRequest::new_with_observed_source(
             ObservedSourceEndpoint::udp(datagram.source, listener),
-            SystemTime::now(),
+            clock.now(),
             datagram.request_bytes,
         ))
         .await;
@@ -285,6 +307,7 @@ fn task_result_to_io(
 pub struct TcpDnsServer {
     listener: TcpListener,
     resolver: Arc<ResolveQuery>,
+    clock: Arc<dyn Clock>,
     local_addr: SocketAddr,
     max_connections: usize,
     max_connections_per_ip: usize,
@@ -292,18 +315,24 @@ pub struct TcpDnsServer {
 }
 
 impl TcpDnsServer {
-    pub async fn bind(address: SocketAddr, resolver: Arc<ResolveQuery>) -> io::Result<Self> {
-        Self::bind_with_max_connections(address, resolver, DEFAULT_MAX_TCP_CONNECTIONS).await
+    pub async fn bind(
+        address: SocketAddr,
+        resolver: Arc<ResolveQuery>,
+        clock: Arc<dyn Clock>,
+    ) -> io::Result<Self> {
+        Self::bind_with_max_connections(address, resolver, clock, DEFAULT_MAX_TCP_CONNECTIONS).await
     }
 
     pub async fn bind_with_max_connections(
         address: SocketAddr,
         resolver: Arc<ResolveQuery>,
+        clock: Arc<dyn Clock>,
         max_connections: usize,
     ) -> io::Result<Self> {
         Self::bind_with_options(
             address,
             resolver,
+            clock,
             max_connections,
             DEFAULT_MAX_TCP_CONNECTIONS_PER_IP,
             TCP_SHUTDOWN_GRACE_PERIOD,
@@ -314,6 +343,7 @@ impl TcpDnsServer {
     async fn bind_with_options(
         address: SocketAddr,
         resolver: Arc<ResolveQuery>,
+        clock: Arc<dyn Clock>,
         max_connections: usize,
         max_connections_per_ip: usize,
         shutdown_grace_period: Duration,
@@ -347,6 +377,7 @@ impl TcpDnsServer {
         Ok(Self {
             listener,
             resolver,
+            clock,
             local_addr,
             max_connections,
             max_connections_per_ip,
@@ -357,6 +388,7 @@ impl TcpDnsServer {
     pub async fn bind_configured(
         config: &RuntimeConfig,
         resolver: Arc<ResolveQuery>,
+        clock: Arc<dyn Clock>,
     ) -> io::Result<Vec<Self>> {
         let mut servers = Vec::with_capacity(config.dns_listen.len());
         let shutdown_grace_period = config.per_query_deadline + TCP_SHUTDOWN_GRACE_BUFFER;
@@ -365,6 +397,7 @@ impl TcpDnsServer {
                 Self::bind_with_options(
                     *address,
                     resolver.clone(),
+                    clock.clone(),
                     config.max_tcp_connections,
                     DEFAULT_MAX_TCP_CONNECTIONS_PER_IP,
                     shutdown_grace_period,
@@ -462,11 +495,14 @@ impl TcpDnsServer {
         tasks: &mut JoinSet<()>,
     ) {
         let resolver = Arc::clone(&self.resolver);
+        let clock = Arc::clone(&self.clock);
         let listener = self.local_addr;
         tasks.spawn(async move {
             let _permit = permit;
             let _per_ip_guard = per_ip_guard;
-            if let Err(error) = serve_tcp_connection(stream, peer_addr, listener, resolver).await {
+            if let Err(error) =
+                serve_tcp_connection(stream, peer_addr, listener, resolver, clock).await
+            {
                 tracing::debug!(%error, %peer_addr, "tcp dns connection closed with error");
             }
         });
@@ -555,6 +591,7 @@ async fn serve_tcp_connection(
     peer_addr: SocketAddr,
     listener: SocketAddr,
     resolver: Arc<ResolveQuery>,
+    clock: Arc<dyn Clock>,
 ) -> io::Result<()> {
     loop {
         let mut length_prefix = [0u8; 2];
@@ -617,7 +654,7 @@ async fn serve_tcp_connection(
         let outcome = resolver
             .resolve(ResolveRequest::new_with_observed_source(
                 ObservedSourceEndpoint::tcp(peer_addr, Some(listener)),
-                SystemTime::now(),
+                clock.now(),
                 message,
             ))
             .await;
@@ -668,7 +705,7 @@ async fn serve_tcp_connection(
 mod tests {
     use super::*;
     use std::pin::Pin;
-    use std::time::Duration;
+    use std::time::{Duration, SystemTime};
 
     use tokio::sync::Notify;
     use tokio::time;
@@ -760,6 +797,10 @@ mod tests {
         }
     }
 
+    fn test_clock() -> Arc<dyn Clock> {
+        Arc::new(FixedClock(SystemTime::UNIX_EPOCH))
+    }
+
     #[derive(Default)]
     struct RecordingEvents {
         events: Mutex<Vec<QueryEventV1>>,
@@ -883,9 +924,10 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(backend_bytes))));
         let events = Arc::new(RecordingEvents::default());
         let resolver = resolve_service(upstream.clone(), events.clone());
-        let server = UdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, 1232)
-            .await
-            .unwrap();
+        let server =
+            UdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, test_clock(), 1232)
+                .await
+                .unwrap();
         let server_addr = server.local_addr().unwrap();
         let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
         let server_task = tokio::spawn(async move {
@@ -958,7 +1000,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
 
-        let servers = UdpDnsServer::bind_configured(&config, resolver)
+        let servers = UdpDnsServer::bind_configured(&config, resolver, test_clock())
             .await
             .unwrap();
 
@@ -992,7 +1034,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(backend_bytes))));
         let events = Arc::new(RecordingEvents::default());
         let resolver = resolve_service(upstream.clone(), events.clone());
-        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
+        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, test_clock())
             .await
             .unwrap();
         let server_addr = server.local_addr().unwrap();
@@ -1043,7 +1085,7 @@ mod tests {
             "example.com",
         )))));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
-        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
+        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, test_clock())
             .await
             .unwrap();
         let server_addr = server.local_addr().unwrap();
@@ -1095,7 +1137,7 @@ mod tests {
         let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
 
-        let servers = TcpDnsServer::bind_configured(&config, resolver)
+        let servers = TcpDnsServer::bind_configured(&config, resolver, test_clock())
             .await
             .unwrap();
 
@@ -1142,6 +1184,7 @@ mod tests {
         let server = TcpDnsServer::bind_with_options(
             "127.0.0.1:0".parse().unwrap(),
             resolver,
+            test_clock(),
             10,
             2,
             Duration::from_secs(1),
@@ -1205,7 +1248,7 @@ mod tests {
         )))));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
 
-        let server = TcpDnsServer::bind_configured(&config, resolver)
+        let server = TcpDnsServer::bind_configured(&config, resolver, test_clock())
             .await
             .unwrap()
             .into_iter()
@@ -1261,7 +1304,7 @@ mod tests {
             oversized_backend_response,
         ))));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
-        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
+        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, test_clock())
             .await
             .unwrap();
         let server_addr = server.local_addr().unwrap();
@@ -1317,7 +1360,7 @@ mod tests {
         // the fallback response reflects the resolver's size, not a mirror
         // of the requester's.
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
-        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
+        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, test_clock())
             .await
             .unwrap();
         let server_addr = server.local_addr().unwrap();
@@ -1416,7 +1459,7 @@ mod tests {
             "example.com",
         )))));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
-        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
+        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, test_clock())
             .await
             .unwrap();
         let server_addr = server.local_addr().unwrap();
@@ -1464,7 +1507,7 @@ mod tests {
             oversized_a_response(0xaaaa, "example.com"),
         ))));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
-        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
+        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, test_clock())
             .await
             .unwrap();
         let server_addr = server.local_addr().unwrap();
@@ -1509,9 +1552,13 @@ mod tests {
             "example.com",
         )))));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
-        let result =
-            TcpDnsServer::bind_with_max_connections("127.0.0.1:0".parse().unwrap(), resolver, 0)
-                .await;
+        let result = TcpDnsServer::bind_with_max_connections(
+            "127.0.0.1:0".parse().unwrap(),
+            resolver,
+            test_clock(),
+            0,
+        )
+        .await;
         match result {
             Ok(_) => panic!("expected max_connections = 0 to be rejected"),
             Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
@@ -1533,6 +1580,7 @@ mod tests {
         let result = TcpDnsServer::bind_with_options(
             "127.0.0.1:0".parse().unwrap(),
             resolver,
+            test_clock(),
             10,
             0,
             Duration::from_secs(1),
@@ -1555,7 +1603,7 @@ mod tests {
             "example.com",
         )))));
         let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
-        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
+        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, test_clock())
             .await
             .unwrap();
         let server_addr = server.local_addr().unwrap();
@@ -1605,7 +1653,8 @@ mod tests {
             Arc::new(NoopMetrics),
         ));
         let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
-        let server = UdpDnsServer::with_max_in_flight_requests(socket, resolver, 1232, 2);
+        let server =
+            UdpDnsServer::with_max_in_flight_requests(socket, resolver, test_clock(), 1232, 2);
         let server_addr = server.local_addr().unwrap();
         let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
         let server_task = tokio::spawn(async move {
@@ -1653,7 +1702,8 @@ mod tests {
             Arc::new(NoopMetrics),
         ));
         let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
-        let server = UdpDnsServer::with_max_in_flight_requests(socket, resolver, 1232, 2);
+        let server =
+            UdpDnsServer::with_max_in_flight_requests(socket, resolver, test_clock(), 1232, 2);
         let server_addr = server.local_addr().unwrap();
         let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
         let mut server_task = tokio::spawn(async move {
diff --git a/src/main.rs b/src/main.rs
index a9fab18..1406ece 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -126,6 +126,7 @@ async fn main() -> io::Result<()> {
         .as_ref()
         .map(|recursive| recursive.max_cname_restarts)
         .unwrap_or(8);
+    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
     let resolver = Arc::new(
         ResolveQuery::with_cache_policy_and_backend_snapshot(
             Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
@@ -135,7 +136,7 @@ async fn main() -> io::Result<()> {
             CacheTtlPolicy::default(),
             backend_snapshot,
             Arc::new(BasicResponseFactory),
-            Arc::new(SystemClock),
+            Arc::clone(&clock),
             Arc::new(StoreRecordingQueryEventSink::new(
                 ChannelQueryEventSink::new(event_tx),
                 Arc::clone(&query_event_store),
@@ -150,7 +151,8 @@ async fn main() -> io::Result<()> {
     let sighup_task =
         spawn_sighup_reload_task(Arc::clone(&resolver), reload_metrics, config_path.clone());
 
-    let servers = UdpDnsServer::bind_configured(&config, Arc::clone(&resolver)).await?;
+    let servers =
+        UdpDnsServer::bind_configured(&config, Arc::clone(&resolver), Arc::clone(&clock)).await?;
     if servers.is_empty() {
         return Err(io::Error::other("no DNS listeners configured"));
     }
@@ -158,7 +160,8 @@ async fn main() -> io::Result<()> {
     // clients may connect over TCP directly, and a UDP response we truncate
     // (`TC=1`) is a promise that the same query will succeed over TCP, so a
     // bind failure here is as fatal as a UDP bind failure.
-    let tcp_servers = TcpDnsServer::bind_configured(&config, Arc::clone(&resolver)).await?;
+    let tcp_servers =
+        TcpDnsServer::bind_configured(&config, Arc::clone(&resolver), Arc::clone(&clock)).await?;
     // A metrics-listener bind failure (e.g. the configured port is already in
     // use by something else on the host) must not prevent the DNS resolver
     // itself from starting — metrics are optional observability, not a core
diff --git a/tests/clock_injection.rs b/tests/clock_injection.rs
new file mode 100644
index 0000000..86a74f4
--- /dev/null
+++ b/tests/clock_injection.rs
@@ -0,0 +1,238 @@
+// Copyright 2026 Ryan Moore
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Live, end-to-end regression test for Clock dependency injection
+//! (`docs/plans/ttl_remaining/` section 02). Drives the actual
+//! socket -> `handle_datagram` -> resolver -> cache -> `assemble_response`
+//! pipeline with an injected, advanceable fake clock, rather than
+//! hand-constructing `now`/`stored_at` values the way unit tests do.
+
+use std::net::SocketAddr;
+use std::sync::Arc;
+use std::sync::atomic::{AtomicU64, Ordering};
+use std::time::{Duration, SystemTime};
+
+use rdns::config::{CacheConfig, RuntimeConfig, UpstreamConfig, UpstreamProtocol};
+use rdns::delivery::dns::UdpDnsServer;
+use rdns::delivery::upstream::ForwardingResolutionBackend;
+use rdns::protocol::Message;
+use rdns::resolver::{
+    BasicResponseFactory, CacheTtlPolicy, Clock, DomainDnsCache, MetricsSink,
+    QueryEventRecordResult, QueryEventSink, QueryEventV1, ResolveQuery, ResolverMetric,
+    ShardedDnsCache, StandardProtocolCodec,
+};
+use tokio::net::UdpSocket;
+
+/// A `Clock` whose value can be advanced in place between two requests in
+/// the same test, unlike this repo's existing `FixedClock` variants (all
+/// single-value, none mutate) -- see the section-02 plan's "FixedClock
+/// precedent" note for why a fourth shape was needed here.
+struct AdvanceableClock {
+    offset_secs: AtomicU64,
+}
+
+impl AdvanceableClock {
+    fn new() -> Self {
+        Self {
+            offset_secs: AtomicU64::new(0),
+        }
+    }
+
+    fn advance(&self, secs: u64) {
+        self.offset_secs.fetch_add(secs, Ordering::SeqCst);
+    }
+}
+
+impl Clock for AdvanceableClock {
+    fn now(&self) -> SystemTime {
+        SystemTime::UNIX_EPOCH + Duration::from_secs(self.offset_secs.load(Ordering::SeqCst))
+    }
+}
+
+struct NoopEvents;
+
+impl QueryEventSink for NoopEvents {
+    fn record(&self, _event: QueryEventV1) -> QueryEventRecordResult {
+        QueryEventRecordResult::Accepted
+    }
+}
+
+struct NoopMetrics;
+
+impl MetricsSink for NoopMetrics {
+    fn increment(&self, _metric: ResolverMetric) {}
+
+    fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
+}
+
+fn a_query(id: u16, name: &str) -> Vec<u8> {
+    let mut bytes = Vec::new();
+    bytes.extend_from_slice(&id.to_be_bytes());
+    bytes.extend_from_slice(&0x0100u16.to_be_bytes());
+    bytes.extend_from_slice(&1u16.to_be_bytes());
+    bytes.extend_from_slice(&0u16.to_be_bytes());
+    bytes.extend_from_slice(&0u16.to_be_bytes());
+    bytes.extend_from_slice(&0u16.to_be_bytes());
+    for label in name.split('.') {
+        bytes.push(label.len() as u8);
+        bytes.extend_from_slice(label.as_bytes());
+    }
+    bytes.push(0);
+    bytes.extend_from_slice(&1u16.to_be_bytes());
+    bytes.extend_from_slice(&1u16.to_be_bytes());
+    bytes
+}
+
+/// A minimal, fully-parseable A response with one answer record carrying
+/// `ttl`, following the same record shape as `dns.rs`'s
+/// `oversized_a_response` test helper (name pointer to the question, TYPE=A,
+/// CLASS=IN, 4-byte RDATA).
+fn a_response_with_ttl(id: u16, name: &str, ttl: u32) -> Vec<u8> {
+    let mut bytes = a_query(id, name);
+    bytes[2] = 0x81;
+    bytes[3] = 0x80;
+    bytes[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
+    bytes.extend_from_slice(&0xc00cu16.to_be_bytes()); // name: pointer to question at offset 12
+    bytes.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
+    bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
+    bytes.extend_from_slice(&ttl.to_be_bytes());
+    bytes.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
+    bytes.extend_from_slice(&[192, 0, 2, 1]);
+    bytes
+}
+
+fn upstream_config(name: &str, endpoint: SocketAddr, priority: u16) -> UpstreamConfig {
+    UpstreamConfig {
+        name: name.to_string(),
+        endpoint,
+        protocol: UpstreamProtocol::Udp,
+        enabled: true,
+        priority,
+        timeout: Duration::from_millis(200),
+    }
+}
+
+fn config_with_upstream(upstream: SocketAddr) -> RuntimeConfig {
+    RuntimeConfig::new(
+        vec!["127.0.0.1:5300".parse().unwrap()],
+        vec![upstream_config("primary", upstream, 10)],
+        Duration::from_millis(200),
+        1232,
+    )
+    .unwrap()
+}
+
+/// Builds a real `UdpDnsServer` and its backing resolver, both sharing one
+/// injected clock -- mirrors `main.rs`'s production wiring, where the
+/// resolver and both transports are handed clones of the same
+/// `Arc<dyn Clock>`.
+async fn run_server_with_clock(
+    config: &RuntimeConfig,
+    clock: Arc<dyn Clock>,
+) -> (
+    SocketAddr,
+    tokio::sync::oneshot::Sender<()>,
+    tokio::task::JoinHandle<std::io::Result<()>>,
+) {
+    let cache = Arc::new(ShardedDnsCache::new(&CacheConfig::default()));
+    let resolver = Arc::new(ResolveQuery::with_cache(
+        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
+        cache as Arc<dyn DomainDnsCache>,
+        CacheTtlPolicy::default(),
+        Arc::new(ForwardingResolutionBackend::from_runtime_config(config).unwrap()),
+        Arc::new(BasicResponseFactory),
+        Arc::clone(&clock),
+        Arc::new(NoopEvents),
+        Arc::new(NoopMetrics),
+    ));
+    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
+    let server = UdpDnsServer::new(socket, resolver, clock, config.max_udp_payload_size);
+    let server_addr = server.local_addr().unwrap();
+    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
+    let server_task = tokio::spawn(async move {
+        server
+            .serve_until(async {
+                let _ = shutdown_rx.await;
+            })
+            .await
+    });
+    (server_addr, shutdown_tx, server_task)
+}
+
+async fn send_query(server_addr: SocketAddr, request: &[u8]) -> Vec<u8> {
+    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
+    client.send_to(request, server_addr).await.unwrap();
+    let mut response = [0u8; 512];
+    let (response_len, source) = client.recv_from(&mut response).await.unwrap();
+    assert_eq!(source, server_addr);
+    response[..response_len].to_vec()
+}
+
+fn answer_ttl(response_bytes: &[u8]) -> u32 {
+    let message = Message::parse(response_bytes).expect("valid dns response");
+    message.answers[0].ttl
+}
+
+/// Regression test for section 02 of `docs/plans/ttl_remaining/`: before
+/// this section's wiring, `handle_datagram` called raw `SystemTime::now()`
+/// with no way to inject a fixed/advanceable time, so this test could not
+/// have been written -- there was nothing to control. It now proves the
+/// whole transport-to-cache pipeline ages a cache-hit's TTL by exactly the
+/// amount the injected clock is advanced between two live requests.
+#[tokio::test]
+async fn clock_injection_ages_cache_hit_ttl_end_to_end() {
+    let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
+    let upstream_addr = upstream_socket.local_addr().unwrap();
+    let origin_ttl = 100u32;
+    // The fake upstream answers exactly once: if the second query below
+    // reached the backend instead of hitting the cache, this task would
+    // never see a second datagram and the test would hang until the
+    // outer harness times it out -- so a passing test also proves the
+    // second query was served from cache, not re-resolved.
+    let upstream_task = tokio::spawn(async move {
+        let mut request = [0u8; 512];
+        let (request_len, source) = upstream_socket.recv_from(&mut request).await.unwrap();
+        assert_ne!(request_len, 0);
+        let upstream_id = u16::from_be_bytes([request[0], request[1]]);
+        upstream_socket
+            .send_to(
+                &a_response_with_ttl(upstream_id, "example.com", origin_ttl),
+                source,
+            )
+            .await
+            .unwrap();
+    });
+
+    let config = config_with_upstream(upstream_addr);
+    let clock: Arc<AdvanceableClock> = Arc::new(AdvanceableClock::new());
+    let clock_dyn: Arc<dyn Clock> = clock.clone();
+    let (server_addr, shutdown_tx, server_task) = run_server_with_clock(&config, clock_dyn).await;
+
+    let first_response = send_query(server_addr, &a_query(0x1111, "example.com")).await;
+    assert_eq!(answer_ttl(&first_response), origin_ttl);
+
+    let advance_by = 40u64;
+    clock.advance(advance_by);
+
+    let second_response = send_query(server_addr, &a_query(0x2222, "example.com")).await;
+    assert_eq!(
+        answer_ttl(&second_response),
+        origin_ttl - advance_by as u32,
+        "cache-hit ttl should be aged by exactly the injected clock's advance"
+    );
+
+    upstream_task.await.unwrap();
+    shutdown_tx.send(()).unwrap();
+    server_task.await.unwrap().unwrap();
+}
diff --git a/tests/forwarding.rs b/tests/forwarding.rs
index 38fae8b..e3b9dfa 100644
--- a/tests/forwarding.rs
+++ b/tests/forwarding.rs
@@ -113,7 +113,12 @@ async fn run_server(
 ) {
     let resolver = resolver_from_config(config);
     let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
-    let server = UdpDnsServer::new(socket, resolver, config.max_udp_payload_size);
+    let server = UdpDnsServer::new(
+        socket,
+        resolver,
+        Arc::new(FixedClock),
+        config.max_udp_payload_size,
+    );
     let server_addr = server.local_addr().unwrap();
     let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
     let server_task = tokio::spawn(async move {
diff --git a/tests/support/mod.rs b/tests/support/mod.rs
index 96f8888..7e3c005 100644
--- a/tests/support/mod.rs
+++ b/tests/support/mod.rs
@@ -138,9 +138,11 @@ async fn spawn_servers(config: &RuntimeConfig, resolver: Arc<ResolveQuery>) -> R
     let udp_socket = UdpSocket::bind("127.0.0.1:0")
         .await
         .expect("bind loopback udp socket");
+    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
     let udp_server = UdpDnsServer::new(
         udp_socket,
         Arc::clone(&resolver),
+        Arc::clone(&clock),
         config.max_udp_payload_size,
     );
     let udp_addr = udp_server.local_addr().expect("udp server local addr");
@@ -153,7 +155,7 @@ async fn spawn_servers(config: &RuntimeConfig, resolver: Arc<ResolveQuery>) -> R
             .await
     });
 
-    let mut tcp_servers = TcpDnsServer::bind_configured(config, resolver)
+    let mut tcp_servers = TcpDnsServer::bind_configured(config, resolver, clock)
         .await
         .expect("bind configured tcp listener(s)");
     assert_eq!(
