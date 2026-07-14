// Copyright 2026 Ryan Moore
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Shared harness for the protocol-conformance e2e suites
//! (`tests/e2e_config_toml.rs`, `tests/e2e_upstream_live.rs`). Not a test
//! binary itself -- nested under `tests/support/`, so cargo doesn't compile
//! it as its own integration-test target.
//!
//! Keeps two concerns separate on purpose: *configuring* a server
//! (`start_forward_server`/`start_recursive_server`, which take real TOML
//! text through `RuntimeConfig::from_toml_str`, the same parser `main.rs`
//! uses) versus *asserting protocol behavior* against whatever `SocketAddr`
//! comes back. The assertion side of each test only ever touches
//! `rdns::protocol::Message` and a `SocketAddr` -- nothing rdns-internal --
//! so the same test bodies could in principle be pointed at any DNS server.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rdns::config::{LocalZoneConfig, RuntimeConfig, parse_local_zone_file};
use rdns::delivery::dns::{TcpDnsServer, UdpDnsServer};
use rdns::delivery::upstream::{ForwardingResolutionBackend, RecursiveAuthorityTransportClient};
use rdns::protocol::{Message, Record, RecordData, encode_tcp_frame};
use rdns::resolver::{
    BackendHealth, BackendSnapshot, BasicResponseFactory, CacheTtlPolicy, Clock, DomainName,
    InMemoryLocalDnsEntries, LocalDnsEntries, MetricsSink, NoopDnsCache, NoopPolicyEvaluator,
    QueryEventRecordResult, QueryEventSink, QueryEventV1, RecursiveResolutionBackend,
    RecursiveResolverConfig, RecursiveRootHint, ResolutionMode, ResolveQuery, ResolverMetric,
    StandardProtocolCodec,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time;

// RCODE values (RFC 1035 §4.1.1), named for readability at call sites.
pub const NOERROR: u8 = 0;
pub const FORMERR: u8 = 1;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const NOTIMP: u8 = 4;

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub struct NoopEvents;

impl QueryEventSink for NoopEvents {
    fn record(&self, _event: QueryEventV1) -> QueryEventRecordResult {
        QueryEventRecordResult::Accepted
    }
}

pub struct NoopMetrics;

impl MetricsSink for NoopMetrics {
    fn increment(&self, _metric: ResolverMetric) {}

    fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
}

/// A running rdns instance (real `UdpDnsServer` + `TcpDnsServer`, bound to
/// loopback ephemeral ports) plus the handles needed to shut it down
/// cleanly at the end of a test.
pub struct RunningServer {
    pub udp_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    udp_shutdown: oneshot::Sender<()>,
    udp_task: JoinHandle<std::io::Result<()>>,
    tcp_shutdown: oneshot::Sender<()>,
    tcp_task: JoinHandle<std::io::Result<()>>,
}

impl RunningServer {
    pub async fn shutdown(self) {
        let _ = self.udp_shutdown.send(());
        let _ = self.tcp_shutdown.send(());
        self.udp_task
            .await
            .expect("udp server task panicked")
            .expect("udp server task returned an error");
        self.tcp_task
            .await
            .expect("tcp server task panicked")
            .expect("tcp server task returned an error");
    }
}

/// Allocates a port on loopback by binding an ephemeral `TcpListener` and
/// immediately dropping it. `RuntimeConfig::validate` rejects a `dns_listen`
/// port of `0` outright (`config/mod.rs:1725`), so every TOML fixture in
/// this suite needs a concrete port number up front; this is the standard
/// bind-then-drop trick for picking one; the tiny window between drop and
/// `TcpDnsServer::bind_configured` rebinding it is an accepted, common test
/// technique (nothing else in this test process races for loopback ports).
pub async fn free_loopback_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port to allocate one");
    listener
        .local_addr()
        .expect("ephemeral listener local addr")
        .port()
}

/// Prepends a concrete `dns_listen` line (see `free_loopback_port`) to a
/// fixture's TOML *body* -- callers write everything else (`[[upstreams]]`,
/// `[[local_dns_entries]]`, deadlines, payload size) themselves; the listen
/// port is the one thing that has to be resolved dynamically no matter how
/// the instance under test is started.
async fn with_allocated_dns_listen(toml_body: &str) -> String {
    let port = free_loopback_port().await;
    format!("dns_listen = [\"127.0.0.1:{port}\"]\n{toml_body}")
}

async fn spawn_servers(config: &RuntimeConfig, resolver: Arc<ResolveQuery>) -> RunningServer {
    let udp_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind loopback udp socket");
    let udp_server = UdpDnsServer::new(
        udp_socket,
        Arc::clone(&resolver),
        config.max_udp_payload_size,
    );
    let udp_addr = udp_server.local_addr().expect("udp server local addr");
    let (udp_shutdown, udp_shutdown_rx) = oneshot::channel();
    let udp_task = tokio::spawn(async move {
        udp_server
            .serve_until(async {
                let _ = udp_shutdown_rx.await;
            })
            .await
    });

    let mut tcp_servers = TcpDnsServer::bind_configured(config, resolver)
        .await
        .expect("bind configured tcp listener(s)");
    assert_eq!(
        tcp_servers.len(),
        1,
        "test fixtures are expected to configure exactly one dns_listen address"
    );
    let tcp_server = tcp_servers.remove(0);
    let tcp_addr = tcp_server.local_addr().expect("tcp server local addr");
    let (tcp_shutdown, tcp_shutdown_rx) = oneshot::channel();
    let tcp_task = tokio::spawn(async move {
        tcp_server
            .serve_until(async {
                let _ = tcp_shutdown_rx.await;
            })
            .await
    });

    RunningServer {
        udp_addr,
        tcp_addr,
        udp_shutdown,
        udp_task,
        tcp_shutdown,
        tcp_task,
    }
}

/// Parses `toml` through the real `RuntimeConfig::from_toml_str`, converts
/// `[[local_dns_entries]]` through the real config-validation path, and
/// starts a forward-mode server against it. `toml`'s `[[upstreams]]` entry
/// is expected to already point at a fake upstream the test spawned first
/// (see `spawn_canned_upstream`).
pub async fn start_forward_server(toml_body: &str) -> RunningServer {
    let toml = with_allocated_dns_listen(toml_body).await;
    let config = RuntimeConfig::from_toml_str(&toml).expect("fixture TOML parses and validates");
    let entries = config
        .local_dns_entries
        .iter()
        .map(|entry| {
            entry
                .to_local_dns_entry()
                .expect("fixture local_dns_entries entry is valid")
        })
        .collect();
    let local_entries: Arc<dyn LocalDnsEntries> = Arc::new(InMemoryLocalDnsEntries::new(entries));
    start_forward_server_with_local_entries(config, local_entries).await
}

/// Same as `start_forward_server`, but additionally loads `zone_file_source`
/// as a `[[local_zones]]` fixture rooted at `zone_root_domain`, exercising
/// `parse_local_zone_file` end to end.
pub async fn start_forward_server_with_zone_file(
    toml_body: &str,
    zone_root_domain: &str,
    zone_file_source: &str,
) -> RunningServer {
    let toml = with_allocated_dns_listen(toml_body).await;
    let config = RuntimeConfig::from_toml_str(&toml).expect("fixture TOML parses and validates");
    let mut entries: Vec<_> = config
        .local_dns_entries
        .iter()
        .map(|entry| {
            entry
                .to_local_dns_entry()
                .expect("fixture local_dns_entries entry is valid")
        })
        .collect();

    let zone_config = LocalZoneConfig {
        path: PathBuf::from("fixture.zone"),
        root_domain: DomainName::parse(zone_root_domain).expect("valid zone root domain fixture"),
        public_address_acknowledged: true,
        enabled: true,
    };
    zone_config
        .validate_root_domain()
        .expect("fixture zone root domain is valid");
    let zone_entries = parse_local_zone_file(&zone_config, zone_file_source)
        .expect("fixture zone file source parses");
    for entry in zone_entries {
        entries.push(
            entry
                .to_local_dns_entry()
                .expect("zone-derived entry is valid"),
        );
    }

    let local_entries: Arc<dyn LocalDnsEntries> = Arc::new(InMemoryLocalDnsEntries::new(entries));
    start_forward_server_with_local_entries(config, local_entries).await
}

async fn start_forward_server_with_local_entries(
    config: RuntimeConfig,
    local_entries: Arc<dyn LocalDnsEntries>,
) -> RunningServer {
    let backend = Arc::new(
        ForwardingResolutionBackend::from_runtime_config(&config)
            .expect("fixture forwarding backend config is valid"),
    );
    // Explicit `BackendSnapshot` tagged `ResolutionMode::Forward` --
    // `ResolveQuery::new`/`with_cache`/`with_cache_and_policy` always wrap
    // whatever backend they're given in `BackendSnapshot::forwarding`
    // regardless of its actual `ResolutionBackend` impl, which happens not
    // to matter for a genuinely-forwarding backend like this one (the mode
    // label and the backend impl agree here), but matters a great deal for
    // a *recursive* backend -- see `start_recursive_server`'s comment.
    let snapshot = BackendSnapshot::new(
        backend,
        ResolutionMode::Forward,
        0,
        BackendHealth::Healthy,
        Some(config.backend_cache_namespace()),
    );
    let resolver = Arc::new(ResolveQuery::with_cache_policy_and_backend_snapshot(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(NoopDnsCache),
        Arc::new(NoopPolicyEvaluator),
        local_entries,
        CacheTtlPolicy::default(),
        snapshot,
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(NoopEvents),
        Arc::new(NoopMetrics),
    ));
    spawn_servers(&config, resolver).await
}

/// Starts a recursive-mode server from literal TOML text whose
/// `root_hints = "custom"` entry points at a fake authority the test
/// spawned first (see `spawn_canned_upstream`). Offline: the recursive
/// backend always sends `dnssec_ok = true` to every authority it queries
/// (`resolve_one_hop`) and treats any `AA=1` answer matching the queried
/// question as terminal (`evaluate_authority_response`), so a single fake
/// "root hint" that answers directly -- no real root/TLD/authority
/// referral chain needed -- is enough to exercise recursive-mode response
/// assembly (including per-client DNSSEC-record filtering) without any
/// network access.
pub async fn start_recursive_server_from_toml(toml_body: &str) -> RunningServer {
    let toml = with_allocated_dns_listen(toml_body).await;
    let config = RuntimeConfig::from_toml_str(&toml).expect("fixture TOML parses and validates");
    start_recursive_server(config).await
}

/// Starts a recursive-mode server (bundled root hints) from an
/// already-built `RuntimeConfig` -- used only by the live/network suite,
/// which needs real root/TLD/authority access and so isn't offline.
///
/// Deliberately does *not* use `ResolveQuery::new` (unlike
/// `tests/live_dns.rs`'s equivalent helper): that constructor always tags
/// its `BackendSnapshot` `ResolutionMode::Forward` regardless of the actual
/// `ResolutionBackend` impl plugged in. That mislabeling is harmless for
/// tests that only assert on the final answer, since iterative resolution
/// itself comes from the `RecursiveResolutionBackend` impl, not the mode
/// label -- but `prepare_backend_result`'s per-client DNSSEC-record
/// filtering (`resolver/mod.rs:4632`) branches on `backend_mode ==
/// ResolutionMode::Recursive`, so a mislabeled snapshot silently skips
/// filtering entirely. An explicit `BackendSnapshot::new(..,
/// ResolutionMode::Recursive, ..)` avoids that trap for any test (like the
/// DNSSEC DO-bit ones) that actually depends on it.
pub async fn start_recursive_server(config: RuntimeConfig) -> RunningServer {
    let recursive = config
        .resolution
        .recursive
        .as_ref()
        .expect("recursive resolution config present");
    let root_hints = recursive
        .load_root_hints()
        .expect("bundled root hints load")
        .into_iter()
        .map(|hint| RecursiveRootHint {
            name: hint.name,
            endpoints: hint.endpoints,
        })
        .collect();
    let transport = Arc::new(
        RecursiveAuthorityTransportClient::from_runtime_config(&config)
            .expect("valid recursive transport config"),
    );
    let backend = Arc::new(RecursiveResolutionBackend::new(
        RecursiveResolverConfig {
            root_hints,
            per_authority_timeout: recursive.per_authority_timeout,
            per_query_deadline: config.per_query_deadline,
            max_recursion_depth: recursive.max_recursion_depth,
            max_cname_restarts: recursive.max_cname_restarts,
            configured_max_udp_payload_size: config.max_udp_payload_size,
        },
        transport,
    ));
    let snapshot = BackendSnapshot::new(
        backend,
        ResolutionMode::Recursive,
        config.resolution.generation,
        BackendHealth::Healthy,
        Some(config.backend_cache_namespace()),
    );
    let resolver = Arc::new(ResolveQuery::with_cache_and_backend_snapshot(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(NoopDnsCache),
        CacheTtlPolicy::default(),
        snapshot,
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(NoopEvents),
        Arc::new(NoopMetrics),
    ));
    spawn_servers(&config, resolver).await
}

/// Spawns a loopback UDP "upstream" that answers exactly one query with a
/// response built from the observed request's own transaction ID (so the
/// canned response always echoes the right ID without the caller having to
/// patch it after the fact). Returns the fake upstream's address and a
/// `JoinHandle` yielding the raw request bytes it saw, for tests that want
/// to assert what rdns forwarded upstream.
pub async fn spawn_canned_upstream(
    response_for_id: impl FnOnce(u16) -> Vec<u8> + Send + 'static,
) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind fake upstream socket");
    let addr = socket.local_addr().expect("fake upstream local addr");
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (len, source) = socket
            .recv_from(&mut buf)
            .await
            .expect("fake upstream recv");
        let request = buf[..len].to_vec();
        let id = u16::from_be_bytes([request[0], request[1]]);
        let response = response_for_id(id);
        socket
            .send_to(&response, source)
            .await
            .expect("fake upstream send");
        request
    });
    (addr, task)
}

/// `RootHintConfig::validate` (`config/mod.rs:618`, via
/// `is_usable_authority_address`) rejects loopback addresses outright --
/// real root hints are never loopback, and that check runs unconditionally
/// (`RuntimeConfig::new`/`new_with_resolution`/`from_toml_str` all call
/// `validate()`), so a recursive-mode fixture can't point its root hint at
/// `127.0.0.1` the way a forward-mode fixture points `[[upstreams]]` there
/// (upstream endpoints have no such restriction). This discovers the
/// host's own non-loopback local address via a UDP "connect" (a route
/// lookup only -- `connect()` on a UDP socket sends no packets), so the
/// fake authority in `spawn_canned_authority` can bind to an address the
/// validator accepts while every byte still only ever travels the
/// loopback/local network stack, not the real internet.
fn local_non_loopback_ip() -> std::net::IpAddr {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind address-discovery probe");
    probe
        .connect("8.8.8.8:80")
        .expect("route-lookup connect for address discovery");
    probe.local_addr().expect("probe socket local addr").ip()
}

/// `spawn_canned_upstream`'s counterpart for a recursive-mode root hint:
/// binds to the host's own non-loopback address (see
/// `local_non_loopback_ip`) instead of loopback, since
/// `RootHintConfig::validate` rejects loopback root hints.
pub async fn spawn_canned_authority(
    response_for_id: impl FnOnce(u16) -> Vec<u8> + Send + 'static,
) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let bind_addr = SocketAddr::new(local_non_loopback_ip(), 0);
    let socket = UdpSocket::bind(bind_addr)
        .await
        .expect("bind fake authority socket");
    let addr = socket.local_addr().expect("fake authority local addr");
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (len, source) = socket
            .recv_from(&mut buf)
            .await
            .expect("fake authority recv");
        let request = buf[..len].to_vec();
        let id = u16::from_be_bytes([request[0], request[1]]);
        let response = response_for_id(id);
        socket
            .send_to(&response, source)
            .await
            .expect("fake authority send");
        request
    });
    (addr, task)
}

/// Spawns a loopback UDP "upstream" that never answers -- used for
/// SERVFAIL-on-timeout tests. The task completes (with the observed
/// request bytes) once it has received the query, regardless of whether
/// the client ever stops waiting.
pub async fn spawn_silent_upstream() -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind fake upstream socket");
    let addr = socket.local_addr().expect("fake upstream local addr");
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (len, _source) = socket
            .recv_from(&mut buf)
            .await
            .expect("fake upstream recv");
        buf[..len].to_vec()
    });
    (addr, task)
}

/// Builder for the hand-rolled DNS wire format the whole suite sends as
/// requests. Covers every well-formed shape the offline suite needs
/// (opcode, question count, EDNS/DO, CD); the handful of deliberately
/// malformed wire shapes (pointer loops, duplicate OPT, bad label lengths,
/// truncated headers) are built as small inline byte vectors directly in
/// their own test functions instead, since forcing every edge case through
/// one builder would obscure exactly what's malformed about each of them.
pub struct RawQueryBuilder {
    id: u16,
    opcode: u8,
    qr: bool,
    rd: bool,
    qdcount: u16,
    ancount: u16,
    qname: String,
    qtype: u16,
    qclass: u16,
    edns: Option<(u16, bool)>,
    cd: bool,
}

impl RawQueryBuilder {
    pub fn new(id: u16, qname: impl Into<String>, qtype: u16) -> Self {
        Self {
            id,
            opcode: 0,
            qr: false,
            rd: true,
            qdcount: 1,
            ancount: 0,
            qname: qname.into(),
            qtype,
            qclass: 1,
            edns: None,
            cd: false,
        }
    }

    pub fn opcode(mut self, opcode: u8) -> Self {
        self.opcode = opcode;
        self
    }

    pub fn qr(mut self, qr: bool) -> Self {
        self.qr = qr;
        self
    }

    pub fn rd(mut self, rd: bool) -> Self {
        self.rd = rd;
        self
    }

    /// Overrides the header's QDCOUNT field independent of how many
    /// questions actually get written to the body -- the query-shape
    /// checks this suite exercises (RFC 1035 §4.1.1) reject on the header
    /// field alone, before ever walking the body.
    pub fn qdcount(mut self, qdcount: u16) -> Self {
        self.qdcount = qdcount;
        self
    }

    pub fn answer_count(mut self, ancount: u16) -> Self {
        self.ancount = ancount;
        self
    }

    pub fn edns(mut self, udp_payload_size: u16, dnssec_ok: bool) -> Self {
        self.edns = Some((udp_payload_size, dnssec_ok));
        self
    }

    pub fn cd(mut self, cd: bool) -> Self {
        self.cd = cd;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());

        let mut flags: u16 = if self.rd { 0x0100 } else { 0 };
        if self.qr {
            flags |= 0x8000;
        }
        flags |= (u16::from(self.opcode) & 0x0f) << 11;
        if self.cd {
            flags |= 0x0010;
        }
        bytes.extend_from_slice(&flags.to_be_bytes());

        bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        bytes.extend_from_slice(&self.ancount.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        let arcount: u16 = u16::from(self.edns.is_some());
        bytes.extend_from_slice(&arcount.to_be_bytes());

        for label in self.qname.split('.') {
            if label.is_empty() {
                continue;
            }
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());

        if let Some((udp_payload_size, dnssec_ok)) = self.edns {
            bytes.push(0); // OPT owner name: root
            bytes.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
            bytes.extend_from_slice(&udp_payload_size.to_be_bytes()); // CLASS = udp payload size
            // extended rcode(8) | version(8) | flags(16); DO is bit 15 of
            // the low 16-bit flags half, i.e. 0x8000 of the full u32.
            let ext_flags: u32 = if dnssec_ok { 0x8000 } else { 0 };
            bytes.extend_from_slice(&ext_flags.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
        }

        bytes
    }
}

pub fn parse_response(bytes: &[u8]) -> Message {
    Message::parse(bytes).expect("response is a well-formed dns message")
}

pub fn opt_record(message: &Message) -> Option<&Record> {
    message
        .additionals
        .iter()
        .find(|record| matches!(record.record, RecordData::OPT(_)))
}

/// Offline suites (synthetic fixtures, loopback-only) resolve near
/// instantly, so a short default keeps a genuine hang failing fast. Live
/// suites need real headroom above whatever `per_query_deadline` the
/// resolver under test is configured with -- see `send_udp_with_timeout`.
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(2);

pub async fn send_udp(target: SocketAddr, request: &[u8]) -> Vec<u8> {
    send_udp_with_timeout(target, request, DEFAULT_UDP_TIMEOUT).await
}

/// Like `send_udp`, but with an explicit read timeout -- for live-network
/// tests whose resolver-under-test may legitimately take several seconds
/// (full root -> TLD -> authority recursion), where `send_udp`'s short
/// default would fail the test before rdns's own `per_query_deadline` even
/// elapses.
pub async fn send_udp_with_timeout(
    target: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> Vec<u8> {
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp test client");
    client
        .send_to(request, target)
        .await
        .expect("send udp query");
    let mut buf = [0u8; 4096];
    let (len, source) = time::timeout(timeout, client.recv_from(&mut buf))
        .await
        .expect("udp response timed out")
        .expect("recv udp response");
    assert_eq!(
        source, target,
        "udp response came from an unexpected source"
    );
    buf[..len].to_vec()
}

/// Returns `true` if no response arrived within `wait` -- used for wire
/// shapes where the correct, documented behavior is that the server drops
/// the datagram outright rather than answering it.
pub async fn expect_no_udp_response(target: SocketAddr, request: &[u8], wait: Duration) -> bool {
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp test client");
    client
        .send_to(request, target)
        .await
        .expect("send udp query");
    let mut buf = [0u8; 4096];
    time::timeout(wait, client.recv_from(&mut buf))
        .await
        .is_err()
}

pub async fn send_tcp(target: SocketAddr, request: &[u8]) -> Vec<u8> {
    send_tcp_with_timeout(target, request, DEFAULT_UDP_TIMEOUT).await
}

/// Like `send_tcp`, but with an explicit read timeout -- see
/// `send_udp_with_timeout`'s doc comment for why live-network tests need
/// one separate from the offline suites' fast default.
pub async fn send_tcp_with_timeout(
    target: SocketAddr,
    request: &[u8],
    timeout: Duration,
) -> Vec<u8> {
    let mut stream = TcpStream::connect(target)
        .await
        .expect("connect tcp test client");
    send_tcp_query(&mut stream, request).await;
    read_tcp_response_with_timeout(&mut stream, timeout).await
}

pub async fn send_tcp_query(stream: &mut TcpStream, request: &[u8]) {
    let framed = encode_tcp_frame(request, u16::MAX as usize).expect("frame tcp query");
    stream.write_all(&framed).await.expect("write tcp query");
}

pub async fn read_tcp_response(stream: &mut TcpStream) -> Vec<u8> {
    read_tcp_response_with_timeout(stream, DEFAULT_UDP_TIMEOUT).await
}

/// Like `read_tcp_response`, but bounds both the length-prefix read and
/// the body read with `timeout` instead of waiting indefinitely -- a
/// regression that drops or stalls a TCP response must fail the test
/// promptly, not hang the test process.
pub async fn read_tcp_response_with_timeout(stream: &mut TcpStream, timeout: Duration) -> Vec<u8> {
    let mut length_prefix = [0u8; 2];
    time::timeout(timeout, stream.read_exact(&mut length_prefix))
        .await
        .expect("read tcp response length prefix timed out")
        .expect("read tcp response length prefix");
    let len = u16::from_be_bytes(length_prefix) as usize;
    let mut response = vec![0u8; len];
    time::timeout(timeout, stream.read_exact(&mut response))
        .await
        .expect("read tcp response body timed out")
        .expect("read tcp response body");
    response
}
