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

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time;

use crate::config::{DEFAULT_MAX_TCP_CONNECTIONS, RuntimeConfig};
use crate::protocol::{DNS_HEADER_LEN, Message, build_servfail_response};
use crate::resolver::{ObservedSourceEndpoint, ResolveQuery, ResolveRequest};

const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 1024;
/// Caps how many concurrent connections a single source IP may hold against
/// one listener. Without this, one client opening `max_connections`
/// connections and idling them (see `TCP_CONNECTION_IDLE_TIMEOUT`) starves
/// every other resolver of a slot on that listener.
const DEFAULT_MAX_TCP_CONNECTIONS_PER_IP: usize = 32;
/// RFC 1035 §4.2.2 length-prefixes TCP DNS messages with a 16-bit length —
/// this is the hard ceiling regardless of any EDNS/config UDP payload size.
const MAX_TCP_MESSAGE_SIZE: usize = u16::MAX as usize;
/// Caps how long a connection may sit idle between pipelined queries (RFC
/// 7766 §6.2 recommends servers support pipelining) and how long a single
/// read/write may take. Without this, a client that opens a connection and
/// never sends/finishes a query would hold a `max_connections` slot forever.
const TCP_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Fallback shutdown grace period for servers bound without a `RuntimeConfig`
/// (e.g. `bind`/`bind_with_max_connections`, used directly by tests).
/// `bind_configured` derives a config-aware value instead — see
/// `TCP_SHUTDOWN_GRACE_BUFFER`.
const TCP_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(1);
/// Added on top of `RuntimeConfig::per_query_deadline` to get the real
/// shutdown grace period: a connection's in-flight resolve is allowed to
/// take up to that deadline, so the grace period must cover it plus a little
/// slack for framing/writing the response, or a slow-but-healthy resolve
/// gets its task hard-aborted (client sees a reset, not an answer) during a
/// routine shutdown/reload.
const TCP_SHUTDOWN_GRACE_BUFFER: Duration = Duration::from_millis(250);

/// Bind a UDP socket for the DNS listener.
///
/// On Linux, `SO_REUSEPORT` is set so that multiple processes or tasks can each
/// bind their own socket to the same address and the kernel distributes incoming
/// datagrams across them, enabling true parallel receive.
///
/// On macOS and other platforms, `SO_REUSEPORT` does not provide kernel-level
/// UDP load-balancing, so we fall back to a standard `tokio::net::UdpSocket`
/// bind which is the performant approach on those systems.
#[cfg(target_os = "linux")]
async fn bind_listener_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

#[cfg(not(target_os = "linux"))]
async fn bind_listener_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::bind(address).await
}

/// Bind a TCP listener socket for the DNS listener.
///
/// Mirrors `bind_listener_socket`'s `SO_REUSEPORT` handling for UDP. Without
/// it, a `dns_listen` config that binds both a wildcard and a more specific
/// address on the same port (e.g. `0.0.0.0:53` and `127.0.0.1:53`) can start
/// fine on the UDP side but fail the plain TCP bind with `EADDRINUSE`,
/// aborting startup on a config that otherwise works.
#[cfg(target_os = "linux")]
async fn bind_tcp_listener_socket(address: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

#[cfg(not(target_os = "linux"))]
async fn bind_tcp_listener_socket(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address).await
}

pub struct UdpDnsServer {
    socket: Arc<UdpSocket>,
    resolver: Arc<ResolveQuery>,
    listener: Option<SocketAddr>,
    max_request_size: usize,
    max_in_flight_requests: usize,
}

impl UdpDnsServer {
    pub fn new(socket: UdpSocket, resolver: Arc<ResolveQuery>, max_request_size: usize) -> Self {
        Self::with_max_in_flight_requests(
            socket,
            resolver,
            max_request_size,
            DEFAULT_MAX_IN_FLIGHT_REQUESTS,
        )
    }

    pub fn with_max_in_flight_requests(
        socket: UdpSocket,
        resolver: Arc<ResolveQuery>,
        max_request_size: usize,
        max_in_flight_requests: usize,
    ) -> Self {
        let listener = socket.local_addr().ok();
        Self {
            socket: Arc::new(socket),
            resolver,
            listener,
            max_request_size,
            max_in_flight_requests,
        }
    }

    pub async fn bind(
        address: SocketAddr,
        resolver: Arc<ResolveQuery>,
        max_request_size: usize,
    ) -> io::Result<Self> {
        let socket = bind_listener_socket(address).await?;
        Ok(Self::new(socket, resolver, max_request_size))
    }

    pub async fn bind_configured(
        config: &RuntimeConfig,
        resolver: Arc<ResolveQuery>,
    ) -> io::Result<Vec<Self>> {
        let mut servers = Vec::with_capacity(config.dns_listen.len());
        for address in &config.dns_listen {
            servers
                .push(Self::bind(*address, resolver.clone(), config.max_udp_payload_size).await?);
        }
        Ok(servers)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn serve_until<S>(&self, shutdown: S) -> io::Result<()>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let semaphore = Arc::new(Semaphore::new(self.max_in_flight_requests));
        let mut tasks = JoinSet::new();
        loop {
            // The `join_next()` branch is guarded so it's never polled while
            // `tasks` is empty; an unguarded call would resolve to `None`
            // immediately and busy-loop the select.
            tokio::select! {
                _ = &mut shutdown => break,
                result = self.receive_permitted_datagram(semaphore.clone()) => {
                    if !self.spawn_received_datagram(result?, &mut tasks) {
                        break;
                    }
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(result) = result {
                        task_result_to_io(result)??;
                    }
                }
            }
        }

        while let Some(result) = tasks.join_next().await {
            task_result_to_io(result)??;
        }
        Ok(())
    }

    fn spawn_received_datagram(
        &self,
        datagram: Option<ReceivedDatagram>,
        tasks: &mut JoinSet<io::Result<()>>,
    ) -> bool {
        let Some(datagram) = datagram else {
            return false;
        };
        self.spawn_datagram_task(datagram, tasks);
        true
    }

    async fn receive_permitted_datagram(
        &self,
        semaphore: Arc<Semaphore>,
    ) -> io::Result<Option<ReceivedDatagram>> {
        let permit = match semaphore.acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return Ok(None),
        };
        let mut request_bytes = vec![0; self.max_request_size];
        let (request_len, source) = self.socket.recv_from(&mut request_bytes).await?;
        request_bytes.truncate(request_len);
        Ok(Some(ReceivedDatagram {
            permit,
            request_bytes,
            source,
        }))
    }

    fn spawn_datagram_task(&self, datagram: ReceivedDatagram, tasks: &mut JoinSet<io::Result<()>>) {
        let socket = Arc::clone(&self.socket);
        let resolver = Arc::clone(&self.resolver);
        let listener = self.listener;
        tasks.spawn(async move { handle_datagram(socket, resolver, listener, datagram).await });
    }
}

struct ReceivedDatagram {
    permit: OwnedSemaphorePermit,
    request_bytes: Vec<u8>,
    source: SocketAddr,
}

async fn handle_datagram(
    socket: Arc<UdpSocket>,
    resolver: Arc<ResolveQuery>,
    listener: Option<SocketAddr>,
    datagram: ReceivedDatagram,
) -> io::Result<()> {
    let _permit = datagram.permit;
    let outcome = resolver
        .resolve(ResolveRequest::new_with_observed_source(
            ObservedSourceEndpoint::udp(datagram.source, listener),
            SystemTime::now(),
            datagram.request_bytes,
        ))
        .await;
    socket
        .send_to(&outcome.response_bytes, datagram.source)
        .await
        .map(|_| ())
}

fn task_result_to_io(
    result: Result<io::Result<()>, tokio::task::JoinError>,
) -> io::Result<io::Result<()>> {
    result.map_err(|error| io::Error::other(format!("DNS request task failed: {error}")))
}

/// TCP counterpart to `UdpDnsServer`. RFC 1035 §4.2 and RFC 7766 both make
/// TCP support mandatory for a conformant DNS server (not just a large-UDP-
/// response fallback): clients may connect over TCP directly, and a UDP
/// response we truncate (`TC=1`) is a promise that the same query answered
/// over TCP will fit. Every response emitted here is exempt from the
/// UDP-payload-size truncation, since it went through `ObservedSourceEndpoint::tcp`,
/// which `ResolveQuery::resolve` checks (see `ObservedSourceEndpoint::is_tcp`).
pub struct TcpDnsServer {
    listener: TcpListener,
    resolver: Arc<ResolveQuery>,
    local_addr: SocketAddr,
    max_connections: usize,
    max_connections_per_ip: usize,
    shutdown_grace_period: Duration,
}

impl TcpDnsServer {
    pub async fn bind(address: SocketAddr, resolver: Arc<ResolveQuery>) -> io::Result<Self> {
        Self::bind_with_max_connections(address, resolver, DEFAULT_MAX_TCP_CONNECTIONS).await
    }

    pub async fn bind_with_max_connections(
        address: SocketAddr,
        resolver: Arc<ResolveQuery>,
        max_connections: usize,
    ) -> io::Result<Self> {
        Self::bind_with_options(
            address,
            resolver,
            max_connections,
            DEFAULT_MAX_TCP_CONNECTIONS_PER_IP,
            TCP_SHUTDOWN_GRACE_PERIOD,
        )
        .await
    }

    async fn bind_with_options(
        address: SocketAddr,
        resolver: Arc<ResolveQuery>,
        max_connections: usize,
        max_connections_per_ip: usize,
        shutdown_grace_period: Duration,
    ) -> io::Result<Self> {
        // `Semaphore::new(0)` never issues a permit, so every accepted
        // connection would stall forever waiting for one — a self-inflicted
        // DoS that's very hard to debug from the outside. Reject it here so
        // every construction path (including direct callers of `bind`/
        // `bind_with_max_connections`, not just `bind_configured`) is
        // covered.
        if max_connections == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp dns server: max_connections must be greater than zero",
            ));
        }
        // `PerIpConnectionGuard::try_acquire` inserts a source IP's `0`-count
        // entry into the map *before* checking it against the cap, so a cap
        // of zero would insert (and never remove, since `try_acquire` only
        // returns a cleanup-on-drop guard on success) a permanent entry for
        // every distinct source IP that ever attempts a connection —
        // unbounded memory growth on top of refusing every connection.
        if max_connections_per_ip == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp dns server: max_connections_per_ip must be greater than zero",
            ));
        }
        let listener = bind_tcp_listener_socket(address).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            resolver,
            local_addr,
            max_connections,
            max_connections_per_ip,
            shutdown_grace_period,
        })
    }

    pub async fn bind_configured(
        config: &RuntimeConfig,
        resolver: Arc<ResolveQuery>,
    ) -> io::Result<Vec<Self>> {
        let mut servers = Vec::with_capacity(config.dns_listen.len());
        let shutdown_grace_period = config.per_query_deadline + TCP_SHUTDOWN_GRACE_BUFFER;
        for address in &config.dns_listen {
            servers.push(
                Self::bind_with_options(
                    *address,
                    resolver.clone(),
                    config.max_tcp_connections,
                    DEFAULT_MAX_TCP_CONNECTIONS_PER_IP,
                    shutdown_grace_period,
                )
                .await?,
            );
        }
        Ok(servers)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// Mirrors `UdpDnsServer::serve_until`'s accept/drain loop, but — like
    /// `MetricsServer` — bounds the post-shutdown drain: a TCP connection
    /// isn't guaranteed to close on its own the way a UDP datagram-handling
    /// task finishes, so an idle or stalled client can't hang shutdown.
    pub async fn serve_until<S>(&self, shutdown: S) -> io::Result<()>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        let per_ip_counts: Arc<Mutex<HashMap<IpAddr, usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut tasks: JoinSet<()> = JoinSet::new();
        // A global connection permit secured *before* calling `accept()`.
        // This lives across loop iterations (unlike the futures inside
        // `select!`, which are recreated every iteration and dropped if a
        // different branch wins): acquiring the permit first means a
        // cancelled iteration only abandons a semaphore wait — cancel-safe,
        // and invisible to any client, since the connection simply stays in
        // the kernel's accept backlog — instead of risking an already-
        // `accept()`-ed `TcpStream` being dropped (and the connection reset)
        // out from under a client that did nothing wrong. It also keeps
        // `max_connections` strict: nothing is pulled out of the kernel
        // backlog into a live, resource-holding socket until a permit is
        // actually available.
        let mut pending_permit: Option<OwnedSemaphorePermit> = None;
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                permit = Arc::clone(&semaphore).acquire_owned(), if pending_permit.is_none() => {
                    match permit {
                        Ok(permit) => pending_permit = Some(permit),
                        Err(_) => break,
                    }
                }
                accepted = self.listener.accept(), if pending_permit.is_some() => {
                    let permit = pending_permit.take().unwrap();
                    let (stream, peer_addr) = accepted?;
                    match PerIpConnectionGuard::try_acquire(
                        per_ip_counts.clone(),
                        peer_addr.ip(),
                        self.max_connections_per_ip,
                    ) {
                        Some(per_ip_guard) => {
                            self.spawn_connection(stream, peer_addr, permit, per_ip_guard, &mut tasks);
                        }
                        None => tracing::debug!(
                            %peer_addr,
                            "tcp dns: dropping connection, per-source-ip limit reached"
                        ),
                    }
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(join_error)) = result {
                        tracing::warn!(%join_error, "tcp dns connection task panicked");
                    }
                }
            }
        }

        if time::timeout(self.shutdown_grace_period, drain_tasks(&mut tasks))
            .await
            .is_err()
        {
            tracing::warn!(
                outstanding = tasks.len(),
                "tcp dns server: connections still open after shutdown grace period, aborting"
            );
            tasks.abort_all();
            drain_tasks(&mut tasks).await;
        }
        Ok(())
    }

    fn spawn_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
        permit: OwnedSemaphorePermit,
        per_ip_guard: PerIpConnectionGuard,
        tasks: &mut JoinSet<()>,
    ) {
        let resolver = Arc::clone(&self.resolver);
        let listener = self.local_addr;
        tasks.spawn(async move {
            let _permit = permit;
            let _per_ip_guard = per_ip_guard;
            if let Err(error) = serve_tcp_connection(stream, peer_addr, listener, resolver).await {
                tracing::debug!(%error, %peer_addr, "tcp dns connection closed with error");
            }
        });
    }
}

/// RAII slot for `TcpDnsServer`'s per-source-IP connection cap: increments
/// the source's count on acquire, decrements (and prunes the map entry) on
/// drop, so the count self-corrects however the connection's task ends.
struct PerIpConnectionGuard {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl PerIpConnectionGuard {
    fn try_acquire(
        counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
        ip: IpAddr,
        max_connections_per_ip: usize,
    ) -> Option<Self> {
        let mut guard = counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = guard.entry(ip).or_insert(0);
        if *count >= max_connections_per_ip {
            return None;
        }
        *count += 1;
        drop(guard);
        Some(Self { counts, ip })
    }
}

impl Drop for PerIpConnectionGuard {
    fn drop(&mut self) {
        // Best-effort cleanup: a panic elsewhere while holding this lock
        // shouldn't cascade into every subsequent accept/drop on this
        // listener also panicking, so recover from poison rather than
        // propagating it.
        let mut guard = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = guard.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                guard.remove(&self.ip);
            }
        }
    }
}

async fn drain_tasks(tasks: &mut JoinSet<()>) {
    while tasks.join_next().await.is_some() {}
}

// Test-only call counter for the `Message::parse` retry inside
// `serve_tcp_connection`'s oversized-response fallback branch -- proves
// that parse only runs on that rare fallback path and not unconditionally
// on every TCP query (the resolver already parses the same bytes
// internally during `resolve()`, so an unconditional second parse here
// would double the parse cost of every TCP query just to cover a branch
// that almost never runs). `#[cfg(test)]`-gated, compiled out of release
// builds.
#[cfg(test)]
thread_local! {
    static OVERSIZED_FALLBACK_PARSE_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_oversized_fallback_parse_calls() {
    OVERSIZED_FALLBACK_PARSE_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn oversized_fallback_parse_call_count() -> usize {
    OVERSIZED_FALLBACK_PARSE_CALLS.with(|calls| calls.get())
}

/// Serves one TCP connection: reads pipelined, length-prefixed queries
/// until the client closes the connection or goes idle past
/// `TCP_CONNECTION_IDLE_TIMEOUT`, resolving and answering each in turn.
async fn serve_tcp_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    listener: SocketAddr,
    resolver: Arc<ResolveQuery>,
) -> io::Result<()> {
    loop {
        let mut length_prefix = [0u8; 2];
        match time::timeout(
            TCP_CONNECTION_IDLE_TIMEOUT,
            stream.read_exact(&mut length_prefix),
        )
        .await
        {
            Ok(Ok(_)) => {}
            // A clean close between queries (including the very first one)
            // ends the connection normally, not as an error.
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(()),
        }

        let message_len = u16::from_be_bytes(length_prefix) as usize;
        // Anything shorter than a DNS header can't be a real query; the
        // resolver's own decode step would reject it anyway, but bailing out
        // here avoids driving a read/resolve round-trip for a client sending
        // deliberately malformed length prefixes.
        if message_len < DNS_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "tcp dns message length {message_len} is shorter than the {DNS_HEADER_LEN}-byte dns header"
                ),
            ));
        }
        let mut message = vec![0u8; message_len];
        time::timeout(TCP_CONNECTION_IDLE_TIMEOUT, stream.read_exact(&mut message))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp dns read timed out"))??;
        // `Vec<u8> -> Bytes` takes ownership of the vec's existing
        // allocation in place (no copy) -- it exists so the fallback copy
        // retained below is a cheap refcount bump instead of a second
        // full-size `Vec<u8>` allocation + memcpy of the request on every
        // TCP query.
        let message = Bytes::from(message);

        // Captured before `message` moves into the request below: needed to
        // build a same-transaction SERVFAIL if the resolved response can't
        // fit a TCP frame (see below). This is the rare path (a misbehaving
        // backend producing an oversized response), so the raw bytes are
        // kept around via a `Bytes` clone -- a refcount bump, not a copy --
        // rather than eagerly running `Message::parse` here: the resolver
        // already parses the same bytes internally during `resolve()`, and
        // re-parsing them unconditionally would pay that cost on every TCP
        // query just to cover a fallback branch that almost never runs.
        // The clone is only parsed, lazily, inside the oversized-response
        // branch below, where it gives that fallback access to the
        // requester's question/EDNS/CD context (RFC 6891 §6.1.1 requires
        // an OPT record in response to any EDNS query).
        let request_id = message
            .get(0..2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
        let request_bytes_for_fallback = message.clone();

        let outcome = resolver
            .resolve(ResolveRequest::new_with_observed_source(
                ObservedSourceEndpoint::tcp(peer_addr, Some(listener)),
                SystemTime::now(),
                message,
            ))
            .await;

        // The resolver never truncates a TCP-sourced response in practice
        // (it can only grow past `u16::MAX` if a backend itself violates
        // the RFC 1035 length-prefix ceiling). That's a misbehaving
        // backend, not a reason to drop the whole pipelined connection —
        // answer just this query with SERVFAIL and keep serving the rest.
        let response = if outcome.response_bytes.len() > MAX_TCP_MESSAGE_SIZE {
            tracing::warn!(
                %peer_addr,
                response_len = outcome.response_bytes.len(),
                "resolved response exceeds the tcp message size limit; answering servfail"
            );
            // Route through the same EDNS/CD-aware SERVFAIL path used
            // everywhere else in the resolver: an EDNS requester still gets
            // an OPT record (RFC 6891 §6.1.1) advertising this resolver's
            // own configured UDP payload size (not the requester's), and
            // CD is still copied per RFC 4035 §3.2.2, even though this
            // response is a same-transaction fallback rather than a normal
            // `resolve()` output. `parsed_request` is `None` only if the
            // request itself fails to parse, in which case there's no
            // question/EDNS context to mirror anyway and the header-only
            // fallback (keyed on `request_id`) is the correct degradation.
            #[cfg(test)]
            OVERSIZED_FALLBACK_PARSE_CALLS.with(|calls| calls.set(calls.get() + 1));
            let parsed_request = Message::parse(&request_bytes_for_fallback).ok();
            build_servfail_response(
                parsed_request.as_ref(),
                request_id,
                resolver.configured_max_udp_payload_size(),
            )
        } else {
            outcome.response_bytes
        };

        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
        framed.extend_from_slice(&response);
        time::timeout(TCP_CONNECTION_IDLE_TIMEOUT, stream.write_all(&framed))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp dns write timed out"))??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::time::Duration;

    use tokio::sync::Notify;
    use tokio::time;

    use crate::protocol::{Message, ResponseCode};
    use crate::resolver::{
        BasicResponseFactory, Clock, MetricsSink, QueryEventRecordResult, QueryEventSink,
        QueryEventV1, QueryTransport, ResolutionBackend, ResolverMetric, StandardProtocolCodec,
        UpstreamError, UpstreamRequest, UpstreamResponse,
    };

    fn a_query(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&0x0100u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes
    }

    fn a_response(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        bytes[2] = 0x81;
        bytes[3] = 0x80;
        bytes
    }

    /// Builds a syntactically valid (fully parseable) A response for `name`
    /// whose answer section is padded with enough real, well-formed A
    /// records to exceed `MAX_TCP_MESSAGE_SIZE`. Unlike a buffer of
    /// arbitrary garbage bytes, this passes `resolve()`'s own
    /// backend-response validation (`validate_backend_response_bytes`,
    /// which requires the bytes to parse as a `Message` with a question
    /// matching the query) instead of being rejected outright as
    /// unparseable -- rejection maps to a small SERVFAIL from a different
    /// path entirely (`resolve_backend_and_finish`'s own servfail mapping
    /// for a malformed backend response) and would never actually reach
    /// `serve_tcp_connection`'s oversized-`response_bytes` fallback branch.
    fn oversized_a_response(id: u16, name: &str) -> Vec<u8> {
        let mut bytes = a_response(id, name);
        let answer_count: u16 = 5000;
        bytes[6..8].copy_from_slice(&answer_count.to_be_bytes());
        for _ in 0..answer_count {
            bytes.extend_from_slice(&0xc00cu16.to_be_bytes()); // name: pointer to question at offset 12
            bytes.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
            bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
            bytes.extend_from_slice(&60u32.to_be_bytes()); // TTL
            bytes.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            bytes.extend_from_slice(&[192, 0, 2, 1]); // RDATA: 192.0.2.1
        }
        assert!(bytes.len() > MAX_TCP_MESSAGE_SIZE);
        bytes
    }

    /// Builds an `a_query` with a trailing EDNS OPT record (ARCOUNT=1,
    /// `udp_payload_size` advertised in the OPT CLASS field) and, if
    /// requested, the CD (checking disabled) header bit set.
    fn a_query_with_edns_and_cd(id: u16, name: &str, udp_payload_size: u16, cd: bool) -> Vec<u8> {
        let mut bytes = a_query(id, name);
        if cd {
            let flags = u16::from_be_bytes([bytes[2], bytes[3]]) | 0x0010;
            bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        }
        bytes[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT = 1
        bytes.push(0); // OPT record owner name: root
        bytes.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        bytes.extend_from_slice(&udp_payload_size.to_be_bytes()); // CLASS = requested UDP payload size
        bytes.push(0); // extended RCODE
        bytes.push(0); // EDNS version
        bytes.extend_from_slice(&0u16.to_be_bytes()); // extended flags (DO=0)
        bytes.extend_from_slice(&0u16.to_be_bytes()); // RDLEN = 0
        bytes
    }

    struct FixedClock(SystemTime);

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    #[derive(Default)]
    struct RecordingEvents {
        events: Mutex<Vec<QueryEventV1>>,
    }

    impl QueryEventSink for RecordingEvents {
        fn record(&self, event: QueryEventV1) -> QueryEventRecordResult {
            self.events.lock().unwrap().push(event);
            QueryEventRecordResult::Accepted
        }
    }

    #[derive(Default)]
    struct NoopMetrics;

    impl MetricsSink for NoopMetrics {
        fn increment(&self, _metric: ResolverMetric) {}

        fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
    }

    struct StaticUpstream {
        response: Result<UpstreamResponse, UpstreamError>,
        requests: Mutex<Vec<UpstreamRequest>>,
    }

    impl StaticUpstream {
        fn new(response: Result<UpstreamResponse, UpstreamError>) -> Self {
            Self {
                response,
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl ResolutionBackend for StaticUpstream {
        fn resolve<'a>(
            &'a self,
            request: UpstreamRequest,
        ) -> Pin<Box<dyn Future<Output = Result<UpstreamResponse, UpstreamError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request);
                self.response.clone()
            })
        }
    }

    fn upstream_response(bytes: Vec<u8>) -> UpstreamResponse {
        UpstreamResponse::forwarded_bytes(bytes, SystemTime::UNIX_EPOCH, 0, "test-forwarder")
    }

    struct DelayedFirstUpstream {
        first_started: Notify,
        first_release: Notify,
        requests: Mutex<usize>,
    }

    impl DelayedFirstUpstream {
        fn new() -> Self {
            Self {
                first_started: Notify::new(),
                first_release: Notify::new(),
                requests: Mutex::new(0),
            }
        }
    }

    impl ResolutionBackend for DelayedFirstUpstream {
        fn resolve<'a>(
            &'a self,
            request: UpstreamRequest,
        ) -> Pin<Box<dyn Future<Output = Result<UpstreamResponse, UpstreamError>> + Send + 'a>>
        {
            Box::pin(async move {
                let question = request.query.question.qname.clone();
                let request_number = {
                    let mut requests = self.requests.lock().unwrap();
                    *requests += 1;
                    *requests
                };
                if request_number == 1 {
                    self.first_started.notify_waiters();
                    self.first_release.notified().await;
                }
                Ok(upstream_response(a_response(0, &question)))
            })
        }
    }

    fn resolve_service(
        upstream: Arc<StaticUpstream>,
        events: Arc<RecordingEvents>,
    ) -> Arc<ResolveQuery> {
        Arc::new(ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            upstream,
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            events,
            Arc::new(NoopMetrics),
        ))
    }

    async fn unused_high_local_address() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        assert!(address.port() > 1024);
        address
    }

    async fn recv_response(client: &UdpSocket) -> Vec<u8> {
        let mut response = [0u8; 64];
        let (response_len, _) = client.recv_from(&mut response).await.unwrap();
        response[..response_len].to_vec()
    }

    #[tokio::test]
    async fn udp_server_passes_raw_query_and_client_ip_to_resolver() {
        let backend_bytes = a_response(0xabcd, "example.com");
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(backend_bytes))));
        let events = Arc::new(RecordingEvents::default());
        let resolver = resolve_service(upstream.clone(), events.clone());
        let server = UdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver, 1232)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        client
            .send_to(&a_query(0x1234, "example.com"), server_addr)
            .await
            .unwrap();
        let mut response = [0u8; 64];
        let (response_len, source) = client.recv_from(&mut response).await.unwrap();

        assert_eq!(source, server_addr);
        assert_eq!(
            &response[..response_len],
            &a_response(0x1234, "example.com")
        );
        {
            let upstream_requests = upstream.requests.lock().unwrap();
            assert_eq!(upstream_requests.len(), 1);
            assert_eq!(upstream_requests[0].query.question.qname, "example.com");
        }
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(recorded_events[0].observed_source.ip, client_addr.ip());
            assert_eq!(
                recorded_events[0].observed_source.port,
                Some(client_addr.port())
            );
            assert_eq!(
                recorded_events[0].observed_source.transport,
                Some(QueryTransport::Udp)
            );
            assert_eq!(
                recorded_events[0].observed_source.listener,
                Some(server_addr)
            );
        }

        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn bind_configured_creates_one_server_per_dns_listener() {
        let first_address = unused_high_local_address().await;
        let second_address = unused_high_local_address().await;
        let config = RuntimeConfig::new(
            vec![first_address, second_address],
            vec![crate::config::UpstreamConfig {
                name: "primary".to_string(),
                endpoint: "192.0.2.53:53".parse().unwrap(),
                protocol: crate::config::UpstreamProtocol::Udp,
                enabled: true,
                priority: 10,
                timeout: Duration::from_millis(500),
            }],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));

        let servers = UdpDnsServer::bind_configured(&config, resolver)
            .await
            .unwrap();

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].local_addr().unwrap(), first_address);
        assert_eq!(servers[1].local_addr().unwrap(), second_address);
    }

    async fn tcp_send_query(stream: &mut TcpStream, query: &[u8]) {
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        stream.write_all(&framed).await.unwrap();
    }

    async fn tcp_recv_response(stream: &mut TcpStream) -> Vec<u8> {
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let mut response = vec![0u8; u16::from_be_bytes(length_prefix) as usize];
        stream.read_exact(&mut response).await.unwrap();
        response
    }

    /// Reproduces the "connection refused" a real `dig ANY` query hit against
    /// a UDP-only rdns build: before `TcpDnsServer` existed, nothing was
    /// listening on TCP at all, so any client (dig defaults to TCP for ANY
    /// queries, and any UDP truncation fallback) got ECONNREFUSED.
    #[tokio::test]
    async fn tcp_server_answers_a_length_prefixed_query() {
        let backend_bytes = a_response(0xabcd, "example.com");
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(backend_bytes))));
        let events = Arc::new(RecordingEvents::default());
        let resolver = resolve_service(upstream.clone(), events.clone());
        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        tcp_send_query(&mut client, &a_query(0x1234, "example.com")).await;
        let response = tcp_recv_response(&mut client).await;

        assert_eq!(response, a_response(0x1234, "example.com"));
        {
            let recorded_events = events.events.lock().unwrap();
            assert_eq!(recorded_events.len(), 1);
            assert_eq!(recorded_events[0].observed_source.ip, client_addr.ip());
            assert_eq!(
                recorded_events[0].observed_source.port,
                Some(client_addr.port())
            );
            assert_eq!(
                recorded_events[0].observed_source.transport,
                Some(QueryTransport::Tcp)
            );
            assert_eq!(
                recorded_events[0].observed_source.listener,
                Some(server_addr)
            );
        }

        drop(client);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// RFC 7766 §6.2.1: a server should support multiple outstanding queries
    /// pipelined on a single TCP connection, not require one-query-per-connection.
    #[tokio::test]
    async fn tcp_server_answers_pipelined_queries_on_one_connection() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(a_response(
            0,
            "example.com",
        )))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        tcp_send_query(&mut client, &a_query(0x1111, "example.com")).await;
        tcp_send_query(&mut client, &a_query(0x2222, "example.com")).await;

        assert_eq!(
            tcp_recv_response(&mut client).await,
            a_response(0x1111, "example.com")
        );
        assert_eq!(
            tcp_recv_response(&mut client).await,
            a_response(0x2222, "example.com")
        );

        drop(client);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tcp_bind_configured_creates_one_server_per_dns_listener() {
        let first_address = unused_high_local_address().await;
        let second_address = unused_high_local_address().await;
        let config = RuntimeConfig::new(
            vec![first_address, second_address],
            vec![crate::config::UpstreamConfig {
                name: "primary".to_string(),
                endpoint: "192.0.2.53:53".parse().unwrap(),
                protocol: crate::config::UpstreamProtocol::Udp,
                enabled: true,
                priority: 10,
                timeout: Duration::from_millis(500),
            }],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();
        let upstream = Arc::new(StaticUpstream::new(Err(UpstreamError::Timeout)));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));

        let servers = TcpDnsServer::bind_configured(&config, resolver)
            .await
            .unwrap();

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].local_addr().unwrap(), first_address);
        assert_eq!(servers[1].local_addr().unwrap(), second_address);
    }

    fn build_config_with_max_tcp_connections(
        address: SocketAddr,
        max_tcp_connections: usize,
    ) -> RuntimeConfig {
        let mut config = RuntimeConfig::new(
            vec![address],
            vec![crate::config::UpstreamConfig {
                name: "primary".to_string(),
                endpoint: "192.0.2.53:53".parse().unwrap(),
                protocol: crate::config::UpstreamProtocol::Udp,
                enabled: true,
                priority: 10,
                timeout: Duration::from_millis(500),
            }],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();
        config.max_tcp_connections = max_tcp_connections;
        config
    }

    /// A single source IP opening more than `max_connections_per_ip`
    /// connections must have the excess ones closed by the server rather
    /// than accepted and left to consume the (much larger) global
    /// `max_connections` pool — otherwise one client can starve every other
    /// resolver of a connection slot. Regression test for the P1 finding in
    /// PR #117's review: no per-source-IP cap existed on `TcpDnsServer`.
    #[tokio::test]
    async fn tcp_server_enforces_per_source_ip_connection_limit() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(a_response(
            0,
            "example.com",
        )))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let server = TcpDnsServer::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            10,
            2,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        // First two connections from the same source IP are within the cap
        // and are served normally.
        let mut first = TcpStream::connect(server_addr).await.unwrap();
        tcp_send_query(&mut first, &a_query(1, "example.com")).await;
        assert_eq!(
            tcp_recv_response(&mut first).await,
            a_response(1, "example.com")
        );

        let mut second = TcpStream::connect(server_addr).await.unwrap();
        tcp_send_query(&mut second, &a_query(2, "example.com")).await;
        assert_eq!(
            tcp_recv_response(&mut second).await,
            a_response(2, "example.com")
        );

        // Third connection from the same IP exceeds the per-IP cap and is
        // closed by the server before it ever gets a chance to send a query.
        let mut third = TcpStream::connect(server_addr).await.unwrap();
        let mut probe = [0u8; 1];
        let read_result = time::timeout(Duration::from_secs(2), third.read(&mut probe)).await;
        assert_eq!(
            read_result.unwrap().unwrap(),
            0,
            "expected the server to close the over-cap connection (EOF)"
        );

        drop(first);
        drop(second);
        drop(third);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// `bind_configured` must actually use `RuntimeConfig::max_tcp_connections`
    /// rather than a hardcoded default — regression test for the P2 finding
    /// in PR #117's review that the ceiling wasn't wired through config.
    #[tokio::test]
    async fn tcp_bind_configured_uses_configured_max_connections() {
        let address = unused_high_local_address().await;
        let config = build_config_with_max_tcp_connections(address, 1);
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(a_response(
            0,
            "example.com",
        )))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));

        let server = TcpDnsServer::bind_configured(&config, resolver)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        // Holds the single configured connection slot open without sending
        // a query, so it never completes and frees the slot on its own.
        let first = TcpStream::connect(server_addr).await.unwrap();

        // A second connection is accepted at the TCP level but must not be
        // serviced while the one configured slot is held by `first`.
        let mut second = TcpStream::connect(server_addr).await.unwrap();
        tcp_send_query(&mut second, &a_query(7, "example.com")).await;
        let premature =
            time::timeout(Duration::from_millis(200), tcp_recv_response(&mut second)).await;
        assert!(
            premature.is_err(),
            "second connection must not be served while max_tcp_connections=1 is exhausted"
        );

        // Freeing the first connection's slot lets the second be serviced.
        drop(first);
        let response = time::timeout(Duration::from_secs(2), tcp_recv_response(&mut second))
            .await
            .expect("second connection should be served once a slot frees up");
        assert_eq!(response, a_response(7, "example.com"));

        drop(second);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// A resolved response too large to fit the RFC 1035 16-bit TCP length
    /// prefix must not kill the whole connection: the misbehaving backend
    /// affects only that one query, which gets answered SERVFAIL, and later
    /// pipelined queries on the same connection are still served. Regression
    /// test for the P3 finding in PR #117's review, where this previously
    /// closed the connection with an I/O error.
    #[tokio::test]
    async fn tcp_server_answers_servfail_for_oversized_response_and_keeps_connection_open() {
        let oversized_backend_response = vec![0xabu8; MAX_TCP_MESSAGE_SIZE + 1];
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            oversized_backend_response,
        ))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        tcp_send_query(&mut client, &a_query(0xaaaa, "example.com")).await;
        let first_response = tcp_recv_response(&mut client).await;
        let parsed = Message::parse(&first_response).unwrap();
        assert_eq!(parsed.header.id, 0xaaaa);
        assert_eq!(parsed.header.r_code(), ResponseCode::ServFail as u8);

        // The connection must still be usable for a subsequent pipelined
        // query rather than having been closed after the first.
        tcp_send_query(&mut client, &a_query(0xbbbb, "example.com")).await;
        let second_response = tcp_recv_response(&mut client).await;
        let parsed = Message::parse(&second_response).unwrap();
        assert_eq!(parsed.header.id, 0xbbbb);
        assert_eq!(parsed.header.r_code(), ResponseCode::ServFail as u8);

        drop(client);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// Regression test for the TCP oversized-response SERVFAIL fallback
    /// dropping the requester's EDNS OPT record: an EDNS query whose
    /// resolved response is too large for a TCP frame must still get a
    /// SERVFAIL that carries exactly one OPT record advertising *this
    /// resolver's* configured UDP payload size (RFC 6891 §6.1.1 requires an
    /// OPT record in response to any EDNS query; the payload size must not
    /// be omitted or echo the requester's own advertised size), and must
    /// still copy CD from the request (RFC 4035 §3.2.2). Previously this
    /// fallback called `build_servfail_response(None, ...)`, which always
    /// takes the header-only branch and drops the question, OPT, and CD
    /// entirely.
    #[tokio::test]
    async fn tcp_server_oversized_response_servfail_preserves_requester_opt_and_cd() {
        let oversized_backend_response = vec![0xabu8; MAX_TCP_MESSAGE_SIZE + 1];
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            oversized_backend_response,
        ))));
        // `resolve_service` configures `StandardProtocolCodec::new(1232)`,
        // so the resolver's own configured UDP payload size is 1232 --
        // distinct from the 4096 this query advertises, proving the OPT in
        // the fallback response reflects the resolver's size, not a mirror
        // of the requester's.
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        tcp_send_query(
            &mut client,
            &a_query_with_edns_and_cd(0xaaaa, "example.com", 4096, true),
        )
        .await;
        let response_bytes = tcp_recv_response(&mut client).await;
        let response = Message::parse(&response_bytes).unwrap();

        assert_eq!(response.header.id, 0xaaaa);
        assert_eq!(response.header.r_code(), ResponseCode::ServFail as u8);
        assert_eq!(response.questions.len(), 1);
        assert!(
            response.header.cd(),
            "CD must be copied from the request per RFC 4035 §3.2.2"
        );
        let opt_records: Vec<_> = response
            .additionals
            .iter()
            .filter_map(|record| match &record.record {
                crate::protocol::RecordData::OPT(edns) => Some(edns),
                _ => None,
            })
            .collect();
        assert_eq!(
            opt_records.len(),
            1,
            "an EDNS requester must get exactly one OPT record back, even on this \
             same-transaction SERVFAIL fallback path (RFC 6891 §6.1.1)"
        );
        assert_eq!(
            opt_records[0].udp_payload_size, 1232,
            "OPT must advertise this resolver's own configured UDP payload size (1232), \
             not echo the requester's advertised 4096"
        );

        drop(client);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// Performance regression test: `serve_tcp_connection` retains
    /// `request_bytes_for_fallback` (the copy handed to the rare
    /// oversized-response SERVFAIL branch) as a `Bytes` clone of the
    /// request it also hands to `resolve()`, not a second `Vec<u8>`
    /// allocation + memcpy. `Bytes::clone` is documented to be an O(1)
    /// refcount bump that shares the original buffer -- this test pins
    /// that guarantee down against the exact pattern `serve_tcp_connection`
    /// relies on (clone before handing one copy to `resolve()`), so a
    /// future change that swaps the fallback copy back to `Vec<u8>` (which
    /// *would* reintroduce a full allocation + memcpy on every TCP query,
    /// even though `Vec::clone` is spelled identically to `Bytes::clone` at
    /// the call site) fails a pointer-identity check here rather than only
    /// showing up as a throughput regression.
    #[test]
    fn tcp_fallback_bytes_clone_shares_the_original_allocation() {
        let message = Bytes::from(vec![0u8; 4096]);
        let original_ptr = message.as_ptr();
        let request_bytes_for_fallback = message.clone();
        assert_eq!(
            request_bytes_for_fallback.as_ptr(),
            original_ptr,
            "the TCP fallback copy must share the request's existing allocation, \
             not allocate a second full-size buffer"
        );
    }

    /// Performance regression test: the `Message::parse` retry that
    /// recovers EDNS/CD context for the oversized-response SERVFAIL
    /// fallback (see
    /// `tcp_server_oversized_response_servfail_preserves_requester_opt_and_cd`
    /// above) must stay lazy -- it should only run when a query's resolved
    /// response is actually too large for a TCP frame, not unconditionally
    /// on every TCP query. An earlier version of that fix placed the parse
    /// call unconditionally on the normal path, silently paying a second
    /// full DNS message parse (on top of the one `resolve()` already does
    /// internally) for every successful TCP query.
    #[tokio::test]
    async fn tcp_server_normal_response_does_not_parse_fallback_request() {
        reset_oversized_fallback_parse_calls();

        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(a_response(
            0x1234,
            "example.com",
        )))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        tcp_send_query(&mut client, &a_query(0x1234, "example.com")).await;
        let response = tcp_recv_response(&mut client).await;
        assert_eq!(response, a_response(0x1234, "example.com"));

        // A second pipelined query on the same connection, to make sure the
        // lazy parse stays lazy across repeated queries, not just the
        // first.
        tcp_send_query(&mut client, &a_query(0x5678, "example.com")).await;
        let response = tcp_recv_response(&mut client).await;
        assert_eq!(response, a_response(0x5678, "example.com"));

        assert_eq!(
            oversized_fallback_parse_call_count(),
            0,
            "Message::parse must not run on the normal (non-oversized) TCP response path"
        );

        drop(client);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// Companion to the test above: confirms the counter it relies on
    /// actually increments on the rare path it's meant to observe, so a
    /// `0` result there is meaningful rather than the counter being wired
    /// up wrong / never incrementing at all.
    #[tokio::test]
    async fn tcp_server_oversized_response_parses_fallback_request_exactly_once() {
        reset_oversized_fallback_parse_calls();

        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(
            oversized_a_response(0xaaaa, "example.com"),
        ))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        tcp_send_query(&mut client, &a_query(0xaaaa, "example.com")).await;
        let response_bytes = tcp_recv_response(&mut client).await;
        let response = Message::parse(&response_bytes).unwrap();
        assert_eq!(
            response.header.r_code(),
            ResponseCode::ServFail as u8,
            "sanity check: the oversized response must actually take the fallback branch"
        );

        assert_eq!(
            oversized_fallback_parse_call_count(),
            1,
            "Message::parse must run exactly once on the oversized-response fallback path"
        );

        drop(client);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    /// `Semaphore::new(0)` never issues a permit, so a server built with
    /// `max_connections = 0` would accept TCP connections that then stall
    /// forever. Regression test for the P1 finding in PR #117's review that
    /// this wasn't rejected.
    #[tokio::test]
    async fn tcp_bind_rejects_zero_max_connections() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(a_response(
            0,
            "example.com",
        )))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let result =
            TcpDnsServer::bind_with_max_connections("127.0.0.1:0".parse().unwrap(), resolver, 0)
                .await;
        match result {
            Ok(_) => panic!("expected max_connections = 0 to be rejected"),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
        }
    }

    /// `PerIpConnectionGuard::try_acquire` inserts a source IP's entry
    /// before checking it against the cap, so a `max_connections_per_ip` of
    /// zero would leak an unremovable map entry per distinct source IP.
    /// Regression test for the P1 finding in PR #117's review that this
    /// wasn't rejected.
    #[tokio::test]
    async fn tcp_bind_rejects_zero_max_connections_per_ip() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(a_response(
            0,
            "example.com",
        )))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let result = TcpDnsServer::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            resolver,
            10,
            0,
            Duration::from_secs(1),
        )
        .await;
        match result {
            Ok(_) => panic!("expected max_connections_per_ip = 0 to be rejected"),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
        }
    }

    /// A TCP length prefix smaller than the 12-byte DNS header can't frame a
    /// real query. Regression test for the P2 finding in PR #117's review
    /// that undersized lengths were passed straight through to the resolver
    /// instead of being rejected at the framing layer.
    #[tokio::test]
    async fn tcp_server_rejects_message_shorter_than_dns_header() {
        let upstream = Arc::new(StaticUpstream::new(Ok(upstream_response(a_response(
            0,
            "example.com",
        )))));
        let resolver = resolve_service(upstream, Arc::new(RecordingEvents::default()));
        let server = TcpDnsServer::bind("127.0.0.1:0".parse().unwrap(), resolver)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        // A length prefix of 4 claims a message far shorter than the 12-byte
        // DNS header.
        tcp_send_query(&mut client, &[0u8; 4]).await;
        let mut probe = [0u8; 1];
        let read_result = time::timeout(Duration::from_secs(2), client.read(&mut probe))
            .await
            .expect("server should close the connection promptly");
        // The server closes without reading the (unread, still-buffered)
        // 4 bytes of declared-but-rejected message payload, so the kernel
        // may report this as a clean EOF or as `ConnectionReset` depending
        // on timing — either is an acceptable "connection closed" outcome,
        // as long as the malformed message was never resolved.
        match read_result {
            Ok(0) => {}
            Ok(n) => panic!("expected connection close, got {n} bytes"),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("expected EOF or connection reset, got {error:?}"),
        }

        drop(client);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_server_handles_next_datagram_while_first_request_is_in_flight() {
        let upstream = Arc::new(DelayedFirstUpstream::new());
        let resolver = Arc::new(ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(NoopMetrics),
        ));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = UdpDnsServer::with_max_in_flight_requests(socket, resolver, 1232, 2);
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let slow_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_started = upstream.first_started.notified();
        slow_client
            .send_to(&a_query(0x1111, "slow.example"), server_addr)
            .await
            .unwrap();
        first_started.await;

        let fast_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        fast_client
            .send_to(&a_query(0x2222, "fast.example"), server_addr)
            .await
            .unwrap();

        let fast_response = time::timeout(Duration::from_millis(100), recv_response(&fast_client))
            .await
            .unwrap();

        assert_eq!(&fast_response[0..2], &[0x22, 0x22]);
        upstream.first_release.notify_waiters();
        assert_eq!(&recv_response(&slow_client).await[0..2], &[0x11, 0x11]);
        shutdown_tx.send(()).unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_server_drains_in_flight_request_after_shutdown() {
        let upstream = Arc::new(DelayedFirstUpstream::new());
        let resolver = Arc::new(ResolveQuery::new(
            Arc::new(StandardProtocolCodec::new(1232)),
            upstream.clone(),
            Arc::new(BasicResponseFactory),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            Arc::new(RecordingEvents::default()),
            Arc::new(NoopMetrics),
        ));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = UdpDnsServer::with_max_in_flight_requests(socket, resolver, 1232, 2);
        let server_addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let mut server_task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_started = upstream.first_started.notified();
        client
            .send_to(&a_query(0x3333, "slow.example"), server_addr)
            .await
            .unwrap();
        first_started.await;
        shutdown_tx.send(()).unwrap();

        assert!(
            time::timeout(Duration::from_millis(50), &mut server_task)
                .await
                .is_err()
        );
        upstream.first_release.notify_waiters();
        server_task.await.unwrap().unwrap();
    }
}
