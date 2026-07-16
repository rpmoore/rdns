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

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{Encoder, Registry, TextEncoder};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

const DEFAULT_MAX_CONNECTIONS: usize = 32;
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(1);
/// Caps how long a single connection (including idle keep-alive time
/// between requests) may hold a semaphore permit. Without this, a client
/// that opens a connection and never sends a request — or never closes one
/// — would starve `max_connections` scrapes indefinitely, since there's no
/// TLS/auth in front of this endpoint to discourage that.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Serves a single `GET /metrics` route with the current Prometheus registry
/// encoded as text exposition format. No TLS, no auth — the endpoint's own
/// reachability is the health check.
pub struct MetricsServer {
    listener: TcpListener,
    registry: Registry,
    local_addr: SocketAddr,
    max_connections: usize,
}

impl MetricsServer {
    pub async fn bind(address: SocketAddr, registry: Registry) -> io::Result<Self> {
        Self::bind_with_max_connections(address, registry, DEFAULT_MAX_CONNECTIONS).await
    }

    pub async fn bind_with_max_connections(
        address: SocketAddr,
        registry: Registry,
        max_connections: usize,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            registry,
            local_addr,
            max_connections,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accepts connections until `shutdown` resolves. Unlike
    /// `UdpDnsServer::serve_until`, the post-shutdown drain is
    /// time-bounded: an HTTP/1.1 connection (idle keep-alive, a stalled
    /// client) isn't guaranteed to finish on its own the way a UDP
    /// datagram-handling task is, so waiting unconditionally for every
    /// in-flight connection could hang process shutdown indefinitely.
    pub async fn serve_until<S>(&self, shutdown: S) -> io::Result<()>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        let mut tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = self.accept_permitted(semaphore.clone()) => {
                    match accepted {
                        Ok(Some((stream, permit))) => self.spawn_connection(stream, permit, &mut tasks),
                        Ok(None) => break,
                        Err(error) => return Err(error),
                    }
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(join_error)) = result {
                        tracing::warn!(%join_error, "metrics server connection task panicked");
                    }
                }
            }
        }

        if tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, drain(&mut tasks))
            .await
            .is_err()
        {
            tracing::warn!(
                outstanding = tasks.len(),
                "metrics server: connections still open after shutdown grace period, aborting"
            );
            tasks.abort_all();
            drain(&mut tasks).await;
        }
        Ok(())
    }

    async fn accept_permitted(
        &self,
        semaphore: Arc<Semaphore>,
    ) -> io::Result<Option<(TcpStream, OwnedSemaphorePermit)>> {
        let (stream, _peer_addr) = self.listener.accept().await?;
        match semaphore.acquire_owned().await {
            Ok(permit) => Ok(Some((stream, permit))),
            Err(_) => Ok(None),
        }
    }

    fn spawn_connection(
        &self,
        stream: TcpStream,
        permit: OwnedSemaphorePermit,
        tasks: &mut JoinSet<()>,
    ) {
        let registry = self.registry.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let io = TokioIo::new(stream);
            let serve = hyper::server::conn::http1::Builder::new().serve_connection(
                io,
                service_fn(move |req| handle_request(req, registry.clone())),
            );
            match tokio::time::timeout(CONNECTION_TIMEOUT, serve).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(%error, "metrics server connection error"),
                Err(_) => tracing::warn!(
                    timeout_secs = CONNECTION_TIMEOUT.as_secs(),
                    "metrics server connection timed out"
                ),
            }
        });
    }
}

async fn drain(tasks: &mut JoinSet<()>) {
    while tasks.join_next().await.is_some() {}
}

async fn handle_request(
    req: Request<Incoming>,
    registry: Registry,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::GET || req.uri().path() != "/metrics" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(
                b"404 Not Found: metrics are served at GET /metrics\n",
            )))
            .expect("static response is well-formed"));
    }

    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    if let Err(error) = TextEncoder::new().encode(&metric_families, &mut buffer) {
        tracing::warn!(%error, "failed to encode prometheus metrics");
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(Bytes::new()))
            .expect("static response is well-formed"));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(buffer)))
        .expect("static response is well-formed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn run_server(
        registry: Registry,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let server = MetricsServer::bind("127.0.0.1:0".parse().unwrap(), registry)
            .await
            .unwrap();
        let addr = server.local_addr();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        (addr, shutdown_tx, task)
    }

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn serves_prometheus_text_on_get_metrics() {
        let registry = Registry::new();
        let counter = prometheus::Counter::new("test_counter_total", "a test counter").unwrap();
        counter.inc();
        registry.register(Box::new(counter)).unwrap();

        let (addr, shutdown_tx, task) = run_server(registry).await;

        let response = http_get(addr, "/metrics").await;
        let lower = response.to_ascii_lowercase();
        assert!(lower.starts_with("http/1.1 200"));
        assert!(lower.contains("content-type: text/plain; version=0.0.4; charset=utf-8"));
        assert!(response.contains("test_counter_total 1"));

        shutdown_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn returns_404_for_unknown_path() {
        let (addr, shutdown_tx, task) = run_server(Registry::new()).await;

        let response = http_get(addr, "/nope").await;
        assert!(response.starts_with("HTTP/1.1 404"));
        assert!(response.contains("404 Not Found: metrics are served at GET /metrics"));

        shutdown_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shuts_down_promptly_with_an_idle_connection_open() {
        let (addr, shutdown_tx, task) = run_server(Registry::new()).await;

        // Open a connection and never send a request, simulating an idle
        // keep-alive client that would otherwise hang the shutdown drain.
        let _idle = TcpStream::connect(addr).await.unwrap();

        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            task.await.unwrap().unwrap();
        })
        .await
        .expect("serve_until should shut down within the grace period, not hang");
    }
}
