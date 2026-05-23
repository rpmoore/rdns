use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rdns::config::RuntimeConfig;
use rdns::delivery::dns::UdpDnsServer;
use rdns::delivery::upstream::UdpUpstreamResolver;
use rdns::resolver::{
    BasicResponseFactory, BoxFuture, Clock, MetricsSink, QueryEventSink, ResolveDecision,
    ResolveQuery, ResolverMetric, StandardProtocolCodec,
};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> io::Result<()> {
    let config = RuntimeConfig::development_default();
    config
        .validate()
        .map_err(|error| io::Error::other(format!("invalid runtime config: {error:?}")))?;

    let resolver = Arc::new(ResolveQuery::new(
        Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
        Arc::new(
            UdpUpstreamResolver::from_runtime_config(&config)
                .map_err(|error| io::Error::other(format!("invalid upstream config: {error:?}")))?,
        ),
        Arc::new(BasicResponseFactory),
        Arc::new(SystemClock),
        Arc::new(StdoutEvents),
        Arc::new(NoopMetrics),
    ));

    let servers = UdpDnsServer::bind_configured(&config, resolver).await?;
    if servers.is_empty() {
        return Err(io::Error::other("no DNS listeners configured"));
    }

    let mut shutdown_senders = Vec::with_capacity(servers.len());
    let mut server_tasks = JoinSet::new();
    for server in servers {
        let address = server.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        shutdown_senders.push(shutdown_tx);
        println!("rdns listening on udp://{address}");
        server_tasks.spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
    }

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            println!("shutdown requested");
        }
        result = server_tasks.join_next() => {
            match result {
                Some(Ok(Ok(()))) => println!("DNS listener stopped"),
                Some(Ok(Err(error))) => return Err(error),
                Some(Err(error)) => return Err(io::Error::other(format!("DNS listener task failed: {error}"))),
                None => return Ok(()),
            }
        }
    }

    for shutdown_tx in shutdown_senders {
        let _ = shutdown_tx.send(());
    }

    while let Some(result) = server_tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(error) => {
                return Err(io::Error::other(format!(
                    "DNS listener task failed: {error}"
                )));
            }
        }
    }

    Ok(())
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct StdoutEvents;

impl QueryEventSink for StdoutEvents {
    fn record<'a>(&'a self, decision: ResolveDecision) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            println!("{decision:?}");
        })
    }
}

struct NoopMetrics;

impl MetricsSink for NoopMetrics {
    fn increment(&self, _metric: ResolverMetric) {}

    fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
}
