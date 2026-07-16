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

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Gauge, Histogram, MeterProvider, ObservableGauge};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Registry;
use rdns::config::{
    LocalZoneConfig, MAX_LOCAL_ZONE_FILE_BYTES, ResolutionMode as ConfigResolutionMode,
    RootHintsSource as ConfigRootHintsSource, RuntimeConfig, parse_local_zone_file,
};
use rdns::delivery::dns::{TcpDnsServer, UdpDnsServer};
use rdns::delivery::metrics_http::MetricsServer;
use rdns::delivery::upstream::{ForwardingResolutionBackend, RecursiveAuthorityTransportClient};
use rdns::resolver::{
    BackendHealth, BackendRootHintsStatus, BackendSnapshot, BackendStatus, BasicResponseFactory,
    CacheTtlPolicy, ChannelQueryEventSink, Clock, CookieSecret, DnssecValidationStatus,
    DomainDnsCache, DomainName, InMemoryLocalDnsEntries, InMemoryQueryEventStore,
    InMemoryQueryEventStoreConfig, InMemorySuspiciousLookupClassifier,
    InMemorySuspiciousLookupClassifierConfig, LocalDnsEntry, MetricsSink, NoopPolicyEvaluator,
    QueryEventRecordResult, QueryEventSink, QueryEventV1, RecursiveResolutionBackend,
    RecursiveResolverConfig, RecursiveRootHint, ResolutionMode as ResolverResolutionMode,
    ResolveQuery, ResolverMetric, ShardedDnsCache, StandardProtocolCodec, SystemClock,
};
use tokio::task::{JoinError, JoinSet};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_QUERY_EVENT_STORE_ENTRIES: usize = 10_000;
const QUERY_EVENT_QUEUE_CAPACITY: usize = 1024;
const CONFIG_PATH_ENV_VAR: &str = "RDNS_CONFIG";
const DEFAULT_CONFIG_PATH: &str = "config.toml";

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Installs the global `tracing` subscriber: JSON-formatted events on
/// stdout, level controlled by `RUST_LOG` (defaults to `info`).
fn init_logging() {
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(io::stdout)
        .init();
}

#[tokio::main]
async fn main() -> io::Result<()> {
    if handle_version_command(std::env::args().skip(1)) {
        return Ok(());
    }

    init_logging();

    let config_path = resolve_config_path();
    let config = load_runtime_config(config_path.as_deref())?;
    match &config_path {
        Some(path) => info!(path = %path.display(), "loaded config"),
        None => info!("no config file found; using built-in development defaults"),
    }

    let stdout_events = Arc::new(StdoutEvents);
    let query_event_store = Arc::new(InMemoryQueryEventStore::new(
        InMemoryQueryEventStoreConfig {
            max_retained_events: DEFAULT_QUERY_EVENT_STORE_ENTRIES,
            ..InMemoryQueryEventStoreConfig::default()
        },
    ));
    let (event_tx, mut event_rx) =
        tokio::sync::mpsc::channel::<QueryEventV1>(QUERY_EVENT_QUEUE_CAPACITY);
    let event_drain = {
        let stdout_events = Arc::clone(&stdout_events);
        let query_event_store = Arc::clone(&query_event_store);
        let classifier = InMemorySuspiciousLookupClassifier::new(
            InMemorySuspiciousLookupClassifierConfig::default(),
        );
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let event = query_event_store.record_classified(event, &classifier);
                stdout_events.record_ref(&event);
            }
        })
    };

    let cache = Arc::new(ShardedDnsCache::new(&config.cache));
    let (metrics, metrics_registry): (Arc<dyn MetricsSink>, Registry) = if !config.metrics.enabled {
        (Arc::new(NoopMetrics), Registry::new())
    } else {
        match OpenTelemetryMetrics::new(Arc::clone(&cache)) {
            Ok(m) => {
                let registry = m.registry.clone();
                (Arc::new(m), registry)
            }
            Err(error) => {
                error!(%error, "failed to initialize Prometheus metrics exporter");
                (Arc::new(NoopMetrics), Registry::new())
            }
        }
    };
    let backend_snapshot = build_backend_snapshot(&config, Arc::clone(&metrics))?;
    let (local_entries, local_entry_counts) = build_local_entries(&config, config_path.as_deref())?;
    info!(summary = %local_entry_summary(&local_entry_counts), "loaded local dns entries");
    let reload_metrics = Arc::clone(&metrics);
    let max_chain_depth = config
        .resolution
        .recursive
        .as_ref()
        .map(|recursive| recursive.max_cname_restarts)
        .unwrap_or(8);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let cookie_secret = Arc::new(CookieSecret::generate());
    let resolver = Arc::new(
        ResolveQuery::with_cache_policy_and_backend_snapshot(
            Arc::new(StandardProtocolCodec::new(config.max_udp_payload_size)),
            Arc::clone(&cache) as Arc<dyn DomainDnsCache>,
            Arc::new(NoopPolicyEvaluator),
            local_entries,
            CacheTtlPolicy::default(),
            backend_snapshot,
            Arc::new(BasicResponseFactory),
            Arc::clone(&clock),
            Arc::new(StoreRecordingQueryEventSink::new(
                ChannelQueryEventSink::new(event_tx),
                Arc::clone(&query_event_store),
            )),
            metrics,
        )
        .with_max_chain_depth(max_chain_depth)
        .with_single_flight_shard_count(cache.shard_count())
        .with_chaos_config(config.chaos.clone())
        .with_cookie_secret(cookie_secret),
    );

    let sighup_task =
        spawn_sighup_reload_task(Arc::clone(&resolver), reload_metrics, config_path.clone());

    let servers =
        UdpDnsServer::bind_configured(&config, Arc::clone(&resolver), Arc::clone(&clock)).await?;
    if servers.is_empty() {
        return Err(io::Error::other("no DNS listeners configured"));
    }
    // TCP is not an optional fallback transport (RFC 1035 §4.2, RFC 7766):
    // clients may connect over TCP directly, and a UDP response we truncate
    // (`TC=1`) is a promise that the same query will succeed over TCP, so a
    // bind failure here is as fatal as a UDP bind failure.
    let tcp_servers =
        TcpDnsServer::bind_configured(&config, Arc::clone(&resolver), Arc::clone(&clock)).await?;
    // A metrics-listener bind failure (e.g. the configured port is already in
    // use by something else on the host) must not prevent the DNS resolver
    // itself from starting — metrics are optional observability, not a core
    // dependency. Log and continue without the endpoint instead of `?`.
    let metrics_server = if config.metrics.enabled {
        match MetricsServer::bind_with_max_connections(
            config.metrics.listen,
            metrics_registry,
            config.metrics.max_connections,
        )
        .await
        {
            Ok(server) => Some(server),
            Err(error) => {
                error!(
                    %error,
                    address = %config.metrics.listen,
                    "failed to bind metrics listener; continuing without it"
                );
                None
            }
        }
    } else {
        None
    };

    serve_until_shutdown(
        servers,
        tcp_servers,
        metrics_server,
        resolver,
        sighup_task,
        event_drain,
    )
    .await
}

/// Runs the bound listeners until `ctrl_c` or a listener task exits, then
/// tears everything down in dependency order: stop accepting new listener
/// work, join the listener tasks, stop the SIGHUP reload task, drop the
/// resolver (closing the query-event channel), and drain the event-recording
/// task.
async fn serve_until_shutdown(
    servers: Vec<UdpDnsServer>,
    tcp_servers: Vec<TcpDnsServer>,
    metrics_server: Option<MetricsServer>,
    resolver: Arc<ResolveQuery>,
    sighup_task: tokio::task::JoinHandle<()>,
    event_drain: tokio::task::JoinHandle<()>,
) -> io::Result<()> {
    let mut shutdown_senders = Vec::with_capacity(servers.len() + tcp_servers.len());
    let mut server_tasks = JoinSet::new();
    for server in servers {
        let address = server.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        shutdown_senders.push(shutdown_tx);
        info!(%address, "rdns listening on udp");
        server_tasks.spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
    }
    for server in tcp_servers {
        let address = server.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        shutdown_senders.push(shutdown_tx);
        info!(%address, "rdns listening on tcp");
        server_tasks.spawn(async move {
            server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
    }

    // The metrics listener is optional observability, not part of the DNS
    // service's fault domain: it gets its own shutdown signal and task
    // handle, kept out of `server_tasks` so a metrics-listener error can
    // never trigger (or block) DNS shutdown — it's only ever logged.
    let metrics_shutdown = metrics_server.map(|metrics_server| {
        let address = metrics_server.local_addr();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        info!(%address, "rdns metrics listening on http");
        let task = tokio::spawn(async move {
            let result = metrics_server
                .serve_until(async {
                    let _ = shutdown_rx.await;
                })
                .await;
            if let Err(error) = &result {
                warn!(%error, "metrics listener exited with an error");
            }
            result
        });
        (shutdown_tx, task)
    });

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal?;
            info!("shutdown requested");
        }
        result = server_tasks.join_next() => {
            match result {
                Some(result) => {
                    listener_task_result_to_io(result)?;
                    warn!("dns listener stopped");
                }
                None => return Ok(()),
            }
        }
    }

    for shutdown_tx in shutdown_senders {
        let _ = shutdown_tx.send(());
    }

    while let Some(result) = server_tasks.join_next().await {
        listener_task_result_to_io(result)?;
    }

    if let Some((shutdown_tx, task)) = metrics_shutdown {
        let _ = shutdown_tx.send(());
        // The `io::Error` case is already logged inside the spawned task the
        // moment `serve_until` returns (see above) — only the panic case is
        // worth surfacing here, so we don't double-log the same failure.
        if let Err(join_error) = task.await {
            warn!(%join_error, "metrics listener task panicked");
        }
    }

    sighup_task.abort();
    let _ = sighup_task.await;

    drop(resolver);
    match event_drain.await {
        Ok(()) => Ok(()),
        Err(error) => Err(io::Error::other(format!(
            "query event drain task failed: {error}"
        ))),
    }
}

fn resolve_config_path() -> Option<PathBuf> {
    if let Some(path) = parse_config_flag(std::env::args().skip(1)) {
        return Some(path);
    }
    if let Ok(path) = std::env::var(CONFIG_PATH_ENV_VAR) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }
    let default_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    default_path.exists().then_some(default_path)
}

/// Handles `rdns version`: prints the compiled-in version to stdout and
/// returns `true` if the first argument (excluding argv[0]) is `version`, so
/// installers and users can query the binary's version without starting the
/// resolver.
fn handle_version_command<I: Iterator<Item = String>>(mut args: I) -> bool {
    if args.next().as_deref() != Some("version") {
        return false;
    }
    println!("rdns {VERSION}");
    true
}

/// Parses a `--config <path>` or `--config=<path>` flag out of an argv
/// iterator (excluding argv[0]). A blank value is treated as absent so it
/// falls through to the env var / default-file lookup, mirroring how the
/// `RDNS_CONFIG` env var handles blank values.
fn parse_config_flag<I: Iterator<Item = String>>(mut args: I) -> Option<PathBuf> {
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--config=") {
            if !value.is_empty() {
                return Some(PathBuf::from(value));
            }
        } else if arg == "--config"
            && let Some(value) = args.next()
            && !value.is_empty()
        {
            return Some(PathBuf::from(value));
        }
    }
    None
}

fn load_runtime_config(path: Option<&Path>) -> io::Result<RuntimeConfig> {
    let Some(path) = path else {
        let config = RuntimeConfig::development_default();
        config.validate().map_err(|error| {
            io::Error::other(format!("invalid development default config: {error:?}"))
        })?;
        return Ok(config);
    };
    let source = std::fs::read_to_string(path)
        .map_err(|error| io::Error::other(format!("failed to read {}: {error}", path.display())))?;
    RuntimeConfig::from_toml_str(&source).map_err(|error| {
        io::Error::other(format!("invalid config at {}: {error:?}", path.display()))
    })
}

/// Counts of local DNS entries actually served after merging
/// `[[local_dns_entries]]` with every `[[local_zones]]` file, for
/// operator-facing reload logging.
#[derive(Debug)]
struct LocalEntryCounts {
    inline: usize,
    zone_derived: usize,
    zone_files: usize,
}

/// Formats the local-DNS-entry count summary shared by the startup log line
/// and the SIGHUP reload log line, e.g. "3 local DNS entries (2 inline, 1
/// from 1 zone file)".
fn local_entry_summary(counts: &LocalEntryCounts) -> String {
    let total = counts.inline + counts.zone_derived;
    format!(
        "{total} local DNS entr{} ({} inline, {} from {} zone file{})",
        if total == 1 { "y" } else { "ies" },
        counts.inline,
        counts.zone_derived,
        counts.zone_files,
        if counts.zone_files == 1 { "" } else { "s" },
    )
}

/// Zone `path` values are resolved relative to the main config file's
/// directory when relative (so a config stays portable across machines/
/// deploy paths, and matches how BIND admins already expect zone paths in
/// `named.conf` to work); absolute paths are used as-is. With no config
/// file loaded (dev defaults), a relative path resolves against the
/// process's current working directory.
fn resolve_zone_path(config_path: Option<&Path>, zone_path: &Path) -> PathBuf {
    if zone_path.is_absolute() {
        return zone_path.to_path_buf();
    }
    match config_path.and_then(Path::parent) {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(zone_path),
        _ => zone_path.to_path_buf(),
    }
}

fn read_local_zone_file(config_path: Option<&Path>, zone: &LocalZoneConfig) -> io::Result<String> {
    use std::io::Read;

    let resolved_path = resolve_zone_path(config_path, &zone.path);
    let mut file = std::fs::File::open(&resolved_path).map_err(|error| {
        io::Error::other(format!(
            "failed to read local zone file {}: {error}",
            resolved_path.display()
        ))
    })?;
    // Bound the read itself (not just the post-hoc size check in
    // `parse_local_zone_file`) so an oversized or unbounded file (e.g. a
    // path pointed at a device or a maliciously huge file) can't be fully
    // allocated into memory before the size ceiling is enforced. Reading
    // one byte past the cap lets the size check below distinguish
    // "exactly at the cap" from "over it" without needing a separate
    // metadata call, which would be racy against a file that grows
    // between the check and the read anyway.
    let mut buffer = Vec::new();
    file.by_ref()
        .take(MAX_LOCAL_ZONE_FILE_BYTES + 1)
        .read_to_end(&mut buffer)
        .map_err(|error| {
            io::Error::other(format!(
                "failed to read local zone file {}: {error}",
                resolved_path.display()
            ))
        })?;
    if buffer.len() as u64 > MAX_LOCAL_ZONE_FILE_BYTES {
        return Err(io::Error::other(format!(
            "local zone file {} exceeds the {MAX_LOCAL_ZONE_FILE_BYTES}-byte size limit",
            resolved_path.display()
        )));
    }
    String::from_utf8(buffer).map_err(|error| {
        io::Error::other(format!(
            "local zone file {} is not valid UTF-8: {error}",
            resolved_path.display()
        ))
    })
}

/// Reads, parses, and converts one enabled zone file's records into
/// `entries`, checking each derived name against `seen` (which also tracks
/// every already-accepted name, inline or zone-derived) to enforce the
/// no-duplicate-names-across-sources invariant. Returns the number of
/// entries this zone contributed.
fn accumulate_zone_local_entries(
    zone: &LocalZoneConfig,
    config_path: Option<&Path>,
    seen: &mut HashSet<DomainName>,
    entries: &mut Vec<LocalDnsEntry>,
) -> io::Result<usize> {
    let resolved_path = resolve_zone_path(config_path, &zone.path);
    let content = read_local_zone_file(config_path, zone)?;
    let zone_entries = parse_local_zone_file(zone, &content).map_err(|error| {
        io::Error::other(format!(
            "invalid local zone {}: {error:?}",
            resolved_path.display()
        ))
    })?;

    let mut zone_derived_count = 0;
    for entry_config in zone_entries {
        let entry = entry_config.to_local_dns_entry().map_err(|error| {
            io::Error::other(format!(
                "invalid local zone {}: {error:?}",
                resolved_path.display()
            ))
        })?;
        if !seen.insert(entry.name.clone()) {
            return Err(io::Error::other(format!(
                "duplicate local DNS entry name across local_dns_entries/local_zones: {}",
                entry.name
            )));
        }
        zone_derived_count += 1;
        entries.push(entry);
    }
    Ok(zone_derived_count)
}

fn build_local_entries(
    config: &RuntimeConfig,
    config_path: Option<&Path>,
) -> io::Result<(Arc<InMemoryLocalDnsEntries>, LocalEntryCounts)> {
    let mut entries = config
        .local_dns_entries
        .iter()
        .map(|entry| entry.to_local_dns_entry())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::other(format!("invalid local DNS entry config: {error:?}")))?;

    // Duplicate detection across every source (inline + every zone file)
    // must happen here, after zone files are actually read: `InMemoryLocalDnsEntries::new`
    // silently keeps the last-inserted entry on a name collision with no
    // error at all, so this check is the only thing standing between a
    // duplicate name and undefined-which-entry-wins behavior. It must run,
    // and fail, before `InMemoryLocalDnsEntries::new` is ever called.
    //
    // Only *enabled* entries are seeded here: `InMemoryLocalDnsEntries::new`
    // filters disabled entries out before they ever reach its name-keyed
    // map, so a disabled inline entry can't actually collide with anything
    // there — treating it as claiming the name would wrongly reject an
    // enabled zone entry sharing that name, and would over-report the
    // "entries actually served" count below.
    let mut seen: HashSet<DomainName> = entries
        .iter()
        .filter(|entry| entry.enabled)
        .map(|entry| entry.name.clone())
        .collect();
    let inline_count = entries.iter().filter(|entry| entry.enabled).count();
    let mut zone_derived_count = 0;
    let mut zone_file_count = 0;

    for zone in config.local_zones.iter().filter(|zone| zone.enabled) {
        zone_derived_count +=
            accumulate_zone_local_entries(zone, config_path, &mut seen, &mut entries)?;
        zone_file_count += 1;
    }

    Ok((
        Arc::new(InMemoryLocalDnsEntries::new(entries)),
        LocalEntryCounts {
            inline: inline_count,
            zone_derived: zone_derived_count,
            zone_files: zone_file_count,
        },
    ))
}

/// Everything a reload needs to publish: the parsed config (kept around for
/// its summary fields), the new backend snapshot, the new local-entry table,
/// and the counts behind the reload's log line.
struct ReloadMaterials {
    config: RuntimeConfig,
    backend_snapshot: BackendSnapshot,
    local_entries: Arc<InMemoryLocalDnsEntries>,
    counts: LocalEntryCounts,
}

/// Loads and fully builds everything a reload needs to publish — reading
/// the config file, reading every enabled zone file, and constructing the
/// backend snapshot — without touching the resolver. Kept separate from
/// publishing so the whole thing (file I/O and zone parsing included) can
/// run inside `spawn_blocking` on the SIGHUP path: publishing itself is a
/// cheap in-memory swap and doesn't need to be.
fn build_reload_materials(
    config_path: &Path,
    metrics: Arc<dyn MetricsSink>,
) -> io::Result<ReloadMaterials> {
    let config = load_runtime_config(Some(config_path))?;
    let backend_snapshot = build_backend_snapshot(&config, metrics)?;
    let (local_entries, counts) = build_local_entries(&config, Some(config_path))?;
    Ok(ReloadMaterials {
        config,
        backend_snapshot,
        local_entries,
        counts,
    })
}

#[cfg(unix)]
fn spawn_sighup_reload_task(
    resolver: Arc<ResolveQuery>,
    metrics: Arc<dyn MetricsSink>,
    config_path: Option<PathBuf>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(error) => {
                error!(%error, "failed to install SIGHUP handler");
                return;
            }
        };
        loop {
            if hangup.recv().await.is_none() {
                warn!("SIGHUP signal stream closed; stopping reload task");
                return;
            }
            let Some(path) = config_path.clone() else {
                warn!("SIGHUP received but no config file was loaded at startup; ignoring");
                continue;
            };
            // Config parsing, every enabled zone file's disk read/parse,
            // and backend-snapshot construction all happen inside this one
            // `spawn_blocking` call — none of it should run on a Tokio
            // worker thread while the server is actively serving queries.
            let load_path = path.clone();
            let reload_metrics = Arc::clone(&metrics);
            let built = tokio::task::spawn_blocking(move || {
                build_reload_materials(&load_path, reload_metrics)
            })
            .await;
            apply_reload_result(&resolver, &path, built);
        }
    })
}

/// Applies a completed `build_reload_materials` result: publishes the new
/// backend/local-entry snapshot to `resolver` on success, otherwise logs why
/// the reload didn't happen.
fn apply_reload_result(
    resolver: &ResolveQuery,
    path: &Path,
    built: Result<io::Result<ReloadMaterials>, tokio::task::JoinError>,
) {
    match built {
        Ok(Ok(ReloadMaterials {
            config,
            backend_snapshot,
            local_entries,
            counts,
        })) => {
            resolver.publish_reload(backend_snapshot, local_entries);
            info!(
                path = %path.display(),
                upstreams = config.upstreams.len(),
                summary = %local_entry_summary(&counts),
                "reloaded config"
            )
        }
        Ok(Err(error)) => {
            error!(path = %path.display(), %error, "failed to reload config")
        }
        Err(join_error) if join_error.is_cancelled() => {
            warn!(path = %path.display(), %join_error, "reload task was cancelled")
        }
        Err(join_error) => {
            error!(path = %path.display(), %join_error, "reload task panicked")
        }
    }
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(
    _resolver: Arc<ResolveQuery>,
    _metrics: Arc<dyn MetricsSink>,
    _config_path: Option<PathBuf>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {})
}

fn build_backend_snapshot(
    config: &RuntimeConfig,
    metrics: Arc<dyn MetricsSink>,
) -> io::Result<BackendSnapshot> {
    match config.resolution.mode {
        ConfigResolutionMode::Forward => build_forward_backend_snapshot(config),
        ConfigResolutionMode::Recursive => build_recursive_backend_snapshot(config, metrics),
    }
}

fn build_forward_backend_snapshot(config: &RuntimeConfig) -> io::Result<BackendSnapshot> {
    let backend = Arc::new(
        ForwardingResolutionBackend::from_runtime_config(config)
            .map_err(|error| io::Error::other(format!("invalid upstream config: {error:?}")))?,
    );
    Ok(BackendSnapshot::new(
        backend,
        ResolverResolutionMode::Forward,
        config.resolution.generation,
        BackendHealth::Healthy,
        Some(config.backend_cache_namespace()),
    ))
}

fn build_recursive_backend_snapshot(
    config: &RuntimeConfig,
    metrics: Arc<dyn MetricsSink>,
) -> io::Result<BackendSnapshot> {
    let recursive = config
        .resolution
        .recursive
        .as_ref()
        .ok_or_else(|| io::Error::other("recursive resolution config is missing"))?;
    let root_hints = recursive
        .load_root_hints()
        .map_err(|error| io::Error::other(format!("invalid root hints: {error:?}")))?
        .into_iter()
        .map(|hint| RecursiveRootHint {
            name: hint.name,
            endpoints: hint.endpoints,
        })
        .collect();
    let transport = Arc::new(
        RecursiveAuthorityTransportClient::from_runtime_config(config)
            .map_err(|error| io::Error::other(format!("invalid recursive transport: {error:?}")))?
            .with_metrics(Arc::clone(&metrics)),
    );
    let backend = Arc::new(RecursiveResolutionBackend::with_metrics(
        RecursiveResolverConfig {
            root_hints,
            per_authority_timeout: recursive.per_authority_timeout,
            per_query_deadline: config.per_query_deadline,
            max_recursion_depth: recursive.max_recursion_depth,
            max_cname_restarts: recursive.max_cname_restarts,
            configured_max_udp_payload_size: config.max_udp_payload_size,
        },
        transport,
        metrics,
    ));
    Ok(BackendSnapshot::new(
        backend,
        ResolverResolutionMode::Recursive,
        config.resolution.generation,
        BackendHealth::Healthy,
        Some(config.backend_cache_namespace()),
    )
    .with_root_hints_status(BackendRootHintsStatus::loaded(
        root_hints_source_label(&recursive.root_hints_source),
        recursive.root_hints_version.clone(),
        SystemTime::now(),
    )))
}

fn root_hints_source_label(source: &ConfigRootHintsSource) -> &'static str {
    match source {
        ConfigRootHintsSource::Bundled => "bundled",
        ConfigRootHintsSource::Static(_) => "static",
    }
}

fn listener_task_result_to_io(result: Result<io::Result<()>, JoinError>) -> io::Result<()> {
    result.map_err(|error| io::Error::other(format!("dns listener task failed: {error}")))?
}

struct StdoutEvents;

impl StdoutEvents {
    /// Per-query audit line, printed as its own top-level JSON object (its
    /// `schema_version` is a stable, documented schema — it deliberately
    /// bypasses the `tracing` JSON formatter so it isn't nested inside a
    /// `message` string). Gated on the `debug` level so it follows `RUST_LOG`
    /// like every other log line: silent by default, `RUST_LOG=debug` (or
    /// higher) turns the per-query trail back on for troubleshooting.
    fn record_ref(&self, event: &QueryEventV1) {
        if !tracing::enabled!(tracing::Level::DEBUG) {
            return;
        }
        match serde_json::to_string(event) {
            Ok(json) => println!("{json}"),
            Err(error) => error!(%error, event = ?event, "failed to serialize query event"),
        }
    }
}

impl QueryEventSink for StdoutEvents {
    fn record(&self, event: QueryEventV1) -> QueryEventRecordResult {
        self.record_ref(&event);
        QueryEventRecordResult::Accepted
    }
}

struct StoreRecordingQueryEventSink {
    inner: ChannelQueryEventSink,
    store: Arc<InMemoryQueryEventStore>,
}

impl StoreRecordingQueryEventSink {
    fn new(inner: ChannelQueryEventSink, store: Arc<InMemoryQueryEventStore>) -> Self {
        Self { inner, store }
    }
}

impl QueryEventSink for StoreRecordingQueryEventSink {
    fn record(&self, event: QueryEventV1) -> QueryEventRecordResult {
        let result = self.inner.record(event);
        if !matches!(result, QueryEventRecordResult::Accepted) {
            self.store.record_outcome(result);
        }
        result
    }
}

struct NoopMetrics;

impl MetricsSink for NoopMetrics {
    fn increment(&self, _metric: ResolverMetric) {}

    fn observe_duration(&self, _metric: ResolverMetric, _duration: Duration) {}
}

struct OpenTelemetryMetrics {
    _provider: SdkMeterProvider,
    registry: Registry,
    query_received_total: Counter<u64>,
    query_allowed_total: Counter<u64>,
    query_blocked_total: Counter<u64>,
    cache_hit_total: Counter<u64>,
    cache_miss_total: Counter<u64>,
    cache_expired_total: Counter<u64>,
    cache_bypass_total: Counter<u64>,
    cache_unavailable_total: Counter<u64>,
    cache_store_total: Counter<u64>,
    cache_store_skipped_total: Counter<u64>,
    cache_negative_store_total: Counter<u64>,
    cache_negative_hit_total: Counter<u64>,
    cache_response_truncated_total: Counter<u64>,
    cache_coalesced_miss_total: Counter<u64>,
    query_event_accepted_total: Counter<u64>,
    query_event_disabled_total: Counter<u64>,
    query_event_dropped_newest_total: Counter<u64>,
    query_event_dropped_oldest_total: Counter<u64>,
    query_event_sampled_total: Counter<u64>,
    upstream_success_total: Counter<u64>,
    upstream_failure_total: Counter<u64>,
    recursive_query_total: Counter<u64>,
    recursive_authority_attempt_total: Counter<u64>,
    recursive_authority_timeout_total: Counter<u64>,
    recursive_authority_error_total: Counter<u64>,
    recursive_bailiwick_reject_total: Counter<u64>,
    recursive_lame_delegation_total: Counter<u64>,
    recursive_referral_loop_total: Counter<u64>,
    recursive_limit_hit_total: Counter<u64>,
    recursive_tcp_fallback_attempt_total: Counter<u64>,
    recursive_tcp_fallback_success_total: Counter<u64>,
    recursive_tcp_fallback_failure_total: Counter<u64>,
    recursive_tcp_fallback_timeout_total: Counter<u64>,
    backend_generation: Gauge<u64>,
    root_hints_age_seconds: Gauge<f64>,
    dnssec_validation_disabled: Gauge<u64>,
    protocol_error_total: Counter<u64>,
    recursion_refused_total: Counter<u64>,
    refresh_triggered_total: Counter<u64>,
    refresh_queue_full_total: Counter<u64>,
    query_duration_seconds: Histogram<f64>,
    recursive_query_duration_seconds: Histogram<f64>,
    cache_hit_query_duration_seconds: Histogram<f64>,
    cache_miss_query_duration_seconds: Histogram<f64>,
    _cache_size_gauge: ObservableGauge<u64>,
    _cache_capacity_gauge: ObservableGauge<u64>,
}

impl OpenTelemetryMetrics {
    fn new(cache: Arc<ShardedDnsCache>) -> Result<Self, String> {
        let registry = Registry::new();
        // Our counter instrument names already end in `_total` (chosen to read
        // correctly as Prometheus metric names directly); without this, the
        // exporter appends its own `_total` on top, producing `..._total_total`.
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .without_counter_suffixes()
            .build()
            .map_err(|error| format!("failed to build Prometheus metrics exporter: {error}"))?;
        let provider = SdkMeterProvider::builder().with_reader(exporter).build();
        let meter = provider.meter("rdns.resolver");

        // `domain_count()`/`capacity()` sum across shards without a single
        // global lock, so under concurrent mutation this gauge is an
        // eventually-consistent approximation, not an exact
        // point-in-time read (the same tradeoff DashMap's `len()` makes).
        let cache_for_size = Arc::clone(&cache);
        let cache_size_gauge = meter
            .u64_observable_gauge("cache_size")
            .with_callback(move |observer| {
                observer.observe(cache_for_size.domain_count() as u64, &[])
            })
            .build();
        let cache_capacity_gauge = meter
            .u64_observable_gauge("cache_capacity")
            .with_callback(move |observer| observer.observe(cache.capacity() as u64, &[]))
            .build();

        Ok(Self {
            _provider: provider,
            registry,
            query_received_total: meter.u64_counter("query_received_total").build(),
            query_allowed_total: meter.u64_counter("query_allowed_total").build(),
            query_blocked_total: meter.u64_counter("query_blocked_total").build(),
            cache_hit_total: meter.u64_counter("cache_hit_total").build(),
            cache_miss_total: meter.u64_counter("cache_miss_total").build(),
            cache_expired_total: meter.u64_counter("cache_expired_total").build(),
            cache_bypass_total: meter.u64_counter("cache_bypass_total").build(),
            cache_unavailable_total: meter.u64_counter("cache_unavailable_total").build(),
            cache_store_total: meter.u64_counter("cache_store_total").build(),
            cache_store_skipped_total: meter.u64_counter("cache_store_skipped_total").build(),
            cache_negative_store_total: meter.u64_counter("cache_negative_store_total").build(),
            cache_negative_hit_total: meter.u64_counter("cache_negative_hit_total").build(),
            cache_response_truncated_total: meter
                .u64_counter("cache_response_truncated_total")
                .build(),
            cache_coalesced_miss_total: meter.u64_counter("cache_coalesced_miss_total").build(),
            query_event_accepted_total: meter.u64_counter("query_event_accepted_total").build(),
            query_event_disabled_total: meter.u64_counter("query_event_disabled_total").build(),
            query_event_dropped_newest_total: meter
                .u64_counter("query_event_dropped_newest_total")
                .build(),
            query_event_dropped_oldest_total: meter
                .u64_counter("query_event_dropped_oldest_total")
                .build(),
            query_event_sampled_total: meter.u64_counter("query_event_sampled_total").build(),
            upstream_success_total: meter.u64_counter("upstream_success_total").build(),
            upstream_failure_total: meter.u64_counter("upstream_failure_total").build(),
            recursive_query_total: meter.u64_counter("recursive_query_total").build(),
            recursive_authority_attempt_total: meter
                .u64_counter("recursive_authority_attempt_total")
                .build(),
            recursive_authority_timeout_total: meter
                .u64_counter("recursive_authority_timeout_total")
                .build(),
            recursive_authority_error_total: meter
                .u64_counter("recursive_authority_error_total")
                .build(),
            recursive_bailiwick_reject_total: meter
                .u64_counter("recursive_bailiwick_reject_total")
                .build(),
            recursive_lame_delegation_total: meter
                .u64_counter("recursive_lame_delegation_total")
                .build(),
            recursive_referral_loop_total: meter
                .u64_counter("recursive_referral_loop_total")
                .build(),
            recursive_limit_hit_total: meter.u64_counter("recursive_limit_hit_total").build(),
            recursive_tcp_fallback_attempt_total: meter
                .u64_counter("recursive_tcp_fallback_attempt_total")
                .build(),
            recursive_tcp_fallback_success_total: meter
                .u64_counter("recursive_tcp_fallback_success_total")
                .build(),
            recursive_tcp_fallback_failure_total: meter
                .u64_counter("recursive_tcp_fallback_failure_total")
                .build(),
            recursive_tcp_fallback_timeout_total: meter
                .u64_counter("recursive_tcp_fallback_timeout_total")
                .build(),
            backend_generation: meter.u64_gauge("backend_generation").build(),
            root_hints_age_seconds: meter.f64_gauge("root_hints_age_seconds").build(),
            dnssec_validation_disabled: meter.u64_gauge("dnssec_validation_disabled").build(),
            protocol_error_total: meter.u64_counter("protocol_error_total").build(),
            recursion_refused_total: meter.u64_counter("recursion_refused_total").build(),
            refresh_triggered_total: meter.u64_counter("refresh_triggered_total").build(),
            refresh_queue_full_total: meter.u64_counter("refresh_queue_full_total").build(),
            query_duration_seconds: meter.f64_histogram("query_duration_seconds").build(),
            recursive_query_duration_seconds: meter
                .f64_histogram("recursive_query_duration_seconds")
                .build(),
            cache_hit_query_duration_seconds: meter
                .f64_histogram("cache_hit_query_duration_seconds")
                .build(),
            cache_miss_query_duration_seconds: meter
                .f64_histogram("cache_miss_query_duration_seconds")
                .build(),
            _cache_size_gauge: cache_size_gauge,
            _cache_capacity_gauge: cache_capacity_gauge,
        })
    }
}

impl MetricsSink for OpenTelemetryMetrics {
    fn increment(&self, metric: ResolverMetric) {
        match metric {
            ResolverMetric::QueryReceived => self.query_received_total.add(1, &[]),
            ResolverMetric::QueryAllowed => self.query_allowed_total.add(1, &[]),
            ResolverMetric::QueryBlocked => self.query_blocked_total.add(1, &[]),
            ResolverMetric::CacheHit => self.cache_hit_total.add(1, &[]),
            ResolverMetric::CacheMiss => self.cache_miss_total.add(1, &[]),
            ResolverMetric::CacheExpired => self.cache_expired_total.add(1, &[]),
            ResolverMetric::CacheBypass => self.cache_bypass_total.add(1, &[]),
            ResolverMetric::CacheUnavailable => self.cache_unavailable_total.add(1, &[]),
            ResolverMetric::CacheStore => self.cache_store_total.add(1, &[]),
            ResolverMetric::CacheStoreSkipped => self.cache_store_skipped_total.add(1, &[]),
            ResolverMetric::CacheNegativeStore => self.cache_negative_store_total.add(1, &[]),
            ResolverMetric::CacheNegativeHit => self.cache_negative_hit_total.add(1, &[]),
            ResolverMetric::CacheResponseTruncated => {
                self.cache_response_truncated_total.add(1, &[])
            }
            ResolverMetric::CacheCoalescedMiss => self.cache_coalesced_miss_total.add(1, &[]),
            ResolverMetric::QueryEventAccepted => self.query_event_accepted_total.add(1, &[]),
            ResolverMetric::QueryEventDisabled => self.query_event_disabled_total.add(1, &[]),
            ResolverMetric::QueryEventDroppedNewest => {
                self.query_event_dropped_newest_total.add(1, &[])
            }
            ResolverMetric::QueryEventDroppedOldest => {
                self.query_event_dropped_oldest_total.add(1, &[])
            }
            ResolverMetric::QueryEventSampled => self.query_event_sampled_total.add(1, &[]),
            ResolverMetric::UpstreamSuccess => self.upstream_success_total.add(1, &[]),
            ResolverMetric::UpstreamFailure => self.upstream_failure_total.add(1, &[]),
            ResolverMetric::RecursiveQuery => self.recursive_query_total.add(1, &[]),
            ResolverMetric::RecursiveAuthorityAttempt => {
                self.recursive_authority_attempt_total.add(1, &[])
            }
            ResolverMetric::RecursiveAuthorityTimeout => {
                self.recursive_authority_timeout_total.add(1, &[])
            }
            ResolverMetric::RecursiveAuthorityError => {
                self.recursive_authority_error_total.add(1, &[])
            }
            ResolverMetric::RecursiveBailiwickReject => {
                self.recursive_bailiwick_reject_total.add(1, &[])
            }
            ResolverMetric::RecursiveLameDelegation => {
                self.recursive_lame_delegation_total.add(1, &[])
            }
            ResolverMetric::RecursiveReferralLoop => self.recursive_referral_loop_total.add(1, &[]),
            ResolverMetric::RecursiveLimitHit => self.recursive_limit_hit_total.add(1, &[]),
            ResolverMetric::RecursiveTcpFallbackAttempt => {
                self.recursive_tcp_fallback_attempt_total.add(1, &[])
            }
            ResolverMetric::RecursiveTcpFallbackSuccess => {
                self.recursive_tcp_fallback_success_total.add(1, &[])
            }
            ResolverMetric::RecursiveTcpFallbackFailure => {
                self.recursive_tcp_fallback_failure_total.add(1, &[])
            }
            ResolverMetric::RecursiveTcpFallbackTimeout => {
                self.recursive_tcp_fallback_timeout_total.add(1, &[])
            }
            ResolverMetric::ProtocolError => self.protocol_error_total.add(1, &[]),
            ResolverMetric::RecursionRefused => self.recursion_refused_total.add(1, &[]),
            ResolverMetric::RefreshTriggered => self.refresh_triggered_total.add(1, &[]),
            ResolverMetric::RefreshQueueFull => self.refresh_queue_full_total.add(1, &[]),
            ResolverMetric::QueryDuration
            | ResolverMetric::RecursiveQueryDuration
            | ResolverMetric::CacheHitQueryDuration
            | ResolverMetric::CacheMissQueryDuration => {}
        }
    }

    fn observe_duration(&self, metric: ResolverMetric, duration: Duration) {
        match metric {
            ResolverMetric::QueryDuration => {
                self.query_duration_seconds
                    .record(duration.as_secs_f64(), &[]);
            }
            ResolverMetric::RecursiveQueryDuration => {
                self.recursive_query_duration_seconds
                    .record(duration.as_secs_f64(), &[]);
            }
            ResolverMetric::CacheHitQueryDuration => {
                self.cache_hit_query_duration_seconds
                    .record(duration.as_secs_f64(), &[]);
            }
            ResolverMetric::CacheMissQueryDuration => {
                self.cache_miss_query_duration_seconds
                    .record(duration.as_secs_f64(), &[]);
            }
            _ => {}
        }
    }

    fn record_backend_status(&self, status: &BackendStatus) {
        let attributes = backend_status_attributes(status);
        self.backend_generation
            .record(status.generation, &attributes);
        self.dnssec_validation_disabled.record(
            u64::from(status.dnssec_validation == DnssecValidationStatus::Disabled),
            &attributes,
        );
        if let Some(root_hints) = &status.root_hints
            && let Some(age) = root_hints.age_at(SystemTime::now())
        {
            self.root_hints_age_seconds
                .record(age.as_secs_f64(), &attributes);
        }
    }
}

fn backend_status_attributes(status: &BackendStatus) -> Vec<KeyValue> {
    let mut attributes = vec![
        KeyValue::new("mode", resolver_mode_label(status.mode)),
        KeyValue::new("health", backend_health_label(status.health)),
        KeyValue::new(
            "dnssec_validation",
            dnssec_validation_label(status.dnssec_validation),
        ),
    ];
    if let Some(root_hints) = &status.root_hints {
        attributes.push(KeyValue::new(
            "root_hints_source",
            root_hints.source.clone(),
        ));
        attributes.push(KeyValue::new(
            "root_hints_version",
            root_hints.version.clone(),
        ));
    }
    attributes
}

fn resolver_mode_label(mode: ResolverResolutionMode) -> &'static str {
    match mode {
        ResolverResolutionMode::Forward => "forward",
        ResolverResolutionMode::Recursive => "recursive",
    }
}

fn backend_health_label(health: BackendHealth) -> &'static str {
    match health {
        BackendHealth::Healthy => "healthy",
        BackendHealth::Degraded => "degraded",
        BackendHealth::Unavailable => "unavailable",
        BackendHealth::Unknown => "unknown",
    }
}

fn dnssec_validation_label(status: DnssecValidationStatus) -> &'static str {
    match status {
        DnssecValidationStatus::Disabled => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use rdns::resolver::{
        LocalDnsEntries, LocalDnsLookup, QueryEventReadModel, QuestionKey, ResolveDecision,
        ResolveDecisionKind,
    };

    fn sample_config_toml() -> &'static str {
        r#"
            dns_listen = ["127.0.0.1:5300"]
            per_query_deadline_ms = 2000
            max_udp_payload_size = 1232

            [[upstreams]]
            name = "cloudflare"
            endpoint = "1.1.1.1:53"
            protocol = "udp"
            enabled = true
            priority = 10
            timeout_ms = 750

            [[local_dns_entries]]
            name = "nas.lan"
            ipv4 = ["192.168.1.10"]
            ttl = 300
            enabled = true
            public_address_acknowledged = false
        "#
    }

    #[test]
    fn open_telemetry_cache_gauges_report_approximate_domain_count() {
        // `cache_size`/`cache_capacity` are OpenTelemetry `ObservableGauge`s
        // whose callback only runs when something actually collects
        // metrics — `registry.gather()` (the same call the Prometheus HTTP
        // exporter makes) triggers that collection pass. Values are
        // asserted as "plausible," not exact, per the documented
        // eventually-consistent-under-sharding tradeoff: an empty,
        // freshly-built single-shard cache should report 0 domains and its
        // full configured capacity.
        let cache = Arc::new(ShardedDnsCache::new(&rdns::config::CacheConfig {
            max_entries: 16,
            shard_count: Some(1),
        }));
        let metrics = OpenTelemetryMetrics::new(Arc::clone(&cache)).expect("metrics exporter");

        let families = metrics.registry.gather();
        let gauge_value = |name: &str| -> f64 {
            families
                .iter()
                .find(|family| family.name() == name)
                .and_then(|family| family.get_metric().first())
                .map(|metric| metric.get_gauge().value())
                .unwrap_or_else(|| panic!("missing gauge {name}"))
        };

        assert_eq!(gauge_value("cache_size"), 0.0);
        assert_eq!(gauge_value("cache_capacity"), 16.0);
    }

    #[test]
    fn local_entry_summary_pluralizes_entries_and_zone_files_independently() {
        assert_eq!(
            local_entry_summary(&LocalEntryCounts {
                inline: 1,
                zone_derived: 0,
                zone_files: 0,
            }),
            "1 local DNS entry (1 inline, 0 from 0 zone files)"
        );
        assert_eq!(
            local_entry_summary(&LocalEntryCounts {
                inline: 2,
                zone_derived: 3,
                zone_files: 1,
            }),
            "5 local DNS entries (2 inline, 3 from 1 zone file)"
        );
    }

    #[test]
    fn config_driven_local_entries_answer_configured_names_only() {
        let config = RuntimeConfig::from_toml_str(sample_config_toml()).unwrap();

        let (local_entries, _counts) = build_local_entries(&config, None).unwrap();

        let local_question = QuestionKey::new("nas.lan", 1, 1);
        match local_entries.lookup(&local_question) {
            LocalDnsLookup::Answer(entry) => {
                assert_eq!(entry.ipv4[0].to_string(), "192.168.1.10");
            }
            other => panic!("expected a local answer, got {other:?}"),
        }

        let unrelated_question = QuestionKey::new("example.com", 1, 1);
        assert_eq!(
            local_entries.lookup(&unrelated_question),
            LocalDnsLookup::NoMatch
        );
    }

    static CONFIG_PATH_ENV_VAR_LOCK: Mutex<()> = Mutex::new(());

    /// Restores `RDNS_CONFIG` to its pre-test value on drop, including on
    /// panic, so a failed assertion (or a panic inside `resolve_config_path`
    /// itself) can't leak the mutated env var to later tests.
    struct RestoreConfigPathEnvVar(Option<String>);

    impl Drop for RestoreConfigPathEnvVar {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => unsafe { std::env::set_var(CONFIG_PATH_ENV_VAR, value) },
                None => unsafe { std::env::remove_var(CONFIG_PATH_ENV_VAR) },
            }
        }
    }

    #[test]
    fn resolve_config_path_treats_blank_env_var_as_unset() {
        // Serializes access to RDNS_CONFIG across tests in this binary; the
        // env mutation functions are unsafe precisely because concurrent
        // reads/writes from other threads are UB, so every test that
        // touches this var must take this lock first.
        let _guard = CONFIG_PATH_ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = RestoreConfigPathEnvVar(std::env::var(CONFIG_PATH_ENV_VAR).ok());

        unsafe {
            std::env::remove_var(CONFIG_PATH_ENV_VAR);
        }
        let expected = resolve_config_path();

        unsafe {
            std::env::set_var(CONFIG_PATH_ENV_VAR, "   ");
        }
        let actual = resolve_config_path();

        assert_eq!(actual, expected);
    }

    #[test]
    fn handle_version_command_matches_only_the_version_subcommand() {
        let args = ["version"].map(String::from);
        assert!(handle_version_command(args.into_iter()));

        let args = ["--config", "/etc/rdns/config.toml"].map(String::from);
        assert!(!handle_version_command(args.into_iter()));

        let args: [String; 0] = [];
        assert!(!handle_version_command(args.into_iter()));
    }

    #[test]
    fn parse_config_flag_supports_space_and_equals_forms() {
        let args = ["--config", "/etc/rdns/config.toml"].map(String::from);
        assert_eq!(
            parse_config_flag(args.into_iter()),
            Some(PathBuf::from("/etc/rdns/config.toml"))
        );

        let args = ["--config=/etc/rdns/other.toml"].map(String::from);
        assert_eq!(
            parse_config_flag(args.into_iter()),
            Some(PathBuf::from("/etc/rdns/other.toml"))
        );
    }

    #[test]
    fn parse_config_flag_ignores_blank_or_missing_value() {
        let args = ["--config", ""].map(String::from);
        assert_eq!(parse_config_flag(args.into_iter()), None);

        let args = ["--config="].map(String::from);
        assert_eq!(parse_config_flag(args.into_iter()), None);

        let args = ["--config"].map(String::from);
        assert_eq!(parse_config_flag(args.into_iter()), None);

        let args: [String; 0] = [];
        assert_eq!(parse_config_flag(args.into_iter()), None);
    }

    #[test]
    fn load_runtime_config_falls_back_to_development_default_without_a_path() {
        let config = load_runtime_config(None).unwrap();

        assert_eq!(config, RuntimeConfig::development_default());
    }

    fn event_for(name: &str) -> QueryEventV1 {
        let decision = ResolveDecision {
            client_ip: "127.0.0.1".parse().unwrap(),
            question: Some(QuestionKey::new(name, 1, 1)),
            kind: ResolveDecisionKind::Allowed,
        };
        QueryEventV1::from_decision(0, None, SystemTime::UNIX_EPOCH, &decision, None, None, None)
    }

    #[tokio::test]
    async fn store_recording_query_event_sink_counts_channel_drops() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(event_for("queued.example")).unwrap();
        let store = Arc::new(InMemoryQueryEventStore::new(
            InMemoryQueryEventStoreConfig::default(),
        ));
        let sink = StoreRecordingQueryEventSink::new(ChannelQueryEventSink::new(tx), store.clone());

        let result = sink.record(event_for("dropped.example"));

        assert_eq!(result, QueryEventRecordResult::DroppedNewest);
        assert_eq!(store.summary().dropped_newest_event_count, 1);
        assert_eq!(
            rx.recv().await.unwrap().normalized_question.unwrap().qname,
            "queued.example"
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn record_classified_attaches_advisory_findings_before_storage() {
        let store = InMemoryQueryEventStore::new(InMemoryQueryEventStoreConfig::default());
        let classifier =
            InMemorySuspiciousLookupClassifier::new(InMemorySuspiciousLookupClassifierConfig {
                high_entropy_min_label_len: 8,
                high_entropy_score_threshold: 60,
                ..InMemorySuspiciousLookupClassifierConfig::default()
            });

        let event = store.record_classified(event_for("a9x4qz7m2p8v.example"), &classifier);

        assert!(!event.advisory_findings.is_empty());
        assert_eq!(store.suspicious_query_events(8).len(), 1);
    }

    #[test]
    fn resolve_zone_path_passes_through_absolute_paths() {
        let absolute = PathBuf::from("/etc/rdns/zones/mynetwork.zone");
        assert_eq!(
            resolve_zone_path(Some(Path::new("/etc/rdns/config.toml")), &absolute),
            absolute
        );
        assert_eq!(resolve_zone_path(None, &absolute), absolute);
    }

    #[test]
    fn resolve_zone_path_resolves_relative_paths_against_the_config_files_directory() {
        let resolved = resolve_zone_path(
            Some(Path::new("/etc/rdns/config.toml")),
            Path::new("zones/mynetwork.zone"),
        );
        assert_eq!(resolved, PathBuf::from("/etc/rdns/zones/mynetwork.zone"));
    }

    #[test]
    fn resolve_zone_path_resolves_relative_paths_against_cwd_without_a_config_file() {
        let resolved = resolve_zone_path(None, Path::new("zones/mynetwork.zone"));
        assert_eq!(resolved, PathBuf::from("zones/mynetwork.zone"));
    }

    /// A scratch file under `std::env::temp_dir()`, removed on drop
    /// (including on panic). Avoids adding a `tempfile` dependency just
    /// for these tests, per "add dependencies conservatively".
    struct ScratchFile(PathBuf);

    impl ScratchFile {
        fn write(name: &str, content: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rdns-test-{}-{}-{name}",
                std::process::id(),
                unique
            ));
            std::fs::write(&path, content).expect("write scratch zone file");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn config_with_one_zone(zone_path: &Path, root_domain: &str) -> RuntimeConfig {
        let toml = format!(
            r#"
            dns_listen = ["127.0.0.1:5300"]
            per_query_deadline_ms = 2000
            max_udp_payload_size = 1232

            [[upstreams]]
            name = "cloudflare"
            endpoint = "1.1.1.1:53"
            protocol = "udp"
            enabled = true
            priority = 10
            timeout_ms = 750

            [[local_zones]]
            path = "{}"
            root_domain = "{root_domain}"
            "#,
            zone_path.display(),
        );
        RuntimeConfig::from_toml_str(&toml).unwrap()
    }

    #[test]
    fn build_local_entries_merges_inline_and_zone_file_entries() {
        let zone_file = ScratchFile::write(
            "merge.zone",
            "$ORIGIN mynetwork.\n$TTL 300\nprinter IN A 192.168.1.50\n",
        );
        let mut config = config_with_one_zone(zone_file.path(), "mynetwork");
        config.local_dns_entries.push(
            RuntimeConfig::from_toml_str(sample_config_toml())
                .unwrap()
                .local_dns_entries
                .remove(0),
        );

        let (local_entries, counts) = build_local_entries(&config, None).unwrap();

        assert_eq!(counts.inline, 1);
        assert_eq!(counts.zone_derived, 1);
        assert_eq!(counts.zone_files, 1);

        let inline_question = QuestionKey::new("nas.lan", 1, 1);
        assert!(matches!(
            local_entries.lookup(&inline_question),
            LocalDnsLookup::Answer(_)
        ));
        let zone_question = QuestionKey::new("printer.mynetwork", 1, 1);
        match local_entries.lookup(&zone_question) {
            LocalDnsLookup::Answer(entry) => {
                assert_eq!(entry.ipv4[0].to_string(), "192.168.1.50");
            }
            other => panic!("expected a zone-derived local answer, got {other:?}"),
        }
    }

    #[test]
    fn build_local_entries_rejects_duplicate_name_across_inline_and_zone_sources() {
        let zone_file = ScratchFile::write(
            "dup.zone",
            "$ORIGIN lan.\n$TTL 300\nnas IN A 192.168.1.99\n",
        );
        let mut config = config_with_one_zone(zone_file.path(), "lan");
        config.local_dns_entries.push(
            RuntimeConfig::from_toml_str(sample_config_toml())
                .unwrap()
                .local_dns_entries
                .remove(0),
        );

        let error = build_local_entries(&config, None).unwrap_err();

        assert!(error.to_string().contains("duplicate local DNS entry name"));
    }

    #[test]
    fn build_local_entries_allows_zone_entry_to_reuse_a_disabled_inline_entrys_name() {
        // A disabled inline entry is filtered out by `InMemoryLocalDnsEntries::new`
        // before it ever reaches the served name-keyed map, so it can't
        // actually collide with anything there. Treating it as claiming
        // the name in `build_local_entries`'s duplicate check would wrongly
        // reject an enabled zone entry sharing that name, and would
        // over-report the "entries actually served" count.
        let zone_file = ScratchFile::write(
            "reuse.zone",
            "$ORIGIN lan.\n$TTL 300\nnas IN A 192.168.1.99\n",
        );
        let mut config = config_with_one_zone(zone_file.path(), "lan");
        let disabled_toml = r#"
            dns_listen = ["127.0.0.1:5300"]
            per_query_deadline_ms = 2000
            max_udp_payload_size = 1232

            [[upstreams]]
            name = "cloudflare"
            endpoint = "1.1.1.1:53"
            protocol = "udp"
            enabled = true
            priority = 10
            timeout_ms = 750

            [[local_dns_entries]]
            name = "nas.lan"
            ipv4 = ["192.168.1.10"]
            ttl = 300
            enabled = false
            public_address_acknowledged = false
        "#;
        config.local_dns_entries.push(
            RuntimeConfig::from_toml_str(disabled_toml)
                .unwrap()
                .local_dns_entries
                .remove(0),
        );

        let (local_entries, counts) = build_local_entries(&config, None).unwrap();

        assert_eq!(
            counts.inline, 0,
            "disabled inline entry must not be counted as served"
        );
        assert_eq!(counts.zone_derived, 1);

        let question = QuestionKey::new("nas.lan", 1, 1);
        match local_entries.lookup(&question) {
            LocalDnsLookup::Answer(entry) => {
                assert_eq!(entry.ipv4[0].to_string(), "192.168.1.99");
            }
            other => panic!("expected the zone-derived entry to win, got {other:?}"),
        }
    }

    #[test]
    fn build_local_entries_errors_on_missing_zone_file_instead_of_panicking() {
        let missing_path = std::env::temp_dir().join(format!(
            "rdns-test-missing-{}-{}.zone",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config = config_with_one_zone(&missing_path, "mynetwork");

        let result = build_local_entries(&config, None);

        assert!(result.is_err());
    }

    #[test]
    fn read_local_zone_file_rejects_oversized_files_without_reading_them_whole() {
        // One byte over the cap: `read_local_zone_file` must reject this
        // via its bounded `Read::take` reader, not by fully allocating the
        // file and checking its length afterward.
        let oversized = "x".repeat((MAX_LOCAL_ZONE_FILE_BYTES + 2) as usize);
        let zone_file = ScratchFile::write("oversized.zone", &oversized);
        let zone = LocalZoneConfig {
            path: zone_file.path().to_path_buf(),
            root_domain: DomainName::parse("mynetwork").unwrap(),
            public_address_acknowledged: false,
            enabled: true,
        };

        let error = read_local_zone_file(None, &zone).unwrap_err();

        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn build_local_entries_skips_disk_io_for_disabled_zones() {
        // Points at a file that doesn't exist; a disabled zone must never
        // be read, so this must succeed with zero zone-derived entries.
        let missing_path = std::env::temp_dir().join(format!(
            "rdns-test-disabled-{}-{}.zone",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let toml = format!(
            r#"
            dns_listen = ["127.0.0.1:5300"]
            per_query_deadline_ms = 2000
            max_udp_payload_size = 1232

            [[upstreams]]
            name = "cloudflare"
            endpoint = "1.1.1.1:53"
            protocol = "udp"
            enabled = true
            priority = 10
            timeout_ms = 750

            [[local_zones]]
            path = "{}"
            root_domain = "mynetwork"
            enabled = false
            "#,
            missing_path.display(),
        );
        let config = RuntimeConfig::from_toml_str(&toml).unwrap();

        let (_local_entries, counts) = build_local_entries(&config, None).unwrap();

        assert_eq!(counts.zone_files, 0);
        assert_eq!(counts.zone_derived, 0);
    }
}
