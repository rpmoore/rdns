// Copyright 2023 Ryan Moore
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

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use domain::base::iana::{Class, Rtype};
use domain::base::RecordData;
use domain::rdata::ZoneRecordData;
use domain::zonefile::inplace::{Entry, Zonefile};
use serde::Deserialize;

use crate::resolver::{DomainName, LocalDnsEntry, LocalDnsEntryValidationError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub dns_listen: Vec<SocketAddr>,
    pub resolution: ResolutionConfig,
    pub upstreams: Vec<UpstreamConfig>,
    pub per_query_deadline: Duration,
    pub max_udp_payload_size: usize,
    pub local_dns_entries: Vec<LocalDnsEntryConfig>,
    pub local_zones: Vec<LocalZoneConfig>,
}

impl RuntimeConfig {
    pub fn new(
        dns_listen: Vec<SocketAddr>,
        upstreams: Vec<UpstreamConfig>,
        per_query_deadline: Duration,
        max_udp_payload_size: usize,
    ) -> Result<Self, ConfigError> {
        Self::new_with_resolution(
            dns_listen,
            ResolutionConfig::forwarding_default(),
            upstreams,
            per_query_deadline,
            max_udp_payload_size,
        )
    }

    pub fn new_with_resolution(
        dns_listen: Vec<SocketAddr>,
        resolution: ResolutionConfig,
        upstreams: Vec<UpstreamConfig>,
        per_query_deadline: Duration,
        max_udp_payload_size: usize,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            dns_listen,
            resolution,
            upstreams,
            per_query_deadline,
            max_udp_payload_size,
            local_dns_entries: Vec::new(),
            local_zones: Vec::new(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn development_default() -> Self {
        Self {
            dns_listen: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                DEFAULT_DNS_LISTEN_PORT,
            )],
            resolution: ResolutionConfig::forwarding_default(),
            upstreams: vec![UpstreamConfig {
                name: "cloudflare".to_string(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
                protocol: UpstreamProtocol::Udp,
                enabled: true,
                priority: 10,
                timeout: Duration::from_millis(750),
            }],
            per_query_deadline: Duration::from_secs(2),
            max_udp_payload_size: 1232,
            local_dns_entries: Vec::new(),
            local_zones: Vec::new(),
        }
    }

    pub fn from_toml_str(source: &str) -> Result<Self, ConfigError> {
        let raw: RawRuntimeConfig =
            toml::from_str(source).map_err(|error| ConfigError::InvalidTomlConfig {
                message: error.to_string(),
            })?;
        raw.try_into()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.dns_listen.is_empty() {
            return Err(ConfigError::NoDnsListenAddress);
        }
        let mut unique_listeners = HashSet::with_capacity(self.dns_listen.len());
        for address in &self.dns_listen {
            validate_listen_address(*address)?;
            if !unique_listeners.insert(*address) {
                return Err(ConfigError::DuplicateListenAddress { address: *address });
            }
        }

        self.resolution.validate()?;
        if self.resolution.mode == ResolutionMode::Forward
            && self.enabled_udp_upstreams().is_empty()
        {
            return Err(ConfigError::NoEnabledUpstream);
        }
        for upstream in &self.upstreams {
            upstream.validate()?;
        }

        let mut normalized_local_names = HashSet::with_capacity(self.local_dns_entries.len());
        for entry in &self.local_dns_entries {
            let local_entry = entry.to_local_dns_entry()?;
            if !normalized_local_names.insert(local_entry.name.clone()) {
                return Err(ConfigError::DuplicateLocalDnsEntryName {
                    name: entry.name.clone(),
                });
            }
        }

        // Only the zone's declared root_domain can be validated here (pure,
        // no disk I/O yet). Whether the zone file's actual records live
        // under that root is checked later, once the file is read and
        // parsed (see `parse_local_zone_file`, invoked from `main.rs`).
        for zone in &self.local_zones {
            zone.validate_root_domain()?;
        }

        validate_duration(
            "per_query_deadline",
            self.per_query_deadline,
            MIN_PER_QUERY_DEADLINE,
            MAX_PER_QUERY_DEADLINE,
        )?;

        if self.max_udp_payload_size < MIN_UDP_PAYLOAD_SIZE
            || self.max_udp_payload_size > MAX_UDP_PAYLOAD_SIZE
        {
            return Err(ConfigError::InvalidUdpPayloadSize {
                field: "max_udp_payload_size",
                value: self.max_udp_payload_size,
                min: MIN_UDP_PAYLOAD_SIZE,
                max: MAX_UDP_PAYLOAD_SIZE,
            });
        }

        Ok(())
    }

    pub fn enabled_upstreams(&self) -> impl Iterator<Item = &UpstreamConfig> {
        let mut upstreams: Vec<_> = self
            .upstreams
            .iter()
            .enumerate()
            .filter(|(_, upstream)| upstream.enabled)
            .collect();
        upstreams.sort_by_key(|(index, upstream)| (upstream.priority, *index));
        upstreams.into_iter().map(|(_, upstream)| upstream)
    }

    fn enabled_udp_upstreams(&self) -> Vec<&UpstreamConfig> {
        let mut upstreams: Vec<_> = self
            .upstreams
            .iter()
            .enumerate()
            .filter(|(_, upstream)| upstream.enabled && upstream.protocol == UpstreamProtocol::Udp)
            .collect();
        upstreams.sort_by_key(|(index, upstream)| (upstream.priority, *index));
        upstreams
            .into_iter()
            .map(|(_, upstream)| upstream)
            .collect()
    }

    pub fn backend_cache_namespace(&self) -> String {
        match self.resolution.mode {
            ResolutionMode::Forward => format!(
                "mode:forward;generation:{};upstreams:{:016x}",
                self.resolution.generation,
                self.forwarding_upstream_set_hash()
            ),
            ResolutionMode::Recursive => {
                let recursive = self.resolution.recursive.as_ref();
                format!(
                    "mode:recursive;generation:{};root-hints:{};dnssec:{};authorities:{:016x}",
                    self.resolution.generation,
                    recursive
                        .map(|recursive| recursive.root_hints_version.as_str())
                        .unwrap_or("missing"),
                    recursive
                        .map(|recursive| recursive.dnssec_validation.cache_namespace_label())
                        .unwrap_or("missing"),
                    recursive
                        .map(RecursiveResolutionConfig::authority_config_hash)
                        .unwrap_or(0)
                )
            }
        }
    }

    fn forwarding_upstream_set_hash(&self) -> u64 {
        let mut hash = FNV1A64_OFFSET;
        for upstream in self.enabled_udp_upstreams() {
            hash_namespace_field(&mut hash, "name", &upstream.name);
            hash_namespace_field(&mut hash, "endpoint", &upstream.endpoint.to_string());
            hash_namespace_field(
                &mut hash,
                "protocol",
                upstream.protocol.cache_namespace_label(),
            );
            hash_namespace_field(&mut hash, "priority", &upstream.priority.to_string());
            hash_namespace_field(
                &mut hash,
                "timeout-nanos",
                &upstream.timeout.as_nanos().to_string(),
            );
        }
        hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionConfig {
    pub mode: ResolutionMode,
    pub generation: u64,
    pub recursive: Option<RecursiveResolutionConfig>,
}

impl ResolutionConfig {
    pub fn forwarding_default() -> Self {
        Self {
            mode: ResolutionMode::Forward,
            generation: 0,
            recursive: None,
        }
    }

    pub fn recursive(generation: u64, recursive: RecursiveResolutionConfig) -> Self {
        Self {
            mode: ResolutionMode::Recursive,
            generation,
            recursive: Some(recursive),
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.generation == u64::MAX {
            return Err(ConfigError::InvalidResolutionGeneration {
                generation: self.generation,
            });
        }
        if self.mode == ResolutionMode::Recursive {
            let Some(recursive) = &self.recursive else {
                return Err(ConfigError::MissingRecursiveResolutionConfig);
            };
            recursive.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMode {
    Forward,
    Recursive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveResolutionConfig {
    pub root_hints_version: String,
    pub root_hints_source: RootHintsSource,
    pub per_authority_timeout: Duration,
    pub max_recursion_depth: u8,
    pub max_cname_restarts: u8,
    pub allowed_transports: Vec<RecursiveTransport>,
    pub dnssec_validation: DnssecValidationMode,
    pub dname_handling: DnameHandlingPolicy,
}

impl RecursiveResolutionConfig {
    pub fn new(
        root_hints_version: impl Into<String>,
        root_hints: Vec<RootHintConfig>,
        dnssec_validation: DnssecValidationMode,
    ) -> Self {
        Self {
            root_hints_version: root_hints_version.into(),
            root_hints_source: RootHintsSource::Static(root_hints),
            per_authority_timeout: Duration::from_millis(750),
            max_recursion_depth: 16,
            max_cname_restarts: 8,
            allowed_transports: vec![RecursiveTransport::Udp, RecursiveTransport::Tcp],
            dnssec_validation,
            dname_handling: DnameHandlingPolicy::Defer,
        }
    }

    pub fn bundled(root_hints_version: impl Into<String>) -> Self {
        Self {
            root_hints_version: root_hints_version.into(),
            root_hints_source: RootHintsSource::Bundled,
            per_authority_timeout: Duration::from_millis(750),
            max_recursion_depth: 16,
            max_cname_restarts: 8,
            allowed_transports: vec![RecursiveTransport::Udp, RecursiveTransport::Tcp],
            dnssec_validation: DnssecValidationMode::Disabled,
            dname_handling: DnameHandlingPolicy::Defer,
        }
    }

    pub fn load_root_hints(&self) -> Result<Vec<RootHintConfig>, ConfigError> {
        match &self.root_hints_source {
            RootHintsSource::Bundled => Ok(bundled_root_hints()),
            RootHintsSource::Static(root_hints) => Ok(root_hints.clone()),
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.root_hints_version.trim().is_empty() {
            return Err(ConfigError::InvalidRootHintsVersion);
        }
        let root_hints = self.load_root_hints()?;
        if root_hints.is_empty() {
            return Err(ConfigError::MissingRootHints);
        }
        for root_hint in &root_hints {
            root_hint.validate()?;
        }
        validate_duration(
            "recursive.per_authority_timeout",
            self.per_authority_timeout,
            MIN_RECURSIVE_AUTHORITY_TIMEOUT,
            MAX_RECURSIVE_AUTHORITY_TIMEOUT,
        )?;
        if self.max_recursion_depth == 0 || self.max_recursion_depth > MAX_RECURSION_DEPTH {
            return Err(ConfigError::InvalidRecursiveDepth {
                value: self.max_recursion_depth,
                max: MAX_RECURSION_DEPTH,
            });
        }
        if self.max_cname_restarts > MAX_CNAME_RESTARTS {
            return Err(ConfigError::InvalidCnameRestartLimit {
                value: self.max_cname_restarts,
                max: MAX_CNAME_RESTARTS,
            });
        }
        if self.allowed_transports.is_empty() {
            return Err(ConfigError::NoRecursiveTransports);
        }
        let mut transports = HashSet::with_capacity(self.allowed_transports.len());
        for transport in &self.allowed_transports {
            if !transports.insert(*transport) {
                return Err(ConfigError::DuplicateRecursiveTransport {
                    transport: *transport,
                });
            }
        }
        Ok(())
    }

    fn authority_config_hash(&self) -> u64 {
        let mut hash = FNV1A64_OFFSET;
        if let Ok(root_hints) = self.load_root_hints() {
            for root_hint in &root_hints {
                let root_name = canonical_authority_name(&root_hint.name)
                    .unwrap_or_else(|_| root_hint.name.clone());
                hash_namespace_field(&mut hash, "root-name", &root_name);
                for endpoint in &root_hint.endpoints {
                    hash_namespace_field(&mut hash, "root-endpoint", &endpoint.to_string());
                }
            }
        }
        hash_namespace_field(
            &mut hash,
            "root-hints-source",
            self.root_hints_source.cache_namespace_label(),
        );
        hash_namespace_field(
            &mut hash,
            "authority-timeout-nanos",
            &self.per_authority_timeout.as_nanos().to_string(),
        );
        hash_namespace_field(
            &mut hash,
            "max-recursion-depth",
            &self.max_recursion_depth.to_string(),
        );
        hash_namespace_field(
            &mut hash,
            "max-cname-restarts",
            &self.max_cname_restarts.to_string(),
        );
        let mut transports = self.allowed_transports.clone();
        transports.sort_by_key(|transport| transport.cache_namespace_label());
        for transport in &transports {
            hash_namespace_field(&mut hash, "transport", transport.cache_namespace_label());
        }
        hash_namespace_field(
            &mut hash,
            "dname-policy",
            self.dname_handling.cache_namespace_label(),
        );
        hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootHintsSource {
    Bundled,
    Static(Vec<RootHintConfig>),
}

impl RootHintsSource {
    fn cache_namespace_label(&self) -> &'static str {
        match self {
            Self::Bundled => "bundled",
            Self::Static(_) => "static",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootHintConfig {
    pub name: String,
    pub endpoints: Vec<SocketAddr>,
}

impl RootHintConfig {
    pub fn new(name: impl Into<String>, endpoints: Vec<SocketAddr>) -> Self {
        Self {
            name: name.into(),
            endpoints,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        canonical_authority_name(&self.name)?;
        if self.endpoints.is_empty() {
            return Err(ConfigError::MissingRootHintEndpoints);
        }
        for endpoint in &self.endpoints {
            if endpoint.port() == 0 {
                return Err(ConfigError::InvalidRootHintEndpoint {
                    endpoint: *endpoint,
                });
            }
            if !is_usable_authority_address(endpoint.ip()) {
                return Err(ConfigError::InvalidRootHintEndpoint {
                    endpoint: *endpoint,
                });
            }
        }
        Ok(())
    }
}

fn is_usable_authority_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_broadcast()
                && !address.is_multicast()
                && !address.is_loopback()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_loopback()
        }
    }
}

/// IANA/InterNIC's root hints zone file, as published at
/// <https://www.internic.net/domain/named.root>. Update by re-fetching that
/// URL over this file; the file's contents are embedded at compile time via
/// `include_str!`, but `parse_named_root` re-derives the bundled hints from
/// it at runtime (see `bundled_root_hints`), so no other code needs to change.
const BUNDLED_NAMED_ROOT: &str = include_str!("named.root");

fn bundled_root_hints() -> Vec<RootHintConfig> {
    parse_named_root(BUNDLED_NAMED_ROOT)
        .unwrap_or_else(|error| panic!("bundled named.root asset failed to parse: {error}"))
}

/// Parses a BIND-style root hints zone file (the format IANA/InterNIC
/// publish as `named.root`/`named.cache`): `;` starts a comment, whether on
/// its own line or trailing data; data lines are `<name> <ttl> [class]
/// <type> <rdata>`, with the class (e.g. `IN`) optional. Only `A`/`AAAA`
/// records are kept (`NS` records are redundant with the owner names of the
/// address records and carry no addresses of their own); root names are
/// returned in first-seen order with all of their glue addresses attached.
fn parse_named_root(source: &str) -> Result<Vec<RootHintConfig>, String> {
    let mut hints: Vec<RootHintConfig> = Vec::new();
    for (line_number, raw_line) in source.lines().enumerate() {
        let line = raw_line.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (name, record_type, rdata) = match fields[..] {
            [name, _ttl, record_type, rdata] => (name, record_type, rdata),
            [name, _ttl, class, record_type, rdata] if class.eq_ignore_ascii_case("IN") => {
                (name, record_type, rdata)
            }
            _ => {
                return Err(format!(
                    "line {}: expected `<name> <ttl> [class] <type> <rdata>`, got `{line}`",
                    line_number + 1
                ));
            }
        };
        if !record_type.eq_ignore_ascii_case("A") && !record_type.eq_ignore_ascii_case("AAAA") {
            continue;
        }
        let address: IpAddr = rdata
            .parse()
            .map_err(|_| format!("line {}: invalid IP address `{rdata}`", line_number + 1))?;
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let endpoint = SocketAddr::new(address, 53);
        match hints.iter_mut().find(|hint| hint.name == name) {
            Some(hint) => hint.endpoints.push(endpoint),
            None => hints.push(RootHintConfig::new(name, vec![endpoint])),
        }
    }
    if hints.is_empty() {
        return Err("no A/AAAA root hint records found".to_string());
    }
    Ok(hints)
}

/// IANA's published list of currently-delegated (root-zone) top-level
/// domains, as fetched from
/// <https://data.iana.org/TLD/tlds-alpha-by-domain.txt>. Update by
/// re-fetching that URL over this file; `parse_iana_tlds` re-derives the
/// bundled set from it at runtime (see `bundled_iana_tlds`).
///
/// This is the *only* list local-zone/local-entry names are checked
/// against (see `validate_not_registered_tld`). IANA's separate
/// Special-Use Domain Names registry (RFC 6761: `test`, `invalid`,
/// `example`, `local`, `onion`, `home.arpa`, `localhost`) is never in this
/// file, so those names are never rejected by that check — they're
/// reserved by IANA precisely for non-public use like this.
const BUNDLED_IANA_TLDS: &str = include_str!("tlds-alpha-by-domain.txt");

fn bundled_iana_tlds() -> &'static HashSet<String> {
    static TLDS: OnceLock<HashSet<String>> = OnceLock::new();
    TLDS.get_or_init(|| {
        parse_iana_tlds(BUNDLED_IANA_TLDS)
            .unwrap_or_else(|error| panic!("bundled IANA TLD asset failed to parse: {error}"))
    })
}

/// Parses IANA's `tlds-alpha-by-domain.txt` format: a `#`-prefixed comment
/// line (its version header), then one TLD per line, uppercase ASCII
/// (punycode `XN--...` form for IDN TLDs). Returns a lowercased set.
fn parse_iana_tlds(source: &str) -> Result<HashSet<String>, String> {
    let mut tlds = HashSet::new();
    for (line_number, raw_line) in source.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.split_whitespace().count() != 1 {
            return Err(format!(
                "line {}: expected a single TLD token, got `{line}`",
                line_number + 1
            ));
        }
        tlds.insert(line.to_ascii_lowercase());
    }
    if tlds.is_empty() {
        return Err("no TLD entries found".to_string());
    }
    Ok(tlds)
}

/// Returns true if `label` (a single DNS label, with no dots) is a
/// currently-delegated IANA top-level domain per the bundled list.
fn is_registered_iana_tld(label: &str) -> bool {
    bundled_iana_tlds().contains(&label.to_ascii_lowercase())
}

/// The single choke point enforcing that a local DNS name (whether from
/// `[[local_dns_entries]]` or derived from a `[[local_zones]]` zone file)
/// does not sit under a real, currently-delegated IANA TLD — so a local
/// override can never claim authority over a real public domain. Checks
/// only the rightmost label (the name's effective TLD), so `nas.lan`
/// checks `lan`, and a bare single-label root domain like `lab` checks
/// `lab` itself.
fn home_arpa() -> &'static DomainName {
    static HOME_ARPA: OnceLock<DomainName> = OnceLock::new();
    HOME_ARPA.get_or_init(|| {
        DomainName::parse("home.arpa").expect("\"home.arpa\" is a valid domain name")
    })
}

fn validate_not_registered_tld(name: &DomainName) -> Result<(), ConfigError> {
    // `home.arpa` is IANA's own Special-Use Domain Name for exactly this
    // purpose (RFC 8375), even though `arpa` itself is a real, delegated
    // infrastructure TLD (it's in the bundled list, so the rightmost-label
    // check below would otherwise wrongly reject it). This is a narrow,
    // explicit exception, not a general subdomain-of-`arpa` allowance —
    // nothing else under `arpa` (e.g. `in-addr.arpa`) is a local-zone
    // concern.
    if name.is_at_or_below(home_arpa()) {
        return Ok(());
    }

    let rightmost_label = name.as_str().rsplit('.').next().unwrap_or(name.as_str());
    if is_registered_iana_tld(rightmost_label) {
        return Err(ConfigError::LocalDnsEntryUsesRegisteredTld {
            name: name.to_string(),
            tld: rightmost_label.to_ascii_lowercase(),
        });
    }
    Ok(())
}

fn canonical_authority_name(name: &str) -> Result<String, ConfigError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed != name || trimmed.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ConfigError::InvalidRootHintName);
    }

    let without_root = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_root.is_empty() || without_root.len() > 253 {
        return Err(ConfigError::InvalidRootHintName);
    }

    let mut wire_len = 1usize;
    for label in without_root.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ConfigError::InvalidRootHintName);
        }
        wire_len = wire_len.saturating_add(1 + label.len());
    }
    if wire_len > 255 {
        return Err(ConfigError::InvalidRootHintName);
    }

    Ok(without_root.to_ascii_lowercase())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecValidationMode {
    Disabled,
}

impl DnssecValidationMode {
    fn cache_namespace_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecursiveTransport {
    Udp,
    Tcp,
}

impl RecursiveTransport {
    fn cache_namespace_label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnameHandlingPolicy {
    Defer,
}

impl DnameHandlingPolicy {
    fn cache_namespace_label(self) -> &'static str {
        match self {
            Self::Defer => "defer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub name: String,
    pub endpoint: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub enabled: bool,
    pub priority: u16,
    pub timeout: Duration,
}

impl UpstreamConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::InvalidUpstreamName);
        }
        if self.endpoint.port() == 0 {
            return Err(ConfigError::InvalidUpstreamEndpoint {
                endpoint: self.endpoint,
            });
        }
        validate_duration(
            "upstream.timeout",
            self.timeout,
            MIN_UPSTREAM_TIMEOUT,
            MAX_UPSTREAM_TIMEOUT,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    Udp,
    Tcp,
}

impl UpstreamProtocol {
    fn cache_namespace_label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDnsEntryConfig {
    pub name: String,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub ttl: u32,
    pub enabled: bool,
    pub public_address_acknowledged: bool,
}

impl LocalDnsEntryConfig {
    pub fn to_local_dns_entry(&self) -> Result<LocalDnsEntry, ConfigError> {
        let name =
            DomainName::parse(&self.name).map_err(|_| ConfigError::InvalidLocalDnsEntryName {
                name: self.name.clone(),
            })?;
        validate_not_registered_tld(&name)?;
        let entry = LocalDnsEntry::new(
            name,
            self.ipv4.clone(),
            self.ipv6.clone(),
            self.ttl,
            self.enabled,
        );
        entry
            .validate(self.public_address_acknowledged)
            .map_err(|reason| ConfigError::InvalidLocalDnsEntry {
                name: self.name.clone(),
                reason,
            })?;
        Ok(entry)
    }
}

/// A BIND-style zone file to load local DNS entries from, additive to
/// (and merged with) `[[local_dns_entries]]`. `root_domain` bounds which
/// names the zone file may define and, via `validate_not_registered_tld`,
/// must not itself sit under a real, currently-delegated IANA TLD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalZoneConfig {
    pub path: PathBuf,
    pub root_domain: DomainName,
    pub public_address_acknowledged: bool,
    pub enabled: bool,
}

impl LocalZoneConfig {
    pub fn validate_root_domain(&self) -> Result<(), ConfigError> {
        validate_not_registered_tld(&self.root_domain)
    }
}

/// Safety ceiling on zone file size, checked before handing content to the
/// scanner. Generous for a hand-maintained local-network zone; bounds
/// worst-case parse time/memory for a misconfigured or malicious file.
pub const MAX_LOCAL_ZONE_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Safety ceiling on the number of A/AAAA records a single zone file may
/// contribute (SOA/NS records don't count).
const MAX_LOCAL_ZONE_RECORDS: usize = 10_000;

/// Parses BIND-format zone file `content` (already read from disk by the
/// caller — this function does no I/O) against an already-validated
/// `LocalZoneConfig`, returning the `LocalDnsEntryConfig`s derived from its
/// `A`/`AAAA` records. `SOA`/`NS` records are recognized and ignored (they're
/// zone-management boilerplate, not answerable local records); any other
/// record type, or a `$INCLUDE` directive, is a hard error rather than
/// being silently dropped. Every record's owner name must fall at or below
/// `zone.root_domain`. Zone files are expected to declare their own
/// `$ORIGIN` for relative names (v1 never calls `Zonefile::set_origin`).
pub fn parse_local_zone_file(
    zone: &LocalZoneConfig,
    content: &str,
) -> Result<Vec<LocalDnsEntryConfig>, ConfigError> {
    let content_len = content.len() as u64;
    if content_len > MAX_LOCAL_ZONE_FILE_BYTES {
        return Err(ConfigError::LocalZoneFileTooLarge {
            path: zone.path.clone(),
            size: content_len,
            max: MAX_LOCAL_ZONE_FILE_BYTES,
        });
    }

    let mut zonefile = Zonefile::from(content);
    // BIND-style zone files commonly omit the class on every record (it's
    // almost always IN), relying on it being inherited from an earlier
    // record. The scanner has nothing to inherit from on a file whose very
    // first record omits it, and errors instead of assuming IN. Since rdns
    // rejects non-IN records anyway (see the class check below), seeding
    // IN as the default costs nothing and avoids spuriously rejecting
    // otherwise-valid zone files.
    zonefile.set_default_class(Class::IN);
    // Accumulate by owner name, preserving first-seen order (same approach
    // as `parse_named_root`). The first TTL seen for a name (across either
    // family) wins for the whole entry, since rdns's `LocalDnsEntry` model
    // has one TTL per entry, not one per family.
    let mut order: Vec<DomainName> = Vec::new();
    let mut by_name: HashMap<DomainName, (Vec<Ipv4Addr>, Vec<Ipv6Addr>, u32)> = HashMap::new();
    let mut record_count: usize = 0;

    while let Some(entry) =
        zonefile
            .next_entry()
            .map_err(|error| ConfigError::LocalZoneParseError {
                path: zone.path.clone(),
                message: error.to_string(),
            })?
    {
        let record = match entry {
            Entry::Include { .. } => {
                return Err(ConfigError::LocalZoneIncludeDirectiveUnsupported {
                    path: zone.path.clone(),
                });
            }
            Entry::Record(record) => record,
        };

        let owner_name = record.owner().to_string();
        let name =
            DomainName::parse(&owner_name).map_err(|_| ConfigError::InvalidLocalDnsEntryName {
                name: owner_name.clone(),
            })?;

        // rdns's local-entry lookup only ever answers qclass IN
        // (`InMemoryLocalDnsEntries::lookup`), so a non-IN record loaded
        // here would otherwise be silently served to ordinary IN clients,
        // crossing DNS class separation. Reject it instead. (The zonefile
        // scanner already requires one consistent class per file, but that
        // invariant says nothing about *which* class — this checks that
        // too.)
        if record.class() != Class::IN {
            return Err(ConfigError::LocalZoneUnsupportedClass {
                path: zone.path.clone(),
                name: name.to_string(),
                class: format!("{:?}", record.class()),
            });
        }

        let rtype = record.data().rtype();
        if rtype == Rtype::SOA || rtype == Rtype::NS {
            continue;
        }
        if !name.is_at_or_below(&zone.root_domain) {
            return Err(ConfigError::LocalZoneRecordOutOfRoot {
                path: zone.path.clone(),
                name: name.to_string(),
                root_domain: zone.root_domain.to_string(),
            });
        }

        record_count += 1;
        if record_count > MAX_LOCAL_ZONE_RECORDS {
            return Err(ConfigError::LocalZoneTooManyRecords {
                path: zone.path.clone(),
                count: record_count,
                max: MAX_LOCAL_ZONE_RECORDS,
            });
        }

        let ttl = record.ttl().as_secs();
        match record.data() {
            ZoneRecordData::A(a) => {
                let addr = a.addr();
                let group = by_name.entry(name.clone()).or_insert_with(|| {
                    order.push(name.clone());
                    (Vec::new(), Vec::new(), ttl)
                });
                group.0.push(addr);
            }
            ZoneRecordData::Aaaa(aaaa) => {
                let addr = aaaa.addr();
                let group = by_name.entry(name.clone()).or_insert_with(|| {
                    order.push(name.clone());
                    (Vec::new(), Vec::new(), ttl)
                });
                group.1.push(addr);
            }
            other => {
                return Err(ConfigError::LocalZoneUnsupportedRecordType {
                    path: zone.path.clone(),
                    name: name.to_string(),
                    record_type: format!("{:?}", other.rtype()),
                });
            }
        }
    }

    Ok(order
        .into_iter()
        .map(|name| {
            let (ipv4, ipv6, ttl) = by_name
                .remove(&name)
                .expect("every name in `order` was inserted into `by_name` at the same time");
            LocalDnsEntryConfig {
                name: name.to_string(),
                ipv4,
                ipv6,
                ttl,
                enabled: zone.enabled,
                public_address_acknowledged: zone.public_address_acknowledged,
            }
        })
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    NoDnsListenAddress,
    InvalidListenAddress {
        address: SocketAddr,
    },
    DuplicateListenAddress {
        address: SocketAddr,
    },
    NoEnabledUpstream,
    InvalidUpstreamName,
    InvalidUpstreamEndpoint {
        endpoint: SocketAddr,
    },
    InvalidDuration {
        field: &'static str,
        value: Duration,
        min: Duration,
        max: Duration,
    },
    InvalidUdpPayloadSize {
        field: &'static str,
        value: usize,
        min: usize,
        max: usize,
    },
    InvalidResolutionGeneration {
        generation: u64,
    },
    MissingRecursiveResolutionConfig,
    InvalidRootHintsVersion,
    MissingRootHints,
    InvalidRootHintName,
    MissingRootHintEndpoints,
    InvalidRootHintEndpoint {
        endpoint: SocketAddr,
    },
    InvalidRecursiveDepth {
        value: u8,
        max: u8,
    },
    InvalidCnameRestartLimit {
        value: u8,
        max: u8,
    },
    NoRecursiveTransports,
    DuplicateRecursiveTransport {
        transport: RecursiveTransport,
    },
    InvalidLocalDnsEntryName {
        name: String,
    },
    InvalidLocalDnsEntry {
        name: String,
        reason: LocalDnsEntryValidationError,
    },
    DuplicateLocalDnsEntryName {
        name: String,
    },
    LocalDnsEntryUsesRegisteredTld {
        name: String,
        tld: String,
    },
    InvalidLocalZoneRootDomain {
        root_domain: String,
    },
    LocalZoneReadError {
        path: PathBuf,
        message: String,
    },
    LocalZoneParseError {
        path: PathBuf,
        message: String,
    },
    LocalZoneIncludeDirectiveUnsupported {
        path: PathBuf,
    },
    LocalZoneUnsupportedRecordType {
        path: PathBuf,
        name: String,
        record_type: String,
    },
    LocalZoneUnsupportedClass {
        path: PathBuf,
        name: String,
        class: String,
    },
    LocalZoneRecordOutOfRoot {
        path: PathBuf,
        name: String,
        root_domain: String,
    },
    LocalZoneFileTooLarge {
        path: PathBuf,
        size: u64,
        max: u64,
    },
    LocalZoneTooManyRecords {
        path: PathBuf,
        count: usize,
        max: usize,
    },
    DuplicateLocalDnsEntryNameAcrossSources {
        name: String,
    },
    InvalidTomlConfig {
        message: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntimeConfig {
    dns_listen: Vec<String>,
    per_query_deadline_ms: u64,
    max_udp_payload_size: usize,
    #[serde(default)]
    resolution: Option<RawResolutionConfig>,
    #[serde(default)]
    upstreams: Vec<RawUpstreamConfig>,
    #[serde(default)]
    local_dns_entries: Vec<RawLocalDnsEntryConfig>,
    #[serde(default)]
    local_zones: Vec<RawLocalZoneConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResolutionConfig {
    mode: String,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    recursive: Option<RawRecursiveResolutionConfig>,
}

impl RawResolutionConfig {
    fn try_into_resolution_config(self) -> Result<ResolutionConfig, ConfigError> {
        match self.mode.as_str() {
            "forward" => Ok(ResolutionConfig {
                mode: ResolutionMode::Forward,
                generation: self.generation,
                recursive: None,
            }),
            "recursive" => {
                let recursive = self
                    .recursive
                    .ok_or(ConfigError::MissingRecursiveResolutionConfig)?
                    .try_into_recursive_resolution_config()?;
                Ok(ResolutionConfig::recursive(self.generation, recursive))
            }
            other => Err(ConfigError::InvalidTomlConfig {
                message: format!("unknown resolution mode: {other}"),
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecursiveResolutionConfig {
    root_hints: String,
    root_hints_version: String,
    #[serde(default)]
    root_hints_entries: Vec<RawRootHintConfig>,
    #[serde(default = "default_per_authority_timeout_ms")]
    per_authority_timeout_ms: u64,
    #[serde(default = "default_max_recursion_depth")]
    max_recursion_depth: u8,
    #[serde(default = "default_max_cname_restarts")]
    max_cname_restarts: u8,
    #[serde(default = "default_allowed_transports")]
    allowed_transports: Vec<String>,
    #[serde(default)]
    dnssec_validation: Option<String>,
    #[serde(default)]
    dname_handling: Option<String>,
}

fn default_per_authority_timeout_ms() -> u64 {
    750
}

fn default_max_recursion_depth() -> u8 {
    16
}

fn default_max_cname_restarts() -> u8 {
    8
}

fn default_allowed_transports() -> Vec<String> {
    vec!["udp".to_string(), "tcp".to_string()]
}

impl RawRecursiveResolutionConfig {
    fn try_into_recursive_resolution_config(
        self,
    ) -> Result<RecursiveResolutionConfig, ConfigError> {
        let dnssec_validation = match self.dnssec_validation.as_deref() {
            None | Some("disabled") => DnssecValidationMode::Disabled,
            Some(other) => {
                return Err(ConfigError::InvalidTomlConfig {
                    message: format!("unknown dnssec_validation mode: {other}"),
                })
            }
        };
        let dname_handling = match self.dname_handling.as_deref() {
            None | Some("defer") => DnameHandlingPolicy::Defer,
            Some(other) => {
                return Err(ConfigError::InvalidTomlConfig {
                    message: format!("unknown dname_handling policy: {other}"),
                })
            }
        };
        let allowed_transports = self
            .allowed_transports
            .iter()
            .map(|value| match value.as_str() {
                "udp" => Ok(RecursiveTransport::Udp),
                "tcp" => Ok(RecursiveTransport::Tcp),
                other => Err(ConfigError::InvalidTomlConfig {
                    message: format!("unknown recursive transport: {other}"),
                }),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut config = match self.root_hints.as_str() {
            "bundled" => RecursiveResolutionConfig::bundled(self.root_hints_version),
            "custom" => {
                let entries = self
                    .root_hints_entries
                    .into_iter()
                    .map(RawRootHintConfig::try_into_root_hint_config)
                    .collect::<Result<Vec<_>, _>>()?;
                RecursiveResolutionConfig::new(self.root_hints_version, entries, dnssec_validation)
            }
            other => {
                return Err(ConfigError::InvalidTomlConfig {
                    message: format!("unknown root_hints source: {other}"),
                })
            }
        };
        config.dnssec_validation = dnssec_validation;
        config.dname_handling = dname_handling;
        config.per_authority_timeout = Duration::from_millis(self.per_authority_timeout_ms);
        config.max_recursion_depth = self.max_recursion_depth;
        config.max_cname_restarts = self.max_cname_restarts;
        config.allowed_transports = allowed_transports;
        Ok(config)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRootHintConfig {
    name: String,
    endpoints: Vec<String>,
}

impl RawRootHintConfig {
    fn try_into_root_hint_config(self) -> Result<RootHintConfig, ConfigError> {
        let endpoints = self
            .endpoints
            .iter()
            .map(|endpoint| parse_socket_addr(endpoint))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RootHintConfig::new(self.name, endpoints))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpstreamConfig {
    name: String,
    endpoint: String,
    protocol: String,
    enabled: bool,
    priority: u16,
    timeout_ms: u64,
}

impl RawUpstreamConfig {
    fn try_into_upstream_config(self) -> Result<UpstreamConfig, ConfigError> {
        let endpoint = parse_socket_addr(&self.endpoint)?;
        let protocol = match self.protocol.as_str() {
            "udp" => UpstreamProtocol::Udp,
            "tcp" => UpstreamProtocol::Tcp,
            other => {
                return Err(ConfigError::InvalidTomlConfig {
                    message: format!("unknown upstream protocol: {other}"),
                })
            }
        };
        Ok(UpstreamConfig {
            name: self.name,
            endpoint,
            protocol,
            enabled: self.enabled,
            priority: self.priority,
            timeout: Duration::from_millis(self.timeout_ms),
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLocalDnsEntryConfig {
    name: String,
    #[serde(default)]
    ipv4: Vec<String>,
    #[serde(default)]
    ipv6: Vec<String>,
    ttl: u32,
    enabled: bool,
    #[serde(default)]
    public_address_acknowledged: bool,
}

impl RawLocalDnsEntryConfig {
    fn try_into_local_dns_entry_config(self) -> Result<LocalDnsEntryConfig, ConfigError> {
        let ipv4 = self
            .ipv4
            .iter()
            .map(|address| parse_ipv4(address))
            .collect::<Result<Vec<_>, _>>()?;
        let ipv6 = self
            .ipv6
            .iter()
            .map(|address| parse_ipv6(address))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LocalDnsEntryConfig {
            name: self.name,
            ipv4,
            ipv6,
            ttl: self.ttl,
            enabled: self.enabled,
            public_address_acknowledged: self.public_address_acknowledged,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLocalZoneConfig {
    path: String,
    root_domain: String,
    #[serde(default)]
    public_address_acknowledged: bool,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

impl RawLocalZoneConfig {
    fn try_into_local_zone_config(self) -> Result<LocalZoneConfig, ConfigError> {
        let root_domain = DomainName::parse(&self.root_domain).map_err(|_| {
            ConfigError::InvalidLocalZoneRootDomain {
                root_domain: self.root_domain.clone(),
            }
        })?;
        let config = LocalZoneConfig {
            path: PathBuf::from(self.path),
            root_domain,
            public_address_acknowledged: self.public_address_acknowledged,
            enabled: self.enabled,
        };
        // Let a registered-TLD failure surface as
        // `LocalDnsEntryUsesRegisteredTld` (it already names the offending
        // TLD) rather than remapping it — `InvalidLocalZoneRootDomain` is
        // reserved for a root_domain that doesn't even parse as a domain
        // name. Both this path and `RuntimeConfig::validate()`'s pure
        // zone-list check go through the same `validate_root_domain()`, so
        // they must produce the same error here.
        config.validate_root_domain()?;
        Ok(config)
    }
}

impl TryFrom<RawRuntimeConfig> for RuntimeConfig {
    type Error = ConfigError;

    fn try_from(raw: RawRuntimeConfig) -> Result<Self, ConfigError> {
        let dns_listen = raw
            .dns_listen
            .iter()
            .map(|address| parse_socket_addr(address))
            .collect::<Result<Vec<_>, _>>()?;
        let resolution = raw
            .resolution
            .map(RawResolutionConfig::try_into_resolution_config)
            .transpose()?
            .unwrap_or_else(ResolutionConfig::forwarding_default);
        let upstreams = raw
            .upstreams
            .into_iter()
            .map(RawUpstreamConfig::try_into_upstream_config)
            .collect::<Result<Vec<_>, _>>()?;
        let local_dns_entries = raw
            .local_dns_entries
            .into_iter()
            .map(RawLocalDnsEntryConfig::try_into_local_dns_entry_config)
            .collect::<Result<Vec<_>, _>>()?;
        let local_zones = raw
            .local_zones
            .into_iter()
            .map(RawLocalZoneConfig::try_into_local_zone_config)
            .collect::<Result<Vec<_>, _>>()?;

        let config = RuntimeConfig {
            dns_listen,
            resolution,
            upstreams,
            per_query_deadline: Duration::from_millis(raw.per_query_deadline_ms),
            max_udp_payload_size: raw.max_udp_payload_size,
            local_dns_entries,
            local_zones,
        };
        config.validate()?;
        Ok(config)
    }
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|_| ConfigError::InvalidTomlConfig {
        message: format!("invalid socket address: {value}"),
    })
}

fn parse_ipv4(value: &str) -> Result<Ipv4Addr, ConfigError> {
    value.parse().map_err(|_| ConfigError::InvalidTomlConfig {
        message: format!("invalid IPv4 address: {value}"),
    })
}

fn parse_ipv6(value: &str) -> Result<Ipv6Addr, ConfigError> {
    value.parse().map_err(|_| ConfigError::InvalidTomlConfig {
        message: format!("invalid IPv6 address: {value}"),
    })
}

const DEFAULT_DNS_LISTEN_PORT: u16 = 5300;
const MIN_UPSTREAM_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_PER_QUERY_DEADLINE: Duration = Duration::from_millis(100);
const MAX_PER_QUERY_DEADLINE: Duration = Duration::from_secs(30);
const MIN_RECURSIVE_AUTHORITY_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_RECURSIVE_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RECURSION_DEPTH: u8 = 64;
const MAX_CNAME_RESTARTS: u8 = 16;
const MIN_UDP_PAYLOAD_SIZE: usize = 512;
const MAX_UDP_PAYLOAD_SIZE: usize = 4096;
const FNV1A64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

fn validate_listen_address(address: SocketAddr) -> Result<(), ConfigError> {
    if address.port() == 0 {
        return Err(ConfigError::InvalidListenAddress { address });
    }
    Ok(())
}

fn validate_duration(
    field: &'static str,
    value: Duration,
    min: Duration,
    max: Duration,
) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::InvalidDuration {
            field,
            value,
            min,
            max,
        });
    }
    Ok(())
}

fn hash_namespace_field(hash: &mut u64, name: &str, value: &str) {
    fn write(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(FNV1A64_PRIME);
        }
    }

    write(hash, name.as_bytes());
    write(hash, b"=");
    write(hash, value.as_bytes());
    write(hash, b";");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(name: &str, priority: u16, enabled: bool) -> UpstreamConfig {
        UpstreamConfig {
            name: name.to_string(),
            endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53),
            protocol: UpstreamProtocol::Udp,
            enabled,
            priority,
            timeout: Duration::from_millis(500),
        }
    }

    fn root_hint(name: &str) -> RootHintConfig {
        RootHintConfig::new(
            name,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53)),
                53,
            )],
        )
    }

    #[test]
    fn development_default_uses_high_local_dns_port_and_enabled_upstream() {
        let config = RuntimeConfig::development_default();

        assert_eq!(config.resolution, ResolutionConfig::forwarding_default());
        assert_eq!(
            config.dns_listen,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                DEFAULT_DNS_LISTEN_PORT
            )]
        );
        assert!(config.dns_listen[0].port() > 1024);
        assert_eq!(config.enabled_upstreams().count(), 1);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_requires_listen_address() {
        let error = RuntimeConfig::new(
            Vec::new(),
            vec![upstream("primary", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();

        assert_eq!(error, ConfigError::NoDnsListenAddress);
    }

    #[test]
    fn config_rejects_port_zero_listen_address() {
        let error = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            vec![upstream("primary", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();

        assert!(matches!(error, ConfigError::InvalidListenAddress { .. }));
    }

    #[test]
    fn config_allows_privileged_listen_address_for_static_runtime() {
        let config = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
            vec![upstream("primary", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();

        assert_eq!(config.dns_listen[0].port(), 53);
    }

    #[test]
    fn config_rejects_duplicate_listen_addresses() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300);
        let error = RuntimeConfig::new(
            vec![address, address],
            vec![upstream("primary", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();

        assert_eq!(error, ConfigError::DuplicateListenAddress { address });
    }

    #[test]
    fn config_requires_enabled_upstream() {
        let error = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![upstream("primary", 10, false)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();

        assert_eq!(error, ConfigError::NoEnabledUpstream);
    }

    #[test]
    fn forward_mode_requires_enabled_upstream() {
        let error = RuntimeConfig::new_with_resolution(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            ResolutionConfig::forwarding_default(),
            vec![upstream("primary", 10, false)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();

        assert_eq!(error, ConfigError::NoEnabledUpstream);

        let mut tcp_only = upstream("tcp-only", 10, true);
        tcp_only.protocol = UpstreamProtocol::Tcp;
        let error = RuntimeConfig::new_with_resolution(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            ResolutionConfig::forwarding_default(),
            vec![tcp_only],
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();

        assert_eq!(error, ConfigError::NoEnabledUpstream);
    }

    #[test]
    fn recursive_mode_requires_settings_but_not_forwarding_upstreams() {
        let config = RuntimeConfig::new_with_resolution(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            ResolutionConfig::recursive(
                7,
                RecursiveResolutionConfig::new(
                    "root-hints:v1",
                    vec![root_hint("a.root-servers.example")],
                    DnssecValidationMode::Disabled,
                ),
            ),
            Vec::new(),
            Duration::from_secs(2),
            1232,
        )
        .unwrap();

        assert_eq!(config.resolution.mode, ResolutionMode::Recursive);
        assert_eq!(config.resolution.generation, 7);
        assert_eq!(config.enabled_upstreams().count(), 0);
    }

    #[test]
    fn recursive_mode_rejects_missing_or_invalid_recursive_settings() {
        let missing_error = RuntimeConfig::new_with_resolution(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            ResolutionConfig {
                mode: ResolutionMode::Recursive,
                generation: 1,
                recursive: None,
            },
            Vec::new(),
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();
        assert_eq!(missing_error, ConfigError::MissingRecursiveResolutionConfig);

        let invalid_error = RuntimeConfig::new_with_resolution(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            ResolutionConfig::recursive(
                1,
                RecursiveResolutionConfig::new(
                    " ",
                    vec![root_hint("a.root-servers.example")],
                    DnssecValidationMode::Disabled,
                ),
            ),
            Vec::new(),
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();
        assert_eq!(invalid_error, ConfigError::InvalidRootHintsVersion);
    }

    #[test]
    fn config_rejects_reserved_resolution_generation() {
        let error = RuntimeConfig::new_with_resolution(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            ResolutionConfig {
                mode: ResolutionMode::Forward,
                generation: u64::MAX,
                recursive: None,
            },
            vec![upstream("primary", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();

        assert_eq!(
            error,
            ConfigError::InvalidResolutionGeneration {
                generation: u64::MAX
            }
        );
    }

    #[test]
    fn enabled_upstreams_are_returned_in_priority_order() {
        let config = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![
                upstream("tertiary", 30, true),
                upstream("disabled", 1, false),
                upstream("primary", 10, true),
            ],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();

        let names: Vec<_> = config
            .enabled_upstreams()
            .map(|upstream| upstream.name.as_str())
            .collect();

        assert_eq!(names, vec!["primary", "tertiary"]);
    }

    #[test]
    fn forwarding_cache_namespace_includes_active_upstream_set() {
        let base = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![upstream("primary", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();
        let same_active_set = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![
                upstream("disabled", 1, false),
                upstream("primary", 10, true),
            ],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();
        let changed_active_set = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![upstream("secondary", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();

        assert!(base
            .backend_cache_namespace()
            .starts_with("mode:forward;generation:0;upstreams:"));
        assert_eq!(
            base.backend_cache_namespace(),
            same_active_set.backend_cache_namespace()
        );
        assert_ne!(
            base.backend_cache_namespace(),
            changed_active_set.backend_cache_namespace()
        );
    }

    #[test]
    fn forwarding_cache_namespace_preserves_equal_priority_backend_order() {
        let corp_first = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![upstream("corp", 10, true), upstream("public", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();
        let public_first = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![upstream("public", 10, true), upstream("corp", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap();

        assert_ne!(
            corp_first.backend_cache_namespace(),
            public_first.backend_cache_namespace()
        );
    }

    #[test]
    fn recursive_cache_namespace_includes_root_hints_and_dnssec_mode() {
        let config = RuntimeConfig::new_with_resolution(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            ResolutionConfig::recursive(
                3,
                RecursiveResolutionConfig::new(
                    "root-hints:v1",
                    vec![root_hint("a.root-servers.example")],
                    DnssecValidationMode::Disabled,
                ),
            ),
            Vec::new(),
            Duration::from_secs(2),
            1232,
        )
        .unwrap();

        assert!(config.backend_cache_namespace().starts_with(
            "mode:recursive;generation:3;root-hints:root-hints:v1;dnssec:disabled;authorities:"
        ));

        let changed_roots = RuntimeConfig::new_with_resolution(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            ResolutionConfig::recursive(
                3,
                RecursiveResolutionConfig::new(
                    "root-hints:v1",
                    vec![root_hint("b.root-servers.example")],
                    DnssecValidationMode::Disabled,
                ),
            ),
            Vec::new(),
            Duration::from_secs(2),
            1232,
        )
        .unwrap();
        assert_ne!(
            config.backend_cache_namespace(),
            changed_roots.backend_cache_namespace()
        );
    }

    #[test]
    fn parse_named_root_extracts_glue_addresses_grouped_by_owner_in_first_seen_order() {
        let source = "\
; comment line, ignored
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
; another comment
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
; End of file
";

        let hints = parse_named_root(source).unwrap();

        assert_eq!(
            hints,
            vec![
                RootHintConfig::new(
                    "a.root-servers.net",
                    vec![
                        "198.41.0.4:53".parse().unwrap(),
                        "[2001:503:ba3e::2:30]:53".parse().unwrap(),
                    ],
                ),
                RootHintConfig::new(
                    "b.root-servers.net",
                    vec!["170.247.170.2:53".parse().unwrap()]
                ),
            ]
        );
    }

    #[test]
    fn parse_named_root_accepts_optional_class_and_inline_comments() {
        let source = "\
.                        3600000  IN  NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000  IN  A     198.41.0.4      ; glue address
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
";

        let hints = parse_named_root(source).unwrap();

        assert_eq!(
            hints,
            vec![RootHintConfig::new(
                "a.root-servers.net",
                vec![
                    "198.41.0.4:53".parse().unwrap(),
                    "[2001:503:ba3e::2:30]:53".parse().unwrap(),
                ],
            )]
        );
    }

    #[test]
    fn parse_named_root_accepts_lowercase_and_mixed_case_record_types() {
        let source = "\
a.root-servers.net.      3600000      a     198.41.0.4
a.root-servers.net.      3600000      Aaaa  2001:503:ba3e::2:30
";

        let hints = parse_named_root(source).unwrap();

        assert_eq!(
            hints,
            vec![RootHintConfig::new(
                "a.root-servers.net",
                vec![
                    "198.41.0.4:53".parse().unwrap(),
                    "[2001:503:ba3e::2:30]:53".parse().unwrap(),
                ],
            )]
        );
    }

    #[test]
    fn parse_named_root_rejects_malformed_or_empty_input() {
        assert!(parse_named_root("").is_err());
        assert!(parse_named_root("; only comments\n").is_err());
        assert!(parse_named_root("A.ROOT-SERVERS.NET. 3600000 A\n").is_err());
        assert!(parse_named_root("A.ROOT-SERVERS.NET. 3600000 A not-an-ip\n").is_err());
    }

    #[test]
    fn parse_named_root_parses_the_bundled_asset() {
        let hints = parse_named_root(BUNDLED_NAMED_ROOT).unwrap();
        assert_eq!(hints.len(), 13);
        assert_eq!(hints[0].name, "a.root-servers.net");
        assert_eq!(hints[12].name, "m.root-servers.net");
    }

    #[test]
    fn recursive_config_validates_root_hints_and_authority_limits() {
        let bundled = RecursiveResolutionConfig::bundled("bundled:v1");
        assert!(bundled.validate().is_ok());
        let root_hints = bundled.load_root_hints().unwrap();
        assert_eq!(root_hints.len(), 13, "expected all 13 root servers");
        for root_hint in &root_hints {
            assert!(
                root_hint.endpoints.iter().any(|e| e.is_ipv4()),
                "{} should have an IPv4 endpoint",
                root_hint.name
            );
            assert!(
                root_hint.endpoints.iter().any(|e| e.is_ipv6()),
                "{} should have an IPv6 endpoint",
                root_hint.name
            );
        }
        assert_eq!(bundled.dname_handling, DnameHandlingPolicy::Defer);

        let missing_roots = RecursiveResolutionConfig::new(
            "root-hints:v1",
            Vec::new(),
            DnssecValidationMode::Disabled,
        )
        .validate()
        .unwrap_err();
        assert_eq!(missing_roots, ConfigError::MissingRootHints);

        let invalid_root = RecursiveResolutionConfig::new(
            "root-hints:v1",
            vec![RootHintConfig::new(
                " ",
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
            )],
            DnssecValidationMode::Disabled,
        )
        .validate()
        .unwrap_err();
        assert_eq!(invalid_root, ConfigError::InvalidRootHintName);

        for invalid_name in [
            "a..root",
            "-a.root",
            "a-.root",
            "root name",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.root",
        ] {
            let invalid_root = RecursiveResolutionConfig::new(
                "root-hints:v1",
                vec![RootHintConfig::new(
                    invalid_name,
                    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
                )],
                DnssecValidationMode::Disabled,
            )
            .validate()
            .unwrap_err();
            assert_eq!(invalid_root, ConfigError::InvalidRootHintName);
        }

        let invalid_endpoint = RecursiveResolutionConfig::new(
            "root-hints:v1",
            vec![RootHintConfig::new(
                "a.root-servers.example",
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
            )],
            DnssecValidationMode::Disabled,
        )
        .validate()
        .unwrap_err();
        assert!(matches!(
            invalid_endpoint,
            ConfigError::InvalidRootHintEndpoint { .. }
        ));

        for invalid_address in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
        ] {
            let invalid_endpoint = RecursiveResolutionConfig::new(
                "root-hints:v1",
                vec![RootHintConfig::new(
                    "a.root-servers.example",
                    vec![SocketAddr::new(invalid_address, 53)],
                )],
                DnssecValidationMode::Disabled,
            )
            .validate()
            .unwrap_err();
            assert!(matches!(
                invalid_endpoint,
                ConfigError::InvalidRootHintEndpoint { .. }
            ));
        }

        let mut invalid_limits = RecursiveResolutionConfig::new(
            "root-hints:v1",
            vec![root_hint("a.root-servers.example")],
            DnssecValidationMode::Disabled,
        );
        invalid_limits.per_authority_timeout = Duration::from_secs(30);
        assert!(matches!(
            invalid_limits.validate().unwrap_err(),
            ConfigError::InvalidDuration {
                field: "recursive.per_authority_timeout",
                ..
            }
        ));

        invalid_limits.per_authority_timeout = Duration::from_millis(750);
        invalid_limits.max_recursion_depth = 0;
        assert_eq!(
            invalid_limits.validate().unwrap_err(),
            ConfigError::InvalidRecursiveDepth {
                value: 0,
                max: MAX_RECURSION_DEPTH
            }
        );

        invalid_limits.max_recursion_depth = 16;
        invalid_limits.max_cname_restarts = MAX_CNAME_RESTARTS + 1;
        assert_eq!(
            invalid_limits.validate().unwrap_err(),
            ConfigError::InvalidCnameRestartLimit {
                value: MAX_CNAME_RESTARTS + 1,
                max: MAX_CNAME_RESTARTS
            }
        );

        invalid_limits.max_cname_restarts = 8;
        invalid_limits.allowed_transports.clear();
        assert_eq!(
            invalid_limits.validate().unwrap_err(),
            ConfigError::NoRecursiveTransports
        );

        invalid_limits.allowed_transports = vec![RecursiveTransport::Udp, RecursiveTransport::Udp];
        assert_eq!(
            invalid_limits.validate().unwrap_err(),
            ConfigError::DuplicateRecursiveTransport {
                transport: RecursiveTransport::Udp
            }
        );
    }

    #[test]
    fn config_rejects_unbounded_timing_and_udp_values() {
        let deadline_error = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![upstream("primary", 10, true)],
            Duration::from_secs(60),
            1232,
        )
        .unwrap_err();
        assert!(matches!(
            deadline_error,
            ConfigError::InvalidDuration {
                field: "per_query_deadline",
                ..
            }
        ));

        let udp_error = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)],
            vec![upstream("primary", 10, true)],
            Duration::from_secs(2),
            64,
        )
        .unwrap_err();
        assert!(matches!(
            udp_error,
            ConfigError::InvalidUdpPayloadSize {
                field: "max_udp_payload_size",
                ..
            }
        ));
    }

    #[test]
    fn upstream_validation_rejects_empty_name_endpoint_port_zero_and_timeout_bounds() {
        let name_error = UpstreamConfig {
            name: " ".to_string(),
            ..upstream("primary", 10, true)
        }
        .validate()
        .unwrap_err();
        assert_eq!(name_error, ConfigError::InvalidUpstreamName);

        let endpoint_error = UpstreamConfig {
            endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 0),
            ..upstream("primary", 10, true)
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            endpoint_error,
            ConfigError::InvalidUpstreamEndpoint { .. }
        ));

        let timeout_error = UpstreamConfig {
            timeout: Duration::from_millis(1),
            ..upstream("primary", 10, true)
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            timeout_error,
            ConfigError::InvalidDuration {
                field: "upstream.timeout",
                ..
            }
        ));
    }

    fn valid_toml() -> String {
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
        .to_string()
    }

    #[test]
    fn toml_config_round_trip_loads_upstreams_and_local_dns_entries() {
        let config = RuntimeConfig::from_toml_str(&valid_toml()).unwrap();

        assert_eq!(
            config.dns_listen,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5300)]
        );
        assert_eq!(config.per_query_deadline, Duration::from_secs(2));
        assert_eq!(config.max_udp_payload_size, 1232);
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].name, "cloudflare");
        assert_eq!(config.local_dns_entries.len(), 1);
        let entry = config.local_dns_entries[0].to_local_dns_entry().unwrap();
        assert_eq!(entry.name, DomainName::parse("nas.lan").unwrap());
        assert_eq!(entry.ipv4, vec![Ipv4Addr::new(192, 168, 1, 10)]);
    }

    #[test]
    fn toml_config_round_trip_loads_local_zones() {
        let mut toml = valid_toml();
        toml.push_str(
            r#"
            [[local_zones]]
            path = "zones/mynetwork.zone"
            root_domain = "mynetwork"
            public_address_acknowledged = false
            enabled = true
            "#,
        );

        let config = RuntimeConfig::from_toml_str(&toml).unwrap();

        assert_eq!(config.local_zones.len(), 1);
        let zone = &config.local_zones[0];
        assert_eq!(zone.path, PathBuf::from("zones/mynetwork.zone"));
        assert_eq!(zone.root_domain, DomainName::parse("mynetwork").unwrap());
        assert!(zone.enabled);
        assert!(!zone.public_address_acknowledged);
    }

    #[test]
    fn toml_config_local_zones_enabled_defaults_to_true() {
        let mut toml = valid_toml();
        toml.push_str(
            r#"
            [[local_zones]]
            path = "zones/mynetwork.zone"
            root_domain = "mynetwork"
            "#,
        );

        let config = RuntimeConfig::from_toml_str(&toml).unwrap();

        assert!(config.local_zones[0].enabled);
    }

    #[test]
    fn toml_config_rejects_local_zone_with_registered_tld_root_domain() {
        let mut toml = valid_toml();
        toml.push_str(
            r#"
            [[local_zones]]
            path = "zones/mynetwork.zone"
            root_domain = "com"
            "#,
        );

        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();

        assert!(matches!(
            error,
            ConfigError::LocalDnsEntryUsesRegisteredTld { .. }
        ));
    }

    #[test]
    fn toml_config_rejects_invalid_syntax() {
        let error = RuntimeConfig::from_toml_str("not valid toml [[[").unwrap_err();

        assert!(matches!(error, ConfigError::InvalidTomlConfig { .. }));
    }

    #[test]
    fn toml_config_rejects_unknown_resolution_mode_instead_of_ignoring_it() {
        // Unknown/unsupported values in `resolution.mode` must fail to load
        // rather than being silently ignored and falling back to forwarding.
        let mut toml = valid_toml();
        toml.push_str(
            r#"
            [resolution]
            mode = "bogus"
            "#,
        );

        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();

        assert!(matches!(error, ConfigError::InvalidTomlConfig { .. }));
    }

    #[test]
    fn toml_config_rejects_recursive_mode_without_recursive_section() {
        let mut toml = valid_toml();
        toml.push_str(
            r#"
            [resolution]
            mode = "recursive"
            "#,
        );

        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();

        assert!(matches!(
            error,
            ConfigError::MissingRecursiveResolutionConfig
        ));
    }

    #[test]
    fn toml_config_round_trip_loads_bundled_recursive_resolution() {
        let mut toml = valid_toml();
        toml.push_str(
            r#"
            [resolution]
            mode = "recursive"

            [resolution.recursive]
            root_hints = "bundled"
            root_hints_version = "bundled:v1"
            "#,
        );

        let config = RuntimeConfig::from_toml_str(&toml).unwrap();

        assert_eq!(config.resolution.mode, ResolutionMode::Recursive);
        let recursive = config.resolution.recursive.as_ref().unwrap();
        assert_eq!(recursive.root_hints_source, RootHintsSource::Bundled);
        assert_eq!(recursive.root_hints_version, "bundled:v1");
        assert_eq!(recursive.per_authority_timeout, Duration::from_millis(750));
        assert_eq!(recursive.max_recursion_depth, 16);
        assert_eq!(recursive.max_cname_restarts, 8);
        assert_eq!(
            recursive.allowed_transports,
            vec![RecursiveTransport::Udp, RecursiveTransport::Tcp]
        );
        assert_eq!(recursive.dnssec_validation, DnssecValidationMode::Disabled);
        assert_eq!(recursive.dname_handling, DnameHandlingPolicy::Defer);
    }

    #[test]
    fn toml_config_round_trip_loads_custom_recursive_root_hints() {
        // Recursive mode doesn't require any forwarding upstreams to be configured.
        let toml = r#"
            dns_listen = ["127.0.0.1:5300"]
            per_query_deadline_ms = 2000
            max_udp_payload_size = 1232

            [resolution]
            mode = "recursive"
            generation = 3

            [resolution.recursive]
            root_hints = "custom"
            root_hints_version = "custom:v1"
            per_authority_timeout_ms = 500
            max_recursion_depth = 8
            max_cname_restarts = 4
            allowed_transports = ["udp"]
            dnssec_validation = "disabled"
            dname_handling = "defer"

            [[resolution.recursive.root_hints_entries]]
            name = "a.root-servers.net"
            endpoints = ["198.41.0.4:53"]
        "#;

        let config = RuntimeConfig::from_toml_str(toml).unwrap();

        assert_eq!(config.resolution.generation, 3);
        let recursive = config.resolution.recursive.as_ref().unwrap();
        assert_eq!(
            recursive.root_hints_source,
            RootHintsSource::Static(vec![RootHintConfig::new(
                "a.root-servers.net",
                vec!["198.41.0.4:53".parse().unwrap()],
            )])
        );
        assert_eq!(recursive.per_authority_timeout, Duration::from_millis(500));
        assert_eq!(recursive.max_recursion_depth, 8);
        assert_eq!(recursive.max_cname_restarts, 4);
        assert_eq!(recursive.allowed_transports, vec![RecursiveTransport::Udp]);
    }

    #[test]
    fn toml_config_rejects_custom_recursive_root_hints_with_no_entries() {
        let toml = r#"
            dns_listen = ["127.0.0.1:5300"]
            per_query_deadline_ms = 2000
            max_udp_payload_size = 1232

            [resolution]
            mode = "recursive"

            [resolution.recursive]
            root_hints = "custom"
            root_hints_version = "custom:v1"
        "#;

        let error = RuntimeConfig::from_toml_str(toml).unwrap_err();

        assert!(matches!(error, ConfigError::MissingRootHints));
    }

    #[test]
    fn toml_config_rejects_invalid_local_entry_address() {
        let toml = valid_toml().replace("192.168.1.10", "not-an-ip");

        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();

        assert!(matches!(error, ConfigError::InvalidTomlConfig { .. }));
    }

    #[test]
    fn toml_config_rejects_public_address_without_acknowledgement() {
        let toml = valid_toml().replace("192.168.1.10", "8.8.8.8");

        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();

        assert!(matches!(
            error,
            ConfigError::InvalidLocalDnsEntry {
                reason: LocalDnsEntryValidationError::PublicAddressRequiresAcknowledgement,
                ..
            }
        ));
    }

    #[test]
    fn toml_config_allows_public_address_with_acknowledgement() {
        let toml = valid_toml().replace("192.168.1.10", "8.8.8.8").replace(
            "public_address_acknowledged = false",
            "public_address_acknowledged = true",
        );

        let config = RuntimeConfig::from_toml_str(&toml).unwrap();

        assert_eq!(
            config.local_dns_entries[0].ipv4,
            vec![Ipv4Addr::new(8, 8, 8, 8)]
        );
    }

    #[test]
    fn toml_config_rejects_zero_ttl_and_empty_addresses() {
        let no_addresses = valid_toml().replace(r#"ipv4 = ["192.168.1.10"]"#, "");
        let error = RuntimeConfig::from_toml_str(&no_addresses).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::InvalidLocalDnsEntry {
                reason: LocalDnsEntryValidationError::NoAddresses,
                ..
            }
        ));

        let zero_ttl = valid_toml().replace("ttl = 300", "ttl = 0");
        let error = RuntimeConfig::from_toml_str(&zero_ttl).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::InvalidLocalDnsEntry {
                reason: LocalDnsEntryValidationError::TtlTooLow,
                ..
            }
        ));
    }

    #[test]
    fn toml_config_rejects_duplicate_local_entry_names() {
        let mut toml = valid_toml();
        toml.push_str(
            r#"
            [[local_dns_entries]]
            name = "NAS.lan."
            ipv4 = ["192.168.1.11"]
            ttl = 300
            enabled = true
            public_address_acknowledged = false
            "#,
        );

        let error = RuntimeConfig::from_toml_str(&toml).unwrap_err();

        assert!(matches!(
            error,
            ConfigError::DuplicateLocalDnsEntryName { .. }
        ));
    }

    #[test]
    fn parse_iana_tlds_rejects_malformed_or_empty_input() {
        assert!(parse_iana_tlds("").is_err());
        assert!(parse_iana_tlds("# only a comment\n").is_err());
        assert!(parse_iana_tlds("COM NET\n").is_err());
    }

    #[test]
    fn parse_iana_tlds_parses_the_bundled_asset() {
        let tlds = bundled_iana_tlds();
        assert!(!tlds.is_empty());
        assert!(tlds.contains("com"));
        assert!(tlds.contains("net"));
        assert!(tlds.contains("org"));
        // Special-use names (RFC 6761) are never delegated TLDs, so they
        // must not appear in this list.
        assert!(!tlds.contains("lab"));
        assert!(!tlds.contains("mynet"));
        assert!(!tlds.contains("local"));
        assert!(!tlds.contains("test"));
        assert!(!tlds.contains("example"));
        assert!(!tlds.contains("invalid"));
    }

    #[test]
    fn is_registered_iana_tld_is_case_insensitive() {
        assert!(is_registered_iana_tld("com"));
        assert!(is_registered_iana_tld("COM"));
        assert!(is_registered_iana_tld("CoM"));
        assert!(!is_registered_iana_tld("lab"));
    }

    #[test]
    fn validate_not_registered_tld_checks_rightmost_label_only() {
        // Multi-label name: only the rightmost label (the TLD) matters.
        assert!(validate_not_registered_tld(&DomainName::parse("nas.lan").unwrap()).is_ok());
        assert!(validate_not_registered_tld(&DomainName::parse("nas.com").unwrap()).is_err());
        // Single-label "root domain" shaped name: checks itself.
        assert!(validate_not_registered_tld(&DomainName::parse("lab").unwrap()).is_ok());
        assert!(validate_not_registered_tld(&DomainName::parse("com").unwrap()).is_err());
        // Special-use names are accepted (not in the delegated-TLD list).
        assert!(validate_not_registered_tld(&DomainName::parse("local").unwrap()).is_ok());
        assert!(validate_not_registered_tld(&DomainName::parse("test").unwrap()).is_ok());
        assert!(validate_not_registered_tld(&DomainName::parse("example").unwrap()).is_ok());
    }

    #[test]
    fn validate_not_registered_tld_allows_home_arpa_despite_arpa_being_a_real_tld() {
        // `arpa` is a real, delegated infrastructure TLD (it's in the
        // bundled list), so the plain rightmost-label rule would otherwise
        // wrongly reject `home.arpa` and anything under it — but
        // `home.arpa` is IANA's own Special-Use Domain Name (RFC 8375) for
        // exactly this purpose.
        assert!(is_registered_iana_tld("arpa"));
        assert!(validate_not_registered_tld(&DomainName::parse("arpa").unwrap()).is_err());
        assert!(validate_not_registered_tld(&DomainName::parse("home.arpa").unwrap()).is_ok());
        assert!(
            validate_not_registered_tld(&DomainName::parse("router.home.arpa").unwrap()).is_ok()
        );
    }

    #[test]
    fn toml_config_accepts_home_arpa_for_local_zone_root_domain_and_inline_entry_name() {
        let mut toml = valid_toml();
        toml.push_str(
            r#"
            [[local_dns_entries]]
            name = "router.home.arpa"
            ipv4 = ["192.168.1.1"]
            ttl = 300
            enabled = true
            public_address_acknowledged = false

            [[local_zones]]
            path = "zones/home.zone"
            root_domain = "home.arpa"
            "#,
        );

        let config = RuntimeConfig::from_toml_str(&toml).unwrap();

        assert_eq!(
            config.local_zones[0].root_domain,
            DomainName::parse("home.arpa").unwrap()
        );
        let inline = config
            .local_dns_entries
            .iter()
            .find(|e| e.name == "router.home.arpa")
            .unwrap();
        assert!(inline.to_local_dns_entry().is_ok());
    }

    #[test]
    fn to_local_dns_entry_rejects_names_using_a_registered_tld() {
        let entry = LocalDnsEntryConfig {
            name: "printer.com".to_string(),
            ipv4: vec![Ipv4Addr::new(192, 168, 1, 20)],
            ipv6: Vec::new(),
            ttl: 300,
            enabled: true,
            public_address_acknowledged: false,
        };

        let error = entry.to_local_dns_entry().unwrap_err();

        assert!(matches!(
            error,
            ConfigError::LocalDnsEntryUsesRegisteredTld { tld, .. } if tld == "com"
        ));
    }

    fn local_zone(root_domain: &str) -> LocalZoneConfig {
        LocalZoneConfig {
            path: PathBuf::from("zones/test.zone"),
            root_domain: DomainName::parse(root_domain).unwrap(),
            public_address_acknowledged: false,
            enabled: true,
        }
    }

    #[test]
    fn raw_local_zone_config_rejects_registered_tld_root_domain() {
        let raw = RawLocalZoneConfig {
            path: "zones/test.zone".to_string(),
            root_domain: "com".to_string(),
            public_address_acknowledged: false,
            enabled: true,
        };

        let error = raw.try_into_local_zone_config().unwrap_err();

        assert!(matches!(
            error,
            ConfigError::LocalDnsEntryUsesRegisteredTld { tld, .. } if tld == "com"
        ));
    }

    #[test]
    fn raw_local_zone_config_rejects_malformed_root_domain() {
        let raw = RawLocalZoneConfig {
            path: "zones/test.zone".to_string(),
            root_domain: "..bad..".to_string(),
            public_address_acknowledged: false,
            enabled: true,
        };

        let error = raw.try_into_local_zone_config().unwrap_err();

        assert!(matches!(
            error,
            ConfigError::InvalidLocalZoneRootDomain { .. }
        ));
    }

    #[test]
    fn raw_local_zone_config_accepts_valid_root_domain() {
        let raw = RawLocalZoneConfig {
            path: "zones/test.zone".to_string(),
            root_domain: "mynetwork".to_string(),
            public_address_acknowledged: false,
            enabled: true,
        };

        let config = raw.try_into_local_zone_config().unwrap();

        assert_eq!(config.root_domain, DomainName::parse("mynetwork").unwrap());
    }

    #[test]
    fn runtime_config_validate_rejects_local_zone_with_registered_tld_root_without_reading_any_file(
    ) {
        let mut config = RuntimeConfig::development_default();
        config.local_zones.push(local_zone("com"));

        let error = config.validate().unwrap_err();

        assert!(
            matches!(error, ConfigError::LocalDnsEntryUsesRegisteredTld { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn parse_local_zone_file_groups_multiple_records_per_owner_and_ignores_soa_ns() {
        let zone = concat!(
            "$ORIGIN mynetwork.\n",
            "$TTL 300\n",
            "@       IN  SOA ns1.mynetwork. admin.mynetwork. ( 1 3600 600 604800 300 )\n",
            "        IN  NS  ns1.mynetwork.\n",
            "ns1     IN  A   192.168.1.1\n",
            "        IN  AAAA fd00::1\n",
            "nas     600 IN  A   192.168.1.10\n",
        );

        let entries = parse_local_zone_file(&local_zone("mynetwork"), zone).unwrap();

        assert_eq!(entries.len(), 2);
        let ns1 = entries.iter().find(|e| e.name == "ns1.mynetwork").unwrap();
        assert_eq!(ns1.ipv4, vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(ns1.ipv6, vec!["fd00::1".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(ns1.ttl, 300);
        let nas = entries.iter().find(|e| e.name == "nas.mynetwork").unwrap();
        assert_eq!(nas.ipv4, vec![Ipv4Addr::new(192, 168, 1, 10)]);
        assert_eq!(nas.ttl, 600);
    }

    #[test]
    fn parse_local_zone_file_accepts_records_that_omit_the_class() {
        // BIND zone files commonly omit `IN` entirely (it's the near-universal
        // default), including on the very first record, where the scanner has
        // no earlier record to inherit a class from. Without an explicit
        // default class this would fail to parse even though it's a
        // perfectly ordinary local zone file.
        let zone = concat!(
            "$ORIGIN mynetwork.\n",
            "$TTL 300\n",
            "router A 192.168.1.1\n",
        );

        let entries = parse_local_zone_file(&local_zone("mynetwork"), zone).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "router.mynetwork");
        assert_eq!(entries[0].ipv4, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[test]
    fn parse_local_zone_file_rejects_record_outside_root_domain() {
        let zone = concat!(
            "$ORIGIN example.\n",
            "$TTL 300\n",
            "nas     IN  A   192.168.1.10\n",
        );

        let error = parse_local_zone_file(&local_zone("mynetwork"), zone).unwrap_err();

        assert!(matches!(
            error,
            ConfigError::LocalZoneRecordOutOfRoot { .. }
        ));
    }

    #[test]
    fn parse_local_zone_file_rejects_unsupported_record_types() {
        for (label, line) in [
            ("CNAME", "www 300 IN CNAME nas.mynetwork.\n"),
            ("MX", "mynetwork. 300 IN MX 10 mail.mynetwork.\n"),
            ("TXT", "mynetwork. 300 IN TXT \"hello\"\n"),
            ("SRV", "_svc._tcp 300 IN SRV 0 0 80 nas.mynetwork.\n"),
        ] {
            let zone = format!("$ORIGIN mynetwork.\n{line}");
            let error = parse_local_zone_file(&local_zone("mynetwork"), &zone).unwrap_err();
            assert!(
                matches!(error, ConfigError::LocalZoneUnsupportedRecordType { .. }),
                "expected {label} to be rejected, got {error:?}"
            );
        }
    }

    #[test]
    fn parse_local_zone_file_rejects_non_in_class_records() {
        // The scanner is seeded with a default class of IN (so files that
        // omit the class entirely, the common BIND style, still parse — see
        // `parse_local_zone_file_accepts_records_that_omit_the_class`). That
        // means an *explicit* non-IN class now conflicts with the
        // already-established IN default and is rejected by the scanner
        // itself (RFC 1035 §5.2's "all RRs in the file should have the same
        // class") before it ever reaches our own `record.class()` check, so
        // this now surfaces as a `LocalZoneParseError` rather than
        // `LocalZoneUnsupportedClass`. The `record.class()` check stays in
        // place as defense-in-depth in case that scanner behavior ever
        // changes; either way, non-IN records must never be loaded.
        for (label, line) in [
            ("CH A", "host CH A 192.168.1.10\n"),
            ("HS AAAA", "host HS AAAA fd00::1\n"),
        ] {
            let zone = format!("$ORIGIN mynetwork.\n{line}");
            let error = parse_local_zone_file(&local_zone("mynetwork"), &zone).unwrap_err();
            assert!(
                matches!(error, ConfigError::LocalZoneParseError { .. }),
                "expected {label} to be rejected, got {error:?}"
            );
        }
    }

    #[test]
    fn parse_local_zone_file_rejects_include_directive() {
        let zone = "$ORIGIN mynetwork.\n$INCLUDE other.zone\n";

        let error = parse_local_zone_file(&local_zone("mynetwork"), zone).unwrap_err();

        assert!(matches!(
            error,
            ConfigError::LocalZoneIncludeDirectiveUnsupported { .. }
        ));
    }

    #[test]
    fn parse_local_zone_file_rejects_malformed_syntax() {
        let zone = "$ORIGIN mynetwork.\nnas 300 IN A this-is-not-an-ip\n";

        let error = parse_local_zone_file(&local_zone("mynetwork"), zone).unwrap_err();

        assert!(matches!(error, ConfigError::LocalZoneParseError { .. }));
    }

    #[test]
    fn parse_local_zone_file_requires_origin_for_relative_names() {
        // No $ORIGIN declared and no `set_origin` call (v1 never calls it).
        let zone = "nas 300 IN A 192.168.1.10\n";

        let error = parse_local_zone_file(&local_zone("mynetwork"), zone).unwrap_err();

        assert!(matches!(error, ConfigError::LocalZoneParseError { .. }));
    }

    #[test]
    fn parse_local_zone_file_rejects_content_over_the_size_ceiling() {
        let huge = "x".repeat((MAX_LOCAL_ZONE_FILE_BYTES + 1) as usize);

        let error = parse_local_zone_file(&local_zone("mynetwork"), &huge).unwrap_err();

        assert!(matches!(error, ConfigError::LocalZoneFileTooLarge { .. }));
    }

    #[test]
    fn parse_local_zone_file_rejects_too_many_records() {
        let mut zone = String::from("$ORIGIN mynetwork.\n$TTL 300\n");
        for i in 0..=MAX_LOCAL_ZONE_RECORDS {
            zone.push_str(&format!("host{i} IN A 192.168.1.1\n"));
        }

        let error = parse_local_zone_file(&local_zone("mynetwork"), &zone).unwrap_err();

        assert!(matches!(error, ConfigError::LocalZoneTooManyRecords { .. }));
    }

    #[test]
    fn parse_local_zone_file_accepts_special_use_root_domains() {
        for root in ["local", "test", "example", "home.arpa"] {
            let zone = format!("$ORIGIN {root}.\n$TTL 300\nnas IN A 192.168.1.10\n");
            let entries = parse_local_zone_file(&local_zone(root), &zone)
                .unwrap_or_else(|error| panic!("root domain {root} should be accepted: {error:?}"));
            assert_eq!(entries.len(), 1);
        }
    }

    #[test]
    fn parse_local_zone_file_entries_flow_through_the_same_validation_as_inline_entries() {
        // A zone-derived entry with a public/routable address and the
        // zone's public_address_acknowledged left false must be rejected,
        // same as an inline entry would be.
        let zone = "$ORIGIN mynetwork.\n$TTL 300\nweb IN A 8.8.8.8\n";
        let zone_config = local_zone("mynetwork");

        let entries = parse_local_zone_file(&zone_config, zone).unwrap();
        let error = entries[0].to_local_dns_entry().unwrap_err();

        assert!(matches!(
            error,
            ConfigError::InvalidLocalDnsEntry {
                reason: LocalDnsEntryValidationError::PublicAddressRequiresAcknowledgement,
                ..
            }
        ));
    }
}
