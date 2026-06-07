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

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub dns_listen: Vec<SocketAddr>,
    pub resolution: ResolutionConfig,
    pub upstreams: Vec<UpstreamConfig>,
    pub per_query_deadline: Duration,
    pub max_udp_payload_size: usize,
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
        }
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

fn bundled_root_hints() -> Vec<RootHintConfig> {
    vec![
        RootHintConfig::new(
            "a.root-servers.net",
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                53,
            )],
        ),
        RootHintConfig::new(
            "b.root-servers.net",
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                53,
            )],
        ),
    ]
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
    if address.port() <= 1024 {
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
    fn config_rejects_privileged_listen_address_for_static_runtime() {
        let error = RuntimeConfig::new(
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
            vec![upstream("primary", 10, true)],
            Duration::from_secs(2),
            1232,
        )
        .unwrap_err();

        assert!(matches!(error, ConfigError::InvalidListenAddress { .. }));
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
    fn recursive_config_validates_root_hints_and_authority_limits() {
        let bundled = RecursiveResolutionConfig::bundled("bundled:v1");
        assert!(bundled.validate().is_ok());
        assert!(!bundled.load_root_hints().unwrap().is_empty());
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
}
