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
        let config = Self {
            dns_listen,
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

        if self.enabled_upstreams().next().is_none() {
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
            .filter(|upstream| upstream.enabled)
            .collect();
        upstreams.sort_by_key(|upstream| upstream.priority);
        upstreams.into_iter()
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
}

const DEFAULT_DNS_LISTEN_PORT: u16 = 5300;
const MIN_UPSTREAM_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_PER_QUERY_DEADLINE: Duration = Duration::from_millis(100);
const MAX_PER_QUERY_DEADLINE: Duration = Duration::from_secs(30);
const MIN_UDP_PAYLOAD_SIZE: usize = 512;
const MAX_UDP_PAYLOAD_SIZE: usize = 4096;

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

    #[test]
    fn development_default_uses_high_local_dns_port_and_enabled_upstream() {
        let config = RuntimeConfig::development_default();

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
