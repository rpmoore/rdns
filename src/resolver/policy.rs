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

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use super::{BlockReason, PolicyBlock, PolicyDecision, PolicyEvaluator, QuestionKey};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainName(String);

impl DomainName {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, DomainNameError> {
        let input = input.as_ref();
        let without_root = input.strip_suffix('.').unwrap_or(input);
        if without_root.is_empty() {
            return Ok(Self::root());
        }
        if without_root.split('.').any(str::is_empty) {
            return Err(DomainNameError::EmptyLabel);
        }

        let normalized = idna::domain_to_ascii(without_root)
            .map_err(|_| DomainNameError::InvalidIdn)?
            .to_ascii_lowercase();
        validate_normalized_domain(&normalized)?;
        Ok(Self(normalized))
    }

    pub fn root() -> Self {
        Self(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    fn is_at_or_below(&self, base: &Self) -> bool {
        if base.is_root() {
            return true;
        }
        self == base || self.0.ends_with(&format!(".{}", base.0))
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            f.write_str(".")
        } else {
            f.write_str(&self.0)
        }
    }
}

impl FromStr for DomainName {
    type Err = DomainNameError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainNameError {
    InvalidIdn,
    EmptyLabel,
    LabelTooLong { label: String, len: usize },
    NameTooLong { len: usize },
    InvalidLabelCharacter { label: String, ch: char },
    InvalidLabelHyphen { label: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DomainSelector {
    Exact(DomainName),
    Subtree(DomainName),
}

impl DomainSelector {
    pub fn exact(domain: impl AsRef<str>) -> Result<Self, DomainNameError> {
        Ok(Self::Exact(DomainName::parse(domain)?))
    }

    pub fn subtree(domain: impl AsRef<str>) -> Result<Self, DomainNameError> {
        Ok(Self::Subtree(DomainName::parse(domain)?))
    }

    pub fn matches(&self, domain: &DomainName) -> bool {
        match self {
            Self::Exact(candidate) => domain == candidate,
            Self::Subtree(base) => domain.is_at_or_below(base),
        }
    }

    pub fn domain(&self) -> &DomainName {
        match self {
            Self::Exact(domain) | Self::Subtree(domain) => domain,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientIdentity {
    Ip(IpAddr),
}

impl ClientIdentity {
    pub fn ip(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }

    pub fn source_ip(&self) -> IpAddr {
        match self {
            Self::Ip(ip) => *ip,
        }
    }
}

impl From<IpAddr> for ClientIdentity {
    fn from(ip: IpAddr) -> Self {
        Self::ip(ip)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientSelector {
    ExactIp(IpAddr),
    Cidr(IpCidr),
}

impl ClientSelector {
    pub fn exact_ip(ip: IpAddr) -> Self {
        Self::ExactIp(ip)
    }

    pub fn cidr(network: IpAddr, prefix_len: u8) -> Result<Self, CidrPrefixError> {
        Ok(Self::Cidr(IpCidr::new(network, prefix_len)?))
    }

    pub fn matches(&self, client: &ClientIdentity) -> bool {
        match self {
            Self::ExactIp(ip) => client.source_ip() == *ip,
            Self::Cidr(cidr) => cidr.contains(client.source_ip()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDenyRule {
    pub id: String,
    pub client: ClientSelector,
    pub domain: DomainSelector,
    pub enabled: bool,
}

impl LocalDenyRule {
    pub fn new(
        id: impl Into<String>,
        client: ClientSelector,
        domain: DomainSelector,
        enabled: bool,
    ) -> Self {
        Self {
            id: id.into(),
            client,
            domain,
            enabled,
        }
    }

    pub fn matches(&self, client: &ClientIdentity, domain: &DomainName) -> bool {
        self.enabled && self.client.matches(client) && self.domain.matches(domain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaliciousDomainRule {
    pub id: String,
    pub domain: DomainSelector,
    pub enabled: bool,
}

impl MaliciousDomainRule {
    pub fn new(id: impl Into<String>, domain: DomainSelector, enabled: bool) -> Self {
        Self {
            id: id.into(),
            domain,
            enabled,
        }
    }

    pub fn matches(&self, domain: &DomainName) -> bool {
        self.enabled && self.domain.matches(domain)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalPolicyEvaluator {
    deny_rules: Vec<LocalDenyRule>,
}

impl LocalPolicyEvaluator {
    pub fn new(deny_rules: Vec<LocalDenyRule>) -> Self {
        Self { deny_rules }
    }

    pub fn deny_rules(&self) -> &[LocalDenyRule] {
        &self.deny_rules
    }

    pub fn evaluate_identity(
        &self,
        client: &ClientIdentity,
        domain: &DomainName,
    ) -> PolicyDecision {
        self.deny_rules
            .iter()
            .find(|rule| rule.matches(client, domain))
            .map(|rule| {
                PolicyDecision::Block(PolicyBlock {
                    reason: BlockReason::LocalRule,
                    rule_id: Some(rule.id.clone()),
                })
            })
            .unwrap_or(PolicyDecision::Allow)
    }
}

impl PolicyEvaluator for LocalPolicyEvaluator {
    fn evaluate(&self, client_ip: IpAddr, question: &QuestionKey) -> PolicyDecision {
        let Ok(domain) = DomainName::parse(&question.qname) else {
            return PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::InvalidDomain,
                rule_id: None,
            });
        };
        self.evaluate_identity(&ClientIdentity::ip(client_ip), &domain)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaliciousDomainPolicyEvaluator {
    rules: Vec<MaliciousDomainRule>,
}

impl MaliciousDomainPolicyEvaluator {
    pub fn new(rules: Vec<MaliciousDomainRule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[MaliciousDomainRule] {
        &self.rules
    }

    pub fn evaluate_domain(&self, domain: &DomainName) -> PolicyDecision {
        self.rules
            .iter()
            .find(|rule| rule.matches(domain))
            .map(|rule| {
                PolicyDecision::Block(PolicyBlock {
                    reason: BlockReason::MaliciousDomain,
                    rule_id: Some(rule.id.clone()),
                })
            })
            .unwrap_or(PolicyDecision::Allow)
    }
}

impl PolicyEvaluator for MaliciousDomainPolicyEvaluator {
    fn evaluate(&self, _client_ip: IpAddr, question: &QuestionKey) -> PolicyDecision {
        let Ok(domain) = DomainName::parse(&question.qname) else {
            return PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::InvalidDomain,
                rule_id: None,
            });
        };
        self.evaluate_domain(&domain)
    }

    fn evaluate_response_name(&self, _client_ip: IpAddr, domain: &DomainName) -> PolicyDecision {
        self.evaluate_domain(domain)
    }
}

pub struct PolicyChain {
    evaluators: Vec<Box<dyn PolicyEvaluator>>,
}

impl PolicyChain {
    pub fn new(evaluators: Vec<Box<dyn PolicyEvaluator>>) -> Self {
        Self { evaluators }
    }
}

impl PolicyEvaluator for PolicyChain {
    fn evaluate(&self, client_ip: IpAddr, question: &QuestionKey) -> PolicyDecision {
        self.evaluators
            .iter()
            .map(|evaluator| evaluator.evaluate(client_ip, question))
            .find(|decision| matches!(decision, PolicyDecision::Block(_)))
            .unwrap_or(PolicyDecision::Allow)
    }

    fn evaluate_response_name(&self, client_ip: IpAddr, domain: &DomainName) -> PolicyDecision {
        self.evaluators
            .iter()
            .map(|evaluator| evaluator.evaluate_response_name(client_ip, domain))
            .find(|decision| matches!(decision, PolicyDecision::Block(_)))
            .unwrap_or(PolicyDecision::Allow)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopPolicyEvaluator;

impl PolicyEvaluator for NoopPolicyEvaluator {
    fn evaluate(&self, _client_ip: IpAddr, _question: &QuestionKey) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, CidrPrefixError> {
        let max_prefix_len = ip_bit_len(network);
        if prefix_len > max_prefix_len {
            return Err(CidrPrefixError {
                prefix_len,
                max_prefix_len,
            });
        }

        Ok(Self {
            network: mask_ip(network, prefix_len),
            prefix_len,
        })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        if !same_ip_family(self.network, ip) {
            return false;
        }
        mask_ip(ip, self.prefix_len) == self.network
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrPrefixError {
    pub prefix_len: u8,
    pub max_prefix_len: u8,
}

fn same_ip_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn ip_bit_len(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn mask_ip(ip: IpAddr, prefix_len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(mask_ipv4(ip, prefix_len)),
        IpAddr::V6(ip) => IpAddr::V6(mask_ipv6(ip, prefix_len)),
    }
}

fn mask_ipv4(ip: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let raw = u32::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(raw & mask)
}

fn mask_ipv6(ip: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let raw = u128::from(ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Ipv6Addr::from(raw & mask)
}

fn validate_normalized_domain(domain: &str) -> Result<(), DomainNameError> {
    if domain.is_empty() {
        return Ok(());
    }

    if domain.len() > 253 {
        return Err(DomainNameError::NameTooLong { len: domain.len() });
    }

    for label in domain.split('.') {
        validate_label(label)?;
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), DomainNameError> {
    if label.is_empty() {
        return Err(DomainNameError::EmptyLabel);
    }

    if label.len() > 63 {
        return Err(DomainNameError::LabelTooLong {
            label: label.to_string(),
            len: label.len(),
        });
    }

    for ch in label.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
            return Err(DomainNameError::InvalidLabelCharacter {
                label: label.to_string(),
                ch,
            });
        }
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(DomainNameError::InvalidLabelHyphen {
            label: label.to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_name_normalizes_case_and_one_trailing_root() {
        let domain = DomainName::parse("ExAmPlE.CoM.").unwrap();

        assert_eq!(domain.as_str(), "example.com");
        assert_eq!(domain.to_string(), "example.com");
    }

    #[test]
    fn domain_name_keeps_ascii_punycode_lowercase() {
        let domain = DomainName::parse("XN--EXAMPLE-9D0B.COM").unwrap();

        assert_eq!(domain.as_str(), "xn--example-9d0b.com");
    }

    #[test]
    fn domain_name_allows_root_name() {
        let domain = DomainName::parse(".").unwrap();

        assert!(domain.is_root());
        assert_eq!(domain.to_string(), ".");
    }

    #[test]
    fn domain_name_rejects_empty_non_root_labels() {
        assert_eq!(
            DomainName::parse("example..com"),
            Err(DomainNameError::EmptyLabel)
        );
        assert_eq!(
            DomainName::parse("example.com.."),
            Err(DomainNameError::EmptyLabel)
        );
    }

    #[test]
    fn domain_name_converts_idn_to_ascii_punycode() {
        let domain = DomainName::parse("exämple.com").unwrap();

        assert_eq!(domain.as_str(), "xn--exmple-cua.com");
    }

    #[test]
    fn domain_name_allows_underscore_service_labels() {
        let domain = DomainName::parse("_acme-challenge.Example.COM").unwrap();

        assert_eq!(domain.as_str(), "_acme-challenge.example.com");
    }

    #[test]
    fn domain_name_rejects_invalid_label_lengths_and_characters() {
        let long_label = format!("{}.com", "a".repeat(64));
        assert_eq!(
            DomainName::parse(&long_label),
            Err(DomainNameError::LabelTooLong {
                label: "a".repeat(64),
                len: 64,
            })
        );
        assert_eq!(
            DomainName::parse("bad!label.example"),
            Err(DomainNameError::InvalidLabelCharacter {
                label: "bad!label".to_string(),
                ch: '!',
            })
        );
        assert_eq!(
            DomainName::parse("-bad.example"),
            Err(DomainNameError::InvalidLabelHyphen {
                label: "-bad".to_string(),
            })
        );
    }

    #[test]
    fn domain_name_rejects_names_over_wire_limit() {
        let name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(name.len(), 253);
        assert!(DomainName::parse(&name).is_ok());

        let too_long = format!("{name}.e");
        assert_eq!(
            DomainName::parse(&too_long),
            Err(DomainNameError::NameTooLong {
                len: too_long.len(),
            })
        );
    }

    #[test]
    fn exact_selector_matches_only_same_domain() {
        let selector = DomainSelector::exact("Example.COM.").unwrap();

        assert!(selector.matches(&DomainName::parse("example.com").unwrap()));
        assert!(!selector.matches(&DomainName::parse("www.example.com").unwrap()));
        assert!(!selector.matches(&DomainName::parse("badexample.com").unwrap()));
    }

    #[test]
    fn subtree_selector_matches_base_and_descendants_not_suffix_siblings() {
        let selector = DomainSelector::subtree("example.com").unwrap();

        assert!(selector.matches(&DomainName::parse("example.com").unwrap()));
        assert!(selector.matches(&DomainName::parse("www.example.com").unwrap()));
        assert!(selector.matches(&DomainName::parse("deep.www.example.com").unwrap()));
        assert!(!selector.matches(&DomainName::parse("badexample.com").unwrap()));
        assert!(!selector.matches(&DomainName::parse("example.com.evil").unwrap()));
    }

    #[test]
    fn client_identity_starts_with_source_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let identity = ClientIdentity::ip(ip);

        assert_eq!(identity.source_ip(), ip);
        assert_eq!(ClientIdentity::from(ip), identity);
    }

    #[test]
    fn exact_ip_selector_matches_only_same_address() {
        let selector = ClientSelector::exact_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));

        assert!(
            selector.matches(&ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 10
            ))))
        );
        assert!(
            !selector.matches(&ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 11
            ))))
        );
        assert!(!selector.matches(&ClientIdentity::ip(IpAddr::V6(Ipv6Addr::LOCALHOST))));
    }

    #[test]
    fn cidr_selector_matches_ipv4_network_boundaries() {
        let selector = ClientSelector::cidr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), 24).unwrap();

        assert_eq!(
            match &selector {
                ClientSelector::Cidr(cidr) => cidr.network(),
                ClientSelector::ExactIp(_) => unreachable!(),
            },
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0))
        );
        assert!(selector.matches(&ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))));
        assert!(
            selector.matches(&ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 255
            ))))
        );
        assert!(!selector.matches(&ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1)))));
    }

    #[test]
    fn cidr_selector_matches_ipv6_network_boundaries() {
        let selector = ClientSelector::cidr(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
            48,
        )
        .unwrap();

        assert!(
            selector.matches(&ClientIdentity::ip(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 1, 0xffff, 0, 0, 0, 1,
            ))))
        );
        assert!(
            !selector.matches(&ClientIdentity::ip(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 2, 0, 0, 0, 0, 1,
            ))))
        );
        assert!(!selector.matches(&ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))));
    }

    #[test]
    fn cidr_prefix_validation_rejects_out_of_range_lengths() {
        assert_eq!(
            IpCidr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 33),
            Err(CidrPrefixError {
                prefix_len: 33,
                max_prefix_len: 32,
            })
        );
        assert_eq!(
            IpCidr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129),
            Err(CidrPrefixError {
                prefix_len: 129,
                max_prefix_len: 128,
            })
        );
    }

    #[test]
    fn zero_length_cidr_prefix_matches_family_only() {
        let ipv4_selector = ClientSelector::cidr(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let ipv6_selector = ClientSelector::cidr(IpAddr::V6(Ipv6Addr::LOCALHOST), 0).unwrap();

        assert!(
            ipv4_selector.matches(&ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(
                203, 0, 113, 1
            ))))
        );
        assert!(!ipv4_selector.matches(&ClientIdentity::ip(IpAddr::V6(Ipv6Addr::LOCALHOST))));
        assert!(
            ipv6_selector.matches(&ClientIdentity::ip(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
            ))))
        );
    }

    #[test]
    fn local_deny_rule_requires_enabled_client_and_domain_match() {
        let rule = LocalDenyRule::new(
            "rule-1",
            ClientSelector::cidr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap(),
            DomainSelector::subtree("blocked.example").unwrap(),
            true,
        );
        let client = ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)));

        assert!(rule.matches(&client, &DomainName::parse("host.blocked.example").unwrap()));
        assert!(!rule.matches(
            &ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            &DomainName::parse("host.blocked.example").unwrap()
        ));
        assert!(!rule.matches(&client, &DomainName::parse("allowed.example").unwrap()));

        let disabled = LocalDenyRule::new(
            "rule-2",
            ClientSelector::exact_ip(client.source_ip()),
            DomainSelector::exact("blocked.example").unwrap(),
            false,
        );
        assert!(!disabled.matches(&client, &DomainName::parse("blocked.example").unwrap()));
    }

    #[test]
    fn local_policy_evaluator_returns_first_matching_rule_identifier() {
        let evaluator = LocalPolicyEvaluator::new(vec![
            LocalDenyRule::new(
                "disabled-first",
                ClientSelector::cidr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap(),
                DomainSelector::subtree("blocked.example").unwrap(),
                false,
            ),
            LocalDenyRule::new(
                "match-first",
                ClientSelector::cidr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap(),
                DomainSelector::subtree("blocked.example").unwrap(),
                true,
            ),
            LocalDenyRule::new(
                "match-second",
                ClientSelector::exact_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))),
                DomainSelector::exact("host.blocked.example").unwrap(),
                true,
            ),
        ]);

        assert_eq!(
            evaluator.evaluate_identity(
                &ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))),
                &DomainName::parse("host.blocked.example").unwrap(),
            ),
            PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::LocalRule,
                rule_id: Some("match-first".to_string()),
            })
        );
    }

    #[test]
    fn local_policy_evaluator_allows_when_no_rule_matches() {
        let evaluator = LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
            "rule-1",
            ClientSelector::exact_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))),
            DomainSelector::exact("blocked.example").unwrap(),
            true,
        )]);

        assert_eq!(
            evaluator.evaluate_identity(
                &ClientIdentity::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))),
                &DomainName::parse("allowed.example").unwrap(),
            ),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn local_policy_evaluator_implements_existing_policy_port() {
        let evaluator = LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
            "rule-1",
            ClientSelector::exact_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))),
            DomainSelector::exact("blocked.example").unwrap(),
            true,
        )]);

        assert_eq!(
            evaluator.evaluate(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
                &QuestionKey::new("Blocked.Example.", 1, 1),
            ),
            PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::LocalRule,
                rule_id: Some("rule-1".to_string()),
            })
        );
    }

    #[test]
    fn local_policy_evaluator_reports_invalid_domain() {
        let evaluator = LocalPolicyEvaluator::default();

        assert_eq!(
            evaluator.evaluate(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
                &QuestionKey::new("bad!label.example", 1, 1),
            ),
            PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::InvalidDomain,
                rule_id: None,
            })
        );
    }

    #[test]
    fn malicious_domain_policy_blocks_request_and_response_names() {
        let evaluator = MaliciousDomainPolicyEvaluator::new(vec![
            MaliciousDomainRule::new(
                "disabled",
                DomainSelector::subtree("disabled.example").unwrap(),
                false,
            ),
            MaliciousDomainRule::new(
                "malware-feed",
                DomainSelector::subtree("malicious.example").unwrap(),
                true,
            ),
        ]);

        assert_eq!(
            evaluator.evaluate(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
                &QuestionKey::new("Host.Malicious.Example.", 1, 1),
            ),
            PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("malware-feed".to_string()),
            })
        );
        assert_eq!(
            evaluator.evaluate_response_name(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
                &DomainName::parse("alias.malicious.example").unwrap(),
            ),
            PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("malware-feed".to_string()),
            })
        );
        assert_eq!(
            evaluator.evaluate(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
                &QuestionKey::new("host.disabled.example", 1, 1),
            ),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn policy_chain_keeps_local_rule_precedence_and_uses_response_aware_rules() {
        let chain = PolicyChain::new(vec![
            Box::new(LocalPolicyEvaluator::new(vec![LocalDenyRule::new(
                "local-rule",
                ClientSelector::exact_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))),
                DomainSelector::exact("blocked.example").unwrap(),
                true,
            )])),
            Box::new(MaliciousDomainPolicyEvaluator::new(vec![
                MaliciousDomainRule::new(
                    "malware-feed",
                    DomainSelector::subtree("blocked.example").unwrap(),
                    true,
                ),
            ])),
        ]);

        assert_eq!(
            chain.evaluate(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
                &QuestionKey::new("blocked.example", 1, 1),
            ),
            PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::LocalRule,
                rule_id: Some("local-rule".to_string()),
            })
        );
        assert_eq!(
            chain.evaluate_response_name(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55)),
                &DomainName::parse("blocked.example").unwrap(),
            ),
            PolicyDecision::Block(PolicyBlock {
                reason: BlockReason::MaliciousDomain,
                rule_id: Some("malware-feed".to_string()),
            })
        );
    }
}
