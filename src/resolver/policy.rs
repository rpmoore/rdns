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
use std::str::FromStr;

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
        if !ch.is_ascii_alphanumeric() && ch != '-' {
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
            DomainName::parse("bad_label.example"),
            Err(DomainNameError::InvalidLabelCharacter {
                label: "bad_label".to_string(),
                ch: '_',
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
}
