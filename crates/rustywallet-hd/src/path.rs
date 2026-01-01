//! BIP32 derivation path parsing and manipulation.

use crate::error::HdError;
use std::fmt;
use std::str::FromStr;

/// Hardened derivation threshold (2^31).
pub const HARDENED_BIT: u32 = 0x80000000;

/// A single component in a derivation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildNumber {
    /// Normal (non-hardened) derivation.
    Normal(u32),
    /// Hardened derivation.
    Hardened(u32),
}

impl ChildNumber {
    /// Create a normal child number.
    pub fn normal(index: u32) -> Result<Self, HdError> {
        if index >= HARDENED_BIT {
            return Err(HdError::InvalidChildNumber(index));
        }
        Ok(ChildNumber::Normal(index))
    }

    /// Create a hardened child number.
    pub fn hardened(index: u32) -> Result<Self, HdError> {
        if index >= HARDENED_BIT {
            return Err(HdError::InvalidChildNumber(index));
        }
        Ok(ChildNumber::Hardened(index))
    }

    /// Check if this is a hardened derivation.
    pub fn is_hardened(&self) -> bool {
        matches!(self, ChildNumber::Hardened(_))
    }

    /// Get the index value (without hardened bit).
    pub fn index(&self) -> u32 {
        match self {
            ChildNumber::Normal(i) | ChildNumber::Hardened(i) => *i,
        }
    }

    /// Get the raw value for derivation (with hardened bit if applicable).
    pub fn raw_index(&self) -> u32 {
        match self {
            ChildNumber::Normal(i) => *i,
            ChildNumber::Hardened(i) => i | HARDENED_BIT,
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChildNumber::Normal(i) => write!(f, "{}", i),
            ChildNumber::Hardened(i) => write!(f, "{}'", i),
        }
    }
}

/// BIP32 derivation path.
///
/// # Example
///
/// ```
/// use rustywallet_hd::DerivationPath;
///
/// // Parse a BIP44 Bitcoin path
/// let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
/// assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
///
/// // Use helper for BIP44 Bitcoin
/// let btc_path = DerivationPath::bip44_bitcoin(0, 0, 0);
/// assert_eq!(btc_path.to_string(), "m/44'/0'/0'/0/0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    components: Vec<ChildNumber>,
}

impl DerivationPath {
    /// Create an empty path (master key).
    pub fn master() -> Self {
        Self { components: vec![] }
    }

    /// Parse a derivation path from string.
    ///
    /// Supports both `'` and `h` notation for hardened derivation.
    pub fn parse(path: &str) -> Result<Self, HdError> {
        let path = path.trim();

        // Handle empty or just "m"
        if path.is_empty() || path == "m" || path == "M" {
            return Ok(Self::master());
        }

        // Must start with m/ or M/
        let path = if path.starts_with("m/") || path.starts_with("M/") {
            &path[2..]
        } else {
            return Err(HdError::InvalidPath(
                "Path must start with 'm/'".to_string(),
            ));
        };

        let mut components = Vec::new();

        for part in path.split('/') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (index_str, hardened) = if part.ends_with('\'') || part.ends_with('h') || part.ends_with('H') {
                (&part[..part.len() - 1], true)
            } else {
                (part, false)
            };

            let index: u32 = index_str.parse().map_err(|_| {
                HdError::InvalidPath(format!("Invalid index: {}", index_str))
            })?;

            if index >= HARDENED_BIT {
                return Err(HdError::InvalidPath(format!(
                    "Index too large: {}",
                    index
                )));
            }

            let child = if hardened {
                ChildNumber::Hardened(index)
            } else {
                ChildNumber::Normal(index)
            };

            components.push(child);
        }

        Ok(Self { components })
    }

    /// Create BIP44 path for Bitcoin: m/44'/0'/account'/change/index
    pub fn bip44_bitcoin(account: u32, change: u32, index: u32) -> Self {
        Self {
            components: vec![
                ChildNumber::Hardened(44),
                ChildNumber::Hardened(0), // Bitcoin coin type
                ChildNumber::Hardened(account),
                ChildNumber::Normal(change),
                ChildNumber::Normal(index),
            ],
        }
    }

    /// Create BIP44 path for Ethereum: m/44'/60'/account'/0/index
    pub fn bip44_ethereum(account: u32, index: u32) -> Self {
        Self {
            components: vec![
                ChildNumber::Hardened(44),
                ChildNumber::Hardened(60), // Ethereum coin type
                ChildNumber::Hardened(account),
                ChildNumber::Normal(0),
                ChildNumber::Normal(index),
            ],
        }
    }

    /// Get path components.
    pub fn components(&self) -> &[ChildNumber] {
        &self.components
    }

    /// Check if path contains any hardened derivation.
    pub fn has_hardened(&self) -> bool {
        self.components.iter().any(|c| c.is_hardened())
    }

    /// Get the depth (number of components).
    pub fn depth(&self) -> u8 {
        self.components.len() as u8
    }

    /// Append a child number to the path.
    pub fn child(&self, child: ChildNumber) -> Self {
        let mut components = self.components.clone();
        components.push(child);
        Self { components }
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;
        for component in &self.components {
            write!(f, "/{}", component)?;
        }
        Ok(())
    }
}

impl FromStr for DerivationPath {
    type Err = HdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_master() {
        let path = DerivationPath::parse("m").unwrap();
        assert!(path.components().is_empty());
    }

    #[test]
    fn test_parse_bip44() {
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.components().len(), 5);
        assert!(path.components()[0].is_hardened());
        assert!(path.components()[1].is_hardened());
        assert!(path.components()[2].is_hardened());
        assert!(!path.components()[3].is_hardened());
        assert!(!path.components()[4].is_hardened());
    }

    #[test]
    fn test_parse_h_notation() {
        let path = DerivationPath::parse("m/44h/0h/0h/0/0").unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_bip44_bitcoin() {
        let path = DerivationPath::bip44_bitcoin(0, 0, 0);
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_bip44_ethereum() {
        let path = DerivationPath::bip44_ethereum(0, 0);
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_roundtrip() {
        let original = "m/44'/0'/0'/0/0";
        let path = DerivationPath::parse(original).unwrap();
        assert_eq!(path.to_string(), original);
    }

    #[test]
    fn test_has_hardened() {
        let path1 = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        assert!(path1.has_hardened());

        let path2 = DerivationPath::parse("m/0/1/2").unwrap();
        assert!(!path2.has_hardened());
    }
}
