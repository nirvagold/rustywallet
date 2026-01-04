//! BIP32 derivation path parsing and manipulation.
//!
//! This module provides:
//! - `DerivationPath` for representing BIP32 derivation paths
//! - `DerivationPathBuilder` for fluent path construction
//! - `ChildNumber` for individual path components
//!
//! ## Example
//!
//! ```
//! use rustywallet_hd::path::{DerivationPath, DerivationPathBuilder};
//!
//! // Using the fluent builder
//! let path = DerivationPathBuilder::new()
//!     .hardened(44)
//!     .hardened(0)
//!     .hardened(0)
//!     .normal(0)
//!     .normal(0)
//!     .build()
//!     .unwrap();
//!
//! assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
//!
//! // Using BIP presets
//! let bip84_path = DerivationPathBuilder::bip84(0, 0)
//!     .normal(0)  // change
//!     .normal(0)  // index
//!     .build()
//!     .unwrap();
//!
//! assert_eq!(bip84_path.to_string(), "m/84'/0'/0'/0/0");
//! ```

use crate::error::HdError;
use std::fmt;
use std::str::FromStr;

/// Hardened derivation threshold (2^31).
pub const HARDENED_BIT: u32 = 0x80000000;

/// Maximum valid index for derivation (2^31 - 1).
pub const MAX_CHILD_INDEX: u32 = HARDENED_BIT - 1;

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

    /// Create a new builder for constructing derivation paths.
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::DerivationPath;
    ///
    /// let path = DerivationPath::builder()
    ///     .hardened(44)
    ///     .hardened(0)
    ///     .hardened(0)
    ///     .normal(0)
    ///     .normal(0)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    /// ```
    pub fn builder() -> DerivationPathBuilder {
        DerivationPathBuilder::new()
    }

    /// Create a path from a vector of child numbers.
    pub fn from_components(components: Vec<ChildNumber>) -> Self {
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

/// Fluent builder for constructing derivation paths.
///
/// Provides a convenient way to build derivation paths with method chaining,
/// including presets for common BIP standards (BIP44, BIP49, BIP84, BIP86).
///
/// # Example
///
/// ```
/// use rustywallet_hd::path::DerivationPathBuilder;
///
/// // Build a custom path
/// let path = DerivationPathBuilder::new()
///     .hardened(44)
///     .hardened(0)
///     .hardened(0)
///     .normal(0)
///     .normal(5)
///     .build()
///     .unwrap();
///
/// assert_eq!(path.to_string(), "m/44'/0'/0'/0/5");
///
/// // Use BIP84 preset for native SegWit
/// let bip84 = DerivationPathBuilder::bip84(0, 0)
///     .normal(0)
///     .normal(0)
///     .build()
///     .unwrap();
///
/// assert_eq!(bip84.to_string(), "m/84'/0'/0'/0/0");
/// ```
#[derive(Debug, Clone, Default)]
pub struct DerivationPathBuilder {
    components: Vec<ChildNumber>,
    /// Track if any validation error occurred during building
    error: Option<HdError>,
}

impl DerivationPathBuilder {
    /// Create a new empty builder (starts at master).
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            error: None,
        }
    }

    /// Add a hardened component to the path.
    ///
    /// # Arguments
    /// * `index` - The index value (must be < 2^31)
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::path::DerivationPathBuilder;
    ///
    /// let path = DerivationPathBuilder::new()
    ///     .hardened(44)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(path.to_string(), "m/44'");
    /// ```
    pub fn hardened(mut self, index: u32) -> Self {
        if self.error.is_some() {
            return self;
        }

        if index > MAX_CHILD_INDEX {
            self.error = Some(HdError::InvalidChildNumber(index));
            return self;
        }

        self.components.push(ChildNumber::Hardened(index));
        self
    }

    /// Add a normal (non-hardened) component to the path.
    ///
    /// # Arguments
    /// * `index` - The index value (must be < 2^31)
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::path::DerivationPathBuilder;
    ///
    /// let path = DerivationPathBuilder::new()
    ///     .normal(0)
    ///     .normal(5)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(path.to_string(), "m/0/5");
    /// ```
    pub fn normal(mut self, index: u32) -> Self {
        if self.error.is_some() {
            return self;
        }

        if index > MAX_CHILD_INDEX {
            self.error = Some(HdError::InvalidChildNumber(index));
            return self;
        }

        self.components.push(ChildNumber::Normal(index));
        self
    }

    /// Add a child number component to the path.
    ///
    /// # Arguments
    /// * `child` - The child number to add
    pub fn child(mut self, child: ChildNumber) -> Self {
        if self.error.is_some() {
            return self;
        }

        self.components.push(child);
        self
    }

    /// Build the derivation path.
    ///
    /// Returns an error if any component had an invalid index.
    pub fn build(self) -> Result<DerivationPath, HdError> {
        if let Some(err) = self.error {
            return Err(err);
        }

        Ok(DerivationPath {
            components: self.components,
        })
    }

    // ========== BIP Presets ==========

    /// Create a BIP44 preset: m/44'/coin_type'/account'
    ///
    /// BIP44 is the standard for multi-account hierarchy for deterministic wallets.
    /// Full path: m/44'/coin_type'/account'/change/address_index
    ///
    /// # Arguments
    /// * `coin_type` - Coin type (0 for Bitcoin, 60 for Ethereum, etc.)
    /// * `account` - Account index
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::path::DerivationPathBuilder;
    ///
    /// // Bitcoin BIP44 path
    /// let path = DerivationPathBuilder::bip44(0, 0)
    ///     .normal(0)  // external chain
    ///     .normal(0)  // first address
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    /// ```
    pub fn bip44(coin_type: u32, account: u32) -> Self {
        Self::new()
            .hardened(44)
            .hardened(coin_type)
            .hardened(account)
    }

    /// Create a BIP49 preset: m/49'/coin_type'/account'
    ///
    /// BIP49 is for P2WPKH-nested-in-P2SH (SegWit wrapped in legacy).
    /// Full path: m/49'/coin_type'/account'/change/address_index
    ///
    /// # Arguments
    /// * `coin_type` - Coin type (0 for Bitcoin)
    /// * `account` - Account index
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::path::DerivationPathBuilder;
    ///
    /// let path = DerivationPathBuilder::bip49(0, 0)
    ///     .normal(0)
    ///     .normal(0)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(path.to_string(), "m/49'/0'/0'/0/0");
    /// ```
    pub fn bip49(coin_type: u32, account: u32) -> Self {
        Self::new()
            .hardened(49)
            .hardened(coin_type)
            .hardened(account)
    }

    /// Create a BIP84 preset: m/84'/coin_type'/account'
    ///
    /// BIP84 is for native SegWit (P2WPKH) addresses (bc1q...).
    /// Full path: m/84'/coin_type'/account'/change/address_index
    ///
    /// # Arguments
    /// * `coin_type` - Coin type (0 for Bitcoin)
    /// * `account` - Account index
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::path::DerivationPathBuilder;
    ///
    /// let path = DerivationPathBuilder::bip84(0, 0)
    ///     .normal(0)
    ///     .normal(0)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(path.to_string(), "m/84'/0'/0'/0/0");
    /// ```
    pub fn bip84(coin_type: u32, account: u32) -> Self {
        Self::new()
            .hardened(84)
            .hardened(coin_type)
            .hardened(account)
    }

    /// Create a BIP86 preset: m/86'/coin_type'/account'
    ///
    /// BIP86 is for Taproot (P2TR) addresses (bc1p...).
    /// Full path: m/86'/coin_type'/account'/change/address_index
    ///
    /// # Arguments
    /// * `coin_type` - Coin type (0 for Bitcoin)
    /// * `account` - Account index
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::path::DerivationPathBuilder;
    ///
    /// let path = DerivationPathBuilder::bip86(0, 0)
    ///     .normal(0)
    ///     .normal(0)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(path.to_string(), "m/86'/0'/0'/0/0");
    /// ```
    pub fn bip86(coin_type: u32, account: u32) -> Self {
        Self::new()
            .hardened(86)
            .hardened(coin_type)
            .hardened(account)
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

    // ========== DerivationPathBuilder Tests ==========

    #[test]
    fn test_builder_empty() {
        let path = DerivationPathBuilder::new().build().unwrap();
        assert_eq!(path.to_string(), "m");
        assert!(path.components().is_empty());
    }

    #[test]
    fn test_builder_hardened() {
        let path = DerivationPathBuilder::new()
            .hardened(44)
            .hardened(0)
            .hardened(0)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'");
    }

    #[test]
    fn test_builder_normal() {
        let path = DerivationPathBuilder::new()
            .normal(0)
            .normal(5)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/0/5");
    }

    #[test]
    fn test_builder_mixed() {
        let path = DerivationPathBuilder::new()
            .hardened(44)
            .hardened(0)
            .hardened(0)
            .normal(0)
            .normal(0)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_builder_bip44_preset() {
        let path = DerivationPathBuilder::bip44(0, 0)
            .normal(0)
            .normal(0)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_builder_bip49_preset() {
        let path = DerivationPathBuilder::bip49(0, 0)
            .normal(0)
            .normal(0)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/49'/0'/0'/0/0");
    }

    #[test]
    fn test_builder_bip84_preset() {
        let path = DerivationPathBuilder::bip84(0, 0)
            .normal(0)
            .normal(0)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_builder_bip86_preset() {
        let path = DerivationPathBuilder::bip86(0, 0)
            .normal(0)
            .normal(0)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/86'/0'/0'/0/0");
    }

    #[test]
    fn test_builder_invalid_index() {
        let result = DerivationPathBuilder::new()
            .hardened(HARDENED_BIT)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_max_valid_index() {
        let path = DerivationPathBuilder::new()
            .hardened(MAX_CHILD_INDEX)
            .normal(MAX_CHILD_INDEX)
            .build()
            .unwrap();
        assert_eq!(path.components().len(), 2);
    }

    #[test]
    fn test_derivation_path_builder_method() {
        let path = DerivationPath::builder()
            .hardened(44)
            .hardened(0)
            .hardened(0)
            .normal(0)
            .normal(0)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_builder_ethereum_path() {
        // Ethereum uses BIP44 with coin type 60
        let path = DerivationPathBuilder::bip44(60, 0)
            .normal(0)
            .normal(0)
            .build()
            .unwrap();
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
    }
}
