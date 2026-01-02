//! Recovery configuration
//!
//! Configuration options for wallet recovery scanning.

use serde::{Deserialize, Serialize};

/// Derivation path standard to scan
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanPath {
    /// BIP44 - Legacy P2PKH (m/44'/0'/account'/change/index)
    Bip44,
    /// BIP49 - Nested SegWit P2SH-P2WPKH (m/49'/0'/account'/change/index)
    Bip49,
    /// BIP84 - Native SegWit P2WPKH (m/84'/0'/account'/change/index)
    Bip84,
    /// BIP86 - Taproot P2TR (m/86'/0'/account'/change/index)
    Bip86,
}

impl ScanPath {
    /// Get the purpose number for this path
    pub fn purpose(&self) -> u32 {
        match self {
            ScanPath::Bip44 => 44,
            ScanPath::Bip49 => 49,
            ScanPath::Bip84 => 84,
            ScanPath::Bip86 => 86,
        }
    }

    /// Get the address type name
    pub fn address_type(&self) -> &'static str {
        match self {
            ScanPath::Bip44 => "P2PKH",
            ScanPath::Bip49 => "P2SH-P2WPKH",
            ScanPath::Bip84 => "P2WPKH",
            ScanPath::Bip86 => "P2TR",
        }
    }

    /// Get all standard scan paths
    pub fn all() -> Vec<ScanPath> {
        vec![ScanPath::Bip44, ScanPath::Bip49, ScanPath::Bip84, ScanPath::Bip86]
    }
}

/// Configuration for wallet recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Number of consecutive empty addresses before stopping (default: 20)
    pub gap_limit: u32,
    /// Number of consecutive empty accounts before stopping (default: 3)
    pub account_gap_limit: u32,
    /// Number of addresses to query in a batch (default: 10)
    pub batch_size: u32,
    /// Derivation paths to scan
    pub scan_paths: Vec<ScanPath>,
    /// Minimum confirmations for UTXOs (default: 1)
    pub min_confirmations: u32,
    /// Scan change addresses (internal chain) (default: true)
    pub scan_change: bool,
    /// Network: mainnet or testnet
    pub testnet: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            gap_limit: 20,
            account_gap_limit: 3,
            batch_size: 10,
            scan_paths: ScanPath::all(),
            min_confirmations: 1,
            scan_change: true,
            testnet: false,
        }
    }
}

impl RecoveryConfig {
    /// Create a new config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the gap limit
    pub fn with_gap_limit(mut self, limit: u32) -> Self {
        self.gap_limit = limit;
        self
    }

    /// Set the account gap limit
    pub fn with_account_gap_limit(mut self, limit: u32) -> Self {
        self.account_gap_limit = limit;
        self
    }

    /// Set the batch size
    pub fn with_batch_size(mut self, size: u32) -> Self {
        self.batch_size = size;
        self
    }

    /// Set the scan paths
    pub fn with_scan_paths(mut self, paths: Vec<ScanPath>) -> Self {
        self.scan_paths = paths;
        self
    }

    /// Set minimum confirmations
    pub fn with_min_confirmations(mut self, confirmations: u32) -> Self {
        self.min_confirmations = confirmations;
        self
    }

    /// Enable/disable change address scanning
    pub fn with_scan_change(mut self, scan: bool) -> Self {
        self.scan_change = scan;
        self
    }

    /// Set testnet mode
    pub fn with_testnet(mut self, testnet: bool) -> Self {
        self.testnet = testnet;
        self
    }

    /// Create config for quick scan (smaller gap limit)
    pub fn quick() -> Self {
        Self::default()
            .with_gap_limit(5)
            .with_account_gap_limit(1)
    }

    /// Create config for thorough scan (larger gap limit)
    pub fn thorough() -> Self {
        Self::default()
            .with_gap_limit(100)
            .with_account_gap_limit(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RecoveryConfig::default();
        assert_eq!(config.gap_limit, 20);
        assert_eq!(config.account_gap_limit, 3);
        assert_eq!(config.scan_paths.len(), 4);
    }

    #[test]
    fn test_builder_pattern() {
        let config = RecoveryConfig::new()
            .with_gap_limit(50)
            .with_testnet(true);
        
        assert_eq!(config.gap_limit, 50);
        assert!(config.testnet);
    }

    #[test]
    fn test_scan_path_purpose() {
        assert_eq!(ScanPath::Bip44.purpose(), 44);
        assert_eq!(ScanPath::Bip49.purpose(), 49);
        assert_eq!(ScanPath::Bip84.purpose(), 84);
        assert_eq!(ScanPath::Bip86.purpose(), 86);
    }
}
