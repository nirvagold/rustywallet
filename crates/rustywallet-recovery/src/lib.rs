//! # rustywallet-recovery
//!
//! Wallet recovery tools for Bitcoin - scan blockchain for funds from mnemonic or xpub.
//!
//! ## Features
//!
//! - **Mnemonic Recovery**: Scan all standard derivation paths from a seed phrase
//! - **Extended Key Recovery**: Scan from xpub or xprv
//! - **Multi-Path Support**: BIP44, BIP49, BIP84, BIP86 (Legacy, SegWit, Native SegWit, Taproot)
//! - **Gap Limit**: Configurable gap limit for address scanning
//! - **UTXO Discovery**: Find all unspent outputs for spending
//! - **Progress Reporting**: Callback for scan progress updates
//!
//! ## Example
//!
//! ```ignore
//! use rustywallet_recovery::{RecoveryScanner, RecoveryConfig, ElectrumBackend};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create backend
//!     let backend = ElectrumBackend::mainnet().await?;
//!
//!     // Configure scan
//!     let config = RecoveryConfig::new()
//!         .with_gap_limit(20);
//!
//!     // Create scanner from mnemonic
//!     let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//!     let scanner = RecoveryScanner::from_mnemonic(mnemonic, None, backend, config)?;
//!
//!     // Run scan
//!     let result = scanner.scan().await?;
//!
//!     println!("Total balance: {} sats", result.total_balance);
//!     println!("Addresses found: {}", result.addresses.len());
//!     println!("UTXOs found: {}", result.utxos.len());
//!     Ok(())
//! }
//! ```
//!
//! ## Quick Scan
//!
//! ```ignore
//! use rustywallet_recovery::{RecoveryScanner, RecoveryConfig, ElectrumBackend, ScanPath};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Quick scan with smaller gap limit
//!     let config = RecoveryConfig::quick()
//!         .with_scan_paths(vec![ScanPath::Bip84]); // Only native segwit
//!
//!     let backend = ElectrumBackend::mainnet().await?;
//!     let scanner = RecoveryScanner::from_mnemonic(
//!         "your mnemonic here...",
//!         None,
//!         backend,
//!         config
//!     )?;
//!
//!     let result = scanner.scan().await?;
//!     println!("{}", result.summary());
//!     Ok(())
//! }
//! ```

pub mod backend;
pub mod config;
pub mod error;
pub mod result;
pub mod scanner;

// Re-exports
pub use backend::{AddressBalance, Backend, ElectrumBackend};
pub use config::{RecoveryConfig, ScanPath};
pub use error::RecoveryError;
pub use result::{FoundAddress, FoundUtxo, RecoveryResult, ScanStats};
pub use scanner::{ProgressCallback, RecoveryScanner, ScanProgress};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = RecoveryConfig::default();
        assert_eq!(config.gap_limit, 20);
        assert_eq!(config.scan_paths.len(), 4);
    }

    #[test]
    fn test_scan_path_all() {
        let paths = ScanPath::all();
        assert_eq!(paths.len(), 4);
        assert!(paths.contains(&ScanPath::Bip44));
        assert!(paths.contains(&ScanPath::Bip84));
    }
}
