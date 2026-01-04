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
//! - **Parallel Scanning**: High-performance parallel scanning with multiple backends
//! - **Descriptor Support**: Scan using output descriptors including tr()
//! - **Connection Pooling**: Efficient backend connection management
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
//! ## Parallel Scanning
//!
//! For high-performance recovery with multiple backends:
//!
//! ```ignore
//! use rustywallet_recovery::{ParallelRecoveryScanner, ParallelScanConfig, ElectrumBackend};
//! use rustywallet_descriptor::Descriptor;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create multiple backends for parallel queries
//!     let backend1 = Arc::new(ElectrumBackend::mainnet().await?);
//!     let backend2 = Arc::new(ElectrumBackend::new("electrum2.example.com").await?);
//!     let backends = vec![backend1, backend2];
//!
//!     // Configure parallel scan
//!     let config = ParallelScanConfig::new()
//!         .with_thread_count(4)
//!         .with_gap_limit(20);
//!
//!     // Create scanner from mnemonic
//!     let scanner = ParallelRecoveryScanner::from_mnemonic(
//!         "abandon abandon abandon...",
//!         None,
//!         backends,
//!         config
//!     )?;
//!
//!     // Parse descriptors to scan
//!     let descriptors = vec![
//!         Descriptor::parse("wpkh(xpub.../0/*)")?,
//!         Descriptor::parse("tr(xpub.../0/*)")?,
//!     ];
//!
//!     // Run parallel scan with progress callback
//!     let result = scanner.scan_parallel(&descriptors, |progress| {
//!         println!("Scanned: {}, Found: {}", progress.total_scanned, progress.found_count);
//!     }).await?;
//!
//!     println!("Total balance: {} sats", result.total_balance);
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
pub mod parallel;
pub mod result;
pub mod scanner;

// Re-exports
pub use backend::{AddressBalance, Backend, ElectrumBackend};
pub use config::{RecoveryConfig, ScanPath};
pub use error::RecoveryError;
pub use parallel::{ParallelRecoveryScanner, ParallelScanConfig, ParallelScanProgress, PooledBackend};
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
