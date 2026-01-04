//! # rustywallet-checker
//!
//! Cryptocurrency balance checker for Bitcoin and Ethereum addresses.
//!
//! This crate provides async functions to check address balances using
//! public blockchain APIs and Electrum protocol.
//!
//! ## Features
//!
//! - Check Bitcoin address balances (legacy, segwit, taproot)
//! - Check Ethereum address balances
//! - Electrum protocol backend (no rate limits)
//! - Batch balance checking for multiple addresses
//! - Multiple API provider fallbacks
//! - Connection caching for efficiency
//! - Async/await support with tokio
//!
//! ## Quick Start
//!
//! ```no_run
//! use rustywallet_checker::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), CheckerError> {
//!     // Check Bitcoin balance (uses API providers)
//!     let btc = check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
//!     println!("BTC Balance: {} satoshis", btc.balance);
//!
//!     // Check Ethereum balance
//!     let eth = check_eth_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").await?;
//!     println!("ETH Balance: {} ETH", eth.balance_eth);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Electrum Backend
//!
//! Use Electrum protocol for direct blockchain queries without rate limits:
//!
//! ```no_run
//! use rustywallet_checker::electrum::{ElectrumChecker, ElectrumConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create checker with custom config
//!     let config = ElectrumConfig::new("electrum.blockstream.info")
//!         .with_port(50002)
//!         .with_ssl(true)
//!         .with_cache(true);
//!     
//!     let checker = ElectrumChecker::with_config(config);
//!     
//!     // Check single address
//!     let balance = checker.check_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
//!     println!("Balance: {} satoshis", balance.balance);
//!     
//!     // Batch check multiple addresses
//!     let addresses = vec![
//!         "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
//!         "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
//!     ];
//!     let balances = checker.check_balances_batch(&addresses).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## API Providers
//!
//! ### Bitcoin
//! - Primary: blockstream.info (supports all address types)
//! - Fallback: blockchain.info (legacy addresses only)
//! - Electrum: Direct protocol connection (no rate limits)
//!
//! ### Ethereum
//! - Multiple public RPC endpoints with automatic fallback

pub mod bitcoin;
pub mod electrum;
pub mod error;
pub mod ethereum;
pub mod prelude;

// Re-export main types at crate root
pub use bitcoin::{check_btc_balance, BitcoinBalance};
pub use electrum::{
    check_btc_balance_electrum, check_btc_balances_batch, ElectrumChecker, ElectrumConfig,
};
pub use error::CheckerError;
pub use ethereum::{check_eth_balance, EthereumBalance};
