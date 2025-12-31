//! # rustywallet-checker
//!
//! Cryptocurrency balance checker for Bitcoin and Ethereum addresses.
//!
//! This crate provides async functions to check address balances using
//! public blockchain APIs.
//!
//! ## Features
//!
//! - Check Bitcoin address balances (legacy, segwit, taproot)
//! - Check Ethereum address balances
//! - Multiple API provider fallbacks
//! - Async/await support with tokio
//!
//! ## Quick Start
//!
//! ```no_run
//! use rustywallet_checker::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), CheckerError> {
//!     // Check Bitcoin balance
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
//! ## API Providers
//!
//! ### Bitcoin
//! - Primary: blockstream.info (supports all address types)
//! - Fallback: blockchain.info (legacy addresses only)
//!
//! ### Ethereum
//! - Multiple public RPC endpoints with automatic fallback

pub mod bitcoin;
pub mod error;
pub mod ethereum;
pub mod prelude;

// Re-export main types at crate root
pub use bitcoin::{check_btc_balance, BitcoinBalance};
pub use error::CheckerError;
pub use ethereum::{check_eth_balance, EthereumBalance};
