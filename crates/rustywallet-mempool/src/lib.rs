//! # rustywallet-mempool
//!
//! Mempool.space API client for fee estimation, address info, and transaction tracking.
//!
//! ## Features
//!
//! - **Fee estimation** - Get recommended fee rates for different confirmation targets
//! - **Address info** - Get balance, transaction count, and UTXOs
//! - **Transaction tracking** - Get transaction details and confirmation status
//! - **Broadcasting** - Broadcast signed transactions to the network
//! - **Block info** - Get current block height and block details
//!
//! ## Quick Start
//!
//! ```no_run
//! use rustywallet_mempool::MempoolClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = MempoolClient::new();
//!     
//!     // Get fee estimates
//!     let fees = client.get_fees().await?;
//!     println!("Next block: {} sat/vB", fees.fastest_fee);
//!     println!("1 hour: {} sat/vB", fees.hour_fee);
//!     println!("Economy: {} sat/vB", fees.economy_fee);
//!     
//!     // Get address balance
//!     let info = client.get_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
//!     println!("Balance: {} sats", info.confirmed_balance());
//!     println!("Transactions: {}", info.tx_count());
//!     
//!     // Get UTXOs
//!     let utxos = client.get_utxos("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
//!     println!("UTXOs: {}", utxos.len());
//!     
//!     // Get current block height
//!     let height = client.get_block_height().await?;
//!     println!("Block height: {}", height);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Networks
//!
//! ```no_run
//! use rustywallet_mempool::MempoolClient;
//!
//! // Mainnet (default)
//! let mainnet = MempoolClient::new();
//!
//! // Testnet
//! let testnet = MempoolClient::testnet();
//!
//! // Signet
//! let signet = MempoolClient::signet();
//!
//! // Custom endpoint
//! let custom = MempoolClient::with_base_url("https://my-mempool.example.com/api");
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod client;
pub mod error;
pub mod types;

// Re-exports
pub use client::{MempoolClient, MAINNET_URL, SIGNET_URL, TESTNET_URL};
pub use error::{MempoolError, Result};
pub use types::{AddressInfo, BlockInfo, ChainStats, FeeEstimates, MempoolStats, Transaction, TxStatus, Utxo, UtxoStatus};
