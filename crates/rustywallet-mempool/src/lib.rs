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
//! - **WebSocket support** - Real-time updates for blocks, fees, and addresses
//! - **Lightning stats** - Lightning Network capacity, nodes, and channels
//! - **Mining stats** - Pool hashrate distribution and difficulty adjustments
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
//! ## WebSocket Real-time Updates
//!
//! ```no_run
//! use rustywallet_mempool::websocket::{MempoolWsClient, WsSubscription};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let ws = MempoolWsClient::new();
//!     
//!     // Configure subscriptions
//!     let sub = WsSubscription::new()
//!         .with_blocks()
//!         .with_fees()
//!         .track_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
//!     
//!     ws.set_subscription(sub).await;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Lightning Network Stats
//!
//! ```no_run
//! use rustywallet_mempool::MempoolClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = MempoolClient::new();
//!     
//!     // Get Lightning Network statistics
//!     let stats = client.get_lightning_stats().await?;
//!     println!("Capacity: {} BTC", stats.latest.capacity_btc());
//!     println!("Channels: {}", stats.latest.channel_count);
//!     println!("Nodes: {}", stats.latest.node_count);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Mining Pool Stats
//!
//! ```no_run
//! use rustywallet_mempool::MempoolClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = MempoolClient::new();
//!     
//!     // Get hashrate distribution
//!     let dist = client.get_hashrate_distribution("1w").await?;
//!     for pool in dist.top_pools(5) {
//!         println!("{}: {:.1}%", pool.pool.name, pool.share_percent());
//!     }
//!     
//!     // Get difficulty adjustment
//!     let adj = client.get_difficulty_adjustment().await?;
//!     println!("Next adjustment: {:.2}%", adj.difficulty_change_percent());
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
pub mod lightning;
pub mod mining;
pub mod types;
pub mod websocket;

// Re-exports
pub use client::{MempoolClient, MAINNET_URL, SIGNET_URL, TESTNET_URL};
pub use error::{MempoolError, Result};
pub use types::{AddressInfo, BlockInfo, ChainStats, FeeEstimates, MempoolStats, Transaction, TxStatus, Utxo, UtxoStatus};

// v0.2 re-exports
pub use lightning::{LightningChannel, LightningNode, LightningNetworkStats, LightningStats};
pub use mining::{BlockRewardStats, DifficultyAdjustment, HashrateDistribution, MiningPoolStats, PoolBlock, PoolInfo};
pub use websocket::{
    AddressTxEvent, BlockEvent, MempoolInfoEvent, MempoolWsClient, TxConfirmedEvent,
    WsConnectionStatus, WsEvent, WsSubscription, WsSubscriptionBuilder,
    MAINNET_WS_URL, TESTNET_WS_URL, SIGNET_WS_URL,
};
