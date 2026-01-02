//! # rustywallet-electrum
//!
//! Electrum protocol client for Bitcoin balance checking and UTXO fetching.
//!
//! This crate provides an async client for communicating with Electrum servers,
//! allowing you to query blockchain data without rate limits.
//!
//! ## Features
//!
//! - **Balance checking** - Get confirmed and unconfirmed balance for any address
//! - **Batch queries** - Check multiple addresses efficiently in a single request
//! - **UTXO listing** - Get unspent outputs for transaction building
//! - **Transaction operations** - Get raw transactions and broadcast signed ones
//! - **TLS support** - Secure connections to Electrum servers
//! - **Certificate pinning** - Enhanced security with SSL certificate pinning
//! - **Server discovery** - DNS-based server discovery
//! - **Connection pooling** - Efficient connection management
//! - **Real-time subscriptions** - Address and header change notifications
//!
//! ## Quick Start
//!
//! ```no_run
//! use rustywallet_electrum::{ElectrumClient, ClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to a public Electrum server
//!     let client = ElectrumClient::new("electrum.blockstream.info").await?;
//!     
//!     // Check server connection
//!     let version = client.server_version().await?;
//!     println!("Connected to: {}", version.server_software);
//!     
//!     // Get balance for an address
//!     let balance = client.get_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
//!     println!("Confirmed: {} sats", balance.confirmed);
//!     println!("Unconfirmed: {} sats", balance.unconfirmed);
//!     
//!     // Batch check multiple addresses
//!     let addresses = vec![
//!         "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
//!         "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
//!     ];
//!     let balances = client.get_balances(&addresses).await?;
//!     for (addr, bal) in addresses.iter().zip(balances.iter()) {
//!         println!("{}: {} sats", addr, bal.confirmed);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Server Discovery
//!
//! ```no_run
//! use rustywallet_electrum::discovery::ServerDiscovery;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let discovery = ServerDiscovery::new();
//!     let best = discovery.best_server().await?;
//!     println!("Best server: {} ({}ms)", best.hostname, best.latency_ms.unwrap_or(0));
//!     Ok(())
//! }
//! ```
//!
//! ## Connection Pooling
//!
//! ```no_run
//! use rustywallet_electrum::{ClientConfig, pool::{ConnectionPool, PoolConfig}};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ClientConfig::ssl("electrum.blockstream.info");
//!     let pool = ConnectionPool::new(config, PoolConfig::default());
//!     pool.initialize().await?;
//!     
//!     let client = pool.acquire().await?;
//!     let balance = client.get_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
//!     // Connection automatically returned to pool when dropped
//!     Ok(())
//! }
//! ```
//!
//! ## Address Support
//!
//! All Bitcoin address types are supported:
//! - P2PKH (1...)
//! - P2SH (3...)
//! - P2WPKH (bc1q...)
//! - P2WSH (bc1q... longer)
//! - P2TR (bc1p...)
//!
//! ## Public Servers
//!
//! Built-in list of public Electrum servers:
//! - `electrum.blockstream.info:50002` (SSL)
//! - `electrum1.bluewallet.io:443` (SSL)
//! - `bitcoin.aranguren.org:50002` (SSL)
//!
//! ## Custom Configuration
//!
//! ```no_run
//! use rustywallet_electrum::{ElectrumClient, ClientConfig};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ClientConfig::ssl("electrum.blockstream.info")
//!         .with_port(50002)
//!         .with_timeout(Duration::from_secs(60))
//!         .with_retry(5, Duration::from_secs(2));
//!     
//!     let client = ElectrumClient::with_config(config).await?;
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod batch;
pub mod client;
pub mod discovery;
pub mod error;
pub mod pinning;
pub mod pool;
pub mod scripthash;
pub mod subscription;
pub mod transport;
pub mod types;

// Re-exports
pub use client::ElectrumClient;
pub use error::{ElectrumError, Result};
pub use scripthash::{address_to_scripthash, addresses_to_scripthashes};
pub use types::{Balance, ClientConfig, ServerVersion, TxHistory, Utxo, DEFAULT_SERVERS};

// New v0.2 re-exports
pub use batch::{BatchRequest, BatchResponse, GapLimitScanner, ParallelBatchExecutor};
pub use discovery::{DiscoveredServer, ServerDiscovery, DNS_SEEDS};
pub use pinning::{CertFingerprint, CertPinStore, PinningConfigBuilder};
pub use pool::{ConnectionPool, PoolConfig, PoolStats, PooledClient};
pub use subscription::{
    AddressStatusEvent, AddressWatcher, BlockHeaderEvent, ConnectionStatus,
    SubscriptionClient, SubscriptionEvent, SubscriptionManager,
};
