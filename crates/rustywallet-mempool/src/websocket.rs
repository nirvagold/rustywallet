//! WebSocket support for real-time mempool data.
//!
//! This module provides WebSocket connectivity for receiving
//! real-time updates from mempool.space.

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};

use crate::types::FeeEstimates;

/// WebSocket endpoint URLs.
pub const MAINNET_WS_URL: &str = "wss://mempool.space/api/v1/ws";
/// Testnet WebSocket URL.
pub const TESTNET_WS_URL: &str = "wss://mempool.space/testnet/api/v1/ws";
/// Signet WebSocket URL.
pub const SIGNET_WS_URL: &str = "wss://mempool.space/signet/api/v1/ws";

/// WebSocket event types.
#[derive(Debug, Clone)]
pub enum WsEvent {
    /// New block mined
    Block(BlockEvent),
    /// Mempool update
    MempoolInfo(MempoolInfoEvent),
    /// Fee rate update
    Fees(FeeEstimates),
    /// Address transaction detected
    AddressTx(AddressTxEvent),
    /// Transaction confirmed
    TxConfirmed(TxConfirmedEvent),
    /// Connection status changed
    ConnectionStatus(WsConnectionStatus),
}

/// Block event data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEvent {
    /// Block height
    pub height: u64,
    /// Block hash
    pub hash: String,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of transactions
    pub tx_count: u32,
    /// Block size in bytes
    pub size: u32,
    /// Block weight
    pub weight: u32,
    /// Total fees in satoshis
    pub total_fees: u64,
    /// Median fee rate
    pub median_fee: f64,
}

/// Mempool info event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolInfoEvent {
    /// Number of transactions in mempool
    pub count: u64,
    /// Total size in virtual bytes
    pub vsize: u64,
    /// Total fees in satoshis
    pub total_fee: u64,
    /// Memory usage in bytes
    pub usage: u64,
}

/// Address transaction event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTxEvent {
    /// The address
    pub address: String,
    /// Transaction ID
    pub txid: String,
    /// Value change in satoshis (positive = received, negative = sent)
    pub value: i64,
    /// Whether confirmed
    pub confirmed: bool,
}

/// Transaction confirmed event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxConfirmedEvent {
    /// Transaction ID
    pub txid: String,
    /// Block height
    pub block_height: u64,
    /// Block hash
    pub block_hash: String,
}

/// WebSocket connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsConnectionStatus {
    /// Connected to server
    Connected,
    /// Disconnected from server
    Disconnected,
    /// Reconnecting to server
    Reconnecting,
    /// Connection error
    Error,
}

/// WebSocket subscription configuration.
#[derive(Debug, Clone, Default)]
pub struct WsSubscription {
    /// Subscribe to new blocks
    pub blocks: bool,
    /// Subscribe to mempool info updates
    pub mempool_info: bool,
    /// Subscribe to fee updates
    pub fees: bool,
    /// Addresses to track
    pub addresses: HashSet<String>,
    /// Transactions to track
    pub transactions: HashSet<String>,
}

impl WsSubscription {
    /// Create a new empty subscription.
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to new blocks.
    pub fn with_blocks(mut self) -> Self {
        self.blocks = true;
        self
    }

    /// Subscribe to mempool info.
    pub fn with_mempool_info(mut self) -> Self {
        self.mempool_info = true;
        self
    }

    /// Subscribe to fee updates.
    pub fn with_fees(mut self) -> Self {
        self.fees = true;
        self
    }

    /// Track an address.
    pub fn track_address(mut self, address: impl Into<String>) -> Self {
        self.addresses.insert(address.into());
        self
    }

    /// Track multiple addresses.
    pub fn track_addresses(mut self, addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.addresses.extend(addresses.into_iter().map(|a| a.into()));
        self
    }

    /// Track a transaction.
    pub fn track_transaction(mut self, txid: impl Into<String>) -> Self {
        self.transactions.insert(txid.into());
        self
    }

    /// Check if any subscriptions are active.
    pub fn has_subscriptions(&self) -> bool {
        self.blocks || self.mempool_info || self.fees || 
        !self.addresses.is_empty() || !self.transactions.is_empty()
    }
}

/// WebSocket client state (simulated - actual WebSocket requires additional deps).
pub struct WsClientState {
    /// Current subscription
    pub subscription: WsSubscription,
    /// Connection status
    pub status: WsConnectionStatus,
    /// Event broadcaster
    event_tx: broadcast::Sender<WsEvent>,
}

impl WsClientState {
    /// Create new client state.
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);
        Self {
            subscription: WsSubscription::new(),
            status: WsConnectionStatus::Disconnected,
            event_tx,
        }
    }

    /// Subscribe to events.
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.event_tx.subscribe()
    }

    /// Broadcast an event.
    pub fn broadcast(&self, event: WsEvent) {
        let _ = self.event_tx.send(event);
    }
}

impl Default for WsClientState {
    fn default() -> Self {
        Self::new()
    }
}

/// WebSocket client for real-time mempool data.
///
/// Note: This is a high-level API. Actual WebSocket connectivity
/// requires the `tokio-tungstenite` crate which can be added as
/// an optional dependency.
pub struct MempoolWsClient {
    ws_url: String,
    state: Arc<RwLock<WsClientState>>,
}

impl MempoolWsClient {
    /// Create a new WebSocket client for mainnet.
    pub fn new() -> Self {
        Self::with_url(MAINNET_WS_URL)
    }

    /// Create a new WebSocket client for testnet.
    pub fn testnet() -> Self {
        Self::with_url(TESTNET_WS_URL)
    }

    /// Create a new WebSocket client for signet.
    pub fn signet() -> Self {
        Self::with_url(SIGNET_WS_URL)
    }

    /// Create a new WebSocket client with custom URL.
    pub fn with_url(url: &str) -> Self {
        Self {
            ws_url: url.to_string(),
            state: Arc::new(RwLock::new(WsClientState::new())),
        }
    }

    /// Get the WebSocket URL.
    pub fn url(&self) -> &str {
        &self.ws_url
    }

    /// Subscribe to events.
    pub async fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.state.read().await.subscribe()
    }

    /// Get current connection status.
    pub async fn status(&self) -> WsConnectionStatus {
        self.state.read().await.status
    }

    /// Update subscription configuration.
    pub async fn set_subscription(&self, subscription: WsSubscription) {
        let mut state = self.state.write().await;
        state.subscription = subscription;
    }

    /// Get current subscription.
    pub async fn get_subscription(&self) -> WsSubscription {
        self.state.read().await.subscription.clone()
    }

    /// Track an address for transactions.
    pub async fn track_address(&self, address: impl Into<String>) {
        let mut state = self.state.write().await;
        state.subscription.addresses.insert(address.into());
    }

    /// Untrack an address.
    pub async fn untrack_address(&self, address: &str) {
        let mut state = self.state.write().await;
        state.subscription.addresses.remove(address);
    }

    /// Track a transaction for confirmation.
    pub async fn track_transaction(&self, txid: impl Into<String>) {
        let mut state = self.state.write().await;
        state.subscription.transactions.insert(txid.into());
    }

    /// Untrack a transaction.
    pub async fn untrack_transaction(&self, txid: &str) {
        let mut state = self.state.write().await;
        state.subscription.transactions.remove(txid);
    }

    /// Simulate receiving a block event (for testing).
    #[cfg(test)]
    pub async fn simulate_block(&self, event: BlockEvent) {
        let state = self.state.read().await;
        state.broadcast(WsEvent::Block(event));
    }

    /// Simulate receiving a fee update (for testing).
    #[cfg(test)]
    pub async fn simulate_fees(&self, fees: FeeEstimates) {
        let state = self.state.read().await;
        state.broadcast(WsEvent::Fees(fees));
    }
}

impl Default for MempoolWsClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for WebSocket subscriptions.
pub struct WsSubscriptionBuilder {
    subscription: WsSubscription,
}

impl WsSubscriptionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            subscription: WsSubscription::new(),
        }
    }

    /// Subscribe to new blocks.
    pub fn blocks(mut self) -> Self {
        self.subscription.blocks = true;
        self
    }

    /// Subscribe to mempool info.
    pub fn mempool_info(mut self) -> Self {
        self.subscription.mempool_info = true;
        self
    }

    /// Subscribe to fee updates.
    pub fn fees(mut self) -> Self {
        self.subscription.fees = true;
        self
    }

    /// Track an address.
    pub fn address(mut self, address: impl Into<String>) -> Self {
        self.subscription.addresses.insert(address.into());
        self
    }

    /// Track a transaction.
    pub fn transaction(mut self, txid: impl Into<String>) -> Self {
        self.subscription.transactions.insert(txid.into());
        self
    }

    /// Build the subscription.
    pub fn build(self) -> WsSubscription {
        self.subscription
    }
}

impl Default for WsSubscriptionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_subscription() {
        let sub = WsSubscription::new()
            .with_blocks()
            .with_fees()
            .track_address("addr1");
        
        assert!(sub.blocks);
        assert!(sub.fees);
        assert!(!sub.mempool_info);
        assert!(sub.addresses.contains("addr1"));
        assert!(sub.has_subscriptions());
    }

    #[test]
    fn test_ws_subscription_builder() {
        let sub = WsSubscriptionBuilder::new()
            .blocks()
            .fees()
            .address("addr1")
            .transaction("txid1")
            .build();
        
        assert!(sub.blocks);
        assert!(sub.fees);
        assert!(sub.addresses.contains("addr1"));
        assert!(sub.transactions.contains("txid1"));
    }

    #[test]
    fn test_ws_connection_status() {
        assert_eq!(WsConnectionStatus::Connected, WsConnectionStatus::Connected);
        assert_ne!(WsConnectionStatus::Connected, WsConnectionStatus::Disconnected);
    }

    #[test]
    fn test_block_event() {
        let event = BlockEvent {
            height: 800000,
            hash: "abc123".to_string(),
            timestamp: 1234567890,
            tx_count: 1000,
            size: 1000000,
            weight: 4000000,
            total_fees: 50000000,
            median_fee: 10.5,
        };
        
        assert_eq!(event.height, 800000);
        assert_eq!(event.tx_count, 1000);
    }

    #[tokio::test]
    async fn test_ws_client() {
        let client = MempoolWsClient::new();
        assert_eq!(client.url(), MAINNET_WS_URL);
        assert_eq!(client.status().await, WsConnectionStatus::Disconnected);
    }
}
