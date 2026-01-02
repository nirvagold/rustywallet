//! Real-time subscriptions for Electrum protocol.
//!
//! This module provides subscription functionality for receiving
//! real-time updates about addresses and blockchain headers.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{broadcast, RwLock};

use crate::error::{ElectrumError, Result};
use crate::scripthash::address_to_scripthash;
use crate::transport::Transport;
use crate::types::ClientConfig;

/// Subscription event types.
#[derive(Debug, Clone)]
pub enum SubscriptionEvent {
    /// Address status changed (new transaction)
    AddressStatus(AddressStatusEvent),
    /// New block header received
    BlockHeader(BlockHeaderEvent),
    /// Connection status changed
    ConnectionStatus(ConnectionStatus),
}

/// Address status change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressStatusEvent {
    /// The address that changed
    pub address: String,
    /// The scripthash
    pub scripthash: String,
    /// New status hash (null if no history)
    pub status: Option<String>,
}

/// Block header event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderEvent {
    /// Block height
    pub height: u64,
    /// Block header hex
    pub hex: String,
}

/// Connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Connected to server
    Connected,
    /// Disconnected from server
    Disconnected,
    /// Reconnecting to server
    Reconnecting,
}

/// Subscription manager for real-time updates.
pub struct SubscriptionManager {
    transport: Arc<Transport>,
    #[allow(dead_code)]
    config: ClientConfig,
    /// Active address subscriptions (scripthash -> address)
    address_subs: RwLock<HashMap<String, String>>,
    /// Whether header subscription is active
    header_sub_active: RwLock<bool>,
    /// Event broadcaster
    event_tx: broadcast::Sender<SubscriptionEvent>,
    /// Request ID counter
    request_id: std::sync::atomic::AtomicU64,
    /// Running flag
    running: RwLock<bool>,
}

impl SubscriptionManager {
    /// Create a new subscription manager.
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let transport = Arc::new(Transport::connect(config.clone()).await?);
        let (event_tx, _) = broadcast::channel(1000);
        
        Ok(Self {
            transport,
            config,
            address_subs: RwLock::new(HashMap::new()),
            header_sub_active: RwLock::new(false),
            event_tx,
            request_id: std::sync::atomic::AtomicU64::new(1),
            running: RwLock::new(true),
        })
    }

    /// Get the next request ID.
    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Subscribe to receive events.
    pub fn subscribe(&self) -> broadcast::Receiver<SubscriptionEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to address status changes.
    ///
    /// Returns the current status hash (or None if no history).
    pub async fn subscribe_address(&self, address: &str) -> Result<Option<String>> {
        let scripthash = address_to_scripthash(address)?;
        
        let id = self.next_id();
        let result = self.transport
            .request(id, "blockchain.scripthash.subscribe", vec![json!(scripthash)])
            .await?;

        // Store subscription
        let mut subs = self.address_subs.write().await;
        subs.insert(scripthash.clone(), address.to_string());

        // Parse status
        let status = result.as_str().map(|s| s.to_string());
        
        Ok(status)
    }

    /// Unsubscribe from address status changes.
    pub async fn unsubscribe_address(&self, address: &str) -> Result<bool> {
        let scripthash = address_to_scripthash(address)?;
        
        let id = self.next_id();
        let result = self.transport
            .request(id, "blockchain.scripthash.unsubscribe", vec![json!(scripthash)])
            .await?;

        // Remove subscription
        let mut subs = self.address_subs.write().await;
        subs.remove(&scripthash);

        Ok(result.as_bool().unwrap_or(false))
    }

    /// Subscribe to new block headers.
    ///
    /// Returns the current tip header.
    pub async fn subscribe_headers(&self) -> Result<BlockHeaderEvent> {
        let id = self.next_id();
        let result = self.transport
            .request(id, "blockchain.headers.subscribe", vec![])
            .await?;

        *self.header_sub_active.write().await = true;

        let height = result.get("height")
            .and_then(|h| h.as_u64())
            .ok_or_else(|| ElectrumError::InvalidResponse("Missing height".into()))?;
        
        let hex = result.get("hex")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();

        Ok(BlockHeaderEvent { height, hex })
    }

    /// Get all subscribed addresses.
    pub async fn subscribed_addresses(&self) -> Vec<String> {
        let subs = self.address_subs.read().await;
        subs.values().cloned().collect()
    }

    /// Check if headers subscription is active.
    pub async fn is_headers_subscribed(&self) -> bool {
        *self.header_sub_active.read().await
    }

    /// Get subscription count.
    pub async fn subscription_count(&self) -> usize {
        let subs = self.address_subs.read().await;
        let header_active = *self.header_sub_active.read().await;
        subs.len() + if header_active { 1 } else { 0 }
    }

    /// Broadcast an event to all subscribers.
    fn broadcast(&self, event: SubscriptionEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Process a notification from the server.
    pub async fn process_notification(&self, method: &str, params: &[serde_json::Value]) -> Result<()> {
        match method {
            "blockchain.scripthash.subscribe" => {
                if params.len() >= 2 {
                    let scripthash = params[0].as_str().unwrap_or("").to_string();
                    let status = params[1].as_str().map(|s| s.to_string());
                    
                    let subs = self.address_subs.read().await;
                    if let Some(address) = subs.get(&scripthash) {
                        self.broadcast(SubscriptionEvent::AddressStatus(AddressStatusEvent {
                            address: address.clone(),
                            scripthash,
                            status,
                        }));
                    }
                }
            }
            "blockchain.headers.subscribe" => {
                if let Some(header) = params.first() {
                    let height = header.get("height")
                        .and_then(|h| h.as_u64())
                        .unwrap_or(0);
                    let hex = header.get("hex")
                        .and_then(|h| h.as_str())
                        .unwrap_or("")
                        .to_string();
                    
                    self.broadcast(SubscriptionEvent::BlockHeader(BlockHeaderEvent {
                        height,
                        hex,
                    }));
                }
            }
            _ => {}
        }
        
        Ok(())
    }

    /// Stop the subscription manager.
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Check if the manager is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

/// Builder for subscription-enabled client.
pub struct SubscriptionClientBuilder {
    config: ClientConfig,
    addresses: Vec<String>,
    subscribe_headers: bool,
}

impl SubscriptionClientBuilder {
    /// Create a new builder.
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            addresses: Vec::new(),
            subscribe_headers: false,
        }
    }

    /// Add an address to subscribe to.
    pub fn subscribe_address(mut self, address: impl Into<String>) -> Self {
        self.addresses.push(address.into());
        self
    }

    /// Add multiple addresses to subscribe to.
    pub fn subscribe_addresses(mut self, addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.addresses.extend(addresses.into_iter().map(|a| a.into()));
        self
    }

    /// Subscribe to block headers.
    pub fn subscribe_headers(mut self) -> Self {
        self.subscribe_headers = true;
        self
    }

    /// Build and connect the subscription client.
    pub async fn build(self) -> Result<SubscriptionClient> {
        let manager = SubscriptionManager::new(self.config).await?;
        
        // Subscribe to addresses
        for address in &self.addresses {
            manager.subscribe_address(address).await?;
        }
        
        // Subscribe to headers if requested
        if self.subscribe_headers {
            manager.subscribe_headers().await?;
        }
        
        Ok(SubscriptionClient { manager })
    }
}

/// Client with subscription support.
pub struct SubscriptionClient {
    manager: SubscriptionManager,
}

impl SubscriptionClient {
    /// Create a new subscription client.
    pub async fn new(config: ClientConfig) -> Result<Self> {
        let manager = SubscriptionManager::new(config).await?;
        Ok(Self { manager })
    }

    /// Get a builder for configuring subscriptions.
    pub fn builder(config: ClientConfig) -> SubscriptionClientBuilder {
        SubscriptionClientBuilder::new(config)
    }

    /// Subscribe to events.
    pub fn subscribe(&self) -> broadcast::Receiver<SubscriptionEvent> {
        self.manager.subscribe()
    }

    /// Subscribe to an address.
    pub async fn subscribe_address(&self, address: &str) -> Result<Option<String>> {
        self.manager.subscribe_address(address).await
    }

    /// Unsubscribe from an address.
    pub async fn unsubscribe_address(&self, address: &str) -> Result<bool> {
        self.manager.unsubscribe_address(address).await
    }

    /// Subscribe to block headers.
    pub async fn subscribe_headers(&self) -> Result<BlockHeaderEvent> {
        self.manager.subscribe_headers().await
    }

    /// Get all subscribed addresses.
    pub async fn subscribed_addresses(&self) -> Vec<String> {
        self.manager.subscribed_addresses().await
    }

    /// Get subscription count.
    pub async fn subscription_count(&self) -> usize {
        self.manager.subscription_count().await
    }

    /// Stop the client.
    pub async fn stop(&self) {
        self.manager.stop().await;
    }
}

/// Address watcher for monitoring specific addresses.
pub struct AddressWatcher {
    client: SubscriptionClient,
    addresses: Vec<String>,
}

impl AddressWatcher {
    /// Create a new address watcher.
    pub async fn new(config: ClientConfig, addresses: Vec<String>) -> Result<Self> {
        let client = SubscriptionClient::new(config).await?;
        
        for address in &addresses {
            client.subscribe_address(address).await?;
        }
        
        Ok(Self { client, addresses })
    }

    /// Subscribe to events.
    pub fn subscribe(&self) -> broadcast::Receiver<SubscriptionEvent> {
        self.client.subscribe()
    }

    /// Get watched addresses.
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    /// Add an address to watch.
    pub async fn watch(&mut self, address: impl Into<String>) -> Result<()> {
        let addr = address.into();
        self.client.subscribe_address(&addr).await?;
        self.addresses.push(addr);
        Ok(())
    }

    /// Stop watching an address.
    pub async fn unwatch(&mut self, address: &str) -> Result<()> {
        self.client.unsubscribe_address(address).await?;
        self.addresses.retain(|a| a != address);
        Ok(())
    }

    /// Stop the watcher.
    pub async fn stop(&self) {
        self.client.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_status_event() {
        let event = AddressStatusEvent {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            scripthash: "abc123".to_string(),
            status: Some("def456".to_string()),
        };
        
        assert_eq!(event.address, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(event.status.is_some());
    }

    #[test]
    fn test_block_header_event() {
        let event = BlockHeaderEvent {
            height: 800000,
            hex: "0100000000000000".to_string(),
        };
        
        assert_eq!(event.height, 800000);
    }

    #[test]
    fn test_connection_status() {
        assert_eq!(ConnectionStatus::Connected, ConnectionStatus::Connected);
        assert_ne!(ConnectionStatus::Connected, ConnectionStatus::Disconnected);
    }
}
