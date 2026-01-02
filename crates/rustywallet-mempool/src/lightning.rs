//! Lightning Network statistics from mempool.space.
//!
//! This module provides access to Lightning Network statistics
//! including network capacity, node counts, and channel information.

use serde::{Deserialize, Serialize};

use crate::client::MempoolClient;
use crate::error::Result;

/// Lightning Network statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightningStats {
    /// Latest statistics
    pub latest: LightningNetworkStats,
    /// Previous period statistics (for comparison)
    #[serde(default)]
    pub previous: Option<LightningNetworkStats>,
}

/// Lightning Network statistics snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightningNetworkStats {
    /// Total network capacity in satoshis
    #[serde(default)]
    pub capacity: u64,
    /// Number of channels
    #[serde(default)]
    pub channel_count: u64,
    /// Number of nodes
    #[serde(default)]
    pub node_count: u64,
    /// Number of Tor nodes
    #[serde(default)]
    pub tor_nodes: u64,
    /// Number of clearnet nodes
    #[serde(default)]
    pub clearnet_nodes: u64,
    /// Number of unannounced nodes
    #[serde(default)]
    pub unannounced_nodes: u64,
    /// Average channel capacity in satoshis
    #[serde(default)]
    pub avg_capacity: u64,
    /// Average fee rate (ppm)
    #[serde(default)]
    pub avg_fee_rate: u64,
    /// Average base fee (msats)
    #[serde(default)]
    pub avg_base_fee_mtokens: u64,
    /// Median channel capacity
    #[serde(default)]
    pub med_capacity: u64,
    /// Median fee rate
    #[serde(default)]
    pub med_fee_rate: u64,
    /// Median base fee
    #[serde(default)]
    pub med_base_fee_mtokens: u64,
}

impl LightningNetworkStats {
    /// Get capacity in BTC.
    pub fn capacity_btc(&self) -> f64 {
        self.capacity as f64 / 100_000_000.0
    }

    /// Get average capacity in BTC.
    pub fn avg_capacity_btc(&self) -> f64 {
        self.avg_capacity as f64 / 100_000_000.0
    }

    /// Get average fee rate in percent.
    pub fn avg_fee_rate_percent(&self) -> f64 {
        self.avg_fee_rate as f64 / 10_000.0
    }
}

/// Lightning node information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightningNode {
    /// Node public key
    pub public_key: String,
    /// Node alias
    #[serde(default)]
    pub alias: String,
    /// Number of channels
    #[serde(default)]
    pub channel_count: u64,
    /// Total capacity in satoshis
    #[serde(default)]
    pub capacity: u64,
    /// First seen timestamp
    #[serde(default)]
    pub first_seen: u64,
    /// Last update timestamp
    #[serde(default)]
    pub updated_at: u64,
    /// City location
    #[serde(default)]
    pub city: Option<LightningNodeCity>,
    /// Country information
    #[serde(default)]
    pub country: Option<LightningNodeCountry>,
}

/// Node city information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightningNodeCity {
    /// City name
    #[serde(default)]
    pub en: String,
}

/// Node country information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightningNodeCountry {
    /// Country name
    #[serde(default)]
    pub en: String,
    /// Country code
    #[serde(default)]
    pub code: String,
}

impl LightningNode {
    /// Get capacity in BTC.
    pub fn capacity_btc(&self) -> f64 {
        self.capacity as f64 / 100_000_000.0
    }

    /// Get location string.
    pub fn location(&self) -> Option<String> {
        match (&self.city, &self.country) {
            (Some(city), Some(country)) => Some(format!("{}, {}", city.en, country.en)),
            (None, Some(country)) => Some(country.en.clone()),
            (Some(city), None) => Some(city.en.clone()),
            (None, None) => None,
        }
    }
}

/// Lightning channel information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightningChannel {
    /// Channel ID
    pub id: String,
    /// Short channel ID
    #[serde(default)]
    pub short_id: String,
    /// Channel capacity in satoshis
    #[serde(default)]
    pub capacity: u64,
    /// Transaction ID
    #[serde(default)]
    pub transaction_id: String,
    /// Transaction output index
    #[serde(default)]
    pub transaction_vout: u32,
    /// Closing transaction ID (if closed)
    #[serde(default)]
    pub closing_transaction_id: Option<String>,
    /// Channel status
    #[serde(default)]
    pub status: u8,
}

impl LightningChannel {
    /// Get capacity in BTC.
    pub fn capacity_btc(&self) -> f64 {
        self.capacity as f64 / 100_000_000.0
    }

    /// Check if channel is open.
    pub fn is_open(&self) -> bool {
        self.status == 1
    }

    /// Check if channel is closed.
    pub fn is_closed(&self) -> bool {
        self.closing_transaction_id.is_some()
    }
}

/// Top Lightning nodes ranking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopNodes {
    /// Nodes ranked by capacity
    #[serde(default)]
    pub by_capacity: Vec<LightningNode>,
    /// Nodes ranked by channel count
    #[serde(default)]
    pub by_channels: Vec<LightningNode>,
}

/// Lightning client extension for MempoolClient.
impl MempoolClient {
    /// Get Lightning Network statistics.
    pub async fn get_lightning_stats(&self) -> Result<LightningStats> {
        self.get_internal("/v1/lightning/statistics/latest").await
    }

    /// Get top Lightning nodes by capacity.
    pub async fn get_top_nodes_by_capacity(&self, limit: Option<u32>) -> Result<Vec<LightningNode>> {
        let limit = limit.unwrap_or(100);
        self.get_internal(&format!("/v1/lightning/nodes/rankings/connectivity?limit={}", limit)).await
    }

    /// Get Lightning node by public key.
    pub async fn get_lightning_node(&self, pubkey: &str) -> Result<LightningNode> {
        self.get_internal(&format!("/v1/lightning/nodes/{}", pubkey)).await
    }

    /// Get channels for a Lightning node.
    pub async fn get_node_channels(&self, pubkey: &str) -> Result<Vec<LightningChannel>> {
        self.get_internal(&format!("/v1/lightning/nodes/{}/channels", pubkey)).await
    }

    /// Get Lightning channel by ID.
    pub async fn get_lightning_channel(&self, channel_id: &str) -> Result<LightningChannel> {
        self.get_internal(&format!("/v1/lightning/channels/{}", channel_id)).await
    }

    /// Internal GET method (to avoid duplicate code).
    async fn get_internal<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        // Use the existing get method from client
        let url = format!("{}{}", self.base_url(), endpoint);
        
        let response = self.http_client().get(&url).send().await?;
        
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(crate::error::MempoolError::RateLimited);
        }
        
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            return Err(crate::error::MempoolError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        response
            .json()
            .await
            .map_err(|e| crate::error::MempoolError::ParseError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lightning_stats() {
        let stats = LightningNetworkStats {
            capacity: 500_000_000_000, // 5000 BTC
            channel_count: 80000,
            node_count: 15000,
            tor_nodes: 5000,
            clearnet_nodes: 8000,
            unannounced_nodes: 2000,
            avg_capacity: 6_250_000, // 0.0625 BTC
            avg_fee_rate: 500, // 0.05%
            avg_base_fee_mtokens: 1000,
            med_capacity: 5_000_000,
            med_fee_rate: 300,
            med_base_fee_mtokens: 500,
        };
        
        assert_eq!(stats.capacity_btc(), 5000.0);
        assert_eq!(stats.avg_capacity_btc(), 0.0625);
        assert_eq!(stats.avg_fee_rate_percent(), 0.05);
    }

    #[test]
    fn test_lightning_node() {
        let node = LightningNode {
            public_key: "abc123".to_string(),
            alias: "TestNode".to_string(),
            channel_count: 100,
            capacity: 100_000_000, // 1 BTC
            first_seen: 1234567890,
            updated_at: 1234567900,
            city: Some(LightningNodeCity { en: "New York".to_string() }),
            country: Some(LightningNodeCountry { en: "United States".to_string(), code: "US".to_string() }),
        };
        
        assert_eq!(node.capacity_btc(), 1.0);
        assert_eq!(node.location(), Some("New York, United States".to_string()));
    }

    #[test]
    fn test_lightning_channel() {
        let channel = LightningChannel {
            id: "channel123".to_string(),
            short_id: "800000x1x0".to_string(),
            capacity: 10_000_000, // 0.1 BTC
            transaction_id: "txid123".to_string(),
            transaction_vout: 0,
            closing_transaction_id: None,
            status: 1,
        };
        
        assert_eq!(channel.capacity_btc(), 0.1);
        assert!(channel.is_open());
        assert!(!channel.is_closed());
    }
}
