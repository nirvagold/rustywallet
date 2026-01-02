//! Mining pool statistics from mempool.space.
//!
//! This module provides access to mining pool statistics
//! including hashrate distribution, block rewards, and pool rankings.

use serde::{Deserialize, Serialize};

use crate::client::MempoolClient;
use crate::error::Result;

/// Mining pool statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MiningPoolStats {
    /// Pool name/slug
    pub pool: PoolInfo,
    /// Number of blocks mined
    #[serde(default)]
    pub block_count: u64,
    /// Estimated hashrate (EH/s)
    #[serde(default, rename = "estimatedHashrate")]
    pub estimated_hashrate: f64,
    /// Share of total hashrate (0-1)
    #[serde(default)]
    pub share: f64,
    /// Average fee rate of blocks
    #[serde(default, rename = "avgFeerate")]
    pub avg_fee_rate: f64,
    /// Average block size
    #[serde(default, rename = "avgBlockSize")]
    pub avg_block_size: u64,
    /// Total rewards earned (satoshis)
    #[serde(default, rename = "totalReward")]
    pub total_reward: u64,
}

/// Pool identification info.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolInfo {
    /// Pool ID/slug
    #[serde(default)]
    pub id: u32,
    /// Pool name
    #[serde(default)]
    pub name: String,
    /// Pool slug (URL-friendly name)
    #[serde(default)]
    pub slug: String,
    /// Pool link
    #[serde(default)]
    pub link: String,
}

impl MiningPoolStats {
    /// Get share as percentage.
    pub fn share_percent(&self) -> f64 {
        self.share * 100.0
    }

    /// Get total reward in BTC.
    pub fn total_reward_btc(&self) -> f64 {
        self.total_reward as f64 / 100_000_000.0
    }
}

/// Hashrate distribution across pools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashrateDistribution {
    /// Pool statistics
    #[serde(default)]
    pub pools: Vec<MiningPoolStats>,
    /// Total block count in period
    #[serde(default, rename = "blockCount")]
    pub block_count: u64,
    /// Time period in seconds
    #[serde(default, rename = "lastEstimatedHashrate")]
    pub last_estimated_hashrate: f64,
}

impl HashrateDistribution {
    /// Get pool by name.
    pub fn get_pool(&self, name: &str) -> Option<&MiningPoolStats> {
        self.pools.iter().find(|p| p.pool.name.eq_ignore_ascii_case(name))
    }

    /// Get top N pools by block count.
    pub fn top_pools(&self, n: usize) -> Vec<&MiningPoolStats> {
        let mut sorted: Vec<_> = self.pools.iter().collect();
        sorted.sort_by(|a, b| b.block_count.cmp(&a.block_count));
        sorted.into_iter().take(n).collect()
    }

    /// Get total hashrate (sum of all pools).
    pub fn total_hashrate(&self) -> f64 {
        self.pools.iter().map(|p| p.estimated_hashrate).sum()
    }
}

/// Block reward statistics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockRewardStats {
    /// Average block reward (satoshis)
    #[serde(default, rename = "avgReward")]
    pub avg_reward: u64,
    /// Average fees per block (satoshis)
    #[serde(default, rename = "avgFees")]
    pub avg_fees: u64,
    /// Average subsidy per block (satoshis)
    #[serde(default, rename = "avgSubsidy")]
    pub avg_subsidy: u64,
    /// Total rewards in period (satoshis)
    #[serde(default, rename = "totalReward")]
    pub total_reward: u64,
    /// Total fees in period (satoshis)
    #[serde(default, rename = "totalFees")]
    pub total_fees: u64,
    /// Block count in period
    #[serde(default, rename = "blockCount")]
    pub block_count: u64,
}

impl BlockRewardStats {
    /// Get average reward in BTC.
    pub fn avg_reward_btc(&self) -> f64 {
        self.avg_reward as f64 / 100_000_000.0
    }

    /// Get average fees in BTC.
    pub fn avg_fees_btc(&self) -> f64 {
        self.avg_fees as f64 / 100_000_000.0
    }

    /// Get fee percentage of total reward.
    pub fn fee_percentage(&self) -> f64 {
        if self.avg_reward == 0 {
            0.0
        } else {
            (self.avg_fees as f64 / self.avg_reward as f64) * 100.0
        }
    }
}

/// Difficulty adjustment information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DifficultyAdjustment {
    /// Current difficulty
    #[serde(default, rename = "difficultyChange")]
    pub difficulty_change: f64,
    /// Estimated seconds until next adjustment
    #[serde(default, rename = "estimatedRetargetDate")]
    pub estimated_retarget_date: u64,
    /// Remaining blocks until adjustment
    #[serde(default, rename = "remainingBlocks")]
    pub remaining_blocks: u64,
    /// Remaining time in seconds
    #[serde(default, rename = "remainingTime")]
    pub remaining_time: u64,
    /// Previous difficulty
    #[serde(default, rename = "previousRetarget")]
    pub previous_retarget: f64,
    /// Previous time
    #[serde(default, rename = "previousTime")]
    pub previous_time: u64,
    /// Next retarget height
    #[serde(default, rename = "nextRetargetHeight")]
    pub next_retarget_height: u64,
    /// Time average in seconds
    #[serde(default, rename = "timeAvg")]
    pub time_avg: u64,
    /// Time offset
    #[serde(default, rename = "timeOffset")]
    pub time_offset: i64,
}

impl DifficultyAdjustment {
    /// Get difficulty change as percentage.
    pub fn difficulty_change_percent(&self) -> f64 {
        self.difficulty_change
    }

    /// Get remaining time in hours.
    pub fn remaining_hours(&self) -> f64 {
        self.remaining_time as f64 / 3600.0
    }

    /// Get remaining time in days.
    pub fn remaining_days(&self) -> f64 {
        self.remaining_time as f64 / 86400.0
    }

    /// Check if difficulty will increase.
    pub fn will_increase(&self) -> bool {
        self.difficulty_change > 0.0
    }
}

/// Mining pool block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PoolBlock {
    /// Block height
    #[serde(default)]
    pub height: u64,
    /// Block hash
    #[serde(default)]
    pub hash: String,
    /// Block timestamp
    #[serde(default)]
    pub timestamp: u64,
    /// Block size
    #[serde(default)]
    pub size: u32,
    /// Transaction count
    #[serde(default)]
    pub tx_count: u32,
    /// Total fees (satoshis)
    #[serde(default)]
    pub total_fees: u64,
    /// Block reward (satoshis)
    #[serde(default)]
    pub reward: u64,
}

impl PoolBlock {
    /// Get reward in BTC.
    pub fn reward_btc(&self) -> f64 {
        self.reward as f64 / 100_000_000.0
    }

    /// Get fees in BTC.
    pub fn fees_btc(&self) -> f64 {
        self.total_fees as f64 / 100_000_000.0
    }
}

/// Mining client extension for MempoolClient.
impl MempoolClient {
    /// Get hashrate distribution across mining pools.
    ///
    /// # Arguments
    /// * `period` - Time period: "24h", "3d", "1w", "1m", "3m", "6m", "1y", "2y", "3y", "all"
    pub async fn get_hashrate_distribution(&self, period: &str) -> Result<HashrateDistribution> {
        self.get_mining(&format!("/v1/mining/hashrate/pools/{}", period)).await
    }

    /// Get difficulty adjustment information.
    pub async fn get_difficulty_adjustment(&self) -> Result<DifficultyAdjustment> {
        self.get_mining("/v1/difficulty-adjustment").await
    }

    /// Get mining pool information by slug.
    pub async fn get_mining_pool(&self, slug: &str) -> Result<MiningPoolStats> {
        self.get_mining(&format!("/v1/mining/pool/{}", slug)).await
    }

    /// Get blocks mined by a pool.
    ///
    /// # Arguments
    /// * `slug` - Pool slug (e.g., "foundryusa", "antpool")
    /// * `block_height` - Optional starting block height
    pub async fn get_pool_blocks(&self, slug: &str, block_height: Option<u64>) -> Result<Vec<PoolBlock>> {
        let endpoint = match block_height {
            Some(h) => format!("/v1/mining/pool/{}/blocks/{}", slug, h),
            None => format!("/v1/mining/pool/{}/blocks", slug),
        };
        self.get_mining(&endpoint).await
    }

    /// Get block reward statistics.
    ///
    /// # Arguments
    /// * `period` - Time period: "24h", "3d", "1w", "1m", "3m", "6m", "1y", "2y", "3y", "all"
    pub async fn get_block_rewards(&self, period: &str) -> Result<BlockRewardStats> {
        self.get_mining(&format!("/v1/mining/reward-stats/{}", period)).await
    }

    /// Internal GET method for mining endpoints.
    async fn get_mining<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
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
    fn test_mining_pool_stats() {
        let stats = MiningPoolStats {
            pool: PoolInfo {
                id: 1,
                name: "Foundry USA".to_string(),
                slug: "foundryusa".to_string(),
                link: "https://foundrydigital.com".to_string(),
            },
            block_count: 1000,
            estimated_hashrate: 150.5,
            share: 0.30,
            avg_fee_rate: 25.5,
            avg_block_size: 1500000,
            total_reward: 625_000_000_000, // 6250 BTC
        };
        
        assert_eq!(stats.share_percent(), 30.0);
        assert_eq!(stats.total_reward_btc(), 6250.0);
    }

    #[test]
    fn test_difficulty_adjustment() {
        let adj = DifficultyAdjustment {
            difficulty_change: 5.5,
            estimated_retarget_date: 1234567890,
            remaining_blocks: 500,
            remaining_time: 86400 * 3, // 3 days
            previous_retarget: 3.2,
            previous_time: 1234000000,
            next_retarget_height: 850000,
            time_avg: 600,
            time_offset: -30,
        };
        
        assert_eq!(adj.difficulty_change_percent(), 5.5);
        assert!(adj.will_increase());
        assert_eq!(adj.remaining_days(), 3.0);
    }

    #[test]
    fn test_block_reward_stats() {
        let stats = BlockRewardStats {
            avg_reward: 650_000_000, // 6.5 BTC
            avg_fees: 25_000_000, // 0.25 BTC
            avg_subsidy: 625_000_000, // 6.25 BTC
            total_reward: 65_000_000_000,
            total_fees: 2_500_000_000,
            block_count: 100,
        };
        
        assert_eq!(stats.avg_reward_btc(), 6.5);
        assert_eq!(stats.avg_fees_btc(), 0.25);
        // Fee percentage: 0.25 / 6.5 * 100 ≈ 3.85%
        assert!((stats.fee_percentage() - 3.846).abs() < 0.01);
    }

    #[test]
    fn test_pool_block() {
        let block = PoolBlock {
            height: 800000,
            hash: "abc123".to_string(),
            timestamp: 1234567890,
            size: 1500000,
            tx_count: 3000,
            total_fees: 25_000_000,
            reward: 650_000_000,
        };
        
        assert_eq!(block.reward_btc(), 6.5);
        assert_eq!(block.fees_btc(), 0.25);
    }
}
