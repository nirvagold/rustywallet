//! Data types for Mempool.space API responses.

use serde::{Deserialize, Serialize};

/// Recommended fee rates from mempool.space.
///
/// All values are in satoshis per virtual byte (sat/vB).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeEstimates {
    /// Fee for next block confirmation (~10 min)
    pub fastest_fee: u64,
    /// Fee for confirmation within ~30 minutes
    pub half_hour_fee: u64,
    /// Fee for confirmation within ~1 hour
    pub hour_fee: u64,
    /// Fee for confirmation within ~6 hours
    pub economy_fee: u64,
    /// Minimum relay fee
    pub minimum_fee: u64,
}

impl FeeEstimates {
    /// Get fee rate for target confirmation time.
    ///
    /// - `blocks <= 1`: fastest
    /// - `blocks <= 3`: half_hour
    /// - `blocks <= 6`: hour
    /// - `blocks > 6`: economy
    pub fn for_blocks(&self, blocks: u32) -> u64 {
        match blocks {
            0..=1 => self.fastest_fee,
            2..=3 => self.half_hour_fee,
            4..=6 => self.hour_fee,
            _ => self.economy_fee,
        }
    }
}

/// Address information from mempool.space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressInfo {
    /// The address
    pub address: String,
    /// On-chain statistics
    pub chain_stats: ChainStats,
    /// Mempool (unconfirmed) statistics
    pub mempool_stats: MempoolStats,
}

impl AddressInfo {
    /// Get confirmed balance in satoshis.
    pub fn confirmed_balance(&self) -> i64 {
        self.chain_stats.funded_txo_sum as i64 - self.chain_stats.spent_txo_sum as i64
    }

    /// Get unconfirmed balance change in satoshis.
    pub fn unconfirmed_balance(&self) -> i64 {
        self.mempool_stats.funded_txo_sum as i64 - self.mempool_stats.spent_txo_sum as i64
    }

    /// Get total balance (confirmed + unconfirmed) in satoshis.
    pub fn total_balance(&self) -> i64 {
        self.confirmed_balance() + self.unconfirmed_balance()
    }

    /// Get total transaction count.
    pub fn tx_count(&self) -> u64 {
        self.chain_stats.tx_count + self.mempool_stats.tx_count
    }
}

/// On-chain statistics for an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStats {
    /// Number of funded transaction outputs
    pub funded_txo_count: u64,
    /// Total value of funded outputs (satoshis)
    pub funded_txo_sum: u64,
    /// Number of spent transaction outputs
    pub spent_txo_count: u64,
    /// Total value of spent outputs (satoshis)
    pub spent_txo_sum: u64,
    /// Total transaction count
    pub tx_count: u64,
}

/// Mempool (unconfirmed) statistics for an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolStats {
    /// Number of funded transaction outputs in mempool
    pub funded_txo_count: u64,
    /// Total value of funded outputs in mempool (satoshis)
    pub funded_txo_sum: u64,
    /// Number of spent transaction outputs in mempool
    pub spent_txo_count: u64,
    /// Total value of spent outputs in mempool (satoshis)
    pub spent_txo_sum: u64,
    /// Transaction count in mempool
    pub tx_count: u64,
}

/// Unspent transaction output (UTXO).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Value in satoshis
    pub value: u64,
    /// Confirmation status
    pub status: UtxoStatus,
}

impl Utxo {
    /// Check if this UTXO is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.status.confirmed
    }

    /// Get the outpoint string (txid:vout).
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }
}

/// UTXO confirmation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoStatus {
    /// Whether the UTXO is confirmed
    pub confirmed: bool,
    /// Block height (if confirmed)
    pub block_height: Option<u64>,
    /// Block hash (if confirmed)
    pub block_hash: Option<String>,
    /// Block time (if confirmed)
    pub block_time: Option<u64>,
}

/// Transaction information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction ID
    pub txid: String,
    /// Transaction version
    pub version: i32,
    /// Lock time
    pub locktime: u32,
    /// Transaction size in bytes
    pub size: u32,
    /// Transaction weight
    pub weight: u32,
    /// Transaction fee in satoshis
    pub fee: u64,
    /// Confirmation status
    pub status: TxStatus,
}

impl Transaction {
    /// Check if this transaction is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.status.confirmed
    }

    /// Get virtual size (vsize) in vbytes.
    pub fn vsize(&self) -> u32 {
        self.weight.div_ceil(4)
    }

    /// Get fee rate in sat/vB.
    pub fn fee_rate(&self) -> f64 {
        self.fee as f64 / self.vsize() as f64
    }
}

/// Transaction confirmation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxStatus {
    /// Whether the transaction is confirmed
    pub confirmed: bool,
    /// Block height (if confirmed)
    pub block_height: Option<u64>,
    /// Block hash (if confirmed)
    pub block_hash: Option<String>,
    /// Block time (if confirmed)
    pub block_time: Option<u64>,
}

/// Block information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block hash
    pub id: String,
    /// Block height
    pub height: u64,
    /// Block version
    pub version: i32,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of transactions
    pub tx_count: u32,
    /// Block size in bytes
    pub size: u32,
    /// Block weight
    pub weight: u32,
    /// Merkle root
    pub merkle_root: String,
    /// Previous block hash
    pub previousblockhash: String,
    /// Nonce
    pub nonce: u32,
    /// Difficulty bits
    pub bits: u32,
}
