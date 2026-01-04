//! Backend trait for blockchain queries

use crate::error::RecoveryError;
use crate::result::FoundUtxo;
use async_trait::async_trait;

/// Balance information for an address
#[derive(Debug, Clone, Default)]
pub struct AddressBalance {
    /// Confirmed balance in satoshis
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis
    pub unconfirmed: i64,
    /// Number of transactions
    pub tx_count: u32,
}

impl AddressBalance {
    /// Get total balance
    pub fn total(&self) -> u64 {
        if self.unconfirmed >= 0 {
            self.confirmed + self.unconfirmed as u64
        } else {
            self.confirmed.saturating_sub((-self.unconfirmed) as u64)
        }
    }

    /// Check if address has any activity
    pub fn has_activity(&self) -> bool {
        self.tx_count > 0 || self.confirmed > 0 || self.unconfirmed != 0
    }
}

/// Trait for blockchain query backends
#[async_trait]
pub trait Backend: Send + Sync {
    /// Get balance for a single address
    async fn get_balance(&self, address: &str) -> Result<AddressBalance, RecoveryError>;
    /// Get UTXOs for an address
    async fn get_utxos(&self, address: &str) -> Result<Vec<FoundUtxo>, RecoveryError>;
    /// Get balances for multiple addresses
    async fn batch_get_balances(&self, addresses: &[String]) -> Result<Vec<AddressBalance>, RecoveryError>;
    /// Get current block height
    async fn get_block_height(&self) -> Result<u32, RecoveryError>;
}

/// Electrum backend implementation
pub struct ElectrumBackend {
    client: rustywallet_electrum::ElectrumClient,
}

impl ElectrumBackend {
    /// Create a new Electrum backend
    pub async fn new(server: &str) -> Result<Self, RecoveryError> {
        let client = rustywallet_electrum::ElectrumClient::new(server).await?;
        Ok(Self { client })
    }

    /// Create with default mainnet server
    pub async fn mainnet() -> Result<Self, RecoveryError> {
        Self::new("electrum.blockstream.info").await
    }

    /// Create with default testnet server
    pub async fn testnet() -> Result<Self, RecoveryError> {
        Self::new("testnet.aranguren.org").await
    }
}

#[async_trait]
impl Backend for ElectrumBackend {
    async fn get_balance(&self, address: &str) -> Result<AddressBalance, RecoveryError> {
        let balance = self.client.get_balance(address).await?;
        Ok(AddressBalance {
            confirmed: balance.confirmed,
            unconfirmed: balance.unconfirmed,
            tx_count: 0,
        })
    }

    async fn get_utxos(&self, address: &str) -> Result<Vec<FoundUtxo>, RecoveryError> {
        let utxos = self.client.list_unspent(address).await?;
        let height = self.get_block_height().await.unwrap_or(0);
        Ok(utxos.into_iter().map(|u| FoundUtxo {
            txid: u.tx_hash,
            vout: u.tx_pos,
            amount: u.value,
            address: address.to_string(),
            path: String::new(),
            confirmations: if u.height > 0 { height.saturating_sub(u.height) + 1 } else { 0 },
            height: u.height,
        }).collect())
    }

    async fn batch_get_balances(&self, addresses: &[String]) -> Result<Vec<AddressBalance>, RecoveryError> {
        let refs: Vec<&str> = addresses.iter().map(|s| s.as_str()).collect();
        let balances = self.client.get_balances(&refs).await?;
        Ok(balances.into_iter().map(|b| AddressBalance {
            confirmed: b.confirmed,
            unconfirmed: b.unconfirmed,
            tx_count: 0,
        }).collect())
    }

    async fn get_block_height(&self) -> Result<u32, RecoveryError> {
        let height = self.client.get_block_height().await?;
        Ok(height as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_balance() {
        let balance = AddressBalance {
            confirmed: 100000,
            unconfirmed: 5000,
            tx_count: 3,
        };
        assert_eq!(balance.total(), 105000);
        assert!(balance.has_activity());
    }
}
