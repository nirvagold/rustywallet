//! Backend trait for blockchain queries

use crate::error::RecoveryError;
use crate::result::FoundUtxo;
use async_trait::async_trait;

/// Balance information for an address
#[derive(Debug, Clone, Default)]
pub struct AddressBalance {
    pub confirmed: u64,
    pub unconfirmed: i64,
    pub tx_count: u32,
}

impl AddressBalance {
    pub fn total(&self) -> u64 {
        if self.unconfirmed >= 0 {
            self.confirmed + self.unconfirmed as u64
        } else {
            self.confirmed.saturating_sub((-self.unconfirmed) as u64)
        }
    }

    pub fn has_activity(&self) -> bool {
        self.tx_count > 0 || self.confirmed > 0 || self.unconfirmed != 0
    }
}

#[async_trait]
pub trait Backend: Send + Sync {
    async fn get_balance(&self, address: &str) -> Result<AddressBalance, RecoveryError>;
    async fn get_utxos(&self, address: &str) -> Result<Vec<FoundUtxo>, RecoveryError>;
    async fn batch_get_balances(&self, addresses: &[String]) -> Result<Vec<AddressBalance>, RecoveryError>;
    async fn get_block_height(&self) -> Result<u32, RecoveryError>;
}

pub struct ElectrumBackend {
    client: rustywallet_electrum::ElectrumClient,
}

impl ElectrumBackend {
    pub async fn new(server: &str) -> Result<Self, RecoveryError> {
        let client = rustywallet_electrum::ElectrumClient::new(server).await?;
        Ok(Self { client })
    }

    pub async fn mainnet() -> Result<Self, RecoveryError> {
        Self::new("electrum.blockstream.info").await
    }

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
            txid: u.txid,
            vout: u.vout,
            amount: u.value,
            address: address.to_string(),
            path: String::new(),
            confirmations: if u.height > 0 { height.saturating_sub(u.height as u32) + 1 } else { 0 },
            height: u.height as u32,
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
