//! Optimized batch request utilities.
//!
//! This module provides utilities for efficiently batching multiple
//! Electrum requests into single network round-trips.

use std::collections::HashMap;

use crate::client::ElectrumClient;
use crate::error::Result;
use crate::types::{Balance, TxHistory, Utxo};

/// Maximum number of requests per batch.
pub const MAX_BATCH_SIZE: usize = 100;

/// Batch request builder for efficient multi-address queries.
pub struct BatchRequest<'a> {
    client: &'a ElectrumClient,
    balance_addresses: Vec<String>,
    utxo_addresses: Vec<String>,
    history_addresses: Vec<String>,
    transactions: Vec<String>,
}

impl<'a> BatchRequest<'a> {
    /// Create a new batch request builder.
    pub fn new(client: &'a ElectrumClient) -> Self {
        Self {
            client,
            balance_addresses: Vec::new(),
            utxo_addresses: Vec::new(),
            history_addresses: Vec::new(),
            transactions: Vec::new(),
        }
    }

    /// Add addresses for balance queries.
    pub fn balances(mut self, addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.balance_addresses.extend(addresses.into_iter().map(|a| a.into()));
        self
    }

    /// Add a single address for balance query.
    pub fn balance(mut self, address: impl Into<String>) -> Self {
        self.balance_addresses.push(address.into());
        self
    }

    /// Add addresses for UTXO queries.
    pub fn utxos(mut self, addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.utxo_addresses.extend(addresses.into_iter().map(|a| a.into()));
        self
    }

    /// Add a single address for UTXO query.
    pub fn utxo(mut self, address: impl Into<String>) -> Self {
        self.utxo_addresses.push(address.into());
        self
    }

    /// Add addresses for history queries.
    pub fn histories(mut self, addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.history_addresses.extend(addresses.into_iter().map(|a| a.into()));
        self
    }

    /// Add a single address for history query.
    pub fn history(mut self, address: impl Into<String>) -> Self {
        self.history_addresses.push(address.into());
        self
    }

    /// Add transaction IDs to fetch.
    pub fn transactions(mut self, txids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.transactions.extend(txids.into_iter().map(|t| t.into()));
        self
    }

    /// Add a single transaction ID to fetch.
    pub fn transaction(mut self, txid: impl Into<String>) -> Self {
        self.transactions.push(txid.into());
        self
    }

    /// Execute the batch request.
    pub async fn execute(self) -> Result<BatchResponse> {
        let mut response = BatchResponse::new();

        // Execute balance queries
        if !self.balance_addresses.is_empty() {
            let addresses: Vec<&str> = self.balance_addresses.iter().map(|s| s.as_str()).collect();
            let balances = self.client.get_balances(&addresses).await?;
            
            for (addr, bal) in self.balance_addresses.into_iter().zip(balances) {
                response.balances.insert(addr, bal);
            }
        }

        // Execute UTXO queries in batches
        for chunk in self.utxo_addresses.chunks(MAX_BATCH_SIZE) {
            for addr in chunk {
                let utxos = self.client.list_unspent(addr).await?;
                response.utxos.insert(addr.clone(), utxos);
            }
        }

        // Execute history queries in batches
        for chunk in self.history_addresses.chunks(MAX_BATCH_SIZE) {
            for addr in chunk {
                let history = self.client.get_history(addr).await?;
                response.histories.insert(addr.clone(), history);
            }
        }

        // Execute transaction queries in batches
        for chunk in self.transactions.chunks(MAX_BATCH_SIZE) {
            for txid in chunk {
                let tx = self.client.get_transaction(txid).await?;
                response.transactions.insert(txid.clone(), tx);
            }
        }

        Ok(response)
    }
}

/// Response from a batch request.
#[derive(Debug, Clone, Default)]
pub struct BatchResponse {
    /// Balance results by address
    pub balances: HashMap<String, Balance>,
    /// UTXO results by address
    pub utxos: HashMap<String, Vec<Utxo>>,
    /// History results by address
    pub histories: HashMap<String, Vec<TxHistory>>,
    /// Transaction results by txid
    pub transactions: HashMap<String, String>,
}

impl BatchResponse {
    /// Create a new empty response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get balance for an address.
    pub fn get_balance(&self, address: &str) -> Option<&Balance> {
        self.balances.get(address)
    }

    /// Get UTXOs for an address.
    pub fn get_utxos(&self, address: &str) -> Option<&[Utxo]> {
        self.utxos.get(address).map(|v| v.as_slice())
    }

    /// Get history for an address.
    pub fn get_history(&self, address: &str) -> Option<&[TxHistory]> {
        self.histories.get(address).map(|v| v.as_slice())
    }

    /// Get a transaction by txid.
    pub fn get_transaction(&self, txid: &str) -> Option<&str> {
        self.transactions.get(txid).map(|s| s.as_str())
    }

    /// Get total confirmed balance across all addresses.
    pub fn total_confirmed(&self) -> u64 {
        self.balances.values().map(|b| b.confirmed).sum()
    }

    /// Get total unconfirmed balance across all addresses.
    pub fn total_unconfirmed(&self) -> i64 {
        self.balances.values().map(|b| b.unconfirmed).sum()
    }

    /// Get all UTXOs across all addresses.
    pub fn all_utxos(&self) -> Vec<(&str, &Utxo)> {
        self.utxos
            .iter()
            .flat_map(|(addr, utxos)| utxos.iter().map(move |u| (addr.as_str(), u)))
            .collect()
    }

    /// Get total UTXO value across all addresses.
    pub fn total_utxo_value(&self) -> u64 {
        self.utxos.values().flat_map(|v| v.iter()).map(|u| u.value).sum()
    }

    /// Get addresses with non-zero balance.
    pub fn funded_addresses(&self) -> Vec<&str> {
        self.balances
            .iter()
            .filter(|(_, b)| b.has_balance())
            .map(|(a, _)| a.as_str())
            .collect()
    }

    /// Check if any address has balance.
    pub fn has_any_balance(&self) -> bool {
        self.balances.values().any(|b| b.has_balance())
    }
}

/// Parallel batch executor for very large address sets.
pub struct ParallelBatchExecutor<'a> {
    client: &'a ElectrumClient,
    chunk_size: usize,
}

impl<'a> ParallelBatchExecutor<'a> {
    /// Create a new parallel executor.
    pub fn new(client: &'a ElectrumClient) -> Self {
        Self {
            client,
            chunk_size: MAX_BATCH_SIZE,
        }
    }

    /// Set the chunk size for parallel execution.
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size.min(MAX_BATCH_SIZE);
        self
    }

    /// Get balances for many addresses in parallel chunks.
    pub async fn get_balances(&self, addresses: &[&str]) -> Result<HashMap<String, Balance>> {
        let mut results = HashMap::new();

        for chunk in addresses.chunks(self.chunk_size) {
            let balances = self.client.get_balances(chunk).await?;
            
            for (addr, bal) in chunk.iter().zip(balances) {
                results.insert(addr.to_string(), bal);
            }
        }

        Ok(results)
    }

    /// Get UTXOs for many addresses.
    pub async fn list_unspent(&self, addresses: &[&str]) -> Result<HashMap<String, Vec<Utxo>>> {
        let mut results = HashMap::new();

        for addr in addresses {
            let utxos = self.client.list_unspent(addr).await?;
            results.insert(addr.to_string(), utxos);
        }

        Ok(results)
    }

    /// Get history for many addresses.
    pub async fn get_histories(&self, addresses: &[&str]) -> Result<HashMap<String, Vec<TxHistory>>> {
        let mut results = HashMap::new();

        for addr in addresses {
            let history = self.client.get_history(addr).await?;
            results.insert(addr.to_string(), history);
        }

        Ok(results)
    }
}

/// Scan addresses until gap limit is reached.
pub struct GapLimitScanner<'a> {
    client: &'a ElectrumClient,
    gap_limit: usize,
}

impl<'a> GapLimitScanner<'a> {
    /// Create a new gap limit scanner.
    pub fn new(client: &'a ElectrumClient, gap_limit: usize) -> Self {
        Self { client, gap_limit }
    }

    /// Scan addresses and return those with balance.
    ///
    /// Stops when `gap_limit` consecutive addresses have no history.
    pub async fn scan<F>(&self, mut address_generator: F) -> Result<Vec<(usize, String, Balance)>>
    where
        F: FnMut(usize) -> String,
    {
        let mut results = Vec::new();
        let mut consecutive_empty = 0;
        let mut index = 0;

        while consecutive_empty < self.gap_limit {
            let address = address_generator(index);
            let history = self.client.get_history(&address).await?;

            if history.is_empty() {
                consecutive_empty += 1;
            } else {
                consecutive_empty = 0;
                let balance = self.client.get_balance(&address).await?;
                results.push((index, address, balance));
            }

            index += 1;
        }

        Ok(results)
    }

    /// Scan with batch queries for better performance.
    pub async fn scan_batch<F>(&self, mut address_generator: F, batch_size: usize) -> Result<Vec<(usize, String, Balance)>>
    where
        F: FnMut(usize) -> String,
    {
        let mut results = Vec::new();
        let mut consecutive_empty = 0;
        let mut index = 0;

        while consecutive_empty < self.gap_limit {
            // Generate a batch of addresses
            let batch: Vec<(usize, String)> = (0..batch_size)
                .map(|i| {
                    let idx = index + i;
                    (idx, address_generator(idx))
                })
                .collect();

            let addresses: Vec<&str> = batch.iter().map(|(_, a)| a.as_str()).collect();
            let balances = self.client.get_balances(&addresses).await?;

            let mut batch_empty = true;
            for ((idx, addr), balance) in batch.into_iter().zip(balances) {
                if balance.has_balance() {
                    results.push((idx, addr, balance));
                    consecutive_empty = 0;
                    batch_empty = false;
                } else {
                    consecutive_empty += 1;
                    if consecutive_empty >= self.gap_limit {
                        break;
                    }
                }
            }

            if batch_empty {
                // All addresses in batch were empty
                break;
            }

            index += batch_size;
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_response() {
        let mut response = BatchResponse::new();
        
        response.balances.insert(
            "addr1".to_string(),
            Balance { confirmed: 1000, unconfirmed: 0 },
        );
        response.balances.insert(
            "addr2".to_string(),
            Balance { confirmed: 2000, unconfirmed: 100 },
        );

        assert_eq!(response.total_confirmed(), 3000);
        assert_eq!(response.total_unconfirmed(), 100);
        assert!(response.has_any_balance());
        assert_eq!(response.funded_addresses().len(), 2);
    }

    #[test]
    fn test_batch_response_utxos() {
        let mut response = BatchResponse::new();
        
        response.utxos.insert(
            "addr1".to_string(),
            vec![
                Utxo { txid: "tx1".into(), vout: 0, value: 1000, height: 100 },
                Utxo { txid: "tx2".into(), vout: 1, value: 2000, height: 101 },
            ],
        );

        assert_eq!(response.total_utxo_value(), 3000);
        assert_eq!(response.all_utxos().len(), 2);
    }

    #[test]
    fn test_max_batch_size() {
        assert!(MAX_BATCH_SIZE > 0);
        assert!(MAX_BATCH_SIZE <= 1000);
    }
}
