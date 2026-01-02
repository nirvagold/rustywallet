//! Electrum client for blockchain queries.
//!
//! This module provides the main `ElectrumClient` for interacting with
//! Electrum servers to query balances, UTXOs, and transactions.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use crate::error::{ElectrumError, Result};
use crate::scripthash::address_to_scripthash;
use crate::transport::Transport;
use crate::types::{Balance, ClientConfig, ServerVersion, TxHistory, Utxo};

/// Electrum protocol client.
///
/// Provides async methods for querying Bitcoin blockchain data via Electrum protocol.
///
/// # Example
/// ```no_run
/// use rustywallet_electrum::{ElectrumClient, ClientConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Connect to server
///     let client = ElectrumClient::new("electrum.blockstream.info").await?;
///     
///     // Check balance
///     let balance = client.get_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
///     println!("Balance: {} satoshis", balance.confirmed);
///     
///     Ok(())
/// }
/// ```
pub struct ElectrumClient {
    transport: Transport,
    request_id: AtomicU64,
}

impl ElectrumClient {
    /// Create a new client with SSL connection to the specified server.
    ///
    /// Uses default port 50002 for SSL.
    pub async fn new(server: &str) -> Result<Self> {
        Self::with_config(ClientConfig::ssl(server)).await
    }

    /// Create a new client with custom configuration.
    pub async fn with_config(config: ClientConfig) -> Result<Self> {
        let transport = Transport::connect(config).await?;
        Ok(Self {
            transport,
            request_id: AtomicU64::new(1),
        })
    }

    /// Get the next request ID.
    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }

    // ========== Balance Methods ==========

    /// Get balance for a single address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
    ///
    /// # Returns
    /// * `Balance` with confirmed and unconfirmed amounts in satoshis
    pub async fn get_balance(&self, address: &str) -> Result<Balance> {
        let scripthash = address_to_scripthash(address)?;
        self.get_balance_scripthash(&scripthash).await
    }

    /// Get balance using scripthash directly.
    pub async fn get_balance_scripthash(&self, scripthash: &str) -> Result<Balance> {
        let id = self.next_id();
        let result = self
            .transport
            .request(
                id,
                "blockchain.scripthash.get_balance",
                vec![json!(scripthash)],
            )
            .await?;

        serde_json::from_value(result).map_err(|e| ElectrumError::InvalidResponse(e.to_string()))
    }

    /// Get balances for multiple addresses in a single batch request.
    ///
    /// This is much more efficient than calling `get_balance` multiple times.
    ///
    /// # Arguments
    /// * `addresses` - Slice of Bitcoin addresses
    ///
    /// # Returns
    /// * Vector of `Balance` in the same order as input addresses
    pub async fn get_balances(&self, addresses: &[&str]) -> Result<Vec<Balance>> {
        if addresses.is_empty() {
            return Ok(vec![]);
        }

        // Convert addresses to scripthashes
        let scripthashes: Vec<String> = addresses
            .iter()
            .map(|a| address_to_scripthash(a))
            .collect::<Result<Vec<_>>>()?;

        self.get_balances_scripthash(&scripthashes).await
    }

    /// Get balances using scripthashes directly (batch).
    pub async fn get_balances_scripthash(&self, scripthashes: &[String]) -> Result<Vec<Balance>> {
        if scripthashes.is_empty() {
            return Ok(vec![]);
        }

        let requests: Vec<(u64, &str, Vec<serde_json::Value>)> = scripthashes
            .iter()
            .map(|sh| {
                (
                    self.next_id(),
                    "blockchain.scripthash.get_balance",
                    vec![json!(sh)],
                )
            })
            .collect();

        let results = self.transport.batch_request(requests).await?;

        results
            .into_iter()
            .map(|r| {
                serde_json::from_value(r)
                    .map_err(|e| ElectrumError::InvalidResponse(e.to_string()))
            })
            .collect()
    }

    // ========== UTXO Methods ==========

    /// List unspent outputs (UTXOs) for an address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address
    ///
    /// # Returns
    /// * Vector of `Utxo` for the address
    pub async fn list_unspent(&self, address: &str) -> Result<Vec<Utxo>> {
        let scripthash = address_to_scripthash(address)?;
        self.list_unspent_scripthash(&scripthash).await
    }

    /// List unspent outputs using scripthash directly.
    pub async fn list_unspent_scripthash(&self, scripthash: &str) -> Result<Vec<Utxo>> {
        let id = self.next_id();
        let result = self
            .transport
            .request(
                id,
                "blockchain.scripthash.listunspent",
                vec![json!(scripthash)],
            )
            .await?;

        serde_json::from_value(result).map_err(|e| ElectrumError::InvalidResponse(e.to_string()))
    }

    // ========== Transaction Methods ==========

    /// Get raw transaction by txid.
    ///
    /// # Arguments
    /// * `txid` - Transaction ID (hex)
    ///
    /// # Returns
    /// * Raw transaction hex string
    pub async fn get_transaction(&self, txid: &str) -> Result<String> {
        let id = self.next_id();
        let result = self
            .transport
            .request(id, "blockchain.transaction.get", vec![json!(txid)])
            .await?;

        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ElectrumError::InvalidResponse("Expected string".into()))
    }

    /// Broadcast a signed transaction.
    ///
    /// # Arguments
    /// * `raw_tx` - Signed transaction in hex format
    ///
    /// # Returns
    /// * Transaction ID if broadcast successful
    pub async fn broadcast(&self, raw_tx: &str) -> Result<String> {
        let id = self.next_id();
        let result = self
            .transport
            .request(id, "blockchain.transaction.broadcast", vec![json!(raw_tx)])
            .await?;

        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ElectrumError::InvalidResponse("Expected txid string".into()))
    }

    /// Get transaction history for an address.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address
    ///
    /// # Returns
    /// * Vector of `TxHistory` entries
    pub async fn get_history(&self, address: &str) -> Result<Vec<TxHistory>> {
        let scripthash = address_to_scripthash(address)?;
        self.get_history_scripthash(&scripthash).await
    }

    /// Get transaction history using scripthash directly.
    pub async fn get_history_scripthash(&self, scripthash: &str) -> Result<Vec<TxHistory>> {
        let id = self.next_id();
        let result = self
            .transport
            .request(
                id,
                "blockchain.scripthash.get_history",
                vec![json!(scripthash)],
            )
            .await?;

        serde_json::from_value(result).map_err(|e| ElectrumError::InvalidResponse(e.to_string()))
    }

    // ========== Server Methods ==========

    /// Get server version information.
    ///
    /// Also performs protocol version negotiation.
    pub async fn server_version(&self) -> Result<ServerVersion> {
        let id = self.next_id();
        let result = self
            .transport
            .request(
                id,
                "server.version",
                vec![json!("rustywallet-electrum"), json!("1.4")],
            )
            .await?;

        let arr = result
            .as_array()
            .ok_or_else(|| ElectrumError::InvalidResponse("Expected array".into()))?;

        if arr.len() < 2 {
            return Err(ElectrumError::InvalidResponse(
                "Expected [server, protocol]".into(),
            ));
        }

        Ok(ServerVersion {
            server_software: arr[0].as_str().unwrap_or("unknown").to_string(),
            protocol_version: arr[1].as_str().unwrap_or("unknown").to_string(),
        })
    }

    /// Ping the server to check connection.
    pub async fn ping(&self) -> Result<()> {
        let id = self.next_id();
        self.transport
            .request(id, "server.ping", vec![])
            .await?;
        Ok(())
    }

    /// Get the current block height.
    pub async fn get_block_height(&self) -> Result<u64> {
        let id = self.next_id();
        let result = self
            .transport
            .request(id, "blockchain.headers.subscribe", vec![])
            .await?;

        result
            .get("height")
            .and_then(|h| h.as_u64())
            .ok_or_else(|| ElectrumError::InvalidResponse("Expected height".into()))
    }

    /// Get estimated fee rate (satoshis per kilobyte).
    ///
    /// # Arguments
    /// * `blocks` - Target confirmation blocks (e.g., 1, 6, 144)
    pub async fn estimate_fee(&self, blocks: u32) -> Result<f64> {
        let id = self.next_id();
        let result = self
            .transport
            .request(id, "blockchain.estimatefee", vec![json!(blocks)])
            .await?;

        result
            .as_f64()
            .ok_or_else(|| ElectrumError::InvalidResponse("Expected fee rate".into()))
    }
}
