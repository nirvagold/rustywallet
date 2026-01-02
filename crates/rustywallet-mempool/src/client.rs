//! Mempool.space API client.

use std::time::Duration;

use reqwest::Client;

use crate::error::{MempoolError, Result};
use crate::types::{AddressInfo, BlockInfo, FeeEstimates, Transaction, Utxo};

/// Base URL for mainnet mempool.space API.
pub const MAINNET_URL: &str = "https://mempool.space/api";
/// Base URL for testnet mempool.space API.
pub const TESTNET_URL: &str = "https://mempool.space/testnet/api";
/// Base URL for signet mempool.space API.
pub const SIGNET_URL: &str = "https://mempool.space/signet/api";

/// Mempool.space API client.
///
/// Provides methods for querying fee estimates, address information,
/// transactions, and broadcasting.
///
/// # Example
/// ```no_run
/// use rustywallet_mempool::MempoolClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = MempoolClient::new();
///     
///     // Get fee estimates
///     let fees = client.get_fees().await?;
///     println!("Next block fee: {} sat/vB", fees.fastest_fee);
///     
///     // Get address info
///     let info = client.get_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
///     println!("Balance: {} sats", info.confirmed_balance());
///     
///     Ok(())
/// }
/// ```
pub struct MempoolClient {
    client: Client,
    base_url: String,
}

impl MempoolClient {
    /// Create a new client for mainnet.
    pub fn new() -> Self {
        Self::with_base_url(MAINNET_URL)
    }

    /// Create a new client for testnet.
    pub fn testnet() -> Self {
        Self::with_base_url(TESTNET_URL)
    }

    /// Create a new client for signet.
    pub fn signet() -> Self {
        Self::with_base_url(SIGNET_URL)
    }

    /// Create a new client with custom base URL.
    pub fn with_base_url(base_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the HTTP client (for internal use by extension modules).
    pub fn http_client(&self) -> &Client {
        &self.client
    }

    /// Make a GET request to the API.
    async fn get<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, endpoint);
        
        let response = self.client.get(&url).send().await?;
        
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(MempoolError::RateLimited);
        }
        
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            return Err(MempoolError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        response
            .json()
            .await
            .map_err(|e| MempoolError::ParseError(e.to_string()))
    }

    /// Make a POST request to the API.
    async fn post(&self, endpoint: &str, body: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, endpoint);
        
        let response = self.client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(body.to_string())
            .send()
            .await?;
        
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(MempoolError::RateLimited);
        }
        
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            return Err(MempoolError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        response
            .text()
            .await
            .map_err(|e| MempoolError::ParseError(e.to_string()))
    }

    // ========== Fee Estimation ==========

    /// Get recommended fee estimates.
    ///
    /// Returns fee rates in sat/vB for different confirmation targets.
    pub async fn get_fees(&self) -> Result<FeeEstimates> {
        self.get("/v1/fees/recommended").await
    }

    // ========== Address Methods ==========

    /// Get address information including balance and transaction count.
    pub async fn get_address(&self, address: &str) -> Result<AddressInfo> {
        self.get(&format!("/address/{}", address)).await
    }

    /// Get UTXOs for an address.
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        self.get(&format!("/address/{}/utxo", address)).await
    }

    /// Get transaction history for an address.
    ///
    /// Returns up to 50 most recent transactions.
    pub async fn get_address_txs(&self, address: &str) -> Result<Vec<Transaction>> {
        self.get(&format!("/address/{}/txs", address)).await
    }

    // ========== Transaction Methods ==========

    /// Get transaction details by txid.
    pub async fn get_tx(&self, txid: &str) -> Result<Transaction> {
        self.get(&format!("/tx/{}", txid)).await
    }

    /// Get raw transaction hex by txid.
    pub async fn get_tx_hex(&self, txid: &str) -> Result<String> {
        let url = format!("{}/tx/{}/hex", self.base_url, txid);
        
        let response = self.client.get(&url).send().await?;
        
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            return Err(MempoolError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        response
            .text()
            .await
            .map_err(|e| MempoolError::ParseError(e.to_string()))
    }

    /// Broadcast a signed transaction.
    ///
    /// # Arguments
    /// * `hex` - Raw transaction in hex format
    ///
    /// # Returns
    /// * Transaction ID on success
    pub async fn broadcast(&self, hex: &str) -> Result<String> {
        self.post("/tx", hex).await
    }

    // ========== Block Methods ==========

    /// Get current block height.
    pub async fn get_block_height(&self) -> Result<u64> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        
        let response = self.client.get(&url).send().await?;
        
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            return Err(MempoolError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        let text = response.text().await?;
        text.trim()
            .parse()
            .map_err(|_| MempoolError::ParseError("Invalid block height".into()))
    }

    /// Get block hash by height.
    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        let url = format!("{}/block-height/{}", self.base_url, height);
        
        let response = self.client.get(&url).send().await?;
        
        let status = response.status();
        if !status.is_success() {
            let message = response.text().await.unwrap_or_default();
            return Err(MempoolError::ApiError {
                status: status.as_u16(),
                message,
            });
        }

        response
            .text()
            .await
            .map_err(|e| MempoolError::ParseError(e.to_string()))
    }

    /// Get block information by hash.
    pub async fn get_block(&self, hash: &str) -> Result<BlockInfo> {
        self.get(&format!("/block/{}", hash)).await
    }
}

impl Default for MempoolClient {
    fn default() -> Self {
        Self::new()
    }
}
