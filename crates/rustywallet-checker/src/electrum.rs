//! Electrum backend for balance checking.
//!
//! Uses the Electrum protocol for direct blockchain queries without rate limits.

use crate::bitcoin::BitcoinBalance;
use crate::error::CheckerError;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Electrum backend configuration.
#[derive(Debug, Clone)]
pub struct ElectrumConfig {
    /// Primary server hostname
    pub server: String,
    /// Server port (default: 50002 for SSL)
    pub port: u16,
    /// Use SSL/TLS connection
    pub use_ssl: bool,
    /// Connection timeout
    pub timeout: Duration,
    /// Enable connection caching
    pub cache_connections: bool,
    /// Fallback to API providers on failure
    pub fallback_to_api: bool,
}

impl Default for ElectrumConfig {
    fn default() -> Self {
        Self {
            server: "electrum.blockstream.info".to_string(),
            port: 50002,
            use_ssl: true,
            timeout: Duration::from_secs(30),
            cache_connections: true,
            fallback_to_api: true,
        }
    }
}

impl ElectrumConfig {
    /// Create a new Electrum configuration.
    pub fn new(server: &str) -> Self {
        Self {
            server: server.to_string(),
            ..Default::default()
        }
    }

    /// Set the server port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Enable or disable SSL.
    pub fn with_ssl(mut self, use_ssl: bool) -> Self {
        self.use_ssl = use_ssl;
        self
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable or disable connection caching.
    pub fn with_cache(mut self, cache: bool) -> Self {
        self.cache_connections = cache;
        self
    }

    /// Enable or disable API fallback.
    pub fn with_fallback(mut self, fallback: bool) -> Self {
        self.fallback_to_api = fallback;
        self
    }
}

/// Cached connection state.
struct CachedConnection {
    #[allow(dead_code)]
    server: String,
    #[allow(dead_code)]
    connected_at: std::time::Instant,
}

/// Electrum balance checker with connection caching.
pub struct ElectrumChecker {
    config: ElectrumConfig,
    connection_cache: Arc<RwLock<Option<CachedConnection>>>,
}

impl ElectrumChecker {
    /// Create a new Electrum checker with default configuration.
    pub fn new() -> Self {
        Self::with_config(ElectrumConfig::default())
    }

    /// Create a new Electrum checker with custom configuration.
    pub fn with_config(config: ElectrumConfig) -> Self {
        Self {
            config,
            connection_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Check balance for a single Bitcoin address using Electrum.
    pub async fn check_balance(&self, address: &str) -> Result<BitcoinBalance, CheckerError> {
        // Try Electrum first
        match self.check_via_electrum(address).await {
            Ok(balance) => Ok(balance),
            Err(e) => {
                // Fallback to API if enabled
                if self.config.fallback_to_api {
                    crate::bitcoin::check_btc_balance(address).await
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Check balances for multiple addresses in batch.
    ///
    /// This is more efficient than checking addresses one by one.
    pub async fn check_balances_batch(
        &self,
        addresses: &[&str],
    ) -> Result<Vec<BitcoinBalance>, CheckerError> {
        // Try Electrum batch first
        match self.check_batch_via_electrum(addresses).await {
            Ok(balances) => Ok(balances),
            Err(e) => {
                // Fallback to API if enabled
                if self.config.fallback_to_api {
                    let mut results = Vec::with_capacity(addresses.len());
                    for addr in addresses {
                        results.push(crate::bitcoin::check_btc_balance(addr).await?);
                    }
                    Ok(results)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Internal: Check balance via Electrum protocol.
    async fn check_via_electrum(&self, address: &str) -> Result<BitcoinBalance, CheckerError> {
        // Use rustywallet-electrum if available
        #[cfg(feature = "electrum")]
        {
            use rustywallet_electrum::{ElectrumClient, ClientConfig};
            
            let config = if self.config.use_ssl {
                ClientConfig::ssl(&self.config.server)
                    .with_port(self.config.port)
                    .with_timeout(self.config.timeout)
            } else {
                ClientConfig::tcp(&self.config.server)
                    .with_port(self.config.port)
                    .with_timeout(self.config.timeout)
            };
            
            let client = ElectrumClient::with_config(config)
                .await
                .map_err(|e| CheckerError::Network(e.into()))?;
            
            // Update cache
            if self.config.cache_connections {
                let mut cache = self.connection_cache.write().await;
                *cache = Some(CachedConnection {
                    server: self.config.server.clone(),
                    connected_at: std::time::Instant::now(),
                });
            }
            
            let balance = client
                .get_balance(address)
                .await
                .map_err(|e| CheckerError::ApiError(e.to_string()))?;
            
            // Get transaction history for tx_count
            let history = client
                .get_history(address)
                .await
                .map_err(|e| CheckerError::ApiError(e.to_string()))?;
            
            Ok(BitcoinBalance {
                address: address.to_string(),
                balance: balance.confirmed,
                unconfirmed: balance.unconfirmed as i64,
                total_received: balance.confirmed + balance.unconfirmed.unsigned_abs(),
                total_sent: 0, // Would need full history analysis
                tx_count: history.len() as u64,
            })
        }
        
        #[cfg(not(feature = "electrum"))]
        {
            // Fallback: use simple TCP connection to Electrum server
            self.check_via_simple_electrum(address).await
        }
    }

    /// Internal: Check balances in batch via Electrum.
    async fn check_batch_via_electrum(
        &self,
        addresses: &[&str],
    ) -> Result<Vec<BitcoinBalance>, CheckerError> {
        #[cfg(feature = "electrum")]
        {
            use rustywallet_electrum::{ElectrumClient, ClientConfig};
            
            let config = if self.config.use_ssl {
                ClientConfig::ssl(&self.config.server)
                    .with_port(self.config.port)
                    .with_timeout(self.config.timeout)
            } else {
                ClientConfig::tcp(&self.config.server)
                    .with_port(self.config.port)
                    .with_timeout(self.config.timeout)
            };
            
            let client = ElectrumClient::with_config(config)
                .await
                .map_err(|e| CheckerError::Network(e.into()))?;
            
            // Batch query balances
            let balances = client
                .get_balances(addresses)
                .await
                .map_err(|e| CheckerError::ApiError(e.to_string()))?;
            
            let mut results = Vec::with_capacity(addresses.len());
            for (addr, balance) in addresses.iter().zip(balances.iter()) {
                results.push(BitcoinBalance {
                    address: addr.to_string(),
                    balance: balance.confirmed,
                    unconfirmed: balance.unconfirmed as i64,
                    total_received: balance.confirmed + balance.unconfirmed.unsigned_abs(),
                    total_sent: 0,
                    tx_count: 0, // Would need separate history query
                });
            }
            
            Ok(results)
        }
        
        #[cfg(not(feature = "electrum"))]
        {
            // Fallback: check one by one
            let mut results = Vec::with_capacity(addresses.len());
            for addr in addresses {
                results.push(self.check_via_simple_electrum(addr).await?);
            }
            Ok(results)
        }
    }

    /// Simple Electrum protocol implementation (fallback when electrum feature is disabled).
    #[cfg(not(feature = "electrum"))]
    async fn check_via_simple_electrum(&self, address: &str) -> Result<BitcoinBalance, CheckerError> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;
        
        // Convert address to scripthash
        let scripthash = address_to_scripthash(address)?;
        
        // Connect to server
        let addr = format!("{}:{}", self.config.server, self.config.port);
        
        let stream = tokio::time::timeout(
            self.config.timeout,
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| CheckerError::IoError("Connection timeout".to_string()))?
        .map_err(|e| CheckerError::IoError(e.to_string()))?;
        
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        
        // Send balance request
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "blockchain.scripthash.get_balance",
            "params": [scripthash]
        });
        
        writer.write_all(request.to_string().as_bytes()).await
            .map_err(|e| CheckerError::IoError(e.to_string()))?;
        writer.write_all(b"\n").await
            .map_err(|e| CheckerError::IoError(e.to_string()))?;
        
        // Read response
        let mut response = String::new();
        reader.read_line(&mut response).await
            .map_err(|e| CheckerError::IoError(e.to_string()))?;
        
        let json: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| CheckerError::ParseError(e.to_string()))?;
        
        let result = json.get("result")
            .ok_or_else(|| CheckerError::ApiError("No result in response".to_string()))?;
        
        let confirmed = result.get("confirmed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let unconfirmed = result.get("unconfirmed")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        
        Ok(BitcoinBalance {
            address: address.to_string(),
            balance: confirmed,
            unconfirmed,
            total_received: confirmed + unconfirmed.unsigned_abs(),
            total_sent: 0,
            tx_count: 0,
        })
    }

    /// Clear the connection cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.connection_cache.write().await;
        *cache = None;
    }

    /// Check if there's a cached connection.
    pub async fn has_cached_connection(&self) -> bool {
        let cache = self.connection_cache.read().await;
        cache.is_some()
    }
}

impl Default for ElectrumChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a Bitcoin address to Electrum scripthash format.
#[cfg(not(feature = "electrum"))]
fn address_to_scripthash(address: &str) -> Result<String, CheckerError> {
    use sha2::{Sha256, Digest};
    
    // Decode address to script
    let script = address_to_script(address)?;
    
    // SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(&script);
    let hash = hasher.finalize();
    
    // Reverse bytes for Electrum format
    let reversed: Vec<u8> = hash.iter().rev().cloned().collect();
    
    Ok(hex::encode(reversed))
}

/// Convert address to output script (simplified).
#[cfg(not(feature = "electrum"))]
fn address_to_script(address: &str) -> Result<Vec<u8>, CheckerError> {
    // P2PKH (1...)
    if address.starts_with('1') {
        let decoded = bs58::decode(address)
            .into_vec()
            .map_err(|_| CheckerError::InvalidAddress(address.to_string()))?;
        
        // Base58Check: 1 byte version + 20 bytes hash + 4 bytes checksum = 25 bytes
        if decoded.len() != 25 {
            return Err(CheckerError::InvalidAddress(address.to_string()));
        }
        
        let pubkey_hash = &decoded[1..21];
        let mut script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20
        script.extend_from_slice(pubkey_hash);
        script.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
        
        return Ok(script);
    }
    
    // P2SH (3...)
    if address.starts_with('3') {
        let decoded = bs58::decode(address)
            .into_vec()
            .map_err(|_| CheckerError::InvalidAddress(address.to_string()))?;
        
        // Base58Check: 1 byte version + 20 bytes hash + 4 bytes checksum = 25 bytes
        if decoded.len() != 25 {
            return Err(CheckerError::InvalidAddress(address.to_string()));
        }
        
        let script_hash = &decoded[1..21];
        let mut script = vec![0xa9, 0x14]; // OP_HASH160 PUSH20
        script.extend_from_slice(script_hash);
        script.push(0x87); // OP_EQUAL
        
        return Ok(script);
    }
    
    // Bech32 (bc1...)
    if address.starts_with("bc1") || address.starts_with("tb1") {
        let (_hrp, data) = bech32_decode(address)?;
        
        if data.is_empty() {
            return Err(CheckerError::InvalidAddress(address.to_string()));
        }
        
        let version = data[0];
        let program: Vec<u8> = convert_bits(&data[1..], 5, 8, false)?;
        
        // Build witness script
        let mut script = Vec::new();
        if version == 0 {
            script.push(0x00); // OP_0
        } else {
            script.push(0x50 + version); // OP_1 through OP_16
        }
        script.push(program.len() as u8);
        script.extend_from_slice(&program);
        
        return Ok(script);
    }
    
    Err(CheckerError::InvalidAddress(address.to_string()))
}

/// Simple bech32 decoder.
#[cfg(not(feature = "electrum"))]
fn bech32_decode(address: &str) -> Result<(String, Vec<u8>), CheckerError> {
    let address = address.to_lowercase();
    let pos = address.rfind('1')
        .ok_or_else(|| CheckerError::InvalidAddress(address.clone()))?;
    
    let hrp = &address[..pos];
    let data_part = &address[pos + 1..];
    
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    
    let mut data = Vec::new();
    for c in data_part.chars() {
        let idx = CHARSET.find(c)
            .ok_or_else(|| CheckerError::InvalidAddress(address.clone()))?;
        data.push(idx as u8);
    }
    
    // Remove checksum (last 6 characters)
    if data.len() < 6 {
        return Err(CheckerError::InvalidAddress(address.clone()));
    }
    data.truncate(data.len() - 6);
    
    Ok((hrp.to_string(), data))
}

/// Convert bits between bases.
#[cfg(not(feature = "electrum"))]
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, CheckerError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << to) - 1;
    
    for &value in data {
        let value = value as u32;
        if (value >> from) != 0 {
            return Err(CheckerError::InvalidAddress("Invalid data".to_string()));
        }
        acc = (acc << from) | value;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(CheckerError::InvalidAddress("Invalid padding".to_string()));
    }
    
    Ok(ret)
}

/// Check Bitcoin balance using Electrum backend.
///
/// This is a convenience function that creates a temporary ElectrumChecker.
///
/// # Example
///
/// ```no_run
/// use rustywallet_checker::electrum::check_btc_balance_electrum;
///
/// #[tokio::main]
/// async fn main() {
///     let balance = check_btc_balance_electrum("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await.unwrap();
///     println!("Balance: {} satoshis", balance.balance);
/// }
/// ```
pub async fn check_btc_balance_electrum(address: &str) -> Result<BitcoinBalance, CheckerError> {
    let checker = ElectrumChecker::new();
    checker.check_balance(address).await
}

/// Check multiple Bitcoin balances using Electrum backend.
///
/// More efficient than checking addresses one by one.
///
/// # Example
///
/// ```no_run
/// use rustywallet_checker::electrum::check_btc_balances_batch;
///
/// #[tokio::main]
/// async fn main() {
///     let addresses = vec![
///         "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
///         "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
///     ];
///     let balances = check_btc_balances_batch(&addresses).await.unwrap();
///     for balance in balances {
///         println!("{}: {} satoshis", balance.address, balance.balance);
///     }
/// }
/// ```
pub async fn check_btc_balances_batch(addresses: &[&str]) -> Result<Vec<BitcoinBalance>, CheckerError> {
    let checker = ElectrumChecker::new();
    checker.check_balances_batch(addresses).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_electrum_config_default() {
        let config = ElectrumConfig::default();
        assert_eq!(config.server, "electrum.blockstream.info");
        assert_eq!(config.port, 50002);
        assert!(config.use_ssl);
        assert!(config.cache_connections);
        assert!(config.fallback_to_api);
    }

    #[test]
    fn test_electrum_config_builder() {
        let config = ElectrumConfig::new("custom.server.com")
            .with_port(50001)
            .with_ssl(false)
            .with_cache(false)
            .with_fallback(false);
        
        assert_eq!(config.server, "custom.server.com");
        assert_eq!(config.port, 50001);
        assert!(!config.use_ssl);
        assert!(!config.cache_connections);
        assert!(!config.fallback_to_api);
    }

    #[test]
    fn test_electrum_checker_creation() {
        let checker = ElectrumChecker::new();
        assert_eq!(checker.config.server, "electrum.blockstream.info");
    }

    #[cfg(not(feature = "electrum"))]
    #[test]
    fn test_address_to_scripthash_p2pkh() {
        // Known test vector
        let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let result = address_to_scripthash(address);
        assert!(result.is_ok());
        let scripthash = result.unwrap();
        assert_eq!(scripthash.len(), 64); // 32 bytes hex
    }

    #[cfg(not(feature = "electrum"))]
    #[test]
    fn test_address_to_script_p2pkh() {
        let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let result = address_to_script(address);
        assert!(result.is_ok());
        let script = result.unwrap();
        assert_eq!(script[0], 0x76); // OP_DUP
        assert_eq!(script[1], 0xa9); // OP_HASH160
    }

    #[cfg(not(feature = "electrum"))]
    #[test]
    fn test_bech32_decode() {
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let result = bech32_decode(address);
        assert!(result.is_ok());
        let (hrp, data) = result.unwrap();
        assert_eq!(hrp, "bc");
        assert!(!data.is_empty());
    }
}
