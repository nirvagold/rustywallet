//! Data types for Electrum protocol responses.

use serde::{Deserialize, Serialize};

/// Balance information for an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// Confirmed balance in satoshis
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis (can be negative when spending)
    pub unconfirmed: i64,
}

impl Balance {
    /// Returns the total balance (confirmed + unconfirmed).
    /// Note: This can be less than confirmed if there are unconfirmed spends.
    #[inline]
    pub fn total(&self) -> i64 {
        self.confirmed as i64 + self.unconfirmed
    }

    /// Returns true if the address has any balance (confirmed or unconfirmed).
    #[inline]
    pub fn has_balance(&self) -> bool {
        self.confirmed > 0 || self.unconfirmed != 0
    }

    /// Returns true if there are unconfirmed transactions.
    #[inline]
    pub fn has_unconfirmed(&self) -> bool {
        self.unconfirmed != 0
    }
}

/// Unspent transaction output (UTXO).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction ID (hex)
    #[serde(rename = "tx_hash")]
    pub txid: String,
    /// Output index
    #[serde(rename = "tx_pos")]
    pub vout: u32,
    /// Value in satoshis
    pub value: u64,
    /// Block height (0 = unconfirmed)
    pub height: u64,
}

impl Utxo {
    /// Returns true if this UTXO is confirmed.
    #[inline]
    pub fn is_confirmed(&self) -> bool {
        self.height > 0
    }

    /// Returns the outpoint string (txid:vout).
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }
}

/// Transaction history entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxHistory {
    /// Transaction ID (hex)
    #[serde(rename = "tx_hash")]
    pub txid: String,
    /// Block height (-1 = unconfirmed in mempool)
    pub height: i64,
    /// Transaction fee in satoshis (optional)
    #[serde(default)]
    pub fee: Option<u64>,
}

impl TxHistory {
    /// Returns true if this transaction is confirmed.
    #[inline]
    pub fn is_confirmed(&self) -> bool {
        self.height > 0
    }
}

/// Server version information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerVersion {
    /// Server software name and version
    pub server_software: String,
    /// Protocol version supported
    pub protocol_version: String,
}

/// Server features and capabilities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerFeatures {
    /// Server software identification
    #[serde(default)]
    pub server_version: String,
    /// Protocol version
    #[serde(default)]
    pub protocol_max: String,
    /// Genesis block hash
    #[serde(default)]
    pub genesis_hash: String,
    /// Hash function used
    #[serde(default)]
    pub hash_function: String,
}

/// Configuration for Electrum client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Server hostname or IP
    pub server: String,
    /// Server port
    pub port: u16,
    /// Use TLS/SSL connection
    pub use_tls: bool,
    /// Connection timeout
    pub timeout: std::time::Duration,
    /// Number of retry attempts
    pub retry_count: u32,
    /// Delay between retries
    pub retry_delay: std::time::Duration,
    /// Skip TLS certificate validation (INSECURE - for testing only)
    pub skip_tls_verify: bool,
}

impl ClientConfig {
    /// Create config for TCP connection (port 50001).
    pub fn tcp(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            port: 50001,
            use_tls: false,
            timeout: std::time::Duration::from_secs(30),
            retry_count: 3,
            retry_delay: std::time::Duration::from_secs(1),
            skip_tls_verify: false,
        }
    }

    /// Create config for SSL/TLS connection (port 50002).
    pub fn ssl(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            port: 50002,
            use_tls: true,
            timeout: std::time::Duration::from_secs(30),
            retry_count: 3,
            retry_delay: std::time::Duration::from_secs(1),
            skip_tls_verify: false,
        }
    }

    /// Set custom port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set retry configuration.
    pub fn with_retry(mut self, count: u32, delay: std::time::Duration) -> Self {
        self.retry_count = count;
        self.retry_delay = delay;
        self
    }

    /// Skip TLS certificate validation (INSECURE - for testing only).
    /// 
    /// # Warning
    /// This disables certificate validation and should only be used for testing
    /// with self-signed certificates. Never use in production!
    pub fn with_skip_tls_verify(mut self) -> Self {
        self.skip_tls_verify = true;
        self
    }

    /// Get the full server address (host:port).
    pub fn address(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::ssl("electrum.blockstream.info")
    }
}

/// Built-in list of public Electrum servers.
pub const DEFAULT_SERVERS: &[(&str, u16, bool)] = &[
    ("electrum.blockstream.info", 50002, true),
    ("electrum.blockstream.info", 50001, false),
    ("electrum1.bluewallet.io", 443, true),
    ("electrum2.bluewallet.io", 443, true),
    ("bitcoin.aranguren.org", 50002, true),
    ("electrum.bitaroo.net", 50002, true),
];
