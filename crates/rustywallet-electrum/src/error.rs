//! Error types for Electrum client operations.

use thiserror::Error;

/// Errors that can occur during Electrum client operations.
#[derive(Debug, Error)]
pub enum ElectrumError {
    /// Failed to connect to server
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection timeout
    #[error("Connection timeout")]
    Timeout,

    /// Server returned an error
    #[error("Server error ({code}): {message}")]
    ServerError {
        /// Error code from server
        code: i32,
        /// Error message from server
        message: String,
    },

    /// Invalid Bitcoin address
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid response from server
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// TLS/SSL error
    #[error("TLS error: {0}")]
    TlsError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON parsing error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Request ID mismatch
    #[error("Request ID mismatch: expected {expected}, got {got}")]
    IdMismatch {
        /// Expected request ID
        expected: u64,
        /// Received request ID
        got: u64,
    },

    /// Server disconnected
    #[error("Server disconnected")]
    Disconnected,

    /// Invalid scripthash
    #[error("Invalid scripthash: {0}")]
    InvalidScripthash(String),

    /// Certificate pinning failed
    #[error("Certificate pinning failed: {0}")]
    CertificatePinningFailed(String),

    /// No servers available
    #[error("No servers available")]
    NoServersAvailable,

    /// Pool exhausted
    #[error("Connection pool exhausted")]
    PoolExhausted,

    /// Subscription error
    #[error("Subscription error: {0}")]
    SubscriptionError(String),
}

/// Result type alias for Electrum operations.
pub type Result<T> = std::result::Result<T, ElectrumError>;
