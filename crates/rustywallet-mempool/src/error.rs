//! Error types for Mempool.space API client.

use thiserror::Error;

/// Errors that can occur during Mempool API operations.
#[derive(Debug, Error)]
pub enum MempoolError {
    /// HTTP request failed
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// API returned an error response
    #[error("API error ({status}): {message}")]
    ApiError {
        /// HTTP status code
        status: u16,
        /// Error message from API
        message: String,
    },

    /// Failed to parse API response
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Request timeout
    #[error("Request timeout")]
    Timeout,

    /// Rate limited by API
    #[error("Rate limited - too many requests")]
    RateLimited,

    /// Invalid address format
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid transaction ID
    #[error("Invalid txid: {0}")]
    InvalidTxid(String),

    /// Transaction not found
    #[error("Transaction not found: {0}")]
    TxNotFound(String),

    /// Address not found
    #[error("Address not found: {0}")]
    AddressNotFound(String),

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocketError(String),

    /// WebSocket connection closed
    #[error("WebSocket connection closed")]
    WebSocketClosed,

    /// Lightning API error
    #[error("Lightning API error: {0}")]
    LightningError(String),

    /// Mining API error
    #[error("Mining API error: {0}")]
    MiningError(String),
}

/// Result type alias for Mempool operations.
pub type Result<T> = std::result::Result<T, MempoolError>;
