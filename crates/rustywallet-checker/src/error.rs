//! Error types for rustywallet-checker

use thiserror::Error;

/// Errors that can occur when checking balances
#[derive(Debug, Error)]
pub enum CheckerError {
    /// Network/HTTP error
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    /// Invalid address format
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// API returned an error
    #[error("API error: {0}")]
    ApiError(String),

    /// Rate limited by API
    #[error("Rate limited, please try again later")]
    RateLimited,

    /// Failed to parse response
    #[error("Parse error: {0}")]
    ParseError(String),
}
