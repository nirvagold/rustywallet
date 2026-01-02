//! Error types for export operations.

use thiserror::Error;

/// Errors that can occur during export operations.
#[derive(Debug, Error)]
pub enum ExportError {
    /// Invalid key
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Serialization failed
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Invalid network
    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    /// Address generation failed
    #[error("Address generation failed: {0}")]
    AddressError(String),
}

/// Result type alias for export operations.
pub type Result<T> = std::result::Result<T, ExportError>;
