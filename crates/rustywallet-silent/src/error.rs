//! Error types for Silent Payments.

use thiserror::Error;

/// Result type for Silent Payment operations.
pub type Result<T> = std::result::Result<T, SilentPaymentError>;

/// Errors that can occur during Silent Payment operations.
#[derive(Debug, Error)]
pub enum SilentPaymentError {
    /// Invalid address format.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid public key.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid private key.
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid network.
    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    /// Bech32 encoding/decoding error.
    #[error("Bech32 error: {0}")]
    Bech32Error(String),

    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// No inputs provided.
    #[error("No inputs provided")]
    NoInputs,

    /// No recipients provided.
    #[error("No recipients provided")]
    NoRecipients,

    /// Invalid label.
    #[error("Invalid label: {0}")]
    InvalidLabel(String),

    /// Hex encoding/decoding error.
    #[error("Hex error: {0}")]
    HexError(String),

    /// Scanning error.
    #[error("Scanning error: {0}")]
    ScanningError(String),
}
