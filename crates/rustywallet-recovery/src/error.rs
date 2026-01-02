//! Error types for wallet recovery
//!
//! Defines all error types that can occur during wallet recovery operations.

use thiserror::Error;

/// Errors that can occur during wallet recovery
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid extended public key
    #[error("Invalid xpub: {0}")]
    InvalidXpub(String),

    /// Invalid extended private key
    #[error("Invalid xprv: {0}")]
    InvalidXprv(String),

    /// Invalid derivation path
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),

    /// Backend/network error
    #[error("Backend error: {0}")]
    BackendError(String),

    /// Network connection error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// API rate limit exceeded
    #[error("Rate limited - please wait before retrying")]
    RateLimited,

    /// Scan was interrupted
    #[error("Scan interrupted")]
    ScanInterrupted,

    /// Address derivation error
    #[error("Address derivation error: {0}")]
    DerivationError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<rustywallet_mnemonic::MnemonicError> for RecoveryError {
    fn from(e: rustywallet_mnemonic::MnemonicError) -> Self {
        RecoveryError::InvalidMnemonic(e.to_string())
    }
}

impl From<rustywallet_hd::HdError> for RecoveryError {
    fn from(e: rustywallet_hd::HdError) -> Self {
        RecoveryError::DerivationError(e.to_string())
    }
}

impl From<rustywallet_electrum::ElectrumError> for RecoveryError {
    fn from(e: rustywallet_electrum::ElectrumError) -> Self {
        RecoveryError::BackendError(e.to_string())
    }
}

impl From<serde_json::Error> for RecoveryError {
    fn from(e: serde_json::Error) -> Self {
        RecoveryError::SerializationError(e.to_string())
    }
}
