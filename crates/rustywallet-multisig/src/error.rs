//! Error types for multisig operations.

use thiserror::Error;

/// Result type for multisig operations.
pub type Result<T> = std::result::Result<T, MultisigError>;

/// Errors that can occur during multisig operations.
#[derive(Debug, Error)]
pub enum MultisigError {
    /// Invalid threshold (M must be >= 1 and <= N)
    #[error("Invalid threshold: M={m} must be >= 1 and <= N={n}")]
    InvalidThreshold { m: u8, n: u8 },

    /// Too many keys (max 15 for standard multisig)
    #[error("Too many keys: {count} (max 15)")]
    TooManyKeys { count: usize },

    /// Not enough keys
    #[error("Not enough keys: need {need}, got {got}")]
    NotEnoughKeys { need: usize, got: usize },

    /// Duplicate public key
    #[error("Duplicate public key at index {index}")]
    DuplicateKey { index: usize },

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid redeem script
    #[error("Invalid redeem script: {0}")]
    InvalidRedeemScript(String),

    /// Not enough signatures
    #[error("Not enough signatures: need {need}, got {got}")]
    NotEnoughSignatures { need: usize, got: usize },

    /// Invalid signature
    #[error("Invalid signature at index {index}: {reason}")]
    InvalidSignature { index: usize, reason: String },

    /// Shamir share error
    #[error("Shamir error: {0}")]
    ShamirError(String),

    /// Invalid share index
    #[error("Invalid share index: {0} (must be 1-255)")]
    InvalidShareIndex(u8),

    /// Duplicate share index
    #[error("Duplicate share index: {0}")]
    DuplicateShareIndex(u8),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Address generation failed
    #[error("Address generation failed: {0}")]
    AddressFailed(String),
}
