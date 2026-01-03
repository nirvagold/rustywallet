//! Error types for CoinJoin operations.

use thiserror::Error;

/// Result type for CoinJoin operations.
pub type Result<T> = std::result::Result<T, CoinJoinError>;

/// Errors that can occur during CoinJoin operations.
#[derive(Debug, Error)]
pub enum CoinJoinError {
    /// Invalid PSBT.
    #[error("Invalid PSBT: {0}")]
    InvalidPsbt(String),

    /// Invalid transaction.
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Insufficient funds.
    #[error("Insufficient funds: need {needed}, have {available}")]
    InsufficientFunds { needed: u64, available: u64 },

    /// Invalid amount.
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// No participants.
    #[error("No participants in CoinJoin")]
    NoParticipants,

    /// Invalid participant.
    #[error("Invalid participant: {0}")]
    InvalidParticipant(String),

    /// Fee calculation error.
    #[error("Fee calculation error: {0}")]
    FeeError(String),

    /// PayJoin protocol error.
    #[error("PayJoin error: {0}")]
    PayJoinError(String),

    /// Invalid output.
    #[error("Invalid output: {0}")]
    InvalidOutput(String),

    /// Unequal outputs.
    #[error("Outputs must be equal: expected {expected}, got {actual}")]
    UnequalOutputs { expected: u64, actual: u64 },

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic error.
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Invalid address.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Verification failed.
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}
