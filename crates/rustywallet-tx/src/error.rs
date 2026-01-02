//! Error types for transaction operations.

use thiserror::Error;

/// Errors that can occur during transaction operations.
#[derive(Debug, Error)]
pub enum TxError {
    /// Insufficient funds to cover outputs + fees
    #[error("Insufficient funds: need {needed} sat, have {available} sat")]
    InsufficientFunds {
        /// Amount needed (outputs + fees)
        needed: u64,
        /// Amount available from UTXOs
        available: u64,
    },

    /// Invalid address format
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid UTXO
    #[error("Invalid UTXO: {0}")]
    InvalidUtxo(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Serialization failed
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    /// Output amount below dust threshold
    #[error("Dust output: {0} sat is below dust threshold")]
    DustOutput(u64),

    /// No inputs provided
    #[error("No inputs provided")]
    NoInputs,

    /// No outputs provided
    #[error("No outputs provided")]
    NoOutputs,

    /// Invalid transaction structure
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Input index out of bounds
    #[error("Input index {index} out of bounds (have {count} inputs)")]
    InputIndexOutOfBounds {
        /// Requested index
        index: usize,
        /// Number of inputs
        count: usize,
    },
}

/// Result type alias for transaction operations.
pub type Result<T> = std::result::Result<T, TxError>;
