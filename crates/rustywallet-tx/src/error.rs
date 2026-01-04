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

    /// RBF not enabled on transaction
    #[error("RBF not enabled: transaction has no replaceable inputs")]
    RbfNotEnabled,

    /// RBF fee too low
    #[error("RBF fee too low: current {current} sat, required at least {required} sat")]
    RbfFeeTooLow {
        /// Current fee
        current: u64,
        /// Minimum required fee
        required: u64,
    },

    /// Invalid output index
    #[error("Invalid output index: {0}")]
    InvalidOutputIndex(usize),

    /// Taproot error
    #[error("Taproot error: {0}")]
    TaprootError(String),

    /// MuSig2 error
    #[error("MuSig2 error: {0}")]
    Musig2Error(String),

    /// FROST error
    #[error("FROST error: {0}")]
    FrostError(String),

    /// Silent Payment error
    #[error("Silent Payment error: {0}")]
    SilentPaymentError(String),

    /// Insufficient signatures for threshold
    #[error("Insufficient signatures: need {needed}, have {have}")]
    InsufficientSignatures {
        /// Number of signatures needed
        needed: usize,
        /// Number of signatures available
        have: usize,
    },
}

/// Result type alias for transaction operations.
pub type Result<T> = std::result::Result<T, TxError>;

impl From<rustywallet_musig::MusigError> for TxError {
    fn from(e: rustywallet_musig::MusigError) -> Self {
        TxError::Musig2Error(e.to_string())
    }
}

impl From<rustywallet_frost::error::FrostError> for TxError {
    fn from(e: rustywallet_frost::error::FrostError) -> Self {
        TxError::FrostError(e.to_string())
    }
}

impl From<rustywallet_silent::SilentPaymentError> for TxError {
    fn from(e: rustywallet_silent::SilentPaymentError) -> Self {
        TxError::SilentPaymentError(e.to_string())
    }
}
