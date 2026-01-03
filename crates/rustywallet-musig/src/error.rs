//! Error types for MuSig2 operations.

use thiserror::Error;

/// Errors that can occur during MuSig2 operations.
#[derive(Debug, Error)]
pub enum MusigError {
    /// Not enough keys for aggregation.
    #[error("Not enough keys: need at least {need}, got {got}")]
    NotEnoughKeys { need: usize, got: usize },

    /// Too many keys for aggregation.
    #[error("Too many keys: {count} exceeds maximum")]
    TooManyKeys { count: usize },

    /// Duplicate key in aggregation.
    #[error("Duplicate key at index {index}")]
    DuplicateKey { index: usize },

    /// Invalid public key.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid secret key.
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Invalid nonce.
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Invalid signature.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Nonce already used (security violation).
    #[error("Nonce reuse detected - this is a critical security violation")]
    NonceReuse,

    /// Missing nonce for signer.
    #[error("Missing nonce for signer at index {index}")]
    MissingNonce { index: usize },

    /// Missing partial signature.
    #[error("Missing partial signature for signer at index {index}")]
    MissingPartialSig { index: usize },

    /// Signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Invalid adaptor signature.
    #[error("Invalid adaptor signature: {0}")]
    InvalidAdaptorSig(String),

    /// Session state error.
    #[error("Invalid session state: {0}")]
    InvalidSessionState(String),

    /// Hex decoding error.
    #[error("Hex decode error: {0}")]
    HexError(String),
}

/// Result type for MuSig2 operations.
pub type Result<T> = std::result::Result<T, MusigError>;
