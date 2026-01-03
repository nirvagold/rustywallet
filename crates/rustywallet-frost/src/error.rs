//! Error types for FROST operations.

use thiserror::Error;

/// Result type for FROST operations.
pub type Result<T> = std::result::Result<T, FrostError>;

/// Errors that can occur during FROST operations.
#[derive(Debug, Error)]
pub enum FrostError {
    /// Invalid threshold configuration.
    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),

    /// Invalid participant identifier.
    #[error("Invalid participant: {0}")]
    InvalidParticipant(String),

    /// Invalid secret share.
    #[error("Invalid secret share: {0}")]
    InvalidShare(String),

    /// Invalid commitment.
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    /// Invalid signature.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Verification failed.
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// DKG error.
    #[error("DKG error: {0}")]
    DkgError(String),

    /// Signing error.
    #[error("Signing error: {0}")]
    SigningError(String),

    /// Malicious participant detected.
    #[error("Malicious participant detected: {0}")]
    MaliciousParticipant(String),

    /// Insufficient signers.
    #[error("Insufficient signers: need {needed}, got {got}")]
    InsufficientSigners { needed: usize, got: usize },

    /// Duplicate participant.
    #[error("Duplicate participant: {0}")]
    DuplicateParticipant(u32),

    /// Missing data.
    #[error("Missing data: {0}")]
    MissingData(String),

    /// Hex encoding/decoding error.
    #[error("Hex error: {0}")]
    HexError(String),

    /// Cryptographic error.
    #[error("Crypto error: {0}")]
    CryptoError(String),
}
