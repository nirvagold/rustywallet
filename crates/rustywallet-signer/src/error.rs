//! Error types for rustywallet-signer

use thiserror::Error;

/// Errors that can occur during signing and verification operations
#[derive(Debug, Error)]
pub enum SignerError {
    /// Invalid signature format or length
    #[error("Invalid signature format")]
    InvalidSignature,

    /// Invalid recovery id (must be 0-3)
    #[error("Invalid recovery id: {0}")]
    InvalidRecoveryId(u8),

    /// Failed to recover public key from signature
    #[error("Failed to recover public key")]
    RecoveryFailed,

    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Invalid message hash length (must be 32 bytes)
    #[error("Invalid message hash length: expected 32, got {0}")]
    InvalidHashLength(usize),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Invalid hex string
    #[error("Invalid hex: {0}")]
    InvalidHex(String),

    /// Invalid base64 string
    #[error("Invalid base64: {0}")]
    InvalidBase64(String),

    /// Invalid address format
    #[error("Invalid address format")]
    InvalidAddress,
}
