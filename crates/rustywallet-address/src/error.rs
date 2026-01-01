//! Error types for address operations.

use thiserror::Error;

/// Errors that can occur during address operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AddressError {
    /// Invalid public key provided.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid address format.
    #[error("Invalid address format: {0}")]
    InvalidFormat(String),

    /// Checksum verification failed.
    #[error("Checksum mismatch")]
    ChecksumMismatch,

    /// Unsupported address type.
    #[error("Unsupported address type: {0}")]
    UnsupportedAddressType(String),

    /// Network mismatch.
    #[error("Network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch { expected: String, actual: String },

    /// SegWit requires compressed public key.
    #[error("SegWit requires compressed public key")]
    UncompressedKeyForSegWit,

    /// Invalid Bech32 encoding.
    #[error("Invalid Bech32 encoding: {0}")]
    InvalidBech32(String),

    /// Invalid Base58 encoding.
    #[error("Invalid Base58 encoding: {0}")]
    InvalidBase58(String),
}
