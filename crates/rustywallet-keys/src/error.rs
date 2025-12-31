//! Error types for rustywallet-keys
//!
//! This module provides error types for private key and public key operations.

use thiserror::Error;

/// Errors that can occur when working with private keys.
#[derive(Debug, Error)]
pub enum PrivateKeyError {
    /// The provided key has an invalid length.
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),

    /// The provided hex string is invalid.
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    /// The provided WIF string is invalid.
    #[error("Invalid WIF format: {0}")]
    InvalidWif(String),

    /// The key value is out of the valid range (must be 1 to curve order - 1).
    #[error("Key out of range: must be between 1 and curve order - 1")]
    OutOfRange,

    /// The WIF checksum is invalid.
    #[error("Invalid checksum in WIF")]
    InvalidChecksum,
}

/// Errors that can occur when working with public keys.
#[derive(Debug, Error)]
pub enum PublicKeyError {
    /// The provided key has an invalid length.
    #[error("Invalid key length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    /// The provided hex string is invalid.
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    /// The provided bytes do not represent a valid point on the curve.
    #[error("Invalid public key point")]
    InvalidPoint,
}

/// Unified error type for the crate.
///
/// This error type wraps both [`PrivateKeyError`] and [`PublicKeyError`]
/// for convenient error handling in user code.
#[derive(Debug, Error)]
pub enum KeyError {
    /// A private key error.
    #[error(transparent)]
    PrivateKey(#[from] PrivateKeyError),

    /// A public key error.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
}
