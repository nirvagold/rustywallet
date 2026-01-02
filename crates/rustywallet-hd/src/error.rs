//! Error types for HD wallet operations.

use thiserror::Error;

/// Errors that can occur during HD wallet operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HdError {
    /// Invalid seed length
    #[error("Invalid seed length: expected 64 bytes, got {0}")]
    InvalidSeedLength(usize),

    /// Invalid derived key (zero or >= curve order)
    #[error("Invalid derived key (zero or >= curve order)")]
    InvalidDerivedKey,

    /// Invalid derivation path
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),

    /// Hardened derivation requires private key
    #[error("Hardened derivation requires private key")]
    HardenedFromPublic,

    /// Invalid extended key format
    #[error("Invalid extended key format")]
    InvalidExtendedKey,

    /// Invalid checksum
    #[error("Invalid checksum")]
    InvalidChecksum,

    /// Invalid child number
    #[error("Invalid child number: {0}")]
    InvalidChildNumber(u32),

    /// Key derivation failed
    #[error("Key derivation failed")]
    DerivationFailed,

    /// Invalid version bytes
    #[error("Invalid version bytes")]
    InvalidVersion,

    /// Invalid BIP85 word count
    #[error("Invalid BIP85 word count: {0} (must be 12, 15, 18, 21, or 24)")]
    InvalidBip85WordCount(u32),

    /// Invalid BIP85 byte count
    #[error("Invalid BIP85 byte count: {0} (must be 16-64)")]
    InvalidBip85ByteCount(usize),
}
