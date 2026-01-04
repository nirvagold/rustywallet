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

    // ========== SLIP39 Errors ==========

    /// Invalid SLIP39 threshold
    #[error("Invalid SLIP39 threshold: {0} (must be 1-16 and <= share_count)")]
    InvalidSlip39Threshold(u8),

    /// Invalid SLIP39 share count
    #[error("Invalid SLIP39 share count: {0} (must be 1-16)")]
    InvalidSlip39ShareCount(u8),

    /// Invalid SLIP39 secret length
    #[error("Invalid SLIP39 secret length: {0} (must be at least 16 bytes)")]
    InvalidSlip39SecretLength(usize),

    /// Insufficient SLIP39 shares for recovery
    #[error("Insufficient SLIP39 shares: need {needed}, have {have}")]
    InsufficientSlip39Shares { needed: usize, have: usize },

    /// Invalid SLIP39 checksum
    #[error("Invalid SLIP39 share checksum")]
    InvalidSlip39Checksum,

    /// SLIP39 identifier mismatch
    #[error("SLIP39 shares have different identifiers")]
    Slip39IdentifierMismatch,

    /// Random generation failed
    #[error("Random number generation failed")]
    RandomGenerationFailed,

    /// Invalid SLIP39 group configuration
    #[error("Invalid SLIP39 group configuration: {0}")]
    InvalidSlip39GroupConfig(String),
}
