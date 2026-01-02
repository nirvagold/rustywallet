//! Error types for import operations.

use thiserror::Error;

/// Errors that can occur during import operations.
#[derive(Debug, Error)]
pub enum ImportError {
    /// Invalid format - cannot parse input
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Invalid checksum in encoded data
    #[error("Invalid checksum")]
    InvalidChecksum,

    /// Invalid WIF format
    #[error("Invalid WIF: {0}")]
    InvalidWif(String),

    /// Invalid hex format
    #[error("Invalid hex: {0}")]
    InvalidHex(String),

    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid mini private key
    #[error("Invalid mini key: {0}")]
    InvalidMiniKey(String),

    /// Invalid BIP38 encrypted key
    #[error("Invalid BIP38: {0}")]
    InvalidBip38(String),

    /// Wrong password for BIP38 decryption
    #[error("Wrong password")]
    WrongPassword,

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Unsupported format
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    /// Private key out of valid range
    #[error("Private key out of range")]
    KeyOutOfRange,
}

/// Result type alias for import operations.
pub type Result<T> = std::result::Result<T, ImportError>;
