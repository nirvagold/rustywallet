//! Error types for mnemonic operations.

use thiserror::Error;

/// Errors that can occur during mnemonic operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MnemonicError {
    /// Invalid word count (must be 12, 15, 18, 21, or 24)
    #[error("Invalid word count: {0}. Must be 12, 15, 18, 21, or 24")]
    InvalidWordCount(usize),

    /// Word not found in wordlist
    #[error("Invalid word: '{0}' not in wordlist")]
    InvalidWord(String),

    /// Checksum validation failed
    #[error("Invalid checksum")]
    InvalidChecksum,

    /// Invalid entropy length
    #[error("Invalid entropy length: expected {expected}, got {actual}")]
    InvalidEntropyLength { expected: usize, actual: usize },

    /// Empty mnemonic phrase
    #[error("Empty mnemonic phrase")]
    EmptyPhrase,

    /// Invalid private key derived from seed
    #[error("Invalid private key derived from seed")]
    InvalidPrivateKey,
}
