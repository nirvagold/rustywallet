//! Error types for vanity address generation.

use thiserror::Error;

/// Errors that can occur during vanity address generation.
#[derive(Debug, Error)]
pub enum VanityError {
    /// Invalid pattern provided.
    #[error("Invalid pattern: {0}")]
    InvalidPattern(#[from] PatternError),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Search timed out.
    #[error("Search timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Maximum attempts reached without finding a match.
    #[error("Maximum attempts ({0}) reached without finding a match")]
    MaxAttemptsReached(u64),

    /// Search was cancelled.
    #[error("Search was cancelled")]
    Cancelled,

    /// Key generation error.
    #[error("Key generation error: {0}")]
    GenerationError(String),

    /// Address derivation error.
    #[error("Address derivation error: {0}")]
    AddressError(String),
}

/// Errors related to pattern validation.
#[derive(Debug, Error, Clone)]
pub enum PatternError {
    /// Pattern is empty.
    #[error("Pattern cannot be empty")]
    EmptyPattern,

    /// Pattern contains invalid character for the address type.
    #[error("Invalid character '{0}' for this address type")]
    InvalidCharacter(char),

    /// Pattern is too long to be practical.
    #[error("Pattern too long ({0} chars), maximum recommended is 8")]
    PatternTooLong(usize),

    /// Pattern is incompatible with the selected address type.
    #[error("Pattern '{0}' is incompatible with address type {1}")]
    IncompatibleWithAddressType(String, String),

    /// Invalid regex pattern.
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),

    /// Pattern conflicts with fixed prefix.
    #[error("Pattern '{0}' conflicts with fixed prefix '{1}' for this address type")]
    ConflictsWithPrefix(String, String),
}
