//! Error types for descriptor parsing and operations

use thiserror::Error;

/// Errors that can occur when working with descriptors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// Invalid descriptor syntax
    #[error("Invalid descriptor syntax at position {position}: {message}")]
    ParseError {
        /// Position in the string where error occurred
        position: usize,
        /// Error message
        message: String,
    },

    /// Invalid checksum
    #[error("Invalid checksum: expected {expected}, got {got}")]
    InvalidChecksum {
        /// Expected checksum
        expected: String,
        /// Actual checksum
        got: String,
    },

    /// Missing checksum
    #[error("Missing checksum")]
    MissingChecksum,

    /// Invalid key
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid extended key
    #[error("Invalid extended key: {0}")]
    InvalidExtendedKey(String),

    /// Invalid derivation path
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// Invalid fingerprint
    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    /// Invalid threshold
    #[error("Invalid threshold: k={k} but n={n}")]
    InvalidThreshold {
        /// Required signatures
        k: usize,
        /// Total keys
        n: usize,
    },

    /// Unsupported descriptor type
    #[error("Unsupported descriptor type: {0}")]
    UnsupportedType(String),

    /// Wildcard not allowed
    #[error("Wildcard not allowed in this context")]
    WildcardNotAllowed,

    /// Index out of range
    #[error("Derivation index out of range: {0}")]
    IndexOutOfRange(u32),

    /// HD derivation error
    #[error("HD derivation error: {0}")]
    DerivationError(String),

    /// Address generation error
    #[error("Address generation error: {0}")]
    AddressError(String),

    /// Script generation error
    #[error("Script generation error: {0}")]
    ScriptError(String),

    /// Empty descriptor
    #[error("Empty descriptor")]
    EmptyDescriptor,

    /// Unexpected end of input
    #[error("Unexpected end of input")]
    UnexpectedEnd,

    /// Unexpected character
    #[error("Unexpected character '{0}' at position {1}")]
    UnexpectedChar(char, usize),
}

impl DescriptorError {
    /// Create a parse error at a specific position
    pub fn parse_error(position: usize, message: impl Into<String>) -> Self {
        Self::ParseError {
            position,
            message: message.into(),
        }
    }
}
