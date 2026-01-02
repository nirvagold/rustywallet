//! Taproot error types

use thiserror::Error;

/// Errors that can occur when working with Taproot
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TaprootError {
    /// Invalid x-only public key
    #[error("invalid x-only public key")]
    InvalidXOnlyKey,

    /// Invalid signature
    #[error("invalid signature")]
    InvalidSignature,

    /// Invalid tweak value
    #[error("invalid tweak: {0}")]
    InvalidTweak(String),

    /// Invalid leaf version
    #[error("invalid leaf version: 0x{0:02x}")]
    InvalidLeafVersion(u8),

    /// Invalid control block
    #[error("invalid control block: {0}")]
    InvalidControlBlock(String),

    /// Tree construction error
    #[error("tree construction error: {0}")]
    TreeError(String),

    /// Verification failed
    #[error("verification failed")]
    VerificationFailed,

    /// Invalid script
    #[error("invalid script: {0}")]
    InvalidScript(String),

    /// Invalid parity
    #[error("invalid parity value")]
    InvalidParity,

    /// Secp256k1 error
    #[error("secp256k1 error: {0}")]
    Secp256k1Error(String),

    /// Invalid length
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    /// Empty tree
    #[error("cannot build empty tree")]
    EmptyTree,

    /// Invalid merkle path
    #[error("invalid merkle path")]
    InvalidMerklePath,
}
