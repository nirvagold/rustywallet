//! PSBT error types

use thiserror::Error;

/// Errors that can occur when working with PSBTs
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PsbtError {
    /// Invalid magic bytes (expected 0x70736274ff)
    #[error("invalid PSBT magic bytes")]
    InvalidMagic,

    /// Invalid PSBT format
    #[error("invalid PSBT format: {0}")]
    InvalidFormat(String),

    /// Missing required field
    #[error("missing required field: {0}")]
    MissingField(String),

    /// Duplicate key in map
    #[error("duplicate key in PSBT map")]
    DuplicateKey,

    /// Invalid key type
    #[error("invalid key type: 0x{0:02x}")]
    InvalidKeyType(u8),

    /// Input index out of bounds
    #[error("input index {0} out of bounds")]
    InputIndexOutOfBounds(usize),

    /// Output index out of bounds
    #[error("output index {0} out of bounds")]
    OutputIndexOutOfBounds(usize),

    /// Cannot sign input
    #[error("cannot sign input: {0}")]
    CannotSign(String),

    /// Incompatible PSBTs for combination
    #[error("incompatible PSBTs for combination")]
    IncompatiblePsbts,

    /// PSBT not finalized
    #[error("PSBT is not finalized")]
    NotFinalized,

    /// Already finalized
    #[error("input is already finalized")]
    AlreadyFinalized,

    /// Invalid signature
    #[error("invalid signature")]
    InvalidSignature,

    /// Unsupported PSBT version
    #[error("unsupported PSBT version: {0}")]
    UnsupportedVersion(u32),

    /// Serialization error
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Base64 decode error
    #[error("base64 decode error: {0}")]
    Base64Error(String),

    /// Invalid public key
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid script
    #[error("invalid script: {0}")]
    InvalidScript(String),

    /// Missing UTXO information
    #[error("missing UTXO information for input {0}")]
    MissingUtxo(usize),

    /// Sighash mismatch
    #[error("sighash type mismatch")]
    SighashMismatch,

    /// Transaction mismatch
    #[error("transaction mismatch between PSBTs")]
    TransactionMismatch,

    /// No unsigned transaction
    #[error("PSBT has no unsigned transaction")]
    NoUnsignedTx,
}
