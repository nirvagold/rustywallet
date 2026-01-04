//! Error types for Lightning Network operations.

use thiserror::Error;

/// Errors that can occur during Lightning operations.
#[derive(Debug, Error)]
pub enum LightningError {
    /// Invalid format (generic).
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Invalid BOLT11 invoice format.
    #[error("Invalid BOLT11 invoice: {0}")]
    InvalidInvoice(String),

    /// Invalid payment hash.
    #[error("Invalid payment hash: {0}")]
    InvalidPaymentHash(String),

    /// Invalid preimage.
    #[error("Invalid preimage: {0}")]
    InvalidPreimage(String),

    /// Invalid node ID.
    #[error("Invalid node ID: {0}")]
    InvalidNodeId(String),

    /// Invalid channel point.
    #[error("Invalid channel point: {0}")]
    InvalidChannelPoint(String),

    /// Invalid route hint.
    #[error("Invalid route hint: {0}")]
    InvalidRouteHint(String),

    /// Bech32 encoding/decoding error.
    #[error("Bech32 error: {0}")]
    Bech32Error(String),

    /// Key derivation error.
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    /// Signature error.
    #[error("Signature error: {0}")]
    SignatureError(String),

    /// Invoice expired.
    #[error("Invoice expired")]
    InvoiceExpired,

    /// Amount mismatch.
    #[error("Amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: u64, actual: u64 },
}
