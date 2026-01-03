//! Error types for batch key generation operations.
//!
//! This module provides the [`BatchError`] enum which covers all possible
//! error conditions during batch key generation.

use thiserror::Error;

/// Errors that can occur during batch key generation.
#[derive(Debug, Error)]
pub enum BatchError {
    /// Invalid configuration parameter.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Insufficient system resources (memory, CPU, etc.).
    #[error("Insufficient system resources: {0}")]
    ResourceExhausted(String),

    /// Cryptographic operation failed.
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Parallel processing error.
    #[error("Parallel processing error: {0}")]
    ParallelError(String),

    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    GenerationError(String),

    /// Scanner operation failed.
    #[error("Scanner operation failed: {0}")]
    ScannerError(String),

    /// Stream operation failed.
    #[error("Stream operation failed: {0}")]
    StreamError(String),

    /// I/O operation failed.
    #[error("I/O error: {0}")]
    IoError(String),
}

impl BatchError {
    /// Create a new invalid configuration error.
    pub fn invalid_config(msg: impl Into<String>) -> Self {
        Self::InvalidConfig(msg.into())
    }

    /// Create a new resource exhausted error.
    pub fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self::ResourceExhausted(msg.into())
    }

    /// Create a new cryptographic error.
    pub fn crypto_error(msg: impl Into<String>) -> Self {
        Self::CryptoError(msg.into())
    }

    /// Create a new parallel processing error.
    pub fn parallel_error(msg: impl Into<String>) -> Self {
        Self::ParallelError(msg.into())
    }

    /// Create a new generation error.
    pub fn generation_error(msg: impl Into<String>) -> Self {
        Self::GenerationError(msg.into())
    }

    /// Create a new scanner error.
    pub fn scanner_error(msg: impl Into<String>) -> Self {
        Self::ScannerError(msg.into())
    }

    /// Create a new stream error.
    pub fn stream_error(msg: impl Into<String>) -> Self {
        Self::StreamError(msg.into())
    }

    /// Create a new I/O error.
    pub fn io_error(msg: impl Into<String>) -> Self {
        Self::IoError(msg.into())
    }
}
