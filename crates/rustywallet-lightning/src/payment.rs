//! Payment hash and preimage handling.
//!
//! This module provides types for working with Lightning payment
//! hashes and preimages.

use crate::error::LightningError;
use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte payment preimage.
///
/// The preimage is the secret that, when hashed with SHA256,
/// produces the payment hash. Revealing the preimage proves
/// that a payment was received.
#[derive(Clone, PartialEq, Eq)]
pub struct PaymentPreimage([u8; 32]);

impl PaymentPreimage {
    /// Create a new payment preimage from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a new payment preimage from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, LightningError> {
        let bytes = hex::decode(hex)
            .map_err(|e| LightningError::InvalidPreimage(e.to_string()))?;
        
        if bytes.len() != 32 {
            return Err(LightningError::InvalidPreimage(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Generate a random payment preimage.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Compute the payment hash from this preimage.
    pub fn payment_hash(&self) -> PaymentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        let result = hasher.finalize();
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        PaymentHash(hash)
    }
}

impl fmt::Debug for PaymentPreimage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PaymentPreimage([REDACTED])")
    }
}

impl fmt::Display for PaymentPreimage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A 32-byte payment hash.
///
/// The payment hash is the SHA256 hash of the preimage and is
/// used to identify payments in the Lightning Network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaymentHash([u8; 32]);

impl PaymentHash {
    /// Create a new payment hash from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a new payment hash from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, LightningError> {
        let bytes = hex::decode(hex)
            .map_err(|e| LightningError::InvalidPaymentHash(e.to_string()))?;
        
        if bytes.len() != 32 {
            return Err(LightningError::InvalidPaymentHash(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Verify that a preimage matches this payment hash.
    pub fn verify(&self, preimage: &PaymentPreimage) -> bool {
        preimage.payment_hash() == *self
    }
}

impl fmt::Display for PaymentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preimage_to_hash() {
        let preimage = PaymentPreimage::from_bytes([0u8; 32]);
        let hash = preimage.payment_hash();
        
        // SHA256 of 32 zero bytes
        assert_eq!(
            hash.to_hex(),
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
        );
    }

    #[test]
    fn test_random_preimage() {
        let preimage1 = PaymentPreimage::random();
        let preimage2 = PaymentPreimage::random();
        
        assert_ne!(preimage1.as_bytes(), preimage2.as_bytes());
    }

    #[test]
    fn test_hash_verification() {
        let preimage = PaymentPreimage::random();
        let hash = preimage.payment_hash();
        
        assert!(hash.verify(&preimage));
        
        let wrong_preimage = PaymentPreimage::random();
        assert!(!hash.verify(&wrong_preimage));
    }

    #[test]
    fn test_hex_roundtrip() {
        let preimage = PaymentPreimage::random();
        let hex = preimage.to_hex();
        let recovered = PaymentPreimage::from_hex(&hex).unwrap();
        
        assert_eq!(preimage.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_preimage_debug_redacted() {
        let preimage = PaymentPreimage::random();
        let debug = format!("{:?}", preimage);
        
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&preimage.to_hex()));
    }
}
