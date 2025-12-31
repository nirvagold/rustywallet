//! Signature types for ECDSA signatures

use crate::error::SignerError;
use std::fmt;

/// ECDSA signature (64 bytes: r || s)
///
/// # Example
/// ```
/// use rustywallet_signer::Signature;
///
/// let bytes = [0u8; 64];
/// let sig = Signature::from_bytes(&bytes).unwrap();
/// assert_eq!(sig.to_bytes().len(), 64);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    /// Create a new signature from r and s components
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Self {
        Self { r, s }
    }

    /// Get the r component
    pub fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// Get the s component
    pub fn s(&self) -> &[u8; 32] {
        &self.s
    }

    /// Convert signature to 64-byte array (r || s)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..].copy_from_slice(&self.s);
        bytes
    }

    /// Parse signature from 64-byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 64 {
            return Err(SignerError::InvalidSignature);
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok(Self { r, s })
    }

    /// Convert signature to hex string
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Parse signature from hex string
    pub fn from_hex(hex: &str) -> Result<Self, SignerError> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        if hex.len() != 128 {
            return Err(SignerError::InvalidHex(format!(
                "expected 128 hex chars, got {}",
                hex.len()
            )));
        }
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SignerError::InvalidHex(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Recoverable ECDSA signature (65 bytes: r || s || v)
///
/// The recovery id (v) allows recovering the public key from the signature.
///
/// # Example
/// ```
/// use rustywallet_signer::{Signature, RecoverableSignature};
///
/// let sig = Signature::from_bytes(&[0u8; 64]).unwrap();
/// let rsig = RecoverableSignature::new(sig, 0).unwrap();
/// assert_eq!(rsig.to_bytes().len(), 65);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct RecoverableSignature {
    signature: Signature,
    recovery_id: u8,
}

impl RecoverableSignature {
    /// Create a new recoverable signature
    ///
    /// # Arguments
    /// * `signature` - The base signature
    /// * `recovery_id` - Recovery id (0-3)
    pub fn new(signature: Signature, recovery_id: u8) -> Result<Self, SignerError> {
        if recovery_id > 3 {
            return Err(SignerError::InvalidRecoveryId(recovery_id));
        }
        Ok(Self {
            signature,
            recovery_id,
        })
    }

    /// Get the base signature
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Get the recovery id (0-3)
    pub fn recovery_id(&self) -> u8 {
        self.recovery_id
    }

    /// Convert to 65-byte array (r || s || v)
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&self.signature.to_bytes());
        bytes[64] = self.recovery_id;
        bytes
    }

    /// Parse from 65-byte array (r || s || v)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 65 {
            return Err(SignerError::InvalidSignature);
        }
        let signature = Signature::from_bytes(&bytes[..64])?;
        let recovery_id = bytes[64];
        Self::new(signature, recovery_id)
    }

    /// Convert to Ethereum format (r || s || v where v = recovery_id + 27)
    pub fn to_ethereum_format(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&self.signature.to_bytes());
        bytes[64] = self.recovery_id + 27;
        bytes
    }

    /// Parse from Ethereum format (r || s || v where v >= 27)
    pub fn from_ethereum_format(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 65 {
            return Err(SignerError::InvalidSignature);
        }
        let signature = Signature::from_bytes(&bytes[..64])?;
        let v = bytes[64];
        // Ethereum v is either 27/28 (legacy) or 0/1 (EIP-155 adjusted)
        let recovery_id = if v >= 27 { v - 27 } else { v };
        Self::new(signature, recovery_id)
    }

    /// Convert to hex string (130 chars)
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Convert to Ethereum hex format (0x prefixed, v = recovery_id + 27)
    pub fn to_ethereum_hex(&self) -> String {
        let bytes = self.to_ethereum_format();
        format!(
            "0x{}",
            bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        )
    }
}

impl fmt::Debug for RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RecoverableSignature({}, v={})",
            self.signature.to_hex(),
            self.recovery_id
        )
    }
}

impl fmt::Display for RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_roundtrip() {
        let r = [1u8; 32];
        let s = [2u8; 32];
        let sig = Signature::new(r, s);

        let bytes = sig.to_bytes();
        let parsed = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let r = [0xab; 32];
        let s = [0xcd; 32];
        let sig = Signature::new(r, s);

        let hex = sig.to_hex();
        let parsed = Signature::from_hex(&hex).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn test_recoverable_signature_roundtrip() {
        let sig = Signature::new([1u8; 32], [2u8; 32]);
        let rsig = RecoverableSignature::new(sig, 1).unwrap();

        let bytes = rsig.to_bytes();
        let parsed = RecoverableSignature::from_bytes(&bytes).unwrap();
        assert_eq!(rsig, parsed);
    }

    #[test]
    fn test_ethereum_format() {
        let sig = Signature::new([1u8; 32], [2u8; 32]);
        let rsig = RecoverableSignature::new(sig, 0).unwrap();

        let eth_bytes = rsig.to_ethereum_format();
        assert_eq!(eth_bytes[64], 27); // v = 0 + 27

        let parsed = RecoverableSignature::from_ethereum_format(&eth_bytes).unwrap();
        assert_eq!(rsig, parsed);
    }

    #[test]
    fn test_invalid_recovery_id() {
        let sig = Signature::new([0u8; 32], [0u8; 32]);
        let result = RecoverableSignature::new(sig, 4);
        assert!(result.is_err());
    }
}
