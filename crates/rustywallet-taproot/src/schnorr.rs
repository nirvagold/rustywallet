//! Schnorr signatures (BIP340)
//!
//! Implements Schnorr signature creation and verification.

use crate::error::TaprootError;
use crate::xonly::XOnlyPublicKey;
use secp256k1::{Secp256k1, SecretKey, Message};
use std::fmt;

/// 64-byte Schnorr signature (BIP340)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SchnorrSignature {
    inner: secp256k1::schnorr::Signature,
}

impl SchnorrSignature {
    /// Sign a 32-byte message with a private key
    pub fn sign(message: &[u8; 32], secret_key: &[u8; 32]) -> Result<Self, TaprootError> {
        let secp = Secp256k1::new();
        
        let sk = SecretKey::from_slice(secret_key)
            .map_err(|e| TaprootError::Secp256k1Error(e.to_string()))?;
        
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let msg = Message::from_digest(*message);
        
        let sig = secp.sign_schnorr(&msg, &keypair);
        
        Ok(Self { inner: sig })
    }

    /// Sign with auxiliary randomness for additional security
    pub fn sign_with_aux(
        message: &[u8; 32],
        secret_key: &[u8; 32],
        aux_rand: &[u8; 32],
    ) -> Result<Self, TaprootError> {
        let secp = Secp256k1::new();
        
        let sk = SecretKey::from_slice(secret_key)
            .map_err(|e| TaprootError::Secp256k1Error(e.to_string()))?;
        
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let msg = Message::from_digest(*message);
        
        let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, aux_rand);
        
        Ok(Self { inner: sig })
    }

    /// Verify signature against a public key
    pub fn verify(&self, message: &[u8; 32], pubkey: &XOnlyPublicKey) -> bool {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(*message);
        
        secp.verify_schnorr(&self.inner, &msg, pubkey.inner()).is_ok()
    }

    /// Serialize to 64 bytes
    pub fn serialize(&self) -> [u8; 64] {
        *self.inner.as_ref()
    }

    /// Parse from 64 bytes
    pub fn from_slice(data: &[u8]) -> Result<Self, TaprootError> {
        if data.len() != 64 {
            return Err(TaprootError::InvalidLength {
                expected: 64,
                got: data.len(),
            });
        }
        
        let inner = secp256k1::schnorr::Signature::from_slice(data)
            .map_err(|e| TaprootError::Secp256k1Error(e.to_string()))?;
        
        Ok(Self { inner })
    }

    /// Parse from byte array
    pub fn from_bytes(data: [u8; 64]) -> Result<Self, TaprootError> {
        Self::from_slice(&data)
    }

    /// Get the inner secp256k1 signature
    pub fn inner(&self) -> &secp256k1::schnorr::Signature {
        &self.inner
    }
}

impl fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SchnorrSignature({})", hex::encode(self.serialize()))
    }
}

impl fmt::Display for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.serialize()))
    }
}

impl AsRef<[u8]> for SchnorrSignature {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_test_keypair() -> ([u8; 32], XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let secret = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let sk = SecretKey::from_slice(&secret).unwrap();
        let pk = sk.public_key(&secp);
        let (xonly, _) = pk.x_only_public_key();
        (secret, XOnlyPublicKey::from_inner(xonly))
    }

    #[test]
    fn test_sign_verify() {
        let (secret, pubkey) = get_test_keypair();
        let message = [0x42u8; 32];
        
        let sig = SchnorrSignature::sign(&message, &secret).unwrap();
        assert!(sig.verify(&message, &pubkey));
    }

    #[test]
    fn test_sign_with_aux() {
        let (secret, pubkey) = get_test_keypair();
        let message = [0x42u8; 32];
        let aux = [0x00u8; 32];
        
        let sig = SchnorrSignature::sign_with_aux(&message, &secret, &aux).unwrap();
        assert!(sig.verify(&message, &pubkey));
    }

    #[test]
    fn test_wrong_message_fails() {
        let (secret, pubkey) = get_test_keypair();
        let message = [0x42u8; 32];
        let wrong_message = [0x43u8; 32];
        
        let sig = SchnorrSignature::sign(&message, &secret).unwrap();
        assert!(!sig.verify(&wrong_message, &pubkey));
    }

    #[test]
    fn test_signature_roundtrip() {
        let (secret, _) = get_test_keypair();
        let message = [0x42u8; 32];
        
        let sig = SchnorrSignature::sign(&message, &secret).unwrap();
        let bytes = sig.serialize();
        let parsed = SchnorrSignature::from_bytes(bytes).unwrap();
        
        assert_eq!(sig.serialize(), parsed.serialize());
    }

    #[test]
    fn test_signature_display() {
        let (secret, _) = get_test_keypair();
        let message = [0x42u8; 32];
        
        let sig = SchnorrSignature::sign(&message, &secret).unwrap();
        let hex_str = sig.to_string();
        
        assert_eq!(hex_str.len(), 128); // 64 bytes = 128 hex chars
    }
}
