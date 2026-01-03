//! Schnorr signing and verification (BIP340)
//!
//! This module provides Schnorr signature support using the BIP340 standard.
//! It integrates with rustywallet-taproot for the underlying cryptographic operations.
//!
//! # Example
//!
//! ```rust
//! use rustywallet_keys::private_key::PrivateKey;
//! use rustywallet_signer::schnorr::{SchnorrSigner, SchnorrVerifier};
//! use sha2::{Sha256, Digest};
//!
//! // Generate a key
//! let key = PrivateKey::random();
//!
//! // Sign a message hash
//! let hash: [u8; 32] = Sha256::digest(b"hello world").into();
//! let signature = key.sign_schnorr(&hash).unwrap();
//!
//! // Get x-only public key for verification
//! let xonly_pubkey = key.x_only_public_key();
//!
//! // Verify the signature
//! assert!(xonly_pubkey.verify_schnorr(&signature, &hash));
//! ```

use crate::error::SignerError;
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_taproot::{SchnorrSignature, XOnlyPublicKey};
use secp256k1::{Secp256k1, SecretKey};

/// Trait for Schnorr signing (BIP340)
///
/// Implementors can sign 32-byte message hashes using BIP340 Schnorr signatures.
pub trait SchnorrSigner {
    /// Sign a 32-byte message hash with BIP340 Schnorr
    ///
    /// # Arguments
    /// * `message_hash` - 32-byte hash of the message to sign
    ///
    /// # Returns
    /// A 64-byte BIP340 Schnorr signature
    ///
    /// # Example
    /// ```rust
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_signer::schnorr::SchnorrSigner;
    /// use sha2::{Sha256, Digest};
    ///
    /// let key = PrivateKey::random();
    /// let hash: [u8; 32] = Sha256::digest(b"hello").into();
    /// let sig = key.sign_schnorr(&hash).unwrap();
    /// ```
    fn sign_schnorr(&self, message_hash: &[u8; 32]) -> Result<SchnorrSignature, SignerError>;

    /// Sign with auxiliary randomness for additional security
    ///
    /// Using auxiliary randomness provides additional protection against
    /// side-channel attacks.
    ///
    /// # Arguments
    /// * `message_hash` - 32-byte hash of the message to sign
    /// * `aux_rand` - 32 bytes of auxiliary randomness
    ///
    /// # Returns
    /// A 64-byte BIP340 Schnorr signature
    fn sign_schnorr_with_aux(
        &self,
        message_hash: &[u8; 32],
        aux_rand: &[u8; 32],
    ) -> Result<SchnorrSignature, SignerError>;

    /// Get the x-only public key for this signer
    ///
    /// Returns the 32-byte x-only public key that can be used
    /// to verify signatures created by this signer.
    fn x_only_public_key(&self) -> XOnlyPublicKey;
}

/// Trait for Schnorr verification (BIP340)
///
/// Implementors can verify BIP340 Schnorr signatures.
pub trait SchnorrVerifier {
    /// Verify a BIP340 Schnorr signature
    ///
    /// # Arguments
    /// * `signature` - The Schnorr signature to verify
    /// * `message_hash` - 32-byte hash of the original message
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Example
    /// ```rust
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_signer::schnorr::{SchnorrSigner, SchnorrVerifier};
    /// use sha2::{Sha256, Digest};
    ///
    /// let key = PrivateKey::random();
    /// let hash: [u8; 32] = Sha256::digest(b"hello").into();
    /// let sig = key.sign_schnorr(&hash).unwrap();
    ///
    /// let xonly = key.x_only_public_key();
    /// assert!(xonly.verify_schnorr(&sig, &hash));
    /// ```
    fn verify_schnorr(&self, signature: &SchnorrSignature, message_hash: &[u8; 32]) -> bool;
}

impl SchnorrSigner for PrivateKey {
    fn sign_schnorr(&self, message_hash: &[u8; 32]) -> Result<SchnorrSignature, SignerError> {
        SchnorrSignature::sign(message_hash, &self.to_bytes())
            .map_err(|e| SignerError::SigningFailed(e.to_string()))
    }

    fn sign_schnorr_with_aux(
        &self,
        message_hash: &[u8; 32],
        aux_rand: &[u8; 32],
    ) -> Result<SchnorrSignature, SignerError> {
        SchnorrSignature::sign_with_aux(message_hash, &self.to_bytes(), aux_rand)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))
    }

    fn x_only_public_key(&self) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&self.to_bytes()).expect("valid private key");
        let pk = sk.public_key(&secp);
        let (xonly, _parity) = pk.x_only_public_key();
        XOnlyPublicKey::from_inner(xonly)
    }
}

impl SchnorrVerifier for XOnlyPublicKey {
    fn verify_schnorr(&self, signature: &SchnorrSignature, message_hash: &[u8; 32]) -> bool {
        signature.verify(message_hash, self)
    }
}

/// Sign a 32-byte message hash with BIP340 Schnorr
///
/// Convenience function for signing without using the trait.
///
/// # Arguments
/// * `private_key` - The private key to sign with
/// * `message_hash` - 32-byte hash of the message
///
/// # Returns
/// A 64-byte BIP340 Schnorr signature
///
/// # Example
/// ```rust
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::schnorr::sign_schnorr;
/// use sha2::{Sha256, Digest};
///
/// let key = PrivateKey::random();
/// let hash: [u8; 32] = Sha256::digest(b"hello").into();
/// let sig = sign_schnorr(&key, &hash).unwrap();
/// ```
pub fn sign_schnorr(
    private_key: &PrivateKey,
    message_hash: &[u8; 32],
) -> Result<SchnorrSignature, SignerError> {
    private_key.sign_schnorr(message_hash)
}

/// Verify a BIP340 Schnorr signature
///
/// Convenience function for verification without using the trait.
///
/// # Arguments
/// * `pubkey` - The x-only public key to verify against
/// * `signature` - The Schnorr signature to verify
/// * `message_hash` - 32-byte hash of the original message
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
///
/// # Example
/// ```rust
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::schnorr::{sign_schnorr, verify_schnorr, SchnorrSigner};
/// use sha2::{Sha256, Digest};
///
/// let key = PrivateKey::random();
/// let hash: [u8; 32] = Sha256::digest(b"hello").into();
/// let sig = sign_schnorr(&key, &hash).unwrap();
///
/// let xonly = key.x_only_public_key();
/// assert!(verify_schnorr(&xonly, &sig, &hash));
/// ```
pub fn verify_schnorr(
    pubkey: &XOnlyPublicKey,
    signature: &SchnorrSignature,
    message_hash: &[u8; 32],
) -> bool {
    pubkey.verify_schnorr(signature, message_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_schnorr_sign_verify_roundtrip() {
        let key = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = key.sign_schnorr(&hash).unwrap();
        let xonly = key.x_only_public_key();

        assert!(xonly.verify_schnorr(&sig, &hash));
    }

    #[test]
    fn test_schnorr_sign_with_aux() {
        let key = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();
        let aux = [0x42u8; 32];

        let sig = key.sign_schnorr_with_aux(&hash, &aux).unwrap();
        let xonly = key.x_only_public_key();

        assert!(xonly.verify_schnorr(&sig, &hash));
    }

    #[test]
    fn test_schnorr_wrong_message_fails() {
        let key = PrivateKey::random();
        let hash1: [u8; 32] = Sha256::digest(b"message 1").into();
        let hash2: [u8; 32] = Sha256::digest(b"message 2").into();

        let sig = key.sign_schnorr(&hash1).unwrap();
        let xonly = key.x_only_public_key();

        assert!(!xonly.verify_schnorr(&sig, &hash2));
    }

    #[test]
    fn test_schnorr_wrong_key_fails() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = key1.sign_schnorr(&hash).unwrap();
        let xonly2 = key2.x_only_public_key();

        assert!(!xonly2.verify_schnorr(&sig, &hash));
    }

    #[test]
    fn test_convenience_functions() {
        let key = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = sign_schnorr(&key, &hash).unwrap();
        let xonly = key.x_only_public_key();

        assert!(verify_schnorr(&xonly, &sig, &hash));
    }

    #[test]
    fn test_deterministic_signing() {
        // BIP340 with no aux randomness should be deterministic
        let key = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"deterministic test").into();

        // Note: sign_schnorr uses internal randomness by default
        // sign_schnorr_with_aux with same aux should be deterministic
        let aux = [0u8; 32];
        let sig1 = key.sign_schnorr_with_aux(&hash, &aux).unwrap();
        let sig2 = key.sign_schnorr_with_aux(&hash, &aux).unwrap();

        assert_eq!(sig1.serialize(), sig2.serialize());
    }
}
