//! Signature verification functionality

use crate::error::SignerError;
use crate::signature::Signature;
use rustywallet_keys::public_key::PublicKey;
use secp256k1::{ecdsa, Message, Secp256k1};

/// Verify a signature against a public key and message hash
///
/// # Arguments
/// * `public_key` - The public key to verify against
/// * `message_hash` - 32-byte hash of the original message
/// * `signature` - The signature to verify
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::{sign, verify};
/// use sha2::{Sha256, Digest};
///
/// let key = PrivateKey::random();
/// let pubkey = key.public_key();
/// let hash: [u8; 32] = Sha256::digest(b"hello").into();
///
/// let sig = sign(&key, &hash).unwrap();
/// assert!(verify(&pubkey, &hash, &sig));
/// ```
pub fn verify(public_key: &PublicKey, message_hash: &[u8; 32], signature: &Signature) -> bool {
    let secp = Secp256k1::verification_only();

    // Parse public key (use compressed format)
    let pk = match secp256k1::PublicKey::from_slice(&public_key.to_compressed()) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Parse signature
    let sig = match ecdsa::Signature::from_compact(&signature.to_bytes()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Create message
    let message = Message::from_digest(*message_hash);

    // Verify
    secp.verify_ecdsa(&message, &sig, &pk).is_ok()
}

/// Verify a signature and return a Result
///
/// Same as `verify` but returns an error instead of false.
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::{sign, verify_strict};
/// use sha2::{Sha256, Digest};
///
/// let key = PrivateKey::random();
/// let pubkey = key.public_key();
/// let hash: [u8; 32] = Sha256::digest(b"hello").into();
///
/// let sig = sign(&key, &hash).unwrap();
/// verify_strict(&pubkey, &hash, &sig).unwrap();
/// ```
pub fn verify_strict(
    public_key: &PublicKey,
    message_hash: &[u8; 32],
    signature: &Signature,
) -> Result<(), SignerError> {
    if verify(public_key, message_hash, signature) {
        Ok(())
    } else {
        Err(SignerError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign;
    use rustywallet_keys::private_key::PrivateKey;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_verify_valid_signature() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = sign(&key, &hash).unwrap();
        assert!(verify(&pubkey, &hash, &sig));
    }

    #[test]
    fn test_verify_wrong_message() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        let hash1: [u8; 32] = Sha256::digest(b"message 1").into();
        let hash2: [u8; 32] = Sha256::digest(b"message 2").into();

        let sig = sign(&key, &hash1).unwrap();
        assert!(!verify(&pubkey, &hash2, &sig));
    }

    #[test]
    fn test_verify_wrong_key() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = sign(&key1, &hash).unwrap();
        assert!(!verify(&key2.public_key(), &hash, &sig));
    }

    #[test]
    fn test_verify_strict_returns_error() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = sign(&key1, &hash).unwrap();
        let result = verify_strict(&key2.public_key(), &hash, &sig);
        assert!(result.is_err());
    }
}
