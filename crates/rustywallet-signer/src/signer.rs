//! Core signing functionality

use crate::error::SignerError;
use crate::signature::{RecoverableSignature, Signature};
use rustywallet_keys::private_key::PrivateKey;
use secp256k1::{Message, Secp256k1};

/// Sign a 32-byte message hash with a private key
///
/// Uses RFC 6979 deterministic nonce generation for security.
///
/// # Arguments
/// * `private_key` - The private key to sign with
/// * `message_hash` - 32-byte hash of the message
///
/// # Returns
/// A 64-byte ECDSA signature (r || s)
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::sign;
/// use sha2::{Sha256, Digest};
///
/// let key = PrivateKey::random();
/// let hash: [u8; 32] = Sha256::digest(b"hello").into();
/// let sig = sign(&key, &hash).unwrap();
/// ```
pub fn sign(private_key: &PrivateKey, message_hash: &[u8; 32]) -> Result<Signature, SignerError> {
    let secp = Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&private_key.to_bytes())
        .map_err(|e| SignerError::SigningFailed(e.to_string()))?;
    let message = Message::from_digest(*message_hash);

    let sig = secp.sign_ecdsa(&message, &secret_key);
    let compact = sig.serialize_compact();

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&compact[..32]);
    s.copy_from_slice(&compact[32..]);

    Ok(Signature::new(r, s))
}

/// Sign a 32-byte message hash with recovery id
///
/// The recovery id allows recovering the public key from the signature.
///
/// # Arguments
/// * `private_key` - The private key to sign with
/// * `message_hash` - 32-byte hash of the message
///
/// # Returns
/// A recoverable signature (64 bytes + recovery id)
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::sign_recoverable;
/// use sha2::{Sha256, Digest};
///
/// let key = PrivateKey::random();
/// let hash: [u8; 32] = Sha256::digest(b"hello").into();
/// let sig = sign_recoverable(&key, &hash).unwrap();
/// assert!(sig.recovery_id() <= 3);
/// ```
pub fn sign_recoverable(
    private_key: &PrivateKey,
    message_hash: &[u8; 32],
) -> Result<RecoverableSignature, SignerError> {
    let secp = Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&private_key.to_bytes())
        .map_err(|e| SignerError::SigningFailed(e.to_string()))?;
    let message = Message::from_digest(*message_hash);

    let (recovery_id, sig) = secp
        .sign_ecdsa_recoverable(&message, &secret_key)
        .serialize_compact();

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);

    let signature = Signature::new(r, s);
    RecoverableSignature::new(signature, recovery_id.to_i32() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_sign_produces_valid_signature() {
        let key = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = sign(&key, &hash).unwrap();
        assert_eq!(sig.to_bytes().len(), 64);
    }

    #[test]
    fn test_sign_recoverable_produces_valid_signature() {
        let key = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = sign_recoverable(&key, &hash).unwrap();
        assert_eq!(sig.to_bytes().len(), 65);
        assert!(sig.recovery_id() <= 3);
    }

    #[test]
    fn test_deterministic_signing() {
        // RFC 6979: same key + same message = same signature
        let key = PrivateKey::random();
        let hash: [u8; 32] = Sha256::digest(b"deterministic test").into();

        let sig1 = sign(&key, &hash).unwrap();
        let sig2 = sign(&key, &hash).unwrap();

        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}
