//! Public key recovery from signatures

use crate::error::SignerError;
use crate::signature::RecoverableSignature;
use rustywallet_keys::public_key::PublicKey;
use secp256k1::{ecdsa::RecoveryId, Message, Secp256k1};

/// Recover the public key from a recoverable signature
///
/// # Arguments
/// * `signature` - A recoverable signature with recovery id
/// * `message_hash` - The 32-byte hash that was signed
///
/// # Returns
/// The public key that created the signature
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::{sign_recoverable, recover_public_key};
/// use sha2::{Sha256, Digest};
///
/// let key = PrivateKey::random();
/// let hash: [u8; 32] = Sha256::digest(b"hello").into();
///
/// let sig = sign_recoverable(&key, &hash).unwrap();
/// let recovered = recover_public_key(&sig, &hash).unwrap();
///
/// assert_eq!(key.public_key().to_compressed(), recovered.to_compressed());
/// ```
pub fn recover_public_key(
    signature: &RecoverableSignature,
    message_hash: &[u8; 32],
) -> Result<PublicKey, SignerError> {
    let secp = Secp256k1::new();

    // Create recovery id
    let recovery_id =
        RecoveryId::from_i32(signature.recovery_id() as i32).map_err(|_| SignerError::RecoveryFailed)?;

    // Create recoverable signature
    let sig_bytes = signature.signature().to_bytes();
    let recoverable_sig =
        secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes, recovery_id)
            .map_err(|_| SignerError::RecoveryFailed)?;

    // Create message
    let message = Message::from_digest(*message_hash);

    // Recover public key
    let pubkey = secp
        .recover_ecdsa(&message, &recoverable_sig)
        .map_err(|_| SignerError::RecoveryFailed)?;

    // Convert to our PublicKey type (compressed)
    let compressed = pubkey.serialize();
    PublicKey::from_compressed(&compressed).map_err(|_| SignerError::RecoveryFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_recoverable;
    use rustywallet_keys::private_key::PrivateKey;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_recover_public_key() {
        let key = PrivateKey::random();
        let expected_pubkey = key.public_key();
        let hash: [u8; 32] = Sha256::digest(b"test message").into();

        let sig = sign_recoverable(&key, &hash).unwrap();
        let recovered = recover_public_key(&sig, &hash).unwrap();

        assert_eq!(expected_pubkey.to_compressed(), recovered.to_compressed());
    }

    #[test]
    fn test_recover_fails_with_wrong_hash() {
        let key = PrivateKey::random();
        let hash1: [u8; 32] = Sha256::digest(b"message 1").into();
        let hash2: [u8; 32] = Sha256::digest(b"message 2").into();

        let sig = sign_recoverable(&key, &hash1).unwrap();
        let recovered = recover_public_key(&sig, &hash2).unwrap();

        // Recovery succeeds but returns wrong key
        assert_ne!(key.public_key().to_compressed(), recovered.to_compressed());
    }
}
