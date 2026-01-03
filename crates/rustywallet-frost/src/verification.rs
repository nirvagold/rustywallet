//! Signature verification for FROST.

use crate::aggregation::Signature;
use crate::error::{FrostError, Result};
use crate::keys::GroupPublicKey;
use secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};

/// Verify a FROST signature.
pub fn verify(
    signature: &Signature,
    group_public_key: &GroupPublicKey,
    msg: &[u8],
) -> Result<bool> {
    let secp = Secp256k1::new();

    // Get x-only public key
    let xonly = group_public_key.to_xonly()?;
    let xonly_pk = XOnlyPublicKey::from_slice(&xonly)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    // Create Schnorr signature
    let sig = schnorr::Signature::from_slice(&signature.to_bytes())
        .map_err(|e| FrostError::InvalidSignature(e.to_string()))?;

    // Create message
    let message = if msg.len() == 32 {
        let mut msg_bytes = [0u8; 32];
        msg_bytes.copy_from_slice(msg);
        Message::from_digest(msg_bytes)
    } else {
        // Hash the message if not 32 bytes
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(msg).into();
        Message::from_digest(hash)
    };

    // Verify
    Ok(secp.verify_schnorr(&sig, &message, &xonly_pk).is_ok())
}

/// Verify a signature against raw x-only public key bytes.
pub fn verify_raw(
    signature: &Signature,
    xonly_pubkey: &[u8; 32],
    msg: &[u8; 32],
) -> Result<bool> {
    let secp = Secp256k1::new();

    let xonly_pk = XOnlyPublicKey::from_slice(xonly_pubkey)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    let sig = schnorr::Signature::from_slice(&signature.to_bytes())
        .map_err(|e| FrostError::InvalidSignature(e.to_string()))?;

    let message = Message::from_digest(*msg);

    Ok(secp.verify_schnorr(&sig, &message, &xonly_pk).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    #[test]
    fn test_verify_valid_signature() {
        // Create a valid Schnorr signature using secp256k1
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);

        let msg = [0u8; 32];
        let message = Message::from_digest(msg);
        let sig = secp.sign_schnorr(&message, &keypair);

        let signature = Signature::from_bytes(&sig.serialize()).unwrap();
        let gpk = GroupPublicKey::from_secret(&sk.secret_bytes()).unwrap();

        let valid = verify(&signature, &gpk, &msg).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_invalid_signature() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let gpk = GroupPublicKey::from_secret(&sk.secret_bytes()).unwrap();

        // Invalid signature (all zeros)
        let signature = Signature {
            r: [0u8; 32],
            s: [0u8; 32],
        };

        let msg = [0u8; 32];
        let valid = verify(&signature, &gpk, &msg).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_raw() {
        let secp = Secp256k1::new();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();

        let msg = [42u8; 32];
        let message = Message::from_digest(msg);
        let sig = secp.sign_schnorr(&message, &keypair);

        let signature = Signature::from_bytes(&sig.serialize()).unwrap();

        let valid = verify_raw(&signature, &xonly.serialize(), &msg).unwrap();
        assert!(valid);
    }
}
