//! Key tweaking for Taproot
//!
//! Implements key tweaking as specified in BIP341.

use crate::error::TaprootError;
use crate::tagged_hash::{TapNodeHash, TapTweakHash};
use crate::xonly::{Parity, XOnlyPublicKey};
use secp256k1::{Secp256k1, SecretKey};

/// Tweak a public key for Taproot
///
/// Computes: P' = P + t*G where t = tagged_hash("TapTweak", P || merkle_root)
pub fn tweak_public_key(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<&TapNodeHash>,
) -> Result<(XOnlyPublicKey, Parity), TaprootError> {
    let secp = Secp256k1::new();
    
    // Compute tweak
    let tweak_hash = TapTweakHash::from_key_and_merkle_root(
        &internal_key.serialize(),
        merkle_root,
    );
    
    // Apply tweak
    internal_key.tweak_add(&secp, tweak_hash.as_bytes())
}

/// Tweak a private key for Taproot
///
/// If the public key has odd y-coordinate, the private key is negated first.
pub fn tweak_private_key(
    secret_key: &[u8; 32],
    internal_pubkey: &XOnlyPublicKey,
    merkle_root: Option<&TapNodeHash>,
) -> Result<[u8; 32], TaprootError> {
    let secp = Secp256k1::new();
    
    // Get the secret key
    let mut sk = SecretKey::from_slice(secret_key)
        .map_err(|e| TaprootError::Secp256k1Error(e.to_string()))?;
    
    // Check if we need to negate (if y-coordinate is odd)
    let pubkey = sk.public_key(&secp);
    let (_, parity) = pubkey.x_only_public_key();
    
    if parity == secp256k1::Parity::Odd {
        sk = sk.negate();
    }
    
    // Compute tweak
    let tweak_hash = TapTweakHash::from_key_and_merkle_root(
        &internal_pubkey.serialize(),
        merkle_root,
    );
    
    // Apply tweak
    let scalar = secp256k1::Scalar::from_be_bytes(*tweak_hash.as_bytes())
        .map_err(|e| TaprootError::InvalidTweak(e.to_string()))?;
    
    let tweaked = sk.add_tweak(&scalar)
        .map_err(|e| TaprootError::InvalidTweak(e.to_string()))?;
    
    Ok(tweaked.secret_bytes())
}

/// Compute the output key from internal key and merkle root
pub fn compute_output_key(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<&TapNodeHash>,
) -> Result<(XOnlyPublicKey, Parity), TaprootError> {
    tweak_public_key(internal_key, merkle_root)
}

/// Compute the tweak value
pub fn compute_tweak(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<&TapNodeHash>,
) -> [u8; 32] {
    TapTweakHash::from_key_and_merkle_root(
        &internal_key.serialize(),
        merkle_root,
    ).to_bytes()
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
    fn test_tweak_public_key_no_merkle() {
        let (_, internal_key) = get_test_keypair();
        
        let (output_key, parity) = tweak_public_key(&internal_key, None).unwrap();
        
        // Output key should be different from internal key
        assert_ne!(output_key.serialize(), internal_key.serialize());
        
        // Should be deterministic
        let (output_key2, parity2) = tweak_public_key(&internal_key, None).unwrap();
        assert_eq!(output_key, output_key2);
        assert_eq!(parity, parity2);
    }

    #[test]
    fn test_tweak_public_key_with_merkle() {
        let (_, internal_key) = get_test_keypair();
        let merkle_root = TapNodeHash::from_bytes([0x42; 32]);
        
        let (output_key1, _) = tweak_public_key(&internal_key, None).unwrap();
        let (output_key2, _) = tweak_public_key(&internal_key, Some(&merkle_root)).unwrap();
        
        // Different merkle roots should produce different output keys
        assert_ne!(output_key1, output_key2);
    }

    #[test]
    fn test_tweak_private_key() {
        let secp = Secp256k1::new();
        let (secret, internal_key) = get_test_keypair();
        
        // Tweak private key
        let tweaked_secret = tweak_private_key(&secret, &internal_key, None).unwrap();
        
        // Derive public key from tweaked private key
        let tweaked_sk = SecretKey::from_slice(&tweaked_secret).unwrap();
        let tweaked_pk = tweaked_sk.public_key(&secp);
        let (tweaked_xonly, _) = tweaked_pk.x_only_public_key();
        
        // Tweak public key directly
        let (output_key, _) = tweak_public_key(&internal_key, None).unwrap();
        
        // They should match
        assert_eq!(tweaked_xonly.serialize(), output_key.serialize());
    }

    #[test]
    fn test_compute_tweak() {
        let (_, internal_key) = get_test_keypair();
        
        let tweak1 = compute_tweak(&internal_key, None);
        let tweak2 = compute_tweak(&internal_key, None);
        
        // Should be deterministic
        assert_eq!(tweak1, tweak2);
        
        // With merkle root should be different
        let merkle_root = TapNodeHash::from_bytes([0x42; 32]);
        let tweak3 = compute_tweak(&internal_key, Some(&merkle_root));
        assert_ne!(tweak1, tweak3);
    }
}
