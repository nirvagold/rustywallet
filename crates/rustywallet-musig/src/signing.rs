//! MuSig2 signing operations.
//!
//! Implements partial signature creation and aggregation.

use crate::error::{MusigError, Result};
use crate::key_agg::KeyAggContext;
use crate::nonce::{compute_nonce_coeff, AggregatedNonce, PublicNonce, SecretNonce};
use crate::tagged_hash::challenge_hash;
use secp256k1::{Secp256k1, SecretKey};

/// A partial signature from one signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSignature {
    /// The partial signature scalar (32 bytes)
    pub s: [u8; 32],
    /// Index of the signer
    pub signer_index: usize,
}

impl PartialSignature {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8], signer_index: usize) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(MusigError::InvalidSignature(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut s = [0u8; 32];
        s.copy_from_slice(bytes);

        Ok(Self { s, signer_index })
    }

    /// Serialize to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.s)
    }

    /// Parse from hex.
    pub fn from_hex(hex_str: &str, signer_index: usize) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| MusigError::HexError(e.to_string()))?;
        Self::from_bytes(&bytes, signer_index)
    }
}

/// A complete Schnorr signature (64 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrSignature {
    /// R.x (32 bytes)
    pub r: [u8; 32],
    /// s (32 bytes)
    pub s: [u8; 32],
}

impl SchnorrSignature {
    /// Create from bytes (64 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(MusigError::InvalidSignature(format!(
                "Expected 64 bytes, got {}",
                bytes.len()
            )));
        }

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);

        Ok(Self { r, s })
    }

    /// Serialize to bytes (64 bytes).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..].copy_from_slice(&self.s);
        bytes
    }

    /// Serialize to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Parse from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| MusigError::HexError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Create a partial signature.
///
/// # Arguments
/// * `secret_nonce` - The signer's secret nonce (will be marked as used)
/// * `secret_key` - The signer's secret key
/// * `key_agg` - Key aggregation context
/// * `agg_nonce` - Aggregated nonce from all signers
/// * `public_nonces` - All public nonces (for computing b)
/// * `msg` - Message to sign (32 bytes)
/// * `signer_index` - Index of this signer in the key aggregation
pub fn create_partial_signature(
    secret_nonce: &mut SecretNonce,
    secret_key: &[u8; 32],
    key_agg: &KeyAggContext,
    agg_nonce: &AggregatedNonce,
    public_nonces: &[PublicNonce],
    msg: &[u8; 32],
    signer_index: usize,
) -> Result<PartialSignature> {
    // Get nonce values (this will fail if nonce was already used)
    let k1 = secret_nonce.k1()?;
    let k2 = secret_nonce.k2()?;

    // Compute nonce coefficient b
    let b = compute_nonce_coeff(public_nonces, key_agg.xonly_pubkey(), msg)?;

    // Compute effective nonce: k = k1 + b * k2
    let k = compute_effective_nonce(k1, k2, &b, agg_nonce.parity)?;

    // Compute challenge e = H(R || P || m)
    let e = challenge_hash(&agg_nonce.agg_r_xonly, key_agg.xonly_pubkey(), msg);

    // Get coefficient for this signer
    let coeff = key_agg
        .coefficient(signer_index)
        .ok_or(MusigError::InvalidSessionState(format!(
            "No coefficient for signer {}",
            signer_index
        )))?;

    // Compute partial signature: s = k + e * a * d
    // where a is the key coefficient and d is the secret key
    let s = compute_partial_sig(&k, &e, coeff, secret_key, key_agg.parity())?;

    // Mark nonce as used to prevent reuse
    secret_nonce.mark_used();

    Ok(PartialSignature { s, signer_index })
}

/// Aggregate partial signatures into a complete Schnorr signature.
pub fn aggregate_partial_signatures(
    partial_sigs: &[PartialSignature],
    agg_nonce: &AggregatedNonce,
    key_agg: &KeyAggContext,
) -> Result<SchnorrSignature> {
    if partial_sigs.len() != key_agg.num_signers() {
        return Err(MusigError::InvalidSignature(format!(
            "Expected {} partial signatures, got {}",
            key_agg.num_signers(),
            partial_sigs.len()
        )));
    }

    // Sum all partial signatures
    let mut s_sum = [0u8; 32];
    for partial in partial_sigs {
        s_sum = scalar_add(&s_sum, &partial.s)?;
    }

    Ok(SchnorrSignature {
        r: agg_nonce.agg_r_xonly,
        s: s_sum,
    })
}

/// Verify a complete Schnorr signature.
pub fn verify_signature(
    signature: &SchnorrSignature,
    pubkey: &[u8; 32],
    msg: &[u8; 32],
) -> Result<bool> {
    use secp256k1::{schnorr::Signature, Message, XOnlyPublicKey};

    let secp = Secp256k1::new();

    let xonly_pk = XOnlyPublicKey::from_slice(pubkey)
        .map_err(|e| MusigError::InvalidPublicKey(e.to_string()))?;

    let sig = Signature::from_slice(&signature.to_bytes())
        .map_err(|e| MusigError::InvalidSignature(e.to_string()))?;

    let message =
        Message::from_digest_slice(msg).map_err(|e| MusigError::InvalidSignature(e.to_string()))?;

    Ok(secp.verify_schnorr(&sig, &message, &xonly_pk).is_ok())
}

/// Compute effective nonce k = k1 + b * k2, negated if R has odd Y.
fn compute_effective_nonce(
    k1: &[u8; 32],
    k2: &[u8; 32],
    b: &[u8; 32],
    negate: bool,
) -> Result<[u8; 32]> {
    // k = k1 + b * k2
    let b_k2 = scalar_mul(b, k2)?;
    let mut k = scalar_add(k1, &b_k2)?;

    // Negate if R has odd Y
    if negate {
        k = scalar_negate(&k)?;
    }

    Ok(k)
}

/// Compute partial signature s = k + e * a * d.
fn compute_partial_sig(
    k: &[u8; 32],
    e: &[u8; 32],
    coeff: &[u8; 32],
    secret_key: &[u8; 32],
    negate_key: bool,
) -> Result<[u8; 32]> {
    // d = secret_key (negated if aggregate key has odd Y)
    let d = if negate_key {
        scalar_negate(secret_key)?
    } else {
        *secret_key
    };

    // e * a
    let e_a = scalar_mul(e, coeff)?;

    // e * a * d
    let e_a_d = scalar_mul(&e_a, &d)?;

    // s = k + e * a * d
    scalar_add(k, &e_a_d)
}

/// Scalar addition modulo curve order.
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    // Handle zero case for a
    let is_a_zero = a.iter().all(|&x| x == 0);
    if is_a_zero {
        return Ok(*b);
    }

    // Handle zero case for b
    let is_b_zero = b.iter().all(|&x| x == 0);
    if is_b_zero {
        return Ok(*a);
    }

    let sk_a =
        SecretKey::from_slice(a).map_err(|e| MusigError::InvalidSignature(e.to_string()))?;
    let sk_b =
        SecretKey::from_slice(b).map_err(|e| MusigError::InvalidSignature(e.to_string()))?;

    let result = sk_a
        .add_tweak(&sk_b.into())
        .map_err(|e| MusigError::InvalidSignature(e.to_string()))?;

    Ok(result.secret_bytes())
}

/// Scalar multiplication modulo curve order.
fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    // Handle zero case
    let is_a_zero = a.iter().all(|&x| x == 0);
    let is_b_zero = b.iter().all(|&x| x == 0);
    if is_a_zero || is_b_zero {
        return Ok([0u8; 32]);
    }

    let sk_a =
        SecretKey::from_slice(a).map_err(|e| MusigError::InvalidSignature(e.to_string()))?;
    let sk_b =
        SecretKey::from_slice(b).map_err(|e| MusigError::InvalidSignature(e.to_string()))?;

    let result = sk_a
        .mul_tweak(&sk_b.into())
        .map_err(|e| MusigError::InvalidSignature(e.to_string()))?;

    Ok(result.secret_bytes())
}

/// Scalar negation modulo curve order.
fn scalar_negate(a: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = SecretKey::from_slice(a).map_err(|e| MusigError::InvalidSignature(e.to_string()))?;
    Ok(sk.negate().secret_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::SecretNonce;
    use rustywallet_keys::prelude::PrivateKey;

    #[test]
    fn test_partial_signature_serialization() {
        let s = [42u8; 32];
        let partial = PartialSignature { s, signer_index: 0 };

        let hex = partial.to_hex();
        let recovered = PartialSignature::from_hex(&hex, 0).unwrap();

        assert_eq!(partial, recovered);
    }

    #[test]
    fn test_schnorr_signature_serialization() {
        let sig = SchnorrSignature {
            r: [1u8; 32],
            s: [2u8; 32],
        };

        let bytes = sig.to_bytes();
        let recovered = SchnorrSignature::from_bytes(&bytes).unwrap();

        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_full_musig2_signing() {
        // Setup: 2-of-2 MuSig
        let sk1 = PrivateKey::random();
        let sk2 = PrivateKey::random();
        let pk1 = sk1.public_key().to_compressed();
        let pk2 = sk2.public_key().to_compressed();

        // Key aggregation
        let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
        let agg_pk = key_agg.xonly_pubkey();

        // Message to sign
        let msg = [0u8; 32];

        // Generate nonces
        let mut nonce1 =
            SecretNonce::generate(&sk1.to_bytes(), &pk1, agg_pk, Some(&msg), None).unwrap();
        let mut nonce2 =
            SecretNonce::generate(&sk2.to_bytes(), &pk2, agg_pk, Some(&msg), None).unwrap();

        let pub_nonce1 = nonce1.public_nonce().unwrap();
        let pub_nonce2 = nonce2.public_nonce().unwrap();
        let public_nonces = vec![pub_nonce1.clone(), pub_nonce2.clone()];

        // Aggregate nonces
        let agg_nonce = AggregatedNonce::aggregate(&public_nonces, agg_pk, &msg).unwrap();

        // Find signer indices
        let idx1 = key_agg.index_of(&pk1).unwrap();
        let idx2 = key_agg.index_of(&pk2).unwrap();

        // Create partial signatures
        let partial1 = create_partial_signature(
            &mut nonce1,
            &sk1.to_bytes(),
            &key_agg,
            &agg_nonce,
            &public_nonces,
            &msg,
            idx1,
        )
        .unwrap();

        let partial2 = create_partial_signature(
            &mut nonce2,
            &sk2.to_bytes(),
            &key_agg,
            &agg_nonce,
            &public_nonces,
            &msg,
            idx2,
        )
        .unwrap();

        // Aggregate signatures
        let signature =
            aggregate_partial_signatures(&[partial1, partial2], &agg_nonce, &key_agg).unwrap();

        // Verify
        let valid = verify_signature(&signature, agg_pk, &msg).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_nonce_reuse_prevented() {
        let sk = PrivateKey::random();
        let pk = sk.public_key().to_compressed();
        let agg_pk = [0u8; 32];
        let msg = [0u8; 32];

        let mut nonce = SecretNonce::generate(&sk.to_bytes(), &pk, &agg_pk, Some(&msg), None).unwrap();
        let pub_nonce = nonce.public_nonce().unwrap();

        let key_agg = KeyAggContext::new(&[pk, PrivateKey::random().public_key().to_compressed()]).unwrap();
        let agg_nonce = AggregatedNonce::aggregate(&[pub_nonce.clone(), pub_nonce.clone()], &agg_pk, &msg).unwrap();

        // First signing should work
        let _ = create_partial_signature(
            &mut nonce,
            &sk.to_bytes(),
            &key_agg,
            &agg_nonce,
            &[pub_nonce.clone(), pub_nonce.clone()],
            &msg,
            0,
        );

        // Second signing should fail (nonce reuse)
        let result = create_partial_signature(
            &mut nonce,
            &sk.to_bytes(),
            &key_agg,
            &agg_nonce,
            &[pub_nonce.clone(), pub_nonce],
            &msg,
            0,
        );

        assert!(result.is_err());
    }
}
