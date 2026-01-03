//! Adaptor signatures for MuSig2.
//!
//! Adaptor signatures allow creating signatures that are "encrypted"
//! to a point T, and can only be completed by someone who knows
//! the discrete log of T.

use crate::error::{MusigError, Result};
use crate::key_agg::KeyAggContext;
use crate::nonce::{compute_nonce_coeff, AggregatedNonce, PublicNonce, SecretNonce};
use crate::signing::{PartialSignature, SchnorrSignature};
use crate::tagged_hash::challenge_hash;
use secp256k1::{PublicKey, SecretKey};

/// An adaptor signature that can be completed with a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorSignature {
    /// R' = R + T (adapted nonce point)
    pub r_prime: [u8; 32],
    /// s' (adapted signature scalar)
    pub s_prime: [u8; 32],
    /// The adaptor point T
    pub adaptor_point: [u8; 33],
}

impl AdaptorSignature {
    /// Serialize to bytes (97 bytes).
    pub fn to_bytes(&self) -> [u8; 97] {
        let mut bytes = [0u8; 97];
        bytes[..32].copy_from_slice(&self.r_prime);
        bytes[32..64].copy_from_slice(&self.s_prime);
        bytes[64..].copy_from_slice(&self.adaptor_point);
        bytes
    }

    /// Parse from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 97 {
            return Err(MusigError::InvalidAdaptorSig(format!(
                "Expected 97 bytes, got {}",
                bytes.len()
            )));
        }

        let mut r_prime = [0u8; 32];
        let mut s_prime = [0u8; 32];
        let mut adaptor_point = [0u8; 33];

        r_prime.copy_from_slice(&bytes[..32]);
        s_prime.copy_from_slice(&bytes[32..64]);
        adaptor_point.copy_from_slice(&bytes[64..]);

        Ok(Self {
            r_prime,
            s_prime,
            adaptor_point,
        })
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

    /// Complete the adaptor signature with the adaptor secret.
    ///
    /// Given the discrete log t of T (where T = t*G), compute
    /// the final signature s = s' + t.
    pub fn complete(&self, adaptor_secret: &[u8; 32]) -> Result<SchnorrSignature> {
        // s = s' + t
        let sk_s_prime = SecretKey::from_slice(&self.s_prime)
            .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;
        let sk_t = SecretKey::from_slice(adaptor_secret)
            .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;

        let s = sk_s_prime
            .add_tweak(&sk_t.into())
            .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;

        Ok(SchnorrSignature {
            r: self.r_prime,
            s: s.secret_bytes(),
        })
    }

    /// Extract the adaptor secret from a completed signature.
    ///
    /// Given the adaptor signature s' and the final signature s,
    /// compute t = s - s'.
    pub fn extract_secret(&self, final_sig: &SchnorrSignature) -> Result<[u8; 32]> {
        // t = s - s'
        let sk_s = SecretKey::from_slice(&final_sig.s)
            .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;
        let sk_s_prime = SecretKey::from_slice(&self.s_prime)
            .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;

        // s - s' = s + (-s')
        let neg_s_prime = sk_s_prime.negate();
        let t = sk_s
            .add_tweak(&neg_s_prime.into())
            .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;

        Ok(t.secret_bytes())
    }
}

/// Create an adaptor partial signature.
///
/// This creates a partial signature that is "encrypted" to the adaptor point T.
/// The signature can only be completed by someone who knows the discrete log of T.
#[allow(clippy::too_many_arguments)]
pub fn create_adaptor_partial_signature(
    secret_nonce: &mut SecretNonce,
    secret_key: &[u8; 32],
    key_agg: &KeyAggContext,
    agg_nonce: &AggregatedNonce,
    public_nonces: &[PublicNonce],
    adaptor_point: &[u8; 33],
    msg: &[u8; 32],
    signer_index: usize,
) -> Result<PartialSignature> {
    // Parse adaptor point
    let t_point = PublicKey::from_slice(adaptor_point)
        .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;

    // Compute R' = R + T
    let r_point = PublicKey::from_slice(&agg_nonce.agg_r)
        .map_err(|e| MusigError::InvalidNonce(e.to_string()))?;

    let r_prime = r_point
        .combine(&t_point)
        .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;

    // Get x-only R'
    let (r_prime_xonly, r_prime_parity) = r_prime.x_only_public_key();
    let mut r_prime_bytes = [0u8; 32];
    r_prime_bytes.copy_from_slice(&r_prime_xonly.serialize());

    // Get nonce values
    let k1 = secret_nonce.k1()?;
    let k2 = secret_nonce.k2()?;

    // Compute nonce coefficient b
    let b = compute_nonce_coeff(public_nonces, key_agg.xonly_pubkey(), msg)?;

    // Compute effective nonce with R' parity
    let negate_nonce = r_prime_parity == secp256k1::Parity::Odd;
    let k = compute_effective_nonce_adaptor(k1, k2, &b, negate_nonce)?;

    // Compute challenge e = H(R' || P || m)
    let e = challenge_hash(&r_prime_bytes, key_agg.xonly_pubkey(), msg);

    // Get coefficient for this signer
    let coeff = key_agg
        .coefficient(signer_index)
        .ok_or(MusigError::InvalidSessionState(format!(
            "No coefficient for signer {}",
            signer_index
        )))?;

    // Compute partial signature: s' = k + e * a * d
    let s = compute_partial_sig_adaptor(&k, &e, coeff, secret_key, key_agg.parity())?;

    // Mark nonce as used
    secret_nonce.mark_used();

    Ok(PartialSignature { s, signer_index })
}

/// Aggregate adaptor partial signatures.
pub fn aggregate_adaptor_signatures(
    partial_sigs: &[PartialSignature],
    agg_nonce: &AggregatedNonce,
    adaptor_point: &[u8; 33],
    key_agg: &KeyAggContext,
) -> Result<AdaptorSignature> {
    if partial_sigs.len() != key_agg.num_signers() {
        return Err(MusigError::InvalidSignature(format!(
            "Expected {} partial signatures, got {}",
            key_agg.num_signers(),
            partial_sigs.len()
        )));
    }

    // Compute R' = R + T
    let r_point = PublicKey::from_slice(&agg_nonce.agg_r)
        .map_err(|e| MusigError::InvalidNonce(e.to_string()))?;
    let t_point = PublicKey::from_slice(adaptor_point)
        .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;

    let r_prime = r_point
        .combine(&t_point)
        .map_err(|e| MusigError::InvalidAdaptorSig(e.to_string()))?;

    let (r_prime_xonly, _) = r_prime.x_only_public_key();
    let mut r_prime_bytes = [0u8; 32];
    r_prime_bytes.copy_from_slice(&r_prime_xonly.serialize());

    // Sum all partial signatures
    let mut s_sum = [0u8; 32];
    for partial in partial_sigs {
        s_sum = scalar_add(&s_sum, &partial.s)?;
    }

    Ok(AdaptorSignature {
        r_prime: r_prime_bytes,
        s_prime: s_sum,
        adaptor_point: *adaptor_point,
    })
}

/// Compute effective nonce for adaptor signatures.
fn compute_effective_nonce_adaptor(
    k1: &[u8; 32],
    k2: &[u8; 32],
    b: &[u8; 32],
    negate: bool,
) -> Result<[u8; 32]> {
    let b_k2 = scalar_mul(b, k2)?;
    let mut k = scalar_add(k1, &b_k2)?;

    if negate {
        k = scalar_negate(&k)?;
    }

    Ok(k)
}

/// Compute partial signature for adaptor.
fn compute_partial_sig_adaptor(
    k: &[u8; 32],
    e: &[u8; 32],
    coeff: &[u8; 32],
    secret_key: &[u8; 32],
    negate_key: bool,
) -> Result<[u8; 32]> {
    let d = if negate_key {
        scalar_negate(secret_key)?
    } else {
        *secret_key
    };

    let e_a = scalar_mul(e, coeff)?;
    let e_a_d = scalar_mul(&e_a, &d)?;
    scalar_add(k, &e_a_d)
}

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

fn scalar_negate(a: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = SecretKey::from_slice(a).map_err(|e| MusigError::InvalidSignature(e.to_string()))?;
    Ok(sk.negate().secret_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::prelude::PrivateKey;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_adaptor_signature_serialization() {
        let adaptor = AdaptorSignature {
            r_prime: [1u8; 32],
            s_prime: [2u8; 32],
            adaptor_point: [3u8; 33],
        };

        let bytes = adaptor.to_bytes();
        let recovered = AdaptorSignature::from_bytes(&bytes).unwrap();

        assert_eq!(adaptor, recovered);
    }

    #[test]
    fn test_adaptor_complete_and_extract() {
        // Create a simple adaptor signature scenario
        let adaptor_secret = PrivateKey::random();
        let secp = Secp256k1::new();
        let sk_bytes = adaptor_secret.to_bytes();
        let adaptor_point = secp256k1::PublicKey::from_secret_key(
            &secp,
            &SecretKey::from_slice(&sk_bytes).unwrap(),
        )
        .serialize();

        // Create a mock adaptor signature
        let s_prime = PrivateKey::random();
        let r_prime = [1u8; 32]; // Simplified for test

        let adaptor = AdaptorSignature {
            r_prime,
            s_prime: s_prime.to_bytes(),
            adaptor_point,
        };

        // Complete the signature
        let final_sig = adaptor.complete(&sk_bytes).unwrap();

        // Extract the secret
        let extracted = adaptor.extract_secret(&final_sig).unwrap();

        assert_eq!(extracted, sk_bytes);
    }
}
