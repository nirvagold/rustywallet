//! Signature aggregation for FROST.

use crate::error::{FrostError, Result};
use crate::identifier::Identifier;
use crate::keys::PublicKeyPackage;
use crate::nonce::{compute_binding_factor, CommitmentShare};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// A complete Schnorr signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// R.x (32 bytes)
    pub r: [u8; 32],
    /// s (32 bytes)
    pub s: [u8; 32],
}

impl Signature {
    /// Create from bytes (64 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(FrostError::InvalidSignature(format!(
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
        let bytes = hex::decode(hex_str).map_err(|e| FrostError::HexError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Aggregate signature shares into a complete signature.
pub fn aggregate(
    commitment_list: &[CommitmentShare],
    signature_shares: &[crate::signing::SignatureShare],
    public_key_package: &PublicKeyPackage,
    msg: &[u8],
) -> Result<Signature> {
    // Verify we have enough shares
    if signature_shares.len() < public_key_package.threshold() {
        return Err(FrostError::InsufficientSigners {
            needed: public_key_package.threshold(),
            got: signature_shares.len(),
        });
    }

    // Compute binding factors
    let binding_factors: Vec<(Identifier, [u8; 32])> = commitment_list
        .iter()
        .map(|cs| {
            let bf = compute_binding_factor(&cs.identifier, commitment_list, msg)?;
            Ok((cs.identifier, bf))
        })
        .collect::<Result<Vec<_>>>()?;

    // Compute group commitment R
    let group_commitment = compute_group_commitment(commitment_list, &binding_factors)?;

    // Get R.x
    let r_pk = PublicKey::from_slice(&group_commitment)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let (r_xonly, _) = r_pk.x_only_public_key();
    let r = r_xonly.serialize();

    // Sum all signature shares
    let mut s = [0u8; 32];
    for share in signature_shares {
        s = scalar_add(&s, &share.share)?;
    }

    Ok(Signature { r, s })
}

/// Compute group commitment R.
fn compute_group_commitment(
    commitment_list: &[CommitmentShare],
    binding_factors: &[(Identifier, [u8; 32])],
) -> Result<[u8; 33]> {
    let secp = Secp256k1::new();
    let mut result: Option<PublicKey> = None;

    for cs in commitment_list {
        let binding = binding_factors
            .iter()
            .find(|(id, _)| *id == cs.identifier)
            .map(|(_, b)| b)
            .ok_or_else(|| FrostError::MissingData(format!(
                "No binding factor for {}",
                cs.identifier
            )))?;

        let d = PublicKey::from_slice(&cs.commitments.hiding)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let e = PublicKey::from_slice(&cs.commitments.binding)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;

        // R_i = D_i + E_i * rho_i
        let binding_sk = SecretKey::from_slice(binding)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let e_scaled = e.mul_tweak(&secp, &binding_sk.into())
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let r_i = d.combine(&e_scaled)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;

        result = match result {
            None => Some(r_i),
            Some(acc) => Some(acc.combine(&r_i)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?),
        };
    }

    let result = result.ok_or_else(|| FrostError::MissingData("No commitments".into()))?;
    Ok(result.serialize())
}

/// Verify a signature share.
pub fn verify_signature_share(
    share: &crate::signing::SignatureShare,
    commitment_list: &[CommitmentShare],
    public_key_package: &PublicKeyPackage,
    msg: &[u8],
) -> Result<bool> {
    let secp = Secp256k1::new();

    // Get participant's verification share
    let vs = public_key_package
        .verification_share(share.identifier)
        .ok_or_else(|| FrostError::InvalidParticipant(format!(
            "No verification share for {}",
            share.identifier
        )))?;

    // Compute binding factors
    let binding_factors: Vec<(Identifier, [u8; 32])> = commitment_list
        .iter()
        .map(|cs| {
            let bf = compute_binding_factor(&cs.identifier, commitment_list, msg)?;
            Ok((cs.identifier, bf))
        })
        .collect::<Result<Vec<_>>>()?;

    // Compute group commitment R
    let group_commitment = compute_group_commitment(commitment_list, &binding_factors)?;

    // Get binding factor for this participant
    let rho = binding_factors
        .iter()
        .find(|(id, _)| *id == share.identifier)
        .map(|(_, b)| b)
        .ok_or_else(|| FrostError::MissingData("No binding factor".into()))?;

    // Compute challenge
    let challenge = compute_challenge(&group_commitment, &public_key_package.group_public_key().to_bytes(), msg)?;

    // Compute Lagrange coefficient
    let lambda = compute_lagrange_coefficient(
        &share.identifier,
        &commitment_list.iter().map(|cs| cs.identifier).collect::<Vec<_>>(),
    )?;

    // Get participant's commitment
    let cs = commitment_list
        .iter()
        .find(|cs| cs.identifier == share.identifier)
        .ok_or_else(|| FrostError::MissingData("No commitment".into()))?;

    // Verify: g^z_i == R_i * Y_i^(c * lambda_i)
    // R_i = D_i + E_i * rho_i
    let d = PublicKey::from_slice(&cs.commitments.hiding)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let e = PublicKey::from_slice(&cs.commitments.binding)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    let rho_sk = SecretKey::from_slice(rho)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let e_scaled = e.mul_tweak(&secp, &rho_sk.into())
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let r_i = d.combine(&e_scaled)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    // Y_i^(c * lambda_i)
    let y_i = PublicKey::from_slice(&vs.public_key)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let c_lambda = scalar_mul(&challenge, &lambda)?;
    let c_lambda_sk = SecretKey::from_slice(&c_lambda)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let y_scaled = y_i.mul_tweak(&secp, &c_lambda_sk.into())
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    // R_i * Y_i^(c * lambda_i)
    let expected = r_i.combine(&y_scaled)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    // g^z_i
    let z_sk = SecretKey::from_slice(&share.share)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let actual = PublicKey::from_secret_key(&secp, &z_sk);

    Ok(actual.serialize() == expected.serialize())
}

/// Compute challenge hash.
fn compute_challenge(
    group_commitment: &[u8; 33],
    group_public_key: &[u8; 33],
    msg: &[u8],
) -> Result<[u8; 32]> {
    let r_pk = PublicKey::from_slice(group_commitment)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let (r_xonly, _) = r_pk.x_only_public_key();

    let p_pk = PublicKey::from_slice(group_public_key)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let (p_xonly, _) = p_pk.x_only_public_key();

    let tag = Sha256::digest(b"BIP0340/challenge");
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    hasher.update(r_xonly.serialize());
    hasher.update(p_xonly.serialize());
    hasher.update(msg);

    Ok(hasher.finalize().into())
}

/// Compute Lagrange coefficient.
fn compute_lagrange_coefficient(
    identifier: &Identifier,
    participants: &[Identifier],
) -> Result<[u8; 32]> {
    let x_i = identifier.value() as i64;
    let mut num: i64 = 1;
    let mut den: i64 = 1;

    for p in participants {
        if p == identifier {
            continue;
        }
        let x_j = p.value() as i64;
        num *= x_j;
        den *= x_j - x_i;
    }

    if den == 0 {
        return Err(FrostError::InvalidParticipant("Duplicate participant".into()));
    }

    let negative = (num < 0) != (den < 0);
    let num = num.unsigned_abs();
    let den = den.unsigned_abs();

    let mut result = [0u8; 32];
    result[24..32].copy_from_slice(&num.to_be_bytes());
    let num_sk = SecretKey::from_slice(&result)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    let mut den_bytes = [0u8; 32];
    den_bytes[24..32].copy_from_slice(&den.to_be_bytes());
    let den_sk = SecretKey::from_slice(&den_bytes)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    let den_inv = scalar_inverse(&den_sk.secret_bytes())?;
    let lambda = scalar_mul(&num_sk.secret_bytes(), &den_inv)?;

    if negative {
        scalar_negate(&lambda)
    } else {
        Ok(lambda)
    }
}

/// Scalar addition.
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    let is_a_zero = a.iter().all(|&x| x == 0);
    if is_a_zero {
        return Ok(*b);
    }

    let is_b_zero = b.iter().all(|&x| x == 0);
    if is_b_zero {
        return Ok(*a);
    }

    let sk_a = SecretKey::from_slice(a)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let sk_b = SecretKey::from_slice(b)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    let result = sk_a.add_tweak(&sk_b.into())
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    Ok(result.secret_bytes())
}

/// Scalar multiplication.
fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    let is_a_zero = a.iter().all(|&x| x == 0);
    let is_b_zero = b.iter().all(|&x| x == 0);
    if is_a_zero || is_b_zero {
        return Ok([0u8; 32]);
    }

    let sk_a = SecretKey::from_slice(a)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let sk_b = SecretKey::from_slice(b)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    let result = sk_a.mul_tweak(&sk_b.into())
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    Ok(result.secret_bytes())
}

/// Scalar negation.
fn scalar_negate(a: &[u8; 32]) -> Result<[u8; 32]> {
    let is_zero = a.iter().all(|&x| x == 0);
    if is_zero {
        return Ok(*a);
    }

    let sk = SecretKey::from_slice(a)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    Ok(sk.negate().secret_bytes())
}

/// Scalar inverse using Fermat's little theorem.
fn scalar_inverse(a: &[u8; 32]) -> Result<[u8; 32]> {
    let is_zero = a.iter().all(|&x| x == 0);
    if is_zero {
        return Err(FrostError::CryptoError("Cannot invert zero".into()));
    }

    let n_minus_2: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3F,
    ];

    let mut result = [0u8; 32];
    result[31] = 1;

    let mut base = *a;

    for i in (0..256).rev() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (n_minus_2[31 - byte_idx] >> bit_idx) & 1;

        if bit == 1 {
            result = scalar_mul(&result, &base)?;
        }

        if i > 0 {
            base = scalar_mul(&base, &base)?;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_serialization() {
        let sig = Signature {
            r: [1u8; 32],
            s: [2u8; 32],
        };

        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes).unwrap();

        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_signature_hex() {
        let sig = Signature {
            r: [0xab; 32],
            s: [0xcd; 32],
        };

        let hex = sig.to_hex();
        let recovered = Signature::from_hex(&hex).unwrap();

        assert_eq!(sig, recovered);
    }
}
