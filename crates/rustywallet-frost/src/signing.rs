//! FROST signing operations.

use crate::error::{FrostError, Result};
use crate::identifier::Identifier;
use crate::keys::KeyPackage;
use crate::nonce::{compute_binding_factor, CommitmentShare, SigningNonces};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// A partial signature from one signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureShare {
    /// Participant identifier
    pub identifier: Identifier,
    /// Signature share value
    pub share: [u8; 32],
}

impl SignatureShare {
    /// Create a new signature share.
    pub fn new(identifier: Identifier, share: [u8; 32]) -> Self {
        Self { identifier, share }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[0..4].copy_from_slice(&self.identifier.value().to_be_bytes());
        bytes[4..36].copy_from_slice(&self.share);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 36 {
            return Err(FrostError::InvalidSignature(format!(
                "Expected 36 bytes, got {}",
                bytes.len()
            )));
        }

        let id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let identifier = Identifier::new(id)?;

        let mut share = [0u8; 32];
        share.copy_from_slice(&bytes[4..36]);

        Ok(Self { identifier, share })
    }

    /// Serialize to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserialize from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| FrostError::HexError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Create a partial signature.
pub fn sign(
    key_package: &KeyPackage,
    nonces: &mut SigningNonces,
    commitment_list: &[CommitmentShare],
    msg: &[u8],
) -> Result<SignatureShare> {
    let identifier = key_package.identifier();

    // Compute binding factors for all participants
    let binding_factors: Vec<(Identifier, [u8; 32])> = commitment_list
        .iter()
        .map(|cs| {
            let bf = compute_binding_factor(&cs.identifier, commitment_list, msg)?;
            Ok((cs.identifier, bf))
        })
        .collect::<Result<Vec<_>>>()?;

    // Compute group commitment R
    let group_commitment = compute_group_commitment(commitment_list, &binding_factors)?;
    let r_pk = PublicKey::from_slice(&group_commitment)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let (r_xonly, r_parity) = r_pk.x_only_public_key();

    // Get group public key parity
    let p_pk = PublicKey::from_slice(key_package.group_public_key())
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let (p_xonly, p_parity) = p_pk.x_only_public_key();

    // Get binding factor for this participant
    let rho = binding_factors
        .iter()
        .find(|(id, _)| *id == identifier)
        .map(|(_, b)| b)
        .ok_or_else(|| FrostError::MissingData("No binding factor for self".into()))?;

    // Compute challenge using x-only keys
    let challenge = compute_challenge(&r_xonly.serialize(), &p_xonly.serialize(), msg)?;

    // Compute Lagrange coefficient
    let lambda = compute_lagrange_coefficient(
        &identifier,
        &commitment_list.iter().map(|cs| cs.identifier).collect::<Vec<_>>(),
    )?;

    // Get nonce values
    let d = nonces.d()?;
    let e = nonces.e()?;

    // Compute k = d + e * rho
    let e_rho = scalar_mul(e, rho)?;
    let mut k = scalar_add(d, &e_rho)?;

    // Negate k if R has odd Y
    if r_parity == secp256k1::Parity::Odd {
        k = scalar_negate(&k)?;
    }

    // Get signing share, negate if P has odd Y
    let mut s = *key_package.signing_share();
    if p_parity == secp256k1::Parity::Odd {
        s = scalar_negate(&s)?;
    }

    // Compute signature share: z_i = k_i + lambda_i * s_i * c
    let lambda_s = scalar_mul(&lambda, &s)?;
    let lambda_s_c = scalar_mul(&lambda_s, &challenge)?;
    let share = scalar_add(&k, &lambda_s_c)?;

    // Mark nonces as used
    nonces.mark_used();

    Ok(SignatureShare::new(identifier, share))
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

/// Compute challenge hash using x-only keys.
fn compute_challenge(
    r_xonly: &[u8; 32],
    p_xonly: &[u8; 32],
    msg: &[u8],
) -> Result<[u8; 32]> {
    // BIP340-style challenge: H(R || P || m)
    let tag = Sha256::digest(b"BIP0340/challenge");
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    hasher.update(r_xonly);
    hasher.update(p_xonly);
    hasher.update(msg);

    Ok(hasher.finalize().into())
}

/// Compute Lagrange coefficient for a participant.
pub fn compute_lagrange_coefficient(
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

    // Handle sign
    let negative = (num < 0) != (den < 0);
    let num = num.unsigned_abs();
    let den = den.unsigned_abs();

    // Create scalar for numerator
    let mut result = [0u8; 32];
    result[24..32].copy_from_slice(&num.to_be_bytes());
    let num_sk = SecretKey::from_slice(&result)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    // Create scalar for denominator and compute inverse
    let mut den_bytes = [0u8; 32];
    den_bytes[24..32].copy_from_slice(&den.to_be_bytes());
    let den_sk = SecretKey::from_slice(&den_bytes)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    // Compute modular inverse of denominator
    let den_inv = scalar_inverse(&den_sk.secret_bytes())?;

    // lambda = num * den^(-1)
    let lambda = scalar_mul(&num_sk.secret_bytes(), &den_inv)?;

    if negative {
        scalar_negate(&lambda)
    } else {
        Ok(lambda)
    }
}

/// Scalar addition modulo curve order.
pub fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
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

/// Scalar multiplication modulo curve order.
pub fn scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
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

/// Scalar negation modulo curve order.
pub fn scalar_negate(a: &[u8; 32]) -> Result<[u8; 32]> {
    let is_zero = a.iter().all(|&x| x == 0);
    if is_zero {
        return Ok(*a);
    }

    let sk = SecretKey::from_slice(a)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    Ok(sk.negate().secret_bytes())
}

/// Compute modular inverse using Fermat's little theorem.
pub fn scalar_inverse(a: &[u8; 32]) -> Result<[u8; 32]> {
    let is_zero = a.iter().all(|&x| x == 0);
    if is_zero {
        return Err(FrostError::CryptoError("Cannot invert zero".into()));
    }

    // secp256k1 order n - 2
    let n_minus_2: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3F,
    ];

    // Use square-and-multiply for a^(n-2)
    let mut result = [0u8; 32];
    result[31] = 1; // result = 1

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
    fn test_signature_share_serialization() {
        let id = Identifier::new(1).unwrap();
        let share = [42u8; 32];
        let sig_share = SignatureShare::new(id, share);

        let bytes = sig_share.to_bytes();
        let recovered = SignatureShare::from_bytes(&bytes).unwrap();

        assert_eq!(sig_share, recovered);
    }

    #[test]
    fn test_lagrange_coefficient() {
        let p1 = Identifier::new(1).unwrap();
        let p2 = Identifier::new(2).unwrap();
        let p3 = Identifier::new(3).unwrap();

        let participants = vec![p1, p2, p3];

        // Should not error
        let _ = compute_lagrange_coefficient(&p1, &participants).unwrap();
        let _ = compute_lagrange_coefficient(&p2, &participants).unwrap();
        let _ = compute_lagrange_coefficient(&p3, &participants).unwrap();
    }
}
