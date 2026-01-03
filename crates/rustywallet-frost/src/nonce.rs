//! Nonce generation for FROST signing.

use crate::error::{FrostError, Result};
use crate::identifier::Identifier;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

/// Secret nonce pair for signing.
#[derive(ZeroizeOnDrop)]
pub struct SigningNonces {
    /// First nonce
    d: [u8; 32],
    /// Second nonce
    e: [u8; 32],
    /// Whether nonces have been used
    #[zeroize(skip)]
    used: bool,
}

impl SigningNonces {
    /// Generate random nonces.
    pub fn generate(signing_share: &[u8; 32]) -> Result<Self> {
        // Generate random nonces with additional entropy from signing share
        let mut hasher = Sha256::new();
        hasher.update(signing_share);
        hasher.update(rand::random::<[u8; 32]>());
        let d_seed: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(signing_share);
        hasher.update(rand::random::<[u8; 32]>());
        let e_seed: [u8; 32] = hasher.finalize().into();

        // Ensure valid scalars
        let d = SecretKey::from_slice(&d_seed)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?
            .secret_bytes();
        let e = SecretKey::from_slice(&e_seed)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?
            .secret_bytes();

        Ok(Self { d, e, used: false })
    }

    /// Get the public nonce commitments.
    pub fn commitments(&self) -> Result<SigningCommitments> {
        if self.used {
            return Err(FrostError::SigningError("Nonces already used".into()));
        }

        let secp = Secp256k1::new();

        let d_sk = SecretKey::from_slice(&self.d)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let e_sk = SecretKey::from_slice(&self.e)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;

        let hiding = PublicKey::from_secret_key(&secp, &d_sk).serialize();
        let binding = PublicKey::from_secret_key(&secp, &e_sk).serialize();

        Ok(SigningCommitments { hiding, binding })
    }

    /// Get d value (for signing).
    pub(crate) fn d(&self) -> Result<&[u8; 32]> {
        if self.used {
            return Err(FrostError::SigningError("Nonces already used".into()));
        }
        Ok(&self.d)
    }

    /// Get e value (for signing).
    pub(crate) fn e(&self) -> Result<&[u8; 32]> {
        if self.used {
            return Err(FrostError::SigningError("Nonces already used".into()));
        }
        Ok(&self.e)
    }

    /// Mark nonces as used.
    pub(crate) fn mark_used(&mut self) {
        self.used = true;
    }
}

/// Public nonce commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningCommitments {
    /// Hiding commitment D = g^d
    pub hiding: [u8; 33],
    /// Binding commitment E = g^e
    pub binding: [u8; 33],
}

impl SigningCommitments {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[0..33].copy_from_slice(&self.hiding);
        bytes[33..66].copy_from_slice(&self.binding);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 66 {
            return Err(FrostError::InvalidCommitment(format!(
                "Expected 66 bytes, got {}",
                bytes.len()
            )));
        }

        let mut hiding = [0u8; 33];
        let mut binding = [0u8; 33];
        hiding.copy_from_slice(&bytes[0..33]);
        binding.copy_from_slice(&bytes[33..66]);

        // Validate public keys
        PublicKey::from_slice(&hiding)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        PublicKey::from_slice(&binding)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;

        Ok(Self { hiding, binding })
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

/// Commitment with participant identifier.
#[derive(Debug, Clone)]
pub struct CommitmentShare {
    /// Participant identifier
    pub identifier: Identifier,
    /// Signing commitments
    pub commitments: SigningCommitments,
}

impl CommitmentShare {
    /// Create a new commitment share.
    pub fn new(identifier: Identifier, commitments: SigningCommitments) -> Self {
        Self {
            identifier,
            commitments,
        }
    }
}

/// Compute binding factor for a participant.
pub fn compute_binding_factor(
    identifier: &Identifier,
    commitment_list: &[CommitmentShare],
    msg: &[u8],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();

    // Hash all commitments
    for cs in commitment_list {
        hasher.update(cs.identifier.value().to_be_bytes());
        hasher.update(cs.commitments.hiding);
        hasher.update(cs.commitments.binding);
    }

    // Hash message
    hasher.update(msg);

    // Hash participant identifier
    hasher.update(identifier.value().to_be_bytes());

    let hash: [u8; 32] = hasher.finalize().into();

    // Ensure valid scalar
    let sk = SecretKey::from_slice(&hash)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    Ok(sk.secret_bytes())
}

/// Compute group commitment R.
pub fn compute_group_commitment(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let signing_share = [42u8; 32];
        let nonces = SigningNonces::generate(&signing_share).unwrap();

        let commitments = nonces.commitments().unwrap();
        assert_eq!(commitments.hiding.len(), 33);
        assert_eq!(commitments.binding.len(), 33);
    }

    #[test]
    fn test_commitments_serialization() {
        let signing_share = [42u8; 32];
        let nonces = SigningNonces::generate(&signing_share).unwrap();
        let commitments = nonces.commitments().unwrap();

        let bytes = commitments.to_bytes();
        let recovered = SigningCommitments::from_bytes(&bytes).unwrap();

        assert_eq!(commitments, recovered);
    }

    #[test]
    fn test_nonce_reuse_prevention() {
        let signing_share = [42u8; 32];
        let mut nonces = SigningNonces::generate(&signing_share).unwrap();

        // First access should work
        let _ = nonces.d().unwrap();
        let _ = nonces.e().unwrap();

        // Mark as used
        nonces.mark_used();

        // Second access should fail
        assert!(nonces.d().is_err());
        assert!(nonces.e().is_err());
        assert!(nonces.commitments().is_err());
    }
}
