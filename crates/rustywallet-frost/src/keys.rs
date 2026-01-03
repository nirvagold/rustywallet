//! Key types for FROST.

use crate::error::{FrostError, Result};
use crate::identifier::Identifier;
use crate::share::{SecretShare, VerificationShare};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::ZeroizeOnDrop;

/// A key package containing a participant's signing key and group information.
#[derive(Clone, ZeroizeOnDrop)]
pub struct KeyPackage {
    /// Participant identifier
    #[zeroize(skip)]
    identifier: Identifier,
    /// Secret signing share
    signing_share: [u8; 32],
    /// Verification share (public)
    #[zeroize(skip)]
    verification_share: [u8; 33],
    /// Group public key
    #[zeroize(skip)]
    group_public_key: [u8; 33],
    /// Threshold
    #[zeroize(skip)]
    threshold: usize,
    /// Total participants
    #[zeroize(skip)]
    num_participants: usize,
}

impl KeyPackage {
    /// Create a new key package.
    pub fn new(
        identifier: Identifier,
        signing_share: [u8; 32],
        verification_share: [u8; 33],
        group_public_key: [u8; 33],
        threshold: usize,
        num_participants: usize,
    ) -> Self {
        Self {
            identifier,
            signing_share,
            verification_share,
            group_public_key,
            threshold,
            num_participants,
        }
    }

    /// Create from a secret share and group info.
    pub fn from_share(
        share: &SecretShare,
        group_public_key: [u8; 33],
        threshold: usize,
        num_participants: usize,
    ) -> Result<Self> {
        let vs = share.verification_share()?;

        Ok(Self {
            identifier: share.identifier(),
            signing_share: *share.value(),
            verification_share: vs.public_key,
            group_public_key,
            threshold,
            num_participants,
        })
    }

    /// Get the participant identifier.
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// Get the signing share.
    pub fn signing_share(&self) -> &[u8; 32] {
        &self.signing_share
    }

    /// Get the verification share.
    pub fn verification_share(&self) -> &[u8; 33] {
        &self.verification_share
    }

    /// Get the group public key.
    pub fn group_public_key(&self) -> &[u8; 33] {
        &self.group_public_key
    }

    /// Get the threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get the number of participants.
    pub fn num_participants(&self) -> usize {
        self.num_participants
    }
}

/// The group's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPublicKey {
    /// Compressed public key (33 bytes)
    key: [u8; 33],
}

impl GroupPublicKey {
    /// Create from compressed bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 {
            return Err(FrostError::CryptoError(format!(
                "Expected 33 bytes, got {}",
                bytes.len()
            )));
        }

        // Validate it's a valid public key
        PublicKey::from_slice(bytes).map_err(|e| FrostError::CryptoError(e.to_string()))?;

        let mut key = [0u8; 33];
        key.copy_from_slice(bytes);

        Ok(Self { key })
    }

    /// Create from a secret key (for testing).
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self> {
        let secp = Secp256k1::new();
        let sk =
            SecretKey::from_slice(secret).map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let pk = PublicKey::from_secret_key(&secp, &sk);

        Ok(Self {
            key: pk.serialize(),
        })
    }

    /// Get the compressed bytes.
    pub fn to_bytes(&self) -> [u8; 33] {
        self.key
    }

    /// Get the x-only public key (32 bytes).
    pub fn to_xonly(&self) -> Result<[u8; 32]> {
        let pk =
            PublicKey::from_slice(&self.key).map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let (xonly, _parity) = pk.x_only_public_key();
        Ok(xonly.serialize())
    }

    /// Serialize to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.key)
    }

    /// Parse from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| FrostError::HexError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Public key package containing all verification shares.
#[derive(Debug, Clone)]
pub struct PublicKeyPackage {
    /// Verification shares for all participants
    verification_shares: Vec<VerificationShare>,
    /// Group public key
    group_public_key: GroupPublicKey,
    /// Threshold
    threshold: usize,
}

impl PublicKeyPackage {
    /// Create a new public key package.
    pub fn new(
        verification_shares: Vec<VerificationShare>,
        group_public_key: GroupPublicKey,
        threshold: usize,
    ) -> Self {
        Self {
            verification_shares,
            group_public_key,
            threshold,
        }
    }

    /// Get verification shares.
    pub fn verification_shares(&self) -> &[VerificationShare] {
        &self.verification_shares
    }

    /// Get the group public key.
    pub fn group_public_key(&self) -> &GroupPublicKey {
        &self.group_public_key
    }

    /// Get the threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get verification share for a participant.
    pub fn verification_share(&self, id: Identifier) -> Option<&VerificationShare> {
        self.verification_shares.iter().find(|vs| vs.identifier == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_public_key() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let gpk = GroupPublicKey::from_secret(&sk.secret_bytes()).unwrap();

        let bytes = gpk.to_bytes();
        let recovered = GroupPublicKey::from_bytes(&bytes).unwrap();

        assert_eq!(gpk, recovered);
    }

    #[test]
    fn test_group_public_key_xonly() {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let gpk = GroupPublicKey::from_secret(&sk.secret_bytes()).unwrap();

        let xonly = gpk.to_xonly().unwrap();
        assert_eq!(xonly.len(), 32);
    }

    #[test]
    fn test_key_package() {
        let id = Identifier::new(1).unwrap();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);

        let kp = KeyPackage::new(
            id,
            sk.secret_bytes(),
            pk.serialize(),
            pk.serialize(),
            2,
            3,
        );

        assert_eq!(kp.identifier(), id);
        assert_eq!(kp.threshold(), 2);
        assert_eq!(kp.num_participants(), 3);
    }
}
