//! Secret shares for FROST.

use crate::error::{FrostError, Result};
use crate::identifier::Identifier;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::ZeroizeOnDrop;

/// A secret share for a participant.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretShare {
    /// Participant identifier
    #[zeroize(skip)]
    identifier: Identifier,
    /// Secret share value
    value: [u8; 32],
}

impl SecretShare {
    /// Create a new secret share.
    pub fn new(identifier: Identifier, value: [u8; 32]) -> Self {
        Self { identifier, value }
    }

    /// Get the participant identifier.
    pub fn identifier(&self) -> Identifier {
        self.identifier
    }

    /// Get the share value.
    pub fn value(&self) -> &[u8; 32] {
        &self.value
    }

    /// Compute the public verification share.
    pub fn verification_share(&self) -> Result<VerificationShare> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&self.value)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let pk = PublicKey::from_secret_key(&secp, &sk);

        Ok(VerificationShare {
            identifier: self.identifier,
            public_key: pk.serialize(),
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];
        bytes[0..4].copy_from_slice(&self.identifier.value().to_be_bytes());
        bytes[4..36].copy_from_slice(&self.value);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 36 {
            return Err(FrostError::InvalidShare(format!(
                "Expected 36 bytes, got {}",
                bytes.len()
            )));
        }

        let id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let identifier = Identifier::new(id)?;

        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes[4..36]);

        Ok(Self { identifier, value })
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

/// A public verification share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationShare {
    /// Participant identifier
    pub identifier: Identifier,
    /// Public key (compressed, 33 bytes)
    pub public_key: [u8; 33],
}

impl VerificationShare {
    /// Create a new verification share.
    pub fn new(identifier: Identifier, public_key: [u8; 33]) -> Self {
        Self {
            identifier,
            public_key,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 37] {
        let mut bytes = [0u8; 37];
        bytes[0..4].copy_from_slice(&self.identifier.value().to_be_bytes());
        bytes[4..37].copy_from_slice(&self.public_key);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 37 {
            return Err(FrostError::InvalidShare(format!(
                "Expected 37 bytes, got {}",
                bytes.len()
            )));
        }

        let id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let identifier = Identifier::new(id)?;

        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(&bytes[4..37]);

        Ok(Self {
            identifier,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_share_serialization() {
        let id = Identifier::new(1).unwrap();
        let value = [42u8; 32];
        let share = SecretShare::new(id, value);

        let bytes = share.to_bytes();
        let recovered = SecretShare::from_bytes(&bytes).unwrap();

        assert_eq!(share.identifier(), recovered.identifier());
        assert_eq!(share.value(), recovered.value());
    }

    #[test]
    fn test_secret_share_hex() {
        let id = Identifier::new(5).unwrap();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let share = SecretShare::new(id, sk.secret_bytes());

        let hex = share.to_hex();
        let recovered = SecretShare::from_hex(&hex).unwrap();

        assert_eq!(share.identifier(), recovered.identifier());
        assert_eq!(share.value(), recovered.value());
    }

    #[test]
    fn test_verification_share() {
        let id = Identifier::new(1).unwrap();
        let sk = SecretKey::new(&mut rand::thread_rng());
        let share = SecretShare::new(id, sk.secret_bytes());

        let vs = share.verification_share().unwrap();
        assert_eq!(vs.identifier, id);
        assert_eq!(vs.public_key.len(), 33);
    }
}
