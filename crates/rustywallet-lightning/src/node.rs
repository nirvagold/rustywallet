//! Node identity and key derivation.
//!
//! This module provides types for deriving Lightning node identity
//! from an HD seed.

use crate::error::LightningError;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// Lightning node identity derived from an HD seed.
///
/// The node identity includes the node's public key (node ID) and
/// the secret key used for signing.
pub struct NodeIdentity {
    /// Node secret key
    secret_key: SecretKey,
    /// Node public key (node ID)
    public_key: PublicKey,
}

impl NodeIdentity {
    /// Derive node identity from an HD seed (64 bytes).
    ///
    /// Uses a deterministic derivation from the seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, LightningError> {
        if seed.len() != 64 {
            return Err(LightningError::KeyDerivationError(format!(
                "Expected 64 byte seed, got {}",
                seed.len()
            )));
        }

        // Derive using a deterministic method
        // We use SHA256(seed || "lightning-node-key") as the secret key
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(b"lightning-node-key");
        let result = hasher.finalize();

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&result)
            .map_err(|e| LightningError::KeyDerivationError(e.to_string()))?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Create from an existing secret key.
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Get the node ID (compressed public key).
    pub fn node_id(&self) -> NodeId {
        NodeId(self.public_key.serialize())
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the secret key (use with caution).
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Sign a message with the node's secret key.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], LightningError> {
        use secp256k1::Message;

        let secp = Secp256k1::new();
        
        // Hash the message
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hash = hasher.finalize();

        let msg = Message::from_digest_slice(&hash)
            .map_err(|e| LightningError::SignatureError(e.to_string()))?;

        let sig = secp.sign_ecdsa(&msg, &self.secret_key);
        Ok(sig.serialize_compact())
    }
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id())
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// A 33-byte compressed public key representing a node ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 33]);

impl NodeId {
    /// Create from bytes.
    pub fn from_bytes(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    /// Create from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, LightningError> {
        let bytes = hex::decode(hex)
            .map_err(|e| LightningError::InvalidNodeId(e.to_string()))?;

        if bytes.len() != 33 {
            return Err(LightningError::InvalidNodeId(format!(
                "Expected 33 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 33];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Get the public key.
    pub fn to_public_key(&self) -> Result<PublicKey, LightningError> {
        PublicKey::from_slice(&self.0)
            .map_err(|e| LightningError::InvalidNodeId(e.to_string()))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_seed() -> [u8; 64] {
        use rand::RngCore;
        let mut seed = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        seed
    }

    #[test]
    fn test_node_identity_from_seed() {
        let seed = random_seed();
        let identity = NodeIdentity::from_seed(&seed).unwrap();

        // Node ID should be 33 bytes (compressed pubkey)
        assert_eq!(identity.node_id().as_bytes().len(), 33);
    }

    #[test]
    fn test_deterministic_derivation() {
        let seed = random_seed();
        let identity1 = NodeIdentity::from_seed(&seed).unwrap();
        let identity2 = NodeIdentity::from_seed(&seed).unwrap();

        assert_eq!(identity1.node_id(), identity2.node_id());
    }

    #[test]
    fn test_different_seeds_different_ids() {
        let seed1 = random_seed();
        let seed2 = random_seed();

        let identity1 = NodeIdentity::from_seed(&seed1).unwrap();
        let identity2 = NodeIdentity::from_seed(&seed2).unwrap();

        assert_ne!(identity1.node_id(), identity2.node_id());
    }

    #[test]
    fn test_node_id_hex_roundtrip() {
        let seed = random_seed();
        let identity = NodeIdentity::from_seed(&seed).unwrap();
        let node_id = identity.node_id();

        let hex = node_id.to_hex();
        let recovered = NodeId::from_hex(&hex).unwrap();

        assert_eq!(node_id, recovered);
    }

    #[test]
    fn test_sign_message() {
        let seed = random_seed();
        let identity = NodeIdentity::from_seed(&seed).unwrap();

        let message = b"Hello, Lightning!";
        let signature = identity.sign(message).unwrap();

        assert_eq!(signature.len(), 64);
    }
}
