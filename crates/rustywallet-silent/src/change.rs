//! Change address handling for Silent Payments.

use crate::address::SilentPaymentAddress;
use crate::error::{Result, SilentPaymentError};
use crate::network::Network;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// BIP352 change tag.
const CHANGE_TAG: &[u8] = b"BIP0352/Change";

/// Change address generator for Silent Payments.
///
/// When sending a Silent Payment, the sender may need to create
/// a change output back to themselves. This module provides
/// utilities for generating deterministic change addresses.
pub struct ChangeAddressGenerator {
    /// Scan private key
    scan_privkey: [u8; 32],
    /// Spend private key
    spend_privkey: [u8; 32],
    /// Network
    network: Network,
}

impl ChangeAddressGenerator {
    /// Create a new change address generator.
    pub fn new(
        scan_privkey: &[u8; 32],
        spend_privkey: &[u8; 32],
        network: Network,
    ) -> Result<Self> {
        // Validate keys
        SecretKey::from_slice(scan_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        SecretKey::from_slice(spend_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;

        Ok(Self {
            scan_privkey: *scan_privkey,
            spend_privkey: *spend_privkey,
            network,
        })
    }

    /// Get the Silent Payment address for this wallet.
    pub fn address(&self) -> Result<SilentPaymentAddress> {
        let secp = Secp256k1::new();

        let scan_sk = SecretKey::from_slice(&self.scan_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        let spend_sk = SecretKey::from_slice(&self.spend_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;

        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        SilentPaymentAddress::from_bytes(scan_pk.serialize(), spend_pk.serialize(), self.network)
    }

    /// Generate a change output key for a transaction.
    ///
    /// # Arguments
    /// * `outpoints` - (txid, vout) pairs for all inputs
    /// * `index` - Change output index (for multiple change outputs)
    ///
    /// # Returns
    /// (output_pubkey, spending_key) tuple
    pub fn generate_change(
        &self,
        outpoints: &[([u8; 32], u32)],
        index: u32,
    ) -> Result<([u8; 32], [u8; 32])> {
        if outpoints.is_empty() {
            return Err(SilentPaymentError::NoInputs);
        }

        let secp = Secp256k1::new();

        // Compute change tweak
        let tweak = self.compute_change_tweak(outpoints, index)?;

        // Compute output key: P = B_spend + tweak * G
        let spend_sk = SecretKey::from_slice(&self.spend_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        let tweak_sk = SecretKey::from_slice(&tweak)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
        let tweak_point = PublicKey::from_secret_key(&secp, &tweak_sk);

        let output_pk = spend_pk
            .combine(&tweak_point)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let (xonly, _parity) = output_pk.x_only_public_key();

        // Compute spending key: b_spend + tweak
        let spending_key = spend_sk
            .add_tweak(&tweak_sk.into())
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        Ok((xonly.serialize(), spending_key.secret_bytes()))
    }

    /// Compute change tweak.
    fn compute_change_tweak(&self, outpoints: &[([u8; 32], u32)], index: u32) -> Result<[u8; 32]> {
        let secp = Secp256k1::new();

        // Sort outpoints
        let mut sorted: Vec<_> = outpoints.to_vec();
        sorted.sort_by(|a, b| {
            let cmp = a.0.cmp(&b.0);
            if cmp == std::cmp::Ordering::Equal {
                a.1.cmp(&b.1)
            } else {
                cmp
            }
        });

        // Get scan public key
        let scan_sk = SecretKey::from_slice(&self.scan_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);

        // Hash: tag || smallest_outpoint || B_scan || index
        let tag_hash = Sha256::digest(CHANGE_TAG);

        let mut hasher = Sha256::new();
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        hasher.update(sorted[0].0);
        hasher.update(sorted[0].1.to_le_bytes());
        hasher.update(scan_pk.serialize());
        hasher.update(index.to_be_bytes());

        let result = hasher.finalize();
        let mut tweak = [0u8; 32];
        tweak.copy_from_slice(&result);

        Ok(tweak)
    }

    /// Check if an output is a change output from this wallet.
    pub fn is_change_output(
        &self,
        output_pk: &[u8; 32],
        outpoints: &[([u8; 32], u32)],
        max_index: u32,
    ) -> Result<Option<(u32, [u8; 32])>> {
        for index in 0..max_index {
            let (expected_pk, spending_key) = self.generate_change(outpoints, index)?;
            if &expected_pk == output_pk {
                return Ok(Some((index, spending_key)));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_change_generator_creation() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let generator = ChangeAddressGenerator::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
            Network::Mainnet,
        )
        .unwrap();

        let addr = generator.address().unwrap();
        assert_eq!(addr.network(), Network::Mainnet);
    }

    #[test]
    fn test_generate_change() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let generator = ChangeAddressGenerator::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([1u8; 32], 0u32)];
        let (output_pk, spending_key) = generator.generate_change(&outpoints, 0).unwrap();

        // Verify spending key produces correct public key
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&spending_key).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let (xonly, _) = pk.x_only_public_key();

        assert_eq!(xonly.serialize(), output_pk);
    }

    #[test]
    fn test_change_deterministic() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let generator = ChangeAddressGenerator::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([1u8; 32], 0u32)];

        let (pk1, _) = generator.generate_change(&outpoints, 0).unwrap();
        let (pk2, _) = generator.generate_change(&outpoints, 0).unwrap();

        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_different_indices() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let generator = ChangeAddressGenerator::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([1u8; 32], 0u32)];

        let (pk0, _) = generator.generate_change(&outpoints, 0).unwrap();
        let (pk1, _) = generator.generate_change(&outpoints, 1).unwrap();

        assert_ne!(pk0, pk1);
    }

    #[test]
    fn test_is_change_output() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let generator = ChangeAddressGenerator::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([1u8; 32], 0u32)];
        let (output_pk, _) = generator.generate_change(&outpoints, 2).unwrap();

        let result = generator.is_change_output(&output_pk, &outpoints, 5).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, 2);
    }
}
