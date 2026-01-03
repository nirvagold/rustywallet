//! Silent Payment labels for multiple addresses.

use crate::error::{Result, SilentPaymentError};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// BIP352 label tag for hashing.
const LABEL_TAG: &[u8] = b"BIP0352/Label";

/// Silent Payment label for deriving multiple addresses.
///
/// Labels allow a receiver to have multiple distinct addresses
/// from a single Silent Payment address, useful for:
/// - Separating payments by purpose
/// - Identifying payment sources
/// - Organizing incoming funds
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// Label index (m value)
    index: u32,
    /// Label tweak (32 bytes)
    tweak: [u8; 32],
}

impl Label {
    /// Create a new label from index.
    pub fn new(index: u32) -> Self {
        let tweak = Self::compute_tweak(index);
        Self { index, tweak }
    }

    /// Compute label tweak from index.
    fn compute_tweak(m: u32) -> [u8; 32] {
        // BIP352: label = hash("BIP0352/Label" || ser32(m))
        let tag_hash = Sha256::digest(LABEL_TAG);

        let mut hasher = Sha256::new();
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        hasher.update(m.to_be_bytes());

        let result = hasher.finalize();
        let mut tweak = [0u8; 32];
        tweak.copy_from_slice(&result);
        tweak
    }

    /// Get the label index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get the label tweak.
    pub fn tweak(&self) -> &[u8; 32] {
        &self.tweak
    }

    /// Apply label to a spend public key.
    ///
    /// Returns B_m = B_spend + label * G
    pub fn apply_to_pubkey(&self, spend_pubkey: &[u8; 33]) -> Result<[u8; 33]> {
        let secp = Secp256k1::new();

        let b_spend = PublicKey::from_slice(spend_pubkey)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

        let label_sk = SecretKey::from_slice(&self.tweak)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let label_point = PublicKey::from_secret_key(&secp, &label_sk);

        let b_m = b_spend
            .combine(&label_point)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        Ok(b_m.serialize())
    }

    /// Apply label to a spend private key.
    ///
    /// Returns b_m = b_spend + label
    pub fn apply_to_privkey(&self, spend_privkey: &[u8; 32]) -> Result<[u8; 32]> {
        let b_spend = SecretKey::from_slice(spend_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;

        let label_sk = SecretKey::from_slice(&self.tweak)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let b_m = b_spend
            .add_tweak(&label_sk.into())
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        Ok(b_m.secret_bytes())
    }
}

/// Label manager for tracking multiple labels.
#[derive(Debug, Clone)]
pub struct LabelManager {
    /// Known labels
    labels: Vec<Label>,
}

impl LabelManager {
    /// Create a new label manager.
    pub fn new() -> Self {
        Self { labels: Vec::new() }
    }

    /// Add a label by index.
    pub fn add(&mut self, index: u32) -> &Label {
        if let Some(pos) = self.labels.iter().position(|l| l.index == index) {
            &self.labels[pos]
        } else {
            self.labels.push(Label::new(index));
            self.labels.last().unwrap()
        }
    }

    /// Get a label by index.
    pub fn get(&self, index: u32) -> Option<&Label> {
        self.labels.iter().find(|l| l.index == index)
    }

    /// Get all labels.
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }

    /// Generate labels from 0 to n-1.
    pub fn generate_range(&mut self, n: u32) {
        for i in 0..n {
            self.add(i);
        }
    }

    /// Check if a public key matches any labeled spend key.
    pub fn find_matching_label(
        &self,
        spend_pubkey: &[u8; 33],
        target_pubkey: &[u8; 33],
    ) -> Option<&Label> {
        for label in &self.labels {
            if let Ok(labeled) = label.apply_to_pubkey(spend_pubkey) {
                if &labeled == target_pubkey {
                    return Some(label);
                }
            }
        }
        None
    }
}

impl Default for LabelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_creation() {
        let label0 = Label::new(0);
        let label1 = Label::new(1);

        assert_eq!(label0.index(), 0);
        assert_eq!(label1.index(), 1);
        assert_ne!(label0.tweak(), label1.tweak());
    }

    #[test]
    fn test_label_deterministic() {
        let label1 = Label::new(42);
        let label2 = Label::new(42);

        assert_eq!(label1.tweak(), label2.tweak());
    }

    #[test]
    fn test_label_apply_pubkey() {
        use rustywallet_keys::private_key::PrivateKey;

        let key = PrivateKey::random();
        let pk: [u8; 33] = key.public_key().to_compressed().try_into().unwrap();

        let label = Label::new(1);
        let labeled = label.apply_to_pubkey(&pk).unwrap();

        // Should be different from original
        assert_ne!(labeled, pk);
    }

    #[test]
    fn test_label_manager() {
        let mut manager = LabelManager::new();

        manager.add(0);
        manager.add(1);
        manager.add(0); // duplicate

        assert_eq!(manager.labels().len(), 2);
        assert!(manager.get(0).is_some());
        assert!(manager.get(1).is_some());
        assert!(manager.get(2).is_none());
    }

    #[test]
    fn test_label_manager_range() {
        let mut manager = LabelManager::new();
        manager.generate_range(5);

        assert_eq!(manager.labels().len(), 5);
        for i in 0..5 {
            assert!(manager.get(i).is_some());
        }
    }
}
