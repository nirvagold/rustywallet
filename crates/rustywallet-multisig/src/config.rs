//! Multisig configuration.

use crate::error::{MultisigError, Result};

/// Maximum number of keys in standard multisig.
pub const MAX_MULTISIG_KEYS: usize = 15;

/// Configuration for a multisig wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigConfig {
    /// Required signatures (M)
    threshold: u8,
    /// Total keys (N)
    total: u8,
    /// Sorted compressed public keys (33 bytes each)
    public_keys: Vec<[u8; 33]>,
}

impl MultisigConfig {
    /// Create a new multisig configuration.
    ///
    /// Public keys will be sorted lexicographically (BIP67).
    ///
    /// # Arguments
    /// * `threshold` - Number of required signatures (M)
    /// * `public_keys` - List of compressed public keys
    ///
    /// # Errors
    /// Returns error if:
    /// - threshold is 0 or greater than number of keys
    /// - more than 15 keys provided
    /// - duplicate keys found
    pub fn new(threshold: u8, public_keys: Vec<[u8; 33]>) -> Result<Self> {
        let n = public_keys.len();

        // Validate threshold
        if threshold == 0 || threshold as usize > n {
            return Err(MultisigError::InvalidThreshold {
                m: threshold,
                n: n as u8,
            });
        }

        // Validate key count
        if n > MAX_MULTISIG_KEYS {
            return Err(MultisigError::TooManyKeys { count: n });
        }

        if n == 0 {
            return Err(MultisigError::NotEnoughKeys { need: 1, got: 0 });
        }

        // Sort keys (BIP67)
        let mut sorted_keys = public_keys;
        sorted_keys.sort();

        // Check for duplicates
        for i in 1..sorted_keys.len() {
            if sorted_keys[i] == sorted_keys[i - 1] {
                return Err(MultisigError::DuplicateKey { index: i });
            }
        }

        Ok(Self {
            threshold,
            total: n as u8,
            public_keys: sorted_keys,
        })
    }

    /// Get the threshold (M).
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Get the total number of keys (N).
    pub fn total(&self) -> u8 {
        self.total
    }

    /// Get the sorted public keys.
    pub fn public_keys(&self) -> &[[u8; 33]] {
        &self.public_keys
    }

    /// Get the M-of-N description.
    pub fn description(&self) -> String {
        format!("{}-of-{}", self.threshold, self.total)
    }

    /// Check if a public key is part of this multisig.
    pub fn contains_key(&self, pubkey: &[u8; 33]) -> bool {
        self.public_keys.contains(pubkey)
    }

    /// Get the index of a public key (if present).
    pub fn key_index(&self, pubkey: &[u8; 33]) -> Option<usize> {
        self.public_keys.iter().position(|k| k == pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pubkey(seed: u8) -> [u8; 33] {
        let mut key = [seed; 33];
        key[0] = 0x02; // Compressed prefix
        key
    }

    #[test]
    fn test_valid_2_of_3() {
        let keys = vec![make_pubkey(1), make_pubkey(2), make_pubkey(3)];
        let config = MultisigConfig::new(2, keys).unwrap();
        assert_eq!(config.threshold(), 2);
        assert_eq!(config.total(), 3);
        assert_eq!(config.description(), "2-of-3");
    }

    #[test]
    fn test_keys_sorted() {
        let keys = vec![make_pubkey(3), make_pubkey(1), make_pubkey(2)];
        let config = MultisigConfig::new(2, keys).unwrap();
        
        // Keys should be sorted
        assert!(config.public_keys()[0] < config.public_keys()[1]);
        assert!(config.public_keys()[1] < config.public_keys()[2]);
    }

    #[test]
    fn test_invalid_threshold_zero() {
        let keys = vec![make_pubkey(1), make_pubkey(2)];
        let result = MultisigConfig::new(0, keys);
        assert!(matches!(result, Err(MultisigError::InvalidThreshold { .. })));
    }

    #[test]
    fn test_invalid_threshold_too_high() {
        let keys = vec![make_pubkey(1), make_pubkey(2)];
        let result = MultisigConfig::new(3, keys);
        assert!(matches!(result, Err(MultisigError::InvalidThreshold { .. })));
    }

    #[test]
    fn test_too_many_keys() {
        let keys: Vec<_> = (0..16).map(|i| make_pubkey(i)).collect();
        let result = MultisigConfig::new(2, keys);
        assert!(matches!(result, Err(MultisigError::TooManyKeys { .. })));
    }

    #[test]
    fn test_duplicate_keys() {
        let keys = vec![make_pubkey(1), make_pubkey(1), make_pubkey(2)];
        let result = MultisigConfig::new(2, keys);
        assert!(matches!(result, Err(MultisigError::DuplicateKey { .. })));
    }

    #[test]
    fn test_contains_key() {
        let keys = vec![make_pubkey(1), make_pubkey(2), make_pubkey(3)];
        let config = MultisigConfig::new(2, keys).unwrap();
        
        assert!(config.contains_key(&make_pubkey(1)));
        assert!(config.contains_key(&make_pubkey(2)));
        assert!(!config.contains_key(&make_pubkey(99)));
    }
}
