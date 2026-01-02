//! PSBT global map

use crate::types::{KeySource, ProprietaryFields, UnknownFields};

/// Extended public key with key source
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XpubEntry {
    /// Extended public key (78 bytes serialized)
    pub xpub: Vec<u8>,
    /// Key source (fingerprint + path)
    pub key_source: KeySource,
}

/// PSBT global map
#[derive(Debug, Clone, Default)]
pub struct GlobalMap {
    /// Unsigned transaction (PSBT v0)
    pub unsigned_tx: Option<Vec<u8>>,
    /// Extended public keys
    pub xpubs: Vec<XpubEntry>,
    /// PSBT version (0 for BIP174, 2 for BIP370)
    pub version: Option<u32>,
    /// PSBT v2: Transaction version
    pub tx_version: Option<i32>,
    /// PSBT v2: Fallback locktime
    pub fallback_locktime: Option<u32>,
    /// PSBT v2: Input count
    pub input_count: Option<u64>,
    /// PSBT v2: Output count
    pub output_count: Option<u64>,
    /// PSBT v2: Transaction modifiable flags
    pub tx_modifiable: Option<u8>,
    /// Proprietary fields
    pub proprietary: ProprietaryFields,
    /// Unknown fields
    pub unknown: UnknownFields,
}

impl GlobalMap {
    /// Create a new empty global map
    pub fn new() -> Self {
        Self::default()
    }

    /// Create global map with unsigned transaction (PSBT v0)
    pub fn with_unsigned_tx(tx: Vec<u8>) -> Self {
        Self {
            unsigned_tx: Some(tx),
            ..Default::default()
        }
    }

    /// Get PSBT version (defaults to 0)
    pub fn psbt_version(&self) -> u32 {
        self.version.unwrap_or(0)
    }

    /// Check if this is PSBT v2
    pub fn is_v2(&self) -> bool {
        self.version == Some(2)
    }

    /// Add an extended public key
    pub fn add_xpub(&mut self, xpub: Vec<u8>, key_source: KeySource) {
        self.xpubs.push(XpubEntry { xpub, key_source });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_map_default() {
        let global = GlobalMap::new();
        assert!(global.unsigned_tx.is_none());
        assert!(global.xpubs.is_empty());
        assert_eq!(global.psbt_version(), 0);
        assert!(!global.is_v2());
    }

    #[test]
    fn test_global_map_with_tx() {
        let tx = vec![0x01, 0x00, 0x00, 0x00]; // minimal tx bytes
        let global = GlobalMap::with_unsigned_tx(tx.clone());
        assert_eq!(global.unsigned_tx, Some(tx));
    }

    #[test]
    fn test_add_xpub() {
        let mut global = GlobalMap::new();
        let xpub = vec![0x04; 78];
        let key_source = KeySource::new([0x01, 0x02, 0x03, 0x04], vec![84 | 0x80000000]);

        global.add_xpub(xpub.clone(), key_source.clone());

        assert_eq!(global.xpubs.len(), 1);
        assert_eq!(global.xpubs[0].xpub, xpub);
        assert_eq!(global.xpubs[0].key_source, key_source);
    }
}
