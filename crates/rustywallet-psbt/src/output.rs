//! PSBT output map

use std::collections::BTreeMap;
use crate::types::{KeySource, ProprietaryFields, UnknownFields};

/// PSBT output map
#[derive(Debug, Clone, Default)]
pub struct OutputMap {
    /// Redeem script (for P2SH outputs)
    pub redeem_script: Option<Vec<u8>>,
    /// Witness script (for P2WSH outputs)
    pub witness_script: Option<Vec<u8>>,
    /// BIP32 derivation paths (pubkey -> key source)
    pub bip32_derivation: BTreeMap<Vec<u8>, KeySource>,
    /// Taproot internal key
    pub tap_internal_key: Option<Vec<u8>>,
    /// Taproot tree
    pub tap_tree: Option<Vec<u8>>,
    /// Taproot BIP32 derivation
    pub tap_bip32_derivation: BTreeMap<Vec<u8>, Vec<u8>>,
    /// PSBT v2: Output amount
    pub amount: Option<u64>,
    /// PSBT v2: Output script
    pub script: Option<Vec<u8>>,
    /// Proprietary fields
    pub proprietary: ProprietaryFields,
    /// Unknown fields
    pub unknown: UnknownFields,
}

impl OutputMap {
    /// Create a new empty output map
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this is a change output (has BIP32 derivation info)
    pub fn is_change(&self) -> bool {
        !self.bip32_derivation.is_empty() || !self.tap_bip32_derivation.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_map_default() {
        let output = OutputMap::new();
        assert!(output.redeem_script.is_none());
        assert!(output.witness_script.is_none());
        assert!(output.bip32_derivation.is_empty());
        assert!(!output.is_change());
    }

    #[test]
    fn test_output_is_change() {
        let mut output = OutputMap::new();
        assert!(!output.is_change());

        output.bip32_derivation.insert(
            vec![0x02; 33],
            KeySource::new([0x01, 0x02, 0x03, 0x04], vec![84 | 0x80000000, 0x80000000, 0x80000000, 1, 0]),
        );
        assert!(output.is_change());
    }
}
