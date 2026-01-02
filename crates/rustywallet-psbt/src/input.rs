//! PSBT input map

use std::collections::BTreeMap;
use crate::error::PsbtError;
use crate::types::{KeySource, PsbtSighashType, ProprietaryFields, UnknownFields};

/// Transaction output (for witness_utxo)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// Value in satoshis
    pub value: u64,
    /// Script pubkey
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    /// Create a new TxOut
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        Self { value, script_pubkey }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.value.to_le_bytes());
        // Compact size for script length
        let script_len = self.script_pubkey.len();
        if script_len < 0xfd {
            bytes.push(script_len as u8);
        } else if script_len <= 0xffff {
            bytes.push(0xfd);
            bytes.extend_from_slice(&(script_len as u16).to_le_bytes());
        } else {
            bytes.push(0xfe);
            bytes.extend_from_slice(&(script_len as u32).to_le_bytes());
        }
        bytes.extend_from_slice(&self.script_pubkey);
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), PsbtError> {
        if bytes.len() < 9 {
            return Err(PsbtError::InvalidFormat("TxOut too short".into()));
        }

        let value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);

        let (script_len, offset) = read_compact_size(&bytes[8..])?;
        let start = 8 + offset;
        let end = start + script_len;

        if bytes.len() < end {
            return Err(PsbtError::InvalidFormat("TxOut script truncated".into()));
        }

        let script_pubkey = bytes[start..end].to_vec();

        Ok((Self { value, script_pubkey }, end))
    }
}

/// Witness stack
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Witness {
    /// Witness stack items
    pub items: Vec<Vec<u8>>,
}

impl Witness {
    /// Create a new empty witness
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Create witness from items
    pub fn from_items(items: Vec<Vec<u8>>) -> Self {
        Self { items }
    }

    /// Add an item to the witness
    pub fn push(&mut self, item: Vec<u8>) {
        self.items.push(item);
    }

    /// Check if witness is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Number of items
        write_compact_size(&mut bytes, self.items.len());
        for item in &self.items {
            write_compact_size(&mut bytes, item.len());
            bytes.extend_from_slice(item);
        }
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PsbtError> {
        let mut offset = 0;
        let (count, size) = read_compact_size(&bytes[offset..])?;
        offset += size;

        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let (item_len, size) = read_compact_size(&bytes[offset..])?;
            offset += size;
            if bytes.len() < offset + item_len {
                return Err(PsbtError::InvalidFormat("Witness item truncated".into()));
            }
            items.push(bytes[offset..offset + item_len].to_vec());
            offset += item_len;
        }

        Ok(Self { items })
    }
}

/// PSBT input map
#[derive(Debug, Clone, Default)]
pub struct InputMap {
    /// Non-witness UTXO (full previous transaction)
    pub non_witness_utxo: Option<Vec<u8>>,
    /// Witness UTXO (just the output being spent)
    pub witness_utxo: Option<TxOut>,
    /// Partial signatures (pubkey -> signature)
    pub partial_sigs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Sighash type
    pub sighash_type: Option<PsbtSighashType>,
    /// Redeem script (for P2SH)
    pub redeem_script: Option<Vec<u8>>,
    /// Witness script (for P2WSH)
    pub witness_script: Option<Vec<u8>>,
    /// BIP32 derivation paths (pubkey -> key source)
    pub bip32_derivation: BTreeMap<Vec<u8>, KeySource>,
    /// Final scriptSig
    pub final_script_sig: Option<Vec<u8>>,
    /// Final witness
    pub final_script_witness: Option<Witness>,
    /// Taproot key spend signature
    pub tap_key_sig: Option<Vec<u8>>,
    /// Taproot script spend signatures
    pub tap_script_sigs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Taproot leaf scripts
    pub tap_leaf_scripts: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Taproot BIP32 derivation
    pub tap_bip32_derivation: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Taproot internal key
    pub tap_internal_key: Option<Vec<u8>>,
    /// Taproot merkle root
    pub tap_merkle_root: Option<Vec<u8>>,
    /// PSBT v2: Previous txid
    pub previous_txid: Option<[u8; 32]>,
    /// PSBT v2: Output index
    pub output_index: Option<u32>,
    /// PSBT v2: Sequence
    pub sequence: Option<u32>,
    /// PSBT v2: Required time locktime
    pub required_time_locktime: Option<u32>,
    /// PSBT v2: Required height locktime
    pub required_height_locktime: Option<u32>,
    /// Proprietary fields
    pub proprietary: ProprietaryFields,
    /// Unknown fields
    pub unknown: UnknownFields,
}

impl InputMap {
    /// Create a new empty input map
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this input is finalized
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig.is_some() || self.final_script_witness.is_some()
    }

    /// Check if this input has UTXO information
    pub fn has_utxo(&self) -> bool {
        self.witness_utxo.is_some() || self.non_witness_utxo.is_some()
    }

    /// Get the value of the UTXO being spent
    pub fn utxo_value(&self) -> Option<u64> {
        self.witness_utxo.as_ref().map(|utxo| utxo.value)
    }

    /// Get the script pubkey of the UTXO being spent
    pub fn utxo_script(&self) -> Option<&[u8]> {
        self.witness_utxo.as_ref().map(|utxo| utxo.script_pubkey.as_slice())
    }

    /// Clear non-final fields (called after finalization)
    pub fn clear_for_finalization(&mut self) {
        self.partial_sigs.clear();
        self.sighash_type = None;
        self.redeem_script = None;
        self.witness_script = None;
        self.bip32_derivation.clear();
        self.tap_key_sig = None;
        self.tap_script_sigs.clear();
        self.tap_leaf_scripts.clear();
        self.tap_bip32_derivation.clear();
        self.tap_internal_key = None;
        self.tap_merkle_root = None;
    }
}

/// Read compact size from bytes
pub fn read_compact_size(bytes: &[u8]) -> Result<(usize, usize), PsbtError> {
    if bytes.is_empty() {
        return Err(PsbtError::InvalidFormat("Empty compact size".into()));
    }

    match bytes[0] {
        0..=0xfc => Ok((bytes[0] as usize, 1)),
        0xfd => {
            if bytes.len() < 3 {
                return Err(PsbtError::InvalidFormat("Truncated compact size".into()));
            }
            let value = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
            Ok((value, 3))
        }
        0xfe => {
            if bytes.len() < 5 {
                return Err(PsbtError::InvalidFormat("Truncated compact size".into()));
            }
            let value = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
            Ok((value, 5))
        }
        0xff => {
            if bytes.len() < 9 {
                return Err(PsbtError::InvalidFormat("Truncated compact size".into()));
            }
            let value = u64::from_le_bytes([
                bytes[1], bytes[2], bytes[3], bytes[4],
                bytes[5], bytes[6], bytes[7], bytes[8],
            ]) as usize;
            Ok((value, 9))
        }
    }
}

/// Write compact size to buffer
pub fn write_compact_size(buf: &mut Vec<u8>, value: usize) {
    if value < 0xfd {
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_txout_roundtrip() {
        let txout = TxOut::new(
            100_000_000,
            vec![0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                 0x13, 0x14],
        );

        let bytes = txout.to_bytes();
        let (parsed, _) = TxOut::from_bytes(&bytes).unwrap();

        assert_eq!(txout, parsed);
    }

    #[test]
    fn test_witness_roundtrip() {
        let witness = Witness::from_items(vec![
            vec![0x30, 0x44], // signature
            vec![0x02, 0x33], // pubkey
        ]);

        let bytes = witness.to_bytes();
        let parsed = Witness::from_bytes(&bytes).unwrap();

        assert_eq!(witness, parsed);
    }

    #[test]
    fn test_compact_size() {
        let test_cases = [
            (0usize, vec![0x00]),
            (252, vec![0xfc]),
            (253, vec![0xfd, 0xfd, 0x00]),
            (0xffff, vec![0xfd, 0xff, 0xff]),
            (0x10000, vec![0xfe, 0x00, 0x00, 0x01, 0x00]),
        ];

        for (value, expected) in test_cases {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, value);
            assert_eq!(buf, expected);

            let (parsed, _) = read_compact_size(&buf).unwrap();
            assert_eq!(parsed, value);
        }
    }
}
