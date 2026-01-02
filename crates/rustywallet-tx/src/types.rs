//! Core transaction types.

use sha2::{Sha256, Digest};

/// A Bitcoin transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Transaction version (typically 1 or 2)
    pub version: i32,
    /// Transaction inputs
    pub inputs: Vec<TxInput>,
    /// Transaction outputs
    pub outputs: Vec<TxOutput>,
    /// Lock time (block height or timestamp)
    pub locktime: u32,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
        }
    }
}

impl Transaction {
    /// Create a new empty transaction.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this is a SegWit transaction (has witness data).
    pub fn is_segwit(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// Calculate the transaction ID (double SHA256 of non-witness serialization).
    pub fn txid(&self) -> [u8; 32] {
        let bytes = self.serialize_legacy();
        let hash1 = Sha256::digest(&bytes);
        let hash2 = Sha256::digest(hash1);
        let mut txid: [u8; 32] = hash2.into();
        txid.reverse(); // Bitcoin uses little-endian for display
        txid
    }

    /// Calculate the witness transaction ID.
    pub fn wtxid(&self) -> [u8; 32] {
        if !self.is_segwit() {
            return self.txid();
        }
        let bytes = self.serialize();
        let hash1 = Sha256::digest(&bytes);
        let hash2 = Sha256::digest(hash1);
        let mut wtxid: [u8; 32] = hash2.into();
        wtxid.reverse();
        wtxid
    }

    /// Serialize transaction (with witness if present).
    pub fn serialize(&self) -> Vec<u8> {
        if self.is_segwit() {
            self.serialize_segwit()
        } else {
            self.serialize_legacy()
        }
    }

    /// Serialize without witness data (for txid calculation).
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Version (4 bytes, little-endian)
        bytes.extend_from_slice(&self.version.to_le_bytes());
        
        // Input count (varint)
        bytes.extend_from_slice(&encode_varint(self.inputs.len() as u64));
        
        // Inputs
        for input in &self.inputs {
            bytes.extend_from_slice(&input.txid);
            bytes.extend_from_slice(&input.vout.to_le_bytes());
            bytes.extend_from_slice(&encode_varint(input.script_sig.len() as u64));
            bytes.extend_from_slice(&input.script_sig);
            bytes.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count (varint)
        bytes.extend_from_slice(&encode_varint(self.outputs.len() as u64));
        
        // Outputs
        for output in &self.outputs {
            bytes.extend_from_slice(&output.value.to_le_bytes());
            bytes.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
            bytes.extend_from_slice(&output.script_pubkey);
        }
        
        // Locktime (4 bytes, little-endian)
        bytes.extend_from_slice(&self.locktime.to_le_bytes());
        
        bytes
    }

    /// Serialize with witness data.
    fn serialize_segwit(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Version
        bytes.extend_from_slice(&self.version.to_le_bytes());
        
        // Marker and flag for SegWit
        bytes.push(0x00); // marker
        bytes.push(0x01); // flag
        
        // Input count
        bytes.extend_from_slice(&encode_varint(self.inputs.len() as u64));
        
        // Inputs (without witness)
        for input in &self.inputs {
            bytes.extend_from_slice(&input.txid);
            bytes.extend_from_slice(&input.vout.to_le_bytes());
            bytes.extend_from_slice(&encode_varint(input.script_sig.len() as u64));
            bytes.extend_from_slice(&input.script_sig);
            bytes.extend_from_slice(&input.sequence.to_le_bytes());
        }
        
        // Output count
        bytes.extend_from_slice(&encode_varint(self.outputs.len() as u64));
        
        // Outputs
        for output in &self.outputs {
            bytes.extend_from_slice(&output.value.to_le_bytes());
            bytes.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
            bytes.extend_from_slice(&output.script_pubkey);
        }
        
        // Witness data
        for input in &self.inputs {
            bytes.extend_from_slice(&encode_varint(input.witness.len() as u64));
            for item in &input.witness {
                bytes.extend_from_slice(&encode_varint(item.len() as u64));
                bytes.extend_from_slice(item);
            }
        }
        
        // Locktime
        bytes.extend_from_slice(&self.locktime.to_le_bytes());
        
        bytes
    }

    /// Get transaction size in bytes.
    pub fn size(&self) -> usize {
        self.serialize().len()
    }

    /// Get transaction weight (for fee calculation).
    pub fn weight(&self) -> usize {
        let base_size = self.serialize_legacy().len();
        let total_size = self.serialize().len();
        base_size * 3 + total_size
    }

    /// Get virtual size (vsize) for fee calculation.
    pub fn vsize(&self) -> usize {
        self.weight().div_ceil(4)
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        self.serialize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

/// A transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    /// Previous transaction ID (32 bytes, internal byte order)
    pub txid: [u8; 32],
    /// Output index in previous transaction
    pub vout: u32,
    /// Unlocking script (scriptSig)
    pub script_sig: Vec<u8>,
    /// Sequence number
    pub sequence: u32,
    /// Witness data (for SegWit)
    pub witness: Vec<Vec<u8>>,
}

impl TxInput {
    /// Create a new input.
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self {
            txid,
            vout,
            script_sig: Vec::new(),
            sequence: 0xFFFFFFFF,
            witness: Vec::new(),
        }
    }
}

/// A transaction output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    /// Value in satoshis
    pub value: u64,
    /// Locking script (scriptPubKey)
    pub script_pubkey: Vec<u8>,
}

impl TxOutput {
    /// Create a new output.
    pub fn new(value: u64, script_pubkey: Vec<u8>) -> Self {
        Self { value, script_pubkey }
    }
}

/// An unspent transaction output (UTXO).
#[derive(Debug, Clone)]
pub struct Utxo {
    /// Transaction ID
    pub txid: [u8; 32],
    /// Output index
    pub vout: u32,
    /// Value in satoshis
    pub value: u64,
    /// Script pubkey
    pub script_pubkey: Vec<u8>,
    /// Address (for display)
    pub address: String,
}

/// Encode a variable-length integer.
pub fn encode_varint(n: u64) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xFFFFFFFF {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFF];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varint() {
        assert_eq!(encode_varint(0), vec![0x00]);
        assert_eq!(encode_varint(252), vec![0xFC]);
        assert_eq!(encode_varint(253), vec![0xFD, 0xFD, 0x00]);
        assert_eq!(encode_varint(0xFFFF), vec![0xFD, 0xFF, 0xFF]);
    }

    #[test]
    fn test_empty_transaction() {
        let tx = Transaction::new();
        assert_eq!(tx.version, 2);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
        assert!(!tx.is_segwit());
    }
}
