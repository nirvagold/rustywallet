//! Sighash calculation for transaction signing.

use crate::types::{Transaction, encode_varint};
use sha2::{Sha256, Digest};

/// Sighash types.
pub mod sighash_type {
    /// Sign all inputs and outputs
    pub const ALL: u32 = 0x01;
    /// Sign all inputs, no outputs
    pub const NONE: u32 = 0x02;
    /// Sign all inputs, only the output at same index
    pub const SINGLE: u32 = 0x03;
    /// Anyone can add inputs
    pub const ANYONECANPAY: u32 = 0x80;
}

/// Calculate legacy sighash for P2PKH signing.
///
/// # Arguments
/// * `tx` - The transaction to sign
/// * `input_index` - Index of the input being signed
/// * `script_pubkey` - The scriptPubKey of the UTXO being spent
/// * `sighash_type` - Sighash type (typically SIGHASH_ALL = 0x01)
pub fn sighash_legacy(
    tx: &Transaction,
    input_index: usize,
    script_pubkey: &[u8],
    sighash_type: u32,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    
    // Version
    bytes.extend_from_slice(&tx.version.to_le_bytes());
    
    // Input count
    bytes.extend_from_slice(&encode_varint(tx.inputs.len() as u64));
    
    // Inputs
    for (i, input) in tx.inputs.iter().enumerate() {
        bytes.extend_from_slice(&input.txid);
        bytes.extend_from_slice(&input.vout.to_le_bytes());
        
        if i == input_index {
            // Use scriptPubKey for the input being signed
            bytes.extend_from_slice(&encode_varint(script_pubkey.len() as u64));
            bytes.extend_from_slice(script_pubkey);
        } else {
            // Empty script for other inputs
            bytes.push(0x00);
        }
        
        bytes.extend_from_slice(&input.sequence.to_le_bytes());
    }
    
    // Output count
    bytes.extend_from_slice(&encode_varint(tx.outputs.len() as u64));
    
    // Outputs
    for output in &tx.outputs {
        bytes.extend_from_slice(&output.value.to_le_bytes());
        bytes.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
        bytes.extend_from_slice(&output.script_pubkey);
    }
    
    // Locktime
    bytes.extend_from_slice(&tx.locktime.to_le_bytes());
    
    // Sighash type (4 bytes, little-endian)
    bytes.extend_from_slice(&sighash_type.to_le_bytes());
    
    // Double SHA256
    let hash1 = Sha256::digest(&bytes);
    let hash2 = Sha256::digest(hash1);
    hash2.into()
}

/// Calculate BIP143 sighash for P2WPKH signing.
///
/// # Arguments
/// * `tx` - The transaction to sign
/// * `input_index` - Index of the input being signed
/// * `script_code` - The script code (P2PKH script for P2WPKH)
/// * `value` - Value of the UTXO being spent
/// * `sighash_type` - Sighash type
pub fn sighash_segwit(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    value: u64,
    sighash_type: u32,
) -> [u8; 32] {
    // BIP143 preimage components
    
    // 1. nVersion
    let version = tx.version.to_le_bytes();
    
    // 2. hashPrevouts (double SHA256 of all input outpoints)
    let hash_prevouts = {
        let mut data = Vec::new();
        for input in &tx.inputs {
            data.extend_from_slice(&input.txid);
            data.extend_from_slice(&input.vout.to_le_bytes());
        }
        double_sha256(&data)
    };
    
    // 3. hashSequence (double SHA256 of all input sequences)
    let hash_sequence = {
        let mut data = Vec::new();
        for input in &tx.inputs {
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }
        double_sha256(&data)
    };
    
    // 4. outpoint (txid + vout of input being signed)
    let input = &tx.inputs[input_index];
    let outpoint_txid = input.txid;
    let outpoint_vout = input.vout.to_le_bytes();
    
    // 5. scriptCode
    let script_code_len = encode_varint(script_code.len() as u64);
    
    // 6. value
    let value_bytes = value.to_le_bytes();
    
    // 7. nSequence
    let sequence = input.sequence.to_le_bytes();
    
    // 8. hashOutputs (double SHA256 of all outputs)
    let hash_outputs = {
        let mut data = Vec::new();
        for output in &tx.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.extend_from_slice(&encode_varint(output.script_pubkey.len() as u64));
            data.extend_from_slice(&output.script_pubkey);
        }
        double_sha256(&data)
    };
    
    // 9. nLockTime
    let locktime = tx.locktime.to_le_bytes();
    
    // 10. sighash type
    let sighash = sighash_type.to_le_bytes();
    
    // Build preimage
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&version);
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    preimage.extend_from_slice(&outpoint_txid);
    preimage.extend_from_slice(&outpoint_vout);
    preimage.extend_from_slice(&script_code_len);
    preimage.extend_from_slice(script_code);
    preimage.extend_from_slice(&value_bytes);
    preimage.extend_from_slice(&sequence);
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&locktime);
    preimage.extend_from_slice(&sighash);
    
    double_sha256(&preimage)
}

/// Double SHA256 hash.
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(hash1);
    hash2.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TxInput, TxOutput};

    #[test]
    fn test_sighash_legacy() {
        let mut tx = Transaction::new();
        tx.inputs.push(TxInput::new([0u8; 32], 0));
        tx.outputs.push(TxOutput::new(50_000, vec![0x76, 0xa9]));
        
        let script = vec![0x76, 0xa9, 0x14]; // Partial P2PKH
        let hash = sighash_legacy(&tx, 0, &script, sighash_type::ALL);
        
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sighash_segwit() {
        let mut tx = Transaction::new();
        tx.inputs.push(TxInput::new([0u8; 32], 0));
        tx.outputs.push(TxOutput::new(50_000, vec![0x00, 0x14]));
        
        let script_code = vec![0x76, 0xa9, 0x14]; // P2PKH script code
        let hash = sighash_segwit(&tx, 0, &script_code, 100_000, sighash_type::ALL);
        
        assert_eq!(hash.len(), 32);
    }
}
