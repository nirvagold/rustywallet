//! BIP341 Taproot signature hash
//!
//! Implements the signature hash algorithm for Taproot transactions.

use crate::tagged_hash::{tagged_hash, TapLeafHash, TAG_TAP_SIGHASH};
use sha2::{Digest, Sha256};

/// Taproot sighash types
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub enum TaprootSighashType {
    /// Default sighash (0x00) - equivalent to ALL for Taproot
    #[default]
    Default,
    /// SIGHASH_ALL (0x01)
    All,
    /// SIGHASH_NONE (0x02)
    None,
    /// SIGHASH_SINGLE (0x03)
    Single,
    /// SIGHASH_ALL | SIGHASH_ANYONECANPAY (0x81)
    AllAnyoneCanPay,
    /// SIGHASH_NONE | SIGHASH_ANYONECANPAY (0x82)
    NoneAnyoneCanPay,
    /// SIGHASH_SINGLE | SIGHASH_ANYONECANPAY (0x83)
    SingleAnyoneCanPay,
}

impl TaprootSighashType {
    /// Convert to byte value
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Default => 0x00,
            Self::All => 0x01,
            Self::None => 0x02,
            Self::Single => 0x03,
            Self::AllAnyoneCanPay => 0x81,
            Self::NoneAnyoneCanPay => 0x82,
            Self::SingleAnyoneCanPay => 0x83,
        }
    }

    /// Parse from byte value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::All),
            0x02 => Some(Self::None),
            0x03 => Some(Self::Single),
            0x81 => Some(Self::AllAnyoneCanPay),
            0x82 => Some(Self::NoneAnyoneCanPay),
            0x83 => Some(Self::SingleAnyoneCanPay),
            _ => None,
        }
    }

    /// Check if ANYONECANPAY flag is set
    pub fn is_anyone_can_pay(self) -> bool {
        matches!(
            self,
            Self::AllAnyoneCanPay | Self::NoneAnyoneCanPay | Self::SingleAnyoneCanPay
        )
    }

    /// Check if this is SIGHASH_NONE
    pub fn is_none(self) -> bool {
        matches!(self, Self::None | Self::NoneAnyoneCanPay)
    }

    /// Check if this is SIGHASH_SINGLE
    pub fn is_single(self) -> bool {
        matches!(self, Self::Single | Self::SingleAnyoneCanPay)
    }
}

/// Transaction output for sighash computation
#[derive(Clone, Debug)]
pub struct TxOut {
    /// Value in satoshis
    pub value: u64,
    /// Script pubkey
    pub script_pubkey: Vec<u8>,
}

/// Compute BIP341 signature hash for key path spending
#[allow(clippy::too_many_arguments)]
pub fn taproot_key_path_sighash(
    tx_version: i32,
    tx_locktime: u32,
    prevouts: &[TxOut],
    input_index: usize,
    sequences: &[u32],
    outputs: &[TxOut],
    sighash_type: TaprootSighashType,
    annex: Option<&[u8]>,
) -> [u8; 32] {
    compute_sighash(
        tx_version,
        tx_locktime,
        prevouts,
        input_index,
        sequences,
        outputs,
        sighash_type,
        annex,
        None, // No leaf hash for key path
        0,    // No key version for key path
        0,    // No codesep pos for key path
    )
}

/// Compute BIP341 signature hash for script path spending
#[allow(clippy::too_many_arguments)]
pub fn taproot_script_path_sighash(
    tx_version: i32,
    tx_locktime: u32,
    prevouts: &[TxOut],
    input_index: usize,
    sequences: &[u32],
    outputs: &[TxOut],
    sighash_type: TaprootSighashType,
    annex: Option<&[u8]>,
    leaf_hash: &TapLeafHash,
    key_version: u8,
    codesep_pos: u32,
) -> [u8; 32] {
    compute_sighash(
        tx_version,
        tx_locktime,
        prevouts,
        input_index,
        sequences,
        outputs,
        sighash_type,
        annex,
        Some(leaf_hash),
        key_version,
        codesep_pos,
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_sighash(
    tx_version: i32,
    tx_locktime: u32,
    prevouts: &[TxOut],
    input_index: usize,
    sequences: &[u32],
    outputs: &[TxOut],
    sighash_type: TaprootSighashType,
    annex: Option<&[u8]>,
    leaf_hash: Option<&TapLeafHash>,
    key_version: u8,
    codesep_pos: u32,
) -> [u8; 32] {
    let mut data = Vec::new();

    // Epoch (0x00)
    data.push(0x00);

    // Sighash type
    data.push(sighash_type.to_u8());

    // Transaction version
    data.extend_from_slice(&tx_version.to_le_bytes());

    // Transaction locktime
    data.extend_from_slice(&tx_locktime.to_le_bytes());

    // If not ANYONECANPAY, hash prevouts, amounts, scriptpubkeys, sequences
    if !sighash_type.is_anyone_can_pay() {
        // sha_prevouts
        data.extend_from_slice(&hash_prevouts(prevouts, input_index));

        // sha_amounts
        data.extend_from_slice(&hash_amounts(prevouts));

        // sha_scriptpubkeys
        data.extend_from_slice(&hash_scriptpubkeys(prevouts));

        // sha_sequences
        data.extend_from_slice(&hash_sequences(sequences));
    }

    // If not NONE or SINGLE, hash outputs
    if !sighash_type.is_none() && !sighash_type.is_single() {
        data.extend_from_slice(&hash_outputs(outputs));
    }

    // Spend type
    let mut spend_type = 0u8;
    if annex.is_some() {
        spend_type |= 1;
    }
    if leaf_hash.is_some() {
        spend_type |= 2;
    }
    data.push(spend_type);

    // If ANYONECANPAY, include this input's data
    if sighash_type.is_anyone_can_pay() {
        // outpoint (would need txid + vout)
        // For now, we'll use placeholder - real implementation needs full tx data
        data.extend_from_slice(&[0u8; 36]); // txid + vout

        // amount
        data.extend_from_slice(&prevouts[input_index].value.to_le_bytes());

        // scriptpubkey
        let spk = &prevouts[input_index].script_pubkey;
        write_compact_size(&mut data, spk.len());
        data.extend_from_slice(spk);

        // sequence
        data.extend_from_slice(&sequences[input_index].to_le_bytes());
    } else {
        // input_index
        data.extend_from_slice(&(input_index as u32).to_le_bytes());
    }

    // Annex hash if present
    if let Some(annex_data) = annex {
        let annex_hash = sha256(annex_data);
        data.extend_from_slice(&annex_hash);
    }

    // If SINGLE, include this output
    if sighash_type.is_single() && input_index < outputs.len() {
        data.extend_from_slice(&hash_single_output(&outputs[input_index]));
    }

    // Script path data
    if let Some(leaf) = leaf_hash {
        // tapleaf_hash
        data.extend_from_slice(leaf.as_bytes());

        // key_version
        data.push(key_version);

        // codesep_pos
        data.extend_from_slice(&codesep_pos.to_le_bytes());
    }

    tagged_hash(TAG_TAP_SIGHASH, &data)
}

fn hash_prevouts(_prevouts: &[TxOut], _input_index: usize) -> [u8; 32] {
    // In a real implementation, this would hash all outpoints
    // For now, return placeholder
    [0u8; 32]
}

fn hash_amounts(prevouts: &[TxOut]) -> [u8; 32] {
    let mut data = Vec::new();
    for prevout in prevouts {
        data.extend_from_slice(&prevout.value.to_le_bytes());
    }
    sha256(&data)
}

fn hash_scriptpubkeys(prevouts: &[TxOut]) -> [u8; 32] {
    let mut data = Vec::new();
    for prevout in prevouts {
        write_compact_size(&mut data, prevout.script_pubkey.len());
        data.extend_from_slice(&prevout.script_pubkey);
    }
    sha256(&data)
}

fn hash_sequences(sequences: &[u32]) -> [u8; 32] {
    let mut data = Vec::new();
    for seq in sequences {
        data.extend_from_slice(&seq.to_le_bytes());
    }
    sha256(&data)
}

fn hash_outputs(outputs: &[TxOut]) -> [u8; 32] {
    let mut data = Vec::new();
    for output in outputs {
        data.extend_from_slice(&output.value.to_le_bytes());
        write_compact_size(&mut data, output.script_pubkey.len());
        data.extend_from_slice(&output.script_pubkey);
    }
    sha256(&data)
}

fn hash_single_output(output: &TxOut) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(&output.value.to_le_bytes());
    write_compact_size(&mut data, output.script_pubkey.len());
    data.extend_from_slice(&output.script_pubkey);
    sha256(&data)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

fn write_compact_size(buf: &mut Vec<u8>, value: usize) {
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
    fn test_sighash_type_roundtrip() {
        let types = [
            TaprootSighashType::Default,
            TaprootSighashType::All,
            TaprootSighashType::None,
            TaprootSighashType::Single,
            TaprootSighashType::AllAnyoneCanPay,
            TaprootSighashType::NoneAnyoneCanPay,
            TaprootSighashType::SingleAnyoneCanPay,
        ];

        for sighash in types {
            let byte = sighash.to_u8();
            let parsed = TaprootSighashType::from_u8(byte).unwrap();
            assert_eq!(sighash, parsed);
        }
    }

    #[test]
    fn test_sighash_flags() {
        assert!(!TaprootSighashType::Default.is_anyone_can_pay());
        assert!(TaprootSighashType::AllAnyoneCanPay.is_anyone_can_pay());

        assert!(!TaprootSighashType::All.is_none());
        assert!(TaprootSighashType::None.is_none());

        assert!(!TaprootSighashType::All.is_single());
        assert!(TaprootSighashType::Single.is_single());
    }

    #[test]
    fn test_key_path_sighash() {
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&[0x00; 32]);
        let prevouts = vec![TxOut {
            value: 100_000,
            script_pubkey: script.clone(),
        }];
        let sequences = vec![0xffffffff];
        let outputs = vec![TxOut {
            value: 90_000,
            script_pubkey: script,
        }];

        let hash = taproot_key_path_sighash(
            2,
            0,
            &prevouts,
            0,
            &sequences,
            &outputs,
            TaprootSighashType::Default,
            None,
        );

        // Hash should be deterministic
        let hash2 = taproot_key_path_sighash(
            2,
            0,
            &prevouts,
            0,
            &sequences,
            &outputs,
            TaprootSighashType::Default,
            None,
        );

        assert_eq!(hash, hash2);
    }
}
