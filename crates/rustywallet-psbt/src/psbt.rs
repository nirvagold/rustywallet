//! Main PSBT struct

use crate::error::PsbtError;
use crate::global::GlobalMap;
use crate::input::{InputMap, TxOut};
use crate::output::OutputMap;
use crate::serialize::{deserialize, serialize};
use crate::types::KeySource;
use base64::{engine::general_purpose::STANDARD, Engine};

/// Partially Signed Bitcoin Transaction (BIP174/BIP370)
#[derive(Debug, Clone)]
pub struct Psbt {
    /// Global map
    pub global: GlobalMap,
    /// Per-input maps
    pub inputs: Vec<InputMap>,
    /// Per-output maps
    pub outputs: Vec<OutputMap>,
}

impl Psbt {
    /// Create a new PSBT from an unsigned transaction
    pub fn from_unsigned_tx(tx: Vec<u8>) -> Result<Self, PsbtError> {
        // Count inputs and outputs
        let (input_count, output_count) = count_tx_io(&tx)?;

        Ok(Self {
            global: GlobalMap::with_unsigned_tx(tx),
            inputs: vec![InputMap::new(); input_count],
            outputs: vec![OutputMap::new(); output_count],
        })
    }

    /// Create a new PSBT v2 (without embedded transaction)
    pub fn new_v2(input_count: usize, output_count: usize) -> Self {
        let mut global = GlobalMap::new();
        global.version = Some(2);
        global.input_count = Some(input_count as u64);
        global.output_count = Some(output_count as u64);
        global.tx_version = Some(2);

        Self {
            global,
            inputs: vec![InputMap::new(); input_count],
            outputs: vec![OutputMap::new(); output_count],
        }
    }

    /// Parse PSBT from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PsbtError> {
        deserialize(bytes)
    }

    /// Parse PSBT from base64 string
    pub fn from_base64(s: &str) -> Result<Self, PsbtError> {
        let bytes = STANDARD
            .decode(s.trim())
            .map_err(|e| PsbtError::Base64Error(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Serialize PSBT to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(self)
    }

    /// Serialize PSBT to base64 string
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_bytes())
    }

    /// Get PSBT version
    pub fn version(&self) -> u32 {
        self.global.psbt_version()
    }

    /// Check if this is PSBT v2
    pub fn is_v2(&self) -> bool {
        self.global.is_v2()
    }

    /// Get the unsigned transaction (PSBT v0 only)
    pub fn unsigned_tx(&self) -> Option<&[u8]> {
        self.global.unsigned_tx.as_deref()
    }

    /// Get number of inputs
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Get number of outputs
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Update input with witness UTXO
    pub fn update_input_with_utxo(&mut self, index: usize, utxo: TxOut) -> Result<(), PsbtError> {
        if index >= self.inputs.len() {
            return Err(PsbtError::InputIndexOutOfBounds(index));
        }
        self.inputs[index].witness_utxo = Some(utxo);
        Ok(())
    }

    /// Update input with non-witness UTXO (full previous transaction)
    pub fn update_input_with_non_witness_utxo(
        &mut self,
        index: usize,
        tx: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if index >= self.inputs.len() {
            return Err(PsbtError::InputIndexOutOfBounds(index));
        }
        self.inputs[index].non_witness_utxo = Some(tx);
        Ok(())
    }

    /// Update input with redeem script
    pub fn update_input_with_redeem_script(
        &mut self,
        index: usize,
        script: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if index >= self.inputs.len() {
            return Err(PsbtError::InputIndexOutOfBounds(index));
        }
        self.inputs[index].redeem_script = Some(script);
        Ok(())
    }

    /// Update input with witness script
    pub fn update_input_with_witness_script(
        &mut self,
        index: usize,
        script: Vec<u8>,
    ) -> Result<(), PsbtError> {
        if index >= self.inputs.len() {
            return Err(PsbtError::InputIndexOutOfBounds(index));
        }
        self.inputs[index].witness_script = Some(script);
        Ok(())
    }

    /// Update input with BIP32 derivation info
    pub fn update_input_with_bip32(
        &mut self,
        index: usize,
        pubkey: Vec<u8>,
        source: KeySource,
    ) -> Result<(), PsbtError> {
        if index >= self.inputs.len() {
            return Err(PsbtError::InputIndexOutOfBounds(index));
        }
        self.inputs[index].bip32_derivation.insert(pubkey, source);
        Ok(())
    }

    /// Update output with BIP32 derivation info
    pub fn update_output_with_bip32(
        &mut self,
        index: usize,
        pubkey: Vec<u8>,
        source: KeySource,
    ) -> Result<(), PsbtError> {
        if index >= self.outputs.len() {
            return Err(PsbtError::OutputIndexOutOfBounds(index));
        }
        self.outputs[index].bip32_derivation.insert(pubkey, source);
        Ok(())
    }

    /// Calculate total input value (if all UTXOs are known)
    pub fn total_input_value(&self) -> Option<u64> {
        let mut total = 0u64;
        for input in &self.inputs {
            total = total.checked_add(input.utxo_value()?)?;
        }
        Some(total)
    }

    /// Calculate fee (if all UTXOs are known)
    pub fn fee(&self) -> Option<u64> {
        let input_value = self.total_input_value()?;
        let output_value = self.total_output_value()?;
        input_value.checked_sub(output_value)
    }

    /// Calculate total output value
    fn total_output_value(&self) -> Option<u64> {
        // For v2, use output.amount
        if self.is_v2() {
            let mut total = 0u64;
            for output in &self.outputs {
                total = total.checked_add(output.amount?)?;
            }
            return Some(total);
        }

        // For v0, parse from unsigned tx
        let tx = self.global.unsigned_tx.as_ref()?;
        parse_output_values(tx).ok()
    }
}

/// Count inputs and outputs from transaction bytes
fn count_tx_io(tx: &[u8]) -> Result<(usize, usize), PsbtError> {
    if tx.len() < 10 {
        return Err(PsbtError::InvalidFormat("Transaction too short".into()));
    }

    let mut offset = 4; // Skip version

    // Check for witness marker
    if tx.get(offset) == Some(&0x00) && tx.get(offset + 1) == Some(&0x01) {
        offset += 2;
    }

    // Input count
    let (input_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size;

    // Skip inputs
    for _ in 0..input_count {
        offset += 36; // txid + vout
        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len + 4; // script + sequence
    }

    // Output count
    let (output_count, _) = crate::input::read_compact_size(&tx[offset..])?;

    Ok((input_count, output_count))
}

/// Parse total output value from transaction
fn parse_output_values(tx: &[u8]) -> Result<u64, PsbtError> {
    let mut offset = 4; // Skip version

    // Check for witness marker
    if tx.get(offset) == Some(&0x00) && tx.get(offset + 1) == Some(&0x01) {
        offset += 2;
    }

    // Skip inputs
    let (input_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size;

    for _ in 0..input_count {
        offset += 36; // txid + vout
        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len + 4; // script + sequence
    }

    // Output count
    let (output_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size;

    let mut total = 0u64;
    for _ in 0..output_count {
        if offset + 8 > tx.len() {
            return Err(PsbtError::InvalidFormat("Output value truncated".into()));
        }
        let value = u64::from_le_bytes([
            tx[offset],
            tx[offset + 1],
            tx[offset + 2],
            tx[offset + 3],
            tx[offset + 4],
            tx[offset + 5],
            tx[offset + 6],
            tx[offset + 7],
        ]);
        total = total
            .checked_add(value)
            .ok_or_else(|| PsbtError::InvalidFormat("Output value overflow".into()))?;
        offset += 8;

        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len;
    }

    Ok(total)
}

impl std::fmt::Display for Psbt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl std::str::FromStr for Psbt {
    type Err = PsbtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base64(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_roundtrip() {
        let tx = vec![
            0x02, 0x00, 0x00, 0x00, // version
            0x01, // 1 input
            // input
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // txid
            0x00, 0x00, 0x00, 0x00, // vout
            0x00, // empty script
            0xff, 0xff, 0xff, 0xff, // sequence
            0x01, // 1 output
            // output
            0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, // value (1 BTC)
            0x16, // script length
            0x00, 0x14, // P2WPKH
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // pubkey hash
            0x00, 0x00, 0x00, 0x00, // locktime
        ];

        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert_eq!(psbt.input_count(), 1);
        assert_eq!(psbt.output_count(), 1);

        let bytes = psbt.to_bytes();
        let parsed = Psbt::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.input_count(), 1);
        assert_eq!(parsed.output_count(), 1);
    }

    #[test]
    fn test_psbt_base64_roundtrip() {
        let tx = vec![
            0x02, 0x00, 0x00, 0x00, // version
            0x00, // no inputs
            0x00, // no outputs
            0x00, 0x00, 0x00, 0x00, // locktime
        ];

        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let base64 = psbt.to_base64();
        let parsed = Psbt::from_base64(&base64).unwrap();

        assert_eq!(psbt.to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn test_psbt_v2() {
        let psbt = Psbt::new_v2(2, 2);
        assert!(psbt.is_v2());
        assert_eq!(psbt.version(), 2);
        assert_eq!(psbt.input_count(), 2);
        assert_eq!(psbt.output_count(), 2);
    }
}
