//! PSBT finalization

use crate::error::PsbtError;
use crate::input::Witness;
use crate::psbt::Psbt;

impl Psbt {
    /// Finalize all inputs
    pub fn finalize(&mut self) -> Result<(), PsbtError> {
        for i in 0..self.inputs.len() {
            self.finalize_input(i)?;
        }
        Ok(())
    }

    /// Finalize a specific input
    pub fn finalize_input(&mut self, index: usize) -> Result<(), PsbtError> {
        if index >= self.inputs.len() {
            return Err(PsbtError::InputIndexOutOfBounds(index));
        }

        let input = &self.inputs[index];

        // Already finalized
        if input.is_finalized() {
            return Ok(());
        }

        // Determine input type and finalize accordingly
        let (final_script_sig, final_witness) = if input.witness_script.is_some() {
            // P2WSH or P2SH-P2WSH
            self.finalize_p2wsh(index)?
        } else if input.redeem_script.is_some() {
            let redeem = input.redeem_script.as_ref().unwrap();
            if is_p2wpkh_script(redeem) {
                // P2SH-P2WPKH
                self.finalize_p2sh_p2wpkh(index)?
            } else {
                // P2SH
                self.finalize_p2sh(index)?
            }
        } else if let Some(ref utxo) = input.witness_utxo {
            if is_p2wpkh_script(&utxo.script_pubkey) {
                // P2WPKH
                self.finalize_p2wpkh(index)?
            } else if is_p2tr_script(&utxo.script_pubkey) {
                // P2TR
                self.finalize_p2tr(index)?
            } else if is_p2pkh_script(&utxo.script_pubkey) {
                // P2PKH
                self.finalize_p2pkh(index)?
            } else {
                return Err(PsbtError::CannotSign("Unknown script type".into()));
            }
        } else {
            return Err(PsbtError::MissingUtxo(index));
        };

        // Set final fields
        self.inputs[index].final_script_sig = final_script_sig;
        self.inputs[index].final_script_witness = final_witness;

        // Clear non-final fields
        self.inputs[index].clear_for_finalization();

        Ok(())
    }

    /// Finalize P2PKH input
    fn finalize_p2pkh(&self, index: usize) -> Result<(Option<Vec<u8>>, Option<Witness>), PsbtError> {
        let input = &self.inputs[index];

        // Need exactly one signature
        if input.partial_sigs.len() != 1 {
            return Err(PsbtError::CannotSign(format!(
                "P2PKH requires 1 signature, got {}",
                input.partial_sigs.len()
            )));
        }

        let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();

        // Build scriptSig: <sig> <pubkey>
        let mut script_sig = Vec::new();
        push_data(&mut script_sig, sig);
        push_data(&mut script_sig, pubkey);

        Ok((Some(script_sig), None))
    }

    /// Finalize P2WPKH input
    fn finalize_p2wpkh(&self, index: usize) -> Result<(Option<Vec<u8>>, Option<Witness>), PsbtError> {
        let input = &self.inputs[index];

        // Need exactly one signature
        if input.partial_sigs.len() != 1 {
            return Err(PsbtError::CannotSign(format!(
                "P2WPKH requires 1 signature, got {}",
                input.partial_sigs.len()
            )));
        }

        let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();

        // Build witness: <sig> <pubkey>
        let witness = Witness::from_items(vec![sig.clone(), pubkey.clone()]);

        Ok((None, Some(witness)))
    }

    /// Finalize P2SH-P2WPKH input
    fn finalize_p2sh_p2wpkh(&self, index: usize) -> Result<(Option<Vec<u8>>, Option<Witness>), PsbtError> {
        let input = &self.inputs[index];

        // Need exactly one signature
        if input.partial_sigs.len() != 1 {
            return Err(PsbtError::CannotSign(format!(
                "P2SH-P2WPKH requires 1 signature, got {}",
                input.partial_sigs.len()
            )));
        }

        let (pubkey, sig) = input.partial_sigs.iter().next().unwrap();
        let redeem_script = input.redeem_script.as_ref().unwrap();

        // Build scriptSig: <redeem_script>
        let mut script_sig = Vec::new();
        push_data(&mut script_sig, redeem_script);

        // Build witness: <sig> <pubkey>
        let witness = Witness::from_items(vec![sig.clone(), pubkey.clone()]);

        Ok((Some(script_sig), Some(witness)))
    }

    /// Finalize P2SH input
    fn finalize_p2sh(&self, index: usize) -> Result<(Option<Vec<u8>>, Option<Witness>), PsbtError> {
        let input = &self.inputs[index];
        let redeem_script = input.redeem_script.as_ref().unwrap();

        // Check if it's a multisig script
        if is_multisig_script(redeem_script) {
            return self.finalize_p2sh_multisig(index);
        }

        // Single sig P2SH
        if input.partial_sigs.len() != 1 {
            return Err(PsbtError::CannotSign(format!(
                "P2SH requires 1 signature, got {}",
                input.partial_sigs.len()
            )));
        }

        let (_, sig) = input.partial_sigs.iter().next().unwrap();

        // Build scriptSig: <sig> <redeem_script>
        let mut script_sig = Vec::new();
        push_data(&mut script_sig, sig);
        push_data(&mut script_sig, redeem_script);

        Ok((Some(script_sig), None))
    }

    /// Finalize P2SH multisig input
    fn finalize_p2sh_multisig(&self, index: usize) -> Result<(Option<Vec<u8>>, Option<Witness>), PsbtError> {
        let input = &self.inputs[index];
        let redeem_script = input.redeem_script.as_ref().unwrap();

        // Get required signature count from script
        let required = get_multisig_threshold(redeem_script)
            .ok_or_else(|| PsbtError::InvalidScript("Invalid multisig script".into()))?;

        if input.partial_sigs.len() < required {
            return Err(PsbtError::CannotSign(format!(
                "Multisig requires {} signatures, got {}",
                required,
                input.partial_sigs.len()
            )));
        }

        // Build scriptSig: OP_0 <sig1> <sig2> ... <redeem_script>
        let mut script_sig = Vec::new();
        script_sig.push(0x00); // OP_0 for CHECKMULTISIG bug

        // Add signatures in order of pubkeys in script
        let pubkeys = extract_multisig_pubkeys(redeem_script);
        let mut sig_count = 0;
        for pubkey in pubkeys {
            if sig_count >= required {
                break;
            }
            if let Some(sig) = input.partial_sigs.get(&pubkey) {
                push_data(&mut script_sig, sig);
                sig_count += 1;
            }
        }

        push_data(&mut script_sig, redeem_script);

        Ok((Some(script_sig), None))
    }

    /// Finalize P2WSH input
    fn finalize_p2wsh(&self, index: usize) -> Result<(Option<Vec<u8>>, Option<Witness>), PsbtError> {
        let input = &self.inputs[index];
        let witness_script = input.witness_script.as_ref().unwrap();

        // Check if it's a multisig script
        if is_multisig_script(witness_script) {
            return self.finalize_p2wsh_multisig(index);
        }

        // Single sig P2WSH
        if input.partial_sigs.len() != 1 {
            return Err(PsbtError::CannotSign(format!(
                "P2WSH requires 1 signature, got {}",
                input.partial_sigs.len()
            )));
        }

        let (_, sig) = input.partial_sigs.iter().next().unwrap();

        // Build witness: <sig> <witness_script>
        let witness = Witness::from_items(vec![sig.clone(), witness_script.clone()]);

        // Check for P2SH-P2WSH
        let script_sig = if input.redeem_script.is_some() {
            let redeem = input.redeem_script.as_ref().unwrap();
            let mut ss = Vec::new();
            push_data(&mut ss, redeem);
            Some(ss)
        } else {
            None
        };

        Ok((script_sig, Some(witness)))
    }

    /// Finalize P2WSH multisig input
    fn finalize_p2wsh_multisig(&self, index: usize) -> Result<(Option<Vec<u8>>, Option<Witness>), PsbtError> {
        let input = &self.inputs[index];
        let witness_script = input.witness_script.as_ref().unwrap();

        // Get required signature count from script
        let required = get_multisig_threshold(witness_script)
            .ok_or_else(|| PsbtError::InvalidScript("Invalid multisig script".into()))?;

        if input.partial_sigs.len() < required {
            return Err(PsbtError::CannotSign(format!(
                "Multisig requires {} signatures, got {}",
                required,
                input.partial_sigs.len()
            )));
        }

        // Build witness: <empty> <sig1> <sig2> ... <witness_script>
        let mut items = Vec::new();
        items.push(Vec::new()); // Empty for CHECKMULTISIG bug

        // Add signatures in order of pubkeys in script
        let pubkeys = extract_multisig_pubkeys(witness_script);
        let mut sig_count = 0;
        for pubkey in pubkeys {
            if sig_count >= required {
                break;
            }
            if let Some(sig) = input.partial_sigs.get(&pubkey) {
                items.push(sig.clone());
                sig_count += 1;
            }
        }

        items.push(witness_script.clone());
        let witness = Witness::from_items(items);

        // Check for P2SH-P2WSH
        let script_sig = if input.redeem_script.is_some() {
            let redeem = input.redeem_script.as_ref().unwrap();
            let mut ss = Vec::new();
            push_data(&mut ss, redeem);
            Some(ss)
        } else {
            None
        };

        Ok((script_sig, Some(witness)))
    }

    /// Finalize P2TR input
    fn finalize_p2tr(&self, index: usize) -> Result<(Option<Vec<u8>>, Option<Witness>), PsbtError> {
        let input = &self.inputs[index];

        // Key path spend
        if let Some(ref sig) = input.tap_key_sig {
            let witness = Witness::from_items(vec![sig.clone()]);
            return Ok((None, Some(witness)));
        }

        // Script path spend
        if !input.tap_script_sigs.is_empty() {
            // This is a simplified implementation
            // Full implementation would handle script path properly
            return Err(PsbtError::CannotSign("Taproot script path not fully implemented".into()));
        }

        Err(PsbtError::CannotSign("No Taproot signature found".into()))
    }

    /// Check if all inputs are finalized
    pub fn is_finalized(&self) -> bool {
        self.inputs.iter().all(|input| input.is_finalized())
    }

    /// Extract the final signed transaction
    pub fn extract_tx(&self) -> Result<Vec<u8>, PsbtError> {
        if !self.is_finalized() {
            return Err(PsbtError::NotFinalized);
        }

        let unsigned_tx = self.global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;

        // Build the signed transaction
        let mut tx = Vec::new();

        // Version
        tx.extend_from_slice(&unsigned_tx[0..4]);

        // Check if we need witness
        let has_witness = self.inputs.iter().any(|i| i.final_script_witness.is_some());

        if has_witness {
            tx.push(0x00); // Marker
            tx.push(0x01); // Flag
        }

        // Input count
        crate::input::write_compact_size(&mut tx, self.inputs.len());

        // Inputs
        for (i, input) in self.inputs.iter().enumerate() {
            // Outpoint
            let outpoint = self.get_outpoint_for_extract(i, unsigned_tx)?;
            tx.extend_from_slice(&outpoint);

            // ScriptSig
            if let Some(ref script_sig) = input.final_script_sig {
                crate::input::write_compact_size(&mut tx, script_sig.len());
                tx.extend_from_slice(script_sig);
            } else {
                tx.push(0x00); // Empty scriptSig
            }

            // Sequence
            let sequence = self.get_sequence_for_extract(i, unsigned_tx)?;
            tx.extend_from_slice(&sequence.to_le_bytes());
        }

        // Outputs (copy from unsigned tx)
        let outputs_data = self.extract_outputs_from_unsigned(unsigned_tx)?;
        tx.extend_from_slice(&outputs_data);

        // Witness data
        if has_witness {
            for input in &self.inputs {
                if let Some(ref witness) = input.final_script_witness {
                    tx.extend_from_slice(&witness.to_bytes());
                } else {
                    tx.push(0x00); // Empty witness
                }
            }
        }

        // Locktime
        let len = unsigned_tx.len();
        tx.extend_from_slice(&unsigned_tx[len - 4..]);

        Ok(tx)
    }

    /// Get outpoint for transaction extraction
    fn get_outpoint_for_extract(&self, index: usize, tx: &[u8]) -> Result<[u8; 36], PsbtError> {
        let input = &self.inputs[index];

        // PSBT v2
        if let (Some(txid), Some(vout)) = (input.previous_txid, input.output_index) {
            let mut outpoint = [0u8; 36];
            outpoint[0..32].copy_from_slice(&txid);
            outpoint[32..36].copy_from_slice(&vout.to_le_bytes());
            return Ok(outpoint);
        }

        // Extract from unsigned tx
        crate::signer::extract_outpoint(tx, index)
    }

    /// Get sequence for transaction extraction
    fn get_sequence_for_extract(&self, index: usize, tx: &[u8]) -> Result<u32, PsbtError> {
        let input = &self.inputs[index];

        // PSBT v2
        if let Some(seq) = input.sequence {
            return Ok(seq);
        }

        // Extract from unsigned tx
        crate::signer::extract_sequence(tx, index)
    }

    /// Extract outputs from unsigned transaction
    fn extract_outputs_from_unsigned(&self, tx: &[u8]) -> Result<Vec<u8>, PsbtError> {
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

        // Output count and outputs
        let outputs_start = offset;
        let (output_count, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size;

        for _ in 0..output_count {
            offset += 8; // value
            let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
            offset += size + script_len;
        }

        Ok(tx[outputs_start..offset].to_vec())
    }
}

/// Push data with length prefix
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 0x4c {
        script.push(len as u8);
    } else if len <= 0xff {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
    } else if len <= 0xffff {
        script.push(0x4d); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        script.push(0x4e); // OP_PUSHDATA4
        script.extend_from_slice(&(len as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// Check if script is P2PKH
fn is_p2pkh_script(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == 0x76  // OP_DUP
        && script[1] == 0xa9  // OP_HASH160
        && script[2] == 0x14  // Push 20 bytes
        && script[23] == 0x88 // OP_EQUALVERIFY
        && script[24] == 0xac // OP_CHECKSIG
}

/// Check if script is P2WPKH
fn is_p2wpkh_script(script: &[u8]) -> bool {
    script.len() == 22 && script[0] == 0x00 && script[1] == 0x14
}

/// Check if script is P2TR
fn is_p2tr_script(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == 0x20
}

/// Check if script is multisig
fn is_multisig_script(script: &[u8]) -> bool {
    if script.len() < 3 {
        return false;
    }
    let last = script[script.len() - 1];
    last == 0xae // OP_CHECKMULTISIG
}

/// Get multisig threshold (M value)
fn get_multisig_threshold(script: &[u8]) -> Option<usize> {
    if script.is_empty() {
        return None;
    }
    let first = script[0];
    if (0x51..=0x60).contains(&first) {
        // OP_1 to OP_16
        Some((first - 0x50) as usize)
    } else {
        None
    }
}

/// Extract pubkeys from multisig script
fn extract_multisig_pubkeys(script: &[u8]) -> Vec<Vec<u8>> {
    let mut pubkeys = Vec::new();
    let mut i = 1; // Skip M value

    while i < script.len() - 2 {
        let len = script[i] as usize;
        if len == 33 || len == 65 {
            // Compressed or uncompressed pubkey
            if i + 1 + len <= script.len() {
                pubkeys.push(script[i + 1..i + 1 + len].to_vec());
                i += 1 + len;
            } else {
                break;
            }
        } else if script[i] >= 0x51 && script[i] <= 0x60 {
            // N value (OP_1 to OP_16)
            break;
        } else {
            i += 1;
        }
    }

    pubkeys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_p2pkh_script() {
        let script = vec![
            0x76, 0xa9, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0xac,
        ];
        assert!(is_p2pkh_script(&script));
    }

    #[test]
    fn test_is_p2wpkh_script() {
        let script = vec![
            0x00, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_p2wpkh_script(&script));
    }

    #[test]
    fn test_is_p2tr_script() {
        let script = vec![
            0x51, 0x20,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert!(is_p2tr_script(&script));
    }

    #[test]
    fn test_get_multisig_threshold() {
        // 2-of-3 multisig
        let script = vec![0x52]; // OP_2
        assert_eq!(get_multisig_threshold(&script), Some(2));

        // 3-of-5 multisig
        let script = vec![0x53]; // OP_3
        assert_eq!(get_multisig_threshold(&script), Some(3));
    }
}
