//! PSBT combination

use crate::error::PsbtError;
use crate::psbt::Psbt;

impl Psbt {
    /// Combine multiple PSBTs into one
    ///
    /// All PSBTs must have the same unsigned transaction
    pub fn combine(psbts: &[Psbt]) -> Result<Self, PsbtError> {
        if psbts.is_empty() {
            return Err(PsbtError::InvalidFormat("No PSBTs to combine".into()));
        }

        let mut result = psbts[0].clone();

        for psbt in &psbts[1..] {
            result.merge(psbt)?;
        }

        Ok(result)
    }

    /// Merge another PSBT into this one
    pub fn merge(&mut self, other: &Psbt) -> Result<(), PsbtError> {
        // Verify same unsigned transaction
        if self.global.unsigned_tx != other.global.unsigned_tx {
            return Err(PsbtError::TransactionMismatch);
        }

        // Verify same number of inputs/outputs
        if self.inputs.len() != other.inputs.len() {
            return Err(PsbtError::IncompatiblePsbts);
        }
        if self.outputs.len() != other.outputs.len() {
            return Err(PsbtError::IncompatiblePsbts);
        }

        // Merge global map
        self.merge_global(&other.global);

        // Merge input maps
        for (i, other_input) in other.inputs.iter().enumerate() {
            self.merge_input(i, other_input)?;
        }

        // Merge output maps
        for (i, other_output) in other.outputs.iter().enumerate() {
            self.merge_output(i, other_output);
        }

        Ok(())
    }

    /// Merge global maps
    fn merge_global(&mut self, other: &crate::global::GlobalMap) {
        // Merge xpubs
        for xpub_entry in &other.xpubs {
            if !self.global.xpubs.iter().any(|x| x.xpub == xpub_entry.xpub) {
                self.global.xpubs.push(xpub_entry.clone());
            }
        }

        // Merge proprietary fields
        for (key, value) in &other.proprietary {
            self.global.proprietary.entry(key.clone()).or_insert_with(|| value.clone());
        }

        // Merge unknown fields
        for (key, value) in &other.unknown {
            self.global.unknown.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }

    /// Merge input maps
    fn merge_input(&mut self, index: usize, other: &crate::input::InputMap) -> Result<(), PsbtError> {
        let input = &mut self.inputs[index];

        // Don't merge if already finalized
        if input.is_finalized() {
            return Ok(());
        }

        // If other is finalized, use its final data
        if other.is_finalized() {
            input.final_script_sig = other.final_script_sig.clone();
            input.final_script_witness = other.final_script_witness.clone();
            input.clear_for_finalization();
            return Ok(());
        }

        // Merge non-witness UTXO
        if input.non_witness_utxo.is_none() {
            input.non_witness_utxo = other.non_witness_utxo.clone();
        }

        // Merge witness UTXO
        if input.witness_utxo.is_none() {
            input.witness_utxo = other.witness_utxo.clone();
        }

        // Merge partial signatures
        for (pubkey, sig) in &other.partial_sigs {
            input.partial_sigs.entry(pubkey.clone()).or_insert_with(|| sig.clone());
        }

        // Merge sighash type (prefer existing)
        if input.sighash_type.is_none() {
            input.sighash_type = other.sighash_type;
        }

        // Merge redeem script
        if input.redeem_script.is_none() {
            input.redeem_script = other.redeem_script.clone();
        }

        // Merge witness script
        if input.witness_script.is_none() {
            input.witness_script = other.witness_script.clone();
        }

        // Merge BIP32 derivation
        for (pubkey, source) in &other.bip32_derivation {
            input.bip32_derivation.entry(pubkey.clone()).or_insert_with(|| source.clone());
        }

        // Merge Taproot fields
        if input.tap_key_sig.is_none() {
            input.tap_key_sig = other.tap_key_sig.clone();
        }

        for (key, sig) in &other.tap_script_sigs {
            input.tap_script_sigs.entry(key.clone()).or_insert_with(|| sig.clone());
        }

        for (key, script) in &other.tap_leaf_scripts {
            input.tap_leaf_scripts.entry(key.clone()).or_insert_with(|| script.clone());
        }

        for (key, derivation) in &other.tap_bip32_derivation {
            input.tap_bip32_derivation.entry(key.clone()).or_insert_with(|| derivation.clone());
        }

        if input.tap_internal_key.is_none() {
            input.tap_internal_key = other.tap_internal_key.clone();
        }

        if input.tap_merkle_root.is_none() {
            input.tap_merkle_root = other.tap_merkle_root.clone();
        }

        // Merge proprietary fields
        for (key, value) in &other.proprietary {
            input.proprietary.entry(key.clone()).or_insert_with(|| value.clone());
        }

        // Merge unknown fields
        for (key, value) in &other.unknown {
            input.unknown.entry(key.clone()).or_insert_with(|| value.clone());
        }

        Ok(())
    }

    /// Merge output maps
    fn merge_output(&mut self, index: usize, other: &crate::output::OutputMap) {
        let output = &mut self.outputs[index];

        // Merge redeem script
        if output.redeem_script.is_none() {
            output.redeem_script = other.redeem_script.clone();
        }

        // Merge witness script
        if output.witness_script.is_none() {
            output.witness_script = other.witness_script.clone();
        }

        // Merge BIP32 derivation
        for (pubkey, source) in &other.bip32_derivation {
            output.bip32_derivation.entry(pubkey.clone()).or_insert_with(|| source.clone());
        }

        // Merge Taproot fields
        if output.tap_internal_key.is_none() {
            output.tap_internal_key = other.tap_internal_key.clone();
        }

        if output.tap_tree.is_none() {
            output.tap_tree = other.tap_tree.clone();
        }

        for (key, derivation) in &other.tap_bip32_derivation {
            output.tap_bip32_derivation.entry(key.clone()).or_insert_with(|| derivation.clone());
        }

        // Merge proprietary fields
        for (key, value) in &other.proprietary {
            output.proprietary.entry(key.clone()).or_insert_with(|| value.clone());
        }

        // Merge unknown fields
        for (key, value) in &other.unknown {
            output.unknown.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::GlobalMap;
    use crate::input::InputMap;
    use crate::output::OutputMap;

    fn create_test_psbt() -> Psbt {
        Psbt {
            global: GlobalMap::with_unsigned_tx(vec![
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
                0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, // value
                0x16, // script length
                0x00, 0x14, // P2WPKH
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, // pubkey hash
                0x00, 0x00, 0x00, 0x00, // locktime
            ]),
            inputs: vec![InputMap::new()],
            outputs: vec![OutputMap::new()],
        }
    }

    #[test]
    fn test_combine_identical() {
        let psbt = create_test_psbt();
        let combined = Psbt::combine(&[psbt.clone(), psbt.clone()]).unwrap();

        assert_eq!(combined.inputs.len(), 1);
        assert_eq!(combined.outputs.len(), 1);
    }

    #[test]
    fn test_combine_with_signatures() {
        let mut psbt1 = create_test_psbt();
        let mut psbt2 = create_test_psbt();

        // Add different signatures
        psbt1.inputs[0].partial_sigs.insert(
            vec![0x02; 33],
            vec![0x30, 0x44, 0x01],
        );
        psbt2.inputs[0].partial_sigs.insert(
            vec![0x03; 33],
            vec![0x30, 0x44, 0x02],
        );

        let combined = Psbt::combine(&[psbt1, psbt2]).unwrap();

        assert_eq!(combined.inputs[0].partial_sigs.len(), 2);
    }

    #[test]
    fn test_combine_different_tx_fails() {
        let psbt1 = create_test_psbt();
        let mut psbt2 = create_test_psbt();
        psbt2.global.unsigned_tx = Some(vec![0x01, 0x00, 0x00, 0x00]);

        let result = Psbt::combine(&[psbt1, psbt2]);
        assert!(matches!(result, Err(PsbtError::TransactionMismatch)));
    }
}
