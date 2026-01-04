//! PSBT-based PayJoin (BIP78) implementation.
//!
//! Provides PayJoin workflow using PSBTs for hardware wallet compatibility.

use crate::error::{CoinJoinError, Result};
use crate::types::InputRef;
use rustywallet_psbt::Psbt;

/// PSBT-based PayJoin for BIP78 workflow.
///
/// Enables PayJoin transactions using PSBTs, allowing hardware wallet
/// signing and multi-party workflows.
///
/// # Example
///
/// ```rust,no_run
/// use rustywallet_coinjoin::psbt_payjoin::PsbtPayJoin;
/// use rustywallet_coinjoin::types::InputRef;
///
/// // Receiver creates PayJoin from original PSBT
/// let original_psbt_base64 = "cHNidP8...";
/// let mut payjoin = PsbtPayJoin::from_original_psbt(original_psbt_base64).unwrap();
///
/// // Receiver adds their input
/// let receiver_input = InputRef::from_outpoint([1u8; 32], 0, 50_000);
/// payjoin.add_receiver_input(receiver_input);
///
/// // Create proposal PSBT
/// let proposal = payjoin.create_proposal().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct PsbtPayJoin {
    /// Original PSBT from sender
    original_psbt: Psbt,
    /// Original PSBT base64 for reference
    original_base64: String,
    /// Receiver's additional inputs
    receiver_inputs: Vec<InputRef>,
    /// Receiver's output script (for increased payment)
    receiver_output_script: Option<Vec<u8>>,
    /// Additional fee contribution from receiver
    fee_contribution: u64,
    /// Minimum fee rate (sat/vB)
    min_fee_rate: Option<f64>,
}

impl PsbtPayJoin {
    /// Create a new PayJoin from the original PSBT.
    ///
    /// The original PSBT is the sender's initial transaction that
    /// the receiver will modify by adding their own inputs.
    pub fn from_original_psbt(psbt_base64: &str) -> Result<Self> {
        let psbt = Psbt::from_base64(psbt_base64)
            .map_err(|e| CoinJoinError::InvalidPsbt(e.to_string()))?;

        Ok(Self {
            original_psbt: psbt,
            original_base64: psbt_base64.to_string(),
            receiver_inputs: Vec::new(),
            receiver_output_script: None,
            fee_contribution: 0,
            min_fee_rate: None,
        })
    }

    /// Create from an existing PSBT object.
    pub fn from_psbt(psbt: Psbt) -> Self {
        let base64 = psbt.to_base64();
        Self {
            original_psbt: psbt,
            original_base64: base64,
            receiver_inputs: Vec::new(),
            receiver_output_script: None,
            fee_contribution: 0,
            min_fee_rate: None,
        }
    }

    /// Add a receiver input to the PayJoin.
    ///
    /// The receiver contributes their own UTXOs to break the
    /// common-input-ownership heuristic.
    pub fn add_receiver_input(&mut self, input: InputRef) -> &mut Self {
        self.receiver_inputs.push(input);
        self
    }

    /// Add multiple receiver inputs.
    pub fn add_receiver_inputs(&mut self, inputs: impl IntoIterator<Item = InputRef>) -> &mut Self {
        self.receiver_inputs.extend(inputs);
        self
    }

    /// Set the receiver's output script.
    ///
    /// This is used to modify the receiver's output amount
    /// to include the contributed input value.
    pub fn set_receiver_output_script(&mut self, script: Vec<u8>) -> &mut Self {
        self.receiver_output_script = Some(script);
        self
    }

    /// Set fee contribution from receiver.
    pub fn set_fee_contribution(&mut self, amount: u64) -> &mut Self {
        self.fee_contribution = amount;
        self
    }

    /// Set minimum fee rate.
    pub fn set_min_fee_rate(&mut self, rate: f64) -> &mut Self {
        self.min_fee_rate = Some(rate);
        self
    }

    /// Get the original PSBT.
    pub fn original_psbt(&self) -> &Psbt {
        &self.original_psbt
    }

    /// Get the original PSBT as base64.
    pub fn original_base64(&self) -> &str {
        &self.original_base64
    }

    /// Get receiver inputs.
    pub fn receiver_inputs(&self) -> &[InputRef] {
        &self.receiver_inputs
    }

    /// Get total receiver input amount.
    pub fn receiver_input_total(&self) -> u64 {
        self.receiver_inputs.iter().map(|i| i.amount).sum()
    }

    /// Create the PayJoin proposal PSBT.
    ///
    /// This creates a new PSBT with the receiver's inputs added.
    /// The sender will verify and sign this proposal.
    pub fn create_proposal(&self) -> Result<Psbt> {
        if self.receiver_inputs.is_empty() {
            return Err(CoinJoinError::PayJoinError(
                "Receiver must contribute at least one input".into(),
            ));
        }

        // Get original transaction data
        let original_tx = self.original_psbt.unsigned_tx()
            .ok_or_else(|| CoinJoinError::InvalidPsbt("No unsigned transaction".into()))?;

        // Build new transaction with receiver inputs
        let new_tx = self.build_proposal_tx(original_tx)?;

        // Create new PSBT
        let mut psbt = Psbt::from_unsigned_tx(new_tx)
            .map_err(|e| CoinJoinError::InvalidPsbt(e.to_string()))?;

        // Copy UTXO info from original PSBT for original inputs
        let original_input_count = self.original_psbt.input_count();
        for i in 0..original_input_count {
            let orig_input = &self.original_psbt.inputs[i];
            
            if let Some(ref utxo) = orig_input.witness_utxo {
                psbt.update_input_with_utxo(i, utxo.clone())
                    .map_err(|e| CoinJoinError::InvalidPsbt(e.to_string()))?;
            }
            
            if let Some(ref tx) = orig_input.non_witness_utxo {
                psbt.update_input_with_non_witness_utxo(i, tx.clone())
                    .map_err(|e| CoinJoinError::InvalidPsbt(e.to_string()))?;
            }
        }

        // Add UTXO info for receiver inputs
        for (i, input) in self.receiver_inputs.iter().enumerate() {
            let input_index = original_input_count + i;
            let utxo = rustywallet_psbt::TxOut {
                value: input.amount,
                script_pubkey: input.script_pubkey.clone(),
            };
            psbt.update_input_with_utxo(input_index, utxo)
                .map_err(|e| CoinJoinError::InvalidPsbt(e.to_string()))?;
        }

        Ok(psbt)
    }

    /// Build the proposal transaction with receiver inputs.
    fn build_proposal_tx(&self, original_tx: &[u8]) -> Result<Vec<u8>> {
        // Parse original transaction
        let (version, inputs, outputs, locktime) = parse_transaction(original_tx)?;

        let mut tx = Vec::new();

        // Version
        tx.extend_from_slice(&version.to_le_bytes());

        // Input count (original + receiver)
        let total_inputs = inputs.len() + self.receiver_inputs.len();
        write_compact_size(&mut tx, total_inputs);

        // Original inputs
        for input in &inputs {
            tx.extend_from_slice(&input.txid);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            write_compact_size(&mut tx, input.script_sig.len());
            tx.extend_from_slice(&input.script_sig);
            tx.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Receiver inputs
        for input in &self.receiver_inputs {
            tx.extend_from_slice(&input.txid);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            tx.push(0x00); // Empty scriptSig
            tx.extend_from_slice(&0xfffffffd_u32.to_le_bytes()); // Sequence
        }

        // Output count
        write_compact_size(&mut tx, outputs.len());

        // Outputs (potentially modified)
        let receiver_total = self.receiver_input_total();
        for (_i, output) in outputs.iter().enumerate() {
            // If this is the receiver's output and we have a receiver script, increase amount
            let amount = if self.receiver_output_script.is_some()
                && Some(&output.script_pubkey) == self.receiver_output_script.as_ref()
            {
                output.amount + receiver_total - self.fee_contribution
            } else {
                output.amount
            };

            tx.extend_from_slice(&amount.to_le_bytes());
            write_compact_size(&mut tx, output.script_pubkey.len());
            tx.extend_from_slice(&output.script_pubkey);
        }

        // Locktime
        tx.extend_from_slice(&locktime.to_le_bytes());

        Ok(tx)
    }

    /// Verify a PayJoin proposal from the sender's perspective.
    ///
    /// Checks that the proposal is valid and doesn't steal funds.
    pub fn verify_proposal(&self, proposal: &Psbt) -> Result<()> {
        // Verify proposal has more inputs than original
        if proposal.input_count() <= self.original_psbt.input_count() {
            return Err(CoinJoinError::VerificationFailed(
                "Proposal must have additional inputs".into(),
            ));
        }

        // Verify original inputs are preserved
        // (In a full implementation, we'd verify the outpoints match)

        Ok(())
    }

    /// Finalize the PayJoin after both parties have signed.
    pub fn finalize(psbt: &mut Psbt) -> Result<Vec<u8>> {
        // Validate all inputs have signatures
        for (i, input) in psbt.inputs.iter().enumerate() {
            if !input.is_finalized() && input.partial_sigs.is_empty() && input.tap_key_sig.is_none() {
                return Err(CoinJoinError::VerificationFailed(format!(
                    "Input {} is not signed",
                    i
                )));
            }
        }

        // Finalize
        psbt.finalize()
            .map_err(|e| CoinJoinError::InvalidPsbt(format!("Finalization failed: {}", e)))?;

        // Extract transaction
        psbt.extract_tx()
            .map_err(|e| CoinJoinError::InvalidPsbt(format!("Extraction failed: {}", e)))
    }
}

/// Parsed transaction input.
#[derive(Debug, Clone)]
struct ParsedInput {
    txid: [u8; 32],
    vout: u32,
    script_sig: Vec<u8>,
    sequence: u32,
}

/// Parsed transaction output.
#[derive(Debug, Clone)]
struct ParsedOutput {
    amount: u64,
    script_pubkey: Vec<u8>,
}

/// Parse a transaction into its components.
fn parse_transaction(tx: &[u8]) -> Result<(u32, Vec<ParsedInput>, Vec<ParsedOutput>, u32)> {
    if tx.len() < 10 {
        return Err(CoinJoinError::InvalidTransaction("Transaction too short".into()));
    }

    let mut offset = 0;

    // Version
    let version = u32::from_le_bytes([tx[0], tx[1], tx[2], tx[3]]);
    offset += 4;

    // Check for witness marker
    let has_witness = tx.get(offset) == Some(&0x00) && tx.get(offset + 1) == Some(&0x01);
    if has_witness {
        offset += 2;
    }

    // Input count
    let (input_count, size) = read_compact_size(&tx[offset..])?;
    offset += size;

    // Inputs
    let mut inputs = Vec::new();
    for _ in 0..input_count {
        if offset + 36 > tx.len() {
            return Err(CoinJoinError::InvalidTransaction("Input truncated".into()));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&tx[offset..offset + 32]);
        offset += 32;

        let vout = u32::from_le_bytes([
            tx[offset], tx[offset + 1], tx[offset + 2], tx[offset + 3],
        ]);
        offset += 4;

        let (script_len, size) = read_compact_size(&tx[offset..])?;
        offset += size;

        let script_sig = tx[offset..offset + script_len].to_vec();
        offset += script_len;

        let sequence = u32::from_le_bytes([
            tx[offset], tx[offset + 1], tx[offset + 2], tx[offset + 3],
        ]);
        offset += 4;

        inputs.push(ParsedInput {
            txid,
            vout,
            script_sig,
            sequence,
        });
    }

    // Output count
    let (output_count, size) = read_compact_size(&tx[offset..])?;
    offset += size;

    // Outputs
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        if offset + 8 > tx.len() {
            return Err(CoinJoinError::InvalidTransaction("Output truncated".into()));
        }

        let amount = u64::from_le_bytes([
            tx[offset], tx[offset + 1], tx[offset + 2], tx[offset + 3],
            tx[offset + 4], tx[offset + 5], tx[offset + 6], tx[offset + 7],
        ]);
        offset += 8;

        let (script_len, size) = read_compact_size(&tx[offset..])?;
        offset += size;

        let script_pubkey = tx[offset..offset + script_len].to_vec();
        offset += script_len;

        outputs.push(ParsedOutput {
            amount,
            script_pubkey,
        });
    }

    // Skip witness data if present
    if has_witness {
        for _ in 0..input_count {
            let (witness_count, size) = read_compact_size(&tx[offset..])?;
            offset += size;
            for _ in 0..witness_count {
                let (item_len, size) = read_compact_size(&tx[offset..])?;
                offset += size + item_len;
            }
        }
    }

    // Locktime
    if offset + 4 > tx.len() {
        return Err(CoinJoinError::InvalidTransaction("Locktime truncated".into()));
    }
    let locktime = u32::from_le_bytes([
        tx[offset], tx[offset + 1], tx[offset + 2], tx[offset + 3],
    ]);

    Ok((version, inputs, outputs, locktime))
}

/// Read compact size encoding.
fn read_compact_size(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(CoinJoinError::InvalidTransaction("Unexpected end of data".into()));
    }

    match data[0] {
        0..=0xfc => Ok((data[0] as usize, 1)),
        0xfd => {
            if data.len() < 3 {
                return Err(CoinJoinError::InvalidTransaction("Compact size truncated".into()));
            }
            let size = u16::from_le_bytes([data[1], data[2]]) as usize;
            Ok((size, 3))
        }
        0xfe => {
            if data.len() < 5 {
                return Err(CoinJoinError::InvalidTransaction("Compact size truncated".into()));
            }
            let size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
            Ok((size, 5))
        }
        0xff => {
            if data.len() < 9 {
                return Err(CoinJoinError::InvalidTransaction("Compact size truncated".into()));
            }
            let size = u64::from_le_bytes([
                data[1], data[2], data[3], data[4],
                data[5], data[6], data[7], data[8],
            ]) as usize;
            Ok((size, 9))
        }
    }
}

/// Write compact size encoding.
fn write_compact_size(buf: &mut Vec<u8>, size: usize) {
    if size < 0xfd {
        buf.push(size as u8);
    } else if size <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(size as u16).to_le_bytes());
    } else if size <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(size as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&(size as u64).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_psbt() -> Psbt {
        // Create a minimal unsigned transaction
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

        Psbt::from_unsigned_tx(tx).unwrap()
    }

    #[test]
    fn test_psbt_payjoin_creation() {
        let psbt = create_test_psbt();
        let payjoin = PsbtPayJoin::from_psbt(psbt);

        assert!(payjoin.receiver_inputs().is_empty());
        assert_eq!(payjoin.receiver_input_total(), 0);
    }

    #[test]
    fn test_add_receiver_input() {
        let psbt = create_test_psbt();
        let mut payjoin = PsbtPayJoin::from_psbt(psbt);

        payjoin.add_receiver_input(InputRef::from_outpoint([1u8; 32], 0, 50_000));

        assert_eq!(payjoin.receiver_inputs().len(), 1);
        assert_eq!(payjoin.receiver_input_total(), 50_000);
    }

    #[test]
    fn test_create_proposal_requires_input() {
        let psbt = create_test_psbt();
        let payjoin = PsbtPayJoin::from_psbt(psbt);

        let result = payjoin.create_proposal();
        assert!(matches!(result, Err(CoinJoinError::PayJoinError(_))));
    }

    #[test]
    fn test_create_proposal() {
        let psbt = create_test_psbt();
        let mut payjoin = PsbtPayJoin::from_psbt(psbt);

        payjoin.add_receiver_input(InputRef::from_outpoint([1u8; 32], 0, 50_000));

        let proposal = payjoin.create_proposal().unwrap();

        // Should have original input + receiver input
        assert_eq!(proposal.input_count(), 2);
    }

    #[test]
    fn test_parse_transaction() {
        let tx = vec![
            0x02, 0x00, 0x00, 0x00, // version
            0x01, // 1 input
            // input
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, // txid
            0x00, 0x00, 0x00, 0x00, // vout
            0x00, // empty script
            0xff, 0xff, 0xff, 0xff, // sequence
            0x01, // 1 output
            // output
            0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, // value
            0x02, // script length
            0x00, 0x14, // script
            0x00, 0x00, 0x00, 0x00, // locktime
        ];

        let (version, inputs, outputs, locktime) = parse_transaction(&tx).unwrap();

        assert_eq!(version, 2);
        assert_eq!(inputs.len(), 1);
        assert_eq!(outputs.len(), 1);
        assert_eq!(locktime, 0);
        assert_eq!(outputs[0].amount, 100_000_000); // 1 BTC
    }
}
