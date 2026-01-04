//! PSBT-based CoinJoin builder.
//!
//! Builds CoinJoin transactions as PSBTs for hardware wallet compatibility
//! and multi-party signing workflows.

use crate::error::{CoinJoinError, Result};
use crate::types::{FeeStrategy, InputRef, OutputDef, Participant};
use rustywallet_psbt::{Psbt, PsbtError};
use sha2::{Digest, Sha256};

/// PSBT-based CoinJoin builder.
///
/// Builds CoinJoin transactions as PSBTs instead of raw transactions,
/// enabling hardware wallet signing and multi-party workflows.
///
/// # Example
///
/// ```rust
/// use rustywallet_coinjoin::psbt_builder::PsbtCoinJoinBuilder;
/// use rustywallet_coinjoin::types::{InputRef, Participant};
///
/// let mut builder = PsbtCoinJoinBuilder::new();
///
/// // Add participants (minimum 2 required)
/// builder.add_participant(Participant::new(
///     "alice",
///     vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
///     vec![0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12],
/// ));
/// builder.add_participant(Participant::new(
///     "bob",
///     vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
///     vec![0x00, 0x14, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12],
/// ));
///
/// builder.set_output_amount(50_000);
/// let psbt = builder.build_psbt().unwrap();
/// ```
pub struct PsbtCoinJoinBuilder {
    /// Participants
    participants: Vec<Participant>,
    /// Output amount (equal for all)
    output_amount: Option<u64>,
    /// Fee rate (sat/vB)
    fee_rate: f64,
    /// Fee distribution strategy
    fee_strategy: FeeStrategy,
    /// Minimum number of participants
    min_participants: usize,
    /// Transaction version
    tx_version: u32,
    /// Locktime
    locktime: u32,
}

impl PsbtCoinJoinBuilder {
    /// Create a new PSBT CoinJoin builder.
    pub fn new() -> Self {
        Self {
            participants: Vec::new(),
            output_amount: None,
            fee_rate: 1.0,
            fee_strategy: FeeStrategy::Equal,
            min_participants: 2,
            tx_version: 2,
            locktime: 0,
        }
    }

    /// Add a participant.
    pub fn add_participant(&mut self, participant: Participant) -> &mut Self {
        self.participants.push(participant);
        self
    }

    /// Add participant with inputs and output.
    pub fn add_participant_simple(
        &mut self,
        id: impl Into<String>,
        inputs: Vec<InputRef>,
        output_script: Vec<u8>,
    ) -> &mut Self {
        self.participants
            .push(Participant::new(id, inputs, output_script));
        self
    }

    /// Set the equal output amount.
    pub fn set_output_amount(&mut self, amount: u64) -> &mut Self {
        self.output_amount = Some(amount);
        self
    }

    /// Set fee rate in sat/vB.
    pub fn set_fee_rate(&mut self, rate: f64) -> &mut Self {
        self.fee_rate = rate;
        self
    }

    /// Set fee distribution strategy.
    pub fn set_fee_strategy(&mut self, strategy: FeeStrategy) -> &mut Self {
        self.fee_strategy = strategy;
        self
    }

    /// Set minimum number of participants.
    pub fn set_min_participants(&mut self, min: usize) -> &mut Self {
        self.min_participants = min;
        self
    }

    /// Set transaction version.
    pub fn set_tx_version(&mut self, version: u32) -> &mut Self {
        self.tx_version = version;
        self
    }

    /// Set locktime.
    pub fn set_locktime(&mut self, locktime: u32) -> &mut Self {
        self.locktime = locktime;
        self
    }

    /// Get participant count.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Get participants.
    pub fn participants(&self) -> &[Participant] {
        &self.participants
    }

    /// Build the CoinJoin transaction as a PSBT.
    pub fn build_psbt(&self) -> Result<Psbt> {
        // Validate
        if self.participants.len() < self.min_participants {
            return Err(CoinJoinError::NoParticipants);
        }

        let output_amount = self
            .output_amount
            .ok_or_else(|| CoinJoinError::InvalidAmount("Output amount not set".into()))?;

        // Calculate total inputs and fees
        let estimated_size = self.estimate_tx_size();
        let total_fee = (estimated_size as f64 * self.fee_rate) as u64;

        // Calculate per-participant fee
        let fees = self.calculate_fees(total_fee)?;

        // Verify each participant has enough funds
        for (i, participant) in self.participants.iter().enumerate() {
            let needed = output_amount + fees[i];
            let available = participant.total_input();
            if available < needed {
                return Err(CoinJoinError::InsufficientFunds { needed, available });
            }
        }

        // Collect all inputs with participant index
        let mut inputs: Vec<(InputRef, usize)> = Vec::new();
        for (idx, participant) in self.participants.iter().enumerate() {
            for input in &participant.inputs {
                inputs.push((input.clone(), idx));
            }
        }

        // Create equal outputs with participant index
        let mut outputs: Vec<(OutputDef, usize)> = Vec::new();
        for (idx, participant) in self.participants.iter().enumerate() {
            outputs.push((
                OutputDef::new(output_amount, participant.output_script.clone()),
                idx,
            ));
        }

        // Create change outputs
        let mut change_outputs: Vec<(OutputDef, usize)> = Vec::new();
        for (idx, participant) in self.participants.iter().enumerate() {
            let change = participant.total_input() - output_amount - fees[idx];
            if change > 546 {
                // Dust threshold
                if let Some(change_script) = &participant.change_script {
                    change_outputs.push((OutputDef::new(change, change_script.clone()), idx));
                }
            }
        }

        // Shuffle inputs and outputs
        let seed = self.generate_shuffle_seed();
        let shuffled_inputs = shuffle_with_seed(&inputs, &seed);
        let shuffled_outputs = shuffle_with_seed(&outputs, &seed);
        let shuffled_change = shuffle_with_seed(&change_outputs, &seed);

        // Build unsigned transaction
        let unsigned_tx = self.build_unsigned_tx(
            &shuffled_inputs,
            &shuffled_outputs,
            &shuffled_change,
        );

        // Create PSBT from unsigned transaction
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
            .map_err(|e| CoinJoinError::InvalidPsbt(e.to_string()))?;

        // Add UTXO information to inputs
        for (i, (input_ref, _)) in shuffled_inputs.iter().enumerate() {
            // Add witness UTXO
            let utxo = rustywallet_psbt::TxOut {
                value: input_ref.amount,
                script_pubkey: input_ref.script_pubkey.clone(),
            };
            psbt.update_input_with_utxo(i, utxo)
                .map_err(|e| CoinJoinError::InvalidPsbt(e.to_string()))?;
        }

        Ok(psbt)
    }

    /// Build unsigned transaction bytes.
    fn build_unsigned_tx(
        &self,
        inputs: &[(InputRef, usize)],
        outputs: &[(OutputDef, usize)],
        change_outputs: &[(OutputDef, usize)],
    ) -> Vec<u8> {
        let mut tx = Vec::new();

        // Version
        tx.extend_from_slice(&self.tx_version.to_le_bytes());

        // Input count
        write_compact_size(&mut tx, inputs.len());

        // Inputs
        for (input, _) in inputs {
            // Previous output (txid + vout)
            tx.extend_from_slice(&input.txid);
            tx.extend_from_slice(&input.vout.to_le_bytes());
            // Empty scriptSig
            tx.push(0x00);
            // Sequence (0xfffffffd for RBF)
            tx.extend_from_slice(&0xfffffffd_u32.to_le_bytes());
        }

        // Output count (main outputs + change outputs)
        let total_outputs = outputs.len() + change_outputs.len();
        write_compact_size(&mut tx, total_outputs);

        // Main outputs
        for (output, _) in outputs {
            tx.extend_from_slice(&output.amount.to_le_bytes());
            write_compact_size(&mut tx, output.script_pubkey.len());
            tx.extend_from_slice(&output.script_pubkey);
        }

        // Change outputs
        for (output, _) in change_outputs {
            tx.extend_from_slice(&output.amount.to_le_bytes());
            write_compact_size(&mut tx, output.script_pubkey.len());
            tx.extend_from_slice(&output.script_pubkey);
        }

        // Locktime
        tx.extend_from_slice(&self.locktime.to_le_bytes());

        tx
    }

    /// Calculate fees per participant.
    fn calculate_fees(&self, total_fee: u64) -> Result<Vec<u64>> {
        let n = self.participants.len();
        if n == 0 {
            return Err(CoinJoinError::NoParticipants);
        }

        match self.fee_strategy {
            FeeStrategy::Equal => {
                let per_participant = total_fee / n as u64;
                let remainder = total_fee % n as u64;
                let mut fees: Vec<u64> = vec![per_participant; n];
                // First participant pays remainder
                fees[0] += remainder;
                Ok(fees)
            }
            FeeStrategy::Proportional => {
                let total_input: u64 = self.participants.iter().map(|p| p.total_input()).sum();
                if total_input == 0 {
                    return Err(CoinJoinError::FeeError("No inputs".into()));
                }
                let fees: Vec<u64> = self
                    .participants
                    .iter()
                    .map(|p| (p.total_input() as f64 / total_input as f64 * total_fee as f64) as u64)
                    .collect();
                Ok(fees)
            }
            FeeStrategy::SinglePayer(idx) => {
                if idx >= n {
                    return Err(CoinJoinError::FeeError("Invalid payer index".into()));
                }
                let mut fees = vec![0u64; n];
                fees[idx] = total_fee;
                Ok(fees)
            }
        }
    }

    /// Estimate transaction size in vBytes.
    fn estimate_tx_size(&self) -> usize {
        let input_count: usize = self.participants.iter().map(|p| p.inputs.len()).sum();
        let output_count = self.participants.len() * 2; // output + change

        // Rough estimate: 10 + 68*inputs + 34*outputs (for P2WPKH)
        10 + 68 * input_count + 34 * output_count
    }

    /// Generate deterministic shuffle seed.
    fn generate_shuffle_seed(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for participant in &self.participants {
            hasher.update(participant.id.as_bytes());
            for input in &participant.inputs {
                hasher.update(input.txid);
                hasher.update(input.vout.to_le_bytes());
            }
        }
        let result = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&result);
        seed
    }
}

impl Default for PsbtCoinJoinBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Combine multiple participant-signed PSBTs into one.
///
/// All PSBTs must have the same unsigned transaction.
/// This merges signatures from all participants.
pub fn combine_participant_psbts(psbts: &[Psbt]) -> Result<Psbt> {
    if psbts.is_empty() {
        return Err(CoinJoinError::InvalidPsbt("No PSBTs to combine".into()));
    }

    Psbt::combine(psbts).map_err(|e| match e {
        PsbtError::TransactionMismatch => {
            CoinJoinError::InvalidPsbt("PSBTs have different transactions".into())
        }
        PsbtError::IncompatiblePsbts => {
            CoinJoinError::InvalidPsbt("PSBTs are incompatible".into())
        }
        _ => CoinJoinError::InvalidPsbt(e.to_string()),
    })
}

/// Finalize a CoinJoin PSBT after all signatures are collected.
///
/// Validates that all inputs are signed before finalization.
pub fn finalize_coinjoin_psbt(psbt: &mut Psbt) -> Result<Vec<u8>> {
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

/// Shuffle a vector deterministically using a seed.
fn shuffle_with_seed<T: Clone>(items: &[T], seed: &[u8; 32]) -> Vec<T> {
    if items.is_empty() {
        return Vec::new();
    }

    let mut result: Vec<(T, u64)> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(i.to_le_bytes());
            let hash = hasher.finalize();
            let sort_key = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            (item.clone(), sort_key)
        })
        .collect();

    result.sort_by_key(|(_, key)| *key);
    result.into_iter().map(|(item, _)| item).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_builder_creation() {
        let builder = PsbtCoinJoinBuilder::new();
        assert_eq!(builder.participant_count(), 0);
        assert_eq!(builder.min_participants, 2);
    }

    #[test]
    fn test_add_participant() {
        let mut builder = PsbtCoinJoinBuilder::new();
        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00],
        );
        assert_eq!(builder.participant_count(), 1);
    }

    #[test]
    fn test_build_psbt() {
        let mut builder = PsbtCoinJoinBuilder::new();

        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00],
        );
        builder.add_participant_simple(
            "bob",
            vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00],
        );
        builder.set_output_amount(50_000);
        builder.set_fee_rate(1.0);

        let psbt = builder.build_psbt().unwrap();

        assert_eq!(psbt.input_count(), 2);
        assert_eq!(psbt.output_count(), 2);
    }

    #[test]
    fn test_insufficient_funds() {
        let mut builder = PsbtCoinJoinBuilder::new();

        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 10_000)],
            vec![0x00, 0x14],
        );
        builder.add_participant_simple(
            "bob",
            vec![InputRef::from_outpoint([2u8; 32], 0, 10_000)],
            vec![0x00, 0x14],
        );
        builder.set_output_amount(50_000);

        let result = builder.build_psbt();
        assert!(matches!(result, Err(CoinJoinError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_combine_empty_fails() {
        let result = combine_participant_psbts(&[]);
        assert!(matches!(result, Err(CoinJoinError::InvalidPsbt(_))));
    }
}
