//! CoinJoin transaction builder.

use crate::error::{CoinJoinError, Result};
use crate::types::{FeeStrategy, InputRef, OutputDef, Participant};
use sha2::{Digest, Sha256};

/// CoinJoin transaction builder.
///
/// Builds CoinJoin transactions with equal output amounts
/// and shuffled inputs/outputs for privacy.
pub struct CoinJoinBuilder {
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
}

impl CoinJoinBuilder {
    /// Create a new CoinJoin builder.
    pub fn new() -> Self {
        Self {
            participants: Vec::new(),
            output_amount: None,
            fee_rate: 1.0,
            fee_strategy: FeeStrategy::Equal,
            min_participants: 2,
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

    /// Build the CoinJoin transaction.
    pub fn build(&self) -> Result<CoinJoinTransaction> {
        // Validate
        if self.participants.len() < self.min_participants {
            return Err(CoinJoinError::NoParticipants);
        }

        let output_amount = self
            .output_amount
            .ok_or_else(|| CoinJoinError::InvalidAmount("Output amount not set".into()))?;

        // Calculate total inputs and fees
        let _total_inputs: u64 = self.participants.iter().map(|p| p.total_input()).sum();
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

        // Collect all inputs
        let mut inputs: Vec<(InputRef, usize)> = Vec::new();
        for (idx, participant) in self.participants.iter().enumerate() {
            for input in &participant.inputs {
                inputs.push((input.clone(), idx));
            }
        }

        // Create equal outputs
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
        let shuffled_inputs = shuffle_with_seed(&inputs, &self.generate_shuffle_seed());
        let shuffled_outputs = shuffle_with_seed(&outputs, &self.generate_shuffle_seed());

        Ok(CoinJoinTransaction {
            inputs: shuffled_inputs.into_iter().map(|(i, _)| i).collect(),
            outputs: shuffled_outputs.into_iter().map(|(o, _)| o).collect(),
            change_outputs: change_outputs.into_iter().map(|(o, _)| o).collect(),
            participant_count: self.participants.len(),
            output_amount,
            total_fee,
        })
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

impl Default for CoinJoinBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Built CoinJoin transaction.
#[derive(Debug, Clone)]
pub struct CoinJoinTransaction {
    /// Shuffled inputs
    pub inputs: Vec<InputRef>,
    /// Equal amount outputs (shuffled)
    pub outputs: Vec<OutputDef>,
    /// Change outputs
    pub change_outputs: Vec<OutputDef>,
    /// Number of participants
    pub participant_count: usize,
    /// Equal output amount
    pub output_amount: u64,
    /// Total fee
    pub total_fee: u64,
}

impl CoinJoinTransaction {
    /// Total input amount.
    pub fn total_input(&self) -> u64 {
        self.inputs.iter().map(|i| i.amount).sum()
    }

    /// Total output amount (excluding change).
    pub fn total_output(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }

    /// Total change amount.
    pub fn total_change(&self) -> u64 {
        self.change_outputs.iter().map(|o| o.amount).sum()
    }

    /// Verify all main outputs are equal.
    pub fn verify_equal_outputs(&self) -> bool {
        self.outputs.iter().all(|o| o.amount == self.output_amount)
    }

    /// Get all outputs (main + change).
    pub fn all_outputs(&self) -> Vec<&OutputDef> {
        self.outputs
            .iter()
            .chain(self.change_outputs.iter())
            .collect()
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
    fn test_builder_creation() {
        let builder = CoinJoinBuilder::new();
        assert_eq!(builder.participants.len(), 0);
        assert_eq!(builder.min_participants, 2);
    }

    #[test]
    fn test_add_participant() {
        let mut builder = CoinJoinBuilder::new();
        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14],
        );
        assert_eq!(builder.participants.len(), 1);
    }

    #[test]
    fn test_build_coinjoin() {
        let mut builder = CoinJoinBuilder::new();

        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x01],
        );
        builder.add_participant_simple(
            "bob",
            vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x02],
        );
        builder.set_output_amount(50_000);
        builder.set_fee_rate(1.0);

        let tx = builder.build().unwrap();

        assert_eq!(tx.participant_count, 2);
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        assert!(tx.verify_equal_outputs());
    }

    #[test]
    fn test_insufficient_funds() {
        let mut builder = CoinJoinBuilder::new();

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

        let result = builder.build();
        assert!(matches!(result, Err(CoinJoinError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_fee_strategies() {
        let mut builder = CoinJoinBuilder::new();
        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14],
        );
        builder.add_participant_simple(
            "bob",
            vec![InputRef::from_outpoint([2u8; 32], 0, 200_000)],
            vec![0x00, 0x14],
        );

        // Equal
        let fees = builder.calculate_fees(1000).unwrap();
        assert_eq!(fees[0], 500);
        assert_eq!(fees[1], 500);

        // Proportional
        builder.set_fee_strategy(FeeStrategy::Proportional);
        let fees = builder.calculate_fees(1000).unwrap();
        assert!(fees[1] > fees[0]); // Bob has more input

        // Single payer
        builder.set_fee_strategy(FeeStrategy::SinglePayer(1));
        let fees = builder.calculate_fees(1000).unwrap();
        assert_eq!(fees[0], 0);
        assert_eq!(fees[1], 1000);
    }

    #[test]
    fn test_shuffle_deterministic() {
        let items = vec![1, 2, 3, 4, 5];
        let seed = [0u8; 32];

        let shuffled1 = shuffle_with_seed(&items, &seed);
        let shuffled2 = shuffle_with_seed(&items, &seed);

        assert_eq!(shuffled1, shuffled2);
    }
}
