//! PayJoin (BIP78) implementation.
//!
//! PayJoin is a privacy technique where the receiver contributes inputs
//! to a transaction, breaking the common-input-ownership heuristic.

use crate::error::{CoinJoinError, Result};
use crate::types::{InputRef, OutputDef};
use serde::{Deserialize, Serialize};

/// PayJoin request from receiver to sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayJoinRequest {
    /// Original PSBT (base64 encoded)
    pub original_psbt: String,
    /// Receiver's additional inputs
    pub receiver_inputs: Vec<InputRef>,
    /// Modified outputs
    pub outputs: Vec<OutputDef>,
    /// Fee contribution from receiver
    pub fee_contribution: u64,
    /// Minimum fee rate (sat/vB)
    pub min_fee_rate: Option<f64>,
}

impl PayJoinRequest {
    /// Create a new PayJoin request.
    pub fn new(original_psbt: String) -> Self {
        Self {
            original_psbt,
            receiver_inputs: Vec::new(),
            outputs: Vec::new(),
            fee_contribution: 0,
            min_fee_rate: None,
        }
    }

    /// Add receiver input.
    pub fn add_input(&mut self, input: InputRef) {
        self.receiver_inputs.push(input);
    }

    /// Set fee contribution.
    pub fn set_fee_contribution(&mut self, amount: u64) {
        self.fee_contribution = amount;
    }

    /// Set minimum fee rate.
    pub fn set_min_fee_rate(&mut self, rate: f64) {
        self.min_fee_rate = Some(rate);
    }

    /// Total receiver input amount.
    pub fn receiver_input_total(&self) -> u64 {
        self.receiver_inputs.iter().map(|i| i.amount).sum()
    }
}

/// PayJoin receiver - creates PayJoin proposals.
pub struct PayJoinReceiver {
    /// Receiver's output script
    output_script: Vec<u8>,
    /// Expected payment amount
    expected_amount: u64,
    /// Available UTXOs
    utxos: Vec<InputRef>,
}

impl PayJoinReceiver {
    /// Create a new PayJoin receiver.
    pub fn new(output_script: Vec<u8>, expected_amount: u64) -> Self {
        Self {
            output_script,
            expected_amount,
            utxos: Vec::new(),
        }
    }

    /// Add available UTXO.
    pub fn add_utxo(&mut self, utxo: InputRef) {
        self.utxos.push(utxo);
    }

    /// Add multiple UTXOs.
    pub fn add_utxos(&mut self, utxos: impl IntoIterator<Item = InputRef>) {
        self.utxos.extend(utxos);
    }

    /// Create PayJoin request from original PSBT.
    ///
    /// The receiver selects inputs to contribute and modifies the transaction.
    pub fn create_request(&self, original_psbt: &str) -> Result<PayJoinRequest> {
        if self.utxos.is_empty() {
            return Err(CoinJoinError::PayJoinError(
                "No UTXOs available for PayJoin".into(),
            ));
        }

        let mut request = PayJoinRequest::new(original_psbt.to_string());

        // Select UTXOs to contribute (simple strategy: use first available)
        // In production, use more sophisticated selection
        let selected = self.select_inputs()?;
        for input in selected {
            request.add_input(input);
        }

        // Receiver's output (payment + contributed inputs)
        let receiver_total = request.receiver_input_total();
        let receiver_output = OutputDef::new(
            self.expected_amount + receiver_total,
            self.output_script.clone(),
        );
        request.outputs.push(receiver_output);

        Ok(request)
    }

    /// Select inputs to contribute.
    fn select_inputs(&self) -> Result<Vec<InputRef>> {
        // Simple selection: contribute one input if available
        if let Some(utxo) = self.utxos.first() {
            Ok(vec![utxo.clone()])
        } else {
            Err(CoinJoinError::PayJoinError("No UTXOs to select".into()))
        }
    }

    /// Verify a PayJoin proposal is valid.
    pub fn verify_proposal(&self, request: &PayJoinRequest) -> Result<()> {
        // Check receiver inputs are from our UTXOs
        for input in &request.receiver_inputs {
            let found = self.utxos.iter().any(|u| u.txid == input.txid && u.vout == input.vout);
            if !found {
                return Err(CoinJoinError::VerificationFailed(
                    "Unknown input in proposal".into(),
                ));
            }
        }

        Ok(())
    }
}

/// PayJoin sender - processes PayJoin requests.
pub struct PayJoinSender {
    /// Sender's UTXOs
    utxos: Vec<InputRef>,
    /// Maximum additional fee willing to pay
    max_additional_fee: u64,
}

impl PayJoinSender {
    /// Create a new PayJoin sender.
    pub fn new() -> Self {
        Self {
            utxos: Vec::new(),
            max_additional_fee: 10_000, // Default 10k sats
        }
    }

    /// Add sender UTXO.
    pub fn add_utxo(&mut self, utxo: InputRef) {
        self.utxos.push(utxo);
    }

    /// Set maximum additional fee.
    pub fn set_max_additional_fee(&mut self, amount: u64) {
        self.max_additional_fee = amount;
    }

    /// Process a PayJoin request.
    ///
    /// Validates the request and creates the final PayJoin PSBT.
    pub fn process_request(&self, request: &PayJoinRequest) -> Result<PayJoinProposal> {
        // Validate request
        self.validate_request(request)?;

        // Create proposal with combined inputs
        let mut all_inputs = Vec::new();

        // Add sender inputs (from original PSBT - simplified)
        all_inputs.extend(self.utxos.clone());

        // Add receiver inputs
        all_inputs.extend(request.receiver_inputs.clone());

        let proposal = PayJoinProposal {
            inputs: all_inputs,
            outputs: request.outputs.clone(),
            original_psbt: request.original_psbt.clone(),
            fee_contribution: request.fee_contribution,
        };

        Ok(proposal)
    }

    /// Validate a PayJoin request.
    fn validate_request(&self, request: &PayJoinRequest) -> Result<()> {
        // Check receiver added inputs
        if request.receiver_inputs.is_empty() {
            return Err(CoinJoinError::PayJoinError(
                "Receiver must contribute at least one input".into(),
            ));
        }

        // Check fee contribution is reasonable
        if request.fee_contribution > self.max_additional_fee {
            return Err(CoinJoinError::PayJoinError(format!(
                "Fee contribution {} exceeds maximum {}",
                request.fee_contribution, self.max_additional_fee
            )));
        }

        Ok(())
    }

    /// Verify the final PayJoin transaction.
    pub fn verify_final(&self, proposal: &PayJoinProposal) -> Result<()> {
        // Verify our inputs are included
        for utxo in &self.utxos {
            let found = proposal
                .inputs
                .iter()
                .any(|i| i.txid == utxo.txid && i.vout == utxo.vout);
            if !found {
                return Err(CoinJoinError::VerificationFailed(
                    "Sender input missing from proposal".into(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for PayJoinSender {
    fn default() -> Self {
        Self::new()
    }
}

/// PayJoin proposal ready for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayJoinProposal {
    /// All inputs (sender + receiver)
    pub inputs: Vec<InputRef>,
    /// All outputs
    pub outputs: Vec<OutputDef>,
    /// Original PSBT for reference
    pub original_psbt: String,
    /// Fee contribution from receiver
    pub fee_contribution: u64,
}

impl PayJoinProposal {
    /// Total input amount.
    pub fn total_input(&self) -> u64 {
        self.inputs.iter().map(|i| i.amount).sum()
    }

    /// Total output amount.
    pub fn total_output(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }

    /// Implied fee.
    pub fn fee(&self) -> u64 {
        self.total_input().saturating_sub(self.total_output())
    }

    /// Number of inputs.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Number of outputs.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payjoin_request() {
        let mut request = PayJoinRequest::new("cHNidP8...".into());
        request.add_input(InputRef::from_outpoint([1u8; 32], 0, 50_000));
        request.set_fee_contribution(1000);

        assert_eq!(request.receiver_input_total(), 50_000);
        assert_eq!(request.fee_contribution, 1000);
    }

    #[test]
    fn test_payjoin_receiver() {
        let mut receiver = PayJoinReceiver::new(vec![0x00, 0x14], 100_000);
        receiver.add_utxo(InputRef::from_outpoint([1u8; 32], 0, 50_000));

        let request = receiver.create_request("cHNidP8...").unwrap();
        assert_eq!(request.receiver_inputs.len(), 1);
    }

    #[test]
    fn test_payjoin_sender() {
        let mut sender = PayJoinSender::new();
        sender.add_utxo(InputRef::from_outpoint([2u8; 32], 0, 100_000));

        let mut request = PayJoinRequest::new("cHNidP8...".into());
        request.add_input(InputRef::from_outpoint([1u8; 32], 0, 50_000));
        request.outputs.push(OutputDef::new(140_000, vec![0x00, 0x14]));

        let proposal = sender.process_request(&request).unwrap();
        assert_eq!(proposal.input_count(), 2);
    }

    #[test]
    fn test_payjoin_proposal() {
        let proposal = PayJoinProposal {
            inputs: vec![
                InputRef::from_outpoint([1u8; 32], 0, 100_000),
                InputRef::from_outpoint([2u8; 32], 0, 50_000),
            ],
            outputs: vec![OutputDef::new(140_000, vec![0x00, 0x14])],
            original_psbt: "cHNidP8...".into(),
            fee_contribution: 1000,
        };

        assert_eq!(proposal.total_input(), 150_000);
        assert_eq!(proposal.total_output(), 140_000);
        assert_eq!(proposal.fee(), 10_000);
    }
}
