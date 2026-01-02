//! Replace-By-Fee (RBF) support
//!
//! BIP125 RBF allows replacing unconfirmed transactions with higher fee versions.

use crate::types::{Transaction, TxInput};
use crate::error::{TxError, Result};

/// RBF sequence number constants
pub mod sequence {
    /// Maximum sequence (RBF disabled, final)
    pub const FINAL: u32 = 0xFFFFFFFF;
    /// RBF enabled (BIP125)
    pub const RBF_ENABLED: u32 = 0xFFFFFFFD;
    /// Default for RBF transactions
    pub const DEFAULT_RBF: u32 = 0xFFFFFFFE - 1;
}

/// Check if a transaction is RBF-enabled (BIP125)
pub fn is_rbf_enabled(tx: &Transaction) -> bool {
    tx.inputs.iter().any(|input| input.sequence < sequence::FINAL - 1)
}

/// Enable RBF on all inputs of a transaction
pub fn enable_rbf(tx: &mut Transaction) {
    for input in &mut tx.inputs {
        if input.sequence == sequence::FINAL {
            input.sequence = sequence::RBF_ENABLED;
        }
    }
}

/// Disable RBF on all inputs (make final)
pub fn disable_rbf(tx: &mut Transaction) {
    for input in &mut tx.inputs {
        input.sequence = sequence::FINAL;
    }
}

/// Create a replacement transaction with higher fee
/// 
/// # Arguments
/// * `original` - The original transaction to replace
/// * `new_fee_rate` - New fee rate in sat/vB (must be higher than original)
/// * `change_output_index` - Index of the change output to reduce
pub fn create_replacement(
    original: &Transaction,
    new_fee_rate: u64,
    change_output_index: usize,
) -> Result<Transaction> {
    if !is_rbf_enabled(original) {
        return Err(TxError::RbfNotEnabled);
    }

    if change_output_index >= original.outputs.len() {
        return Err(TxError::InvalidOutputIndex(change_output_index));
    }

    let mut replacement = original.clone();
    
    // Calculate current and new fees
    let current_vsize = original.vsize();
    let current_fee = calculate_current_fee(original);
    let new_fee = (current_vsize as u64) * new_fee_rate;
    
    if new_fee <= current_fee {
        return Err(TxError::RbfFeeTooLow {
            current: current_fee,
            required: current_fee + 1,
        });
    }

    let fee_increase = new_fee - current_fee;
    
    // Reduce change output
    if replacement.outputs[change_output_index].value < fee_increase {
        return Err(TxError::InsufficientFunds {
            needed: fee_increase,
            available: replacement.outputs[change_output_index].value,
        });
    }
    
    replacement.outputs[change_output_index].value -= fee_increase;
    
    // Decrement sequence numbers to signal replacement
    for input in &mut replacement.inputs {
        if input.sequence > 0 {
            input.sequence -= 1;
        }
    }
    
    // Clear signatures (need to re-sign)
    for input in &mut replacement.inputs {
        input.script_sig.clear();
        input.witness.clear();
    }
    
    Ok(replacement)
}

/// Bump fee by a specific amount
pub fn bump_fee(
    tx: &mut Transaction,
    fee_increase: u64,
    change_output_index: usize,
) -> Result<()> {
    if !is_rbf_enabled(tx) {
        return Err(TxError::RbfNotEnabled);
    }

    if change_output_index >= tx.outputs.len() {
        return Err(TxError::InvalidOutputIndex(change_output_index));
    }

    if tx.outputs[change_output_index].value < fee_increase {
        return Err(TxError::InsufficientFunds {
            needed: fee_increase,
            available: tx.outputs[change_output_index].value,
        });
    }

    tx.outputs[change_output_index].value -= fee_increase;
    
    // Decrement sequence
    for input in &mut tx.inputs {
        if input.sequence > 0 {
            input.sequence -= 1;
        }
    }

    // Clear signatures
    for input in &mut tx.inputs {
        input.script_sig.clear();
        input.witness.clear();
    }

    Ok(())
}

/// Calculate current fee (input total - output total)
/// Note: This requires knowing input values, which we estimate here
fn calculate_current_fee(tx: &Transaction) -> u64 {
    // Without input values, we estimate based on typical fee rates
    // In practice, caller should track this
    let vsize = tx.vsize() as u64;
    vsize * 10 // Assume 10 sat/vB as baseline
}

/// RBF transaction builder helper
pub struct RbfBuilder {
    sequence: u32,
}

impl Default for RbfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RbfBuilder {
    /// Create new RBF builder with default sequence
    pub fn new() -> Self {
        Self {
            sequence: sequence::RBF_ENABLED,
        }
    }

    /// Set custom sequence number
    pub fn with_sequence(mut self, seq: u32) -> Self {
        self.sequence = seq;
        self
    }

    /// Create an RBF-enabled input
    pub fn create_input(&self, txid: [u8; 32], vout: u32) -> TxInput {
        let mut input = TxInput::new(txid, vout);
        input.sequence = self.sequence;
        input
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TxOutput;

    fn create_test_tx() -> Transaction {
        let mut tx = Transaction::new();
        let mut input = TxInput::new([0u8; 32], 0);
        input.sequence = sequence::RBF_ENABLED;
        tx.inputs.push(input);
        tx.outputs.push(TxOutput::new(50000, vec![0x00, 0x14]));
        tx.outputs.push(TxOutput::new(40000, vec![0x00, 0x14])); // change
        tx
    }

    #[test]
    fn test_is_rbf_enabled() {
        let mut tx = create_test_tx();
        assert!(is_rbf_enabled(&tx));
        
        tx.inputs[0].sequence = sequence::FINAL;
        assert!(!is_rbf_enabled(&tx));
    }

    #[test]
    fn test_enable_disable_rbf() {
        let mut tx = Transaction::new();
        tx.inputs.push(TxInput::new([0u8; 32], 0));
        
        assert!(!is_rbf_enabled(&tx)); // Default is FINAL
        
        enable_rbf(&mut tx);
        assert!(is_rbf_enabled(&tx));
        
        disable_rbf(&mut tx);
        assert!(!is_rbf_enabled(&tx));
    }

    #[test]
    fn test_bump_fee() {
        let mut tx = create_test_tx();
        let original_change = tx.outputs[1].value;
        
        bump_fee(&mut tx, 1000, 1).unwrap();
        
        assert_eq!(tx.outputs[1].value, original_change - 1000);
    }

    #[test]
    fn test_rbf_builder() {
        let builder = RbfBuilder::new();
        let input = builder.create_input([1u8; 32], 0);
        
        assert_eq!(input.sequence, sequence::RBF_ENABLED);
    }
}
