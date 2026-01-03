//! Common types for CoinJoin operations.

use serde::{Deserialize, Serialize};

/// A transaction input reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InputRef {
    /// Transaction ID (32 bytes)
    pub txid: [u8; 32],
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Script pubkey (for verification)
    pub script_pubkey: Vec<u8>,
}

impl InputRef {
    /// Create a new input reference.
    pub fn new(txid: [u8; 32], vout: u32, amount: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            txid,
            vout,
            amount,
            script_pubkey,
        }
    }

    /// Create from outpoint.
    pub fn from_outpoint(txid: [u8; 32], vout: u32, amount: u64) -> Self {
        Self {
            txid,
            vout,
            amount,
            script_pubkey: Vec::new(),
        }
    }
}

/// A transaction output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputDef {
    /// Amount in satoshis
    pub amount: u64,
    /// Script pubkey
    pub script_pubkey: Vec<u8>,
    /// Address (for display)
    pub address: Option<String>,
}

impl OutputDef {
    /// Create a new output definition.
    pub fn new(amount: u64, script_pubkey: Vec<u8>) -> Self {
        Self {
            amount,
            script_pubkey,
            address: None,
        }
    }

    /// Create with address.
    pub fn with_address(amount: u64, script_pubkey: Vec<u8>, address: String) -> Self {
        Self {
            amount,
            script_pubkey,
            address: Some(address),
        }
    }
}

/// CoinJoin participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Participant ID
    pub id: String,
    /// Inputs contributed
    pub inputs: Vec<InputRef>,
    /// Output address (script pubkey)
    pub output_script: Vec<u8>,
    /// Change address (optional)
    pub change_script: Option<Vec<u8>>,
}

impl Participant {
    /// Create a new participant.
    pub fn new(id: impl Into<String>, inputs: Vec<InputRef>, output_script: Vec<u8>) -> Self {
        Self {
            id: id.into(),
            inputs,
            output_script,
            change_script: None,
        }
    }

    /// Set change address.
    pub fn with_change(mut self, change_script: Vec<u8>) -> Self {
        self.change_script = Some(change_script);
        self
    }

    /// Total input amount.
    pub fn total_input(&self) -> u64 {
        self.inputs.iter().map(|i| i.amount).sum()
    }
}

/// Fee distribution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FeeStrategy {
    /// Split fee equally among participants
    #[default]
    Equal,
    /// Fee proportional to input amounts
    Proportional,
    /// Single participant pays all fees
    SinglePayer(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_ref() {
        let input = InputRef::new([1u8; 32], 0, 100_000, vec![0x00, 0x14]);
        assert_eq!(input.amount, 100_000);
        assert_eq!(input.vout, 0);
    }

    #[test]
    fn test_output_def() {
        let output = OutputDef::with_address(50_000, vec![0x00, 0x14], "bc1q...".into());
        assert_eq!(output.amount, 50_000);
        assert!(output.address.is_some());
    }

    #[test]
    fn test_participant() {
        let inputs = vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)];
        let participant = Participant::new("alice", inputs, vec![0x00, 0x14]);
        assert_eq!(participant.total_input(), 100_000);
    }
}
