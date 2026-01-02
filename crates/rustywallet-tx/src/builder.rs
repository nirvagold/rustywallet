//! Transaction builder.

use crate::error::{TxError, Result};
use crate::types::{Transaction, TxInput, TxOutput, Utxo};
use crate::fee::{estimate_fee, is_dust, DUST_THRESHOLD_P2WPKH};
use crate::coin_selection::select_coins;

/// Transaction builder for creating unsigned transactions.
#[derive(Debug, Clone)]
pub struct TxBuilder {
    inputs: Vec<(Utxo, Option<[u8; 33]>)>, // UTXO + optional pubkey for signing
    outputs: Vec<TxOutput>,
    change_address: Option<String>,
    fee_rate: u64,
    version: i32,
    locktime: u32,
}

impl Default for TxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TxBuilder {
    /// Create a new transaction builder.
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            change_address: None,
            fee_rate: 1, // 1 sat/vB default
            version: 2,
            locktime: 0,
        }
    }

    /// Add an input from a UTXO.
    pub fn add_input(mut self, utxo: Utxo) -> Self {
        self.inputs.push((utxo, None));
        self
    }

    /// Add an input with the public key for signing.
    pub fn add_input_with_key(mut self, utxo: Utxo, pubkey: [u8; 33]) -> Self {
        self.inputs.push((utxo, Some(pubkey)));
        self
    }

    /// Add an output to a P2PKH address.
    pub fn add_output_p2pkh(mut self, address: &str, value: u64) -> Result<Self> {
        let script = address_to_script(address)?;
        self.outputs.push(TxOutput::new(value, script));
        Ok(self)
    }

    /// Add an output with raw script.
    pub fn add_output(mut self, value: u64, script_pubkey: Vec<u8>) -> Self {
        self.outputs.push(TxOutput::new(value, script_pubkey));
        self
    }

    /// Set the change address.
    pub fn set_change_address(mut self, address: &str) -> Self {
        self.change_address = Some(address.to_string());
        self
    }

    /// Set the fee rate in satoshis per virtual byte.
    pub fn set_fee_rate(mut self, sat_per_vb: u64) -> Self {
        self.fee_rate = sat_per_vb;
        self
    }

    /// Set transaction version.
    pub fn set_version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    /// Set locktime.
    pub fn set_locktime(mut self, locktime: u32) -> Self {
        self.locktime = locktime;
        self
    }

    /// Build the unsigned transaction.
    pub fn build(self) -> Result<UnsignedTx> {
        if self.inputs.is_empty() {
            return Err(TxError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(TxError::NoOutputs);
        }

        // Check for dust outputs
        for output in &self.outputs {
            if is_dust(output.value, true) {
                return Err(TxError::DustOutput(output.value));
            }
        }

        // Calculate totals
        let input_total: u64 = self.inputs.iter().map(|(u, _)| u.value).sum();
        let output_total: u64 = self.outputs.iter().map(|o| o.value).sum();

        // Estimate fee
        let num_outputs = if self.change_address.is_some() {
            self.outputs.len() + 1
        } else {
            self.outputs.len()
        };
        let fee = estimate_fee(self.inputs.len(), num_outputs, self.fee_rate);

        // Check if we have enough
        let needed = output_total.saturating_add(fee);
        if input_total < needed {
            return Err(TxError::InsufficientFunds {
                needed,
                available: input_total,
            });
        }

        // Build transaction
        let mut tx = Transaction {
            version: self.version,
            inputs: Vec::new(),
            outputs: self.outputs.clone(),
            locktime: self.locktime,
        };

        // Add inputs
        let mut input_info = Vec::new();
        for (utxo, pubkey) in &self.inputs {
            let input = TxInput::new(utxo.txid, utxo.vout);
            tx.inputs.push(input);
            input_info.push(InputInfo {
                utxo: utxo.clone(),
                pubkey: *pubkey,
            });
        }

        // Add change output if needed
        let change = input_total - output_total - fee;
        if change > DUST_THRESHOLD_P2WPKH {
            if let Some(addr) = &self.change_address {
                let script = address_to_script(addr)?;
                tx.outputs.push(TxOutput::new(change, script));
            }
        }

        Ok(UnsignedTx {
            tx,
            input_info,
            fee,
        })
    }

    /// Build transaction with automatic coin selection.
    pub fn build_with_coin_selection(
        mut self,
        utxos: &[Utxo],
    ) -> Result<UnsignedTx> {
        let output_total: u64 = self.outputs.iter().map(|o| o.value).sum();
        
        // Select coins
        let (selected, _) = select_coins(utxos, output_total, self.fee_rate)?;
        
        // Add selected UTXOs as inputs
        for utxo in selected {
            self = self.add_input(utxo);
        }
        
        self.build()
    }
}

/// Information about an input for signing.
#[derive(Debug, Clone)]
pub struct InputInfo {
    /// The UTXO being spent
    pub utxo: Utxo,
    /// Public key (if provided)
    pub pubkey: Option<[u8; 33]>,
}

/// An unsigned transaction ready for signing.
#[derive(Debug, Clone)]
pub struct UnsignedTx {
    /// The transaction
    pub tx: Transaction,
    /// Input information for signing
    pub input_info: Vec<InputInfo>,
    /// Calculated fee
    pub fee: u64,
}

impl UnsignedTx {
    /// Get the transaction.
    pub fn transaction(&self) -> &Transaction {
        &self.tx
    }

    /// Get the fee.
    pub fn fee(&self) -> u64 {
        self.fee
    }
}

/// Convert an address string to scriptPubKey.
fn address_to_script(address: &str) -> Result<Vec<u8>> {
    // Try P2PKH (starts with 1 or m/n)
    if address.starts_with('1') || address.starts_with('m') || address.starts_with('n') {
        // Decode base58check
        let decoded = bs58::decode(address)
            .into_vec()
            .map_err(|e| TxError::InvalidAddress(e.to_string()))?;
        
        if decoded.len() != 25 {
            return Err(TxError::InvalidAddress("Invalid P2PKH address length".to_string()));
        }
        
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&decoded[1..21]);
        
        Ok(crate::script::build_p2pkh_script(&pubkey_hash))
    }
    // Try P2WPKH (starts with bc1q or tb1q)
    else if address.starts_with("bc1q") || address.starts_with("tb1q") {
        // Decode bech32
        let (_, data) = bech32_decode(address)
            .map_err(TxError::InvalidAddress)?;
        
        if data.len() != 20 {
            return Err(TxError::InvalidAddress("Invalid P2WPKH address".to_string()));
        }
        
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&data);
        
        Ok(crate::script::build_p2wpkh_script(&pubkey_hash))
    }
    else {
        Err(TxError::InvalidAddress(format!("Unsupported address format: {}", address)))
    }
}

/// Simple bech32 decoder (for P2WPKH only).
fn bech32_decode(address: &str) -> std::result::Result<(String, Vec<u8>), String> {
    let address = address.to_lowercase();
    let pos = address.rfind('1').ok_or("No separator found")?;
    let hrp = &address[..pos];
    let data_part = &address[pos + 1..];
    
    // Decode base32
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut values = Vec::new();
    for c in data_part.chars() {
        let idx = CHARSET.find(c).ok_or("Invalid character")?;
        values.push(idx as u8);
    }
    
    // Skip checksum (last 6 values) and version (first value)
    if values.len() < 7 {
        return Err("Too short".to_string());
    }
    let data_values = &values[1..values.len() - 6];
    
    // Convert from 5-bit to 8-bit
    let mut result = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &v in data_values {
        acc = (acc << 5) | (v as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    
    Ok((hrp.to_string(), result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo(value: u64) -> Utxo {
        Utxo {
            txid: [0u8; 32],
            vout: 0,
            value,
            script_pubkey: vec![0x76, 0xa9, 0x14], // Partial P2PKH
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
        }
    }

    #[test]
    fn test_builder_no_inputs() {
        let result = TxBuilder::new()
            .add_output(50_000, vec![0x00])
            .build();
        assert!(matches!(result, Err(TxError::NoInputs)));
    }

    #[test]
    fn test_builder_no_outputs() {
        let result = TxBuilder::new()
            .add_input(make_utxo(100_000))
            .build();
        assert!(matches!(result, Err(TxError::NoOutputs)));
    }

    #[test]
    fn test_builder_dust_output() {
        let result = TxBuilder::new()
            .add_input(make_utxo(100_000))
            .add_output(100, vec![0x00, 0x14]) // Dust
            .build();
        assert!(matches!(result, Err(TxError::DustOutput(_))));
    }

    #[test]
    fn test_builder_success() {
        let result = TxBuilder::new()
            .add_input(make_utxo(100_000))
            .add_output(50_000, vec![0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac])
            .set_fee_rate(1)
            .build();
        
        assert!(result.is_ok());
        let unsigned = result.unwrap();
        assert_eq!(unsigned.tx.inputs.len(), 1);
        assert_eq!(unsigned.tx.outputs.len(), 1);
    }
}
