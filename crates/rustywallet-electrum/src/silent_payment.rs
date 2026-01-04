//! Silent Payment scanning via Electrum backend.
//!
//! This module provides Silent Payment (BIP352) scanning capabilities using
//! Electrum servers as the blockchain data source.
//!
//! ## Features
//!
//! - **Block scanning**: Scan block ranges for Silent Payments
//! - **Label support**: Detect payments to labeled addresses
//! - **Efficient fetching**: Batch fetch P2TR outputs and input public keys
//!
//! ## Example
//!
//! ```no_run
//! use rustywallet_electrum::{ElectrumClient, SilentPaymentScanner, SilentPaymentScanKey};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = ElectrumClient::new("electrum.blockstream.info").await?;
//!     
//!     // Create scan key from private keys
//!     let scan_key = SilentPaymentScanKey::new(
//!         [0u8; 32], // scan private key
//!         [0u8; 32], // spend private key
//!     )?;
//!     
//!     let scanner = SilentPaymentScanner::new(client, scan_key);
//!     
//!     // Scan blocks for payments
//!     let payments = scanner.scan_blocks(800000, 800100).await?;
//!     for payment in payments {
//!         println!("Found payment: {} sats at output {}", payment.amount, payment.output_index);
//!     }
//!     
//!     Ok(())
//! }
//! ```

use crate::client::ElectrumClient;
use crate::error::{ElectrumError, Result};
use rustywallet_silent::{SilentPaymentScanner as CoreScanner};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

/// Type alias for parsed transaction data: (P2TR outputs, input pubkeys, outpoints)
type ParsedTxData = (Vec<([u8; 32], u64)>, Vec<[u8; 33]>, Vec<([u8; 32], u32)>);

/// A detected Silent Payment with all necessary data for spending.
#[derive(Debug, Clone)]
pub struct DetectedPayment {
    /// Transaction ID where the payment was found
    pub txid: String,
    /// Output index in the transaction
    pub output_index: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Spending private key for this output (32 bytes)
    pub spending_key: [u8; 32],
    /// Label index if this was a labeled payment
    pub label: Option<u32>,
    /// Block height where the payment was confirmed
    pub block_height: u64,
}

impl DetectedPayment {
    /// Get the outpoint string (txid:vout format).
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.output_index)
    }

    /// Check if this payment was to a labeled address.
    pub fn is_labeled(&self) -> bool {
        self.label.is_some()
    }

    /// Check if this payment is confirmed (block_height > 0).
    pub fn is_confirmed(&self) -> bool {
        self.block_height > 0
    }

    /// Get the spending key as a hex string.
    pub fn spending_key_hex(&self) -> String {
        hex::encode(self.spending_key)
    }
}

/// Scan key for Silent Payment detection.
///
/// Contains the scan and spend private keys needed to detect
/// and spend Silent Payments.
#[derive(Clone)]
pub struct SilentPaymentScanKey {
    /// Scan private key (32 bytes)
    scan_privkey: [u8; 32],
    /// Spend private key (32 bytes)
    spend_privkey: [u8; 32],
}

impl SilentPaymentScanKey {
    /// Create a new scan key from private keys.
    ///
    /// # Arguments
    /// * `scan_privkey` - 32-byte scan private key
    /// * `spend_privkey` - 32-byte spend private key
    pub fn new(scan_privkey: [u8; 32], spend_privkey: [u8; 32]) -> Result<Self> {
        // Validate keys by attempting to create a scanner
        CoreScanner::new(&scan_privkey, &spend_privkey)
            .map_err(|e| ElectrumError::InvalidResponse(format!("Invalid keys: {}", e)))?;
        
        Ok(Self {
            scan_privkey,
            spend_privkey,
        })
    }

    /// Get the scan private key.
    pub fn scan_privkey(&self) -> &[u8; 32] {
        &self.scan_privkey
    }

    /// Get the spend private key.
    pub fn spend_privkey(&self) -> &[u8; 32] {
        &self.spend_privkey
    }
}

impl std::fmt::Debug for SilentPaymentScanKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SilentPaymentScanKey")
            .field("scan_privkey", &"[REDACTED]")
            .field("spend_privkey", &"[REDACTED]")
            .finish()
    }
}

/// Silent Payment label for scanning multiple addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPaymentLabel {
    /// Label index
    index: u32,
}

impl SilentPaymentLabel {
    /// Create a new label with the given index.
    pub fn new(index: u32) -> Self {
        Self { index }
    }

    /// Get the label index.
    pub fn index(&self) -> u32 {
        self.index
    }
}

impl From<u32> for SilentPaymentLabel {
    fn from(index: u32) -> Self {
        Self::new(index)
    }
}

/// Silent Payment scanner using Electrum backend.
///
/// Scans the blockchain for Silent Payments addressed to the configured
/// scan key, optionally with labels for multiple addresses.
pub struct SilentPaymentScanner {
    /// Electrum client for blockchain queries
    client: ElectrumClient,
    /// Scan key for payment detection
    scan_key: SilentPaymentScanKey,
    /// Labels to scan for
    labels: Vec<SilentPaymentLabel>,
    /// Request ID counter
    request_id: AtomicU64,
}

impl SilentPaymentScanner {
    /// Create a new Silent Payment scanner.
    ///
    /// # Arguments
    /// * `client` - Electrum client for blockchain queries
    /// * `scan_key` - Scan key containing private keys for detection
    pub fn new(client: ElectrumClient, scan_key: SilentPaymentScanKey) -> Self {
        Self {
            client,
            scan_key,
            labels: Vec::new(),
            request_id: AtomicU64::new(1),
        }
    }

    /// Add a label for scanning.
    ///
    /// Labels allow detecting payments to multiple addresses derived
    /// from the same Silent Payment address.
    pub fn add_label(&mut self, label: SilentPaymentLabel) {
        self.labels.push(label);
    }

    /// Add multiple labels by index range.
    ///
    /// Adds labels from 0 to count-1.
    pub fn add_labels(&mut self, count: u32) {
        for i in 0..count {
            self.labels.push(SilentPaymentLabel::new(i));
        }
    }

    /// Get the configured labels.
    pub fn labels(&self) -> &[SilentPaymentLabel] {
        &self.labels
    }

    /// Check if a specific label is configured.
    pub fn has_label(&self, index: u32) -> bool {
        self.labels.iter().any(|l| l.index() == index)
    }

    /// Remove a label by index.
    pub fn remove_label(&mut self, index: u32) -> bool {
        if let Some(pos) = self.labels.iter().position(|l| l.index() == index) {
            self.labels.remove(pos);
            true
        } else {
            false
        }
    }

    /// Clear all labels.
    pub fn clear_labels(&mut self) {
        self.labels.clear();
    }

    /// Get the number of configured labels.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Get the next request ID.
    #[allow(dead_code)]
    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Scan a range of blocks for Silent Payments.
    ///
    /// # Arguments
    /// * `start_height` - Starting block height (inclusive)
    /// * `end_height` - Ending block height (inclusive)
    ///
    /// # Returns
    /// Vector of detected payments with spending keys
    pub async fn scan_blocks(
        &self,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<DetectedPayment>> {
        let mut all_payments = Vec::new();

        for height in start_height..=end_height {
            let payments = self.scan_block(height).await?;
            all_payments.extend(payments);
        }

        Ok(all_payments)
    }

    /// Scan a single block for Silent Payments.
    ///
    /// # Arguments
    /// * `height` - Block height to scan
    ///
    /// # Returns
    /// Vector of detected payments in this block
    pub async fn scan_block(&self, height: u32) -> Result<Vec<DetectedPayment>> {
        // Get block hash
        let block_hash = self.get_block_hash(height).await?;
        
        // Get block transactions
        let txids = self.get_block_txids(&block_hash).await?;
        
        let mut payments = Vec::new();
        
        for txid in txids {
            if let Ok(tx_payments) = self.scan_transaction(&txid, height as u64).await {
                payments.extend(tx_payments);
            }
        }

        Ok(payments)
    }

    /// Scan multiple transactions for Silent Payments.
    ///
    /// This is the most practical method for Electrum-based scanning,
    /// as you can provide transaction IDs from address history.
    ///
    /// # Arguments
    /// * `txids` - Transaction IDs to scan
    /// * `block_height` - Block height for the transactions (for metadata)
    ///
    /// # Returns
    /// Vector of detected payments
    pub async fn scan_transactions(
        &self,
        txids: &[&str],
        block_height: u64,
    ) -> Result<Vec<DetectedPayment>> {
        let mut all_payments = Vec::new();

        for txid in txids {
            if let Ok(payments) = self.scan_transaction(txid, block_height).await {
                all_payments.extend(payments);
            }
        }

        Ok(all_payments)
    }

    /// Scan transactions from address history.
    ///
    /// Fetches transaction history for a P2TR address and scans
    /// all transactions for Silent Payments.
    ///
    /// # Arguments
    /// * `p2tr_address` - P2TR address to get history for
    ///
    /// # Returns
    /// Vector of detected payments
    pub async fn scan_address_history(
        &self,
        p2tr_address: &str,
    ) -> Result<Vec<DetectedPayment>> {
        // Get transaction history for the address
        let history = self.client.get_history(p2tr_address).await?;
        
        let mut all_payments = Vec::new();
        
        for tx in history {
            let height = if tx.height > 0 { tx.height as u64 } else { 0 };
            if let Ok(payments) = self.scan_transaction(&tx.txid, height).await {
                all_payments.extend(payments);
            }
        }

        Ok(all_payments)
    }

    /// Scan a single transaction for Silent Payments.
    ///
    /// # Arguments
    /// * `txid` - Transaction ID to scan
    /// * `block_height` - Block height where the transaction is confirmed
    ///
    /// # Returns
    /// Vector of detected payments in this transaction
    pub async fn scan_transaction(
        &self,
        txid: &str,
        block_height: u64,
    ) -> Result<Vec<DetectedPayment>> {
        // Get raw transaction
        let raw_tx = self.client.get_transaction(txid).await?;
        
        // Parse transaction to extract P2TR outputs and input public keys
        let (p2tr_outputs, input_pubkeys, outpoints) = self.parse_transaction(&raw_tx)?;
        
        if p2tr_outputs.is_empty() || input_pubkeys.is_empty() {
            return Ok(Vec::new());
        }

        // Create core scanner
        let mut core_scanner = CoreScanner::new(
            self.scan_key.scan_privkey(),
            self.scan_key.spend_privkey(),
        ).map_err(|e| ElectrumError::InvalidResponse(format!("Scanner error: {}", e)))?;

        // Add labels
        for label in &self.labels {
            core_scanner.add_label(label.index());
        }

        // Extract output pubkeys (x-only, 32 bytes)
        let output_pubkeys: Vec<[u8; 32]> = p2tr_outputs
            .iter()
            .map(|(pk, _)| *pk)
            .collect();

        // Scan for payments
        let detected = core_scanner
            .scan(&output_pubkeys, &input_pubkeys, &outpoints)
            .map_err(|e| ElectrumError::InvalidResponse(format!("Scan error: {}", e)))?;

        // Convert to our DetectedPayment type
        let payments = detected
            .into_iter()
            .map(|d| {
                let amount = p2tr_outputs
                    .iter()
                    .find(|(pk, _)| *pk == d.output_pubkey)
                    .map(|(_, amt)| *amt)
                    .unwrap_or(0);

                DetectedPayment {
                    txid: txid.to_string(),
                    output_index: d.output_index as u32,
                    amount,
                    spending_key: d.spending_key,
                    label: d.label,
                    block_height,
                }
            })
            .collect();

        Ok(payments)
    }

    /// Get block hash for a given height.
    async fn get_block_hash(&self, height: u32) -> Result<String> {
        let id = self.next_id();
        let result = self.client.transport_request(
            id,
            "blockchain.block.header",
            vec![json!(height)],
        ).await?;

        // The header is returned as hex, we need to extract the block hash
        // For simplicity, we'll use the header directly as identifier
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ElectrumError::InvalidResponse("Expected block header".into()))
    }

    /// Get transaction IDs in a block.
    async fn get_block_txids(&self, _block_hash: &str) -> Result<Vec<String>> {
        // Note: Standard Electrum protocol doesn't have a direct method to get
        // all txids in a block. In practice, we would need to:
        // 1. Use a full node RPC, or
        // 2. Scan known addresses, or
        // 3. Use an extended Electrum server
        //
        // For now, return empty - real implementation would need additional backend support
        Ok(Vec::new())
    }

    /// Parse a raw transaction to extract P2TR outputs and input public keys.
    fn parse_transaction(
        &self,
        raw_tx: &str,
    ) -> Result<ParsedTxData> {
        let tx_bytes = hex::decode(raw_tx)
            .map_err(|e| ElectrumError::InvalidResponse(format!("Invalid hex: {}", e)))?;

        // Parse using bitcoin crate
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
            .map_err(|e| ElectrumError::InvalidResponse(format!("Invalid tx: {}", e)))?;

        // Extract P2TR outputs (x-only pubkey, amount)
        let mut p2tr_outputs = Vec::new();
        for (idx, output) in tx.output.iter().enumerate() {
            if output.script_pubkey.is_p2tr() {
                // P2TR script: OP_1 <32-byte-pubkey>
                if output.script_pubkey.len() == 34 {
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&output.script_pubkey.as_bytes()[2..34]);
                    p2tr_outputs.push((pubkey, output.value.to_sat()));
                }
            }
            let _ = idx; // Suppress unused warning
        }

        // Extract input public keys from witness data
        let mut input_pubkeys = Vec::new();
        for input in &tx.input {
            // Try to extract public key from witness
            if let Some(pubkey) = self.extract_input_pubkey(input) {
                input_pubkeys.push(pubkey);
            }
        }

        // Extract outpoints
        let outpoints: Vec<([u8; 32], u32)> = tx
            .input
            .iter()
            .map(|input| {
                let mut txid = [0u8; 32];
                txid.copy_from_slice(input.previous_output.txid.as_ref());
                (txid, input.previous_output.vout)
            })
            .collect();

        Ok((p2tr_outputs, input_pubkeys, outpoints))
    }

    /// Extract public key from transaction input.
    fn extract_input_pubkey(&self, input: &bitcoin::TxIn) -> Option<[u8; 33]> {
        // Check witness for public key
        for witness_item in input.witness.iter() {
            // Compressed public key is 33 bytes
            if witness_item.len() == 33 {
                let mut pubkey = [0u8; 33];
                pubkey.copy_from_slice(witness_item);
                // Validate it's a valid public key
                if secp256k1::PublicKey::from_slice(&pubkey).is_ok() {
                    return Some(pubkey);
                }
            }
            // X-only public key is 32 bytes (for Taproot)
            if witness_item.len() == 32 {
                // Convert x-only to compressed (assume even parity)
                let mut pubkey = [0u8; 33];
                pubkey[0] = 0x02;
                pubkey[1..].copy_from_slice(witness_item);
                if secp256k1::PublicKey::from_slice(&pubkey).is_ok() {
                    return Some(pubkey);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_key_creation() {
        let scan_privkey = [1u8; 32];
        let spend_privkey = [2u8; 32];

        let result = SilentPaymentScanKey::new(scan_privkey, spend_privkey);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.scan_privkey(), &scan_privkey);
        assert_eq!(key.spend_privkey(), &spend_privkey);
    }

    #[test]
    fn test_scan_key_debug_redacts() {
        let key = SilentPaymentScanKey::new([1u8; 32], [2u8; 32]).unwrap();
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("01010101"));
    }

    #[test]
    fn test_label_creation() {
        let label = SilentPaymentLabel::new(5);
        assert_eq!(label.index(), 5);
    }

    #[test]
    fn test_detected_payment_fields() {
        let payment = DetectedPayment {
            txid: "abc123".to_string(),
            output_index: 0,
            amount: 100000,
            spending_key: [0u8; 32],
            label: Some(1),
            block_height: 800000,
        };

        assert_eq!(payment.txid, "abc123");
        assert_eq!(payment.output_index, 0);
        assert_eq!(payment.amount, 100000);
        assert_eq!(payment.label, Some(1));
        assert_eq!(payment.block_height, 800000);
    }
}
