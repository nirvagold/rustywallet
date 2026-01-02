//! Recovery result types
//!
//! Types for representing wallet recovery scan results.

use crate::config::ScanPath;
use serde::{Deserialize, Serialize};

/// Complete result of a wallet recovery scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult {
    /// Total balance found (in satoshis)
    pub total_balance: u64,
    /// All addresses with activity
    pub addresses: Vec<FoundAddress>,
    /// All unspent transaction outputs
    pub utxos: Vec<FoundUtxo>,
    /// Scan statistics
    pub stats: ScanStats,
}

impl RecoveryResult {
    /// Create a new empty result
    pub fn new() -> Self {
        Self {
            total_balance: 0,
            addresses: Vec::new(),
            utxos: Vec::new(),
            stats: ScanStats::new(),
        }
    }

    /// Add a found address
    pub fn add_address(&mut self, address: FoundAddress) {
        self.total_balance += address.balance;
        self.stats.addresses_with_balance += if address.balance > 0 { 1 } else { 0 };
        self.addresses.push(address);
    }

    /// Add a found UTXO
    pub fn add_utxo(&mut self, utxo: FoundUtxo) {
        self.stats.total_utxos += 1;
        self.utxos.push(utxo);
    }

    /// Get balance by address type
    pub fn balance_by_type(&self, scan_path: ScanPath) -> u64 {
        self.addresses
            .iter()
            .filter(|a| a.scan_path == scan_path)
            .map(|a| a.balance)
            .sum()
    }

    /// Get addresses by type
    pub fn addresses_by_type(&self, scan_path: ScanPath) -> Vec<&FoundAddress> {
        self.addresses
            .iter()
            .filter(|a| a.scan_path == scan_path)
            .collect()
    }

    /// Export to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Generate summary report
    pub fn summary(&self) -> String {
        let mut report = String::new();
        report.push_str("=== Wallet Recovery Summary ===\n\n");
        
        report.push_str(&format!("Total Balance: {} satoshis ({:.8} BTC)\n", 
            self.total_balance, 
            self.total_balance as f64 / 100_000_000.0));
        report.push_str(&format!("Addresses Found: {}\n", self.addresses.len()));
        report.push_str(&format!("UTXOs Found: {}\n", self.utxos.len()));
        report.push_str(&format!("Addresses Scanned: {}\n\n", self.stats.addresses_scanned));

        report.push_str("By Address Type:\n");
        for path in &[ScanPath::Bip44, ScanPath::Bip49, ScanPath::Bip84, ScanPath::Bip86] {
            let balance = self.balance_by_type(*path);
            let count = self.addresses_by_type(*path).len();
            if count > 0 {
                report.push_str(&format!("  {}: {} addresses, {} sats\n", 
                    path.address_type(), count, balance));
            }
        }

        report.push_str(&format!("\nScan Duration: {} ms\n", self.stats.scan_duration_ms));
        
        report
    }
}

impl Default for RecoveryResult {
    fn default() -> Self {
        Self::new()
    }
}

/// An address found during recovery scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundAddress {
    /// The address string
    pub address: String,
    /// Full derivation path (e.g., "m/84'/0'/0'/0/5")
    pub path: String,
    /// The scan path type used
    pub scan_path: ScanPath,
    /// Account number
    pub account: u32,
    /// Change (0 = external, 1 = internal)
    pub change: u32,
    /// Address index
    pub index: u32,
    /// Current balance (in satoshis)
    pub balance: u64,
    /// Number of transactions
    pub tx_count: u32,
}

impl FoundAddress {
    /// Create a new found address
    pub fn new(
        address: String,
        path: String,
        scan_path: ScanPath,
        account: u32,
        change: u32,
        index: u32,
    ) -> Self {
        Self {
            address,
            path,
            scan_path,
            account,
            change,
            index,
            balance: 0,
            tx_count: 0,
        }
    }

    /// Check if this is a change address
    pub fn is_change(&self) -> bool {
        self.change == 1
    }
}

/// An unspent transaction output found during recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundUtxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Address this UTXO belongs to
    pub address: String,
    /// Derivation path
    pub path: String,
    /// Number of confirmations
    pub confirmations: u32,
    /// Block height (0 if unconfirmed)
    pub height: u32,
}

impl FoundUtxo {
    /// Check if this UTXO is confirmed
    pub fn is_confirmed(&self) -> bool {
        self.confirmations > 0
    }
}

/// Statistics about the recovery scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    /// Total addresses scanned
    pub addresses_scanned: u32,
    /// Addresses with non-zero balance
    pub addresses_with_balance: u32,
    /// Total UTXOs found
    pub total_utxos: u32,
    /// Accounts scanned
    pub accounts_scanned: u32,
    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,
}

impl ScanStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_result_new() {
        let result = RecoveryResult::new();
        assert_eq!(result.total_balance, 0);
        assert!(result.addresses.is_empty());
        assert!(result.utxos.is_empty());
    }

    #[test]
    fn test_add_address() {
        let mut result = RecoveryResult::new();
        
        let addr = FoundAddress {
            address: "bc1q...".into(),
            path: "m/84'/0'/0'/0/0".into(),
            scan_path: ScanPath::Bip84,
            account: 0,
            change: 0,
            index: 0,
            balance: 100000,
            tx_count: 5,
        };
        
        result.add_address(addr);
        
        assert_eq!(result.total_balance, 100000);
        assert_eq!(result.addresses.len(), 1);
        assert_eq!(result.stats.addresses_with_balance, 1);
    }

    #[test]
    fn test_balance_by_type() {
        let mut result = RecoveryResult::new();
        
        result.add_address(FoundAddress {
            address: "bc1q...".into(),
            path: "m/84'/0'/0'/0/0".into(),
            scan_path: ScanPath::Bip84,
            account: 0, change: 0, index: 0,
            balance: 50000, tx_count: 1,
        });
        
        result.add_address(FoundAddress {
            address: "1...".into(),
            path: "m/44'/0'/0'/0/0".into(),
            scan_path: ScanPath::Bip44,
            account: 0, change: 0, index: 0,
            balance: 30000, tx_count: 1,
        });
        
        assert_eq!(result.balance_by_type(ScanPath::Bip84), 50000);
        assert_eq!(result.balance_by_type(ScanPath::Bip44), 30000);
        assert_eq!(result.balance_by_type(ScanPath::Bip49), 0);
    }
}
