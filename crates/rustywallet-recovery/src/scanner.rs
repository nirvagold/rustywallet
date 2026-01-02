//! Recovery scanner
//!
//! Core scanning logic for wallet recovery.

use crate::backend::{AddressBalance, Backend};
use crate::config::{RecoveryConfig, ScanPath};
use crate::error::RecoveryError;
use crate::result::{FoundAddress, FoundUtxo, RecoveryResult};

use rustywallet_address::Network;
use rustywallet_hd::{DerivationPath, ExtendedPrivateKey, ExtendedPublicKey};
use rustywallet_mnemonic::Mnemonic;

use std::sync::Arc;
use std::time::Instant;

/// Progress callback for scan updates
pub trait ProgressCallback: Send + Sync {
    /// Called when scan progress updates
    fn on_progress(&self, progress: ScanProgress);
}

/// Scan progress information
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Current derivation path being scanned
    pub current_path: String,
    /// Total addresses scanned so far
    pub addresses_scanned: u32,
    /// Addresses with balance found
    pub addresses_found: u32,
    /// Current total balance found
    pub current_balance: u64,
    /// Estimated completion percentage (0-100)
    pub percent_complete: f32,
}

/// Wallet recovery scanner
pub struct RecoveryScanner {
    backend: Arc<dyn Backend>,
    config: RecoveryConfig,
    master_xprv: Option<ExtendedPrivateKey>,
    master_xpub: Option<ExtendedPublicKey>,
    progress_callback: Option<Arc<dyn ProgressCallback>>,
}

impl RecoveryScanner {
    /// Create scanner from mnemonic phrase
    pub fn from_mnemonic<B: Backend + 'static>(
        mnemonic: &str,
        passphrase: Option<&str>,
        backend: B,
        config: RecoveryConfig,
    ) -> Result<Self, RecoveryError> {
        let mnemonic = Mnemonic::from_phrase(mnemonic)?;
        let seed = mnemonic.to_seed(passphrase.unwrap_or(""));
        let network = if config.testnet {
            rustywallet_hd::Network::Testnet
        } else {
            rustywallet_hd::Network::Mainnet
        };
        let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), network)?;
        
        Ok(Self {
            backend: Arc::new(backend),
            config,
            master_xprv: Some(master),
            master_xpub: None,
            progress_callback: None,
        })
    }

    /// Create scanner from extended public key
    pub fn from_xpub<B: Backend + 'static>(
        xpub: &str,
        backend: B,
        config: RecoveryConfig,
    ) -> Result<Self, RecoveryError> {
        let xpub = ExtendedPublicKey::from_xpub(xpub)
            .map_err(|e| RecoveryError::InvalidXpub(e.to_string()))?;
        
        Ok(Self {
            backend: Arc::new(backend),
            config,
            master_xprv: None,
            master_xpub: Some(xpub),
            progress_callback: None,
        })
    }

    /// Create scanner from extended private key
    pub fn from_xprv<B: Backend + 'static>(
        xprv: &str,
        backend: B,
        config: RecoveryConfig,
    ) -> Result<Self, RecoveryError> {
        let xprv = ExtendedPrivateKey::from_xprv(xprv)
            .map_err(|e| RecoveryError::InvalidXprv(e.to_string()))?;
        
        Ok(Self {
            backend: Arc::new(backend),
            config,
            master_xprv: Some(xprv),
            master_xpub: None,
            progress_callback: None,
        })
    }

    /// Set progress callback
    pub fn with_progress<P: ProgressCallback + 'static>(mut self, callback: P) -> Self {
        self.progress_callback = Some(Arc::new(callback));
        self
    }

    /// Run the recovery scan
    pub async fn scan(&self) -> Result<RecoveryResult, RecoveryError> {
        let start = Instant::now();
        let mut result = RecoveryResult::new();
        
        let network = if self.config.testnet {
            Network::BitcoinTestnet
        } else {
            Network::BitcoinMainnet
        };

        // Scan each configured path
        for scan_path in &self.config.scan_paths {
            self.scan_path(*scan_path, network, &mut result).await?;
        }

        result.stats.scan_duration_ms = start.elapsed().as_millis() as u64;
        
        // Collect UTXOs for addresses with balance
        self.collect_utxos(&mut result).await?;
        
        Ok(result)
    }

    /// Scan a specific derivation path standard
    async fn scan_path(
        &self,
        scan_path: ScanPath,
        network: Network,
        result: &mut RecoveryResult,
    ) -> Result<(), RecoveryError> {
        let mut account = 0u32;
        let mut consecutive_empty_accounts = 0u32;

        while consecutive_empty_accounts < self.config.account_gap_limit {
            let found_in_account = self.scan_account(scan_path, account, network, result).await?;
            
            if found_in_account {
                consecutive_empty_accounts = 0;
            } else {
                consecutive_empty_accounts += 1;
            }
            
            result.stats.accounts_scanned += 1;
            account += 1;
        }

        Ok(())
    }

    /// Scan a single account
    async fn scan_account(
        &self,
        scan_path: ScanPath,
        account: u32,
        network: Network,
        result: &mut RecoveryResult,
    ) -> Result<bool, RecoveryError> {
        let mut found_any = false;

        // Scan external chain (change = 0)
        if self.scan_chain(scan_path, account, 0, network, result).await? {
            found_any = true;
        }

        // Scan internal chain (change = 1) if configured
        if self.config.scan_change
            && self.scan_chain(scan_path, account, 1, network, result).await?
        {
            found_any = true;
        }

        Ok(found_any)
    }

    /// Scan a single chain (external or internal)
    async fn scan_chain(
        &self,
        scan_path: ScanPath,
        account: u32,
        change: u32,
        network: Network,
        result: &mut RecoveryResult,
    ) -> Result<bool, RecoveryError> {
        let mut index = 0u32;
        let mut consecutive_empty = 0u32;
        let mut found_any = false;

        while consecutive_empty < self.config.gap_limit {
            // Generate batch of addresses
            let batch_end = index + self.config.batch_size;
            let mut addresses = Vec::new();
            let mut address_info = Vec::new();

            for i in index..batch_end {
                let (address, path) = self.derive_address(scan_path, account, change, i, network)?;
                addresses.push(address.clone());
                address_info.push((address, path, i));
            }

            // Batch query balances
            let balances: Vec<AddressBalance> = self.backend.batch_get_balances(&addresses).await?;

            // Process results
            for ((address, path, idx), balance) in address_info.into_iter().zip(balances.into_iter()) {
                result.stats.addresses_scanned += 1;
                
                if balance.has_activity() {
                    let found = FoundAddress {
                        address,
                        path,
                        scan_path,
                        account,
                        change,
                        index: idx,
                        balance: balance.confirmed,
                        tx_count: balance.tx_count,
                    };
                    result.add_address(found);
                    found_any = true;
                    consecutive_empty = 0;
                } else {
                    consecutive_empty += 1;
                }

                // Report progress
                if let Some(ref callback) = self.progress_callback {
                    callback.on_progress(ScanProgress {
                        current_path: format!("m/{}'/{}'/{}'/{}/{}", 
                            scan_path.purpose(), 
                            if self.config.testnet { 1 } else { 0 },
                            account, change, idx),
                        addresses_scanned: result.stats.addresses_scanned,
                        addresses_found: result.addresses.len() as u32,
                        current_balance: result.total_balance,
                        percent_complete: 0.0,
                    });
                }

                if consecutive_empty >= self.config.gap_limit {
                    break;
                }
            }

            index = batch_end;
        }

        Ok(found_any)
    }

    /// Derive an address for the given path components
    fn derive_address(
        &self,
        scan_path: ScanPath,
        account: u32,
        change: u32,
        index: u32,
        network: Network,
    ) -> Result<(String, String), RecoveryError> {
        let coin_type = if network == Network::BitcoinTestnet { 1 } else { 0 };
        let purpose = scan_path.purpose();
        
        let path_str = format!("m/{}'/{}'/{}'/{}/{}", purpose, coin_type, account, change, index);
        let path = DerivationPath::parse(&path_str)
            .map_err(|e| RecoveryError::InvalidPath(e.to_string()))?;

        let address = if let Some(ref master) = self.master_xprv {
            let derived = master.derive_path(&path)?;
            let pubkey = derived.public_key();
            self.pubkey_to_address(&pubkey, scan_path, network)?
        } else if let Some(ref master) = self.master_xpub {
            // For xpub, we can only derive non-hardened paths
            let child_path = DerivationPath::parse(&format!("{}/{}", change, index))
                .map_err(|e| RecoveryError::InvalidPath(e.to_string()))?;
            let derived = master.derive_path(&child_path)?;
            self.xpub_to_address(&derived, scan_path, network)?
        } else {
            return Err(RecoveryError::InvalidXpub("No master key available".into()));
        };

        Ok((address, path_str))
    }

    /// Convert public key to address based on scan path
    fn pubkey_to_address(
        &self,
        pubkey: &rustywallet_keys::public_key::PublicKey,
        scan_path: ScanPath,
        network: Network,
    ) -> Result<String, RecoveryError> {
        use rustywallet_address::{P2PKHAddress, P2WPKHAddress, P2TRAddress};

        let address = match scan_path {
            ScanPath::Bip44 => {
                P2PKHAddress::from_public_key(pubkey, network)
                    .map_err(|e| RecoveryError::DerivationError(e.to_string()))?
                    .to_string()
            }
            ScanPath::Bip49 => {
                // P2SH-P2WPKH: for now return native segwit
                // TODO: implement proper P2SH-P2WPKH
                P2WPKHAddress::from_public_key(pubkey, network)
                    .map_err(|e| RecoveryError::DerivationError(e.to_string()))?
                    .to_string()
            }
            ScanPath::Bip84 => {
                P2WPKHAddress::from_public_key(pubkey, network)
                    .map_err(|e| RecoveryError::DerivationError(e.to_string()))?
                    .to_string()
            }
            ScanPath::Bip86 => {
                P2TRAddress::from_public_key(pubkey, network)
                    .map_err(|e| RecoveryError::DerivationError(e.to_string()))?
                    .to_string()
            }
        };

        Ok(address)
    }

    /// Convert extended public key to address
    fn xpub_to_address(
        &self,
        xpub: &ExtendedPublicKey,
        scan_path: ScanPath,
        network: Network,
    ) -> Result<String, RecoveryError> {
        let pubkey = xpub.public_key();
        self.pubkey_to_address(&pubkey, scan_path, network)
    }

    /// Collect UTXOs for all found addresses
    async fn collect_utxos(&self, result: &mut RecoveryResult) -> Result<(), RecoveryError> {
        let addresses_with_balance: Vec<_> = result.addresses
            .iter()
            .filter(|a| a.balance > 0)
            .map(|a| (a.address.clone(), a.path.clone()))
            .collect();
        
        for (address, path) in addresses_with_balance {
            let mut utxos: Vec<FoundUtxo> = self.backend.get_utxos(&address).await?;
            
            // Fill in the derivation path
            for utxo in &mut utxos {
                utxo.path = path.clone();
            }
            
            // Filter by min confirmations
            let filtered: Vec<FoundUtxo> = utxos
                .into_iter()
                .filter(|u| u.confirmations >= self.config.min_confirmations)
                .collect();
            
            for utxo in filtered {
                result.add_utxo(utxo);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_progress() {
        let progress = ScanProgress {
            current_path: "m/84'/0'/0'/0/0".to_string(),
            addresses_scanned: 100,
            addresses_found: 5,
            current_balance: 50000,
            percent_complete: 25.0,
        };
        
        assert_eq!(progress.addresses_scanned, 100);
    }
}
