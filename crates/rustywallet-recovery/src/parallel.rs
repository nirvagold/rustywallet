//! Parallel recovery scanner
//!
//! High-performance parallel scanning for wallet recovery using multiple
//! backends and connection pooling.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use futures::future::join_all;
use tokio::sync::Mutex;

use crate::backend::Backend;
use crate::config::ScanPath;
use crate::error::RecoveryError;
use crate::result::{FoundAddress, FoundUtxo, RecoveryResult, ScanStats};

use rustywallet_address::Network;
use rustywallet_descriptor::{derive_address as descriptor_derive_address, Descriptor};
use rustywallet_electrum::{ClientConfig, ConnectionPool, PoolConfig};
use rustywallet_hd::{DerivationPath, ExtendedPrivateKey, ExtendedPublicKey};
use rustywallet_mnemonic::Mnemonic;

/// Progress information for parallel scanning
#[derive(Debug, Clone)]
pub struct ParallelScanProgress {
    /// Index of the descriptor being scanned
    pub descriptor_index: usize,
    /// Current address index being scanned
    pub current_index: u32,
    /// Number of addresses with balance found so far
    pub found_count: usize,
    /// Total addresses scanned across all descriptors
    pub total_scanned: u32,
    /// Estimated completion percentage (0-100)
    pub percent_complete: f32,
}

/// Configuration for parallel recovery scanning
#[derive(Debug, Clone)]
pub struct ParallelScanConfig {
    /// Number of parallel threads/tasks to use
    pub thread_count: usize,
    /// Gap limit for address scanning
    pub gap_limit: u32,
    /// Batch size for address queries
    pub batch_size: u32,
    /// Minimum confirmations for UTXOs
    pub min_confirmations: u32,
    /// Network (mainnet or testnet)
    pub testnet: bool,
}

impl Default for ParallelScanConfig {
    fn default() -> Self {
        Self {
            thread_count: 4,
            gap_limit: 20,
            batch_size: 10,
            min_confirmations: 1,
            testnet: false,
        }
    }
}

impl ParallelScanConfig {
    /// Create a new config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of parallel threads
    pub fn with_thread_count(mut self, count: usize) -> Self {
        self.thread_count = count.max(1);
        self
    }

    /// Set the gap limit
    pub fn with_gap_limit(mut self, limit: u32) -> Self {
        self.gap_limit = limit;
        self
    }

    /// Set the batch size
    pub fn with_batch_size(mut self, size: u32) -> Self {
        self.batch_size = size;
        self
    }

    /// Set minimum confirmations
    pub fn with_min_confirmations(mut self, confirmations: u32) -> Self {
        self.min_confirmations = confirmations;
        self
    }

    /// Set testnet mode
    pub fn with_testnet(mut self, testnet: bool) -> Self {
        self.testnet = testnet;
        self
    }
}

/// Pooled backend wrapper that uses connection pooling
pub struct PooledBackend {
    pool: Arc<ConnectionPool>,
}

impl PooledBackend {
    /// Create a new pooled backend
    pub fn new(pool: Arc<ConnectionPool>) -> Self {
        Self { pool }
    }

    /// Create a pooled backend from server address
    pub async fn from_server(server: &str, pool_config: PoolConfig) -> Result<Self, RecoveryError> {
        let client_config = ClientConfig::ssl(server);
        let pool = ConnectionPool::new(client_config, pool_config);
        pool.initialize().await?;
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    /// Create with default mainnet server
    pub async fn mainnet() -> Result<Self, RecoveryError> {
        Self::from_server("electrum.blockstream.info", PoolConfig::default()).await
    }

    /// Create with default testnet server
    pub async fn testnet() -> Result<Self, RecoveryError> {
        Self::from_server("testnet.aranguren.org", PoolConfig::default()).await
    }

    /// Get pool statistics
    pub async fn stats(&self) -> rustywallet_electrum::PoolStats {
        self.pool.stats().await
    }
}

#[async_trait::async_trait]
impl Backend for PooledBackend {
    async fn get_balance(&self, address: &str) -> Result<crate::backend::AddressBalance, RecoveryError> {
        let client = self.pool.acquire().await?;
        let balance = client.get_balance(address).await?;
        Ok(crate::backend::AddressBalance {
            confirmed: balance.confirmed,
            unconfirmed: balance.unconfirmed,
            tx_count: 0,
        })
    }

    async fn get_utxos(&self, address: &str) -> Result<Vec<FoundUtxo>, RecoveryError> {
        let client = self.pool.acquire().await?;
        let utxos = client.list_unspent(address).await?;
        let height = client.get_block_height().await.unwrap_or(0) as u32;
        Ok(utxos
            .into_iter()
            .map(|u| FoundUtxo {
                txid: u.tx_hash,
                vout: u.tx_pos,
                amount: u.value,
                address: address.to_string(),
                path: String::new(),
                confirmations: if u.height > 0 {
                    height.saturating_sub(u.height) + 1
                } else {
                    0
                },
                height: u.height,
            })
            .collect())
    }

    async fn batch_get_balances(
        &self,
        addresses: &[String],
    ) -> Result<Vec<crate::backend::AddressBalance>, RecoveryError> {
        let client = self.pool.acquire().await?;
        let refs: Vec<&str> = addresses.iter().map(|s| s.as_str()).collect();
        let balances = client.get_balances(&refs).await?;
        Ok(balances
            .into_iter()
            .map(|b| crate::backend::AddressBalance {
                confirmed: b.confirmed,
                unconfirmed: b.unconfirmed,
                tx_count: 0,
            })
            .collect())
    }

    async fn get_block_height(&self) -> Result<u32, RecoveryError> {
        let client = self.pool.acquire().await?;
        let height = client.get_block_height().await?;
        Ok(height as u32)
    }
}

/// Parallel recovery scanner with multiple backends and connection pooling
pub struct ParallelRecoveryScanner {
    /// Multiple backends for parallel queries
    backends: Vec<Arc<dyn Backend>>,
    /// Configuration
    config: ParallelScanConfig,
    /// Master extended private key (if available)
    master_xprv: Option<ExtendedPrivateKey>,
    /// Master extended public key (if available)
    master_xpub: Option<ExtendedPublicKey>,
}

impl ParallelRecoveryScanner {
    /// Create a new parallel scanner with multiple backends
    pub fn new(backends: Vec<Arc<dyn Backend>>, config: ParallelScanConfig) -> Self {
        Self {
            backends,
            config,
            master_xprv: None,
            master_xpub: None,
        }
    }

    /// Create a parallel scanner with connection pooling
    ///
    /// This creates a scanner that uses connection pooling for efficient
    /// parallel queries to Electrum servers.
    pub async fn with_pool(
        servers: &[&str],
        pool_config: PoolConfig,
        scan_config: ParallelScanConfig,
    ) -> Result<Self, RecoveryError> {
        let mut backends: Vec<Arc<dyn Backend>> = Vec::new();

        for server in servers {
            let backend = PooledBackend::from_server(server, pool_config.clone()).await?;
            backends.push(Arc::new(backend));
        }

        Ok(Self {
            backends,
            config: scan_config,
            master_xprv: None,
            master_xpub: None,
        })
    }

    /// Create scanner from mnemonic phrase
    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: Option<&str>,
        backends: Vec<Arc<dyn Backend>>,
        config: ParallelScanConfig,
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
            backends,
            config,
            master_xprv: Some(master),
            master_xpub: None,
        })
    }

    /// Create scanner from mnemonic with connection pooling
    pub async fn from_mnemonic_with_pool(
        mnemonic: &str,
        passphrase: Option<&str>,
        servers: &[&str],
        pool_config: PoolConfig,
        scan_config: ParallelScanConfig,
    ) -> Result<Self, RecoveryError> {
        let mut scanner = Self::with_pool(servers, pool_config, scan_config.clone()).await?;

        let mnemonic_parsed = Mnemonic::from_phrase(mnemonic)?;
        let seed = mnemonic_parsed.to_seed(passphrase.unwrap_or(""));
        let network = if scan_config.testnet {
            rustywallet_hd::Network::Testnet
        } else {
            rustywallet_hd::Network::Mainnet
        };
        let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), network)?;

        scanner.master_xprv = Some(master);
        Ok(scanner)
    }

    /// Create scanner from extended public key
    pub fn from_xpub(
        xpub: &str,
        backends: Vec<Arc<dyn Backend>>,
        config: ParallelScanConfig,
    ) -> Result<Self, RecoveryError> {
        let xpub = ExtendedPublicKey::from_xpub(xpub)
            .map_err(|e| RecoveryError::InvalidXpub(e.to_string()))?;

        Ok(Self {
            backends,
            config,
            master_xprv: None,
            master_xpub: Some(xpub),
        })
    }

    /// Create scanner from extended private key
    pub fn from_xprv(
        xprv: &str,
        backends: Vec<Arc<dyn Backend>>,
        config: ParallelScanConfig,
    ) -> Result<Self, RecoveryError> {
        let xprv = ExtendedPrivateKey::from_xprv(xprv)
            .map_err(|e| RecoveryError::InvalidXprv(e.to_string()))?;

        Ok(Self {
            backends,
            config,
            master_xprv: Some(xprv),
            master_xpub: None,
        })
    }

    /// Get the number of backends
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }

    /// Get the thread count
    pub fn thread_count(&self) -> usize {
        self.config.thread_count
    }

    /// Run parallel scan with descriptors
    ///
    /// Scans multiple descriptors in parallel, using connection pooling
    /// for efficient backend queries.
    pub async fn scan_parallel<F>(
        &self,
        descriptors: &[Descriptor],
        progress_callback: F,
    ) -> Result<RecoveryResult, RecoveryError>
    where
        F: Fn(ParallelScanProgress) + Send + Sync + 'static,
    {
        let start = Instant::now();
        let network = if self.config.testnet {
            Network::BitcoinTestnet
        } else {
            Network::BitcoinMainnet
        };

        // Shared state for aggregation
        let result = Arc::new(Mutex::new(RecoveryResult::new()));
        let total_scanned = Arc::new(AtomicU32::new(0));
        let found_count = Arc::new(AtomicUsize::new(0));
        let progress_callback = Arc::new(progress_callback);

        // Create tasks for each descriptor
        let mut tasks = Vec::new();

        for (desc_idx, descriptor) in descriptors.iter().enumerate() {
            let backend = self.backends[desc_idx % self.backends.len()].clone();
            let descriptor = descriptor.clone();
            let config = self.config.clone();
            let result = result.clone();
            let total_scanned = total_scanned.clone();
            let found_count = found_count.clone();
            let progress_callback = progress_callback.clone();

            let task = tokio::spawn(async move {
                Self::scan_descriptor(
                    backend,
                    &descriptor,
                    desc_idx,
                    network,
                    &config,
                    result,
                    total_scanned,
                    found_count,
                    progress_callback,
                )
                .await
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        let results = join_all(tasks).await;

        // Check for errors
        for task_result in results {
            match task_result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(RecoveryError::BackendError(e.to_string())),
            }
        }

        // Finalize result
        let mut final_result = result.lock().await;
        final_result.stats.scan_duration_ms = start.elapsed().as_millis() as u64;
        final_result.stats.addresses_scanned = total_scanned.load(Ordering::SeqCst);

        // Collect UTXOs for addresses with balance
        self.collect_utxos_parallel(&mut final_result).await?;

        Ok(final_result.clone())
    }

    /// Scan a single descriptor
    async fn scan_descriptor<F>(
        backend: Arc<dyn Backend>,
        descriptor: &Descriptor,
        desc_idx: usize,
        network: Network,
        config: &ParallelScanConfig,
        result: Arc<Mutex<RecoveryResult>>,
        total_scanned: Arc<AtomicU32>,
        found_count: Arc<AtomicUsize>,
        progress_callback: Arc<F>,
    ) -> Result<(), RecoveryError>
    where
        F: Fn(ParallelScanProgress) + Send + Sync,
    {
        let mut index = 0u32;
        let mut consecutive_empty = 0u32;

        while consecutive_empty < config.gap_limit {
            // Generate batch of addresses
            let batch_end = index + config.batch_size;
            let mut addresses = Vec::new();
            let mut address_info = Vec::new();

            for i in index..batch_end {
                match descriptor_derive_address(descriptor, network, i) {
                    Ok(address) => {
                        addresses.push(address.clone());
                        address_info.push((address, i));
                    }
                    Err(e) => {
                        // If descriptor doesn't support derivation at this index, skip
                        if !descriptor.has_wildcard() && i > 0 {
                            break;
                        }
                        return Err(RecoveryError::DerivationError(e.to_string()));
                    }
                }
            }

            if addresses.is_empty() {
                break;
            }

            // Batch query balances
            let balances = backend.batch_get_balances(&addresses).await?;

            // Process results
            for ((address, idx), balance) in address_info.into_iter().zip(balances.into_iter()) {
                total_scanned.fetch_add(1, Ordering::SeqCst);

                if balance.has_activity() {
                    let found = FoundAddress {
                        address,
                        path: format!("descriptor[{}]/{}", desc_idx, idx),
                        scan_path: ScanPath::Bip84, // Default, will be overridden if needed
                        account: 0,
                        change: 0,
                        index: idx,
                        balance: balance.confirmed,
                        tx_count: balance.tx_count,
                    };

                    let mut result = result.lock().await;
                    result.add_address(found);
                    drop(result);

                    found_count.fetch_add(1, Ordering::SeqCst);
                    consecutive_empty = 0;
                } else {
                    consecutive_empty += 1;
                }

                // Report progress
                progress_callback(ParallelScanProgress {
                    descriptor_index: desc_idx,
                    current_index: idx,
                    found_count: found_count.load(Ordering::SeqCst),
                    total_scanned: total_scanned.load(Ordering::SeqCst),
                    percent_complete: 0.0, // Hard to estimate with gap limit
                });

                if consecutive_empty >= config.gap_limit {
                    break;
                }
            }

            // For non-wildcard descriptors, only scan once
            if !descriptor.has_wildcard() {
                break;
            }

            index = batch_end;
        }

        Ok(())
    }

    /// Collect UTXOs for all found addresses in parallel
    async fn collect_utxos_parallel(
        &self,
        result: &mut RecoveryResult,
    ) -> Result<(), RecoveryError> {
        let addresses_with_balance: Vec<_> = result
            .addresses
            .iter()
            .filter(|a| a.balance > 0)
            .map(|a| (a.address.clone(), a.path.clone()))
            .collect();

        if addresses_with_balance.is_empty() {
            return Ok(());
        }

        // Create tasks for UTXO collection
        let mut tasks = Vec::new();

        for (idx, (address, path)) in addresses_with_balance.into_iter().enumerate() {
            let backend = self.backends[idx % self.backends.len()].clone();
            let min_confirmations = self.config.min_confirmations;

            let task = tokio::spawn(async move {
                let mut utxos: Vec<FoundUtxo> = backend.get_utxos(&address).await?;

                // Fill in the derivation path
                for utxo in &mut utxos {
                    utxo.path = path.clone();
                }

                // Filter by min confirmations
                let filtered: Vec<FoundUtxo> = utxos
                    .into_iter()
                    .filter(|u| u.confirmations >= min_confirmations)
                    .collect();

                Ok::<Vec<FoundUtxo>, RecoveryError>(filtered)
            });

            tasks.push(task);
        }

        // Wait for all tasks and aggregate results
        let results = join_all(tasks).await;

        for task_result in results {
            match task_result {
                Ok(Ok(utxos)) => {
                    for utxo in utxos {
                        result.add_utxo(utxo);
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(RecoveryError::BackendError(e.to_string())),
            }
        }

        Ok(())
    }

    /// Scan standard BIP paths in parallel
    ///
    /// Convenience method that scans BIP44, BIP49, BIP84, and BIP86 paths
    /// in parallel using the master key.
    pub async fn scan_standard_paths<F>(
        &self,
        progress_callback: F,
    ) -> Result<RecoveryResult, RecoveryError>
    where
        F: Fn(ParallelScanProgress) + Send + Sync + 'static,
    {
        let start = Instant::now();
        let network = if self.config.testnet {
            Network::BitcoinTestnet
        } else {
            Network::BitcoinMainnet
        };

        // Shared state for aggregation
        let result = Arc::new(Mutex::new(RecoveryResult::new()));
        let total_scanned = Arc::new(AtomicU32::new(0));
        let found_count = Arc::new(AtomicUsize::new(0));
        let progress_callback = Arc::new(progress_callback);

        // Standard paths to scan
        let scan_paths = vec![
            ScanPath::Bip44,
            ScanPath::Bip49,
            ScanPath::Bip84,
            ScanPath::Bip86,
        ];

        // Create tasks for each path
        let mut tasks = Vec::new();

        for (path_idx, scan_path) in scan_paths.iter().enumerate() {
            let backend = self.backends[path_idx % self.backends.len()].clone();
            let scan_path = *scan_path;
            let config = self.config.clone();
            let result = result.clone();
            let total_scanned = total_scanned.clone();
            let found_count = found_count.clone();
            let progress_callback = progress_callback.clone();
            let master_xprv = self.master_xprv.clone();
            let master_xpub = self.master_xpub.clone();

            let task = tokio::spawn(async move {
                Self::scan_standard_path(
                    backend,
                    scan_path,
                    path_idx,
                    network,
                    &config,
                    master_xprv.as_ref(),
                    master_xpub.as_ref(),
                    result,
                    total_scanned,
                    found_count,
                    progress_callback,
                )
                .await
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        let results = join_all(tasks).await;

        // Check for errors
        for task_result in results {
            match task_result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(RecoveryError::BackendError(e.to_string())),
            }
        }

        // Finalize result
        let mut final_result = result.lock().await;
        final_result.stats.scan_duration_ms = start.elapsed().as_millis() as u64;
        final_result.stats.addresses_scanned = total_scanned.load(Ordering::SeqCst);

        // Collect UTXOs for addresses with balance
        self.collect_utxos_parallel(&mut final_result).await?;

        Ok(final_result.clone())
    }

    /// Scan a standard BIP path
    #[allow(clippy::too_many_arguments)]
    async fn scan_standard_path<F>(
        backend: Arc<dyn Backend>,
        scan_path: ScanPath,
        path_idx: usize,
        network: Network,
        config: &ParallelScanConfig,
        master_xprv: Option<&ExtendedPrivateKey>,
        master_xpub: Option<&ExtendedPublicKey>,
        result: Arc<Mutex<RecoveryResult>>,
        total_scanned: Arc<AtomicU32>,
        found_count: Arc<AtomicUsize>,
        progress_callback: Arc<F>,
    ) -> Result<(), RecoveryError>
    where
        F: Fn(ParallelScanProgress) + Send + Sync,
    {
        let coin_type = if network == Network::BitcoinTestnet {
            1
        } else {
            0
        };
        let purpose = scan_path.purpose();

        // Scan account 0, external chain (change = 0)
        let mut index = 0u32;
        let mut consecutive_empty = 0u32;

        while consecutive_empty < config.gap_limit {
            // Generate batch of addresses
            let batch_end = index + config.batch_size;
            let mut addresses = Vec::new();
            let mut address_info = Vec::new();

            for i in index..batch_end {
                let path_str = format!("m/{}'/{}'/{}'/{}/{}", purpose, coin_type, 0, 0, i);
                let path = DerivationPath::parse(&path_str)
                    .map_err(|e| RecoveryError::InvalidPath(e.to_string()))?;

                let address = if let Some(master) = master_xprv {
                    let derived = master.derive_path(&path)?;
                    let pubkey = derived.public_key();
                    Self::pubkey_to_address(&pubkey, scan_path, network)?
                } else if let Some(master) = master_xpub {
                    let child_path = DerivationPath::parse(&format!("{}/{}", 0, i))
                        .map_err(|e| RecoveryError::InvalidPath(e.to_string()))?;
                    let derived = master.derive_path(&child_path)?;
                    let pubkey = derived.public_key();
                    Self::pubkey_to_address(&pubkey, scan_path, network)?
                } else {
                    return Err(RecoveryError::InvalidXpub("No master key available".into()));
                };

                addresses.push(address.clone());
                address_info.push((address, path_str, i));
            }

            // Batch query balances
            let balances = backend.batch_get_balances(&addresses).await?;

            // Process results
            for ((address, path_str, idx), balance) in
                address_info.into_iter().zip(balances.into_iter())
            {
                total_scanned.fetch_add(1, Ordering::SeqCst);

                if balance.has_activity() {
                    let found = FoundAddress {
                        address,
                        path: path_str,
                        scan_path,
                        account: 0,
                        change: 0,
                        index: idx,
                        balance: balance.confirmed,
                        tx_count: balance.tx_count,
                    };

                    let mut result = result.lock().await;
                    result.add_address(found);
                    drop(result);

                    found_count.fetch_add(1, Ordering::SeqCst);
                    consecutive_empty = 0;
                } else {
                    consecutive_empty += 1;
                }

                // Report progress
                progress_callback(ParallelScanProgress {
                    descriptor_index: path_idx,
                    current_index: idx,
                    found_count: found_count.load(Ordering::SeqCst),
                    total_scanned: total_scanned.load(Ordering::SeqCst),
                    percent_complete: 0.0,
                });

                if consecutive_empty >= config.gap_limit {
                    break;
                }
            }

            index = batch_end;
        }

        Ok(())
    }

    /// Convert public key to address based on scan path
    fn pubkey_to_address(
        pubkey: &rustywallet_keys::public_key::PublicKey,
        scan_path: ScanPath,
        network: Network,
    ) -> Result<String, RecoveryError> {
        use rustywallet_address::{P2PKHAddress, P2TRAddress, P2WPKHAddress};

        let address = match scan_path {
            ScanPath::Bip44 => P2PKHAddress::from_public_key(pubkey, network)
                .map_err(|e| RecoveryError::DerivationError(e.to_string()))?
                .to_string(),
            ScanPath::Bip49 => {
                // P2SH-P2WPKH: for now return native segwit
                P2WPKHAddress::from_public_key(pubkey, network)
                    .map_err(|e| RecoveryError::DerivationError(e.to_string()))?
                    .to_string()
            }
            ScanPath::Bip84 => P2WPKHAddress::from_public_key(pubkey, network)
                .map_err(|e| RecoveryError::DerivationError(e.to_string()))?
                .to_string(),
            ScanPath::Bip86 => P2TRAddress::from_public_key(pubkey, network)
                .map_err(|e| RecoveryError::DerivationError(e.to_string()))?
                .to_string(),
        };

        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_scan_config_default() {
        let config = ParallelScanConfig::default();
        assert_eq!(config.thread_count, 4);
        assert_eq!(config.gap_limit, 20);
        assert_eq!(config.batch_size, 10);
    }

    #[test]
    fn test_parallel_scan_config_builder() {
        let config = ParallelScanConfig::new()
            .with_thread_count(8)
            .with_gap_limit(50)
            .with_testnet(true);

        assert_eq!(config.thread_count, 8);
        assert_eq!(config.gap_limit, 50);
        assert!(config.testnet);
    }

    #[test]
    fn test_parallel_scan_progress() {
        let progress = ParallelScanProgress {
            descriptor_index: 0,
            current_index: 10,
            found_count: 2,
            total_scanned: 100,
            percent_complete: 25.0,
        };

        assert_eq!(progress.descriptor_index, 0);
        assert_eq!(progress.current_index, 10);
        assert_eq!(progress.found_count, 2);
    }
}
