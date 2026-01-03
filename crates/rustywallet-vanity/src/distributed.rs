//! Distributed vanity address search.
//!
//! This module provides infrastructure for distributing vanity address
//! search across multiple workers, either locally or over a network.

use crate::address_type::AddressType;
use crate::error::VanityError;
use crate::result::{SearchStats, VanityResult};
use rustywallet_keys::private_key::PrivateKey;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A work unit for distributed search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkUnit {
    /// Unique identifier for this work unit
    pub id: u64,
    /// Pattern to search for
    pub pattern: String,
    /// Address type to generate
    pub address_type: String,
    /// Whether pattern matching is case-insensitive
    pub case_insensitive: bool,
    /// Number of keys to check in this unit
    pub key_count: usize,
    /// Whether to use testnet
    pub testnet: bool,
}

impl WorkUnit {
    /// Create a new work unit.
    pub fn new(
        id: u64,
        pattern: &str,
        address_type: AddressType,
        case_insensitive: bool,
        key_count: usize,
        testnet: bool,
    ) -> Self {
        Self {
            id,
            pattern: pattern.to_string(),
            address_type: format!("{:?}", address_type),
            case_insensitive,
            key_count,
            testnet,
        }
    }

    /// Parse address type from string.
    pub fn get_address_type(&self) -> Result<AddressType, VanityError> {
        match self.address_type.as_str() {
            "P2PKH" => Ok(AddressType::P2PKH),
            "P2WPKH" => Ok(AddressType::P2WPKH),
            "P2TR" => Ok(AddressType::P2TR),
            "Ethereum" => Ok(AddressType::Ethereum),
            _ => Err(VanityError::InvalidConfig(format!(
                "Unknown address type: {}",
                self.address_type
            ))),
        }
    }
}

/// Result from processing a work unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkResult {
    /// Work unit ID
    pub work_id: u64,
    /// Worker ID
    pub worker_id: String,
    /// Whether a match was found
    pub found: bool,
    /// The matching address (if found)
    pub address: Option<String>,
    /// The private key in WIF format (if found)
    pub private_key_wif: Option<String>,
    /// Number of keys checked
    pub keys_checked: u64,
    /// Time taken in milliseconds
    pub duration_ms: u64,
}

impl WorkResult {
    /// Create a result indicating no match found.
    pub fn not_found(work_id: u64, worker_id: &str, keys_checked: u64, duration_ms: u64) -> Self {
        Self {
            work_id,
            worker_id: worker_id.to_string(),
            found: false,
            address: None,
            private_key_wif: None,
            keys_checked,
            duration_ms,
        }
    }

    /// Create a result indicating a match was found.
    pub fn found(
        work_id: u64,
        worker_id: &str,
        address: &str,
        private_key_wif: &str,
        keys_checked: u64,
        duration_ms: u64,
    ) -> Self {
        Self {
            work_id,
            worker_id: worker_id.to_string(),
            found: true,
            address: Some(address.to_string()),
            private_key_wif: Some(private_key_wif.to_string()),
            keys_checked,
            duration_ms,
        }
    }
}

/// Coordinator for distributed vanity search.
///
/// The coordinator manages work distribution and result collection
/// across multiple workers.
pub struct SearchCoordinator {
    /// Pattern to search for
    pattern: String,
    /// Address type
    address_type: AddressType,
    /// Case insensitive matching
    case_insensitive: bool,
    /// Use testnet
    testnet: bool,
    /// Keys per work unit
    keys_per_unit: usize,
    /// Next work unit ID
    next_id: AtomicU64,
    /// Total keys checked
    total_checked: AtomicU64,
    /// Whether search is complete
    found: AtomicBool,
    /// Start time
    start_time: Instant,
}

impl SearchCoordinator {
    /// Create a new search coordinator.
    pub fn new(
        pattern: &str,
        address_type: AddressType,
        case_insensitive: bool,
        testnet: bool,
    ) -> Self {
        Self {
            pattern: pattern.to_string(),
            address_type,
            case_insensitive,
            testnet,
            keys_per_unit: 100_000,
            next_id: AtomicU64::new(0),
            total_checked: AtomicU64::new(0),
            found: AtomicBool::new(false),
            start_time: Instant::now(),
        }
    }

    /// Set the number of keys per work unit.
    pub fn keys_per_unit(mut self, count: usize) -> Self {
        self.keys_per_unit = count;
        self
    }

    /// Get the next work unit.
    ///
    /// Returns `None` if a match has already been found.
    pub fn next_work_unit(&self) -> Option<WorkUnit> {
        if self.found.load(Ordering::Relaxed) {
            return None;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        Some(WorkUnit::new(
            id,
            &self.pattern,
            self.address_type,
            self.case_insensitive,
            self.keys_per_unit,
            self.testnet,
        ))
    }

    /// Submit a work result.
    ///
    /// Returns `true` if this result contains the winning match.
    pub fn submit_result(&self, result: &WorkResult) -> bool {
        self.total_checked.fetch_add(result.keys_checked, Ordering::Relaxed);

        if result.found {
            self.found.store(true, Ordering::Relaxed);
            return true;
        }

        false
    }

    /// Check if search is complete.
    pub fn is_complete(&self) -> bool {
        self.found.load(Ordering::Relaxed)
    }

    /// Get current statistics.
    pub fn stats(&self) -> SearchStats {
        let elapsed = self.start_time.elapsed();
        let total = self.total_checked.load(Ordering::Relaxed);
        let rate = if elapsed.as_secs_f64() > 0.0 {
            total as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        SearchStats {
            attempts: total,
            elapsed,
            rate,
        }
    }
}

/// A worker for distributed vanity search.
///
/// Workers process work units and report results back to the coordinator.
pub struct SearchWorker {
    /// Worker identifier
    id: String,
    /// Stop signal
    stop: Arc<AtomicBool>,
}

impl SearchWorker {
    /// Create a new search worker.
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get the worker ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get a stop signal handle.
    pub fn stop_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Signal the worker to stop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Process a work unit.
    pub fn process(&self, work: &WorkUnit) -> Result<WorkResult, VanityError> {
        use crate::pattern::Pattern;

        let start = Instant::now();
        let address_type = work.get_address_type()?;
        let pattern = Pattern::prefix(&work.pattern)?;

        // Search with limit
        let mut checked = 0u64;
        while checked < work.key_count as u64 {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }

            // Generate and check a batch
            let batch_size = 1000.min((work.key_count as u64 - checked) as usize);
            
            for _ in 0..batch_size {
                let key = PrivateKey::random();
                let address = address_type.derive_address(&key, work.testnet)
                    .map_err(VanityError::AddressError)?;

                if pattern.matches(&address, !work.case_insensitive) {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    let wif = key.to_wif(rustywallet_keys::network::Network::Mainnet);
                    return Ok(WorkResult::found(
                        work.id,
                        &self.id,
                        &address,
                        &wif,
                        checked + 1,
                        duration_ms,
                    ));
                }
                checked += 1;
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        Ok(WorkResult::not_found(work.id, &self.id, checked, duration_ms))
    }
}

/// Configuration for distributed search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedConfig {
    /// Number of local workers
    pub local_workers: usize,
    /// Keys per work unit
    pub keys_per_unit: usize,
    /// Progress report interval in seconds
    pub report_interval_secs: u64,
}

impl Default for DistributedConfig {
    fn default() -> Self {
        Self {
            local_workers: num_cpus(),
            keys_per_unit: 100_000,
            report_interval_secs: 5,
        }
    }
}

/// Get the number of CPUs.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

/// Run a distributed search with local workers.
///
/// This function spawns multiple worker threads and coordinates
/// the search across them.
pub fn run_distributed_search<F>(
    pattern: &str,
    address_type: AddressType,
    case_insensitive: bool,
    testnet: bool,
    config: DistributedConfig,
    mut progress_callback: F,
) -> Result<Option<VanityResult>, VanityError>
where
    F: FnMut(&SearchStats),
{
    use crate::pattern::Pattern;
    use std::sync::mpsc;
    use std::thread;

    let coordinator = Arc::new(SearchCoordinator::new(
        pattern,
        address_type,
        case_insensitive,
        testnet,
    ).keys_per_unit(config.keys_per_unit));

    let (tx, rx) = mpsc::channel::<WorkResult>();
    let mut handles = Vec::new();

    // Spawn workers
    for i in 0..config.local_workers {
        let coord = Arc::clone(&coordinator);
        let tx = tx.clone();
        let worker_id = format!("worker-{}", i);

        let handle = thread::spawn(move || {
            let worker = SearchWorker::new(&worker_id);

            while let Some(work) = coord.next_work_unit() {
                match worker.process(&work) {
                    Ok(result) => {
                        let found = result.found;
                        let _ = tx.send(result);
                        if found {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        handles.push(handle);
    }

    // Drop the original sender so rx will close when all workers finish
    drop(tx);

    // Collect results
    let mut result: Option<VanityResult> = None;
    let mut last_report = Instant::now();
    let report_interval = Duration::from_secs(config.report_interval_secs);

    for work_result in rx {
        coordinator.submit_result(&work_result);

        if work_result.found {
            if let (Some(addr), Some(wif)) = (&work_result.address, &work_result.private_key_wif) {
                let key = PrivateKey::from_wif(wif)
                    .map_err(|e| VanityError::GenerationFailed(e.to_string()))?;

                let matched = Pattern::prefix(pattern)?;

                result = Some(VanityResult::new(
                    key,
                    addr.clone(),
                    matched,
                    coordinator.stats(),
                ));
            }
            break;
        }

        // Progress report
        if last_report.elapsed() >= report_interval {
            progress_callback(&coordinator.stats());
            last_report = Instant::now();
        }
    }

    // Wait for all workers to finish
    for handle in handles {
        let _ = handle.join();
    }

    // Final progress report
    progress_callback(&coordinator.stats());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_unit_creation() {
        let work = WorkUnit::new(1, "1A", AddressType::P2PKH, false, 1000, false);
        assert_eq!(work.id, 1);
        assert_eq!(work.pattern, "1A");
        assert_eq!(work.key_count, 1000);
    }

    #[test]
    fn test_work_result_not_found() {
        let result = WorkResult::not_found(1, "worker-0", 1000, 100);
        assert!(!result.found);
        assert!(result.address.is_none());
    }

    #[test]
    fn test_work_result_found() {
        let result = WorkResult::found(1, "worker-0", "1ABC123", "WIF123", 500, 50);
        assert!(result.found);
        assert_eq!(result.address, Some("1ABC123".to_string()));
    }

    #[test]
    fn test_coordinator_work_distribution() {
        let coord = SearchCoordinator::new("1A", AddressType::P2PKH, false, false)
            .keys_per_unit(1000);

        let work1 = coord.next_work_unit().unwrap();
        let work2 = coord.next_work_unit().unwrap();

        assert_eq!(work1.id, 0);
        assert_eq!(work2.id, 1);
    }

    #[test]
    fn test_coordinator_completion() {
        let coord = SearchCoordinator::new("1A", AddressType::P2PKH, false, false);

        assert!(!coord.is_complete());

        let result = WorkResult::found(0, "worker-0", "1ABC", "WIF", 100, 10);
        coord.submit_result(&result);

        assert!(coord.is_complete());
        assert!(coord.next_work_unit().is_none());
    }

    #[test]
    fn test_distributed_config_default() {
        let config = DistributedConfig::default();
        assert!(config.local_workers > 0);
        assert!(config.keys_per_unit > 0);
    }
}
