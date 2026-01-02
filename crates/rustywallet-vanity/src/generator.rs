//! Vanity address generator.

use crate::address_type::AddressType;
use crate::config::VanityConfig;
use crate::difficulty::DifficultyEstimate;
use crate::error::VanityError;
use crate::pattern::Pattern;
use crate::result::{SearchProgress, SearchStats, VanityResult};
use rayon::prelude::*;
use rustywallet_batch::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// High-performance vanity address generator.
///
/// `VanityGenerator` provides a fluent API for searching for addresses
/// that match specific patterns.
///
/// # Example
///
/// ```rust,no_run
/// use rustywallet_vanity::prelude::*;
///
/// // Search for an address starting with "1Love"
/// let result = VanityGenerator::new()
///     .pattern("1Love")
///     .search()
///     .unwrap();
///
/// println!("Found: {}", result.address);
/// println!("Private key: {}", result.private_key.to_wif(rustywallet_keys::prelude::Network::Mainnet));
/// ```
#[derive(Debug, Clone)]
pub struct VanityGenerator {
    config: VanityConfig,
}

impl Default for VanityGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl VanityGenerator {
    /// Create a new vanity generator with default configuration.
    pub fn new() -> Self {
        Self {
            config: VanityConfig::default(),
        }
    }

    /// Create a vanity generator with a specific configuration.
    pub fn with_config(config: VanityConfig) -> Self {
        Self { config }
    }

    /// Add a prefix pattern to search for.
    pub fn pattern(mut self, prefix: &str) -> Self {
        if let Ok(p) = Pattern::prefix(prefix) {
            self.config.patterns.push(p);
        }
        self
    }

    /// Add multiple prefix patterns to search for.
    pub fn patterns(mut self, prefixes: &[&str]) -> Self {
        for prefix in prefixes {
            if let Ok(p) = Pattern::prefix(prefix) {
                self.config.patterns.push(p);
            }
        }
        self
    }

    /// Add a suffix pattern.
    pub fn suffix(mut self, suffix: &str) -> Self {
        if let Ok(p) = Pattern::suffix(suffix) {
            self.config.patterns.push(p);
        }
        self
    }

    /// Add a contains pattern.
    pub fn contains(mut self, substring: &str) -> Self {
        if let Ok(p) = Pattern::contains(substring) {
            self.config.patterns.push(p);
        }
        self
    }

    /// Set the address type.
    pub fn address_type(mut self, addr_type: AddressType) -> Self {
        self.config.address_type = addr_type;
        self
    }

    /// Use testnet addresses.
    pub fn testnet(mut self) -> Self {
        self.config.testnet = true;
        self
    }

    /// Enable case-insensitive matching.
    pub fn case_insensitive(mut self) -> Self {
        self.config.case_sensitive = false;
        self
    }

    /// Set maximum attempts.
    pub fn max_attempts(mut self, max: u64) -> Self {
        self.config.max_attempts = Some(max);
        self
    }

    /// Set timeout.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.config.timeout = Some(duration);
        self
    }

    /// Set number of threads.
    pub fn threads(mut self, count: usize) -> Self {
        self.config.thread_count = Some(count);
        self
    }

    /// Set batch size.
    pub fn batch_size(mut self, size: usize) -> Self {
        self.config.batch_size = size;
        self
    }

    /// Estimate difficulty for the configured patterns.
    pub fn estimate_difficulty(&self) -> Vec<DifficultyEstimate> {
        // Assume ~1M keys/sec generation rate
        let rate = 1_000_000.0;

        self.config
            .patterns
            .iter()
            .map(|p| {
                DifficultyEstimate::calculate(
                    p,
                    self.config.address_type,
                    self.config.case_sensitive,
                    rate,
                )
            })
            .collect()
    }

    /// Search for a matching address (single-threaded).
    pub fn search(&self) -> Result<VanityResult, VanityError> {
        self.config.validate()?;
        self.search_internal(false, None)
    }

    /// Search for a matching address with parallel processing.
    pub fn search_parallel(&self) -> Result<VanityResult, VanityError> {
        self.config.validate()?;
        self.search_internal(true, None)
    }

    /// Search with a progress callback.
    pub fn search_with_progress<F>(&self, callback: F) -> Result<VanityResult, VanityError>
    where
        F: Fn(SearchProgress) + Send + Sync + 'static,
    {
        self.config.validate()?;
        self.search_internal(true, Some(Arc::new(callback)))
    }

    fn search_internal(
        &self,
        parallel: bool,
        progress_callback: Option<Arc<dyn Fn(SearchProgress) + Send + Sync>>,
    ) -> Result<VanityResult, VanityError> {
        let start = Instant::now();
        let attempts = Arc::new(AtomicU64::new(0));
        let found = Arc::new(AtomicBool::new(false));

        // Calculate expected attempts for progress
        let expected_attempts = self
            .config
            .patterns
            .iter()
            .map(|p| p.difficulty(self.config.address_type, self.config.case_sensitive) as u64)
            .min();

        // Progress tracking
        let last_progress = Arc::new(std::sync::Mutex::new(Instant::now()));
        let progress_interval = self.config.progress_interval;

        loop {
            // Check timeout
            if let Some(timeout) = self.config.timeout {
                if start.elapsed() > timeout {
                    return Err(VanityError::Timeout(timeout));
                }
            }

            // Check max attempts
            let current_attempts = attempts.load(Ordering::Relaxed);
            if let Some(max) = self.config.max_attempts {
                if current_attempts >= max {
                    return Err(VanityError::MaxAttemptsReached(max));
                }
            }

            // Check if already found
            if found.load(Ordering::Relaxed) {
                // This shouldn't happen in single-threaded, but handle it
                break;
            }

            // Generate batch of keys
            let batch_size = self.config.batch_size;
            let keys = BatchGenerator::new()
                .count(batch_size)
                .parallel()
                .generate_vec()
                .map_err(|e| VanityError::GenerationError(e.to_string()))?;

            // Search through keys
            let result = if parallel {
                self.search_batch_parallel(&keys, &attempts, &found)?
            } else {
                self.search_batch_sequential(&keys, &attempts)?
            };

            // Report progress
            if let Some(ref callback) = progress_callback {
                let mut last = last_progress.lock().unwrap();
                if last.elapsed() >= progress_interval {
                    let progress = SearchProgress::new(
                        attempts.load(Ordering::Relaxed),
                        start.elapsed(),
                        expected_attempts,
                    );
                    callback(progress);
                    *last = Instant::now();
                }
            }

            if let Some((key, address, pattern)) = result {
                let stats = SearchStats::new(attempts.load(Ordering::Relaxed), start.elapsed());
                return Ok(VanityResult::new(key, address, pattern, stats));
            }
        }

        // Should not reach here
        Err(VanityError::Cancelled)
    }

    fn search_batch_sequential(
        &self,
        keys: &[rustywallet_keys::prelude::PrivateKey],
        attempts: &AtomicU64,
    ) -> Result<Option<(rustywallet_keys::prelude::PrivateKey, String, Pattern)>, VanityError> {
        for key in keys {
            attempts.fetch_add(1, Ordering::Relaxed);

            let address = self
                .config
                .address_type
                .derive_address(key, self.config.testnet)
                .map_err(VanityError::AddressError)?;

            for pattern in &self.config.patterns {
                if pattern.matches(&address, self.config.case_sensitive) {
                    return Ok(Some((key.clone(), address, pattern.clone())));
                }
            }
        }

        Ok(None)
    }

    fn search_batch_parallel(
        &self,
        keys: &[rustywallet_keys::prelude::PrivateKey],
        attempts: &AtomicU64,
        found: &AtomicBool,
    ) -> Result<Option<(rustywallet_keys::prelude::PrivateKey, String, Pattern)>, VanityError> {
        let result: Option<(rustywallet_keys::prelude::PrivateKey, String, Pattern)> = keys
            .par_iter()
            .find_map_any(|key| {
                if found.load(Ordering::Relaxed) {
                    return None;
                }

                attempts.fetch_add(1, Ordering::Relaxed);

                let address = self
                    .config
                    .address_type
                    .derive_address(key, self.config.testnet)
                    .ok()?;

                for pattern in &self.config.patterns {
                    if pattern.matches(&address, self.config.case_sensitive) {
                        found.store(true, Ordering::Relaxed);
                        return Some((key.clone(), address, pattern.clone()));
                    }
                }

                None
            });

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_creation() {
        let gen = VanityGenerator::new()
            .pattern("1A")
            .address_type(AddressType::P2PKH);

        assert_eq!(gen.config.patterns.len(), 1);
        assert_eq!(gen.config.address_type, AddressType::P2PKH);
    }

    #[test]
    fn test_difficulty_estimation() {
        let gen = VanityGenerator::new().pattern("1A");

        let estimates = gen.estimate_difficulty();
        assert_eq!(estimates.len(), 1);
    }

    #[test]
    fn test_search_simple_pattern() {
        // Search for a very simple pattern (just "1") which should match immediately
        let result = VanityGenerator::new()
            .pattern("1")
            .address_type(AddressType::P2PKH)
            .max_attempts(1000)
            .search();

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.address.starts_with('1'));
    }

    #[test]
    fn test_search_parallel() {
        let result = VanityGenerator::new()
            .pattern("1")
            .address_type(AddressType::P2PKH)
            .max_attempts(1000)
            .search_parallel();

        assert!(result.is_ok());
    }

    #[test]
    fn test_max_attempts_reached() {
        // Search for impossible pattern with low max attempts
        let result = VanityGenerator::new()
            .pattern("1ZZZZZZZZ") // Very unlikely
            .max_attempts(100)
            .search();

        assert!(matches!(result, Err(VanityError::MaxAttemptsReached(_))));
    }
}
