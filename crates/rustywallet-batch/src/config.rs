//! Configuration types for batch key generation.
//!
//! This module provides [`BatchConfig`] for customizing batch generation behavior.

use crate::error::BatchError;

/// Configuration for batch key generation.
///
/// Use the builder pattern or preset configurations for common use cases.
///
/// # Example
///
/// ```rust
/// use rustywallet_batch::config::BatchConfig;
///
/// // Custom configuration
/// let config = BatchConfig::default()
///     .with_batch_size(100_000)
///     .with_thread_count(Some(4))
///     .with_chunk_size(1000);
///
/// // Or use presets
/// let fast = BatchConfig::fast();
/// let balanced = BatchConfig::balanced();
/// let memory_efficient = BatchConfig::memory_efficient();
/// ```
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Number of keys to generate in a batch.
    pub batch_size: usize,

    /// Number of threads to use for parallel processing.
    /// None means auto-detect based on available CPU cores.
    pub thread_count: Option<usize>,

    /// Whether to use SIMD optimization when available.
    pub use_simd: bool,

    /// Size of chunks for streaming operations.
    pub chunk_size: usize,

    /// Maximum memory limit in bytes (optional).
    pub memory_limit: Option<usize>,

    /// Whether to use parallel processing.
    pub parallel: bool,

    /// Whether to maintain deterministic ordering in parallel mode.
    pub deterministic_order: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            batch_size: 10_000,
            thread_count: None,
            use_simd: true,
            chunk_size: 1_000,
            memory_limit: None,
            parallel: false,
            deterministic_order: false,
        }
    }
}

impl BatchConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Preset configuration optimized for maximum speed.
    ///
    /// Uses parallel processing with all available cores and larger chunk sizes.
    pub fn fast() -> Self {
        Self {
            batch_size: 100_000,
            thread_count: None, // Auto-detect
            use_simd: true,
            chunk_size: 10_000,
            memory_limit: None,
            parallel: true,
            deterministic_order: false,
        }
    }

    /// Preset configuration balancing speed and memory usage.
    ///
    /// Uses parallel processing with moderate chunk sizes.
    pub fn balanced() -> Self {
        Self {
            batch_size: 50_000,
            thread_count: None,
            use_simd: true,
            chunk_size: 5_000,
            memory_limit: Some(100 * 1024 * 1024), // 100MB
            parallel: true,
            deterministic_order: false,
        }
    }

    /// Preset configuration optimized for minimal memory usage.
    ///
    /// Uses smaller chunk sizes and streaming to minimize memory footprint.
    pub fn memory_efficient() -> Self {
        Self {
            batch_size: 10_000,
            thread_count: Some(2),
            use_simd: true,
            chunk_size: 100,
            memory_limit: Some(10 * 1024 * 1024), // 10MB
            parallel: true,
            deterministic_order: false,
        }
    }

    /// Set the batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set the thread count for parallel processing.
    pub fn with_thread_count(mut self, count: Option<usize>) -> Self {
        self.thread_count = count;
        self
    }

    /// Enable or disable SIMD optimization.
    pub fn with_simd(mut self, enabled: bool) -> Self {
        self.use_simd = enabled;
        self
    }

    /// Set the chunk size for streaming operations.
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Set the memory limit in bytes.
    pub fn with_memory_limit(mut self, limit: Option<usize>) -> Self {
        self.memory_limit = limit;
        self
    }

    /// Enable or disable parallel processing.
    pub fn with_parallel(mut self, enabled: bool) -> Self {
        self.parallel = enabled;
        self
    }

    /// Enable or disable deterministic ordering in parallel mode.
    pub fn with_deterministic_order(mut self, enabled: bool) -> Self {
        self.deterministic_order = enabled;
        self
    }

    /// Validate the configuration.
    ///
    /// Returns an error if any configuration parameter is invalid.
    pub fn validate(&self) -> Result<(), BatchError> {
        if self.batch_size == 0 {
            return Err(BatchError::invalid_config("batch_size must be greater than 0"));
        }

        if self.chunk_size == 0 {
            return Err(BatchError::invalid_config("chunk_size must be greater than 0"));
        }

        if let Some(count) = self.thread_count {
            if count == 0 {
                return Err(BatchError::invalid_config("thread_count must be greater than 0"));
            }
        }

        if let Some(limit) = self.memory_limit {
            if limit == 0 {
                return Err(BatchError::invalid_config("memory_limit must be greater than 0"));
            }
        }

        Ok(())
    }

    /// Get the effective thread count.
    ///
    /// Returns the configured thread count or the number of available CPU cores.
    pub fn effective_thread_count(&self) -> usize {
        self.thread_count.unwrap_or_else(|| {
            rayon::current_num_threads()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BatchConfig::default();
        assert_eq!(config.batch_size, 10_000);
        assert!(config.thread_count.is_none());
        assert!(config.use_simd);
        assert_eq!(config.chunk_size, 1_000);
        assert!(config.memory_limit.is_none());
        assert!(!config.parallel);
        assert!(!config.deterministic_order);
    }

    #[test]
    fn test_fast_preset() {
        let config = BatchConfig::fast();
        assert_eq!(config.batch_size, 100_000);
        assert!(config.parallel);
        assert_eq!(config.chunk_size, 10_000);
    }

    #[test]
    fn test_balanced_preset() {
        let config = BatchConfig::balanced();
        assert_eq!(config.batch_size, 50_000);
        assert!(config.parallel);
        assert!(config.memory_limit.is_some());
    }

    #[test]
    fn test_memory_efficient_preset() {
        let config = BatchConfig::memory_efficient();
        assert_eq!(config.chunk_size, 100);
        assert!(config.memory_limit.is_some());
    }

    #[test]
    fn test_builder_pattern() {
        let config = BatchConfig::new()
            .with_batch_size(50_000)
            .with_thread_count(Some(4))
            .with_chunk_size(500)
            .with_parallel(true);

        assert_eq!(config.batch_size, 50_000);
        assert_eq!(config.thread_count, Some(4));
        assert_eq!(config.chunk_size, 500);
        assert!(config.parallel);
    }

    #[test]
    fn test_validation_valid() {
        let config = BatchConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validation_invalid_batch_size() {
        let config = BatchConfig::default().with_batch_size(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_invalid_chunk_size() {
        let config = BatchConfig::default().with_chunk_size(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_invalid_thread_count() {
        let config = BatchConfig::default().with_thread_count(Some(0));
        assert!(config.validate().is_err());
    }
}
