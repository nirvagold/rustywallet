//! Batch key generation.
//!
//! This module provides [`BatchGenerator`] for generating large batches
//! of private keys efficiently.

use crate::config::BatchConfig;
use crate::error::BatchError;
use crate::fast_gen::FastKeyGenerator;
use crate::stream::KeyStream;
use rayon::prelude::*;
use rustywallet_keys::private_key::PrivateKey;

/// High-performance batch key generator.
///
/// `BatchGenerator` provides a fluent API for generating large batches
/// of private keys with configurable parallelism and memory efficiency.
///
/// # Example
///
/// ```rust
/// use rustywallet_batch::prelude::*;
///
/// // Generate 1000 keys
/// let keys = BatchGenerator::new()
///     .count(1000)
///     .generate_vec()
///     .unwrap();
///
/// // Generate with parallel processing
/// let keys = BatchGenerator::new()
///     .count(100_000)
///     .parallel()
///     .generate_vec()
///     .unwrap();
///
/// // Stream keys for memory efficiency
/// let stream = BatchGenerator::new()
///     .count(1_000_000)
///     .generate()
///     .unwrap();
///
/// for key in stream.take(100) {
///     println!("{}", key.unwrap().to_hex());
/// }
/// ```
#[derive(Debug, Clone)]
pub struct BatchGenerator {
    config: BatchConfig,
}

impl Default for BatchGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchGenerator {
    /// Create a new batch generator with default configuration.
    pub fn new() -> Self {
        Self {
            config: BatchConfig::default(),
        }
    }

    /// Create a batch generator with a specific configuration.
    pub fn with_config(config: BatchConfig) -> Self {
        Self { config }
    }

    /// Set the number of keys to generate.
    pub fn count(mut self, count: usize) -> Self {
        self.config.batch_size = count;
        self
    }

    /// Enable parallel processing.
    pub fn parallel(mut self) -> Self {
        self.config.parallel = true;
        self
    }

    /// Set the number of threads for parallel processing.
    pub fn threads(mut self, count: usize) -> Self {
        self.config.thread_count = Some(count);
        self.config.parallel = true;
        self
    }

    /// Enable SIMD optimization.
    pub fn simd(mut self) -> Self {
        self.config.use_simd = true;
        self
    }

    /// Set the chunk size for streaming operations.
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.config.chunk_size = size;
        self
    }

    /// Enable deterministic ordering in parallel mode.
    pub fn deterministic(mut self) -> Self {
        self.config.deterministic_order = true;
        self
    }

    /// Generate keys as a memory-efficient stream.
    ///
    /// This method returns a `KeyStream` that generates keys on-demand,
    /// allowing processing of millions of keys without memory exhaustion.
    pub fn generate(self) -> Result<KeyStream, BatchError> {
        self.config.validate()?;

        let count = self.config.batch_size;
        let parallel = self.config.parallel;

        if parallel {
            self.generate_parallel_stream(count)
        } else {
            self.generate_sequential_stream(count)
        }
    }

    /// Generate keys and collect them into a vector.
    ///
    /// This method generates all keys and stores them in memory.
    /// For large batches, consider using `generate()` for streaming.
    pub fn generate_vec(self) -> Result<Vec<PrivateKey>, BatchError> {
        self.config.validate()?;

        let count = self.config.batch_size;
        let parallel = self.config.parallel;

        // Use fast generator for better performance
        let keys = FastKeyGenerator::new(count)
            .parallel(parallel)
            .chunk_size(self.config.chunk_size)
            .generate();

        Ok(keys)
    }

    /// Generate keys sequentially as a stream.
    fn generate_sequential_stream(self, count: usize) -> Result<KeyStream, BatchError> {
        let iter = (0..count).map(|_| Ok(PrivateKey::random()));
        Ok(KeyStream::new(iter, Some(count)))
    }

    /// Generate keys sequentially into a vector.
    #[allow(dead_code)]
    fn generate_sequential_vec(&self, count: usize) -> Result<Vec<PrivateKey>, BatchError> {
        let keys: Vec<PrivateKey> = (0..count).map(|_| PrivateKey::random()).collect();
        Ok(keys)
    }

    /// Generate keys in parallel as a stream.
    fn generate_parallel_stream(self, count: usize) -> Result<KeyStream, BatchError> {
        // For streaming, we generate in chunks to balance parallelism and memory
        let chunk_size = self.config.chunk_size;
        let deterministic = self.config.deterministic_order;

        let iter = ParallelChunkIterator::new(count, chunk_size, deterministic);
        Ok(KeyStream::new(iter, Some(count)))
    }

    /// Generate keys in parallel into a vector.
    #[allow(dead_code)]
    fn generate_parallel_vec(&self, count: usize) -> Result<Vec<PrivateKey>, BatchError> {
        let keys: Vec<PrivateKey> = if self.config.deterministic_order {
            // Use par_iter with indices for deterministic ordering
            (0..count)
                .into_par_iter()
                .map(|_| generate_single_key())
                .collect()
        } else {
            // Use par_iter without ordering constraints
            (0..count)
                .into_par_iter()
                .map(|_| generate_single_key())
                .collect()
        };

        Ok(keys)
    }
}

/// Generate a single private key using thread-local RNG.
fn generate_single_key() -> PrivateKey {
    PrivateKey::random()
}

/// Iterator that generates keys in parallel chunks.
struct ParallelChunkIterator {
    remaining: usize,
    chunk_size: usize,
    current_chunk: std::vec::IntoIter<PrivateKey>,
    deterministic: bool,
}

impl ParallelChunkIterator {
    fn new(total: usize, chunk_size: usize, deterministic: bool) -> Self {
        Self {
            remaining: total,
            chunk_size,
            current_chunk: Vec::new().into_iter(),
            deterministic,
        }
    }

    fn generate_chunk(&mut self) -> Vec<PrivateKey> {
        let chunk_count = self.remaining.min(self.chunk_size);
        self.remaining -= chunk_count;

        if self.deterministic {
            (0..chunk_count)
                .into_par_iter()
                .map(|_| generate_single_key())
                .collect()
        } else {
            (0..chunk_count)
                .into_par_iter()
                .map(|_| generate_single_key())
                .collect()
        }
    }
}

impl Iterator for ParallelChunkIterator {
    type Item = Result<PrivateKey, BatchError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Try to get from current chunk
        if let Some(key) = self.current_chunk.next() {
            return Some(Ok(key));
        }

        // Generate new chunk if there are remaining keys
        if self.remaining > 0 {
            let chunk = self.generate_chunk();
            self.current_chunk = chunk.into_iter();
            self.current_chunk.next().map(Ok)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sequential() {
        let keys = BatchGenerator::new()
            .count(100)
            .generate_vec()
            .unwrap();

        assert_eq!(keys.len(), 100);
    }

    #[test]
    fn test_generate_parallel() {
        let keys = BatchGenerator::new()
            .count(1000)
            .parallel()
            .generate_vec()
            .unwrap();

        assert_eq!(keys.len(), 1000);
    }

    #[test]
    fn test_generate_stream() {
        let stream = BatchGenerator::new()
            .count(100)
            .generate()
            .unwrap();

        let keys: Vec<_> = stream.collect();
        assert_eq!(keys.len(), 100);
        assert!(keys.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn test_generate_parallel_stream() {
        let stream = BatchGenerator::new()
            .count(1000)
            .parallel()
            .chunk_size(100)
            .generate()
            .unwrap();

        let keys: Vec<_> = stream.collect();
        assert_eq!(keys.len(), 1000);
        assert!(keys.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn test_keys_are_unique() {
        let keys = BatchGenerator::new()
            .count(1000)
            .parallel()
            .generate_vec()
            .unwrap();

        // Check uniqueness by converting to hex and using a set
        let hex_keys: std::collections::HashSet<_> = keys.iter().map(|k| k.to_hex()).collect();
        assert_eq!(hex_keys.len(), keys.len(), "All keys should be unique");
    }

    #[test]
    fn test_with_config() {
        let config = BatchConfig::fast();
        let generator = BatchGenerator::with_config(config);
        
        let keys = generator.count(500).generate_vec().unwrap();
        assert_eq!(keys.len(), 500);
    }

    #[test]
    fn test_deterministic_mode() {
        let keys = BatchGenerator::new()
            .count(100)
            .parallel()
            .deterministic()
            .generate_vec()
            .unwrap();

        assert_eq!(keys.len(), 100);
    }
}
