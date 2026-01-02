//! Memory-efficient key streaming.
//!
//! This module provides [`KeyStream`] for generating keys on-demand
//! without storing all keys in memory.

use crate::error::BatchError;
use rustywallet_keys::private_key::PrivateKey;

/// A memory-efficient stream of generated private keys.
///
/// `KeyStream` implements the `Iterator` trait, allowing keys to be
/// generated on-demand without storing all keys in memory.
///
/// # Example
///
/// ```rust
/// use rustywallet_batch::prelude::*;
///
/// let stream = BatchGenerator::new()
///     .count(1_000_000)
///     .generate()
///     .unwrap();
///
/// // Process keys one at a time
/// for key in stream.take(100) {
///     println!("{}", key.unwrap().to_hex());
/// }
/// ```
pub struct KeyStream {
    /// The inner iterator that generates keys.
    inner: Box<dyn Iterator<Item = Result<PrivateKey, BatchError>> + Send>,

    /// Total number of keys to generate (if known).
    total_count: Option<usize>,

    /// Number of keys generated so far.
    generated_count: usize,
}

impl KeyStream {
    /// Create a new key stream from an iterator.
    pub fn new<I>(iter: I, total_count: Option<usize>) -> Self
    where
        I: Iterator<Item = Result<PrivateKey, BatchError>> + Send + 'static,
    {
        Self {
            inner: Box::new(iter),
            total_count,
            generated_count: 0,
        }
    }

    /// Get the progress as a percentage (0.0 to 1.0).
    ///
    /// Returns `None` if the total count is unknown.
    pub fn progress(&self) -> Option<f64> {
        self.total_count.map(|total| {
            if total == 0 {
                1.0
            } else {
                self.generated_count as f64 / total as f64
            }
        })
    }

    /// Get the number of keys generated so far.
    pub fn generated(&self) -> usize {
        self.generated_count
    }

    /// Get the total number of keys to generate (if known).
    pub fn total(&self) -> Option<usize> {
        self.total_count
    }

    /// Get the number of remaining keys (if known).
    pub fn remaining(&self) -> Option<usize> {
        self.total_count.map(|total| total.saturating_sub(self.generated_count))
    }

    /// Collect a chunk of keys from the stream.
    ///
    /// This is useful for processing keys in batches while still
    /// maintaining memory efficiency.
    pub fn collect_chunk(&mut self, size: usize) -> Vec<Result<PrivateKey, BatchError>> {
        let mut chunk = Vec::with_capacity(size);
        for _ in 0..size {
            match self.next() {
                Some(key) => chunk.push(key),
                None => break,
            }
        }
        chunk
    }
}

impl Iterator for KeyStream {
    type Item = Result<PrivateKey, BatchError>;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.inner.next();
        if result.is_some() {
            self.generated_count += 1;
        }
        result
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.total_count {
            Some(total) => {
                let remaining = total.saturating_sub(self.generated_count);
                (remaining, Some(remaining))
            }
            None => (0, None),
        }
    }
}

impl ExactSizeIterator for KeyStream {
    fn len(&self) -> usize {
        self.total_count
            .map(|total| total.saturating_sub(self.generated_count))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_progress() {
        let keys: Vec<Result<PrivateKey, BatchError>> = (0..10)
            .map(|_| Ok(PrivateKey::random()))
            .collect();
        
        let mut stream = KeyStream::new(keys.into_iter(), Some(10));
        
        assert_eq!(stream.progress(), Some(0.0));
        assert_eq!(stream.generated(), 0);
        assert_eq!(stream.total(), Some(10));
        assert_eq!(stream.remaining(), Some(10));

        // Consume 5 keys
        for _ in 0..5 {
            stream.next();
        }

        assert_eq!(stream.progress(), Some(0.5));
        assert_eq!(stream.generated(), 5);
        assert_eq!(stream.remaining(), Some(5));
    }

    #[test]
    fn test_stream_collect_chunk() {
        let keys: Vec<Result<PrivateKey, BatchError>> = (0..100)
            .map(|_| Ok(PrivateKey::random()))
            .collect();
        
        let mut stream = KeyStream::new(keys.into_iter(), Some(100));
        
        let chunk = stream.collect_chunk(25);
        assert_eq!(chunk.len(), 25);
        assert_eq!(stream.generated(), 25);
        assert_eq!(stream.remaining(), Some(75));
    }

    #[test]
    fn test_stream_size_hint() {
        let keys: Vec<Result<PrivateKey, BatchError>> = (0..50)
            .map(|_| Ok(PrivateKey::random()))
            .collect();
        
        let mut stream = KeyStream::new(keys.into_iter(), Some(50));
        
        assert_eq!(stream.size_hint(), (50, Some(50)));
        
        for _ in 0..20 {
            stream.next();
        }
        
        assert_eq!(stream.size_hint(), (30, Some(30)));
    }
}
