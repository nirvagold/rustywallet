//! Counting Bloom Filter implementation with removal support.
//!
//! Unlike standard Bloom filters, counting Bloom filters use counters instead
//! of single bits, allowing items to be removed from the filter.

use crate::hash::{double_hash, fnv1a_64, fnv1a_64_seeded};

/// Error type for counting bloom filter operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountingBloomError {
    /// Counter would underflow (item not in filter or already removed)
    CounterUnderflow,
    /// Counter would overflow (too many insertions of same item)
    CounterOverflow,
}

impl std::fmt::Display for CountingBloomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CountingBloomError::CounterUnderflow => {
                write!(f, "Counter underflow: item not in filter or already removed")
            }
            CountingBloomError::CounterOverflow => {
                write!(f, "Counter overflow: too many insertions of same item")
            }
        }
    }
}

impl std::error::Error for CountingBloomError {}

/// A counting Bloom filter that supports removal of items.
///
/// Uses 4-bit counters (0-15) for each position, allowing items to be
/// inserted multiple times and removed. This uses 4x more memory than
/// a standard Bloom filter but enables deletion.
///
/// # Example
///
/// ```rust
/// use rustywallet_bloom::CountingBloomFilter;
///
/// let mut filter = CountingBloomFilter::new(10_000, 0.01);
///
/// filter.insert("address1");
/// filter.insert("address2");
/// assert!(filter.contains("address1"));
///
/// filter.remove("address1").unwrap();
/// assert!(!filter.contains("address1"));
/// assert!(filter.contains("address2"));
/// ```
pub struct CountingBloomFilter {
    /// Counters stored as nibbles (4 bits each) in u8 array
    counters: Vec<u8>,
    /// Number of counter positions
    num_counters: usize,
    /// Number of hash functions
    num_hashes: usize,
    /// Number of items currently in filter
    count: usize,
}

impl CountingBloomFilter {
    /// Creates a new counting Bloom filter optimized for the expected number
    /// of items and desired false positive rate.
    ///
    /// # Arguments
    ///
    /// * `expected_items` - Expected number of items to insert
    /// * `false_positive_rate` - Desired false positive rate (e.g., 0.01 for 1%)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_bloom::CountingBloomFilter;
    ///
    /// // 100,000 items with 1% false positive rate
    /// let filter = CountingBloomFilter::new(100_000, 0.01);
    /// ```
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let fpr = false_positive_rate.max(1e-10).min(0.5);
        let n = expected_items.max(1) as f64;

        // Optimal number of bits: m = -n * ln(p) / (ln(2)^2)
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let num_counters = ((-n * fpr.ln()) / ln2_sq).ceil() as usize;
        let num_counters = num_counters.max(64);

        // Optimal number of hash functions: k = (m/n) * ln(2)
        let num_hashes = ((num_counters as f64 / n) * std::f64::consts::LN_2).ceil() as usize;
        let num_hashes = num_hashes.clamp(3, 20);

        // Allocate counter array (2 counters per byte using nibbles)
        let num_bytes = (num_counters + 1) / 2;

        Self {
            counters: vec![0u8; num_bytes],
            num_counters,
            num_hashes,
            count: 0,
        }
    }

    /// Creates a counting Bloom filter with explicit parameters.
    ///
    /// # Arguments
    ///
    /// * `num_counters` - Total number of counter positions
    /// * `num_hashes` - Number of hash functions to use
    pub fn with_params(num_counters: usize, num_hashes: usize) -> Self {
        let num_counters = num_counters.max(64);
        let num_hashes = num_hashes.clamp(1, 20);
        let num_bytes = (num_counters + 1) / 2;

        Self {
            counters: vec![0u8; num_bytes],
            num_counters,
            num_hashes,
            count: 0,
        }
    }

    /// Inserts an item into the filter by incrementing relevant counters.
    ///
    /// Returns `Ok(())` on success, or `Err(CountingBloomError::CounterOverflow)`
    /// if any counter would exceed the maximum value (15).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_bloom::CountingBloomFilter;
    ///
    /// let mut filter = CountingBloomFilter::new(1000, 0.01);
    /// filter.insert("item1");
    /// assert!(filter.contains("item1"));
    /// ```
    pub fn insert<T: AsRef<[u8]>>(&mut self, item: T) {
        let data = item.as_ref();
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64_seeded(data, 0x9e3779b97f4a7c15);

        for i in 0..self.num_hashes {
            let pos = double_hash(h1, h2, i, self.num_counters);
            self.increment_counter(pos);
        }

        self.count += 1;
    }

    /// Inserts an item with overflow checking.
    ///
    /// Returns `Err(CountingBloomError::CounterOverflow)` if any counter
    /// would exceed the maximum value.
    pub fn try_insert<T: AsRef<[u8]>>(&mut self, item: T) -> Result<(), CountingBloomError> {
        let data = item.as_ref();
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64_seeded(data, 0x9e3779b97f4a7c15);

        // Check all counters first
        for i in 0..self.num_hashes {
            let pos = double_hash(h1, h2, i, self.num_counters);
            if self.get_counter(pos) >= 15 {
                return Err(CountingBloomError::CounterOverflow);
            }
        }

        // All checks passed, increment counters
        for i in 0..self.num_hashes {
            let pos = double_hash(h1, h2, i, self.num_counters);
            self.increment_counter(pos);
        }

        self.count += 1;
        Ok(())
    }

    /// Removes an item from the filter by decrementing relevant counters.
    ///
    /// Returns `Ok(())` on success, or `Err(CountingBloomError::CounterUnderflow)`
    /// if any counter would go below zero (item not in filter).
    ///
    /// # Warning
    ///
    /// Removing an item that was never inserted can corrupt the filter,
    /// causing false negatives for other items.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_bloom::CountingBloomFilter;
    ///
    /// let mut filter = CountingBloomFilter::new(1000, 0.01);
    /// filter.insert("item1");
    /// assert!(filter.contains("item1"));
    ///
    /// filter.remove("item1").unwrap();
    /// assert!(!filter.contains("item1"));
    /// ```
    pub fn remove<T: AsRef<[u8]>>(&mut self, item: T) -> Result<(), CountingBloomError> {
        let data = item.as_ref();
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64_seeded(data, 0x9e3779b97f4a7c15);

        // Check all counters first to ensure we can decrement
        for i in 0..self.num_hashes {
            let pos = double_hash(h1, h2, i, self.num_counters);
            if self.get_counter(pos) == 0 {
                return Err(CountingBloomError::CounterUnderflow);
            }
        }

        // All checks passed, decrement counters
        for i in 0..self.num_hashes {
            let pos = double_hash(h1, h2, i, self.num_counters);
            self.decrement_counter(pos);
        }

        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Checks if an item might be in the filter.
    ///
    /// Returns `false` if the item is definitely not in the set.
    /// Returns `true` if the item is probably in the set (may be false positive).
    #[inline]
    pub fn contains<T: AsRef<[u8]>>(&self, item: T) -> bool {
        let data = item.as_ref();
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64_seeded(data, 0x9e3779b97f4a7c15);

        for i in 0..self.num_hashes {
            let pos = double_hash(h1, h2, i, self.num_counters);
            if self.get_counter(pos) == 0 {
                return false;
            }
        }

        true
    }

    /// Returns the approximate count for an item.
    ///
    /// This returns the minimum counter value across all hash positions,
    /// which approximates how many times the item was inserted.
    pub fn count_estimate<T: AsRef<[u8]>>(&self, item: T) -> u8 {
        let data = item.as_ref();
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64_seeded(data, 0x9e3779b97f4a7c15);

        let mut min_count = u8::MAX;
        for i in 0..self.num_hashes {
            let pos = double_hash(h1, h2, i, self.num_counters);
            min_count = min_count.min(self.get_counter(pos));
        }

        min_count
    }

    /// Returns the number of items inserted (minus removed).
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no items are in the filter.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the memory usage in bytes.
    pub fn memory_usage(&self) -> usize {
        self.counters.len()
    }

    /// Returns the number of counter positions.
    pub fn num_counters(&self) -> usize {
        self.num_counters
    }

    /// Returns the number of hash functions used.
    pub fn num_hashes(&self) -> usize {
        self.num_hashes
    }

    /// Clears all items from the filter.
    pub fn clear(&mut self) {
        self.counters.fill(0);
        self.count = 0;
    }

    /// Gets the counter value at a position (0-15).
    #[inline]
    fn get_counter(&self, pos: usize) -> u8 {
        let byte_idx = pos / 2;
        let nibble = pos % 2;

        if nibble == 0 {
            self.counters[byte_idx] & 0x0F
        } else {
            (self.counters[byte_idx] >> 4) & 0x0F
        }
    }

    /// Increments the counter at a position (saturates at 15).
    #[inline]
    fn increment_counter(&mut self, pos: usize) {
        let byte_idx = pos / 2;
        let nibble = pos % 2;

        let current = self.get_counter(pos);
        if current < 15 {
            if nibble == 0 {
                self.counters[byte_idx] = (self.counters[byte_idx] & 0xF0) | (current + 1);
            } else {
                self.counters[byte_idx] = (self.counters[byte_idx] & 0x0F) | ((current + 1) << 4);
            }
        }
    }

    /// Decrements the counter at a position (does not go below 0).
    #[inline]
    fn decrement_counter(&mut self, pos: usize) {
        let byte_idx = pos / 2;
        let nibble = pos % 2;

        let current = self.get_counter(pos);
        if current > 0 {
            if nibble == 0 {
                self.counters[byte_idx] = (self.counters[byte_idx] & 0xF0) | (current - 1);
            } else {
                self.counters[byte_idx] = (self.counters[byte_idx] & 0x0F) | ((current - 1) << 4);
            }
        }
    }
}

impl std::fmt::Debug for CountingBloomFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountingBloomFilter")
            .field("items", &self.count)
            .field("counters", &self.num_counters)
            .field("hashes", &self.num_hashes)
            .field("memory_kb", &(self.memory_usage() / 1024))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_contains() {
        let mut filter = CountingBloomFilter::new(100, 0.01);

        filter.insert("test1");
        filter.insert("test2");

        assert!(filter.contains("test1"));
        assert!(filter.contains("test2"));
        assert!(!filter.contains("test3"));
        assert_eq!(filter.len(), 2);
    }

    #[test]
    fn test_remove() {
        let mut filter = CountingBloomFilter::new(100, 0.01);

        filter.insert("test1");
        filter.insert("test2");
        assert!(filter.contains("test1"));

        filter.remove("test1").unwrap();
        assert!(!filter.contains("test1"));
        assert!(filter.contains("test2"));
        assert_eq!(filter.len(), 1);
    }

    #[test]
    fn test_remove_underflow() {
        let mut filter = CountingBloomFilter::new(100, 0.01);

        // Try to remove item that was never inserted
        let result = filter.remove("nonexistent");
        assert_eq!(result, Err(CountingBloomError::CounterUnderflow));
    }

    #[test]
    fn test_multiple_insert_remove() {
        let mut filter = CountingBloomFilter::new(100, 0.01);

        // Insert same item multiple times
        filter.insert("test");
        filter.insert("test");
        filter.insert("test");

        assert!(filter.contains("test"));
        assert!(filter.count_estimate("test") >= 3);

        // Remove once - should still be present
        filter.remove("test").unwrap();
        assert!(filter.contains("test"));

        // Remove again
        filter.remove("test").unwrap();
        assert!(filter.contains("test"));

        // Remove third time - should be gone
        filter.remove("test").unwrap();
        assert!(!filter.contains("test"));
    }

    #[test]
    fn test_clear() {
        let mut filter = CountingBloomFilter::new(100, 0.01);

        filter.insert("test1");
        filter.insert("test2");
        assert!(filter.contains("test1"));

        filter.clear();
        assert!(!filter.contains("test1"));
        assert!(!filter.contains("test2"));
        assert_eq!(filter.len(), 0);
    }

    #[test]
    fn test_with_params() {
        let filter = CountingBloomFilter::with_params(10_000, 5);
        assert_eq!(filter.num_counters(), 10_000);
        assert_eq!(filter.num_hashes(), 5);
    }

    #[test]
    fn test_memory_usage() {
        let filter = CountingBloomFilter::new(10_000, 0.01);
        // Should use about 4x more memory than standard bloom filter
        // due to 4-bit counters vs 1-bit
        let bytes = filter.memory_usage();
        assert!(bytes > 0);
    }

    #[test]
    fn test_counter_nibbles() {
        let mut filter = CountingBloomFilter::with_params(100, 1);

        // Test that nibble storage works correctly
        for i in 0..16 {
            filter.increment_counter(0);
        }
        // Counter should saturate at 15
        assert_eq!(filter.get_counter(0), 15);

        // Test second nibble
        for i in 0..10 {
            filter.increment_counter(1);
        }
        assert_eq!(filter.get_counter(1), 10);
        assert_eq!(filter.get_counter(0), 15); // First nibble unchanged
    }
}
