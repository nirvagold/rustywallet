//! Bloom Filter implementation

use crate::hash::{double_hash, fnv1a_64, fnv1a_64_seeded};

/// A space-efficient probabilistic data structure for set membership testing.
///
/// Bloom filters can have false positives but never false negatives.
/// If `contains()` returns `false`, the item is definitely not in the set.
/// If `contains()` returns `true`, the item is probably in the set.
///
/// # Memory Usage
///
/// For a given number of items `n` and false positive rate `p`:
/// - Optimal bits: `m = -n * ln(p) / (ln(2)^2)` ≈ `n * 9.6` for 1% FPR
/// - Optimal hashes: `k = (m/n) * ln(2)` ≈ 7 for 1% FPR
///
/// # Example
///
/// ```rust
/// use rustywallet_bloom::BloomFilter;
///
/// let mut filter = BloomFilter::new(100_000, 0.01);
/// filter.insert("address1");
/// assert!(filter.contains("address1"));
/// ```
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
    count: usize,
}

impl BloomFilter {
    /// Creates a new Bloom filter optimized for the expected number of items
    /// and desired false positive rate.
    ///
    /// # Arguments
    ///
    /// * `expected_items` - Expected number of items to insert
    /// * `false_positive_rate` - Desired false positive rate (e.g., 0.01 for 1%)
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_bloom::BloomFilter;
    ///
    /// // 1 million items with 1% false positive rate
    /// let filter = BloomFilter::new(1_000_000, 0.01);
    /// ```
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        let fpr = false_positive_rate.clamp(1e-15, 0.5); // Allow ultra-low FPR
        let n = expected_items.max(1) as f64;
        
        // Optimal number of bits: m = -n * ln(p) / (ln(2)^2)
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let num_bits = ((-n * fpr.ln()) / ln2_sq).ceil() as usize;
        let num_bits = num_bits.max(64);
        
        // Optimal number of hash functions: k = (m/n) * ln(2)
        // Allow up to 50 hashes for ultra-low FPR
        let num_hashes = ((num_bits as f64 / n) * std::f64::consts::LN_2).ceil() as usize;
        let num_hashes = num_hashes.clamp(3, 50);
        
        // Allocate bit array (using u64 chunks)
        let num_words = num_bits.div_ceil(64);
        
        Self {
            bits: vec![0u64; num_words],
            num_bits,
            num_hashes,
            count: 0,
        }
    }

    /// Creates a Bloom filter with explicit parameters.
    ///
    /// Use this if you need precise control over the filter size.
    ///
    /// # Arguments
    ///
    /// * `num_bits` - Total number of bits in the filter
    /// * `num_hashes` - Number of hash functions to use
    pub fn with_params(num_bits: usize, num_hashes: usize) -> Self {
        let num_bits = num_bits.max(64);
        let num_hashes = num_hashes.clamp(1, 16);
        let num_words = num_bits.div_ceil(64);
        
        Self {
            bits: vec![0u64; num_words],
            num_bits,
            num_hashes,
            count: 0,
        }
    }

    /// Inserts an item into the filter.
    ///
    /// After insertion, `contains()` will always return `true` for this item.
    #[inline]
    pub fn insert<T: AsRef<[u8]>>(&mut self, item: T) {
        let data = item.as_ref();
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64_seeded(data, 0x9e3779b97f4a7c15); // Golden ratio
        
        for i in 0..self.num_hashes {
            let pos = double_hash(h1, h2, i, self.num_bits);
            self.set_bit(pos);
        }
        
        self.count += 1;
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
            let pos = double_hash(h1, h2, i, self.num_bits);
            if !self.get_bit(pos) {
                return false;
            }
        }
        
        true
    }

    /// Returns the number of items inserted.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no items have been inserted.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the memory usage in bytes.
    pub fn memory_usage(&self) -> usize {
        self.bits.len() * 8
    }

    /// Returns the number of bits in the filter.
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Returns the number of hash functions used.
    pub fn num_hashes(&self) -> usize {
        self.num_hashes
    }

    /// Returns the estimated false positive rate based on current fill.
    pub fn estimated_fpr(&self) -> f64 {
        let bits_set = self.bits.iter().map(|w| w.count_ones() as usize).sum::<usize>();
        let fill_ratio = bits_set as f64 / self.num_bits as f64;
        fill_ratio.powi(self.num_hashes as i32)
    }

    /// Clears all items from the filter.
    pub fn clear(&mut self) {
        self.bits.fill(0);
        self.count = 0;
    }

    #[inline]
    fn set_bit(&mut self, pos: usize) {
        let word = pos / 64;
        let bit = pos % 64;
        self.bits[word] |= 1u64 << bit;
    }

    #[inline]
    fn get_bit(&self, pos: usize) -> bool {
        let word = pos / 64;
        let bit = pos % 64;
        (self.bits[word] & (1u64 << bit)) != 0
    }
}

impl std::fmt::Debug for BloomFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BloomFilter")
            .field("items", &self.count)
            .field("bits", &self.num_bits)
            .field("hashes", &self.num_hashes)
            .field("memory_mb", &(self.memory_usage() / 1_000_000))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_contains() {
        let mut bloom = BloomFilter::new(100, 0.01);
        
        bloom.insert("test1");
        bloom.insert("test2");
        bloom.insert(b"binary_data");
        
        assert!(bloom.contains("test1"));
        assert!(bloom.contains("test2"));
        assert!(bloom.contains(b"binary_data"));
        assert_eq!(bloom.len(), 3);
    }

    #[test]
    fn test_clear() {
        let mut bloom = BloomFilter::new(100, 0.01);
        bloom.insert("test");
        assert!(bloom.contains("test"));
        
        bloom.clear();
        assert!(!bloom.contains("test"));
        assert_eq!(bloom.len(), 0);
    }

    #[test]
    fn test_with_params() {
        let bloom = BloomFilter::with_params(1_000_000, 5);
        assert_eq!(bloom.num_bits(), 1_000_000);
        assert_eq!(bloom.num_hashes(), 5);
    }

    #[test]
    fn test_large_dataset() {
        let n = 100_000;
        let mut bloom = BloomFilter::new(n, 0.01);
        
        for i in 0..n {
            bloom.insert(format!("addr_{}", i));
        }
        
        // All inserted items should be found
        for i in 0..n {
            assert!(bloom.contains(format!("addr_{}", i)));
        }
        
        assert_eq!(bloom.len(), n);
    }
}
