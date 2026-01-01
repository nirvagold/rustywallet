//! # rustywallet-bloom
//!
//! Fast and memory-efficient Bloom Filter implementation optimized for
//! large datasets like cryptocurrency address lookups.
//!
//! ## Features
//!
//! - **Memory efficient**: ~1.2 bytes per item at 1% false positive rate
//! - **Fast**: Uses FNV-1a hash with double hashing technique
//! - **No dependencies**: Pure Rust implementation
//! - **Streaming insert**: Load millions of items efficiently
//!
//! ## Example
//!
//! ```rust
//! use rustywallet_bloom::BloomFilter;
//!
//! // Create filter for 1 million items with 1% false positive rate
//! let mut bloom = BloomFilter::new(1_000_000, 0.01);
//!
//! bloom.insert("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
//! bloom.insert("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
//!
//! assert!(bloom.contains("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
//! assert!(!bloom.contains("not_in_filter")); // probably false
//! ```

mod bloom;
mod hash;

pub use bloom::BloomFilter;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::BloomFilter;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut bloom = BloomFilter::new(1000, 0.01);
        
        bloom.insert("hello");
        bloom.insert("world");
        
        assert!(bloom.contains("hello"));
        assert!(bloom.contains("world"));
    }

    #[test]
    fn test_false_positive_rate() {
        let items = 10_000usize;
        let fpr = 0.01;
        let mut bloom = BloomFilter::new(items, fpr);
        
        // Insert items
        for i in 0..items {
            bloom.insert(&format!("item_{}", i));
        }
        
        // Check inserted items - should all be found
        for i in 0..items {
            assert!(bloom.contains(&format!("item_{}", i)));
        }
        
        // Check non-existent items - count false positives
        let test_count = 10_000;
        let mut false_positives = 0;
        for i in 0..test_count {
            if bloom.contains(&format!("nonexistent_{}", i)) {
                false_positives += 1;
            }
        }
        
        let actual_fpr = false_positives as f64 / test_count as f64;
        // Allow 3x tolerance for statistical variance
        assert!(actual_fpr < fpr * 3.0, 
            "FPR too high: {} (expected < {})", actual_fpr, fpr * 3.0);
    }

    #[test]
    fn test_memory_estimate() {
        let bloom = BloomFilter::new(1_000_000, 0.01);
        let bytes = bloom.memory_usage();
        
        // Should be around 1.2MB for 1M items at 1% FPR
        assert!(bytes > 1_000_000, "Too small: {} bytes", bytes);
        assert!(bytes < 2_000_000, "Too large: {} bytes", bytes);
    }
}
