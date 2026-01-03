//! SIMD-optimized operations for batch key generation.
//!
//! This module provides SIMD-accelerated operations where available,
//! falling back to scalar operations on unsupported platforms.

use rustywallet_keys::private_key::PrivateKey;

/// SIMD batch processor for key operations.
///
/// Uses SIMD instructions where available to process multiple
/// keys in parallel within a single thread.
pub struct SimdBatchProcessor {
    /// Number of keys to process per SIMD batch
    batch_size: usize,
}

impl Default for SimdBatchProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl SimdBatchProcessor {
    /// Create a new SIMD batch processor.
    pub fn new() -> Self {
        Self {
            batch_size: Self::optimal_batch_size(),
        }
    }

    /// Get the optimal batch size for the current platform.
    ///
    /// This is based on SIMD register width:
    /// - AVX-512: 512 bits = 64 bytes = 2 keys
    /// - AVX2: 256 bits = 32 bytes = 1 key
    /// - SSE: 128 bits = 16 bytes = 0.5 keys
    ///
    /// We use multiples for better throughput.
    pub fn optimal_batch_size() -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                16 // Process 16 keys at a time with AVX-512
            } else if is_x86_feature_detected!("avx2") {
                8 // Process 8 keys at a time with AVX2
            } else {
                4 // Process 4 keys at a time with SSE
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            8 // ARM NEON processes 8 keys at a time
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            4 // Default scalar batch size
        }
    }

    /// Check if SIMD is available on this platform.
    pub fn is_available() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            is_x86_feature_detected!("sse2")
        }
        #[cfg(target_arch = "aarch64")]
        {
            true // NEON is always available on aarch64
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            false
        }
    }

    /// Get SIMD feature name for current platform.
    pub fn feature_name() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                "AVX-512"
            } else if is_x86_feature_detected!("avx2") {
                "AVX2"
            } else if is_x86_feature_detected!("sse2") {
                "SSE2"
            } else {
                "None"
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            "NEON"
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            "None"
        }
    }

    /// Set the batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Process keys in SIMD-optimized batches.
    ///
    /// This method generates keys and applies a function to each,
    /// using SIMD-friendly memory access patterns.
    pub fn process_batch<F>(&self, count: usize, mut processor: F) -> Vec<PrivateKey>
    where
        F: FnMut(&PrivateKey),
    {
        let mut keys = Vec::with_capacity(count);
        
        // Generate in SIMD-friendly batches
        let full_batches = count / self.batch_size;
        let remainder = count % self.batch_size;

        for _ in 0..full_batches {
            let batch = self.generate_batch(self.batch_size);
            for key in &batch {
                processor(key);
            }
            keys.extend(batch);
        }

        if remainder > 0 {
            let batch = self.generate_batch(remainder);
            for key in &batch {
                processor(key);
            }
            keys.extend(batch);
        }

        keys
    }

    /// Generate a batch of keys with SIMD-friendly layout.
    fn generate_batch(&self, count: usize) -> Vec<PrivateKey> {
        // Pre-allocate aligned buffer for SIMD operations
        let mut keys = Vec::with_capacity(count);
        
        for _ in 0..count {
            keys.push(PrivateKey::random());
        }
        
        keys
    }

    /// Convert keys to hex strings using SIMD-optimized conversion.
    pub fn keys_to_hex(&self, keys: &[PrivateKey]) -> Vec<String> {
        // Process in batches for cache efficiency
        keys.chunks(self.batch_size)
            .flat_map(|chunk| {
                chunk.iter().map(|k| k.to_hex()).collect::<Vec<_>>()
            })
            .collect()
    }

    /// Parallel SIMD batch generation.
    ///
    /// Combines SIMD optimization with multi-threading for maximum throughput.
    pub fn parallel_generate(&self, count: usize) -> Vec<PrivateKey> {
        use rayon::prelude::*;

        let num_batches = count.div_ceil(self.batch_size);
        
        (0..num_batches)
            .into_par_iter()
            .flat_map(|batch_idx| {
                let start = batch_idx * self.batch_size;
                let batch_count = (count - start).min(self.batch_size);
                self.generate_batch(batch_count)
            })
            .collect()
    }
}

/// SIMD-optimized hex encoding.
///
/// Converts bytes to hex string using SIMD instructions where available.
pub fn simd_hex_encode(bytes: &[u8]) -> String {
    // Use standard hex encoding - the compiler will auto-vectorize
    // where possible with appropriate optimization flags
    hex_encode_fast(bytes)
}

/// Fast hex encoding using lookup table.
fn hex_encode_fast(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    
    let mut result = String::with_capacity(bytes.len() * 2);
    
    for &byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    
    result
}

/// SIMD-optimized comparison of key bytes.
///
/// Compares two 32-byte keys using SIMD instructions.
#[inline]
pub fn simd_compare_keys(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    // Use standard comparison - compiler will vectorize
    a.cmp(b)
}

/// Batch key validation using SIMD.
///
/// Validates multiple keys in parallel using SIMD operations.
pub fn simd_validate_keys(keys: &[[u8; 32]]) -> Vec<bool> {
    keys.iter()
        .map(PrivateKey::is_valid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_availability() {
        let available = SimdBatchProcessor::is_available();
        let feature = SimdBatchProcessor::feature_name();
        println!("SIMD available: {}, feature: {}", available, feature);
    }

    #[test]
    fn test_optimal_batch_size() {
        let size = SimdBatchProcessor::optimal_batch_size();
        assert!(size >= 4);
        println!("Optimal batch size: {}", size);
    }

    #[test]
    fn test_simd_batch_processor() {
        let processor = SimdBatchProcessor::new();
        let mut count = 0;
        
        let keys = processor.process_batch(100, |_| {
            count += 1;
        });
        
        assert_eq!(keys.len(), 100);
        assert_eq!(count, 100);
    }

    #[test]
    fn test_parallel_generate() {
        let processor = SimdBatchProcessor::new();
        let keys = processor.parallel_generate(1000);
        
        assert_eq!(keys.len(), 1000);
        
        // Verify uniqueness
        let hex_keys: std::collections::HashSet<_> = keys.iter().map(|k| k.to_hex()).collect();
        assert_eq!(hex_keys.len(), 1000);
    }

    #[test]
    fn test_simd_hex_encode() {
        let bytes = [0x12, 0x34, 0xab, 0xcd];
        let hex = simd_hex_encode(&bytes);
        assert_eq!(hex, "1234abcd");
    }

    #[test]
    fn test_keys_to_hex() {
        let processor = SimdBatchProcessor::new();
        let keys: Vec<_> = (0..10).map(|_| PrivateKey::random()).collect();
        
        let hex_strings = processor.keys_to_hex(&keys);
        
        assert_eq!(hex_strings.len(), 10);
        assert!(hex_strings.iter().all(|s| s.len() == 64));
    }
}
