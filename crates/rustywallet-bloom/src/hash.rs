//! Fast hash functions for Bloom Filter
//!
//! Uses FNV-1a hash which is simple and fast for string hashing.

/// FNV-1a 64-bit hash
/// 
/// Fast non-cryptographic hash function, good for hash tables and bloom filters.
#[inline]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    
    let mut hash = FNV_OFFSET;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// FNV-1a 64-bit hash with seed
/// 
/// Variant that accepts a seed for generating multiple hash values.
#[inline]
pub fn fnv1a_64_seeded(data: &[u8], seed: u64) -> u64 {
    const FNV_PRIME: u64 = 0x100000001b3;
    
    let mut hash = seed;
    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Double hashing technique
/// 
/// Generates k hash values from two base hashes using:
/// h(i) = h1 + i * h2
/// 
/// This is more efficient than computing k independent hashes.
#[inline]
pub fn double_hash(h1: u64, h2: u64, i: usize, size: usize) -> usize {
    let h = h1.wrapping_add((i as u64).wrapping_mul(h2));
    (h % size as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_consistency() {
        let data = b"hello world";
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_fnv1a_different_inputs() {
        let h1 = fnv1a_64(b"hello");
        let h2 = fnv1a_64(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_double_hash_distribution() {
        let h1 = fnv1a_64(b"test");
        let h2 = fnv1a_64_seeded(b"test", 0x12345678);
        
        let size = 1000;
        let mut positions = Vec::new();
        
        for i in 0..7 {
            positions.push(double_hash(h1, h2, i, size));
        }
        
        // All positions should be different (with high probability)
        positions.sort();
        positions.dedup();
        assert!(positions.len() >= 5, "Too many collisions");
    }
}
