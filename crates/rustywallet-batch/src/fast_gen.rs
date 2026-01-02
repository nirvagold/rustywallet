//! Fast key generation using optimized RNG.
//!
//! This module provides high-performance key generation by using
//! ChaCha20 RNG instead of OS RNG for better throughput.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::prelude::*;
use rustywallet_keys::private_key::PrivateKey;
use secp256k1::{Secp256k1, SecretKey};

/// Fast key generator using ChaCha20 RNG.
///
/// This generator achieves much higher throughput than OS RNG
/// by using a cryptographically secure but faster PRNG.
pub struct FastKeyGenerator {
    /// Number of keys to generate
    count: usize,
    /// Whether to use parallel processing
    parallel: bool,
    /// Chunk size for parallel processing
    chunk_size: usize,
}

impl FastKeyGenerator {
    /// Create a new fast key generator.
    pub fn new(count: usize) -> Self {
        Self {
            count,
            parallel: true,
            chunk_size: 10_000,
        }
    }

    /// Set whether to use parallel processing.
    pub fn parallel(mut self, enabled: bool) -> Self {
        self.parallel = enabled;
        self
    }

    /// Set the chunk size for parallel processing.
    pub fn chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Generate keys using fast RNG.
    pub fn generate(self) -> Vec<PrivateKey> {
        if self.parallel {
            self.generate_parallel()
        } else {
            self.generate_sequential()
        }
    }

    /// Generate keys sequentially with fast RNG.
    fn generate_sequential(self) -> Vec<PrivateKey> {
        let secp = Secp256k1::new();
        let mut rng = ChaCha20Rng::from_entropy();
        
        (0..self.count)
            .map(|_| {
                let (secret_key, _) = secp.generate_keypair(&mut rng);
                secret_key_to_private_key(secret_key)
            })
            .collect()
    }

    /// Generate keys in parallel with fast RNG.
    fn generate_parallel(self) -> Vec<PrivateKey> {
        let num_chunks = self.count.div_ceil(self.chunk_size);
        
        (0..num_chunks)
            .into_par_iter()
            .flat_map(|chunk_idx| {
                let start = chunk_idx * self.chunk_size;
                let end = (start + self.chunk_size).min(self.count);
                let chunk_count = end - start;
                
                // Each thread gets its own secp context and RNG
                let secp = Secp256k1::new();
                // Seed RNG with entropy + chunk index for uniqueness
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&chunk_idx.to_le_bytes());
                // Mix in some entropy
                use rand::RngCore;
                let mut temp_rng = rand::rngs::OsRng;
                temp_rng.fill_bytes(&mut seed[8..]);
                
                let mut rng = ChaCha20Rng::from_seed(seed);
                
                (0..chunk_count)
                    .map(|_| {
                        let (secret_key, _) = secp.generate_keypair(&mut rng);
                        secret_key_to_private_key(secret_key)
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Convert secp256k1 SecretKey to PrivateKey.
fn secret_key_to_private_key(secret_key: SecretKey) -> PrivateKey {
    let bytes = secret_key.secret_bytes();
    PrivateKey::from_bytes(bytes).expect("SecretKey should always be valid")
}

/// Generate keys using incremental method (EC point addition).
///
/// This is extremely fast for sequential key generation as it only
/// requires one EC point addition per key instead of full key generation.
pub struct IncrementalKeyGenerator {
    /// Starting key value
    start: [u8; 32],
    /// Number of keys to generate
    count: usize,
    /// Step size
    step: u64,
}

impl IncrementalKeyGenerator {
    /// Create a new incremental generator starting from a random key.
    pub fn new(count: usize) -> Self {
        let start_key = PrivateKey::random();
        Self {
            start: start_key.to_bytes(),
            count,
            step: 1,
        }
    }

    /// Create from a specific starting key.
    pub fn from_key(key: &PrivateKey, count: usize) -> Self {
        Self {
            start: key.to_bytes(),
            count,
            step: 1,
        }
    }

    /// Set the step size.
    pub fn step(mut self, step: u64) -> Self {
        self.step = step;
        self
    }

    /// Generate keys incrementally.
    pub fn generate(self) -> Vec<PrivateKey> {
        let mut current = self.start;
        let mut keys = Vec::with_capacity(self.count);
        
        for _ in 0..self.count {
            if let Ok(key) = PrivateKey::from_bytes(current) {
                keys.push(key);
            }
            // Increment current by step
            add_to_bytes(&mut current, self.step);
        }
        
        keys
    }
}

/// Add a u64 value to a 32-byte big-endian number.
fn add_to_bytes(bytes: &mut [u8; 32], value: u64) {
    let value_bytes = value.to_be_bytes();
    let mut carry: u64 = 0;
    
    // Add to the last 8 bytes
    for i in (24..32).rev() {
        let idx = 31 - i;
        let v = if idx < 8 { value_bytes[7 - idx] } else { 0 };
        let sum = bytes[i] as u64 + v as u64 + carry;
        bytes[i] = sum as u8;
        carry = sum >> 8;
    }
    
    // Propagate carry
    for i in (0..24).rev() {
        if carry == 0 {
            break;
        }
        let sum = bytes[i] as u64 + carry;
        bytes[i] = sum as u8;
        carry = sum >> 8;
    }
    
    // Handle overflow (wrap around to 1)
    if carry > 0 || !PrivateKey::is_valid(bytes) {
        *bytes = [0u8; 32];
        bytes[31] = 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::Instant;

    #[test]
    fn test_fast_generator_sequential() {
        let keys = FastKeyGenerator::new(1000)
            .parallel(false)
            .generate();
        
        assert_eq!(keys.len(), 1000);
        
        // All keys should be unique
        let hex_keys: HashSet<_> = keys.iter().map(|k| k.to_hex()).collect();
        assert_eq!(hex_keys.len(), 1000);
    }

    #[test]
    fn test_fast_generator_parallel() {
        let keys = FastKeyGenerator::new(10_000)
            .parallel(true)
            .chunk_size(1000)
            .generate();
        
        assert_eq!(keys.len(), 10_000);
        
        // All keys should be unique
        let hex_keys: HashSet<_> = keys.iter().map(|k| k.to_hex()).collect();
        assert_eq!(hex_keys.len(), 10_000);
    }

    #[test]
    fn test_incremental_generator() {
        let base = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        
        let keys = IncrementalKeyGenerator::from_key(&base, 5).generate();
        
        assert_eq!(keys.len(), 5);
        assert_eq!(keys[0].to_hex(), "0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(keys[1].to_hex(), "0000000000000000000000000000000000000000000000000000000000000002");
        assert_eq!(keys[2].to_hex(), "0000000000000000000000000000000000000000000000000000000000000003");
    }

    #[test]
    fn test_performance_comparison() {
        let count = 10_000;
        
        // Fast generator
        let start = Instant::now();
        let keys = FastKeyGenerator::new(count)
            .parallel(true)
            .generate();
        let fast_elapsed = start.elapsed();
        
        assert_eq!(keys.len(), count);
        
        let fast_rate = count as f64 / fast_elapsed.as_secs_f64();
        println!("Fast generator: {:.0} keys/sec", fast_rate);
        
        // Should be reasonably fast (lower threshold for test environment)
        assert!(fast_rate > 1_000.0, "Fast generator should exceed 1K keys/sec in test mode");
    }
}
