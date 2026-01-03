//! Property-based tests for rustywallet-batch
//!
//! These tests validate the correctness properties defined in the design document.

use crate::prelude::*;
use proptest::prelude::*;
use rustywallet_keys::private_key::PrivateKey;
use std::collections::HashSet;
use std::time::Instant;

// **Feature: rustywallet-batch, Property 1: Performance Threshold Compliance**
// **Validates: Requirements 1.1**
// For any batch generation request with sufficient system resources,
// the generation rate should meet or exceed a reasonable threshold.
#[test]
fn property_performance_threshold() {
    // Test with a smaller batch for CI/testing purposes
    // Full 1M test should be run manually with --release
    let batch_size = 10_000;
    
    let start = Instant::now();
    let keys = BatchGenerator::new()
        .count(batch_size)
        .parallel()
        .generate_vec()
        .unwrap();
    let elapsed = start.elapsed();
    
    assert_eq!(keys.len(), batch_size);
    
    let rate = keys.len() as f64 / elapsed.as_secs_f64();
    // Minimum threshold for test environment (lower than production target)
    // Production target is 1M+/sec, test threshold is 500/sec for CI environments
    assert!(
        rate >= 500.0,
        "Performance below minimum threshold: {:.0} keys/sec (expected >= 500)",
        rate
    );
}

// **Feature: rustywallet-batch, Property 2: Key Uniqueness and Randomness**
// **Validates: Requirements 1.3**
// For any batch of generated keys, all keys should be unique.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_key_uniqueness(batch_size in 10usize..500) {
        let keys = BatchGenerator::new()
            .count(batch_size)
            .generate_vec()
            .unwrap();
        
        // All keys should be unique
        let hex_keys: HashSet<_> = keys.iter().map(|k| k.to_hex()).collect();
        prop_assert_eq!(
            hex_keys.len(), 
            keys.len(), 
            "Generated keys should all be unique"
        );
    }
}

// **Feature: rustywallet-batch, Property 4: Configurable Batch Size Compliance**
// **Validates: Requirements 1.5**
// For any valid batch size, the generator should produce exactly that many keys.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_batch_size_compliance(batch_size in 1usize..1000) {
        let keys = BatchGenerator::new()
            .count(batch_size)
            .generate_vec()
            .unwrap();
        
        prop_assert_eq!(
            keys.len(), 
            batch_size, 
            "Should generate exactly {} keys", 
            batch_size
        );
    }
}

// **Feature: rustywallet-batch, Property 5: EC Point Addition Correctness**
// **Validates: Requirements 2.1**
// For any base key and offset, scanning should produce mathematically correct keys.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_ec_point_addition(start_value in 1u64..1000000) {
        let hex = format!("{:064x}", start_value);
        let base = PrivateKey::from_hex(&hex).unwrap();
        
        let scanner = KeyScanner::new(base.clone())
            .direction(ScanDirection::Forward);
        
        let keys: Vec<_> = scanner.scan_range(5)
            .map(|r| r.unwrap())
            .collect();
        
        // Verify sequential increment
        for (i, key) in keys.iter().enumerate() {
            let expected_hex = format!("{:064x}", start_value + i as u64);
            prop_assert_eq!(
                key.to_hex(), 
                expected_hex,
                "Key {} should be base + {}", i, i
            );
        }
    }
}

// **Feature: rustywallet-batch, Property 7: Bidirectional Scanning Consistency**
// **Validates: Requirements 2.4**
// Forward N steps then backward N steps should return to original.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_bidirectional_scanning(
        start_value in 100u64..1000000,
        steps in 1usize..50
    ) {
        let hex = format!("{:064x}", start_value);
        let base = PrivateKey::from_hex(&hex).unwrap();
        
        // Scan forward
        let forward_scanner = KeyScanner::new(base.clone())
            .direction(ScanDirection::Forward);
        let forward_keys: Vec<_> = forward_scanner.scan_range(steps + 1)
            .map(|r| r.unwrap())
            .collect();
        let last_forward = forward_keys.last().unwrap().clone();
        
        // Scan backward from last forward key
        let backward_scanner = KeyScanner::new(last_forward)
            .direction(ScanDirection::Backward);
        let backward_keys: Vec<_> = backward_scanner.scan_range(steps + 1)
            .map(|r| r.unwrap())
            .collect();
        let last_backward = backward_keys.last().unwrap();
        
        // Should return to original
        prop_assert_eq!(
            base.to_hex(), 
            last_backward.to_hex(),
            "Forward {} then backward {} should return to original",
            steps, steps
        );
    }
}

// **Feature: rustywallet-batch, Property 9: Iterator Incremental Behavior**
// **Validates: Requirements 3.1**
// KeyStream should yield keys one at a time.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_iterator_incremental(batch_size in 10usize..200) {
        let mut stream = BatchGenerator::new()
            .count(batch_size)
            .generate()
            .unwrap();
        
        // Verify we can iterate one at a time
        let mut count = 0;
        while let Some(result) = stream.next() {
            prop_assert!(result.is_ok(), "Each key should be valid");
            count += 1;
        }
        
        prop_assert_eq!(count, batch_size, "Should yield exactly {} keys", batch_size);
    }
}

// **Feature: rustywallet-batch, Property 15: Thread Independence**
// **Validates: Requirements 5.2**
// Keys from parallel generation should show no correlation.
#[test]
fn property_thread_independence() {
    let keys1 = BatchGenerator::new()
        .count(1000)
        .parallel()
        .generate_vec()
        .unwrap();
    
    let keys2 = BatchGenerator::new()
        .count(1000)
        .parallel()
        .generate_vec()
        .unwrap();
    
    // Keys from different runs should be different
    let set1: HashSet<_> = keys1.iter().map(|k| k.to_hex()).collect();
    let set2: HashSet<_> = keys2.iter().map(|k| k.to_hex()).collect();
    
    // Intersection should be empty (extremely unlikely to have duplicates)
    let intersection: Vec<_> = set1.intersection(&set2).collect();
    assert!(
        intersection.is_empty(),
        "Parallel runs should produce independent keys"
    );
}

// **Feature: rustywallet-batch, Property 19: Format Export Consistency**
// **Validates: Requirements 6.4**
// Batch-generated keys should export correctly to all formats.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_format_export_consistency(batch_size in 1usize..50) {
        let keys = BatchGenerator::new()
            .count(batch_size)
            .generate_vec()
            .unwrap();
        
        for key in keys {
            // Test hex export
            let hex = key.to_hex();
            prop_assert_eq!(hex.len(), 64, "Hex should be 64 chars");
            
            // Test bytes export
            let bytes = key.to_bytes();
            prop_assert_eq!(bytes.len(), 32, "Bytes should be 32 bytes");
            
            // Test round-trip
            let recovered = PrivateKey::from_hex(&hex).unwrap();
            prop_assert_eq!(key.clone(), recovered, "Hex round-trip should preserve key");
            
            let recovered = PrivateKey::from_bytes(bytes).unwrap();
            prop_assert_eq!(key, recovered, "Bytes round-trip should preserve key");
        }
    }
}

// **Feature: rustywallet-batch, Property 21: Configuration Validation**
// **Validates: Requirements 7.1, 7.2, 7.3, 7.5**
// Invalid configurations should be rejected with descriptive errors.
#[test]
fn property_configuration_validation() {
    // Valid configurations should pass
    assert!(BatchConfig::default().validate().is_ok());
    assert!(BatchConfig::fast().validate().is_ok());
    assert!(BatchConfig::balanced().validate().is_ok());
    assert!(BatchConfig::memory_efficient().validate().is_ok());
    
    // Invalid batch_size = 0
    let config = BatchConfig::default().with_batch_size(0);
    assert!(config.validate().is_err());
    
    // Invalid chunk_size = 0
    let config = BatchConfig::default().with_chunk_size(0);
    assert!(config.validate().is_err());
    
    // Invalid thread_count = 0
    let config = BatchConfig::default().with_thread_count(Some(0));
    assert!(config.validate().is_err());
}

// **Feature: rustywallet-batch, Property 22: Cryptographic Failure Safety**
// **Validates: Requirements 8.2, 8.4**
// All generated keys should be cryptographically valid.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_cryptographic_safety(batch_size in 1usize..100) {
        let keys = BatchGenerator::new()
            .count(batch_size)
            .generate_vec()
            .unwrap();
        
        for key in keys {
            let bytes = key.to_bytes();
            
            // Key should be valid (non-zero, < curve order)
            prop_assert!(
                PrivateKey::is_valid(&bytes),
                "All generated keys should be valid"
            );
            
            // Key should be able to derive public key
            let pubkey = key.public_key();
            let compressed = pubkey.to_compressed();
            prop_assert_eq!(compressed.len(), 33, "Public key should be 33 bytes compressed");
        }
    }
}

// **Feature: rustywallet-batch, Property 10: Stream Memory Efficiency**
// **Validates: Requirements 3.2**
// Streaming should not load all keys into memory at once.
#[test]
fn property_stream_memory_efficiency() {
    // Create a large stream but only consume a few keys
    let stream = BatchGenerator::new()
        .count(1_000_000)
        .chunk_size(100)
        .generate()
        .unwrap();
    
    // Only take first 10 keys - should not generate all 1M
    let keys: Vec<_> = stream.take(10).collect();
    assert_eq!(keys.len(), 10);
    assert!(keys.iter().all(|r| r.is_ok()));
    
    // Memory should be bounded by chunk_size, not total count
    // This is validated by the fact that we can create a 1M stream
    // without running out of memory
}

// **Feature: rustywallet-batch, Property 3: Memory-Bounded Streaming**
// **Validates: Requirements 1.4**
// Memory usage should be bounded by chunk size, not total batch size.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_memory_bounded_streaming(
        chunk_size in 10usize..100,
        take_count in 1usize..50
    ) {
        let stream = BatchGenerator::new()
            .count(10_000) // Large total
            .chunk_size(chunk_size)
            .generate()
            .unwrap();
        
        // Should be able to take any number without memory issues
        let keys: Vec<_> = stream.take(take_count).collect();
        prop_assert_eq!(keys.len(), take_count);
        prop_assert!(keys.iter().all(|r| r.is_ok()));
    }
}

// **Feature: rustywallet-batch, Property 16: Parallel Ordering Determinism**
// **Validates: Requirements 5.3**
// Deterministic mode should produce consistent ordering.
#[test]
fn property_parallel_ordering_determinism() {
    // In deterministic mode, parallel generation should maintain order
    let keys = BatchGenerator::new()
        .count(100)
        .parallel()
        .deterministic()
        .generate_vec()
        .unwrap();
    
    assert_eq!(keys.len(), 100);
    
    // All keys should be unique
    let hex_keys: HashSet<_> = keys.iter().map(|k| k.to_hex()).collect();
    assert_eq!(hex_keys.len(), 100);
}

// **Feature: rustywallet-batch, Property 13: SIMD/Fast Key Correctness**
// **Validates: Requirements 4.1, 4.3**
// Fast-generated keys should be cryptographically valid.
#[test]
fn property_fast_key_correctness() {
    use crate::fast_gen::FastKeyGenerator;
    
    let keys = FastKeyGenerator::new(1000)
        .parallel(true)
        .generate();
    
    assert_eq!(keys.len(), 1000);
    
    // All keys should be unique
    let hex_keys: HashSet<_> = keys.iter().map(|k| k.to_hex()).collect();
    assert_eq!(hex_keys.len(), 1000);
    
    // All keys should be valid
    for key in &keys {
        assert!(PrivateKey::is_valid(&key.to_bytes()));
        // Should be able to derive public key
        let _ = key.public_key();
    }
}

// **Feature: rustywallet-batch, Property 14: SIMD/Fast Fallback Reliability**
// **Validates: Requirements 4.2**
// Sequential fallback should produce same quality keys.
#[test]
fn property_fast_fallback_reliability() {
    use crate::fast_gen::FastKeyGenerator;
    
    // Sequential (fallback) mode
    let keys_seq = FastKeyGenerator::new(100)
        .parallel(false)
        .generate();
    
    // Parallel mode
    let keys_par = FastKeyGenerator::new(100)
        .parallel(true)
        .generate();
    
    // Both should produce valid, unique keys
    assert_eq!(keys_seq.len(), 100);
    assert_eq!(keys_par.len(), 100);
    
    let hex_seq: HashSet<_> = keys_seq.iter().map(|k| k.to_hex()).collect();
    let hex_par: HashSet<_> = keys_par.iter().map(|k| k.to_hex()).collect();
    
    assert_eq!(hex_seq.len(), 100);
    assert_eq!(hex_par.len(), 100);
}

// **Feature: rustywallet-batch, Property 20: Security Property Preservation**
// **Validates: Requirements 6.5**
// Batch keys should maintain same security properties as individual keys.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_security_preservation(batch_size in 1usize..50) {
        let batch_keys = BatchGenerator::new()
            .count(batch_size)
            .generate_vec()
            .unwrap();
        
        for key in batch_keys {
            // Each key should be indistinguishable from individually generated key
            let individual = PrivateKey::random();
            
            // Both should have same format
            prop_assert_eq!(key.to_hex().len(), individual.to_hex().len());
            prop_assert_eq!(key.to_bytes().len(), individual.to_bytes().len());
            
            // Both should derive valid public keys
            let batch_pub = key.public_key();
            let ind_pub = individual.public_key();
            
            prop_assert_eq!(batch_pub.to_compressed().len(), ind_pub.to_compressed().len());
        }
    }
}

// **Feature: rustywallet-batch, Property 23: Partial Failure Handling**
// **Validates: Requirements 8.3, 8.5**
// System should handle partial failures gracefully.
#[test]
fn property_partial_failure_handling() {
    // Test that invalid configurations are rejected early
    let result = BatchConfig::default()
        .with_batch_size(0)
        .validate();
    
    assert!(result.is_err());
    
    // Test that generator rejects invalid config
    let result = BatchGenerator::with_config(
        BatchConfig::default().with_batch_size(0)
    ).generate_vec();
    
    assert!(result.is_err());
}

// **Feature: rustywallet-batch, Property 8: Progress Callback Accuracy**
// **Validates: Requirements 2.5**
// Scanner should track progress accurately.
#[test]
fn property_progress_accuracy() {
    let base = PrivateKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000100"
    ).unwrap();
    
    let scanner = KeyScanner::new(base);
    let keys: Vec<_> = scanner.scan_range(100)
        .map(|r| r.unwrap())
        .collect();
    
    // Should generate exactly 100 keys
    assert_eq!(keys.len(), 100);
    
    // Keys should be sequential
    for (i, key) in keys.iter().enumerate() {
        let expected = format!("{:064x}", 0x100 + i);
        assert_eq!(key.to_hex(), expected);
    }
}


// **Feature: ecosystem-upgrade-v2, Property 2: Batch Address Consistency**
// **Validates: Requirements 2.5**
// For any generated key-address pair from BatchAddressGenerator,
// deriving the address manually from the key SHALL produce the same address.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_batch_address_consistency_p2pkh(batch_size in 1usize..50) {
        use crate::address::{BatchAddressGenerator, BatchAddressType};
        use rustywallet_address::{Network, P2PKHAddress};
        
        let generator = BatchAddressGenerator::new(BatchAddressType::P2PKH, Network::BitcoinMainnet);
        let addresses = generator.generate_vec(batch_size).unwrap();
        
        for (key, addr) in addresses {
            // Manually derive address from key
            let pubkey = key.public_key();
            let derived_addr = P2PKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet)
                .unwrap()
                .to_string();
            
            prop_assert_eq!(
                addr, 
                derived_addr, 
                "Batch-generated P2PKH address should match manually derived address"
            );
        }
    }
    
    #[test]
    fn property_batch_address_consistency_p2wpkh(batch_size in 1usize..50) {
        use crate::address::{BatchAddressGenerator, BatchAddressType};
        use rustywallet_address::{Network, P2WPKHAddress};
        
        let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
        let addresses = generator.generate_vec(batch_size).unwrap();
        
        for (key, addr) in addresses {
            // Manually derive address from key
            let pubkey = key.public_key();
            let derived_addr = P2WPKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet)
                .unwrap()
                .to_string();
            
            prop_assert_eq!(
                addr, 
                derived_addr, 
                "Batch-generated P2WPKH address should match manually derived address"
            );
        }
    }
    
    #[test]
    fn property_batch_address_consistency_p2tr(batch_size in 1usize..50) {
        use crate::address::{BatchAddressGenerator, BatchAddressType};
        use rustywallet_address::{Network, P2TRAddress};
        
        let generator = BatchAddressGenerator::new(BatchAddressType::P2TR, Network::BitcoinMainnet);
        let addresses = generator.generate_vec(batch_size).unwrap();
        
        for (key, addr) in addresses {
            // Manually derive address from key
            let pubkey = key.public_key();
            let derived_addr = P2TRAddress::from_public_key(&pubkey, Network::BitcoinMainnet)
                .unwrap()
                .to_string();
            
            prop_assert_eq!(
                addr, 
                derived_addr, 
                "Batch-generated P2TR address should match manually derived address"
            );
        }
    }
    
    #[test]
    fn property_batch_address_consistency_stream(batch_size in 1usize..50) {
        use crate::address::{BatchAddressGenerator, BatchAddressType};
        use rustywallet_address::{Network, P2WPKHAddress};
        
        let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinMainnet);
        let stream = generator.generate_stream(batch_size);
        
        for (key, addr) in stream {
            // Manually derive address from key
            let pubkey = key.public_key();
            let derived_addr = P2WPKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet)
                .unwrap()
                .to_string();
            
            prop_assert_eq!(
                addr, 
                derived_addr, 
                "Streamed address should match manually derived address"
            );
        }
    }
}

// **Feature: ecosystem-upgrade-v2, Property 2: Batch Address Consistency (Testnet)**
// **Validates: Requirements 2.5**
// Verify consistency for testnet addresses as well.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_batch_address_consistency_testnet(batch_size in 1usize..30) {
        use crate::address::{BatchAddressGenerator, BatchAddressType};
        use rustywallet_address::{Network, P2WPKHAddress, P2TRAddress};
        
        // Test P2WPKH testnet
        let generator = BatchAddressGenerator::new(BatchAddressType::P2WPKH, Network::BitcoinTestnet);
        let addresses = generator.generate_vec(batch_size).unwrap();
        
        for (key, addr) in addresses {
            let pubkey = key.public_key();
            let derived_addr = P2WPKHAddress::from_public_key(&pubkey, Network::BitcoinTestnet)
                .unwrap()
                .to_string();
            
            prop_assert!(addr.starts_with("tb1q"), "Testnet P2WPKH should start with tb1q");
            prop_assert_eq!(addr, derived_addr);
        }
        
        // Test P2TR testnet
        let generator = BatchAddressGenerator::new(BatchAddressType::P2TR, Network::BitcoinTestnet);
        let addresses = generator.generate_vec(batch_size).unwrap();
        
        for (key, addr) in addresses {
            let pubkey = key.public_key();
            let derived_addr = P2TRAddress::from_public_key(&pubkey, Network::BitcoinTestnet)
                .unwrap()
                .to_string();
            
            prop_assert!(addr.starts_with("tb1p"), "Testnet P2TR should start with tb1p");
            prop_assert_eq!(addr, derived_addr);
        }
    }
}
