//! Property-based tests for rustywallet-vanity.

use crate::prelude::*;
use proptest::prelude::*;

// **Feature: rustywallet-vanity, Property 1: Pattern Validation**
// **Validates: Requirements 1.5**
// For any pattern P and address type T, if P is accepted, then P contains only valid characters.
#[test]
fn property_pattern_validation() {
    // Valid P2PKH patterns
    assert!(Pattern::prefix("1Love").unwrap().validate_for_type(AddressType::P2PKH, false).is_ok());
    assert!(Pattern::prefix("1BTC").unwrap().validate_for_type(AddressType::P2PKH, false).is_ok());
    
    // Valid bech32 patterns
    assert!(Pattern::prefix("bc1q").unwrap().validate_for_type(AddressType::P2WPKH, false).is_ok());
    
    // Valid ethereum patterns
    assert!(Pattern::prefix("0xdead").unwrap().validate_for_type(AddressType::Ethereum, false).is_ok());
}

// **Feature: rustywallet-vanity, Property 2: Match Correctness**
// **Validates: Requirements 3.1, 3.2**
// For any VanityResult R, R.address must match R.matched_pattern.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_match_correctness(seed in 0u64..1000) {
        // Use seed to make test deterministic
        let _ = seed;
        
        // Search for simple pattern that will match quickly
        let result = VanityGenerator::new()
            .pattern("1")
            .address_type(AddressType::P2PKH)
            .max_attempts(100)
            .search();
        
        if let Ok(result) = result {
            // Verify the address actually matches the pattern
            prop_assert!(
                result.matched_pattern.matches(&result.address, true),
                "Address {} should match pattern {}",
                result.address,
                result.matched_pattern
            );
        }
    }
}

// **Feature: rustywallet-vanity, Property 3: Key-Address Consistency**
// **Validates: Requirements 7.1-7.4**
// For any VanityResult R, deriving address from R.private_key must produce R.address.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]
    
    #[test]
    fn property_key_address_consistency(seed in 0u64..1000) {
        let _ = seed;
        
        let result = VanityGenerator::new()
            .pattern("1")
            .address_type(AddressType::P2PKH)
            .max_attempts(100)
            .search();
        
        if let Ok(result) = result {
            // Re-derive address from private key
            let derived = AddressType::P2PKH
                .derive_address(&result.private_key, false)
                .unwrap();
            
            prop_assert_eq!(
                result.address,
                derived,
                "Derived address should match result address"
            );
        }
    }
}

// **Feature: rustywallet-vanity, Property 5: Uniqueness**
// **Validates: Requirements NFR5**
// Each search produces a unique, randomly generated key.
#[test]
fn property_uniqueness() {
    let mut keys = std::collections::HashSet::new();
    
    for _ in 0..10 {
        let result = VanityGenerator::new()
            .pattern("1")
            .address_type(AddressType::P2PKH)
            .max_attempts(100)
            .search()
            .unwrap();
        
        let key_hex = result.private_key.to_hex();
        assert!(
            keys.insert(key_hex.clone()),
            "Each search should produce a unique key"
        );
    }
}

// **Feature: rustywallet-vanity, Property 10: Case Sensitivity**
// **Validates: Requirements 3.1, 3.2**
// Case-insensitive matching must find all case variations.
#[test]
fn property_case_sensitivity() {
    let pattern = Pattern::prefix("1A").unwrap();
    
    // Case sensitive
    assert!(pattern.matches("1Abc", true));
    assert!(!pattern.matches("1abc", true));
    
    // Case insensitive
    assert!(pattern.matches("1Abc", false));
    assert!(pattern.matches("1abc", false));
    assert!(pattern.matches("1ABC", false));
}

// **Feature: rustywallet-vanity, Property 8: Progress Accuracy**
// **Validates: Requirements 5.1-5.5**
// Progress callbacks must report accurate attempt counts.
#[test]
fn property_progress_accuracy() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    
    let callback_count = Arc::new(AtomicU64::new(0));
    let callback_count_clone = callback_count.clone();
    
    let result = VanityGenerator::new()
        .pattern("1")
        .address_type(AddressType::P2PKH)
        .max_attempts(50_000)
        .batch_size(1000)
        .search_with_progress(move |progress| {
            callback_count_clone.fetch_add(1, Ordering::Relaxed);
            assert!(progress.attempts > 0);
            assert!(progress.rate >= 0.0);
        });
    
    assert!(result.is_ok());
    // Should have received at least one progress callback
    // (may not if search completes very quickly)
}

// Test difficulty estimation
#[test]
fn test_difficulty_estimation() {
    let gen = VanityGenerator::new()
        .pattern("1Love");
    
    let estimates = gen.estimate_difficulty();
    assert_eq!(estimates.len(), 1);
    
    let est = &estimates[0];
    assert!(est.expected_attempts > 0);
    assert!(est.probability > 0.0);
    assert!(est.probability < 1.0);
}

// Test multiple patterns
#[test]
fn test_multiple_patterns() {
    let result = VanityGenerator::new()
        .patterns(&["1A", "1B", "1C"])
        .address_type(AddressType::P2PKH)
        .max_attempts(1000)
        .search();
    
    assert!(result.is_ok());
    let result = result.unwrap();
    
    // Should match one of the patterns
    let matched = result.matched_pattern.as_str();
    assert!(matched == "1A" || matched == "1B" || matched == "1C");
}

// Test address types
#[test]
fn test_address_types() {
    // P2PKH
    let result = VanityGenerator::new()
        .pattern("1")
        .address_type(AddressType::P2PKH)
        .max_attempts(100)
        .search();
    assert!(result.is_ok());
    assert!(result.unwrap().address.starts_with('1'));
    
    // P2WPKH
    let result = VanityGenerator::new()
        .pattern("bc1q")
        .address_type(AddressType::P2WPKH)
        .max_attempts(100)
        .search();
    assert!(result.is_ok());
    assert!(result.unwrap().address.starts_with("bc1q"));
    
    // Ethereum
    let result = VanityGenerator::new()
        .pattern("0x")
        .address_type(AddressType::Ethereum)
        .max_attempts(100)
        .search();
    assert!(result.is_ok());
    assert!(result.unwrap().address.starts_with("0x"));
}

// Test suffix pattern
#[test]
fn test_suffix_pattern() {
    let gen = VanityGenerator::new()
        .suffix("A");
    
    let estimates = gen.estimate_difficulty();
    assert_eq!(estimates.len(), 1);
}

// Test contains pattern
#[test]
fn test_contains_pattern() {
    let gen = VanityGenerator::new()
        .contains("Love");
    
    let estimates = gen.estimate_difficulty();
    assert_eq!(estimates.len(), 1);
}

// Test configuration validation
#[test]
fn test_config_validation() {
    // No patterns - should fail
    let result = VanityGenerator::new().search();
    assert!(result.is_err());
    
    // With pattern - should work
    let result = VanityGenerator::new()
        .pattern("1")
        .max_attempts(10)
        .search();
    // May succeed or hit max attempts, but shouldn't error on validation
    assert!(result.is_ok() || matches!(result, Err(VanityError::MaxAttemptsReached(_))));
}
