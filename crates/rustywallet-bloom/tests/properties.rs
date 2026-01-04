//! Property-based tests for rustywallet-bloom.

use proptest::prelude::*;
use rustywallet_bloom::{CountingBloomFilter, CountingBloomError};

/// Generate a random string for testing
fn arb_item() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9]{1,64}".prop_map(|s| s)
}

/// Generate a vector of unique items
fn arb_unique_items(max_count: usize) -> impl Strategy<Value = Vec<String>> {
    proptest::collection::hash_set(arb_item(), 1..=max_count)
        .prop_map(|set| set.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 17: Counting Bloom Filter Insert/Remove**
    // **Validates: Requirements 15.2, 15.3**
    //
    // For any item inserted then removed from a counting bloom filter,
    // the filter state SHALL be equivalent to never inserting the item
    // (assuming no hash collisions).
    #[test]
    fn prop_counting_bloom_insert_remove_roundtrip(
        items in arb_unique_items(50),
    ) {
        let mut filter = CountingBloomFilter::new(1000, 0.01);
        
        // Insert all items
        for item in &items {
            filter.insert(item);
        }
        
        // Verify all items are present
        for item in &items {
            prop_assert!(
                filter.contains(item),
                "Item {} should be present after insertion",
                item
            );
        }
        
        // Remove all items
        for item in &items {
            let result = filter.remove(item);
            prop_assert!(
                result.is_ok(),
                "Should be able to remove item {}",
                item
            );
        }
        
        // Verify all items are gone
        for item in &items {
            prop_assert!(
                !filter.contains(item),
                "Item {} should not be present after removal",
                item
            );
        }
        
        // Filter should be empty
        prop_assert_eq!(filter.len(), 0, "Filter should be empty after removing all items");
    }

    // Test that multiple insertions require multiple removals
    #[test]
    fn prop_counting_bloom_multiple_insert_remove(
        item in arb_item(),
        insert_count in 1usize..5,  // Keep small to avoid counter saturation
    ) {
        let mut filter = CountingBloomFilter::new(1000, 0.01);
        
        // Insert item multiple times
        for _ in 0..insert_count {
            filter.insert(&item);
        }
        
        prop_assert!(filter.contains(&item), "Item should be present");
        
        // Remove all but one - should still be present
        for i in 0..(insert_count - 1) {
            let result = filter.remove(&item);
            prop_assert!(result.is_ok(), "Should be able to remove (iteration {})", i);
        }
        
        // Item should still be present after partial removal
        // (unless counters saturated, which we avoid by keeping insert_count small)
        if insert_count <= 4 {
            prop_assert!(filter.contains(&item), "Item should still be present after partial removal");
        }
        
        // Final removal - should be gone
        let result = filter.remove(&item);
        prop_assert!(result.is_ok(), "Should be able to remove final time");
        prop_assert!(!filter.contains(&item), "Item should be gone after all removals");
    }

    // Test underflow protection
    #[test]
    fn prop_counting_bloom_underflow_protection(
        item in arb_item(),
    ) {
        let mut filter = CountingBloomFilter::new(1000, 0.01);
        
        // Try to remove item that was never inserted
        let result = filter.remove(&item);
        prop_assert_eq!(
            result,
            Err(CountingBloomError::CounterUnderflow),
            "Should get underflow error when removing non-existent item"
        );
        
        // Insert and remove once
        filter.insert(&item);
        filter.remove(&item).unwrap();
        
        // Try to remove again - should fail
        let result = filter.remove(&item);
        prop_assert_eq!(
            result,
            Err(CountingBloomError::CounterUnderflow),
            "Should get underflow error when removing already-removed item"
        );
    }

    // Test that clear resets the filter
    #[test]
    fn prop_counting_bloom_clear(
        items in arb_unique_items(20),
    ) {
        let mut filter = CountingBloomFilter::new(1000, 0.01);
        
        // Insert items
        for item in &items {
            filter.insert(item);
        }
        
        prop_assert!(!filter.is_empty(), "Filter should not be empty");
        
        // Clear
        filter.clear();
        
        prop_assert!(filter.is_empty(), "Filter should be empty after clear");
        prop_assert_eq!(filter.len(), 0, "Length should be 0 after clear");
        
        // All items should be gone
        for item in &items {
            prop_assert!(
                !filter.contains(item),
                "Item {} should not be present after clear",
                item
            );
        }
    }

    // Test count estimate accuracy
    #[test]
    fn prop_counting_bloom_count_estimate(
        item in arb_item(),
        insert_count in 1usize..10,
    ) {
        let mut filter = CountingBloomFilter::new(1000, 0.01);
        
        // Insert item multiple times
        for _ in 0..insert_count {
            filter.insert(&item);
        }
        
        let estimate = filter.count_estimate(&item);
        
        // Estimate should be at least the insert count (may be higher due to collisions)
        prop_assert!(
            estimate as usize >= insert_count,
            "Count estimate {} should be >= insert count {}",
            estimate,
            insert_count
        );
    }

    // Test that inserted items are always found (no false negatives)
    #[test]
    fn prop_counting_bloom_no_false_negatives(
        items in arb_unique_items(100),
    ) {
        let mut filter = CountingBloomFilter::new(1000, 0.01);
        
        // Insert all items
        for item in &items {
            filter.insert(item);
        }
        
        // All inserted items must be found
        for item in &items {
            prop_assert!(
                filter.contains(item),
                "Inserted item {} must be found (no false negatives allowed)",
                item
            );
        }
    }
}
