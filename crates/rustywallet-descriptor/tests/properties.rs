//! Property-based tests for rustywallet-descriptor
//!
//! Tests correctness properties using proptest.

use proptest::prelude::*;
use rustywallet_descriptor::taproot::TaprootDescriptor;
use rustywallet_address::Network;

// Test public keys for property tests
const TEST_PUBKEY_1: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const TEST_PUBKEY_2: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TEST_PUBKEY_3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

/// Strategy for generating valid public key hex strings
fn arb_pubkey() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(TEST_PUBKEY_1.to_string()),
        Just(TEST_PUBKEY_2.to_string()),
        Just(TEST_PUBKEY_3.to_string()),
    ]
}

/// Strategy for generating key-path only Taproot descriptors
fn arb_key_path_descriptor() -> impl Strategy<Value = String> {
    arb_pubkey().prop_map(|pk| format!("tr({})", pk))
}

/// Strategy for generating script-path Taproot descriptors with single leaf
fn arb_single_leaf_descriptor() -> impl Strategy<Value = String> {
    (arb_pubkey(), arb_pubkey()).prop_map(|(internal, leaf)| {
        format!("tr({},{{pk({})}})", internal, leaf)
    })
}

/// Strategy for generating script-path Taproot descriptors with two leaves
fn arb_two_leaf_descriptor() -> impl Strategy<Value = String> {
    (arb_pubkey(), arb_pubkey(), arb_pubkey()).prop_map(|(internal, leaf1, leaf2)| {
        format!("tr({},{{pk({}),pk({})}})", internal, leaf1, leaf2)
    })
}

/// Strategy for generating nested script tree descriptors
fn arb_nested_tree_descriptor() -> impl Strategy<Value = String> {
    (arb_pubkey(), arb_pubkey(), arb_pubkey(), arb_pubkey(), arb_pubkey())
        .prop_map(|(internal, l1, l2, l3, l4)| {
            format!("tr({},{{{{pk({}),pk({})}},{{pk({}),pk({})}}}})", internal, l1, l2, l3, l4)
        })
}

/// Strategy for generating any valid Taproot descriptor
fn arb_taproot_descriptor() -> impl Strategy<Value = String> {
    prop_oneof![
        arb_key_path_descriptor(),
        arb_single_leaf_descriptor(),
        arb_two_leaf_descriptor(),
        arb_nested_tree_descriptor(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 10: Taproot Descriptor Round-Trip**
    // **Validates: Requirements 7.4, 7.5**
    //
    // For any valid Taproot descriptor, parsing then serializing SHALL produce
    // an equivalent descriptor string.
    #[test]
    fn prop_taproot_descriptor_roundtrip(desc_str in arb_taproot_descriptor()) {
        // Parse the descriptor
        let parsed = TaprootDescriptor::parse(&desc_str)
            .expect("Should parse valid descriptor");
        
        // Serialize back to string
        let serialized = parsed.to_string();
        
        // Parse the serialized string
        let reparsed = TaprootDescriptor::parse(&serialized)
            .expect("Should parse serialized descriptor");
        
        // The two parsed descriptors should produce the same string
        prop_assert_eq!(
            parsed.to_string(),
            reparsed.to_string(),
            "Round-trip should preserve descriptor"
        );
    }

    // **Feature: ecosystem-upgrade-v2, Property 10: Taproot Descriptor Round-Trip (Address)**
    // **Validates: Requirements 7.4, 7.5**
    //
    // For any valid Taproot descriptor, deriving an address at any index should
    // produce a valid bc1p address, and the same descriptor should always produce
    // the same address at the same index.
    #[test]
    fn prop_taproot_address_derivation_consistency(
        desc_str in arb_taproot_descriptor(),
        index in 0u32..100
    ) {
        let parsed = TaprootDescriptor::parse(&desc_str)
            .expect("Should parse valid descriptor");
        
        // Derive address at index
        let address1 = parsed.derive_address(index, Network::BitcoinMainnet)
            .expect("Should derive address");
        
        // Address should start with bc1p (Taproot mainnet)
        prop_assert!(
            address1.starts_with("bc1p"),
            "Taproot address should start with bc1p, got: {}",
            address1
        );
        
        // Derive again - should be deterministic
        let address2 = parsed.derive_address(index, Network::BitcoinMainnet)
            .expect("Should derive address again");
        
        prop_assert_eq!(
            address1,
            address2,
            "Address derivation should be deterministic"
        );
    }

    // **Feature: ecosystem-upgrade-v2, Property 10: Taproot Descriptor Round-Trip (Script Tree)**
    // **Validates: Requirements 7.4, 7.5**
    //
    // For any Taproot descriptor with a script tree, the number of leaves should
    // be preserved after round-trip.
    #[test]
    fn prop_taproot_script_tree_leaves_preserved(
        desc_str in prop_oneof![
            arb_single_leaf_descriptor(),
            arb_two_leaf_descriptor(),
            arb_nested_tree_descriptor(),
        ]
    ) {
        let parsed = TaprootDescriptor::parse(&desc_str)
            .expect("Should parse valid descriptor");
        
        let original_leaves = parsed.script_tree()
            .map(|t| t.leaves().len())
            .unwrap_or(0);
        
        // Round-trip
        let serialized = parsed.to_string();
        let reparsed = TaprootDescriptor::parse(&serialized)
            .expect("Should parse serialized descriptor");
        
        let reparsed_leaves = reparsed.script_tree()
            .map(|t| t.leaves().len())
            .unwrap_or(0);
        
        prop_assert_eq!(
            original_leaves,
            reparsed_leaves,
            "Number of leaves should be preserved after round-trip"
        );
    }

    // **Feature: ecosystem-upgrade-v2, Property 10: Taproot Descriptor Round-Trip (Key Path)**
    // **Validates: Requirements 7.4, 7.5**
    //
    // For any key-path only Taproot descriptor, is_key_path_only() should return true
    // and be preserved after round-trip.
    #[test]
    fn prop_taproot_key_path_preserved(desc_str in arb_key_path_descriptor()) {
        let parsed = TaprootDescriptor::parse(&desc_str)
            .expect("Should parse valid descriptor");
        
        prop_assert!(
            parsed.is_key_path_only(),
            "Key-path descriptor should be key-path only"
        );
        
        // Round-trip
        let serialized = parsed.to_string();
        let reparsed = TaprootDescriptor::parse(&serialized)
            .expect("Should parse serialized descriptor");
        
        prop_assert!(
            reparsed.is_key_path_only(),
            "Key-path only should be preserved after round-trip"
        );
    }
}
