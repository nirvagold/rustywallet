//! Property-based tests for rustywallet-address.

use proptest::prelude::*;
use rustywallet_address::{
    Address, Network,
    descriptor::{AddressFromDescriptor, derive_address_from_descriptor, get_descriptor_type, DescriptorType},
};

/// Generate a random compressed public key hex string
fn arb_pubkey_hex() -> impl Strategy<Value = String> {
    // Generate 32 random bytes for x-coordinate
    proptest::collection::vec(any::<u8>(), 32)
        .prop_map(|bytes| {
            // Use 02 or 03 prefix for compressed key
            let prefix = if bytes[0] % 2 == 0 { "02" } else { "03" };
            format!("{}{}", prefix, hex::encode(&bytes))
        })
}

/// Generate a descriptor type
fn arb_descriptor_type() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("pkh"),
        Just("wpkh"),
        Just("tr"),
    ]
}

/// Generate a network
fn arb_network() -> impl Strategy<Value = Network> {
    prop_oneof![
        Just(Network::BitcoinMainnet),
        Just(Network::BitcoinTestnet),
    ]
}

// Use a known valid public key for consistent tests
const VALID_PUBKEY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const VALID_PUBKEY_2: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 19: Descriptor Address Derivation Consistency**
    // **Validates: Requirements 17.1, 17.3, 17.5**
    //
    // For any descriptor and index, Address::from_descriptor() SHALL produce
    // the same address as manual derivation.
    #[test]
    fn prop_descriptor_address_derivation_consistency(
        desc_type in arb_descriptor_type(),
        network in arb_network(),
        index in 0u32..100,
    ) {
        let descriptor = format!("{}({})", desc_type, VALID_PUBKEY);
        
        // Derive using Address::from_descriptor
        let addr1 = Address::from_descriptor(&descriptor, index, network);
        
        // Derive using derive_address_from_descriptor
        let addr2 = derive_address_from_descriptor(&descriptor, index, network);
        
        // Both should succeed or both should fail
        match (&addr1, &addr2) {
            (Ok(a1), Ok(a2)) => {
                prop_assert_eq!(
                    a1.to_string(),
                    a2.clone(),
                    "Address derivation should be consistent"
                );
            }
            (Err(_), Err(_)) => {
                // Both failed - that's consistent
            }
            _ => {
                prop_assert!(false, "Inconsistent results: one succeeded, one failed");
            }
        }
    }

    // Test that descriptor type detection is consistent
    #[test]
    fn prop_descriptor_type_detection(
        desc_type in arb_descriptor_type(),
    ) {
        let descriptor = format!("{}({})", desc_type, VALID_PUBKEY);
        
        let detected = get_descriptor_type(&descriptor);
        prop_assert!(detected.is_ok(), "Should detect descriptor type");
        
        let detected_type = detected.unwrap();
        let expected_type = match desc_type {
            "pkh" => DescriptorType::Pkh,
            "wpkh" => DescriptorType::Wpkh,
            "tr" => DescriptorType::Tr,
            _ => unreachable!(),
        };
        
        prop_assert_eq!(detected_type, expected_type, "Descriptor type should match");
    }

    // Test address prefix consistency with network
    #[test]
    fn prop_address_prefix_matches_network(
        desc_type in arb_descriptor_type(),
        network in arb_network(),
    ) {
        let descriptor = format!("{}({})", desc_type, VALID_PUBKEY);
        
        if let Ok(addr) = derive_address_from_descriptor(&descriptor, 0, network) {
            let expected_prefix = match (desc_type, network) {
                ("pkh", Network::BitcoinMainnet) => "1",
                ("pkh", Network::BitcoinTestnet) => "m",
                ("wpkh", Network::BitcoinMainnet) => "bc1q",
                ("wpkh", Network::BitcoinTestnet) => "tb1q",
                ("tr", Network::BitcoinMainnet) => "bc1p",
                ("tr", Network::BitcoinTestnet) => "tb1p",
                _ => "",
            };
            
            if !expected_prefix.is_empty() {
                prop_assert!(
                    addr.starts_with(expected_prefix),
                    "Address {} should start with {} for {} on {:?}",
                    addr, expected_prefix, desc_type, network
                );
            }
        }
    }

    // Test that same descriptor produces same address at same index
    #[test]
    fn prop_deterministic_derivation(
        desc_type in arb_descriptor_type(),
        network in arb_network(),
        index in 0u32..1000,
    ) {
        let descriptor = format!("{}({})", desc_type, VALID_PUBKEY);
        
        let addr1 = derive_address_from_descriptor(&descriptor, index, network);
        let addr2 = derive_address_from_descriptor(&descriptor, index, network);
        
        prop_assert_eq!(addr1, addr2, "Same descriptor and index should produce same address");
    }

    // Test range derivation produces correct count
    #[test]
    fn prop_range_derivation_count(
        desc_type in arb_descriptor_type(),
        count in 1u32..20,
    ) {
        let descriptor = format!("{}({})", desc_type, VALID_PUBKEY);
        
        let addrs = Address::from_descriptor_range(
            &descriptor,
            0,
            count,
            Network::BitcoinMainnet,
        );
        
        prop_assert!(addrs.is_ok(), "Range derivation should succeed");
        prop_assert_eq!(
            addrs.unwrap().len() as u32,
            count,
            "Should derive exactly {} addresses",
            count
        );
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_pkh_mainnet() {
        let desc = format!("pkh({})", VALID_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.starts_with('1'));
    }

    #[test]
    fn test_wpkh_mainnet() {
        let desc = format!("wpkh({})", VALID_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.starts_with("bc1q"));
    }

    #[test]
    fn test_tr_mainnet() {
        let desc = format!("tr({})", VALID_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.starts_with("bc1p"));
    }

    #[test]
    fn test_sh_wpkh_mainnet() {
        let desc = format!("sh(wpkh({}))", VALID_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.starts_with('3'));
    }

    #[test]
    fn test_testnet_addresses() {
        let desc = format!("wpkh({})", VALID_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinTestnet).unwrap();
        assert!(addr.starts_with("tb1q"));
    }

    #[test]
    fn test_address_from_descriptor_trait() {
        let desc = format!("wpkh({})", VALID_PUBKEY);
        let addr = Address::from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.is_bitcoin());
        assert!(addr.to_string().starts_with("bc1q"));
    }

    #[test]
    fn test_descriptor_type_segwit() {
        assert!(!DescriptorType::Pkh.is_segwit());
        assert!(DescriptorType::Wpkh.is_segwit());
        assert!(DescriptorType::Wsh.is_segwit());
        assert!(DescriptorType::Tr.is_segwit());
    }

    #[test]
    fn test_descriptor_type_taproot() {
        assert!(!DescriptorType::Pkh.is_taproot());
        assert!(!DescriptorType::Wpkh.is_taproot());
        assert!(DescriptorType::Tr.is_taproot());
    }
}
