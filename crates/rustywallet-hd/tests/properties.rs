//! Property-based tests for rustywallet-hd
//!
//! These tests verify correctness properties using proptest.

use proptest::prelude::*;
use rustywallet_hd::path::{DerivationPath, DerivationPathBuilder, ChildNumber, MAX_CHILD_INDEX};
use rustywallet_hd::slip39::{Slip39, Slip39MultiGroup, GroupConfig, MAX_SHARES, MIN_THRESHOLD};

/// Strategy for generating valid child indices (0 to MAX_CHILD_INDEX)
fn valid_index() -> impl Strategy<Value = u32> {
    0..=MAX_CHILD_INDEX
}

/// Strategy for generating a ChildNumber
fn arb_child_number() -> impl Strategy<Value = ChildNumber> {
    prop_oneof![
        valid_index().prop_map(|i| ChildNumber::Normal(i)),
        valid_index().prop_map(|i| ChildNumber::Hardened(i)),
    ]
}

/// Strategy for generating a vector of ChildNumbers (path components)
fn arb_path_components() -> impl Strategy<Value = Vec<ChildNumber>> {
    prop::collection::vec(arb_child_number(), 0..10)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 11: Derivation Path Round-Trip**
    // **Validates: Requirements 8.5**
    //
    // For any derivation path built with DerivationPathBuilder, the path SHALL be
    // parseable back to the same components.
    #[test]
    fn prop_derivation_path_roundtrip(components in arb_path_components()) {
        // Build path using builder
        let mut builder = DerivationPathBuilder::new();
        for child in &components {
            builder = match child {
                ChildNumber::Normal(i) => builder.normal(*i),
                ChildNumber::Hardened(i) => builder.hardened(*i),
            };
        }
        let path = builder.build().unwrap();

        // Convert to string and parse back
        let path_str = path.to_string();
        let parsed = DerivationPath::parse(&path_str).unwrap();

        // Verify components match
        prop_assert_eq!(path.components().len(), parsed.components().len());
        for (original, parsed_child) in path.components().iter().zip(parsed.components().iter()) {
            prop_assert_eq!(original, parsed_child);
        }
    }

    // Additional property: Builder produces same result as direct construction
    #[test]
    fn prop_builder_consistency(components in arb_path_components()) {
        // Build using builder
        let mut builder = DerivationPathBuilder::new();
        for child in &components {
            builder = match child {
                ChildNumber::Normal(i) => builder.normal(*i),
                ChildNumber::Hardened(i) => builder.hardened(*i),
            };
        }
        let built_path = builder.build().unwrap();

        // Build using from_components
        let direct_path = DerivationPath::from_components(components.clone());

        // Should be equal
        prop_assert_eq!(built_path.to_string(), direct_path.to_string());
    }

    // Property: Invalid indices are rejected
    #[test]
    fn prop_invalid_index_rejected(index in (MAX_CHILD_INDEX + 1)..=u32::MAX) {
        let result = DerivationPathBuilder::new()
            .hardened(index)
            .build();
        prop_assert!(result.is_err());

        let result2 = DerivationPathBuilder::new()
            .normal(index)
            .build();
        prop_assert!(result2.is_err());
    }

    // Property: BIP presets produce valid paths
    #[test]
    fn prop_bip_presets_valid(
        coin_type in valid_index(),
        account in valid_index(),
        change in 0u32..2,
        index in valid_index()
    ) {
        // BIP44
        let bip44 = DerivationPathBuilder::bip44(coin_type, account)
            .normal(change)
            .normal(index)
            .build()
            .unwrap();
        prop_assert_eq!(bip44.depth(), 5);
        prop_assert!(bip44.has_hardened());

        // BIP49
        let bip49 = DerivationPathBuilder::bip49(coin_type, account)
            .normal(change)
            .normal(index)
            .build()
            .unwrap();
        prop_assert_eq!(bip49.depth(), 5);

        // BIP84
        let bip84 = DerivationPathBuilder::bip84(coin_type, account)
            .normal(change)
            .normal(index)
            .build()
            .unwrap();
        prop_assert_eq!(bip84.depth(), 5);

        // BIP86
        let bip86 = DerivationPathBuilder::bip86(coin_type, account)
            .normal(change)
            .normal(index)
            .build()
            .unwrap();
        prop_assert_eq!(bip86.depth(), 5);
    }
}


// ========== SLIP39 Property Tests ==========

/// Strategy for generating valid threshold and share count pairs
fn valid_slip39_params() -> impl Strategy<Value = (u8, u8)> {
    (MIN_THRESHOLD..=MAX_SHARES).prop_flat_map(|threshold| {
        (Just(threshold), threshold..=MAX_SHARES)
    })
}

/// Strategy for generating valid secrets (16-64 bytes)
fn valid_secret() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 16..=64)
}

/// Strategy for generating valid group configurations
fn valid_group_config() -> impl Strategy<Value = GroupConfig> {
    valid_slip39_params().prop_map(|(threshold, share_count)| {
        GroupConfig::new(threshold, share_count).unwrap()
    })
}

/// Strategy for generating valid multi-group configurations
fn valid_multi_group_params() -> impl Strategy<Value = (u8, Vec<GroupConfig>)> {
    // Generate 1-4 groups
    prop::collection::vec(valid_group_config(), 1..=4).prop_flat_map(|groups| {
        let group_count = groups.len() as u8;
        (MIN_THRESHOLD..=group_count).prop_map(move |group_threshold| {
            (group_threshold, groups.clone())
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 18: SLIP39 Split/Combine Round-Trip**
    // **Validates: Requirements 16.1, 16.2, 16.5**
    //
    // For any valid seed and threshold configuration, splitting then combining
    // with threshold shares SHALL recover the original seed.
    #[test]
    fn prop_slip39_split_combine_roundtrip(
        (threshold, share_count) in valid_slip39_params(),
        secret in valid_secret()
    ) {
        let slip39 = Slip39::new(threshold, share_count).unwrap();
        let shares = slip39.split(&secret).unwrap();
        
        // Verify we got the expected number of shares
        prop_assert_eq!(shares.len(), share_count as usize);
        
        // Recover using exactly threshold shares
        let recovered = Slip39::combine(&shares[0..threshold as usize]).unwrap();
        prop_assert_eq!(secret, recovered);
    }

    // Property: Any subset of threshold shares can recover the secret
    #[test]
    fn prop_slip39_any_threshold_subset_recovers(
        (threshold, share_count) in valid_slip39_params(),
        secret in valid_secret()
    ) {
        let slip39 = Slip39::new(threshold, share_count).unwrap();
        let shares = slip39.split(&secret).unwrap();
        
        // Try recovering with different subsets of threshold shares
        // Use first threshold shares
        let recovered1 = Slip39::combine(&shares[0..threshold as usize]).unwrap();
        prop_assert_eq!(&secret, &recovered1);
        
        // Use last threshold shares (if different from first)
        if share_count > threshold {
            let start = (share_count - threshold) as usize;
            let recovered2 = Slip39::combine(&shares[start..]).unwrap();
            prop_assert_eq!(&secret, &recovered2);
        }
    }

    // Property: All shares have valid checksums
    #[test]
    fn prop_slip39_shares_have_valid_checksums(
        (threshold, share_count) in valid_slip39_params(),
        secret in valid_secret()
    ) {
        let slip39 = Slip39::new(threshold, share_count).unwrap();
        let shares = slip39.split(&secret).unwrap();
        
        for share in &shares {
            prop_assert!(share.validate(), "Share checksum validation failed");
        }
    }

    // Property: All shares have the same identifier
    #[test]
    fn prop_slip39_shares_same_identifier(
        (threshold, share_count) in valid_slip39_params(),
        secret in valid_secret()
    ) {
        let slip39 = Slip39::new(threshold, share_count).unwrap();
        let shares = slip39.split(&secret).unwrap();
        
        let identifier = shares[0].identifier;
        for share in &shares {
            prop_assert_eq!(share.identifier, identifier);
        }
    }

    // Property: Multi-group split/combine round-trip
    #[test]
    fn prop_slip39_multi_group_roundtrip(
        (group_threshold, groups) in valid_multi_group_params(),
        secret in valid_secret()
    ) {
        let multi = Slip39MultiGroup::new(group_threshold, groups.clone()).unwrap();
        let all_shares = multi.split(&secret).unwrap();
        
        // Verify we got the expected number of groups
        prop_assert_eq!(all_shares.len(), groups.len());
        
        // Collect enough shares from enough groups
        let mut combined_shares = Vec::new();
        for (group_idx, group_shares) in all_shares.iter().enumerate().take(group_threshold as usize) {
            let member_threshold = groups[group_idx].threshold as usize;
            combined_shares.extend(group_shares[0..member_threshold].iter().cloned());
        }
        
        let recovered = Slip39MultiGroup::combine(&combined_shares).unwrap();
        prop_assert_eq!(secret, recovered);
    }

    // Property: Insufficient shares fail to recover
    #[test]
    fn prop_slip39_insufficient_shares_fail(
        (threshold, share_count) in valid_slip39_params().prop_filter(
            "need threshold > 1 for this test",
            |(t, _)| *t > 1
        ),
        secret in valid_secret()
    ) {
        let slip39 = Slip39::new(threshold, share_count).unwrap();
        let shares = slip39.split(&secret).unwrap();
        
        // Try to recover with fewer than threshold shares
        let insufficient = threshold as usize - 1;
        let result = Slip39::combine(&shares[0..insufficient]);
        prop_assert!(result.is_err());
    }
}
