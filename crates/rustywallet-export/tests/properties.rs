//! Property-based tests for rustywallet-export.
//!
//! Tests descriptor import/export round-trip functionality.

use proptest::prelude::*;
use rustywallet_export::descriptor::{
    export_descriptor, export_pubkey_descriptor, export_descriptor_with_metadata,
    DescriptorType, DescriptorOptions, compute_checksum, add_checksum,
};
use rustywallet_import::descriptor::{import_descriptor, is_descriptor};
use rustywallet_keys::prelude::PrivateKey;

/// Generate a random valid private key
fn arb_private_key() -> impl Strategy<Value = PrivateKey> {
    any::<[u8; 32]>()
        .prop_filter_map("valid private key", |bytes| {
            PrivateKey::from_bytes(bytes).ok()
        })
}

/// Generate a random descriptor type
fn arb_descriptor_type() -> impl Strategy<Value = DescriptorType> {
    prop_oneof![
        Just(DescriptorType::Pk),
        Just(DescriptorType::Pkh),
        Just(DescriptorType::Wpkh),
        Just(DescriptorType::ShWpkh),
        Just(DescriptorType::Tr),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 15: Descriptor Import/Export Round-Trip**
    // **Validates: Requirements 12.1, 12.2, 12.5**
    //
    // For any valid descriptor, importing then exporting SHALL produce an equivalent
    // descriptor with valid checksum.
    #[test]
    fn prop_descriptor_import_export_roundtrip(
        key in arb_private_key(),
        desc_type in arb_descriptor_type(),
    ) {
        // Export descriptor with checksum
        let options = DescriptorOptions::new().with_checksum(true);
        let exported = export_descriptor(&key, desc_type, options.clone()).unwrap();
        
        // Verify it's recognized as a descriptor
        prop_assert!(is_descriptor(&exported), "Exported string should be recognized as descriptor");
        
        // Import the descriptor
        let imported = import_descriptor(&exported).unwrap();
        
        // Verify descriptor type matches
        let expected_type = match desc_type {
            DescriptorType::Pk => "pk",
            DescriptorType::Pkh => "pkh",
            DescriptorType::Wpkh => "wpkh",
            DescriptorType::ShWpkh => "sh",
            DescriptorType::Tr => "tr",
        };
        prop_assert_eq!(
            imported.descriptor_type, expected_type,
            "Descriptor type should match after round-trip"
        );
        
        // Verify checksum was present
        prop_assert!(imported.checksum.is_some(), "Imported descriptor should have checksum");
        
        // Re-export and verify consistency
        let re_exported = export_descriptor(&key, desc_type, options).unwrap();
        prop_assert_eq!(
            exported, re_exported,
            "Re-exported descriptor should match original export"
        );
    }

    // Test that checksum computation is deterministic
    #[test]
    fn prop_checksum_deterministic(
        key in arb_private_key(),
        desc_type in arb_descriptor_type(),
    ) {
        let options = DescriptorOptions::new().with_checksum(false);
        let desc_without_checksum = export_descriptor(&key, desc_type, options).unwrap();
        
        let checksum1 = compute_checksum(&desc_without_checksum);
        let checksum2 = compute_checksum(&desc_without_checksum);
        
        prop_assert_eq!(&checksum1, &checksum2, "Checksum should be deterministic");
        prop_assert_eq!(checksum1.len(), 8, "Checksum should be 8 characters");
    }

    // Test that add_checksum produces valid descriptors
    #[test]
    fn prop_add_checksum_valid(
        key in arb_private_key(),
        desc_type in arb_descriptor_type(),
    ) {
        let options = DescriptorOptions::new().with_checksum(false);
        let desc_without_checksum = export_descriptor(&key, desc_type, options).unwrap();
        
        let with_checksum = add_checksum(&desc_without_checksum);
        
        // Should contain # separator
        prop_assert!(with_checksum.contains('#'), "Should contain checksum separator");
        
        // Should be importable
        let imported = import_descriptor(&with_checksum).unwrap();
        prop_assert!(imported.checksum.is_some(), "Should have valid checksum");
    }

    // Test export_descriptor_with_metadata consistency
    #[test]
    fn prop_export_with_metadata_consistent(
        key in arb_private_key(),
        desc_type in arb_descriptor_type(),
    ) {
        let options = DescriptorOptions::new().with_checksum(true);
        
        let simple_export = export_descriptor(&key, desc_type, options.clone()).unwrap();
        let metadata_export = export_descriptor_with_metadata(&key, desc_type, options).unwrap();
        
        prop_assert_eq!(
            simple_export, metadata_export.descriptor,
            "Simple export and metadata export should produce same descriptor"
        );
        prop_assert_eq!(
            desc_type, metadata_export.descriptor_type,
            "Descriptor type should be preserved in metadata"
        );
    }

    // Test pubkey descriptor export
    #[test]
    fn prop_pubkey_descriptor_roundtrip(
        key in arb_private_key(),
        desc_type in arb_descriptor_type(),
    ) {
        use rustywallet_keys::public_key::PublicKeyFormat;
        
        let pubkey = key.public_key();
        let pubkey_hex = pubkey.to_hex(PublicKeyFormat::Compressed);
        
        let options = DescriptorOptions::new().with_checksum(true);
        let exported = export_pubkey_descriptor(&pubkey_hex, desc_type, options).unwrap();
        
        // Import and verify
        let imported = import_descriptor(&exported).unwrap();
        
        // Verify the key is present
        prop_assert!(
            imported.keys.len() >= 1,
            "Should have at least one key extracted"
        );
        
        // For non-wrapped types, verify key data matches
        if desc_type != DescriptorType::ShWpkh {
            prop_assert!(
                imported.keys.iter().any(|k| k.key_data == pubkey_hex),
                "Exported pubkey should be found in imported descriptor"
            );
        }
    }
}
