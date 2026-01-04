//! Property-based tests for rustywallet-recovery
//!
//! Tests correctness properties using proptest.

use proptest::prelude::*;
use rustywallet_recovery::{
    config::ScanPath,
    result::{FoundAddress, FoundUtxo, RecoveryResult},
};

/// Generate an arbitrary ScanPath
fn arb_scan_path() -> impl Strategy<Value = ScanPath> {
    prop_oneof![
        Just(ScanPath::Bip44),
        Just(ScanPath::Bip49),
        Just(ScanPath::Bip84),
        Just(ScanPath::Bip86),
    ]
}

/// Generate an arbitrary FoundAddress
fn arb_found_address() -> impl Strategy<Value = FoundAddress> {
    (
        "[a-zA-Z0-9]{10,50}",  // address
        "m/[0-9'/]+",          // path
        arb_scan_path(),
        0u32..10,              // account
        0u32..2,               // change
        0u32..1000,            // index
        0u64..1_000_000_000,   // balance
        0u32..1000,            // tx_count
    )
        .prop_map(|(address, path, scan_path, account, change, index, balance, tx_count)| {
            FoundAddress {
                address,
                path,
                scan_path,
                account,
                change,
                index,
                balance,
                tx_count,
            }
        })
}

/// Generate an arbitrary FoundUtxo
fn arb_found_utxo() -> impl Strategy<Value = FoundUtxo> {
    (
        "[a-f0-9]{64}",        // txid
        0u32..10,              // vout
        1u64..1_000_000_000,   // amount
        "[a-zA-Z0-9]{10,50}",  // address
        "m/[0-9'/]+",          // path
        0u32..1000,            // confirmations
        0u32..1_000_000,       // height
    )
        .prop_map(|(txid, vout, amount, address, path, confirmations, height)| {
            FoundUtxo {
                txid,
                vout,
                amount,
                address,
                path,
                confirmations,
                height,
            }
        })
}

/// Generate an arbitrary RecoveryResult with addresses and UTXOs
fn arb_recovery_result() -> impl Strategy<Value = RecoveryResult> {
    (
        prop::collection::vec(arb_found_address(), 0..5),
        prop::collection::vec(arb_found_utxo(), 0..5),
    )
        .prop_map(|(addresses, utxos)| {
            let mut result = RecoveryResult::new();
            for addr in addresses {
                result.add_address(addr);
            }
            for utxo in utxos {
                result.add_utxo(utxo);
            }
            result
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    // **Feature: ecosystem-upgrade-v2, Property 9: Recovery Result Aggregation**
    // **Validates: Requirements 6.5**
    //
    // For any parallel scan with multiple descriptors, the aggregated RecoveryResult
    // SHALL contain all found UTXOs from all scans.
    #[test]
    fn prop_recovery_result_aggregation_preserves_all_utxos(
        result1 in arb_recovery_result(),
        result2 in arb_recovery_result(),
    ) {
        // Record original counts
        let original_utxo_count = result1.utxos.len() + result2.utxos.len();
        let original_address_count = result1.addresses.len() + result2.addresses.len();
        let original_balance = result1.total_balance + result2.total_balance;

        // Merge results
        let mut merged = result1.clone();
        merged.merge(result2.clone());

        // Property: All UTXOs from both results are preserved
        prop_assert_eq!(
            merged.utxos.len(),
            original_utxo_count,
            "Merged result should contain all UTXOs from both results"
        );

        // Property: All addresses from both results are preserved
        prop_assert_eq!(
            merged.addresses.len(),
            original_address_count,
            "Merged result should contain all addresses from both results"
        );

        // Property: Total balance is sum of both results
        prop_assert_eq!(
            merged.total_balance,
            original_balance,
            "Merged total balance should equal sum of individual balances"
        );

        // Property: Stats are aggregated correctly
        prop_assert_eq!(
            merged.stats.total_utxos,
            result1.stats.total_utxos + result2.stats.total_utxos,
            "Merged UTXO count in stats should equal sum"
        );

        prop_assert_eq!(
            merged.stats.addresses_with_balance,
            result1.stats.addresses_with_balance + result2.stats.addresses_with_balance,
            "Merged addresses_with_balance should equal sum"
        );
    }

    // Property: Merging with empty result is identity
    #[test]
    fn prop_merge_with_empty_is_identity(
        result in arb_recovery_result(),
    ) {
        let original = result.clone();
        let empty = RecoveryResult::new();

        let mut merged = result.clone();
        merged.merge(empty);

        prop_assert_eq!(
            merged.utxos.len(),
            original.utxos.len(),
            "Merging with empty should preserve UTXOs"
        );

        prop_assert_eq!(
            merged.addresses.len(),
            original.addresses.len(),
            "Merging with empty should preserve addresses"
        );

        prop_assert_eq!(
            merged.total_balance,
            original.total_balance,
            "Merging with empty should preserve balance"
        );
    }

    // Property: Merge is associative for counts
    #[test]
    fn prop_merge_is_associative_for_counts(
        result1 in arb_recovery_result(),
        result2 in arb_recovery_result(),
        result3 in arb_recovery_result(),
    ) {
        // (result1 + result2) + result3
        let mut merged_left = result1.clone();
        merged_left.merge(result2.clone());
        merged_left.merge(result3.clone());

        // result1 + (result2 + result3)
        let mut merged_right = result2.clone();
        merged_right.merge(result3.clone());
        let mut final_right = result1.clone();
        final_right.merge(merged_right);

        // Counts should be the same regardless of merge order
        prop_assert_eq!(
            merged_left.utxos.len(),
            final_right.utxos.len(),
            "UTXO count should be same regardless of merge order"
        );

        prop_assert_eq!(
            merged_left.addresses.len(),
            final_right.addresses.len(),
            "Address count should be same regardless of merge order"
        );

        prop_assert_eq!(
            merged_left.total_balance,
            final_right.total_balance,
            "Total balance should be same regardless of merge order"
        );
    }

    // Property: Adding address updates balance correctly
    #[test]
    fn prop_add_address_updates_balance(
        addresses in prop::collection::vec(arb_found_address(), 1..5),
    ) {
        let mut result = RecoveryResult::new();
        let expected_balance: u64 = addresses.iter().map(|a| a.balance).sum();

        for addr in addresses {
            result.add_address(addr);
        }

        prop_assert_eq!(
            result.total_balance,
            expected_balance,
            "Total balance should equal sum of all address balances"
        );
    }

    // Property: Adding UTXO updates stats correctly
    #[test]
    fn prop_add_utxo_updates_stats(
        utxos in prop::collection::vec(arb_found_utxo(), 1..5),
    ) {
        let mut result = RecoveryResult::new();
        let expected_count = utxos.len() as u32;

        for utxo in utxos {
            result.add_utxo(utxo);
        }

        prop_assert_eq!(
            result.stats.total_utxos,
            expected_count,
            "UTXO count in stats should equal number of UTXOs added"
        );

        prop_assert_eq!(
            result.utxos.len() as u32,
            expected_count,
            "UTXO vector length should equal number of UTXOs added"
        );
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_empty_merge() {
        let mut result1 = RecoveryResult::new();
        let result2 = RecoveryResult::new();

        result1.merge(result2);

        assert_eq!(result1.total_balance, 0);
        assert!(result1.addresses.is_empty());
        assert!(result1.utxos.is_empty());
    }

    #[test]
    fn test_merge_preserves_all_data() {
        let mut result1 = RecoveryResult::new();
        result1.add_address(FoundAddress {
            address: "addr1".into(),
            path: "m/84'/0'/0'/0/0".into(),
            scan_path: ScanPath::Bip84,
            account: 0,
            change: 0,
            index: 0,
            balance: 100000,
            tx_count: 1,
        });
        result1.add_utxo(FoundUtxo {
            txid: "tx1".into(),
            vout: 0,
            amount: 100000,
            address: "addr1".into(),
            path: "m/84'/0'/0'/0/0".into(),
            confirmations: 6,
            height: 100,
        });

        let mut result2 = RecoveryResult::new();
        result2.add_address(FoundAddress {
            address: "addr2".into(),
            path: "m/44'/0'/0'/0/0".into(),
            scan_path: ScanPath::Bip44,
            account: 0,
            change: 0,
            index: 0,
            balance: 50000,
            tx_count: 2,
        });
        result2.add_utxo(FoundUtxo {
            txid: "tx2".into(),
            vout: 1,
            amount: 50000,
            address: "addr2".into(),
            path: "m/44'/0'/0'/0/0".into(),
            confirmations: 3,
            height: 103,
        });

        result1.merge(result2);

        assert_eq!(result1.total_balance, 150000);
        assert_eq!(result1.addresses.len(), 2);
        assert_eq!(result1.utxos.len(), 2);
        assert_eq!(result1.stats.total_utxos, 2);
        assert_eq!(result1.stats.addresses_with_balance, 2);
    }
}
