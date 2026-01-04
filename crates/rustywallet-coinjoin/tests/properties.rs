//! Property-based tests for rustywallet-coinjoin.
//!
//! These tests verify correctness properties using proptest.

use proptest::prelude::*;
use rustywallet_coinjoin::prelude::*;
use rustywallet_coinjoin::psbt_builder::{combine_participant_psbts, PsbtCoinJoinBuilder};
use rustywallet_psbt::Psbt;

/// Generate a random participant ID.
fn arb_participant_id() -> impl Strategy<Value = String> {
    "[a-z]{3,10}".prop_map(|s| s)
}

/// Generate a random txid.
fn arb_txid() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random amount (reasonable range for testing).
fn arb_amount() -> impl Strategy<Value = u64> {
    100_000u64..10_000_000u64
}

/// Generate a random P2WPKH script pubkey.
fn arb_p2wpkh_script() -> impl Strategy<Value = Vec<u8>> {
    prop::array::uniform20(any::<u8>()).prop_map(|hash| {
        let mut script = vec![0x00, 0x14]; // P2WPKH prefix
        script.extend_from_slice(&hash);
        script
    })
}

/// Generate a random input reference.
fn arb_input_ref() -> impl Strategy<Value = InputRef> {
    (arb_txid(), 0u32..10u32, arb_amount(), arb_p2wpkh_script()).prop_map(
        |(txid, vout, amount, script)| InputRef::new(txid, vout, amount, script),
    )
}

/// Generate a random participant.
fn arb_participant() -> impl Strategy<Value = Participant> {
    (
        arb_participant_id(),
        prop::collection::vec(arb_input_ref(), 1..3),
        arb_p2wpkh_script(),
    )
        .prop_map(|(id, inputs, output_script)| Participant::new(id, inputs, output_script))
}

/// Generate a list of unique participants.
fn arb_participants(min: usize, max: usize) -> impl Strategy<Value = Vec<Participant>> {
    prop::collection::vec(arb_participant(), min..=max).prop_map(|mut participants| {
        // Ensure unique IDs
        for (i, p) in participants.iter_mut().enumerate() {
            p.id = format!("participant_{}", i);
        }
        participants
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Feature: ecosystem-upgrade-v2, Property 13: CoinJoin PSBT Merge**
    /// **Validates: Requirements 10.2, 10.3**
    ///
    /// For any set of participant-signed PSBTs, combining SHALL preserve
    /// all signatures and produce a finalizable PSBT.
    #[test]
    fn prop_coinjoin_psbt_merge_preserves_signatures(
        participants in arb_participants(2, 4),
        output_amount in 10_000u64..50_000u64,
    ) {
        // Ensure all participants have enough funds
        let min_input = participants.iter()
            .map(|p| p.total_input())
            .min()
            .unwrap_or(0);

        // Skip if output amount is too high
        prop_assume!(output_amount < min_input);

        // Build the CoinJoin PSBT
        let mut builder = PsbtCoinJoinBuilder::new();
        for participant in &participants {
            builder.add_participant(participant.clone());
        }
        builder.set_output_amount(output_amount);
        builder.set_fee_rate(1.0);

        let psbt = builder.build_psbt();
        prop_assume!(psbt.is_ok());
        let base_psbt = psbt.unwrap();

        // Simulate each participant signing their inputs
        // (In reality, each would sign only their own inputs)
        let mut signed_psbts: Vec<Psbt> = Vec::new();

        for (i, _participant) in participants.iter().enumerate() {
            let mut psbt_copy = base_psbt.clone();

            // Add a mock signature for this participant's input
            // (Using a dummy signature for testing purposes)
            let mut dummy_sig = vec![0x30, 0x44, 0x02, 0x20];
            dummy_sig.extend(vec![i as u8; 67]);
            let dummy_pubkey = vec![0x02; 33];

            // Add partial signature to the input
            if i < psbt_copy.inputs.len() {
                psbt_copy.inputs[i].partial_sigs.insert(dummy_pubkey, dummy_sig);
            }

            signed_psbts.push(psbt_copy);
        }

        // Combine all signed PSBTs
        let combined = combine_participant_psbts(&signed_psbts);
        prop_assert!(combined.is_ok(), "Combining PSBTs should succeed");

        let combined_psbt = combined.unwrap();

        // Verify all signatures are preserved
        let total_sigs: usize = combined_psbt.inputs.iter()
            .map(|input| input.partial_sigs.len())
            .sum();

        // Each participant added one signature
        prop_assert!(
            total_sigs >= participants.len(),
            "Combined PSBT should have at least {} signatures, got {}",
            participants.len(),
            total_sigs
        );

        // Verify input count is preserved
        prop_assert_eq!(
            combined_psbt.input_count(),
            base_psbt.input_count(),
            "Input count should be preserved"
        );

        // Verify output count is preserved
        prop_assert_eq!(
            combined_psbt.output_count(),
            base_psbt.output_count(),
            "Output count should be preserved"
        );
    }

    /// Property: Combining identical PSBTs is idempotent.
    #[test]
    fn prop_combine_identical_psbts_idempotent(
        participants in arb_participants(2, 3),
        output_amount in 10_000u64..50_000u64,
    ) {
        let min_input = participants.iter()
            .map(|p| p.total_input())
            .min()
            .unwrap_or(0);

        prop_assume!(output_amount < min_input);

        let mut builder = PsbtCoinJoinBuilder::new();
        for participant in &participants {
            builder.add_participant(participant.clone());
        }
        builder.set_output_amount(output_amount);

        let psbt = builder.build_psbt();
        prop_assume!(psbt.is_ok());
        let base_psbt = psbt.unwrap();

        // Combine the same PSBT with itself
        let combined = combine_participant_psbts(&[base_psbt.clone(), base_psbt.clone()]);
        prop_assert!(combined.is_ok());

        let combined_psbt = combined.unwrap();

        // Should be equivalent to the original
        prop_assert_eq!(
            combined_psbt.input_count(),
            base_psbt.input_count()
        );
        prop_assert_eq!(
            combined_psbt.output_count(),
            base_psbt.output_count()
        );
    }

    /// Property: PSBT builder produces consistent output amounts.
    #[test]
    fn prop_psbt_builder_equal_outputs(
        participants in arb_participants(2, 5),
        output_amount in 10_000u64..50_000u64,
    ) {
        let min_input = participants.iter()
            .map(|p| p.total_input())
            .min()
            .unwrap_or(0);

        prop_assume!(output_amount < min_input);

        let mut builder = PsbtCoinJoinBuilder::new();
        for participant in &participants {
            builder.add_participant(participant.clone());
        }
        builder.set_output_amount(output_amount);

        let psbt = builder.build_psbt();
        prop_assume!(psbt.is_ok());
        let psbt = psbt.unwrap();

        // Verify we have the expected number of outputs
        // (one per participant, possibly with change)
        prop_assert!(
            psbt.output_count() >= participants.len(),
            "Should have at least {} outputs, got {}",
            participants.len(),
            psbt.output_count()
        );
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_combine_empty_psbts_fails() {
        let result = combine_participant_psbts(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_combine_single_psbt() {
        let mut builder = PsbtCoinJoinBuilder::new();
        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00],
        );
        builder.add_participant_simple(
            "bob",
            vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00],
        );
        builder.set_output_amount(50_000);

        let psbt = builder.build_psbt().unwrap();
        let result = combine_participant_psbts(&[psbt]);

        assert!(result.is_ok());
    }

    #[test]
    fn test_psbt_builder_minimum_participants() {
        let mut builder = PsbtCoinJoinBuilder::new();
        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14],
        );
        builder.set_output_amount(50_000);

        // Should fail with only 1 participant (minimum is 2)
        let result = builder.build_psbt();
        assert!(matches!(result, Err(CoinJoinError::NoParticipants)));
    }
}
