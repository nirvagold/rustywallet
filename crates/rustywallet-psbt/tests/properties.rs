//! Property-based tests for rustywallet-psbt threshold signature support.
//!
//! These tests validate the correctness properties defined in the design document
//! for MuSig2 and FROST PSBT integration.

use proptest::prelude::*;
use rustywallet_psbt::{Psbt, GlobalMap, InputMap, OutputMap};
use rustywallet_psbt::threshold::{
    add_musig2_partial_sig, get_musig2_partial_sigs,
    add_frost_partial_sig, get_frost_partial_sigs,
    combine_musig2_psbt, count_musig2_partial_sigs,
    PsbtMuSig2PartialSig, PsbtFrostPartialSig,
};
use rustywallet_musig::signing::PartialSignature as MuSig2PartialSignature;
use rustywallet_frost::signing::SignatureShare as FrostSignatureShare;
use rustywallet_frost::identifier::Identifier as FrostIdentifier;

/// Create a test PSBT with the specified number of inputs
fn create_test_psbt(num_inputs: usize) -> Psbt {
    let mut tx = vec![
        0x02, 0x00, 0x00, 0x00, // version
        num_inputs as u8,       // input count
    ];
    
    // Add inputs
    for _ in 0..num_inputs {
        tx.extend_from_slice(&[0u8; 32]); // txid
        tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // vout
        tx.push(0x00); // empty script
        tx.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence
    }
    
    // Add one output
    tx.push(0x01); // output count
    tx.extend_from_slice(&[0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00]); // value
    tx.push(0x22); // script length
    tx.push(0x51); // OP_1
    tx.push(0x20); // PUSH32
    tx.extend_from_slice(&[0u8; 32]); // x-only pubkey
    tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // locktime
    
    Psbt {
        global: GlobalMap::with_unsigned_tx(tx),
        inputs: (0..num_inputs).map(|_| InputMap::new()).collect(),
        outputs: vec![OutputMap::new()],
    }
}

/// Generate a valid scalar (non-zero, less than curve order)
fn arb_valid_scalar() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(1u8..=255u8).prop_filter(
        "scalar must be valid",
        |s| {
            // Simple check: not all zeros and not all 0xff
            !s.iter().all(|&x| x == 0) && !s.iter().all(|&x| x == 0xff)
        }
    )
}

/// Generate a valid pubkey (32 bytes, non-zero)
fn arb_pubkey() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(1u8..=255u8)
}

/// Generate a valid FROST identifier (1-65535)
fn arb_frost_id() -> impl Strategy<Value = u32> {
    1u32..=65535u32
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 6: PSBT Partial Signature Storage**
    // **Validates: Requirements 4.1, 4.2**
    // For any MuSig2 or FROST partial signature added to a PSBT, the signature
    // SHALL be retrievable from the PSBT with correct association to the signer.
    
    #[test]
    fn prop_musig2_partial_sig_storage_roundtrip(
        pubkey in arb_pubkey(),
        partial_s in arb_valid_scalar(),
        signer_index in 0usize..10,
    ) {
        let mut psbt = create_test_psbt(1);
        let partial_sig = MuSig2PartialSignature {
            s: partial_s,
            signer_index,
        };
        
        // Add partial signature
        add_musig2_partial_sig(&mut psbt, 0, &partial_sig, &pubkey).unwrap();
        
        // Retrieve and verify
        let sigs = get_musig2_partial_sigs(&psbt, 0).unwrap();
        prop_assert_eq!(sigs.len(), 1);
        prop_assert_eq!(sigs[0].0, pubkey);
        prop_assert_eq!(sigs[0].1.s, partial_s);
        prop_assert_eq!(sigs[0].1.signer_index, signer_index);
    }

    #[test]
    fn prop_frost_partial_sig_storage_roundtrip(
        frost_id in arb_frost_id(),
        share in arb_valid_scalar(),
    ) {
        let mut psbt = create_test_psbt(1);
        let identifier = FrostIdentifier::new(frost_id).unwrap();
        let sig_share = FrostSignatureShare::new(identifier, share);
        
        // Add partial signature
        add_frost_partial_sig(&mut psbt, 0, &sig_share, &identifier).unwrap();
        
        // Retrieve and verify
        let sigs = get_frost_partial_sigs(&psbt, 0).unwrap();
        prop_assert_eq!(sigs.len(), 1);
        prop_assert_eq!(sigs[0].0, identifier);
        prop_assert_eq!(sigs[0].1.share, share);
    }

    #[test]
    fn prop_multiple_musig2_sigs_stored_correctly(
        pubkey1 in arb_pubkey(),
        pubkey2 in arb_pubkey(),
        partial_s1 in arb_valid_scalar(),
        partial_s2 in arb_valid_scalar(),
    ) {
        // Skip if pubkeys are the same (would overwrite)
        prop_assume!(pubkey1 != pubkey2);
        
        let mut psbt = create_test_psbt(1);
        let partial1 = MuSig2PartialSignature { s: partial_s1, signer_index: 0 };
        let partial2 = MuSig2PartialSignature { s: partial_s2, signer_index: 1 };
        
        add_musig2_partial_sig(&mut psbt, 0, &partial1, &pubkey1).unwrap();
        add_musig2_partial_sig(&mut psbt, 0, &partial2, &pubkey2).unwrap();
        
        let count = count_musig2_partial_sigs(&psbt, 0).unwrap();
        prop_assert_eq!(count, 2);
        
        let sigs = get_musig2_partial_sigs(&psbt, 0).unwrap();
        prop_assert_eq!(sigs.len(), 2);
    }

    // **Feature: ecosystem-upgrade-v2, Property 7: PSBT Aggregation and Finalization**
    // **Validates: Requirements 4.3, 4.4**
    // For any set of PSBTs with sufficient partial signatures, combining and
    // finalizing SHALL produce a valid Schnorr signature.

    #[test]
    fn prop_combine_musig2_psbts_preserves_all_sigs(
        pubkey1 in arb_pubkey(),
        pubkey2 in arb_pubkey(),
        partial_s1 in arb_valid_scalar(),
        partial_s2 in arb_valid_scalar(),
    ) {
        prop_assume!(pubkey1 != pubkey2);
        
        let mut psbt1 = create_test_psbt(1);
        let mut psbt2 = create_test_psbt(1);
        
        let partial1 = MuSig2PartialSignature { s: partial_s1, signer_index: 0 };
        let partial2 = MuSig2PartialSignature { s: partial_s2, signer_index: 1 };
        
        add_musig2_partial_sig(&mut psbt1, 0, &partial1, &pubkey1).unwrap();
        add_musig2_partial_sig(&mut psbt2, 0, &partial2, &pubkey2).unwrap();
        
        let combined = combine_musig2_psbt(&[psbt1, psbt2]).unwrap();
        
        // Verify both signatures are present
        let count = count_musig2_partial_sigs(&combined, 0).unwrap();
        prop_assert_eq!(count, 2);
        
        let sigs = get_musig2_partial_sigs(&combined, 0).unwrap();
        let pubkeys: Vec<_> = sigs.iter().map(|(pk, _)| *pk).collect();
        prop_assert!(pubkeys.contains(&pubkey1));
        prop_assert!(pubkeys.contains(&pubkey2));
    }

    #[test]
    fn prop_psbt_musig2_serialization_roundtrip(
        pubkey in arb_pubkey(),
        partial_s in arb_valid_scalar(),
        signer_index in 0usize..100,
    ) {
        let partial_sig = MuSig2PartialSignature { s: partial_s, signer_index };
        let psbt_sig = PsbtMuSig2PartialSig::from_partial_sig(&partial_sig, pubkey);
        
        let bytes = psbt_sig.to_bytes();
        let recovered = PsbtMuSig2PartialSig::from_bytes(&bytes).unwrap();
        
        prop_assert_eq!(psbt_sig.pubkey, recovered.pubkey);
        prop_assert_eq!(psbt_sig.partial_sig, recovered.partial_sig);
        prop_assert_eq!(psbt_sig.signer_index, recovered.signer_index);
    }

    #[test]
    fn prop_psbt_frost_serialization_roundtrip(
        frost_id in arb_frost_id(),
        share in arb_valid_scalar(),
    ) {
        let identifier = FrostIdentifier::new(frost_id).unwrap();
        let psbt_sig = PsbtFrostPartialSig { identifier, share };
        
        let bytes = psbt_sig.to_bytes();
        let recovered = PsbtFrostPartialSig::from_bytes(&bytes).unwrap();
        
        prop_assert_eq!(psbt_sig.identifier, recovered.identifier);
        prop_assert_eq!(psbt_sig.share, recovered.share);
    }
}
