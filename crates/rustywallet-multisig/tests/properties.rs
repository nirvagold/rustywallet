//! Property-based tests for rustywallet-multisig.
//!
//! These tests verify correctness properties using proptest.

use proptest::prelude::*;
use rustywallet_frost::prelude::{
    verify, DkgParticipant, Identifier, KeyPackage, PublicKeyPackage,
};
use rustywallet_multisig::frost::{FrostMultisig, FrostParticipant};

/// Run DKG for a given threshold and number of participants.
fn run_dkg(threshold: usize, num_participants: usize) -> (Vec<KeyPackage>, PublicKeyPackage) {
    let mut participants: Vec<DkgParticipant> = (1..=num_participants as u32)
        .map(|i| {
            DkgParticipant::new(Identifier::new(i).unwrap(), threshold, num_participants).unwrap()
        })
        .collect();

    // Round 1
    let r1_packages: Vec<_> = participants.iter_mut().map(|p| p.round1().unwrap()).collect();

    for p in &mut participants {
        for pkg in &r1_packages {
            p.receive_round1(pkg.clone()).unwrap();
        }
    }

    // Round 2
    let r2_packages: Vec<Vec<_>> = participants.iter().map(|p| p.round2().unwrap()).collect();

    for pkgs in &r2_packages {
        for pkg in pkgs {
            let receiver_idx = pkg.receiver.value() as usize - 1;
            participants[receiver_idx].receive_round2(pkg.clone()).unwrap();
        }
    }

    // Finalize
    let results: Vec<_> = participants.iter().map(|p| p.finalize().unwrap()).collect();
    let key_packages: Vec<_> = results.iter().map(|(kp, _)| kp.clone()).collect();
    let public_key_package = results[0].1.clone();

    (key_packages, public_key_package)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Feature: ecosystem-upgrade-v2, Property 12: FROST Multisig Aggregation**
    /// **Validates: Requirements 9.2, 9.3**
    ///
    /// *For any* FROST signing round with threshold partial signatures,
    /// aggregation SHALL produce a valid Schnorr signature.
    #[test]
    fn prop_frost_multisig_aggregation(
        message in prop::array::uniform32(any::<u8>()),
        // Use fixed threshold/participants for deterministic DKG
        // (proptest doesn't work well with complex setup)
    ) {
        // Run 2-of-3 DKG
        let (key_packages, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package.clone());

        // Start signing round
        let mut round = frost_multisig.start_signing(message);

        // Create participants (use first 2 for threshold)
        let mut p1 = FrostParticipant::new(key_packages[0].clone());
        let mut p2 = FrostParticipant::new(key_packages[1].clone());

        // Generate commitments
        let c1 = p1.generate_nonces().unwrap();
        let c2 = p2.generate_nonces().unwrap();

        // Add commitments
        round.add_commitment(p1.identifier(), c1).unwrap();
        round.add_commitment(p2.identifier(), c2).unwrap();
        round.finalize_commitments().unwrap();

        // Sign
        let sig1 = p1.sign(round.commitments(), &message).unwrap();
        let sig2 = p2.sign(round.commitments(), &message).unwrap();

        // Add partial signatures
        round.add_partial_sig(sig1).unwrap();
        round.add_partial_sig(sig2).unwrap();

        // Finalize
        prop_assert!(round.can_finalize(), "Should be able to finalize with threshold signatures");
        let signature = round.finalize().unwrap();

        // Verify the aggregated signature
        let group_pk = frost_multisig.group_public_key();
        let is_valid = verify(&signature, group_pk, &message).unwrap();
        prop_assert!(is_valid, "Aggregated signature should be valid");
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_frost_insufficient_signatures() {
        let (key_packages, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        let message = [0xab; 32];
        let mut round = frost_multisig.start_signing(message);

        // Add two signers for commitments (need threshold for commitment phase)
        let mut p1 = FrostParticipant::new(key_packages[0].clone());
        let mut p2 = FrostParticipant::new(key_packages[1].clone());
        
        let c1 = p1.generate_nonces().unwrap();
        let c2 = p2.generate_nonces().unwrap();
        
        round.add_commitment(p1.identifier(), c1).unwrap();
        round.add_commitment(p2.identifier(), c2).unwrap();
        round.finalize_commitments().unwrap();

        // Only add one signature (below threshold)
        let sig1 = p1.sign(round.commitments(), &message).unwrap();
        round.add_partial_sig(sig1).unwrap();

        // Should not be able to finalize with only 1 signature
        assert!(!round.can_finalize());
        assert!(round.finalize().is_err());
    }

    #[test]
    fn test_frost_duplicate_commitment_rejected() {
        let (key_packages, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        let message = [0xab; 32];
        let mut round = frost_multisig.start_signing(message);

        let mut p1 = FrostParticipant::new(key_packages[0].clone());
        let c1 = p1.generate_nonces().unwrap();
        round.add_commitment(p1.identifier(), c1.clone()).unwrap();

        // Try to add duplicate commitment
        let result = round.add_commitment(p1.identifier(), c1);
        assert!(result.is_err());
    }

    #[test]
    fn test_frost_duplicate_signature_rejected() {
        let (key_packages, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        let message = [0xab; 32];
        let mut round = frost_multisig.start_signing(message);

        let mut p1 = FrostParticipant::new(key_packages[0].clone());
        let mut p2 = FrostParticipant::new(key_packages[1].clone());

        let c1 = p1.generate_nonces().unwrap();
        let c2 = p2.generate_nonces().unwrap();

        round.add_commitment(p1.identifier(), c1).unwrap();
        round.add_commitment(p2.identifier(), c2).unwrap();
        round.finalize_commitments().unwrap();

        let sig1 = p1.sign(round.commitments(), &message).unwrap();
        round.add_partial_sig(sig1.clone()).unwrap();

        // Try to add duplicate signature
        let result = round.add_partial_sig(sig1);
        assert!(result.is_err());
    }
}
