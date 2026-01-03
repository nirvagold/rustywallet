//! Integration tests for FROST.

use crate::prelude::*;
use secp256k1::{Secp256k1, SecretKey, Message, Keypair};

/// Simple test: verify that DKG produces valid shares that can reconstruct the secret
#[test]
fn test_dkg_share_reconstruction() {
    let threshold = 2;
    let num_participants = 3;

    let mut p1 = DkgParticipant::new(Identifier::new(1).unwrap(), threshold, num_participants).unwrap();
    let mut p2 = DkgParticipant::new(Identifier::new(2).unwrap(), threshold, num_participants).unwrap();
    let mut p3 = DkgParticipant::new(Identifier::new(3).unwrap(), threshold, num_participants).unwrap();

    let r1_p1 = p1.round1().unwrap();
    let r1_p2 = p2.round1().unwrap();
    let r1_p3 = p3.round1().unwrap();

    for p in [&mut p1, &mut p2, &mut p3] {
        p.receive_round1(r1_p1.clone()).unwrap();
        p.receive_round1(r1_p2.clone()).unwrap();
        p.receive_round1(r1_p3.clone()).unwrap();
    }

    let r2_p1 = p1.round2().unwrap();
    let r2_p2 = p2.round2().unwrap();
    let r2_p3 = p3.round2().unwrap();

    for pkg in r2_p1.iter().chain(r2_p2.iter()).chain(r2_p3.iter()) {
        match pkg.receiver.value() {
            1 => p1.receive_round2(pkg.clone()).unwrap(),
            2 => p2.receive_round2(pkg.clone()).unwrap(),
            3 => p3.receive_round2(pkg.clone()).unwrap(),
            _ => unreachable!(),
        }
    }

    let (kp1, _pkp) = p1.finalize().unwrap();
    let (kp2, _) = p2.finalize().unwrap();
    let (kp3, _) = p3.finalize().unwrap();

    // Verify all have same group key
    assert_eq!(kp1.group_public_key(), kp2.group_public_key());
    assert_eq!(kp2.group_public_key(), kp3.group_public_key());

    // Verify that lambda_1 * s_1 + lambda_2 * s_2 reconstructs the secret
    // for participants 1 and 2
    let participants = vec![Identifier::new(1).unwrap(), Identifier::new(2).unwrap()];
    
    let lambda1 = crate::signing::compute_lagrange_coefficient(&participants[0], &participants).unwrap();
    let lambda2 = crate::signing::compute_lagrange_coefficient(&participants[1], &participants).unwrap();

    let term1 = crate::signing::scalar_mul(&lambda1, kp1.signing_share()).unwrap();
    let term2 = crate::signing::scalar_mul(&lambda2, kp2.signing_share()).unwrap();
    let reconstructed = crate::signing::scalar_add(&term1, &term2).unwrap();

    // The reconstructed secret should produce the group public key
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&reconstructed).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

    assert_eq!(pk.serialize(), *kp1.group_public_key());
}

#[test]
fn test_single_signer_schnorr() {
    // First verify that basic Schnorr signing works
    let secp = Secp256k1::new();
    let sk = SecretKey::new(&mut rand::thread_rng());
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = keypair.x_only_public_key();

    let msg = [0u8; 32];
    let message = Message::from_digest(msg);
    let sig = secp.sign_schnorr(&message, &keypair);

    assert!(secp.verify_schnorr(&sig, &message, &xonly).is_ok());
}

#[test]
fn test_nonce_reuse_prevention() {
    let signing_share = [42u8; 32];
    let mut nonces = SigningNonces::generate(&signing_share).unwrap();

    // First access works
    let _ = nonces.commitments().unwrap();

    // Mark as used
    nonces.mark_used();

    // Second access fails
    assert!(nonces.commitments().is_err());
}

#[test]
fn test_identifier_validation() {
    assert!(Identifier::new(0).is_err());
    assert!(Identifier::new(1).is_ok());
    assert!(Identifier::new(u32::MAX).is_ok());
}

#[test]
fn test_threshold_validation() {
    // Threshold 0 should fail
    assert!(DkgParticipant::new(Identifier::new(1).unwrap(), 0, 3).is_err());

    // Threshold > participants should fail
    assert!(DkgParticipant::new(Identifier::new(1).unwrap(), 4, 3).is_err());

    // Valid threshold should work
    assert!(DkgParticipant::new(Identifier::new(1).unwrap(), 2, 3).is_ok());
}

#[test]
fn test_signature_serialization() {
    let sig = Signature {
        r: [0xab; 32],
        s: [0xcd; 32],
    };

    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), 64);

    let recovered = Signature::from_bytes(&bytes).unwrap();
    assert_eq!(sig, recovered);

    let hex = sig.to_hex();
    let from_hex = Signature::from_hex(&hex).unwrap();
    assert_eq!(sig, from_hex);
}

#[test]
fn test_signature_share_serialization() {
    let id = Identifier::new(5).unwrap();
    let share = SignatureShare::new(id, [0x42; 32]);

    let bytes = share.to_bytes();
    assert_eq!(bytes.len(), 36);

    let recovered = SignatureShare::from_bytes(&bytes).unwrap();
    assert_eq!(share, recovered);

    let hex = share.to_hex();
    let from_hex = SignatureShare::from_hex(&hex).unwrap();
    assert_eq!(share, from_hex);
}

#[test]
fn test_group_public_key() {
    let sk = secp256k1::SecretKey::new(&mut rand::thread_rng());
    let gpk = GroupPublicKey::from_secret(&sk.secret_bytes()).unwrap();

    let bytes = gpk.to_bytes();
    assert_eq!(bytes.len(), 33);

    let recovered = GroupPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(gpk, recovered);

    let xonly = gpk.to_xonly().unwrap();
    assert_eq!(xonly.len(), 32);
}

#[test]
fn test_lagrange_coefficients_sum_to_one() {
    // For participants at x=1, x=2, the Lagrange coefficients should sum to 1
    // when evaluated at x=0 (to reconstruct the secret)
    let p1 = Identifier::new(1).unwrap();
    let p2 = Identifier::new(2).unwrap();
    let participants = vec![p1, p2];

    let lambda1 = crate::signing::compute_lagrange_coefficient(&p1, &participants).unwrap();
    let lambda2 = crate::signing::compute_lagrange_coefficient(&p2, &participants).unwrap();

    // lambda_1 = 2/(2-1) = 2
    // lambda_2 = 1/(1-2) = -1
    // lambda_1 + lambda_2 = 2 + (-1) = 1

    let sum = crate::signing::scalar_add(&lambda1, &lambda2).unwrap();
    
    // sum should be 1
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(sum, one);
}
