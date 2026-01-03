//! Property-based tests for rustywallet-signer
//!
//! These tests verify correctness properties using proptest.

use proptest::prelude::*;
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_signer::schnorr::{SchnorrSigner, SchnorrVerifier};

/// Generate a valid private key (non-zero, less than curve order)
fn arb_private_key() -> impl Strategy<Value = PrivateKey> {
    // Generate 32 random bytes and create a private key
    // PrivateKey::from_bytes will handle validation
    prop::array::uniform32(1u8..=255u8).prop_filter_map("valid private key", |bytes| {
        PrivateKey::from_bytes(bytes).ok()
    })
}

/// Generate a random 32-byte message hash
fn arb_message_hash() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// **Feature: ecosystem-upgrade-v2, Property 1: Schnorr Sign-Verify Round-Trip**
    /// **Validates: Requirements 1.1, 1.2, 1.4**
    ///
    /// For any valid private key and message hash, signing with sign_schnorr()
    /// then verifying with verify_schnorr() SHALL return true.
    #[test]
    fn prop_schnorr_sign_verify_roundtrip(
        key in arb_private_key(),
        message in arb_message_hash(),
    ) {
        // Sign the message
        let signature = key.sign_schnorr(&message).expect("signing should succeed");
        
        // Get the x-only public key
        let pubkey = key.x_only_public_key();
        
        // Verify the signature
        prop_assert!(
            pubkey.verify_schnorr(&signature, &message),
            "Signature verification failed for valid key-message pair"
        );
    }

    /// Property: Schnorr signatures with auxiliary randomness should also verify
    /// **Validates: Requirements 1.1, 1.2**
    #[test]
    fn prop_schnorr_sign_with_aux_verifies(
        key in arb_private_key(),
        message in arb_message_hash(),
        aux_rand in arb_message_hash(),
    ) {
        // Sign with auxiliary randomness
        let signature = key.sign_schnorr_with_aux(&message, &aux_rand)
            .expect("signing with aux should succeed");
        
        // Get the x-only public key
        let pubkey = key.x_only_public_key();
        
        // Verify the signature
        prop_assert!(
            pubkey.verify_schnorr(&signature, &message),
            "Signature with aux randomness verification failed"
        );
    }

    /// Property: Different messages should produce different signatures
    /// (with high probability due to deterministic signing)
    /// **Validates: Requirements 1.1**
    #[test]
    fn prop_different_messages_different_signatures(
        key in arb_private_key(),
        message1 in arb_message_hash(),
        message2 in arb_message_hash(),
    ) {
        prop_assume!(message1 != message2);
        
        // Use deterministic signing (same aux rand)
        let aux = [0u8; 32];
        let sig1 = key.sign_schnorr_with_aux(&message1, &aux)
            .expect("signing should succeed");
        let sig2 = key.sign_schnorr_with_aux(&message2, &aux)
            .expect("signing should succeed");
        
        // Signatures should be different
        prop_assert_ne!(
            sig1.serialize(),
            sig2.serialize(),
            "Different messages should produce different signatures"
        );
    }

    /// Property: Wrong message should fail verification
    /// **Validates: Requirements 1.2**
    #[test]
    fn prop_wrong_message_fails_verification(
        key in arb_private_key(),
        message1 in arb_message_hash(),
        message2 in arb_message_hash(),
    ) {
        prop_assume!(message1 != message2);
        
        let signature = key.sign_schnorr(&message1).expect("signing should succeed");
        let pubkey = key.x_only_public_key();
        
        // Verification with wrong message should fail
        prop_assert!(
            !pubkey.verify_schnorr(&signature, &message2),
            "Verification should fail with wrong message"
        );
    }

    /// Property: Wrong key should fail verification
    /// **Validates: Requirements 1.2**
    #[test]
    fn prop_wrong_key_fails_verification(
        key1 in arb_private_key(),
        key2 in arb_private_key(),
        message in arb_message_hash(),
    ) {
        // Skip if keys happen to be the same (extremely unlikely)
        prop_assume!(key1.to_bytes() != key2.to_bytes());
        
        let signature = key1.sign_schnorr(&message).expect("signing should succeed");
        let wrong_pubkey = key2.x_only_public_key();
        
        // Verification with wrong key should fail
        prop_assert!(
            !wrong_pubkey.verify_schnorr(&signature, &message),
            "Verification should fail with wrong public key"
        );
    }
}
