//! Property-based tests for rustywallet-tx advanced signing features.
//!
//! These tests verify the correctness properties defined in the design document.

use proptest::prelude::*;
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_musig::{
    signing::{create_partial_signature, verify_signature},
    AggregatedNonce, KeyAggContext, SecretNonce,
};
use rustywallet_frost::prelude::*;
use rustywallet_silent::{Network, SilentPaymentAddress, SilentPaymentScanner};
use rustywallet_tx::{
    create_musig2_session, finalize_musig2, finalize_frost, get_frost_sighash,
    create_silent_payment_outputs, sign_frost, Transaction, TxInput, TxOutput,
};
use rustywallet_taproot::TaprootSighashType;

/// Generate a random transaction value (1000 to 1_000_000 sats)
fn arb_tx_value() -> impl Strategy<Value = u64> {
    1000u64..1_000_000u64
}

/// Create a test transaction with the given output value
fn create_test_tx(output_value: u64) -> Transaction {
    let mut tx = Transaction::new();
    tx.version = 2;
    tx.inputs.push(TxInput::new([0u8; 32], 0));
    tx.outputs.push(TxOutput::new(
        output_value,
        vec![
            0x51, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    ));
    tx
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 3: MuSig2 Transaction Signing**
    // **Validates: Requirements 3.1**
    //
    // *For any* valid MuSig2 session and transaction, `sign_musig2()` SHALL produce
    // a signature that verifies against the aggregated public key.
    #[test]
    fn prop_musig2_transaction_signing(output_value in arb_tx_value()) {
        // Setup: 2-of-2 MuSig
        let sk1 = PrivateKey::random();
        let sk2 = PrivateKey::random();
        let pk1 = sk1.public_key().to_compressed();
        let pk2 = sk2.public_key().to_compressed();

        // Key aggregation
        let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
        let agg_pk = key_agg.xonly_pubkey();

        // Create transaction
        let mut tx = create_test_tx(output_value);
        let prevouts = vec![(output_value * 2, vec![0x51, 0x20])];

        // Create session and get sighash
        let session = create_musig2_session(&tx, 0, &prevouts, key_agg.clone()).unwrap();
        let sighash = *session.message();

        // Generate nonces
        let mut nonce1 =
            SecretNonce::generate(&sk1.to_bytes(), &pk1, agg_pk, Some(&sighash), None).unwrap();
        let mut nonce2 =
            SecretNonce::generate(&sk2.to_bytes(), &pk2, agg_pk, Some(&sighash), None).unwrap();

        let pub_nonce1 = nonce1.public_nonce().unwrap();
        let pub_nonce2 = nonce2.public_nonce().unwrap();
        let public_nonces = vec![pub_nonce1.clone(), pub_nonce2.clone()];

        // Aggregate nonces
        let agg_nonce = AggregatedNonce::aggregate(&public_nonces, agg_pk, &sighash).unwrap();

        // Find signer indices
        let idx1 = key_agg.index_of(&pk1).unwrap();
        let idx2 = key_agg.index_of(&pk2).unwrap();

        // Create partial signatures
        let partial1 = create_partial_signature(
            &mut nonce1,
            &sk1.to_bytes(),
            &key_agg,
            &agg_nonce,
            &public_nonces,
            &sighash,
            idx1,
        )
        .unwrap();

        let partial2 = create_partial_signature(
            &mut nonce2,
            &sk2.to_bytes(),
            &key_agg,
            &agg_nonce,
            &public_nonces,
            &sighash,
            idx2,
        )
        .unwrap();

        // Finalize
        let sig = finalize_musig2(
            &mut tx,
            0,
            &[partial1, partial2],
            &agg_nonce,
            &key_agg,
            TaprootSighashType::Default,
        )
        .unwrap();

        // Property: signature verifies against aggregated public key
        prop_assert!(verify_signature(&sig, agg_pk, &sighash).unwrap());

        // Property: witness was correctly set
        prop_assert!(!tx.inputs[0].witness.is_empty());
        prop_assert_eq!(tx.inputs[0].witness[0].len(), 64); // Schnorr sig without sighash byte
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 4: FROST Threshold Signing**
    // **Validates: Requirements 3.2**
    //
    // *For any* valid FROST key shares (meeting threshold) and transaction,
    // `sign_frost()` SHALL produce a signature that verifies against the group public key.
    #[test]
    fn prop_frost_threshold_signing(output_value in arb_tx_value()) {
        // Setup: 2-of-3 FROST
        let threshold = 2;
        let num_participants = 3;

        // Create DKG participants
        let mut p1 = DkgParticipant::new(Identifier::new(1).unwrap(), threshold, num_participants).unwrap();
        let mut p2 = DkgParticipant::new(Identifier::new(2).unwrap(), threshold, num_participants).unwrap();
        let mut p3 = DkgParticipant::new(Identifier::new(3).unwrap(), threshold, num_participants).unwrap();

        // Round 1
        let r1_p1 = p1.round1().unwrap();
        let r1_p2 = p2.round1().unwrap();
        let r1_p3 = p3.round1().unwrap();

        for p in [&mut p1, &mut p2, &mut p3] {
            p.receive_round1(r1_p1.clone()).unwrap();
            p.receive_round1(r1_p2.clone()).unwrap();
            p.receive_round1(r1_p3.clone()).unwrap();
        }

        // Round 2
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

        // Finalize DKG
        let (kp1, pkp) = p1.finalize().unwrap();
        let (kp2, _) = p2.finalize().unwrap();

        // Create transaction
        let mut tx = create_test_tx(output_value);
        let prevouts = vec![(output_value * 2, vec![0x51, 0x20])];

        // Generate nonces for signers 1 and 2 (threshold = 2)
        let mut nonces1 = SigningNonces::generate(kp1.signing_share()).unwrap();
        let mut nonces2 = SigningNonces::generate(kp2.signing_share()).unwrap();

        let commitments1 = nonces1.commitments().unwrap();
        let commitments2 = nonces2.commitments().unwrap();

        let commitment_list = vec![
            CommitmentShare::new(kp1.identifier(), commitments1),
            CommitmentShare::new(kp2.identifier(), commitments2),
        ];

        // Create signature shares
        let share1 = sign_frost(&tx, 0, &prevouts, &kp1, &mut nonces1, &commitment_list).unwrap();
        let share2 = sign_frost(&tx, 0, &prevouts, &kp2, &mut nonces2, &commitment_list).unwrap();

        // Finalize
        let sig = finalize_frost(
            &mut tx,
            0,
            &prevouts,
            &commitment_list,
            &[share1, share2],
            &pkp,
            TaprootSighashType::Default,
        )
        .unwrap();

        // Property: signature verifies against group public key
        let sighash = get_frost_sighash(&tx, 0, &prevouts).unwrap();
        prop_assert!(verify(&sig, pkp.group_public_key(), &sighash).unwrap());

        // Property: witness was correctly set
        prop_assert!(!tx.inputs[0].witness.is_empty());
        prop_assert_eq!(tx.inputs[0].witness[0].len(), 64); // Schnorr sig without sighash byte
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // **Feature: ecosystem-upgrade-v2, Property 5: Silent Payment Output Correctness**
    // **Validates: Requirements 3.3**
    //
    // *For any* valid sender keys and Silent Payment addresses,
    // `create_silent_payment_outputs()` SHALL produce P2TR outputs that
    // the recipient can detect and spend.
    #[test]
    fn prop_silent_payment_output_correctness(
        output_value in arb_tx_value(),
        txid_byte in any::<u8>(),
    ) {
        // Sender setup
        let sender_key = PrivateKey::random();
        let sender_pubkey: [u8; 33] = sender_key.public_key().to_compressed().try_into().unwrap();

        // Recipient setup
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        // Create outpoints with varying txid
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        let outpoints = vec![(txid, 0u32)];

        // Create Silent Payment outputs
        let outputs = create_silent_payment_outputs(
            &[sender_key.to_bytes()],
            &outpoints,
            &[recipient],
            &[output_value],
        )
        .unwrap();

        // Property: exactly one output created
        prop_assert_eq!(outputs.len(), 1);

        // Property: output has correct value
        prop_assert_eq!(outputs[0].value, output_value);

        // Property: output is valid P2TR script
        prop_assert_eq!(outputs[0].script_pubkey.len(), 34);
        prop_assert_eq!(outputs[0].script_pubkey[0], 0x51); // OP_1
        prop_assert_eq!(outputs[0].script_pubkey[1], 0x20); // Push 32 bytes

        // Extract output pubkey
        let mut output_pubkey = [0u8; 32];
        output_pubkey.copy_from_slice(&outputs[0].script_pubkey[2..34]);

        // Property: recipient can detect the payment
        let scanner = SilentPaymentScanner::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
        )
        .unwrap();

        let detected = scanner
            .scan(&[output_pubkey], &[sender_pubkey], &outpoints)
            .unwrap();

        // Property: payment is detected
        prop_assert_eq!(detected.len(), 1);

        // Property: spending key is valid (can derive the output pubkey)
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&detected[0].spending_key).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let (xonly, _) = pk.x_only_public_key();

        prop_assert_eq!(xonly.serialize(), output_pubkey);
    }
}
