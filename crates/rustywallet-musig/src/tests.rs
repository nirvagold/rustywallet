//! Integration tests for rustywallet-musig.

use crate::prelude::*;
use rustywallet_keys::prelude::PrivateKey;

#[test]
fn test_2_of_2_musig() {
    let sk1 = PrivateKey::random();
    let sk2 = PrivateKey::random();
    let pk1 = sk1.public_key().to_compressed();
    let pk2 = sk2.public_key().to_compressed();

    let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
    let msg = [42u8; 32];

    let mut nonce1 =
        SecretNonce::generate(&sk1.to_bytes(), &pk1, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();
    let mut nonce2 =
        SecretNonce::generate(&sk2.to_bytes(), &pk2, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();

    let pub_nonces = vec![
        nonce1.public_nonce().unwrap(),
        nonce2.public_nonce().unwrap(),
    ];

    let agg_nonce = AggregatedNonce::aggregate(&pub_nonces, key_agg.xonly_pubkey(), &msg).unwrap();

    let idx1 = key_agg.index_of(&pk1).unwrap();
    let idx2 = key_agg.index_of(&pk2).unwrap();

    let partial1 = create_partial_signature(
        &mut nonce1,
        &sk1.to_bytes(),
        &key_agg,
        &agg_nonce,
        &pub_nonces,
        &msg,
        idx1,
    )
    .unwrap();

    let partial2 = create_partial_signature(
        &mut nonce2,
        &sk2.to_bytes(),
        &key_agg,
        &agg_nonce,
        &pub_nonces,
        &msg,
        idx2,
    )
    .unwrap();

    let sig = aggregate_partial_signatures(&[partial1, partial2], &agg_nonce, &key_agg).unwrap();

    assert!(verify_signature(&sig, key_agg.xonly_pubkey(), &msg).unwrap());
}

#[test]
fn test_3_of_3_musig() {
    let sk1 = PrivateKey::random();
    let sk2 = PrivateKey::random();
    let sk3 = PrivateKey::random();
    let pk1 = sk1.public_key().to_compressed();
    let pk2 = sk2.public_key().to_compressed();
    let pk3 = sk3.public_key().to_compressed();

    let key_agg = KeyAggContext::new(&[pk1, pk2, pk3]).unwrap();
    let msg = [0u8; 32];

    let mut nonce1 =
        SecretNonce::generate(&sk1.to_bytes(), &pk1, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();
    let mut nonce2 =
        SecretNonce::generate(&sk2.to_bytes(), &pk2, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();
    let mut nonce3 =
        SecretNonce::generate(&sk3.to_bytes(), &pk3, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();

    let pub_nonces = vec![
        nonce1.public_nonce().unwrap(),
        nonce2.public_nonce().unwrap(),
        nonce3.public_nonce().unwrap(),
    ];

    let agg_nonce = AggregatedNonce::aggregate(&pub_nonces, key_agg.xonly_pubkey(), &msg).unwrap();

    let idx1 = key_agg.index_of(&pk1).unwrap();
    let idx2 = key_agg.index_of(&pk2).unwrap();
    let idx3 = key_agg.index_of(&pk3).unwrap();

    let partial1 =
        create_partial_signature(&mut nonce1, &sk1.to_bytes(), &key_agg, &agg_nonce, &pub_nonces, &msg, idx1).unwrap();
    let partial2 =
        create_partial_signature(&mut nonce2, &sk2.to_bytes(), &key_agg, &agg_nonce, &pub_nonces, &msg, idx2).unwrap();
    let partial3 =
        create_partial_signature(&mut nonce3, &sk3.to_bytes(), &key_agg, &agg_nonce, &pub_nonces, &msg, idx3).unwrap();

    let sig = aggregate_partial_signatures(&[partial1, partial2, partial3], &agg_nonce, &key_agg).unwrap();

    assert!(verify_signature(&sig, key_agg.xonly_pubkey(), &msg).unwrap());
}

#[test]
fn test_signing_session() {
    let sk1 = PrivateKey::random();
    let sk2 = PrivateKey::random();
    let pk1 = sk1.public_key().to_compressed();
    let pk2 = sk2.public_key().to_compressed();

    let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
    let msg = [0u8; 32];

    let mut session = SigningSession::new(key_agg.clone(), msg);
    assert_eq!(session.state(), SessionState::AwaitingNonces);

    let mut nonce1 =
        SecretNonce::generate(&sk1.to_bytes(), &pk1, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();
    let mut nonce2 =
        SecretNonce::generate(&sk2.to_bytes(), &pk2, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();

    let idx1 = key_agg.index_of(&pk1).unwrap();
    let idx2 = key_agg.index_of(&pk2).unwrap();

    session.add_nonce(idx1, nonce1.public_nonce().unwrap()).unwrap();
    session.add_nonce(idx2, nonce2.public_nonce().unwrap()).unwrap();
    assert_eq!(session.state(), SessionState::ReadyToSign);

    let partial1 = session.sign(&mut nonce1, &sk1.to_bytes(), idx1).unwrap();
    let partial2 = session.sign(&mut nonce2, &sk2.to_bytes(), idx2).unwrap();

    session.add_partial_signature(partial1).unwrap();
    session.add_partial_signature(partial2).unwrap();
    assert_eq!(session.state(), SessionState::ReadyToAggregate);

    let _sig = session.aggregate().unwrap();
    assert_eq!(session.state(), SessionState::Complete);
    assert!(session.verify().unwrap());
}

#[test]
fn test_key_aggregation_deterministic() {
    let sk1 = PrivateKey::random();
    let sk2 = PrivateKey::random();
    let pk1 = sk1.public_key().to_compressed();
    let pk2 = sk2.public_key().to_compressed();

    let key_agg1 = KeyAggContext::new(&[pk1, pk2]).unwrap();
    let key_agg2 = KeyAggContext::new(&[pk2, pk1]).unwrap();

    assert_eq!(key_agg1.aggregated_pubkey(), key_agg2.aggregated_pubkey());
}

#[test]
fn test_adaptor_signature() {
    let sk1 = PrivateKey::random();
    let sk2 = PrivateKey::random();
    let pk1 = sk1.public_key().to_compressed();
    let pk2 = sk2.public_key().to_compressed();

    let adaptor_sk = PrivateKey::random();
    let adaptor_point = adaptor_sk.public_key().to_compressed();

    let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
    let msg = [0u8; 32];

    let mut nonce1 =
        SecretNonce::generate(&sk1.to_bytes(), &pk1, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();
    let mut nonce2 =
        SecretNonce::generate(&sk2.to_bytes(), &pk2, key_agg.xonly_pubkey(), Some(&msg), None).unwrap();

    let pub_nonces = vec![
        nonce1.public_nonce().unwrap(),
        nonce2.public_nonce().unwrap(),
    ];

    let agg_nonce = AggregatedNonce::aggregate(&pub_nonces, key_agg.xonly_pubkey(), &msg).unwrap();

    let idx1 = key_agg.index_of(&pk1).unwrap();
    let idx2 = key_agg.index_of(&pk2).unwrap();

    let partial1 = create_adaptor_partial_signature(
        &mut nonce1, &sk1.to_bytes(), &key_agg, &agg_nonce, &pub_nonces, &adaptor_point, &msg, idx1,
    ).unwrap();

    let partial2 = create_adaptor_partial_signature(
        &mut nonce2, &sk2.to_bytes(), &key_agg, &agg_nonce, &pub_nonces, &adaptor_point, &msg, idx2,
    ).unwrap();

    let adaptor_sig =
        aggregate_adaptor_signatures(&[partial1, partial2], &agg_nonce, &adaptor_point, &key_agg).unwrap();

    let adaptor_sk_bytes = adaptor_sk.to_bytes();
    let final_sig = adaptor_sig.complete(&adaptor_sk_bytes).unwrap();
    let extracted = adaptor_sig.extract_secret(&final_sig).unwrap();
    assert_eq!(extracted, adaptor_sk_bytes);
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// **Feature: rustywallet-musig, Property 1: Key aggregation is deterministic**
        #[test]
        fn prop_key_agg_deterministic(seed1 in any::<[u8; 32]>(), seed2 in any::<[u8; 32]>()) {
            prop_assume!(seed1 != seed2);

            let sk1 = PrivateKey::from_bytes(seed1).unwrap_or_else(|_| PrivateKey::random());
            let sk2 = PrivateKey::from_bytes(seed2).unwrap_or_else(|_| PrivateKey::random());
            let pk1 = sk1.public_key().to_compressed();
            let pk2 = sk2.public_key().to_compressed();

            prop_assume!(pk1 != pk2);

            let key_agg1 = KeyAggContext::new(&[pk1, pk2]).unwrap();
            let key_agg2 = KeyAggContext::new(&[pk1, pk2]).unwrap();

            prop_assert_eq!(key_agg1.aggregated_pubkey(), key_agg2.aggregated_pubkey());
        }

        /// **Feature: rustywallet-musig, Property 2: Key aggregation is order-independent**
        #[test]
        fn prop_key_agg_order_independent(seed1 in any::<[u8; 32]>(), seed2 in any::<[u8; 32]>()) {
            prop_assume!(seed1 != seed2);

            let sk1 = PrivateKey::from_bytes(seed1).unwrap_or_else(|_| PrivateKey::random());
            let sk2 = PrivateKey::from_bytes(seed2).unwrap_or_else(|_| PrivateKey::random());
            let pk1 = sk1.public_key().to_compressed();
            let pk2 = sk2.public_key().to_compressed();

            prop_assume!(pk1 != pk2);

            let key_agg1 = KeyAggContext::new(&[pk1, pk2]).unwrap();
            let key_agg2 = KeyAggContext::new(&[pk2, pk1]).unwrap();

            prop_assert_eq!(key_agg1.aggregated_pubkey(), key_agg2.aggregated_pubkey());
        }

        /// **Feature: rustywallet-musig, Property 3: Signature verification succeeds for valid signatures**
        #[test]
        fn prop_valid_signature_verifies(msg in any::<[u8; 32]>()) {
            let sk1 = PrivateKey::random();
            let sk2 = PrivateKey::random();
            let pk1 = sk1.public_key().to_compressed();
            let pk2 = sk2.public_key().to_compressed();

            let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();

            let mut nonce1 = SecretNonce::generate(
                &sk1.to_bytes(), &pk1, key_agg.xonly_pubkey(), Some(&msg), None
            ).unwrap();
            let mut nonce2 = SecretNonce::generate(
                &sk2.to_bytes(), &pk2, key_agg.xonly_pubkey(), Some(&msg), None
            ).unwrap();

            let pub_nonces = vec![
                nonce1.public_nonce().unwrap(),
                nonce2.public_nonce().unwrap(),
            ];

            let agg_nonce = AggregatedNonce::aggregate(
                &pub_nonces, key_agg.xonly_pubkey(), &msg
            ).unwrap();

            let idx1 = key_agg.index_of(&pk1).unwrap();
            let idx2 = key_agg.index_of(&pk2).unwrap();

            let partial1 = create_partial_signature(
                &mut nonce1, &sk1.to_bytes(), &key_agg, &agg_nonce, &pub_nonces, &msg, idx1
            ).unwrap();
            let partial2 = create_partial_signature(
                &mut nonce2, &sk2.to_bytes(), &key_agg, &agg_nonce, &pub_nonces, &msg, idx2
            ).unwrap();

            let sig = aggregate_partial_signatures(&[partial1, partial2], &agg_nonce, &key_agg).unwrap();

            prop_assert!(verify_signature(&sig, key_agg.xonly_pubkey(), &msg).unwrap());
        }
    }
}
