//! MuSig2 transaction signing support.
//!
//! Provides functions for signing P2TR inputs using MuSig2 n-of-n multisignatures.

use crate::error::{Result, TxError};
use crate::types::Transaction;
use rustywallet_musig::{
    KeyAggContext, SigningSession, SecretNonce, AggregatedNonce,
    signing::{create_partial_signature, aggregate_partial_signatures, PartialSignature, SchnorrSignature},
};
use rustywallet_taproot::{TaprootSighashType, taproot_key_path_sighash, sighash::TxOut as TaprootTxOut};

/// Sign a P2TR input using MuSig2.
///
/// This function creates a partial signature for a MuSig2 signing session.
/// All participants must call this function with their own secret nonce and key.
///
/// # Arguments
/// * `tx` - The transaction to sign
/// * `input_index` - Index of the input to sign
/// * `prevouts` - All previous outputs (values and scriptPubKeys)
/// * `session` - The MuSig2 signing session
/// * `secret_nonce` - The signer's secret nonce (will be marked as used)
/// * `secret_key` - The signer's 32-byte secret key
/// * `signer_index` - Index of this signer in the key aggregation
///
/// # Returns
/// A partial signature that can be aggregated with other partial signatures.
pub fn sign_musig2(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[(u64, Vec<u8>)],
    session: &SigningSession,
    secret_nonce: &mut SecretNonce,
    secret_key: &[u8; 32],
    signer_index: usize,
) -> Result<PartialSignature> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }

    // Compute the sighash for this input
    let sighash = compute_musig2_sighash(tx, input_index, prevouts, TaprootSighashType::Default)?;

    // Verify the session message matches our sighash
    if session.message() != &sighash {
        return Err(TxError::Musig2Error(
            "Session message does not match transaction sighash".into(),
        ));
    }

    // Get the aggregated nonce from the session
    let agg_nonce = session
        .aggregated_nonce()
        .ok_or_else(|| TxError::Musig2Error("Session has no aggregated nonce".into()))?;

    let public_nonces = session.public_nonces();

    // Create partial signature
    let partial = create_partial_signature(
        secret_nonce,
        secret_key,
        session.key_agg(),
        agg_nonce,
        &public_nonces,
        &sighash,
        signer_index,
    )?;

    Ok(partial)
}

/// Aggregate MuSig2 partial signatures and apply to transaction.
///
/// This function aggregates all partial signatures into a final Schnorr signature
/// and applies it to the transaction witness.
///
/// # Arguments
/// * `tx` - The transaction to sign (will be modified)
/// * `input_index` - Index of the input to sign
/// * `partial_sigs` - All partial signatures from participants
/// * `agg_nonce` - The aggregated nonce
/// * `key_agg` - The key aggregation context
/// * `sighash_type` - The sighash type (default is Default)
pub fn finalize_musig2(
    tx: &mut Transaction,
    input_index: usize,
    partial_sigs: &[PartialSignature],
    agg_nonce: &AggregatedNonce,
    key_agg: &KeyAggContext,
    sighash_type: TaprootSighashType,
) -> Result<SchnorrSignature> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }

    // Aggregate partial signatures
    let signature = aggregate_partial_signatures(partial_sigs, agg_nonce, key_agg)?;

    // Build witness with sighash type byte if not DEFAULT
    let mut sig_bytes = signature.to_bytes().to_vec();
    if sighash_type != TaprootSighashType::Default {
        sig_bytes.push(sighash_type.to_u8());
    }
    tx.inputs[input_index].witness = vec![sig_bytes];

    Ok(signature)
}

/// Create a MuSig2 signing session for a transaction input.
///
/// # Arguments
/// * `tx` - The transaction to sign
/// * `input_index` - Index of the input to sign
/// * `prevouts` - All previous outputs (values and scriptPubKeys)
/// * `key_agg` - The key aggregation context
///
/// # Returns
/// A new signing session initialized with the transaction sighash.
pub fn create_musig2_session(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[(u64, Vec<u8>)],
    key_agg: KeyAggContext,
) -> Result<SigningSession> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }

    let sighash = compute_musig2_sighash(tx, input_index, prevouts, TaprootSighashType::Default)?;
    Ok(SigningSession::new(key_agg, sighash))
}

/// Compute the sighash for MuSig2 signing.
fn compute_musig2_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[(u64, Vec<u8>)],
    sighash_type: TaprootSighashType,
) -> Result<[u8; 32]> {
    // Convert prevouts to TaprootTxOut format
    let taproot_prevouts: Vec<TaprootTxOut> = prevouts
        .iter()
        .map(|(value, script)| TaprootTxOut {
            value: *value,
            script_pubkey: script.clone(),
        })
        .collect();

    // Convert outputs to TaprootTxOut format
    let taproot_outputs: Vec<TaprootTxOut> = tx
        .outputs
        .iter()
        .map(|o| TaprootTxOut {
            value: o.value,
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect();

    // Get sequences
    let sequences: Vec<u32> = tx.inputs.iter().map(|i| i.sequence).collect();

    Ok(taproot_key_path_sighash(
        tx.version,
        tx.locktime,
        &taproot_prevouts,
        input_index,
        &sequences,
        &taproot_outputs,
        sighash_type,
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TxInput, TxOutput};
    use rustywallet_keys::prelude::PrivateKey;
    use rustywallet_musig::signing::verify_signature;

    fn create_test_tx() -> Transaction {
        let mut tx = Transaction::new();
        tx.version = 2;
        tx.inputs.push(TxInput::new([0u8; 32], 0));
        tx.outputs.push(TxOutput::new(
            50000,
            vec![
                0x51, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        ));
        tx
    }

    #[test]
    fn test_musig2_signing_workflow() {
        // Setup: 2-of-2 MuSig
        let sk1 = PrivateKey::random();
        let sk2 = PrivateKey::random();
        let pk1 = sk1.public_key().to_compressed();
        let pk2 = sk2.public_key().to_compressed();

        // Key aggregation
        let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
        let agg_pk = key_agg.xonly_pubkey();

        // Create transaction
        let mut tx = create_test_tx();
        let prevouts = vec![(100000u64, vec![0x51, 0x20])];

        // Create session
        let sighash =
            compute_musig2_sighash(&tx, 0, &prevouts, TaprootSighashType::Default).unwrap();

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

        // Verify signature
        assert!(verify_signature(&sig, agg_pk, &sighash).unwrap());

        // Verify witness was set
        assert!(!tx.inputs[0].witness.is_empty());
        assert_eq!(tx.inputs[0].witness[0].len(), 64); // Schnorr sig without sighash byte
    }

    #[test]
    fn test_musig2_input_index_bounds() {
        let tx = create_test_tx();
        let prevouts = vec![(100000u64, vec![0x51, 0x20])];

        let sk1 = PrivateKey::random();
        let sk2 = PrivateKey::random();
        let pk1 = sk1.public_key().to_compressed();
        let pk2 = sk2.public_key().to_compressed();
        let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();

        let result = create_musig2_session(&tx, 5, &prevouts, key_agg);
        assert!(matches!(result, Err(TxError::InputIndexOutOfBounds { .. })));
    }
}
