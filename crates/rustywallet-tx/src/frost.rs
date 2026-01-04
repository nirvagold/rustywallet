//! FROST threshold transaction signing support.
//!
//! Provides functions for signing P2TR inputs using FROST t-of-n threshold signatures.

use crate::error::{Result, TxError};
use crate::types::Transaction;
use rustywallet_frost::prelude::{
    aggregate, sign, CommitmentShare, KeyPackage, PublicKeyPackage, Signature, SignatureShare,
    SigningNonces,
};
use rustywallet_taproot::{sighash::TxOut as TaprootTxOut, taproot_key_path_sighash, TaprootSighashType};

/// Sign a P2TR input using FROST threshold signatures.
///
/// This function creates a signature share for a FROST signing session.
/// At least `threshold` participants must call this function.
///
/// # Arguments
/// * `tx` - The transaction to sign
/// * `input_index` - Index of the input to sign
/// * `prevouts` - All previous outputs (values and scriptPubKeys)
/// * `key_package` - The signer's key package from DKG
/// * `nonces` - The signer's signing nonces (will be marked as used)
/// * `commitment_list` - All participants' commitments
///
/// # Returns
/// A signature share that can be aggregated with other shares.
pub fn sign_frost(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[(u64, Vec<u8>)],
    key_package: &KeyPackage,
    nonces: &mut SigningNonces,
    commitment_list: &[CommitmentShare],
) -> Result<SignatureShare> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }

    // Compute the sighash for this input
    let sighash = compute_frost_sighash(tx, input_index, prevouts, TaprootSighashType::Default)?;

    // Create signature share
    let share = sign(key_package, nonces, commitment_list, &sighash)?;

    Ok(share)
}

/// Aggregate FROST signature shares and apply to transaction.
///
/// This function aggregates threshold signature shares into a final Schnorr signature
/// and applies it to the transaction witness.
///
/// # Arguments
/// * `tx` - The transaction to sign (will be modified)
/// * `input_index` - Index of the input to sign
/// * `commitment_list` - All participants' commitments
/// * `signature_shares` - Signature shares from threshold participants
/// * `public_key_package` - The group's public key package
/// * `sighash_type` - The sighash type (default is Default)
///
/// # Returns
/// The aggregated Schnorr signature.
pub fn finalize_frost(
    tx: &mut Transaction,
    input_index: usize,
    prevouts: &[(u64, Vec<u8>)],
    commitment_list: &[CommitmentShare],
    signature_shares: &[SignatureShare],
    public_key_package: &PublicKeyPackage,
    sighash_type: TaprootSighashType,
) -> Result<Signature> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }

    // Check we have enough signatures
    if signature_shares.len() < public_key_package.threshold() {
        return Err(TxError::InsufficientSignatures {
            needed: public_key_package.threshold(),
            have: signature_shares.len(),
        });
    }

    // Compute the sighash
    let sighash = compute_frost_sighash(tx, input_index, prevouts, sighash_type)?;

    // Aggregate signature shares
    let signature = aggregate(commitment_list, signature_shares, public_key_package, &sighash)?;

    // Build witness with sighash type byte if not DEFAULT
    let mut sig_bytes = signature.to_bytes().to_vec();
    if sighash_type != TaprootSighashType::Default {
        sig_bytes.push(sighash_type.to_u8());
    }
    tx.inputs[input_index].witness = vec![sig_bytes];

    Ok(signature)
}

/// Compute the sighash for FROST signing.
fn compute_frost_sighash(
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

/// Get the sighash for a FROST signing session.
///
/// This is useful for generating nonces with the correct message.
pub fn get_frost_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[(u64, Vec<u8>)],
) -> Result<[u8; 32]> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }
    compute_frost_sighash(tx, input_index, prevouts, TaprootSighashType::Default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TxInput, TxOutput};
    use rustywallet_frost::prelude::*;

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
    fn test_frost_signing_workflow() {
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
        let mut tx = create_test_tx();
        let prevouts = vec![(100000u64, vec![0x51, 0x20])];

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

        // Verify witness was set
        assert!(!tx.inputs[0].witness.is_empty());
        assert_eq!(tx.inputs[0].witness[0].len(), 64); // Schnorr sig without sighash byte

        // Verify signature
        let sighash = get_frost_sighash(&tx, 0, &prevouts).unwrap();
        assert!(verify(&sig, pkp.group_public_key(), &sighash).unwrap());
    }

    #[test]
    fn test_frost_input_index_bounds() {
        let tx = create_test_tx();
        let prevouts = vec![(100000u64, vec![0x51, 0x20])];

        let result = get_frost_sighash(&tx, 5, &prevouts);
        assert!(matches!(result, Err(TxError::InputIndexOutOfBounds { .. })));
    }

    #[test]
    fn test_frost_insufficient_signatures() {
        // Setup: 2-of-3 FROST
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

        let (kp1, pkp) = p1.finalize().unwrap();

        let mut tx = create_test_tx();
        let prevouts = vec![(100000u64, vec![0x51, 0x20])];

        let mut nonces1 = SigningNonces::generate(kp1.signing_share()).unwrap();
        let commitments1 = nonces1.commitments().unwrap();
        let commitment_list = vec![CommitmentShare::new(kp1.identifier(), commitments1)];

        let share1 = sign_frost(&tx, 0, &prevouts, &kp1, &mut nonces1, &commitment_list).unwrap();

        // Try to finalize with only 1 signature (threshold is 2)
        let result = finalize_frost(
            &mut tx,
            0,
            &prevouts,
            &commitment_list,
            &[share1],
            &pkp,
            TaprootSighashType::Default,
        );

        assert!(matches!(
            result,
            Err(TxError::InsufficientSignatures { needed: 2, have: 1 })
        ));
    }
}
