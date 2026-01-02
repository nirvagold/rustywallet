//! Taproot (P2TR) transaction signing support
//!
//! Provides key-path and script-path signing for Taproot inputs.

use crate::types::Transaction;
use crate::error::{TxError, Result};
use rustywallet_taproot::{
    XOnlyPublicKey, SchnorrSignature, TaprootSighashType,
    taproot_key_path_sighash, tweak_private_key,
    sighash::TxOut as TaprootTxOut,
};
use secp256k1::{Secp256k1, SecretKey};

/// Sign a P2TR key-path input
///
/// # Arguments
/// * `tx` - Transaction to sign
/// * `input_index` - Index of the input to sign
/// * `prevouts` - All previous outputs (values and scriptPubKeys)
/// * `private_key` - 32-byte private key
pub fn sign_p2tr_key_path(
    tx: &mut Transaction,
    input_index: usize,
    prevouts: &[(u64, Vec<u8>)],
    private_key: &[u8; 32],
) -> Result<()> {
    sign_p2tr_key_path_with_sighash(tx, input_index, prevouts, private_key, TaprootSighashType::Default)
}

/// Sign a P2TR key-path input with explicit sighash type
pub fn sign_p2tr_key_path_with_sighash(
    tx: &mut Transaction,
    input_index: usize,
    prevouts: &[(u64, Vec<u8>)],
    private_key: &[u8; 32],
    sighash_type: TaprootSighashType,
) -> Result<()> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }

    // Compute sighash
    let sighash = compute_key_path_sighash(tx, input_index, prevouts, sighash_type)?;

    // Derive x-only public key
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(private_key)
        .map_err(|e| TxError::SigningFailed(e.to_string()))?;
    let pk = sk.public_key(&secp);
    let (xonly, _) = pk.x_only_public_key();
    let internal_key = XOnlyPublicKey::from_inner(xonly);

    // Tweak private key for key-path spending (no script tree)
    let tweaked_key = tweak_private_key(private_key, &internal_key, None)
        .map_err(|e| TxError::TaprootError(e.to_string()))?;

    // Sign with tweaked key
    let sig = SchnorrSignature::sign(&sighash, &tweaked_key)
        .map_err(|e| TxError::TaprootError(e.to_string()))?;

    // Build witness with sighash type byte if not DEFAULT
    let mut sig_bytes = sig.serialize().to_vec();
    if sighash_type != TaprootSighashType::Default {
        sig_bytes.push(sighash_type.to_u8());
    }
    tx.inputs[input_index].witness = vec![sig_bytes];

    Ok(())
}

/// Compute key-path sighash for a Taproot input
fn compute_key_path_sighash(
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
    let taproot_outputs: Vec<TaprootTxOut> = tx.outputs
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

/// Sign all P2TR inputs in a transaction
pub fn sign_all_p2tr(
    tx: &mut Transaction,
    prevouts: &[(u64, Vec<u8>)],
    private_keys: &[(usize, [u8; 32])],
) -> Result<()> {
    for (input_index, private_key) in private_keys {
        sign_p2tr_key_path(tx, *input_index, prevouts, private_key)?;
    }
    Ok(())
}

/// Check if a scriptPubKey is P2TR
pub fn is_p2tr_script(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == 0x20
}

/// Extract x-only public key from P2TR scriptPubKey
pub fn extract_p2tr_pubkey(script: &[u8]) -> Option<[u8; 32]> {
    if !is_p2tr_script(script) {
        return None;
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&script[2..34]);
    Some(pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TxInput, TxOutput};

    fn create_test_tx() -> Transaction {
        let mut tx = Transaction::new();
        tx.version = 2;
        tx.inputs.push(TxInput::new([0u8; 32], 0));
        tx.outputs.push(TxOutput::new(50000, vec![0x51, 0x20,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]));
        tx
    }

    #[test]
    fn test_is_p2tr_script() {
        let p2tr = vec![0x51, 0x20, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_p2tr_script(&p2tr));

        let p2wpkh = vec![0x00, 0x14, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!is_p2tr_script(&p2wpkh));
    }

    #[test]
    fn test_extract_p2tr_pubkey() {
        let pubkey = [0x42u8; 32];
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&pubkey);
        
        let extracted = extract_p2tr_pubkey(&script).unwrap();
        assert_eq!(extracted, pubkey);
    }

    #[test]
    fn test_sign_p2tr_input_index_bounds() {
        let mut tx = create_test_tx();
        let prevouts = vec![(100000u64, vec![0x51, 0x20])];
        let key = [1u8; 32];

        let result = sign_p2tr_key_path(&mut tx, 5, &prevouts, &key);
        assert!(matches!(result, Err(TxError::InputIndexOutOfBounds { .. })));
    }
}
