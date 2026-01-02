//! Transaction signing.

use crate::error::{TxError, Result};
use crate::types::Transaction;
use crate::sighash::{sighash_legacy, sighash_segwit, sighash_type};
use crate::script::{build_p2pkh_script, hash160, is_p2pkh, is_p2wpkh};
use rustywallet_keys::prelude::PrivateKey;
use secp256k1::{Secp256k1, Message, SecretKey};

/// Sign a P2PKH input.
///
/// # Arguments
/// * `tx` - The transaction to sign
/// * `input_index` - Index of the input to sign
/// * `script_pubkey` - The scriptPubKey of the UTXO being spent
/// * `private_key` - The private key to sign with
pub fn sign_p2pkh(
    tx: &mut Transaction,
    input_index: usize,
    script_pubkey: &[u8],
    private_key: &PrivateKey,
) -> Result<()> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }

    if !is_p2pkh(script_pubkey) {
        return Err(TxError::SigningFailed("Not a P2PKH script".to_string()));
    }

    // Calculate sighash
    let sighash = sighash_legacy(tx, input_index, script_pubkey, sighash_type::ALL);

    // Sign
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key.to_bytes())
        .map_err(|e| TxError::SigningFailed(e.to_string()))?;
    let message = Message::from_digest(sighash);
    let signature = secp.sign_ecdsa(&message, &secret_key);

    // Serialize signature in DER format + sighash type
    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(sighash_type::ALL as u8);

    // Get public key
    let pubkey = private_key.public_key().to_compressed();

    // Build scriptSig: <sig> <pubkey>
    let mut script_sig = Vec::new();
    script_sig.push(sig_bytes.len() as u8);
    script_sig.extend_from_slice(&sig_bytes);
    script_sig.push(pubkey.len() as u8);
    script_sig.extend_from_slice(&pubkey);

    tx.inputs[input_index].script_sig = script_sig;

    Ok(())
}

/// Sign a P2WPKH input.
///
/// # Arguments
/// * `tx` - The transaction to sign
/// * `input_index` - Index of the input to sign
/// * `value` - Value of the UTXO being spent
/// * `private_key` - The private key to sign with
pub fn sign_p2wpkh(
    tx: &mut Transaction,
    input_index: usize,
    value: u64,
    private_key: &PrivateKey,
) -> Result<()> {
    if input_index >= tx.inputs.len() {
        return Err(TxError::InputIndexOutOfBounds {
            index: input_index,
            count: tx.inputs.len(),
        });
    }

    // Get public key and hash
    let pubkey = private_key.public_key().to_compressed();
    let pubkey_hash = hash160(&pubkey);

    // Script code for P2WPKH is P2PKH script
    let script_code = build_p2pkh_script(&pubkey_hash);

    // Calculate BIP143 sighash
    let sighash = sighash_segwit(tx, input_index, &script_code, value, sighash_type::ALL);

    // Sign
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key.to_bytes())
        .map_err(|e| TxError::SigningFailed(e.to_string()))?;
    let message = Message::from_digest(sighash);
    let signature = secp.sign_ecdsa(&message, &secret_key);

    // Serialize signature + sighash type
    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(sighash_type::ALL as u8);

    // Set witness data
    tx.inputs[input_index].witness = vec![sig_bytes, pubkey.to_vec()];

    Ok(())
}

/// Sign all inputs in a transaction.
///
/// # Arguments
/// * `tx` - The transaction to sign
/// * `utxo_info` - List of (script_pubkey, value, private_key) for each input
pub fn sign_all(
    tx: &mut Transaction,
    utxo_info: &[(Vec<u8>, u64, &PrivateKey)],
) -> Result<()> {
    if utxo_info.len() != tx.inputs.len() {
        return Err(TxError::SigningFailed(format!(
            "Expected {} UTXO infos, got {}",
            tx.inputs.len(),
            utxo_info.len()
        )));
    }

    for (i, (script_pubkey, value, private_key)) in utxo_info.iter().enumerate() {
        if is_p2pkh(script_pubkey) {
            sign_p2pkh(tx, i, script_pubkey, private_key)?;
        } else if is_p2wpkh(script_pubkey) {
            sign_p2wpkh(tx, i, *value, private_key)?;
        } else {
            return Err(TxError::SigningFailed(format!(
                "Unsupported script type for input {}",
                i
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TxInput, TxOutput};

    #[test]
    fn test_sign_p2pkh() {
        let private_key = PrivateKey::random();
        let pubkey = private_key.public_key().to_compressed();
        let pubkey_hash = hash160(&pubkey);
        let script_pubkey = build_p2pkh_script(&pubkey_hash);

        let mut tx = Transaction::new();
        tx.inputs.push(TxInput::new([0u8; 32], 0));
        tx.outputs.push(TxOutput::new(50_000, script_pubkey.clone()));

        let result = sign_p2pkh(&mut tx, 0, &script_pubkey, &private_key);
        assert!(result.is_ok());
        assert!(!tx.inputs[0].script_sig.is_empty());
    }

    #[test]
    fn test_sign_p2wpkh() {
        let private_key = PrivateKey::random();

        let mut tx = Transaction::new();
        tx.inputs.push(TxInput::new([0u8; 32], 0));
        tx.outputs.push(TxOutput::new(50_000, vec![0x00, 0x14]));

        let result = sign_p2wpkh(&mut tx, 0, 100_000, &private_key);
        assert!(result.is_ok());
        assert!(!tx.inputs[0].witness.is_empty());
        assert_eq!(tx.inputs[0].witness.len(), 2); // sig + pubkey
    }

    #[test]
    fn test_sign_invalid_index() {
        let private_key = PrivateKey::random();
        let mut tx = Transaction::new();
        tx.inputs.push(TxInput::new([0u8; 32], 0));

        let result = sign_p2wpkh(&mut tx, 5, 100_000, &private_key);
        assert!(matches!(result, Err(TxError::InputIndexOutOfBounds { .. })));
    }
}
