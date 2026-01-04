//! Silent Payment output creation support.
//!
//! Provides functions for creating P2TR outputs for Silent Payment recipients.

use crate::error::{Result, TxError};
use crate::types::TxOutput;
use rustywallet_silent::{create_outputs, create_multiple_outputs, SilentPaymentAddress, SilentPaymentOutput};

/// Create Silent Payment outputs for recipients.
///
/// This function creates P2TR outputs that can be detected and spent by
/// Silent Payment recipients using their scan and spend keys.
///
/// # Arguments
/// * `sender_keys` - Private keys of all inputs being spent (32 bytes each)
/// * `outpoints` - (txid, vout) pairs for all inputs
/// * `recipients` - Silent Payment addresses to pay
/// * `amounts` - Amount in satoshis for each recipient
///
/// # Returns
/// A vector of TxOutput ready to be added to a transaction.
///
/// # Example
/// ```rust,ignore
/// use rustywallet_tx::create_silent_payment_outputs;
/// use rustywallet_silent::SilentPaymentAddress;
///
/// let sender_key = [/* 32 bytes */];
/// let outpoints = vec![([0u8; 32], 0u32)];
/// let recipient: SilentPaymentAddress = "sp1...".parse().unwrap();
/// let amounts = vec![50000u64];
///
/// let outputs = create_silent_payment_outputs(
///     &[sender_key],
///     &outpoints,
///     &[recipient],
///     &amounts,
/// ).unwrap();
///
/// // Add outputs to transaction
/// for output in outputs {
///     tx.outputs.push(output);
/// }
/// ```
pub fn create_silent_payment_outputs(
    sender_keys: &[[u8; 32]],
    outpoints: &[([u8; 32], u32)],
    recipients: &[SilentPaymentAddress],
    amounts: &[u64],
) -> Result<Vec<TxOutput>> {
    if sender_keys.is_empty() {
        return Err(TxError::NoInputs);
    }

    if recipients.is_empty() {
        return Err(TxError::SilentPaymentError("No recipients provided".into()));
    }

    if recipients.len() != amounts.len() {
        return Err(TxError::SilentPaymentError(format!(
            "Recipients count ({}) does not match amounts count ({})",
            recipients.len(),
            amounts.len()
        )));
    }

    // Create Silent Payment outputs
    let sp_outputs = create_outputs(sender_keys, outpoints, recipients)?;

    // Convert to TxOutput with amounts
    let tx_outputs: Vec<TxOutput> = sp_outputs
        .into_iter()
        .zip(amounts.iter())
        .map(|(sp_out, &amount)| {
            let script_pubkey = build_p2tr_script(&sp_out.output_pubkey);
            TxOutput::new(amount, script_pubkey)
        })
        .collect();

    Ok(tx_outputs)
}

/// Create multiple Silent Payment outputs for a single recipient.
///
/// This is useful when sending multiple outputs to the same recipient
/// (e.g., for privacy or UTXO management).
///
/// # Arguments
/// * `sender_keys` - Private keys of all inputs being spent
/// * `outpoints` - (txid, vout) pairs for all inputs
/// * `recipient` - Silent Payment address to pay
/// * `amounts` - Amount in satoshis for each output
///
/// # Returns
/// A vector of TxOutput ready to be added to a transaction.
pub fn create_multiple_silent_payment_outputs(
    sender_keys: &[[u8; 32]],
    outpoints: &[([u8; 32], u32)],
    recipient: &SilentPaymentAddress,
    amounts: &[u64],
) -> Result<Vec<TxOutput>> {
    if sender_keys.is_empty() {
        return Err(TxError::NoInputs);
    }

    if amounts.is_empty() {
        return Err(TxError::SilentPaymentError("No amounts provided".into()));
    }

    // Create Silent Payment outputs
    let sp_outputs = create_multiple_outputs(sender_keys, outpoints, recipient, amounts.len() as u32)?;

    // Convert to TxOutput with amounts
    let tx_outputs: Vec<TxOutput> = sp_outputs
        .into_iter()
        .zip(amounts.iter())
        .map(|(sp_out, &amount)| {
            let script_pubkey = build_p2tr_script(&sp_out.output_pubkey);
            TxOutput::new(amount, script_pubkey)
        })
        .collect();

    Ok(tx_outputs)
}

/// Get the raw Silent Payment output data.
///
/// This returns the full SilentPaymentOutput including the output public key,
/// which can be useful for tracking or verification purposes.
///
/// # Arguments
/// * `sender_keys` - Private keys of all inputs being spent
/// * `outpoints` - (txid, vout) pairs for all inputs
/// * `recipients` - Silent Payment addresses to pay
///
/// # Returns
/// A vector of SilentPaymentOutput with output public keys.
pub fn get_silent_payment_output_data(
    sender_keys: &[[u8; 32]],
    outpoints: &[([u8; 32], u32)],
    recipients: &[SilentPaymentAddress],
) -> Result<Vec<SilentPaymentOutput>> {
    if sender_keys.is_empty() {
        return Err(TxError::NoInputs);
    }

    if recipients.is_empty() {
        return Err(TxError::SilentPaymentError("No recipients provided".into()));
    }

    let outputs = create_outputs(sender_keys, outpoints, recipients)?;
    Ok(outputs)
}

/// Build a P2TR scriptPubKey from an x-only public key.
fn build_p2tr_script(xonly_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(0x51); // OP_1 (witness version 1)
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(xonly_pubkey);
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;
    use rustywallet_silent::Network;

    #[test]
    fn test_create_silent_payment_outputs() {
        let sender = PrivateKey::random();
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([0u8; 32], 0u32)];
        let amounts = vec![50000u64];

        let outputs = create_silent_payment_outputs(
            &[sender.to_bytes()],
            &outpoints,
            &[recipient],
            &amounts,
        )
        .unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 50000);
        assert_eq!(outputs[0].script_pubkey.len(), 34);
        assert_eq!(outputs[0].script_pubkey[0], 0x51); // OP_1
        assert_eq!(outputs[0].script_pubkey[1], 0x20); // Push 32
    }

    #[test]
    fn test_create_multiple_silent_payment_outputs() {
        let sender = PrivateKey::random();
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([0u8; 32], 0u32)];
        let amounts = vec![10000u64, 20000u64, 30000u64];

        let outputs = create_multiple_silent_payment_outputs(
            &[sender.to_bytes()],
            &outpoints,
            &recipient,
            &amounts,
        )
        .unwrap();

        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[0].value, 10000);
        assert_eq!(outputs[1].value, 20000);
        assert_eq!(outputs[2].value, 30000);

        // All outputs should have unique scriptPubKeys
        assert_ne!(outputs[0].script_pubkey, outputs[1].script_pubkey);
        assert_ne!(outputs[1].script_pubkey, outputs[2].script_pubkey);
    }

    #[test]
    fn test_no_inputs_error() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        let result = create_silent_payment_outputs(&[], &[], &[recipient], &[50000]);
        assert!(matches!(result, Err(TxError::NoInputs)));
    }

    #[test]
    fn test_no_recipients_error() {
        let sender = PrivateKey::random();
        let outpoints = vec![([0u8; 32], 0u32)];

        let result = create_silent_payment_outputs(&[sender.to_bytes()], &outpoints, &[], &[]);
        assert!(matches!(result, Err(TxError::SilentPaymentError(_))));
    }

    #[test]
    fn test_mismatched_recipients_amounts() {
        let sender = PrivateKey::random();
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([0u8; 32], 0u32)];
        let amounts = vec![50000u64, 60000u64]; // 2 amounts but 1 recipient

        let result = create_silent_payment_outputs(
            &[sender.to_bytes()],
            &outpoints,
            &[recipient],
            &amounts,
        );
        assert!(matches!(result, Err(TxError::SilentPaymentError(_))));
    }

    #[test]
    fn test_get_silent_payment_output_data() {
        let sender = PrivateKey::random();
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([0u8; 32], 0u32)];

        let outputs = get_silent_payment_output_data(
            &[sender.to_bytes()],
            &outpoints,
            &[recipient.clone()],
        )
        .unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].output_pubkey.len(), 32);
        assert_eq!(outputs[0].output_index, 0);
    }

    #[test]
    fn test_build_p2tr_script() {
        let pubkey = [0x42u8; 32];
        let script = build_p2tr_script(&pubkey);

        assert_eq!(script.len(), 34);
        assert_eq!(script[0], 0x51); // OP_1
        assert_eq!(script[1], 0x20); // Push 32 bytes
        assert_eq!(&script[2..], &pubkey);
    }
}
