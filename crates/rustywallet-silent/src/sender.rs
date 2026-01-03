//! Silent Payment output creation for senders.

use crate::address::SilentPaymentAddress;
use crate::error::{Result, SilentPaymentError};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// BIP352 shared secret tag.
const SHARED_SECRET_TAG: &[u8] = b"BIP0352/SharedSecret";

/// Output for a Silent Payment recipient.
#[derive(Debug, Clone)]
pub struct SilentPaymentOutput {
    /// Output public key (x-only, 32 bytes)
    pub output_pubkey: [u8; 32],
    /// Recipient address (for reference)
    pub recipient: SilentPaymentAddress,
    /// Output index within this recipient's outputs
    pub output_index: u32,
}

/// Create Silent Payment outputs for recipients.
///
/// # Arguments
/// * `sender_privkeys` - Private keys of all inputs being spent
/// * `outpoints` - (txid, vout) pairs for all inputs
/// * `recipients` - Silent Payment addresses to pay
///
/// # Returns
/// Vector of outputs, one per recipient
pub fn create_outputs(
    sender_privkeys: &[[u8; 32]],
    outpoints: &[([u8; 32], u32)],
    recipients: &[SilentPaymentAddress],
) -> Result<Vec<SilentPaymentOutput>> {
    if sender_privkeys.is_empty() {
        return Err(SilentPaymentError::NoInputs);
    }
    if recipients.is_empty() {
        return Err(SilentPaymentError::NoRecipients);
    }

    let secp = Secp256k1::new();

    // Step 1: Compute sum of input private keys
    let a_sum = sum_private_keys(sender_privkeys)?;

    // Step 2: Compute input hash
    let input_hash = compute_input_hash(outpoints, sender_privkeys)?;

    // Step 3: Compute a_sum * input_hash
    let a_sum_sk = SecretKey::from_slice(&a_sum)
        .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
    let input_hash_sk = SecretKey::from_slice(&input_hash)
        .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
    let tweaked = a_sum_sk
        .mul_tweak(&input_hash_sk.into())
        .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

    let mut outputs = Vec::with_capacity(recipients.len());

    // Step 4: For each recipient, compute output
    for recipient in recipients {
        let b_scan = PublicKey::from_slice(recipient.scan_pubkey())
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

        // Compute shared secret: ECDH(a_sum * input_hash, B_scan)
        let shared_secret_point = b_scan
            .mul_tweak(&secp, &tweaked.into())
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        // Hash the shared secret
        let t_k = compute_output_tweak(&shared_secret_point.serialize(), 0);

        // Compute output key: P = B_spend + t_k * G
        let b_spend = PublicKey::from_slice(recipient.spend_pubkey())
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

        let t_k_sk = SecretKey::from_slice(&t_k)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
        let t_k_point = PublicKey::from_secret_key(&secp, &t_k_sk);

        let output_pk = b_spend
            .combine(&t_k_point)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        // Convert to x-only
        let (xonly, _parity) = output_pk.x_only_public_key();

        outputs.push(SilentPaymentOutput {
            output_pubkey: xonly.serialize(),
            recipient: recipient.clone(),
            output_index: 0,
        });
    }

    Ok(outputs)
}

/// Create multiple outputs for a single recipient (with different indices).
pub fn create_multiple_outputs(
    sender_privkeys: &[[u8; 32]],
    outpoints: &[([u8; 32], u32)],
    recipient: &SilentPaymentAddress,
    count: u32,
) -> Result<Vec<SilentPaymentOutput>> {
    if sender_privkeys.is_empty() {
        return Err(SilentPaymentError::NoInputs);
    }
    if count == 0 {
        return Err(SilentPaymentError::NoRecipients);
    }

    let secp = Secp256k1::new();

    let a_sum = sum_private_keys(sender_privkeys)?;
    let input_hash = compute_input_hash(outpoints, sender_privkeys)?;

    let a_sum_sk = SecretKey::from_slice(&a_sum)
        .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
    let input_hash_sk = SecretKey::from_slice(&input_hash)
        .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
    let tweaked = a_sum_sk
        .mul_tweak(&input_hash_sk.into())
        .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

    let b_scan = PublicKey::from_slice(recipient.scan_pubkey())
        .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

    let shared_secret_point = b_scan
        .mul_tweak(&secp, &tweaked.into())
        .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

    let b_spend = PublicKey::from_slice(recipient.spend_pubkey())
        .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

    let mut outputs = Vec::with_capacity(count as usize);

    for k in 0..count {
        let t_k = compute_output_tweak(&shared_secret_point.serialize(), k);

        let t_k_sk = SecretKey::from_slice(&t_k)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
        let t_k_point = PublicKey::from_secret_key(&secp, &t_k_sk);

        let output_pk = b_spend
            .combine(&t_k_point)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let (xonly, _parity) = output_pk.x_only_public_key();

        outputs.push(SilentPaymentOutput {
            output_pubkey: xonly.serialize(),
            recipient: recipient.clone(),
            output_index: k,
        });
    }

    Ok(outputs)
}

/// Sum private keys.
fn sum_private_keys(keys: &[[u8; 32]]) -> Result<[u8; 32]> {
    if keys.is_empty() {
        return Err(SilentPaymentError::NoInputs);
    }

    let mut sum = SecretKey::from_slice(&keys[0])
        .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;

    for key in &keys[1..] {
        let sk = SecretKey::from_slice(key)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        sum = sum
            .add_tweak(&sk.into())
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
    }

    Ok(sum.secret_bytes())
}

/// Compute input hash from outpoints.
fn compute_input_hash(outpoints: &[([u8; 32], u32)], privkeys: &[[u8; 32]]) -> Result<[u8; 32]> {
    let secp = Secp256k1::new();

    // Sort outpoints lexicographically
    let mut sorted: Vec<_> = outpoints.to_vec();
    sorted.sort_by(|a, b| {
        let cmp = a.0.cmp(&b.0);
        if cmp == std::cmp::Ordering::Equal {
            a.1.cmp(&b.1)
        } else {
            cmp
        }
    });

    // Compute sum of public keys
    let mut pubkey_sum: Option<PublicKey> = None;
    for key in privkeys {
        let sk = SecretKey::from_slice(key)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        let pk = PublicKey::from_secret_key(&secp, &sk);

        pubkey_sum = match pubkey_sum {
            None => Some(pk),
            Some(sum) => Some(
                sum.combine(&pk)
                    .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?,
            ),
        };
    }

    let pubkey_sum = pubkey_sum.ok_or(SilentPaymentError::NoInputs)?;

    // Hash: smallest_outpoint || A_sum
    let mut hasher = Sha256::new();
    hasher.update(sorted[0].0);
    hasher.update(sorted[0].1.to_le_bytes());
    hasher.update(pubkey_sum.serialize());

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);

    Ok(hash)
}

/// Compute output tweak t_k.
fn compute_output_tweak(shared_secret: &[u8; 33], k: u32) -> [u8; 32] {
    let tag_hash = Sha256::digest(SHARED_SECRET_TAG);

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(shared_secret);
    hasher.update(k.to_be_bytes());

    let result = hasher.finalize();
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&result);
    tweak
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_create_outputs() {
        let sender = PrivateKey::random();
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            crate::network::Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([0u8; 32], 0u32)];

        let outputs =
            create_outputs(&[sender.to_bytes()], &outpoints, &[recipient.clone()]).unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].output_pubkey.len(), 32);
    }

    #[test]
    fn test_create_multiple_outputs() {
        let sender = PrivateKey::random();
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            crate::network::Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([0u8; 32], 0u32)];

        let outputs =
            create_multiple_outputs(&[sender.to_bytes()], &outpoints, &recipient, 3).unwrap();

        assert_eq!(outputs.len(), 3);

        // Each output should be different
        assert_ne!(outputs[0].output_pubkey, outputs[1].output_pubkey);
        assert_ne!(outputs[1].output_pubkey, outputs[2].output_pubkey);
    }

    #[test]
    fn test_no_inputs_error() {
        let scan_key = PrivateKey::random();
        let recipient = SilentPaymentAddress::from_single_key(
            &scan_key.public_key(),
            crate::network::Network::Mainnet,
        )
        .unwrap();

        let result = create_outputs(&[], &[], &[recipient]);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_recipients_error() {
        let sender = PrivateKey::random();
        let outpoints = vec![([0u8; 32], 0u32)];

        let result = create_outputs(&[sender.to_bytes()], &outpoints, &[]);
        assert!(result.is_err());
    }
}
