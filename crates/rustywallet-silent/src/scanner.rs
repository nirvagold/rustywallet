//! Silent Payment scanning for receivers.

use crate::error::{Result, SilentPaymentError};
use crate::label::{Label, LabelManager};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

/// BIP352 shared secret tag.
const SHARED_SECRET_TAG: &[u8] = b"BIP0352/SharedSecret";

/// A detected Silent Payment.
#[derive(Debug, Clone)]
pub struct DetectedPayment {
    /// Output public key (x-only, 32 bytes)
    pub output_pubkey: [u8; 32],
    /// Spending private key for this output
    pub spending_key: [u8; 32],
    /// Output index in the transaction
    pub output_index: usize,
    /// Label if matched (None for unlabeled)
    pub label: Option<u32>,
}

/// Scanner for detecting Silent Payments.
pub struct SilentPaymentScanner {
    /// Scan private key
    scan_privkey: [u8; 32],
    /// Spend private key
    spend_privkey: [u8; 32],
    /// Spend public key
    spend_pubkey: [u8; 33],
    /// Label manager
    labels: LabelManager,
}

impl SilentPaymentScanner {
    /// Create a new scanner.
    pub fn new(scan_privkey: &[u8; 32], spend_privkey: &[u8; 32]) -> Result<Self> {
        let secp = Secp256k1::new();

        let spend_sk = SecretKey::from_slice(spend_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        Ok(Self {
            scan_privkey: *scan_privkey,
            spend_privkey: *spend_privkey,
            spend_pubkey: spend_pk.serialize(),
            labels: LabelManager::new(),
        })
    }

    /// Add a label to scan for.
    pub fn add_label(&mut self, index: u32) {
        self.labels.add(index);
    }

    /// Add multiple labels.
    pub fn add_labels(&mut self, count: u32) {
        self.labels.generate_range(count);
    }

    /// Scan transaction outputs for payments.
    ///
    /// # Arguments
    /// * `output_pubkeys` - X-only public keys of transaction outputs
    /// * `input_pubkeys` - Public keys of transaction inputs
    /// * `outpoints` - (txid, vout) pairs for inputs
    pub fn scan(
        &self,
        output_pubkeys: &[[u8; 32]],
        input_pubkeys: &[[u8; 33]],
        outpoints: &[([u8; 32], u32)],
    ) -> Result<Vec<DetectedPayment>> {
        if input_pubkeys.is_empty() || outpoints.is_empty() {
            return Ok(Vec::new());
        }

        let secp = Secp256k1::new();

        // Compute sum of input public keys
        let a_sum = sum_public_keys(input_pubkeys)?;

        // Compute input hash
        let input_hash = compute_input_hash(outpoints, &a_sum)?;

        // Compute A_sum * input_hash
        let a_sum_pk = PublicKey::from_slice(&a_sum)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;
        let input_hash_sk = SecretKey::from_slice(&input_hash)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
        let tweaked_a = a_sum_pk
            .mul_tweak(&secp, &input_hash_sk.into())
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        // Compute shared secret: ECDH(b_scan, A_sum * input_hash)
        let b_scan = SecretKey::from_slice(&self.scan_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        let shared_secret_point = tweaked_a
            .mul_tweak(&secp, &b_scan.into())
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let mut detected = Vec::new();

        // Try to match each output
        for (output_idx, output_pk) in output_pubkeys.iter().enumerate() {
            // Try k = 0, 1, 2, ... until no match
            for k in 0..100 {
                // Reasonable limit
                let t_k = compute_output_tweak(&shared_secret_point.serialize(), k);

                // Check unlabeled: P = B_spend + t_k * G
                if let Some(payment) =
                    self.try_match_output(output_pk, &t_k, output_idx, None, &secp)?
                {
                    detected.push(payment);
                    break;
                }

                // Check labeled outputs
                let mut found_label = false;
                for label in self.labels.labels() {
                    if let Some(payment) =
                        self.try_match_labeled_output(output_pk, &t_k, output_idx, label, &secp)?
                    {
                        detected.push(payment);
                        found_label = true;
                        break;
                    }
                }

                if found_label {
                    break;
                }

                // If k > 0 and no match, stop trying higher k values
                if k > 0 {
                    break;
                }
            }
        }

        Ok(detected)
    }

    /// Try to match an output without label.
    fn try_match_output(
        &self,
        output_pk: &[u8; 32],
        t_k: &[u8; 32],
        output_idx: usize,
        label: Option<u32>,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<Option<DetectedPayment>> {
        let b_spend = PublicKey::from_slice(&self.spend_pubkey)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

        let t_k_sk = SecretKey::from_slice(t_k)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
        let t_k_point = PublicKey::from_secret_key(secp, &t_k_sk);

        let expected_pk = b_spend
            .combine(&t_k_point)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let (expected_xonly, _parity) = expected_pk.x_only_public_key();

        if expected_xonly.serialize() == *output_pk {
            // Compute spending key: b_spend + t_k
            let b_spend_sk = SecretKey::from_slice(&self.spend_privkey)
                .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
            let spending_key = b_spend_sk
                .add_tweak(&t_k_sk.into())
                .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

            return Ok(Some(DetectedPayment {
                output_pubkey: *output_pk,
                spending_key: spending_key.secret_bytes(),
                output_index: output_idx,
                label,
            }));
        }

        Ok(None)
    }

    /// Try to match a labeled output.
    fn try_match_labeled_output(
        &self,
        output_pk: &[u8; 32],
        t_k: &[u8; 32],
        output_idx: usize,
        label: &Label,
        secp: &Secp256k1<secp256k1::All>,
    ) -> Result<Option<DetectedPayment>> {
        // B_m = B_spend + label * G
        let b_m = label.apply_to_pubkey(&self.spend_pubkey)?;

        let b_m_pk = PublicKey::from_slice(&b_m)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

        let t_k_sk = SecretKey::from_slice(t_k)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
        let t_k_point = PublicKey::from_secret_key(secp, &t_k_sk);

        let expected_pk = b_m_pk
            .combine(&t_k_point)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let (expected_xonly, _parity) = expected_pk.x_only_public_key();

        if expected_xonly.serialize() == *output_pk {
            // Compute spending key: b_spend + label + t_k
            let b_m_sk = label.apply_to_privkey(&self.spend_privkey)?;
            let b_m_secret = SecretKey::from_slice(&b_m_sk)
                .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
            let spending_key = b_m_secret
                .add_tweak(&t_k_sk.into())
                .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

            return Ok(Some(DetectedPayment {
                output_pubkey: *output_pk,
                spending_key: spending_key.secret_bytes(),
                output_index: output_idx,
                label: Some(label.index()),
            }));
        }

        Ok(None)
    }
}

/// Light scanner using only scan key (cannot compute spending keys).
pub struct LightScanner {
    /// Scan private key
    scan_privkey: [u8; 32],
    /// Spend public key
    spend_pubkey: [u8; 33],
}

impl LightScanner {
    /// Create a new light scanner.
    pub fn new(scan_privkey: &[u8; 32], spend_pubkey: &[u8; 33]) -> Result<Self> {
        // Validate keys
        SecretKey::from_slice(scan_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        PublicKey::from_slice(spend_pubkey)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

        Ok(Self {
            scan_privkey: *scan_privkey,
            spend_pubkey: *spend_pubkey,
        })
    }

    /// Check if an output belongs to this address.
    pub fn check_output(
        &self,
        output_pk: &[u8; 32],
        input_pubkeys: &[[u8; 33]],
        outpoints: &[([u8; 32], u32)],
    ) -> Result<bool> {
        if input_pubkeys.is_empty() || outpoints.is_empty() {
            return Ok(false);
        }

        let secp = Secp256k1::new();

        let a_sum = sum_public_keys(input_pubkeys)?;
        let input_hash = compute_input_hash(outpoints, &a_sum)?;

        let a_sum_pk = PublicKey::from_slice(&a_sum)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;
        let input_hash_sk = SecretKey::from_slice(&input_hash)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
        let tweaked_a = a_sum_pk
            .mul_tweak(&secp, &input_hash_sk.into())
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let b_scan = SecretKey::from_slice(&self.scan_privkey)
            .map_err(|e| SilentPaymentError::InvalidPrivateKey(e.to_string()))?;
        let shared_secret_point = tweaked_a
            .mul_tweak(&secp, &b_scan.into())
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let t_0 = compute_output_tweak(&shared_secret_point.serialize(), 0);

        let b_spend = PublicKey::from_slice(&self.spend_pubkey)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;
        let t_0_sk = SecretKey::from_slice(&t_0)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
        let t_0_point = PublicKey::from_secret_key(&secp, &t_0_sk);

        let expected_pk = b_spend
            .combine(&t_0_point)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;

        let (expected_xonly, _parity) = expected_pk.x_only_public_key();

        Ok(expected_xonly.serialize() == *output_pk)
    }
}

/// Sum public keys.
fn sum_public_keys(keys: &[[u8; 33]]) -> Result<[u8; 33]> {
    if keys.is_empty() {
        return Err(SilentPaymentError::NoInputs);
    }

    let mut sum = PublicKey::from_slice(&keys[0])
        .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

    for key in &keys[1..] {
        let pk = PublicKey::from_slice(key)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;
        sum = sum
            .combine(&pk)
            .map_err(|e| SilentPaymentError::CryptoError(e.to_string()))?;
    }

    Ok(sum.serialize())
}

/// Compute input hash.
fn compute_input_hash(outpoints: &[([u8; 32], u32)], a_sum: &[u8; 33]) -> Result<[u8; 32]> {
    let mut sorted: Vec<_> = outpoints.to_vec();
    sorted.sort_by(|a, b| {
        let cmp = a.0.cmp(&b.0);
        if cmp == std::cmp::Ordering::Equal {
            a.1.cmp(&b.1)
        } else {
            cmp
        }
    });

    let mut hasher = Sha256::new();
    hasher.update(sorted[0].0);
    hasher.update(sorted[0].1.to_le_bytes());
    hasher.update(a_sum);

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);

    Ok(hash)
}

/// Compute output tweak.
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
    use crate::address::SilentPaymentAddress;
    use crate::network::Network;
    use crate::sender::create_outputs;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_scanner_creation() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let scanner =
            SilentPaymentScanner::new(&scan_key.to_bytes(), &spend_key.to_bytes()).unwrap();

        assert!(scanner.labels.labels().is_empty());
    }

    #[test]
    fn test_light_scanner() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let scanner = LightScanner::new(
            &scan_key.to_bytes(),
            &spend_key.public_key().to_compressed().try_into().unwrap(),
        )
        .unwrap();

        // Just verify it was created
        assert_eq!(scanner.spend_pubkey.len(), 33);
    }

    #[test]
    fn test_end_to_end_payment() {
        // Sender setup
        let sender_key = PrivateKey::random();
        let sender_pubkey: [u8; 33] = sender_key
            .public_key()
            .to_compressed()
            .try_into()
            .unwrap();

        // Receiver setup
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let sp_address = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        // Create payment
        let outpoints = vec![([1u8; 32], 0u32)];
        let outputs =
            create_outputs(&[sender_key.to_bytes()], &outpoints, &[sp_address]).unwrap();

        assert_eq!(outputs.len(), 1);

        // Scan for payment
        let scanner =
            SilentPaymentScanner::new(&scan_key.to_bytes(), &spend_key.to_bytes()).unwrap();

        let detected = scanner
            .scan(&[outputs[0].output_pubkey], &[sender_pubkey], &outpoints)
            .unwrap();

        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].output_pubkey, outputs[0].output_pubkey);
        assert!(detected[0].label.is_none());

        // Verify spending key produces correct public key
        let secp = Secp256k1::new();
        let spending_sk = SecretKey::from_slice(&detected[0].spending_key).unwrap();
        let spending_pk = PublicKey::from_secret_key(&secp, &spending_sk);
        let (xonly, _) = spending_pk.x_only_public_key();

        assert_eq!(xonly.serialize(), outputs[0].output_pubkey);
    }
}
