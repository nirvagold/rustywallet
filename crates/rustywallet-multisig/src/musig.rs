//! MuSig2 Schnorr multisig support
//!
//! Implements key aggregation for n-of-n Schnorr multisig (BIP327).
//! Note: This is a simplified implementation for key aggregation only.
//! Full MuSig2 signing requires nonce handling which is complex.

use crate::error::{MultisigError, Result};
use secp256k1::{Secp256k1, PublicKey, SecretKey};
use sha2::{Sha256, Digest};

/// MuSig2 key aggregation context
#[derive(Debug, Clone)]
pub struct MuSigKeyAgg {
    /// Individual public keys (33 bytes compressed)
    pub pubkeys: Vec<[u8; 33]>,
    /// Aggregated public key (33 bytes compressed)
    pub aggregated_pubkey: [u8; 33],
    /// X-only aggregated public key (32 bytes)
    pub xonly_pubkey: [u8; 32],
    /// Key aggregation coefficients
    pub coefficients: Vec<[u8; 32]>,
    /// Whether the aggregated key needed negation
    pub parity: bool,
}

impl MuSigKeyAgg {
    /// Aggregate multiple public keys into a single key (BIP327 KeyAgg)
    ///
    /// # Arguments
    /// * `pubkeys` - List of 33-byte compressed public keys
    ///
    /// # Returns
    /// MuSigKeyAgg context with aggregated key
    pub fn new(pubkeys: Vec<[u8; 33]>) -> Result<Self> {
        if pubkeys.len() < 2 {
            return Err(MultisigError::NotEnoughKeys {
                need: 2,
                got: pubkeys.len(),
            });
        }

        if pubkeys.len() > 100 {
            return Err(MultisigError::TooManyKeys { count: pubkeys.len() });
        }

        // Check for duplicates
        for (i, pk1) in pubkeys.iter().enumerate() {
            for pk2 in pubkeys.iter().skip(i + 1) {
                if pk1 == pk2 {
                    return Err(MultisigError::DuplicateKey { index: i });
                }
            }
        }

        let secp = Secp256k1::new();

        // Sort pubkeys lexicographically (BIP327)
        let mut sorted_pubkeys = pubkeys.clone();
        sorted_pubkeys.sort();

        // Compute L = H(pk1 || pk2 || ... || pkn)
        let l_hash = compute_l_hash(&sorted_pubkeys);

        // Compute coefficients for each key
        let mut coefficients = Vec::with_capacity(sorted_pubkeys.len());
        for pk in &sorted_pubkeys {
            let coeff = compute_key_agg_coeff(&l_hash, pk, &sorted_pubkeys);
            coefficients.push(coeff);
        }

        // Aggregate: Q = sum(a_i * P_i)
        let mut agg_point: Option<PublicKey> = None;

        for (pk_bytes, coeff) in sorted_pubkeys.iter().zip(coefficients.iter()) {
            let pk = PublicKey::from_slice(pk_bytes)
                .map_err(|e| MultisigError::InvalidPublicKey(e.to_string()))?;

            // Multiply pubkey by coefficient
            let tweaked = tweak_pubkey_mul(&secp, &pk, coeff)?;

            agg_point = match agg_point {
                None => Some(tweaked),
                Some(acc) => Some(acc.combine(&tweaked)
                    .map_err(|e| MultisigError::InvalidPublicKey(e.to_string()))?),
            };
        }

        let agg_pubkey = agg_point.ok_or_else(|| {
            MultisigError::InvalidPublicKey("Failed to aggregate keys".to_string())
        })?;

        // Get x-only pubkey and parity
        let (xonly, parity) = agg_pubkey.x_only_public_key();
        let mut xonly_bytes = [0u8; 32];
        xonly_bytes.copy_from_slice(&xonly.serialize());

        Ok(Self {
            pubkeys: sorted_pubkeys,
            aggregated_pubkey: agg_pubkey.serialize(),
            xonly_pubkey: xonly_bytes,
            coefficients,
            parity: parity == secp256k1::Parity::Odd,
        })
    }

    /// Get the aggregated public key (33 bytes compressed)
    pub fn aggregated_pubkey(&self) -> &[u8; 33] {
        &self.aggregated_pubkey
    }

    /// Get the x-only aggregated public key (32 bytes, for Taproot)
    pub fn xonly_pubkey(&self) -> &[u8; 32] {
        &self.xonly_pubkey
    }

    /// Get the coefficient for a specific public key
    pub fn coefficient_for(&self, pubkey: &[u8; 33]) -> Option<&[u8; 32]> {
        self.pubkeys
            .iter()
            .position(|pk| pk == pubkey)
            .map(|idx| &self.coefficients[idx])
    }

    /// Check if a public key is part of this aggregation
    pub fn contains(&self, pubkey: &[u8; 33]) -> bool {
        self.pubkeys.contains(pubkey)
    }

    /// Get number of participants
    pub fn participant_count(&self) -> usize {
        self.pubkeys.len()
    }

    /// Tweak the aggregated key (for Taproot)
    pub fn tweak_add(&self, tweak: &[u8; 32]) -> Result<[u8; 33]> {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_slice(&self.aggregated_pubkey)
            .map_err(|e| MultisigError::InvalidPublicKey(e.to_string()))?;

        let tweaked = pk.add_exp_tweak(&secp, &secp256k1::Scalar::from_be_bytes(*tweak).unwrap())
            .map_err(|e| MultisigError::InvalidPublicKey(e.to_string()))?;

        Ok(tweaked.serialize())
    }
}

/// Compute L = tagged_hash("KeyAgg list", pk1 || pk2 || ... || pkn)
fn compute_l_hash(pubkeys: &[[u8; 33]]) -> [u8; 32] {
    let tag = b"KeyAgg list";
    let tag_hash = Sha256::digest(tag);

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    for pk in pubkeys {
        hasher.update(pk);
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    result
}

/// Compute key aggregation coefficient for a pubkey
fn compute_key_agg_coeff(l_hash: &[u8; 32], pubkey: &[u8; 33], all_pubkeys: &[[u8; 33]]) -> [u8; 32] {
    // If this is the "second" unique pubkey, coefficient is 1
    // This is an optimization from BIP327
    if is_second_unique(pubkey, all_pubkeys) {
        let mut one = [0u8; 32];
        one[31] = 1;
        return one;
    }

    // Otherwise: a_i = tagged_hash("KeyAgg coefficient", L || pk_i)
    let tag = b"KeyAgg coefficient";
    let tag_hash = Sha256::digest(tag);

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(l_hash);
    hasher.update(pubkey);

    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    result
}

/// Check if pubkey is the "second" unique pubkey (BIP327 optimization)
fn is_second_unique(pubkey: &[u8; 33], all_pubkeys: &[[u8; 33]]) -> bool {
    if all_pubkeys.len() < 2 {
        return false;
    }

    // Find first pubkey that's different from the first one
    let first = &all_pubkeys[0];
    for pk in all_pubkeys.iter().skip(1) {
        if pk != first {
            return pk == pubkey;
        }
    }
    false
}

/// Multiply a public key by a scalar
fn tweak_pubkey_mul(secp: &Secp256k1<secp256k1::All>, pk: &PublicKey, scalar: &[u8; 32]) -> Result<PublicKey> {
    // Convert scalar to SecretKey (which acts as a scalar)
    let sk = SecretKey::from_slice(scalar)
        .map_err(|e| MultisigError::InvalidPublicKey(format!("Invalid scalar: {}", e)))?;

    // pk * scalar = (sk * G) where we want pk * scalar
    // We use the fact that pk.mul_tweak multiplies by scalar
    pk.mul_tweak(secp, &sk.into())
        .map_err(|e| MultisigError::InvalidPublicKey(e.to_string()))
}

/// Generate a P2TR address from aggregated MuSig key
pub fn musig_to_p2tr_address(key_agg: &MuSigKeyAgg, network: crate::address::Network) -> Result<String> {
    use bech32::Hrp;

    let hrp = match network {
        crate::address::Network::Mainnet => Hrp::parse("bc").unwrap(),
        crate::address::Network::Testnet => Hrp::parse("tb").unwrap(),
    };

    bech32::segwit::encode(hrp, bech32::segwit::VERSION_1, &key_agg.xonly_pubkey)
        .map_err(|e| MultisigError::AddressFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::prelude::PrivateKey;

    fn generate_pubkeys(count: usize) -> Vec<[u8; 33]> {
        (0..count)
            .map(|_| PrivateKey::random().public_key().to_compressed())
            .collect()
    }

    #[test]
    fn test_key_aggregation_2_of_2() {
        let pubkeys = generate_pubkeys(2);
        let key_agg = MuSigKeyAgg::new(pubkeys.clone()).unwrap();

        assert_eq!(key_agg.participant_count(), 2);
        assert!(key_agg.contains(&pubkeys[0]));
        assert!(key_agg.contains(&pubkeys[1]));

        // Aggregated key should be different from individual keys
        assert_ne!(&key_agg.aggregated_pubkey, &pubkeys[0]);
        assert_ne!(&key_agg.aggregated_pubkey, &pubkeys[1]);
    }

    #[test]
    fn test_key_aggregation_3_of_3() {
        let pubkeys = generate_pubkeys(3);
        let key_agg = MuSigKeyAgg::new(pubkeys).unwrap();

        assert_eq!(key_agg.participant_count(), 3);
        assert_eq!(key_agg.xonly_pubkey.len(), 32);
    }

    #[test]
    fn test_deterministic_aggregation() {
        let pubkeys = generate_pubkeys(3);

        let key_agg1 = MuSigKeyAgg::new(pubkeys.clone()).unwrap();
        let key_agg2 = MuSigKeyAgg::new(pubkeys).unwrap();

        assert_eq!(key_agg1.aggregated_pubkey, key_agg2.aggregated_pubkey);
        assert_eq!(key_agg1.xonly_pubkey, key_agg2.xonly_pubkey);
    }

    #[test]
    fn test_order_independent() {
        let pubkeys = generate_pubkeys(3);
        let mut reversed = pubkeys.clone();
        reversed.reverse();

        let key_agg1 = MuSigKeyAgg::new(pubkeys).unwrap();
        let key_agg2 = MuSigKeyAgg::new(reversed).unwrap();

        // Should produce same result regardless of input order
        assert_eq!(key_agg1.aggregated_pubkey, key_agg2.aggregated_pubkey);
    }

    #[test]
    fn test_duplicate_key_rejected() {
        let pk = PrivateKey::random().public_key().to_compressed();
        let pubkeys = vec![pk, pk];

        let result = MuSigKeyAgg::new(pubkeys);
        assert!(result.is_err());
    }

    #[test]
    fn test_single_key_rejected() {
        let pubkeys = generate_pubkeys(1);
        let result = MuSigKeyAgg::new(pubkeys);
        assert!(result.is_err());
    }

    #[test]
    fn test_coefficients_exist() {
        let pubkeys = generate_pubkeys(3);
        let key_agg = MuSigKeyAgg::new(pubkeys.clone()).unwrap();

        for pk in &key_agg.pubkeys {
            assert!(key_agg.coefficient_for(pk).is_some());
        }
    }

    #[test]
    fn test_p2tr_address_generation() {
        let pubkeys = generate_pubkeys(2);
        let key_agg = MuSigKeyAgg::new(pubkeys).unwrap();

        let address = musig_to_p2tr_address(&key_agg, crate::address::Network::Mainnet).unwrap();
        assert!(address.starts_with("bc1p"));

        let testnet_addr = musig_to_p2tr_address(&key_agg, crate::address::Network::Testnet).unwrap();
        assert!(testnet_addr.starts_with("tb1p"));
    }
}
