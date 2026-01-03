//! MuSig2 key aggregation (BIP327).
//!
//! Implements the KeyAgg algorithm for aggregating multiple public keys
//! into a single aggregate public key.

use crate::error::{MusigError, Result};
use crate::tagged_hash::{tagged_hash, KEYAGG_COEFF_TAG, KEYAGG_LIST_TAG};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Maximum number of signers supported.
pub const MAX_SIGNERS: usize = 100;

/// MuSig2 key aggregation context.
#[derive(Debug, Clone)]
pub struct KeyAggContext {
    /// Sorted individual public keys
    pubkeys: Vec<PublicKey>,
    /// Aggregated public key
    agg_pk: PublicKey,
    /// X-only aggregated public key (32 bytes)
    agg_pk_xonly: [u8; 32],
    /// Key aggregation coefficients
    coefficients: Vec<[u8; 32]>,
    /// Whether the aggregated key has odd Y coordinate
    parity: bool,
    /// Tweak accumulator for key tweaking
    tweak_acc: Option<[u8; 32]>,
}

impl KeyAggContext {
    /// Create a new key aggregation context from public keys.
    ///
    /// Keys are sorted lexicographically as per BIP327.
    pub fn new(pubkeys: &[[u8; 33]]) -> Result<Self> {
        if pubkeys.len() < 2 {
            return Err(MusigError::NotEnoughKeys {
                need: 2,
                got: pubkeys.len(),
            });
        }

        if pubkeys.len() > MAX_SIGNERS {
            return Err(MusigError::TooManyKeys {
                count: pubkeys.len(),
            });
        }

        // Check for duplicates
        for (i, pk1) in pubkeys.iter().enumerate() {
            for pk2 in pubkeys.iter().skip(i + 1) {
                if pk1 == pk2 {
                    return Err(MusigError::DuplicateKey { index: i });
                }
            }
        }

        // Parse and sort public keys
        let mut parsed_keys: Vec<PublicKey> = pubkeys
            .iter()
            .map(|pk| {
                PublicKey::from_slice(pk)
                    .map_err(|e| MusigError::InvalidPublicKey(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;

        parsed_keys.sort_by_key(|a| a.serialize());

        // Compute L = H("KeyAgg list", pk1 || pk2 || ... || pkn)
        let l_hash = compute_l_hash(&parsed_keys);

        // Compute coefficients
        let coefficients: Vec<[u8; 32]> = parsed_keys
            .iter()
            .map(|pk| compute_key_agg_coeff(&l_hash, pk, &parsed_keys))
            .collect();

        // Aggregate keys: Q = sum(a_i * P_i)
        let secp = Secp256k1::new();
        let agg_pk = aggregate_keys(&secp, &parsed_keys, &coefficients)?;

        // Get x-only representation
        let (xonly, parity) = agg_pk.x_only_public_key();
        let mut agg_pk_xonly = [0u8; 32];
        agg_pk_xonly.copy_from_slice(&xonly.serialize());

        Ok(Self {
            pubkeys: parsed_keys,
            agg_pk,
            agg_pk_xonly,
            coefficients,
            parity: parity == secp256k1::Parity::Odd,
            tweak_acc: None,
        })
    }

    /// Get the aggregated public key (33 bytes compressed).
    pub fn aggregated_pubkey(&self) -> [u8; 33] {
        self.agg_pk.serialize()
    }

    /// Get the x-only aggregated public key (32 bytes).
    pub fn xonly_pubkey(&self) -> &[u8; 32] {
        &self.agg_pk_xonly
    }

    /// Get the parity of the aggregated key.
    pub fn parity(&self) -> bool {
        self.parity
    }

    /// Get the number of participants.
    pub fn num_signers(&self) -> usize {
        self.pubkeys.len()
    }

    /// Get the coefficient for a specific public key.
    pub fn coefficient(&self, index: usize) -> Option<&[u8; 32]> {
        self.coefficients.get(index)
    }

    /// Get the sorted public keys.
    pub fn pubkeys(&self) -> Vec<[u8; 33]> {
        self.pubkeys.iter().map(|pk| pk.serialize()).collect()
    }

    /// Find the index of a public key.
    pub fn index_of(&self, pubkey: &[u8; 33]) -> Option<usize> {
        let pk = PublicKey::from_slice(pubkey).ok()?;
        self.pubkeys.iter().position(|p| p == &pk)
    }

    /// Apply a tweak to the aggregated key (for Taproot).
    pub fn apply_tweak(&mut self, tweak: &[u8; 32], is_xonly: bool) -> Result<()> {
        let secp = Secp256k1::new();

        // If xonly tweak and parity is odd, negate the key first
        let mut pk = self.agg_pk;
        if is_xonly && self.parity {
            pk = pk.negate(&secp);
        }

        // Apply the tweak
        let scalar = secp256k1::Scalar::from_be_bytes(*tweak)
            .map_err(|_| MusigError::InvalidPublicKey("Invalid tweak scalar".into()))?;

        let tweaked = pk
            .add_exp_tweak(&secp, &scalar)
            .map_err(|e| MusigError::InvalidPublicKey(e.to_string()))?;

        // Update state
        self.agg_pk = tweaked;
        let (xonly, parity) = tweaked.x_only_public_key();
        self.agg_pk_xonly.copy_from_slice(&xonly.serialize());
        self.parity = parity == secp256k1::Parity::Odd;

        // Accumulate tweak
        self.tweak_acc = Some(*tweak);

        Ok(())
    }

    /// Get the tweak accumulator.
    pub fn tweak_acc(&self) -> Option<&[u8; 32]> {
        self.tweak_acc.as_ref()
    }
}

/// Compute L = tagged_hash("KeyAgg list", pk1 || pk2 || ... || pkn)
fn compute_l_hash(pubkeys: &[PublicKey]) -> [u8; 32] {
    let mut data = Vec::with_capacity(pubkeys.len() * 33);
    for pk in pubkeys {
        data.extend_from_slice(&pk.serialize());
    }
    tagged_hash(KEYAGG_LIST_TAG, &data)
}

/// Compute key aggregation coefficient for a pubkey.
fn compute_key_agg_coeff(l_hash: &[u8; 32], pubkey: &PublicKey, all_pubkeys: &[PublicKey]) -> [u8; 32] {
    // BIP327 optimization: second unique key gets coefficient 1
    if is_second_unique(pubkey, all_pubkeys) {
        let mut one = [0u8; 32];
        one[31] = 1;
        return one;
    }

    // a_i = tagged_hash("KeyAgg coefficient", L || pk_i)
    let mut data = Vec::with_capacity(32 + 33);
    data.extend_from_slice(l_hash);
    data.extend_from_slice(&pubkey.serialize());
    tagged_hash(KEYAGG_COEFF_TAG, &data)
}

/// Check if pubkey is the "second" unique pubkey (BIP327 optimization).
fn is_second_unique(pubkey: &PublicKey, all_pubkeys: &[PublicKey]) -> bool {
    if all_pubkeys.len() < 2 {
        return false;
    }

    let first = &all_pubkeys[0];
    for pk in all_pubkeys.iter().skip(1) {
        if pk != first {
            return pk == pubkey;
        }
    }
    false
}

/// Aggregate public keys with coefficients.
fn aggregate_keys(
    secp: &Secp256k1<secp256k1::All>,
    pubkeys: &[PublicKey],
    coefficients: &[[u8; 32]],
) -> Result<PublicKey> {
    let mut result: Option<PublicKey> = None;

    for (pk, coeff) in pubkeys.iter().zip(coefficients.iter()) {
        // Multiply pubkey by coefficient
        let sk = SecretKey::from_slice(coeff)
            .map_err(|e| MusigError::InvalidPublicKey(format!("Invalid coefficient: {}", e)))?;

        let tweaked = pk
            .mul_tweak(secp, &sk.into())
            .map_err(|e| MusigError::InvalidPublicKey(e.to_string()))?;

        result = match result {
            None => Some(tweaked),
            Some(acc) => Some(
                acc.combine(&tweaked)
                    .map_err(|e| MusigError::InvalidPublicKey(e.to_string()))?,
            ),
        };
    }

    result.ok_or_else(|| MusigError::InvalidPublicKey("Failed to aggregate keys".into()))
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
    fn test_key_agg_2_of_2() {
        let pubkeys = generate_pubkeys(2);
        let ctx = KeyAggContext::new(&pubkeys).unwrap();

        assert_eq!(ctx.num_signers(), 2);
        assert_eq!(ctx.xonly_pubkey().len(), 32);
    }

    #[test]
    fn test_key_agg_deterministic() {
        let pubkeys = generate_pubkeys(3);

        let ctx1 = KeyAggContext::new(&pubkeys).unwrap();
        let ctx2 = KeyAggContext::new(&pubkeys).unwrap();

        assert_eq!(ctx1.aggregated_pubkey(), ctx2.aggregated_pubkey());
    }

    #[test]
    fn test_key_agg_order_independent() {
        let pubkeys = generate_pubkeys(3);
        let mut reversed = pubkeys.clone();
        reversed.reverse();

        let ctx1 = KeyAggContext::new(&pubkeys).unwrap();
        let ctx2 = KeyAggContext::new(&reversed).unwrap();

        assert_eq!(ctx1.aggregated_pubkey(), ctx2.aggregated_pubkey());
    }

    #[test]
    fn test_duplicate_rejected() {
        let pk = PrivateKey::random().public_key().to_compressed();
        let pubkeys = vec![pk, pk];

        assert!(KeyAggContext::new(&pubkeys).is_err());
    }

    #[test]
    fn test_single_key_rejected() {
        let pubkeys = generate_pubkeys(1);
        assert!(KeyAggContext::new(&pubkeys).is_err());
    }
}
