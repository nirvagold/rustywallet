//! MuSig2 nonce generation and aggregation.
//!
//! Implements secure nonce generation as per BIP327.
//! CRITICAL: Nonces must NEVER be reused!

use crate::error::{MusigError, Result};
use crate::tagged_hash::{tagged_hash, MUSIG_AUX_TAG, MUSIG_NONCE_TAG, MUSIG_NONCECOEF_TAG};
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret nonce pair (k1, k2) - MUST be kept secret and used only once.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretNonce {
    /// First secret nonce
    k1: [u8; 32],
    /// Second secret nonce
    k2: [u8; 32],
    /// Flag to track if nonce has been used
    #[zeroize(skip)]
    used: bool,
}

impl SecretNonce {
    /// Generate a new random secret nonce.
    ///
    /// Uses secure randomness with optional auxiliary data for extra entropy.
    pub fn generate(
        secret_key: &[u8; 32],
        pubkey: &[u8; 33],
        agg_pk: &[u8; 32],
        msg: Option<&[u8; 32]>,
        extra_input: Option<&[u8]>,
    ) -> Result<Self> {
        let mut rand_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut rand_bytes);

        Self::generate_with_aux(secret_key, pubkey, agg_pk, msg, extra_input, &rand_bytes)
    }

    /// Generate nonce with explicit auxiliary randomness.
    pub fn generate_with_aux(
        secret_key: &[u8; 32],
        pubkey: &[u8; 33],
        agg_pk: &[u8; 32],
        msg: Option<&[u8; 32]>,
        extra_input: Option<&[u8]>,
        aux_rand: &[u8; 32],
    ) -> Result<Self> {
        // XOR secret key with tagged hash of aux randomness
        let aux_hash = tagged_hash(MUSIG_AUX_TAG, aux_rand);
        let mut masked_sk = [0u8; 32];
        for i in 0..32 {
            masked_sk[i] = secret_key[i] ^ aux_hash[i];
        }

        // Generate k1
        let k1 = generate_nonce_k(&masked_sk, pubkey, agg_pk, msg, extra_input, 0)?;

        // Generate k2
        let k2 = generate_nonce_k(&masked_sk, pubkey, agg_pk, msg, extra_input, 1)?;

        // Zeroize masked secret key
        masked_sk.zeroize();

        Ok(Self {
            k1,
            k2,
            used: false,
        })
    }

    /// Get the public nonce corresponding to this secret nonce.
    pub fn public_nonce(&self) -> Result<PublicNonce> {
        let secp = Secp256k1::new();

        let sk1 = SecretKey::from_slice(&self.k1)
            .map_err(|e| MusigError::InvalidNonce(e.to_string()))?;
        let sk2 = SecretKey::from_slice(&self.k2)
            .map_err(|e| MusigError::InvalidNonce(e.to_string()))?;

        let r1 = PublicKey::from_secret_key(&secp, &sk1);
        let r2 = PublicKey::from_secret_key(&secp, &sk2);

        Ok(PublicNonce {
            r1: r1.serialize(),
            r2: r2.serialize(),
        })
    }

    /// Mark this nonce as used (prevents reuse).
    pub fn mark_used(&mut self) {
        self.used = true;
    }

    /// Check if this nonce has been used.
    pub fn is_used(&self) -> bool {
        self.used
    }

    /// Get k1 (for signing) - only if not used.
    pub(crate) fn k1(&self) -> Result<&[u8; 32]> {
        if self.used {
            return Err(MusigError::NonceReuse);
        }
        Ok(&self.k1)
    }

    /// Get k2 (for signing) - only if not used.
    pub(crate) fn k2(&self) -> Result<&[u8; 32]> {
        if self.used {
            return Err(MusigError::NonceReuse);
        }
        Ok(&self.k2)
    }
}

impl fmt::Debug for SecretNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretNonce")
            .field("k1", &"[REDACTED]")
            .field("k2", &"[REDACTED]")
            .field("used", &self.used)
            .finish()
    }
}

/// Public nonce pair (R1, R2) - can be shared publicly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNonce {
    /// First public nonce point (33 bytes compressed)
    pub r1: [u8; 33],
    /// Second public nonce point (33 bytes compressed)
    pub r2: [u8; 33],
}

impl PublicNonce {
    /// Create from raw bytes (66 bytes total).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 66 {
            return Err(MusigError::InvalidNonce(format!(
                "Expected 66 bytes, got {}",
                bytes.len()
            )));
        }

        let mut r1 = [0u8; 33];
        let mut r2 = [0u8; 33];
        r1.copy_from_slice(&bytes[..33]);
        r2.copy_from_slice(&bytes[33..]);

        // Validate points
        PublicKey::from_slice(&r1).map_err(|e| MusigError::InvalidNonce(e.to_string()))?;
        PublicKey::from_slice(&r2).map_err(|e| MusigError::InvalidNonce(e.to_string()))?;

        Ok(Self { r1, r2 })
    }

    /// Serialize to bytes (66 bytes).
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(&self.r1);
        bytes[33..].copy_from_slice(&self.r2);
        bytes
    }

    /// Serialize to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Parse from hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str).map_err(|e| MusigError::HexError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Aggregated nonce from all signers.
#[derive(Debug, Clone)]
pub struct AggregatedNonce {
    /// Aggregated R point (33 bytes compressed)
    pub agg_r: [u8; 33],
    /// X-only R (32 bytes)
    pub agg_r_xonly: [u8; 32],
    /// Whether R needed negation
    pub parity: bool,
}

impl AggregatedNonce {
    /// Aggregate public nonces from all signers.
    pub fn aggregate(
        public_nonces: &[PublicNonce],
        agg_pk: &[u8; 32],
        msg: &[u8; 32],
    ) -> Result<Self> {
        if public_nonces.is_empty() {
            return Err(MusigError::InvalidNonce("No nonces to aggregate".into()));
        }

        let secp = Secp256k1::new();

        // Compute nonce coefficient b
        let b = compute_nonce_coeff(public_nonces, agg_pk, msg)?;

        // Aggregate: R = sum(R1_i) + b * sum(R2_i)
        let mut sum_r1: Option<PublicKey> = None;
        let mut sum_r2: Option<PublicKey> = None;

        for nonce in public_nonces {
            let r1 = PublicKey::from_slice(&nonce.r1)
                .map_err(|e| MusigError::InvalidNonce(e.to_string()))?;
            let r2 = PublicKey::from_slice(&nonce.r2)
                .map_err(|e| MusigError::InvalidNonce(e.to_string()))?;

            sum_r1 = match sum_r1 {
                None => Some(r1),
                Some(acc) => Some(
                    acc.combine(&r1)
                        .map_err(|e| MusigError::InvalidNonce(e.to_string()))?,
                ),
            };

            sum_r2 = match sum_r2 {
                None => Some(r2),
                Some(acc) => Some(
                    acc.combine(&r2)
                        .map_err(|e| MusigError::InvalidNonce(e.to_string()))?,
                ),
            };
        }

        let sum_r1 = sum_r1.ok_or_else(|| MusigError::InvalidNonce("Empty R1 sum".into()))?;
        let sum_r2 = sum_r2.ok_or_else(|| MusigError::InvalidNonce("Empty R2 sum".into()))?;

        // Multiply sum_r2 by b
        let b_scalar = SecretKey::from_slice(&b)
            .map_err(|e| MusigError::InvalidNonce(format!("Invalid b scalar: {}", e)))?;

        let b_times_r2 = sum_r2
            .mul_tweak(&secp, &b_scalar.into())
            .map_err(|e| MusigError::InvalidNonce(e.to_string()))?;

        // R = sum_r1 + b * sum_r2
        let agg_r = sum_r1
            .combine(&b_times_r2)
            .map_err(|e| MusigError::InvalidNonce(e.to_string()))?;

        // Get x-only representation
        let (xonly, parity) = agg_r.x_only_public_key();
        let mut agg_r_xonly = [0u8; 32];
        agg_r_xonly.copy_from_slice(&xonly.serialize());

        Ok(Self {
            agg_r: agg_r.serialize(),
            agg_r_xonly,
            parity: parity == secp256k1::Parity::Odd,
        })
    }
}

/// Generate a single nonce value k.
fn generate_nonce_k(
    masked_sk: &[u8; 32],
    pubkey: &[u8; 33],
    agg_pk: &[u8; 32],
    msg: Option<&[u8; 32]>,
    extra_input: Option<&[u8]>,
    index: u8,
) -> Result<[u8; 32]> {
    let mut data = Vec::new();
    data.extend_from_slice(masked_sk);
    data.extend_from_slice(pubkey);
    data.extend_from_slice(agg_pk);

    if let Some(m) = msg {
        data.push(32); // length prefix
        data.extend_from_slice(m);
    } else {
        data.push(0);
    }

    if let Some(extra) = extra_input {
        data.extend_from_slice(&(extra.len() as u32).to_be_bytes());
        data.extend_from_slice(extra);
    } else {
        data.extend_from_slice(&0u32.to_be_bytes());
    }

    data.push(index);

    let hash = tagged_hash(MUSIG_NONCE_TAG, &data);

    // Ensure it's a valid scalar (non-zero)
    if hash == [0u8; 32] {
        return Err(MusigError::InvalidNonce("Generated zero nonce".into()));
    }

    Ok(hash)
}

/// Compute nonce coefficient b.
pub fn compute_nonce_coeff(
    public_nonces: &[PublicNonce],
    agg_pk: &[u8; 32],
    msg: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut data = Vec::new();

    // Concatenate all public nonces
    for nonce in public_nonces {
        data.extend_from_slice(&nonce.r1);
        data.extend_from_slice(&nonce.r2);
    }

    data.extend_from_slice(agg_pk);
    data.extend_from_slice(msg);

    Ok(tagged_hash(MUSIG_NONCECOEF_TAG, &data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::prelude::PrivateKey;

    #[test]
    fn test_secret_nonce_generation() {
        let sk = PrivateKey::random();
        let pk = sk.public_key().to_compressed();
        let agg_pk = [0u8; 32];

        let nonce = SecretNonce::generate(&sk.to_bytes(), &pk, &agg_pk, None, None).unwrap();

        assert!(!nonce.is_used());
    }

    #[test]
    fn test_public_nonce_from_secret() {
        let sk = PrivateKey::random();
        let pk = sk.public_key().to_compressed();
        let agg_pk = [0u8; 32];

        let secret_nonce =
            SecretNonce::generate(&sk.to_bytes(), &pk, &agg_pk, None, None).unwrap();
        let public_nonce = secret_nonce.public_nonce().unwrap();

        assert_eq!(public_nonce.r1.len(), 33);
        assert_eq!(public_nonce.r2.len(), 33);
    }

    #[test]
    fn test_public_nonce_serialization() {
        let sk = PrivateKey::random();
        let pk = sk.public_key().to_compressed();
        let agg_pk = [0u8; 32];

        let secret_nonce =
            SecretNonce::generate(&sk.to_bytes(), &pk, &agg_pk, None, None).unwrap();
        let public_nonce = secret_nonce.public_nonce().unwrap();

        let bytes = public_nonce.to_bytes();
        let recovered = PublicNonce::from_bytes(&bytes).unwrap();

        assert_eq!(public_nonce, recovered);
    }

    #[test]
    fn test_nonce_aggregation() {
        let sk1 = PrivateKey::random();
        let sk2 = PrivateKey::random();
        let pk1 = sk1.public_key().to_compressed();
        let pk2 = sk2.public_key().to_compressed();
        let agg_pk = [1u8; 32];
        let msg = [2u8; 32];

        let nonce1 = SecretNonce::generate(&sk1.to_bytes(), &pk1, &agg_pk, Some(&msg), None)
            .unwrap()
            .public_nonce()
            .unwrap();
        let nonce2 = SecretNonce::generate(&sk2.to_bytes(), &pk2, &agg_pk, Some(&msg), None)
            .unwrap()
            .public_nonce()
            .unwrap();

        let agg_nonce = AggregatedNonce::aggregate(&[nonce1, nonce2], &agg_pk, &msg).unwrap();

        assert_eq!(agg_nonce.agg_r.len(), 33);
        assert_eq!(agg_nonce.agg_r_xonly.len(), 32);
    }

    #[test]
    fn test_nonce_reuse_prevention() {
        let sk = PrivateKey::random();
        let pk = sk.public_key().to_compressed();
        let agg_pk = [0u8; 32];

        let mut nonce = SecretNonce::generate(&sk.to_bytes(), &pk, &agg_pk, None, None).unwrap();

        // First access should work
        assert!(nonce.k1().is_ok());

        // Mark as used
        nonce.mark_used();

        // Second access should fail
        assert!(nonce.k1().is_err());
    }
}
