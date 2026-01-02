//! Shamir Secret Sharing implementation.
//!
//! Uses GF(256) finite field arithmetic for splitting and combining secrets.

use crate::error::{MultisigError, Result};
use zeroize::Zeroize;

/// A single share of a split secret.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct ShamirShare {
    /// Share index (1-255)
    pub index: u8,
    /// Threshold required to reconstruct
    pub threshold: u8,
    /// Total number of shares
    pub total: u8,
    /// Share data (32 bytes for a private key)
    pub data: [u8; 32],
}

impl ShamirShare {
    /// Create a new share.
    pub fn new(index: u8, threshold: u8, total: u8, data: [u8; 32]) -> Result<Self> {
        if index == 0 {
            return Err(MultisigError::InvalidShareIndex(index));
        }
        Ok(Self {
            index,
            threshold,
            total,
            data,
        })
    }

    /// Encode share to hex string.
    pub fn to_hex(&self) -> String {
        let mut bytes = Vec::with_capacity(35);
        bytes.push(self.index);
        bytes.push(self.threshold);
        bytes.push(self.total);
        bytes.extend_from_slice(&self.data);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Decode share from hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| MultisigError::ShamirError("Invalid hex".to_string()))?;

        if bytes.len() != 35 {
            return Err(MultisigError::ShamirError("Invalid share length".to_string()));
        }

        let mut data = [0u8; 32];
        data.copy_from_slice(&bytes[3..35]);

        Self::new(bytes[0], bytes[1], bytes[2], data)
    }
}

/// Split a 32-byte secret into N shares with M threshold.
///
/// # Arguments
/// * `secret` - The 32-byte secret to split
/// * `threshold` - Minimum shares needed to reconstruct (M)
/// * `total` - Total number of shares to generate (N)
///
/// # Returns
/// Vector of shares
pub fn split_secret(secret: &[u8; 32], threshold: u8, total: u8) -> Result<Vec<ShamirShare>> {
    if threshold == 0 || threshold > total {
        return Err(MultisigError::InvalidThreshold {
            m: threshold,
            n: total,
        });
    }

    if total == 0 {
        return Err(MultisigError::ShamirError("Total must be > 0".to_string()));
    }

    let mut shares = Vec::with_capacity(total as usize);

    // For each byte position
    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        // Generate random coefficients for polynomial
        // f(x) = secret + a1*x + a2*x^2 + ... + a(m-1)*x^(m-1)
        let mut coefficients = vec![secret_byte];
        for _ in 1..threshold {
            coefficients.push(rand_byte());
        }

        // Evaluate polynomial at x = 1, 2, ..., N
        for share_idx in 0..total {
            let x = share_idx + 1;
            let y = evaluate_polynomial(&coefficients, x);

            if byte_idx == 0 {
                shares.push(ShamirShare {
                    index: x,
                    threshold,
                    total,
                    data: [0u8; 32],
                });
            }
            shares[share_idx as usize].data[byte_idx] = y;
        }
    }

    Ok(shares)
}

/// Combine shares to reconstruct the secret.
///
/// # Arguments
/// * `shares` - At least M shares
///
/// # Returns
/// The reconstructed 32-byte secret
pub fn combine_shares(shares: &[ShamirShare]) -> Result<[u8; 32]> {
    if shares.is_empty() {
        return Err(MultisigError::ShamirError("No shares provided".to_string()));
    }

    let threshold = shares[0].threshold;
    if shares.len() < threshold as usize {
        return Err(MultisigError::NotEnoughSignatures {
            need: threshold as usize,
            got: shares.len(),
        });
    }

    // Check for duplicate indices
    let mut seen = std::collections::HashSet::new();
    for share in shares {
        if !seen.insert(share.index) {
            return Err(MultisigError::DuplicateShareIndex(share.index));
        }
    }

    let mut secret = [0u8; 32];

    // Use Lagrange interpolation for each byte
    for (byte_idx, secret_byte) in secret.iter_mut().enumerate() {
        let points: Vec<(u8, u8)> = shares
            .iter()
            .take(threshold as usize)
            .map(|s| (s.index, s.data[byte_idx]))
            .collect();

        *secret_byte = lagrange_interpolate(&points, 0);
    }

    Ok(secret)
}

/// Evaluate polynomial at x using Horner's method in GF(256).
fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &coef in coefficients.iter().rev() {
        result = gf256_add(gf256_mul(result, x), coef);
    }
    result
}

/// Lagrange interpolation at x=0 in GF(256).
fn lagrange_interpolate(points: &[(u8, u8)], _x: u8) -> u8 {
    let mut result = 0u8;

    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut term = yi;

        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                // term *= xj / (xj - xi)
                let num = xj;
                let denom = gf256_sub(xj, xi);
                term = gf256_mul(term, gf256_mul(num, gf256_inv(denom)));
            }
        }

        result = gf256_add(result, term);
    }

    result
}

// GF(256) arithmetic using the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)

/// Addition in GF(256) is XOR.
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtraction in GF(256) is also XOR.
fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(256).
fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;

    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1b; // Reduce by x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }

    result
}

/// Multiplicative inverse in GF(256) using extended Euclidean algorithm.
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0; // 0 has no inverse, but we handle it gracefully
    }

    // Use exponentiation: a^254 = a^(-1) in GF(256)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

/// Generate a random byte.
fn rand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    static mut COUNTER: u64 = 0;
    
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    unsafe {
        COUNTER = COUNTER.wrapping_add(1);
        let seed = time ^ COUNTER;
        // Simple PRNG
        ((seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407)) >> 56) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_combine_2_of_3() {
        let secret = [0x42u8; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();
        
        assert_eq!(shares.len(), 3);
        
        // Combine with first 2 shares
        let recovered = combine_shares(&shares[0..2]).unwrap();
        assert_eq!(recovered, secret);
        
        // Combine with last 2 shares
        let recovered = combine_shares(&shares[1..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_split_and_combine_3_of_5() {
        let secret = [0xab; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        
        assert_eq!(shares.len(), 5);
        
        // Combine with shares 0, 2, 4
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = combine_shares(&subset).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_not_enough_shares() {
        let secret = [0x11; 32];
        let shares = split_secret(&secret, 3, 5).unwrap();
        
        // Try with only 2 shares (need 3)
        let result = combine_shares(&shares[0..2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_share_index() {
        let secret = [0x22; 32];
        let shares = split_secret(&secret, 2, 3).unwrap();
        
        // Duplicate the first share
        let duplicate = vec![shares[0].clone(), shares[0].clone()];
        let result = combine_shares(&duplicate);
        assert!(matches!(result, Err(MultisigError::DuplicateShareIndex(_))));
    }

    #[test]
    fn test_share_serialization() {
        let share = ShamirShare::new(1, 2, 3, [0xab; 32]).unwrap();
        let hex = share.to_hex();
        let recovered = ShamirShare::from_hex(&hex).unwrap();
        
        assert_eq!(recovered.index, share.index);
        assert_eq!(recovered.threshold, share.threshold);
        assert_eq!(recovered.total, share.total);
        assert_eq!(recovered.data, share.data);
    }

    #[test]
    fn test_gf256_arithmetic() {
        // Test that a * inv(a) = 1
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            let product = gf256_mul(a, inv);
            assert_eq!(product, 1, "Failed for a={}", a);
        }
    }

    #[test]
    fn test_invalid_threshold() {
        let secret = [0x00; 32];
        
        // threshold = 0
        let result = split_secret(&secret, 0, 3);
        assert!(result.is_err());
        
        // threshold > total
        let result = split_secret(&secret, 5, 3);
        assert!(result.is_err());
    }
}
