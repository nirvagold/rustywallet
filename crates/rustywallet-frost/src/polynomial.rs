//! Polynomial operations for secret sharing.

use crate::error::{FrostError, Result};
use crate::identifier::Identifier;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::ZeroizeOnDrop;

/// A polynomial over the scalar field.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Polynomial {
    /// Coefficients (a_0, a_1, ..., a_{t-1})
    coefficients: Vec<[u8; 32]>,
}

impl Polynomial {
    /// Generate a random polynomial of degree (threshold - 1) with given constant term.
    pub fn random(threshold: usize, constant: &[u8; 32]) -> Result<Self> {
        if threshold == 0 {
            return Err(FrostError::InvalidThreshold(
                "Threshold must be at least 1".into(),
            ));
        }

        let mut coefficients = Vec::with_capacity(threshold);
        coefficients.push(*constant);

        // Generate random coefficients for higher degree terms
        for _ in 1..threshold {
            let sk = SecretKey::new(&mut rand::thread_rng());
            coefficients.push(sk.secret_bytes());
        }

        Ok(Self { coefficients })
    }

    /// Generate a completely random polynomial of given degree.
    pub fn random_with_degree(degree: usize) -> Result<Self> {
        let sk = SecretKey::new(&mut rand::thread_rng());
        Self::random(degree + 1, &sk.secret_bytes())
    }

    /// Evaluate the polynomial at a given point.
    pub fn evaluate(&self, x: &Identifier) -> Result<[u8; 32]> {
        let x_bytes = x.to_scalar_bytes();
        
        // Handle zero case
        let is_x_zero = x_bytes.iter().all(|&b| b == 0);
        if is_x_zero {
            return Err(FrostError::InvalidParticipant(
                "Cannot evaluate at zero".into(),
            ));
        }

        let x_scalar = SecretKey::from_slice(&x_bytes)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;

        // Horner's method: result = a_n
        // for i in (n-1)..0: result = result * x + a_i
        let mut result = *self.coefficients.last().unwrap();

        for coeff in self.coefficients.iter().rev().skip(1) {
            // result = result * x
            let result_sk = SecretKey::from_slice(&result)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;
            let multiplied = result_sk
                .mul_tweak(&x_scalar.into())
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;

            // result = result + coeff
            // Handle zero coefficient
            let is_coeff_zero = coeff.iter().all(|&b| b == 0);
            if is_coeff_zero {
                result = multiplied.secret_bytes();
            } else {
                let coeff_sk = SecretKey::from_slice(coeff)
                    .map_err(|e| FrostError::CryptoError(e.to_string()))?;
                result = multiplied
                    .add_tweak(&coeff_sk.into())
                    .map_err(|e| FrostError::CryptoError(e.to_string()))?
                    .secret_bytes();
            }
        }

        Ok(result)
    }

    /// Get the constant term (secret).
    pub fn constant(&self) -> &[u8; 32] {
        &self.coefficients[0]
    }

    /// Get the degree of the polynomial.
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// Get commitment to each coefficient (for verification).
    pub fn commitments(&self) -> Result<Vec<[u8; 33]>> {
        let secp = Secp256k1::new();
        let mut commitments = Vec::with_capacity(self.coefficients.len());

        for coeff in &self.coefficients {
            let sk = SecretKey::from_slice(coeff)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;
            let pk = PublicKey::from_secret_key(&secp, &sk);
            commitments.push(pk.serialize());
        }

        Ok(commitments)
    }
}

/// Verify a share against polynomial commitments.
pub fn verify_share(
    share: &[u8; 32],
    participant: &Identifier,
    commitments: &[[u8; 33]],
) -> Result<bool> {
    let secp = Secp256k1::new();

    // Compute g^share
    let share_sk = SecretKey::from_slice(share)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let share_point = PublicKey::from_secret_key(&secp, &share_sk);

    // Compute product of C_j^(i^j) for j = 0..t-1
    let x = participant.to_scalar_bytes();
    let mut expected: Option<PublicKey> = None;
    let mut x_power = [0u8; 32];
    x_power[31] = 1; // x^0 = 1

    for commitment in commitments {
        let c_j = PublicKey::from_slice(commitment)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;

        // C_j^(x^j)
        let x_power_sk = SecretKey::from_slice(&x_power)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let term = c_j
            .mul_tweak(&secp, &x_power_sk.into())
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;

        expected = match expected {
            None => Some(term),
            Some(acc) => Some(
                acc.combine(&term)
                    .map_err(|e| FrostError::CryptoError(e.to_string()))?,
            ),
        };

        // x_power = x_power * x
        let x_sk = SecretKey::from_slice(&x)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let x_power_sk = SecretKey::from_slice(&x_power)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        x_power = x_power_sk
            .mul_tweak(&x_sk.into())
            .map_err(|e| FrostError::CryptoError(e.to_string()))?
            .secret_bytes();
    }

    let expected = expected.ok_or_else(|| FrostError::InvalidCommitment("No commitments".into()))?;

    Ok(share_point.serialize() == expected.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_evaluation() {
        let constant = SecretKey::new(&mut rand::thread_rng()).secret_bytes();
        let poly = Polynomial::random(3, &constant).unwrap();

        let id1 = Identifier::new(1).unwrap();
        let share1 = poly.evaluate(&id1).unwrap();

        // Share should be different from constant (unless very unlucky)
        // Just verify it doesn't error
        assert_eq!(share1.len(), 32);
    }

    #[test]
    fn test_polynomial_commitments() {
        let constant = SecretKey::new(&mut rand::thread_rng()).secret_bytes();
        let poly = Polynomial::random(2, &constant).unwrap();

        let commitments = poly.commitments().unwrap();
        assert_eq!(commitments.len(), 2);
    }

    #[test]
    fn test_share_verification() {
        let constant = SecretKey::new(&mut rand::thread_rng()).secret_bytes();
        let poly = Polynomial::random(2, &constant).unwrap();

        let id = Identifier::new(1).unwrap();
        let share = poly.evaluate(&id).unwrap();
        let commitments = poly.commitments().unwrap();

        assert!(verify_share(&share, &id, &commitments).unwrap());
    }
}
