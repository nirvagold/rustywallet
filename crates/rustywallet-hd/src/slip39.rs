//! SLIP39 - Shamir's Secret Sharing for Mnemonic Codes
//!
//! This module implements SLIP39 (Shamir's Secret-Sharing for Mnemonic Codes),
//! which allows splitting a master secret into multiple shares where a threshold
//! number of shares is required to reconstruct the original secret.
//!
//! ## Features
//!
//! - Split secrets into multiple shares with configurable threshold
//! - Combine shares to recover the original secret
//! - Multi-group support with different thresholds per group
//! - Checksum validation for share integrity
//!
//! ## Example
//!
//! ```
//! use rustywallet_hd::slip39::{Slip39, Slip39Share};
//!
//! // Create a 2-of-3 sharing scheme
//! let slip39 = Slip39::new(2, 3).unwrap();
//!
//! // Split a 32-byte secret
//! let secret = [0x42u8; 32];
//! let shares = slip39.split(&secret).unwrap();
//!
//! // Recover using any 2 shares
//! let recovered = Slip39::combine(&shares[0..2]).unwrap();
//! assert_eq!(secret.to_vec(), recovered);
//! ```
//!
//! ## Security
//!
//! - Uses GF(256) arithmetic for Shamir's Secret Sharing
//! - Shares are zeroized on drop
//! - Minimum threshold of 1, maximum of 16 shares per group

use crate::error::HdError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of shares in a single group
pub const MAX_SHARES: u8 = 16;

/// Minimum threshold (at least 1 share required)
pub const MIN_THRESHOLD: u8 = 1;

/// SLIP39 share identifier
pub const SLIP39_ID_LENGTH: usize = 2;

/// SLIP39 share data
#[derive(Clone)]
pub struct Slip39Share {
    /// Share identifier (random, same for all shares in a set)
    pub identifier: [u8; SLIP39_ID_LENGTH],
    /// Iteration exponent for PBKDF2 (0-3)
    pub iteration_exponent: u8,
    /// Group index (0-15)
    pub group_index: u8,
    /// Group threshold (1-16)
    pub group_threshold: u8,
    /// Group count (1-16)
    pub group_count: u8,
    /// Member index within group (0-15)
    pub member_index: u8,
    /// Member threshold (1-16)
    pub member_threshold: u8,
    /// Share value (the actual secret share data)
    pub share_value: Zeroizing<Vec<u8>>,
    /// Checksum for validation
    pub checksum: [u8; 4],
}

impl Slip39Share {
    /// Create a new share with the given parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identifier: [u8; SLIP39_ID_LENGTH],
        iteration_exponent: u8,
        group_index: u8,
        group_threshold: u8,
        group_count: u8,
        member_index: u8,
        member_threshold: u8,
        share_value: Vec<u8>,
    ) -> Self {
        let mut share = Self {
            identifier,
            iteration_exponent,
            group_index,
            group_threshold,
            group_count,
            member_index,
            member_threshold,
            share_value: Zeroizing::new(share_value),
            checksum: [0; 4],
        };
        share.checksum = share.compute_checksum();
        share
    }

    /// Compute checksum for this share
    fn compute_checksum(&self) -> [u8; 4] {
        let mut mac = HmacSha256::new_from_slice(b"slip39-checksum")
            .expect("HMAC can take key of any size");
        mac.update(&self.identifier);
        mac.update(&[self.iteration_exponent]);
        mac.update(&[self.group_index]);
        mac.update(&[self.group_threshold]);
        mac.update(&[self.group_count]);
        mac.update(&[self.member_index]);
        mac.update(&[self.member_threshold]);
        mac.update(&self.share_value);
        
        let result = mac.finalize().into_bytes();
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&result[..4]);
        checksum
    }

    /// Validate the share checksum
    pub fn validate(&self) -> bool {
        self.checksum == self.compute_checksum()
    }
}

impl std::fmt::Debug for Slip39Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slip39Share")
            .field("identifier", &hex::encode(self.identifier))
            .field("group_index", &self.group_index)
            .field("member_index", &self.member_index)
            .field("member_threshold", &self.member_threshold)
            .field("share_value", &"****")
            .finish()
    }
}

impl Drop for Slip39Share {
    fn drop(&mut self) {
        // share_value is Zeroizing, auto-zeroizes
    }
}

/// SLIP39 Shamir Secret Sharing implementation
///
/// Provides methods to split secrets into shares and combine shares to recover secrets.
#[derive(Debug, Clone)]
pub struct Slip39 {
    /// Threshold number of shares required to recover the secret
    threshold: u8,
    /// Total number of shares to generate
    share_count: u8,
}

impl Slip39 {
    /// Create a new SLIP39 instance with the given threshold and share count.
    ///
    /// # Arguments
    /// * `threshold` - Minimum number of shares required to recover the secret (1-16)
    /// * `share_count` - Total number of shares to generate (threshold <= share_count <= 16)
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::slip39::Slip39;
    ///
    /// // Create a 2-of-3 scheme
    /// let slip39 = Slip39::new(2, 3).unwrap();
    /// ```
    pub fn new(threshold: u8, share_count: u8) -> Result<Self, HdError> {
        if threshold < MIN_THRESHOLD {
            return Err(HdError::InvalidSlip39Threshold(threshold));
        }
        if share_count > MAX_SHARES {
            return Err(HdError::InvalidSlip39ShareCount(share_count));
        }
        if threshold > share_count {
            return Err(HdError::InvalidSlip39Threshold(threshold));
        }

        Ok(Self {
            threshold,
            share_count,
        })
    }

    /// Get the threshold
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Get the share count
    pub fn share_count(&self) -> u8 {
        self.share_count
    }

    /// Split a secret into shares using Shamir's Secret Sharing.
    ///
    /// # Arguments
    /// * `secret` - The secret to split (must be at least 16 bytes)
    ///
    /// # Returns
    /// A vector of shares that can be used to recover the secret
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::slip39::Slip39;
    ///
    /// let slip39 = Slip39::new(2, 3).unwrap();
    /// let secret = [0x42u8; 32];
    /// let shares = slip39.split(&secret).unwrap();
    /// assert_eq!(shares.len(), 3);
    /// ```
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Slip39Share>, HdError> {
        if secret.len() < 16 {
            return Err(HdError::InvalidSlip39SecretLength(secret.len()));
        }

        // Generate random identifier
        let mut identifier = [0u8; SLIP39_ID_LENGTH];
        getrandom::getrandom(&mut identifier)
            .map_err(|_| HdError::RandomGenerationFailed)?;

        // Generate shares using Shamir's Secret Sharing in GF(256)
        let shares = self.shamir_split(secret, &identifier)?;

        Ok(shares)
    }

    /// Combine shares to recover the original secret.
    ///
    /// # Arguments
    /// * `shares` - The shares to combine (must have at least threshold shares)
    ///
    /// # Returns
    /// The recovered secret
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::slip39::Slip39;
    ///
    /// let slip39 = Slip39::new(2, 3).unwrap();
    /// let secret = [0x42u8; 32];
    /// let shares = slip39.split(&secret).unwrap();
    ///
    /// // Recover using any 2 shares
    /// let recovered = Slip39::combine(&shares[0..2]).unwrap();
    /// assert_eq!(secret.to_vec(), recovered);
    /// ```
    pub fn combine(shares: &[Slip39Share]) -> Result<Vec<u8>, HdError> {
        if shares.is_empty() {
            return Err(HdError::InsufficientSlip39Shares { needed: 1, have: 0 });
        }

        // Validate all shares
        for share in shares {
            if !share.validate() {
                return Err(HdError::InvalidSlip39Checksum);
            }
        }

        // Check that all shares have the same identifier
        let identifier = shares[0].identifier;
        for share in shares.iter().skip(1) {
            if share.identifier != identifier {
                return Err(HdError::Slip39IdentifierMismatch);
            }
        }

        // Check threshold
        let threshold = shares[0].member_threshold;
        if shares.len() < threshold as usize {
            return Err(HdError::InsufficientSlip39Shares {
                needed: threshold as usize,
                have: shares.len(),
            });
        }

        // Recover secret using Lagrange interpolation in GF(256)
        Self::shamir_combine(shares)
    }

    /// Internal: Split secret using Shamir's Secret Sharing in GF(256)
    fn shamir_split(&self, secret: &[u8], identifier: &[u8; SLIP39_ID_LENGTH]) -> Result<Vec<Slip39Share>, HdError> {
        let mut shares = Vec::with_capacity(self.share_count as usize);

        // For each byte position in the secret, we create a polynomial
        // The coefficients must be the same for all shares at each byte position
        
        // Pre-generate all random coefficients for all byte positions
        // coefficients[byte_index][coef_index] where coef_index 0 is the secret byte
        let mut all_coefficients: Vec<Vec<u8>> = Vec::with_capacity(secret.len());
        
        for &secret_byte in secret {
            let mut coefficients = vec![secret_byte];
            
            // Generate random coefficients for degree 1 to threshold-1
            for _ in 1..self.threshold {
                let mut random_byte = [0u8; 1];
                getrandom::getrandom(&mut random_byte)
                    .map_err(|_| HdError::RandomGenerationFailed)?;
                coefficients.push(random_byte[0]);
            }
            
            all_coefficients.push(coefficients);
        }

        // Now generate shares by evaluating the polynomials at different x values
        for member_index in 0..self.share_count {
            let mut share_value = Vec::with_capacity(secret.len());

            for coefficients in &all_coefficients {
                // Evaluate polynomial at x = member_index + 1 (x must be non-zero)
                let x = member_index + 1;
                let y = Self::evaluate_polynomial(coefficients, x);
                share_value.push(y);
            }

            let share = Slip39Share::new(
                *identifier,
                0, // iteration_exponent
                0, // group_index (single group)
                1, // group_threshold (single group)
                1, // group_count (single group)
                member_index,
                self.threshold,
                share_value,
            );
            shares.push(share);
        }

        Ok(shares)
    }

    /// Internal: Combine shares using Lagrange interpolation in GF(256)
    fn shamir_combine(shares: &[Slip39Share]) -> Result<Vec<u8>, HdError> {
        let secret_len = shares[0].share_value.len();
        let mut secret = vec![0u8; secret_len];

        // For each byte position
        for (byte_index, secret_byte) in secret.iter_mut().enumerate() {
            // Collect (x, y) pairs for this byte position
            let points: Vec<(u8, u8)> = shares
                .iter()
                .map(|s| (s.member_index + 1, s.share_value[byte_index]))
                .collect();

            // Lagrange interpolation to find f(0)
            *secret_byte = Self::lagrange_interpolate(&points, 0);
        }

        Ok(secret)
    }

    /// Evaluate polynomial at x using Horner's method in GF(256)
    fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
        let mut result = 0u8;
        for &coef in coefficients.iter().rev() {
            result = gf256_mul(result, x) ^ coef;
        }
        result
    }

    /// Lagrange interpolation in GF(256) to find f(x_target)
    fn lagrange_interpolate(points: &[(u8, u8)], x_target: u8) -> u8 {
        let mut result = 0u8;

        for (i, &(x_i, y_i)) in points.iter().enumerate() {
            let mut term = y_i;

            for (j, &(x_j, _)) in points.iter().enumerate() {
                if i != j {
                    // term *= (x_target - x_j) / (x_i - x_j)
                    let numerator = x_target ^ x_j;
                    let denominator = x_i ^ x_j;
                    term = gf256_mul(term, gf256_mul(numerator, gf256_inv(denominator)));
                }
            }

            result ^= term;
        }

        result
    }
}

// ========== GF(256) Arithmetic ==========

/// GF(256) multiplication using the irreducible polynomial x^8 + x^4 + x^3 + x + 1
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
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }

    result
}

/// GF(256) multiplicative inverse using extended Euclidean algorithm
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0; // 0 has no inverse, but we return 0 for safety
    }

    // Use Fermat's little theorem: a^(-1) = a^(254) in GF(256)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

// ========== Multi-Group Support ==========

/// Configuration for a single group in multi-group SLIP39
#[derive(Debug, Clone)]
pub struct GroupConfig {
    /// Threshold number of shares required from this group
    pub threshold: u8,
    /// Total number of shares in this group
    pub share_count: u8,
}

impl GroupConfig {
    /// Create a new group configuration
    pub fn new(threshold: u8, share_count: u8) -> Result<Self, HdError> {
        if threshold < MIN_THRESHOLD {
            return Err(HdError::InvalidSlip39Threshold(threshold));
        }
        if share_count > MAX_SHARES {
            return Err(HdError::InvalidSlip39ShareCount(share_count));
        }
        if threshold > share_count {
            return Err(HdError::InvalidSlip39Threshold(threshold));
        }
        Ok(Self { threshold, share_count })
    }
}

/// Multi-group SLIP39 implementation
///
/// Allows splitting a secret across multiple groups, where a threshold number
/// of groups must contribute shares to recover the secret.
///
/// # Example
///
/// ```
/// use rustywallet_hd::slip39::{Slip39MultiGroup, GroupConfig};
///
/// // Create a 2-of-3 group scheme where:
/// // - Group 0: 2-of-3 shares
/// // - Group 1: 2-of-3 shares  
/// // - Group 2: 3-of-5 shares
/// // Need shares from any 2 groups to recover
/// let groups = vec![
///     GroupConfig::new(2, 3).unwrap(),
///     GroupConfig::new(2, 3).unwrap(),
///     GroupConfig::new(3, 5).unwrap(),
/// ];
/// let multi = Slip39MultiGroup::new(2, groups).unwrap();
///
/// let secret = [0x42u8; 32];
/// let all_shares = multi.split(&secret).unwrap();
///
/// // Recover using shares from groups 0 and 1
/// let group0_shares = &all_shares[0][0..2]; // 2 shares from group 0
/// let group1_shares = &all_shares[1][0..2]; // 2 shares from group 1
/// let mut combined: Vec<_> = group0_shares.iter().cloned().collect();
/// combined.extend(group1_shares.iter().cloned());
/// let recovered = Slip39MultiGroup::combine(&combined).unwrap();
/// assert_eq!(secret.to_vec(), recovered);
/// ```
#[derive(Debug, Clone)]
pub struct Slip39MultiGroup {
    /// Threshold number of groups required
    group_threshold: u8,
    /// Configuration for each group
    groups: Vec<GroupConfig>,
}

impl Slip39MultiGroup {
    /// Create a new multi-group SLIP39 instance.
    ///
    /// # Arguments
    /// * `group_threshold` - Minimum number of groups required to recover the secret
    /// * `groups` - Configuration for each group
    ///
    /// # Example
    /// ```
    /// use rustywallet_hd::slip39::{Slip39MultiGroup, GroupConfig};
    ///
    /// let groups = vec![
    ///     GroupConfig::new(2, 3).unwrap(),
    ///     GroupConfig::new(2, 3).unwrap(),
    /// ];
    /// let multi = Slip39MultiGroup::new(2, groups).unwrap();
    /// ```
    pub fn new(group_threshold: u8, groups: Vec<GroupConfig>) -> Result<Self, HdError> {
        if groups.is_empty() {
            return Err(HdError::InvalidSlip39GroupConfig(
                "At least one group required".to_string(),
            ));
        }
        if groups.len() > MAX_SHARES as usize {
            return Err(HdError::InvalidSlip39GroupConfig(
                format!("Maximum {} groups allowed", MAX_SHARES),
            ));
        }
        if group_threshold < MIN_THRESHOLD {
            return Err(HdError::InvalidSlip39Threshold(group_threshold));
        }
        if group_threshold > groups.len() as u8 {
            return Err(HdError::InvalidSlip39GroupConfig(
                "Group threshold exceeds number of groups".to_string(),
            ));
        }

        Ok(Self {
            group_threshold,
            groups,
        })
    }

    /// Get the group threshold
    pub fn group_threshold(&self) -> u8 {
        self.group_threshold
    }

    /// Get the number of groups
    pub fn group_count(&self) -> u8 {
        self.groups.len() as u8
    }

    /// Get the group configurations
    pub fn groups(&self) -> &[GroupConfig] {
        &self.groups
    }

    /// Split a secret into shares across multiple groups.
    ///
    /// # Arguments
    /// * `secret` - The secret to split (must be at least 16 bytes)
    ///
    /// # Returns
    /// A vector of vectors, where each inner vector contains the shares for one group
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Vec<Slip39Share>>, HdError> {
        if secret.len() < 16 {
            return Err(HdError::InvalidSlip39SecretLength(secret.len()));
        }

        // Generate random identifier (same for all shares)
        let mut identifier = [0u8; SLIP39_ID_LENGTH];
        getrandom::getrandom(&mut identifier)
            .map_err(|_| HdError::RandomGenerationFailed)?;

        // First, split the secret into group shares using group_threshold
        let group_secret_shares = Self::shamir_split_internal(
            secret,
            self.group_threshold,
            self.groups.len() as u8,
        )?;

        // For each group, split its group share into member shares
        let mut all_shares = Vec::with_capacity(self.groups.len());

        for (group_index, (group_config, group_share)) in 
            self.groups.iter().zip(group_secret_shares.iter()).enumerate() 
        {
            let member_shares = Self::split_group_share(
                group_share,
                &identifier,
                group_index as u8,
                self.group_threshold,
                self.groups.len() as u8,
                group_config.threshold,
                group_config.share_count,
            )?;
            all_shares.push(member_shares);
        }

        Ok(all_shares)
    }

    /// Combine shares from multiple groups to recover the original secret.
    ///
    /// # Arguments
    /// * `shares` - Shares from multiple groups (must have sufficient shares from sufficient groups)
    pub fn combine(shares: &[Slip39Share]) -> Result<Vec<u8>, HdError> {
        if shares.is_empty() {
            return Err(HdError::InsufficientSlip39Shares { needed: 1, have: 0 });
        }

        // Validate all shares
        for share in shares {
            if !share.validate() {
                return Err(HdError::InvalidSlip39Checksum);
            }
        }

        // Check that all shares have the same identifier
        let identifier = shares[0].identifier;
        let group_threshold = shares[0].group_threshold;
        let _group_count = shares[0].group_count;

        for share in shares.iter().skip(1) {
            if share.identifier != identifier {
                return Err(HdError::Slip39IdentifierMismatch);
            }
        }

        // Group shares by group_index
        let mut groups: std::collections::HashMap<u8, Vec<&Slip39Share>> = 
            std::collections::HashMap::new();
        for share in shares {
            groups.entry(share.group_index).or_default().push(share);
        }

        // Check that we have enough groups
        if groups.len() < group_threshold as usize {
            return Err(HdError::InsufficientSlip39Shares {
                needed: group_threshold as usize,
                have: groups.len(),
            });
        }

        // For each group, recover the group share
        let mut group_shares: Vec<(u8, Vec<u8>)> = Vec::new();

        for (group_index, group_members) in groups.iter() {
            let member_threshold = group_members[0].member_threshold;
            
            if group_members.len() < member_threshold as usize {
                continue; // Skip groups without enough shares
            }

            // Recover group share using Lagrange interpolation
            let secret_len = group_members[0].share_value.len();
            let mut group_share = vec![0u8; secret_len];

            for (byte_index, group_byte) in group_share.iter_mut().enumerate() {
                let points: Vec<(u8, u8)> = group_members
                    .iter()
                    .take(member_threshold as usize)
                    .map(|s| (s.member_index + 1, s.share_value[byte_index]))
                    .collect();

                *group_byte = Slip39::lagrange_interpolate(&points, 0);
            }

            group_shares.push((*group_index, group_share));
        }

        // Check that we have enough recovered group shares
        if group_shares.len() < group_threshold as usize {
            return Err(HdError::InsufficientSlip39Shares {
                needed: group_threshold as usize,
                have: group_shares.len(),
            });
        }

        // Recover the original secret from group shares
        let secret_len = group_shares[0].1.len();
        let mut secret = vec![0u8; secret_len];

        for (byte_index, secret_byte) in secret.iter_mut().enumerate() {
            let points: Vec<(u8, u8)> = group_shares
                .iter()
                .take(group_threshold as usize)
                .map(|(idx, share)| (*idx + 1, share[byte_index]))
                .collect();

            *secret_byte = Slip39::lagrange_interpolate(&points, 0);
        }

        Ok(secret)
    }

    /// Internal: Split data using Shamir's Secret Sharing
    fn shamir_split_internal(
        data: &[u8],
        threshold: u8,
        share_count: u8,
    ) -> Result<Vec<Vec<u8>>, HdError> {
        let mut shares = Vec::with_capacity(share_count as usize);

        // Pre-generate all random coefficients
        let mut all_coefficients: Vec<Vec<u8>> = Vec::with_capacity(data.len());
        
        for &data_byte in data {
            let mut coefficients = vec![data_byte];
            
            for _ in 1..threshold {
                let mut random_byte = [0u8; 1];
                getrandom::getrandom(&mut random_byte)
                    .map_err(|_| HdError::RandomGenerationFailed)?;
                coefficients.push(random_byte[0]);
            }
            
            all_coefficients.push(coefficients);
        }

        // Generate shares
        for share_index in 0..share_count {
            let mut share_value = Vec::with_capacity(data.len());

            for coefficients in &all_coefficients {
                let x = share_index + 1;
                let y = Slip39::evaluate_polynomial(coefficients, x);
                share_value.push(y);
            }

            shares.push(share_value);
        }

        Ok(shares)
    }

    /// Internal: Split a group share into member shares
    fn split_group_share(
        group_share: &[u8],
        identifier: &[u8; SLIP39_ID_LENGTH],
        group_index: u8,
        group_threshold: u8,
        group_count: u8,
        member_threshold: u8,
        member_count: u8,
    ) -> Result<Vec<Slip39Share>, HdError> {
        let member_shares = Self::shamir_split_internal(
            group_share,
            member_threshold,
            member_count,
        )?;

        let mut shares = Vec::with_capacity(member_count as usize);

        for (member_index, share_value) in member_shares.into_iter().enumerate() {
            let share = Slip39Share::new(
                *identifier,
                0, // iteration_exponent
                group_index,
                group_threshold,
                group_count,
                member_index as u8,
                member_threshold,
                share_value,
            );
            shares.push(share);
        }

        Ok(shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slip39_new_valid() {
        let slip39 = Slip39::new(2, 3).unwrap();
        assert_eq!(slip39.threshold(), 2);
        assert_eq!(slip39.share_count(), 3);
    }

    #[test]
    fn test_slip39_new_invalid_threshold() {
        let result = Slip39::new(0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_slip39_new_threshold_exceeds_count() {
        let result = Slip39::new(5, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_slip39_new_exceeds_max_shares() {
        let result = Slip39::new(2, 20);
        assert!(result.is_err());
    }

    #[test]
    fn test_slip39_split_combine_2_of_3() {
        let slip39 = Slip39::new(2, 3).unwrap();
        let secret = [0x42u8; 32];
        let shares = slip39.split(&secret).unwrap();
        
        assert_eq!(shares.len(), 3);
        
        // Recover using shares 0 and 1
        let recovered = Slip39::combine(&shares[0..2]).unwrap();
        assert_eq!(secret.to_vec(), recovered);
        
        // Recover using shares 1 and 2
        let recovered = Slip39::combine(&shares[1..3]).unwrap();
        assert_eq!(secret.to_vec(), recovered);
        
        // Recover using shares 0 and 2
        let recovered = Slip39::combine(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(secret.to_vec(), recovered);
    }

    #[test]
    fn test_slip39_split_combine_3_of_5() {
        let slip39 = Slip39::new(3, 5).unwrap();
        let secret = vec![0xABu8; 64];
        let shares = slip39.split(&secret).unwrap();
        
        assert_eq!(shares.len(), 5);
        
        // Recover using first 3 shares
        let recovered = Slip39::combine(&shares[0..3]).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_slip39_insufficient_shares() {
        let slip39 = Slip39::new(3, 5).unwrap();
        let secret = [0x42u8; 32];
        let shares = slip39.split(&secret).unwrap();
        
        // Try to recover with only 2 shares (need 3)
        let result = Slip39::combine(&shares[0..2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_slip39_1_of_1() {
        let slip39 = Slip39::new(1, 1).unwrap();
        let secret = [0x42u8; 32];
        let shares = slip39.split(&secret).unwrap();
        
        assert_eq!(shares.len(), 1);
        
        let recovered = Slip39::combine(&shares).unwrap();
        assert_eq!(secret.to_vec(), recovered);
    }

    #[test]
    fn test_slip39_share_validation() {
        let slip39 = Slip39::new(2, 3).unwrap();
        let secret = [0x42u8; 32];
        let shares = slip39.split(&secret).unwrap();
        
        for share in &shares {
            assert!(share.validate());
        }
    }

    #[test]
    fn test_slip39_invalid_checksum() {
        let slip39 = Slip39::new(2, 3).unwrap();
        let secret = [0x42u8; 32];
        let mut shares = slip39.split(&secret).unwrap();
        
        // Corrupt the checksum
        shares[0].checksum[0] ^= 0xFF;
        
        let result = Slip39::combine(&shares[0..2]);
        assert!(result.is_err());
    }

    #[test]
    fn test_slip39_secret_too_short() {
        let slip39 = Slip39::new(2, 3).unwrap();
        let secret = [0x42u8; 8]; // Too short
        
        let result = slip39.split(&secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_gf256_mul() {
        // Test some known GF(256) multiplications
        assert_eq!(gf256_mul(0, 5), 0);
        assert_eq!(gf256_mul(1, 5), 5);
        assert_eq!(gf256_mul(2, 2), 4);
        assert_eq!(gf256_mul(0x53, 0xCA), 0x01); // Known result
    }

    #[test]
    fn test_gf256_inv() {
        // Test that a * inv(a) = 1 for non-zero a
        for a in 1..=255u8 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "Failed for a={}", a);
        }
    }

    // ========== Multi-Group Tests ==========

    #[test]
    fn test_multi_group_2_of_2_groups() {
        let groups = vec![
            GroupConfig::new(2, 3).unwrap(),
            GroupConfig::new(2, 3).unwrap(),
        ];
        let multi = Slip39MultiGroup::new(2, groups).unwrap();
        
        let secret = [0x42u8; 32];
        let all_shares = multi.split(&secret).unwrap();
        
        assert_eq!(all_shares.len(), 2);
        assert_eq!(all_shares[0].len(), 3);
        assert_eq!(all_shares[1].len(), 3);
        
        // Recover using 2 shares from each group
        let mut combined: Vec<Slip39Share> = Vec::new();
        combined.extend(all_shares[0][0..2].iter().cloned());
        combined.extend(all_shares[1][0..2].iter().cloned());
        
        let recovered = Slip39MultiGroup::combine(&combined).unwrap();
        assert_eq!(secret.to_vec(), recovered);
    }

    #[test]
    fn test_multi_group_2_of_3_groups() {
        let groups = vec![
            GroupConfig::new(2, 3).unwrap(),
            GroupConfig::new(2, 3).unwrap(),
            GroupConfig::new(3, 5).unwrap(),
        ];
        let multi = Slip39MultiGroup::new(2, groups).unwrap();
        
        let secret = [0x42u8; 32];
        let all_shares = multi.split(&secret).unwrap();
        
        assert_eq!(all_shares.len(), 3);
        
        // Recover using groups 0 and 1 only
        let mut combined: Vec<Slip39Share> = Vec::new();
        combined.extend(all_shares[0][0..2].iter().cloned());
        combined.extend(all_shares[1][0..2].iter().cloned());
        
        let recovered = Slip39MultiGroup::combine(&combined).unwrap();
        assert_eq!(secret.to_vec(), recovered);
        
        // Recover using groups 0 and 2
        let mut combined2: Vec<Slip39Share> = Vec::new();
        combined2.extend(all_shares[0][0..2].iter().cloned());
        combined2.extend(all_shares[2][0..3].iter().cloned());
        
        let recovered2 = Slip39MultiGroup::combine(&combined2).unwrap();
        assert_eq!(secret.to_vec(), recovered2);
    }

    #[test]
    fn test_multi_group_insufficient_groups() {
        let groups = vec![
            GroupConfig::new(2, 3).unwrap(),
            GroupConfig::new(2, 3).unwrap(),
            GroupConfig::new(2, 3).unwrap(),
        ];
        let multi = Slip39MultiGroup::new(2, groups).unwrap();
        
        let secret = [0x42u8; 32];
        let all_shares = multi.split(&secret).unwrap();
        
        // Try to recover with only 1 group (need 2)
        let combined: Vec<Slip39Share> = all_shares[0][0..2].iter().cloned().collect();
        
        let result = Slip39MultiGroup::combine(&combined);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_group_1_of_1() {
        let groups = vec![
            GroupConfig::new(2, 3).unwrap(),
        ];
        let multi = Slip39MultiGroup::new(1, groups).unwrap();
        
        let secret = [0x42u8; 32];
        let all_shares = multi.split(&secret).unwrap();
        
        // Recover using 2 shares from the single group
        let combined: Vec<Slip39Share> = all_shares[0][0..2].iter().cloned().collect();
        
        let recovered = Slip39MultiGroup::combine(&combined).unwrap();
        assert_eq!(secret.to_vec(), recovered);
    }

    #[test]
    fn test_group_config_validation() {
        // Valid config
        assert!(GroupConfig::new(2, 3).is_ok());
        
        // Invalid: threshold 0
        assert!(GroupConfig::new(0, 3).is_err());
        
        // Invalid: threshold > share_count
        assert!(GroupConfig::new(5, 3).is_err());
        
        // Invalid: share_count > MAX_SHARES
        assert!(GroupConfig::new(2, 20).is_err());
    }

    #[test]
    fn test_multi_group_validation() {
        // Valid
        let groups = vec![GroupConfig::new(2, 3).unwrap()];
        assert!(Slip39MultiGroup::new(1, groups).is_ok());
        
        // Invalid: empty groups
        assert!(Slip39MultiGroup::new(1, vec![]).is_err());
        
        // Invalid: group_threshold > group_count
        let groups = vec![GroupConfig::new(2, 3).unwrap()];
        assert!(Slip39MultiGroup::new(2, groups).is_err());
    }
}
