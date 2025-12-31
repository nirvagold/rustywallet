//! Ethereum address with EIP-55 checksum support.

use crate::encoding::HexEncoder;
use crate::error::AddressError;
use rustywallet_keys::public_key::PublicKey;
use tiny_keccak::{Hasher, Keccak};

/// Ethereum address (20 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthereumAddress {
    bytes: [u8; 20],
}

impl EthereumAddress {
    /// Generate Ethereum address from public key.
    ///
    /// Uses Keccak-256 hash of the uncompressed public key (without 0x04 prefix),
    /// taking the last 20 bytes.
    ///
    /// # Example
    /// ```
    /// use rustywallet_keys::prelude::*;
    /// use rustywallet_address::EthereumAddress;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let address = EthereumAddress::from_public_key(&public_key).unwrap();
    /// assert!(address.to_checksum_string().starts_with("0x"));
    /// ```
    pub fn from_public_key(public_key: &PublicKey) -> Result<Self, AddressError> {
        // Get uncompressed public key bytes (65 bytes with 0x04 prefix)
        let pubkey_bytes = public_key.to_uncompressed();

        // Skip the 0x04 prefix for uncompressed key
        let key_data = &pubkey_bytes[1..]; // 64 bytes

        // Keccak-256 hash
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(key_data);
        hasher.finalize(&mut hash);

        // Take last 20 bytes
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash[12..]);

        Ok(Self { bytes })
    }

    /// Parse Ethereum address from string.
    ///
    /// Accepts addresses with or without "0x" prefix, and with or without checksum.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        s.parse()
    }

    /// Validate Ethereum address with EIP-55 checksum.
    ///
    /// Returns Ok if the address has valid checksum or is all lowercase/uppercase.
    pub fn validate_checksum(s: &str) -> Result<(), AddressError> {
        let addr: Self = s.parse()?;
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);

        // If all lowercase or all uppercase, no checksum to validate
        if s == s.to_lowercase() || s == s.to_uppercase() {
            return Ok(());
        }

        // Validate EIP-55 checksum
        let checksummed = addr.to_checksum_string();
        let checksummed_hex = checksummed.strip_prefix("0x").unwrap();

        if s != checksummed_hex {
            return Err(AddressError::ChecksumMismatch);
        }

        Ok(())
    }

    /// Convert to EIP-55 checksummed string.
    ///
    /// Uses mixed-case hex encoding where uppercase indicates checksum bits.
    pub fn to_checksum_string(&self) -> String {
        let hex_addr = HexEncoder::encode(&self.bytes);

        // Keccak-256 hash of lowercase hex address
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(hex_addr.as_bytes());
        hasher.finalize(&mut hash);

        // Apply checksum
        let mut result = String::with_capacity(42);
        result.push_str("0x");

        for (i, c) in hex_addr.chars().enumerate() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            if hash_nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Convert to lowercase string (no checksum).
    pub fn to_lowercase_string(&self) -> String {
        format!("0x{}", HexEncoder::encode(&self.bytes))
    }

    /// Get raw address bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.bytes
    }
}

impl std::fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_checksum_string())
    }
}

impl std::str::FromStr for EthereumAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);

        if s.len() != 40 {
            return Err(AddressError::InvalidFormat(format!(
                "Invalid Ethereum address length: expected 40 hex chars, got {}",
                s.len()
            )));
        }

        let bytes_vec = HexEncoder::decode(s)?;
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&bytes_vec);

        Ok(Self { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_ethereum_address_generation() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = EthereumAddress::from_public_key(&public_key).unwrap();
        let addr_str = address.to_checksum_string();
        assert!(addr_str.starts_with("0x"));
        assert_eq!(addr_str.len(), 42);
    }

    #[test]
    fn test_ethereum_checksum_validation() {
        // Valid checksummed address
        let addr: EthereumAddress = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".parse().unwrap();
        assert!(EthereumAddress::validate_checksum(&addr.to_checksum_string()).is_ok());
    }

    #[test]
    fn test_ethereum_lowercase_valid() {
        // Lowercase is always valid (no checksum)
        let result = EthereumAddress::validate_checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assert!(result.is_ok());
    }

    #[test]
    fn test_ethereum_roundtrip() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = EthereumAddress::from_public_key(&public_key).unwrap();
        let parsed: EthereumAddress = address.to_checksum_string().parse().unwrap();
        assert_eq!(address.as_bytes(), parsed.as_bytes());
    }

    #[test]
    fn test_eip55_checksum() {
        // Test vector from EIP-55
        let addr: EthereumAddress = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".parse().unwrap();
        assert_eq!(
            addr.to_checksum_string(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }
}
