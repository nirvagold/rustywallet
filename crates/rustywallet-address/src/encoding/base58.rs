//! Base58Check encoding for Bitcoin Legacy addresses.

use crate::error::AddressError;
use sha2::{Digest, Sha256};

/// Base58Check encoder/decoder.
pub struct Base58Check;

impl Base58Check {
    /// Encode data with version byte using Base58Check.
    ///
    /// Format: Base58(version + payload + checksum)
    /// where checksum = first 4 bytes of SHA256(SHA256(version + payload))
    pub fn encode(version: u8, payload: &[u8]) -> String {
        let mut data = Vec::with_capacity(1 + payload.len() + 4);
        data.push(version);
        data.extend_from_slice(payload);

        // Calculate checksum
        let checksum = Self::checksum(&data);
        data.extend_from_slice(&checksum);

        bs58::encode(data).into_string()
    }

    /// Decode Base58Check encoded string.
    ///
    /// Returns (version, payload) if valid.
    pub fn decode(s: &str) -> Result<(u8, Vec<u8>), AddressError> {
        let data = bs58::decode(s)
            .into_vec()
            .map_err(|e| AddressError::InvalidBase58(e.to_string()))?;

        if data.len() < 5 {
            return Err(AddressError::InvalidBase58("Data too short".to_string()));
        }

        let (payload_with_version, checksum) = data.split_at(data.len() - 4);
        let expected_checksum = Self::checksum(payload_with_version);

        if checksum != expected_checksum {
            return Err(AddressError::ChecksumMismatch);
        }

        let version = payload_with_version[0];
        let payload = payload_with_version[1..].to_vec();

        Ok((version, payload))
    }

    /// Calculate double SHA256 checksum (first 4 bytes).
    fn checksum(data: &[u8]) -> [u8; 4] {
        let hash1 = Sha256::digest(data);
        let hash2 = Sha256::digest(hash1);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&hash2[..4]);
        checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base58check_roundtrip() {
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = Base58Check::encode(0x00, &payload);
        let (version, decoded) = Base58Check::decode(&encoded).unwrap();
        assert_eq!(version, 0x00);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_base58check_invalid_checksum() {
        let encoded = Base58Check::encode(0x00, &[0x01, 0x02, 0x03]);
        // Corrupt the encoded string
        let mut chars: Vec<char> = encoded.chars().collect();
        if let Some(c) = chars.last_mut() {
            *c = if *c == '1' { '2' } else { '1' };
        }
        let corrupted: String = chars.into_iter().collect();
        assert!(Base58Check::decode(&corrupted).is_err());
    }
}
