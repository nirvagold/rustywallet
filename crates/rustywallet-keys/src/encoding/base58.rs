//! Base58Check encoding/decoding utilities

use std::fmt;

/// Error type for Base58Check decoding operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base58Error {
    /// Invalid Base58 character
    InvalidCharacter(char),
    /// Invalid checksum
    InvalidChecksum,
    /// Data too short (needs at least 4 bytes for checksum)
    TooShort,
}

impl fmt::Display for Base58Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Base58Error::InvalidCharacter(c) => write!(f, "invalid base58 character: '{}'", c),
            Base58Error::InvalidChecksum => write!(f, "invalid checksum"),
            Base58Error::TooShort => write!(f, "data too short for base58check"),
        }
    }
}

impl std::error::Error for Base58Error {}

/// Compute double SHA256 checksum (first 4 bytes)
fn checksum(data: &[u8]) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(hash1);
    let mut result = [0u8; 4];
    result.copy_from_slice(&hash2[..4]);
    result
}

/// Encode data with Base58Check (adds 4-byte checksum)
pub fn encode(data: &[u8]) -> String {
    let check = checksum(data);
    let mut payload = Vec::with_capacity(data.len() + 4);
    payload.extend_from_slice(data);
    payload.extend_from_slice(&check);
    bs58::encode(payload).into_string()
}

/// Decode Base58Check string and verify checksum
pub fn decode(encoded: &str) -> Result<Vec<u8>, Base58Error> {
    let decoded = bs58::decode(encoded).into_vec().map_err(|e| match e {
        bs58::decode::Error::InvalidCharacter { character, .. } => {
            Base58Error::InvalidCharacter(character)
        }
        _ => Base58Error::InvalidCharacter('\0'),
    })?;

    if decoded.len() < 4 {
        return Err(Base58Error::TooShort);
    }

    let (data, check_bytes) = decoded.split_at(decoded.len() - 4);
    let expected_check = checksum(data);

    if check_bytes != expected_check {
        return Err(Base58Error::InvalidChecksum);
    }

    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        // Empty data still gets checksum
        let encoded = encode(&[]);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let data = vec![0x80, 0x01, 0x02, 0x03];
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_invalid_checksum() {
        let data = vec![0x80, 0x01, 0x02, 0x03];
        let encoded = encode(&data);

        // Corrupt the encoded string by changing a character
        let mut chars: Vec<char> = encoded.chars().collect();
        if let Some(c) = chars.last_mut() {
            *c = if *c == '1' { '2' } else { '1' };
        }
        let corrupted: String = chars.into_iter().collect();

        assert!(matches!(
            decode(&corrupted),
            Err(Base58Error::InvalidChecksum)
        ));
    }

    #[test]
    fn test_invalid_character() {
        // '0', 'O', 'I', 'l' are not valid Base58 characters
        assert!(matches!(
            decode("0invalid"),
            Err(Base58Error::InvalidCharacter(_))
        ));
    }

    #[test]
    fn test_too_short() {
        // Base58 "1" decodes to a single zero byte, which is too short
        assert!(matches!(decode("1"), Err(Base58Error::TooShort)));
    }
}
