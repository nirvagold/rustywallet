//! Hex encoding/decoding utilities

use std::fmt;

/// Error type for hex decoding operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// Invalid character in hex string
    InvalidCharacter(char),
    /// Odd length hex string
    OddLength,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexError::InvalidCharacter(c) => write!(f, "invalid hex character: '{}'", c),
            HexError::OddLength => write!(f, "hex string has odd length"),
        }
    }
}

impl std::error::Error for HexError {}

/// Encode bytes to lowercase hex string
pub fn encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Decode hex string to bytes (case-insensitive)
pub fn decode(hex: &str) -> Result<Vec<u8>, HexError> {
    if !hex.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();

    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi = hex_char_to_nibble(hi)?;
        let lo = hex_char_to_nibble(lo)?;
        bytes.push((hi << 4) | lo);
    }

    Ok(bytes)
}

/// Convert a hex character to its nibble value
fn hex_char_to_nibble(c: char) -> Result<u8, HexError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        _ => Err(HexError::InvalidCharacter(c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn test_encode_single_byte() {
        assert_eq!(encode(&[0x00]), "00");
        assert_eq!(encode(&[0xff]), "ff");
        assert_eq!(encode(&[0xab]), "ab");
    }

    #[test]
    fn test_encode_multiple_bytes() {
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn test_decode_empty() {
        assert_eq!(decode("").unwrap(), vec![]);
    }

    #[test]
    fn test_decode_lowercase() {
        assert_eq!(decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_uppercase() {
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_mixed_case() {
        assert_eq!(decode("DeAdBeEf").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_odd_length() {
        assert_eq!(decode("abc"), Err(HexError::OddLength));
    }

    #[test]
    fn test_decode_invalid_char() {
        assert_eq!(decode("gg"), Err(HexError::InvalidCharacter('g')));
    }

    #[test]
    fn test_roundtrip() {
        let original = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let encoded = encode(&original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
