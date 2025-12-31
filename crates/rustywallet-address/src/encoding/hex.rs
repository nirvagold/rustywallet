//! Hex encoding utilities for Ethereum addresses.

use crate::error::AddressError;

/// Hex encoder/decoder.
pub struct HexEncoder;

impl HexEncoder {
    /// Encode bytes to lowercase hex string.
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Decode hex string to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>, AddressError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        
        if !s.len().is_multiple_of(2) {
            return Err(AddressError::InvalidFormat("Odd hex string length".to_string()));
        }

        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|_| AddressError::InvalidFormat("Invalid hex character".to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let encoded = HexEncoder::encode(&data);
        assert_eq!(encoded, "deadbeef");
        
        let decoded = HexEncoder::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_with_prefix() {
        let decoded = HexEncoder::decode("0xdeadbeef").unwrap();
        assert_eq!(decoded, [0xde, 0xad, 0xbe, 0xef]);
    }
}
