//! Bech32/Bech32m encoding for SegWit and Taproot addresses.

use crate::error::AddressError;
use bech32::Hrp;

/// Bech32 encoder/decoder for Bitcoin SegWit addresses.
pub struct Bech32Encoder;

impl Bech32Encoder {
    /// Encode data using Bech32 (witness version 0 - SegWit).
    pub fn encode_bech32(hrp: &str, _witness_version: u8, data: &[u8]) -> Result<String, AddressError> {
        let hrp = Hrp::parse(hrp).map_err(|e| AddressError::InvalidBech32(e.to_string()))?;
        
        bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, data)
            .map_err(|e| AddressError::InvalidBech32(e.to_string()))
    }

    /// Encode data using Bech32m (witness version 1+ - Taproot).
    pub fn encode_bech32m(hrp: &str, data: &[u8]) -> Result<String, AddressError> {
        let hrp = Hrp::parse(hrp).map_err(|e| AddressError::InvalidBech32(e.to_string()))?;
        
        bech32::segwit::encode(hrp, bech32::segwit::VERSION_1, data)
            .map_err(|e| AddressError::InvalidBech32(e.to_string()))
    }

    /// Decode Bech32/Bech32m encoded address.
    /// Returns (hrp, witness_version, program).
    pub fn decode(s: &str) -> Result<(String, u8, Vec<u8>), AddressError> {
        let (hrp, version, program) = bech32::segwit::decode(s)
            .map_err(|e| AddressError::InvalidBech32(e.to_string()))?;

        Ok((hrp.to_string(), version.to_u8(), program))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bech32_segwit_roundtrip() {
        let data = [0u8; 20]; // 20-byte hash for P2WPKH
        let encoded = Bech32Encoder::encode_bech32("bc", 0, &data).unwrap();
        assert!(encoded.starts_with("bc1q"));
        
        let (hrp, version, decoded) = Bech32Encoder::decode(&encoded).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(version, 0);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_bech32m_taproot_roundtrip() {
        let data = [0u8; 32]; // 32-byte x-only pubkey for P2TR
        let encoded = Bech32Encoder::encode_bech32m("bc", &data).unwrap();
        assert!(encoded.starts_with("bc1p"));
        
        let (hrp, version, decoded) = Bech32Encoder::decode(&encoded).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(version, 1);
        assert_eq!(decoded, data);
    }
}
