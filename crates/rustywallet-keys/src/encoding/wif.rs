//! WIF (Wallet Import Format) encoding/decoding utilities

use crate::encoding::base58;
use crate::network::Network;
use std::fmt;

/// Error type for WIF decoding operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifError {
    /// Invalid Base58 encoding
    Base58(base58::Base58Error),
    /// Invalid WIF length
    InvalidLength(usize),
    /// Unknown version byte
    UnknownVersion(u8),
    /// Invalid checksum
    InvalidChecksum,
}

impl fmt::Display for WifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WifError::Base58(e) => write!(f, "base58 error: {}", e),
            WifError::InvalidLength(len) => {
                write!(
                    f,
                    "invalid WIF length: expected 33 or 34 bytes, got {}",
                    len
                )
            }
            WifError::UnknownVersion(v) => write!(f, "unknown WIF version byte: 0x{:02x}", v),
            WifError::InvalidChecksum => write!(f, "invalid WIF checksum"),
        }
    }
}

impl std::error::Error for WifError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WifError::Base58(e) => Some(e),
            _ => None,
        }
    }
}

impl From<base58::Base58Error> for WifError {
    fn from(e: base58::Base58Error) -> Self {
        match e {
            base58::Base58Error::InvalidChecksum => WifError::InvalidChecksum,
            other => WifError::Base58(other),
        }
    }
}

/// Encode a private key to WIF format
///
/// # Arguments
/// * `key` - 32-byte private key
/// * `network` - Network type (Mainnet or Testnet)
/// * `compressed` - Whether to use compressed public key format
///
/// # Returns
/// Base58Check encoded WIF string
pub fn encode(key: &[u8; 32], network: Network, compressed: bool) -> String {
    let version = network.wif_version_byte();

    let mut payload = Vec::with_capacity(if compressed { 34 } else { 33 });
    payload.push(version);
    payload.extend_from_slice(key);

    if compressed {
        payload.push(0x01); // Compression flag
    }

    base58::encode(&payload)
}

/// Decode a WIF string to private key bytes
///
/// # Arguments
/// * `wif` - WIF encoded string
///
/// # Returns
/// Tuple of (32-byte key, network, compressed flag)
pub fn decode(wif: &str) -> Result<([u8; 32], Network, bool), WifError> {
    let decoded = base58::decode(wif)?;

    // WIF format: version (1) + key (32) + optional compression flag (1)
    // So valid lengths are 33 (uncompressed) or 34 (compressed)
    let (network, key_bytes, compressed) = match decoded.len() {
        33 => {
            // Uncompressed: version + 32-byte key
            let version = decoded[0];
            let network = version_to_network(version)?;
            let key_bytes = &decoded[1..33];
            (network, key_bytes, false)
        }
        34 => {
            // Compressed: version + 32-byte key + 0x01
            let version = decoded[0];
            let network = version_to_network(version)?;
            let key_bytes = &decoded[1..33];

            if decoded[33] != 0x01 {
                return Err(WifError::InvalidLength(decoded.len()));
            }

            (network, key_bytes, true)
        }
        len => return Err(WifError::InvalidLength(len)),
    };

    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);

    Ok((key, network, compressed))
}

/// Convert version byte to Network
fn version_to_network(version: u8) -> Result<Network, WifError> {
    match version {
        0x80 => Ok(Network::Mainnet),
        0xEF => Ok(Network::Testnet),
        v => Err(WifError::UnknownVersion(v)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_mainnet_compressed() {
        let key = [0x01u8; 32];
        let wif = encode(&key, Network::Mainnet, true);
        assert!(wif.starts_with('K') || wif.starts_with('L'));
    }

    #[test]
    fn test_encode_mainnet_uncompressed() {
        let key = [0x01u8; 32];
        let wif = encode(&key, Network::Mainnet, false);
        assert!(wif.starts_with('5'));
    }

    #[test]
    fn test_encode_testnet_compressed() {
        let key = [0x01u8; 32];
        let wif = encode(&key, Network::Testnet, true);
        assert!(wif.starts_with('c'));
    }

    #[test]
    fn test_encode_testnet_uncompressed() {
        let key = [0x01u8; 32];
        let wif = encode(&key, Network::Testnet, false);
        assert!(wif.starts_with('9'));
    }

    #[test]
    fn test_roundtrip_mainnet_compressed() {
        let original_key = [0xab; 32];
        let wif = encode(&original_key, Network::Mainnet, true);
        let (decoded_key, network, compressed) = decode(&wif).unwrap();

        assert_eq!(original_key, decoded_key);
        assert_eq!(network, Network::Mainnet);
        assert!(compressed);
    }

    #[test]
    fn test_roundtrip_mainnet_uncompressed() {
        let original_key = [0xcd; 32];
        let wif = encode(&original_key, Network::Mainnet, false);
        let (decoded_key, network, compressed) = decode(&wif).unwrap();

        assert_eq!(original_key, decoded_key);
        assert_eq!(network, Network::Mainnet);
        assert!(!compressed);
    }

    #[test]
    fn test_roundtrip_testnet_compressed() {
        let original_key = [0xef; 32];
        let wif = encode(&original_key, Network::Testnet, true);
        let (decoded_key, network, compressed) = decode(&wif).unwrap();

        assert_eq!(original_key, decoded_key);
        assert_eq!(network, Network::Testnet);
        assert!(compressed);
    }

    #[test]
    fn test_roundtrip_testnet_uncompressed() {
        let original_key = [0x12; 32];
        let wif = encode(&original_key, Network::Testnet, false);
        let (decoded_key, network, compressed) = decode(&wif).unwrap();

        assert_eq!(original_key, decoded_key);
        assert_eq!(network, Network::Testnet);
        assert!(!compressed);
    }

    #[test]
    fn test_known_vector() {
        // Known test vector from Bitcoin wiki
        // Private key: 0x0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
        let key: [u8; 32] = [
            0x0C, 0x28, 0xFC, 0xA3, 0x86, 0xC7, 0xA2, 0x27, 0x60, 0x0B, 0x2F, 0xE5, 0x0B, 0x7C,
            0xAE, 0x11, 0xEC, 0x86, 0xD3, 0xBF, 0x1F, 0xBE, 0x47, 0x1B, 0xE8, 0x98, 0x27, 0xE1,
            0x9D, 0x72, 0xAA, 0x1D,
        ];

        let wif = encode(&key, Network::Mainnet, false);
        assert_eq!(wif, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
    }

    #[test]
    fn test_decode_invalid_version() {
        // Create a WIF with invalid version byte
        let key = [0x01u8; 32];
        let mut payload = vec![0x00]; // Invalid version
        payload.extend_from_slice(&key);
        let invalid_wif = base58::encode(&payload);

        assert!(matches!(
            decode(&invalid_wif),
            Err(WifError::UnknownVersion(0x00))
        ));
    }

    #[test]
    fn test_decode_invalid_length() {
        // Too short
        let short_payload = vec![0x80, 0x01, 0x02];
        let short_wif = base58::encode(&short_payload);
        assert!(matches!(
            decode(&short_wif),
            Err(WifError::InvalidLength(_))
        ));
    }
}
