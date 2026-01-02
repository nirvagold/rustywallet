//! WIF (Wallet Import Format) importer.

use crate::error::{ImportError, Result};
use rustywallet_keys::prelude::{Network, PrivateKey};
use sha2::{Sha256, Digest};

/// Import a private key from WIF format.
///
/// Returns the private key, detected network, and whether it's compressed.
///
/// # Example
///
/// ```rust
/// use rustywallet_import::import_wif;
/// use rustywallet_keys::prelude::Network;
///
/// // Uncompressed mainnet WIF
/// let (key, network, compressed) = import_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ").unwrap();
/// assert_eq!(network, Network::Mainnet);
/// assert!(!compressed);
///
/// // Compressed mainnet WIF
/// let (key, network, compressed) = import_wif("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617").unwrap();
/// assert_eq!(network, Network::Mainnet);
/// assert!(compressed);
/// ```
pub fn import_wif(wif: &str) -> Result<(PrivateKey, Network, bool)> {
    let wif = wif.trim();
    
    // Decode base58
    let decoded = bs58::decode(wif)
        .into_vec()
        .map_err(|e| ImportError::InvalidWif(format!("Base58 decode failed: {}", e)))?;
    
    // Minimum length: 1 (version) + 32 (key) + 4 (checksum) = 37
    // With compression flag: 38
    if decoded.len() < 37 || decoded.len() > 38 {
        return Err(ImportError::InvalidWif(format!(
            "Invalid length: expected 37-38 bytes, got {}",
            decoded.len()
        )));
    }
    
    // Verify checksum
    let checksum_pos = decoded.len() - 4;
    let payload = &decoded[..checksum_pos];
    let checksum = &decoded[checksum_pos..];
    
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);
    
    if &hash2[..4] != checksum {
        return Err(ImportError::InvalidChecksum);
    }
    
    // Parse version byte
    let version = decoded[0];
    let (network, compressed) = match version {
        0x80 => {
            // Mainnet
            let compressed = decoded.len() == 38 && decoded[33] == 0x01;
            (Network::Mainnet, compressed)
        }
        0xEF => {
            // Testnet
            let compressed = decoded.len() == 38 && decoded[33] == 0x01;
            (Network::Testnet, compressed)
        }
        _ => {
            return Err(ImportError::InvalidWif(format!(
                "Unknown version byte: 0x{:02x}",
                version
            )));
        }
    };
    
    // Extract private key bytes
    let key_bytes: [u8; 32] = decoded[1..33]
        .try_into()
        .map_err(|_| ImportError::InvalidWif("Invalid key length".to_string()))?;
    
    // Create private key
    let private_key = PrivateKey::from_bytes(key_bytes)
        .map_err(|e| ImportError::InvalidWif(format!("Invalid key: {}", e)))?;
    
    Ok((private_key, network, compressed))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_import_uncompressed_mainnet() {
        // Known test vector
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let (key, network, compressed) = import_wif(wif).unwrap();
        
        assert_eq!(network, Network::Mainnet);
        assert!(!compressed);
        
        // Verify key bytes
        let expected_hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        assert_eq!(hex::encode(key.to_bytes()), expected_hex);
    }
    
    #[test]
    fn test_import_compressed_mainnet() {
        let wif = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
        let (key, network, compressed) = import_wif(wif).unwrap();
        
        assert_eq!(network, Network::Mainnet);
        assert!(compressed);
    }
    
    #[test]
    fn test_invalid_checksum() {
        // Modified last character
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTK";
        let result = import_wif(wif);
        assert!(matches!(result, Err(ImportError::InvalidChecksum)));
    }
    
    #[test]
    fn test_invalid_base58() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvy0O"; // 0 and O invalid
        let result = import_wif(wif);
        assert!(result.is_err());
    }
}
