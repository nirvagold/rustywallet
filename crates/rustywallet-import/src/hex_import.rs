//! Hex format importer.

use crate::error::{ImportError, Result};
use rustywallet_keys::prelude::PrivateKey;

/// Import a private key from hex format.
///
/// Accepts a 64-character hex string (32 bytes).
///
/// # Example
///
/// ```rust
/// use rustywallet_import::import_hex;
///
/// let key = import_hex("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d").unwrap();
/// ```
pub fn import_hex(hex_str: &str) -> Result<PrivateKey> {
    let hex_str = hex_str.trim();
    
    // Remove optional 0x prefix
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let hex_str = hex_str.strip_prefix("0X").unwrap_or(hex_str);
    
    // Validate length
    if hex_str.len() != 64 {
        return Err(ImportError::InvalidHex(format!(
            "Expected 64 hex characters, got {}",
            hex_str.len()
        )));
    }
    
    // Decode hex
    let bytes = hex::decode(hex_str)
        .map_err(|e| ImportError::InvalidHex(format!("Invalid hex: {}", e)))?;
    
    // Convert to array
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ImportError::InvalidHex("Invalid length".to_string()))?;
    
    // Create private key
    PrivateKey::from_bytes(key_bytes)
        .map_err(|e| ImportError::InvalidHex(format!("Invalid key: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_import_hex() {
        let hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let key = import_hex(hex).unwrap();
        assert_eq!(hex::encode(key.to_bytes()), hex);
    }
    
    #[test]
    fn test_import_hex_with_prefix() {
        let hex = "0x0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let key = import_hex(hex).unwrap();
        let expected = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        assert_eq!(hex::encode(key.to_bytes()), expected);
    }
    
    #[test]
    fn test_import_hex_uppercase() {
        let hex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
        let key = import_hex(hex).unwrap();
        let expected = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        assert_eq!(hex::encode(key.to_bytes()), expected);
    }
    
    #[test]
    fn test_invalid_length() {
        let hex = "0c28fca386c7a227600b2fe50b7cae11";
        let result = import_hex(hex);
        assert!(matches!(result, Err(ImportError::InvalidHex(_))));
    }
    
    #[test]
    fn test_invalid_hex_chars() {
        let hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aagg";
        let result = import_hex(hex);
        assert!(matches!(result, Err(ImportError::InvalidHex(_))));
    }
    
    #[test]
    fn test_zero_key_rejected() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = import_hex(hex);
        assert!(result.is_err());
    }
}
