//! Mini private key importer (Casascius format).

use crate::error::{ImportError, Result};
use rustywallet_keys::prelude::PrivateKey;
use sha2::{Sha256, Digest};

/// Import a private key from mini key format.
///
/// Mini keys are 22 or 30 character strings starting with 'S'.
/// The private key is SHA256(mini_key).
///
/// # Validation
///
/// A valid mini key must satisfy: SHA256(mini_key + '?')[0] == 0x00
///
/// # Example
///
/// ```rust
/// use rustywallet_import::import_mini_key;
///
/// // Valid mini key (22 chars)
/// let key = import_mini_key("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy").unwrap();
/// ```
pub fn import_mini_key(mini: &str) -> Result<PrivateKey> {
    let mini = mini.trim();
    
    // Validate format
    if !mini.starts_with('S') {
        return Err(ImportError::InvalidMiniKey(
            "Mini key must start with 'S'".to_string()
        ));
    }
    
    // Valid lengths: 22 or 30 characters
    if mini.len() != 22 && mini.len() != 30 {
        return Err(ImportError::InvalidMiniKey(format!(
            "Invalid length: expected 22 or 30 characters, got {}",
            mini.len()
        )));
    }
    
    // Validate characters (base58 alphabet)
    for c in mini.chars() {
        if !is_base58_char(c) {
            return Err(ImportError::InvalidMiniKey(format!(
                "Invalid character: '{}'",
                c
            )));
        }
    }
    
    // Validate checksum: SHA256(mini + '?')[0] == 0x00
    let check_input = format!("{}?", mini);
    let check_hash = Sha256::digest(check_input.as_bytes());
    
    if check_hash[0] != 0x00 {
        return Err(ImportError::InvalidMiniKey(
            "Invalid checksum (SHA256 check failed)".to_string()
        ));
    }
    
    // Derive private key: SHA256(mini)
    let key_hash = Sha256::digest(mini.as_bytes());
    let key_bytes: [u8; 32] = key_hash.into();
    
    PrivateKey::from_bytes(key_bytes)
        .map_err(|e| ImportError::InvalidMiniKey(format!("Invalid key: {}", e)))
}

/// Check if character is valid base58.
fn is_base58_char(c: char) -> bool {
    matches!(c, 
        '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_mini_key() {
        // Known valid mini key
        let mini = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
        let result = import_mini_key(mini);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_invalid_start() {
        let mini = "A6c56bnXQiBjk9mqSYE7yk";
        let result = import_mini_key(mini);
        assert!(matches!(result, Err(ImportError::InvalidMiniKey(_))));
    }
    
    #[test]
    fn test_invalid_length() {
        let mini = "S6c56bnXQiBjk9mq"; // Too short
        let result = import_mini_key(mini);
        assert!(matches!(result, Err(ImportError::InvalidMiniKey(_))));
    }
    
    #[test]
    fn test_invalid_checksum() {
        // Valid format but invalid checksum
        let mini = "S6c56bnXQiBjk9mqSYE7yA";
        let result = import_mini_key(mini);
        assert!(matches!(result, Err(ImportError::InvalidMiniKey(_))));
    }
    
    #[test]
    fn test_invalid_character() {
        let mini = "S6c56bnXQiBjk9mqSYE70l"; // 0 and l are invalid
        let result = import_mini_key(mini);
        assert!(matches!(result, Err(ImportError::InvalidMiniKey(_))));
    }
}
