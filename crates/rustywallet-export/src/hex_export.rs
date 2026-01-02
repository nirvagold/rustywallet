//! Hex export functions.

use crate::types::HexOptions;
use rustywallet_keys::prelude::PrivateKey;

/// Export a private key to hex format.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::{export_hex, HexOptions};
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let key = PrivateKey::random();
///
/// // Default: lowercase, no prefix
/// let hex = export_hex(&key, HexOptions::new());
/// assert_eq!(hex.len(), 64);
///
/// // With 0x prefix
/// let hex = export_hex(&key, HexOptions::new().with_prefix(true));
/// assert!(hex.starts_with("0x"));
/// assert_eq!(hex.len(), 66);
///
/// // Uppercase
/// let hex = export_hex(&key, HexOptions::new().with_uppercase(true));
/// assert!(hex.chars().all(|c| !c.is_ascii_lowercase() || !c.is_alphabetic()));
/// ```
pub fn export_hex(key: &PrivateKey, options: HexOptions) -> String {
    let bytes = key.to_bytes();
    
    let hex = if options.uppercase {
        bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>()
    } else {
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };
    
    if options.prefix {
        format!("0x{}", hex)
    } else {
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_export_hex_default() {
        let key = PrivateKey::random();
        let hex = export_hex(&key, HexOptions::new());
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
    
    #[test]
    fn test_export_hex_with_prefix() {
        let key = PrivateKey::random();
        let hex = export_hex(&key, HexOptions::new().with_prefix(true));
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66);
    }
    
    #[test]
    fn test_export_hex_uppercase() {
        let key = PrivateKey::random();
        let hex = export_hex(&key, HexOptions::new().with_uppercase(true));
        assert!(hex.chars().filter(|c| c.is_alphabetic()).all(|c| c.is_uppercase()));
    }
    
    #[test]
    fn test_export_hex_roundtrip() {
        let key = PrivateKey::random();
        let hex = export_hex(&key, HexOptions::new());
        let recovered = PrivateKey::from_hex(&hex).unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }
}
