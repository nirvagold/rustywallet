//! Format detection and unified import.

use crate::error::{ImportError, Result};
use crate::types::{ImportFormat, ImportResult};
use crate::{import_wif, import_hex, import_mini_key, import_mnemonic, MnemonicImport};
use rustywallet_hd::Network as HdNetwork;
use rustywallet_keys::prelude::Network as KeysNetwork;

/// Convert keys Network to hd Network
fn convert_network(network: KeysNetwork) -> HdNetwork {
    match network {
        KeysNetwork::Mainnet => HdNetwork::Mainnet,
        KeysNetwork::Testnet => HdNetwork::Testnet,
    }
}

/// Detect the format of an input string.
///
/// # Example
///
/// ```rust
/// use rustywallet_import::{detect_format, ImportFormat};
///
/// assert_eq!(detect_format("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"), Some(ImportFormat::Wif));
/// assert_eq!(detect_format("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"), Some(ImportFormat::Hex));
/// ```
pub fn detect_format(input: &str) -> Option<ImportFormat> {
    let input = input.trim();
    
    // BIP38: starts with 6P, 58 characters
    if input.starts_with("6P") && input.len() == 58 {
        return Some(ImportFormat::Bip38);
    }
    
    // WIF: 51-52 characters, starts with 5, K, L (mainnet) or 9, c (testnet)
    if (input.len() == 51 || input.len() == 52) && 
       (input.starts_with('5') || input.starts_with('K') || 
        input.starts_with('L') || input.starts_with('9') || 
        input.starts_with('c')) {
        return Some(ImportFormat::Wif);
    }
    
    // Hex: 64 hex characters (with optional 0x prefix)
    let hex_input = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")).unwrap_or(input);
    if hex_input.len() == 64 && hex_input.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(ImportFormat::Hex);
    }
    
    // Mini key: starts with S, 22 or 30 characters
    if input.starts_with('S') && (input.len() == 22 || input.len() == 30) {
        return Some(ImportFormat::MiniKey);
    }
    
    // Mnemonic: 12, 15, 18, 21, or 24 words
    let words: Vec<&str> = input.split_whitespace().collect();
    if [12, 15, 18, 21, 24].contains(&words.len()) {
        return Some(ImportFormat::Mnemonic);
    }
    
    None
}

/// Import a private key from any supported format.
///
/// Automatically detects the format and imports accordingly.
/// For mnemonic imports, uses default BIP44 path (m/44'/0'/0'/0/0).
///
/// # Example
///
/// ```rust
/// use rustywallet_import::import_any;
///
/// // WIF
/// let result = import_any("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ").unwrap();
/// println!("Format: {}", result.format);
///
/// // Hex
/// let result = import_any("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d").unwrap();
/// println!("Format: {}", result.format);
/// ```
pub fn import_any(input: &str) -> Result<ImportResult> {
    let input = input.trim();
    
    let format = detect_format(input)
        .ok_or_else(|| ImportError::InvalidFormat("Could not detect format".to_string()))?;
    
    match format {
        ImportFormat::Wif => {
            let (key, network, compressed) = import_wif(input)?;
            Ok(ImportResult::new(key, ImportFormat::Wif)
                .with_network(convert_network(network))
                .with_compressed(compressed))
        }
        ImportFormat::Hex => {
            let key = import_hex(input)?;
            Ok(ImportResult::new(key, ImportFormat::Hex)
                .with_compressed(true))
        }
        ImportFormat::MiniKey => {
            let key = import_mini_key(input)?;
            Ok(ImportResult::new(key, ImportFormat::MiniKey)
                .with_compressed(false)) // Mini keys traditionally use uncompressed
        }
        ImportFormat::Mnemonic => {
            let config = MnemonicImport::new(input);
            import_mnemonic(config)
        }
        ImportFormat::Bip38 => {
            Err(ImportError::InvalidFormat(
                "BIP38 requires password - use import_bip38() directly".to_string()
            ))
        }
        ImportFormat::ElectrumSeed => {
            Err(ImportError::UnsupportedFormat(
                "Electrum seed format not yet supported".to_string()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detect_wif_uncompressed() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        assert_eq!(detect_format(wif), Some(ImportFormat::Wif));
    }
    
    #[test]
    fn test_detect_wif_compressed() {
        let wif = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
        assert_eq!(detect_format(wif), Some(ImportFormat::Wif));
    }
    
    #[test]
    fn test_detect_hex() {
        let hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        assert_eq!(detect_format(hex), Some(ImportFormat::Hex));
    }
    
    #[test]
    fn test_detect_hex_with_prefix() {
        let hex = "0x0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        assert_eq!(detect_format(hex), Some(ImportFormat::Hex));
    }
    
    #[test]
    fn test_detect_bip38() {
        let bip38 = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
        assert_eq!(detect_format(bip38), Some(ImportFormat::Bip38));
    }
    
    #[test]
    fn test_detect_mini_key() {
        let mini = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy";
        assert_eq!(detect_format(mini), Some(ImportFormat::MiniKey));
    }
    
    #[test]
    fn test_detect_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(detect_format(mnemonic), Some(ImportFormat::Mnemonic));
    }
    
    #[test]
    fn test_detect_unknown() {
        let unknown = "not a valid format";
        assert_eq!(detect_format(unknown), None);
    }
    
    #[test]
    fn test_import_any_wif() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let result = import_any(wif).unwrap();
        assert_eq!(result.format, ImportFormat::Wif);
        assert!(!result.compressed);
    }
    
    #[test]
    fn test_import_any_hex() {
        let hex = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let result = import_any(hex).unwrap();
        assert_eq!(result.format, ImportFormat::Hex);
    }
    
    #[test]
    fn test_import_any_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = import_any(mnemonic).unwrap();
        assert_eq!(result.format, ImportFormat::Mnemonic);
    }
    
    #[test]
    fn test_import_any_bip38_requires_password() {
        let bip38 = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg";
        let result = import_any(bip38);
        assert!(matches!(result, Err(ImportError::InvalidFormat(_))));
    }
}
