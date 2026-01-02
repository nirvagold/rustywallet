//! Mnemonic (BIP39) importer.

use crate::error::{ImportError, Result};
use crate::types::{ImportMetadata, ImportResult, ImportFormat};
use rustywallet_mnemonic::Mnemonic;
use rustywallet_hd::{ExtendedPrivateKey, DerivationPath, Network};

/// Configuration for mnemonic import.
#[derive(Debug, Clone)]
pub struct MnemonicImport {
    /// The mnemonic phrase (12-24 words)
    pub mnemonic: String,
    /// Optional passphrase (BIP39)
    pub passphrase: Option<String>,
    /// Derivation path (default: m/44'/0'/0'/0/0)
    pub path: Option<String>,
    /// Network (default: Mainnet)
    pub network: Option<Network>,
}

impl MnemonicImport {
    /// Create a new mnemonic import config.
    pub fn new(mnemonic: impl Into<String>) -> Self {
        Self {
            mnemonic: mnemonic.into(),
            passphrase: None,
            path: None,
            network: None,
        }
    }
    
    /// Set passphrase.
    pub fn with_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }
    
    /// Set derivation path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
    
    /// Set network.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }
}

/// Default derivation paths for different address types.
pub mod paths {
    /// BIP44 path for legacy addresses (P2PKH)
    pub const BIP44: &str = "m/44'/0'/0'/0/0";
    /// BIP49 path for SegWit-compatible addresses (P2SH-P2WPKH)
    pub const BIP49: &str = "m/49'/0'/0'/0/0";
    /// BIP84 path for native SegWit addresses (P2WPKH)
    pub const BIP84: &str = "m/84'/0'/0'/0/0";
}

/// Import a private key from a mnemonic phrase.
///
/// # Example
///
/// ```rust
/// use rustywallet_import::{import_mnemonic, MnemonicImport};
///
/// let config = MnemonicImport::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
///     .with_path("m/44'/0'/0'/0/0");
///
/// let result = import_mnemonic(config).unwrap();
/// println!("Imported key from {} word mnemonic", result.metadata.word_count.unwrap());
/// ```
pub fn import_mnemonic(config: MnemonicImport) -> Result<ImportResult> {
    let mnemonic_str = config.mnemonic.trim();
    
    // Parse mnemonic
    let mnemonic = Mnemonic::from_phrase(mnemonic_str)
        .map_err(|e| ImportError::InvalidMnemonic(format!("{}", e)))?;
    
    let word_count = mnemonic_str.split_whitespace().count();
    
    // Get passphrase
    let passphrase = config.passphrase.as_deref().unwrap_or("");
    
    // Generate seed
    let seed = mnemonic.to_seed(passphrase);
    
    // Get network
    let network = config.network.unwrap_or(Network::Mainnet);
    
    // Create master key
    let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), network)
        .map_err(|e| ImportError::KeyDerivationFailed(format!("{}", e)))?;
    
    // Get derivation path
    let path_str = config.path.as_deref().unwrap_or(paths::BIP44);
    
    // Parse and derive
    let path: DerivationPath = path_str.parse()
        .map_err(|e| ImportError::KeyDerivationFailed(format!("Invalid path: {}", e)))?;
    
    let derived = master.derive_path(&path)
        .map_err(|e| ImportError::KeyDerivationFailed(format!("{}", e)))?;
    
    // Get private key
    let private_key = derived.private_key()
        .map_err(|e| ImportError::KeyDerivationFailed(format!("{}", e)))?;
    
    // Build metadata
    let metadata = ImportMetadata {
        derivation_path: Some(path_str.to_string()),
        word_count: Some(word_count),
        has_passphrase: !passphrase.is_empty(),
    };
    
    Ok(ImportResult::new(private_key, ImportFormat::Mnemonic)
        .with_network(network)
        .with_compressed(true)
        .with_metadata(metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_import_12_word_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let config = MnemonicImport::new(mnemonic);
        let result = import_mnemonic(config).unwrap();
        
        assert_eq!(result.format, ImportFormat::Mnemonic);
        assert_eq!(result.metadata.word_count, Some(12));
        assert!(!result.metadata.has_passphrase);
    }
    
    #[test]
    fn test_import_with_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let config = MnemonicImport::new(mnemonic)
            .with_passphrase("TREZOR");
        let result = import_mnemonic(config).unwrap();
        
        assert!(result.metadata.has_passphrase);
    }
    
    #[test]
    fn test_import_with_custom_path() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let config = MnemonicImport::new(mnemonic)
            .with_path("m/84'/0'/0'/0/0");
        let result = import_mnemonic(config).unwrap();
        
        assert_eq!(result.metadata.derivation_path, Some("m/84'/0'/0'/0/0".to_string()));
    }
    
    #[test]
    fn test_invalid_mnemonic() {
        let mnemonic = "invalid words that are not a valid mnemonic phrase at all";
        let config = MnemonicImport::new(mnemonic);
        let result = import_mnemonic(config);
        
        assert!(matches!(result, Err(ImportError::InvalidMnemonic(_))));
    }
    
    #[test]
    fn test_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let config1 = MnemonicImport::new(mnemonic).with_path("m/44'/0'/0'/0/0");
        let config2 = MnemonicImport::new(mnemonic).with_path("m/44'/0'/0'/0/0");
        
        let result1 = import_mnemonic(config1).unwrap();
        let result2 = import_mnemonic(config2).unwrap();
        
        assert_eq!(result1.private_key.to_bytes(), result2.private_key.to_bytes());
    }
}
