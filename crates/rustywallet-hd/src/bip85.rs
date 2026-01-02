//! BIP85 - Deterministic Entropy From BIP32 Keychains
//!
//! Derives deterministic entropy from a BIP32 master key for various applications:
//! - Child mnemonics (BIP39)
//! - WIF private keys
//! - Hex entropy
//! - XPRV keys
//!
//! Reference: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki

use crate::error::HdError;
use crate::extended_key::ExtendedPrivateKey;
use crate::path::DerivationPath;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// BIP85 application numbers
pub mod app {
    /// BIP39 mnemonic (application 39')
    pub const BIP39: u32 = 39;
    /// WIF private key (application 2')
    pub const WIF: u32 = 2;
    /// XPRV extended private key (application 32')
    pub const XPRV: u32 = 32;
    /// Hex entropy (application 128169')
    pub const HEX: u32 = 128169;
    /// PWD Base64 password (application 707764')
    pub const PWD_BASE64: u32 = 707764;
    /// PWD Base85 password (application 707785')
    pub const PWD_BASE85: u32 = 707785;
}

/// BIP39 language codes for BIP85
pub mod language {
    pub const ENGLISH: u32 = 0;
    pub const JAPANESE: u32 = 1;
    pub const KOREAN: u32 = 2;
    pub const SPANISH: u32 = 3;
    pub const CHINESE_SIMPLIFIED: u32 = 4;
    pub const CHINESE_TRADITIONAL: u32 = 5;
    pub const FRENCH: u32 = 6;
    pub const ITALIAN: u32 = 7;
    pub const CZECH: u32 = 8;
    pub const PORTUGUESE: u32 = 9;
}

/// BIP85 entropy derivation
pub struct Bip85 {
    master: ExtendedPrivateKey,
}

impl Bip85 {
    /// Create BIP85 context from master extended private key
    pub fn new(master: ExtendedPrivateKey) -> Self {
        Self { master }
    }

    /// Derive raw entropy at a given path
    ///
    /// Returns 64 bytes of entropy derived using HMAC-SHA512
    fn derive_entropy(&self, path: &DerivationPath) -> Result<Zeroizing<[u8; 64]>, HdError> {
        // Derive child key at path
        let child = self.master.derive_path(path)?;

        // HMAC-SHA512 with key "bip-entropy-from-k"
        let mut mac = HmacSha512::new_from_slice(b"bip-entropy-from-k")
            .expect("HMAC can take key of any size");

        // Use the private key as data
        let private_key = child.private_key()?;
        mac.update(&private_key.to_bytes());

        let result = mac.finalize().into_bytes();
        let mut entropy = [0u8; 64];
        entropy.copy_from_slice(&result);

        Ok(Zeroizing::new(entropy))
    }

    /// Derive BIP39 mnemonic entropy
    ///
    /// Path: m/83696968'/39'/{language}'/{words}'/{index}'
    ///
    /// # Arguments
    /// * `language` - Language code (0 = English)
    /// * `words` - Number of words (12, 15, 18, 21, or 24)
    /// * `index` - Derivation index
    ///
    /// # Returns
    /// Raw entropy bytes (16, 20, 24, 28, or 32 bytes depending on word count)
    pub fn derive_mnemonic_entropy(
        &self,
        language: u32,
        words: u32,
        index: u32,
    ) -> Result<Zeroizing<Vec<u8>>, HdError> {
        // Validate word count
        let entropy_bytes = match words {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(HdError::InvalidBip85WordCount(words)),
        };

        // Build path: m/83696968'/39'/{language}'/{words}'/{index}'
        let path_str = format!(
            "m/83696968'/{}'/{}'/{}'/{}",
            app::BIP39,
            language,
            words,
            index
        );
        let path = DerivationPath::parse(&path_str)?;

        let entropy = self.derive_entropy(&path)?;

        // Take first entropy_bytes
        let mut result = vec![0u8; entropy_bytes];
        result.copy_from_slice(&entropy[..entropy_bytes]);

        Ok(Zeroizing::new(result))
    }

    /// Derive WIF private key entropy
    ///
    /// Path: m/83696968'/2'/{index}'
    ///
    /// # Returns
    /// 32 bytes of entropy for a private key
    pub fn derive_wif_entropy(&self, index: u32) -> Result<Zeroizing<[u8; 32]>, HdError> {
        let path_str = format!("m/83696968'/{}'/{}'/0'", app::WIF, index);
        let path = DerivationPath::parse(&path_str)?;

        let entropy = self.derive_entropy(&path)?;

        let mut result = [0u8; 32];
        result.copy_from_slice(&entropy[..32]);

        Ok(Zeroizing::new(result))
    }

    /// Derive XPRV entropy
    ///
    /// Path: m/83696968'/32'/{index}'
    ///
    /// # Returns
    /// 64 bytes of entropy (can be used as seed for new master key)
    pub fn derive_xprv_entropy(&self, index: u32) -> Result<Zeroizing<[u8; 64]>, HdError> {
        let path_str = format!("m/83696968'/{}'/{}'/0'", app::XPRV, index);
        let path = DerivationPath::parse(&path_str)?;

        self.derive_entropy(&path)
    }

    /// Derive hex entropy of specified length
    ///
    /// Path: m/83696968'/128169'/{num_bytes}'/{index}'
    ///
    /// # Arguments
    /// * `num_bytes` - Number of bytes (16-64)
    /// * `index` - Derivation index
    pub fn derive_hex_entropy(
        &self,
        num_bytes: usize,
        index: u32,
    ) -> Result<Zeroizing<Vec<u8>>, HdError> {
        if !(16..=64).contains(&num_bytes) {
            return Err(HdError::InvalidBip85ByteCount(num_bytes));
        }

        let path_str = format!("m/83696968'/{}'/{}'/{}'/0'", app::HEX, num_bytes, index);
        let path = DerivationPath::parse(&path_str)?;

        let entropy = self.derive_entropy(&path)?;

        let mut result = vec![0u8; num_bytes];
        result.copy_from_slice(&entropy[..num_bytes]);

        Ok(Zeroizing::new(result))
    }

    /// Derive a child mnemonic (convenience method)
    ///
    /// Derives entropy and converts to mnemonic words using English wordlist.
    /// Requires rustywallet-mnemonic crate for full functionality.
    ///
    /// # Returns
    /// Raw entropy that can be converted to mnemonic
    pub fn derive_child_mnemonic(
        &self,
        words: u32,
        index: u32,
    ) -> Result<Zeroizing<Vec<u8>>, HdError> {
        self.derive_mnemonic_entropy(language::ENGLISH, words, index)
    }

    /// Derive a new master key from this master key
    ///
    /// Creates a completely independent HD wallet from the parent.
    pub fn derive_child_master(
        &self,
        index: u32,
        network: crate::network::Network,
    ) -> Result<ExtendedPrivateKey, HdError> {
        let entropy = self.derive_xprv_entropy(index)?;
        ExtendedPrivateKey::from_seed(&*entropy, network)
    }

    /// Derive password entropy (Base64)
    ///
    /// Path: m/83696968'/707764'/{pwd_len}'/{index}'
    ///
    /// # Arguments
    /// * `pwd_len` - Password length (20-86)
    /// * `index` - Derivation index
    pub fn derive_pwd_base64(
        &self,
        pwd_len: usize,
        index: u32,
    ) -> Result<Zeroizing<Vec<u8>>, HdError> {
        if !(20..=86).contains(&pwd_len) {
            return Err(HdError::InvalidBip85ByteCount(pwd_len));
        }

        let path_str = format!("m/83696968'/{}'/{}'/{}'/0'", app::PWD_BASE64, pwd_len, index);
        let path = DerivationPath::parse(&path_str)?;

        let entropy = self.derive_entropy(&path)?;

        // Calculate bytes needed for base64 encoding
        let bytes_needed = (pwd_len * 3).div_ceil(4);
        let len = bytes_needed.min(64);
        let mut result = vec![0u8; len];
        result.copy_from_slice(&entropy[..len]);

        Ok(Zeroizing::new(result))
    }
}

/// Convenience function to derive child mnemonic entropy
pub fn derive_bip85_mnemonic(
    master: &ExtendedPrivateKey,
    words: u32,
    index: u32,
) -> Result<Zeroizing<Vec<u8>>, HdError> {
    let bip85 = Bip85::new(master.clone());
    bip85.derive_child_mnemonic(words, index)
}

/// Convenience function to derive child master key
pub fn derive_bip85_master(
    master: &ExtendedPrivateKey,
    index: u32,
    network: crate::network::Network,
) -> Result<ExtendedPrivateKey, HdError> {
    let bip85 = Bip85::new(master.clone());
    bip85.derive_child_master(index, network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Network;

    fn get_test_master() -> ExtendedPrivateKey {
        // Test vector from BIP85
        let xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
        ExtendedPrivateKey::from_xprv(xprv).unwrap()
    }

    #[test]
    fn test_derive_mnemonic_12_words() {
        let master = get_test_master();
        let bip85 = Bip85::new(master);

        let entropy = bip85.derive_mnemonic_entropy(language::ENGLISH, 12, 0).unwrap();
        assert_eq!(entropy.len(), 16); // 12 words = 128 bits = 16 bytes
    }

    #[test]
    fn test_derive_mnemonic_24_words() {
        let master = get_test_master();
        let bip85 = Bip85::new(master);

        let entropy = bip85.derive_mnemonic_entropy(language::ENGLISH, 24, 0).unwrap();
        assert_eq!(entropy.len(), 32); // 24 words = 256 bits = 32 bytes
    }

    #[test]
    fn test_derive_wif_entropy() {
        let master = get_test_master();
        let bip85 = Bip85::new(master);

        let entropy = bip85.derive_wif_entropy(0).unwrap();
        assert_eq!(entropy.len(), 32);
    }

    #[test]
    fn test_derive_xprv_entropy() {
        let master = get_test_master();
        let bip85 = Bip85::new(master);

        let entropy = bip85.derive_xprv_entropy(0).unwrap();
        assert_eq!(entropy.len(), 64);
    }

    #[test]
    fn test_derive_hex_entropy() {
        let master = get_test_master();
        let bip85 = Bip85::new(master);

        let entropy = bip85.derive_hex_entropy(32, 0).unwrap();
        assert_eq!(entropy.len(), 32);

        let entropy64 = bip85.derive_hex_entropy(64, 0).unwrap();
        assert_eq!(entropy64.len(), 64);
    }

    #[test]
    fn test_derive_child_master() {
        let master = get_test_master();
        let bip85 = Bip85::new(master.clone());

        let child_master = bip85.derive_child_master(0, Network::Mainnet).unwrap();

        // Child master should be different from parent
        assert_ne!(child_master.to_xprv(), master.to_xprv());

        // Should be a valid master key (depth 0)
        assert_eq!(child_master.depth(), 0);
    }

    #[test]
    fn test_deterministic_derivation() {
        let master = get_test_master();

        let entropy1 = derive_bip85_mnemonic(&master, 12, 0).unwrap();
        let entropy2 = derive_bip85_mnemonic(&master, 12, 0).unwrap();

        assert_eq!(*entropy1, *entropy2);
    }

    #[test]
    fn test_different_indices_different_entropy() {
        let master = get_test_master();

        let entropy0 = derive_bip85_mnemonic(&master, 12, 0).unwrap();
        let entropy1 = derive_bip85_mnemonic(&master, 12, 1).unwrap();

        assert_ne!(*entropy0, *entropy1);
    }

    #[test]
    fn test_invalid_word_count() {
        let master = get_test_master();
        let bip85 = Bip85::new(master);

        let result = bip85.derive_mnemonic_entropy(language::ENGLISH, 13, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex_byte_count() {
        let master = get_test_master();
        let bip85 = Bip85::new(master);

        let result = bip85.derive_hex_entropy(10, 0); // Too small
        assert!(result.is_err());

        let result = bip85.derive_hex_entropy(100, 0); // Too large
        assert!(result.is_err());
    }

    #[test]
    fn test_convenience_functions() {
        let master = get_test_master();

        let entropy = derive_bip85_mnemonic(&master, 24, 0).unwrap();
        assert_eq!(entropy.len(), 32);

        let child = derive_bip85_master(&master, 0, Network::Mainnet).unwrap();
        assert_eq!(child.depth(), 0);
    }
}
