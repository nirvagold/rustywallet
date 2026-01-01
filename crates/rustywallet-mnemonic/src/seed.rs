//! Seed derivation from mnemonic using PBKDF2.

use crate::error::MnemonicError;
use crate::mnemonic::Mnemonic;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use std::fmt;
use zeroize::Zeroizing;

/// 512-bit seed derived from mnemonic.
///
/// The seed is derived using PBKDF2-HMAC-SHA512 with 2048 iterations.
/// The seed bytes are zeroized on drop.
///
/// # Example
///
/// ```
/// use rustywallet_mnemonic::{Mnemonic, Seed};
///
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
///
/// // Derive seed with passphrase
/// let seed = Seed::new(&mnemonic, "TREZOR");
/// assert_eq!(seed.as_bytes().len(), 64);
///
/// // Derive seed without passphrase
/// let seed_no_pass = Seed::new(&mnemonic, "");
/// ```
pub struct Seed {
    bytes: Zeroizing<[u8; 64]>,
}

impl Seed {
    /// Create a new seed from mnemonic and passphrase.
    ///
    /// Uses PBKDF2-HMAC-SHA512 with 2048 iterations.
    /// Salt is "mnemonic" + passphrase.
    pub fn new(mnemonic: &Mnemonic, passphrase: &str) -> Self {
        let phrase = mnemonic.to_phrase();
        let salt = format!("mnemonic{}", passphrase);

        let mut seed = [0u8; 64];
        pbkdf2::<Hmac<Sha512>>(phrase.as_bytes(), salt.as_bytes(), 2048, &mut seed)
            .expect("PBKDF2 should not fail with valid parameters");

        Self {
            bytes: Zeroizing::new(seed),
        }
    }

    /// Get the seed bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// Derive a private key from the seed.
    ///
    /// Takes the first 32 bytes of the seed as the private key.
    pub fn to_private_key(&self) -> Result<rustywallet_keys::private_key::PrivateKey, MnemonicError> {
        let key_bytes: [u8; 32] = self.bytes[..32]
            .try_into()
            .expect("Slice is exactly 32 bytes");

        rustywallet_keys::private_key::PrivateKey::from_bytes(key_bytes)
            .map_err(|_| MnemonicError::InvalidPrivateKey)
    }

    /// Get seed as hex string.
    pub fn to_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seed(****)")
    }
}

impl Clone for Seed {
    fn clone(&self) -> Self {
        Self {
            bytes: Zeroizing::new(*self.bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_test_vector() {
        // BIP39 test vector
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = Seed::new(&mnemonic, "TREZOR");

        let expected = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        assert_eq!(seed.to_hex(), expected);
    }

    #[test]
    fn test_seed_length() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = Seed::new(&mnemonic, "");
        assert_eq!(seed.as_bytes().len(), 64);
    }

    #[test]
    fn test_different_passphrase_different_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

        let seed1 = Seed::new(&mnemonic, "");
        let seed2 = Seed::new(&mnemonic, "password");

        assert_ne!(seed1.as_bytes(), seed2.as_bytes());
    }

    #[test]
    fn test_debug_masked() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = Seed::new(&mnemonic, "");

        let debug = format!("{:?}", seed);
        assert_eq!(debug, "Seed(****)");
    }

    #[test]
    fn test_to_private_key() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        let seed = Seed::new(&mnemonic, "");

        let private_key = seed.to_private_key();
        assert!(private_key.is_ok());
    }
}
