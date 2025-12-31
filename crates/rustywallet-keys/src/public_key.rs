//! Public key implementation
//!
//! This module provides the [`PublicKey`] type for working with secp256k1 public keys.

use crate::encoding::hex;
use crate::error::PublicKeyError;
use crate::private_key::PrivateKey;
use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1};

/// Public key serialization format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyFormat {
    /// Compressed format (33 bytes, prefix 02 or 03)
    Compressed,
    /// Uncompressed format (65 bytes, prefix 04)
    Uncompressed,
}

/// A secp256k1 public key.
///
/// This struct wraps a `secp256k1::PublicKey` and provides convenient methods
/// for key derivation, import, and export in various formats.
///
/// # Example
///
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_keys::public_key::{PublicKey, PublicKeyFormat};
///
/// let private_key = PrivateKey::random();
/// let public_key = private_key.public_key();
///
/// // Export to compressed format (33 bytes)
/// let compressed = public_key.to_compressed();
/// assert_eq!(compressed.len(), 33);
///
/// // Export to uncompressed format (65 bytes)
/// let uncompressed = public_key.to_uncompressed();
/// assert_eq!(uncompressed.len(), 65);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: Secp256k1PublicKey,
}

impl PublicKey {
    /// Create a public key from a private key.
    ///
    /// This performs the secp256k1 point multiplication to derive the public key.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_keys::public_key::PublicKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = PublicKey::from_private_key(&private_key);
    /// ```
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        let secp = Secp256k1::new();
        let secret_key = secp256k1::SecretKey::from_slice(&private_key.to_bytes())
            .expect("PrivateKey should always contain valid bytes");
        let public_key = Secp256k1PublicKey::from_secret_key(&secp, &secret_key);
        Self { inner: public_key }
    }

    /// Create a public key from compressed bytes (33 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError::InvalidLength`] if the slice is not 33 bytes.
    /// Returns [`PublicKeyError::InvalidPoint`] if the bytes don't represent a valid point.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_keys::public_key::PublicKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let compressed = public_key.to_compressed();
    /// let recovered = PublicKey::from_compressed(&compressed).unwrap();
    /// assert_eq!(public_key, recovered);
    /// ```
    pub fn from_compressed(bytes: &[u8; 33]) -> Result<Self, PublicKeyError> {
        let public_key =
            Secp256k1PublicKey::from_slice(bytes).map_err(|_| PublicKeyError::InvalidPoint)?;
        Ok(Self { inner: public_key })
    }

    /// Create a public key from uncompressed bytes (65 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError::InvalidLength`] if the slice is not 65 bytes.
    /// Returns [`PublicKeyError::InvalidPoint`] if the bytes don't represent a valid point.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_keys::public_key::PublicKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let uncompressed = public_key.to_uncompressed();
    /// let recovered = PublicKey::from_uncompressed(&uncompressed).unwrap();
    /// assert_eq!(public_key, recovered);
    /// ```
    pub fn from_uncompressed(bytes: &[u8; 65]) -> Result<Self, PublicKeyError> {
        let public_key =
            Secp256k1PublicKey::from_slice(bytes).map_err(|_| PublicKeyError::InvalidPoint)?;
        Ok(Self { inner: public_key })
    }

    /// Create a public key from a hex string.
    ///
    /// Accepts both compressed (66 chars) and uncompressed (130 chars) formats.
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError::InvalidLength`] if the hex string has wrong length.
    /// Returns [`PublicKeyError::InvalidHex`] if the string contains invalid hex characters.
    /// Returns [`PublicKeyError::InvalidPoint`] if the decoded bytes don't represent a valid point.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_keys::public_key::{PublicKey, PublicKeyFormat};
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let hex = public_key.to_hex(PublicKeyFormat::Compressed);
    /// let recovered = PublicKey::from_hex(&hex).unwrap();
    /// assert_eq!(public_key, recovered);
    /// ```
    pub fn from_hex(hex_str: &str) -> Result<Self, PublicKeyError> {
        let expected_len = match hex_str.len() {
            66 => 33,  // Compressed
            130 => 65, // Uncompressed
            _ => {
                return Err(PublicKeyError::InvalidLength {
                    expected: 33,
                    actual: hex_str.len() / 2,
                })
            }
        };

        let bytes = hex::decode(hex_str).map_err(|e| PublicKeyError::InvalidHex(e.to_string()))?;

        if bytes.len() != expected_len {
            return Err(PublicKeyError::InvalidLength {
                expected: expected_len,
                actual: bytes.len(),
            });
        }

        let public_key =
            Secp256k1PublicKey::from_slice(&bytes).map_err(|_| PublicKeyError::InvalidPoint)?;
        Ok(Self { inner: public_key })
    }

    /// Export the public key as compressed bytes (33 bytes).
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let compressed = public_key.to_compressed();
    /// assert_eq!(compressed.len(), 33);
    /// assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    /// ```
    pub fn to_compressed(&self) -> [u8; 33] {
        self.inner.serialize()
    }

    /// Export the public key as uncompressed bytes (65 bytes).
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let uncompressed = public_key.to_uncompressed();
    /// assert_eq!(uncompressed.len(), 65);
    /// assert_eq!(uncompressed[0], 0x04);
    /// ```
    pub fn to_uncompressed(&self) -> [u8; 65] {
        self.inner.serialize_uncompressed()
    }

    /// Export the public key as a hex string.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_keys::public_key::PublicKeyFormat;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    ///
    /// let compressed_hex = public_key.to_hex(PublicKeyFormat::Compressed);
    /// assert_eq!(compressed_hex.len(), 66);
    ///
    /// let uncompressed_hex = public_key.to_hex(PublicKeyFormat::Uncompressed);
    /// assert_eq!(uncompressed_hex.len(), 130);
    /// ```
    pub fn to_hex(&self, format: PublicKeyFormat) -> String {
        match format {
            PublicKeyFormat::Compressed => hex::encode(&self.to_compressed()),
            PublicKeyFormat::Uncompressed => hex::encode(&self.to_uncompressed()),
        }
    }

    /// Export the public key as bytes with the specified format.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_keys::public_key::PublicKeyFormat;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    ///
    /// let compressed = public_key.to_bytes(PublicKeyFormat::Compressed);
    /// assert_eq!(compressed.len(), 33);
    ///
    /// let uncompressed = public_key.to_bytes(PublicKeyFormat::Uncompressed);
    /// assert_eq!(uncompressed.len(), 65);
    /// ```
    pub fn to_bytes(&self, format: PublicKeyFormat) -> Vec<u8> {
        match format {
            PublicKeyFormat::Compressed => self.to_compressed().to_vec(),
            PublicKeyFormat::Uncompressed => self.to_uncompressed().to_vec(),
        }
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.to_hex(PublicKeyFormat::Compressed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy to generate valid private key bytes
    fn valid_private_key_bytes() -> impl Strategy<Value = [u8; 32]> {
        prop::array::uniform32(any::<u8>()).prop_filter("must be valid secp256k1 key", |bytes| {
            PrivateKey::is_valid(bytes)
        })
    }

    // **Feature: rustywallet-keys, Property 7: Public Key Derivation Determinism**
    // **Validates: Requirements 5.4**
    // For any private key, deriving the public key multiple times SHALL produce
    // identical results.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_public_key_derivation_determinism(bytes in valid_private_key_bytes()) {
            let private_key = PrivateKey::from_bytes(bytes).unwrap();

            let public_key1 = private_key.public_key();
            let public_key2 = private_key.public_key();
            let public_key3 = PublicKey::from_private_key(&private_key);

            prop_assert_eq!(&public_key1, &public_key2);
            prop_assert_eq!(&public_key2, &public_key3);
        }
    }

    // **Feature: rustywallet-keys, Property 8: Public Key Format Invariants**
    // **Validates: Requirements 5.2, 5.3, 7.1, 7.2**
    // For any private key, the derived compressed public key SHALL be 33 bytes
    // and uncompressed SHALL be 65 bytes.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_public_key_format_invariants(bytes in valid_private_key_bytes()) {
            let private_key = PrivateKey::from_bytes(bytes).unwrap();
            let public_key = private_key.public_key();

            // Compressed format invariants
            let compressed = public_key.to_compressed();
            prop_assert_eq!(compressed.len(), 33);
            prop_assert!(compressed[0] == 0x02 || compressed[0] == 0x03,
                "Compressed prefix must be 02 or 03");

            // Uncompressed format invariants
            let uncompressed = public_key.to_uncompressed();
            prop_assert_eq!(uncompressed.len(), 65);
            prop_assert_eq!(uncompressed[0], 0x04,
                "Uncompressed prefix must be 04");

            // Hex format invariants
            let compressed_hex = public_key.to_hex(PublicKeyFormat::Compressed);
            prop_assert_eq!(compressed_hex.len(), 66);

            let uncompressed_hex = public_key.to_hex(PublicKeyFormat::Uncompressed);
            prop_assert_eq!(uncompressed_hex.len(), 130);

            // to_bytes format invariants
            let compressed_bytes = public_key.to_bytes(PublicKeyFormat::Compressed);
            prop_assert_eq!(compressed_bytes.len(), 33);

            let uncompressed_bytes = public_key.to_bytes(PublicKeyFormat::Uncompressed);
            prop_assert_eq!(uncompressed_bytes.len(), 65);
        }
    }

    // **Feature: rustywallet-keys, Property 9: Public Key Format Round-Trip**
    // **Validates: Requirements 6.1, 6.2, 6.3, 6.4**
    // For any public key, converting between compressed and uncompressed formats
    // SHALL preserve the underlying key data.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_public_key_format_roundtrip(bytes in valid_private_key_bytes()) {
            let private_key = PrivateKey::from_bytes(bytes).unwrap();
            let original = private_key.public_key();

            // Compressed round-trip
            let compressed = original.to_compressed();
            let from_compressed = PublicKey::from_compressed(&compressed).unwrap();
            prop_assert_eq!(&original, &from_compressed);

            // Uncompressed round-trip
            let uncompressed = original.to_uncompressed();
            let from_uncompressed = PublicKey::from_uncompressed(&uncompressed).unwrap();
            prop_assert_eq!(&original, &from_uncompressed);

            // Cross-format: compressed -> uncompressed -> compressed
            let from_compressed_uncompressed = from_compressed.to_uncompressed();
            let back_to_compressed = PublicKey::from_uncompressed(&from_compressed_uncompressed)
                .unwrap()
                .to_compressed();
            prop_assert_eq!(compressed, back_to_compressed);
        }
    }

    // **Feature: rustywallet-keys, Property 10: Public Key Serialization Round-Trip**
    // **Validates: Requirements 7.3**
    // For any public key, serializing to bytes/hex and deserializing back SHALL
    // produce an equivalent public key.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_public_key_serialization_roundtrip(bytes in valid_private_key_bytes()) {
            let private_key = PrivateKey::from_bytes(bytes).unwrap();
            let original = private_key.public_key();

            // Hex round-trip (compressed)
            let hex_compressed = original.to_hex(PublicKeyFormat::Compressed);
            let from_hex_compressed = PublicKey::from_hex(&hex_compressed).unwrap();
            prop_assert_eq!(&original, &from_hex_compressed);

            // Hex round-trip (uncompressed)
            let hex_uncompressed = original.to_hex(PublicKeyFormat::Uncompressed);
            let from_hex_uncompressed = PublicKey::from_hex(&hex_uncompressed).unwrap();
            prop_assert_eq!(&original, &from_hex_uncompressed);
        }
    }
}
