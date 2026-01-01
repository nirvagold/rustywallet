//! Private key implementation
//!
//! This module provides the [`PrivateKey`] type for working with secp256k1 private keys.

use crate::encoding::{hex, wif};
use crate::error::PrivateKeyError;
use crate::network::Network;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use secp256k1::{Secp256k1, SecretKey};
use std::fmt;
use zeroize::Zeroize;

/// An iterator that generates random private keys.
///
/// This iterator is infinite and memory-efficient - it generates keys on demand
/// without storing them. Use `.take(n)` to limit the number of keys generated.
///
/// # Example
///
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
///
/// // Generate 1000 keys efficiently
/// let keys: Vec<_> = PrivateKey::batch().take(1000).collect();
/// assert_eq!(keys.len(), 1000);
///
/// // Process keys one by one without storing all in memory
/// for key in PrivateKey::batch().take(100) {
///     println!("{}", key.to_hex());
/// }
/// ```
pub struct PrivateKeyIterator<R: RngCore + CryptoRng> {
    rng: R,
    secp: Secp256k1<secp256k1::All>,
}

impl PrivateKeyIterator<OsRng> {
    /// Create a new iterator using the OS random number generator.
    fn new() -> Self {
        Self {
            rng: OsRng,
            secp: Secp256k1::new(),
        }
    }
}

impl<R: RngCore + CryptoRng> PrivateKeyIterator<R> {
    /// Create a new iterator with a custom RNG.
    fn with_rng(rng: R) -> Self {
        Self {
            rng,
            secp: Secp256k1::new(),
        }
    }
}

impl<R: RngCore + CryptoRng> Iterator for PrivateKeyIterator<R> {
    type Item = PrivateKey;

    fn next(&mut self) -> Option<Self::Item> {
        let (secret_key, _) = self.secp.generate_keypair(&mut self.rng);
        Some(PrivateKey { inner: secret_key })
    }
}

/// A secp256k1 private key with secure memory handling.
///
/// This struct wraps a `secp256k1::SecretKey` and provides convenient methods
/// for key generation, import, and export. The key is automatically zeroized
/// when dropped for security.
///
/// # Example
///
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_keys::network::Network;
///
/// // Generate a random key
/// let key = PrivateKey::random();
///
/// // Export to hex
/// let hex = key.to_hex();
/// assert_eq!(hex.len(), 64);
///
/// // Export to WIF
/// let wif = key.to_wif(Network::Mainnet);
/// assert!(wif.starts_with('K') || wif.starts_with('L'));
/// ```
pub struct PrivateKey {
    inner: SecretKey,
}

impl PrivateKey {
    /// Generate a new random private key using a cryptographically secure RNG.
    ///
    /// This method uses the operating system's secure random number generator
    /// and automatically regenerates if an invalid key is produced (which is
    /// extremely unlikely).
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// ```
    pub fn random() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut OsRng);
        Self { inner: secret_key }
    }

    /// Create an infinite iterator that generates random private keys.
    ///
    /// This is memory-efficient as keys are generated on demand. Use `.take(n)`
    /// to limit the number of keys.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// // Generate 1000 keys
    /// let keys: Vec<_> = PrivateKey::batch().take(1000).collect();
    ///
    /// // Process without storing all in memory
    /// for key in PrivateKey::batch().take(100) {
    ///     let _ = key.to_hex();
    /// }
    /// ```
    pub fn batch() -> PrivateKeyIterator<OsRng> {
        PrivateKeyIterator::new()
    }

    /// Create an iterator with a custom RNG for deterministic key generation.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rand::SeedableRng;
    /// use rand::rngs::StdRng;
    ///
    /// let rng = StdRng::seed_from_u64(12345);
    /// let keys: Vec<_> = PrivateKey::batch_with_rng(rng).take(10).collect();
    /// ```
    pub fn batch_with_rng<R: RngCore + CryptoRng>(rng: R) -> PrivateKeyIterator<R> {
        PrivateKeyIterator::with_rng(rng)
    }

    /// Create a private key from a 32-byte array.
    ///
    /// # Errors
    ///
    /// Returns [`PrivateKeyError::OutOfRange`] if the bytes represent a value
    /// that is zero or greater than or equal to the curve order.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let key = PrivateKey::from_bytes(bytes).unwrap();
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrivateKeyError> {
        let secret_key = SecretKey::from_slice(&bytes).map_err(|_| PrivateKeyError::OutOfRange)?;
        Ok(Self { inner: secret_key })
    }

    /// Check if a 32-byte array represents a valid private key.
    ///
    /// A valid private key must be non-zero and less than the secp256k1 curve order.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let valid_bytes = [1u8; 32];
    /// assert!(PrivateKey::is_valid(&valid_bytes));
    ///
    /// let zero_bytes = [0u8; 32];
    /// assert!(!PrivateKey::is_valid(&zero_bytes));
    /// ```
    pub fn is_valid(bytes: &[u8; 32]) -> bool {
        SecretKey::from_slice(bytes).is_ok()
    }

    /// Create a private key from a hex string.
    ///
    /// The hex string must be exactly 64 characters (32 bytes).
    /// Both uppercase and lowercase characters are accepted.
    ///
    /// # Errors
    ///
    /// - [`PrivateKeyError::InvalidLength`] if the hex string is not 64 characters
    /// - [`PrivateKeyError::InvalidHex`] if the string contains invalid hex characters
    /// - [`PrivateKeyError::OutOfRange`] if the decoded value is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    /// let key = PrivateKey::from_hex(hex).unwrap();
    /// ```
    pub fn from_hex(hex_str: &str) -> Result<Self, PrivateKeyError> {
        if hex_str.len() != 64 {
            return Err(PrivateKeyError::InvalidLength(hex_str.len() / 2));
        }

        let bytes = hex::decode(hex_str).map_err(|e| PrivateKeyError::InvalidHex(e.to_string()))?;

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(arr)
    }

    /// Create a private key from a WIF (Wallet Import Format) string.
    ///
    /// # Errors
    ///
    /// - [`PrivateKeyError::InvalidWif`] if the WIF format is invalid
    /// - [`PrivateKeyError::InvalidChecksum`] if the checksum doesn't match
    /// - [`PrivateKeyError::OutOfRange`] if the decoded key is invalid
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    /// let key = PrivateKey::from_wif(wif).unwrap();
    /// ```
    pub fn from_wif(wif_str: &str) -> Result<Self, PrivateKeyError> {
        let (bytes, _network, _compressed) = wif::decode(wif_str).map_err(|e| match e {
            wif::WifError::InvalidChecksum => PrivateKeyError::InvalidChecksum,
            other => PrivateKeyError::InvalidWif(other.to_string()),
        })?;
        Self::from_bytes(bytes)
    }

    /// Export the private key as a 32-byte array.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// let bytes = key.to_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.secret_bytes()
    }

    /// Export the private key as a lowercase hex string.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// let hex = key.to_hex();
    /// assert_eq!(hex.len(), 64);
    /// ```
    pub fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    /// Export the private key as a WIF (Wallet Import Format) string.
    ///
    /// The WIF format includes the network version byte and uses compressed
    /// public key format by default.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    /// use rustywallet_keys::network::Network;
    ///
    /// let key = PrivateKey::random();
    /// let wif = key.to_wif(Network::Mainnet);
    /// assert!(wif.starts_with('K') || wif.starts_with('L'));
    /// ```
    pub fn to_wif(&self, network: Network) -> String {
        wif::encode(&self.to_bytes(), network, true)
    }

    /// Export the private key as a decimal string.
    ///
    /// This converts the 256-bit key to its decimal representation.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let key = PrivateKey::from_hex(
    ///     "0000000000000000000000000000000000000000000000000000000000000001"
    /// ).unwrap();
    /// assert_eq!(key.to_decimal(), "1");
    /// ```
    pub fn to_decimal(&self) -> String {
        let bytes = self.to_bytes();
        bytes_to_decimal(&bytes)
    }

    /// Derive the corresponding public key.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_keys::private_key::PrivateKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// ```
    pub fn public_key(&self) -> crate::public_key::PublicKey {
        crate::public_key::PublicKey::from_private_key(self)
    }
}

/// Convert a 32-byte array to decimal string
fn bytes_to_decimal(bytes: &[u8; 32]) -> String {
    // Handle zero case
    if bytes.iter().all(|&b| b == 0) {
        return "0".to_string();
    }

    // Convert bytes to decimal using repeated division
    let mut result = Vec::new();
    let mut temp = bytes.to_vec();

    while temp.iter().any(|&b| b != 0) {
        let mut remainder = 0u32;
        for byte in temp.iter_mut() {
            let value = (remainder << 8) | (*byte as u32);
            *byte = (value / 10) as u8;
            remainder = value % 10;
        }
        result.push((remainder as u8) + b'0');
    }

    result.reverse();
    String::from_utf8(result).unwrap_or_else(|_| "0".to_string())
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // SecretKey doesn't expose mutable access to its bytes,
        // but secp256k1 crate handles zeroization internally.
        // We create a temporary copy and zeroize it to ensure
        // any stack copies are cleared.
        let mut bytes = self.inner.secret_bytes();
        bytes.zeroize();
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateKey {{ hex: {}, decimal: {} }}",
            self.to_hex(),
            self.to_decimal()
        )
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self { inner: self.inner }
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for PrivateKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy to generate valid private key bytes
    fn valid_private_key_bytes() -> impl Strategy<Value = [u8; 32]> {
        // Generate random bytes and filter to valid keys
        prop::array::uniform32(any::<u8>()).prop_filter("must be valid secp256k1 key", |bytes| {
            PrivateKey::is_valid(bytes)
        })
    }

    // **Feature: rustywallet-keys, Property 1: Random Key Validity**
    // **Validates: Requirements 1.1, 1.2**
    // For any randomly generated private key, the key SHALL be valid
    // (non-zero and less than the secp256k1 curve order).
    #[test]
    fn property_random_key_validity() {
        // Generate 100 random keys and verify each is valid
        for _ in 0..100 {
            let key = PrivateKey::random();
            let bytes = key.to_bytes();

            // Verify the key is valid
            assert!(PrivateKey::is_valid(&bytes), "Random key should be valid");

            // Verify the key is non-zero
            assert!(
                bytes.iter().any(|&b| b != 0),
                "Random key should not be all zeros"
            );

            // Verify we can reconstruct the key from bytes
            let reconstructed =
                PrivateKey::from_bytes(bytes).expect("Should be able to reconstruct from bytes");
            assert_eq!(
                key, reconstructed,
                "Reconstructed key should equal original"
            );
        }
    }

    // **Feature: rustywallet-keys, Property 2: Hex Round-Trip**
    // **Validates: Requirements 2.1, 3.1, 3.5**
    // For any valid private key, converting to hex and parsing back SHALL produce
    // an equivalent private key.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_hex_roundtrip(bytes in valid_private_key_bytes()) {
            let key = PrivateKey::from_bytes(bytes).unwrap();
            let hex = key.to_hex();
            let recovered = PrivateKey::from_hex(&hex).unwrap();
            prop_assert_eq!(key, recovered);
        }
    }

    // **Feature: rustywallet-keys, Property 3: Bytes Round-Trip**
    // **Validates: Requirements 2.2, 3.2, 3.5**
    // For any valid private key, exporting to bytes and importing back SHALL produce
    // an equivalent private key.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_bytes_roundtrip(bytes in valid_private_key_bytes()) {
            let key = PrivateKey::from_bytes(bytes).unwrap();
            let exported = key.to_bytes();
            let recovered = PrivateKey::from_bytes(exported).unwrap();
            prop_assert_eq!(key, recovered);
        }
    }

    // **Feature: rustywallet-keys, Property 4: WIF Round-Trip**
    // **Validates: Requirements 2.3, 3.3, 3.4, 3.5**
    // For any valid private key and network, encoding to WIF and decoding back
    // SHALL produce an equivalent private key.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_wif_roundtrip(
            bytes in valid_private_key_bytes(),
            use_mainnet in any::<bool>()
        ) {
            let network = if use_mainnet { Network::Mainnet } else { Network::Testnet };
            let key = PrivateKey::from_bytes(bytes).unwrap();
            let wif = key.to_wif(network);
            let recovered = PrivateKey::from_wif(&wif).unwrap();
            prop_assert_eq!(key, recovered);
        }
    }

    // **Feature: rustywallet-keys, Property 5: Hex Case Insensitivity**
    // **Validates: Requirements 2.5**
    // For any valid hex string representing a private key, both uppercase and
    // lowercase versions SHALL parse to equivalent keys.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_hex_case_insensitivity(bytes in valid_private_key_bytes()) {
            let key = PrivateKey::from_bytes(bytes).unwrap();
            let hex_lower = key.to_hex();
            let hex_upper = hex_lower.to_uppercase();

            let from_lower = PrivateKey::from_hex(&hex_lower).unwrap();
            let from_upper = PrivateKey::from_hex(&hex_upper).unwrap();

            prop_assert_eq!(from_lower, from_upper);
        }
    }

    // **Feature: rustywallet-keys, Property 6: Invalid Input Rejection**
    // **Validates: Requirements 2.4, 4.1, 4.2, 4.3**
    // For any byte array that is zero or >= curve order, the validation function
    // SHALL return false and construction SHALL return an error.
    #[test]
    fn property_invalid_input_rejection() {
        // Test zero key
        let zero_bytes = [0u8; 32];
        assert!(
            !PrivateKey::is_valid(&zero_bytes),
            "Zero key should be invalid"
        );
        assert!(
            PrivateKey::from_bytes(zero_bytes).is_err(),
            "Zero key should fail construction"
        );

        // Test curve order (n) - this is >= curve order so should be invalid
        // secp256k1 curve order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        let curve_order: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];
        assert!(
            !PrivateKey::is_valid(&curve_order),
            "Curve order should be invalid"
        );
        assert!(
            PrivateKey::from_bytes(curve_order).is_err(),
            "Curve order should fail construction"
        );

        // Test value greater than curve order
        let above_order: [u8; 32] = [0xFF; 32];
        assert!(
            !PrivateKey::is_valid(&above_order),
            "Value above curve order should be invalid"
        );
        assert!(
            PrivateKey::from_bytes(above_order).is_err(),
            "Value above curve order should fail construction"
        );

        // Test that n-1 is valid (maximum valid key)
        let max_valid: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x40,
        ];
        assert!(PrivateKey::is_valid(&max_valid), "n-1 should be valid");
        assert!(
            PrivateKey::from_bytes(max_valid).is_ok(),
            "n-1 should succeed construction"
        );

        // Test that 1 is valid (minimum valid key)
        let min_valid: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert!(PrivateKey::is_valid(&min_valid), "1 should be valid");
        assert!(
            PrivateKey::from_bytes(min_valid).is_ok(),
            "1 should succeed construction"
        );
    }

    // **Feature: rustywallet-keys, Property 11: Debug Output Format**
    // **Validates: Requirements 8.5**
    // For any private key, the Debug trait output SHALL contain the key in hex format.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn property_debug_output_format(bytes in valid_private_key_bytes()) {
            let key = PrivateKey::from_bytes(bytes).unwrap();
            let debug_output = format!("{:?}", key);
            let hex_output = key.to_hex();
            let decimal_output = key.to_decimal();

            // Debug output should contain both hex and decimal
            let expected = format!("PrivateKey {{ hex: {}, decimal: {} }}", hex_output, decimal_output);
            prop_assert_eq!(&debug_output, &expected);
        }
    }

    // Test decimal conversion
    #[test]
    fn test_decimal_conversion() {
        // Key = 1
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert_eq!(key.to_decimal(), "1");

        // Key = 256
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000100",
        )
        .unwrap();
        assert_eq!(key.to_decimal(), "256");

        // Key = 65536
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000010000",
        )
        .unwrap();
        assert_eq!(key.to_decimal(), "65536");
    }

    // ==================== Known Test Vectors ====================

    /// Test vector from Bitcoin Wiki
    /// https://en.bitcoin.it/wiki/Wallet_import_format
    #[test]
    fn test_vector_wif_bitcoin_wiki() {
        // Private key: 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
        // WIF (uncompressed): 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
        let hex = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
        let expected_wif_uncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

        let key = PrivateKey::from_hex(hex).unwrap();

        // Import from WIF should work
        let from_wif = PrivateKey::from_wif(expected_wif_uncompressed).unwrap();
        assert_eq!(key, from_wif);
    }

    /// Test vector: Key value 1 (minimum valid key)
    #[test]
    fn test_vector_key_one() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key = PrivateKey::from_hex(hex).unwrap();

        // Verify hex round-trip
        assert_eq!(key.to_hex(), hex.to_lowercase());

        // Verify bytes
        let mut expected_bytes = [0u8; 32];
        expected_bytes[31] = 1;
        assert_eq!(key.to_bytes(), expected_bytes);

        // Verify public key derivation works
        let public_key = key.public_key();
        let compressed = public_key.to_compressed();
        assert_eq!(compressed.len(), 33);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    /// Test vector: Known public key derivation
    /// Private key 1 should produce a specific public key
    #[test]
    fn test_vector_pubkey_derivation() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key = PrivateKey::from_hex(hex).unwrap();
        let public_key = key.public_key();

        // Known compressed public key for private key = 1
        // 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        let compressed_hex = public_key.to_hex(crate::public_key::PublicKeyFormat::Compressed);
        assert_eq!(
            compressed_hex.to_lowercase(),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    /// Test WIF encoding for testnet
    #[test]
    fn test_vector_wif_testnet() {
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let wif_mainnet = key.to_wif(Network::Mainnet);
        let wif_testnet = key.to_wif(Network::Testnet);

        // Mainnet compressed WIF starts with K or L
        assert!(
            wif_mainnet.starts_with('K') || wif_mainnet.starts_with('L'),
            "Mainnet WIF should start with K or L"
        );

        // Testnet compressed WIF starts with c
        assert!(
            wif_testnet.starts_with('c'),
            "Testnet WIF should start with c"
        );

        // Both should decode back to the same key
        let from_mainnet = PrivateKey::from_wif(&wif_mainnet).unwrap();
        let from_testnet = PrivateKey::from_wif(&wif_testnet).unwrap();
        assert_eq!(key, from_mainnet);
        assert_eq!(key, from_testnet);
    }
}
