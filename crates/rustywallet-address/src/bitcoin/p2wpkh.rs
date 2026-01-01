//! P2WPKH (Pay-to-Witness-Public-Key-Hash) Bitcoin SegWit address.

use crate::encoding::Bech32Encoder;
use crate::error::AddressError;
use crate::network::Network;
use ripemd::Ripemd160;
use rustywallet_keys::public_key::PublicKey;
use sha2::{Digest, Sha256};

/// HRP for mainnet SegWit addresses.
const MAINNET_HRP: &str = "bc";
/// HRP for testnet SegWit addresses.
const TESTNET_HRP: &str = "tb";

/// P2WPKH (SegWit) Bitcoin address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2WPKHAddress {
    hash: [u8; 20],
    network: Network,
    encoded: String,
}

impl P2WPKHAddress {
    /// Generate P2WPKH address from compressed public key.
    ///
    /// SegWit addresses require compressed public keys.
    ///
    /// # Example
    /// ```
    /// use rustywallet_keys::prelude::*;
    /// use rustywallet_address::{P2WPKHAddress, Network};
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let address = P2WPKHAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
    /// assert!(address.to_string().starts_with("bc1q"));
    /// ```
    pub fn from_public_key(public_key: &PublicKey, network: Network) -> Result<Self, AddressError> {
        if !network.is_bitcoin() {
            return Err(AddressError::NetworkMismatch {
                expected: "Bitcoin".to_string(),
                actual: network.to_string(),
            });
        }

        // SegWit always uses compressed public key (33 bytes)
        let pubkey_bytes = public_key.to_compressed();
        let hash = hash160(&pubkey_bytes);
        let hrp = Self::hrp(network);
        let encoded = Bech32Encoder::encode_bech32(hrp, 0, &hash)?;

        Ok(Self {
            hash,
            network,
            encoded,
        })
    }

    /// Parse P2WPKH address from string.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        s.parse()
    }

    /// Validate P2WPKH address string.
    pub fn validate(s: &str) -> Result<(), AddressError> {
        s.parse::<Self>().map(|_| ())
    }

    /// Get the hash160 of the public key.
    #[inline]
    pub fn hash(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Get the network.
    #[inline]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get HRP for network.
    fn hrp(network: Network) -> &'static str {
        match network {
            Network::BitcoinMainnet => MAINNET_HRP,
            Network::BitcoinTestnet => TESTNET_HRP,
            _ => MAINNET_HRP,
        }
    }
}

impl std::fmt::Display for P2WPKHAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

impl std::str::FromStr for P2WPKHAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, version, program) = Bech32Encoder::decode(s)?;

        if version != 0 {
            return Err(AddressError::InvalidFormat(format!(
                "Invalid witness version for P2WPKH: expected 0, got {}",
                version
            )));
        }

        let network = match hrp.as_str() {
            MAINNET_HRP => Network::BitcoinMainnet,
            TESTNET_HRP => Network::BitcoinTestnet,
            _ => {
                return Err(AddressError::InvalidFormat(format!(
                    "Unknown HRP: {}",
                    hrp
                )))
            }
        };

        if program.len() != 20 {
            return Err(AddressError::InvalidFormat(format!(
                "Invalid program length for P2WPKH: expected 20, got {}",
                program.len()
            )));
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&program);

        Ok(Self {
            hash,
            network,
            encoded: s.to_lowercase(),
        })
    }
}

/// Calculate HASH160 (SHA256 + RIPEMD160).
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let ripemd_hash = Ripemd160::digest(sha256_hash);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_p2wpkh_mainnet() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2WPKHAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
        assert!(address.to_string().starts_with("bc1q"));
    }

    #[test]
    fn test_p2wpkh_testnet() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2WPKHAddress::from_public_key(&public_key, Network::BitcoinTestnet).unwrap();
        assert!(address.to_string().starts_with("tb1q"));
    }

    #[test]
    fn test_p2wpkh_roundtrip() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2WPKHAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
        let parsed: P2WPKHAddress = address.to_string().parse().unwrap();
        assert_eq!(address.hash(), parsed.hash());
        assert_eq!(address.network(), parsed.network());
    }
}
