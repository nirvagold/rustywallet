//! P2PKH (Pay-to-Public-Key-Hash) Bitcoin Legacy address.

use crate::encoding::Base58Check;
use crate::error::AddressError;
use crate::network::Network;
use ripemd::Ripemd160;
use rustywallet_keys::public_key::PublicKey;
use sha2::{Digest, Sha256};

/// Version byte for mainnet P2PKH addresses.
const MAINNET_VERSION: u8 = 0x00;
/// Version byte for testnet P2PKH addresses.
const TESTNET_VERSION: u8 = 0x6f;

/// P2PKH (Legacy) Bitcoin address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2PKHAddress {
    hash: [u8; 20],
    network: Network,
    encoded: String,
}

impl P2PKHAddress {
    /// Generate P2PKH address from public key.
    ///
    /// Works with both compressed and uncompressed public keys.
    ///
    /// # Example
    /// ```
    /// use rustywallet_keys::prelude::*;
    /// use rustywallet_address::{P2PKHAddress, Network};
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let address = P2PKHAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
    /// assert!(address.to_string().starts_with('1'));
    /// ```
    pub fn from_public_key(public_key: &PublicKey, network: Network) -> Result<Self, AddressError> {
        if !network.is_bitcoin() {
            return Err(AddressError::NetworkMismatch {
                expected: "Bitcoin".to_string(),
                actual: network.to_string(),
            });
        }

        let pubkey_bytes = public_key.to_compressed();
        let hash = hash160(&pubkey_bytes);
        let version = Self::version_byte(network);
        let encoded = Base58Check::encode(version, &hash);

        Ok(Self {
            hash,
            network,
            encoded,
        })
    }

    /// Parse P2PKH address from string.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        s.parse()
    }

    /// Validate P2PKH address string.
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

    /// Get version byte for network.
    fn version_byte(network: Network) -> u8 {
        match network {
            Network::BitcoinMainnet => MAINNET_VERSION,
            Network::BitcoinTestnet => TESTNET_VERSION,
            _ => MAINNET_VERSION,
        }
    }
}

impl std::fmt::Display for P2PKHAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

impl std::str::FromStr for P2PKHAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (version, payload) = Base58Check::decode(s)?;

        let network = match version {
            MAINNET_VERSION => Network::BitcoinMainnet,
            TESTNET_VERSION => Network::BitcoinTestnet,
            _ => {
                return Err(AddressError::InvalidFormat(format!(
                    "Unknown version byte: 0x{:02x}",
                    version
                )))
            }
        };

        if payload.len() != 20 {
            return Err(AddressError::InvalidFormat(format!(
                "Invalid hash length: expected 20, got {}",
                payload.len()
            )));
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&payload);

        Ok(Self {
            hash,
            network,
            encoded: s.to_string(),
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
    fn test_p2pkh_mainnet_compressed() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2PKHAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
        assert!(address.to_string().starts_with('1'));
    }

    #[test]
    fn test_p2pkh_testnet() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2PKHAddress::from_public_key(&public_key, Network::BitcoinTestnet).unwrap();
        let addr_str = address.to_string();
        assert!(addr_str.starts_with('m') || addr_str.starts_with('n'));
    }

    #[test]
    fn test_p2pkh_roundtrip() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2PKHAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
        let parsed: P2PKHAddress = address.to_string().parse().unwrap();
        assert_eq!(address.hash(), parsed.hash());
        assert_eq!(address.network(), parsed.network());
    }
}
