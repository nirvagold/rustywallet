//! P2TR (Pay-to-Taproot) Bitcoin Taproot address.

use crate::encoding::Bech32Encoder;
use crate::error::AddressError;
use crate::network::Network;
use rustywallet_keys::public_key::PublicKey;

/// HRP for mainnet Taproot addresses.
const MAINNET_HRP: &str = "bc";
/// HRP for testnet Taproot addresses.
const TESTNET_HRP: &str = "tb";

/// P2TR (Taproot) Bitcoin address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2TRAddress {
    x_only_pubkey: [u8; 32],
    network: Network,
    encoded: String,
}

impl P2TRAddress {
    /// Generate P2TR address from public key.
    ///
    /// Converts the public key to x-only format (32 bytes) for Taproot.
    ///
    /// # Example
    /// ```
    /// use rustywallet_keys::prelude::*;
    /// use rustywallet_address::{P2TRAddress, Network};
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let address = P2TRAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
    /// assert!(address.to_string().starts_with("bc1p"));
    /// ```
    pub fn from_public_key(public_key: &PublicKey, network: Network) -> Result<Self, AddressError> {
        if !network.is_bitcoin() {
            return Err(AddressError::NetworkMismatch {
                expected: "Bitcoin".to_string(),
                actual: network.to_string(),
            });
        }

        // Get x-only public key (32 bytes) from compressed format
        // Compressed key is 33 bytes: prefix (02/03) + x-coordinate (32 bytes)
        let pubkey_bytes = public_key.to_compressed();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&pubkey_bytes[1..33]);

        let hrp = Self::hrp(network);
        let encoded = Bech32Encoder::encode_bech32m(hrp, &x_only)?;

        Ok(Self {
            x_only_pubkey: x_only,
            network,
            encoded,
        })
    }

    /// Parse P2TR address from string.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        s.parse()
    }

    /// Validate P2TR address string.
    pub fn validate(s: &str) -> Result<(), AddressError> {
        s.parse::<Self>().map(|_| ())
    }

    /// Get the x-only public key.
    #[inline]
    pub fn x_only_pubkey(&self) -> &[u8; 32] {
        &self.x_only_pubkey
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

impl std::fmt::Display for P2TRAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

impl std::str::FromStr for P2TRAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, version, program) = Bech32Encoder::decode(s)?;

        if version != 1 {
            return Err(AddressError::InvalidFormat(format!(
                "Invalid witness version for P2TR: expected 1, got {}",
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

        if program.len() != 32 {
            return Err(AddressError::InvalidFormat(format!(
                "Invalid program length for P2TR: expected 32, got {}",
                program.len()
            )));
        }

        let mut x_only_pubkey = [0u8; 32];
        x_only_pubkey.copy_from_slice(&program);

        Ok(Self {
            x_only_pubkey,
            network,
            encoded: s.to_lowercase(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_p2tr_mainnet() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2TRAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
        assert!(address.to_string().starts_with("bc1p"));
    }

    #[test]
    fn test_p2tr_testnet() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2TRAddress::from_public_key(&public_key, Network::BitcoinTestnet).unwrap();
        assert!(address.to_string().starts_with("tb1p"));
    }

    #[test]
    fn test_p2tr_roundtrip() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let address = P2TRAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
        let parsed: P2TRAddress = address.to_string().parse().unwrap();
        assert_eq!(address.x_only_pubkey(), parsed.x_only_pubkey());
        assert_eq!(address.network(), parsed.network());
    }
}
