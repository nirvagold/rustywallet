//! Unified address type for all supported blockchains.

use crate::bitcoin::BitcoinAddress;
use crate::error::AddressError;
use crate::ethereum::EthereumAddress;
use crate::network::Network;

/// Unified address type supporting Bitcoin and Ethereum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// Bitcoin address (P2PKH, P2WPKH, or P2TR)
    Bitcoin(BitcoinAddress),
    /// Ethereum address
    Ethereum(EthereumAddress),
}

impl Address {
    /// Parse address from string with auto-detection.
    ///
    /// Detects address type based on prefix:
    /// - `1`, `m`, `n` → Bitcoin P2PKH
    /// - `bc1q`, `tb1q` → Bitcoin P2WPKH
    /// - `bc1p`, `tb1p` → Bitcoin P2TR
    /// - `0x` → Ethereum
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        s.parse()
    }

    /// Validate address string.
    pub fn validate(s: &str) -> Result<(), AddressError> {
        s.parse::<Self>().map(|_| ())
    }

    /// Get the network for this address.
    pub fn network(&self) -> Network {
        match self {
            Address::Bitcoin(addr) => addr.network(),
            Address::Ethereum(_) => Network::Ethereum,
        }
    }

    /// Check if this is a Bitcoin address.
    #[inline]
    pub fn is_bitcoin(&self) -> bool {
        matches!(self, Address::Bitcoin(_))
    }

    /// Check if this is an Ethereum address.
    #[inline]
    pub fn is_ethereum(&self) -> bool {
        matches!(self, Address::Ethereum(_))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Bitcoin(addr) => write!(f, "{}", addr),
            Address::Ethereum(addr) => write!(f, "{}", addr),
        }
    }
}

impl std::str::FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try Ethereum first (0x prefix)
        if s.starts_with("0x") || s.starts_with("0X") {
            return s.parse::<EthereumAddress>().map(Address::Ethereum);
        }

        // Try Bitcoin
        s.parse::<BitcoinAddress>().map(Address::Bitcoin)
    }
}

impl From<BitcoinAddress> for Address {
    fn from(addr: BitcoinAddress) -> Self {
        Address::Bitcoin(addr)
    }
}

impl From<EthereumAddress> for Address {
    fn from(addr: EthereumAddress) -> Self {
        Address::Ethereum(addr)
    }
}

/// Common trait for all address types.
pub trait AddressFormat: Sized {
    /// Parse from string.
    fn parse(s: &str) -> Result<Self, AddressError>;

    /// Validate string format.
    fn validate(s: &str) -> Result<(), AddressError>;

    /// Convert to canonical string representation.
    fn to_string(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::{P2PKHAddress, P2TRAddress, P2WPKHAddress};
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_address_detection_p2pkh() {
        let pk = PrivateKey::random();
        let pubkey = pk.public_key();
        let addr = P2PKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
        let parsed: Address = addr.to_string().parse().unwrap();
        assert!(parsed.is_bitcoin());
    }

    #[test]
    fn test_address_detection_p2wpkh() {
        let pk = PrivateKey::random();
        let pubkey = pk.public_key();
        let addr = P2WPKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
        let parsed: Address = addr.to_string().parse().unwrap();
        assert!(parsed.is_bitcoin());
    }

    #[test]
    fn test_address_detection_p2tr() {
        let pk = PrivateKey::random();
        let pubkey = pk.public_key();
        let addr = P2TRAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
        let parsed: Address = addr.to_string().parse().unwrap();
        assert!(parsed.is_bitcoin());
    }

    #[test]
    fn test_address_detection_ethereum() {
        let pk = PrivateKey::random();
        let pubkey = pk.public_key();
        let addr = EthereumAddress::from_public_key(&pubkey).unwrap();
        let parsed: Address = addr.to_string().parse().unwrap();
        assert!(parsed.is_ethereum());
    }
}
