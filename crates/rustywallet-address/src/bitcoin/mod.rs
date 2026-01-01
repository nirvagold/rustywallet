//! Bitcoin address types and generation.

mod p2pkh;
mod p2wpkh;
mod p2tr;

pub use p2pkh::*;
pub use p2wpkh::*;
pub use p2tr::*;

use crate::error::AddressError;
use crate::network::Network;

/// Bitcoin address types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BitcoinAddressType {
    /// Pay-to-Public-Key-Hash (Legacy)
    P2PKH,
    /// Pay-to-Witness-Public-Key-Hash (SegWit)
    P2WPKH,
    /// Pay-to-Taproot
    P2TR,
}

impl std::fmt::Display for BitcoinAddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinAddressType::P2PKH => write!(f, "P2PKH"),
            BitcoinAddressType::P2WPKH => write!(f, "P2WPKH"),
            BitcoinAddressType::P2TR => write!(f, "P2TR"),
        }
    }
}

/// Bitcoin address with type and network info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinAddress {
    address_type: BitcoinAddressType,
    network: Network,
    payload: Vec<u8>,
    encoded: String,
}

impl BitcoinAddress {
    /// Get the address type.
    #[inline]
    pub fn address_type(&self) -> BitcoinAddressType {
        self.address_type
    }

    /// Get the network.
    #[inline]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get the payload (hash or x-only pubkey).
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Parse address from string with auto-detection.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        s.parse()
    }

    /// Validate address string.
    pub fn validate(s: &str) -> Result<(), AddressError> {
        s.parse::<Self>().map(|_| ())
    }
}

impl std::fmt::Display for BitcoinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

impl std::str::FromStr for BitcoinAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try P2PKH (Base58Check)
        if s.starts_with('1') || s.starts_with('m') || s.starts_with('n') {
            return s.parse::<P2PKHAddress>().map(|a| a.into());
        }

        // Try SegWit/Taproot (Bech32/Bech32m)
        let lower = s.to_lowercase();
        if lower.starts_with("bc1q") || lower.starts_with("tb1q") {
            return s.parse::<P2WPKHAddress>().map(|a| a.into());
        }
        if lower.starts_with("bc1p") || lower.starts_with("tb1p") {
            return s.parse::<P2TRAddress>().map(|a| a.into());
        }

        Err(AddressError::UnsupportedAddressType(format!(
            "Unknown Bitcoin address format: {}",
            s
        )))
    }
}

impl From<P2PKHAddress> for BitcoinAddress {
    fn from(addr: P2PKHAddress) -> Self {
        Self {
            address_type: BitcoinAddressType::P2PKH,
            network: addr.network(),
            payload: addr.hash().to_vec(),
            encoded: addr.to_string(),
        }
    }
}

impl From<P2WPKHAddress> for BitcoinAddress {
    fn from(addr: P2WPKHAddress) -> Self {
        Self {
            address_type: BitcoinAddressType::P2WPKH,
            network: addr.network(),
            payload: addr.hash().to_vec(),
            encoded: addr.to_string(),
        }
    }
}

impl From<P2TRAddress> for BitcoinAddress {
    fn from(addr: P2TRAddress) -> Self {
        Self {
            address_type: BitcoinAddressType::P2TR,
            network: addr.network(),
            payload: addr.x_only_pubkey().to_vec(),
            encoded: addr.to_string(),
        }
    }
}
