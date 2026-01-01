//! Network type definitions
//!
//! This module provides the [`Network`] enum for distinguishing between
//! Bitcoin mainnet and testnet.

/// Blockchain network type.
///
/// Used to determine version bytes for WIF encoding and other network-specific
/// operations.
///
/// # Example
///
/// ```
/// use rustywallet_keys::network::Network;
///
/// let mainnet = Network::Mainnet;
/// assert_eq!(mainnet.wif_version_byte(), 0x80);
///
/// let testnet = Network::Testnet;
/// assert_eq!(testnet.wif_version_byte(), 0xEF);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin Mainnet (WIF prefix: 0x80)
    Mainnet,
    /// Bitcoin Testnet (WIF prefix: 0xEF)
    Testnet,
}

impl Network {
    /// Returns the WIF version byte for this network.
    ///
    /// - Mainnet: `0x80`
    /// - Testnet: `0xEF`
    #[inline]
    pub fn wif_version_byte(&self) -> u8 {
        match self {
            Network::Mainnet => 0x80,
            Network::Testnet => 0xEF,
        }
    }
}

impl Default for Network {
    /// Returns [`Network::Mainnet`] as the default network.
    fn default() -> Self {
        Network::Mainnet
    }
}
