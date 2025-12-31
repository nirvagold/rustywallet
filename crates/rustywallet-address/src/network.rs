//! Network types for address generation.

/// Supported blockchain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin Mainnet
    BitcoinMainnet,
    /// Bitcoin Testnet
    BitcoinTestnet,
    /// Ethereum (network-agnostic)
    Ethereum,
}

impl Network {
    /// Returns true if this is a Bitcoin network.
    #[inline]
    pub fn is_bitcoin(&self) -> bool {
        matches!(self, Network::BitcoinMainnet | Network::BitcoinTestnet)
    }

    /// Returns true if this is Ethereum.
    #[inline]
    pub fn is_ethereum(&self) -> bool {
        matches!(self, Network::Ethereum)
    }

    /// Returns true if this is a testnet.
    #[inline]
    pub fn is_testnet(&self) -> bool {
        matches!(self, Network::BitcoinTestnet)
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::BitcoinMainnet => write!(f, "Bitcoin Mainnet"),
            Network::BitcoinTestnet => write!(f, "Bitcoin Testnet"),
            Network::Ethereum => write!(f, "Ethereum"),
        }
    }
}
