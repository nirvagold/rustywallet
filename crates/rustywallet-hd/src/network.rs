//! Network types and version bytes for extended keys.

/// Network for extended key serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    /// Bitcoin Mainnet (xprv/xpub)
    #[default]
    Mainnet,
    /// Bitcoin Testnet (tprv/tpub)
    Testnet,
}

impl Network {
    /// Version bytes for extended private key (xprv/tprv).
    pub fn xprv_version(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0x04, 0x88, 0xAD, 0xE4], // xprv
            Network::Testnet => [0x04, 0x35, 0x83, 0x94], // tprv
        }
    }

    /// Version bytes for extended public key (xpub/tpub).
    pub fn xpub_version(&self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0x04, 0x88, 0xB2, 0x1E], // xpub
            Network::Testnet => [0x04, 0x35, 0x87, 0xCF], // tpub
        }
    }

    /// Detect network from version bytes.
    pub fn from_version(version: &[u8; 4]) -> Option<(Self, bool)> {
        match version {
            [0x04, 0x88, 0xAD, 0xE4] => Some((Network::Mainnet, true)),  // xprv
            [0x04, 0x88, 0xB2, 0x1E] => Some((Network::Mainnet, false)), // xpub
            [0x04, 0x35, 0x83, 0x94] => Some((Network::Testnet, true)),  // tprv
            [0x04, 0x35, 0x87, 0xCF] => Some((Network::Testnet, false)), // tpub
            _ => None,
        }
    }
}
