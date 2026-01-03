//! Network types for Silent Payments.

use crate::error::{Result, SilentPaymentError};

/// Network for Silent Payments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
}

impl Network {
    /// Get the HRP (Human Readable Part) for bech32m encoding.
    pub fn hrp(&self) -> &'static str {
        match self {
            Network::Mainnet => "sp",
            Network::Testnet => "tsp",
        }
    }

    /// Parse network from HRP.
    pub fn from_hrp(hrp: &str) -> Result<Self> {
        match hrp {
            "sp" => Ok(Network::Mainnet),
            "tsp" => Ok(Network::Testnet),
            _ => Err(SilentPaymentError::InvalidNetwork(format!(
                "Unknown HRP: {}",
                hrp
            ))),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
        }
    }
}
