//! Types for import results.

use rustywallet_keys::prelude::PrivateKey;
use rustywallet_hd::Network;

/// Detected import format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    /// Wallet Import Format (WIF)
    Wif,
    /// Raw hex (64 characters)
    Hex,
    /// BIP39 mnemonic phrase
    Mnemonic,
    /// Electrum seed format
    ElectrumSeed,
    /// BIP38 encrypted key
    Bip38,
    /// Mini private key (Casascius)
    MiniKey,
    /// Output descriptor (BIP380-386)
    Descriptor,
}

impl std::fmt::Display for ImportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportFormat::Wif => write!(f, "WIF"),
            ImportFormat::Hex => write!(f, "Hex"),
            ImportFormat::Mnemonic => write!(f, "Mnemonic"),
            ImportFormat::ElectrumSeed => write!(f, "Electrum Seed"),
            ImportFormat::Bip38 => write!(f, "BIP38"),
            ImportFormat::MiniKey => write!(f, "Mini Key"),
            ImportFormat::Descriptor => write!(f, "Descriptor"),
        }
    }
}

/// Result of a successful import.
#[derive(Debug)]
pub struct ImportResult {
    /// The imported private key
    pub private_key: PrivateKey,
    /// Detected format
    pub format: ImportFormat,
    /// Detected network (if applicable)
    pub network: Option<Network>,
    /// Whether the key is compressed (for WIF)
    pub compressed: bool,
    /// Additional metadata
    pub metadata: ImportMetadata,
}

/// Additional metadata from import.
#[derive(Debug, Default)]
pub struct ImportMetadata {
    /// Derivation path (for mnemonic imports)
    pub derivation_path: Option<String>,
    /// Number of words (for mnemonic)
    pub word_count: Option<usize>,
    /// Whether passphrase was used
    pub has_passphrase: bool,
}

impl ImportResult {
    /// Create a new import result.
    pub fn new(private_key: PrivateKey, format: ImportFormat) -> Self {
        Self {
            private_key,
            format,
            network: None,
            compressed: true,
            metadata: ImportMetadata::default(),
        }
    }

    /// Set the network.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// Set compressed flag.
    pub fn with_compressed(mut self, compressed: bool) -> Self {
        self.compressed = compressed;
        self
    }

    /// Set metadata.
    pub fn with_metadata(mut self, metadata: ImportMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}
