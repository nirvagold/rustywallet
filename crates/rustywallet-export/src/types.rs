//! Types for export operations.

use serde::{Deserialize, Serialize};

/// Network type for export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet"),
        }
    }
}

/// Options for hex export.
#[derive(Debug, Clone, Default)]
pub struct HexOptions {
    /// Include 0x prefix
    pub prefix: bool,
    /// Use uppercase hex
    pub uppercase: bool,
}

impl HexOptions {
    /// Create default options (no prefix, lowercase).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set prefix option.
    pub fn with_prefix(mut self, prefix: bool) -> Self {
        self.prefix = prefix;
        self
    }

    /// Set uppercase option.
    pub fn with_uppercase(mut self, uppercase: bool) -> Self {
        self.uppercase = uppercase;
        self
    }
}

/// Exported key data in JSON format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExport {
    /// Bitcoin address (P2PKH)
    pub address: String,
    /// WIF format
    pub wif: String,
    /// Hex format (no prefix)
    pub hex: String,
    /// Compressed public key hex
    pub public_key: String,
    /// Network
    pub network: String,
    /// Whether key is compressed
    pub compressed: bool,
}

/// CSV column options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvColumn {
    /// Bitcoin address
    Address,
    /// WIF format
    Wif,
    /// Hex format
    Hex,
    /// Public key
    PublicKey,
    /// Network
    Network,
}

impl CsvColumn {
    /// Get column header name.
    pub fn header(&self) -> &'static str {
        match self {
            CsvColumn::Address => "address",
            CsvColumn::Wif => "wif",
            CsvColumn::Hex => "hex",
            CsvColumn::PublicKey => "public_key",
            CsvColumn::Network => "network",
        }
    }
}

/// Options for CSV export.
#[derive(Debug, Clone)]
pub struct CsvOptions {
    /// Columns to include
    pub columns: Vec<CsvColumn>,
    /// Include header row
    pub header: bool,
    /// Network for export
    pub network: Network,
}

impl Default for CsvOptions {
    fn default() -> Self {
        Self {
            columns: vec![
                CsvColumn::Address,
                CsvColumn::Wif,
                CsvColumn::Hex,
            ],
            header: true,
            network: Network::Mainnet,
        }
    }
}

impl CsvOptions {
    /// Create default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set columns.
    pub fn with_columns(mut self, columns: Vec<CsvColumn>) -> Self {
        self.columns = columns;
        self
    }

    /// Set header option.
    pub fn with_header(mut self, header: bool) -> Self {
        self.header = header;
        self
    }

    /// Set network.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }
}

/// Paper wallet data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperWallet {
    /// Public address for receiving
    pub address: String,
    /// Private key in WIF format
    pub wif: String,
    /// Network
    pub network: String,
    /// Address type (p2pkh, p2wpkh, etc.)
    pub address_type: String,
}

/// Address type for paper wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Legacy P2PKH (1...)
    P2PKH,
    /// Native SegWit P2WPKH (bc1q...)
    P2WPKH,
    /// Taproot P2TR (bc1p...)
    P2TR,
}

impl std::fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressType::P2PKH => write!(f, "p2pkh"),
            AddressType::P2WPKH => write!(f, "p2wpkh"),
            AddressType::P2TR => write!(f, "p2tr"),
        }
    }
}

/// Options for BIP21 URI generation.
#[derive(Debug, Clone, Default)]
pub struct Bip21Options {
    /// Amount in BTC
    pub amount: Option<f64>,
    /// Label for the address
    pub label: Option<String>,
    /// Message/memo
    pub message: Option<String>,
}

impl Bip21Options {
    /// Create empty options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set amount.
    pub fn with_amount(mut self, amount: f64) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Set label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set message.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}
