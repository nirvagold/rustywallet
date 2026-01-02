//! # rustywallet-export
//!
//! Export private keys to various formats.
//!
//! ## Supported Formats
//!
//! - **WIF** - Wallet Import Format (compressed/uncompressed)
//! - **Hex** - Raw hex string (with optional 0x prefix)
//! - **JSON** - Structured JSON with address, WIF, hex, public key
//! - **CSV** - Comma-separated values for batch export
//! - **Paper Wallet** - Address + WIF pair for cold storage
//! - **BIP38** - Password-encrypted private key
//! - **BIP21** - Bitcoin URI format for QR codes
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_export::prelude::*;
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! let key = PrivateKey::random();
//!
//! // Export to WIF
//! let wif = export_wif(&key, Network::Mainnet, true);
//! println!("WIF: {}", wif);
//!
//! // Export to hex
//! let hex = export_hex(&key, HexOptions::new());
//! println!("Hex: {}", hex);
//!
//! // Export to JSON
//! let json = export_json(&key, Network::Mainnet).unwrap();
//! println!("{}", json);
//!
//! // Generate paper wallet
//! let paper = to_paper_wallet(&key, Network::Mainnet, AddressType::P2PKH).unwrap();
//! println!("Address: {}", paper.address);
//! println!("WIF: {}", paper.wif);
//! ```

pub mod error;
pub mod types;

mod wif;
mod hex_export;
mod json;
mod csv;
mod paper_wallet;
mod bip38;
mod bip21;

pub use error::{ExportError, Result};
pub use types::{
    Network, HexOptions, KeyExport, CsvColumn, CsvOptions,
    PaperWallet, AddressType, Bip21Options,
};

pub use wif::export_wif;
pub use hex_export::export_hex;
pub use json::{export_json, export_json_batch};
pub use csv::export_csv;
pub use paper_wallet::to_paper_wallet;
pub use bip38::export_bip38;
pub use bip21::to_bip21_uri;

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        export_wif, export_hex, export_json, export_json_batch,
        export_csv, to_paper_wallet, export_bip38, to_bip21_uri,
        ExportError, Network, HexOptions, KeyExport, CsvColumn, CsvOptions,
        PaperWallet, AddressType, Bip21Options,
    };
}
