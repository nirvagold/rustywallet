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
//! - **Descriptor** - Output descriptors (BIP380-386) with checksum
//! - **PSBT** - Partially Signed Bitcoin Transactions with descriptor context
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
//!
//! ## Descriptor Export
//!
//! ```rust
//! use rustywallet_export::descriptor::{export_descriptor, DescriptorType, DescriptorOptions};
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! let key = PrivateKey::random();
//!
//! // Export as wpkh descriptor
//! let desc = export_descriptor(&key, DescriptorType::Wpkh, DescriptorOptions::new()).unwrap();
//! println!("Descriptor: {}", desc);
//!
//! // Export as Taproot descriptor
//! let desc = export_descriptor(&key, DescriptorType::Tr, DescriptorOptions::new()).unwrap();
//! println!("Taproot: {}", desc);
//! ```
//!
//! ## PSBT Export
//!
//! ```rust,no_run
//! use rustywallet_export::psbt_export::{export_psbt, export_descriptor_with_psbts, PsbtExportOptions};
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! let key = PrivateKey::random();
//! let psbt_bytes = vec![0x70, 0x73, 0x62, 0x74, 0xff]; // PSBT magic + data
//!
//! // Export PSBT with descriptor
//! let result = export_psbt(&psbt_bytes, Some(&key), PsbtExportOptions::new());
//! ```

pub mod error;
pub mod types;
pub mod descriptor;
pub mod psbt_export;

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
pub use descriptor::{
    export_descriptor, export_pubkey_descriptor, export_multisig_descriptor,
    export_wrapped_multisig_descriptor, export_descriptor_with_metadata,
    compute_checksum, add_checksum,
    DescriptorType, DescriptorOptions, DescriptorExport,
};
pub use psbt_export::{
    export_psbt, export_psbt_json, export_psbt_for_file, export_descriptor_with_psbts,
    PsbtExport, PsbtMetadata, PsbtExportOptions, PsbtFileExport, DescriptorPsbtBundle,
};

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        export_wif, export_hex, export_json, export_json_batch,
        export_csv, to_paper_wallet, export_bip38, to_bip21_uri,
        ExportError, Network, HexOptions, KeyExport, CsvColumn, CsvOptions,
        PaperWallet, AddressType, Bip21Options,
        // Descriptor exports
        export_descriptor, export_pubkey_descriptor, export_multisig_descriptor,
        export_wrapped_multisig_descriptor, export_descriptor_with_metadata,
        DescriptorType, DescriptorOptions, DescriptorExport,
        // PSBT exports
        export_psbt, export_psbt_json, export_psbt_for_file, export_descriptor_with_psbts,
        PsbtExport, PsbtMetadata, PsbtExportOptions, PsbtFileExport, DescriptorPsbtBundle,
    };
}
