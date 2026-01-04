//! # rustywallet-import
//!
//! Import private keys from various wallet formats.
//!
//! ## Supported Formats
//!
//! - **WIF** - Wallet Import Format (compressed/uncompressed)
//! - **Hex** - Raw 64-character hex string
//! - **Mini Key** - Casascius mini private key (22 or 30 chars)
//! - **Mnemonic** - BIP39 mnemonic phrase with BIP44/49/84 derivation
//! - **BIP38** - Password-encrypted private key
//! - **Descriptor** - Output descriptors (BIP380-386)
//! - **Wallet Files** - Electrum, Sparrow, Bitcoin Core wallet formats
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_import::{import_any, import_wif, import_hex};
//!
//! // Auto-detect format
//! let result = import_any("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
//! assert!(result.is_ok());
//!
//! // Import WIF directly
//! let (key, network, compressed) = import_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ").unwrap();
//!
//! // Import hex
//! let key = import_hex("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d").unwrap();
//! ```
//!
//! ## Descriptor Import
//!
//! ```rust
//! use rustywallet_import::descriptor::{import_descriptor, is_descriptor};
//!
//! // Check if string is a descriptor
//! assert!(is_descriptor("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"));
//!
//! // Import descriptor
//! let result = import_descriptor("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)").unwrap();
//! println!("Type: {}, Ranged: {}", result.descriptor_type, result.is_ranged);
//! ```
//!
//! ## Wallet Format Import
//!
//! ```rust,no_run
//! use rustywallet_import::wallet_format::{import_wallet_auto, import_sparrow_wallet};
//!
//! // Auto-detect and import wallet file
//! let json = r#"{"label": "My Wallet", "descriptor": "wpkh(...)"}"#;
//! let result = import_wallet_auto(json);
//! ```

pub mod error;
pub mod types;
pub mod descriptor;
pub mod wallet_format;

mod wif;
mod hex_import;
mod mini_key;
mod mnemonic_import;
mod bip38;
mod detect;

pub use error::{ImportError, Result};
pub use types::{ImportFormat, ImportResult, ImportMetadata};

pub use wif::import_wif;
pub use hex_import::import_hex;
pub use mini_key::import_mini_key;
pub use mnemonic_import::{import_mnemonic, MnemonicImport, paths};
pub use bip38::import_bip38;
pub use detect::{detect_format, import_any};
pub use descriptor::{import_descriptor, import_taproot_descriptor, is_descriptor, DescriptorImport, ExtractedKey, KeyType};
pub use wallet_format::{
    import_wallet_auto, import_electrum_wallet, import_sparrow_wallet, import_bitcoin_core_wallet,
    WalletFormat, WalletImport, WalletMetadata,
};

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        import_any, import_wif, import_hex, import_mini_key,
        import_mnemonic, import_bip38, detect_format,
        ImportError, ImportFormat, ImportResult, ImportMetadata,
        MnemonicImport,
        // Descriptor imports
        import_descriptor, import_taproot_descriptor, is_descriptor,
        DescriptorImport, ExtractedKey, KeyType,
        // Wallet format imports
        import_wallet_auto, import_electrum_wallet, import_sparrow_wallet, import_bitcoin_core_wallet,
        WalletFormat, WalletImport, WalletMetadata,
    };
}
