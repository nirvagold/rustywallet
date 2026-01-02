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

pub mod error;
pub mod types;

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

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        import_any, import_wif, import_hex, import_mini_key,
        import_mnemonic, import_bip38, detect_format,
        ImportError, ImportFormat, ImportResult, ImportMetadata,
        MnemonicImport,
    };
}
