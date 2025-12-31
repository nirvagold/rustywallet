//! # rustywallet-hd
//!
//! BIP32/BIP44 Hierarchical Deterministic wallet for cryptocurrency key derivation.
//!
//! This crate provides functionality to:
//! - Create master keys from seeds
//! - Derive child keys using BIP32 derivation
//! - Support BIP44 standard paths
//! - Export/import extended keys (xprv/xpub)
//!
//! ## Example
//!
//! ```
//! use rustywallet_hd::prelude::*;
//!
//! // Create master key from seed (64 bytes, typically from mnemonic)
//! let seed = [0u8; 64];
//! let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
//!
//! // Derive BIP44 Bitcoin path: m/44'/0'/0'/0/0
//! let path = DerivationPath::bip44_bitcoin(0, 0, 0);
//! let child = master.derive_path(&path).unwrap();
//!
//! // Get keys
//! let private_key = child.private_key().unwrap();
//! let public_key = child.public_key();
//!
//! // Export as xprv/xpub
//! let xprv = child.to_xprv();
//! let xpub = child.extended_public_key().to_xpub();
//! ```
//!
//! ## BIP44 Paths
//!
//! ```text
//! m / purpose' / coin_type' / account' / change / address_index
//!
//! Bitcoin:  m/44'/0'/0'/0/0
//! Ethereum: m/44'/60'/0'/0/0
//! ```
//!
//! ## Security
//!
//! - Private keys and chain codes are zeroized on drop
//! - Debug output masks sensitive data
//! - Hardened derivation prevents public key derivation

pub mod error;
pub mod extended_key;
pub mod network;
pub mod path;
pub mod prelude;

pub use error::HdError;
pub use extended_key::{ExtendedPrivateKey, ExtendedPublicKey};
pub use network::Network;
pub use path::{ChildNumber, DerivationPath};
