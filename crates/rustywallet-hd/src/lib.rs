//! # rustywallet-hd
//!
//! BIP32/BIP44/BIP85/SLIP39 Hierarchical Deterministic wallet for cryptocurrency key derivation.
//!
//! This crate provides functionality to:
//! - Create master keys from seeds
//! - Derive child keys using BIP32 derivation
//! - Support BIP44 standard paths
//! - Export/import extended keys (xprv/xpub)
//! - BIP85 deterministic entropy derivation
//! - SLIP39 Shamir secret sharing for mnemonic backup
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
//! ## BIP85 - Deterministic Entropy
//!
//! ```
//! use rustywallet_hd::{ExtendedPrivateKey, Network, Bip85, derive_bip85_mnemonic};
//!
//! let seed = [0u8; 64];
//! let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
//!
//! // Derive child mnemonic entropy (12 words, index 0)
//! let entropy = derive_bip85_mnemonic(&master, 12, 0).unwrap();
//! assert_eq!(entropy.len(), 16); // 128 bits for 12 words
//!
//! // Or use Bip85 struct for more options
//! let bip85 = Bip85::new(master.clone());
//! let child_master = bip85.derive_child_master(0, Network::Mainnet).unwrap();
//! ```
//!
//! ## SLIP39 - Shamir Secret Sharing
//!
//! ```
//! use rustywallet_hd::slip39::Slip39;
//!
//! // Create a 2-of-3 sharing scheme
//! let slip39 = Slip39::new(2, 3).unwrap();
//!
//! // Split a 32-byte secret
//! let secret = [0x42u8; 32];
//! let shares = slip39.split(&secret).unwrap();
//!
//! // Recover using any 2 shares
//! let recovered = Slip39::combine(&shares[0..2]).unwrap();
//! assert_eq!(secret.to_vec(), recovered);
//! ```
//!
//! ## Derivation Path Builder
//!
//! ```
//! use rustywallet_hd::path::DerivationPathBuilder;
//!
//! // Build custom paths fluently
//! let path = DerivationPathBuilder::new()
//!     .hardened(44)
//!     .hardened(0)
//!     .hardened(0)
//!     .normal(0)
//!     .normal(0)
//!     .build()
//!     .unwrap();
//!
//! // Use BIP presets
//! let bip84 = DerivationPathBuilder::bip84(0, 0)
//!     .normal(0)
//!     .normal(0)
//!     .build()
//!     .unwrap();
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
pub mod bip85;
pub mod slip39;

pub use error::HdError;
pub use extended_key::{ExtendedPrivateKey, ExtendedPublicKey};
pub use network::Network;
pub use path::{ChildNumber, DerivationPath, DerivationPathBuilder, MAX_CHILD_INDEX, HARDENED_BIT};
pub use bip85::{Bip85, derive_bip85_mnemonic, derive_bip85_master, app as bip85_app, language as bip85_language};
pub use slip39::{Slip39, Slip39Share, Slip39MultiGroup, GroupConfig};
