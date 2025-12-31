//! Common imports for rustywallet
//!
//! This module re-exports the most commonly used types from all sub-crates.
//!
//! # Example
//!
//! ```rust
//! use rustywallet::prelude::*;
//!
//! let key = PrivateKey::random();
//! let pubkey = key.public_key();
//! ```

// Keys
#[cfg(feature = "keys")]
pub use crate::keys::network::Network;
#[cfg(feature = "keys")]
pub use crate::keys::private_key::PrivateKey;
#[cfg(feature = "keys")]
pub use crate::keys::public_key::{PublicKey, PublicKeyFormat};

// Address
#[cfg(feature = "address")]
pub use crate::address::bitcoin::{BitcoinAddress, BitcoinAddressType};
#[cfg(feature = "address")]
pub use crate::address::ethereum::EthereumAddress;
#[cfg(feature = "address")]
pub use crate::address::network::Network as AddressNetwork;
#[cfg(feature = "address")]
pub use crate::address::Address;

// Mnemonic
#[cfg(feature = "mnemonic")]
pub use crate::mnemonic::{Language, Mnemonic, Seed, WordCount};

// HD
#[cfg(feature = "hd")]
pub use crate::hd::extended_key::{ExtendedPrivateKey, ExtendedPublicKey};
#[cfg(feature = "hd")]
pub use crate::hd::network::Network as HdNetwork;
#[cfg(feature = "hd")]
pub use crate::hd::path::DerivationPath;

// Signer
#[cfg(feature = "signer")]
pub use crate::signer::signature::{RecoverableSignature, Signature};
#[cfg(feature = "signer")]
pub use crate::signer::{recover_public_key, sign, sign_recoverable, verify};
