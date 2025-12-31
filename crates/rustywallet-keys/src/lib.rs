//! # rustywallet-keys
//!
//! Type-safe private and public key management for cryptocurrency wallets.
//!
//! This crate provides ergonomic APIs for working with secp256k1 keys,
//! with a focus on security and developer experience.
//!
//! ## Features
//!
//! - **Key Generation**: Generate cryptographically secure random private keys
//! - **Multiple Formats**: Import/export keys in hex, WIF, and raw bytes
//! - **Public Key Derivation**: Derive public keys in compressed or uncompressed format
//! - **Secure by Default**: Private keys are zeroized on drop, debug output is masked
//! - **Type Safety**: Strong typing prevents common mistakes at compile time
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_keys::prelude::*;
//!
//! // Generate a random private key
//! let private_key = PrivateKey::random();
//!
//! // Export to various formats
//! let hex = private_key.to_hex();
//! let wif = private_key.to_wif(Network::Mainnet);
//! let bytes = private_key.to_bytes();
//!
//! // Derive public key
//! let public_key = private_key.public_key();
//! let compressed = public_key.to_hex(PublicKeyFormat::Compressed);
//! let uncompressed = public_key.to_hex(PublicKeyFormat::Uncompressed);
//! ```
//!
//! ## Import Existing Keys
//!
//! ```rust
//! use rustywallet_keys::prelude::*;
//!
//! // From hex string
//! let hex = "0000000000000000000000000000000000000000000000000000000000000001";
//! let key = PrivateKey::from_hex(hex).unwrap();
//!
//! // From WIF (Wallet Import Format)
//! let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
//! let key = PrivateKey::from_wif(wif).unwrap();
//!
//! // From raw bytes
//! let bytes = [1u8; 32];
//! let key = PrivateKey::from_bytes(bytes).unwrap();
//! ```
//!
//! ## Error Handling
//!
//! All fallible operations return `Result` types with descriptive errors:
//!
//! ```rust
//! use rustywallet_keys::prelude::*;
//!
//! // Invalid hex string
//! let result = PrivateKey::from_hex("invalid");
//! assert!(result.is_err());
//!
//! // Zero key (invalid)
//! let zero_bytes = [0u8; 32];
//! assert!(!PrivateKey::is_valid(&zero_bytes));
//! ```
//!
//! ## Security
//!
//! This crate takes security seriously:
//!
//! - Private keys are automatically zeroized when dropped
//! - Debug output shows `PrivateKey(****)` instead of actual key data
//! - Uses the battle-tested `secp256k1` crate for cryptographic operations
//!
//! ## Modules
//!
//! - [`private_key`] - Private key generation, import, and export
//! - [`public_key`] - Public key derivation and format conversion
//! - [`network`] - Network type (Mainnet/Testnet) for WIF encoding
//! - [`error`] - Error types for all operations
//! - [`prelude`] - Convenient re-exports for common types

pub mod error;
pub mod network;
pub mod prelude;
pub mod private_key;
pub mod public_key;

mod encoding;
