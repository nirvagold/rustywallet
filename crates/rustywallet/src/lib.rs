//! # rustywallet
//!
//! A comprehensive Rust library for cryptocurrency wallet utilities.
//!
//! This crate provides a unified API for working with cryptocurrency wallets,
//! including key management, address generation, mnemonic phrases, HD wallets,
//! and message signing.
//!
//! ## Features
//!
//! - **keys** - Private and public key management (secp256k1)
//! - **address** - Bitcoin and Ethereum address generation
//! - **mnemonic** - BIP39 mnemonic phrase support
//! - **hd** - BIP32/BIP44 hierarchical deterministic wallets
//! - **signer** - ECDSA message signing and verification
//!
//! All features are enabled by default. You can disable default features and
//! enable only what you need:
//!
//! ```toml
//! [dependencies]
//! rustywallet = { version = "0.1", default-features = false, features = ["keys", "address"] }
//! ```
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet::prelude::*;
//!
//! // Generate a random private key
//! let key = PrivateKey::random();
//! let pubkey = key.public_key();
//!
//! println!("Private key: {}", key.to_hex());
//! println!("Public key: {}", pubkey.to_hex(PublicKeyFormat::Compressed));
//! ```
//!
//! ## Full Wallet Workflow
//!
//! ```rust,ignore
//! use rustywallet::prelude::*;
//!
//! // 1. Generate mnemonic
//! let mnemonic = Mnemonic::generate(WordCount::Words12);
//! println!("Mnemonic: {}", mnemonic.phrase());
//!
//! // 2. Derive seed
//! let seed = mnemonic.to_seed("");
//!
//! // 3. Create HD wallet
//! let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), HdNetwork::Mainnet).unwrap();
//!
//! // 4. Derive child key (BIP44: m/44'/0'/0'/0/0)
//! let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
//! let child = master.derive_path(&path).unwrap();
//! let privkey = child.private_key().unwrap();
//!
//! println!("Private key: {}", privkey.to_hex());
//! println!("Public key: {}", privkey.public_key().to_hex(PublicKeyFormat::Compressed));
//! ```
//!
//! ## Module Overview
//!
//! | Module | Feature | Description |
//! |--------|---------|-------------|
//! | [`keys`] | `keys` | Private/public key management |
//! | [`address`] | `address` | Address generation (Bitcoin, Ethereum) |
//! | [`mnemonic`] | `mnemonic` | BIP39 mnemonic phrases |
//! | [`hd`] | `hd` | BIP32/BIP44 HD wallets |
//! | [`signer`] | `signer` | Message signing and verification |

// Re-export sub-crates
#[cfg(feature = "keys")]
pub use rustywallet_keys as keys;

#[cfg(feature = "address")]
pub use rustywallet_address as address;

#[cfg(feature = "mnemonic")]
pub use rustywallet_mnemonic as mnemonic;

#[cfg(feature = "hd")]
pub use rustywallet_hd as hd;

#[cfg(feature = "signer")]
pub use rustywallet_signer as signer;

pub mod prelude;

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_key_generation() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();
        assert_eq!(pubkey.to_compressed().len(), 33);
    }

    #[test]
    #[cfg(feature = "mnemonic")]
    fn test_mnemonic_generation() {
        let mnemonic = Mnemonic::generate(WordCount::Words12);
        assert_eq!(mnemonic.word_count(), WordCount::Words12);
    }

    #[test]
    #[cfg(all(feature = "mnemonic", feature = "hd"))]
    fn test_full_workflow() {
        // Generate mnemonic
        let mnemonic = Mnemonic::generate(WordCount::Words12);
        let seed = mnemonic.to_seed("");

        // Derive master key
        let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), HdNetwork::Mainnet).unwrap();

        // Derive child
        let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
        let child = master.derive_path(&path).unwrap();

        // Get private key
        let privkey = child.private_key().unwrap();
        assert_eq!(privkey.to_bytes().len(), 32);
    }
}
