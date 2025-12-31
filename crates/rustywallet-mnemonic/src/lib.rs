//! # rustywallet-mnemonic
//!
//! BIP39 mnemonic (seed phrase) generation and management for cryptocurrency wallets.
//!
//! This crate provides functionality to:
//! - Generate random mnemonic phrases (12, 15, 18, 21, or 24 words)
//! - Validate mnemonic phrases (checksum and wordlist)
//! - Derive seeds from mnemonics with optional passphrase
//! - Derive private keys from seeds
//!
//! ## Example
//!
//! ```
//! use rustywallet_mnemonic::prelude::*;
//!
//! // Generate a new 12-word mnemonic
//! let mnemonic = Mnemonic::generate(WordCount::Words12);
//! println!("Generated mnemonic: {}", mnemonic.to_phrase());
//!
//! // Parse an existing mnemonic
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
//!
//! // Derive seed with passphrase
//! let seed = mnemonic.to_seed("my-passphrase");
//! println!("Seed: {}", seed.to_hex());
//!
//! // Derive private key
//! let private_key = mnemonic.to_private_key("my-passphrase").unwrap();
//! ```
//!
//! ## BIP39 Specification
//!
//! | Word Count | Entropy Bits | Checksum Bits |
//! |------------|--------------|---------------|
//! | 12         | 128          | 4             |
//! | 15         | 160          | 5             |
//! | 18         | 192          | 6             |
//! | 21         | 224          | 7             |
//! | 24         | 256          | 8             |
//!
//! ## Security
//!
//! - Entropy and seed bytes are zeroized on drop
//! - Debug output is masked to prevent accidental exposure
//! - Uses cryptographically secure random number generation

pub mod error;
pub mod mnemonic;
pub mod prelude;
pub mod seed;
pub mod wordlist;

pub use error::MnemonicError;
pub use mnemonic::{Mnemonic, WordCount};
pub use seed::Seed;
pub use wordlist::Language;
