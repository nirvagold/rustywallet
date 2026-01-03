//! # rustywallet-signer
//!
//! ECDSA and Schnorr message signing and verification for Bitcoin and Ethereum.
//!
//! ## Features
//!
//! - Sign arbitrary messages with ECDSA secp256k1
//! - Sign messages with BIP340 Schnorr signatures
//! - Verify signatures against public keys
//! - Bitcoin message signing (BIP-137 compatible)
//! - Ethereum personal_sign (EIP-191)
//! - Recoverable signatures for public key recovery
//!
//! ## Quick Start (ECDSA)
//!
//! ```rust
//! use rustywallet_keys::private_key::PrivateKey;
//! use rustywallet_signer::prelude::*;
//! use sha2::{Sha256, Digest};
//!
//! // Generate a key
//! let key = PrivateKey::random();
//! let pubkey = key.public_key();
//!
//! // Sign a message hash
//! let hash: [u8; 32] = Sha256::digest(b"hello world").into();
//! let signature = sign(&key, &hash).unwrap();
//!
//! // Verify the signature
//! assert!(verify(&pubkey, &hash, &signature));
//! ```
//!
//! ## Schnorr Signing (BIP340)
//!
//! ```rust
//! use rustywallet_keys::private_key::PrivateKey;
//! use rustywallet_signer::schnorr::{SchnorrSigner, SchnorrVerifier};
//! use sha2::{Sha256, Digest};
//!
//! // Generate a key
//! let key = PrivateKey::random();
//!
//! // Sign a message hash with Schnorr
//! let hash: [u8; 32] = Sha256::digest(b"hello world").into();
//! let signature = key.sign_schnorr(&hash).unwrap();
//!
//! // Get x-only public key and verify
//! let xonly = key.x_only_public_key();
//! assert!(xonly.verify_schnorr(&signature, &hash));
//! ```
//!
//! ## Bitcoin Message Signing
//!
//! ```rust
//! use rustywallet_keys::private_key::PrivateKey;
//! use rustywallet_signer::bitcoin::sign_bitcoin_message;
//!
//! let key = PrivateKey::random();
//! let signature = sign_bitcoin_message(&key, "Hello Bitcoin!").unwrap();
//! println!("Base64 signature: {}", signature);
//! ```
//!
//! ## Ethereum Personal Sign
//!
//! ```rust
//! use rustywallet_keys::private_key::PrivateKey;
//! use rustywallet_signer::ethereum::{sign_ethereum_message, public_key_to_address, format_address};
//!
//! let key = PrivateKey::random();
//! let address = public_key_to_address(&key.public_key());
//! let signature = sign_ethereum_message(&key, b"Hello Ethereum!").unwrap();
//!
//! println!("Address: {}", format_address(&address));
//! println!("Signature: {}", signature.to_ethereum_hex());
//! ```

pub mod bitcoin;
pub mod error;
pub mod ethereum;
pub mod prelude;
pub mod recovery;
pub mod schnorr;
pub mod signature;
pub mod signer;
pub mod verifier;

// Re-export main types at crate root
pub use error::SignerError;
pub use recovery::recover_public_key;
pub use signature::{RecoverableSignature, Signature};
pub use signer::{sign, sign_recoverable};
pub use verifier::{verify, verify_strict};

// Re-export Schnorr types from rustywallet-taproot for convenience
pub use rustywallet_taproot::{SchnorrSignature, XOnlyPublicKey};

// Re-export Schnorr signing functions
pub use schnorr::{sign_schnorr, verify_schnorr, SchnorrSigner, SchnorrVerifier};
