//! # rustywallet-musig
//!
//! MuSig2 Schnorr multisig implementation (BIP327).
//!
//! This crate provides a complete implementation of the MuSig2 protocol
//! for n-of-n Schnorr multisignatures.
//!
//! ## Features
//!
//! - **Key Aggregation**: Combine multiple public keys into one aggregate key
//! - **Nonce Generation**: Secure nonce generation with reuse prevention
//! - **Partial Signatures**: Create and aggregate partial signatures
//! - **Adaptor Signatures**: Support for atomic swaps and other protocols
//! - **Session Management**: High-level API for signing sessions
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_musig::prelude::*;
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! // Generate keys for 2 signers
//! let sk1 = PrivateKey::random();
//! let sk2 = PrivateKey::random();
//! let pk1 = sk1.public_key().to_compressed();
//! let pk2 = sk2.public_key().to_compressed();
//!
//! // Aggregate keys
//! let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
//! let agg_pubkey = key_agg.xonly_pubkey();
//!
//! // Message to sign
//! let msg = [0u8; 32];
//!
//! // Generate nonces
//! let mut nonce1 = SecretNonce::generate(
//!     &sk1.to_bytes(), &pk1, agg_pubkey, Some(&msg), None
//! ).unwrap();
//! let mut nonce2 = SecretNonce::generate(
//!     &sk2.to_bytes(), &pk2, agg_pubkey, Some(&msg), None
//! ).unwrap();
//!
//! let pub_nonce1 = nonce1.public_nonce().unwrap();
//! let pub_nonce2 = nonce2.public_nonce().unwrap();
//! let public_nonces = vec![pub_nonce1.clone(), pub_nonce2.clone()];
//!
//! // Aggregate nonces
//! let agg_nonce = AggregatedNonce::aggregate(&public_nonces, agg_pubkey, &msg).unwrap();
//!
//! // Create partial signatures
//! let idx1 = key_agg.index_of(&pk1).unwrap();
//! let idx2 = key_agg.index_of(&pk2).unwrap();
//!
//! let partial1 = create_partial_signature(
//!     &mut nonce1, &sk1.to_bytes(), &key_agg, &agg_nonce, &public_nonces, &msg, idx1
//! ).unwrap();
//! let partial2 = create_partial_signature(
//!     &mut nonce2, &sk2.to_bytes(), &key_agg, &agg_nonce, &public_nonces, &msg, idx2
//! ).unwrap();
//!
//! // Aggregate signatures
//! let signature = aggregate_partial_signatures(&[partial1, partial2], &agg_nonce, &key_agg).unwrap();
//!
//! // Verify
//! assert!(verify_signature(&signature, agg_pubkey, &msg).unwrap());
//! ```
//!
//! ## Using SigningSession
//!
//! For a higher-level API, use `SigningSession`:
//!
//! ```rust
//! use rustywallet_musig::prelude::*;
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! let sk1 = PrivateKey::random();
//! let sk2 = PrivateKey::random();
//! let pk1 = sk1.public_key().to_compressed();
//! let pk2 = sk2.public_key().to_compressed();
//!
//! let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
//! let msg = [0u8; 32];
//!
//! // Create session
//! let mut session = SigningSession::new(key_agg.clone(), msg);
//!
//! // Generate nonces
//! let mut nonce1 = SecretNonce::generate(
//!     &sk1.to_bytes(), &pk1, key_agg.xonly_pubkey(), Some(&msg), None
//! ).unwrap();
//! let mut nonce2 = SecretNonce::generate(
//!     &sk2.to_bytes(), &pk2, key_agg.xonly_pubkey(), Some(&msg), None
//! ).unwrap();
//!
//! let idx1 = key_agg.index_of(&pk1).unwrap();
//! let idx2 = key_agg.index_of(&pk2).unwrap();
//!
//! // Add nonces
//! session.add_nonce(idx1, nonce1.public_nonce().unwrap()).unwrap();
//! session.add_nonce(idx2, nonce2.public_nonce().unwrap()).unwrap();
//!
//! // Sign and add partial signatures
//! let partial1 = session.sign(&mut nonce1, &sk1.to_bytes(), idx1).unwrap();
//! let partial2 = session.sign(&mut nonce2, &sk2.to_bytes(), idx2).unwrap();
//! session.add_partial_signature(partial1).unwrap();
//! session.add_partial_signature(partial2).unwrap();
//!
//! // Aggregate and verify
//! let sig = session.aggregate().unwrap();
//! assert!(session.verify().unwrap());
//! ```
//!
//! ## Security Notes
//!
//! - **NEVER reuse nonces** - this will leak your private key
//! - Secret nonces are automatically marked as used after signing
//! - Debug output for secret values is redacted
//! - Secret nonces are zeroized on drop

pub mod adaptor;
pub mod error;
pub mod key_agg;
pub mod nonce;
pub mod prelude;
pub mod session;
pub mod signing;
pub mod tagged_hash;

#[cfg(test)]
mod tests;

// Re-export main types
pub use adaptor::AdaptorSignature;
pub use error::MusigError;
pub use key_agg::KeyAggContext;
pub use nonce::{AggregatedNonce, PublicNonce, SecretNonce};
pub use session::SigningSession;
pub use signing::{PartialSignature, SchnorrSignature};
