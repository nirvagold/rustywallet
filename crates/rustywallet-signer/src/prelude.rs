//! Common imports for rustywallet-signer
//!
//! # Example
//! ```
//! use rustywallet_signer::prelude::*;
//! ```

pub use crate::error::SignerError;
pub use crate::recovery::recover_public_key;
pub use crate::signature::{RecoverableSignature, Signature};
pub use crate::signer::{sign, sign_recoverable};
pub use crate::verifier::{verify, verify_strict};

// Schnorr signing (BIP340)
pub use crate::schnorr::{sign_schnorr, verify_schnorr, SchnorrSigner, SchnorrVerifier};
pub use rustywallet_taproot::{SchnorrSignature, XOnlyPublicKey};
