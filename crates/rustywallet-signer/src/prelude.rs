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
