//! Prelude module for convenient imports.
//!
//! # Example
//!
//! ```rust
//! use rustywallet_musig::prelude::*;
//! ```

pub use crate::adaptor::{
    aggregate_adaptor_signatures, create_adaptor_partial_signature, AdaptorSignature,
};
pub use crate::error::{MusigError, Result};
pub use crate::key_agg::KeyAggContext;
pub use crate::nonce::{AggregatedNonce, PublicNonce, SecretNonce};
pub use crate::session::{SessionState, SigningSession};
pub use crate::signing::{
    aggregate_partial_signatures, create_partial_signature, verify_signature, PartialSignature,
    SchnorrSignature,
};
