//! Convenient re-exports for common types.
//!
//! This module provides a convenient way to import all commonly used types
//! from the `rustywallet-keys` crate with a single import statement.
//!
//! # Example
//!
//! ```rust
//! use rustywallet_keys::prelude::*;
//!
//! // Now you can use all types directly
//! let private_key = PrivateKey::random();
//! let public_key = private_key.public_key();
//! let wif = private_key.to_wif(Network::Mainnet);
//! let hex = public_key.to_hex(PublicKeyFormat::Compressed);
//! ```

// Error types
pub use crate::error::{KeyError, PrivateKeyError, PublicKeyError};

// Network type
pub use crate::network::Network;

// Key types
pub use crate::private_key::{PrivateKey, PrivateKeyIterator};
pub use crate::public_key::{PublicKey, PublicKeyFormat};
