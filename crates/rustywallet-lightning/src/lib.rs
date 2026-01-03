//! # rustywallet-lightning
//!
//! Lightning Network utilities for Bitcoin wallets.
//!
//! This crate provides tools for working with the Lightning Network,
//! including BOLT11 invoice parsing/creation, payment hash handling,
//! and node identity derivation.
//!
//! ## Features
//!
//! - **BOLT11 Invoices**: Parse and create Lightning invoices
//! - **Payment Hashes**: Generate and verify payment hashes/preimages
//! - **Node Identity**: Derive node ID from HD seed
//! - **Route Hints**: Parse and create route hints
//! - **Channel Points**: Handle channel point references
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_lightning::prelude::*;
//!
//! // Generate payment hash from preimage
//! let preimage = PaymentPreimage::random();
//! let hash = preimage.payment_hash();
//! println!("Payment hash: {}", hash);
//!
//! // Verify preimage matches hash
//! assert!(hash.verify(&preimage));
//! ```
//!
//! ## Node Identity
//!
//! ```rust
//! use rustywallet_lightning::node::NodeIdentity;
//!
//! // Derive node identity from 64-byte seed
//! let seed = [0u8; 64]; // In practice, use a proper seed
//! let identity = NodeIdentity::from_seed(&seed).unwrap();
//! println!("Node ID: {}", identity.node_id());
//! ```

pub mod bolt11;
pub mod channel;
pub mod error;
pub mod node;
pub mod payment;
pub mod prelude;
pub mod route;

#[cfg(test)]
mod tests;

// Re-export main types
pub use bolt11::{Bolt11Invoice, InvoiceBuilder, InvoiceData};
pub use channel::ChannelPoint;
pub use error::LightningError;
pub use node::NodeIdentity;
pub use payment::{PaymentHash, PaymentPreimage};
pub use route::{RouteHint, RouteHintHop};
