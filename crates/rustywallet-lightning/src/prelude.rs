//! Prelude module for convenient imports.
//!
//! This module re-exports the most commonly used types for convenience.
//!
//! # Example
//!
//! ```rust
//! use rustywallet_lightning::prelude::*;
//!
//! // Now you can use all common types directly
//! let preimage = PaymentPreimage::random();
//! let hash = preimage.payment_hash();
//! ```

pub use crate::bolt11::{Bolt11Invoice, InvoiceBuilder, InvoiceData, Network};
pub use crate::bolt12::{Bolt12Offer, OfferBuilder, OfferAmount, BlindedPath};
pub use crate::channel::{ChannelPoint, ShortChannelId};
pub use crate::error::LightningError;
pub use crate::node::{NodeId, NodeIdentity};
pub use crate::payment::{PaymentHash, PaymentPreimage};
pub use crate::route::{RouteHint, RouteHintBuilder, RouteHintHop};
