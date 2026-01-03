//! Prelude module for convenient imports.
//!
//! # Example
//!
//! ```
//! use rustywallet_silent::prelude::*;
//! ```

pub use crate::address::SilentPaymentAddress;
pub use crate::change::ChangeAddressGenerator;
pub use crate::error::{Result, SilentPaymentError};
pub use crate::label::{Label, LabelManager};
pub use crate::network::Network;
pub use crate::scanner::{DetectedPayment, LightScanner, SilentPaymentScanner};
pub use crate::sender::{create_multiple_outputs, create_outputs, SilentPaymentOutput};
