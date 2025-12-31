//! Convenient re-exports for common usage.
//!
//! ```
//! use rustywallet_address::prelude::*;
//! ```

pub use crate::address::{Address, AddressFormat};
pub use crate::bitcoin::{BitcoinAddress, BitcoinAddressType, P2PKHAddress, P2TRAddress, P2WPKHAddress};
pub use crate::error::AddressError;
pub use crate::ethereum::EthereumAddress;
pub use crate::network::Network;
