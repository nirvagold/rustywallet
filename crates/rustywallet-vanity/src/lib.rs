//! # rustywallet-vanity
//!
//! High-performance vanity address generator for Bitcoin and Ethereum.
//!
//! This crate provides tools for generating cryptocurrency addresses that match
//! specific patterns, such as addresses starting with "1Love" or "1BTC".
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rustywallet_vanity::prelude::*;
//! use rustywallet_keys::prelude::Network;
//!
//! // Search for an address starting with "1A"
//! let result = VanityGenerator::new()
//!     .pattern("1A")
//!     .search()
//!     .unwrap();
//!
//! println!("Address: {}", result.address);
//! println!("Private Key (WIF): {}", result.private_key.to_wif(Network::Mainnet));
//! println!("Attempts: {}", result.stats.attempts);
//! ```
//!
//! ## Multi-Pattern Search
//!
//! ```rust,no_run
//! use rustywallet_vanity::prelude::*;
//!
//! // Search for any of multiple patterns
//! let result = VanityGenerator::new()
//!     .patterns(&["1Love", "1BTC", "1Coin"])
//!     .case_insensitive()
//!     .search_parallel()
//!     .unwrap();
//!
//! println!("Found: {} (matched {})", result.address, result.matched_pattern);
//! ```
//!
//! ## Difficulty Estimation
//!
//! ```rust
//! use rustywallet_vanity::prelude::*;
//!
//! let gen = VanityGenerator::new().pattern("1Love");
//! let estimates = gen.estimate_difficulty();
//!
//! for est in estimates {
//!     println!("{}", est);
//!     if let Some(warning) = est.warning() {
//!         println!("  {}", warning);
//!     }
//! }
//! ```
//!
//! ## Address Types
//!
//! ```rust,no_run
//! use rustywallet_vanity::prelude::*;
//!
//! // Legacy P2PKH (1...)
//! let result = VanityGenerator::new()
//!     .pattern("1Love")
//!     .address_type(AddressType::P2PKH)
//!     .search();
//!
//! // Native SegWit (bc1q...)
//! let result = VanityGenerator::new()
//!     .pattern("bc1qtest")
//!     .address_type(AddressType::P2WPKH)
//!     .search();
//!
//! // Ethereum (0x...)
//! let result = VanityGenerator::new()
//!     .pattern("0xdead")
//!     .address_type(AddressType::Ethereum)
//!     .case_insensitive()
//!     .search();
//! ```
//!
//! ## Progress Tracking
//!
//! ```rust,no_run
//! use rustywallet_vanity::prelude::*;
//!
//! let result = VanityGenerator::new()
//!     .pattern("1Love")
//!     .search_with_progress(|progress| {
//!         println!(
//!             "Checked {} keys ({:.0} keys/sec)",
//!             progress.attempts,
//!             progress.rate
//!         );
//!     });
//! ```

pub mod address_type;
pub mod config;
pub mod difficulty;
pub mod error;
pub mod generator;
pub mod pattern;
pub mod prelude;
pub mod result;

#[cfg(test)]
mod tests;

// Re-export main types
pub use address_type::AddressType;
pub use config::VanityConfig;
pub use difficulty::{DifficultyEstimate, DifficultyLevel};
pub use error::{PatternError, VanityError};
pub use generator::VanityGenerator;
pub use pattern::Pattern;
pub use result::{SearchProgress, SearchStats, VanityResult};
