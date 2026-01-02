//! # rustywallet-batch
//!
//! High-performance batch key generation for cryptocurrency wallets.
//!
//! This crate provides efficient APIs for generating large batches of private keys
//! with parallel processing, SIMD optimization, and memory-efficient streaming.
//!
//! ## Features
//!
//! - **Batch Generation**: Generate millions of keys efficiently
//! - **Parallel Processing**: Utilize all CPU cores with rayon
//! - **Memory Streaming**: Process unlimited keys without memory exhaustion
//! - **Incremental Scanning**: Scan key ranges using EC point addition
//! - **Configurable**: Flexible configuration for different use cases
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_batch::prelude::*;
//!
//! // Generate 1000 keys in parallel
//! let keys = BatchGenerator::new()
//!     .count(1000)
//!     .parallel()
//!     .generate_vec()
//!     .unwrap();
//!
//! println!("Generated {} keys", keys.len());
//! ```
//!
//! ## Streaming Large Batches
//!
//! ```rust
//! use rustywallet_batch::prelude::*;
//!
//! // Stream keys without storing all in memory
//! let stream = BatchGenerator::new()
//!     .count(1_000_000)
//!     .generate()
//!     .unwrap();
//!
//! for key in stream.take(100) {
//!     println!("{}", key.unwrap().to_hex());
//! }
//! ```
//!
//! ## Incremental Key Scanning
//!
//! ```rust
//! use rustywallet_batch::prelude::*;
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! // Scan from a base key
//! let base = PrivateKey::from_hex(
//!     "0000000000000000000000000000000000000000000000000000000000000001"
//! ).unwrap();
//!
//! let scanner = KeyScanner::new(base)
//!     .direction(ScanDirection::Forward);
//!
//! for key in scanner.scan_range(10) {
//!     println!("{}", key.unwrap().to_hex());
//! }
//! ```
//!
//! ## Configuration Presets
//!
//! ```rust
//! use rustywallet_batch::prelude::*;
//!
//! // Fast mode - maximum speed
//! let config = BatchConfig::fast();
//!
//! // Balanced mode - good speed with reasonable memory
//! let config = BatchConfig::balanced();
//!
//! // Memory efficient - minimal memory usage
//! let config = BatchConfig::memory_efficient();
//! ```

pub mod config;
pub mod error;
pub mod fast_gen;
pub mod generator;
pub mod prelude;
pub mod scanner;
pub mod stream;

#[cfg(test)]
mod tests;

// Re-export main types at crate root
pub use config::BatchConfig;
pub use error::BatchError;
pub use fast_gen::{FastKeyGenerator, IncrementalKeyGenerator};
pub use generator::BatchGenerator;
pub use scanner::{KeyScanner, ScanDirection};
pub use stream::KeyStream;
