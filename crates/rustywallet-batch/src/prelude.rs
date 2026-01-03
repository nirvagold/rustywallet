//! Convenient re-exports for common types.
//!
//! This module provides a prelude that re-exports the most commonly used
//! types from this crate for convenient importing.
//!
//! # Example
//!
//! ```rust
//! use rustywallet_batch::prelude::*;
//!
//! let keys = BatchGenerator::new()
//!     .count(100)
//!     .parallel()
//!     .generate_vec()
//!     .unwrap();
//! ```

pub use crate::address::{AddressStream, BatchAddressGenerator, BatchAddressType};
pub use crate::checkpoint::{Checkpoint, GenerationMode, ResumableBatchGenerator};
pub use crate::config::BatchConfig;
pub use crate::error::BatchError;
pub use crate::fast_gen::{FastKeyGenerator, IncrementalKeyGenerator};
pub use crate::generator::BatchGenerator;
pub use crate::mmap::{MmapBatchGenerator, MmapWriter, OutputFormat};
pub use crate::scanner::{KeyScanner, ScanDirection};
pub use crate::simd::SimdBatchProcessor;
pub use crate::stream::KeyStream;
