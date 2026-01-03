//! Convenient re-exports for common usage.
//!
//! # Example
//!
//! ```rust
//! use rustywallet_vanity::prelude::*;
//!
//! // All common types are now available
//! let gen = VanityGenerator::new();
//! ```

pub use crate::address_type::AddressType;
pub use crate::config::VanityConfig;
pub use crate::difficulty::{DifficultyEstimate, DifficultyLevel};
pub use crate::distributed::{DistributedConfig, SearchCoordinator, SearchWorker, run_distributed_search};
pub use crate::error::{PatternError, VanityError};
pub use crate::generator::VanityGenerator;
pub use crate::pattern::Pattern;
pub use crate::regex_pattern::{CommonPatterns, RegexPattern};
pub use crate::result::{SearchProgress, SearchStats, VanityResult};
