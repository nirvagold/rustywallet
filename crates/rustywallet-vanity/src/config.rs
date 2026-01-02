//! Configuration for vanity address generation.

use crate::address_type::AddressType;
use crate::error::VanityError;
use crate::pattern::Pattern;
use std::time::Duration;

/// Configuration for vanity address generation.
#[derive(Debug, Clone)]
pub struct VanityConfig {
    /// Patterns to search for.
    pub patterns: Vec<Pattern>,
    /// Address type to generate.
    pub address_type: AddressType,
    /// Whether to use testnet.
    pub testnet: bool,
    /// Whether matching is case-sensitive.
    pub case_sensitive: bool,
    /// Maximum number of attempts before giving up.
    pub max_attempts: Option<u64>,
    /// Maximum time to search.
    pub timeout: Option<Duration>,
    /// Number of threads for parallel search.
    pub thread_count: Option<usize>,
    /// Batch size for key generation.
    pub batch_size: usize,
    /// Interval for progress callbacks.
    pub progress_interval: Duration,
}

impl Default for VanityConfig {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            address_type: AddressType::P2PKH,
            testnet: false,
            case_sensitive: true,
            max_attempts: None,
            timeout: None,
            thread_count: None,
            batch_size: 10_000,
            progress_interval: Duration::from_secs(1),
        }
    }
}

impl VanityConfig {
    /// Create a new default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fast configuration optimized for speed.
    pub fn fast() -> Self {
        Self {
            batch_size: 50_000,
            progress_interval: Duration::from_millis(500),
            ..Default::default()
        }
    }

    /// Create a thorough configuration with more patterns.
    pub fn thorough() -> Self {
        Self {
            batch_size: 10_000,
            progress_interval: Duration::from_secs(2),
            ..Default::default()
        }
    }

    /// Set the patterns to search for.
    pub fn with_patterns(mut self, patterns: Vec<Pattern>) -> Self {
        self.patterns = patterns;
        self
    }

    /// Add a pattern to search for.
    pub fn with_pattern(mut self, pattern: Pattern) -> Self {
        self.patterns.push(pattern);
        self
    }

    /// Set the address type.
    pub fn with_address_type(mut self, address_type: AddressType) -> Self {
        self.address_type = address_type;
        self
    }

    /// Set whether to use testnet.
    pub fn with_testnet(mut self, testnet: bool) -> Self {
        self.testnet = testnet;
        self
    }

    /// Set case sensitivity.
    pub fn with_case_sensitive(mut self, case_sensitive: bool) -> Self {
        self.case_sensitive = case_sensitive;
        self
    }

    /// Set maximum attempts.
    pub fn with_max_attempts(mut self, max: u64) -> Self {
        self.max_attempts = Some(max);
        self
    }

    /// Set timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set thread count.
    pub fn with_thread_count(mut self, count: usize) -> Self {
        self.thread_count = Some(count);
        self
    }

    /// Set batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), VanityError> {
        if self.patterns.is_empty() {
            return Err(VanityError::InvalidConfig(
                "At least one pattern is required".to_string(),
            ));
        }

        if self.batch_size == 0 {
            return Err(VanityError::InvalidConfig(
                "Batch size must be greater than 0".to_string(),
            ));
        }

        if let Some(count) = self.thread_count {
            if count == 0 {
                return Err(VanityError::InvalidConfig(
                    "Thread count must be greater than 0".to_string(),
                ));
            }
        }

        // Validate each pattern for the address type
        for pattern in &self.patterns {
            pattern
                .validate_for_type(self.address_type, self.testnet)
                .map_err(VanityError::InvalidPattern)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VanityConfig::default();
        assert!(config.patterns.is_empty());
        assert_eq!(config.address_type, AddressType::P2PKH);
        assert!(config.case_sensitive);
    }

    #[test]
    fn test_fast_preset() {
        let config = VanityConfig::fast();
        assert_eq!(config.batch_size, 50_000);
    }

    #[test]
    fn test_validation_no_patterns() {
        let config = VanityConfig::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_with_pattern() {
        let config = VanityConfig::default()
            .with_pattern(Pattern::prefix("1Love").unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_builder_pattern() {
        let config = VanityConfig::new()
            .with_address_type(AddressType::P2WPKH)
            .with_case_sensitive(false)
            .with_max_attempts(1_000_000)
            .with_timeout(Duration::from_secs(60));

        assert_eq!(config.address_type, AddressType::P2WPKH);
        assert!(!config.case_sensitive);
        assert_eq!(config.max_attempts, Some(1_000_000));
    }
}
