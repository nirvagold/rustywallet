//! Result types for vanity address generation.

use crate::pattern::Pattern;
use rustywallet_keys::prelude::*;
use std::time::Duration;

/// Result of a successful vanity address search.
#[derive(Debug, Clone)]
pub struct VanityResult {
    /// The private key that generates the vanity address.
    pub private_key: PrivateKey,
    /// The public key derived from the private key.
    pub public_key: PublicKey,
    /// The vanity address that matched the pattern.
    pub address: String,
    /// The pattern that was matched.
    pub matched_pattern: Pattern,
    /// Statistics about the search.
    pub stats: SearchStats,
}

impl VanityResult {
    /// Create a new vanity result.
    pub fn new(
        private_key: PrivateKey,
        address: String,
        matched_pattern: Pattern,
        stats: SearchStats,
    ) -> Self {
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
            address,
            matched_pattern,
            stats,
        }
    }
}

/// Statistics about a vanity search.
#[derive(Debug, Clone)]
pub struct SearchStats {
    /// Number of keys checked.
    pub attempts: u64,
    /// Time elapsed during search.
    pub elapsed: Duration,
    /// Keys checked per second.
    pub rate: f64,
}

impl SearchStats {
    /// Create new search stats.
    pub fn new(attempts: u64, elapsed: Duration) -> Self {
        let rate = if elapsed.as_secs_f64() > 0.0 {
            attempts as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        Self {
            attempts,
            elapsed,
            rate,
        }
    }
}

/// Progress information during a search.
#[derive(Debug, Clone)]
pub struct SearchProgress {
    /// Number of keys checked so far.
    pub attempts: u64,
    /// Time elapsed so far.
    pub elapsed: Duration,
    /// Current rate (keys/sec).
    pub rate: f64,
    /// Estimated time remaining (if calculable).
    pub estimated_remaining: Option<Duration>,
}

impl SearchProgress {
    /// Create new progress info.
    pub fn new(attempts: u64, elapsed: Duration, expected_attempts: Option<u64>) -> Self {
        let rate = if elapsed.as_secs_f64() > 0.0 {
            attempts as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let estimated_remaining = expected_attempts.and_then(|expected| {
            if rate > 0.0 && attempts < expected {
                let remaining_attempts = expected - attempts;
                Some(Duration::from_secs_f64(remaining_attempts as f64 / rate))
            } else {
                None
            }
        });

        Self {
            attempts,
            elapsed,
            rate,
            estimated_remaining,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_stats() {
        let stats = SearchStats::new(1000, Duration::from_secs(1));
        assert_eq!(stats.attempts, 1000);
        assert!((stats.rate - 1000.0).abs() < 0.1);
    }

    #[test]
    fn test_search_progress() {
        let progress = SearchProgress::new(500, Duration::from_secs(1), Some(1000));
        assert_eq!(progress.attempts, 500);
        assert!(progress.estimated_remaining.is_some());
    }
}
