//! Difficulty estimation for vanity patterns.

use crate::address_type::AddressType;
use crate::pattern::Pattern;
use std::time::Duration;

/// Difficulty level for a vanity pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifficultyLevel {
    /// Very easy, typically < 1 minute.
    Easy,
    /// Medium difficulty, 1-10 minutes.
    Medium,
    /// Hard, 10-60 minutes.
    Hard,
    /// Very hard, 1-24 hours.
    VeryHard,
    /// Extreme, > 24 hours.
    Extreme,
}

impl DifficultyLevel {
    /// Get a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            DifficultyLevel::Easy => "Easy (< 1 minute)",
            DifficultyLevel::Medium => "Medium (1-10 minutes)",
            DifficultyLevel::Hard => "Hard (10-60 minutes)",
            DifficultyLevel::VeryHard => "Very Hard (1-24 hours)",
            DifficultyLevel::Extreme => "Extreme (> 24 hours)",
        }
    }
}

impl std::fmt::Display for DifficultyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Difficulty estimate for a vanity pattern.
#[derive(Debug, Clone)]
pub struct DifficultyEstimate {
    /// The pattern being estimated.
    pub pattern: Pattern,
    /// Probability of finding a match per attempt.
    pub probability: f64,
    /// Expected number of attempts to find a match.
    pub expected_attempts: u64,
    /// Estimated time to find a match at given rate.
    pub estimated_time: Duration,
    /// Difficulty level category.
    pub difficulty_level: DifficultyLevel,
}

impl DifficultyEstimate {
    /// Calculate difficulty estimate for a pattern.
    pub fn calculate(
        pattern: &Pattern,
        address_type: AddressType,
        case_sensitive: bool,
        generation_rate: f64,
    ) -> Self {
        let expected_attempts = pattern.difficulty(address_type, case_sensitive) as u64;
        let probability = 1.0 / expected_attempts as f64;

        let estimated_secs = if generation_rate > 0.0 {
            expected_attempts as f64 / generation_rate
        } else {
            f64::INFINITY
        };
        let estimated_time = Duration::from_secs_f64(estimated_secs.min(f64::MAX / 2.0));

        let difficulty_level = Self::categorize_difficulty(estimated_time);

        Self {
            pattern: pattern.clone(),
            probability,
            expected_attempts,
            estimated_time,
            difficulty_level,
        }
    }

    /// Categorize difficulty based on estimated time.
    fn categorize_difficulty(estimated_time: Duration) -> DifficultyLevel {
        let secs = estimated_time.as_secs();
        if secs < 60 {
            DifficultyLevel::Easy
        } else if secs < 600 {
            DifficultyLevel::Medium
        } else if secs < 3600 {
            DifficultyLevel::Hard
        } else if secs < 86400 {
            DifficultyLevel::VeryHard
        } else {
            DifficultyLevel::Extreme
        }
    }

    /// Check if this pattern is practical to search for.
    pub fn is_practical(&self) -> bool {
        matches!(
            self.difficulty_level,
            DifficultyLevel::Easy | DifficultyLevel::Medium | DifficultyLevel::Hard
        )
    }

    /// Get a warning message if the pattern is very difficult.
    pub fn warning(&self) -> Option<String> {
        match self.difficulty_level {
            DifficultyLevel::VeryHard => Some(format!(
                "Warning: Pattern '{}' is very difficult. Expected time: {:?}",
                self.pattern, self.estimated_time
            )),
            DifficultyLevel::Extreme => Some(format!(
                "Warning: Pattern '{}' is extremely difficult and may take days or longer. Expected time: {:?}",
                self.pattern, self.estimated_time
            )),
            _ => None,
        }
    }
}

impl std::fmt::Display for DifficultyEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Pattern: {}, Difficulty: {}, Expected attempts: {}, Estimated time: {:?}",
            self.pattern, self.difficulty_level, self.expected_attempts, self.estimated_time
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_levels() {
        assert_eq!(
            DifficultyEstimate::categorize_difficulty(Duration::from_secs(30)),
            DifficultyLevel::Easy
        );
        assert_eq!(
            DifficultyEstimate::categorize_difficulty(Duration::from_secs(300)),
            DifficultyLevel::Medium
        );
        assert_eq!(
            DifficultyEstimate::categorize_difficulty(Duration::from_secs(1800)),
            DifficultyLevel::Hard
        );
    }

    #[test]
    fn test_difficulty_estimate() {
        let pattern = Pattern::prefix("1A").unwrap();
        let estimate =
            DifficultyEstimate::calculate(&pattern, AddressType::P2PKH, true, 1_000_000.0);

        // 1 char after prefix = ~58 attempts at 1M/sec = very fast
        assert_eq!(estimate.difficulty_level, DifficultyLevel::Easy);
        assert!(estimate.is_practical());
    }

    #[test]
    fn test_hard_pattern() {
        let pattern = Pattern::prefix("1Bitcoin").unwrap();
        let estimate =
            DifficultyEstimate::calculate(&pattern, AddressType::P2PKH, true, 1_000_000.0);

        // 7 chars = 58^7 = huge number
        assert!(matches!(
            estimate.difficulty_level,
            DifficultyLevel::VeryHard | DifficultyLevel::Extreme
        ));
    }
}
