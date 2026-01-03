//! Regex pattern matching for vanity addresses.
//!
//! This module provides regex-based pattern matching for more flexible
//! vanity address generation.

use crate::address_type::AddressType;
use crate::error::PatternError;
use regex::Regex;

/// A regex pattern for matching addresses.
///
/// Supports full Rust regex syntax for flexible pattern matching.
///
/// # Example
///
/// ```rust
/// use rustywallet_vanity::regex_pattern::RegexPattern;
///
/// // Match addresses starting with "1" followed by 3-5 letters
/// let pattern = RegexPattern::new(r"^1[A-Za-z]{3,5}").unwrap();
/// assert!(pattern.matches("1Love123"));
/// assert!(pattern.matches("1BTC456"));
/// assert!(!pattern.matches("1AB789")); // Only 2 letters
/// ```
#[derive(Debug, Clone)]
pub struct RegexPattern {
    /// The compiled regex
    regex: Regex,
    /// Original pattern string
    pattern_str: String,
    /// Whether to match case-insensitively
    case_insensitive: bool,
}

impl RegexPattern {
    /// Create a new regex pattern.
    ///
    /// # Arguments
    ///
    /// * `pattern` - A valid Rust regex pattern
    ///
    /// # Errors
    ///
    /// Returns `PatternError::InvalidRegex` if the pattern is invalid.
    pub fn new(pattern: &str) -> Result<Self, PatternError> {
        if pattern.is_empty() {
            return Err(PatternError::EmptyPattern);
        }

        let regex = Regex::new(pattern)
            .map_err(|e| PatternError::InvalidRegex(e.to_string()))?;

        Ok(Self {
            regex,
            pattern_str: pattern.to_string(),
            case_insensitive: false,
        })
    }

    /// Create a case-insensitive regex pattern.
    pub fn new_case_insensitive(pattern: &str) -> Result<Self, PatternError> {
        if pattern.is_empty() {
            return Err(PatternError::EmptyPattern);
        }

        // Prepend (?i) for case-insensitive matching
        let ci_pattern = format!("(?i){}", pattern);
        let regex = Regex::new(&ci_pattern)
            .map_err(|e| PatternError::InvalidRegex(e.to_string()))?;

        Ok(Self {
            regex,
            pattern_str: pattern.to_string(),
            case_insensitive: true,
        })
    }

    /// Check if an address matches this pattern.
    pub fn matches(&self, address: &str) -> bool {
        self.regex.is_match(address)
    }

    /// Get the original pattern string.
    pub fn as_str(&self) -> &str {
        &self.pattern_str
    }

    /// Check if pattern is case-insensitive.
    pub fn is_case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    /// Estimate difficulty of finding a match.
    ///
    /// This is a rough estimate based on pattern complexity.
    pub fn estimate_difficulty(&self, address_type: AddressType) -> f64 {
        // Base alphabet size
        let alphabet_size: f64 = match address_type {
            AddressType::P2PKH => 58.0,
            AddressType::P2WPKH => 32.0,
            AddressType::P2TR => 32.0,
            AddressType::Ethereum => 16.0,
        };

        // Estimate based on pattern length (rough approximation)
        // Count non-metacharacters as required matches
        let effective_len = self.pattern_str
            .chars()
            .filter(|c| c.is_alphanumeric())
            .count();

        if effective_len == 0 {
            return 1.0;
        }

        // Case insensitivity factor
        let case_factor = if self.case_insensitive {
            let letter_count = self.pattern_str
                .chars()
                .filter(|c| c.is_alphabetic())
                .count();
            2.0_f64.powi(letter_count as i32)
        } else {
            1.0
        };

        alphabet_size.powi(effective_len as i32) / case_factor
    }
}

impl std::fmt::Display for RegexPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "regex:{}", self.pattern_str)
    }
}

/// Common regex patterns for vanity addresses.
pub struct CommonPatterns;

impl CommonPatterns {
    /// Match addresses starting with specific text.
    pub fn starts_with(text: &str) -> Result<RegexPattern, PatternError> {
        RegexPattern::new(&format!("^{}", regex::escape(text)))
    }

    /// Match addresses ending with specific text.
    pub fn ends_with(text: &str) -> Result<RegexPattern, PatternError> {
        RegexPattern::new(&format!("{}$", regex::escape(text)))
    }

    /// Match addresses containing specific text.
    pub fn contains(text: &str) -> Result<RegexPattern, PatternError> {
        RegexPattern::new(&regex::escape(text))
    }

    /// Match addresses with repeated characters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_vanity::regex_pattern::CommonPatterns;
    ///
    /// let pattern = CommonPatterns::repeated_char('A', 3).unwrap();
    /// assert!(pattern.matches("1AAA123"));
    /// assert!(!pattern.matches("1AA123")); // Only 2 A's
    /// ```
    pub fn repeated_char(c: char, count: usize) -> Result<RegexPattern, PatternError> {
        if count == 0 {
            return Err(PatternError::EmptyPattern);
        }
        RegexPattern::new(&format!("{}{{{}}}", regex::escape(&c.to_string()), count))
    }

    /// Match addresses with alternating characters.
    pub fn alternating(chars: &str) -> Result<RegexPattern, PatternError> {
        if chars.len() < 2 {
            return Err(PatternError::InvalidPattern("Need at least 2 characters".into()));
        }
        let pattern: String = chars.chars()
            .map(|c| regex::escape(&c.to_string()))
            .collect::<Vec<_>>()
            .join("");
        RegexPattern::new(&pattern)
    }

    /// Match addresses with a word boundary pattern.
    pub fn word(word: &str) -> Result<RegexPattern, PatternError> {
        RegexPattern::new_case_insensitive(&regex::escape(word))
    }

    /// Match addresses with numeric sequences.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rustywallet_vanity::regex_pattern::CommonPatterns;
    ///
    /// let pattern = CommonPatterns::numeric_sequence(4).unwrap();
    /// assert!(pattern.matches("1abc1234xyz"));
    /// assert!(!pattern.matches("1abc123xyz")); // Only 3 digits
    /// ```
    pub fn numeric_sequence(min_length: usize) -> Result<RegexPattern, PatternError> {
        if min_length == 0 {
            return Err(PatternError::EmptyPattern);
        }
        RegexPattern::new(&format!(r"\d{{{},}}", min_length))
    }

    /// Match addresses with letter sequences.
    pub fn letter_sequence(min_length: usize) -> Result<RegexPattern, PatternError> {
        if min_length == 0 {
            return Err(PatternError::EmptyPattern);
        }
        RegexPattern::new(&format!(r"[A-Za-z]{{{},}}", min_length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_pattern_basic() {
        let pattern = RegexPattern::new(r"^1[A-Z]{3}").unwrap();
        assert!(pattern.matches("1ABC123"));
        assert!(pattern.matches("1XYZ456"));
        assert!(!pattern.matches("1abc123")); // lowercase
        assert!(!pattern.matches("2ABC123")); // wrong start
    }

    #[test]
    fn test_regex_pattern_case_insensitive() {
        let pattern = RegexPattern::new_case_insensitive(r"^1love").unwrap();
        assert!(pattern.matches("1Love123"));
        assert!(pattern.matches("1LOVE123"));
        assert!(pattern.matches("1love123"));
    }

    #[test]
    fn test_common_patterns_starts_with() {
        let pattern = CommonPatterns::starts_with("1BTC").unwrap();
        assert!(pattern.matches("1BTC123"));
        assert!(!pattern.matches("2BTC123"));
    }

    #[test]
    fn test_common_patterns_ends_with() {
        let pattern = CommonPatterns::ends_with("BTC").unwrap();
        assert!(pattern.matches("1abcBTC"));
        assert!(!pattern.matches("1BTCabc"));
    }

    #[test]
    fn test_common_patterns_repeated() {
        let pattern = CommonPatterns::repeated_char('A', 3).unwrap();
        assert!(pattern.matches("1AAA123"));
        assert!(pattern.matches("1AAAA123")); // 4 A's also matches
        assert!(!pattern.matches("1AA123"));
    }

    #[test]
    fn test_common_patterns_numeric() {
        let pattern = CommonPatterns::numeric_sequence(4).unwrap();
        assert!(pattern.matches("1abc1234xyz"));
        assert!(pattern.matches("1abc12345xyz"));
        assert!(!pattern.matches("1abc123xyz"));
    }

    #[test]
    fn test_difficulty_estimate() {
        let pattern = RegexPattern::new(r"^1[A-Z]{2}").unwrap();
        let diff = pattern.estimate_difficulty(AddressType::P2PKH);
        // Should be roughly 58^2 = 3364 for 2 characters
        assert!(diff > 1000.0);
    }

    #[test]
    fn test_invalid_regex() {
        let result = RegexPattern::new(r"[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_pattern() {
        assert!(RegexPattern::new("").is_err());
    }
}
