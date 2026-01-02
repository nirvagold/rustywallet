//! Pattern matching for vanity addresses.

use crate::address_type::AddressType;
use crate::error::PatternError;

/// A pattern to match against addresses.
#[derive(Debug, Clone)]
pub enum Pattern {
    /// Match addresses starting with this prefix.
    Prefix(String),
    /// Match addresses ending with this suffix.
    Suffix(String),
    /// Match addresses containing this substring.
    Contains(String),
}

impl Pattern {
    /// Create a prefix pattern.
    pub fn prefix(s: &str) -> Result<Self, PatternError> {
        if s.is_empty() {
            return Err(PatternError::EmptyPattern);
        }
        Ok(Pattern::Prefix(s.to_string()))
    }

    /// Create a suffix pattern.
    pub fn suffix(s: &str) -> Result<Self, PatternError> {
        if s.is_empty() {
            return Err(PatternError::EmptyPattern);
        }
        Ok(Pattern::Suffix(s.to_string()))
    }

    /// Create a contains pattern.
    pub fn contains(s: &str) -> Result<Self, PatternError> {
        if s.is_empty() {
            return Err(PatternError::EmptyPattern);
        }
        Ok(Pattern::Contains(s.to_string()))
    }

    /// Get the pattern string.
    pub fn as_str(&self) -> &str {
        match self {
            Pattern::Prefix(s) => s,
            Pattern::Suffix(s) => s,
            Pattern::Contains(s) => s,
        }
    }

    /// Check if an address matches this pattern.
    pub fn matches(&self, address: &str, case_sensitive: bool) -> bool {
        if case_sensitive {
            self.matches_case_sensitive(address)
        } else {
            self.matches_case_insensitive(address)
        }
    }

    fn matches_case_sensitive(&self, address: &str) -> bool {
        match self {
            Pattern::Prefix(p) => address.starts_with(p),
            Pattern::Suffix(s) => address.ends_with(s),
            Pattern::Contains(c) => address.contains(c),
        }
    }

    fn matches_case_insensitive(&self, address: &str) -> bool {
        let addr_lower = address.to_lowercase();
        match self {
            Pattern::Prefix(p) => addr_lower.starts_with(&p.to_lowercase()),
            Pattern::Suffix(s) => addr_lower.ends_with(&s.to_lowercase()),
            Pattern::Contains(c) => addr_lower.contains(&c.to_lowercase()),
        }
    }

    /// Validate this pattern for a specific address type.
    pub fn validate_for_type(
        &self,
        address_type: AddressType,
        testnet: bool,
    ) -> Result<(), PatternError> {
        let pattern_str = self.as_str();

        // For prefix patterns, use address type validation
        if let Pattern::Prefix(_) = self {
            address_type.validate_pattern(pattern_str, testnet)?;
        } else {
            // For suffix/contains, just validate characters
            let valid_chars = address_type.valid_chars();
            for c in pattern_str.chars() {
                let c_lower = c.to_ascii_lowercase();
                if !valid_chars.contains(c_lower) && !valid_chars.contains(c) {
                    return Err(PatternError::InvalidCharacter(c));
                }
            }
        }

        Ok(())
    }

    /// Calculate the difficulty of finding this pattern.
    /// Returns the expected number of attempts.
    pub fn difficulty(&self, address_type: AddressType, case_sensitive: bool) -> f64 {
        let pattern_str = self.as_str();
        let fixed_prefix = address_type.fixed_prefix(false);

        // Calculate effective pattern length (excluding fixed prefix for prefix patterns)
        let effective_len = match self {
            Pattern::Prefix(p) => {
                if p.len() > fixed_prefix.len() {
                    p.len() - fixed_prefix.len()
                } else {
                    0
                }
            }
            Pattern::Suffix(s) => s.len(),
            Pattern::Contains(c) => c.len(),
        };

        if effective_len == 0 {
            return 1.0;
        }

        // Base alphabet size
        let alphabet_size: f64 = match address_type {
            AddressType::P2PKH => 58.0,       // Base58
            AddressType::P2WPKH => 32.0,      // Bech32
            AddressType::P2TR => 32.0,        // Bech32
            AddressType::Ethereum => 16.0,    // Hex
        };

        // Case sensitivity factor
        let case_factor = if case_sensitive {
            1.0
        } else {
            // For case-insensitive, we have more matches
            // Roughly 2x for each letter that has case variants
            let letter_count = pattern_str.chars().filter(|c| c.is_alphabetic()).count();
            2.0_f64.powi(letter_count as i32)
        };

        // Expected attempts = alphabet_size ^ effective_len / case_factor
        let base_difficulty = alphabet_size.powi(effective_len as i32);

        // For suffix/contains, multiply by address length factor
        let position_factor = match self {
            Pattern::Prefix(_) => 1.0,
            Pattern::Suffix(_) => 1.0,
            Pattern::Contains(_) => 0.5, // Can match anywhere, so easier
        };

        base_difficulty / case_factor * position_factor
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pattern::Prefix(p) => write!(f, "prefix:{}", p),
            Pattern::Suffix(s) => write!(f, "suffix:{}", s),
            Pattern::Contains(c) => write!(f, "contains:{}", c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_matching() {
        let pattern = Pattern::prefix("1Love").unwrap();

        assert!(pattern.matches("1LoveXYZ123", true));
        assert!(!pattern.matches("1loveXYZ123", true)); // case sensitive
        assert!(pattern.matches("1loveXYZ123", false)); // case insensitive
        assert!(!pattern.matches("2LoveXYZ123", true));
    }

    #[test]
    fn test_suffix_matching() {
        let pattern = Pattern::suffix("BTC").unwrap();

        assert!(pattern.matches("1abcdefBTC", true));
        assert!(!pattern.matches("1abcdefbtc", true));
        assert!(pattern.matches("1abcdefbtc", false));
    }

    #[test]
    fn test_contains_matching() {
        let pattern = Pattern::contains("Love").unwrap();

        assert!(pattern.matches("1abcLoveXYZ", true));
        assert!(pattern.matches("1LoveXYZ", true));
        assert!(pattern.matches("1XYZLove", true));
    }

    #[test]
    fn test_difficulty_calculation() {
        let pattern = Pattern::prefix("1A").unwrap();
        let diff = pattern.difficulty(AddressType::P2PKH, true);

        // 1 char after prefix, Base58 = 58 expected attempts
        assert!(diff > 50.0 && diff < 70.0);
    }

    #[test]
    fn test_empty_pattern_rejected() {
        assert!(Pattern::prefix("").is_err());
        assert!(Pattern::suffix("").is_err());
        assert!(Pattern::contains("").is_err());
    }
}
