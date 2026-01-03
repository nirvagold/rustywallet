//! Participant identifiers for FROST.

use crate::error::{FrostError, Result};
use std::fmt;

/// A participant identifier (1-indexed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifier(u32);

impl Identifier {
    /// Create a new identifier.
    ///
    /// Identifiers must be non-zero (1-indexed).
    pub fn new(id: u32) -> Result<Self> {
        if id == 0 {
            return Err(FrostError::InvalidParticipant(
                "Identifier must be non-zero".into(),
            ));
        }
        Ok(Self(id))
    }

    /// Get the raw identifier value.
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Convert to scalar bytes for cryptographic operations.
    pub fn to_scalar_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[28..32].copy_from_slice(&self.0.to_be_bytes());
        bytes
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P{}", self.0)
    }
}

impl TryFrom<u32> for Identifier {
    type Error = FrostError;

    fn try_from(value: u32) -> Result<Self> {
        Self::new(value)
    }
}

impl From<Identifier> for u32 {
    fn from(id: Identifier) -> Self {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifier_creation() {
        assert!(Identifier::new(1).is_ok());
        assert!(Identifier::new(100).is_ok());
        assert!(Identifier::new(0).is_err());
    }

    #[test]
    fn test_identifier_value() {
        let id = Identifier::new(42).unwrap();
        assert_eq!(id.value(), 42);
    }

    #[test]
    fn test_identifier_display() {
        let id = Identifier::new(5).unwrap();
        assert_eq!(format!("{}", id), "P5");
    }

    #[test]
    fn test_identifier_scalar_bytes() {
        let id = Identifier::new(1).unwrap();
        let bytes = id.to_scalar_bytes();
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[0..28], [0u8; 28]);
    }
}
