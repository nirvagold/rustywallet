//! Address type definitions and utilities.

use crate::error::PatternError;
use rustywallet_address::{
    EthereumAddress, Network as AddrNetwork, P2PKHAddress, P2TRAddress, P2WPKHAddress,
};
use rustywallet_keys::prelude::*;

/// Supported address types for vanity generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressType {
    /// Legacy P2PKH address (starts with 1 on mainnet).
    #[default]
    P2PKH,
    /// Native SegWit P2WPKH address (starts with bc1q on mainnet).
    P2WPKH,
    /// Taproot P2TR address (starts with bc1p on mainnet).
    P2TR,
    /// Ethereum address (starts with 0x).
    Ethereum,
}

impl AddressType {
    /// Get the valid characters for this address type's variable portion.
    pub fn valid_chars(&self) -> &'static str {
        match self {
            // Base58 alphabet (no 0, O, I, l)
            AddressType::P2PKH => "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            // Bech32 alphabet (lowercase only, no 1, b, i, o)
            AddressType::P2WPKH | AddressType::P2TR => "023456789acdefghjklmnpqrstuvwxyz",
            // Hex alphabet
            AddressType::Ethereum => "0123456789abcdefABCDEF",
        }
    }

    /// Get the fixed prefix for this address type on mainnet.
    pub fn fixed_prefix(&self, testnet: bool) -> &'static str {
        match (self, testnet) {
            (AddressType::P2PKH, false) => "1",
            (AddressType::P2PKH, true) => "m", // or 'n'
            (AddressType::P2WPKH, false) => "bc1q",
            (AddressType::P2WPKH, true) => "tb1q",
            (AddressType::P2TR, false) => "bc1p",
            (AddressType::P2TR, true) => "tb1p",
            (AddressType::Ethereum, _) => "0x",
        }
    }

    /// Validate that a pattern is compatible with this address type.
    pub fn validate_pattern(&self, pattern: &str, testnet: bool) -> Result<(), PatternError> {
        if pattern.is_empty() {
            return Err(PatternError::EmptyPattern);
        }

        let fixed_prefix = self.fixed_prefix(testnet);
        let valid_chars = self.valid_chars();

        // Check if pattern conflicts with fixed prefix
        if pattern.len() <= fixed_prefix.len() {
            // Pattern must match the beginning of fixed prefix
            let prefix_start = &fixed_prefix[..pattern.len().min(fixed_prefix.len())];
            if !prefix_start.eq_ignore_ascii_case(pattern) && !pattern.starts_with(prefix_start) {
                return Err(PatternError::ConflictsWithPrefix(
                    pattern.to_string(),
                    fixed_prefix.to_string(),
                ));
            }
        }

        // For patterns longer than fixed prefix, validate remaining chars
        if pattern.len() > fixed_prefix.len() {
            let variable_part = &pattern[fixed_prefix.len()..];
            for c in variable_part.chars() {
                // For case-insensitive matching, check both cases
                let c_lower = c.to_ascii_lowercase();
                let c_upper = c.to_ascii_uppercase();
                if !valid_chars.contains(c_lower) && !valid_chars.contains(c_upper) {
                    return Err(PatternError::InvalidCharacter(c));
                }
            }
        }

        // Warn about very long patterns
        if pattern.len() > fixed_prefix.len() + 8 {
            return Err(PatternError::PatternTooLong(
                pattern.len() - fixed_prefix.len(),
            ));
        }

        Ok(())
    }

    /// Derive an address from a private key.
    pub fn derive_address(&self, key: &PrivateKey, testnet: bool) -> Result<String, String> {
        let pubkey = key.public_key();
        let network = if testnet {
            AddrNetwork::BitcoinTestnet
        } else {
            AddrNetwork::BitcoinMainnet
        };

        match self {
            AddressType::P2PKH => P2PKHAddress::from_public_key(&pubkey, network)
                .map(|a| a.to_string())
                .map_err(|e| e.to_string()),
            AddressType::P2WPKH => P2WPKHAddress::from_public_key(&pubkey, network)
                .map(|a| a.to_string())
                .map_err(|e| e.to_string()),
            AddressType::P2TR => P2TRAddress::from_public_key(&pubkey, network)
                .map(|a| a.to_string())
                .map_err(|e| e.to_string()),
            AddressType::Ethereum => EthereumAddress::from_public_key(&pubkey)
                .map(|a| a.to_checksum_string())
                .map_err(|e| e.to_string()),
        }
    }
}

impl std::fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressType::P2PKH => write!(f, "P2PKH"),
            AddressType::P2WPKH => write!(f, "P2WPKH"),
            AddressType::P2TR => write!(f, "P2TR"),
            AddressType::Ethereum => write!(f, "Ethereum"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_prefixes() {
        assert_eq!(AddressType::P2PKH.fixed_prefix(false), "1");
        assert_eq!(AddressType::P2WPKH.fixed_prefix(false), "bc1q");
        assert_eq!(AddressType::P2TR.fixed_prefix(false), "bc1p");
        assert_eq!(AddressType::Ethereum.fixed_prefix(false), "0x");
    }

    #[test]
    fn test_validate_pattern_p2pkh() {
        // Valid patterns
        assert!(AddressType::P2PKH.validate_pattern("1Love", false).is_ok());
        assert!(AddressType::P2PKH.validate_pattern("1BTC", false).is_ok());

        // Invalid character (0 not in Base58)
        assert!(AddressType::P2PKH.validate_pattern("10", false).is_err());
    }

    #[test]
    fn test_validate_pattern_bech32() {
        // Valid patterns
        assert!(AddressType::P2WPKH
            .validate_pattern("bc1qtest", false)
            .is_ok());

        // Invalid - uppercase not allowed in bech32 variable part
        // Actually bech32 is case-insensitive but typically lowercase
    }

    #[test]
    fn test_derive_address() {
        let key = PrivateKey::random();

        let p2pkh = AddressType::P2PKH.derive_address(&key, false).unwrap();
        assert!(p2pkh.starts_with('1'));

        let p2wpkh = AddressType::P2WPKH.derive_address(&key, false).unwrap();
        assert!(p2wpkh.starts_with("bc1q"));

        let eth = AddressType::Ethereum.derive_address(&key, false).unwrap();
        assert!(eth.starts_with("0x"));
    }
}
