//! Address to scripthash conversion utilities.
//!
//! Electrum protocol uses a reversed SHA256 hash of the scriptPubKey
//! to identify addresses. This module provides conversion functions.

use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use sha2::{Digest, Sha256};

use crate::error::{ElectrumError, Result};

/// Convert a Bitcoin address to Electrum scripthash format.
///
/// The scripthash is computed as:
/// 1. Parse address to get scriptPubKey
/// 2. SHA256 hash the scriptPubKey
/// 3. Reverse the bytes
/// 4. Encode as hex
///
/// # Arguments
/// * `address` - Bitcoin address string (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
///
/// # Returns
/// * `Ok(String)` - 64-character hex scripthash
/// * `Err(ElectrumError)` - If address is invalid
///
/// # Example
/// ```
/// use rustywallet_electrum::scripthash::address_to_scripthash;
///
/// let scripthash = address_to_scripthash("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
/// assert_eq!(scripthash.len(), 64);
/// ```
pub fn address_to_scripthash(address: &str) -> Result<String> {
    // Parse address (network-unchecked to support any network)
    let addr: Address<NetworkUnchecked> = address
        .parse()
        .map_err(|e| ElectrumError::InvalidAddress(format!("{}: {}", address, e)))?;

    // Get scriptPubKey - assume mainnet for script generation
    let script = addr.assume_checked().script_pubkey();

    // SHA256 hash
    let hash = Sha256::digest(script.as_bytes());

    // Reverse bytes and encode as hex
    let reversed: Vec<u8> = hash.iter().rev().cloned().collect();
    Ok(hex::encode(reversed))
}

/// Convert multiple addresses to scripthashes.
///
/// # Arguments
/// * `addresses` - Slice of Bitcoin address strings
///
/// # Returns
/// * `Ok(Vec<String>)` - Vector of scripthashes (same order as input)
/// * `Err(ElectrumError)` - If any address is invalid
pub fn addresses_to_scripthashes(addresses: &[&str]) -> Result<Vec<String>> {
    addresses.iter().map(|a| address_to_scripthash(a)).collect()
}

/// Validate that a string is a valid scripthash (64 hex chars).
pub fn is_valid_scripthash(scripthash: &str) -> bool {
    scripthash.len() == 64 && scripthash.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_address() {
        // Satoshi's genesis address
        let scripthash =
            address_to_scripthash("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(scripthash.len(), 64);
        // Known scripthash for this address
        assert_eq!(
            scripthash,
            "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161"
        );
    }

    #[test]
    fn test_p2sh_address() {
        // Example P2SH address
        let scripthash =
            address_to_scripthash("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        assert_eq!(scripthash.len(), 64);
    }

    #[test]
    fn test_p2wpkh_address() {
        // Example native SegWit address
        let scripthash =
            address_to_scripthash("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
        assert_eq!(scripthash.len(), 64);
    }

    #[test]
    fn test_p2tr_address() {
        // Example Taproot address
        let scripthash = address_to_scripthash(
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
        )
        .unwrap();
        assert_eq!(scripthash.len(), 64);
    }

    #[test]
    fn test_invalid_address() {
        let result = address_to_scripthash("invalid_address");
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_conversion() {
        let addresses = vec![
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        ];
        let scripthashes = addresses_to_scripthashes(&addresses).unwrap();
        assert_eq!(scripthashes.len(), 2);
    }

    #[test]
    fn test_valid_scripthash() {
        assert!(is_valid_scripthash(
            "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161"
        ));
        assert!(!is_valid_scripthash("invalid"));
        assert!(!is_valid_scripthash("8b01df4e368ea28f8dc0423bcf7a4923")); // too short
    }
}
