//! WIF export functions.

use crate::types::Network;
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_keys::prelude::Network as KeysNetwork;
use sha2::{Sha256, Digest};

/// Export a private key to WIF format.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::{export_wif, Network};
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let key = PrivateKey::random();
///
/// // Compressed mainnet WIF (starts with K or L)
/// let wif = export_wif(&key, Network::Mainnet, true);
/// assert!(wif.starts_with('K') || wif.starts_with('L'));
///
/// // Uncompressed mainnet WIF (starts with 5)
/// let wif = export_wif(&key, Network::Mainnet, false);
/// assert!(wif.starts_with('5'));
/// ```
pub fn export_wif(key: &PrivateKey, network: Network, compressed: bool) -> String {
    let keys_network = match network {
        Network::Mainnet => KeysNetwork::Mainnet,
        Network::Testnet => KeysNetwork::Testnet,
    };
    
    if compressed {
        key.to_wif(keys_network)
    } else {
        // Manual WIF encoding for uncompressed
        encode_wif_uncompressed(&key.to_bytes(), keys_network)
    }
}

/// Encode WIF for uncompressed key.
fn encode_wif_uncompressed(key: &[u8; 32], network: KeysNetwork) -> String {
    let version = match network {
        KeysNetwork::Mainnet => 0x80,
        KeysNetwork::Testnet => 0xEF,
    };
    
    // Build payload: version + key (no compression flag)
    let mut payload = Vec::with_capacity(37);
    payload.push(version);
    payload.extend_from_slice(key);
    
    // Add checksum
    let hash1 = Sha256::digest(&payload);
    let hash2 = Sha256::digest(hash1);
    payload.extend_from_slice(&hash2[0..4]);
    
    bs58::encode(payload).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_export_wif_compressed_mainnet() {
        let key = PrivateKey::random();
        let wif = export_wif(&key, Network::Mainnet, true);
        assert!(wif.starts_with('K') || wif.starts_with('L'));
        assert_eq!(wif.len(), 52);
    }
    
    #[test]
    fn test_export_wif_uncompressed_mainnet() {
        let key = PrivateKey::random();
        let wif = export_wif(&key, Network::Mainnet, false);
        assert!(wif.starts_with('5'));
        assert_eq!(wif.len(), 51);
    }
    
    #[test]
    fn test_export_wif_compressed_testnet() {
        let key = PrivateKey::random();
        let wif = export_wif(&key, Network::Testnet, true);
        assert!(wif.starts_with('c'));
    }
    
    #[test]
    fn test_export_wif_uncompressed_testnet() {
        let key = PrivateKey::random();
        let wif = export_wif(&key, Network::Testnet, false);
        assert!(wif.starts_with('9'));
    }
}
