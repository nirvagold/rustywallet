//! JSON export functions.

use crate::error::{ExportError, Result};
use crate::types::{KeyExport, Network};
use crate::{export_wif, export_hex, HexOptions};
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_keys::public_key::PublicKeyFormat;
use rustywallet_address::{P2PKHAddress, Network as AddrNetwork};

/// Export a private key to JSON format.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::{export_json, Network};
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let key = PrivateKey::random();
/// let json = export_json(&key, Network::Mainnet).unwrap();
/// println!("{}", json);
/// ```
pub fn export_json(key: &PrivateKey, network: Network) -> Result<String> {
    let export = key_to_export(key, network)?;
    serde_json::to_string_pretty(&export)
        .map_err(|e| ExportError::SerializationFailed(e.to_string()))
}

/// Export multiple private keys to JSON array.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::{export_json_batch, Network};
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::random()).collect();
/// let json = export_json_batch(&keys, Network::Mainnet).unwrap();
/// println!("{}", json);
/// ```
pub fn export_json_batch(keys: &[PrivateKey], network: Network) -> Result<String> {
    let exports: Result<Vec<KeyExport>> = keys
        .iter()
        .map(|k| key_to_export(k, network))
        .collect();
    
    serde_json::to_string_pretty(&exports?)
        .map_err(|e| ExportError::SerializationFailed(e.to_string()))
}

/// Convert a key to KeyExport struct.
fn key_to_export(key: &PrivateKey, network: Network) -> Result<KeyExport> {
    let public_key = key.public_key();
    
    let addr_network = match network {
        Network::Mainnet => AddrNetwork::BitcoinMainnet,
        Network::Testnet => AddrNetwork::BitcoinTestnet,
    };
    
    let address = P2PKHAddress::from_public_key(&public_key, addr_network)
        .map_err(|e| ExportError::AddressError(e.to_string()))?
        .to_string();
    
    Ok(KeyExport {
        address,
        wif: export_wif(key, network, true),
        hex: export_hex(key, HexOptions::new()),
        public_key: public_key.to_hex(PublicKeyFormat::Compressed),
        network: network.to_string(),
        compressed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_export_json() {
        let key = PrivateKey::random();
        let json = export_json(&key, Network::Mainnet).unwrap();
        
        // Verify it's valid JSON
        let parsed: KeyExport = serde_json::from_str(&json).unwrap();
        assert!(parsed.address.starts_with('1'));
        assert!(parsed.wif.starts_with('K') || parsed.wif.starts_with('L'));
    }
    
    #[test]
    fn test_export_json_batch() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::random()).collect();
        let json = export_json_batch(&keys, Network::Mainnet).unwrap();
        
        // Verify it's valid JSON array
        let parsed: Vec<KeyExport> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 3);
    }
}
