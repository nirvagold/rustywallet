//! Wallet format import functionality.
//!
//! Import from common wallet formats like Electrum and Sparrow.

use crate::error::{ImportError, Result};
use crate::descriptor::{import_descriptor, DescriptorImport};

/// Supported wallet formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletFormat {
    /// Electrum wallet format
    Electrum,
    /// Sparrow wallet format
    Sparrow,
    /// Bitcoin Core wallet format
    BitcoinCore,
    /// Generic JSON format
    GenericJson,
}

impl std::fmt::Display for WalletFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletFormat::Electrum => write!(f, "Electrum"),
            WalletFormat::Sparrow => write!(f, "Sparrow"),
            WalletFormat::BitcoinCore => write!(f, "Bitcoin Core"),
            WalletFormat::GenericJson => write!(f, "Generic JSON"),
        }
    }
}

/// Result of importing a wallet file.
#[derive(Debug, Clone)]
pub struct WalletImport {
    /// Detected wallet format
    pub format: WalletFormat,
    /// Wallet name (if available)
    pub name: Option<String>,
    /// Imported descriptors
    pub descriptors: Vec<DescriptorImport>,
    /// Master fingerprint (if available)
    pub master_fingerprint: Option<String>,
    /// Network (mainnet/testnet)
    pub network: Option<String>,
    /// Additional metadata
    pub metadata: WalletMetadata,
}

/// Additional wallet metadata.
#[derive(Debug, Clone, Default)]
pub struct WalletMetadata {
    /// Wallet type (e.g., "standard", "2of3", etc.)
    pub wallet_type: Option<String>,
    /// Gap limit for address derivation
    pub gap_limit: Option<u32>,
    /// Whether the wallet is watch-only
    pub watch_only: bool,
    /// Creation timestamp
    pub created_at: Option<String>,
}

/// Import from Electrum wallet JSON format.
///
/// Electrum wallets store descriptors in a JSON format with keystore information.
///
/// # Example
///
/// ```rust,no_run
/// use rustywallet_import::wallet_format::import_electrum_wallet;
///
/// let json = r#"{"wallet_type": "standard", "keystore": {"type": "bip32", "xpub": "xpub..."}}"#;
/// let result = import_electrum_wallet(json);
/// ```
pub fn import_electrum_wallet(json_str: &str) -> Result<WalletImport> {
    // Parse JSON
    let json: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| ImportError::InvalidFormat(format!("Invalid JSON: {}", e)))?;
    
    let mut descriptors = Vec::new();
    let mut metadata = WalletMetadata::default();
    
    // Extract wallet type
    let wallet_type = json.get("wallet_type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    metadata.wallet_type = wallet_type.clone();
    
    // Check if watch-only
    metadata.watch_only = json.get("keystore")
        .and_then(|ks| ks.get("type"))
        .and_then(|t| t.as_str())
        .map(|t| t == "imported" || t == "hardware")
        .unwrap_or(false);
    
    // Extract gap limit
    metadata.gap_limit = json.get("gap_limit")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    
    // Extract keystore
    if let Some(keystore) = json.get("keystore") {
        // Try to get xpub
        if let Some(xpub) = keystore.get("xpub").and_then(|v| v.as_str()) {
            // Determine descriptor type based on wallet type
            let desc_type = match wallet_type.as_deref() {
                Some("standard") => "pkh",
                Some("p2wpkh") | Some("segwit") => "wpkh",
                Some("p2wpkh-p2sh") => "sh(wpkh",
                Some("p2tr") | Some("taproot") => "tr",
                _ => "wpkh", // Default to native segwit
            };
            
            // Build descriptor
            let derivation = keystore.get("derivation")
                .and_then(|v| v.as_str())
                .unwrap_or("m/84'/0'/0'");
            
            // Create receive descriptor
            let receive_desc = if desc_type == "sh(wpkh" {
                format!("sh(wpkh([{}]{}/0/*)))", 
                    keystore.get("root_fingerprint").and_then(|v| v.as_str()).unwrap_or("00000000"),
                    xpub)
            } else {
                format!("{}([{}]{}/0/*)", desc_type,
                    keystore.get("root_fingerprint").and_then(|v| v.as_str()).unwrap_or("00000000"),
                    xpub)
            };
            
            if let Ok(desc) = import_descriptor(&receive_desc) {
                descriptors.push(desc);
            }
            
            // Create change descriptor
            let change_desc = if desc_type == "sh(wpkh" {
                format!("sh(wpkh([{}]{}/1/*)))", 
                    keystore.get("root_fingerprint").and_then(|v| v.as_str()).unwrap_or("00000000"),
                    xpub)
            } else {
                format!("{}([{}]{}/1/*)", desc_type,
                    keystore.get("root_fingerprint").and_then(|v| v.as_str()).unwrap_or("00000000"),
                    xpub)
            };
            
            if let Ok(desc) = import_descriptor(&change_desc) {
                descriptors.push(desc);
            }
        }
    }
    
    // Extract master fingerprint
    let master_fingerprint = json.get("keystore")
        .and_then(|ks| ks.get("root_fingerprint"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    Ok(WalletImport {
        format: WalletFormat::Electrum,
        name: json.get("wallet_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
        descriptors,
        master_fingerprint,
        network: None,
        metadata,
    })
}

/// Import from Sparrow wallet JSON format.
///
/// Sparrow uses a different JSON structure with explicit descriptor fields.
///
/// # Example
///
/// ```rust,no_run
/// use rustywallet_import::wallet_format::import_sparrow_wallet;
///
/// let json = r#"{"label": "My Wallet", "descriptor": "wpkh([fingerprint/84'/0'/0']xpub.../0/*)"}"#;
/// let result = import_sparrow_wallet(json);
/// ```
pub fn import_sparrow_wallet(json_str: &str) -> Result<WalletImport> {
    // Parse JSON
    let json: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| ImportError::InvalidFormat(format!("Invalid JSON: {}", e)))?;
    
    let mut descriptors = Vec::new();
    let mut metadata = WalletMetadata::default();
    
    // Extract wallet name/label
    let name = json.get("label")
        .or_else(|| json.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    // Check if watch-only
    metadata.watch_only = json.get("watchOnly")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    
    // Extract gap limit
    metadata.gap_limit = json.get("gapLimit")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    
    // Extract descriptors - Sparrow stores them directly
    if let Some(desc_str) = json.get("descriptor").and_then(|v| v.as_str()) {
        if let Ok(desc) = import_descriptor(desc_str) {
            descriptors.push(desc);
        }
    }
    
    // Also check for receive/change descriptors
    if let Some(receive) = json.get("receiveDescriptor").and_then(|v| v.as_str()) {
        if let Ok(desc) = import_descriptor(receive) {
            descriptors.push(desc);
        }
    }
    
    if let Some(change) = json.get("changeDescriptor").and_then(|v| v.as_str()) {
        if let Ok(desc) = import_descriptor(change) {
            descriptors.push(desc);
        }
    }
    
    // Extract keystores array (for multisig)
    if let Some(keystores) = json.get("keystores").and_then(|v| v.as_array()) {
        for ks in keystores {
            if let Some(xpub) = ks.get("xpub").and_then(|v| v.as_str()) {
                // Try to build a descriptor from the keystore
                let fingerprint = ks.get("masterFingerprint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("00000000");
                let derivation = ks.get("keyDerivation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("84'/0'/0'");
                
                let desc_str = format!("wpkh([{}/{}]{}/0/*)", fingerprint, derivation, xpub);
                if let Ok(desc) = import_descriptor(&desc_str) {
                    descriptors.push(desc);
                }
            }
        }
    }
    
    // Extract master fingerprint
    let master_fingerprint = json.get("masterFingerprint")
        .or_else(|| json.get("keystores")
            .and_then(|ks| ks.get(0))
            .and_then(|k| k.get("masterFingerprint")))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    // Extract network
    let network = json.get("network")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    Ok(WalletImport {
        format: WalletFormat::Sparrow,
        name,
        descriptors,
        master_fingerprint,
        network,
        metadata,
    })
}

/// Import from Bitcoin Core wallet dump format.
///
/// Bitcoin Core uses a specific format for wallet dumps.
pub fn import_bitcoin_core_wallet(json_str: &str) -> Result<WalletImport> {
    // Parse JSON
    let json: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| ImportError::InvalidFormat(format!("Invalid JSON: {}", e)))?;
    
    let mut descriptors = Vec::new();
    let metadata = WalletMetadata::default();
    
    // Bitcoin Core stores descriptors in an array
    if let Some(desc_array) = json.get("descriptors").and_then(|v| v.as_array()) {
        for desc_obj in desc_array {
            if let Some(desc_str) = desc_obj.get("desc").and_then(|v| v.as_str()) {
                if let Ok(desc) = import_descriptor(desc_str) {
                    descriptors.push(desc);
                }
            }
        }
    }
    
    // Also check for single descriptor
    if let Some(desc_str) = json.get("descriptor").and_then(|v| v.as_str()) {
        if let Ok(desc) = import_descriptor(desc_str) {
            descriptors.push(desc);
        }
    }
    
    let name = json.get("name")
        .or_else(|| json.get("label"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    Ok(WalletImport {
        format: WalletFormat::BitcoinCore,
        name,
        descriptors,
        master_fingerprint: None,
        network: None,
        metadata,
    })
}

/// Auto-detect wallet format and import.
///
/// Tries to detect the wallet format from the JSON structure.
///
/// # Example
///
/// ```rust,no_run
/// use rustywallet_import::wallet_format::import_wallet_auto;
///
/// let json = r#"{"wallet_type": "standard", "keystore": {...}}"#;
/// let result = import_wallet_auto(json);
/// ```
pub fn import_wallet_auto(json_str: &str) -> Result<WalletImport> {
    // Parse JSON first to detect format
    let json: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| ImportError::InvalidFormat(format!("Invalid JSON: {}", e)))?;
    
    // Detect format based on JSON structure
    let format = detect_wallet_format(&json);
    
    match format {
        WalletFormat::Electrum => import_electrum_wallet(json_str),
        WalletFormat::Sparrow => import_sparrow_wallet(json_str),
        WalletFormat::BitcoinCore => import_bitcoin_core_wallet(json_str),
        WalletFormat::GenericJson => {
            // Try each format
            if let Ok(result) = import_electrum_wallet(json_str) {
                if !result.descriptors.is_empty() {
                    return Ok(result);
                }
            }
            if let Ok(result) = import_sparrow_wallet(json_str) {
                if !result.descriptors.is_empty() {
                    return Ok(result);
                }
            }
            if let Ok(result) = import_bitcoin_core_wallet(json_str) {
                if !result.descriptors.is_empty() {
                    return Ok(result);
                }
            }
            
            Err(ImportError::InvalidFormat(
                "Could not detect wallet format or extract descriptors".to_string()
            ))
        }
    }
}

/// Detect wallet format from JSON structure.
fn detect_wallet_format(json: &serde_json::Value) -> WalletFormat {
    // Electrum: has "wallet_type" and "keystore"
    if json.get("wallet_type").is_some() && json.get("keystore").is_some() {
        return WalletFormat::Electrum;
    }
    
    // Sparrow: has "keystores" array or specific Sparrow fields
    if json.get("keystores").is_some() || 
       (json.get("label").is_some() && json.get("descriptor").is_some()) {
        return WalletFormat::Sparrow;
    }
    
    // Bitcoin Core: has "descriptors" array with "desc" fields
    if let Some(descs) = json.get("descriptors").and_then(|v| v.as_array()) {
        if descs.iter().any(|d| d.get("desc").is_some()) {
            return WalletFormat::BitcoinCore;
        }
    }
    
    WalletFormat::GenericJson
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detect_electrum_format() {
        let json = r#"{"wallet_type": "standard", "keystore": {"type": "bip32"}}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(detect_wallet_format(&parsed), WalletFormat::Electrum);
    }
    
    #[test]
    fn test_detect_sparrow_format() {
        let json = r#"{"label": "My Wallet", "descriptor": "wpkh(...)"}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(detect_wallet_format(&parsed), WalletFormat::Sparrow);
    }
    
    #[test]
    fn test_detect_bitcoin_core_format() {
        let json = r#"{"descriptors": [{"desc": "wpkh(...)"}]}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(detect_wallet_format(&parsed), WalletFormat::BitcoinCore);
    }
    
    #[test]
    fn test_import_sparrow_simple() {
        let json = r#"{
            "label": "Test Wallet",
            "descriptor": "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
            "watchOnly": true
        }"#;
        
        let result = import_sparrow_wallet(json).unwrap();
        assert_eq!(result.format, WalletFormat::Sparrow);
        assert_eq!(result.name, Some("Test Wallet".to_string()));
        assert!(result.metadata.watch_only);
        assert_eq!(result.descriptors.len(), 1);
    }
    
    #[test]
    fn test_import_bitcoin_core_simple() {
        let json = r#"{
            "name": "Core Wallet",
            "descriptors": [
                {"desc": "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"}
            ]
        }"#;
        
        let result = import_bitcoin_core_wallet(json).unwrap();
        assert_eq!(result.format, WalletFormat::BitcoinCore);
        assert_eq!(result.name, Some("Core Wallet".to_string()));
        assert_eq!(result.descriptors.len(), 1);
    }
    
    #[test]
    fn test_wallet_format_display() {
        assert_eq!(WalletFormat::Electrum.to_string(), "Electrum");
        assert_eq!(WalletFormat::Sparrow.to_string(), "Sparrow");
        assert_eq!(WalletFormat::BitcoinCore.to_string(), "Bitcoin Core");
    }
}
