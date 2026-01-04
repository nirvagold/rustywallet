//! PSBT export functionality.
//!
//! Export PSBTs with descriptor context.

use crate::error::{ExportError, Result};
use crate::types::Network;
use crate::descriptor::{export_descriptor, DescriptorType, DescriptorOptions};
use rustywallet_keys::prelude::PrivateKey;
use serde::{Deserialize, Serialize};

/// PSBT export with descriptor context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtExport {
    /// PSBT in base64 format
    pub psbt_base64: String,
    /// PSBT in hex format
    pub psbt_hex: String,
    /// Associated descriptor (if available)
    pub descriptor: Option<String>,
    /// Network
    pub network: String,
    /// Additional metadata
    pub metadata: PsbtMetadata,
}

/// PSBT metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PsbtMetadata {
    /// Number of inputs
    pub input_count: usize,
    /// Number of outputs
    pub output_count: usize,
    /// Total input value (if known)
    pub total_input_value: Option<u64>,
    /// Total output value (if known)
    pub total_output_value: Option<u64>,
    /// Fee (if calculable)
    pub fee: Option<u64>,
    /// Whether all inputs are signed
    pub fully_signed: bool,
    /// PSBT version
    pub version: u32,
}

/// Options for PSBT export.
#[derive(Debug, Clone)]
pub struct PsbtExportOptions {
    /// Network
    pub network: Network,
    /// Include descriptor in export
    pub include_descriptor: bool,
    /// Descriptor type (if including descriptor)
    pub descriptor_type: DescriptorType,
    /// Include hex format
    pub include_hex: bool,
}

impl Default for PsbtExportOptions {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            include_descriptor: true,
            descriptor_type: DescriptorType::Wpkh,
            include_hex: true,
        }
    }
}

impl PsbtExportOptions {
    /// Create new options with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set network.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Set include descriptor option.
    pub fn with_descriptor(mut self, include: bool) -> Self {
        self.include_descriptor = include;
        self
    }

    /// Set descriptor type.
    pub fn with_descriptor_type(mut self, desc_type: DescriptorType) -> Self {
        self.descriptor_type = desc_type;
        self
    }

    /// Set include hex option.
    pub fn with_hex(mut self, include: bool) -> Self {
        self.include_hex = include;
        self
    }
}

/// Export PSBT bytes with descriptor context.
///
/// # Example
///
/// ```rust,no_run
/// use rustywallet_export::psbt_export::{export_psbt, PsbtExportOptions};
///
/// let psbt_bytes = vec![0x70, 0x73, 0x62, 0x74, 0xff]; // PSBT magic
/// let result = export_psbt(&psbt_bytes, None, PsbtExportOptions::new());
/// ```
pub fn export_psbt(
    psbt_bytes: &[u8],
    signing_key: Option<&PrivateKey>,
    options: PsbtExportOptions,
) -> Result<PsbtExport> {
    // Validate PSBT magic
    if psbt_bytes.len() < 5 || &psbt_bytes[0..5] != b"psbt\xff" {
        return Err(ExportError::InvalidKey("Invalid PSBT: missing magic bytes".to_string()));
    }
    
    // Encode to base64
    let psbt_base64 = base64_encode(psbt_bytes);
    
    // Encode to hex
    let psbt_hex = if options.include_hex {
        hex_encode(psbt_bytes)
    } else {
        String::new()
    };
    
    // Generate descriptor if key provided and option enabled
    let descriptor = if options.include_descriptor {
        if let Some(key) = signing_key {
            let desc_options = DescriptorOptions::new()
                .with_network(options.network)
                .with_checksum(true);
            export_descriptor(key, options.descriptor_type, desc_options).ok()
        } else {
            None
        }
    } else {
        None
    };
    
    // Parse basic PSBT metadata
    let metadata = parse_psbt_metadata(psbt_bytes);
    
    Ok(PsbtExport {
        psbt_base64,
        psbt_hex,
        descriptor,
        network: options.network.to_string(),
        metadata,
    })
}

/// Export PSBT to JSON format with descriptor.
///
/// # Example
///
/// ```rust,no_run
/// use rustywallet_export::psbt_export::{export_psbt_json, PsbtExportOptions};
///
/// let psbt_bytes = vec![0x70, 0x73, 0x62, 0x74, 0xff];
/// let json = export_psbt_json(&psbt_bytes, None, PsbtExportOptions::new()).unwrap();
/// println!("{}", json);
/// ```
pub fn export_psbt_json(
    psbt_bytes: &[u8],
    signing_key: Option<&PrivateKey>,
    options: PsbtExportOptions,
) -> Result<String> {
    let export = export_psbt(psbt_bytes, signing_key, options)?;
    
    serde_json::to_string_pretty(&export)
        .map_err(|e| ExportError::SerializationFailed(e.to_string()))
}

/// Export PSBT to file-compatible format.
///
/// Returns a struct suitable for saving to a .psbt file or sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtFileExport {
    /// PSBT in base64 (standard format)
    pub psbt: String,
    /// Descriptor for the signing key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<String>,
    /// Label/name for the PSBT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Network
    pub network: String,
}

/// Export PSBT for file storage.
pub fn export_psbt_for_file(
    psbt_bytes: &[u8],
    signing_key: Option<&PrivateKey>,
    label: Option<&str>,
    options: PsbtExportOptions,
) -> Result<PsbtFileExport> {
    // Validate PSBT magic
    if psbt_bytes.len() < 5 || &psbt_bytes[0..5] != b"psbt\xff" {
        return Err(ExportError::InvalidKey("Invalid PSBT: missing magic bytes".to_string()));
    }
    
    let psbt_base64 = base64_encode(psbt_bytes);
    
    let descriptor = if options.include_descriptor {
        if let Some(key) = signing_key {
            let desc_options = DescriptorOptions::new()
                .with_network(options.network)
                .with_checksum(true);
            export_descriptor(key, options.descriptor_type, desc_options).ok()
        } else {
            None
        }
    } else {
        None
    };
    
    Ok(PsbtFileExport {
        psbt: psbt_base64,
        descriptor,
        label: label.map(|s| s.to_string()),
        network: options.network.to_string(),
    })
}

/// Combined export of descriptor and PSBT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorPsbtBundle {
    /// The descriptor
    pub descriptor: String,
    /// Associated PSBTs (if any)
    pub psbts: Vec<String>,
    /// Network
    pub network: String,
    /// Wallet label
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Export a descriptor with associated PSBTs.
pub fn export_descriptor_with_psbts(
    key: &PrivateKey,
    psbts: &[&[u8]],
    label: Option<&str>,
    options: PsbtExportOptions,
) -> Result<DescriptorPsbtBundle> {
    let desc_options = DescriptorOptions::new()
        .with_network(options.network)
        .with_checksum(true);
    
    let descriptor = export_descriptor(key, options.descriptor_type, desc_options)?;
    
    let mut psbt_strings = Vec::new();
    for psbt_bytes in psbts {
        if psbt_bytes.len() >= 5 && &psbt_bytes[0..5] == b"psbt\xff" {
            psbt_strings.push(base64_encode(psbt_bytes));
        }
    }
    
    Ok(DescriptorPsbtBundle {
        descriptor,
        psbts: psbt_strings,
        network: options.network.to_string(),
        label: label.map(|s| s.to_string()),
    })
}

// ============================================================================
// Helper functions
// ============================================================================

/// Base64 encode bytes.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = String::new();
    let mut i = 0;
    
    while i < bytes.len() {
        let b0 = bytes[i] as usize;
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] as usize } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] as usize } else { 0 };
        
        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if i + 1 < bytes.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        
        if i + 2 < bytes.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
        
        i += 3;
    }
    
    result
}

/// Hex encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Parse basic PSBT metadata from bytes.
fn parse_psbt_metadata(psbt_bytes: &[u8]) -> PsbtMetadata {
    // This is a simplified parser - just extracts basic info
    // A full implementation would parse the entire PSBT structure
    
    let mut metadata = PsbtMetadata::default();
    
    // Skip magic bytes
    if psbt_bytes.len() < 5 {
        return metadata;
    }
    
    // Try to count inputs and outputs by scanning for key-value separators
    // This is a heuristic - proper parsing would require full PSBT implementation
    let mut pos = 5;
    let mut in_global = true;
    let mut input_count = 0;
    let mut output_count = 0;
    
    while pos < psbt_bytes.len() {
        // Look for separator (0x00)
        if psbt_bytes[pos] == 0x00 {
            if in_global {
                in_global = false;
            } else if input_count == 0 || output_count > 0 {
                output_count += 1;
            } else {
                input_count += 1;
            }
        }
        pos += 1;
    }
    
    // Rough estimate based on structure
    metadata.input_count = input_count.max(1);
    metadata.output_count = output_count.max(1);
    metadata.version = 0; // PSBT v0
    
    metadata
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::prelude::PrivateKey;

    fn create_minimal_psbt() -> Vec<u8> {
        // Minimal valid PSBT structure
        let mut psbt = vec![0x70, 0x73, 0x62, 0x74, 0xff]; // magic
        
        // Global map with unsigned tx
        psbt.push(0x01); // key length
        psbt.push(0x00); // PSBT_GLOBAL_UNSIGNED_TX
        
        // Minimal unsigned tx
        let tx = vec![
            0x02, 0x00, 0x00, 0x00, // version
            0x00, // no inputs
            0x00, // no outputs
            0x00, 0x00, 0x00, 0x00, // locktime
        ];
        
        // Compact size for tx length
        psbt.push(tx.len() as u8);
        psbt.extend_from_slice(&tx);
        
        // End global map
        psbt.push(0x00);
        
        psbt
    }

    #[test]
    fn test_export_psbt_basic() {
        let psbt_bytes = create_minimal_psbt();
        let result = export_psbt(&psbt_bytes, None, PsbtExportOptions::new()).unwrap();
        
        assert!(!result.psbt_base64.is_empty());
        assert!(!result.psbt_hex.is_empty());
        assert!(result.descriptor.is_none()); // No key provided
    }

    #[test]
    fn test_export_psbt_with_key() {
        let psbt_bytes = create_minimal_psbt();
        let key = PrivateKey::random();
        let result = export_psbt(&psbt_bytes, Some(&key), PsbtExportOptions::new()).unwrap();
        
        assert!(result.descriptor.is_some());
        assert!(result.descriptor.unwrap().starts_with("wpkh("));
    }

    #[test]
    fn test_export_psbt_json() {
        let psbt_bytes = create_minimal_psbt();
        let json = export_psbt_json(&psbt_bytes, None, PsbtExportOptions::new()).unwrap();
        
        assert!(json.contains("psbt_base64"));
        assert!(json.contains("network"));
    }

    #[test]
    fn test_export_psbt_for_file() {
        let psbt_bytes = create_minimal_psbt();
        let key = PrivateKey::random();
        let result = export_psbt_for_file(
            &psbt_bytes, 
            Some(&key), 
            Some("Test PSBT"),
            PsbtExportOptions::new()
        ).unwrap();
        
        assert!(!result.psbt.is_empty());
        assert!(result.descriptor.is_some());
        assert_eq!(result.label, Some("Test PSBT".to_string()));
    }

    #[test]
    fn test_export_descriptor_with_psbts() {
        let psbt_bytes = create_minimal_psbt();
        let key = PrivateKey::random();
        let result = export_descriptor_with_psbts(
            &key,
            &[&psbt_bytes],
            Some("My Wallet"),
            PsbtExportOptions::new()
        ).unwrap();
        
        assert!(result.descriptor.starts_with("wpkh("));
        assert_eq!(result.psbts.len(), 1);
        assert_eq!(result.label, Some("My Wallet".to_string()));
    }

    #[test]
    fn test_invalid_psbt() {
        let invalid = vec![0x00, 0x01, 0x02];
        let result = export_psbt(&invalid, None, PsbtExportOptions::new());
        
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_encode() {
        let data = b"psbt";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "cHNidA==");
    }

    #[test]
    fn test_hex_encode() {
        let data = vec![0x70, 0x73, 0x62, 0x74];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "70736274");
    }
}
