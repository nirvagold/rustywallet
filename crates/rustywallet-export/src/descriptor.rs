//! Descriptor export functionality.
//!
//! Generate output descriptor strings with checksum.

use crate::error::{ExportError, Result};
use crate::types::Network;
use rustywallet_keys::prelude::PrivateKey;

/// Options for descriptor export.
#[derive(Debug, Clone)]
pub struct DescriptorOptions {
    /// Network for the descriptor
    pub network: Network,
    /// Include checksum in output
    pub include_checksum: bool,
    /// Use extended key format (xpub/xprv) if available
    pub use_extended_key: bool,
}

impl Default for DescriptorOptions {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            include_checksum: true,
            use_extended_key: false,
        }
    }
}

impl DescriptorOptions {
    /// Create new options with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set network.
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Set checksum option.
    pub fn with_checksum(mut self, include: bool) -> Self {
        self.include_checksum = include;
        self
    }

    /// Set extended key option.
    pub fn with_extended_key(mut self, use_extended: bool) -> Self {
        self.use_extended_key = use_extended;
        self
    }
}

/// Descriptor type for export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorType {
    /// pk(KEY) - Pay to pubkey (bare)
    Pk,
    /// pkh(KEY) - Pay to pubkey hash (P2PKH)
    Pkh,
    /// wpkh(KEY) - Pay to witness pubkey hash (P2WPKH)
    Wpkh,
    /// sh(wpkh(KEY)) - Pay to script hash wrapping witness pubkey hash
    ShWpkh,
    /// tr(KEY) - Pay to Taproot (key path only)
    Tr,
}

impl std::fmt::Display for DescriptorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DescriptorType::Pk => write!(f, "pk"),
            DescriptorType::Pkh => write!(f, "pkh"),
            DescriptorType::Wpkh => write!(f, "wpkh"),
            DescriptorType::ShWpkh => write!(f, "sh(wpkh)"),
            DescriptorType::Tr => write!(f, "tr"),
        }
    }
}

/// Export a private key as a descriptor string.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::descriptor::{export_descriptor, DescriptorType, DescriptorOptions};
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let key = PrivateKey::random();
/// let desc = export_descriptor(&key, DescriptorType::Wpkh, DescriptorOptions::new()).unwrap();
/// assert!(desc.starts_with("wpkh("));
/// ```
pub fn export_descriptor(
    key: &PrivateKey,
    desc_type: DescriptorType,
    options: DescriptorOptions,
) -> Result<String> {
    use rustywallet_keys::public_key::PublicKeyFormat;
    
    let pubkey = key.public_key();
    let pubkey_hex = pubkey.to_hex(PublicKeyFormat::Compressed);
    
    let descriptor = match desc_type {
        DescriptorType::Pk => format!("pk({})", pubkey_hex),
        DescriptorType::Pkh => format!("pkh({})", pubkey_hex),
        DescriptorType::Wpkh => format!("wpkh({})", pubkey_hex),
        DescriptorType::ShWpkh => format!("sh(wpkh({}))", pubkey_hex),
        DescriptorType::Tr => format!("tr({})", pubkey_hex),
    };
    
    if options.include_checksum {
        Ok(add_checksum(&descriptor))
    } else {
        Ok(descriptor)
    }
}

/// Export a public key hex as a descriptor string.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::descriptor::{export_pubkey_descriptor, DescriptorType, DescriptorOptions};
///
/// let pubkey_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
/// let desc = export_pubkey_descriptor(pubkey_hex, DescriptorType::Wpkh, DescriptorOptions::new()).unwrap();
/// assert!(desc.starts_with("wpkh("));
/// ```
pub fn export_pubkey_descriptor(
    pubkey_hex: &str,
    desc_type: DescriptorType,
    options: DescriptorOptions,
) -> Result<String> {
    // Validate pubkey hex
    if !is_valid_pubkey_hex(pubkey_hex) {
        return Err(ExportError::InvalidKey(
            "Invalid public key hex".to_string()
        ));
    }
    
    let descriptor = match desc_type {
        DescriptorType::Pk => format!("pk({})", pubkey_hex),
        DescriptorType::Pkh => format!("pkh({})", pubkey_hex),
        DescriptorType::Wpkh => format!("wpkh({})", pubkey_hex),
        DescriptorType::ShWpkh => format!("sh(wpkh({}))", pubkey_hex),
        DescriptorType::Tr => format!("tr({})", pubkey_hex),
    };
    
    if options.include_checksum {
        Ok(add_checksum(&descriptor))
    } else {
        Ok(descriptor)
    }
}

/// Export a multisig descriptor.
///
/// # Example
///
/// ```rust
/// use rustywallet_export::descriptor::{export_multisig_descriptor, DescriptorOptions};
///
/// let pubkeys = vec![
///     "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
///     "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
/// ];
/// let desc = export_multisig_descriptor(2, &pubkeys, false, DescriptorOptions::new()).unwrap();
/// assert!(desc.starts_with("multi(2,"));
/// ```
pub fn export_multisig_descriptor(
    threshold: usize,
    pubkeys: &[&str],
    sorted: bool,
    options: DescriptorOptions,
) -> Result<String> {
    if threshold == 0 || threshold > pubkeys.len() {
        return Err(ExportError::InvalidKey(
            format!("Invalid threshold: {} of {}", threshold, pubkeys.len())
        ));
    }
    
    // Validate all pubkeys
    for pubkey in pubkeys {
        if !is_valid_pubkey_hex(pubkey) {
            return Err(ExportError::InvalidKey(
                format!("Invalid public key hex: {}", pubkey)
            ));
        }
    }
    
    let func_name = if sorted { "sortedmulti" } else { "multi" };
    let keys_str = pubkeys.join(",");
    let descriptor = format!("{}({},{})", func_name, threshold, keys_str);
    
    if options.include_checksum {
        Ok(add_checksum(&descriptor))
    } else {
        Ok(descriptor)
    }
}

/// Export a wrapped multisig descriptor (wsh or sh).
///
/// # Example
///
/// ```rust
/// use rustywallet_export::descriptor::{export_wrapped_multisig_descriptor, DescriptorOptions};
///
/// let pubkeys = vec![
///     "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
///     "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
/// ];
/// let desc = export_wrapped_multisig_descriptor(2, &pubkeys, true, true, DescriptorOptions::new()).unwrap();
/// assert!(desc.starts_with("wsh(sortedmulti(2,"));
/// ```
pub fn export_wrapped_multisig_descriptor(
    threshold: usize,
    pubkeys: &[&str],
    sorted: bool,
    witness: bool,
    options: DescriptorOptions,
) -> Result<String> {
    if threshold == 0 || threshold > pubkeys.len() {
        return Err(ExportError::InvalidKey(
            format!("Invalid threshold: {} of {}", threshold, pubkeys.len())
        ));
    }
    
    // Validate all pubkeys
    for pubkey in pubkeys {
        if !is_valid_pubkey_hex(pubkey) {
            return Err(ExportError::InvalidKey(
                format!("Invalid public key hex: {}", pubkey)
            ));
        }
    }
    
    let func_name = if sorted { "sortedmulti" } else { "multi" };
    let keys_str = pubkeys.join(",");
    let inner = format!("{}({},{})", func_name, threshold, keys_str);
    
    let descriptor = if witness {
        format!("wsh({})", inner)
    } else {
        format!("sh({})", inner)
    };
    
    if options.include_checksum {
        Ok(add_checksum(&descriptor))
    } else {
        Ok(descriptor)
    }
}

/// Exported descriptor with metadata.
#[derive(Debug, Clone)]
pub struct DescriptorExport {
    /// The descriptor string (with or without checksum)
    pub descriptor: String,
    /// The descriptor type
    pub descriptor_type: DescriptorType,
    /// The checksum (if included)
    pub checksum: Option<String>,
    /// Network
    pub network: Network,
}

/// Export a key with full metadata.
pub fn export_descriptor_with_metadata(
    key: &PrivateKey,
    desc_type: DescriptorType,
    options: DescriptorOptions,
) -> Result<DescriptorExport> {
    use rustywallet_keys::public_key::PublicKeyFormat;
    
    let pubkey = key.public_key();
    let pubkey_hex = pubkey.to_hex(PublicKeyFormat::Compressed);
    
    let descriptor_without_checksum = match desc_type {
        DescriptorType::Pk => format!("pk({})", pubkey_hex),
        DescriptorType::Pkh => format!("pkh({})", pubkey_hex),
        DescriptorType::Wpkh => format!("wpkh({})", pubkey_hex),
        DescriptorType::ShWpkh => format!("sh(wpkh({}))", pubkey_hex),
        DescriptorType::Tr => format!("tr({})", pubkey_hex),
    };
    
    let (descriptor, checksum) = if options.include_checksum {
        let cs = compute_checksum(&descriptor_without_checksum);
        let desc = format!("{}#{}", descriptor_without_checksum, cs);
        (desc, Some(cs))
    } else {
        (descriptor_without_checksum, None)
    };
    
    Ok(DescriptorExport {
        descriptor,
        descriptor_type: desc_type,
        checksum,
        network: options.network,
    })
}

/// Validate a public key hex string.
fn is_valid_pubkey_hex(s: &str) -> bool {
    // Compressed: 02/03 + 64 hex = 66 chars
    // Uncompressed: 04 + 128 hex = 130 chars
    let len = s.len();
    
    if len == 66 {
        (s.starts_with("02") || s.starts_with("03")) && 
        s.chars().all(|c| c.is_ascii_hexdigit())
    } else if len == 130 {
        s.starts_with("04") && s.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        false
    }
}

// ============================================================================
// Checksum implementation (BIP380)
// ============================================================================

/// Character set for descriptor checksum (same as bech32)
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Generator coefficients for the checksum polynomial
const GENERATOR: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

/// Compute the polymod for the checksum
fn polymod(values: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for v in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x7ffffffff) << 5) ^ (*v as u64);
        for (i, gen) in GENERATOR.iter().enumerate() {
            if (c0 >> i) & 1 != 0 {
                c ^= gen;
            }
        }
    }
    c
}

/// Convert descriptor string to checksum input values
fn descriptor_to_values(desc: &str) -> Vec<u8> {
    let mut values = Vec::new();
    
    for c in desc.chars() {
        let cp = c as u32;
        if cp > 127 {
            // Non-ASCII character
            values.push((cp >> 8) as u8);
            values.push((cp & 0xff) as u8);
        } else {
            values.push(cp as u8 & 31);
            values.push(cp as u8 >> 5);
        }
    }
    
    values
}

/// Compute the checksum for a descriptor string (without existing checksum)
pub fn compute_checksum(descriptor: &str) -> String {
    let mut values = descriptor_to_values(descriptor);
    
    // Append 8 zeros for checksum computation
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    
    let plm = polymod(&values) ^ 1;
    
    let mut checksum = String::with_capacity(8);
    for i in 0..8 {
        let idx = ((plm >> (5 * (7 - i))) & 31) as usize;
        checksum.push(CHECKSUM_CHARSET[idx] as char);
    }
    
    checksum
}

/// Add checksum to a descriptor string
pub fn add_checksum(descriptor: &str) -> String {
    let checksum = compute_checksum(descriptor);
    format!("{}#{}", descriptor, checksum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::prelude::PrivateKey;

    #[test]
    fn test_export_wpkh_descriptor() {
        let key = PrivateKey::random();
        let desc = export_descriptor(&key, DescriptorType::Wpkh, DescriptorOptions::new()).unwrap();
        
        assert!(desc.starts_with("wpkh("));
        assert!(desc.contains('#')); // Has checksum
    }

    #[test]
    fn test_export_without_checksum() {
        let key = PrivateKey::random();
        let options = DescriptorOptions::new().with_checksum(false);
        let desc = export_descriptor(&key, DescriptorType::Wpkh, options).unwrap();
        
        assert!(desc.starts_with("wpkh("));
        assert!(!desc.contains('#')); // No checksum
    }

    #[test]
    fn test_export_taproot_descriptor() {
        let key = PrivateKey::random();
        let desc = export_descriptor(&key, DescriptorType::Tr, DescriptorOptions::new()).unwrap();
        
        assert!(desc.starts_with("tr("));
    }

    #[test]
    fn test_export_pubkey_descriptor() {
        let pubkey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let desc = export_pubkey_descriptor(pubkey, DescriptorType::Wpkh, DescriptorOptions::new()).unwrap();
        
        assert!(desc.contains(pubkey));
    }

    #[test]
    fn test_export_multisig_descriptor() {
        let pubkeys = vec![
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ];
        let desc = export_multisig_descriptor(2, &pubkeys, false, DescriptorOptions::new()).unwrap();
        
        assert!(desc.starts_with("multi(2,"));
    }

    #[test]
    fn test_export_sorted_multisig_descriptor() {
        let pubkeys = vec![
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ];
        let desc = export_multisig_descriptor(2, &pubkeys, true, DescriptorOptions::new()).unwrap();
        
        assert!(desc.starts_with("sortedmulti(2,"));
    }

    #[test]
    fn test_export_wrapped_multisig() {
        let pubkeys = vec![
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ];
        let desc = export_wrapped_multisig_descriptor(2, &pubkeys, true, true, DescriptorOptions::new()).unwrap();
        
        assert!(desc.starts_with("wsh(sortedmulti(2,"));
    }

    #[test]
    fn test_invalid_threshold() {
        let pubkeys = vec![
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        ];
        let result = export_multisig_descriptor(2, &pubkeys, false, DescriptorOptions::new());
        
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pubkey() {
        let result = export_pubkey_descriptor("invalid", DescriptorType::Wpkh, DescriptorOptions::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum_computation() {
        let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let checksum = compute_checksum(desc);
        
        assert_eq!(checksum.len(), 8);
    }

    #[test]
    fn test_descriptor_with_metadata() {
        let key = PrivateKey::random();
        let export = export_descriptor_with_metadata(&key, DescriptorType::Wpkh, DescriptorOptions::new()).unwrap();
        
        assert_eq!(export.descriptor_type, DescriptorType::Wpkh);
        assert!(export.checksum.is_some());
        assert_eq!(export.network, Network::Mainnet);
    }
}
