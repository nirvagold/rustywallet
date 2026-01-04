//! Descriptor import functionality.
//!
//! Parse output descriptor strings and extract keys/scripts.

use crate::error::{ImportError, Result};
use rustywallet_descriptor::{
    Descriptor, verify_checksum,
};

/// Result of importing a descriptor.
#[derive(Debug, Clone)]
pub struct DescriptorImport {
    /// The parsed descriptor
    pub descriptor: Descriptor,
    /// Descriptor string (without checksum)
    pub descriptor_string: String,
    /// Descriptor type (pkh, wpkh, sh, wsh, tr, etc.)
    pub descriptor_type: String,
    /// Whether the descriptor has a wildcard (ranged)
    pub is_ranged: bool,
    /// Whether the descriptor is SegWit
    pub is_segwit: bool,
    /// Whether the descriptor is Taproot
    pub is_taproot: bool,
    /// Extracted keys from the descriptor
    pub keys: Vec<ExtractedKey>,
    /// Checksum (if present in original)
    pub checksum: Option<String>,
}

/// A key extracted from a descriptor.
#[derive(Debug, Clone)]
pub struct ExtractedKey {
    /// Key type (pubkey, xpub, xprv, etc.)
    pub key_type: KeyType,
    /// Key data as string
    pub key_data: String,
    /// Key origin (if present)
    pub origin: Option<String>,
    /// Derivation path suffix (if present)
    pub derivation_path: Option<String>,
    /// Whether this key has a wildcard
    pub has_wildcard: bool,
}

/// Type of key in a descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Raw public key (compressed or uncompressed)
    PublicKey,
    /// Extended public key (xpub, ypub, zpub, etc.)
    ExtendedPublicKey,
    /// Extended private key (xprv, yprv, zprv, etc.)
    ExtendedPrivateKey,
    /// X-only public key (for Taproot)
    XOnlyPublicKey,
    /// WIF private key
    WifPrivateKey,
    /// Hex private key
    HexPrivateKey,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::PublicKey => write!(f, "pubkey"),
            KeyType::ExtendedPublicKey => write!(f, "xpub"),
            KeyType::ExtendedPrivateKey => write!(f, "xprv"),
            KeyType::XOnlyPublicKey => write!(f, "x-only"),
            KeyType::WifPrivateKey => write!(f, "wif"),
            KeyType::HexPrivateKey => write!(f, "hex"),
        }
    }
}

/// Import a descriptor string.
///
/// Parses the descriptor and extracts all keys and metadata.
///
/// # Example
///
/// ```rust
/// use rustywallet_import::descriptor::import_descriptor;
///
/// let result = import_descriptor(
///     "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
/// ).unwrap();
///
/// assert_eq!(result.descriptor_type, "wpkh");
/// assert!(!result.is_ranged);
/// assert!(result.is_segwit);
/// ```
pub fn import_descriptor(descriptor_str: &str) -> Result<DescriptorImport> {
    let descriptor_str = descriptor_str.trim();
    
    // Check for checksum
    let (desc_without_checksum, checksum) = if descriptor_str.contains('#') {
        let parts: Vec<&str> = descriptor_str.splitn(2, '#').collect();
        if parts.len() == 2 {
            // Verify checksum
            if verify_checksum(descriptor_str).is_err() {
                return Err(ImportError::InvalidFormat(
                    "Invalid descriptor checksum".to_string()
                ));
            }
            (parts[0].to_string(), Some(parts[1].to_string()))
        } else {
            (descriptor_str.to_string(), None)
        }
    } else {
        (descriptor_str.to_string(), None)
    };
    
    // Parse the descriptor
    let descriptor = Descriptor::parse(&desc_without_checksum)
        .map_err(|e| ImportError::InvalidFormat(format!("Invalid descriptor: {}", e)))?;
    
    let descriptor_type = descriptor.descriptor_type().to_string();
    let is_ranged = descriptor.has_wildcard();
    let is_segwit = descriptor.is_segwit();
    let is_taproot = descriptor_type == "tr";
    
    // Extract keys
    let keys = extract_keys_from_descriptor(&desc_without_checksum)?;
    
    Ok(DescriptorImport {
        descriptor,
        descriptor_string: desc_without_checksum,
        descriptor_type,
        is_ranged,
        is_segwit,
        is_taproot,
        keys,
        checksum,
    })
}

/// Import a Taproot descriptor specifically.
///
/// # Example
///
/// ```rust
/// use rustywallet_import::descriptor::import_taproot_descriptor;
///
/// let result = import_taproot_descriptor(
///     "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
/// ).unwrap();
///
/// assert!(result.is_taproot);
/// ```
pub fn import_taproot_descriptor(descriptor_str: &str) -> Result<DescriptorImport> {
    let result = import_descriptor(descriptor_str)?;
    
    if !result.is_taproot {
        return Err(ImportError::InvalidFormat(
            format!("Expected Taproot descriptor, got {}", result.descriptor_type)
        ));
    }
    
    Ok(result)
}

/// Extract keys from a descriptor string.
fn extract_keys_from_descriptor(descriptor_str: &str) -> Result<Vec<ExtractedKey>> {
    let mut keys = Vec::new();
    
    // Find all key-like patterns in the descriptor
    // Keys can be:
    // - Raw pubkeys: 02/03/04 followed by hex
    // - xpub/xprv: starts with xpub/xprv/tpub/tprv/etc.
    // - With origin: [fingerprint/path]key
    // - With derivation: key/path/*
    
    let mut chars = descriptor_str.chars().peekable();
    let mut current_pos = 0;
    
    while let Some(c) = chars.next() {
        current_pos += 1;
        
        // Look for key start patterns
        if c == '(' || c == ',' || c == '{' {
            // Skip whitespace
            while chars.peek() == Some(&' ') {
                chars.next();
                current_pos += 1;
            }
            
            // Check what follows
            if let Some(&next_c) = chars.peek() {
                // Origin: [fingerprint/path]
                if next_c == '[' {
                    if let Some(key) = parse_key_with_origin(&descriptor_str[current_pos..]) {
                        keys.push(key);
                    }
                }
                // Extended key: xpub, xprv, tpub, tprv, etc.
                else if next_c == 'x' || next_c == 't' || next_c == 'y' || next_c == 'z' {
                    if let Some(key) = parse_extended_key(&descriptor_str[current_pos..]) {
                        keys.push(key);
                    }
                }
                // Raw pubkey: 02, 03, 04
                else if next_c == '0' {
                    if let Some(key) = parse_raw_pubkey(&descriptor_str[current_pos..]) {
                        keys.push(key);
                    }
                }
                // WIF key: 5, K, L, 9, c
                else if next_c == '5' || next_c == 'K' || next_c == 'L' || next_c == '9' || next_c == 'c' {
                    if let Some(key) = parse_wif_key(&descriptor_str[current_pos..]) {
                        keys.push(key);
                    }
                }
            }
        }
    }
    
    Ok(keys)
}

/// Parse a key with origin [fingerprint/path]key.
fn parse_key_with_origin(s: &str) -> Option<ExtractedKey> {
    if !s.starts_with('[') {
        return None;
    }
    
    // Find closing bracket
    let close_bracket = s.find(']')?;
    let origin = s[1..close_bracket].to_string();
    let rest = &s[close_bracket + 1..];
    
    // Parse the key part
    let mut key = if rest.starts_with('x') || rest.starts_with('t') || 
                     rest.starts_with('y') || rest.starts_with('z') {
        parse_extended_key(rest)?
    } else if rest.starts_with("02") || rest.starts_with("03") || rest.starts_with("04") {
        parse_raw_pubkey(rest)?
    } else {
        return None;
    };
    
    key.origin = Some(origin);
    Some(key)
}

/// Parse an extended key (xpub, xprv, etc.).
fn parse_extended_key(s: &str) -> Option<ExtractedKey> {
    // Extended keys are 111 characters (base58)
    // Find the end of the key
    let key_end = s.chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .count();
    
    if key_end < 100 {
        return None;
    }
    
    let key_data = s[..key_end].to_string();
    let rest = &s[key_end..];
    
    // Check for derivation path
    let (derivation_path, has_wildcard) = if rest.starts_with('/') {
        let path_end = rest.chars()
            .take_while(|c| *c == '/' || *c == '*' || *c == '\'' || *c == 'h' || c.is_ascii_digit())
            .count();
        let path = rest[..path_end].to_string();
        let wildcard = path.contains('*');
        (Some(path), wildcard)
    } else {
        (None, false)
    };
    
    let key_type = if key_data.starts_with("xprv") || key_data.starts_with("tprv") ||
                      key_data.starts_with("yprv") || key_data.starts_with("zprv") {
        KeyType::ExtendedPrivateKey
    } else {
        KeyType::ExtendedPublicKey
    };
    
    Some(ExtractedKey {
        key_type,
        key_data,
        origin: None,
        derivation_path,
        has_wildcard,
    })
}

/// Parse a raw public key (02/03/04...).
fn parse_raw_pubkey(s: &str) -> Option<ExtractedKey> {
    // Compressed: 02/03 + 64 hex = 66 chars
    // Uncompressed: 04 + 128 hex = 130 chars
    // X-only: 64 hex chars
    
    let prefix = &s[..2];
    let expected_len = match prefix {
        "02" | "03" => 66,
        "04" => 130,
        _ => return None,
    };
    
    // Check if we have enough hex chars
    let hex_end = s.chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .count();
    
    if hex_end < expected_len {
        return None;
    }
    
    let key_data = s[..expected_len].to_string();
    
    Some(ExtractedKey {
        key_type: KeyType::PublicKey,
        key_data,
        origin: None,
        derivation_path: None,
        has_wildcard: false,
    })
}

/// Parse a WIF private key.
fn parse_wif_key(s: &str) -> Option<ExtractedKey> {
    // WIF: 51-52 characters
    let key_end = s.chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .count();
    
    if key_end < 51 || key_end > 52 {
        return None;
    }
    
    let key_data = s[..key_end].to_string();
    
    // Validate WIF prefix
    let first_char = key_data.chars().next()?;
    if !matches!(first_char, '5' | 'K' | 'L' | '9' | 'c') {
        return None;
    }
    
    Some(ExtractedKey {
        key_type: KeyType::WifPrivateKey,
        key_data,
        origin: None,
        derivation_path: None,
        has_wildcard: false,
    })
}

/// Check if a string looks like a descriptor.
pub fn is_descriptor(s: &str) -> bool {
    let s = s.trim();
    
    // Check for common descriptor prefixes
    s.starts_with("pk(") ||
    s.starts_with("pkh(") ||
    s.starts_with("wpkh(") ||
    s.starts_with("sh(") ||
    s.starts_with("wsh(") ||
    s.starts_with("tr(") ||
    s.starts_with("multi(") ||
    s.starts_with("sortedmulti(") ||
    s.starts_with("combo(") ||
    s.starts_with("addr(") ||
    s.starts_with("raw(")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_descriptor::add_checksum;
    
    #[test]
    fn test_import_wpkh_descriptor() {
        let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let result = import_descriptor(desc).unwrap();
        
        assert_eq!(result.descriptor_type, "wpkh");
        assert!(!result.is_ranged);
        assert!(result.is_segwit);
        assert!(!result.is_taproot);
        assert_eq!(result.keys.len(), 1);
        assert_eq!(result.keys[0].key_type, KeyType::PublicKey);
    }
    
    #[test]
    fn test_import_taproot_descriptor() {
        let desc = "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let result = import_descriptor(desc).unwrap();
        
        assert_eq!(result.descriptor_type, "tr");
        assert!(result.is_taproot);
        assert_eq!(result.keys.len(), 1);
    }
    
    #[test]
    fn test_import_ranged_descriptor() {
        let desc = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
        let result = import_descriptor(desc).unwrap();
        
        assert!(result.is_ranged);
        assert_eq!(result.keys.len(), 1);
        assert!(result.keys[0].has_wildcard);
        assert_eq!(result.keys[0].key_type, KeyType::ExtendedPublicKey);
    }
    
    #[test]
    fn test_import_descriptor_with_checksum() {
        let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let with_checksum = add_checksum(desc);
        
        let result = import_descriptor(&with_checksum).unwrap();
        assert!(result.checksum.is_some());
    }
    
    #[test]
    fn test_import_descriptor_invalid_checksum() {
        let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#invalid1";
        let result = import_descriptor(desc);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_is_descriptor() {
        assert!(is_descriptor("wpkh(...)"));
        assert!(is_descriptor("tr(...)"));
        assert!(is_descriptor("sh(wpkh(...))"));
        assert!(!is_descriptor("5HueCGU8..."));
        assert!(!is_descriptor("xpub661..."));
    }
    
    #[test]
    fn test_import_taproot_only() {
        let desc = "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let result = import_taproot_descriptor(desc).unwrap();
        assert!(result.is_taproot);
        
        let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let result = import_taproot_descriptor(desc);
        assert!(result.is_err());
    }
}
