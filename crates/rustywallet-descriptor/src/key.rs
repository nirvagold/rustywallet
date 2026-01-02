//! Key expressions for descriptors
//!
//! Handles parsing and representation of keys in descriptors.

use crate::error::DescriptorError;
use rustywallet_hd::{DerivationPath, ChildNumber, ExtendedPublicKey, ExtendedPrivateKey};
use rustywallet_keys::public_key::PublicKey;
use std::fmt;

/// Key origin information [fingerprint/path]
#[derive(Clone, Debug)]
pub struct KeyOrigin {
    /// Master key fingerprint (4 bytes)
    pub fingerprint: [u8; 4],
    /// Derivation path from master
    pub path: DerivationPath,
}

impl KeyOrigin {
    /// Create a new key origin
    pub fn new(fingerprint: [u8; 4], path: DerivationPath) -> Self {
        Self { fingerprint, path }
    }

    /// Parse from string like "fingerprint/path"
    pub fn from_str_inner(s: &str) -> Result<Self, DescriptorError> {
        // Format: fingerprint/path or just fingerprint
        let parts: Vec<&str> = s.splitn(2, '/').collect();
        
        let fingerprint = parse_fingerprint(parts[0])?;
        
        let path = if parts.len() > 1 {
            DerivationPath::parse(&format!("m/{}", parts[1]))
                .map_err(|e| DescriptorError::InvalidDerivationPath(e.to_string()))?
        } else {
            DerivationPath::master()
        };
        
        Ok(Self { fingerprint, path })
    }
}

impl fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.fingerprint))?;
        for child in self.path.components() {
            match child {
                ChildNumber::Normal(i) => write!(f, "/{}", i)?,
                ChildNumber::Hardened(i) => write!(f, "/{}h", i)?,
            }
        }
        Ok(())
    }
}

/// Wildcard type for ranged descriptors
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Wildcard {
    /// No wildcard - single key
    #[default]
    None,
    /// Unhardened wildcard /*
    Unhardened,
    /// Hardened wildcard /*' or /*h
    Hardened,
}

impl Wildcard {
    /// Check if this is a wildcard
    pub fn is_wildcard(&self) -> bool {
        !matches!(self, Wildcard::None)
    }
}

/// A key expression in a descriptor
#[derive(Clone, Debug)]
pub enum DescriptorKey {
    /// Raw public key (compressed, 33 bytes)
    Single(PublicKey),
    
    /// Extended public key with optional origin and derivation
    Xpub {
        /// The extended public key
        xpub: ExtendedPublicKey,
        /// Optional origin information
        origin: Option<KeyOrigin>,
        /// Additional derivation path after xpub
        derivation: Vec<ChildNumber>,
        /// Wildcard for range derivation
        wildcard: Wildcard,
    },
    
    /// Extended private key with optional origin and derivation
    Xprv {
        /// The extended private key
        xprv: ExtendedPrivateKey,
        /// Optional origin information
        origin: Option<KeyOrigin>,
        /// Additional derivation path after xprv
        derivation: Vec<ChildNumber>,
        /// Wildcard for range derivation
        wildcard: Wildcard,
    },
}

impl DescriptorKey {
    /// Create from a single public key
    pub fn from_public_key(pubkey: PublicKey) -> Self {
        Self::Single(pubkey)
    }

    /// Create from an extended public key
    pub fn from_xpub(xpub: ExtendedPublicKey) -> Self {
        Self::Xpub {
            xpub,
            origin: None,
            derivation: Vec::new(),
            wildcard: Wildcard::None,
        }
    }

    /// Create from an extended private key
    pub fn from_xprv(xprv: ExtendedPrivateKey) -> Self {
        Self::Xprv {
            xprv,
            origin: None,
            derivation: Vec::new(),
            wildcard: Wildcard::None,
        }
    }

    /// Check if this key has a wildcard
    pub fn has_wildcard(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::Xpub { wildcard, .. } | Self::Xprv { wildcard, .. } => wildcard.is_wildcard(),
        }
    }

    /// Derive the public key at a specific index (for wildcards)
    pub fn derive_public_key(&self, index: u32) -> Result<PublicKey, DescriptorError> {
        match self {
            Self::Single(pk) => Ok(pk.clone()),
            Self::Xpub { xpub, derivation, wildcard, .. } => {
                let mut key = xpub.clone();
                
                // Apply derivation path
                for child in derivation {
                    let idx = child.raw_index();
                    key = key.derive_child(idx)
                        .map_err(|e| DescriptorError::DerivationError(e.to_string()))?;
                }
                
                // Apply wildcard index
                if wildcard.is_wildcard() {
                    let idx = match wildcard {
                        Wildcard::Unhardened => index,
                        Wildcard::Hardened => index | 0x80000000,
                        Wildcard::None => unreachable!(),
                    };
                    key = key.derive_child(idx)
                        .map_err(|e| DescriptorError::DerivationError(e.to_string()))?;
                }
                
                Ok(key.public_key().clone())
            }
            Self::Xprv { xprv, derivation, wildcard, .. } => {
                let mut key = xprv.clone();
                
                // Apply derivation path
                for child in derivation {
                    let idx = child.raw_index();
                    key = key.derive_child(idx)
                        .map_err(|e| DescriptorError::DerivationError(e.to_string()))?;
                }
                
                // Apply wildcard index
                if wildcard.is_wildcard() {
                    let idx = match wildcard {
                        Wildcard::Unhardened => index,
                        Wildcard::Hardened => index | 0x80000000,
                        Wildcard::None => unreachable!(),
                    };
                    key = key.derive_child(idx)
                        .map_err(|e| DescriptorError::DerivationError(e.to_string()))?;
                }
                
                Ok(key.public_key().clone())
            }
        }
    }

    /// Get the public key (for non-wildcard keys)
    pub fn public_key(&self) -> Result<PublicKey, DescriptorError> {
        if self.has_wildcard() {
            return Err(DescriptorError::WildcardNotAllowed);
        }
        self.derive_public_key(0)
    }
}

impl fmt::Display for DescriptorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(pk) => {
                write!(f, "{}", pk.to_hex(rustywallet_keys::public_key::PublicKeyFormat::Compressed))
            }
            Self::Xpub { xpub, origin, derivation, wildcard } => {
                if let Some(orig) = origin {
                    write!(f, "[{}]", orig)?;
                }
                write!(f, "{}", xpub.to_xpub())?;
                for child in derivation {
                    match child {
                        ChildNumber::Normal(i) => write!(f, "/{}", i)?,
                        ChildNumber::Hardened(i) => write!(f, "/{}h", i)?,
                    }
                }
                match wildcard {
                    Wildcard::None => {}
                    Wildcard::Unhardened => write!(f, "/*")?,
                    Wildcard::Hardened => write!(f, "/*h")?,
                }
                Ok(())
            }
            Self::Xprv { xprv, origin, derivation, wildcard } => {
                if let Some(orig) = origin {
                    write!(f, "[{}]", orig)?;
                }
                write!(f, "{}", xprv.to_xprv())?;
                for child in derivation {
                    match child {
                        ChildNumber::Normal(i) => write!(f, "/{}", i)?,
                        ChildNumber::Hardened(i) => write!(f, "/{}h", i)?,
                    }
                }
                match wildcard {
                    Wildcard::None => {}
                    Wildcard::Unhardened => write!(f, "/*")?,
                    Wildcard::Hardened => write!(f, "/*h")?,
                }
                Ok(())
            }
        }
    }
}

/// Parse a fingerprint from hex string
fn parse_fingerprint(s: &str) -> Result<[u8; 4], DescriptorError> {
    let bytes = hex::decode(s)
        .map_err(|_| DescriptorError::InvalidFingerprint(s.to_string()))?;
    
    if bytes.len() != 4 {
        return Err(DescriptorError::InvalidFingerprint(format!(
            "Expected 4 bytes, got {}",
            bytes.len()
        )));
    }
    
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&bytes);
    Ok(fingerprint)
}

/// Parse a key expression from string
pub fn parse_key(s: &str) -> Result<DescriptorKey, DescriptorError> {
    let s = s.trim();
    
    if s.is_empty() {
        return Err(DescriptorError::InvalidKey("Empty key".into()));
    }
    
    // Check for origin [fingerprint/path]
    let (origin, rest) = if s.starts_with('[') {
        let end = s.find(']')
            .ok_or_else(|| DescriptorError::InvalidKey("Unclosed origin bracket".into()))?;
        let origin_str = &s[1..end];
        let origin = KeyOrigin::from_str_inner(origin_str)?;
        (Some(origin), &s[end + 1..])
    } else {
        (None, s)
    };
    
    // Check for xpub/xprv
    if rest.starts_with("xpub") || rest.starts_with("tpub") {
        return parse_xpub_key(rest, origin);
    }
    
    if rest.starts_with("xprv") || rest.starts_with("tprv") {
        return parse_xprv_key(rest, origin);
    }
    
    // Try to parse as raw public key (hex)
    if rest.len() == 66 || rest.len() == 130 {
        // Compressed (33 bytes = 66 hex) or uncompressed (65 bytes = 130 hex)
        let pubkey = PublicKey::from_hex(rest)
            .map_err(|e| DescriptorError::InvalidPublicKey(e.to_string()))?;
        return Ok(DescriptorKey::Single(pubkey));
    }
    
    Err(DescriptorError::InvalidKey(format!("Unknown key format: {}", rest)))
}

fn parse_xpub_key(s: &str, origin: Option<KeyOrigin>) -> Result<DescriptorKey, DescriptorError> {
    // Find the end of the xpub (111 chars for mainnet, 111 for testnet)
    let xpub_end = s.find('/').unwrap_or(s.len());
    let xpub_str = &s[..xpub_end];
    
    let xpub = ExtendedPublicKey::from_xpub(xpub_str)
        .map_err(|e| DescriptorError::InvalidExtendedKey(e.to_string()))?;
    
    // Parse derivation path and wildcard
    let (derivation, wildcard) = if xpub_end < s.len() {
        parse_derivation_suffix(&s[xpub_end..])?
    } else {
        (Vec::new(), Wildcard::None)
    };
    
    Ok(DescriptorKey::Xpub {
        xpub,
        origin,
        derivation,
        wildcard,
    })
}

fn parse_xprv_key(s: &str, origin: Option<KeyOrigin>) -> Result<DescriptorKey, DescriptorError> {
    // Find the end of the xprv
    let xprv_end = s.find('/').unwrap_or(s.len());
    let xprv_str = &s[..xprv_end];
    
    let xprv = ExtendedPrivateKey::from_xprv(xprv_str)
        .map_err(|e| DescriptorError::InvalidExtendedKey(e.to_string()))?;
    
    // Parse derivation path and wildcard
    let (derivation, wildcard) = if xprv_end < s.len() {
        parse_derivation_suffix(&s[xprv_end..])?
    } else {
        (Vec::new(), Wildcard::None)
    };
    
    Ok(DescriptorKey::Xprv {
        xprv,
        origin,
        derivation,
        wildcard,
    })
}

fn parse_derivation_suffix(s: &str) -> Result<(Vec<ChildNumber>, Wildcard), DescriptorError> {
    // s starts with /
    let mut path_parts = Vec::new();
    let mut wildcard = Wildcard::None;
    
    for part in s.split('/').skip(1) {
        if part.is_empty() {
            continue;
        }
        
        if part == "*" {
            wildcard = Wildcard::Unhardened;
            break;
        } else if part == "*'" || part == "*h" {
            wildcard = Wildcard::Hardened;
            break;
        } else {
            // Parse as child number
            let (num_str, hardened) = if part.ends_with('\'') || part.ends_with('h') {
                (&part[..part.len() - 1], true)
            } else {
                (part, false)
            };
            
            let num: u32 = num_str.parse()
                .map_err(|_| DescriptorError::InvalidDerivationPath(part.to_string()))?;
            
            let child = if hardened {
                ChildNumber::Hardened(num)
            } else {
                ChildNumber::Normal(num)
            };
            
            path_parts.push(child);
        }
    }
    
    Ok((path_parts, wildcard))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_raw_pubkey() {
        let hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let key = parse_key(hex).unwrap();
        
        match key {
            DescriptorKey::Single(_) => {}
            _ => panic!("Expected Single key"),
        }
    }

    #[test]
    fn test_parse_xpub() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let key = parse_key(xpub).unwrap();
        
        match key {
            DescriptorKey::Xpub { wildcard, .. } => {
                assert_eq!(wildcard, Wildcard::None);
            }
            _ => panic!("Expected Xpub key"),
        }
    }

    #[test]
    fn test_parse_xpub_with_derivation() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/1";
        let key = parse_key(xpub).unwrap();
        
        match key {
            DescriptorKey::Xpub { derivation, wildcard, .. } => {
                assert_eq!(derivation.len(), 2);
                assert_eq!(wildcard, Wildcard::None);
            }
            _ => panic!("Expected Xpub key"),
        }
    }

    #[test]
    fn test_parse_xpub_with_wildcard() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*";
        let key = parse_key(xpub).unwrap();
        
        match key {
            DescriptorKey::Xpub { derivation, wildcard, .. } => {
                assert_eq!(derivation.len(), 1);
                assert_eq!(wildcard, Wildcard::Unhardened);
            }
            _ => panic!("Expected Xpub key"),
        }
    }

    #[test]
    fn test_parse_key_with_origin() {
        let key_str = "[deadbeef/44h/0h/0h]xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*";
        let key = parse_key(key_str).unwrap();
        
        match key {
            DescriptorKey::Xpub { origin, wildcard, .. } => {
                assert!(origin.is_some());
                let orig = origin.unwrap();
                assert_eq!(orig.fingerprint, [0xde, 0xad, 0xbe, 0xef]);
                assert_eq!(wildcard, Wildcard::Unhardened);
            }
            _ => panic!("Expected Xpub key"),
        }
    }
}
