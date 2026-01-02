//! Descriptor types and parsing
//!
//! Implements output descriptor parsing and representation.

use crate::checksum::{strip_checksum, verify_checksum, add_checksum};
use crate::error::DescriptorError;
use crate::key::{parse_key, DescriptorKey};
use std::fmt;
use std::str::FromStr;

/// Output descriptor
#[derive(Clone, Debug)]
pub enum Descriptor {
    /// pk(KEY) - Pay to pubkey (bare)
    Pk(DescriptorKey),
    
    /// pkh(KEY) - Pay to pubkey hash (P2PKH)
    Pkh(DescriptorKey),
    
    /// wpkh(KEY) - Pay to witness pubkey hash (P2WPKH)
    Wpkh(DescriptorKey),
    
    /// sh(SCRIPT) - Pay to script hash (P2SH)
    Sh(Box<Descriptor>),
    
    /// wsh(SCRIPT) - Pay to witness script hash (P2WSH)
    Wsh(Box<Descriptor>),
    
    /// tr(KEY) - Pay to Taproot (key path only)
    Tr(DescriptorKey),
    
    /// multi(k, KEY1, KEY2, ...) - k-of-n multisig
    Multi {
        /// Required signatures
        threshold: usize,
        /// Public keys
        keys: Vec<DescriptorKey>,
    },
    
    /// sortedmulti(k, KEY1, KEY2, ...) - sorted k-of-n multisig
    SortedMulti {
        /// Required signatures
        threshold: usize,
        /// Public keys (will be sorted)
        keys: Vec<DescriptorKey>,
    },
}

impl Descriptor {
    /// Parse a descriptor string
    pub fn parse(s: &str) -> Result<Self, DescriptorError> {
        let s = s.trim();
        
        if s.is_empty() {
            return Err(DescriptorError::EmptyDescriptor);
        }
        
        // Check and strip checksum if present
        let desc_str = if s.contains('#') {
            verify_checksum(s)?;
            strip_checksum(s)
        } else {
            s
        };
        
        parse_descriptor_inner(desc_str, 0)
    }

    /// Convert to string with checksum
    pub fn to_string_with_checksum(&self) -> String {
        add_checksum(&self.to_string())
    }

    /// Check if this descriptor has a wildcard
    pub fn has_wildcard(&self) -> bool {
        match self {
            Self::Pk(key) | Self::Pkh(key) | Self::Wpkh(key) | Self::Tr(key) => {
                key.has_wildcard()
            }
            Self::Sh(inner) | Self::Wsh(inner) => inner.has_wildcard(),
            Self::Multi { keys, .. } | Self::SortedMulti { keys, .. } => {
                keys.iter().any(|k| k.has_wildcard())
            }
        }
    }

    /// Get the descriptor type as a string
    pub fn descriptor_type(&self) -> &'static str {
        match self {
            Self::Pk(_) => "pk",
            Self::Pkh(_) => "pkh",
            Self::Wpkh(_) => "wpkh",
            Self::Sh(_) => "sh",
            Self::Wsh(_) => "wsh",
            Self::Tr(_) => "tr",
            Self::Multi { .. } => "multi",
            Self::SortedMulti { .. } => "sortedmulti",
        }
    }

    /// Check if this is a SegWit descriptor
    pub fn is_segwit(&self) -> bool {
        match self {
            Self::Wpkh(_) | Self::Wsh(_) | Self::Tr(_) => true,
            Self::Sh(inner) => matches!(inner.as_ref(), Self::Wpkh(_) | Self::Wsh(_)),
            _ => false,
        }
    }

    /// Check if this is a Taproot descriptor
    pub fn is_taproot(&self) -> bool {
        matches!(self, Self::Tr(_))
    }
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pk(key) => write!(f, "pk({})", key),
            Self::Pkh(key) => write!(f, "pkh({})", key),
            Self::Wpkh(key) => write!(f, "wpkh({})", key),
            Self::Sh(inner) => write!(f, "sh({})", inner),
            Self::Wsh(inner) => write!(f, "wsh({})", inner),
            Self::Tr(key) => write!(f, "tr({})", key),
            Self::Multi { threshold, keys } => {
                write!(f, "multi({}", threshold)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            Self::SortedMulti { threshold, keys } => {
                write!(f, "sortedmulti({}", threshold)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
        }
    }
}

impl FromStr for Descriptor {
    type Err = DescriptorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Parse descriptor inner content
fn parse_descriptor_inner(s: &str, pos: usize) -> Result<Descriptor, DescriptorError> {
    let s = s.trim();
    
    // Find the function name and opening paren
    let open_paren = s.find('(')
        .ok_or_else(|| DescriptorError::parse_error(pos, "Expected '('"))?;
    
    let func_name = &s[..open_paren];
    let content = extract_parentheses_content(s, open_paren)?;
    
    match func_name {
        "pk" => {
            let key = parse_key(content)?;
            Ok(Descriptor::Pk(key))
        }
        "pkh" => {
            let key = parse_key(content)?;
            Ok(Descriptor::Pkh(key))
        }
        "wpkh" => {
            let key = parse_key(content)?;
            Ok(Descriptor::Wpkh(key))
        }
        "sh" => {
            let inner = parse_descriptor_inner(content, pos + open_paren + 1)?;
            Ok(Descriptor::Sh(Box::new(inner)))
        }
        "wsh" => {
            let inner = parse_descriptor_inner(content, pos + open_paren + 1)?;
            Ok(Descriptor::Wsh(Box::new(inner)))
        }
        "tr" => {
            // For now, only support key-path (no script tree)
            let key = parse_key(content)?;
            Ok(Descriptor::Tr(key))
        }
        "multi" => {
            parse_multi(content, false)
        }
        "sortedmulti" => {
            parse_multi(content, true)
        }
        _ => Err(DescriptorError::UnsupportedType(func_name.to_string())),
    }
}

/// Extract content between matching parentheses
fn extract_parentheses_content(s: &str, open_pos: usize) -> Result<&str, DescriptorError> {
    let mut depth = 0;
    let mut close_pos = None;
    
    for (i, c) in s[open_pos..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close_pos = Some(open_pos + i);
                    break;
                }
            }
            _ => {}
        }
    }
    
    let close = close_pos.ok_or_else(|| DescriptorError::parse_error(open_pos, "Unmatched '('"))?;
    
    Ok(&s[open_pos + 1..close])
}

/// Parse multi/sortedmulti content
fn parse_multi(content: &str, sorted: bool) -> Result<Descriptor, DescriptorError> {
    let parts: Vec<&str> = split_top_level(content, ',');
    
    if parts.is_empty() {
        return Err(DescriptorError::parse_error(0, "Empty multi descriptor"));
    }
    
    // First part is threshold
    let threshold: usize = parts[0].trim().parse()
        .map_err(|_| DescriptorError::parse_error(0, "Invalid threshold"))?;
    
    // Rest are keys
    let mut keys = Vec::new();
    for part in &parts[1..] {
        let key = parse_key(part.trim())?;
        keys.push(key);
    }
    
    // Validate threshold
    if threshold == 0 || threshold > keys.len() {
        return Err(DescriptorError::InvalidThreshold {
            k: threshold,
            n: keys.len(),
        });
    }
    
    if sorted {
        Ok(Descriptor::SortedMulti { threshold, keys })
    } else {
        Ok(Descriptor::Multi { threshold, keys })
    }
}

/// Split string by delimiter, respecting nested parentheses and brackets
fn split_top_level(s: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut bracket_depth = 0;
    let mut start = 0;
    
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            '[' => bracket_depth += 1,
            ']' => bracket_depth -= 1,
            c if c == delimiter && depth == 0 && bracket_depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    
    // Add the last part
    if start < s.len() {
        parts.push(&s[start..]);
    }
    
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pk() {
        let desc = "pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let parsed = Descriptor::parse(desc).unwrap();
        
        assert_eq!(parsed.descriptor_type(), "pk");
        assert!(!parsed.has_wildcard());
    }

    #[test]
    fn test_parse_pkh() {
        let desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let parsed = Descriptor::parse(desc).unwrap();
        
        assert_eq!(parsed.descriptor_type(), "pkh");
    }

    #[test]
    fn test_parse_wpkh() {
        let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let parsed = Descriptor::parse(desc).unwrap();
        
        assert_eq!(parsed.descriptor_type(), "wpkh");
        assert!(parsed.is_segwit());
    }

    #[test]
    fn test_parse_sh_wpkh() {
        let desc = "sh(wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))";
        let parsed = Descriptor::parse(desc).unwrap();
        
        assert_eq!(parsed.descriptor_type(), "sh");
        assert!(parsed.is_segwit());
    }

    #[test]
    fn test_parse_tr() {
        let desc = "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let parsed = Descriptor::parse(desc).unwrap();
        
        assert_eq!(parsed.descriptor_type(), "tr");
        assert!(parsed.is_taproot());
    }

    #[test]
    fn test_parse_multi() {
        let desc = "multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let parsed = Descriptor::parse(desc).unwrap();
        
        match parsed {
            Descriptor::Multi { threshold, keys } => {
                assert_eq!(threshold, 2);
                assert_eq!(keys.len(), 2);
            }
            _ => panic!("Expected Multi"),
        }
    }

    #[test]
    fn test_parse_with_checksum() {
        let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let with_checksum = add_checksum(desc);
        
        let parsed = Descriptor::parse(&with_checksum).unwrap();
        assert_eq!(parsed.descriptor_type(), "wpkh");
    }

    #[test]
    fn test_descriptor_roundtrip() {
        let desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let parsed = Descriptor::parse(desc).unwrap();
        let displayed = parsed.to_string();
        
        // Should be able to parse the displayed string
        let reparsed = Descriptor::parse(&displayed).unwrap();
        // Compare by string since we removed PartialEq
        assert_eq!(parsed.to_string(), reparsed.to_string());
    }

    #[test]
    fn test_invalid_threshold() {
        let desc = "multi(3,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        let result = Descriptor::parse(desc);
        
        assert!(matches!(result, Err(DescriptorError::InvalidThreshold { .. })));
    }

    #[test]
    fn test_parse_xpub_descriptor() {
        let desc = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";
        let parsed = Descriptor::parse(desc).unwrap();
        
        assert!(parsed.has_wildcard());
    }
}
