//! Taproot descriptor support
//!
//! Implements BIP386 Taproot descriptors with key-path and script-path spending.
//!
//! ## Supported Formats
//!
//! - `tr(KEY)` - Key-path only spending
//! - `tr(KEY,{SCRIPT})` - Key-path with script tree
//! - `tr(KEY,{SCRIPT,SCRIPT})` - Key-path with multiple scripts
//!
//! ## Example
//!
//! ```rust,ignore
//! use rustywallet_descriptor::taproot::{TaprootDescriptor, TapTree};
//!
//! // Key-path only
//! let desc = TaprootDescriptor::parse("tr(KEY)").unwrap();
//!
//! // With script tree
//! let desc = TaprootDescriptor::parse("tr(KEY,{pk(KEY2)})").unwrap();
//! ```

use crate::error::DescriptorError;
use crate::key::{parse_key, DescriptorKey};
use rustywallet_taproot::{
    TapTree as RwTapTree, TapLeaf, TapNode, XOnlyPublicKey,
    TaprootOutput, Network as TaprootNetwork,
};
use rustywallet_address::Network;
use rustywallet_keys::public_key::{PublicKey, PublicKeyFormat};
use std::fmt;

/// A script leaf in a Taproot descriptor tree
#[derive(Clone, Debug)]
pub struct TapDescriptorLeaf {
    /// The script descriptor (e.g., pk(KEY), multi(k,KEY,...))
    pub script: TapScript,
    /// Depth in the tree (for building)
    pub depth: u8,
}

impl TapDescriptorLeaf {
    /// Create a new leaf with a script
    pub fn new(script: TapScript, depth: u8) -> Self {
        Self { script, depth }
    }
}

/// A script in a Taproot leaf
#[derive(Clone, Debug)]
pub enum TapScript {
    /// pk(KEY) - Pay to pubkey
    Pk(DescriptorKey),
    /// pkh(KEY) - Pay to pubkey hash (not recommended in Taproot)
    Pkh(DescriptorKey),
    /// multi_a(k, KEY1, KEY2, ...) - Tapscript multisig
    MultiA {
        threshold: usize,
        keys: Vec<DescriptorKey>,
    },
    /// sortedmulti_a(k, KEY1, KEY2, ...) - Sorted Tapscript multisig
    SortedMultiA {
        threshold: usize,
        keys: Vec<DescriptorKey>,
    },
    /// Raw script bytes (for advanced use)
    Raw(Vec<u8>),
}

impl TapScript {
    /// Generate the script bytes for this tap script at a given index
    pub fn to_script(&self, index: u32) -> Result<Vec<u8>, DescriptorError> {
        match self {
            TapScript::Pk(key) => {
                let pubkey = key.derive_public_key(index)?;
                let pk_hex = pubkey.to_hex(PublicKeyFormat::Compressed);
                let pk_bytes = hex::decode(&pk_hex).unwrap();
                // x-only pubkey (32 bytes) + OP_CHECKSIG
                let mut script = Vec::with_capacity(34);
                script.push(0x20); // Push 32 bytes
                script.extend_from_slice(&pk_bytes[1..33]); // Skip prefix
                script.push(0xac); // OP_CHECKSIG
                Ok(script)
            }
            TapScript::Pkh(key) => {
                let pubkey = key.derive_public_key(index)?;
                let pk_hex = pubkey.to_hex(PublicKeyFormat::Compressed);
                let pk_bytes = hex::decode(&pk_hex).unwrap();
                let pubkey_hash = hash160(&pk_bytes);
                // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                let mut script = Vec::with_capacity(25);
                script.push(0x76); // OP_DUP
                script.push(0xa9); // OP_HASH160
                script.push(0x14); // Push 20 bytes
                script.extend_from_slice(&pubkey_hash);
                script.push(0x88); // OP_EQUALVERIFY
                script.push(0xac); // OP_CHECKSIG
                Ok(script)
            }
            TapScript::MultiA { threshold, keys } => {
                let pubkeys: Result<Vec<_>, _> = keys
                    .iter()
                    .map(|k| k.derive_public_key(index))
                    .collect();
                let pubkeys = pubkeys?;
                tapscript_multisig(*threshold, &pubkeys)
            }
            TapScript::SortedMultiA { threshold, keys } => {
                let mut pubkeys: Vec<_> = keys
                    .iter()
                    .map(|k| k.derive_public_key(index))
                    .collect::<Result<Vec<_>, _>>()?;
                pubkeys.sort_by(|a, b| {
                    let a_hex = a.to_hex(PublicKeyFormat::Compressed);
                    let b_hex = b.to_hex(PublicKeyFormat::Compressed);
                    a_hex.cmp(&b_hex)
                });
                tapscript_multisig(*threshold, &pubkeys)
            }
            TapScript::Raw(bytes) => Ok(bytes.clone()),
        }
    }

    /// Check if this script has a wildcard
    pub fn has_wildcard(&self) -> bool {
        match self {
            TapScript::Pk(key) | TapScript::Pkh(key) => key.has_wildcard(),
            TapScript::MultiA { keys, .. } | TapScript::SortedMultiA { keys, .. } => {
                keys.iter().any(|k| k.has_wildcard())
            }
            TapScript::Raw(_) => false,
        }
    }
}

impl fmt::Display for TapScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapScript::Pk(key) => write!(f, "pk({})", key),
            TapScript::Pkh(key) => write!(f, "pkh({})", key),
            TapScript::MultiA { threshold, keys } => {
                write!(f, "multi_a({}", threshold)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            TapScript::SortedMultiA { threshold, keys } => {
                write!(f, "sortedmulti_a({}", threshold)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            TapScript::Raw(bytes) => write!(f, "raw({})", hex::encode(bytes)),
        }
    }
}

/// Taproot descriptor tree structure
#[derive(Clone, Debug)]
pub enum TapDescriptorTree {
    /// A single leaf script
    Leaf(TapDescriptorLeaf),
    /// A branch with two children
    Branch(Box<TapDescriptorTree>, Box<TapDescriptorTree>),
}

impl TapDescriptorTree {
    /// Create a single leaf tree
    pub fn leaf(script: TapScript) -> Self {
        TapDescriptorTree::Leaf(TapDescriptorLeaf::new(script, 0))
    }

    /// Create a branch with two children
    pub fn branch(left: TapDescriptorTree, right: TapDescriptorTree) -> Self {
        TapDescriptorTree::Branch(Box::new(left), Box::new(right))
    }

    /// Get all leaves in the tree
    pub fn leaves(&self) -> Vec<&TapDescriptorLeaf> {
        let mut result = Vec::new();
        self.collect_leaves(&mut result);
        result
    }

    fn collect_leaves<'a>(&'a self, leaves: &mut Vec<&'a TapDescriptorLeaf>) {
        match self {
            TapDescriptorTree::Leaf(leaf) => leaves.push(leaf),
            TapDescriptorTree::Branch(left, right) => {
                left.collect_leaves(leaves);
                right.collect_leaves(leaves);
            }
        }
    }

    /// Check if any script has a wildcard
    pub fn has_wildcard(&self) -> bool {
        match self {
            TapDescriptorTree::Leaf(leaf) => leaf.script.has_wildcard(),
            TapDescriptorTree::Branch(left, right) => {
                left.has_wildcard() || right.has_wildcard()
            }
        }
    }

    /// Convert to rustywallet-taproot TapTree at a specific index
    pub fn to_tap_tree(&self, index: u32) -> Result<RwTapTree, DescriptorError> {
        let node = self.to_tap_node(index)?;
        Ok(RwTapTree::from_node(node))
    }

    fn to_tap_node(&self, index: u32) -> Result<TapNode, DescriptorError> {
        match self {
            TapDescriptorTree::Leaf(leaf) => {
                let script = leaf.script.to_script(index)?;
                Ok(TapNode::Leaf(TapLeaf::new(script)))
            }
            TapDescriptorTree::Branch(left, right) => {
                let left_node = left.to_tap_node(index)?;
                let right_node = right.to_tap_node(index)?;
                Ok(TapNode::Branch(Box::new(left_node), Box::new(right_node)))
            }
        }
    }
}

impl fmt::Display for TapDescriptorTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapDescriptorTree::Leaf(leaf) => write!(f, "{}", leaf.script),
            TapDescriptorTree::Branch(left, right) => {
                write!(f, "{{{},{}}}", left, right)
            }
        }
    }
}

/// Taproot descriptor (BIP386)
///
/// Supports both key-path only and script-path spending.
#[derive(Clone, Debug)]
pub enum TaprootDescriptor {
    /// Key-path only: tr(KEY)
    KeyPath(DescriptorKey),
    /// Script-path: tr(KEY,{SCRIPT_TREE})
    ScriptPath {
        /// Internal key
        internal_key: DescriptorKey,
        /// Script tree
        script_tree: TapDescriptorTree,
    },
}

impl TaprootDescriptor {
    /// Create a key-path only descriptor
    pub fn key_path(key: DescriptorKey) -> Self {
        TaprootDescriptor::KeyPath(key)
    }

    /// Create a script-path descriptor
    pub fn script_path(internal_key: DescriptorKey, script_tree: TapDescriptorTree) -> Self {
        TaprootDescriptor::ScriptPath {
            internal_key,
            script_tree,
        }
    }

    /// Parse a Taproot descriptor string
    pub fn parse(s: &str) -> Result<Self, DescriptorError> {
        let s = s.trim();
        
        // Must start with "tr("
        if !s.starts_with("tr(") {
            return Err(DescriptorError::parse_error(0, "Expected 'tr('"));
        }
        
        // Find matching closing paren
        let content = extract_tr_content(s)?;
        
        // Check for script tree (comma separates key from tree)
        if let Some(comma_pos) = find_top_level_comma(content) {
            // Script path: tr(KEY,{TREE})
            let key_str = &content[..comma_pos];
            let tree_str = &content[comma_pos + 1..];
            
            let internal_key = parse_key(key_str.trim())?;
            let script_tree = parse_tap_tree(tree_str.trim())?;
            
            Ok(TaprootDescriptor::ScriptPath {
                internal_key,
                script_tree,
            })
        } else {
            // Key path only: tr(KEY)
            let key = parse_key(content)?;
            Ok(TaprootDescriptor::KeyPath(key))
        }
    }

    /// Check if this is a key-path only descriptor
    pub fn is_key_path_only(&self) -> bool {
        matches!(self, TaprootDescriptor::KeyPath(_))
    }

    /// Check if this descriptor has a wildcard
    pub fn has_wildcard(&self) -> bool {
        match self {
            TaprootDescriptor::KeyPath(key) => key.has_wildcard(),
            TaprootDescriptor::ScriptPath { internal_key, script_tree } => {
                internal_key.has_wildcard() || script_tree.has_wildcard()
            }
        }
    }

    /// Get the internal key
    pub fn internal_key(&self) -> &DescriptorKey {
        match self {
            TaprootDescriptor::KeyPath(key) => key,
            TaprootDescriptor::ScriptPath { internal_key, .. } => internal_key,
        }
    }

    /// Get the script tree (if any)
    pub fn script_tree(&self) -> Option<&TapDescriptorTree> {
        match self {
            TaprootDescriptor::KeyPath(_) => None,
            TaprootDescriptor::ScriptPath { script_tree, .. } => Some(script_tree),
        }
    }

    /// Derive the x-only public key at a specific index
    pub fn derive_internal_xonly(&self, index: u32) -> Result<XOnlyPublicKey, DescriptorError> {
        let pubkey = self.internal_key().derive_public_key(index)?;
        let pk_hex = pubkey.to_hex(PublicKeyFormat::Compressed);
        let pk_bytes = hex::decode(&pk_hex).unwrap();
        
        // Convert to x-only (skip the prefix byte)
        let mut xonly_bytes = [0u8; 32];
        xonly_bytes.copy_from_slice(&pk_bytes[1..33]);
        
        XOnlyPublicKey::from_bytes(xonly_bytes)
            .map_err(|e| DescriptorError::InvalidPublicKey(e.to_string()))
    }

    /// Derive the Taproot output at a specific index
    pub fn derive_output(&self, index: u32) -> Result<TaprootOutput, DescriptorError> {
        let internal_key = self.derive_internal_xonly(index)?;
        
        match self {
            TaprootDescriptor::KeyPath(_) => {
                TaprootOutput::key_path_only(internal_key)
                    .map_err(|e| DescriptorError::AddressError(e.to_string()))
            }
            TaprootDescriptor::ScriptPath { script_tree, .. } => {
                let tap_tree = script_tree.to_tap_tree(index)?;
                TaprootOutput::with_script_tree(internal_key, &tap_tree)
                    .map_err(|e| DescriptorError::AddressError(e.to_string()))
            }
        }
    }

    /// Derive a P2TR address at a specific index
    pub fn derive_address(&self, index: u32, network: Network) -> Result<String, DescriptorError> {
        let output = self.derive_output(index)?;
        let taproot_network = match network {
            Network::BitcoinMainnet => TaprootNetwork::Mainnet,
            Network::BitcoinTestnet => TaprootNetwork::Testnet,
            _ => return Err(DescriptorError::AddressError(
                "Unsupported network for Taproot".into()
            )),
        };
        output.address(taproot_network)
            .map_err(|e| DescriptorError::AddressError(e.to_string()))
    }

    /// Derive multiple P2TR addresses
    pub fn derive_addresses(
        &self,
        network: Network,
        start: u32,
        count: u32,
    ) -> Result<Vec<String>, DescriptorError> {
        let mut addresses = Vec::with_capacity(count as usize);
        for i in start..start + count {
            addresses.push(self.derive_address(i, network)?);
        }
        Ok(addresses)
    }

    /// Get the script pubkey at a specific index
    pub fn script_pubkey(&self, index: u32) -> Result<Vec<u8>, DescriptorError> {
        let output = self.derive_output(index)?;
        Ok(output.script_pubkey())
    }
}

impl fmt::Display for TaprootDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaprootDescriptor::KeyPath(key) => write!(f, "tr({})", key),
            TaprootDescriptor::ScriptPath { internal_key, script_tree } => {
                write!(f, "tr({},{})", internal_key, script_tree)
            }
        }
    }
}

// Helper functions

/// Extract content inside tr(...)
fn extract_tr_content(s: &str) -> Result<&str, DescriptorError> {
    // s starts with "tr("
    let start = 3;
    let mut depth = 1;
    
    for (i, c) in s[start..].char_indices() {
        match c {
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&s[start..start + i]);
                }
            }
            _ => {}
        }
    }
    
    Err(DescriptorError::parse_error(0, "Unmatched parenthesis in tr()"))
}

/// Find top-level comma (not inside nested parens/braces)
fn find_top_level_comma(s: &str) -> Option<usize> {
    let mut depth = 0;
    
    for (i, c) in s.char_indices() {
        match c {
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth -= 1,
            ',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    
    None
}

/// Parse a tap tree from string
fn parse_tap_tree(s: &str) -> Result<TapDescriptorTree, DescriptorError> {
    let s = s.trim();
    
    if s.is_empty() {
        return Err(DescriptorError::parse_error(0, "Empty script tree"));
    }
    
    // Check if it's a branch: {left,right}
    if s.starts_with('{') && s.ends_with('}') {
        let inner = &s[1..s.len() - 1];
        
        // Find the comma separating left and right
        if let Some(comma_pos) = find_top_level_comma(inner) {
            let left_str = &inner[..comma_pos];
            let right_str = &inner[comma_pos + 1..];
            
            let left = parse_tap_tree(left_str.trim())?;
            let right = parse_tap_tree(right_str.trim())?;
            
            return Ok(TapDescriptorTree::branch(left, right));
        } else {
            // Single item in braces - treat as leaf
            return parse_tap_tree(inner.trim());
        }
    }
    
    // Otherwise it's a leaf script
    let script = parse_tap_script(s)?;
    Ok(TapDescriptorTree::leaf(script))
}

/// Parse a tap script (leaf content)
fn parse_tap_script(s: &str) -> Result<TapScript, DescriptorError> {
    let s = s.trim();
    
    // Find function name
    let open_paren = s.find('(')
        .ok_or_else(|| DescriptorError::parse_error(0, "Expected '(' in tap script"))?;
    
    let func_name = &s[..open_paren];
    let content = extract_paren_content(s, open_paren)?;
    
    match func_name {
        "pk" => {
            let key = parse_key(content)?;
            Ok(TapScript::Pk(key))
        }
        "pkh" => {
            let key = parse_key(content)?;
            Ok(TapScript::Pkh(key))
        }
        "multi_a" => {
            parse_multi_a(content, false)
        }
        "sortedmulti_a" => {
            parse_multi_a(content, true)
        }
        "raw" => {
            let bytes = hex::decode(content)
                .map_err(|_| DescriptorError::parse_error(0, "Invalid hex in raw()"))?;
            Ok(TapScript::Raw(bytes))
        }
        _ => Err(DescriptorError::UnsupportedType(format!(
            "Unsupported tap script type: {}",
            func_name
        ))),
    }
}

/// Extract content between parentheses
fn extract_paren_content(s: &str, open_pos: usize) -> Result<&str, DescriptorError> {
    let mut depth = 0;
    
    for (i, c) in s[open_pos..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&s[open_pos + 1..open_pos + i]);
                }
            }
            _ => {}
        }
    }
    
    Err(DescriptorError::parse_error(open_pos, "Unmatched '('"))
}

/// Parse multi_a or sortedmulti_a content
fn parse_multi_a(content: &str, sorted: bool) -> Result<TapScript, DescriptorError> {
    let parts: Vec<&str> = split_top_level(content, ',');
    
    if parts.is_empty() {
        return Err(DescriptorError::parse_error(0, "Empty multi_a descriptor"));
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
        Ok(TapScript::SortedMultiA { threshold, keys })
    } else {
        Ok(TapScript::MultiA { threshold, keys })
    }
}

/// Split string by delimiter, respecting nested structures
fn split_top_level(s: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    
    for (i, c) in s.char_indices() {
        match c {
            '(' | '{' | '[' => depth += 1,
            ')' | '}' | ']' => depth -= 1,
            c if c == delimiter && depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    
    if start < s.len() {
        parts.push(&s[start..]);
    }
    
    parts
}

/// Generate Tapscript multisig script
fn tapscript_multisig(threshold: usize, pubkeys: &[PublicKey]) -> Result<Vec<u8>, DescriptorError> {
    if threshold == 0 || threshold > pubkeys.len() {
        return Err(DescriptorError::InvalidThreshold {
            k: threshold,
            n: pubkeys.len(),
        });
    }
    
    let mut script = Vec::new();
    
    // Push each x-only pubkey with OP_CHECKSIG or OP_CHECKSIGADD
    for (i, pk) in pubkeys.iter().enumerate() {
        let pk_hex = pk.to_hex(PublicKeyFormat::Compressed);
        let pk_bytes = hex::decode(&pk_hex).unwrap();
        
        // Push 32-byte x-only pubkey
        script.push(0x20); // Push 32 bytes
        script.extend_from_slice(&pk_bytes[1..33]); // Skip prefix
        
        if i == 0 {
            script.push(0xac); // OP_CHECKSIG
        } else {
            script.push(0xba); // OP_CHECKSIGADD
        }
    }
    
    // Push threshold and OP_NUMEQUAL
    if threshold <= 16 {
        script.push(0x50 + threshold as u8); // OP_1 through OP_16
    } else {
        // For larger thresholds, use OP_PUSHDATA
        script.push(0x01); // Push 1 byte
        script.push(threshold as u8);
    }
    script.push(0x9c); // OP_NUMEQUAL
    
    Ok(script)
}

/// HASH160 = RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;
    
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_path_only() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
        ).unwrap();
        
        assert!(desc.is_key_path_only());
        assert!(!desc.has_wildcard());
    }

    #[test]
    fn test_parse_script_path_single_leaf() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)})"
        ).unwrap();
        
        assert!(!desc.is_key_path_only());
        assert!(desc.script_tree().is_some());
    }

    #[test]
    fn test_parse_script_path_two_leaves() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)})"
        ).unwrap();
        
        assert!(!desc.is_key_path_only());
        let tree = desc.script_tree().unwrap();
        assert_eq!(tree.leaves().len(), 2);
    }

    #[test]
    fn test_parse_nested_script_tree() {
        // Nested tree: {{A,B},{C,D}}
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)},{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)}})"
        ).unwrap();
        
        assert!(!desc.is_key_path_only());
        let tree = desc.script_tree().unwrap();
        assert_eq!(tree.leaves().len(), 4);
    }

    #[test]
    fn test_parse_deeply_nested_tree() {
        // Deeply nested: {A,{B,{C,D}}}
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),{pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5),{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)}}})"
        ).unwrap();
        
        assert!(!desc.is_key_path_only());
        let tree = desc.script_tree().unwrap();
        assert_eq!(tree.leaves().len(), 4);
    }

    #[test]
    fn test_display_key_path() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
        ).unwrap();
        
        let displayed = desc.to_string();
        assert!(displayed.starts_with("tr("));
        assert!(displayed.ends_with(")"));
    }

    #[test]
    fn test_display_script_path() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)})"
        ).unwrap();
        
        let displayed = desc.to_string();
        assert!(displayed.contains("pk("));
    }

    #[test]
    fn test_derive_address_key_path() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
        ).unwrap();
        
        let address = desc.derive_address(0, Network::BitcoinMainnet).unwrap();
        assert!(address.starts_with("bc1p"));
    }

    #[test]
    fn test_derive_address_script_path() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)})"
        ).unwrap();
        
        let address = desc.derive_address(0, Network::BitcoinMainnet).unwrap();
        assert!(address.starts_with("bc1p"));
    }

    #[test]
    fn test_derive_address_nested_tree() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)},{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)}})"
        ).unwrap();
        
        let address = desc.derive_address(0, Network::BitcoinMainnet).unwrap();
        assert!(address.starts_with("bc1p"));
    }

    #[test]
    fn test_roundtrip_key_path() {
        let original = "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let desc = TaprootDescriptor::parse(original).unwrap();
        let displayed = desc.to_string();
        let reparsed = TaprootDescriptor::parse(&displayed).unwrap();
        
        assert_eq!(desc.to_string(), reparsed.to_string());
    }

    #[test]
    fn test_roundtrip_script_path() {
        let original = "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)})";
        let desc = TaprootDescriptor::parse(original).unwrap();
        let displayed = desc.to_string();
        let reparsed = TaprootDescriptor::parse(&displayed).unwrap();
        
        assert_eq!(desc.to_string(), reparsed.to_string());
    }

    #[test]
    fn test_multi_a_script() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{multi_a(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)})"
        ).unwrap();
        
        assert!(!desc.is_key_path_only());
    }

    #[test]
    fn test_tap_tree_to_tap_node() {
        let desc = TaprootDescriptor::parse(
            "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)})"
        ).unwrap();
        
        let tree = desc.script_tree().unwrap();
        let tap_tree = tree.to_tap_tree(0).unwrap();
        
        // Verify the tap tree has the expected structure
        assert_eq!(tap_tree.leaves().len(), 2);
    }

    #[test]
    fn test_tap_descriptor_tree_builder() {
        // Build a tree programmatically
        let key1 = parse_key("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let key2 = parse_key("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").unwrap();
        
        let leaf1 = TapDescriptorTree::leaf(TapScript::Pk(key1));
        let leaf2 = TapDescriptorTree::leaf(TapScript::Pk(key2));
        let tree = TapDescriptorTree::branch(leaf1, leaf2);
        
        assert_eq!(tree.leaves().len(), 2);
    }
}
