//! Tagged hashes for BIP340/341
//!
//! Tagged hashes provide domain separation: SHA256(SHA256(tag) || SHA256(tag) || data)

use sha2::{Digest, Sha256};

/// Predefined tag for TapLeaf hash
pub const TAG_TAP_LEAF: &str = "TapLeaf";
/// Predefined tag for TapBranch hash
pub const TAG_TAP_BRANCH: &str = "TapBranch";
/// Predefined tag for TapTweak hash
pub const TAG_TAP_TWEAK: &str = "TapTweak";
/// Predefined tag for TapSighash
pub const TAG_TAP_SIGHASH: &str = "TapSighash";
/// Predefined tag for BIP340 challenge
pub const TAG_BIP340_CHALLENGE: &str = "BIP0340/challenge";
/// Predefined tag for BIP340 aux
pub const TAG_BIP340_AUX: &str = "BIP0340/aux";
/// Predefined tag for BIP340 nonce
pub const TAG_BIP340_NONCE: &str = "BIP0340/nonce";

/// Compute a tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// TapLeaf hash
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TapLeafHash(pub [u8; 32]);

impl TapLeafHash {
    /// Compute TapLeaf hash from leaf version and script
    pub fn from_script(leaf_version: u8, script: &[u8]) -> Self {
        let mut data = Vec::with_capacity(1 + script.len());
        data.push(leaf_version);
        data.extend_from_slice(script);
        Self(tagged_hash(TAG_TAP_LEAF, &data))
    }

    /// Get the inner bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to byte array
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for TapLeafHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// TapBranch/TapNode hash
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TapNodeHash(pub [u8; 32]);

impl TapNodeHash {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Compute TapBranch hash from two child hashes
    /// Children are sorted lexicographically before hashing
    pub fn from_children(left: &TapNodeHash, right: &TapNodeHash) -> Self {
        let mut data = [0u8; 64];
        
        // Sort lexicographically
        if left.0 <= right.0 {
            data[..32].copy_from_slice(&left.0);
            data[32..].copy_from_slice(&right.0);
        } else {
            data[..32].copy_from_slice(&right.0);
            data[32..].copy_from_slice(&left.0);
        }
        
        Self(tagged_hash(TAG_TAP_BRANCH, &data))
    }

    /// Create from a leaf hash
    pub fn from_leaf(leaf: TapLeafHash) -> Self {
        Self(leaf.0)
    }

    /// Get the inner bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to byte array
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for TapNodeHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<TapLeafHash> for TapNodeHash {
    fn from(leaf: TapLeafHash) -> Self {
        Self(leaf.0)
    }
}

/// TapTweak hash
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TapTweakHash(pub [u8; 32]);

impl TapTweakHash {
    /// Compute TapTweak hash from internal key and merkle root
    pub fn from_key_and_merkle_root(internal_key: &[u8; 32], merkle_root: Option<&TapNodeHash>) -> Self {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(internal_key);
        if let Some(root) = merkle_root {
            data.extend_from_slice(&root.0);
        }
        Self(tagged_hash(TAG_TAP_TWEAK, &data))
    }

    /// Get the inner bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to byte array
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for TapTweakHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_hash() {
        // Test that tagged hash produces consistent results
        let hash1 = tagged_hash("test", b"data");
        let hash2 = tagged_hash("test", b"data");
        assert_eq!(hash1, hash2);

        // Different tags produce different hashes
        let hash3 = tagged_hash("other", b"data");
        assert_ne!(hash1, hash3);

        // Different data produces different hashes
        let hash4 = tagged_hash("test", b"other");
        assert_ne!(hash1, hash4);
    }

    #[test]
    fn test_tap_leaf_hash() {
        let script = vec![0x51]; // OP_1
        let leaf_hash = TapLeafHash::from_script(0xc0, &script);
        
        // Should be deterministic
        let leaf_hash2 = TapLeafHash::from_script(0xc0, &script);
        assert_eq!(leaf_hash, leaf_hash2);
    }

    #[test]
    fn test_tap_branch_hash_ordering() {
        let left = TapNodeHash([0x01; 32]);
        let right = TapNodeHash([0x02; 32]);

        // Order shouldn't matter - children are sorted
        let hash1 = TapNodeHash::from_children(&left, &right);
        let hash2 = TapNodeHash::from_children(&right, &left);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_tap_tweak_hash() {
        let internal_key = [0x02; 32];
        
        // Without merkle root
        let tweak1 = TapTweakHash::from_key_and_merkle_root(&internal_key, None);
        
        // With merkle root
        let merkle_root = TapNodeHash([0x03; 32]);
        let tweak2 = TapTweakHash::from_key_and_merkle_root(&internal_key, Some(&merkle_root));
        
        assert_ne!(tweak1.0, tweak2.0);
    }
}
