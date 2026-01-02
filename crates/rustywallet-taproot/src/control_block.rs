//! Control block for Taproot script path spending
//!
//! The control block proves that a script is part of the tap tree.

use crate::error::TaprootError;
use crate::tagged_hash::TapNodeHash;
use crate::taptree::{LeafVersion, TapLeaf, TapTree};
use crate::xonly::{Parity, XOnlyPublicKey};

/// Control block for script path spending
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlBlock {
    /// Leaf version and output key parity (combined in first byte)
    pub leaf_version: LeafVersion,
    /// Output key parity
    pub output_key_parity: Parity,
    /// Internal key (32 bytes)
    pub internal_key: XOnlyPublicKey,
    /// Merkle path (32-byte hashes)
    pub merkle_path: Vec<TapNodeHash>,
}

impl ControlBlock {
    /// Create a new control block
    pub fn new(
        leaf_version: LeafVersion,
        output_key_parity: Parity,
        internal_key: XOnlyPublicKey,
        merkle_path: Vec<TapNodeHash>,
    ) -> Self {
        Self {
            leaf_version,
            output_key_parity,
            internal_key,
            merkle_path,
        }
    }

    /// Create control block for a leaf in a tree
    pub fn for_leaf(
        tree: &TapTree,
        leaf: &TapLeaf,
        internal_key: XOnlyPublicKey,
        output_key_parity: Parity,
    ) -> Result<Self, TaprootError> {
        let merkle_path = tree
            .merkle_path(leaf)
            .ok_or(TaprootError::InvalidMerklePath)?;

        Ok(Self {
            leaf_version: leaf.version,
            output_key_parity,
            internal_key,
            merkle_path,
        })
    }

    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33 + self.merkle_path.len() * 32);

        // First byte: leaf version | parity bit
        let first_byte = self.leaf_version.0 | self.output_key_parity.to_u8();
        bytes.push(first_byte);

        // Internal key (32 bytes)
        bytes.extend_from_slice(&self.internal_key.serialize());

        // Merkle path
        for hash in &self.merkle_path {
            bytes.extend_from_slice(hash.as_bytes());
        }

        bytes
    }

    /// Parse from bytes
    pub fn from_slice(data: &[u8]) -> Result<Self, TaprootError> {
        if data.len() < 33 {
            return Err(TaprootError::InvalidControlBlock(
                "Control block too short".into(),
            ));
        }

        if !(data.len() - 33).is_multiple_of(32) {
            return Err(TaprootError::InvalidControlBlock(
                "Invalid merkle path length".into(),
            ));
        }

        let first_byte = data[0];
        let leaf_version = LeafVersion(first_byte & 0xfe);
        let output_key_parity = Parity::from_u8(first_byte & 0x01)?;

        let internal_key = XOnlyPublicKey::from_slice(&data[1..33])?;

        let path_count = (data.len() - 33) / 32;
        let mut merkle_path = Vec::with_capacity(path_count);
        for i in 0..path_count {
            let start = 33 + i * 32;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[start..start + 32]);
            merkle_path.push(TapNodeHash::from_bytes(hash));
        }

        Ok(Self {
            leaf_version,
            output_key_parity,
            internal_key,
            merkle_path,
        })
    }

    /// Verify the control block against an output key and script
    pub fn verify(
        &self,
        output_key: &XOnlyPublicKey,
        script: &[u8],
    ) -> Result<bool, TaprootError> {
        use crate::tweak::tweak_public_key;

        // Compute leaf hash
        let leaf_hash = crate::tagged_hash::TapLeafHash::from_script(
            self.leaf_version.0,
            script,
        );

        // Compute merkle root by walking up the path
        let mut current = TapNodeHash::from_leaf(leaf_hash);
        for sibling in &self.merkle_path {
            current = TapNodeHash::from_children(&current, sibling);
        }

        // Compute expected output key
        let (expected_output, expected_parity) = tweak_public_key(
            &self.internal_key,
            Some(&current),
        )?;

        // Verify
        Ok(expected_output == *output_key && expected_parity == self.output_key_parity)
    }

    /// Get the size in bytes
    pub fn size(&self) -> usize {
        33 + self.merkle_path.len() * 32
    }

    /// Get the merkle path depth
    pub fn depth(&self) -> usize {
        self.merkle_path.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taptree::two_leaf_tree;
    use crate::tweak::tweak_public_key;
    use secp256k1::{Secp256k1, SecretKey};

    fn get_test_internal_key() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let secret = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let sk = SecretKey::from_slice(&secret).unwrap();
        let pk = sk.public_key(&secp);
        let (xonly, _) = pk.x_only_public_key();
        XOnlyPublicKey::from_inner(xonly)
    }

    #[test]
    fn test_control_block_roundtrip() {
        let internal_key = get_test_internal_key();
        let merkle_path = vec![TapNodeHash::from_bytes([0x42; 32])];

        let cb = ControlBlock::new(
            LeafVersion::TAPSCRIPT,
            Parity::Even,
            internal_key,
            merkle_path,
        );

        let bytes = cb.serialize();
        let parsed = ControlBlock::from_slice(&bytes).unwrap();

        assert_eq!(cb.leaf_version, parsed.leaf_version);
        assert_eq!(cb.output_key_parity, parsed.output_key_parity);
        assert_eq!(cb.internal_key, parsed.internal_key);
        assert_eq!(cb.merkle_path, parsed.merkle_path);
    }

    #[test]
    fn test_control_block_size() {
        let internal_key = get_test_internal_key();

        // No merkle path
        let cb = ControlBlock::new(
            LeafVersion::TAPSCRIPT,
            Parity::Even,
            internal_key,
            vec![],
        );
        assert_eq!(cb.size(), 33);

        // One element in path
        let cb = ControlBlock::new(
            LeafVersion::TAPSCRIPT,
            Parity::Even,
            internal_key,
            vec![TapNodeHash::from_bytes([0; 32])],
        );
        assert_eq!(cb.size(), 65);
    }

    #[test]
    fn test_control_block_verify() {
        let internal_key = get_test_internal_key();
        let script1 = vec![0x51]; // OP_1
        let script2 = vec![0x52]; // OP_2

        let tree = two_leaf_tree(script1.clone(), script2);
        let merkle_root = tree.root_hash();

        let (output_key, parity) = tweak_public_key(&internal_key, Some(&merkle_root)).unwrap();

        let leaf = crate::taptree::TapLeaf::new(script1.clone());
        let cb = ControlBlock::for_leaf(&tree, &leaf, internal_key, parity).unwrap();

        assert!(cb.verify(&output_key, &script1).unwrap());
    }

    #[test]
    fn test_first_byte_encoding() {
        let internal_key = get_test_internal_key();

        // Even parity
        let cb = ControlBlock::new(
            LeafVersion::TAPSCRIPT,
            Parity::Even,
            internal_key,
            vec![],
        );
        let bytes = cb.serialize();
        assert_eq!(bytes[0], 0xc0); // 0xc0 | 0 = 0xc0

        // Odd parity
        let cb = ControlBlock::new(
            LeafVersion::TAPSCRIPT,
            Parity::Odd,
            internal_key,
            vec![],
        );
        let bytes = cb.serialize();
        assert_eq!(bytes[0], 0xc1); // 0xc0 | 1 = 0xc1
    }
}
