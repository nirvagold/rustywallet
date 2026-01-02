//! Tap tree (MAST) construction
//!
//! Implements Merkle Abstract Syntax Trees for Taproot script paths.

use crate::error::TaprootError;
use crate::tagged_hash::{TapLeafHash, TapNodeHash};

/// Leaf version for Tapscript
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// Leaf version
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct LeafVersion(pub u8);

impl LeafVersion {
    /// Tapscript version (0xc0)
    pub const TAPSCRIPT: Self = Self(TAPSCRIPT_LEAF_VERSION);

    /// Create a new leaf version
    pub fn new(version: u8) -> Result<Self, TaprootError> {
        // Valid leaf versions have the lowest bit unset
        if version & 0x01 != 0 {
            return Err(TaprootError::InvalidLeafVersion(version));
        }
        Ok(Self(version))
    }

    /// Get the version byte
    pub fn to_u8(self) -> u8 {
        self.0
    }
}

impl Default for LeafVersion {
    fn default() -> Self {
        Self::TAPSCRIPT
    }
}

/// A leaf in the tap tree
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TapLeaf {
    /// Leaf version
    pub version: LeafVersion,
    /// The script
    pub script: Vec<u8>,
}

impl TapLeaf {
    /// Create a new Tapscript leaf
    pub fn new(script: Vec<u8>) -> Self {
        Self {
            version: LeafVersion::TAPSCRIPT,
            script,
        }
    }

    /// Create a leaf with custom version
    pub fn with_version(version: LeafVersion, script: Vec<u8>) -> Self {
        Self { version, script }
    }

    /// Compute the leaf hash
    pub fn hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(self.version.0, &self.script)
    }
}

/// A node in the tap tree
#[derive(Clone, Debug)]
pub enum TapNode {
    /// A leaf script
    Leaf(TapLeaf),
    /// A branch with two children
    Branch(Box<TapNode>, Box<TapNode>),
}

impl TapNode {
    /// Compute the hash of this node
    pub fn hash(&self) -> TapNodeHash {
        match self {
            TapNode::Leaf(leaf) => TapNodeHash::from_leaf(leaf.hash()),
            TapNode::Branch(left, right) => {
                TapNodeHash::from_children(&left.hash(), &right.hash())
            }
        }
    }

    /// Check if this is a leaf
    pub fn is_leaf(&self) -> bool {
        matches!(self, TapNode::Leaf(_))
    }

    /// Get the leaf if this is a leaf node
    pub fn as_leaf(&self) -> Option<&TapLeaf> {
        match self {
            TapNode::Leaf(leaf) => Some(leaf),
            TapNode::Branch(_, _) => None,
        }
    }
}

/// Complete tap tree
#[derive(Clone, Debug)]
pub struct TapTree {
    root: TapNode,
}

impl TapTree {
    /// Create a tap tree from a root node
    pub fn from_node(root: TapNode) -> Self {
        Self { root }
    }

    /// Create a tap tree with a single leaf
    pub fn single_leaf(script: Vec<u8>) -> Self {
        Self {
            root: TapNode::Leaf(TapLeaf::new(script)),
        }
    }

    /// Get the merkle root hash
    pub fn root_hash(&self) -> TapNodeHash {
        self.root.hash()
    }

    /// Get the root node
    pub fn root(&self) -> &TapNode {
        &self.root
    }

    /// Find the merkle path to a leaf
    pub fn merkle_path(&self, target_leaf: &TapLeaf) -> Option<Vec<TapNodeHash>> {
        let target_hash = target_leaf.hash();
        self.find_path(&self.root, &TapNodeHash::from_leaf(target_hash))
    }

    fn find_path(&self, node: &TapNode, target: &TapNodeHash) -> Option<Vec<TapNodeHash>> {
        match node {
            TapNode::Leaf(leaf) => {
                if TapNodeHash::from_leaf(leaf.hash()) == *target {
                    Some(Vec::new())
                } else {
                    None
                }
            }
            TapNode::Branch(left, right) => {
                // Try left branch
                if let Some(mut path) = self.find_path(left, target) {
                    path.push(right.hash());
                    return Some(path);
                }
                // Try right branch
                if let Some(mut path) = self.find_path(right, target) {
                    path.push(left.hash());
                    return Some(path);
                }
                None
            }
        }
    }

    /// Get all leaves in the tree
    pub fn leaves(&self) -> Vec<&TapLeaf> {
        let mut leaves = Vec::new();
        self.collect_leaves(&self.root, &mut leaves);
        leaves
    }

    fn collect_leaves<'a>(&'a self, node: &'a TapNode, leaves: &mut Vec<&'a TapLeaf>) {
        match node {
            TapNode::Leaf(leaf) => leaves.push(leaf),
            TapNode::Branch(left, right) => {
                self.collect_leaves(left, leaves);
                self.collect_leaves(right, leaves);
            }
        }
    }
}

/// Builder for constructing tap trees
#[derive(Default)]
pub struct TapTreeBuilder {
    leaves: Vec<(TapLeaf, u8)>, // (leaf, depth)
}

impl TapTreeBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a leaf at a specific depth
    pub fn add_leaf(mut self, depth: u8, script: Vec<u8>) -> Self {
        self.leaves.push((TapLeaf::new(script), depth));
        self
    }

    /// Add a leaf with custom version at a specific depth
    pub fn add_leaf_with_version(
        mut self,
        depth: u8,
        version: LeafVersion,
        script: Vec<u8>,
    ) -> Self {
        self.leaves.push((TapLeaf::with_version(version, script), depth));
        self
    }

    /// Build the tap tree
    pub fn build(self) -> Result<TapTree, TaprootError> {
        if self.leaves.is_empty() {
            return Err(TaprootError::EmptyTree);
        }

        if self.leaves.len() == 1 {
            return Ok(TapTree::single_leaf(self.leaves[0].0.script.clone()));
        }

        // Sort by depth (descending) for proper tree construction
        let mut leaves = self.leaves;
        leaves.sort_by(|a, b| b.1.cmp(&a.1));

        // Build tree from leaves
        let mut nodes: Vec<(TapNode, u8)> = leaves
            .into_iter()
            .map(|(leaf, depth)| (TapNode::Leaf(leaf), depth))
            .collect();

        while nodes.len() > 1 {
            // Find two nodes at the same depth
            let mut i = 0;
            while i < nodes.len() - 1 {
                if nodes[i].1 == nodes[i + 1].1 {
                    let (right, _) = nodes.remove(i + 1);
                    let (left, depth) = nodes.remove(i);
                    let branch = TapNode::Branch(Box::new(left), Box::new(right));
                    nodes.insert(i, (branch, depth.saturating_sub(1)));
                } else {
                    i += 1;
                }
            }

            // If no pairs found at same depth, we have an unbalanced tree
            // Combine the deepest nodes
            if nodes.len() > 1 && nodes.iter().all(|(_, d)| *d == nodes[0].1) {
                // All at same depth but odd number - this shouldn't happen with valid input
                break;
            }
        }

        if nodes.len() != 1 {
            return Err(TaprootError::TreeError(
                "Could not build balanced tree".into(),
            ));
        }

        Ok(TapTree::from_node(nodes.remove(0).0))
    }
}

/// Create a simple 2-leaf tree
pub fn two_leaf_tree(script1: Vec<u8>, script2: Vec<u8>) -> TapTree {
    let left = TapNode::Leaf(TapLeaf::new(script1));
    let right = TapNode::Leaf(TapLeaf::new(script2));
    TapTree::from_node(TapNode::Branch(Box::new(left), Box::new(right)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash() {
        let leaf = TapLeaf::new(vec![0x51]); // OP_1
        let hash = leaf.hash();
        
        // Hash should be deterministic
        let hash2 = leaf.hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_single_leaf_tree() {
        let tree = TapTree::single_leaf(vec![0x51]);
        let leaves = tree.leaves();
        assert_eq!(leaves.len(), 1);
    }

    #[test]
    fn test_two_leaf_tree() {
        let tree = two_leaf_tree(vec![0x51], vec![0x52]);
        let leaves = tree.leaves();
        assert_eq!(leaves.len(), 2);
    }

    #[test]
    fn test_merkle_path() {
        let script1 = vec![0x51];
        let script2 = vec![0x52];
        let tree = two_leaf_tree(script1.clone(), script2.clone());
        
        let leaf1 = TapLeaf::new(script1);
        let path = tree.merkle_path(&leaf1).unwrap();
        
        // Path should have one element (the sibling hash)
        assert_eq!(path.len(), 1);
    }

    #[test]
    fn test_builder_single_leaf() {
        let tree = TapTreeBuilder::new()
            .add_leaf(0, vec![0x51])
            .build()
            .unwrap();
        
        assert_eq!(tree.leaves().len(), 1);
    }

    #[test]
    fn test_builder_two_leaves() {
        let tree = TapTreeBuilder::new()
            .add_leaf(1, vec![0x51])
            .add_leaf(1, vec![0x52])
            .build()
            .unwrap();
        
        assert_eq!(tree.leaves().len(), 2);
    }

    #[test]
    fn test_leaf_version() {
        assert!(LeafVersion::new(0xc0).is_ok());
        assert!(LeafVersion::new(0xc2).is_ok());
        assert!(LeafVersion::new(0xc1).is_err()); // Odd version invalid
    }

    #[test]
    fn test_branch_hash_deterministic() {
        let tree1 = two_leaf_tree(vec![0x51], vec![0x52]);
        let tree2 = two_leaf_tree(vec![0x51], vec![0x52]);
        
        assert_eq!(tree1.root_hash(), tree2.root_hash());
    }
}
