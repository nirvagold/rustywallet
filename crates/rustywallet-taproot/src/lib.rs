//! # rustywallet-taproot
//!
//! Full Taproot support implementing BIP340 (Schnorr), BIP341 (Taproot), and BIP342 (Tapscript).
//!
//! ## Features
//!
//! - Schnorr signatures (BIP340)
//! - X-only public keys
//! - Key tweaking for Taproot
//! - Tap tree (MAST) construction
//! - Control block generation
//! - P2TR address generation
//! - BIP341 signature hash
//!
//! ## Example
//!
//! ```rust
//! use rustywallet_taproot::{XOnlyPublicKey, TaprootOutput, Network};
//! use secp256k1::{Secp256k1, SecretKey};
//!
//! // Generate a key pair
//! let secp = Secp256k1::new();
//! let secret = [1u8; 32];
//! let sk = SecretKey::from_slice(&secret).unwrap();
//! let pk = sk.public_key(&secp);
//! let (xonly, _) = pk.x_only_public_key();
//! let internal_key = XOnlyPublicKey::from_inner(xonly);
//!
//! // Create a key-path only Taproot output
//! let output = TaprootOutput::key_path_only(internal_key).unwrap();
//!
//! // Get the P2TR address
//! let address = output.address(Network::Mainnet).unwrap();
//! assert!(address.starts_with("bc1p"));
//! ```
//!
//! ## Script Path Example
//!
//! ```rust
//! use rustywallet_taproot::{XOnlyPublicKey, TaprootOutput, TapTreeBuilder, Network};
//! use secp256k1::{Secp256k1, SecretKey};
//!
//! let secp = Secp256k1::new();
//! let secret = [1u8; 32];
//! let sk = SecretKey::from_slice(&secret).unwrap();
//! let pk = sk.public_key(&secp);
//! let (xonly, _) = pk.x_only_public_key();
//! let internal_key = XOnlyPublicKey::from_inner(xonly);
//!
//! // Build a tap tree with two scripts
//! let tree = TapTreeBuilder::new()
//!     .add_leaf(1, vec![0x51]) // OP_1
//!     .add_leaf(1, vec![0x52]) // OP_2
//!     .build()
//!     .unwrap();
//!
//! // Create output with script tree
//! let output = TaprootOutput::with_script_tree(internal_key, &tree).unwrap();
//! let address = output.address(Network::Mainnet).unwrap();
//! ```

pub mod control_block;
pub mod error;
pub mod schnorr;
pub mod sighash;
pub mod tagged_hash;
pub mod taproot;
pub mod taptree;
pub mod tweak;
pub mod xonly;

// Re-exports
pub use control_block::ControlBlock;
pub use error::TaprootError;
pub use schnorr::SchnorrSignature;
pub use sighash::{taproot_key_path_sighash, taproot_script_path_sighash, TaprootSighashType};
pub use tagged_hash::{tagged_hash, TapLeafHash, TapNodeHash, TapTweakHash};
pub use taproot::{create_address, is_p2tr_address, parse_address, Network, TaprootOutput};
pub use taptree::{LeafVersion, TapLeaf, TapNode, TapTree, TapTreeBuilder};
pub use tweak::{compute_output_key, compute_tweak, tweak_private_key, tweak_public_key};
pub use xonly::{Parity, XOnlyPublicKey};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::control_block::ControlBlock;
    pub use crate::error::TaprootError;
    pub use crate::schnorr::SchnorrSignature;
    pub use crate::sighash::TaprootSighashType;
    pub use crate::tagged_hash::{TapLeafHash, TapNodeHash, TapTweakHash};
    pub use crate::taproot::{Network, TaprootOutput};
    pub use crate::taptree::{LeafVersion, TapLeaf, TapTree, TapTreeBuilder};
    pub use crate::xonly::{Parity, XOnlyPublicKey};
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn get_test_keypair() -> ([u8; 32], XOnlyPublicKey) {
        let secp = Secp256k1::new();
        let secret = [1u8; 32];
        let sk = SecretKey::from_slice(&secret).unwrap();
        let pk = sk.public_key(&secp);
        let (xonly, _) = pk.x_only_public_key();
        (secret, XOnlyPublicKey::from_inner(xonly))
    }

    #[test]
    fn test_key_path_workflow() {
        let (secret, internal_key) = get_test_keypair();

        // Create output
        let output = TaprootOutput::key_path_only(internal_key).unwrap();

        // Get address
        let address = output.address(Network::Mainnet).unwrap();
        assert!(address.starts_with("bc1p"));

        // Parse address back
        let parsed = parse_address(&address).unwrap();
        assert_eq!(output.output_key, parsed);
    }

    #[test]
    fn test_script_path_workflow() {
        let (_, internal_key) = get_test_keypair();

        // Build tree
        let tree = TapTreeBuilder::new()
            .add_leaf(1, vec![0x51])
            .add_leaf(1, vec![0x52])
            .build()
            .unwrap();

        // Create output
        let output = TaprootOutput::with_script_tree(internal_key, &tree).unwrap();
        assert!(!output.is_key_path_only());

        // Get control block for first leaf
        let leaf = TapLeaf::new(vec![0x51]);
        let cb = ControlBlock::for_leaf(&tree, &leaf, internal_key, output.parity).unwrap();

        // Verify control block
        assert!(cb.verify(&output.output_key, &leaf.script).unwrap());
    }

    #[test]
    fn test_schnorr_signing() {
        let (secret, pubkey) = get_test_keypair();
        let message = [0x42u8; 32];

        let sig = SchnorrSignature::sign(&message, &secret).unwrap();
        assert!(sig.verify(&message, &pubkey));
    }
}
