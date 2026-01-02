//! Taproot output and address generation
//!
//! Implements P2TR address generation from internal keys and script trees.

use crate::error::TaprootError;
use crate::tagged_hash::TapNodeHash;
use crate::taptree::TapTree;
use crate::tweak::tweak_public_key;
use crate::xonly::{Parity, XOnlyPublicKey};
use bech32::Hrp;

/// Network for address generation
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin signet
    Signet,
    /// Bitcoin regtest
    Regtest,
}

impl Network {
    /// Get the bech32 human-readable part
    pub fn hrp(&self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet | Network::Signet => "tb",
            Network::Regtest => "bcrt",
        }
    }
}

/// Taproot output key and spending info
#[derive(Clone, Debug)]
pub struct TaprootOutput {
    /// The output public key (tweaked)
    pub output_key: XOnlyPublicKey,
    /// Parity of the output key
    pub parity: Parity,
    /// Internal key (before tweaking)
    pub internal_key: XOnlyPublicKey,
    /// Merkle root (None for key-path only)
    pub merkle_root: Option<TapNodeHash>,
}

impl TaprootOutput {
    /// Create a key-path only output (no script tree)
    pub fn key_path_only(internal_key: XOnlyPublicKey) -> Result<Self, TaprootError> {
        let (output_key, parity) = tweak_public_key(&internal_key, None)?;

        Ok(Self {
            output_key,
            parity,
            internal_key,
            merkle_root: None,
        })
    }

    /// Create an output with a script tree
    pub fn with_script_tree(
        internal_key: XOnlyPublicKey,
        tree: &TapTree,
    ) -> Result<Self, TaprootError> {
        let merkle_root = tree.root_hash();
        let (output_key, parity) = tweak_public_key(&internal_key, Some(&merkle_root))?;

        Ok(Self {
            output_key,
            parity,
            internal_key,
            merkle_root: Some(merkle_root),
        })
    }

    /// Create from output key directly (for parsing existing outputs)
    pub fn from_output_key(output_key: XOnlyPublicKey) -> Self {
        Self {
            output_key,
            parity: Parity::Even, // Unknown, default to even
            internal_key: output_key, // Unknown, use output key
            merkle_root: None,
        }
    }

    /// Get the P2TR script pubkey (OP_1 <32-byte-key>)
    pub fn script_pubkey(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(34);
        script.push(0x51); // OP_1 (witness version 1)
        script.push(0x20); // Push 32 bytes
        script.extend_from_slice(&self.output_key.serialize());
        script
    }

    /// Get the bech32m address
    pub fn address(&self, network: Network) -> Result<String, TaprootError> {
        let hrp = Hrp::parse(network.hrp())
            .map_err(|e| TaprootError::InvalidScript(e.to_string()))?;

        // Witness version 1 + 32-byte key
        let mut data = Vec::with_capacity(33);
        data.push(1); // witness version
        data.extend_from_slice(&self.output_key.serialize());

        bech32::segwit::encode(hrp, bech32::segwit::VERSION_1, &self.output_key.serialize())
            .map_err(|e| TaprootError::InvalidScript(e.to_string()))
    }

    /// Check if this is a key-path only output
    pub fn is_key_path_only(&self) -> bool {
        self.merkle_root.is_none()
    }
}

/// Parse a P2TR address
pub fn parse_address(address: &str) -> Result<XOnlyPublicKey, TaprootError> {
    let (_hrp, version, program) = bech32::segwit::decode(address)
        .map_err(|e| TaprootError::InvalidScript(e.to_string()))?;

    // Check witness version
    if version != bech32::segwit::VERSION_1 {
        return Err(TaprootError::InvalidScript(format!(
            "Expected witness version 1, got {:?}",
            version
        )));
    }

    // Check program length
    if program.len() != 32 {
        return Err(TaprootError::InvalidLength {
            expected: 32,
            got: program.len(),
        });
    }

    XOnlyPublicKey::from_slice(&program)
}

/// Check if an address is a valid P2TR address
pub fn is_p2tr_address(address: &str) -> bool {
    parse_address(address).is_ok()
}

/// Create a P2TR address from an x-only public key
pub fn create_address(pubkey: &XOnlyPublicKey, network: Network) -> Result<String, TaprootError> {
    let output = TaprootOutput::from_output_key(*pubkey);
    output.address(network)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_key_path_only() {
        let internal_key = get_test_internal_key();
        let output = TaprootOutput::key_path_only(internal_key).unwrap();

        assert!(output.is_key_path_only());
        assert!(output.merkle_root.is_none());
        assert_ne!(output.output_key, internal_key); // Should be tweaked
    }

    #[test]
    fn test_script_pubkey() {
        let internal_key = get_test_internal_key();
        let output = TaprootOutput::key_path_only(internal_key).unwrap();

        let script = output.script_pubkey();
        assert_eq!(script.len(), 34);
        assert_eq!(script[0], 0x51); // OP_1
        assert_eq!(script[1], 0x20); // Push 32 bytes
    }

    #[test]
    fn test_address_mainnet() {
        let internal_key = get_test_internal_key();
        let output = TaprootOutput::key_path_only(internal_key).unwrap();

        let address = output.address(Network::Mainnet).unwrap();
        assert!(address.starts_with("bc1p"));
    }

    #[test]
    fn test_address_testnet() {
        let internal_key = get_test_internal_key();
        let output = TaprootOutput::key_path_only(internal_key).unwrap();

        let address = output.address(Network::Testnet).unwrap();
        assert!(address.starts_with("tb1p"));
    }

    #[test]
    fn test_address_roundtrip() {
        let internal_key = get_test_internal_key();
        let output = TaprootOutput::key_path_only(internal_key).unwrap();

        let address = output.address(Network::Mainnet).unwrap();
        let parsed = parse_address(&address).unwrap();

        assert_eq!(output.output_key, parsed);
    }

    #[test]
    fn test_with_script_tree() {
        use crate::taptree::two_leaf_tree;

        let internal_key = get_test_internal_key();
        let tree = two_leaf_tree(vec![0x51], vec![0x52]);

        let output = TaprootOutput::with_script_tree(internal_key, &tree).unwrap();

        assert!(!output.is_key_path_only());
        assert!(output.merkle_root.is_some());
    }

    #[test]
    fn test_is_p2tr_address() {
        let internal_key = get_test_internal_key();
        let output = TaprootOutput::key_path_only(internal_key).unwrap();
        let address = output.address(Network::Mainnet).unwrap();

        assert!(is_p2tr_address(&address));
        assert!(!is_p2tr_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")); // P2WPKH
        assert!(!is_p2tr_address("invalid"));
    }
}
