//! Multisig address generation.

use crate::config::MultisigConfig;
use crate::error::{MultisigError, Result};
use crate::script::{build_multisig_script, build_p2sh_p2wsh_redeem_script};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

/// Network for address generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
}

/// A complete multisig wallet with all address types.
#[derive(Debug, Clone)]
pub struct MultisigWallet {
    /// The multisig configuration
    pub config: MultisigConfig,
    /// The redeem script (for P2SH)
    pub redeem_script: Vec<u8>,
    /// P2SH address (legacy, starts with 3 or 2)
    pub address_p2sh: String,
    /// P2WSH address (native SegWit, starts with bc1q or tb1q)
    pub address_p2wsh: String,
    /// P2SH-P2WSH address (nested SegWit, starts with 3 or 2)
    pub address_p2sh_p2wsh: String,
    /// Network
    pub network: Network,
}

impl MultisigWallet {
    /// Create a new multisig wallet from configuration.
    pub fn new(config: MultisigConfig, network: Network) -> Result<Self> {
        let redeem_script = build_multisig_script(&config);
        
        // P2SH address
        let script_hash = hash160(&redeem_script);
        let address_p2sh = encode_p2sh_address(&script_hash, network);

        // P2WSH address (witness script = redeem script for multisig)
        let witness_script_hash = sha256(&redeem_script);
        let address_p2wsh = encode_p2wsh_address(&witness_script_hash, network)
            .map_err(MultisigError::AddressFailed)?;

        // P2SH-P2WSH address
        let nested_redeem = build_p2sh_p2wsh_redeem_script(&witness_script_hash);
        let nested_hash = hash160(&nested_redeem);
        let address_p2sh_p2wsh = encode_p2sh_address(&nested_hash, network);

        Ok(Self {
            config,
            redeem_script,
            address_p2sh,
            address_p2wsh,
            address_p2sh_p2wsh,
            network,
        })
    }

    /// Create from public keys.
    pub fn from_pubkeys(
        threshold: u8,
        public_keys: Vec<[u8; 33]>,
        network: Network,
    ) -> Result<Self> {
        let config = MultisigConfig::new(threshold, public_keys)?;
        Self::new(config, network)
    }

    /// Get the witness script (same as redeem script for P2WSH).
    pub fn witness_script(&self) -> &[u8] {
        &self.redeem_script
    }

    /// Get the witness script hash (for P2WSH).
    pub fn witness_script_hash(&self) -> [u8; 32] {
        sha256(&self.redeem_script)
    }

    /// Get the nested redeem script (for P2SH-P2WSH).
    pub fn nested_redeem_script(&self) -> Vec<u8> {
        let wsh = self.witness_script_hash();
        build_p2sh_p2wsh_redeem_script(&wsh)
    }
}

/// Compute HASH160 (SHA256 + RIPEMD160).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd);
    result
}

/// Compute SHA256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Encode P2SH address (base58check).
fn encode_p2sh_address(script_hash: &[u8; 20], network: Network) -> String {
    let version = match network {
        Network::Mainnet => 0x05,
        Network::Testnet => 0xc4,
    };

    let mut data = Vec::with_capacity(25);
    data.push(version);
    data.extend_from_slice(script_hash);

    // Checksum
    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);

    bs58::encode(data).into_string()
}

/// Encode P2WSH address (bech32).
fn encode_p2wsh_address(script_hash: &[u8; 32], network: Network) -> std::result::Result<String, String> {
    let hrp = match network {
        Network::Mainnet => bech32::Hrp::parse("bc").unwrap(),
        Network::Testnet => bech32::Hrp::parse("tb").unwrap(),
    };

    // Witness version 0 + 32-byte hash
    let mut data = Vec::with_capacity(33);
    data.push(0); // witness version
    data.extend_from_slice(script_hash);

    bech32::segwit::encode(hrp, bech32::segwit::VERSION_0, script_hash)
        .map_err(|e| e.to_string())
}

/// Double SHA256.
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pubkey(seed: u8) -> [u8; 33] {
        let mut key = [seed; 33];
        key[0] = 0x02;
        key
    }

    #[test]
    fn test_create_2_of_3_wallet() {
        let keys = vec![make_pubkey(1), make_pubkey(2), make_pubkey(3)];
        let wallet = MultisigWallet::from_pubkeys(2, keys, Network::Mainnet).unwrap();

        assert!(wallet.address_p2sh.starts_with('3'));
        assert!(wallet.address_p2wsh.starts_with("bc1q"));
        assert!(wallet.address_p2sh_p2wsh.starts_with('3'));
    }

    #[test]
    fn test_testnet_addresses() {
        let keys = vec![make_pubkey(1), make_pubkey(2), make_pubkey(3)];
        let wallet = MultisigWallet::from_pubkeys(2, keys, Network::Testnet).unwrap();

        assert!(wallet.address_p2sh.starts_with('2'));
        assert!(wallet.address_p2wsh.starts_with("tb1q"));
        assert!(wallet.address_p2sh_p2wsh.starts_with('2'));
    }

    #[test]
    fn test_redeem_script_not_empty() {
        let keys = vec![make_pubkey(1), make_pubkey(2)];
        let wallet = MultisigWallet::from_pubkeys(2, keys, Network::Mainnet).unwrap();

        assert!(!wallet.redeem_script.is_empty());
        assert!(!wallet.witness_script().is_empty());
    }

    #[test]
    fn test_hash160() {
        let data = b"hello";
        let hash = hash160(data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha256() {
        let data = b"hello";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
    }
}
