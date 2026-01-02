//! Script building utilities.

use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

/// Script opcodes.
pub mod opcodes {
    pub const OP_0: u8 = 0x00;
    pub const OP_PUSHBYTES_20: u8 = 0x14;
    pub const OP_PUSHBYTES_32: u8 = 0x20;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_EQUAL: u8 = 0x87;
}

/// Build a P2PKH (Pay-to-Public-Key-Hash) script.
///
/// Format: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
pub fn build_p2pkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(opcodes::OP_DUP);
    script.push(opcodes::OP_HASH160);
    script.push(opcodes::OP_PUSHBYTES_20);
    script.extend_from_slice(pubkey_hash);
    script.push(opcodes::OP_EQUALVERIFY);
    script.push(opcodes::OP_CHECKSIG);
    script
}

/// Build a P2WPKH (Pay-to-Witness-Public-Key-Hash) script.
///
/// Format: OP_0 <20-byte hash>
pub fn build_p2wpkh_script(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(opcodes::OP_0);
    script.push(opcodes::OP_PUSHBYTES_20);
    script.extend_from_slice(pubkey_hash);
    script
}

/// Build a P2TR (Pay-to-Taproot) script.
///
/// Format: OP_1 <32-byte x-only pubkey>
pub fn build_p2tr_script(x_only_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(0x51); // OP_1
    script.push(opcodes::OP_PUSHBYTES_32);
    script.extend_from_slice(x_only_pubkey);
    script
}

/// Hash160 (SHA256 + RIPEMD160).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    ripemd.into()
}

/// Build P2PKH scriptPubKey from compressed public key.
pub fn p2pkh_script_from_pubkey(pubkey: &[u8; 33]) -> Vec<u8> {
    let pubkey_hash = hash160(pubkey);
    build_p2pkh_script(&pubkey_hash)
}

/// Build P2WPKH scriptPubKey from compressed public key.
pub fn p2wpkh_script_from_pubkey(pubkey: &[u8; 33]) -> Vec<u8> {
    let pubkey_hash = hash160(pubkey);
    build_p2wpkh_script(&pubkey_hash)
}

/// Extract pubkey hash from P2PKH script.
pub fn extract_p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 25
        && script[0] == opcodes::OP_DUP
        && script[1] == opcodes::OP_HASH160
        && script[2] == opcodes::OP_PUSHBYTES_20
        && script[23] == opcodes::OP_EQUALVERIFY
        && script[24] == opcodes::OP_CHECKSIG
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[3..23]);
        Some(hash)
    } else {
        None
    }
}

/// Extract pubkey hash from P2WPKH script.
pub fn extract_p2wpkh_hash(script: &[u8]) -> Option<[u8; 20]> {
    if script.len() == 22
        && script[0] == opcodes::OP_0
        && script[1] == opcodes::OP_PUSHBYTES_20
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[2..22]);
        Some(hash)
    } else {
        None
    }
}

/// Check if script is P2PKH.
pub fn is_p2pkh(script: &[u8]) -> bool {
    extract_p2pkh_hash(script).is_some()
}

/// Check if script is P2WPKH.
pub fn is_p2wpkh(script: &[u8]) -> bool {
    extract_p2wpkh_hash(script).is_some()
}

/// Check if script is P2TR.
pub fn is_p2tr(script: &[u8]) -> bool {
    script.len() == 34 && script[0] == 0x51 && script[1] == opcodes::OP_PUSHBYTES_32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_p2pkh_script() {
        let hash = [0u8; 20];
        let script = build_p2pkh_script(&hash);
        assert_eq!(script.len(), 25);
        assert!(is_p2pkh(&script));
    }

    #[test]
    fn test_build_p2wpkh_script() {
        let hash = [0u8; 20];
        let script = build_p2wpkh_script(&hash);
        assert_eq!(script.len(), 22);
        assert!(is_p2wpkh(&script));
    }

    #[test]
    fn test_build_p2tr_script() {
        let pubkey = [0u8; 32];
        let script = build_p2tr_script(&pubkey);
        assert_eq!(script.len(), 34);
        assert!(is_p2tr(&script));
    }

    #[test]
    fn test_extract_p2pkh_hash() {
        let hash = [1u8; 20];
        let script = build_p2pkh_script(&hash);
        let extracted = extract_p2pkh_hash(&script).unwrap();
        assert_eq!(extracted, hash);
    }
}
