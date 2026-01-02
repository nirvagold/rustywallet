//! Script generation from descriptors
//!
//! Generates script pubkeys for different descriptor types.

use crate::descriptor::Descriptor;
use crate::error::DescriptorError;
use rustywallet_keys::public_key::{PublicKey, PublicKeyFormat};
use sha2::{Sha256, Digest};

/// Script pubkey generated from a descriptor
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptPubkey {
    /// The raw script bytes
    pub script: Vec<u8>,
    /// Script type
    pub script_type: ScriptType,
}

/// Type of script
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptType {
    /// P2PK - Pay to pubkey
    P2pk,
    /// P2PKH - Pay to pubkey hash
    P2pkh,
    /// P2SH - Pay to script hash
    P2sh,
    /// P2WPKH - Pay to witness pubkey hash
    P2wpkh,
    /// P2WSH - Pay to witness script hash
    P2wsh,
    /// P2TR - Pay to Taproot
    P2tr,
}

impl ScriptPubkey {
    /// Create a P2PK script
    pub fn p2pk(pubkey: &PublicKey) -> Self {
        let pk_bytes = hex::decode(pubkey.to_hex(PublicKeyFormat::Compressed)).unwrap();
        let mut script = Vec::with_capacity(pk_bytes.len() + 2);
        script.push(pk_bytes.len() as u8); // Push pubkey length
        script.extend_from_slice(&pk_bytes);
        script.push(0xac); // OP_CHECKSIG
        
        Self {
            script,
            script_type: ScriptType::P2pk,
        }
    }

    /// Create a P2PKH script
    pub fn p2pkh(pubkey: &PublicKey) -> Self {
        let pk_bytes = hex::decode(pubkey.to_hex(PublicKeyFormat::Compressed)).unwrap();
        let pubkey_hash = hash160(&pk_bytes);
        
        let mut script = Vec::with_capacity(25);
        script.push(0x76); // OP_DUP
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(&pubkey_hash);
        script.push(0x88); // OP_EQUALVERIFY
        script.push(0xac); // OP_CHECKSIG
        
        Self {
            script,
            script_type: ScriptType::P2pkh,
        }
    }

    /// Create a P2SH script
    pub fn p2sh(redeem_script: &[u8]) -> Self {
        let script_hash = hash160(redeem_script);
        
        let mut script = Vec::with_capacity(23);
        script.push(0xa9); // OP_HASH160
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(&script_hash);
        script.push(0x87); // OP_EQUAL
        
        Self {
            script,
            script_type: ScriptType::P2sh,
        }
    }

    /// Create a P2WPKH script
    pub fn p2wpkh(pubkey: &PublicKey) -> Self {
        let pk_bytes = hex::decode(pubkey.to_hex(PublicKeyFormat::Compressed)).unwrap();
        let pubkey_hash = hash160(&pk_bytes);
        
        let mut script = Vec::with_capacity(22);
        script.push(0x00); // OP_0 (witness version 0)
        script.push(0x14); // Push 20 bytes
        script.extend_from_slice(&pubkey_hash);
        
        Self {
            script,
            script_type: ScriptType::P2wpkh,
        }
    }

    /// Create a P2WSH script
    pub fn p2wsh(witness_script: &[u8]) -> Self {
        let script_hash = sha256(witness_script);
        
        let mut script = Vec::with_capacity(34);
        script.push(0x00); // OP_0 (witness version 0)
        script.push(0x20); // Push 32 bytes
        script.extend_from_slice(&script_hash);
        
        Self {
            script,
            script_type: ScriptType::P2wsh,
        }
    }

    /// Create a P2TR script
    pub fn p2tr(output_key: &[u8; 32]) -> Self {
        let mut script = Vec::with_capacity(34);
        script.push(0x51); // OP_1 (witness version 1)
        script.push(0x20); // Push 32 bytes
        script.extend_from_slice(output_key);
        
        Self {
            script,
            script_type: ScriptType::P2tr,
        }
    }

    /// Create a multisig script
    pub fn multisig(threshold: usize, pubkeys: &[PublicKey]) -> Result<Vec<u8>, DescriptorError> {
        if threshold == 0 || threshold > pubkeys.len() || pubkeys.len() > 16 {
            return Err(DescriptorError::InvalidThreshold {
                k: threshold,
                n: pubkeys.len(),
            });
        }
        
        let mut script = Vec::new();
        
        // OP_k (threshold)
        script.push(0x50 + threshold as u8); // OP_1 = 0x51, etc.
        
        // Push each pubkey
        for pk in pubkeys {
            let pk_bytes = hex::decode(pk.to_hex(PublicKeyFormat::Compressed)).unwrap();
            script.push(pk_bytes.len() as u8);
            script.extend_from_slice(&pk_bytes);
        }
        
        // OP_n (total keys)
        script.push(0x50 + pubkeys.len() as u8);
        
        // OP_CHECKMULTISIG
        script.push(0xae);
        
        Ok(script)
    }

    /// Get the script bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.script
    }

    /// Get the script type
    pub fn script_type(&self) -> ScriptType {
        self.script_type
    }

    /// Check if this is a witness script
    pub fn is_witness(&self) -> bool {
        matches!(
            self.script_type,
            ScriptType::P2wpkh | ScriptType::P2wsh | ScriptType::P2tr
        )
    }
}

/// Generate script pubkey from descriptor at a specific index
pub fn generate_script_pubkey(
    descriptor: &Descriptor,
    index: u32,
) -> Result<ScriptPubkey, DescriptorError> {
    match descriptor {
        Descriptor::Pk(key) => {
            let pubkey = key.derive_public_key(index)?;
            Ok(ScriptPubkey::p2pk(&pubkey))
        }
        Descriptor::Pkh(key) => {
            let pubkey = key.derive_public_key(index)?;
            Ok(ScriptPubkey::p2pkh(&pubkey))
        }
        Descriptor::Wpkh(key) => {
            let pubkey = key.derive_public_key(index)?;
            Ok(ScriptPubkey::p2wpkh(&pubkey))
        }
        Descriptor::Sh(inner) => {
            // Generate the inner script as redeem script
            let inner_script = generate_redeem_script(inner, index)?;
            Ok(ScriptPubkey::p2sh(&inner_script))
        }
        Descriptor::Wsh(inner) => {
            // Generate the inner script as witness script
            let witness_script = generate_witness_script(inner, index)?;
            Ok(ScriptPubkey::p2wsh(&witness_script))
        }
        Descriptor::Tr(key) => {
            let pubkey = key.derive_public_key(index)?;
            // For Taproot, we need the x-only pubkey (32 bytes)
            let pk_hex = pubkey.to_hex(PublicKeyFormat::Compressed);
            let pk_bytes = hex::decode(&pk_hex).unwrap();
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&pk_bytes[1..33]); // Skip the prefix byte
            Ok(ScriptPubkey::p2tr(&xonly))
        }
        Descriptor::Multi { threshold, keys } => {
            let pubkeys: Result<Vec<_>, _> = keys
                .iter()
                .map(|k| k.derive_public_key(index))
                .collect();
            let pubkeys = pubkeys?;
            let script = ScriptPubkey::multisig(*threshold, &pubkeys)?;
            // Bare multisig - wrap in P2SH
            Ok(ScriptPubkey::p2sh(&script))
        }
        Descriptor::SortedMulti { threshold, keys } => {
            let mut pubkeys: Vec<_> = keys
                .iter()
                .map(|k| k.derive_public_key(index))
                .collect::<Result<Vec<_>, _>>()?;
            // Sort pubkeys lexicographically
            pubkeys.sort_by(|a, b| {
                let a_hex = a.to_hex(PublicKeyFormat::Compressed);
                let b_hex = b.to_hex(PublicKeyFormat::Compressed);
                a_hex.cmp(&b_hex)
            });
            let script = ScriptPubkey::multisig(*threshold, &pubkeys)?;
            // Bare multisig - wrap in P2SH
            Ok(ScriptPubkey::p2sh(&script))
        }
    }
}

/// Generate redeem script for P2SH
fn generate_redeem_script(descriptor: &Descriptor, index: u32) -> Result<Vec<u8>, DescriptorError> {
    match descriptor {
        Descriptor::Wpkh(key) => {
            // P2SH-P2WPKH: redeem script is the P2WPKH script
            let pubkey = key.derive_public_key(index)?;
            let script = ScriptPubkey::p2wpkh(&pubkey);
            Ok(script.script)
        }
        Descriptor::Wsh(inner) => {
            // P2SH-P2WSH: redeem script is the P2WSH script
            let witness_script = generate_witness_script(inner, index)?;
            let script = ScriptPubkey::p2wsh(&witness_script);
            Ok(script.script)
        }
        Descriptor::Multi { threshold, keys } => {
            let pubkeys: Result<Vec<_>, _> = keys
                .iter()
                .map(|k| k.derive_public_key(index))
                .collect();
            ScriptPubkey::multisig(*threshold, &pubkeys?)
        }
        Descriptor::SortedMulti { threshold, keys } => {
            let mut pubkeys: Vec<_> = keys
                .iter()
                .map(|k| k.derive_public_key(index))
                .collect::<Result<Vec<_>, _>>()?;
            pubkeys.sort_by(|a, b| {
                let a_hex = a.to_hex(PublicKeyFormat::Compressed);
                let b_hex = b.to_hex(PublicKeyFormat::Compressed);
                a_hex.cmp(&b_hex)
            });
            ScriptPubkey::multisig(*threshold, &pubkeys)
        }
        _ => Err(DescriptorError::ScriptError(format!(
            "Cannot create redeem script for {}",
            descriptor.descriptor_type()
        ))),
    }
}

/// Generate witness script for P2WSH
fn generate_witness_script(descriptor: &Descriptor, index: u32) -> Result<Vec<u8>, DescriptorError> {
    match descriptor {
        Descriptor::Multi { threshold, keys } => {
            let pubkeys: Result<Vec<_>, _> = keys
                .iter()
                .map(|k| k.derive_public_key(index))
                .collect();
            ScriptPubkey::multisig(*threshold, &pubkeys?)
        }
        Descriptor::SortedMulti { threshold, keys } => {
            let mut pubkeys: Vec<_> = keys
                .iter()
                .map(|k| k.derive_public_key(index))
                .collect::<Result<Vec<_>, _>>()?;
            pubkeys.sort_by(|a, b| {
                let a_hex = a.to_hex(PublicKeyFormat::Compressed);
                let b_hex = b.to_hex(PublicKeyFormat::Compressed);
                a_hex.cmp(&b_hex)
            });
            ScriptPubkey::multisig(*threshold, &pubkeys)
        }
        _ => Err(DescriptorError::ScriptError(format!(
            "Cannot create witness script for {}",
            descriptor.descriptor_type()
        ))),
    }
}

/// HASH160 = RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd);
    result
}

/// SHA256
fn sha256(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2pkh_script() {
        let pubkey_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let pubkey = PublicKey::from_hex(pubkey_hex).unwrap();
        
        let script = ScriptPubkey::p2pkh(&pubkey);
        
        assert_eq!(script.script_type, ScriptType::P2pkh);
        assert_eq!(script.script.len(), 25);
        assert_eq!(script.script[0], 0x76); // OP_DUP
        assert_eq!(script.script[1], 0xa9); // OP_HASH160
    }

    #[test]
    fn test_p2wpkh_script() {
        let pubkey_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let pubkey = PublicKey::from_hex(pubkey_hex).unwrap();
        
        let script = ScriptPubkey::p2wpkh(&pubkey);
        
        assert_eq!(script.script_type, ScriptType::P2wpkh);
        assert_eq!(script.script.len(), 22);
        assert_eq!(script.script[0], 0x00); // OP_0
        assert_eq!(script.script[1], 0x14); // Push 20 bytes
    }

    #[test]
    fn test_p2tr_script() {
        let output_key = [0x42u8; 32];
        let script = ScriptPubkey::p2tr(&output_key);
        
        assert_eq!(script.script_type, ScriptType::P2tr);
        assert_eq!(script.script.len(), 34);
        assert_eq!(script.script[0], 0x51); // OP_1
        assert_eq!(script.script[1], 0x20); // Push 32 bytes
    }

    #[test]
    fn test_multisig_script() {
        let pk1_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let pk2_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        
        let pk1 = PublicKey::from_hex(pk1_hex).unwrap();
        let pk2 = PublicKey::from_hex(pk2_hex).unwrap();
        
        let script = ScriptPubkey::multisig(2, &[pk1, pk2]).unwrap();
        
        assert_eq!(script[0], 0x52); // OP_2
        assert_eq!(*script.last().unwrap(), 0xae); // OP_CHECKMULTISIG
    }
}
