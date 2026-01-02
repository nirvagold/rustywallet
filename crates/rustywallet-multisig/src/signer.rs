//! Multisig transaction signing.

use crate::address::MultisigWallet;
use crate::error::{MultisigError, Result};
use rustywallet_keys::prelude::PrivateKey;
use secp256k1::{Secp256k1, Message, SecretKey};
use sha2::{Sha256, Digest};

/// Sighash types.
pub mod sighash_type {
    pub const ALL: u32 = 0x01;
    pub const NONE: u32 = 0x02;
    pub const SINGLE: u32 = 0x03;
    pub const ANYONECANPAY: u32 = 0x80;
}

/// A partial signature for a multisig input.
#[derive(Debug, Clone)]
pub struct PartialSignature {
    /// The public key that signed
    pub pubkey: [u8; 33],
    /// The DER-encoded signature with sighash type
    pub signature: Vec<u8>,
    /// Index of this key in the multisig
    pub key_index: usize,
}

/// Sign a P2SH multisig input.
///
/// # Arguments
/// * `sighash` - The sighash to sign (computed externally)
/// * `private_key` - The private key to sign with
/// * `wallet` - The multisig wallet configuration
pub fn sign_p2sh_multisig(
    sighash: &[u8; 32],
    private_key: &PrivateKey,
    wallet: &MultisigWallet,
) -> Result<PartialSignature> {
    let pubkey = private_key.public_key().to_compressed();

    // Verify this key is part of the multisig
    let key_index = wallet
        .config
        .key_index(&pubkey)
        .ok_or_else(|| MultisigError::InvalidPublicKey("Key not in multisig".to_string()))?;

    // Sign
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key.to_bytes())
        .map_err(|e| MultisigError::SigningFailed(e.to_string()))?;
    let message = Message::from_digest(*sighash);
    let signature = secp.sign_ecdsa(&message, &secret_key);

    // Serialize signature + sighash type
    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(sighash_type::ALL as u8);

    Ok(PartialSignature {
        pubkey,
        signature: sig_bytes,
        key_index,
    })
}

/// Sign a P2WSH multisig input (BIP143 sighash).
///
/// # Arguments
/// * `sighash` - The BIP143 sighash to sign
/// * `private_key` - The private key to sign with
/// * `wallet` - The multisig wallet configuration
pub fn sign_p2wsh_multisig(
    sighash: &[u8; 32],
    private_key: &PrivateKey,
    wallet: &MultisigWallet,
) -> Result<PartialSignature> {
    // Same signing process, different sighash computation
    sign_p2sh_multisig(sighash, private_key, wallet)
}

/// Compute legacy sighash for P2SH multisig.
pub fn compute_p2sh_sighash(
    tx_bytes: &[u8],
    input_index: usize,
    redeem_script: &[u8],
) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(tx_bytes);
    data.extend_from_slice(&(input_index as u32).to_le_bytes());
    data.extend_from_slice(redeem_script);
    data.extend_from_slice(&sighash_type::ALL.to_le_bytes());
    
    double_sha256(&data)
}

/// Parameters for BIP143 sighash computation.
pub struct Bip143SighashParams<'a> {
    pub version: i32,
    pub hash_prevouts: &'a [u8; 32],
    pub hash_sequence: &'a [u8; 32],
    pub outpoint: &'a [u8],
    pub script_code: &'a [u8],
    pub value: u64,
    pub sequence: u32,
    pub hash_outputs: &'a [u8; 32],
    pub locktime: u32,
}

/// Compute BIP143 sighash for P2WSH multisig.
#[allow(clippy::too_many_arguments)]
pub fn compute_p2wsh_sighash(params: &Bip143SighashParams) -> [u8; 32] {
    let mut data = Vec::new();
    
    // Version
    data.extend_from_slice(&params.version.to_le_bytes());
    
    // hashPrevouts
    data.extend_from_slice(params.hash_prevouts);
    
    // hashSequence
    data.extend_from_slice(params.hash_sequence);
    
    // Outpoint
    data.extend_from_slice(params.outpoint);
    
    // scriptCode (with length prefix)
    encode_varint(&mut data, params.script_code.len() as u64);
    data.extend_from_slice(params.script_code);
    
    // Value
    data.extend_from_slice(&params.value.to_le_bytes());
    
    // Sequence
    data.extend_from_slice(&params.sequence.to_le_bytes());
    
    // hashOutputs
    data.extend_from_slice(params.hash_outputs);
    
    // Locktime
    data.extend_from_slice(&params.locktime.to_le_bytes());
    
    // Sighash type
    data.extend_from_slice(&sighash_type::ALL.to_le_bytes());
    
    double_sha256(&data)
}

/// Double SHA256.
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Encode a variable-length integer.
fn encode_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;

    fn make_pubkey_from_privkey(privkey: &PrivateKey) -> [u8; 33] {
        privkey.public_key().to_compressed()
    }

    #[test]
    fn test_sign_p2sh_multisig() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let key3 = PrivateKey::random();

        let pubkeys = vec![
            make_pubkey_from_privkey(&key1),
            make_pubkey_from_privkey(&key2),
            make_pubkey_from_privkey(&key3),
        ];

        let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
        let sighash = [0xab; 32];

        // Sign with key1
        let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet).unwrap();
        assert!(!sig1.signature.is_empty());
        assert!(wallet.config.contains_key(&sig1.pubkey));

        // Sign with key2
        let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet).unwrap();
        assert!(!sig2.signature.is_empty());
    }

    #[test]
    fn test_sign_with_wrong_key() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let wrong_key = PrivateKey::random();

        let pubkeys = vec![
            make_pubkey_from_privkey(&key1),
            make_pubkey_from_privkey(&key2),
        ];

        let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
        let sighash = [0xcd; 32];

        // Try to sign with a key not in the multisig
        let result = sign_p2sh_multisig(&sighash, &wrong_key, &wallet);
        assert!(result.is_err());
    }
}
