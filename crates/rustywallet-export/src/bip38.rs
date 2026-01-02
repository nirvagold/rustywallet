//! BIP38 encryption export.

use crate::error::{ExportError, Result};
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_address::{P2PKHAddress, Network as AddrNetwork};
use sha2::{Sha256, Digest};
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use scrypt::{scrypt, Params};

/// Export a private key to BIP38 encrypted format.
///
/// BIP38 keys start with "6P" and are password-protected.
///
/// # Example
///
/// ```rust,ignore
/// use rustywallet_export::{export_bip38, Network};
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let key = PrivateKey::random();
/// let encrypted = export_bip38(&key, "mypassword", true).unwrap();
/// assert!(encrypted.starts_with("6P"));
/// ```
pub fn export_bip38(key: &PrivateKey, password: &str, compressed: bool) -> Result<String> {
    let public_key = key.public_key();
    
    // Generate address for hash
    let address = P2PKHAddress::from_public_key(&public_key, AddrNetwork::BitcoinMainnet)
        .map_err(|e| ExportError::AddressError(e.to_string()))?
        .to_string();
    
    // Address hash (first 4 bytes of double SHA256)
    let addr_hash1 = Sha256::digest(address.as_bytes());
    let addr_hash2 = Sha256::digest(addr_hash1);
    let address_hash: [u8; 4] = addr_hash2[0..4].try_into().unwrap();
    
    // Derive key using scrypt
    // BIP38 parameters: N=16384, r=8, p=8
    let params = Params::new(14, 8, 8, 64) // log2(16384) = 14
        .map_err(|e| ExportError::EncryptionFailed(format!("Scrypt params error: {}", e)))?;
    
    let mut derived_key = [0u8; 64];
    scrypt(password.as_bytes(), &address_hash, &params, &mut derived_key)
        .map_err(|e| ExportError::EncryptionFailed(format!("Scrypt failed: {}", e)))?;
    
    let derived_half1 = &derived_key[0..32];
    let derived_half2 = &derived_key[32..64];
    
    // XOR private key with derived_half1
    let key_bytes = key.to_bytes();
    let mut xored = [0u8; 32];
    for i in 0..32 {
        xored[i] = key_bytes[i] ^ derived_half1[i];
    }
    
    // AES-256-ECB encrypt
    let cipher = Aes256::new_from_slice(derived_half2)
        .map_err(|e| ExportError::EncryptionFailed(format!("AES init failed: {}", e)))?;
    
    let mut encrypted = [0u8; 32];
    
    // Encrypt first half
    let mut block1: [u8; 16] = xored[0..16].try_into().unwrap();
    cipher.encrypt_block((&mut block1).into());
    encrypted[0..16].copy_from_slice(&block1);
    
    // Encrypt second half
    let mut block2: [u8; 16] = xored[16..32].try_into().unwrap();
    cipher.encrypt_block((&mut block2).into());
    encrypted[16..32].copy_from_slice(&block2);
    
    // Build payload
    // Prefix: 0x01 0x42 (non-EC-multiply)
    // Flag: 0xC0 (compressed) or 0x00 (uncompressed)
    let flag = if compressed { 0xE0 } else { 0xC0 };
    
    let mut payload = Vec::with_capacity(39);
    payload.push(0x01);
    payload.push(0x42);
    payload.push(flag);
    payload.extend_from_slice(&address_hash);
    payload.extend_from_slice(&encrypted);
    
    // Add checksum
    let check1 = Sha256::digest(&payload);
    let check2 = Sha256::digest(check1);
    payload.extend_from_slice(&check2[0..4]);
    
    // Base58 encode
    Ok(bs58::encode(payload).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_export_bip38_format() {
        let key = PrivateKey::random();
        let encrypted = export_bip38(&key, "testpassword", true).unwrap();
        
        assert!(encrypted.starts_with("6P"));
        assert_eq!(encrypted.len(), 58);
    }
    
    // Note: Full roundtrip test requires rustywallet-import
    // which is in dev-dependencies
}
