//! Ethereum personal_sign (EIP-191) implementation

use crate::error::SignerError;
use crate::recovery::recover_public_key;
use crate::signature::RecoverableSignature;
use rustywallet_keys::private_key::PrivateKey;
use secp256k1::{Message, Secp256k1};
use tiny_keccak::{Hasher, Keccak};

/// Hash a message using Ethereum's personal_sign format (EIP-191)
///
/// Format: Keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
pub fn ethereum_message_hash(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());

    let mut hasher = Keccak::v256();
    hasher.update(prefix.as_bytes());
    hasher.update(message);

    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hash
}

/// Keccak256 hash (used for Ethereum address derivation)
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hash
}

/// Sign a message using Ethereum's personal_sign format (EIP-191)
///
/// # Arguments
/// * `private_key` - The private key to sign with
/// * `message` - The message to sign
///
/// # Returns
/// A recoverable signature with Ethereum-style recovery id
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::ethereum::sign_ethereum_message;
///
/// let key = PrivateKey::random();
/// let sig = sign_ethereum_message(&key, b"Hello Ethereum!").unwrap();
/// println!("Signature: {}", sig.to_ethereum_hex());
/// ```
pub fn sign_ethereum_message(
    private_key: &PrivateKey,
    message: &[u8],
) -> Result<RecoverableSignature, SignerError> {
    let hash = ethereum_message_hash(message);

    let secp = Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&private_key.to_bytes())
        .map_err(|e| SignerError::SigningFailed(e.to_string()))?;
    let msg = Message::from_digest(hash);

    let (recovery_id, sig) = secp
        .sign_ecdsa_recoverable(&msg, &secret_key)
        .serialize_compact();

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);

    let signature = crate::signature::Signature::new(r, s);
    RecoverableSignature::new(signature, recovery_id.to_i32() as u8)
}

/// Verify an Ethereum signed message
///
/// # Arguments
/// * `address` - The Ethereum address (20 bytes)
/// * `message` - The original message
/// * `signature` - The recoverable signature
///
/// # Returns
/// `true` if the signature is valid for the address
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::ethereum::{sign_ethereum_message, verify_ethereum_message, public_key_to_address};
///
/// let key = PrivateKey::random();
/// let address = public_key_to_address(&key.public_key());
/// let message = b"Hello Ethereum!";
///
/// let sig = sign_ethereum_message(&key, message).unwrap();
/// assert!(verify_ethereum_message(&address, message, &sig).unwrap());
/// ```
pub fn verify_ethereum_message(
    address: &[u8; 20],
    message: &[u8],
    signature: &RecoverableSignature,
) -> Result<bool, SignerError> {
    let recovered_address = recover_ethereum_address(signature, message)?;
    Ok(&recovered_address == address)
}

/// Recover the Ethereum address from a signature
///
/// # Arguments
/// * `signature` - The recoverable signature
/// * `message` - The original message (will be hashed with EIP-191 prefix)
///
/// # Returns
/// The 20-byte Ethereum address
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::ethereum::{sign_ethereum_message, recover_ethereum_address, public_key_to_address};
///
/// let key = PrivateKey::random();
/// let expected_address = public_key_to_address(&key.public_key());
/// let message = b"Hello Ethereum!";
///
/// let sig = sign_ethereum_message(&key, message).unwrap();
/// let recovered = recover_ethereum_address(&sig, message).unwrap();
///
/// assert_eq!(expected_address, recovered);
/// ```
pub fn recover_ethereum_address(
    signature: &RecoverableSignature,
    message: &[u8],
) -> Result<[u8; 20], SignerError> {
    let hash = ethereum_message_hash(message);
    let pubkey = recover_public_key(signature, &hash)?;

    // Ethereum uses uncompressed public key (without 04 prefix) for address derivation
    let uncompressed = pubkey.to_uncompressed();
    // Skip the 04 prefix byte
    let pubkey_bytes = &uncompressed[1..];

    // Keccak256 hash of public key, take last 20 bytes
    let hash = keccak256(pubkey_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);

    Ok(address)
}

/// Derive Ethereum address from public key
///
/// # Arguments
/// * `public_key` - The public key
///
/// # Returns
/// The 20-byte Ethereum address
pub fn public_key_to_address(public_key: &rustywallet_keys::public_key::PublicKey) -> [u8; 20] {
    let uncompressed = public_key.to_uncompressed();
    // Skip the 04 prefix byte
    let pubkey_bytes = &uncompressed[1..];

    // Keccak256 hash of public key, take last 20 bytes
    let hash = keccak256(pubkey_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Format an Ethereum address as checksummed hex string (EIP-55)
///
/// # Example
/// ```
/// use rustywallet_signer::ethereum::format_address;
///
/// let address = [0xab; 20];
/// let formatted = format_address(&address);
/// assert!(formatted.starts_with("0x"));
/// ```
pub fn format_address(address: &[u8; 20]) -> String {
    let hex_addr: String = address.iter().map(|b| format!("{:02x}", b)).collect();
    let hash = keccak256(hex_addr.as_bytes());

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        let hash_nibble = if i % 2 == 0 {
            (hash[i / 2] >> 4) & 0xf
        } else {
            hash[i / 2] & 0xf
        };

        if hash_nibble >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_message_hash() {
        let hash = ethereum_message_hash(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let key = PrivateKey::random();
        let address = public_key_to_address(&key.public_key());
        let message = b"Hello Ethereum!";

        let sig = sign_ethereum_message(&key, message).unwrap();
        assert!(verify_ethereum_message(&address, message, &sig).unwrap());
    }

    #[test]
    fn test_recover_address() {
        let key = PrivateKey::random();
        let expected = public_key_to_address(&key.public_key());
        let message = b"test message";

        let sig = sign_ethereum_message(&key, message).unwrap();
        let recovered = recover_ethereum_address(&sig, message).unwrap();

        assert_eq!(expected, recovered);
    }

    #[test]
    fn test_format_address() {
        let address = [0x5a; 20];
        let formatted = format_address(&address);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 42);
    }

    #[test]
    fn test_wrong_address_fails_verification() {
        let key = PrivateKey::random();
        let wrong_address = [0u8; 20];
        let message = b"test";

        let sig = sign_ethereum_message(&key, message).unwrap();
        assert!(!verify_ethereum_message(&wrong_address, message, &sig).unwrap());
    }
}
