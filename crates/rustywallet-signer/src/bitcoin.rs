//! Bitcoin message signing (BIP-137 compatible)

use crate::error::SignerError;
use crate::recovery::recover_public_key;
use crate::signature::RecoverableSignature;
use base64::{engine::general_purpose::STANDARD, Engine};
use rustywallet_keys::private_key::PrivateKey;
use secp256k1::{Message, Secp256k1};
use sha2::{Digest, Sha256};

const BITCOIN_MESSAGE_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

/// Hash a message using Bitcoin's message signing format
///
/// Format: SHA256(SHA256(prefix || varint(len) || message))
fn bitcoin_message_hash(message: &[u8]) -> [u8; 32] {
    let mut data = Vec::new();
    data.extend_from_slice(BITCOIN_MESSAGE_PREFIX);
    // Varint encoding for message length
    encode_varint(&mut data, message.len());
    data.extend_from_slice(message);

    // Double SHA256
    let hash1 = Sha256::digest(&data);
    Sha256::digest(hash1).into()
}

/// Encode a length as Bitcoin varint
fn encode_varint(buf: &mut Vec<u8>, len: usize) {
    if len < 0xfd {
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(len as u16).to_le_bytes());
    } else if len <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&(len as u64).to_le_bytes());
    }
}

/// Sign a message in Bitcoin's standard format
///
/// Returns a base64-encoded signature compatible with Bitcoin Core's `signmessage`.
///
/// # Arguments
/// * `private_key` - The private key to sign with
/// * `message` - The message to sign
///
/// # Returns
/// Base64-encoded signature string
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::bitcoin::sign_bitcoin_message;
///
/// let key = PrivateKey::random();
/// let sig = sign_bitcoin_message(&key, "Hello Bitcoin!").unwrap();
/// println!("Signature: {}", sig);
/// ```
pub fn sign_bitcoin_message(private_key: &PrivateKey, message: &str) -> Result<String, SignerError> {
    let hash = bitcoin_message_hash(message.as_bytes());

    let secp = Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&private_key.to_bytes())
        .map_err(|e| SignerError::SigningFailed(e.to_string()))?;
    let msg = Message::from_digest(hash);

    let (recovery_id, sig) = secp
        .sign_ecdsa_recoverable(&msg, &secret_key)
        .serialize_compact();

    // Bitcoin signature format: 1 byte header + 64 bytes signature
    // Header = 27 + recovery_id + (compressed ? 4 : 0)
    // We always use compressed keys
    let header = 27 + recovery_id.to_i32() as u8 + 4;

    let mut sig_bytes = [0u8; 65];
    sig_bytes[0] = header;
    sig_bytes[1..].copy_from_slice(&sig);

    Ok(STANDARD.encode(sig_bytes))
}

/// Verify a Bitcoin signed message
///
/// # Arguments
/// * `address` - The Bitcoin address (P2PKH format, starting with 1 or m/n)
/// * `message` - The original message
/// * `signature` - Base64-encoded signature
///
/// # Returns
/// `true` if the signature is valid for the address
///
/// # Example
/// ```
/// use rustywallet_keys::private_key::PrivateKey;
/// use rustywallet_signer::bitcoin::{sign_bitcoin_message, verify_bitcoin_message};
///
/// let key = PrivateKey::random();
/// let message = "Hello Bitcoin!";
/// let sig = sign_bitcoin_message(&key, message).unwrap();
///
/// // Get the address from the key (you'd normally use rustywallet-address)
/// // For this example, we'll just verify the signature recovers correctly
/// ```
pub fn verify_bitcoin_message(
    address: &str,
    message: &str,
    signature: &str,
) -> Result<bool, SignerError> {
    let sig_bytes = STANDARD
        .decode(signature)
        .map_err(|e| SignerError::InvalidBase64(e.to_string()))?;

    if sig_bytes.len() != 65 {
        return Err(SignerError::InvalidSignature);
    }

    let header = sig_bytes[0];
    if !(27..=34).contains(&header) {
        return Err(SignerError::InvalidSignature);
    }

    // Extract recovery id from header
    let recovery_id = (header - 27) & 3;

    // Parse signature
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[1..33]);
    s.copy_from_slice(&sig_bytes[33..65]);

    let signature = crate::signature::Signature::new(r, s);
    let recoverable = RecoverableSignature::new(signature, recovery_id)?;

    // Hash the message
    let hash = bitcoin_message_hash(message.as_bytes());

    // Recover public key
    let pubkey = recover_public_key(&recoverable, &hash)?;

    // Derive address from public key and compare
    // For P2PKH: RIPEMD160(SHA256(pubkey))
    let pubkey_hash = {
        let sha = Sha256::digest(pubkey.to_compressed());
        ripemd160_hash(&sha)
    };

    // Base58Check decode the address
    let decoded = bs58_decode_check(address)?;
    if decoded.len() != 21 {
        return Err(SignerError::InvalidAddress);
    }

    // Compare pubkey hash (skip version byte)
    Ok(decoded[1..] == pubkey_hash)
}

/// Simple RIPEMD160 implementation for pubkey hashing
fn ripemd160_hash(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

use ripemd::Ripemd160;

/// Base58Check decode
fn bs58_decode_check(input: &str) -> Result<Vec<u8>, SignerError> {
    let decoded = bs58::decode(input)
        .into_vec()
        .map_err(|_| SignerError::InvalidAddress)?;

    if decoded.len() < 5 {
        return Err(SignerError::InvalidAddress);
    }

    // Verify checksum
    let payload = &decoded[..decoded.len() - 4];
    let checksum = &decoded[decoded.len() - 4..];

    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);

    if &hash2[..4] != checksum {
        return Err(SignerError::InvalidAddress);
    }

    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_message_hash() {
        let hash = bitcoin_message_hash(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sign_bitcoin_message() {
        let key = PrivateKey::random();
        let sig = sign_bitcoin_message(&key, "Hello Bitcoin!").unwrap();

        // Should be valid base64
        let decoded = STANDARD.decode(&sig).unwrap();
        assert_eq!(decoded.len(), 65);

        // Header should be in valid range (27-34)
        assert!(decoded[0] >= 27 && decoded[0] <= 34);
    }

    #[test]
    fn test_varint_encoding() {
        let mut buf = Vec::new();
        encode_varint(&mut buf, 10);
        assert_eq!(buf, vec![10]);

        let mut buf = Vec::new();
        encode_varint(&mut buf, 253);
        assert_eq!(buf, vec![0xfd, 253, 0]);
    }
}
