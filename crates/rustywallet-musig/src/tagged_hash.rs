//! Tagged hash functions for MuSig2 (BIP327/BIP340).

use sha2::{Digest, Sha256};

/// Tag for KeyAgg list hash.
pub const KEYAGG_LIST_TAG: &[u8] = b"KeyAgg list";

/// Tag for KeyAgg coefficient hash.
pub const KEYAGG_COEFF_TAG: &[u8] = b"KeyAgg coefficient";

/// Tag for MuSig nonce hash.
pub const MUSIG_NONCE_TAG: &[u8] = b"MuSig/nonce";

/// Tag for MuSig noncecoef hash.
pub const MUSIG_NONCECOEF_TAG: &[u8] = b"MuSig/noncecoef";

/// Tag for MuSig aux hash.
pub const MUSIG_AUX_TAG: &[u8] = b"MuSig/aux";

/// Tag for BIP340 challenge hash.
pub const BIP340_CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// Compute a tagged hash as per BIP340.
///
/// tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);

    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    result
}

/// Compute BIP340 challenge hash.
pub fn challenge_hash(r_x: &[u8; 32], pk_x: &[u8; 32], msg: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(r_x);
    data.extend_from_slice(pk_x);
    data.extend_from_slice(msg);
    tagged_hash(BIP340_CHALLENGE_TAG, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_hash() {
        let hash = tagged_hash(b"test", b"message");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_tagged_hash_deterministic() {
        let hash1 = tagged_hash(b"tag", b"data");
        let hash2 = tagged_hash(b"tag", b"data");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_tags_different_hashes() {
        let hash1 = tagged_hash(b"tag1", b"data");
        let hash2 = tagged_hash(b"tag2", b"data");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_challenge_hash() {
        let r_x = [1u8; 32];
        let pk_x = [2u8; 32];
        let msg = [3u8; 32];

        let hash = challenge_hash(&r_x, &pk_x, &msg);
        assert_eq!(hash.len(), 32);
    }
}
