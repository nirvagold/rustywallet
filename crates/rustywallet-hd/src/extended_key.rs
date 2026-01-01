//! Extended key types for BIP32 HD wallets.

use crate::error::HdError;
use crate::network::Network;
use crate::path::{DerivationPath, HARDENED_BIT};
use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use rustywallet_keys::private_key::PrivateKey;
use rustywallet_keys::public_key::PublicKey;
use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// Extended private key (BIP32).
///
/// Contains a private key and chain code for hierarchical derivation.
///
/// # Example
///
/// ```
/// use rustywallet_hd::{ExtendedPrivateKey, DerivationPath, Network};
///
/// // Create from seed (typically from mnemonic)
/// let seed = [0u8; 64];
/// let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
///
/// // Derive child key
/// let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
/// let child = master.derive_path(&path).unwrap();
///
/// // Export as xprv
/// let xprv = child.to_xprv();
/// ```
pub struct ExtendedPrivateKey {
    /// Private key bytes
    private_key: Zeroizing<[u8; 32]>,
    /// Chain code for derivation
    chain_code: Zeroizing<[u8; 32]>,
    /// Depth in derivation tree (0 for master)
    depth: u8,
    /// Parent key fingerprint (0x00000000 for master)
    parent_fingerprint: [u8; 4],
    /// Child number (0 for master)
    child_number: u32,
    /// Network
    network: Network,
}

impl ExtendedPrivateKey {
    /// Create master extended private key from seed.
    ///
    /// The seed should be 64 bytes (typically from BIP39 mnemonic).
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self, HdError> {
        if seed.len() != 64 {
            return Err(HdError::InvalidSeedLength(seed.len()));
        }

        // HMAC-SHA512 with key "Bitcoin seed"
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        private_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        // Validate private key
        SecretKey::from_slice(&private_key).map_err(|_| HdError::InvalidDerivedKey)?;

        Ok(Self {
            private_key: Zeroizing::new(private_key),
            chain_code: Zeroizing::new(chain_code),
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
            network,
        })
    }

    /// Derive child extended private key at index.
    ///
    /// For hardened derivation, use index >= 0x80000000 or use `derive_hardened`.
    pub fn derive_child(&self, index: u32) -> Result<Self, HdError> {
        let secp = Secp256k1::new();
        let parent_key =
            SecretKey::from_slice(&*self.private_key).map_err(|_| HdError::InvalidDerivedKey)?;

        let mut mac =
            HmacSha512::new_from_slice(&*self.chain_code).expect("HMAC can take key of any size");

        if index >= HARDENED_BIT {
            // Hardened derivation: 0x00 || private_key || index
            mac.update(&[0x00]);
            mac.update(&*self.private_key);
        } else {
            // Normal derivation: public_key || index
            let public_key = secp256k1::PublicKey::from_secret_key(&secp, &parent_key);
            mac.update(&public_key.serialize());
        }
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        let mut child_key_bytes = [0u8; 32];
        let mut child_chain_code = [0u8; 32];
        child_key_bytes.copy_from_slice(&result[..32]);
        child_chain_code.copy_from_slice(&result[32..]);

        // Add parent key to derived key (mod curve order)
        let tweak =
            SecretKey::from_slice(&child_key_bytes).map_err(|_| HdError::InvalidDerivedKey)?;
        let child_key = parent_key
            .add_tweak(&tweak.into())
            .map_err(|_| HdError::InvalidDerivedKey)?;

        let mut final_key = [0u8; 32];
        final_key.copy_from_slice(&child_key.secret_bytes());

        Ok(Self {
            private_key: Zeroizing::new(final_key),
            chain_code: Zeroizing::new(child_chain_code),
            depth: self.depth.saturating_add(1),
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            network: self.network,
        })
    }

    /// Derive hardened child at index (adds 0x80000000 to index).
    pub fn derive_hardened(&self, index: u32) -> Result<Self, HdError> {
        if index >= HARDENED_BIT {
            return Err(HdError::InvalidChildNumber(index));
        }
        self.derive_child(index | HARDENED_BIT)
    }

    /// Derive key at derivation path.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, HdError> {
        let mut current = self.clone();
        for child in path.components() {
            current = current.derive_child(child.raw_index())?;
        }
        Ok(current)
    }

    /// Get the extended public key.
    pub fn extended_public_key(&self) -> ExtendedPublicKey {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(&*self.private_key).expect("Private key should be valid");
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        ExtendedPublicKey {
            public_key: public_key.serialize(),
            chain_code: *self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            network: self.network,
        }
    }

    /// Get the underlying private key.
    pub fn private_key(&self) -> Result<PrivateKey, HdError> {
        PrivateKey::from_bytes(*self.private_key).map_err(|_| HdError::InvalidDerivedKey)
    }

    /// Get the underlying public key.
    pub fn public_key(&self) -> PublicKey {
        self.private_key()
            .expect("Private key should be valid")
            .public_key()
    }

    /// Get fingerprint (first 4 bytes of HASH160 of public key).
    pub fn fingerprint(&self) -> [u8; 4] {
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(&*self.private_key).expect("Private key should be valid");
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        let sha256 = Sha256::digest(public_key.serialize());
        let hash160 = Ripemd160::digest(sha256);

        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash160[..4]);
        fingerprint
    }

    /// Get depth in derivation tree.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Get chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Serialize to xprv string (Base58Check).
    pub fn to_xprv(&self) -> String {
        let mut data = Vec::with_capacity(78);

        // Version (4 bytes)
        data.extend_from_slice(&self.network.xprv_version());
        // Depth (1 byte)
        data.push(self.depth);
        // Parent fingerprint (4 bytes)
        data.extend_from_slice(&self.parent_fingerprint);
        // Child number (4 bytes)
        data.extend_from_slice(&self.child_number.to_be_bytes());
        // Chain code (32 bytes)
        data.extend_from_slice(&*self.chain_code);
        // Key (33 bytes: 0x00 prefix + 32 bytes private key)
        data.push(0x00);
        data.extend_from_slice(&*self.private_key);

        bs58::encode(data).with_check().into_string()
    }

    /// Parse from xprv string (Base58Check).
    pub fn from_xprv(xprv: &str) -> Result<Self, HdError> {
        let data = bs58::decode(xprv)
            .with_check(None)
            .into_vec()
            .map_err(|_| HdError::InvalidChecksum)?;

        if data.len() != 78 {
            return Err(HdError::InvalidExtendedKey);
        }

        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);

        let (network, is_private) =
            Network::from_version(&version).ok_or(HdError::InvalidVersion)?;

        if !is_private {
            return Err(HdError::InvalidExtendedKey);
        }

        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        // Key starts with 0x00 for private key
        if data[45] != 0x00 {
            return Err(HdError::InvalidExtendedKey);
        }

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&data[46..78]);

        // Validate private key
        SecretKey::from_slice(&private_key).map_err(|_| HdError::InvalidDerivedKey)?;

        Ok(Self {
            private_key: Zeroizing::new(private_key),
            chain_code: Zeroizing::new(chain_code),
            depth,
            parent_fingerprint,
            child_number,
            network,
        })
    }
}


impl Clone for ExtendedPrivateKey {
    fn clone(&self) -> Self {
        Self {
            private_key: Zeroizing::new(*self.private_key),
            chain_code: Zeroizing::new(*self.chain_code),
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            network: self.network,
        }
    }
}

impl fmt::Display for ExtendedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_xprv())
    }
}

impl fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtendedPrivateKey {{ depth: {}, fingerprint: {:02x}{:02x}{:02x}{:02x}, key: **** }}",
            self.depth,
            self.parent_fingerprint[0],
            self.parent_fingerprint[1],
            self.parent_fingerprint[2],
            self.parent_fingerprint[3]
        )
    }
}

impl Drop for ExtendedPrivateKey {
    fn drop(&mut self) {
        // private_key and chain_code are Zeroizing, they auto-zeroize
    }
}

/// Extended public key (BIP32).
///
/// Can derive child public keys for non-hardened paths only.
#[derive(Clone)]
pub struct ExtendedPublicKey {
    /// Public key (33 bytes compressed)
    public_key: [u8; 33],
    /// Chain code for derivation
    chain_code: [u8; 32],
    /// Depth in derivation tree
    depth: u8,
    /// Parent key fingerprint
    parent_fingerprint: [u8; 4],
    /// Child number
    child_number: u32,
    /// Network
    network: Network,
}

impl ExtendedPublicKey {
    /// Derive child public key (normal derivation only).
    ///
    /// Returns error for hardened derivation (index >= 0x80000000).
    pub fn derive_child(&self, index: u32) -> Result<Self, HdError> {
        if index >= HARDENED_BIT {
            return Err(HdError::HardenedFromPublic);
        }

        let secp = Secp256k1::new();
        let parent_key = secp256k1::PublicKey::from_slice(&self.public_key)
            .map_err(|_| HdError::InvalidDerivedKey)?;

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC can take key of any size");
        mac.update(&self.public_key);
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        let mut tweak_bytes = [0u8; 32];
        let mut child_chain_code = [0u8; 32];
        tweak_bytes.copy_from_slice(&result[..32]);
        child_chain_code.copy_from_slice(&result[32..]);

        // Add tweak to parent public key
        let tweak = SecretKey::from_slice(&tweak_bytes).map_err(|_| HdError::InvalidDerivedKey)?;
        let child_key = parent_key
            .add_exp_tweak(&secp, &tweak.into())
            .map_err(|_| HdError::InvalidDerivedKey)?;

        Ok(Self {
            public_key: child_key.serialize(),
            chain_code: child_chain_code,
            depth: self.depth.saturating_add(1),
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            network: self.network,
        })
    }

    /// Derive key at derivation path (normal derivation only).
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, HdError> {
        if path.has_hardened() {
            return Err(HdError::HardenedFromPublic);
        }

        let mut current = self.clone();
        for child in path.components() {
            current = current.derive_child(child.raw_index())?;
        }
        Ok(current)
    }

    /// Get the underlying public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_compressed(&self.public_key).expect("Public key should be valid")
    }

    /// Get fingerprint (first 4 bytes of HASH160 of public key).
    pub fn fingerprint(&self) -> [u8; 4] {
        let sha256 = Sha256::digest(self.public_key);
        let hash160 = Ripemd160::digest(sha256);

        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash160[..4]);
        fingerprint
    }

    /// Get depth in derivation tree.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Get chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Serialize to xpub string (Base58Check).
    pub fn to_xpub(&self) -> String {
        let mut data = Vec::with_capacity(78);

        // Version (4 bytes)
        data.extend_from_slice(&self.network.xpub_version());
        // Depth (1 byte)
        data.push(self.depth);
        // Parent fingerprint (4 bytes)
        data.extend_from_slice(&self.parent_fingerprint);
        // Child number (4 bytes)
        data.extend_from_slice(&self.child_number.to_be_bytes());
        // Chain code (32 bytes)
        data.extend_from_slice(&self.chain_code);
        // Public key (33 bytes)
        data.extend_from_slice(&self.public_key);

        bs58::encode(data).with_check().into_string()
    }

    /// Parse from xpub string (Base58Check).
    pub fn from_xpub(xpub: &str) -> Result<Self, HdError> {
        let data = bs58::decode(xpub)
            .with_check(None)
            .into_vec()
            .map_err(|_| HdError::InvalidChecksum)?;

        if data.len() != 78 {
            return Err(HdError::InvalidExtendedKey);
        }

        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);

        let (network, is_private) =
            Network::from_version(&version).ok_or(HdError::InvalidVersion)?;

        if is_private {
            return Err(HdError::InvalidExtendedKey);
        }

        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(&data[45..78]);

        // Validate public key
        secp256k1::PublicKey::from_slice(&public_key).map_err(|_| HdError::InvalidDerivedKey)?;

        Ok(Self {
            public_key,
            chain_code,
            depth,
            parent_fingerprint,
            child_number,
            network,
        })
    }
}

impl fmt::Display for ExtendedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_xpub())
    }
}

impl fmt::Debug for ExtendedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtendedPublicKey {{ depth: {}, fingerprint: {:02x}{:02x}{:02x}{:02x} }}",
            self.depth,
            self.parent_fingerprint[0],
            self.parent_fingerprint[1],
            self.parent_fingerprint[2],
            self.parent_fingerprint[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP32 Test Vector 2 (64 byte seed)
    const TEST_SEED_2: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    const TEST_XPRV_M2: &str = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
    const TEST_XPUB_M2: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";

    fn get_test_seed_64() -> Vec<u8> {
        hex::decode(TEST_SEED_2).unwrap()
    }

    #[test]
    fn test_master_from_seed() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        assert_eq!(master.depth(), 0);
        assert_eq!(master.to_xprv(), TEST_XPRV_M2);
    }

    #[test]
    fn test_master_xpub() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        let xpub = master.extended_public_key();
        assert_eq!(xpub.to_xpub(), TEST_XPUB_M2);
    }

    #[test]
    fn test_xprv_roundtrip() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        let xprv = master.to_xprv();
        let parsed = ExtendedPrivateKey::from_xprv(&xprv).unwrap();
        assert_eq!(parsed.to_xprv(), xprv);
    }

    #[test]
    fn test_xpub_roundtrip() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        let xpub = master.extended_public_key();
        let xpub_str = xpub.to_xpub();
        let parsed = ExtendedPublicKey::from_xpub(&xpub_str).unwrap();
        assert_eq!(parsed.to_xpub(), xpub_str);
    }

    #[test]
    fn test_hardened_from_public_fails() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        let xpub = master.extended_public_key();
        let result = xpub.derive_child(HARDENED_BIT);
        assert!(matches!(result, Err(HdError::HardenedFromPublic)));
    }

    #[test]
    fn test_derive_path() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        let path = DerivationPath::parse("m/0'").unwrap();
        let child = master.derive_path(&path).unwrap();
        assert_eq!(child.depth(), 1);
    }

    #[test]
    fn test_debug_masked() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        let debug = format!("{:?}", master);
        assert!(debug.contains("****"));
        assert!(!debug.contains(&master.to_xprv()));
    }

    #[test]
    fn test_bip44_derivation() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        let path = DerivationPath::bip44_bitcoin(0, 0, 0);
        let child = master.derive_path(&path).unwrap();
        assert_eq!(child.depth(), 5);
    }

    #[test]
    fn test_public_key_derivation_consistency() {
        let seed = get_test_seed_64();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet).unwrap();
        
        // Derive child private key then get public
        let child_priv = master.derive_child(0).unwrap();
        let pub_from_priv = child_priv.extended_public_key();
        
        // Derive child public key directly
        let master_pub = master.extended_public_key();
        let pub_direct = master_pub.derive_child(0).unwrap();
        
        assert_eq!(pub_from_priv.to_xpub(), pub_direct.to_xpub());
    }
}
