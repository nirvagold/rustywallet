//! PSBT types and constants

use std::collections::BTreeMap;

/// PSBT magic bytes: "psbt" + 0xff separator
pub const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// PSBT separator byte
pub const PSBT_SEPARATOR: u8 = 0x00;

// Global key types
pub const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
pub const PSBT_GLOBAL_XPUB: u8 = 0x01;
pub const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
pub const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
pub const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
pub const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
pub const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
pub const PSBT_GLOBAL_VERSION: u8 = 0xFB;
pub const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

// Input key types
pub const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
pub const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
pub const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
pub const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
pub const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
pub const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
pub const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
pub const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
pub const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
pub const PSBT_IN_POR_COMMITMENT: u8 = 0x09;
pub const PSBT_IN_RIPEMD160: u8 = 0x0A;
pub const PSBT_IN_SHA256: u8 = 0x0B;
pub const PSBT_IN_HASH160: u8 = 0x0C;
pub const PSBT_IN_HASH256: u8 = 0x0D;
pub const PSBT_IN_PREVIOUS_TXID: u8 = 0x0E;
pub const PSBT_IN_OUTPUT_INDEX: u8 = 0x0F;
pub const PSBT_IN_SEQUENCE: u8 = 0x10;
pub const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
pub const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
pub const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
pub const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
pub const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
pub const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
pub const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
pub const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;
pub const PSBT_IN_PROPRIETARY: u8 = 0xFC;

// Output key types
pub const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
pub const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
pub const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
pub const PSBT_OUT_AMOUNT: u8 = 0x03;
pub const PSBT_OUT_SCRIPT: u8 = 0x04;
pub const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
pub const PSBT_OUT_TAP_TREE: u8 = 0x06;
pub const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
pub const PSBT_OUT_PROPRIETARY: u8 = 0xFC;

/// Sighash types for PSBT signing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PsbtSighashType {
    /// SIGHASH_ALL (0x01)
    #[default]
    All,
    /// SIGHASH_NONE (0x02)
    None,
    /// SIGHASH_SINGLE (0x03)
    Single,
    /// SIGHASH_ALL | SIGHASH_ANYONECANPAY (0x81)
    AllAnyoneCanPay,
    /// SIGHASH_NONE | SIGHASH_ANYONECANPAY (0x82)
    NoneAnyoneCanPay,
    /// SIGHASH_SINGLE | SIGHASH_ANYONECANPAY (0x83)
    SingleAnyoneCanPay,
    /// SIGHASH_DEFAULT for Taproot (0x00)
    Default,
}

impl PsbtSighashType {
    /// Convert to u32 for serialization
    pub fn to_u32(self) -> u32 {
        match self {
            Self::All => 0x01,
            Self::None => 0x02,
            Self::Single => 0x03,
            Self::AllAnyoneCanPay => 0x81,
            Self::NoneAnyoneCanPay => 0x82,
            Self::SingleAnyoneCanPay => 0x83,
            Self::Default => 0x00,
        }
    }

    /// Parse from u32
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::All),
            0x02 => Some(Self::None),
            0x03 => Some(Self::Single),
            0x81 => Some(Self::AllAnyoneCanPay),
            0x82 => Some(Self::NoneAnyoneCanPay),
            0x83 => Some(Self::SingleAnyoneCanPay),
            _ => None,
        }
    }
}

/// Key source information (master fingerprint + derivation path)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySource {
    /// Master key fingerprint (first 4 bytes of hash160 of master pubkey)
    pub fingerprint: [u8; 4],
    /// BIP32 derivation path
    pub path: Vec<u32>,
}

impl KeySource {
    /// Create a new key source
    pub fn new(fingerprint: [u8; 4], path: Vec<u32>) -> Self {
        Self { fingerprint, path }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.path.len() * 4);
        bytes.extend_from_slice(&self.fingerprint);
        for &index in &self.path {
            bytes.extend_from_slice(&index.to_le_bytes());
        }
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 || !((bytes.len() - 4).is_multiple_of(4)) {
            return None;
        }

        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&bytes[0..4]);

        let path_len = (bytes.len() - 4) / 4;
        let mut path = Vec::with_capacity(path_len);
        for i in 0..path_len {
            let start = 4 + i * 4;
            let index = u32::from_le_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ]);
            path.push(index);
        }

        Some(Self { fingerprint, path })
    }

    /// Format path as string (e.g., "m/84'/0'/0'/0/0")
    pub fn path_string(&self) -> String {
        let mut s = String::from("m");
        for &index in &self.path {
            if index >= 0x80000000 {
                s.push_str(&format!("/{}'", index - 0x80000000));
            } else {
                s.push_str(&format!("/{}", index));
            }
        }
        s
    }
}

/// Proprietary key identifier
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProprietaryKey {
    /// Identifier prefix
    pub prefix: Vec<u8>,
    /// Subtype
    pub subtype: u8,
    /// Key data
    pub key: Vec<u8>,
}

impl ProprietaryKey {
    /// Create a new proprietary key
    pub fn new(prefix: Vec<u8>, subtype: u8, key: Vec<u8>) -> Self {
        Self { prefix, subtype, key }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Compact size for prefix length
        bytes.push(self.prefix.len() as u8);
        bytes.extend_from_slice(&self.prefix);
        bytes.push(self.subtype);
        bytes.extend_from_slice(&self.key);
        bytes
    }

    /// Parse from bytes (after key type byte)
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }

        let prefix_len = bytes[0] as usize;
        if bytes.len() < 1 + prefix_len + 1 {
            return None;
        }

        let prefix = bytes[1..1 + prefix_len].to_vec();
        let subtype = bytes[1 + prefix_len];
        let key = bytes[2 + prefix_len..].to_vec();

        Some(Self { prefix, subtype, key })
    }
}

/// Raw key in PSBT map
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawKey {
    /// Key type
    pub key_type: u8,
    /// Key data (may be empty)
    pub key_data: Vec<u8>,
}

impl RawKey {
    /// Create a new raw key
    pub fn new(key_type: u8, key_data: Vec<u8>) -> Self {
        Self { key_type, key_data }
    }

    /// Create a key with no data
    pub fn type_only(key_type: u8) -> Self {
        Self {
            key_type,
            key_data: Vec::new(),
        }
    }
}

/// Unknown fields storage
pub type UnknownFields = BTreeMap<RawKey, Vec<u8>>;

/// Proprietary fields storage
pub type ProprietaryFields = BTreeMap<ProprietaryKey, Vec<u8>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sighash_type_roundtrip() {
        let types = [
            PsbtSighashType::All,
            PsbtSighashType::None,
            PsbtSighashType::Single,
            PsbtSighashType::AllAnyoneCanPay,
            PsbtSighashType::NoneAnyoneCanPay,
            PsbtSighashType::SingleAnyoneCanPay,
            PsbtSighashType::Default,
        ];

        for sighash in types {
            let value = sighash.to_u32();
            let parsed = PsbtSighashType::from_u32(value).unwrap();
            assert_eq!(sighash, parsed);
        }
    }

    #[test]
    fn test_key_source_roundtrip() {
        let source = KeySource::new(
            [0x01, 0x02, 0x03, 0x04],
            vec![0x80000054, 0x80000000, 0x80000000, 0, 0],
        );

        let bytes = source.to_bytes();
        let parsed = KeySource::from_bytes(&bytes).unwrap();

        assert_eq!(source, parsed);
        assert_eq!(parsed.path_string(), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_proprietary_key_roundtrip() {
        let key = ProprietaryKey::new(b"test".to_vec(), 0x01, b"data".to_vec());
        let bytes = key.to_bytes();
        let parsed = ProprietaryKey::from_bytes(&bytes).unwrap();
        assert_eq!(key, parsed);
    }
}
