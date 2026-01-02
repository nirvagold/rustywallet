//! Silent Payments (BIP352) support.
//!
//! Silent Payments allow receivers to publish a single static address
//! while each payment generates a unique on-chain address that only
//! the receiver can detect and spend.

use sha2::{Digest, Sha256};

use crate::error::AddressError;
use crate::network::Network;
use rustywallet_keys::public_key::PublicKey;

/// HRP for mainnet Silent Payment addresses.
const SP_MAINNET_HRP: &str = "sp";
/// HRP for testnet Silent Payment addresses.
const SP_TESTNET_HRP: &str = "tsp";

/// Silent Payment address (BIP352).
///
/// A Silent Payment address consists of two public keys:
/// - Scan key (B_scan): Used to detect incoming payments
/// - Spend key (B_spend): Used to derive the actual spending key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    /// Scan public key (33 bytes compressed)
    scan_pubkey: [u8; 33],
    /// Spend public key (33 bytes compressed)  
    spend_pubkey: [u8; 33],
    /// Network
    network: Network,
    /// Encoded address string
    encoded: String,
}

impl SilentPaymentAddress {
    /// Create a Silent Payment address from scan and spend public keys.
    pub fn new(
        scan_pubkey: &PublicKey,
        spend_pubkey: &PublicKey,
        network: Network,
    ) -> Result<Self, AddressError> {
        if !network.is_bitcoin() {
            return Err(AddressError::NetworkMismatch {
                expected: "Bitcoin".to_string(),
                actual: network.to_string(),
            });
        }

        let scan_bytes = scan_pubkey.to_compressed();
        let spend_bytes = spend_pubkey.to_compressed();

        let mut scan_arr = [0u8; 33];
        let mut spend_arr = [0u8; 33];
        scan_arr.copy_from_slice(&scan_bytes);
        spend_arr.copy_from_slice(&spend_bytes);

        let hrp = Self::hrp(network);
        
        // Encode using custom bech32m for Silent Payments
        // Format: hrp + "1" + version(0) + bech32m(scan_pubkey || spend_pubkey)
        let encoded = Self::encode_sp_address(hrp, &scan_arr, &spend_arr)?;

        Ok(Self {
            scan_pubkey: scan_arr,
            spend_pubkey: spend_arr,
            network,
            encoded,
        })
    }

    /// Encode Silent Payment address using bech32m.
    fn encode_sp_address(hrp: &str, scan: &[u8; 33], spend: &[u8; 33]) -> Result<String, AddressError> {
        use bech32::{Bech32m, Hrp};
        
        let hrp = Hrp::parse(hrp).map_err(|e| AddressError::InvalidBech32(e.to_string()))?;
        
        // Combine scan + spend (version is prepended separately)
        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(scan);
        payload.extend_from_slice(spend);
        
        // Convert to 5-bit groups for bech32
        let mut data_5bit = Vec::with_capacity(1 + payload.len() * 8 / 5 + 1);
        data_5bit.push(0u8); // version 0
        
        let converted = Self::convert_bits(&payload, 8, 5, true)?;
        data_5bit.extend(converted);
        
        bech32::encode::<Bech32m>(hrp, &data_5bit)
            .map_err(|e| AddressError::InvalidBech32(e.to_string()))
    }

    /// Convert between bit sizes.
    fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, AddressError> {
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut ret = Vec::new();
        let maxv: u32 = (1 << to_bits) - 1;
        
        for &value in data {
            let value = value as u32;
            if (value >> from_bits) != 0 {
                return Err(AddressError::InvalidFormat("Invalid bit conversion".into()));
            }
            acc = (acc << from_bits) | value;
            bits += from_bits;
            while bits >= to_bits {
                bits -= to_bits;
                ret.push(((acc >> bits) & maxv) as u8);
            }
        }
        
        if pad {
            if bits > 0 {
                ret.push(((acc << (to_bits - bits)) & maxv) as u8);
            }
        } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
            return Err(AddressError::InvalidFormat("Invalid padding".into()));
        }
        
        Ok(ret)
    }

    /// Create from a single key pair (scan = spend).
    pub fn from_single_key(pubkey: &PublicKey, network: Network) -> Result<Self, AddressError> {
        Self::new(pubkey, pubkey, network)
    }

    /// Get the scan public key.
    #[inline]
    pub fn scan_pubkey(&self) -> &[u8; 33] {
        &self.scan_pubkey
    }

    /// Get the spend public key.
    #[inline]
    pub fn spend_pubkey(&self) -> &[u8; 33] {
        &self.spend_pubkey
    }

    /// Get the network.
    #[inline]
    pub fn network(&self) -> Network {
        self.network
    }

    /// Parse Silent Payment address from string.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        s.parse()
    }

    /// Validate Silent Payment address string.
    pub fn validate(s: &str) -> Result<(), AddressError> {
        s.parse::<Self>().map(|_| ())
    }

    /// Get HRP for network.
    fn hrp(network: Network) -> &'static str {
        match network {
            Network::BitcoinMainnet => SP_MAINNET_HRP,
            Network::BitcoinTestnet => SP_TESTNET_HRP,
            _ => SP_MAINNET_HRP,
        }
    }

    /// Check if scan and spend keys are the same.
    pub fn is_single_key(&self) -> bool {
        self.scan_pubkey == self.spend_pubkey
    }
}

impl std::fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encoded)
    }
}

impl std::str::FromStr for SilentPaymentAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data) = bech32::decode(s)
            .map_err(|e| AddressError::InvalidBech32(e.to_string()))?;

        let network = match hrp.as_str() {
            SP_MAINNET_HRP => Network::BitcoinMainnet,
            SP_TESTNET_HRP => Network::BitcoinTestnet,
            _ => {
                return Err(AddressError::InvalidFormat(format!(
                    "Unknown SP HRP: {}",
                    hrp
                )))
            }
        };

        if data.is_empty() {
            return Err(AddressError::InvalidFormat("Empty SP data".into()));
        }

        let version = data[0];
        if version != 0 {
            return Err(AddressError::InvalidFormat(format!(
                "Invalid SP version: expected 0, got {}",
                version
            )));
        }

        // Convert from 5-bit to 8-bit (skip version byte)
        let bytes = Self::convert_bits(&data[1..], 5, 8, false)?;
        
        if bytes.len() < 66 {
            return Err(AddressError::InvalidFormat(format!(
                "Invalid SP data length: expected 66, got {}",
                bytes.len()
            )));
        }

        let mut scan_pubkey = [0u8; 33];
        let mut spend_pubkey = [0u8; 33];
        scan_pubkey.copy_from_slice(&bytes[0..33]);
        spend_pubkey.copy_from_slice(&bytes[33..66]);

        Ok(Self {
            scan_pubkey,
            spend_pubkey,
            network,
            encoded: s.to_lowercase(),
        })
    }
}

/// Silent Payment output derivation utilities.
pub struct SilentPaymentDeriver;

impl SilentPaymentDeriver {
    /// Compute shared secret for payment detection.
    ///
    /// This is a simplified version - full BIP352 requires ECDH.
    pub fn compute_tweak(
        scan_pubkey: &[u8; 33],
        input_hash: &[u8; 32],
        output_index: u32,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(scan_pubkey);
        hasher.update(input_hash);
        hasher.update(output_index.to_le_bytes());
        
        let result = hasher.finalize();
        let mut tweak = [0u8; 32];
        tweak.copy_from_slice(&result);
        tweak
    }

    /// Hash input outpoints for Silent Payment derivation.
    pub fn hash_outpoints(outpoints: &[(String, u32)]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Sort outpoints lexicographically
        let mut sorted: Vec<_> = outpoints.to_vec();
        sorted.sort();
        
        for (txid, vout) in sorted {
            if let Ok(txid_bytes) = hex::decode(&txid) {
                hasher.update(&txid_bytes);
                hasher.update(vout.to_le_bytes());
            }
        }
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Silent Payment label for multiple addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPaymentLabel {
    /// Label value (32 bytes)
    value: [u8; 32],
}

impl SilentPaymentLabel {
    /// Create a new label from integer.
    pub fn new(m: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"BIP0352/Label");
        hasher.update(m.to_le_bytes());
        
        let result = hasher.finalize();
        let mut value = [0u8; 32];
        value.copy_from_slice(&result);
        
        Self { value }
    }

    /// Get the label value.
    pub fn value(&self) -> &[u8; 32] {
        &self.value
    }

    /// Create label from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { value: bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_silent_payment_address_creation() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();
        
        let addr = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::BitcoinMainnet,
        ).unwrap();
        
        assert!(addr.to_string().starts_with("sp1"));
        assert!(!addr.is_single_key());
    }

    #[test]
    fn test_silent_payment_single_key() {
        let key = PrivateKey::random();
        
        let addr = SilentPaymentAddress::from_single_key(
            &key.public_key(),
            Network::BitcoinMainnet,
        ).unwrap();
        
        assert!(addr.is_single_key());
        assert_eq!(addr.scan_pubkey(), addr.spend_pubkey());
    }

    #[test]
    fn test_silent_payment_testnet() {
        let key = PrivateKey::random();
        
        let addr = SilentPaymentAddress::from_single_key(
            &key.public_key(),
            Network::BitcoinTestnet,
        ).unwrap();
        
        assert!(addr.to_string().starts_with("tsp1"));
    }

    #[test]
    fn test_silent_payment_label() {
        let label0 = SilentPaymentLabel::new(0);
        let label1 = SilentPaymentLabel::new(1);
        
        assert_ne!(label0.value(), label1.value());
        assert_eq!(label0.value().len(), 32);
    }

    #[test]
    fn test_hash_outpoints() {
        let outpoints = vec![
            ("abc123".to_string(), 0),
            ("def456".to_string(), 1),
        ];
        
        let hash = SilentPaymentDeriver::hash_outpoints(&outpoints);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_compute_tweak() {
        let scan_pubkey = [0u8; 33];
        let input_hash = [1u8; 32];
        
        let tweak = SilentPaymentDeriver::compute_tweak(&scan_pubkey, &input_hash, 0);
        assert_eq!(tweak.len(), 32);
        
        // Different index should give different tweak
        let tweak2 = SilentPaymentDeriver::compute_tweak(&scan_pubkey, &input_hash, 1);
        assert_ne!(tweak, tweak2);
    }
}
