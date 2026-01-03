//! Silent Payment address encoding and parsing.

use crate::error::{Result, SilentPaymentError};
use crate::network::Network;
use bech32::{Bech32m, Hrp};
use rustywallet_keys::public_key::PublicKey;

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
}

impl SilentPaymentAddress {
    /// Create a Silent Payment address from scan and spend public keys.
    pub fn new(
        scan_pubkey: &PublicKey,
        spend_pubkey: &PublicKey,
        network: Network,
    ) -> Result<Self> {
        let scan_bytes = scan_pubkey.to_compressed();
        let spend_bytes = spend_pubkey.to_compressed();

        let mut scan_arr = [0u8; 33];
        let mut spend_arr = [0u8; 33];
        scan_arr.copy_from_slice(&scan_bytes);
        spend_arr.copy_from_slice(&spend_bytes);

        Ok(Self {
            scan_pubkey: scan_arr,
            spend_pubkey: spend_arr,
            network,
        })
    }

    /// Create from raw bytes.
    pub fn from_bytes(
        scan_pubkey: [u8; 33],
        spend_pubkey: [u8; 33],
        network: Network,
    ) -> Result<Self> {
        // Validate public keys
        secp256k1::PublicKey::from_slice(&scan_pubkey)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;
        secp256k1::PublicKey::from_slice(&spend_pubkey)
            .map_err(|e| SilentPaymentError::InvalidPublicKey(e.to_string()))?;

        Ok(Self {
            scan_pubkey,
            spend_pubkey,
            network,
        })
    }

    /// Create from a single key pair (scan = spend).
    pub fn from_single_key(pubkey: &PublicKey, network: Network) -> Result<Self> {
        Self::new(pubkey, pubkey, network)
    }

    /// Get the scan public key.
    pub fn scan_pubkey(&self) -> &[u8; 33] {
        &self.scan_pubkey
    }

    /// Get the spend public key.
    pub fn spend_pubkey(&self) -> &[u8; 33] {
        &self.spend_pubkey
    }

    /// Get the network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Check if scan and spend keys are the same.
    pub fn is_single_key(&self) -> bool {
        self.scan_pubkey == self.spend_pubkey
    }

    /// Encode to bech32m string.
    pub fn encode(&self) -> Result<String> {
        let hrp = Hrp::parse(self.network.hrp())
            .map_err(|e| SilentPaymentError::Bech32Error(e.to_string()))?;

        // Combine scan + spend
        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(&self.scan_pubkey);
        payload.extend_from_slice(&self.spend_pubkey);

        // Convert to 5-bit groups
        let mut data_5bit = Vec::with_capacity(1 + payload.len() * 8 / 5 + 1);
        data_5bit.push(0u8); // version 0

        let converted = convert_bits(&payload, 8, 5, true)?;
        data_5bit.extend(converted);

        bech32::encode::<Bech32m>(hrp, &data_5bit)
            .map_err(|e| SilentPaymentError::Bech32Error(e.to_string()))
    }

    /// Parse from bech32m string.
    pub fn decode(s: &str) -> Result<Self> {
        let (hrp, data) =
            bech32::decode(s).map_err(|e| SilentPaymentError::Bech32Error(e.to_string()))?;

        let network = Network::from_hrp(hrp.as_str())?;

        if data.is_empty() {
            return Err(SilentPaymentError::InvalidAddress("Empty data".into()));
        }

        let version = data[0];
        if version != 0 {
            return Err(SilentPaymentError::InvalidAddress(format!(
                "Invalid version: expected 0, got {}",
                version
            )));
        }

        // Convert from 5-bit to 8-bit
        let bytes = convert_bits(&data[1..], 5, 8, false)?;

        if bytes.len() < 66 {
            return Err(SilentPaymentError::InvalidAddress(format!(
                "Invalid data length: expected 66, got {}",
                bytes.len()
            )));
        }

        let mut scan_pubkey = [0u8; 33];
        let mut spend_pubkey = [0u8; 33];
        scan_pubkey.copy_from_slice(&bytes[0..33]);
        spend_pubkey.copy_from_slice(&bytes[33..66]);

        Self::from_bytes(scan_pubkey, spend_pubkey, network)
    }
}

impl std::fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.encode() {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "<invalid>"),
        }
    }
}

impl std::str::FromStr for SilentPaymentAddress {
    type Err = SilentPaymentError;

    fn from_str(s: &str) -> Result<Self> {
        Self::decode(s)
    }
}

/// Convert between bit sizes.
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << to_bits) - 1;

    for &value in data {
        let value = value as u32;
        if (value >> from_bits) != 0 {
            return Err(SilentPaymentError::InvalidAddress(
                "Invalid bit conversion".into(),
            ));
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
        return Err(SilentPaymentError::InvalidAddress("Invalid padding".into()));
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_address_creation() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let addr = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        assert!(!addr.is_single_key());
        assert_eq!(addr.network(), Network::Mainnet);
    }

    #[test]
    fn test_single_key_address() {
        let key = PrivateKey::random();

        let addr =
            SilentPaymentAddress::from_single_key(&key.public_key(), Network::Mainnet).unwrap();

        assert!(addr.is_single_key());
        assert_eq!(addr.scan_pubkey(), addr.spend_pubkey());
    }

    #[test]
    fn test_address_encoding() {
        let key = PrivateKey::random();
        let addr =
            SilentPaymentAddress::from_single_key(&key.public_key(), Network::Mainnet).unwrap();

        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("sp1"));

        let decoded = SilentPaymentAddress::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_testnet_address() {
        let key = PrivateKey::random();
        let addr =
            SilentPaymentAddress::from_single_key(&key.public_key(), Network::Testnet).unwrap();

        let encoded = addr.encode().unwrap();
        assert!(encoded.starts_with("tsp1"));
    }

    #[test]
    fn test_address_roundtrip() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let addr = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        let encoded = addr.to_string();
        let decoded: SilentPaymentAddress = encoded.parse().unwrap();

        assert_eq!(addr.scan_pubkey(), decoded.scan_pubkey());
        assert_eq!(addr.spend_pubkey(), decoded.spend_pubkey());
        assert_eq!(addr.network(), decoded.network());
    }
}
