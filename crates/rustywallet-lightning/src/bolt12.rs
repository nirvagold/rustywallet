//! BOLT12 Offers support.
//!
//! This module implements BOLT12 offers, which provide a more flexible
//! and privacy-preserving way to request payments compared to BOLT11 invoices.
//!
//! ## Features
//!
//! - Parse and encode BOLT12 offer strings
//! - Support for amount, description, expiry, and other fields
//! - Signature validation
//! - Blinded paths for receiver privacy
//!
//! ## Example
//!
//! ```rust,ignore
//! use rustywallet_lightning::bolt12::{Bolt12Offer, OfferBuilder};
//!
//! // Parse an offer
//! let offer = Bolt12Offer::parse("lno1...")?;
//! println!("Amount: {:?}", offer.amount());
//! println!("Description: {}", offer.description());
//!
//! // Create an offer
//! let offer = OfferBuilder::new()
//!     .description("Coffee")
//!     .amount_msats(10_000)
//!     .build()?;
//! println!("Offer: {}", offer.encode());
//! ```

use crate::error::LightningError;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Sha256, Digest};

/// Amount in an offer (can be fixed or variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferAmount {
    /// Fixed amount in millisatoshis
    Fixed(u64),
    /// Variable amount (payer chooses)
    Variable,
    /// Currency amount (e.g., USD)
    Currency {
        /// ISO 4217 currency code
        currency: String,
        /// Amount in smallest currency unit
        amount: u64,
    },
}

impl OfferAmount {
    /// Create a fixed amount in millisatoshis.
    pub fn msats(amount: u64) -> Self {
        OfferAmount::Fixed(amount)
    }

    /// Create a variable amount.
    pub fn variable() -> Self {
        OfferAmount::Variable
    }

    /// Create a currency amount.
    pub fn currency(currency: impl Into<String>, amount: u64) -> Self {
        OfferAmount::Currency {
            currency: currency.into(),
            amount,
        }
    }

    /// Check if this is a fixed amount.
    pub fn is_fixed(&self) -> bool {
        matches!(self, OfferAmount::Fixed(_))
    }

    /// Get the fixed amount in millisatoshis, if any.
    pub fn as_msats(&self) -> Option<u64> {
        match self {
            OfferAmount::Fixed(amount) => Some(*amount),
            _ => None,
        }
    }
}

/// A blinded path for receiver privacy.
#[derive(Debug, Clone)]
pub struct BlindedPath {
    /// Introduction node public key
    pub introduction_node: PublicKey,
    /// Blinding point
    pub blinding_point: PublicKey,
    /// Encrypted path data
    pub encrypted_data: Vec<u8>,
}

impl BlindedPath {
    /// Create a new blinded path.
    pub fn new(
        introduction_node: PublicKey,
        blinding_point: PublicKey,
        encrypted_data: Vec<u8>,
    ) -> Self {
        Self {
            introduction_node,
            blinding_point,
            encrypted_data,
        }
    }
}

/// BOLT12 Offer.
///
/// An offer is a static payment request that can be used multiple times.
/// Unlike BOLT11 invoices, offers don't expire and can be reused.
#[derive(Debug, Clone)]
pub struct Bolt12Offer {
    /// Offer ID (hash of the offer)
    offer_id: [u8; 32],
    /// Amount (optional for variable amount offers)
    amount: Option<OfferAmount>,
    /// Human-readable description
    description: String,
    /// Absolute expiry time (Unix timestamp)
    expiry: Option<u64>,
    /// Issuer name/identifier
    issuer: Option<String>,
    /// Node ID of the recipient
    node_id: Option<PublicKey>,
    /// Blinded paths for privacy
    paths: Vec<BlindedPath>,
    /// Supported chains (empty = Bitcoin mainnet only)
    chains: Vec<[u8; 32]>,
    /// Minimum amount in millisatoshis
    min_amount: Option<u64>,
    /// Maximum amount in millisatoshis
    max_amount: Option<u64>,
    /// Quantity supported
    quantity_max: Option<u64>,
    /// Signature over the offer
    signature: Option<[u8; 64]>,
    /// Raw TLV data for encoding
    raw_tlv: Vec<u8>,
}

impl Bolt12Offer {
    /// Parse a BOLT12 offer from a string.
    ///
    /// The string should start with "lno1" (Lightning Network Offer).
    pub fn parse(s: &str) -> Result<Self, LightningError> {
        let s = s.trim().to_lowercase();
        
        // Check prefix
        if !s.starts_with("lno1") {
            return Err(LightningError::InvalidFormat(
                "BOLT12 offer must start with 'lno1'".into()
            ));
        }

        // Decode bech32
        let (hrp, data) = bech32::decode(&s)
            .map_err(|e| LightningError::InvalidFormat(format!("Bech32 decode error: {}", e)))?;

        let hrp_str = hrp.to_string();
        if hrp_str != "lno" {
            return Err(LightningError::InvalidFormat(
                format!("Invalid HRP: expected 'lno', got '{}'", hrp_str)
            ));
        }

        // Parse TLV stream
        Self::parse_tlv(&data)
    }

    /// Parse TLV data into an offer.
    fn parse_tlv(data: &[u8]) -> Result<Self, LightningError> {
        let mut offer = Bolt12Offer {
            offer_id: [0u8; 32],
            amount: None,
            description: String::new(),
            expiry: None,
            issuer: None,
            node_id: None,
            paths: Vec::new(),
            chains: Vec::new(),
            min_amount: None,
            max_amount: None,
            quantity_max: None,
            signature: None,
            raw_tlv: data.to_vec(),
        };

        let mut pos = 0;
        while pos < data.len() {
            // Read type (BigSize)
            let (tlv_type, bytes_read) = read_bigsize(&data[pos..])?;
            pos += bytes_read;

            if pos >= data.len() {
                break;
            }

            // Read length (BigSize)
            let (tlv_len, bytes_read) = read_bigsize(&data[pos..])?;
            pos += bytes_read;

            if pos + tlv_len as usize > data.len() {
                return Err(LightningError::InvalidFormat("TLV length exceeds data".into()));
            }

            let value = &data[pos..pos + tlv_len as usize];
            pos += tlv_len as usize;

            // Parse known TLV types
            match tlv_type {
                2 => {
                    // chains
                    if value.len().is_multiple_of(32) {
                        for chunk in value.chunks(32) {
                            let mut chain = [0u8; 32];
                            chain.copy_from_slice(chunk);
                            offer.chains.push(chain);
                        }
                    }
                }
                6 => {
                    // amount (currency)
                    if value.len() >= 3 {
                        let currency = String::from_utf8_lossy(&value[..3]).to_string();
                        if value.len() > 3 {
                            let amount = read_tu64(&value[3..])?;
                            offer.amount = Some(OfferAmount::Currency { currency, amount });
                        }
                    }
                }
                8 => {
                    // amount (msats)
                    let amount = read_tu64(value)?;
                    offer.amount = Some(OfferAmount::Fixed(amount));
                }
                10 => {
                    // description
                    offer.description = String::from_utf8_lossy(value).to_string();
                }
                12 => {
                    // features (ignored for now)
                }
                14 => {
                    // absolute_expiry
                    offer.expiry = Some(read_tu64(value)?);
                }
                16 => {
                    // paths (blinded paths)
                    // Simplified parsing - just store raw data
                }
                18 => {
                    // issuer
                    offer.issuer = Some(String::from_utf8_lossy(value).to_string());
                }
                20 => {
                    // quantity_max
                    offer.quantity_max = Some(read_tu64(value)?);
                }
                22 => {
                    // node_id
                    if value.len() == 33 {
                        offer.node_id = PublicKey::from_slice(value).ok();
                    }
                }
                240 => {
                    // signature
                    if value.len() == 64 {
                        let mut sig = [0u8; 64];
                        sig.copy_from_slice(value);
                        offer.signature = Some(sig);
                    }
                }
                _ => {
                    // Unknown TLV - skip
                }
            }
        }

        // Compute offer ID
        offer.offer_id = compute_offer_id(&offer.raw_tlv);

        Ok(offer)
    }

    /// Encode the offer to a string.
    pub fn encode(&self) -> String {
        let hrp = bech32::Hrp::parse("lno").unwrap();
        bech32::encode::<bech32::Bech32m>(hrp, &self.raw_tlv)
            .unwrap_or_else(|_| String::from("lno1invalid"))
    }

    /// Get the offer ID.
    pub fn offer_id(&self) -> &[u8; 32] {
        &self.offer_id
    }

    /// Get the offer ID as hex string.
    pub fn offer_id_hex(&self) -> String {
        hex::encode(self.offer_id)
    }

    /// Get the amount.
    pub fn amount(&self) -> Option<&OfferAmount> {
        self.amount.as_ref()
    }

    /// Get the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the expiry timestamp.
    pub fn expiry(&self) -> Option<u64> {
        self.expiry
    }

    /// Check if the offer has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now > expiry
        } else {
            false
        }
    }

    /// Get the issuer.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Get the node ID.
    pub fn node_id(&self) -> Option<&PublicKey> {
        self.node_id.as_ref()
    }

    /// Get the blinded paths.
    pub fn paths(&self) -> &[BlindedPath] {
        &self.paths
    }

    /// Get the supported chains.
    pub fn chains(&self) -> &[[u8; 32]] {
        &self.chains
    }

    /// Check if this offer supports Bitcoin mainnet.
    pub fn supports_bitcoin_mainnet(&self) -> bool {
        if self.chains.is_empty() {
            return true; // Empty means Bitcoin mainnet only
        }
        // Bitcoin mainnet genesis block hash
        let bitcoin_mainnet = hex::decode(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        ).unwrap();
        self.chains.iter().any(|c| c[..] == bitcoin_mainnet[..])
    }

    /// Get the minimum amount.
    pub fn min_amount(&self) -> Option<u64> {
        self.min_amount
    }

    /// Get the maximum amount.
    pub fn max_amount(&self) -> Option<u64> {
        self.max_amount
    }

    /// Get the maximum quantity.
    pub fn quantity_max(&self) -> Option<u64> {
        self.quantity_max
    }

    /// Get the signature.
    pub fn signature(&self) -> Option<&[u8; 64]> {
        self.signature.as_ref()
    }

    /// Validate the signature.
    pub fn validate_signature(&self) -> bool {
        let Some(sig_bytes) = &self.signature else {
            return false;
        };
        let Some(node_id) = &self.node_id else {
            return false;
        };

        // Create message to sign (offer without signature)
        let msg = compute_offer_id(&self.raw_tlv);
        
        // Verify signature
        let secp = Secp256k1::verification_only();
        let msg = secp256k1::Message::from_digest(msg);
        
        if let Ok(sig) = secp256k1::ecdsa::Signature::from_compact(sig_bytes) {
            secp.verify_ecdsa(&msg, &sig, node_id).is_ok()
        } else {
            false
        }
    }
}

impl std::fmt::Display for Bolt12Offer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl std::str::FromStr for Bolt12Offer {
    type Err = LightningError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Builder for creating BOLT12 offers.
#[derive(Debug, Default)]
pub struct OfferBuilder {
    amount: Option<OfferAmount>,
    description: String,
    expiry: Option<u64>,
    issuer: Option<String>,
    node_id: Option<PublicKey>,
    paths: Vec<BlindedPath>,
    chains: Vec<[u8; 32]>,
    min_amount: Option<u64>,
    max_amount: Option<u64>,
    quantity_max: Option<u64>,
}

impl OfferBuilder {
    /// Create a new offer builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set a fixed amount in millisatoshis.
    pub fn amount_msats(mut self, amount: u64) -> Self {
        self.amount = Some(OfferAmount::Fixed(amount));
        self
    }

    /// Set a variable amount (payer chooses).
    pub fn amount_variable(mut self) -> Self {
        self.amount = Some(OfferAmount::Variable);
        self
    }

    /// Set a currency amount.
    pub fn amount_currency(mut self, currency: impl Into<String>, amount: u64) -> Self {
        self.amount = Some(OfferAmount::Currency {
            currency: currency.into(),
            amount,
        });
        self
    }

    /// Set the expiry timestamp.
    pub fn expiry(mut self, timestamp: u64) -> Self {
        self.expiry = Some(timestamp);
        self
    }

    /// Set the expiry relative to now.
    pub fn expires_in(mut self, seconds: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expiry = Some(now + seconds);
        self
    }

    /// Set the issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set the node ID.
    pub fn node_id(mut self, node_id: PublicKey) -> Self {
        self.node_id = Some(node_id);
        self
    }

    /// Add a blinded path.
    pub fn add_path(mut self, path: BlindedPath) -> Self {
        self.paths.push(path);
        self
    }

    /// Add a supported chain.
    pub fn add_chain(mut self, chain_hash: [u8; 32]) -> Self {
        self.chains.push(chain_hash);
        self
    }

    /// Set the minimum amount.
    pub fn min_amount(mut self, amount: u64) -> Self {
        self.min_amount = Some(amount);
        self
    }

    /// Set the maximum amount.
    pub fn max_amount(mut self, amount: u64) -> Self {
        self.max_amount = Some(amount);
        self
    }

    /// Set the maximum quantity.
    pub fn quantity_max(mut self, quantity: u64) -> Self {
        self.quantity_max = Some(quantity);
        self
    }

    /// Build the offer.
    pub fn build(self) -> Result<Bolt12Offer, LightningError> {
        if self.description.is_empty() {
            return Err(LightningError::InvalidFormat(
                "Offer must have a description".into()
            ));
        }

        // Build TLV stream
        let mut tlv = Vec::new();

        // chains (type 2)
        if !self.chains.is_empty() {
            let mut chain_data = Vec::new();
            for chain in &self.chains {
                chain_data.extend_from_slice(chain);
            }
            write_tlv(&mut tlv, 2, &chain_data);
        }

        // amount (type 8)
        if let Some(OfferAmount::Fixed(amount)) = &self.amount {
            write_tlv(&mut tlv, 8, &encode_tu64(*amount));
        }

        // description (type 10)
        write_tlv(&mut tlv, 10, self.description.as_bytes());

        // absolute_expiry (type 14)
        if let Some(expiry) = self.expiry {
            write_tlv(&mut tlv, 14, &encode_tu64(expiry));
        }

        // issuer (type 18)
        if let Some(issuer) = &self.issuer {
            write_tlv(&mut tlv, 18, issuer.as_bytes());
        }

        // quantity_max (type 20)
        if let Some(qty) = self.quantity_max {
            write_tlv(&mut tlv, 20, &encode_tu64(qty));
        }

        // node_id (type 22)
        if let Some(node_id) = &self.node_id {
            write_tlv(&mut tlv, 22, &node_id.serialize());
        }

        let offer_id = compute_offer_id(&tlv);

        Ok(Bolt12Offer {
            offer_id,
            amount: self.amount,
            description: self.description,
            expiry: self.expiry,
            issuer: self.issuer,
            node_id: self.node_id,
            paths: self.paths,
            chains: self.chains,
            min_amount: self.min_amount,
            max_amount: self.max_amount,
            quantity_max: self.quantity_max,
            signature: None,
            raw_tlv: tlv,
        })
    }

    /// Build and sign the offer.
    pub fn build_signed(self, secret_key: &SecretKey) -> Result<Bolt12Offer, LightningError> {
        let mut offer = self.build()?;
        
        // Sign the offer
        let secp = Secp256k1::signing_only();
        let msg = secp256k1::Message::from_digest(offer.offer_id);
        let sig = secp.sign_ecdsa(&msg, secret_key);
        
        // Add signature to TLV
        let sig_bytes = sig.serialize_compact();
        write_tlv(&mut offer.raw_tlv, 240, &sig_bytes);
        
        offer.signature = Some(sig_bytes);
        offer.node_id = Some(secret_key.public_key(&secp));
        
        Ok(offer)
    }
}

// Helper functions

/// Read a BigSize value from bytes.
fn read_bigsize(data: &[u8]) -> Result<(u64, usize), LightningError> {
    if data.is_empty() {
        return Err(LightningError::InvalidFormat("Empty BigSize".into()));
    }

    match data[0] {
        0..=0xfc => Ok((data[0] as u64, 1)),
        0xfd => {
            if data.len() < 3 {
                return Err(LightningError::InvalidFormat("Truncated BigSize".into()));
            }
            let val = u16::from_be_bytes([data[1], data[2]]) as u64;
            Ok((val, 3))
        }
        0xfe => {
            if data.len() < 5 {
                return Err(LightningError::InvalidFormat("Truncated BigSize".into()));
            }
            let val = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64;
            Ok((val, 5))
        }
        0xff => {
            if data.len() < 9 {
                return Err(LightningError::InvalidFormat("Truncated BigSize".into()));
            }
            let val = u64::from_be_bytes([
                data[1], data[2], data[3], data[4],
                data[5], data[6], data[7], data[8],
            ]);
            Ok((val, 9))
        }
    }
}

/// Read a truncated u64 (tu64) from bytes.
fn read_tu64(data: &[u8]) -> Result<u64, LightningError> {
    if data.is_empty() {
        return Ok(0);
    }
    if data.len() > 8 {
        return Err(LightningError::InvalidFormat("tu64 too long".into()));
    }
    
    let mut bytes = [0u8; 8];
    bytes[8 - data.len()..].copy_from_slice(data);
    Ok(u64::from_be_bytes(bytes))
}

/// Encode a u64 as truncated bytes.
fn encode_tu64(val: u64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

/// Write a BigSize value.
fn write_bigsize(out: &mut Vec<u8>, val: u64) {
    if val <= 0xfc {
        out.push(val as u8);
    } else if val <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xffffffff {
        out.push(0xfe);
        out.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&val.to_be_bytes());
    }
}

/// Write a TLV record.
fn write_tlv(out: &mut Vec<u8>, tlv_type: u64, value: &[u8]) {
    write_bigsize(out, tlv_type);
    write_bigsize(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// Compute the offer ID (SHA256 hash of TLV data).
fn compute_offer_id(tlv: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"lightning");
    hasher.update(b"offer");
    hasher.update(b"offer_id");
    hasher.update(tlv);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offer_builder() {
        let offer = OfferBuilder::new()
            .description("Test offer")
            .amount_msats(10_000)
            .build()
            .unwrap();

        assert_eq!(offer.description(), "Test offer");
        assert_eq!(offer.amount().unwrap().as_msats(), Some(10_000));
    }

    #[test]
    fn test_offer_builder_with_expiry() {
        let offer = OfferBuilder::new()
            .description("Expiring offer")
            .expires_in(3600)
            .build()
            .unwrap();

        assert!(offer.expiry().is_some());
        assert!(!offer.is_expired());
    }

    #[test]
    fn test_offer_builder_with_issuer() {
        let offer = OfferBuilder::new()
            .description("Coffee")
            .issuer("Bob's Coffee Shop")
            .build()
            .unwrap();

        assert_eq!(offer.issuer(), Some("Bob's Coffee Shop"));
    }

    #[test]
    fn test_offer_encode_decode() {
        let offer = OfferBuilder::new()
            .description("Test roundtrip")
            .amount_msats(50_000)
            .build()
            .unwrap();

        let encoded = offer.encode();
        assert!(encoded.starts_with("lno1"));

        let decoded = Bolt12Offer::parse(&encoded).unwrap();
        assert_eq!(decoded.description(), "Test roundtrip");
        assert_eq!(decoded.amount().unwrap().as_msats(), Some(50_000));
    }

    #[test]
    fn test_offer_variable_amount() {
        let offer = OfferBuilder::new()
            .description("Donation")
            .amount_variable()
            .build()
            .unwrap();

        assert!(matches!(offer.amount(), Some(OfferAmount::Variable)));
    }

    #[test]
    fn test_offer_id_computation() {
        let offer1 = OfferBuilder::new()
            .description("Offer 1")
            .build()
            .unwrap();

        let offer2 = OfferBuilder::new()
            .description("Offer 2")
            .build()
            .unwrap();

        // Different offers should have different IDs
        assert_ne!(offer1.offer_id(), offer2.offer_id());
    }

    #[test]
    fn test_offer_amount_types() {
        let fixed = OfferAmount::msats(1000);
        assert!(fixed.is_fixed());
        assert_eq!(fixed.as_msats(), Some(1000));

        let variable = OfferAmount::variable();
        assert!(!variable.is_fixed());
        assert_eq!(variable.as_msats(), None);

        let currency = OfferAmount::currency("USD", 100);
        assert!(!currency.is_fixed());
    }

    #[test]
    fn test_empty_description_fails() {
        let result = OfferBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_bitcoin_mainnet_support() {
        let offer = OfferBuilder::new()
            .description("Bitcoin offer")
            .build()
            .unwrap();

        // Empty chains means Bitcoin mainnet only
        assert!(offer.supports_bitcoin_mainnet());
    }
}
