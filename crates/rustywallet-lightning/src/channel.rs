//! Channel point handling.
//!
//! This module provides types for working with Lightning channel points,
//! which identify specific channels by their funding transaction.

use crate::error::LightningError;
use std::fmt;
use std::str::FromStr;

/// A channel point identifying a Lightning channel.
///
/// A channel point consists of a funding transaction ID and output index.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChannelPoint {
    /// Funding transaction ID (32 bytes, reversed for display)
    txid: [u8; 32],
    /// Output index in the funding transaction
    output_index: u32,
}

impl ChannelPoint {
    /// Create a new channel point.
    pub fn new(txid: [u8; 32], output_index: u32) -> Self {
        Self { txid, output_index }
    }

    /// Create from txid hex string and output index.
    pub fn from_parts(txid_hex: &str, output_index: u32) -> Result<Self, LightningError> {
        let bytes = hex::decode(txid_hex)
            .map_err(|e| LightningError::InvalidChannelPoint(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(LightningError::InvalidChannelPoint(format!(
                "Expected 32 bytes for txid, got {}",
                bytes.len()
            )));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes);

        Ok(Self { txid, output_index })
    }

    /// Parse from string format "txid:index".
    pub fn parse(s: &str) -> Result<Self, LightningError> {
        s.parse()
    }

    /// Get the funding transaction ID.
    pub fn txid(&self) -> &[u8; 32] {
        &self.txid
    }

    /// Get the funding transaction ID as hex (reversed for display).
    pub fn txid_hex(&self) -> String {
        // Bitcoin txids are displayed in reversed byte order
        let mut reversed = self.txid;
        reversed.reverse();
        hex::encode(reversed)
    }

    /// Get the output index.
    pub fn output_index(&self) -> u32 {
        self.output_index
    }

    /// Convert to the standard string format "txid:index".
    pub fn to_string_format(&self) -> String {
        format!("{}:{}", self.txid_hex(), self.output_index)
    }

    /// Get the raw txid bytes (not reversed).
    pub fn txid_bytes(&self) -> &[u8; 32] {
        &self.txid
    }
}

impl fmt::Display for ChannelPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_format())
    }
}

impl FromStr for ChannelPoint {
    type Err = LightningError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(LightningError::InvalidChannelPoint(
                "Expected format 'txid:index'".into(),
            ));
        }

        let txid_hex = parts[0];
        let output_index: u32 = parts[1]
            .parse()
            .map_err(|e| LightningError::InvalidChannelPoint(format!("Invalid index: {}", e)))?;

        // Parse txid (displayed in reversed order)
        let bytes = hex::decode(txid_hex)
            .map_err(|e| LightningError::InvalidChannelPoint(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(LightningError::InvalidChannelPoint(format!(
                "Expected 32 bytes for txid, got {}",
                bytes.len()
            )));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes);
        // Reverse to internal format
        txid.reverse();

        Ok(Self { txid, output_index })
    }
}

/// Short channel ID (SCID) - compact channel identifier.
///
/// Encodes block height, transaction index, and output index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShortChannelId(u64);

impl ShortChannelId {
    /// Create from components.
    pub fn new(block_height: u32, tx_index: u32, output_index: u16) -> Self {
        let scid = ((block_height as u64) << 40)
            | ((tx_index as u64) << 16)
            | (output_index as u64);
        Self(scid)
    }

    /// Create from raw u64 value.
    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Parse from string format "block:tx:output".
    pub fn parse(s: &str) -> Result<Self, LightningError> {
        let parts: Vec<&str> = s.split('x').collect();
        if parts.len() != 3 {
            return Err(LightningError::InvalidChannelPoint(
                "Expected format 'blockxTxxoutput'".into(),
            ));
        }

        let block: u32 = parts[0]
            .parse()
            .map_err(|e| LightningError::InvalidChannelPoint(format!("Invalid block: {}", e)))?;
        let tx: u32 = parts[1]
            .parse()
            .map_err(|e| LightningError::InvalidChannelPoint(format!("Invalid tx: {}", e)))?;
        let output: u16 = parts[2]
            .parse()
            .map_err(|e| LightningError::InvalidChannelPoint(format!("Invalid output: {}", e)))?;

        Ok(Self::new(block, tx, output))
    }

    /// Get the raw u64 value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Get the block height.
    pub fn block_height(&self) -> u32 {
        (self.0 >> 40) as u32
    }

    /// Get the transaction index.
    pub fn tx_index(&self) -> u32 {
        ((self.0 >> 16) & 0xFFFFFF) as u32
    }

    /// Get the output index.
    pub fn output_index(&self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

impl fmt::Display for ShortChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}x{}x{}",
            self.block_height(),
            self.tx_index(),
            self.output_index()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_point_parse() {
        let cp_str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:1";
        let cp = ChannelPoint::parse(cp_str).unwrap();

        assert_eq!(cp.output_index(), 1);
        assert_eq!(cp.to_string(), cp_str);
    }

    #[test]
    fn test_channel_point_from_parts() {
        let txid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let cp = ChannelPoint::from_parts(txid, 0).unwrap();

        assert_eq!(cp.output_index(), 0);
    }

    #[test]
    fn test_short_channel_id() {
        let scid = ShortChannelId::new(700000, 1234, 0);

        assert_eq!(scid.block_height(), 700000);
        assert_eq!(scid.tx_index(), 1234);
        assert_eq!(scid.output_index(), 0);
    }

    #[test]
    fn test_short_channel_id_display() {
        let scid = ShortChannelId::new(700000, 1234, 1);
        assert_eq!(scid.to_string(), "700000x1234x1");
    }

    #[test]
    fn test_short_channel_id_parse() {
        let scid = ShortChannelId::parse("700000x1234x1").unwrap();

        assert_eq!(scid.block_height(), 700000);
        assert_eq!(scid.tx_index(), 1234);
        assert_eq!(scid.output_index(), 1);
    }
}
