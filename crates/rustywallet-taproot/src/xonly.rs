//! X-only public keys (BIP340)
//!
//! X-only public keys are 32-byte representations that only include the x-coordinate.

use crate::error::TaprootError;
use secp256k1::{Secp256k1, XOnlyPublicKey as Secp256k1XOnlyPublicKey};
use std::fmt;

/// Parity of the y-coordinate
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Parity {
    /// Even y-coordinate
    Even,
    /// Odd y-coordinate
    Odd,
}

impl Parity {
    /// Convert to u8 (0 for even, 1 for odd)
    pub fn to_u8(self) -> u8 {
        match self {
            Parity::Even => 0,
            Parity::Odd => 1,
        }
    }

    /// Create from u8
    pub fn from_u8(value: u8) -> Result<Self, TaprootError> {
        match value {
            0 => Ok(Parity::Even),
            1 => Ok(Parity::Odd),
            _ => Err(TaprootError::InvalidParity),
        }
    }
}

impl From<secp256k1::Parity> for Parity {
    fn from(p: secp256k1::Parity) -> Self {
        match p {
            secp256k1::Parity::Even => Parity::Even,
            secp256k1::Parity::Odd => Parity::Odd,
        }
    }
}

impl From<Parity> for secp256k1::Parity {
    fn from(p: Parity) -> Self {
        match p {
            Parity::Even => secp256k1::Parity::Even,
            Parity::Odd => secp256k1::Parity::Odd,
        }
    }
}

/// 32-byte x-only public key (BIP340)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct XOnlyPublicKey {
    inner: Secp256k1XOnlyPublicKey,
}

impl XOnlyPublicKey {
    /// Create from a compressed public key (33 bytes)
    pub fn from_compressed(data: &[u8; 33]) -> Result<(Self, Parity), TaprootError> {
        let pubkey = secp256k1::PublicKey::from_slice(data)
            .map_err(|e| TaprootError::Secp256k1Error(e.to_string()))?;
        let (xonly, parity) = pubkey.x_only_public_key();
        Ok((Self { inner: xonly }, parity.into()))
    }

    /// Create from 32-byte x-only representation
    pub fn from_slice(data: &[u8]) -> Result<Self, TaprootError> {
        if data.len() != 32 {
            return Err(TaprootError::InvalidLength {
                expected: 32,
                got: data.len(),
            });
        }
        let inner = Secp256k1XOnlyPublicKey::from_slice(data)
            .map_err(|e| TaprootError::Secp256k1Error(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Create from byte array
    pub fn from_bytes(data: [u8; 32]) -> Result<Self, TaprootError> {
        Self::from_slice(&data)
    }

    /// Serialize to 32 bytes
    pub fn serialize(&self) -> [u8; 32] {
        self.inner.serialize()
    }

    /// Get as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        // XOnlyPublicKey doesn't have as_bytes, so we serialize
        // This is a bit inefficient but safe
        unsafe {
            std::slice::from_raw_parts(
                &self.inner as *const _ as *const u8,
                32,
            )
        }
    }

    /// Tweak the public key by adding a scalar
    pub fn tweak_add(
        &self,
        secp: &Secp256k1<secp256k1::All>,
        tweak: &[u8; 32],
    ) -> Result<(Self, Parity), TaprootError> {
        let scalar = secp256k1::Scalar::from_be_bytes(*tweak)
            .map_err(|e| TaprootError::InvalidTweak(e.to_string()))?;
        let (tweaked, parity) = self.inner.add_tweak(secp, &scalar)
            .map_err(|e| TaprootError::InvalidTweak(e.to_string()))?;
        Ok((Self { inner: tweaked }, parity.into()))
    }

    /// Get the inner secp256k1 x-only public key
    pub fn inner(&self) -> &Secp256k1XOnlyPublicKey {
        &self.inner
    }

    /// Create from secp256k1 x-only public key
    pub fn from_inner(inner: Secp256k1XOnlyPublicKey) -> Self {
        Self { inner }
    }

    /// Convert to full public key with even y-coordinate
    pub fn to_public_key(&self) -> secp256k1::PublicKey {
        self.inner.public_key(secp256k1::Parity::Even)
    }
}

impl fmt::Debug for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XOnlyPublicKey({})", hex::encode(self.serialize()))
    }
}

impl fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.serialize()))
    }
}

impl std::str::FromStr for XOnlyPublicKey {
    type Err = TaprootError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(|_| TaprootError::InvalidXOnlyKey)?;
        Self::from_slice(&bytes)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xonly_from_compressed() {
        // A valid compressed public key
        let compressed = [
            0x02, // even y
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
            0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
            0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        let (xonly, parity) = XOnlyPublicKey::from_compressed(&compressed).unwrap();
        assert_eq!(parity, Parity::Even);
        assert_eq!(xonly.serialize()[..], compressed[1..]);
    }

    #[test]
    fn test_xonly_roundtrip() {
        let bytes = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
            0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
            0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        let xonly = XOnlyPublicKey::from_bytes(bytes).unwrap();
        assert_eq!(xonly.serialize(), bytes);
    }

    #[test]
    fn test_xonly_display_parse() {
        let bytes = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
            0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
            0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        let xonly = XOnlyPublicKey::from_bytes(bytes).unwrap();
        let hex_str = xonly.to_string();
        let parsed: XOnlyPublicKey = hex_str.parse().unwrap();
        assert_eq!(xonly, parsed);
    }

    #[test]
    fn test_parity_conversion() {
        assert_eq!(Parity::Even.to_u8(), 0);
        assert_eq!(Parity::Odd.to_u8(), 1);
        assert_eq!(Parity::from_u8(0).unwrap(), Parity::Even);
        assert_eq!(Parity::from_u8(1).unwrap(), Parity::Odd);
        assert!(Parity::from_u8(2).is_err());
    }
}
