//! Descriptor-based address derivation.
//!
//! This module provides functionality to derive addresses from output descriptors,
//! supporting all standard descriptor types including Taproot.
//!
//! ## Supported Descriptors
//!
//! | Type | Description | Address Format |
//! |------|-------------|----------------|
//! | `pkh()` | Pay to pubkey hash | P2PKH (1...) |
//! | `wpkh()` | Pay to witness pubkey hash | P2WPKH (bc1q...) |
//! | `sh(wpkh())` | Nested SegWit | P2SH-P2WPKH (3...) |
//! | `tr()` | Pay to Taproot | P2TR (bc1p...) |
//! | `wsh()` | Pay to witness script hash | P2WSH (bc1q...) |
//!
//! ## Example
//!
//! ```rust,ignore
//! use rustywallet_address::{Address, Network};
//! use rustywallet_address::descriptor::AddressFromDescriptor;
//!
//! // Derive address from wpkh descriptor
//! let address = Address::from_descriptor(
//!     "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
//!     0,
//!     Network::BitcoinMainnet,
//! ).unwrap();
//! assert!(address.to_string().starts_with("bc1q"));
//!
//! // Derive from ranged descriptor with wildcard
//! let address = Address::from_descriptor(
//!     "wpkh(xpub.../0/*)",
//!     5,  // index 5
//!     Network::BitcoinMainnet,
//! ).unwrap();
//! ```

use crate::error::AddressError;
use crate::network::Network;
use crate::Address;

/// Trait for deriving addresses from descriptors.
pub trait AddressFromDescriptor {
    /// Derive an address from a descriptor string at a specific index.
    ///
    /// # Arguments
    ///
    /// * `descriptor` - The descriptor string (e.g., "wpkh(KEY)" or "tr(KEY)")
    /// * `index` - The derivation index (used for wildcard descriptors)
    /// * `network` - The target network (mainnet/testnet)
    ///
    /// # Returns
    ///
    /// The derived address or an error if the descriptor is invalid.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustywallet_address::{Address, Network};
    /// use rustywallet_address::descriptor::AddressFromDescriptor;
    ///
    /// let addr = Address::from_descriptor(
    ///     "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
    ///     0,
    ///     Network::BitcoinMainnet,
    /// ).unwrap();
    /// ```
    fn from_descriptor(
        descriptor: &str,
        index: u32,
        network: Network,
    ) -> Result<Self, AddressError>
    where
        Self: Sized;

    /// Derive multiple addresses from a descriptor.
    ///
    /// # Arguments
    ///
    /// * `descriptor` - The descriptor string
    /// * `start` - Starting index
    /// * `count` - Number of addresses to derive
    /// * `network` - The target network
    ///
    /// # Returns
    ///
    /// A vector of derived addresses.
    fn from_descriptor_range(
        descriptor: &str,
        start: u32,
        count: u32,
        network: Network,
    ) -> Result<Vec<Self>, AddressError>
    where
        Self: Sized;
}

impl AddressFromDescriptor for Address {
    fn from_descriptor(
        descriptor: &str,
        index: u32,
        network: Network,
    ) -> Result<Self, AddressError> {
        let address_str = derive_address_from_descriptor(descriptor, index, network)?;
        address_str.parse()
    }

    fn from_descriptor_range(
        descriptor: &str,
        start: u32,
        count: u32,
        network: Network,
    ) -> Result<Vec<Self>, AddressError> {
        let mut addresses = Vec::with_capacity(count as usize);
        for i in start..start + count {
            addresses.push(Self::from_descriptor(descriptor, i, network)?);
        }
        Ok(addresses)
    }
}

/// Derive an address string from a descriptor.
///
/// This is the core function that handles all descriptor types.
pub fn derive_address_from_descriptor(
    descriptor: &str,
    index: u32,
    network: Network,
) -> Result<String, AddressError> {
    // Use rustywallet-descriptor for parsing and derivation
    use rustywallet_descriptor::{derive_address, Descriptor};

    // Parse the descriptor
    let desc = Descriptor::parse(descriptor)
        .map_err(|e| AddressError::InvalidFormat(e.to_string()))?;

    // Derive the address
    derive_address(&desc, network, index)
        .map_err(|e| AddressError::InvalidFormat(e.to_string()))
}

/// Derive multiple addresses from a descriptor.
pub fn derive_addresses_from_descriptor(
    descriptor: &str,
    network: Network,
    start: u32,
    count: u32,
) -> Result<Vec<String>, AddressError> {
    use rustywallet_descriptor::{derive_addresses, Descriptor};

    let desc = Descriptor::parse(descriptor)
        .map_err(|e| AddressError::InvalidFormat(e.to_string()))?;

    derive_addresses(&desc, network, start, count)
        .map_err(|e| AddressError::InvalidFormat(e.to_string()))
}

/// Get the descriptor type from a descriptor string.
pub fn get_descriptor_type(descriptor: &str) -> Result<DescriptorType, AddressError> {
    use rustywallet_descriptor::Descriptor;

    let desc = Descriptor::parse(descriptor)
        .map_err(|e| AddressError::InvalidFormat(e.to_string()))?;

    Ok(match desc.descriptor_type() {
        "pk" => DescriptorType::Pk,
        "pkh" => DescriptorType::Pkh,
        "wpkh" => DescriptorType::Wpkh,
        "sh" => DescriptorType::Sh,
        "wsh" => DescriptorType::Wsh,
        "tr" => DescriptorType::Tr,
        "multi" => DescriptorType::Multi,
        "sortedmulti" => DescriptorType::SortedMulti,
        other => return Err(AddressError::UnsupportedAddressType(other.into())),
    })
}

/// Check if a descriptor has a wildcard (ranged descriptor).
pub fn descriptor_has_wildcard(descriptor: &str) -> Result<bool, AddressError> {
    use rustywallet_descriptor::Descriptor;

    let desc = Descriptor::parse(descriptor)
        .map_err(|e| AddressError::InvalidFormat(e.to_string()))?;

    Ok(desc.has_wildcard())
}

/// Supported descriptor types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorType {
    /// pk(KEY) - Pay to pubkey (bare)
    Pk,
    /// pkh(KEY) - Pay to pubkey hash (P2PKH)
    Pkh,
    /// wpkh(KEY) - Pay to witness pubkey hash (P2WPKH)
    Wpkh,
    /// sh(SCRIPT) - Pay to script hash (P2SH)
    Sh,
    /// wsh(SCRIPT) - Pay to witness script hash (P2WSH)
    Wsh,
    /// tr(KEY) - Pay to Taproot (P2TR)
    Tr,
    /// multi(k, KEY1, KEY2, ...) - k-of-n multisig
    Multi,
    /// sortedmulti(k, KEY1, KEY2, ...) - sorted k-of-n multisig
    SortedMulti,
}

impl DescriptorType {
    /// Check if this descriptor type produces SegWit addresses.
    pub fn is_segwit(&self) -> bool {
        matches!(self, Self::Wpkh | Self::Wsh | Self::Tr)
    }

    /// Check if this descriptor type produces Taproot addresses.
    pub fn is_taproot(&self) -> bool {
        matches!(self, Self::Tr)
    }

    /// Get the expected address prefix for mainnet.
    pub fn mainnet_prefix(&self) -> &'static str {
        match self {
            Self::Pk | Self::Pkh => "1",
            Self::Wpkh | Self::Wsh => "bc1q",
            Self::Sh => "3",
            Self::Tr => "bc1p",
            Self::Multi | Self::SortedMulti => "3", // Usually wrapped in sh()
        }
    }

    /// Get the expected address prefix for testnet.
    pub fn testnet_prefix(&self) -> &'static str {
        match self {
            Self::Pk | Self::Pkh => "m",
            Self::Wpkh | Self::Wsh => "tb1q",
            Self::Sh => "2",
            Self::Tr => "tb1p",
            Self::Multi | Self::SortedMulti => "2",
        }
    }
}

impl std::fmt::Display for DescriptorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pk => write!(f, "pk"),
            Self::Pkh => write!(f, "pkh"),
            Self::Wpkh => write!(f, "wpkh"),
            Self::Sh => write!(f, "sh"),
            Self::Wsh => write!(f, "wsh"),
            Self::Tr => write!(f, "tr"),
            Self::Multi => write!(f, "multi"),
            Self::SortedMulti => write!(f, "sortedmulti"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBKEY: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    #[test]
    fn test_derive_pkh_address() {
        let desc = format!("pkh({})", TEST_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.starts_with('1'));
    }

    #[test]
    fn test_derive_wpkh_address() {
        let desc = format!("wpkh({})", TEST_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.starts_with("bc1q"));
    }

    #[test]
    fn test_derive_tr_address() {
        let desc = format!("tr({})", TEST_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.starts_with("bc1p"));
    }

    #[test]
    fn test_derive_sh_wpkh_address() {
        let desc = format!("sh(wpkh({}))", TEST_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.starts_with('3'));
    }

    #[test]
    fn test_address_from_descriptor_trait() {
        let desc = format!("wpkh({})", TEST_PUBKEY);
        let addr = Address::from_descriptor(&desc, 0, Network::BitcoinMainnet).unwrap();
        assert!(addr.is_bitcoin());
    }

    #[test]
    fn test_address_from_descriptor_range() {
        let desc = format!("wpkh({})", TEST_PUBKEY);
        let addrs = Address::from_descriptor_range(&desc, 0, 3, Network::BitcoinMainnet).unwrap();
        assert_eq!(addrs.len(), 3);
        // Without wildcard, all addresses should be the same
        assert_eq!(addrs[0].to_string(), addrs[1].to_string());
    }

    #[test]
    fn test_get_descriptor_type() {
        assert_eq!(
            get_descriptor_type(&format!("pkh({})", TEST_PUBKEY)).unwrap(),
            DescriptorType::Pkh
        );
        assert_eq!(
            get_descriptor_type(&format!("wpkh({})", TEST_PUBKEY)).unwrap(),
            DescriptorType::Wpkh
        );
        assert_eq!(
            get_descriptor_type(&format!("tr({})", TEST_PUBKEY)).unwrap(),
            DescriptorType::Tr
        );
    }

    #[test]
    fn test_descriptor_type_properties() {
        assert!(!DescriptorType::Pkh.is_segwit());
        assert!(DescriptorType::Wpkh.is_segwit());
        assert!(DescriptorType::Tr.is_segwit());
        assert!(DescriptorType::Tr.is_taproot());
        assert!(!DescriptorType::Wpkh.is_taproot());
    }

    #[test]
    fn test_testnet_addresses() {
        let desc = format!("wpkh({})", TEST_PUBKEY);
        let addr = derive_address_from_descriptor(&desc, 0, Network::BitcoinTestnet).unwrap();
        assert!(addr.starts_with("tb1q"));
    }

    #[test]
    fn test_invalid_descriptor() {
        let result = derive_address_from_descriptor("invalid()", 0, Network::BitcoinMainnet);
        assert!(result.is_err());
    }
}
