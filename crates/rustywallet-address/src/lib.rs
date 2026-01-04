//! # rustywallet-address
//!
//! Cryptocurrency address generation and validation for Bitcoin and Ethereum.
//!
//! This crate provides type-safe APIs for generating and validating addresses
//! from public keys, supporting multiple address formats:
//!
//! - **Bitcoin Legacy (P2PKH)** - Addresses starting with `1` (mainnet) or `m`/`n` (testnet)
//! - **Bitcoin SegWit (P2WPKH)** - Addresses starting with `bc1q` (mainnet) or `tb1q` (testnet)
//! - **Bitcoin Taproot (P2TR)** - Addresses starting with `bc1p` (mainnet) or `tb1p` (testnet)
//! - **Ethereum** - Addresses starting with `0x` with EIP-55 checksum support
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_keys::prelude::PrivateKey;
//! use rustywallet_address::prelude::*;
//!
//! // Generate a random private key
//! let private_key = PrivateKey::random();
//!
//! // Bitcoin addresses
//! let public_key = private_key.public_key();
//!
//! // Legacy P2PKH address
//! let p2pkh = P2PKHAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
//! println!("P2PKH: {}", p2pkh); // 1...
//!
//! // SegWit P2WPKH address
//! let p2wpkh = P2WPKHAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
//! println!("P2WPKH: {}", p2wpkh); // bc1q...
//!
//! // Taproot P2TR address
//! let p2tr = P2TRAddress::from_public_key(&public_key, Network::BitcoinMainnet).unwrap();
//! println!("P2TR: {}", p2tr); // bc1p...
//!
//! // Ethereum address
//! let eth_addr = EthereumAddress::from_public_key(&public_key).unwrap();
//! println!("Ethereum: {}", eth_addr); // 0x...
//! ```
//!
//! ## Descriptor-Based Derivation
//!
//! Derive addresses from output descriptors (BIP380-386):
//!
//! ```rust,ignore
//! use rustywallet_address::{Address, Network};
//! use rustywallet_address::descriptor::AddressFromDescriptor;
//!
//! // Derive from wpkh descriptor
//! let addr = Address::from_descriptor(
//!     "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
//!     0,
//!     Network::BitcoinMainnet,
//! ).unwrap();
//!
//! // Derive from Taproot descriptor
//! let addr = Address::from_descriptor(
//!     "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
//!     0,
//!     Network::BitcoinMainnet,
//! ).unwrap();
//! ```
//!
//! ## Address Validation
//!
//! ```rust
//! use rustywallet_address::prelude::*;
//!
//! // Validate any address
//! let result = Address::validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
//! assert!(result.is_ok());
//!
//! // Validate specific types
//! let result = P2WPKHAddress::validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
//! assert!(result.is_ok());
//!
//! // Validate Ethereum checksum
//! let result = EthereumAddress::validate_checksum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
//! assert!(result.is_ok());
//! ```
//!
//! ## Address Type Detection
//!
//! ```rust
//! use rustywallet_address::prelude::*;
//!
//! let addr: Address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".parse().unwrap();
//! assert!(addr.is_bitcoin());
//!
//! let addr: Address = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".parse().unwrap();
//! assert!(addr.is_ethereum());
//! ```

pub mod address;
pub mod bitcoin;
pub mod descriptor;
pub mod encoding;
pub mod error;
pub mod ethereum;
pub mod network;
pub mod prelude;
pub mod silent_payments;

// Re-export main types at crate root
pub use address::{Address, AddressFormat};
pub use bitcoin::{BitcoinAddress, BitcoinAddressType, P2PKHAddress, P2TRAddress, P2WPKHAddress};
pub use descriptor::{
    AddressFromDescriptor, DescriptorType, derive_address_from_descriptor,
    derive_addresses_from_descriptor, descriptor_has_wildcard, get_descriptor_type,
};
pub use error::AddressError;
pub use ethereum::EthereumAddress;
pub use network::Network;
pub use silent_payments::{SilentPaymentAddress, SilentPaymentDeriver, SilentPaymentLabel};

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_all_bitcoin_address_types() {
        let pk = PrivateKey::random();
        let pubkey = pk.public_key();

        // P2PKH
        let p2pkh = P2PKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
        assert!(p2pkh.to_string().starts_with('1'));

        // P2WPKH
        let p2wpkh = P2WPKHAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
        assert!(p2wpkh.to_string().starts_with("bc1q"));

        // P2TR
        let p2tr = P2TRAddress::from_public_key(&pubkey, Network::BitcoinMainnet).unwrap();
        assert!(p2tr.to_string().starts_with("bc1p"));
    }

    #[test]
    fn test_ethereum_address() {
        let pk = PrivateKey::random();
        let pubkey = pk.public_key();

        let addr = EthereumAddress::from_public_key(&pubkey).unwrap();
        let addr_str = addr.to_checksum_string();
        assert!(addr_str.starts_with("0x"));
        assert_eq!(addr_str.len(), 42);
    }
}
