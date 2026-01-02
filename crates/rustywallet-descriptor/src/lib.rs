//! # rustywallet-descriptor
//!
//! Output descriptors (BIP380-386) for Bitcoin wallet development.
//!
//! This crate provides functionality to:
//! - Parse output descriptor strings
//! - Derive addresses from descriptors
//! - Generate script pubkeys
//! - Support ranged descriptors with wildcards
//!
//! ## Supported Descriptors
//!
//! | Type | Description | Example |
//! |------|-------------|---------|
//! | `pk()` | Pay to pubkey | `pk(KEY)` |
//! | `pkh()` | Pay to pubkey hash (P2PKH) | `pkh(KEY)` |
//! | `wpkh()` | Pay to witness pubkey hash (P2WPKH) | `wpkh(KEY)` |
//! | `sh()` | Pay to script hash (P2SH) | `sh(wpkh(KEY))` |
//! | `wsh()` | Pay to witness script hash (P2WSH) | `wsh(multi(2,KEY,KEY))` |
//! | `tr()` | Pay to Taproot (P2TR) | `tr(KEY)` |
//! | `multi()` | k-of-n multisig | `multi(2,KEY,KEY,KEY)` |
//! | `sortedmulti()` | Sorted k-of-n multisig | `sortedmulti(2,KEY,KEY,KEY)` |
//!
//! ## Example
//!
//! ```rust
//! use rustywallet_descriptor::{Descriptor, derive_address};
//! use rustywallet_address::Network;
//!
//! // Parse a descriptor
//! let desc = Descriptor::parse("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)").unwrap();
//!
//! // Derive an address
//! let address = derive_address(&desc, Network::BitcoinMainnet, 0).unwrap();
//! println!("Address: {}", address);
//! ```
//!
//! ## Ranged Descriptors
//!
//! ```rust
//! use rustywallet_descriptor::{Descriptor, derive_addresses};
//! use rustywallet_address::Network;
//!
//! // Parse a ranged descriptor with wildcard
//! let desc = Descriptor::parse(
//!     "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)"
//! ).unwrap();
//!
//! // Derive multiple addresses
//! let addresses = derive_addresses(&desc, Network::BitcoinMainnet, 0, 10).unwrap();
//! for (i, addr) in addresses.iter().enumerate() {
//!     println!("Address {}: {}", i, addr);
//! }
//! ```
//!
//! ## Checksum
//!
//! Descriptors can include a checksum for error detection:
//!
//! ```rust
//! use rustywallet_descriptor::{Descriptor, add_checksum};
//!
//! let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
//! let with_checksum = add_checksum(desc);
//! println!("With checksum: {}", with_checksum);
//!
//! // Parse validates checksum automatically
//! let parsed = Descriptor::parse(&with_checksum).unwrap();
//! ```

pub mod address;
pub mod checksum;
pub mod descriptor;
pub mod error;
pub mod key;
pub mod script;

// Re-exports
pub use address::{derive_address, derive_addresses};
pub use checksum::{add_checksum, compute_checksum, strip_checksum, verify_checksum};
pub use descriptor::Descriptor;
pub use error::DescriptorError;
pub use key::{parse_key, DescriptorKey, KeyOrigin, Wildcard};
pub use script::{generate_script_pubkey, ScriptPubkey, ScriptType};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::address::{derive_address, derive_addresses};
    pub use crate::checksum::add_checksum;
    pub use crate::descriptor::Descriptor;
    pub use crate::error::DescriptorError;
    pub use crate::key::{DescriptorKey, Wildcard};
    pub use crate::script::{ScriptPubkey, ScriptType};
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_address::Network;

    #[test]
    fn test_basic_workflow() {
        // Parse descriptor
        let desc = Descriptor::parse(
            "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        )
        .unwrap();

        // Generate script
        let script = generate_script_pubkey(&desc, 0).unwrap();
        assert_eq!(script.script_type(), ScriptType::P2wpkh);

        // Derive address
        let address = derive_address(&desc, Network::BitcoinMainnet, 0).unwrap();
        assert!(address.starts_with("bc1q"));
    }

    #[test]
    fn test_checksum_workflow() {
        let desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

        // Add checksum
        let with_checksum = add_checksum(desc);
        assert!(with_checksum.contains('#'));

        // Parse with checksum
        let parsed = Descriptor::parse(&with_checksum).unwrap();
        assert_eq!(parsed.descriptor_type(), "pkh");
    }

    #[test]
    fn test_nested_descriptor() {
        let desc = Descriptor::parse(
            "sh(wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))",
        )
        .unwrap();

        assert!(desc.is_segwit());
        assert_eq!(desc.descriptor_type(), "sh");

        let address = derive_address(&desc, Network::BitcoinMainnet, 0).unwrap();
        assert!(address.starts_with('3'));
    }
}
