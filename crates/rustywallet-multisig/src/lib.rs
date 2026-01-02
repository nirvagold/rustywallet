//! # rustywallet-multisig
//!
//! Bitcoin multi-signature wallet utilities with Shamir Secret Sharing.
//!
//! ## Features
//!
//! - Create M-of-N multisig wallets (up to 15-of-15)
//! - Generate P2SH, P2WSH, and P2SH-P2WSH addresses
//! - Sign and combine multisig transactions
//! - Shamir Secret Sharing for key backup
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_multisig::prelude::*;
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! // Generate 3 keys
//! let key1 = PrivateKey::random();
//! let key2 = PrivateKey::random();
//! let key3 = PrivateKey::random();
//!
//! let pubkeys = vec![
//!     key1.public_key().to_compressed(),
//!     key2.public_key().to_compressed(),
//!     key3.public_key().to_compressed(),
//! ];
//!
//! // Create 2-of-3 multisig wallet
//! let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
//!
//! println!("P2SH address: {}", wallet.address_p2sh);
//! println!("P2WSH address: {}", wallet.address_p2wsh);
//! println!("P2SH-P2WSH address: {}", wallet.address_p2sh_p2wsh);
//! ```
//!
//! ## Shamir Secret Sharing
//!
//! ```rust
//! use rustywallet_multisig::{split_secret, combine_shares};
//!
//! // Split a 32-byte secret into 5 shares, requiring 3 to recover
//! let secret = [0x42u8; 32];
//! let shares = split_secret(&secret, 3, 5).unwrap();
//!
//! // Recover with any 3 shares
//! let recovered = combine_shares(&shares[0..3]).unwrap();
//! assert_eq!(recovered, secret);
//! ```
//!
//! ## Signing Multisig Transactions
//!
//! ```rust,ignore
//! use rustywallet_multisig::{sign_p2sh_multisig, combine_signatures};
//!
//! // Each party signs with their key
//! let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet).unwrap();
//! let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet).unwrap();
//!
//! // Combine signatures
//! let combined = combine_signatures(&[sig1, sig2], &wallet).unwrap();
//!
//! // Build scriptSig for P2SH
//! let script_sig = combined.build_script_sig();
//!
//! // Or build witness for P2WSH
//! let witness = combined.build_witness();
//! ```

pub mod error;
pub mod config;
pub mod script;
pub mod address;
pub mod signer;
pub mod combiner;
pub mod shamir;

pub use error::{MultisigError, Result};
pub use config::MultisigConfig;
pub use address::{MultisigWallet, Network, hash160, sha256};
pub use script::{build_multisig_script, parse_multisig_script};
pub use signer::{sign_p2sh_multisig, sign_p2wsh_multisig, PartialSignature};
pub use combiner::{combine_signatures, CombinedSignatures};
pub use shamir::{split_secret, combine_shares, ShamirShare};

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        MultisigConfig, MultisigWallet, Network,
        MultisigError, Result,
        sign_p2sh_multisig, sign_p2wsh_multisig,
        combine_signatures, CombinedSignatures,
        split_secret, combine_shares, ShamirShare,
    };
}
