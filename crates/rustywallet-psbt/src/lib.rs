//! # rustywallet-psbt
//!
//! PSBT (Partially Signed Bitcoin Transaction) implementation for Bitcoin wallet development.
//!
//! This crate implements BIP174 (PSBT v0) and BIP370 (PSBT v2) for hardware wallet
//! interoperability and multi-party signing workflows.
//!
//! ## Features
//!
//! - Parse and create PSBTs
//! - Sign PSBTs with private keys
//! - Combine PSBTs from multiple signers
//! - Finalize PSBTs and extract signed transactions
//! - Support for P2PKH, P2WPKH, P2SH, P2WSH, and P2TR inputs
//! - PSBT v2 (BIP370) support
//!
//! ## Example
//!
//! ```rust,no_run
//! use rustywallet_psbt::{Psbt, PsbtError};
//!
//! // Parse PSBT from base64
//! let psbt_base64 = "cHNidP8BAH...";
//! let mut psbt = Psbt::from_base64(psbt_base64)?;
//!
//! // Sign with private key
//! // let signed = psbt.sign(&private_key)?;
//!
//! // Finalize
//! psbt.finalize()?;
//!
//! // Extract signed transaction
//! let tx = psbt.extract_tx()?;
//! # Ok::<(), PsbtError>(())
//! ```
//!
//! ## BIP174 Roles
//!
//! This crate implements all BIP174 roles:
//!
//! - **Creator**: Create PSBT from unsigned transaction
//! - **Updater**: Add UTXO info, scripts, derivation paths
//! - **Signer**: Add partial signatures
//! - **Combiner**: Merge PSBTs from multiple signers
//! - **Finalizer**: Construct final scriptSig/witness
//! - **Extractor**: Extract signed transaction

pub mod error;
pub mod global;
pub mod input;
pub mod output;
pub mod psbt;
pub mod serialize;
pub mod threshold;
pub mod types;

mod combiner;
mod finalizer;
mod signer;

// Re-exports
pub use error::PsbtError;
pub use global::GlobalMap;
pub use input::{InputMap, TxOut, Witness};
pub use output::OutputMap;
pub use psbt::Psbt;
pub use types::{KeySource, PsbtSighashType};

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::error::PsbtError;
    pub use crate::global::GlobalMap;
    pub use crate::input::{InputMap, TxOut, Witness};
    pub use crate::output::OutputMap;
    pub use crate::psbt::Psbt;
    pub use crate::types::{KeySource, PsbtSighashType};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_magic() {
        let magic = types::PSBT_MAGIC;
        assert_eq!(magic, [0x70, 0x73, 0x62, 0x74, 0xff]);
        assert_eq!(&magic[0..4], b"psbt");
    }

    #[test]
    fn test_create_psbt() {
        // Minimal unsigned transaction
        let tx = vec![
            0x02, 0x00, 0x00, 0x00, // version
            0x00, // no inputs
            0x00, // no outputs
            0x00, 0x00, 0x00, 0x00, // locktime
        ];

        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        assert_eq!(psbt.version(), 0);
        assert_eq!(psbt.input_count(), 0);
        assert_eq!(psbt.output_count(), 0);
    }

    #[test]
    fn test_psbt_serialization() {
        let tx = vec![
            0x02, 0x00, 0x00, 0x00, // version
            0x00, // no inputs
            0x00, // no outputs
            0x00, 0x00, 0x00, 0x00, // locktime
        ];

        let psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let bytes = psbt.to_bytes();

        // Check magic
        assert_eq!(&bytes[0..5], &types::PSBT_MAGIC);

        // Roundtrip
        let parsed = Psbt::from_bytes(&bytes).unwrap();
        assert_eq!(psbt.to_bytes(), parsed.to_bytes());
    }
}
