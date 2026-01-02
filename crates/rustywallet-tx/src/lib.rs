//! # rustywallet-tx
//!
//! Bitcoin transaction building, signing, and serialization.
//!
//! ## Features
//!
//! - Build transactions with multiple inputs and outputs
//! - Automatic coin selection
//! - Fee calculation (vsize-based)
//! - Sign P2PKH and P2WPKH inputs
//! - Serialize transactions for broadcasting
//!
//! ## Quick Start
//!
//! ```rust
//! use rustywallet_tx::prelude::*;
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! // Create a UTXO
//! let utxo = Utxo {
//!     txid: [0u8; 32],
//!     vout: 0,
//!     value: 100_000,
//!     script_pubkey: vec![0x00, 0x14, /* ... 20 bytes ... */],
//!     address: "bc1q...".to_string(),
//! };
//!
//! // Build transaction
//! let unsigned = TxBuilder::new()
//!     .add_input(utxo)
//!     .add_output(50_000, vec![/* scriptPubKey */])
//!     .set_fee_rate(10) // 10 sat/vB
//!     .build()
//!     .unwrap();
//!
//! println!("Fee: {} sats", unsigned.fee());
//! ```
//!
//! ## Signing
//!
//! ```rust,ignore
//! use rustywallet_tx::{sign_p2wpkh, Transaction};
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! let private_key = PrivateKey::random();
//! let mut tx = unsigned.tx;
//!
//! // Sign P2WPKH input
//! sign_p2wpkh(&mut tx, 0, 100_000, &private_key).unwrap();
//!
//! // Serialize for broadcast
//! let hex = tx.to_hex();
//! ```

pub mod error;
pub mod types;
pub mod fee;
pub mod script;
pub mod coin_selection;
pub mod sighash;
pub mod builder;
pub mod signing;

pub use error::{TxError, Result};
pub use types::{Transaction, TxInput, TxOutput, Utxo};
pub use fee::{estimate_vsize, calculate_fee, estimate_fee, is_dust};
pub use script::{
    build_p2pkh_script, build_p2wpkh_script, build_p2tr_script,
    hash160, is_p2pkh, is_p2wpkh, is_p2tr,
};
pub use coin_selection::select_coins;
pub use sighash::{sighash_legacy, sighash_segwit, sighash_type};
pub use builder::{TxBuilder, UnsignedTx, InputInfo};
pub use signing::{sign_p2pkh, sign_p2wpkh, sign_all};

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        Transaction, TxInput, TxOutput, Utxo,
        TxBuilder, UnsignedTx,
        TxError, Result,
        sign_p2pkh, sign_p2wpkh, sign_all,
        estimate_fee, calculate_fee, is_dust,
        select_coins,
    };
}
