//! # rustywallet-tx
//!
//! Bitcoin transaction building, signing, and serialization.
//!
//! ## Features
//!
//! - Build transactions with multiple inputs and outputs
//! - Automatic coin selection
//! - Fee calculation (vsize-based)
//! - Sign P2PKH, P2WPKH, and P2TR inputs
//! - MuSig2 n-of-n multisignature support
//! - FROST t-of-n threshold signature support
//! - Silent Payment output creation
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
//!
//! ## MuSig2 Signing
//!
//! ```rust,ignore
//! use rustywallet_tx::{create_musig2_session, sign_musig2, finalize_musig2};
//! use rustywallet_musig::{KeyAggContext, SecretNonce};
//!
//! // Create session with aggregated key
//! let session = create_musig2_session(&tx, 0, &prevouts, key_agg)?;
//!
//! // Each signer creates partial signature
//! let partial = sign_musig2(&tx, 0, &prevouts, &session, &mut nonce, &secret_key, idx)?;
//!
//! // Aggregate and finalize
//! finalize_musig2(&mut tx, 0, &partials, &agg_nonce, &key_agg, sighash_type)?;
//! ```
//!
//! ## FROST Threshold Signing
//!
//! ```rust,ignore
//! use rustywallet_tx::{sign_frost, finalize_frost};
//! use rustywallet_frost::prelude::*;
//!
//! // Each signer creates partial signature
//! let share = sign_frost(&tx, 0, &prevouts, &key_package, &mut nonces, &commitments)?;
//!
//! // Aggregate threshold signatures
//! finalize_frost(&mut tx, 0, &commitments, &shares, &public_key_package, sighash_type)?;
//! ```
//!
//! ## Silent Payments
//!
//! ```rust,ignore
//! use rustywallet_tx::create_silent_payment_outputs;
//! use rustywallet_silent::SilentPaymentAddress;
//!
//! // Create outputs for Silent Payment recipients
//! let outputs = create_silent_payment_outputs(
//!     &sender_keys,
//!     &outpoints,
//!     &recipients,
//!     &amounts,
//! )?;
//! ```

pub mod error;
pub mod types;
pub mod fee;
pub mod script;
pub mod coin_selection;
pub mod sighash;
pub mod builder;
pub mod signing;
pub mod rbf;
pub mod taproot;
pub mod musig2;
pub mod frost;
pub mod silent_payment;

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
pub use rbf::{
    is_rbf_enabled, enable_rbf, disable_rbf, 
    create_replacement, bump_fee, RbfBuilder,
    sequence as rbf_sequence,
};
pub use taproot::{
    sign_p2tr_key_path, sign_p2tr_key_path_with_sighash,
    sign_all_p2tr, is_p2tr_script, extract_p2tr_pubkey,
};
pub use musig2::{sign_musig2, finalize_musig2, create_musig2_session};
pub use frost::{sign_frost, finalize_frost, get_frost_sighash};
pub use silent_payment::create_silent_payment_outputs;

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        Transaction, TxInput, TxOutput, Utxo,
        TxBuilder, UnsignedTx,
        TxError, Result,
        sign_p2pkh, sign_p2wpkh, sign_all,
        sign_p2tr_key_path, sign_all_p2tr,
        sign_musig2, finalize_musig2, create_musig2_session,
        sign_frost, finalize_frost, get_frost_sighash,
        create_silent_payment_outputs,
        estimate_fee, calculate_fee, is_dust,
        select_coins,
        is_rbf_enabled, enable_rbf, disable_rbf,
        bump_fee, RbfBuilder,
    };
}
