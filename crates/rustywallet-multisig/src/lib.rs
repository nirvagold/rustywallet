//! # rustywallet-multisig
//!
//! Bitcoin multi-signature wallet utilities with Shamir Secret Sharing, MuSig2, and FROST support.
//!
//! ## Features
//!
//! - Create M-of-N multisig wallets (up to 15-of-15)
//! - Generate P2SH, P2WSH, and P2SH-P2WSH addresses
//! - Sign and combine multisig transactions
//! - PSBT integration for hardware wallet interoperability
//! - MuSig2 key aggregation for n-of-n Schnorr multisig
//! - FROST threshold signatures for t-of-n Schnorr multisig
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
//! ## FROST Threshold Multisig
//!
//! ```rust,ignore
//! use rustywallet_multisig::frost::{FrostMultisig, FrostParticipant, FrostSigningRound};
//! use rustywallet_frost::prelude::*;
//!
//! // After DKG, create FrostMultisig
//! let frost_multisig = FrostMultisig::from_dkg(public_key_package);
//!
//! // Start signing round
//! let message = [0xab; 32];
//! let mut round = frost_multisig.start_signing(message);
//!
//! // Each participant generates commitments
//! let mut participant = FrostParticipant::new(key_package);
//! let commitments = participant.generate_nonces().unwrap();
//! round.add_commitment(participant.identifier(), commitments).unwrap();
//!
//! // After collecting threshold commitments, finalize commitment phase
//! round.finalize_commitments().unwrap();
//!
//! // Each participant signs
//! let partial_sig = participant.sign(round.commitments(), &message).unwrap();
//! round.add_partial_sig(partial_sig).unwrap();
//!
//! // Finalize to get the aggregated signature
//! let signature = round.finalize().unwrap();
//! ```
//!
//! ## PSBT Integration
//!
//! ```rust
//! use rustywallet_multisig::{MultisigWallet, MultisigPsbtBuilder, Network};
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! let key1 = PrivateKey::random();
//! let key2 = PrivateKey::random();
//! let pubkeys = vec![
//!     key1.public_key().to_compressed(),
//!     key2.public_key().to_compressed(),
//! ];
//!
//! let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
//! let mut builder = MultisigPsbtBuilder::new(wallet, 1);
//!
//! // Each party signs
//! let sighash = [0u8; 32]; // Compute actual sighash
//! builder.sign_input(0, &sighash, &key1).unwrap();
//! builder.sign_input(0, &sighash, &key2).unwrap();
//!
//! // Build final witness
//! let witness = builder.build_witness(0).unwrap();
//! ```
//!
//! ## MuSig2 Key Aggregation
//!
//! ```rust
//! use rustywallet_multisig::{MuSigKeyAgg, musig_to_p2tr_address, Network};
//! use rustywallet_keys::prelude::PrivateKey;
//!
//! let key1 = PrivateKey::random();
//! let key2 = PrivateKey::random();
//! let pubkeys = vec![
//!     key1.public_key().to_compressed(),
//!     key2.public_key().to_compressed(),
//! ];
//!
//! // Aggregate keys for n-of-n Schnorr multisig
//! let key_agg = MuSigKeyAgg::new(pubkeys).unwrap();
//!
//! // Get P2TR address
//! let address = musig_to_p2tr_address(&key_agg, Network::Mainnet).unwrap();
//! println!("MuSig P2TR address: {}", address);
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

pub mod error;
pub mod config;
pub mod script;
pub mod address;
pub mod signer;
pub mod combiner;
pub mod shamir;
pub mod psbt;
pub mod musig;
pub mod frost;

pub use error::{MultisigError, Result};
pub use config::MultisigConfig;
pub use address::{MultisigWallet, Network, hash160, sha256};
pub use script::{build_multisig_script, parse_multisig_script};
pub use signer::{sign_p2sh_multisig, sign_p2wsh_multisig, PartialSignature};
pub use combiner::{combine_signatures, CombinedSignatures};
pub use shamir::{split_secret, combine_shares, ShamirShare};
pub use psbt::{MultisigPsbtBuilder, PsbtPartialSig};
pub use musig::{MuSigKeyAgg, musig_to_p2tr_address};
pub use frost::{FrostMultisig, FrostSigningRound, FrostParticipant, FrostPsbtBuilder};

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::{
        MultisigConfig, MultisigWallet, Network,
        MultisigError, Result,
        sign_p2sh_multisig, sign_p2wsh_multisig,
        combine_signatures, CombinedSignatures,
        split_secret, combine_shares, ShamirShare,
        MultisigPsbtBuilder, PsbtPartialSig,
        MuSigKeyAgg, musig_to_p2tr_address,
        FrostMultisig, FrostSigningRound, FrostParticipant, FrostPsbtBuilder,
    };
}
