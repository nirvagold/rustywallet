//! # rustywallet-frost
//!
//! FROST (Flexible Round-Optimized Schnorr Threshold) signatures for Bitcoin.
//!
//! This crate implements threshold Schnorr signatures using the FROST protocol,
//! allowing t-of-n participants to collaboratively sign messages without
//! reconstructing the private key.
//!
//! ## Features
//!
//! - **Distributed Key Generation (DKG)**: Pedersen's verifiable secret sharing
//! - **Threshold Signing**: t-of-n signature creation
//! - **BIP340 Compatible**: Produces standard Schnorr signatures
//! - **Secure**: Nonce reuse prevention, zeroization of secrets
//!
//! ## Example: Distributed Key Generation
//!
//! ```rust
//! use rustywallet_frost::prelude::*;
//!
//! // Create a 2-of-3 threshold setup
//! let threshold = 2;
//! let num_participants = 3;
//!
//! // Create DKG participants
//! let mut p1 = DkgParticipant::new(Identifier::new(1).unwrap(), threshold, num_participants).unwrap();
//! let mut p2 = DkgParticipant::new(Identifier::new(2).unwrap(), threshold, num_participants).unwrap();
//! let mut p3 = DkgParticipant::new(Identifier::new(3).unwrap(), threshold, num_participants).unwrap();
//!
//! // Round 1: Generate commitments
//! let r1_p1 = p1.round1().unwrap();
//! let r1_p2 = p2.round1().unwrap();
//! let r1_p3 = p3.round1().unwrap();
//!
//! // Distribute Round 1 packages
//! for p in [&mut p1, &mut p2, &mut p3] {
//!     p.receive_round1(r1_p1.clone()).unwrap();
//!     p.receive_round1(r1_p2.clone()).unwrap();
//!     p.receive_round1(r1_p3.clone()).unwrap();
//! }
//!
//! // Round 2: Generate shares
//! let r2_p1 = p1.round2().unwrap();
//! let r2_p2 = p2.round2().unwrap();
//! let r2_p3 = p3.round2().unwrap();
//!
//! // Distribute Round 2 packages
//! for pkg in r2_p1.iter().chain(r2_p2.iter()).chain(r2_p3.iter()) {
//!     match pkg.receiver.value() {
//!         1 => p1.receive_round2(pkg.clone()).unwrap(),
//!         2 => p2.receive_round2(pkg.clone()).unwrap(),
//!         3 => p3.receive_round2(pkg.clone()).unwrap(),
//!         _ => unreachable!(),
//!     }
//! }
//!
//! // Finalize DKG
//! let (kp1, pkp) = p1.finalize().unwrap();
//! let (kp2, _) = p2.finalize().unwrap();
//! let (kp3, _) = p3.finalize().unwrap();
//!
//! // All participants have the same group public key
//! assert_eq!(kp1.group_public_key(), kp2.group_public_key());
//! assert_eq!(kp2.group_public_key(), kp3.group_public_key());
//! ```
//!
//! ## Security Considerations
//!
//! - **Nonce Reuse**: Nonces are automatically marked as used after signing
//! - **Secret Zeroization**: All secret values are zeroized on drop
//! - **Share Verification**: DKG includes verifiable secret sharing
//!
//! ## Protocol Overview
//!
//! ### Distributed Key Generation (DKG)
//!
//! 1. Each participant generates a random polynomial
//! 2. Round 1: Broadcast commitments to polynomial coefficients
//! 3. Round 2: Send secret shares to each participant
//! 4. Verify received shares against commitments
//! 5. Compute signing share and group public key
//!
//! ### Signing
//!
//! 1. Each signer generates nonces and broadcasts commitments
//! 2. Compute binding factors and group commitment
//! 3. Each signer creates a partial signature
//! 4. Aggregate partial signatures into final signature

pub mod aggregation;
pub mod dkg;
pub mod error;
pub mod identifier;
pub mod keys;
pub mod nonce;
pub mod polynomial;
pub mod prelude;
pub mod share;
pub mod signing;
pub mod verification;

#[cfg(test)]
mod tests;
