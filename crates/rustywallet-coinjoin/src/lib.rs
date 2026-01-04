//! # rustywallet-coinjoin
//!
//! CoinJoin and PayJoin (BIP78) utilities for rustywallet.
//!
//! This crate provides tools for building privacy-enhancing Bitcoin transactions:
//!
//! - **PayJoin (BIP78)**: Receiver contributes inputs to break common-input-ownership heuristic
//! - **CoinJoin**: Multiple users combine transactions with equal outputs
//! - **Output Mixing**: Shuffle and equalize outputs for privacy
//! - **Coordinator-less Protocol**: P2P CoinJoin without central coordinator
//!
//! ## Quick Start
//!
//! ### PayJoin (BIP78)
//!
//! ```rust
//! use rustywallet_coinjoin::prelude::*;
//!
//! // Receiver creates PayJoin request
//! let mut receiver = PayJoinReceiver::new(vec![0x00, 0x14], 100_000);
//! receiver.add_utxo(InputRef::from_outpoint([1u8; 32], 0, 50_000));
//!
//! let request = receiver.create_request("cHNidP8...").unwrap();
//! println!("Receiver inputs: {}", request.receiver_inputs.len());
//! ```
//!
//! ### CoinJoin Transaction
//!
//! ```rust
//! use rustywallet_coinjoin::prelude::*;
//!
//! let mut builder = CoinJoinBuilder::new();
//!
//! // Add participants
//! builder.add_participant_simple(
//!     "alice",
//!     vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
//!     vec![0x00, 0x14, 0x01],
//! );
//! builder.add_participant_simple(
//!     "bob",
//!     vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
//!     vec![0x00, 0x14, 0x02],
//! );
//!
//! builder.set_output_amount(50_000);
//! let tx = builder.build().unwrap();
//!
//! assert!(tx.verify_equal_outputs());
//! ```
//!
//! ### Coordinator-less Session
//!
//! ```rust
//! use rustywallet_coinjoin::prelude::*;
//!
//! // Create session
//! let mut session = CoinJoinSession::new(50_000);
//!
//! // Participants join
//! let alice = Participant::new(
//!     "alice",
//!     vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
//!     vec![0x00, 0x14],
//! );
//! session.join(alice).unwrap();
//!
//! let bob = Participant::new(
//!     "bob",
//!     vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
//!     vec![0x00, 0x14],
//! );
//! session.join(bob).unwrap();
//!
//! // Build transaction
//! let tx = session.build_transaction().unwrap();
//! ```
//!
//! ## Privacy Considerations
//!
//! - Use equal output amounts to maximize anonymity set
//! - Shuffle inputs and outputs to hide ownership
//! - Avoid unique change amounts that can be linked
//! - Use standard denominations when possible
//!
//! ## Security
//!
//! - Verify all inputs before signing
//! - Check fee calculations
//! - Validate output amounts match expectations
//! - Use commitments to prevent manipulation

pub mod builder;
pub mod coordinator;
pub mod error;
pub mod mixer;
pub mod payjoin;
pub mod prelude;
pub mod psbt_builder;
pub mod psbt_payjoin;
pub mod types;

pub use builder::{CoinJoinBuilder, CoinJoinTransaction};
pub use coordinator::{CoinJoinSession, JoinResponse, SessionAnnouncement, SessionState};
pub use error::{CoinJoinError, Result};
pub use mixer::{analyze_privacy, find_best_denomination, OutputMixer, PrivacyAnalysis};
pub use payjoin::{PayJoinProposal, PayJoinReceiver, PayJoinRequest, PayJoinSender};
pub use psbt_builder::{combine_participant_psbts, finalize_coinjoin_psbt, PsbtCoinJoinBuilder};
pub use psbt_payjoin::PsbtPayJoin;
pub use types::{FeeStrategy, InputRef, OutputDef, Participant};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_coinjoin_workflow() {
        // Create CoinJoin with 3 participants
        let mut builder = CoinJoinBuilder::new();

        builder.add_participant_simple(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x01],
        );
        builder.add_participant_simple(
            "bob",
            vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x02],
        );
        builder.add_participant_simple(
            "carol",
            vec![InputRef::from_outpoint([3u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x03],
        );

        builder.set_output_amount(50_000);
        builder.set_fee_rate(1.0);

        let tx = builder.build().unwrap();

        // Verify
        assert_eq!(tx.participant_count, 3);
        assert_eq!(tx.inputs.len(), 3);
        assert_eq!(tx.outputs.len(), 3);
        assert!(tx.verify_equal_outputs());
        assert_eq!(tx.output_amount, 50_000);

        // Analyze privacy
        let analysis = analyze_privacy(&tx.outputs);
        assert_eq!(analysis.anonymity_set, 3);
        assert!(!analysis.has_change);
    }

    #[test]
    fn test_payjoin_workflow() {
        // Receiver setup
        let mut receiver = PayJoinReceiver::new(vec![0x00, 0x14], 100_000);
        receiver.add_utxo(InputRef::from_outpoint([1u8; 32], 0, 50_000));

        // Create request
        let request = receiver.create_request("cHNidP8...").unwrap();
        assert_eq!(request.receiver_inputs.len(), 1);

        // Sender processes
        let mut sender = PayJoinSender::new();
        sender.add_utxo(InputRef::from_outpoint([2u8; 32], 0, 150_000));

        let proposal = sender.process_request(&request).unwrap();
        assert_eq!(proposal.input_count(), 2);
    }

    #[test]
    fn test_session_workflow() {
        let mut session = CoinJoinSession::new(50_000);

        // Join participants
        let alice = Participant::new(
            "alice",
            vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x01],
        );
        let bob = Participant::new(
            "bob",
            vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
            vec![0x00, 0x14, 0x02],
        );

        session.join(alice).unwrap();
        let response = session.join(bob).unwrap();
        assert!(response.ready);

        // Build
        let tx = session.build_transaction().unwrap();
        assert_eq!(tx.participant_count, 2);

        // Sign
        session.submit_signature("alice", vec![1, 2, 3]).unwrap();
        session.submit_signature("bob", vec![4, 5, 6]).unwrap();

        assert!(session.is_complete());
    }

    #[test]
    fn test_denominations() {
        // Find best denomination
        let denom = find_best_denomination(150_000, 1000);
        assert_eq!(denom, Some(100_000));

        // Split into denominations
        let splits = mixer::split_into_denominations(350_000, 1000);
        let total: u64 = splits.iter().sum();
        assert!(total <= 350_000);
    }

    #[test]
    fn test_output_mixing() {
        let mut mixer = OutputMixer::new();

        for i in 0..5 {
            mixer.add_output(OutputDef::new(50_000, vec![i]));
        }

        // Verify equal
        let amount = mixer.verify_equal().unwrap();
        assert_eq!(amount, 50_000);

        // Shuffle
        mixer.set_seed([42u8; 32]);
        let shuffled = mixer.shuffle();
        assert_eq!(shuffled.len(), 5);
    }
}
