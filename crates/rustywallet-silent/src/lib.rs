//! # rustywallet-silent
//!
//! Silent Payments (BIP352) implementation for rustywallet.
//!
//! Silent Payments allow receivers to publish a static address that senders
//! can use to derive unique output addresses, providing privacy without
//! requiring interaction between sender and receiver.
//!
//! ## Features
//!
//! - **Address Generation**: Create Silent Payment addresses with scan and spend keys
//! - **Sending**: Derive unique output addresses for recipients
//! - **Scanning**: Detect incoming payments using scan key
//! - **Labels**: Support multiple addresses from a single Silent Payment address
//! - **Change Handling**: Generate deterministic change outputs
//!
//! ## Quick Start
//!
//! ### Creating a Silent Payment Address
//!
//! ```rust
//! use rustywallet_silent::prelude::*;
//! use rustywallet_keys::private_key::PrivateKey;
//!
//! // Generate keys
//! let scan_key = PrivateKey::random();
//! let spend_key = PrivateKey::random();
//!
//! // Create address
//! let address = SilentPaymentAddress::new(
//!     &scan_key.public_key(),
//!     &spend_key.public_key(),
//!     Network::Mainnet,
//! ).unwrap();
//!
//! println!("Address: {}", address);
//! ```
//!
//! ### Sending a Payment
//!
//! ```rust
//! use rustywallet_silent::prelude::*;
//! use rustywallet_keys::private_key::PrivateKey;
//!
//! // Sender's input key
//! let sender_key = PrivateKey::random();
//!
//! // Recipient's address (normally parsed from string)
//! let scan_key = PrivateKey::random();
//! let spend_key = PrivateKey::random();
//! let recipient = SilentPaymentAddress::new(
//!     &scan_key.public_key(),
//!     &spend_key.public_key(),
//!     Network::Mainnet,
//! ).unwrap();
//!
//! // Create outputs
//! let outpoints = vec![([0u8; 32], 0u32)]; // txid, vout
//! let outputs = create_outputs(
//!     &[sender_key.to_bytes()],
//!     &outpoints,
//!     &[recipient],
//! ).unwrap();
//!
//! // Use outputs[0].output_pubkey as the taproot output key
//! ```
//!
//! ### Scanning for Payments
//!
//! ```rust
//! use rustywallet_silent::prelude::*;
//! use rustywallet_keys::private_key::PrivateKey;
//!
//! // Receiver's keys
//! let scan_key = PrivateKey::random();
//! let spend_key = PrivateKey::random();
//!
//! // Create scanner
//! let scanner = SilentPaymentScanner::new(
//!     &scan_key.to_bytes(),
//!     &spend_key.to_bytes(),
//! ).unwrap();
//!
//! // Scan transaction outputs
//! // let detected = scanner.scan(&output_pubkeys, &input_pubkeys, &outpoints).unwrap();
//! ```
//!
//! ## BIP352 Compliance
//!
//! This implementation follows BIP352 specification:
//! - Bech32m encoding with `sp` (mainnet) and `tsp` (testnet) prefixes
//! - ECDH-based shared secret derivation
//! - Tagged hashing for domain separation
//! - Support for labeled addresses
//!
//! ## Security Considerations
//!
//! - Keep scan and spend private keys secure
//! - Scan key can be shared with a light client for detection
//! - Spend key is required to actually spend received funds
//! - Labels provide address separation without additional key material

pub mod address;
pub mod change;
pub mod error;
pub mod label;
pub mod network;
pub mod prelude;
pub mod scanner;
pub mod sender;

pub use address::SilentPaymentAddress;
pub use change::ChangeAddressGenerator;
pub use error::{Result, SilentPaymentError};
pub use label::{Label, LabelManager};
pub use network::Network;
pub use scanner::{DetectedPayment, LightScanner, SilentPaymentScanner};
pub use sender::{create_multiple_outputs, create_outputs, SilentPaymentOutput};

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::private_key::PrivateKey;

    #[test]
    fn test_full_workflow() {
        // === Receiver Setup ===
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let sp_address = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        // Encode and share address
        let encoded = sp_address.encode().unwrap();
        assert!(encoded.starts_with("sp1"));

        // === Sender Creates Payment ===
        let sender_key = PrivateKey::random();
        let sender_pubkey: [u8; 33] = sender_key
            .public_key()
            .to_compressed()
            .try_into()
            .unwrap();

        let outpoints = vec![([1u8; 32], 0u32)];

        // Parse recipient address
        let recipient: SilentPaymentAddress = encoded.parse().unwrap();

        // Create output
        let outputs = create_outputs(
            &[sender_key.to_bytes()],
            &outpoints,
            &[recipient],
        )
        .unwrap();

        assert_eq!(outputs.len(), 1);

        // === Receiver Scans ===
        let scanner = SilentPaymentScanner::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
        )
        .unwrap();

        let detected = scanner
            .scan(&[outputs[0].output_pubkey], &[sender_pubkey], &outpoints)
            .unwrap();

        assert_eq!(detected.len(), 1);

        // Verify spending key
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&detected[0].spending_key).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let (xonly, _) = pk.x_only_public_key();

        assert_eq!(xonly.serialize(), outputs[0].output_pubkey);
    }

    #[test]
    fn test_labeled_payment() {
        // Receiver with labels
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let mut scanner = SilentPaymentScanner::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
        )
        .unwrap();

        // Add labels
        scanner.add_labels(5);

        // Create labeled address
        let label = Label::new(2);
        let labeled_spend = label
            .apply_to_pubkey(
                &spend_key
                    .public_key()
                    .to_compressed()
                    .try_into()
                    .unwrap(),
            )
            .unwrap();

        let labeled_spend_pk = secp256k1::PublicKey::from_slice(&labeled_spend).unwrap();
        let labeled_address = SilentPaymentAddress::from_bytes(
            scan_key
                .public_key()
                .to_compressed()
                .try_into()
                .unwrap(),
            labeled_spend_pk.serialize(),
            Network::Mainnet,
        )
        .unwrap();

        // Sender pays to labeled address
        let sender_key = PrivateKey::random();
        let sender_pubkey: [u8; 33] = sender_key
            .public_key()
            .to_compressed()
            .try_into()
            .unwrap();

        let outpoints = vec![([2u8; 32], 0u32)];

        let outputs = create_outputs(
            &[sender_key.to_bytes()],
            &outpoints,
            &[labeled_address],
        )
        .unwrap();

        // Scan should detect with label
        let detected = scanner
            .scan(&[outputs[0].output_pubkey], &[sender_pubkey], &outpoints)
            .unwrap();

        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].label, Some(2));
    }

    #[test]
    fn test_multiple_outputs() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let recipient = SilentPaymentAddress::new(
            &scan_key.public_key(),
            &spend_key.public_key(),
            Network::Mainnet,
        )
        .unwrap();

        let sender_key = PrivateKey::random();
        let outpoints = vec![([3u8; 32], 0u32)];

        // Create 3 outputs to same recipient
        let outputs = create_multiple_outputs(
            &[sender_key.to_bytes()],
            &outpoints,
            &recipient,
            3,
        )
        .unwrap();

        assert_eq!(outputs.len(), 3);

        // All outputs should be unique
        let mut pubkeys: Vec<_> = outputs.iter().map(|o| o.output_pubkey).collect();
        pubkeys.sort();
        pubkeys.dedup();
        assert_eq!(pubkeys.len(), 3);
    }

    #[test]
    fn test_change_address() {
        let scan_key = PrivateKey::random();
        let spend_key = PrivateKey::random();

        let generator = ChangeAddressGenerator::new(
            &scan_key.to_bytes(),
            &spend_key.to_bytes(),
            Network::Mainnet,
        )
        .unwrap();

        let outpoints = vec![([4u8; 32], 0u32)];

        // Generate change
        let (change_pk, spending_key) = generator.generate_change(&outpoints, 0).unwrap();

        // Verify it's a valid change output
        let result = generator
            .is_change_output(&change_pk, &outpoints, 5)
            .unwrap();

        assert!(result.is_some());
        let (index, recovered_key) = result.unwrap();
        assert_eq!(index, 0);
        assert_eq!(recovered_key, spending_key);
    }
}
