//! PSBT integration for multisig wallets
//!
//! Provides utilities to create, sign, and finalize PSBTs for multisig transactions.

use crate::address::MultisigWallet;
use crate::error::{MultisigError, Result};
use crate::signer::PartialSignature;
use rustywallet_keys::prelude::PrivateKey;
use secp256k1::{Secp256k1, Message, SecretKey};

/// PSBT partial signature with pubkey
#[derive(Debug, Clone)]
pub struct PsbtPartialSig {
    /// Public key (33 bytes compressed)
    pub pubkey: [u8; 33],
    /// DER-encoded signature (without sighash byte for PSBT)
    pub signature: Vec<u8>,
}

/// Multisig PSBT builder
#[derive(Debug, Clone)]
pub struct MultisigPsbtBuilder {
    /// The multisig wallet configuration
    pub wallet: MultisigWallet,
    /// Collected partial signatures per input
    pub input_signatures: Vec<Vec<PsbtPartialSig>>,
    /// Witness UTXOs (value, scriptPubKey) per input
    pub witness_utxos: Vec<Option<(u64, Vec<u8>)>>,
    /// Non-witness UTXOs (full prev tx) per input
    pub non_witness_utxos: Vec<Option<Vec<u8>>>,
}

impl MultisigPsbtBuilder {
    /// Create a new PSBT builder for a multisig wallet
    pub fn new(wallet: MultisigWallet, input_count: usize) -> Self {
        Self {
            wallet,
            input_signatures: vec![Vec::new(); input_count],
            witness_utxos: vec![None; input_count],
            non_witness_utxos: vec![None; input_count],
        }
    }

    /// Set witness UTXO for an input
    pub fn set_witness_utxo(&mut self, input_index: usize, value: u64, script_pubkey: Vec<u8>) -> Result<()> {
        if input_index >= self.witness_utxos.len() {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: "Input index out of bounds".to_string(),
            });
        }
        self.witness_utxos[input_index] = Some((value, script_pubkey));
        Ok(())
    }

    /// Set non-witness UTXO for an input
    pub fn set_non_witness_utxo(&mut self, input_index: usize, prev_tx: Vec<u8>) -> Result<()> {
        if input_index >= self.non_witness_utxos.len() {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: "Input index out of bounds".to_string(),
            });
        }
        self.non_witness_utxos[input_index] = Some(prev_tx);
        Ok(())
    }

    /// Add a partial signature for an input
    pub fn add_signature(&mut self, input_index: usize, sig: PsbtPartialSig) -> Result<()> {
        if input_index >= self.input_signatures.len() {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: "Input index out of bounds".to_string(),
            });
        }

        // Verify pubkey is in the multisig
        if !self.wallet.config.contains_key(&sig.pubkey) {
            return Err(MultisigError::InvalidPublicKey(
                "Public key not in multisig".to_string(),
            ));
        }

        // Check for duplicate
        if self.input_signatures[input_index]
            .iter()
            .any(|s| s.pubkey == sig.pubkey)
        {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: "Duplicate signature for this pubkey".to_string(),
            });
        }

        self.input_signatures[input_index].push(sig);
        Ok(())
    }

    /// Sign an input with a private key
    pub fn sign_input(
        &mut self,
        input_index: usize,
        sighash: &[u8; 32],
        private_key: &PrivateKey,
    ) -> Result<()> {
        let pubkey = private_key.public_key().to_compressed();

        // Verify key is in multisig
        if !self.wallet.config.contains_key(&pubkey) {
            return Err(MultisigError::InvalidPublicKey(
                "Private key not in multisig".to_string(),
            ));
        }

        // Sign
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&private_key.to_bytes())
            .map_err(|e| MultisigError::SigningFailed(e.to_string()))?;
        let message = Message::from_digest(*sighash);
        let signature = secp.sign_ecdsa(&message, &secret_key);

        // DER encode (without sighash byte for PSBT format)
        let sig_bytes = signature.serialize_der().to_vec();

        self.add_signature(input_index, PsbtPartialSig {
            pubkey,
            signature: sig_bytes,
        })
    }

    /// Check if an input has enough signatures
    pub fn input_is_complete(&self, input_index: usize) -> bool {
        if input_index >= self.input_signatures.len() {
            return false;
        }
        self.input_signatures[input_index].len() >= self.wallet.config.threshold() as usize
    }

    /// Check if all inputs have enough signatures
    pub fn is_complete(&self) -> bool {
        (0..self.input_signatures.len()).all(|i| self.input_is_complete(i))
    }

    /// Get signature count for an input
    pub fn signature_count(&self, input_index: usize) -> usize {
        self.input_signatures
            .get(input_index)
            .map(|sigs| sigs.len())
            .unwrap_or(0)
    }

    /// Get the redeem script (for P2SH)
    pub fn redeem_script(&self) -> &[u8] {
        &self.wallet.redeem_script
    }

    /// Get the witness script (for P2WSH)
    pub fn witness_script(&self) -> &[u8] {
        &self.wallet.redeem_script
    }

    /// Build final witness for a P2WSH input
    pub fn build_witness(&self, input_index: usize) -> Result<Vec<Vec<u8>>> {
        if !self.input_is_complete(input_index) {
            return Err(MultisigError::NotEnoughSignatures {
                need: self.wallet.config.threshold() as usize,
                got: self.signature_count(input_index),
            });
        }

        let mut witness = Vec::new();

        // Empty element (CHECKMULTISIG bug)
        witness.push(Vec::new());

        // Sort signatures by key index and add with sighash byte
        let mut sigs: Vec<_> = self.input_signatures[input_index]
            .iter()
            .filter_map(|sig| {
                self.wallet.config.key_index(&sig.pubkey).map(|idx| (idx, sig))
            })
            .collect();
        sigs.sort_by_key(|(idx, _)| *idx);

        for (_, sig) in sigs.iter().take(self.wallet.config.threshold() as usize) {
            let mut sig_with_sighash = sig.signature.clone();
            sig_with_sighash.push(0x01); // SIGHASH_ALL
            witness.push(sig_with_sighash);
        }

        // Witness script
        witness.push(self.wallet.redeem_script.clone());

        Ok(witness)
    }

    /// Build final scriptSig for a P2SH input
    pub fn build_script_sig(&self, input_index: usize) -> Result<Vec<u8>> {
        if !self.input_is_complete(input_index) {
            return Err(MultisigError::NotEnoughSignatures {
                need: self.wallet.config.threshold() as usize,
                got: self.signature_count(input_index),
            });
        }

        let mut script_sig = Vec::new();

        // OP_0 (CHECKMULTISIG bug)
        script_sig.push(0x00);

        // Sort signatures by key index
        let mut sigs: Vec<_> = self.input_signatures[input_index]
            .iter()
            .filter_map(|sig| {
                self.wallet.config.key_index(&sig.pubkey).map(|idx| (idx, sig))
            })
            .collect();
        sigs.sort_by_key(|(idx, _)| *idx);

        for (_, sig) in sigs.iter().take(self.wallet.config.threshold() as usize) {
            let mut sig_with_sighash = sig.signature.clone();
            sig_with_sighash.push(0x01); // SIGHASH_ALL
            push_data(&mut script_sig, &sig_with_sighash);
        }

        // Redeem script
        push_data(&mut script_sig, &self.wallet.redeem_script);

        Ok(script_sig)
    }
}

/// Convert PartialSignature to PsbtPartialSig
impl From<PartialSignature> for PsbtPartialSig {
    fn from(sig: PartialSignature) -> Self {
        // Remove sighash byte if present
        let signature = if sig.signature.last() == Some(&0x01) {
            sig.signature[..sig.signature.len() - 1].to_vec()
        } else {
            sig.signature
        };

        Self {
            pubkey: sig.pubkey,
            signature,
        }
    }
}

/// Push data with length prefix
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 76 {
        script.push(len as u8);
    } else if len <= 255 {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
    } else if len <= 65535 {
        script.push(0x4d); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        script.push(0x4e); // OP_PUSHDATA4
        script.extend_from_slice(&(len as u32).to_le_bytes());
    }
    script.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;

    fn create_test_wallet() -> (MultisigWallet, PrivateKey, PrivateKey, PrivateKey) {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let key3 = PrivateKey::random();

        let pubkeys = vec![
            key1.public_key().to_compressed(),
            key2.public_key().to_compressed(),
            key3.public_key().to_compressed(),
        ];

        let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
        (wallet, key1, key2, key3)
    }

    #[test]
    fn test_psbt_builder_creation() {
        let (wallet, _, _, _) = create_test_wallet();
        let builder = MultisigPsbtBuilder::new(wallet, 2);

        assert_eq!(builder.input_signatures.len(), 2);
        assert!(!builder.is_complete());
    }

    #[test]
    fn test_sign_input() {
        let (wallet, key1, key2, _) = create_test_wallet();
        let mut builder = MultisigPsbtBuilder::new(wallet, 1);
        let sighash = [0xab; 32];

        // Sign with key1
        builder.sign_input(0, &sighash, &key1).unwrap();
        assert_eq!(builder.signature_count(0), 1);
        assert!(!builder.input_is_complete(0));

        // Sign with key2
        builder.sign_input(0, &sighash, &key2).unwrap();
        assert_eq!(builder.signature_count(0), 2);
        assert!(builder.input_is_complete(0));
    }

    #[test]
    fn test_build_witness() {
        let (wallet, key1, key2, _) = create_test_wallet();
        let mut builder = MultisigPsbtBuilder::new(wallet, 1);
        let sighash = [0xcd; 32];

        builder.sign_input(0, &sighash, &key1).unwrap();
        builder.sign_input(0, &sighash, &key2).unwrap();

        let witness = builder.build_witness(0).unwrap();
        // Empty + 2 sigs + witness script = 4 items
        assert_eq!(witness.len(), 4);
        assert!(witness[0].is_empty());
    }

    #[test]
    fn test_build_script_sig() {
        let (wallet, key1, key2, _) = create_test_wallet();
        let mut builder = MultisigPsbtBuilder::new(wallet, 1);
        let sighash = [0xef; 32];

        builder.sign_input(0, &sighash, &key1).unwrap();
        builder.sign_input(0, &sighash, &key2).unwrap();

        let script_sig = builder.build_script_sig(0).unwrap();
        assert_eq!(script_sig[0], 0x00); // OP_0
    }

    #[test]
    fn test_duplicate_signature_rejected() {
        let (wallet, key1, _, _) = create_test_wallet();
        let mut builder = MultisigPsbtBuilder::new(wallet, 1);
        let sighash = [0x11; 32];

        builder.sign_input(0, &sighash, &key1).unwrap();
        let result = builder.sign_input(0, &sighash, &key1);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (wallet, _, _, _) = create_test_wallet();
        let mut builder = MultisigPsbtBuilder::new(wallet, 1);
        let wrong_key = PrivateKey::random();
        let sighash = [0x22; 32];

        let result = builder.sign_input(0, &sighash, &wrong_key);
        assert!(result.is_err());
    }
}
