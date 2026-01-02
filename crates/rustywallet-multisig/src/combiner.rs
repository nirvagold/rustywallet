//! Signature combination for multisig transactions.

use crate::address::MultisigWallet;
use crate::error::{MultisigError, Result};
use crate::script::opcodes;
use crate::signer::PartialSignature;

/// Combined signatures ready for transaction.
#[derive(Debug, Clone)]
pub struct CombinedSignatures {
    /// Sorted signatures (by key index)
    pub signatures: Vec<Vec<u8>>,
    /// The redeem/witness script
    pub script: Vec<u8>,
}

impl CombinedSignatures {
    /// Build scriptSig for P2SH multisig.
    ///
    /// Format: `OP_0 <sig1> <sig2> ... <redeemScript>`
    pub fn build_script_sig(&self) -> Vec<u8> {
        let mut script_sig = Vec::new();

        // OP_0 (due to CHECKMULTISIG bug)
        script_sig.push(opcodes::OP_0);

        // Push each signature
        for sig in &self.signatures {
            push_data(&mut script_sig, sig);
        }

        // Push redeem script
        push_data(&mut script_sig, &self.script);

        script_sig
    }

    /// Build witness for P2WSH multisig.
    ///
    /// Format: `<> <sig1> <sig2> ... <witnessScript>`
    pub fn build_witness(&self) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();

        // Empty element (CHECKMULTISIG bug)
        witness.push(Vec::new());

        // Signatures
        for sig in &self.signatures {
            witness.push(sig.clone());
        }

        // Witness script
        witness.push(self.script.clone());

        witness
    }

    /// Build witness for P2SH-P2WSH multisig.
    ///
    /// Returns (scriptSig, witness)
    pub fn build_nested(&self, nested_redeem_script: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        // scriptSig just pushes the nested redeem script
        let mut script_sig = Vec::new();
        push_data(&mut script_sig, nested_redeem_script);

        // Witness is same as P2WSH
        let witness = self.build_witness();

        (script_sig, witness)
    }
}

/// Combine partial signatures into a complete multisig signature set.
///
/// # Arguments
/// * `signatures` - Partial signatures from different signers
/// * `wallet` - The multisig wallet
///
/// # Returns
/// Combined signatures ready for transaction
pub fn combine_signatures(
    signatures: &[PartialSignature],
    wallet: &MultisigWallet,
) -> Result<CombinedSignatures> {
    let threshold = wallet.config.threshold() as usize;

    // Check we have enough signatures
    if signatures.len() < threshold {
        return Err(MultisigError::NotEnoughSignatures {
            need: threshold,
            got: signatures.len(),
        });
    }

    // Verify all signatures are from keys in the multisig
    for sig in signatures {
        if !wallet.config.contains_key(&sig.pubkey) {
            return Err(MultisigError::InvalidSignature {
                index: sig.key_index,
                reason: "Key not in multisig".to_string(),
            });
        }
    }

    // Sort signatures by key index (required for CHECKMULTISIG)
    let mut sorted_sigs: Vec<_> = signatures.iter().collect();
    sorted_sigs.sort_by_key(|s| s.key_index);

    // Take only threshold signatures
    let final_sigs: Vec<Vec<u8>> = sorted_sigs
        .iter()
        .take(threshold)
        .map(|s| s.signature.clone())
        .collect();

    Ok(CombinedSignatures {
        signatures: final_sigs,
        script: wallet.redeem_script.clone(),
    })
}

/// Verify that we have enough valid signatures.
pub fn verify_signature_count(
    signatures: &[PartialSignature],
    wallet: &MultisigWallet,
) -> Result<()> {
    let threshold = wallet.config.threshold() as usize;
    let valid_count = signatures
        .iter()
        .filter(|s| wallet.config.contains_key(&s.pubkey))
        .count();

    if valid_count < threshold {
        return Err(MultisigError::NotEnoughSignatures {
            need: threshold,
            got: valid_count,
        });
    }

    Ok(())
}

/// Push data with appropriate opcode.
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
    use crate::signer::sign_p2sh_multisig;
    use rustywallet_keys::prelude::PrivateKey;

    fn make_pubkey_from_privkey(privkey: &PrivateKey) -> [u8; 33] {
        privkey.public_key().to_compressed()
    }

    #[test]
    fn test_combine_2_of_3() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let key3 = PrivateKey::random();

        let pubkeys = vec![
            make_pubkey_from_privkey(&key1),
            make_pubkey_from_privkey(&key2),
            make_pubkey_from_privkey(&key3),
        ];

        let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
        let sighash = [0xab; 32];

        // Get 2 signatures
        let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet).unwrap();
        let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet).unwrap();

        // Combine
        let combined = combine_signatures(&[sig1, sig2], &wallet).unwrap();
        assert_eq!(combined.signatures.len(), 2);
    }

    #[test]
    fn test_not_enough_signatures() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let key3 = PrivateKey::random();

        let pubkeys = vec![
            make_pubkey_from_privkey(&key1),
            make_pubkey_from_privkey(&key2),
            make_pubkey_from_privkey(&key3),
        ];

        let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
        let sighash = [0xcd; 32];

        // Only 1 signature
        let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet).unwrap();

        let result = combine_signatures(&[sig1], &wallet);
        assert!(matches!(result, Err(MultisigError::NotEnoughSignatures { .. })));
    }

    #[test]
    fn test_build_script_sig() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let pubkeys = vec![
            make_pubkey_from_privkey(&key1),
            make_pubkey_from_privkey(&key2),
        ];

        let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
        let sighash = [0xef; 32];

        let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet).unwrap();
        let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet).unwrap();

        let combined = combine_signatures(&[sig1, sig2], &wallet).unwrap();
        let script_sig = combined.build_script_sig();

        // Should start with OP_0
        assert_eq!(script_sig[0], opcodes::OP_0);
        assert!(!script_sig.is_empty());
    }

    #[test]
    fn test_build_witness() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let pubkeys = vec![
            make_pubkey_from_privkey(&key1),
            make_pubkey_from_privkey(&key2),
        ];

        let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet).unwrap();
        let sighash = [0x11; 32];

        let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet).unwrap();
        let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet).unwrap();

        let combined = combine_signatures(&[sig1, sig2], &wallet).unwrap();
        let witness = combined.build_witness();

        // Empty element + 2 sigs + witness script = 4 items
        assert_eq!(witness.len(), 4);
        assert!(witness[0].is_empty()); // Empty element
    }
}
