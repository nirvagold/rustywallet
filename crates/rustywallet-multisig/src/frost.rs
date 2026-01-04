//! FROST threshold multisig integration.
//!
//! Provides a high-level interface for FROST threshold signatures in multisig wallets.
//!
//! ## Example
//!
//! ```rust
//! use rustywallet_multisig::frost::{FrostMultisig, FrostSigningRound};
//! use rustywallet_frost::prelude::*;
//!
//! // After DKG, create FrostMultisig from key packages
//! // let frost_multisig = FrostMultisig::from_dkg(key_packages, public_key_package);
//! ```

use crate::error::{MultisigError, Result};
use rustywallet_frost::prelude::{
    aggregate, sign, CommitmentShare, GroupPublicKey, Identifier, KeyPackage,
    PublicKeyPackage, Signature, SignatureShare, SigningCommitments, SigningNonces,
};

/// FROST threshold multisig wallet.
///
/// Manages threshold signing using the FROST protocol.
#[derive(Clone)]
pub struct FrostMultisig {
    /// Threshold required for signing
    threshold: usize,
    /// Total number of participants
    num_participants: usize,
    /// Group public key (aggregated)
    group_public_key: GroupPublicKey,
    /// Public key package with verification shares
    public_key_package: PublicKeyPackage,
}

impl FrostMultisig {
    /// Create a new FROST multisig from DKG result.
    ///
    /// # Arguments
    ///
    /// * `public_key_package` - The public key package from DKG containing verification shares
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rustywallet_multisig::frost::FrostMultisig;
    /// use rustywallet_frost::prelude::*;
    ///
    /// // After DKG finalization
    /// let (key_package, public_key_package) = participant.finalize().unwrap();
    /// let frost_multisig = FrostMultisig::from_dkg(public_key_package);
    /// ```
    pub fn from_dkg(public_key_package: PublicKeyPackage) -> Self {
        let threshold = public_key_package.threshold();
        let num_participants = public_key_package.verification_shares().len();
        let group_public_key = public_key_package.group_public_key().clone();

        Self {
            threshold,
            num_participants,
            group_public_key,
            public_key_package,
        }
    }

    /// Create from components.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Minimum signers required
    /// * `num_participants` - Total number of participants
    /// * `group_public_key` - The aggregated group public key
    /// * `public_key_package` - Public key package with verification shares
    pub fn new(
        threshold: usize,
        num_participants: usize,
        group_public_key: GroupPublicKey,
        public_key_package: PublicKeyPackage,
    ) -> Result<Self> {
        if threshold == 0 {
            return Err(MultisigError::InvalidThreshold {
                m: 0,
                n: num_participants as u8,
            });
        }
        if threshold > num_participants {
            return Err(MultisigError::InvalidThreshold {
                m: threshold as u8,
                n: num_participants as u8,
            });
        }

        Ok(Self {
            threshold,
            num_participants,
            group_public_key,
            public_key_package,
        })
    }

    /// Get the threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Get the number of participants.
    pub fn num_participants(&self) -> usize {
        self.num_participants
    }

    /// Get the group public key.
    pub fn group_public_key(&self) -> &GroupPublicKey {
        &self.group_public_key
    }

    /// Get the x-only public key (32 bytes) for P2TR addresses.
    pub fn xonly_public_key(&self) -> Result<[u8; 32]> {
        self.group_public_key
            .to_xonly()
            .map_err(|e| MultisigError::AddressFailed(e.to_string()))
    }

    /// Get the public key package.
    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    /// Start a new signing round.
    ///
    /// # Arguments
    ///
    /// * `message` - The 32-byte message hash to sign
    ///
    /// # Returns
    ///
    /// A new `FrostSigningRound` that can collect commitments and partial signatures.
    pub fn start_signing(&self, message: [u8; 32]) -> FrostSigningRound {
        FrostSigningRound::new(
            message,
            self.threshold,
            self.public_key_package.clone(),
        )
    }

    /// Generate a P2TR address for this FROST multisig.
    ///
    /// # Arguments
    ///
    /// * `network` - The Bitcoin network (mainnet or testnet)
    pub fn p2tr_address(&self, network: crate::address::Network) -> Result<String> {
        let xonly = self.xonly_public_key()?;
        
        // Use bech32m encoding for P2TR
        let hrp = match network {
            crate::address::Network::Mainnet => bech32::Hrp::parse("bc").unwrap(),
            crate::address::Network::Testnet => bech32::Hrp::parse("tb").unwrap(),
        };

        // Convert x-only pubkey to 5-bit groups for bech32m
        let converted = convert_bits(&xonly, 8, 5, true)
            .map_err(|e| MultisigError::AddressFailed(e))?;
        
        // Prepend witness version 1 for Taproot
        let mut data = vec![1u8]; // witness version 1
        data.extend(converted);

        // Use segwit encoding which handles witness version correctly
        let address = bech32::segwit::encode(hrp, bech32::segwit::VERSION_1, &xonly)
            .map_err(|e| MultisigError::AddressFailed(e.to_string()))?;

        Ok(address)
    }
}

/// A FROST signing round that collects commitments and partial signatures.
pub struct FrostSigningRound {
    /// Message being signed
    message: [u8; 32],
    /// Threshold required
    threshold: usize,
    /// Public key package
    public_key_package: PublicKeyPackage,
    /// Collected commitments
    commitments: Vec<CommitmentShare>,
    /// Collected partial signatures
    partial_signatures: Vec<SignatureShare>,
    /// Whether commitments phase is complete
    commitments_complete: bool,
}

impl FrostSigningRound {
    /// Create a new signing round.
    fn new(message: [u8; 32], threshold: usize, public_key_package: PublicKeyPackage) -> Self {
        Self {
            message,
            threshold,
            public_key_package,
            commitments: Vec::new(),
            partial_signatures: Vec::new(),
            commitments_complete: false,
        }
    }

    /// Get the message being signed.
    pub fn message(&self) -> &[u8; 32] {
        &self.message
    }

    /// Get the threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Add a commitment from a participant.
    ///
    /// # Arguments
    ///
    /// * `identifier` - The participant's identifier
    /// * `commitments` - The participant's signing commitments
    pub fn add_commitment(
        &mut self,
        identifier: Identifier,
        commitments: SigningCommitments,
    ) -> Result<()> {
        if self.commitments_complete {
            return Err(MultisigError::SigningFailed(
                "Commitment phase already complete".to_string(),
            ));
        }

        // Check for duplicate
        if self.commitments.iter().any(|c| c.identifier == identifier) {
            return Err(MultisigError::SigningFailed(format!(
                "Duplicate commitment from {}",
                identifier
            )));
        }

        // Verify participant exists
        if self.public_key_package.verification_share(identifier).is_none() {
            return Err(MultisigError::SigningFailed(format!(
                "Unknown participant {}",
                identifier
            )));
        }

        self.commitments.push(CommitmentShare::new(identifier, commitments));
        Ok(())
    }

    /// Mark the commitment phase as complete.
    ///
    /// Call this after collecting at least `threshold` commitments.
    pub fn finalize_commitments(&mut self) -> Result<()> {
        if self.commitments.len() < self.threshold {
            return Err(MultisigError::NotEnoughSignatures {
                need: self.threshold,
                got: self.commitments.len(),
            });
        }
        self.commitments_complete = true;
        Ok(())
    }

    /// Get the collected commitments.
    ///
    /// Returns the commitment list needed for signing.
    pub fn commitments(&self) -> &[CommitmentShare] {
        &self.commitments
    }

    /// Check if commitment phase is complete.
    pub fn is_commitment_phase_complete(&self) -> bool {
        self.commitments_complete
    }

    /// Add a partial signature from a participant.
    ///
    /// # Arguments
    ///
    /// * `signature_share` - The participant's partial signature
    pub fn add_partial_sig(&mut self, signature_share: SignatureShare) -> Result<()> {
        if !self.commitments_complete {
            return Err(MultisigError::SigningFailed(
                "Commitment phase not complete".to_string(),
            ));
        }

        // Check for duplicate
        if self.partial_signatures.iter().any(|s| s.identifier == signature_share.identifier) {
            return Err(MultisigError::SigningFailed(format!(
                "Duplicate signature from {}",
                signature_share.identifier
            )));
        }

        // Verify participant has a commitment
        if !self.commitments.iter().any(|c| c.identifier == signature_share.identifier) {
            return Err(MultisigError::SigningFailed(format!(
                "No commitment from {}",
                signature_share.identifier
            )));
        }

        self.partial_signatures.push(signature_share);
        Ok(())
    }

    /// Get the number of partial signatures collected.
    pub fn signature_count(&self) -> usize {
        self.partial_signatures.len()
    }

    /// Check if we have enough signatures to finalize.
    pub fn can_finalize(&self) -> bool {
        self.commitments_complete && self.partial_signatures.len() >= self.threshold
    }

    /// Finalize the signing round and produce the final signature.
    ///
    /// # Returns
    ///
    /// The aggregated Schnorr signature.
    pub fn finalize(&self) -> Result<Signature> {
        if !self.can_finalize() {
            return Err(MultisigError::NotEnoughSignatures {
                need: self.threshold,
                got: self.partial_signatures.len(),
            });
        }

        aggregate(
            &self.commitments,
            &self.partial_signatures,
            &self.public_key_package,
            &self.message,
        )
        .map_err(|e| MultisigError::SigningFailed(e.to_string()))
    }

    /// Get the partial signatures collected so far.
    pub fn partial_signatures(&self) -> &[SignatureShare] {
        &self.partial_signatures
    }
}

/// FROST participant for signing operations.
///
/// Wraps a KeyPackage and provides signing functionality.
pub struct FrostParticipant {
    /// The participant's key package
    key_package: KeyPackage,
    /// Current signing nonces (if any)
    nonces: Option<SigningNonces>,
}

impl FrostParticipant {
    /// Create a new participant from a key package.
    pub fn new(key_package: KeyPackage) -> Self {
        Self {
            key_package,
            nonces: None,
        }
    }

    /// Get the participant's identifier.
    pub fn identifier(&self) -> Identifier {
        self.key_package.identifier()
    }

    /// Get the key package.
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// Generate nonces and return commitments for a signing round.
    ///
    /// # Returns
    ///
    /// The signing commitments to share with other participants.
    pub fn generate_nonces(&mut self) -> Result<SigningCommitments> {
        let nonces = SigningNonces::generate(self.key_package.signing_share())
            .map_err(|e| MultisigError::SigningFailed(e.to_string()))?;
        
        let commitments = nonces.commitments()
            .map_err(|e| MultisigError::SigningFailed(e.to_string()))?;
        
        self.nonces = Some(nonces);
        Ok(commitments)
    }

    /// Create a partial signature for a signing round.
    ///
    /// # Arguments
    ///
    /// * `commitment_list` - All commitments from participating signers
    /// * `message` - The message being signed
    ///
    /// # Returns
    ///
    /// The participant's partial signature.
    pub fn sign(
        &mut self,
        commitment_list: &[CommitmentShare],
        message: &[u8],
    ) -> Result<SignatureShare> {
        let nonces = self.nonces.as_mut().ok_or_else(|| {
            MultisigError::SigningFailed("No nonces generated".to_string())
        })?;

        let signature_share = sign(&self.key_package, nonces, commitment_list, message)
            .map_err(|e| MultisigError::SigningFailed(e.to_string()))?;

        // Clear nonces after use
        self.nonces = None;

        Ok(signature_share)
    }

    /// Check if nonces are available for signing.
    pub fn has_nonces(&self) -> bool {
        self.nonces.is_some()
    }
}

/// Convert bits between different bases.
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> std::result::Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv: u32 = (1 << to_bits) - 1;

    for &value in data {
        let value = value as u32;
        if (value >> from_bits) != 0 {
            return Err("Invalid data range".to_string());
        }
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err("Invalid padding".to_string());
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_frost::prelude::DkgParticipant;

    fn run_dkg(threshold: usize, num_participants: usize) -> (Vec<KeyPackage>, PublicKeyPackage) {
        // Create participants
        let mut participants: Vec<DkgParticipant> = (1..=num_participants as u32)
            .map(|i| DkgParticipant::new(Identifier::new(i).unwrap(), threshold, num_participants).unwrap())
            .collect();

        // Round 1
        let r1_packages: Vec<_> = participants.iter_mut().map(|p| p.round1().unwrap()).collect();

        // Distribute Round 1 packages
        for p in &mut participants {
            for pkg in &r1_packages {
                p.receive_round1(pkg.clone()).unwrap();
            }
        }

        // Round 2
        let r2_packages: Vec<Vec<_>> = participants.iter().map(|p| p.round2().unwrap()).collect();

        // Distribute Round 2 packages
        for pkgs in &r2_packages {
            for pkg in pkgs {
                let receiver_idx = pkg.receiver.value() as usize - 1;
                participants[receiver_idx].receive_round2(pkg.clone()).unwrap();
            }
        }

        // Finalize
        let results: Vec<_> = participants.iter().map(|p| p.finalize().unwrap()).collect();
        let key_packages: Vec<_> = results.iter().map(|(kp, _)| kp.clone()).collect();
        let public_key_package = results[0].1.clone();

        (key_packages, public_key_package)
    }

    #[test]
    fn test_frost_multisig_creation() {
        let (_, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        assert_eq!(frost_multisig.threshold(), 2);
        assert_eq!(frost_multisig.num_participants(), 3);
    }

    #[test]
    fn test_frost_multisig_xonly_key() {
        let (_, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        let xonly = frost_multisig.xonly_public_key().unwrap();
        assert_eq!(xonly.len(), 32);
    }

    #[test]
    fn test_frost_signing_round() {
        let (key_packages, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        let message = [0xab; 32];
        let mut round = frost_multisig.start_signing(message);

        // Create participants
        let mut p1 = FrostParticipant::new(key_packages[0].clone());
        let mut p2 = FrostParticipant::new(key_packages[1].clone());

        // Generate commitments
        let c1 = p1.generate_nonces().unwrap();
        let c2 = p2.generate_nonces().unwrap();

        // Add commitments
        round.add_commitment(p1.identifier(), c1).unwrap();
        round.add_commitment(p2.identifier(), c2).unwrap();
        round.finalize_commitments().unwrap();

        // Sign
        let sig1 = p1.sign(round.commitments(), &message).unwrap();
        let sig2 = p2.sign(round.commitments(), &message).unwrap();

        // Add partial signatures
        round.add_partial_sig(sig1).unwrap();
        round.add_partial_sig(sig2).unwrap();

        // Finalize
        assert!(round.can_finalize());
        let signature = round.finalize().unwrap();
        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn test_frost_p2tr_address() {
        let (_, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        let address = frost_multisig.p2tr_address(crate::address::Network::Mainnet).unwrap();
        println!("Generated address: {}", address);
        assert!(address.starts_with("bc1p"), "Address should start with bc1p, got: {}", address);

        let testnet_address = frost_multisig.p2tr_address(crate::address::Network::Testnet).unwrap();
        println!("Generated testnet address: {}", testnet_address);
        assert!(testnet_address.starts_with("tb1p"), "Testnet address should start with tb1p, got: {}", testnet_address);
    }
}


/// FROST PSBT builder for hardware wallet compatibility.
///
/// This builder helps create and manage PSBTs for FROST threshold signing,
/// enabling hardware wallet workflows where each participant signs independently.
pub struct FrostPsbtBuilder {
    /// The FROST multisig configuration
    frost_multisig: FrostMultisig,
    /// Number of inputs
    input_count: usize,
    /// Collected commitments per input
    input_commitments: Vec<Vec<CommitmentShare>>,
    /// Collected partial signatures per input
    input_partial_sigs: Vec<Vec<SignatureShare>>,
    /// Message hashes per input
    input_messages: Vec<Option<[u8; 32]>>,
}

impl FrostPsbtBuilder {
    /// Create a new FROST PSBT builder.
    ///
    /// # Arguments
    ///
    /// * `frost_multisig` - The FROST multisig configuration
    /// * `input_count` - Number of inputs in the transaction
    pub fn new(frost_multisig: FrostMultisig, input_count: usize) -> Self {
        Self {
            frost_multisig,
            input_count,
            input_commitments: vec![Vec::new(); input_count],
            input_partial_sigs: vec![Vec::new(); input_count],
            input_messages: vec![None; input_count],
        }
    }

    /// Set the message hash for an input.
    ///
    /// # Arguments
    ///
    /// * `input_index` - The input index
    /// * `message` - The 32-byte message hash (sighash)
    pub fn set_message(&mut self, input_index: usize, message: [u8; 32]) -> Result<()> {
        if input_index >= self.input_count {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: "Input index out of bounds".to_string(),
            });
        }
        self.input_messages[input_index] = Some(message);
        Ok(())
    }

    /// Add a commitment for an input.
    ///
    /// # Arguments
    ///
    /// * `input_index` - The input index
    /// * `identifier` - The participant's identifier
    /// * `commitments` - The participant's signing commitments
    pub fn add_commitment(
        &mut self,
        input_index: usize,
        identifier: Identifier,
        commitments: SigningCommitments,
    ) -> Result<()> {
        if input_index >= self.input_count {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: "Input index out of bounds".to_string(),
            });
        }

        // Check for duplicate
        if self.input_commitments[input_index]
            .iter()
            .any(|c| c.identifier == identifier)
        {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: format!("Duplicate commitment from {}", identifier),
            });
        }

        self.input_commitments[input_index].push(CommitmentShare::new(identifier, commitments));
        Ok(())
    }

    /// Get commitments for an input.
    pub fn commitments(&self, input_index: usize) -> Option<&[CommitmentShare]> {
        self.input_commitments.get(input_index).map(|v| v.as_slice())
    }

    /// Check if an input has enough commitments.
    pub fn has_enough_commitments(&self, input_index: usize) -> bool {
        self.input_commitments
            .get(input_index)
            .map(|c| c.len() >= self.frost_multisig.threshold())
            .unwrap_or(false)
    }

    /// Add a partial signature for an input.
    ///
    /// # Arguments
    ///
    /// * `input_index` - The input index
    /// * `signature_share` - The participant's partial signature
    pub fn add_partial_sig(
        &mut self,
        input_index: usize,
        signature_share: SignatureShare,
    ) -> Result<()> {
        if input_index >= self.input_count {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: "Input index out of bounds".to_string(),
            });
        }

        // Check for duplicate
        if self.input_partial_sigs[input_index]
            .iter()
            .any(|s| s.identifier == signature_share.identifier)
        {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: format!("Duplicate signature from {}", signature_share.identifier),
            });
        }

        // Verify participant has a commitment
        if !self.input_commitments[input_index]
            .iter()
            .any(|c| c.identifier == signature_share.identifier)
        {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: format!("No commitment from {}", signature_share.identifier),
            });
        }

        self.input_partial_sigs[input_index].push(signature_share);
        Ok(())
    }

    /// Get the number of partial signatures for an input.
    pub fn signature_count(&self, input_index: usize) -> usize {
        self.input_partial_sigs
            .get(input_index)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Check if an input has enough signatures.
    pub fn input_is_complete(&self, input_index: usize) -> bool {
        self.input_partial_sigs
            .get(input_index)
            .map(|s| s.len() >= self.frost_multisig.threshold())
            .unwrap_or(false)
    }

    /// Check if all inputs have enough signatures.
    pub fn is_complete(&self) -> bool {
        (0..self.input_count).all(|i| self.input_is_complete(i))
    }

    /// Finalize an input and produce the aggregated signature.
    ///
    /// # Arguments
    ///
    /// * `input_index` - The input index
    ///
    /// # Returns
    ///
    /// The aggregated Schnorr signature for the input.
    pub fn finalize_input(&self, input_index: usize) -> Result<Signature> {
        if input_index >= self.input_count {
            return Err(MultisigError::InvalidSignature {
                index: input_index,
                reason: "Input index out of bounds".to_string(),
            });
        }

        if !self.input_is_complete(input_index) {
            return Err(MultisigError::NotEnoughSignatures {
                need: self.frost_multisig.threshold(),
                got: self.signature_count(input_index),
            });
        }

        let message = self.input_messages[input_index].ok_or_else(|| {
            MultisigError::SigningFailed("No message set for input".to_string())
        })?;

        aggregate(
            &self.input_commitments[input_index],
            &self.input_partial_sigs[input_index],
            self.frost_multisig.public_key_package(),
            &message,
        )
        .map_err(|e| MultisigError::SigningFailed(e.to_string()))
    }

    /// Get the FROST multisig configuration.
    pub fn frost_multisig(&self) -> &FrostMultisig {
        &self.frost_multisig
    }

    /// Get the threshold.
    pub fn threshold(&self) -> usize {
        self.frost_multisig.threshold()
    }
}

#[cfg(test)]
mod psbt_tests {
    use super::*;
    use rustywallet_frost::prelude::DkgParticipant;

    fn run_dkg(threshold: usize, num_participants: usize) -> (Vec<KeyPackage>, PublicKeyPackage) {
        let mut participants: Vec<DkgParticipant> = (1..=num_participants as u32)
            .map(|i| DkgParticipant::new(Identifier::new(i).unwrap(), threshold, num_participants).unwrap())
            .collect();

        let r1_packages: Vec<_> = participants.iter_mut().map(|p| p.round1().unwrap()).collect();

        for p in &mut participants {
            for pkg in &r1_packages {
                p.receive_round1(pkg.clone()).unwrap();
            }
        }

        let r2_packages: Vec<Vec<_>> = participants.iter().map(|p| p.round2().unwrap()).collect();

        for pkgs in &r2_packages {
            for pkg in pkgs {
                let receiver_idx = pkg.receiver.value() as usize - 1;
                participants[receiver_idx].receive_round2(pkg.clone()).unwrap();
            }
        }

        let results: Vec<_> = participants.iter().map(|p| p.finalize().unwrap()).collect();
        let key_packages: Vec<_> = results.iter().map(|(kp, _)| kp.clone()).collect();
        let public_key_package = results[0].1.clone();

        (key_packages, public_key_package)
    }

    #[test]
    fn test_frost_psbt_builder() {
        let (key_packages, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        let mut builder = FrostPsbtBuilder::new(frost_multisig, 1);
        let message = [0xab; 32];
        builder.set_message(0, message).unwrap();

        // Create participants
        let mut p1 = FrostParticipant::new(key_packages[0].clone());
        let mut p2 = FrostParticipant::new(key_packages[1].clone());

        // Generate and add commitments
        let c1 = p1.generate_nonces().unwrap();
        let c2 = p2.generate_nonces().unwrap();

        builder.add_commitment(0, p1.identifier(), c1).unwrap();
        builder.add_commitment(0, p2.identifier(), c2).unwrap();

        assert!(builder.has_enough_commitments(0));

        // Sign
        let commitments = builder.commitments(0).unwrap();
        let sig1 = p1.sign(commitments, &message).unwrap();
        let sig2 = p2.sign(commitments, &message).unwrap();

        // Add partial signatures
        builder.add_partial_sig(0, sig1).unwrap();
        builder.add_partial_sig(0, sig2).unwrap();

        assert!(builder.input_is_complete(0));
        assert!(builder.is_complete());

        // Finalize
        let signature = builder.finalize_input(0).unwrap();
        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn test_frost_psbt_builder_multiple_inputs() {
        let (key_packages, public_key_package) = run_dkg(2, 3);
        let frost_multisig = FrostMultisig::from_dkg(public_key_package);

        let mut builder = FrostPsbtBuilder::new(frost_multisig, 2);

        // Set messages for both inputs
        builder.set_message(0, [0xaa; 32]).unwrap();
        builder.set_message(1, [0xbb; 32]).unwrap();

        // Create participants
        let mut p1 = FrostParticipant::new(key_packages[0].clone());
        let mut p2 = FrostParticipant::new(key_packages[1].clone());

        // Input 0
        let c1_0 = p1.generate_nonces().unwrap();
        let c2_0 = p2.generate_nonces().unwrap();
        builder.add_commitment(0, p1.identifier(), c1_0).unwrap();
        builder.add_commitment(0, p2.identifier(), c2_0).unwrap();

        let commitments_0 = builder.commitments(0).unwrap().to_vec();
        let sig1_0 = p1.sign(&commitments_0, &[0xaa; 32]).unwrap();
        let sig2_0 = p2.sign(&commitments_0, &[0xaa; 32]).unwrap();
        builder.add_partial_sig(0, sig1_0).unwrap();
        builder.add_partial_sig(0, sig2_0).unwrap();

        // Input 1
        let c1_1 = p1.generate_nonces().unwrap();
        let c2_1 = p2.generate_nonces().unwrap();
        builder.add_commitment(1, p1.identifier(), c1_1).unwrap();
        builder.add_commitment(1, p2.identifier(), c2_1).unwrap();

        let commitments_1 = builder.commitments(1).unwrap().to_vec();
        let sig1_1 = p1.sign(&commitments_1, &[0xbb; 32]).unwrap();
        let sig2_1 = p2.sign(&commitments_1, &[0xbb; 32]).unwrap();
        builder.add_partial_sig(1, sig1_1).unwrap();
        builder.add_partial_sig(1, sig2_1).unwrap();

        assert!(builder.is_complete());

        // Finalize both inputs
        let sig0 = builder.finalize_input(0).unwrap();
        let sig1 = builder.finalize_input(1).unwrap();

        assert_eq!(sig0.to_bytes().len(), 64);
        assert_eq!(sig1.to_bytes().len(), 64);
    }
}
