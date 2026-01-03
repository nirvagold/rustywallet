//! MuSig2 signing session management.
//!
//! Provides a high-level API for managing MuSig2 signing sessions.

use crate::error::{MusigError, Result};
use crate::key_agg::KeyAggContext;
use crate::nonce::{AggregatedNonce, PublicNonce, SecretNonce};
use crate::signing::{
    aggregate_partial_signatures, create_partial_signature, verify_signature, PartialSignature,
    SchnorrSignature,
};

/// State of a MuSig2 signing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, waiting for nonces.
    AwaitingNonces,
    /// All nonces received, ready to sign.
    ReadyToSign,
    /// Signing in progress.
    Signing,
    /// All signatures collected, ready to aggregate.
    ReadyToAggregate,
    /// Session complete.
    Complete,
}

/// A MuSig2 signing session.
pub struct SigningSession {
    /// Key aggregation context
    key_agg: KeyAggContext,
    /// Message to sign
    msg: [u8; 32],
    /// Current session state
    state: SessionState,
    /// Collected public nonces
    public_nonces: Vec<Option<PublicNonce>>,
    /// Aggregated nonce (computed when all nonces received)
    agg_nonce: Option<AggregatedNonce>,
    /// Collected partial signatures
    partial_sigs: Vec<Option<PartialSignature>>,
    /// Final signature
    final_sig: Option<SchnorrSignature>,
}

impl SigningSession {
    /// Create a new signing session.
    pub fn new(key_agg: KeyAggContext, msg: [u8; 32]) -> Self {
        let num_signers = key_agg.num_signers();
        Self {
            key_agg,
            msg,
            state: SessionState::AwaitingNonces,
            public_nonces: vec![None; num_signers],
            agg_nonce: None,
            partial_sigs: vec![None; num_signers],
            final_sig: None,
        }
    }

    /// Get the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get the key aggregation context.
    pub fn key_agg(&self) -> &KeyAggContext {
        &self.key_agg
    }

    /// Get the message being signed.
    pub fn message(&self) -> &[u8; 32] {
        &self.msg
    }

    /// Add a public nonce from a signer.
    pub fn add_nonce(&mut self, signer_index: usize, nonce: PublicNonce) -> Result<()> {
        if self.state != SessionState::AwaitingNonces {
            return Err(MusigError::InvalidSessionState(
                "Not accepting nonces".into(),
            ));
        }

        if signer_index >= self.public_nonces.len() {
            return Err(MusigError::InvalidSessionState(format!(
                "Invalid signer index: {}",
                signer_index
            )));
        }

        self.public_nonces[signer_index] = Some(nonce);

        // Check if all nonces received
        if self.public_nonces.iter().all(|n| n.is_some()) {
            self.compute_aggregated_nonce()?;
            self.state = SessionState::ReadyToSign;
        }

        Ok(())
    }

    /// Compute the aggregated nonce.
    fn compute_aggregated_nonce(&mut self) -> Result<()> {
        let nonces: Vec<PublicNonce> = self
            .public_nonces
            .iter()
            .map(|n| n.clone().unwrap())
            .collect();

        self.agg_nonce = Some(AggregatedNonce::aggregate(
            &nonces,
            self.key_agg.xonly_pubkey(),
            &self.msg,
        )?);

        Ok(())
    }

    /// Get the aggregated nonce (available after all nonces received).
    pub fn aggregated_nonce(&self) -> Option<&AggregatedNonce> {
        self.agg_nonce.as_ref()
    }

    /// Get all public nonces.
    pub fn public_nonces(&self) -> Vec<PublicNonce> {
        self.public_nonces
            .iter()
            .filter_map(|n| n.clone())
            .collect()
    }

    /// Create a partial signature for this session.
    pub fn sign(
        &mut self,
        secret_nonce: &mut SecretNonce,
        secret_key: &[u8; 32],
        signer_index: usize,
    ) -> Result<PartialSignature> {
        if self.state != SessionState::ReadyToSign && self.state != SessionState::Signing {
            return Err(MusigError::InvalidSessionState("Not ready to sign".into()));
        }

        let agg_nonce = self
            .agg_nonce
            .as_ref()
            .ok_or_else(|| MusigError::InvalidSessionState("No aggregated nonce".into()))?;

        let public_nonces = self.public_nonces();

        let partial = create_partial_signature(
            secret_nonce,
            secret_key,
            &self.key_agg,
            agg_nonce,
            &public_nonces,
            &self.msg,
            signer_index,
        )?;

        self.state = SessionState::Signing;

        Ok(partial)
    }

    /// Add a partial signature from a signer.
    pub fn add_partial_signature(&mut self, partial: PartialSignature) -> Result<()> {
        if self.state != SessionState::Signing && self.state != SessionState::ReadyToSign {
            return Err(MusigError::InvalidSessionState(
                "Not accepting signatures".into(),
            ));
        }

        let index = partial.signer_index;
        if index >= self.partial_sigs.len() {
            return Err(MusigError::InvalidSessionState(format!(
                "Invalid signer index: {}",
                index
            )));
        }

        self.partial_sigs[index] = Some(partial);
        self.state = SessionState::Signing;

        // Check if all signatures received
        if self.partial_sigs.iter().all(|s| s.is_some()) {
            self.state = SessionState::ReadyToAggregate;
        }

        Ok(())
    }

    /// Aggregate all partial signatures into the final signature.
    pub fn aggregate(&mut self) -> Result<SchnorrSignature> {
        if self.state != SessionState::ReadyToAggregate {
            return Err(MusigError::InvalidSessionState(
                "Not ready to aggregate".into(),
            ));
        }

        let agg_nonce = self
            .agg_nonce
            .as_ref()
            .ok_or_else(|| MusigError::InvalidSessionState("No aggregated nonce".into()))?;

        let partial_sigs: Vec<PartialSignature> = self
            .partial_sigs
            .iter()
            .map(|s| s.clone().unwrap())
            .collect();

        let sig = aggregate_partial_signatures(&partial_sigs, agg_nonce, &self.key_agg)?;

        self.final_sig = Some(sig.clone());
        self.state = SessionState::Complete;

        Ok(sig)
    }

    /// Get the final signature (available after aggregation).
    pub fn final_signature(&self) -> Option<&SchnorrSignature> {
        self.final_sig.as_ref()
    }

    /// Verify the final signature.
    pub fn verify(&self) -> Result<bool> {
        let sig = self
            .final_sig
            .as_ref()
            .ok_or_else(|| MusigError::InvalidSessionState("No final signature".into()))?;

        verify_signature(sig, self.key_agg.xonly_pubkey(), &self.msg)
    }

    /// Check if a specific signer has submitted their nonce.
    pub fn has_nonce(&self, signer_index: usize) -> bool {
        self.public_nonces
            .get(signer_index)
            .map(|n| n.is_some())
            .unwrap_or(false)
    }

    /// Check if a specific signer has submitted their partial signature.
    pub fn has_partial_sig(&self, signer_index: usize) -> bool {
        self.partial_sigs
            .get(signer_index)
            .map(|s| s.is_some())
            .unwrap_or(false)
    }

    /// Get the number of nonces received.
    pub fn nonces_received(&self) -> usize {
        self.public_nonces.iter().filter(|n| n.is_some()).count()
    }

    /// Get the number of partial signatures received.
    pub fn partial_sigs_received(&self) -> usize {
        self.partial_sigs.iter().filter(|s| s.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustywallet_keys::prelude::PrivateKey;

    #[test]
    fn test_signing_session_workflow() {
        // Setup
        let sk1 = PrivateKey::random();
        let sk2 = PrivateKey::random();
        let pk1 = sk1.public_key().to_compressed();
        let pk2 = sk2.public_key().to_compressed();

        let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
        let msg = [0u8; 32];

        // Create session
        let mut session = SigningSession::new(key_agg.clone(), msg);
        assert_eq!(session.state(), SessionState::AwaitingNonces);

        // Generate and add nonces
        let mut nonce1 = SecretNonce::generate(
            &sk1.to_bytes(),
            &pk1,
            key_agg.xonly_pubkey(),
            Some(&msg),
            None,
        )
        .unwrap();
        let mut nonce2 = SecretNonce::generate(
            &sk2.to_bytes(),
            &pk2,
            key_agg.xonly_pubkey(),
            Some(&msg),
            None,
        )
        .unwrap();

        let idx1 = key_agg.index_of(&pk1).unwrap();
        let idx2 = key_agg.index_of(&pk2).unwrap();

        session
            .add_nonce(idx1, nonce1.public_nonce().unwrap())
            .unwrap();
        assert_eq!(session.state(), SessionState::AwaitingNonces);

        session
            .add_nonce(idx2, nonce2.public_nonce().unwrap())
            .unwrap();
        assert_eq!(session.state(), SessionState::ReadyToSign);

        // Sign
        let partial1 = session.sign(&mut nonce1, &sk1.to_bytes(), idx1).unwrap();
        let partial2 = session.sign(&mut nonce2, &sk2.to_bytes(), idx2).unwrap();

        // Add partial signatures
        session.add_partial_signature(partial1).unwrap();
        session.add_partial_signature(partial2).unwrap();
        assert_eq!(session.state(), SessionState::ReadyToAggregate);

        // Aggregate
        let sig = session.aggregate().unwrap();
        assert_eq!(session.state(), SessionState::Complete);

        // Verify
        assert!(session.verify().unwrap());
        assert_eq!(sig.to_bytes().len(), 64);
    }

    #[test]
    fn test_session_state_transitions() {
        let sk1 = PrivateKey::random();
        let sk2 = PrivateKey::random();
        let pk1 = sk1.public_key().to_compressed();
        let pk2 = sk2.public_key().to_compressed();

        let key_agg = KeyAggContext::new(&[pk1, pk2]).unwrap();
        let msg = [0u8; 32];

        let session = SigningSession::new(key_agg, msg);

        // Cannot sign before nonces
        assert_eq!(session.state(), SessionState::AwaitingNonces);
        assert!(session.aggregated_nonce().is_none());
    }
}
