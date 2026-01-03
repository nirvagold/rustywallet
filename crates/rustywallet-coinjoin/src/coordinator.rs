//! Coordinator-less CoinJoin protocol.
//!
//! Implements a simple P2P CoinJoin protocol without a central coordinator.

use crate::builder::{CoinJoinBuilder, CoinJoinTransaction};
use crate::error::{CoinJoinError, Result};
use crate::types::Participant;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// CoinJoin session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Waiting for participants
    Gathering,
    /// All participants joined, ready to build
    Ready,
    /// Transaction built, waiting for signatures
    Signing,
    /// All signatures collected
    Complete,
    /// Session failed or cancelled
    Failed,
}

/// CoinJoin session for coordinator-less protocol.
pub struct CoinJoinSession {
    /// Session ID
    id: [u8; 32],
    /// Current state
    state: SessionState,
    /// Participants
    participants: Vec<Participant>,
    /// Required output amount
    output_amount: u64,
    /// Minimum participants
    min_participants: usize,
    /// Maximum participants
    max_participants: usize,
    /// Built transaction (when ready)
    transaction: Option<CoinJoinTransaction>,
    /// Collected signatures (participant_id -> signature)
    signatures: Vec<(String, Vec<u8>)>,
}

impl CoinJoinSession {
    /// Create a new CoinJoin session.
    pub fn new(output_amount: u64) -> Self {
        let id = Self::generate_session_id();
        Self {
            id,
            state: SessionState::Gathering,
            participants: Vec::new(),
            output_amount,
            min_participants: 2,
            max_participants: 10,
            transaction: None,
            signatures: Vec::new(),
        }
    }

    /// Generate random session ID.
    fn generate_session_id() -> [u8; 32] {
        use sha2::Sha256;
        let mut hasher = Sha256::new();
        hasher.update(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// Get session ID.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get output amount.
    pub fn output_amount(&self) -> u64 {
        self.output_amount
    }

    /// Get participant count.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Set minimum participants.
    pub fn set_min_participants(&mut self, min: usize) {
        self.min_participants = min;
    }

    /// Set maximum participants.
    pub fn set_max_participants(&mut self, max: usize) {
        self.max_participants = max;
    }

    /// Join the session as a participant.
    pub fn join(&mut self, participant: Participant) -> Result<JoinResponse> {
        if self.state != SessionState::Gathering {
            return Err(CoinJoinError::PayJoinError(
                "Session not accepting participants".into(),
            ));
        }

        if self.participants.len() >= self.max_participants {
            return Err(CoinJoinError::PayJoinError("Session is full".into()));
        }

        // Verify participant has enough funds
        let total_input = participant.total_input();
        if total_input < self.output_amount {
            return Err(CoinJoinError::InsufficientFunds {
                needed: self.output_amount,
                available: total_input,
            });
        }

        // Check for duplicate
        if self.participants.iter().any(|p| p.id == participant.id) {
            return Err(CoinJoinError::InvalidParticipant(
                "Already joined".into(),
            ));
        }

        self.participants.push(participant.clone());

        // Check if ready
        if self.participants.len() >= self.min_participants {
            self.state = SessionState::Ready;
        }

        Ok(JoinResponse {
            session_id: self.id,
            participant_id: participant.id,
            position: self.participants.len() - 1,
            current_count: self.participants.len(),
            ready: self.state == SessionState::Ready,
        })
    }

    /// Build the CoinJoin transaction.
    pub fn build_transaction(&mut self) -> Result<&CoinJoinTransaction> {
        if self.state != SessionState::Ready {
            return Err(CoinJoinError::PayJoinError(
                "Session not ready to build".into(),
            ));
        }

        let mut builder = CoinJoinBuilder::new();
        builder.set_output_amount(self.output_amount);
        builder.set_min_participants(self.min_participants);

        for participant in &self.participants {
            builder.add_participant(participant.clone());
        }

        let tx = builder.build()?;
        self.transaction = Some(tx);
        self.state = SessionState::Signing;

        Ok(self.transaction.as_ref().unwrap())
    }

    /// Submit a signature.
    pub fn submit_signature(&mut self, participant_id: &str, signature: Vec<u8>) -> Result<()> {
        if self.state != SessionState::Signing {
            return Err(CoinJoinError::PayJoinError(
                "Session not accepting signatures".into(),
            ));
        }

        // Verify participant exists
        if !self.participants.iter().any(|p| p.id == participant_id) {
            return Err(CoinJoinError::InvalidParticipant(
                "Unknown participant".into(),
            ));
        }

        // Check for duplicate signature
        if self.signatures.iter().any(|(id, _)| id == participant_id) {
            return Err(CoinJoinError::PayJoinError(
                "Signature already submitted".into(),
            ));
        }

        self.signatures.push((participant_id.to_string(), signature));

        // Check if all signatures collected
        if self.signatures.len() == self.participants.len() {
            self.state = SessionState::Complete;
        }

        Ok(())
    }

    /// Get the built transaction.
    pub fn transaction(&self) -> Option<&CoinJoinTransaction> {
        self.transaction.as_ref()
    }

    /// Get collected signatures.
    pub fn signatures(&self) -> &[(String, Vec<u8>)] {
        &self.signatures
    }

    /// Check if session is complete.
    pub fn is_complete(&self) -> bool {
        self.state == SessionState::Complete
    }

    /// Cancel the session.
    pub fn cancel(&mut self) {
        self.state = SessionState::Failed;
    }
}

/// Response when joining a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    /// Session ID
    pub session_id: [u8; 32],
    /// Participant ID
    pub participant_id: String,
    /// Position in participant list
    pub position: usize,
    /// Current participant count
    pub current_count: usize,
    /// Whether session is ready to build
    pub ready: bool,
}

/// Session announcement for discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAnnouncement {
    /// Session ID
    pub session_id: [u8; 32],
    /// Required output amount
    pub output_amount: u64,
    /// Current participant count
    pub current_count: usize,
    /// Minimum participants needed
    pub min_participants: usize,
    /// Maximum participants allowed
    pub max_participants: usize,
    /// Session state
    pub state: String,
}

impl From<&CoinJoinSession> for SessionAnnouncement {
    fn from(session: &CoinJoinSession) -> Self {
        Self {
            session_id: session.id,
            output_amount: session.output_amount,
            current_count: session.participants.len(),
            min_participants: session.min_participants,
            max_participants: session.max_participants,
            state: format!("{:?}", session.state),
        }
    }
}

/// Verify a participant's commitment.
pub fn verify_commitment(
    participant: &Participant,
    commitment: &[u8; 32],
) -> bool {
    let computed = compute_commitment(participant);
    &computed == commitment
}

/// Compute commitment hash for a participant.
pub fn compute_commitment(participant: &Participant) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(participant.id.as_bytes());
    for input in &participant.inputs {
        hasher.update(input.txid);
        hasher.update(input.vout.to_le_bytes());
        hasher.update(input.amount.to_le_bytes());
    }
    hasher.update(&participant.output_script);
    let result = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&result);
    commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_participant(id: &str, amount: u64) -> Participant {
        Participant::new(
            id,
            vec![InputRef::from_outpoint([1u8; 32], 0, amount)],
            vec![0x00, 0x14],
        )
    }

    #[test]
    fn test_session_creation() {
        let session = CoinJoinSession::new(50_000);
        assert_eq!(session.state(), SessionState::Gathering);
        assert_eq!(session.output_amount(), 50_000);
    }

    #[test]
    fn test_join_session() {
        let mut session = CoinJoinSession::new(50_000);

        let alice = create_test_participant("alice", 100_000);
        let response = session.join(alice).unwrap();

        assert_eq!(response.position, 0);
        assert!(!response.ready);
        assert_eq!(session.participant_count(), 1);
    }

    #[test]
    fn test_session_ready() {
        let mut session = CoinJoinSession::new(50_000);

        session.join(create_test_participant("alice", 100_000)).unwrap();
        let response = session.join(create_test_participant("bob", 100_000)).unwrap();

        assert!(response.ready);
        assert_eq!(session.state(), SessionState::Ready);
    }

    #[test]
    fn test_build_transaction() {
        let mut session = CoinJoinSession::new(50_000);

        session.join(create_test_participant("alice", 100_000)).unwrap();
        session.join(create_test_participant("bob", 100_000)).unwrap();

        let tx = session.build_transaction().unwrap();
        assert_eq!(tx.participant_count, 2);
        assert_eq!(session.state(), SessionState::Signing);
    }

    #[test]
    fn test_submit_signatures() {
        let mut session = CoinJoinSession::new(50_000);

        session.join(create_test_participant("alice", 100_000)).unwrap();
        session.join(create_test_participant("bob", 100_000)).unwrap();
        session.build_transaction().unwrap();

        session.submit_signature("alice", vec![1, 2, 3]).unwrap();
        assert!(!session.is_complete());

        session.submit_signature("bob", vec![4, 5, 6]).unwrap();
        assert!(session.is_complete());
    }

    #[test]
    fn test_insufficient_funds() {
        let mut session = CoinJoinSession::new(50_000);

        let poor = create_test_participant("poor", 10_000);
        let result = session.join(poor);

        assert!(matches!(result, Err(CoinJoinError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_commitment() {
        let participant = create_test_participant("alice", 100_000);
        let commitment = compute_commitment(&participant);

        assert!(verify_commitment(&participant, &commitment));

        // Different participant should have different commitment
        let other = create_test_participant("bob", 100_000);
        assert!(!verify_commitment(&other, &commitment));
    }
}
