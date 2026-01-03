//! Distributed Key Generation (DKG) for FROST.
//!
//! Implements Pedersen's DKG with verifiable secret sharing.

use crate::error::{FrostError, Result};
use crate::identifier::Identifier;
use crate::keys::{GroupPublicKey, KeyPackage, PublicKeyPackage};
use crate::polynomial::{verify_share, Polynomial};
use crate::share::VerificationShare;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;

/// Round 1 output from a participant.
#[derive(Debug, Clone)]
pub struct Round1Package {
    /// Participant identifier
    pub identifier: Identifier,
    /// Commitments to polynomial coefficients
    pub commitments: Vec<[u8; 33]>,
}

impl Round1Package {
    /// Get the commitment to the constant term (verification share).
    pub fn verification_share_commitment(&self) -> Option<&[u8; 33]> {
        self.commitments.first()
    }
}

/// Round 2 output from a participant (secret share for another participant).
#[derive(Clone)]
pub struct Round2Package {
    /// Sender identifier
    pub sender: Identifier,
    /// Receiver identifier
    pub receiver: Identifier,
    /// Secret share for the receiver
    pub share: [u8; 32],
}

/// DKG participant state.
pub struct DkgParticipant {
    /// Participant identifier
    identifier: Identifier,
    /// Threshold
    threshold: usize,
    /// Total participants
    num_participants: usize,
    /// Secret polynomial
    polynomial: Option<Polynomial>,
    /// Round 1 packages from all participants
    round1_packages: HashMap<u32, Round1Package>,
    /// Received shares from other participants
    received_shares: HashMap<u32, [u8; 32]>,
}

impl DkgParticipant {
    /// Create a new DKG participant.
    pub fn new(identifier: Identifier, threshold: usize, num_participants: usize) -> Result<Self> {
        if threshold == 0 {
            return Err(FrostError::InvalidThreshold(
                "Threshold must be at least 1".into(),
            ));
        }
        if threshold > num_participants {
            return Err(FrostError::InvalidThreshold(format!(
                "Threshold {} exceeds participants {}",
                threshold, num_participants
            )));
        }

        Ok(Self {
            identifier,
            threshold,
            num_participants,
            polynomial: None,
            round1_packages: HashMap::new(),
            received_shares: HashMap::new(),
        })
    }

    /// Execute Round 1: Generate polynomial and commitments.
    pub fn round1(&mut self) -> Result<Round1Package> {
        // Generate random polynomial
        let poly = Polynomial::random_with_degree(self.threshold - 1)?;
        let commitments = poly.commitments()?;

        self.polynomial = Some(poly);

        Ok(Round1Package {
            identifier: self.identifier,
            commitments,
        })
    }

    /// Receive Round 1 package from another participant.
    pub fn receive_round1(&mut self, package: Round1Package) -> Result<()> {
        if package.commitments.len() != self.threshold {
            return Err(FrostError::InvalidCommitment(format!(
                "Expected {} commitments, got {}",
                self.threshold,
                package.commitments.len()
            )));
        }

        let id = package.identifier.value();
        if self.round1_packages.contains_key(&id) {
            return Err(FrostError::DuplicateParticipant(id));
        }

        self.round1_packages.insert(id, package);
        Ok(())
    }

    /// Execute Round 2: Generate shares for all participants.
    pub fn round2(&self) -> Result<Vec<Round2Package>> {
        let poly = self.polynomial.as_ref().ok_or_else(|| {
            FrostError::DkgError("Round 1 not completed".into())
        })?;

        let mut packages = Vec::with_capacity(self.num_participants);

        for i in 1..=self.num_participants as u32 {
            let receiver = Identifier::new(i)?;
            let share = poly.evaluate(&receiver)?;

            packages.push(Round2Package {
                sender: self.identifier,
                receiver,
                share,
            });
        }

        Ok(packages)
    }

    /// Receive Round 2 package (share) from another participant.
    pub fn receive_round2(&mut self, package: Round2Package) -> Result<()> {
        // Verify the share against sender's commitments
        let sender_package = self.round1_packages.get(&package.sender.value())
            .ok_or_else(|| FrostError::MissingData(format!(
                "No Round 1 package from {}",
                package.sender
            )))?;

        let valid = verify_share(&package.share, &package.receiver, &sender_package.commitments)?;
        if !valid {
            return Err(FrostError::MaliciousParticipant(format!(
                "Invalid share from {}",
                package.sender
            )));
        }

        self.received_shares.insert(package.sender.value(), package.share);
        Ok(())
    }

    /// Finalize DKG and compute key package.
    pub fn finalize(&self) -> Result<(KeyPackage, PublicKeyPackage)> {
        // Check we have all shares
        if self.received_shares.len() != self.num_participants {
            return Err(FrostError::MissingData(format!(
                "Expected {} shares, got {}",
                self.num_participants,
                self.received_shares.len()
            )));
        }

        // Sum all received shares to get signing share
        let mut signing_share = [0u8; 32];
        for share in self.received_shares.values() {
            signing_share = scalar_add(&signing_share, share)?;
        }

        // Compute verification share
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&signing_share)
            .map_err(|e| FrostError::CryptoError(e.to_string()))?;
        let verification_share = PublicKey::from_secret_key(&secp, &sk).serialize();

        // Compute group public key (sum of all constant term commitments)
        let mut group_pk: Option<PublicKey> = None;
        for package in self.round1_packages.values() {
            let commitment = package.verification_share_commitment()
                .ok_or_else(|| FrostError::InvalidCommitment("Empty commitments".into()))?;
            let pk = PublicKey::from_slice(commitment)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;

            group_pk = match group_pk {
                None => Some(pk),
                Some(acc) => Some(acc.combine(&pk)
                    .map_err(|e| FrostError::CryptoError(e.to_string()))?),
            };
        }

        let group_pk = group_pk.ok_or_else(|| FrostError::MissingData("No commitments".into()))?;
        let group_public_key = GroupPublicKey::from_bytes(&group_pk.serialize())?;

        // Compute all verification shares
        let mut verification_shares = Vec::with_capacity(self.num_participants);
        for i in 1..=self.num_participants as u32 {
            let id = Identifier::new(i)?;
            let vs = compute_verification_share(&id, &self.round1_packages)?;
            verification_shares.push(VerificationShare::new(id, vs));
        }

        let key_package = KeyPackage::new(
            self.identifier,
            signing_share,
            verification_share,
            group_pk.serialize(),
            self.threshold,
            self.num_participants,
        );

        let public_key_package = PublicKeyPackage::new(
            verification_shares,
            group_public_key,
            self.threshold,
        );

        Ok((key_package, public_key_package))
    }
}

/// Compute verification share for a participant from all commitments.
fn compute_verification_share(
    id: &Identifier,
    packages: &HashMap<u32, Round1Package>,
) -> Result<[u8; 33]> {
    let secp = Secp256k1::new();
    let x = id.to_scalar_bytes();
    let mut result: Option<PublicKey> = None;

    for package in packages.values() {
        // Evaluate commitment polynomial at x
        let mut x_power = [0u8; 32];
        x_power[31] = 1; // x^0 = 1
        let mut term: Option<PublicKey> = None;

        for commitment in &package.commitments {
            let c_j = PublicKey::from_slice(commitment)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;

            // C_j^(x^j)
            let x_power_sk = SecretKey::from_slice(&x_power)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;
            let scaled = c_j.mul_tweak(&secp, &x_power_sk.into())
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;

            term = match term {
                None => Some(scaled),
                Some(acc) => Some(acc.combine(&scaled)
                    .map_err(|e| FrostError::CryptoError(e.to_string()))?),
            };

            // x_power = x_power * x
            let x_sk = SecretKey::from_slice(&x)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;
            let x_power_sk = SecretKey::from_slice(&x_power)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?;
            x_power = x_power_sk.mul_tweak(&x_sk.into())
                .map_err(|e| FrostError::CryptoError(e.to_string()))?
                .secret_bytes();
        }

        let term = term.ok_or_else(|| FrostError::InvalidCommitment("Empty commitments".into()))?;

        result = match result {
            None => Some(term),
            Some(acc) => Some(acc.combine(&term)
                .map_err(|e| FrostError::CryptoError(e.to_string()))?),
        };
    }

    let result = result.ok_or_else(|| FrostError::MissingData("No packages".into()))?;
    Ok(result.serialize())
}

/// Scalar addition modulo curve order.
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32]> {
    let is_a_zero = a.iter().all(|&x| x == 0);
    if is_a_zero {
        return Ok(*b);
    }

    let is_b_zero = b.iter().all(|&x| x == 0);
    if is_b_zero {
        return Ok(*a);
    }

    let sk_a = SecretKey::from_slice(a)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;
    let sk_b = SecretKey::from_slice(b)
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    let result = sk_a.add_tweak(&sk_b.into())
        .map_err(|e| FrostError::CryptoError(e.to_string()))?;

    Ok(result.secret_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkg_2_of_3() {
        let threshold = 2;
        let num_participants = 3;

        // Create participants
        let mut p1 = DkgParticipant::new(Identifier::new(1).unwrap(), threshold, num_participants).unwrap();
        let mut p2 = DkgParticipant::new(Identifier::new(2).unwrap(), threshold, num_participants).unwrap();
        let mut p3 = DkgParticipant::new(Identifier::new(3).unwrap(), threshold, num_participants).unwrap();

        // Round 1
        let r1_p1 = p1.round1().unwrap();
        let r1_p2 = p2.round1().unwrap();
        let r1_p3 = p3.round1().unwrap();

        // Distribute Round 1 packages
        for p in [&mut p1, &mut p2, &mut p3] {
            p.receive_round1(r1_p1.clone()).unwrap();
            p.receive_round1(r1_p2.clone()).unwrap();
            p.receive_round1(r1_p3.clone()).unwrap();
        }

        // Round 2
        let r2_p1 = p1.round2().unwrap();
        let r2_p2 = p2.round2().unwrap();
        let r2_p3 = p3.round2().unwrap();

        // Distribute Round 2 packages
        for pkg in &r2_p1 {
            match pkg.receiver.value() {
                1 => p1.receive_round2(pkg.clone()).unwrap(),
                2 => p2.receive_round2(pkg.clone()).unwrap(),
                3 => p3.receive_round2(pkg.clone()).unwrap(),
                _ => unreachable!(),
            }
        }
        for pkg in &r2_p2 {
            match pkg.receiver.value() {
                1 => p1.receive_round2(pkg.clone()).unwrap(),
                2 => p2.receive_round2(pkg.clone()).unwrap(),
                3 => p3.receive_round2(pkg.clone()).unwrap(),
                _ => unreachable!(),
            }
        }
        for pkg in &r2_p3 {
            match pkg.receiver.value() {
                1 => p1.receive_round2(pkg.clone()).unwrap(),
                2 => p2.receive_round2(pkg.clone()).unwrap(),
                3 => p3.receive_round2(pkg.clone()).unwrap(),
                _ => unreachable!(),
            }
        }

        // Finalize
        let (kp1, pkp1) = p1.finalize().unwrap();
        let (kp2, pkp2) = p2.finalize().unwrap();
        let (kp3, pkp3) = p3.finalize().unwrap();

        // All should have same group public key
        assert_eq!(kp1.group_public_key(), kp2.group_public_key());
        assert_eq!(kp2.group_public_key(), kp3.group_public_key());

        // Public key packages should match
        assert_eq!(pkp1.group_public_key(), pkp2.group_public_key());
        assert_eq!(pkp2.group_public_key(), pkp3.group_public_key());
    }
}
