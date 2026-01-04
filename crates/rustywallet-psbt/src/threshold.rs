//! Advanced signature support for PSBTs.
//!
//! This module provides MuSig2 and FROST threshold signature support for PSBTs,
//! enabling multi-party signing workflows with hardware wallet compatibility.
//!
//! ## MuSig2 Support
//!
//! MuSig2 partial signatures are stored in PSBT proprietary fields with the
//! prefix "musig2" and can be combined from multiple PSBTs.
//!
//! ## FROST Support
//!
//! FROST partial signatures are stored with signer identifiers, allowing
//! threshold signing workflows where t-of-n participants can sign.

use crate::error::PsbtError;
use crate::psbt::Psbt;
use crate::types::ProprietaryKey;
use rustywallet_frost::identifier::Identifier as FrostIdentifier;
use rustywallet_frost::signing::SignatureShare as FrostSignatureShare;
use rustywallet_musig::signing::PartialSignature as MuSig2PartialSignature;

/// Proprietary prefix for MuSig2 data
pub const MUSIG2_PREFIX: &[u8] = b"musig2";

/// Proprietary prefix for FROST data
pub const FROST_PREFIX: &[u8] = b"frost";

/// MuSig2 proprietary subtypes
pub mod musig2_subtypes {
    /// Partial signature subtype
    pub const PARTIAL_SIG: u8 = 0x01;
    /// Public nonce subtype
    pub const PUBLIC_NONCE: u8 = 0x02;
    /// Aggregated nonce subtype
    pub const AGG_NONCE: u8 = 0x03;
}

/// FROST proprietary subtypes
pub mod frost_subtypes {
    /// Partial signature subtype
    pub const PARTIAL_SIG: u8 = 0x01;
    /// Commitment share subtype
    pub const COMMITMENT: u8 = 0x02;
}


/// MuSig2 partial signature stored in PSBT
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtMuSig2PartialSig {
    /// The x-only public key of the signer (32 bytes)
    pub pubkey: [u8; 32],
    /// The partial signature scalar (32 bytes)
    pub partial_sig: [u8; 32],
    /// Signer index in the key aggregation
    pub signer_index: usize,
}

impl PsbtMuSig2PartialSig {
    /// Create from MuSig2 partial signature
    pub fn from_partial_sig(partial: &MuSig2PartialSignature, pubkey: [u8; 32]) -> Self {
        Self {
            pubkey,
            partial_sig: partial.s,
            signer_index: partial.signer_index,
        }
    }

    /// Convert to MuSig2 partial signature
    pub fn to_partial_sig(&self) -> MuSig2PartialSignature {
        MuSig2PartialSignature {
            s: self.partial_sig,
            signer_index: self.signer_index,
        }
    }

    /// Serialize to bytes for PSBT storage
    /// Format: [pubkey (32)] [partial_sig (32)] [signer_index (4)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(68);
        bytes.extend_from_slice(&self.pubkey);
        bytes.extend_from_slice(&self.partial_sig);
        bytes.extend_from_slice(&(self.signer_index as u32).to_le_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PsbtError> {
        if bytes.len() != 68 {
            return Err(PsbtError::InvalidFormat(format!(
                "MuSig2 partial sig expected 68 bytes, got {}",
                bytes.len()
            )));
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes[0..32]);

        let mut partial_sig = [0u8; 32];
        partial_sig.copy_from_slice(&bytes[32..64]);

        let signer_index = u32::from_le_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]) as usize;

        Ok(Self {
            pubkey,
            partial_sig,
            signer_index,
        })
    }
}

/// FROST partial signature stored in PSBT
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtFrostPartialSig {
    /// The signer identifier
    pub identifier: FrostIdentifier,
    /// The signature share (32 bytes)
    pub share: [u8; 32],
}

impl PsbtFrostPartialSig {
    /// Create from FROST signature share
    pub fn from_signature_share(share: &FrostSignatureShare) -> Self {
        Self {
            identifier: share.identifier,
            share: share.share,
        }
    }

    /// Convert to FROST signature share
    pub fn to_signature_share(&self) -> FrostSignatureShare {
        FrostSignatureShare::new(self.identifier, self.share)
    }

    /// Serialize to bytes for PSBT storage
    /// Format: [identifier (4)] [share (32)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&self.identifier.value().to_be_bytes());
        bytes.extend_from_slice(&self.share);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PsbtError> {
        if bytes.len() != 36 {
            return Err(PsbtError::InvalidFormat(format!(
                "FROST partial sig expected 36 bytes, got {}",
                bytes.len()
            )));
        }

        let id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let identifier = FrostIdentifier::new(id)
            .map_err(|e| PsbtError::InvalidFormat(format!("Invalid FROST identifier: {}", e)))?;

        let mut share = [0u8; 32];
        share.copy_from_slice(&bytes[4..36]);

        Ok(Self { identifier, share })
    }
}


/// Add a MuSig2 partial signature to a PSBT input.
///
/// The partial signature is stored in a proprietary field with the "musig2" prefix.
/// Multiple partial signatures can be added for the same input from different signers.
///
/// # Arguments
///
/// * `psbt` - The PSBT to modify
/// * `input_index` - The index of the input to add the signature to
/// * `partial_sig` - The MuSig2 partial signature
/// * `pubkey` - The x-only public key of the signer (32 bytes)
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if the input index is out of bounds.
pub fn add_musig2_partial_sig(
    psbt: &mut Psbt,
    input_index: usize,
    partial_sig: &MuSig2PartialSignature,
    pubkey: &[u8; 32],
) -> Result<(), PsbtError> {
    if input_index >= psbt.inputs.len() {
        return Err(PsbtError::InputIndexOutOfBounds(input_index));
    }

    let psbt_sig = PsbtMuSig2PartialSig::from_partial_sig(partial_sig, *pubkey);

    let prop_key = ProprietaryKey::new(
        MUSIG2_PREFIX.to_vec(),
        musig2_subtypes::PARTIAL_SIG,
        pubkey.to_vec(),
    );

    psbt.inputs[input_index]
        .proprietary
        .insert(prop_key, psbt_sig.to_bytes());

    Ok(())
}

/// Get all MuSig2 partial signatures from a PSBT input.
///
/// # Arguments
///
/// * `psbt` - The PSBT to read from
/// * `input_index` - The index of the input
///
/// # Returns
///
/// A vector of (pubkey, partial_sig) tuples for all MuSig2 partial signatures.
pub fn get_musig2_partial_sigs(
    psbt: &Psbt,
    input_index: usize,
) -> Result<Vec<([u8; 32], MuSig2PartialSignature)>, PsbtError> {
    if input_index >= psbt.inputs.len() {
        return Err(PsbtError::InputIndexOutOfBounds(input_index));
    }

    let mut result = Vec::new();

    for (key, value) in &psbt.inputs[input_index].proprietary {
        if key.prefix == MUSIG2_PREFIX && key.subtype == musig2_subtypes::PARTIAL_SIG {
            let psbt_sig = PsbtMuSig2PartialSig::from_bytes(value)?;
            result.push((psbt_sig.pubkey, psbt_sig.to_partial_sig()));
        }
    }

    Ok(result)
}

/// Add a FROST partial signature to a PSBT input.
///
/// The partial signature is stored in a proprietary field with the "frost" prefix.
/// Multiple partial signatures can be added for the same input from different signers.
///
/// # Arguments
///
/// * `psbt` - The PSBT to modify
/// * `input_index` - The index of the input to add the signature to
/// * `partial_sig` - The FROST signature share
/// * `signer_id` - The FROST participant identifier
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if the input index is out of bounds.
pub fn add_frost_partial_sig(
    psbt: &mut Psbt,
    input_index: usize,
    partial_sig: &FrostSignatureShare,
    signer_id: &FrostIdentifier,
) -> Result<(), PsbtError> {
    if input_index >= psbt.inputs.len() {
        return Err(PsbtError::InputIndexOutOfBounds(input_index));
    }

    let psbt_sig = PsbtFrostPartialSig::from_signature_share(partial_sig);

    let prop_key = ProprietaryKey::new(
        FROST_PREFIX.to_vec(),
        frost_subtypes::PARTIAL_SIG,
        signer_id.value().to_be_bytes().to_vec(),
    );

    psbt.inputs[input_index]
        .proprietary
        .insert(prop_key, psbt_sig.to_bytes());

    Ok(())
}

/// Get all FROST partial signatures from a PSBT input.
///
/// # Arguments
///
/// * `psbt` - The PSBT to read from
/// * `input_index` - The index of the input
///
/// # Returns
///
/// A vector of (identifier, signature_share) tuples for all FROST partial signatures.
pub fn get_frost_partial_sigs(
    psbt: &Psbt,
    input_index: usize,
) -> Result<Vec<(FrostIdentifier, FrostSignatureShare)>, PsbtError> {
    if input_index >= psbt.inputs.len() {
        return Err(PsbtError::InputIndexOutOfBounds(input_index));
    }

    let mut result = Vec::new();

    for (key, value) in &psbt.inputs[input_index].proprietary {
        if key.prefix == FROST_PREFIX && key.subtype == frost_subtypes::PARTIAL_SIG {
            let psbt_sig = PsbtFrostPartialSig::from_bytes(value)?;
            result.push((psbt_sig.identifier, psbt_sig.to_signature_share()));
        }
    }

    Ok(result)
}


/// Combine PSBTs with MuSig2 partial signatures.
///
/// This function merges MuSig2 partial signatures from multiple PSBTs into a single PSBT.
/// All PSBTs must have the same unsigned transaction.
///
/// # Arguments
///
/// * `psbts` - The PSBTs to combine
///
/// # Returns
///
/// A new PSBT containing all MuSig2 partial signatures from the input PSBTs.
pub fn combine_musig2_psbt(psbts: &[Psbt]) -> Result<Psbt, PsbtError> {
    if psbts.is_empty() {
        return Err(PsbtError::InvalidFormat("No PSBTs to combine".into()));
    }

    let mut result = psbts[0].clone();

    for psbt in &psbts[1..] {
        if result.inputs.len() != psbt.inputs.len() {
            return Err(PsbtError::IncompatiblePsbts);
        }

        for (i, input) in psbt.inputs.iter().enumerate() {
            for (key, value) in &input.proprietary {
                if key.prefix == MUSIG2_PREFIX && key.subtype == musig2_subtypes::PARTIAL_SIG {
                    result.inputs[i]
                        .proprietary
                        .entry(key.clone())
                        .or_insert_with(|| value.clone());
                }
            }
        }
    }

    Ok(result)
}

/// Count MuSig2 partial signatures for an input.
///
/// # Arguments
///
/// * `psbt` - The PSBT to check
/// * `input_index` - The index of the input
///
/// # Returns
///
/// The number of MuSig2 partial signatures for the input.
pub fn count_musig2_partial_sigs(psbt: &Psbt, input_index: usize) -> Result<usize, PsbtError> {
    if input_index >= psbt.inputs.len() {
        return Err(PsbtError::InputIndexOutOfBounds(input_index));
    }

    let count = psbt.inputs[input_index]
        .proprietary
        .keys()
        .filter(|k| k.prefix == MUSIG2_PREFIX && k.subtype == musig2_subtypes::PARTIAL_SIG)
        .count();

    Ok(count)
}

/// Count FROST partial signatures for an input.
///
/// # Arguments
///
/// * `psbt` - The PSBT to check
/// * `input_index` - The index of the input
///
/// # Returns
///
/// The number of FROST partial signatures for the input.
pub fn count_frost_partial_sigs(psbt: &Psbt, input_index: usize) -> Result<usize, PsbtError> {
    if input_index >= psbt.inputs.len() {
        return Err(PsbtError::InputIndexOutOfBounds(input_index));
    }

    let count = psbt.inputs[input_index]
        .proprietary
        .keys()
        .filter(|k| k.prefix == FROST_PREFIX && k.subtype == frost_subtypes::PARTIAL_SIG)
        .count();

    Ok(count)
}


/// Finalize a PSBT with threshold signatures (MuSig2 or FROST).
///
/// This function aggregates partial signatures and creates the final Schnorr signature
/// for Taproot inputs. It validates that sufficient partial signatures exist before
/// finalization.
///
/// # Arguments
///
/// * `psbt` - The PSBT to finalize
/// * `input_index` - The index of the input to finalize
/// * `required_sigs` - The number of signatures required (n for MuSig2, t for FROST)
/// * `agg_nonce_r` - The aggregated nonce R point (x-only, 32 bytes) for MuSig2
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if finalization fails.
pub fn finalize_threshold_psbt(
    psbt: &mut Psbt,
    input_index: usize,
    required_sigs: usize,
    agg_nonce_r: &[u8; 32],
) -> Result<(), PsbtError> {
    if input_index >= psbt.inputs.len() {
        return Err(PsbtError::InputIndexOutOfBounds(input_index));
    }

    if psbt.inputs[input_index].is_finalized() {
        return Err(PsbtError::AlreadyFinalized);
    }

    // Try MuSig2 first
    let musig2_sigs = get_musig2_partial_sigs(psbt, input_index)?;
    if !musig2_sigs.is_empty() {
        return finalize_musig2_input(psbt, input_index, required_sigs, agg_nonce_r, &musig2_sigs);
    }

    // Try FROST
    let frost_sigs = get_frost_partial_sigs(psbt, input_index)?;
    if !frost_sigs.is_empty() {
        return finalize_frost_input(psbt, input_index, required_sigs, agg_nonce_r, &frost_sigs);
    }

    Err(PsbtError::CannotSign(
        "No MuSig2 or FROST partial signatures found".into(),
    ))
}

/// Finalize a MuSig2 input by aggregating partial signatures.
fn finalize_musig2_input(
    psbt: &mut Psbt,
    input_index: usize,
    required_sigs: usize,
    agg_nonce_r: &[u8; 32],
    partial_sigs: &[([u8; 32], MuSig2PartialSignature)],
) -> Result<(), PsbtError> {
    if partial_sigs.len() < required_sigs {
        return Err(PsbtError::CannotSign(format!(
            "MuSig2 requires {} signatures, got {}",
            required_sigs,
            partial_sigs.len()
        )));
    }

    // Aggregate partial signatures: s = s1 + s2 + ... + sn
    let mut s_sum = [0u8; 32];
    for (_, partial) in partial_sigs {
        s_sum = scalar_add(&s_sum, &partial.s)?;
    }

    // Create final Schnorr signature: (R, s)
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(agg_nonce_r);
    signature.extend_from_slice(&s_sum);

    // Set as Taproot key signature
    psbt.inputs[input_index].tap_key_sig = Some(signature.clone());

    // Create witness: just the signature for key path spend
    let witness = crate::input::Witness::from_items(vec![signature]);
    psbt.inputs[input_index].final_script_witness = Some(witness);

    // Clear partial signatures and other non-final fields
    clear_threshold_fields(&mut psbt.inputs[input_index]);

    Ok(())
}

/// Finalize a FROST input by aggregating partial signatures.
fn finalize_frost_input(
    psbt: &mut Psbt,
    input_index: usize,
    required_sigs: usize,
    agg_nonce_r: &[u8; 32],
    partial_sigs: &[(FrostIdentifier, FrostSignatureShare)],
) -> Result<(), PsbtError> {
    if partial_sigs.len() < required_sigs {
        return Err(PsbtError::CannotSign(format!(
            "FROST requires {} signatures, got {}",
            required_sigs,
            partial_sigs.len()
        )));
    }

    // Aggregate partial signatures: z = z1 + z2 + ... + zt
    let mut z_sum = [0u8; 32];
    for (_, share) in partial_sigs {
        z_sum = scalar_add(&z_sum, &share.share)?;
    }

    // Create final Schnorr signature: (R, z)
    let mut signature = Vec::with_capacity(64);
    signature.extend_from_slice(agg_nonce_r);
    signature.extend_from_slice(&z_sum);

    // Set as Taproot key signature
    psbt.inputs[input_index].tap_key_sig = Some(signature.clone());

    // Create witness: just the signature for key path spend
    let witness = crate::input::Witness::from_items(vec![signature]);
    psbt.inputs[input_index].final_script_witness = Some(witness);

    // Clear partial signatures and other non-final fields
    clear_threshold_fields(&mut psbt.inputs[input_index]);

    Ok(())
}

/// Clear threshold-related fields after finalization.
fn clear_threshold_fields(input: &mut crate::input::InputMap) {
    input.proprietary.retain(|k, _| {
        !(k.prefix == MUSIG2_PREFIX || k.prefix == FROST_PREFIX)
    });

    input.partial_sigs.clear();
    input.sighash_type = None;
    input.bip32_derivation.clear();
    input.tap_script_sigs.clear();
    input.tap_leaf_scripts.clear();
    input.tap_bip32_derivation.clear();
}

/// Scalar addition modulo secp256k1 curve order.
fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], PsbtError> {
    use secp256k1::SecretKey;

    let is_a_zero = a.iter().all(|&x| x == 0);
    if is_a_zero {
        return Ok(*b);
    }

    let is_b_zero = b.iter().all(|&x| x == 0);
    if is_b_zero {
        return Ok(*a);
    }

    let sk_a = SecretKey::from_slice(a)
        .map_err(|_| PsbtError::InvalidSignature)?;
    let sk_b = SecretKey::from_slice(b)
        .map_err(|_| PsbtError::InvalidSignature)?;

    let result = sk_a
        .add_tweak(&sk_b.into())
        .map_err(|_| PsbtError::InvalidSignature)?;

    Ok(result.secret_bytes())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::InputMap;
    use crate::output::OutputMap;
    use crate::global::GlobalMap;

    fn create_test_psbt() -> Psbt {
        Psbt {
            global: GlobalMap::with_unsigned_tx(vec![
                0x02, 0x00, 0x00, 0x00, // version
                0x01, // 1 input
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // txid
                0x00, 0x00, 0x00, 0x00, // vout
                0x00, // empty script
                0xff, 0xff, 0xff, 0xff, // sequence
                0x01, // 1 output
                0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, // value
                0x22, // script length (P2TR)
                0x51, 0x20, // OP_1 PUSH32
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // x-only pubkey
                0x00, 0x00, 0x00, 0x00, // locktime
            ]),
            inputs: vec![InputMap::new()],
            outputs: vec![OutputMap::new()],
        }
    }

    #[test]
    fn test_psbt_musig2_partial_sig_roundtrip() {
        let pubkey = [1u8; 32];
        let partial_sig = MuSig2PartialSignature {
            s: [2u8; 32],
            signer_index: 0,
        };

        let psbt_sig = PsbtMuSig2PartialSig::from_partial_sig(&partial_sig, pubkey);
        let bytes = psbt_sig.to_bytes();
        let recovered = PsbtMuSig2PartialSig::from_bytes(&bytes).unwrap();

        assert_eq!(psbt_sig, recovered);
        assert_eq!(recovered.pubkey, pubkey);
        assert_eq!(recovered.partial_sig, partial_sig.s);
    }

    #[test]
    fn test_psbt_frost_partial_sig_roundtrip() {
        let identifier = FrostIdentifier::new(1).unwrap();
        let share = [3u8; 32];

        let psbt_sig = PsbtFrostPartialSig {
            identifier,
            share,
        };

        let bytes = psbt_sig.to_bytes();
        let recovered = PsbtFrostPartialSig::from_bytes(&bytes).unwrap();

        assert_eq!(psbt_sig, recovered);
    }

    #[test]
    fn test_add_musig2_partial_sig() {
        let mut psbt = create_test_psbt();
        let pubkey = [1u8; 32];
        let partial_sig = MuSig2PartialSignature {
            s: [2u8; 32],
            signer_index: 0,
        };

        add_musig2_partial_sig(&mut psbt, 0, &partial_sig, &pubkey).unwrap();

        let sigs = get_musig2_partial_sigs(&psbt, 0).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].0, pubkey);
        assert_eq!(sigs[0].1.s, partial_sig.s);
    }

    #[test]
    fn test_add_frost_partial_sig() {
        let mut psbt = create_test_psbt();
        let identifier = FrostIdentifier::new(1).unwrap();
        let share = FrostSignatureShare::new(identifier, [3u8; 32]);

        add_frost_partial_sig(&mut psbt, 0, &share, &identifier).unwrap();

        let sigs = get_frost_partial_sigs(&psbt, 0).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].0, identifier);
        assert_eq!(sigs[0].1.share, share.share);
    }

    #[test]
    fn test_add_multiple_musig2_sigs() {
        let mut psbt = create_test_psbt();

        let pubkey1 = [1u8; 32];
        let partial1 = MuSig2PartialSignature {
            s: [2u8; 32],
            signer_index: 0,
        };

        let pubkey2 = [3u8; 32];
        let partial2 = MuSig2PartialSignature {
            s: [4u8; 32],
            signer_index: 1,
        };

        add_musig2_partial_sig(&mut psbt, 0, &partial1, &pubkey1).unwrap();
        add_musig2_partial_sig(&mut psbt, 0, &partial2, &pubkey2).unwrap();

        let count = count_musig2_partial_sigs(&psbt, 0).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_combine_musig2_psbt() {
        let mut psbt1 = create_test_psbt();
        let mut psbt2 = create_test_psbt();

        let pubkey1 = [1u8; 32];
        let partial1 = MuSig2PartialSignature {
            s: [2u8; 32],
            signer_index: 0,
        };

        let pubkey2 = [3u8; 32];
        let partial2 = MuSig2PartialSignature {
            s: [4u8; 32],
            signer_index: 1,
        };

        add_musig2_partial_sig(&mut psbt1, 0, &partial1, &pubkey1).unwrap();
        add_musig2_partial_sig(&mut psbt2, 0, &partial2, &pubkey2).unwrap();

        let combined = combine_musig2_psbt(&[psbt1, psbt2]).unwrap();

        let count = count_musig2_partial_sigs(&combined, 0).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_input_index_out_of_bounds() {
        let mut psbt = create_test_psbt();
        let pubkey = [1u8; 32];
        let partial_sig = MuSig2PartialSignature {
            s: [2u8; 32],
            signer_index: 0,
        };

        let result = add_musig2_partial_sig(&mut psbt, 5, &partial_sig, &pubkey);
        assert!(matches!(result, Err(PsbtError::InputIndexOutOfBounds(5))));
    }

    #[test]
    fn test_scalar_add() {
        let a = [0u8; 32];
        let b = [1u8; 32];
        let result = scalar_add(&a, &b).unwrap();
        assert_eq!(result, b);

        let mut c = [0u8; 32];
        c[31] = 1;
        let mut d = [0u8; 32];
        d[31] = 2;
        let result = scalar_add(&c, &d).unwrap();
        assert_eq!(result[31], 3);
    }
}
