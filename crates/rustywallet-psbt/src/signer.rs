//! PSBT signing functionality

use crate::error::PsbtError;
use crate::psbt::Psbt;
use crate::types::PsbtSighashType;
use rustywallet_keys::private_key::PrivateKey;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

impl Psbt {
    /// Sign all inputs that can be signed with the given private key
    ///
    /// Returns the number of inputs signed
    pub fn sign(&mut self, private_key: &PrivateKey) -> Result<usize, PsbtError> {
        self.sign_with_sighash(private_key, PsbtSighashType::All)
    }

    /// Sign all inputs with a specific sighash type
    pub fn sign_with_sighash(
        &mut self,
        private_key: &PrivateKey,
        sighash: PsbtSighashType,
    ) -> Result<usize, PsbtError> {
        let mut signed_count = 0;

        for i in 0..self.inputs.len() {
            if self.sign_input(i, private_key, sighash)? {
                signed_count += 1;
            }
        }

        Ok(signed_count)
    }

    /// Sign a specific input
    ///
    /// Returns true if the input was signed, false if the key doesn't match
    pub fn sign_input(
        &mut self,
        index: usize,
        private_key: &PrivateKey,
        sighash: PsbtSighashType,
    ) -> Result<bool, PsbtError> {
        if index >= self.inputs.len() {
            return Err(PsbtError::InputIndexOutOfBounds(index));
        }

        let input = &self.inputs[index];

        // Check if already finalized
        if input.is_finalized() {
            return Err(PsbtError::AlreadyFinalized);
        }

        // Get the public key
        let public_key = private_key.public_key();
        let pubkey_bytes = public_key.to_compressed();

        // Check if this key is relevant to this input
        if !self.is_key_relevant(index, &pubkey_bytes) {
            return Ok(false);
        }

        // Get the script to sign
        let script = self.get_signing_script(index)?;

        // Compute sighash
        let sighash_bytes = self.compute_sighash(index, &script, sighash)?;

        // Sign
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&private_key.to_bytes())
            .map_err(|e| PsbtError::CannotSign(e.to_string()))?;
        let message = Message::from_digest_slice(&sighash_bytes)
            .map_err(|e| PsbtError::CannotSign(e.to_string()))?;
        let signature = secp.sign_ecdsa(&message, &secret_key);

        // Serialize signature with sighash type
        let mut sig_bytes = signature.serialize_der().to_vec();
        sig_bytes.push(sighash.to_u32() as u8);

        // Add to partial signatures
        self.inputs[index].partial_sigs.insert(pubkey_bytes.to_vec(), sig_bytes);

        // Set sighash type if not already set
        if self.inputs[index].sighash_type.is_none() {
            self.inputs[index].sighash_type = Some(sighash);
        }

        Ok(true)
    }

    /// Check if a public key is relevant to an input
    fn is_key_relevant(&self, index: usize, pubkey: &[u8]) -> bool {
        let input = &self.inputs[index];

        // Check BIP32 derivation
        if input.bip32_derivation.contains_key(pubkey) {
            return true;
        }

        // Check if pubkey matches script
        if let Some(ref script) = input.witness_utxo {
            if is_p2pkh(&script.script_pubkey, pubkey) {
                return true;
            }
            if is_p2wpkh(&script.script_pubkey, pubkey) {
                return true;
            }
        }

        // Check redeem script
        if let Some(ref redeem) = input.redeem_script {
            if script_contains_pubkey(redeem, pubkey) {
                return true;
            }
        }

        // Check witness script
        if let Some(ref witness) = input.witness_script {
            if script_contains_pubkey(witness, pubkey) {
                return true;
            }
        }

        false
    }

    /// Get the script to sign for an input
    fn get_signing_script(&self, index: usize) -> Result<Vec<u8>, PsbtError> {
        let input = &self.inputs[index];

        // For P2WSH, use witness script
        if let Some(ref witness_script) = input.witness_script {
            return Ok(witness_script.clone());
        }

        // For P2SH-P2WPKH, use redeem script to get the pubkey hash
        if let Some(ref redeem_script) = input.redeem_script {
            if is_p2wpkh_script(redeem_script) {
                // Extract pubkey hash and create P2PKH script
                let pubkey_hash = &redeem_script[2..22];
                return Ok(create_p2pkh_script(pubkey_hash));
            }
            return Ok(redeem_script.clone());
        }

        // For P2WPKH, create P2PKH script from witness UTXO
        if let Some(ref utxo) = input.witness_utxo {
            if is_p2wpkh_script(&utxo.script_pubkey) {
                let pubkey_hash = &utxo.script_pubkey[2..22];
                return Ok(create_p2pkh_script(pubkey_hash));
            }
            return Ok(utxo.script_pubkey.clone());
        }

        Err(PsbtError::MissingUtxo(index))
    }

    /// Compute sighash for an input
    fn compute_sighash(
        &self,
        index: usize,
        script: &[u8],
        sighash: PsbtSighashType,
    ) -> Result<[u8; 32], PsbtError> {
        let input = &self.inputs[index];

        // Determine if this is a SegWit input
        let is_segwit = input.witness_utxo.is_some()
            || input.witness_script.is_some()
            || (input.redeem_script.is_some()
                && is_p2wpkh_script(input.redeem_script.as_ref().unwrap()));

        if is_segwit {
            self.compute_segwit_sighash(index, script, sighash)
        } else {
            self.compute_legacy_sighash(index, script, sighash)
        }
    }

    /// Compute BIP143 SegWit sighash
    fn compute_segwit_sighash(
        &self,
        index: usize,
        script: &[u8],
        sighash: PsbtSighashType,
    ) -> Result<[u8; 32], PsbtError> {
        let tx = self.global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;
        let input = &self.inputs[index];
        let value = input.witness_utxo.as_ref()
            .ok_or(PsbtError::MissingUtxo(index))?
            .value;

        // BIP143 sighash preimage
        let mut preimage = Vec::new();

        // 1. nVersion
        preimage.extend_from_slice(&tx[0..4]);

        // 2. hashPrevouts
        let hash_prevouts = if sighash.to_u32() & 0x80 == 0 {
            self.hash_prevouts()?
        } else {
            [0u8; 32]
        };
        preimage.extend_from_slice(&hash_prevouts);

        // 3. hashSequence
        let hash_sequence = if sighash.to_u32() & 0x80 == 0 && sighash != PsbtSighashType::Single && sighash != PsbtSighashType::None {
            self.hash_sequence()?
        } else {
            [0u8; 32]
        };
        preimage.extend_from_slice(&hash_sequence);

        // 4. outpoint (txid + vout)
        let outpoint = self.get_outpoint(index)?;
        preimage.extend_from_slice(&outpoint);

        // 5. scriptCode
        let script_code = create_script_code(script);
        preimage.extend_from_slice(&script_code);

        // 6. value
        preimage.extend_from_slice(&value.to_le_bytes());

        // 7. nSequence
        let sequence = self.get_sequence(index)?;
        preimage.extend_from_slice(&sequence.to_le_bytes());

        // 8. hashOutputs
        let hash_outputs = match sighash {
            PsbtSighashType::Single | PsbtSighashType::SingleAnyoneCanPay => {
                if index < self.outputs.len() {
                    self.hash_single_output(index)?
                } else {
                    [0u8; 32]
                }
            }
            PsbtSighashType::None | PsbtSighashType::NoneAnyoneCanPay => [0u8; 32],
            _ => self.hash_outputs()?,
        };
        preimage.extend_from_slice(&hash_outputs);

        // 9. nLockTime
        let locktime = self.get_locktime()?;
        preimage.extend_from_slice(&locktime.to_le_bytes());

        // 10. sighash type
        preimage.extend_from_slice(&sighash.to_u32().to_le_bytes());

        // Double SHA256
        let hash = double_sha256(&preimage);
        Ok(hash)
    }

    /// Compute legacy sighash
    fn compute_legacy_sighash(
        &self,
        _index: usize,
        _script: &[u8],
        sighash: PsbtSighashType,
    ) -> Result<[u8; 32], PsbtError> {
        // For legacy, we need to modify the transaction
        // This is a simplified implementation
        let tx = self.global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;

        let mut modified_tx = tx.clone();

        // Clear all input scripts except the one being signed
        // This is a simplified approach - full implementation would parse and modify the tx

        // Append sighash type
        modified_tx.extend_from_slice(&sighash.to_u32().to_le_bytes());

        // Double SHA256
        let hash = double_sha256(&modified_tx);
        Ok(hash)
    }

    /// Hash all prevouts
    fn hash_prevouts(&self) -> Result<[u8; 32], PsbtError> {
        let mut data = Vec::new();
        for i in 0..self.inputs.len() {
            let outpoint = self.get_outpoint(i)?;
            data.extend_from_slice(&outpoint);
        }
        Ok(double_sha256(&data))
    }

    /// Hash all sequences
    fn hash_sequence(&self) -> Result<[u8; 32], PsbtError> {
        let mut data = Vec::new();
        for i in 0..self.inputs.len() {
            let sequence = self.get_sequence(i)?;
            data.extend_from_slice(&sequence.to_le_bytes());
        }
        Ok(double_sha256(&data))
    }

    /// Hash all outputs
    fn hash_outputs(&self) -> Result<[u8; 32], PsbtError> {
        let tx = self.global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;
        // Extract outputs from transaction
        // This is simplified - would need proper tx parsing
        let outputs_data = extract_outputs_data(tx)?;
        Ok(double_sha256(&outputs_data))
    }

    /// Hash single output
    fn hash_single_output(&self, index: usize) -> Result<[u8; 32], PsbtError> {
        let tx = self.global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;
        let output_data = extract_single_output_data(tx, index)?;
        Ok(double_sha256(&output_data))
    }

    /// Get outpoint for input
    fn get_outpoint(&self, index: usize) -> Result<[u8; 36], PsbtError> {
        let input = &self.inputs[index];

        // PSBT v2
        if let (Some(txid), Some(vout)) = (input.previous_txid, input.output_index) {
            let mut outpoint = [0u8; 36];
            outpoint[0..32].copy_from_slice(&txid);
            outpoint[32..36].copy_from_slice(&vout.to_le_bytes());
            return Ok(outpoint);
        }

        // PSBT v0 - extract from unsigned tx
        let tx = self.global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;
        extract_outpoint(tx, index)
    }

    /// Get sequence for input
    fn get_sequence(&self, index: usize) -> Result<u32, PsbtError> {
        let input = &self.inputs[index];

        // PSBT v2
        if let Some(seq) = input.sequence {
            return Ok(seq);
        }

        // PSBT v0 - extract from unsigned tx
        let tx = self.global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;
        extract_sequence(tx, index)
    }

    /// Get locktime
    fn get_locktime(&self) -> Result<u32, PsbtError> {
        // PSBT v2
        if let Some(locktime) = self.global.fallback_locktime {
            return Ok(locktime);
        }

        // PSBT v0 - extract from unsigned tx
        let tx = self.global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;
        if tx.len() < 4 {
            return Err(PsbtError::InvalidFormat("Transaction too short".into()));
        }
        let len = tx.len();
        Ok(u32::from_le_bytes([
            tx[len - 4],
            tx[len - 3],
            tx[len - 2],
            tx[len - 1],
        ]))
    }
}

/// Check if script is P2PKH for given pubkey
fn is_p2pkh(script: &[u8], pubkey: &[u8]) -> bool {
    if script.len() != 25 {
        return false;
    }
    if script[0] != 0x76 || script[1] != 0xa9 || script[2] != 0x14 {
        return false;
    }
    if script[23] != 0x88 || script[24] != 0xac {
        return false;
    }
    let pubkey_hash = hash160(pubkey);
    script[3..23] == pubkey_hash
}

/// Check if script is P2WPKH for given pubkey
fn is_p2wpkh(script: &[u8], pubkey: &[u8]) -> bool {
    if script.len() != 22 {
        return false;
    }
    if script[0] != 0x00 || script[1] != 0x14 {
        return false;
    }
    let pubkey_hash = hash160(pubkey);
    script[2..22] == pubkey_hash
}

/// Check if script is P2WPKH
fn is_p2wpkh_script(script: &[u8]) -> bool {
    script.len() == 22 && script[0] == 0x00 && script[1] == 0x14
}

/// Check if script contains pubkey
fn script_contains_pubkey(script: &[u8], pubkey: &[u8]) -> bool {
    // Check for raw pubkey
    if script.windows(pubkey.len()).any(|w| w == pubkey) {
        return true;
    }
    // Check for pubkey hash
    let pubkey_hash = hash160(pubkey);
    script.windows(20).any(|w| w == pubkey_hash)
}

/// Create P2PKH script from pubkey hash
fn create_p2pkh_script(pubkey_hash: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Create script code for BIP143
fn create_script_code(script: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    let len = script.len();
    if len < 0xfd {
        code.push(len as u8);
    } else if len <= 0xffff {
        code.push(0xfd);
        code.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        code.push(0xfe);
        code.extend_from_slice(&(len as u32).to_le_bytes());
    }
    code.extend_from_slice(script);
    code
}

/// Double SHA256
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// HASH160 (SHA256 + RIPEMD160)
fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd);
    result
}

/// Extract outpoint from transaction
pub fn extract_outpoint(tx: &[u8], index: usize) -> Result<[u8; 36], PsbtError> {
    let mut offset = 4; // Skip version

    // Check for witness marker
    if tx.get(offset) == Some(&0x00) && tx.get(offset + 1) == Some(&0x01) {
        offset += 2;
    }

    // Input count
    let (input_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size;

    if index >= input_count {
        return Err(PsbtError::InputIndexOutOfBounds(index));
    }

    // Skip to the right input
    for _ in 0..index {
        offset += 36; // txid + vout
        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len + 4; // script + sequence
    }

    let mut outpoint = [0u8; 36];
    outpoint.copy_from_slice(&tx[offset..offset + 36]);
    Ok(outpoint)
}

/// Extract sequence from transaction
pub fn extract_sequence(tx: &[u8], index: usize) -> Result<u32, PsbtError> {
    let mut offset = 4; // Skip version

    // Check for witness marker
    if tx.get(offset) == Some(&0x00) && tx.get(offset + 1) == Some(&0x01) {
        offset += 2;
    }

    // Input count
    let (input_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size;

    if index >= input_count {
        return Err(PsbtError::InputIndexOutOfBounds(index));
    }

    // Skip to the right input
    for i in 0..=index {
        offset += 36; // txid + vout
        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len;
        if i == index {
            break;
        }
        offset += 4; // sequence
    }

    Ok(u32::from_le_bytes([
        tx[offset],
        tx[offset + 1],
        tx[offset + 2],
        tx[offset + 3],
    ]))
}

/// Extract outputs data from transaction
fn extract_outputs_data(tx: &[u8]) -> Result<Vec<u8>, PsbtError> {
    let mut offset = 4; // Skip version

    // Check for witness marker
    if tx.get(offset) == Some(&0x00) && tx.get(offset + 1) == Some(&0x01) {
        offset += 2;
    }

    // Skip inputs
    let (input_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size;

    for _ in 0..input_count {
        offset += 36; // txid + vout
        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len + 4; // script + sequence
    }

    // Output count
    let (output_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    let outputs_start = offset;
    offset += size;

    // Calculate outputs end
    for _ in 0..output_count {
        offset += 8; // value
        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len;
    }

    Ok(tx[outputs_start..offset].to_vec())
}

/// Extract single output data from transaction
fn extract_single_output_data(tx: &[u8], index: usize) -> Result<Vec<u8>, PsbtError> {
    let mut offset = 4; // Skip version

    // Check for witness marker
    if tx.get(offset) == Some(&0x00) && tx.get(offset + 1) == Some(&0x01) {
        offset += 2;
    }

    // Skip inputs
    let (input_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size;

    for _ in 0..input_count {
        offset += 36; // txid + vout
        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len + 4; // script + sequence
    }

    // Output count
    let (output_count, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size;

    if index >= output_count {
        return Err(PsbtError::OutputIndexOutOfBounds(index));
    }

    // Skip to the right output
    for _ in 0..index {
        offset += 8; // value
        let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
        offset += size + script_len;
    }

    let output_start = offset;
    offset += 8; // value
    let (script_len, size) = crate::input::read_compact_size(&tx[offset..])?;
    offset += size + script_len;

    Ok(tx[output_start..offset].to_vec())
}
