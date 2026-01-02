//! PSBT serialization and deserialization

use crate::error::PsbtError;
use crate::global::GlobalMap;
use crate::input::{read_compact_size, write_compact_size, InputMap, TxOut, Witness};
use crate::output::OutputMap;
use crate::psbt::Psbt;
use crate::types::*;

/// Serialize PSBT to bytes
pub fn serialize(psbt: &Psbt) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Magic bytes
    bytes.extend_from_slice(&PSBT_MAGIC);

    // Global map
    serialize_global(&mut bytes, &psbt.global);

    // Input maps
    for input in &psbt.inputs {
        serialize_input(&mut bytes, input);
    }

    // Output maps
    for output in &psbt.outputs {
        serialize_output(&mut bytes, output);
    }

    bytes
}

/// Serialize global map
fn serialize_global(bytes: &mut Vec<u8>, global: &GlobalMap) {
    // Unsigned transaction
    if let Some(ref tx) = global.unsigned_tx {
        write_key_value(bytes, PSBT_GLOBAL_UNSIGNED_TX, &[], tx);
    }

    // Extended public keys
    for xpub_entry in &global.xpubs {
        write_key_value(
            bytes,
            PSBT_GLOBAL_XPUB,
            &xpub_entry.xpub,
            &xpub_entry.key_source.to_bytes(),
        );
    }

    // PSBT v2 fields
    if let Some(tx_version) = global.tx_version {
        write_key_value(bytes, PSBT_GLOBAL_TX_VERSION, &[], &tx_version.to_le_bytes());
    }

    if let Some(locktime) = global.fallback_locktime {
        write_key_value(bytes, PSBT_GLOBAL_FALLBACK_LOCKTIME, &[], &locktime.to_le_bytes());
    }

    if let Some(count) = global.input_count {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, count as usize);
        write_key_value(bytes, PSBT_GLOBAL_INPUT_COUNT, &[], &buf);
    }

    if let Some(count) = global.output_count {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, count as usize);
        write_key_value(bytes, PSBT_GLOBAL_OUTPUT_COUNT, &[], &buf);
    }

    if let Some(modifiable) = global.tx_modifiable {
        write_key_value(bytes, PSBT_GLOBAL_TX_MODIFIABLE, &[], &[modifiable]);
    }

    // Version
    if let Some(version) = global.version {
        write_key_value(bytes, PSBT_GLOBAL_VERSION, &[], &version.to_le_bytes());
    }

    // Proprietary fields
    for (key, value) in &global.proprietary {
        let key_bytes = key.to_bytes();
        write_key_value(bytes, PSBT_GLOBAL_PROPRIETARY, &key_bytes, value);
    }

    // Unknown fields
    for (key, value) in &global.unknown {
        write_key_value(bytes, key.key_type, &key.key_data, value);
    }

    // Map separator
    bytes.push(PSBT_SEPARATOR);
}

/// Serialize input map
fn serialize_input(bytes: &mut Vec<u8>, input: &InputMap) {
    // Non-witness UTXO
    if let Some(ref utxo) = input.non_witness_utxo {
        write_key_value(bytes, PSBT_IN_NON_WITNESS_UTXO, &[], utxo);
    }

    // Witness UTXO
    if let Some(ref utxo) = input.witness_utxo {
        write_key_value(bytes, PSBT_IN_WITNESS_UTXO, &[], &utxo.to_bytes());
    }

    // Partial signatures
    for (pubkey, sig) in &input.partial_sigs {
        write_key_value(bytes, PSBT_IN_PARTIAL_SIG, pubkey, sig);
    }

    // Sighash type
    if let Some(sighash) = input.sighash_type {
        write_key_value(bytes, PSBT_IN_SIGHASH_TYPE, &[], &sighash.to_u32().to_le_bytes());
    }

    // Redeem script
    if let Some(ref script) = input.redeem_script {
        write_key_value(bytes, PSBT_IN_REDEEM_SCRIPT, &[], script);
    }

    // Witness script
    if let Some(ref script) = input.witness_script {
        write_key_value(bytes, PSBT_IN_WITNESS_SCRIPT, &[], script);
    }

    // BIP32 derivation
    for (pubkey, source) in &input.bip32_derivation {
        write_key_value(bytes, PSBT_IN_BIP32_DERIVATION, pubkey, &source.to_bytes());
    }

    // Final scriptSig
    if let Some(ref script) = input.final_script_sig {
        write_key_value(bytes, PSBT_IN_FINAL_SCRIPTSIG, &[], script);
    }

    // Final witness
    if let Some(ref witness) = input.final_script_witness {
        write_key_value(bytes, PSBT_IN_FINAL_SCRIPTWITNESS, &[], &witness.to_bytes());
    }

    // Taproot key signature
    if let Some(ref sig) = input.tap_key_sig {
        write_key_value(bytes, PSBT_IN_TAP_KEY_SIG, &[], sig);
    }

    // Taproot script signatures
    for (key, sig) in &input.tap_script_sigs {
        write_key_value(bytes, PSBT_IN_TAP_SCRIPT_SIG, key, sig);
    }

    // Taproot leaf scripts
    for (control_block, script) in &input.tap_leaf_scripts {
        write_key_value(bytes, PSBT_IN_TAP_LEAF_SCRIPT, control_block, script);
    }

    // Taproot BIP32 derivation
    for (pubkey, derivation) in &input.tap_bip32_derivation {
        write_key_value(bytes, PSBT_IN_TAP_BIP32_DERIVATION, pubkey, derivation);
    }

    // Taproot internal key
    if let Some(ref key) = input.tap_internal_key {
        write_key_value(bytes, PSBT_IN_TAP_INTERNAL_KEY, &[], key);
    }

    // Taproot merkle root
    if let Some(ref root) = input.tap_merkle_root {
        write_key_value(bytes, PSBT_IN_TAP_MERKLE_ROOT, &[], root);
    }

    // PSBT v2 fields
    if let Some(txid) = input.previous_txid {
        write_key_value(bytes, PSBT_IN_PREVIOUS_TXID, &[], &txid);
    }

    if let Some(index) = input.output_index {
        write_key_value(bytes, PSBT_IN_OUTPUT_INDEX, &[], &index.to_le_bytes());
    }

    if let Some(seq) = input.sequence {
        write_key_value(bytes, PSBT_IN_SEQUENCE, &[], &seq.to_le_bytes());
    }

    if let Some(locktime) = input.required_time_locktime {
        write_key_value(bytes, PSBT_IN_REQUIRED_TIME_LOCKTIME, &[], &locktime.to_le_bytes());
    }

    if let Some(locktime) = input.required_height_locktime {
        write_key_value(bytes, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, &[], &locktime.to_le_bytes());
    }

    // Proprietary fields
    for (key, value) in &input.proprietary {
        let key_bytes = key.to_bytes();
        write_key_value(bytes, PSBT_IN_PROPRIETARY, &key_bytes, value);
    }

    // Unknown fields
    for (key, value) in &input.unknown {
        write_key_value(bytes, key.key_type, &key.key_data, value);
    }

    // Map separator
    bytes.push(PSBT_SEPARATOR);
}

/// Serialize output map
fn serialize_output(bytes: &mut Vec<u8>, output: &OutputMap) {
    // Redeem script
    if let Some(ref script) = output.redeem_script {
        write_key_value(bytes, PSBT_OUT_REDEEM_SCRIPT, &[], script);
    }

    // Witness script
    if let Some(ref script) = output.witness_script {
        write_key_value(bytes, PSBT_OUT_WITNESS_SCRIPT, &[], script);
    }

    // BIP32 derivation
    for (pubkey, source) in &output.bip32_derivation {
        write_key_value(bytes, PSBT_OUT_BIP32_DERIVATION, pubkey, &source.to_bytes());
    }

    // PSBT v2 fields
    if let Some(amount) = output.amount {
        write_key_value(bytes, PSBT_OUT_AMOUNT, &[], &amount.to_le_bytes());
    }

    if let Some(ref script) = output.script {
        write_key_value(bytes, PSBT_OUT_SCRIPT, &[], script);
    }

    // Taproot internal key
    if let Some(ref key) = output.tap_internal_key {
        write_key_value(bytes, PSBT_OUT_TAP_INTERNAL_KEY, &[], key);
    }

    // Taproot tree
    if let Some(ref tree) = output.tap_tree {
        write_key_value(bytes, PSBT_OUT_TAP_TREE, &[], tree);
    }

    // Taproot BIP32 derivation
    for (pubkey, derivation) in &output.tap_bip32_derivation {
        write_key_value(bytes, PSBT_OUT_TAP_BIP32_DERIVATION, pubkey, derivation);
    }

    // Proprietary fields
    for (key, value) in &output.proprietary {
        let key_bytes = key.to_bytes();
        write_key_value(bytes, PSBT_OUT_PROPRIETARY, &key_bytes, value);
    }

    // Unknown fields
    for (key, value) in &output.unknown {
        write_key_value(bytes, key.key_type, &key.key_data, value);
    }

    // Map separator
    bytes.push(PSBT_SEPARATOR);
}

/// Write a key-value pair
fn write_key_value(bytes: &mut Vec<u8>, key_type: u8, key_data: &[u8], value: &[u8]) {
    // Key length (type + data)
    let key_len = 1 + key_data.len();
    write_compact_size(bytes, key_len);

    // Key type
    bytes.push(key_type);

    // Key data
    bytes.extend_from_slice(key_data);

    // Value length
    write_compact_size(bytes, value.len());

    // Value
    bytes.extend_from_slice(value);
}

/// Deserialize PSBT from bytes
pub fn deserialize(bytes: &[u8]) -> Result<Psbt, PsbtError> {
    if bytes.len() < 5 {
        return Err(PsbtError::InvalidFormat("PSBT too short".into()));
    }

    // Check magic bytes
    if bytes[0..5] != PSBT_MAGIC {
        return Err(PsbtError::InvalidMagic);
    }

    let mut offset = 5;

    // Parse global map
    let (global, new_offset) = parse_global(&bytes[offset..])?;
    offset += new_offset;

    // Determine input/output counts
    let (input_count, output_count) = if global.is_v2() {
        let inputs = global.input_count.ok_or_else(|| {
            PsbtError::MissingField("input_count required for PSBT v2".into())
        })? as usize;
        let outputs = global.output_count.ok_or_else(|| {
            PsbtError::MissingField("output_count required for PSBT v2".into())
        })? as usize;
        (inputs, outputs)
    } else {
        // For v0, count from unsigned transaction
        let tx = global.unsigned_tx.as_ref().ok_or(PsbtError::NoUnsignedTx)?;
        count_tx_inputs_outputs(tx)?
    };

    // Parse input maps
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let (input, new_offset) = parse_input(&bytes[offset..])?;
        offset += new_offset;
        inputs.push(input);
    }

    // Parse output maps
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let (output, new_offset) = parse_output(&bytes[offset..])?;
        offset += new_offset;
        outputs.push(output);
    }

    Ok(Psbt {
        global,
        inputs,
        outputs,
    })
}

/// Parse global map
fn parse_global(bytes: &[u8]) -> Result<(GlobalMap, usize), PsbtError> {
    let mut global = GlobalMap::new();
    let mut offset = 0;

    loop {
        if offset >= bytes.len() {
            return Err(PsbtError::InvalidFormat("Unexpected end of global map".into()));
        }

        // Check for separator
        if bytes[offset] == PSBT_SEPARATOR {
            offset += 1;
            break;
        }

        // Read key
        let (key_len, size) = read_compact_size(&bytes[offset..])?;
        offset += size;

        if key_len == 0 {
            return Err(PsbtError::InvalidFormat("Empty key".into()));
        }

        if offset + key_len > bytes.len() {
            return Err(PsbtError::InvalidFormat("Key truncated".into()));
        }

        let key_type = bytes[offset];
        let key_data = bytes[offset + 1..offset + key_len].to_vec();
        offset += key_len;

        // Read value
        let (value_len, size) = read_compact_size(&bytes[offset..])?;
        offset += size;

        if offset + value_len > bytes.len() {
            return Err(PsbtError::InvalidFormat("Value truncated".into()));
        }

        let value = bytes[offset..offset + value_len].to_vec();
        offset += value_len;

        // Process key-value pair
        match key_type {
            PSBT_GLOBAL_UNSIGNED_TX => {
                if global.unsigned_tx.is_some() {
                    return Err(PsbtError::DuplicateKey);
                }
                global.unsigned_tx = Some(value);
            }
            PSBT_GLOBAL_XPUB => {
                if let Some(source) = KeySource::from_bytes(&value) {
                    global.xpubs.push(crate::global::XpubEntry {
                        xpub: key_data,
                        key_source: source,
                    });
                }
            }
            PSBT_GLOBAL_TX_VERSION => {
                if value.len() == 4 {
                    global.tx_version = Some(i32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                }
            }
            PSBT_GLOBAL_FALLBACK_LOCKTIME => {
                if value.len() == 4 {
                    global.fallback_locktime = Some(u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                }
            }
            PSBT_GLOBAL_INPUT_COUNT => {
                let (count, _) = read_compact_size(&value)?;
                global.input_count = Some(count as u64);
            }
            PSBT_GLOBAL_OUTPUT_COUNT => {
                let (count, _) = read_compact_size(&value)?;
                global.output_count = Some(count as u64);
            }
            PSBT_GLOBAL_TX_MODIFIABLE => {
                if !value.is_empty() {
                    global.tx_modifiable = Some(value[0]);
                }
            }
            PSBT_GLOBAL_VERSION => {
                if value.len() == 4 {
                    global.version = Some(u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                }
            }
            PSBT_GLOBAL_PROPRIETARY => {
                if let Some(prop_key) = ProprietaryKey::from_bytes(&key_data) {
                    global.proprietary.insert(prop_key, value);
                }
            }
            _ => {
                global.unknown.insert(RawKey::new(key_type, key_data), value);
            }
        }
    }

    Ok((global, offset))
}

/// Parse input map
fn parse_input(bytes: &[u8]) -> Result<(InputMap, usize), PsbtError> {
    let mut input = InputMap::new();
    let mut offset = 0;

    loop {
        if offset >= bytes.len() {
            return Err(PsbtError::InvalidFormat("Unexpected end of input map".into()));
        }

        // Check for separator
        if bytes[offset] == PSBT_SEPARATOR {
            offset += 1;
            break;
        }

        // Read key
        let (key_len, size) = read_compact_size(&bytes[offset..])?;
        offset += size;

        if key_len == 0 {
            return Err(PsbtError::InvalidFormat("Empty key".into()));
        }

        if offset + key_len > bytes.len() {
            return Err(PsbtError::InvalidFormat("Key truncated".into()));
        }

        let key_type = bytes[offset];
        let key_data = bytes[offset + 1..offset + key_len].to_vec();
        offset += key_len;

        // Read value
        let (value_len, size) = read_compact_size(&bytes[offset..])?;
        offset += size;

        if offset + value_len > bytes.len() {
            return Err(PsbtError::InvalidFormat("Value truncated".into()));
        }

        let value = bytes[offset..offset + value_len].to_vec();
        offset += value_len;

        // Process key-value pair
        match key_type {
            PSBT_IN_NON_WITNESS_UTXO => {
                input.non_witness_utxo = Some(value);
            }
            PSBT_IN_WITNESS_UTXO => {
                let (txout, _) = TxOut::from_bytes(&value)?;
                input.witness_utxo = Some(txout);
            }
            PSBT_IN_PARTIAL_SIG => {
                input.partial_sigs.insert(key_data, value);
            }
            PSBT_IN_SIGHASH_TYPE => {
                if value.len() == 4 {
                    let sighash_value = u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]);
                    input.sighash_type = PsbtSighashType::from_u32(sighash_value);
                }
            }
            PSBT_IN_REDEEM_SCRIPT => {
                input.redeem_script = Some(value);
            }
            PSBT_IN_WITNESS_SCRIPT => {
                input.witness_script = Some(value);
            }
            PSBT_IN_BIP32_DERIVATION => {
                if let Some(source) = KeySource::from_bytes(&value) {
                    input.bip32_derivation.insert(key_data, source);
                }
            }
            PSBT_IN_FINAL_SCRIPTSIG => {
                input.final_script_sig = Some(value);
            }
            PSBT_IN_FINAL_SCRIPTWITNESS => {
                input.final_script_witness = Some(Witness::from_bytes(&value)?);
            }
            PSBT_IN_TAP_KEY_SIG => {
                input.tap_key_sig = Some(value);
            }
            PSBT_IN_TAP_SCRIPT_SIG => {
                input.tap_script_sigs.insert(key_data, value);
            }
            PSBT_IN_TAP_LEAF_SCRIPT => {
                input.tap_leaf_scripts.insert(key_data, value);
            }
            PSBT_IN_TAP_BIP32_DERIVATION => {
                input.tap_bip32_derivation.insert(key_data, value);
            }
            PSBT_IN_TAP_INTERNAL_KEY => {
                input.tap_internal_key = Some(value);
            }
            PSBT_IN_TAP_MERKLE_ROOT => {
                input.tap_merkle_root = Some(value);
            }
            PSBT_IN_PREVIOUS_TXID => {
                if value.len() == 32 {
                    let mut txid = [0u8; 32];
                    txid.copy_from_slice(&value);
                    input.previous_txid = Some(txid);
                }
            }
            PSBT_IN_OUTPUT_INDEX => {
                if value.len() == 4 {
                    input.output_index = Some(u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                }
            }
            PSBT_IN_SEQUENCE => {
                if value.len() == 4 {
                    input.sequence = Some(u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                }
            }
            PSBT_IN_REQUIRED_TIME_LOCKTIME => {
                if value.len() == 4 {
                    input.required_time_locktime = Some(u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                }
            }
            PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => {
                if value.len() == 4 {
                    input.required_height_locktime = Some(u32::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                    ]));
                }
            }
            PSBT_IN_PROPRIETARY => {
                if let Some(prop_key) = ProprietaryKey::from_bytes(&key_data) {
                    input.proprietary.insert(prop_key, value);
                }
            }
            _ => {
                input.unknown.insert(RawKey::new(key_type, key_data), value);
            }
        }
    }

    Ok((input, offset))
}

/// Parse output map
fn parse_output(bytes: &[u8]) -> Result<(OutputMap, usize), PsbtError> {
    let mut output = OutputMap::new();
    let mut offset = 0;

    loop {
        if offset >= bytes.len() {
            return Err(PsbtError::InvalidFormat("Unexpected end of output map".into()));
        }

        // Check for separator
        if bytes[offset] == PSBT_SEPARATOR {
            offset += 1;
            break;
        }

        // Read key
        let (key_len, size) = read_compact_size(&bytes[offset..])?;
        offset += size;

        if key_len == 0 {
            return Err(PsbtError::InvalidFormat("Empty key".into()));
        }

        if offset + key_len > bytes.len() {
            return Err(PsbtError::InvalidFormat("Key truncated".into()));
        }

        let key_type = bytes[offset];
        let key_data = bytes[offset + 1..offset + key_len].to_vec();
        offset += key_len;

        // Read value
        let (value_len, size) = read_compact_size(&bytes[offset..])?;
        offset += size;

        if offset + value_len > bytes.len() {
            return Err(PsbtError::InvalidFormat("Value truncated".into()));
        }

        let value = bytes[offset..offset + value_len].to_vec();
        offset += value_len;

        // Process key-value pair
        match key_type {
            PSBT_OUT_REDEEM_SCRIPT => {
                output.redeem_script = Some(value);
            }
            PSBT_OUT_WITNESS_SCRIPT => {
                output.witness_script = Some(value);
            }
            PSBT_OUT_BIP32_DERIVATION => {
                if let Some(source) = KeySource::from_bytes(&value) {
                    output.bip32_derivation.insert(key_data, source);
                }
            }
            PSBT_OUT_AMOUNT => {
                if value.len() == 8 {
                    output.amount = Some(u64::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                        value[4], value[5], value[6], value[7],
                    ]));
                }
            }
            PSBT_OUT_SCRIPT => {
                output.script = Some(value);
            }
            PSBT_OUT_TAP_INTERNAL_KEY => {
                output.tap_internal_key = Some(value);
            }
            PSBT_OUT_TAP_TREE => {
                output.tap_tree = Some(value);
            }
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                output.tap_bip32_derivation.insert(key_data, value);
            }
            PSBT_OUT_PROPRIETARY => {
                if let Some(prop_key) = ProprietaryKey::from_bytes(&key_data) {
                    output.proprietary.insert(prop_key, value);
                }
            }
            _ => {
                output.unknown.insert(RawKey::new(key_type, key_data), value);
            }
        }
    }

    Ok((output, offset))
}

/// Count inputs and outputs from raw transaction bytes
fn count_tx_inputs_outputs(tx: &[u8]) -> Result<(usize, usize), PsbtError> {
    if tx.len() < 10 {
        return Err(PsbtError::InvalidFormat("Transaction too short".into()));
    }

    let mut offset = 4; // Skip version

    // Check for witness marker
    let has_witness = tx[offset] == 0x00 && tx.get(offset + 1) == Some(&0x01);
    if has_witness {
        offset += 2;
    }

    // Input count
    let (input_count, size) = read_compact_size(&tx[offset..])?;
    offset += size;

    // Skip inputs
    for _ in 0..input_count {
        offset += 36; // txid + vout
        let (script_len, size) = read_compact_size(&tx[offset..])?;
        offset += size + script_len + 4; // script + sequence
    }

    // Output count
    let (output_count, _) = read_compact_size(&tx[offset..])?;

    Ok((input_count, output_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_empty_psbt() {
        let psbt = Psbt {
            global: GlobalMap::with_unsigned_tx(vec![
                0x02, 0x00, 0x00, 0x00, // version
                0x00, // no inputs
                0x00, // no outputs
                0x00, 0x00, 0x00, 0x00, // locktime
            ]),
            inputs: vec![],
            outputs: vec![],
        };

        let bytes = serialize(&psbt);
        assert!(bytes.starts_with(&PSBT_MAGIC));

        let parsed = deserialize(&bytes).unwrap();
        assert_eq!(parsed.inputs.len(), 0);
        assert_eq!(parsed.outputs.len(), 0);
    }
}
