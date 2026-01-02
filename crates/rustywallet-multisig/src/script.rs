//! Multisig script generation.

use crate::config::MultisigConfig;

/// Bitcoin script opcodes.
pub mod opcodes {
    pub const OP_0: u8 = 0x00;
    pub const OP_1: u8 = 0x51;
    pub const OP_16: u8 = 0x60;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_EQUAL: u8 = 0x87;
}

/// Build a multisig redeem script.
///
/// Format: `OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG`
pub fn build_multisig_script(config: &MultisigConfig) -> Vec<u8> {
    let mut script = Vec::new();

    // OP_M (threshold)
    script.push(number_to_opcode(config.threshold()));

    // Push each public key
    for pubkey in config.public_keys() {
        script.push(33); // Push 33 bytes
        script.extend_from_slice(pubkey);
    }

    // OP_N (total keys)
    script.push(number_to_opcode(config.total()));

    // OP_CHECKMULTISIG
    script.push(opcodes::OP_CHECKMULTISIG);

    script
}

/// Build P2SH scriptPubKey from script hash.
///
/// Format: `OP_HASH160 <20-byte-hash> OP_EQUAL`
pub fn build_p2sh_script_pubkey(script_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(23);
    script.push(opcodes::OP_HASH160);
    script.push(20); // Push 20 bytes
    script.extend_from_slice(script_hash);
    script.push(opcodes::OP_EQUAL);
    script
}

/// Build P2WSH scriptPubKey from witness script hash.
///
/// Format: `OP_0 <32-byte-hash>`
pub fn build_p2wsh_script_pubkey(script_hash: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(opcodes::OP_0);
    script.push(32); // Push 32 bytes
    script.extend_from_slice(script_hash);
    script
}

/// Build P2SH-P2WSH redeem script (wraps P2WSH in P2SH).
///
/// Format: `OP_0 <32-byte-witness-script-hash>`
pub fn build_p2sh_p2wsh_redeem_script(witness_script_hash: &[u8; 32]) -> Vec<u8> {
    build_p2wsh_script_pubkey(witness_script_hash)
}

/// Convert a number (1-16) to its opcode representation.
fn number_to_opcode(n: u8) -> u8 {
    if n == 0 {
        opcodes::OP_0
    } else if n <= 16 {
        opcodes::OP_1 + n - 1
    } else {
        // For numbers > 16, we'd need to push the value
        // But multisig is limited to 15 keys, so this shouldn't happen
        panic!("Number too large for opcode: {}", n);
    }
}

/// Parse M and N from a multisig redeem script.
pub fn parse_multisig_script(script: &[u8]) -> Option<(u8, u8, Vec<[u8; 33]>)> {
    if script.len() < 3 {
        return None;
    }

    // First byte should be OP_M
    let m = opcode_to_number(script[0])?;
    if m == 0 || m > 15 {
        return None;
    }

    // Parse public keys
    let mut pos = 1;
    let mut pubkeys = Vec::new();

    while pos < script.len() {
        let byte = script[pos];
        
        // Check if this is OP_N (end of pubkeys)
        if (opcodes::OP_1..=opcodes::OP_16).contains(&byte) {
            break;
        }

        // Should be a push of 33 bytes
        if byte != 33 {
            return None;
        }

        if pos + 34 > script.len() {
            return None;
        }

        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&script[pos + 1..pos + 34]);
        pubkeys.push(pubkey);
        pos += 34;
    }

    if pos >= script.len() {
        return None;
    }

    // Parse OP_N
    let n = opcode_to_number(script[pos])?;
    if n as usize != pubkeys.len() {
        return None;
    }

    // Check OP_CHECKMULTISIG
    if pos + 1 >= script.len() || script[pos + 1] != opcodes::OP_CHECKMULTISIG {
        return None;
    }

    Some((m, n, pubkeys))
}

/// Convert an opcode to its number value.
fn opcode_to_number(opcode: u8) -> Option<u8> {
    if opcode == opcodes::OP_0 {
        Some(0)
    } else if (opcodes::OP_1..=opcodes::OP_16).contains(&opcode) {
        Some(opcode - opcodes::OP_1 + 1)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MultisigConfig;

    fn make_pubkey(seed: u8) -> [u8; 33] {
        let mut key = [seed; 33];
        key[0] = 0x02;
        key
    }

    #[test]
    fn test_build_2_of_3_script() {
        let keys = vec![make_pubkey(1), make_pubkey(2), make_pubkey(3)];
        let config = MultisigConfig::new(2, keys).unwrap();
        let script = build_multisig_script(&config);

        // OP_2 + 3*(1+33) + OP_3 + OP_CHECKMULTISIG = 1 + 102 + 1 + 1 = 105
        assert_eq!(script.len(), 105);
        assert_eq!(script[0], opcodes::OP_1 + 1); // OP_2
        assert_eq!(script[script.len() - 2], opcodes::OP_1 + 2); // OP_3
        assert_eq!(script[script.len() - 1], opcodes::OP_CHECKMULTISIG);
    }

    #[test]
    fn test_parse_multisig_script() {
        let keys = vec![make_pubkey(1), make_pubkey(2), make_pubkey(3)];
        let config = MultisigConfig::new(2, keys.clone()).unwrap();
        let script = build_multisig_script(&config);

        let (m, n, parsed_keys) = parse_multisig_script(&script).unwrap();
        assert_eq!(m, 2);
        assert_eq!(n, 3);
        assert_eq!(parsed_keys.len(), 3);
    }

    #[test]
    fn test_p2sh_script_pubkey() {
        let hash = [0xab; 20];
        let script = build_p2sh_script_pubkey(&hash);
        
        assert_eq!(script.len(), 23);
        assert_eq!(script[0], opcodes::OP_HASH160);
        assert_eq!(script[1], 20);
        assert_eq!(script[22], opcodes::OP_EQUAL);
    }

    #[test]
    fn test_p2wsh_script_pubkey() {
        let hash = [0xcd; 32];
        let script = build_p2wsh_script_pubkey(&hash);
        
        assert_eq!(script.len(), 34);
        assert_eq!(script[0], opcodes::OP_0);
        assert_eq!(script[1], 32);
    }
}
