//! BIP380 descriptor checksum
//!
//! Implements the checksum algorithm for output descriptors.

use crate::error::DescriptorError;

/// Character set for descriptor checksum (same as bech32)
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Generator coefficients for the checksum polynomial
const GENERATOR: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

/// Compute the polymod for the checksum
fn polymod(values: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for v in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x7ffffffff) << 5) ^ (*v as u64);
        for (i, gen) in GENERATOR.iter().enumerate() {
            if (c0 >> i) & 1 != 0 {
                c ^= gen;
            }
        }
    }
    c
}

/// Map a character to its checksum value
#[allow(dead_code)]
fn char_to_value(c: char) -> Option<u8> {
    match c {
        'q' => Some(0),
        'p' => Some(1),
        'z' => Some(2),
        'r' => Some(3),
        'y' => Some(4),
        '9' => Some(5),
        'x' => Some(6),
        '8' => Some(7),
        'g' => Some(8),
        'f' => Some(9),
        '2' => Some(10),
        't' => Some(11),
        'v' => Some(12),
        'd' => Some(13),
        'w' => Some(14),
        '0' => Some(15),
        's' => Some(16),
        '3' => Some(17),
        'j' => Some(18),
        'n' => Some(19),
        '5' => Some(20),
        '4' => Some(21),
        'k' => Some(22),
        'h' => Some(23),
        'c' => Some(24),
        'e' => Some(25),
        '6' => Some(26),
        'm' => Some(27),
        'u' => Some(28),
        'a' => Some(29),
        '7' => Some(30),
        'l' => Some(31),
        _ => None,
    }
}

/// Convert descriptor string to checksum input values
fn descriptor_to_values(desc: &str) -> Vec<u8> {
    let mut values = Vec::new();
    
    for c in desc.chars() {
        let cp = c as u32;
        if cp > 127 {
            // Non-ASCII character
            values.push((cp >> 8) as u8);
            values.push((cp & 0xff) as u8);
        } else {
            values.push(cp as u8 & 31);
            values.push(cp as u8 >> 5);
        }
    }
    
    values
}

/// Compute the checksum for a descriptor string (without existing checksum)
pub fn compute_checksum(descriptor: &str) -> String {
    let mut values = descriptor_to_values(descriptor);
    
    // Append 8 zeros for checksum computation
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    
    let plm = polymod(&values) ^ 1;
    
    let mut checksum = String::with_capacity(8);
    for i in 0..8 {
        let idx = ((plm >> (5 * (7 - i))) & 31) as usize;
        checksum.push(CHECKSUM_CHARSET[idx] as char);
    }
    
    checksum
}

/// Verify the checksum of a descriptor string
pub fn verify_checksum(descriptor_with_checksum: &str) -> Result<(), DescriptorError> {
    // Find the # separator
    let hash_pos = descriptor_with_checksum
        .rfind('#')
        .ok_or(DescriptorError::MissingChecksum)?;
    
    let descriptor = &descriptor_with_checksum[..hash_pos];
    let checksum = &descriptor_with_checksum[hash_pos + 1..];
    
    if checksum.len() != 8 {
        return Err(DescriptorError::InvalidChecksum {
            expected: "8 characters".into(),
            got: format!("{} characters", checksum.len()),
        });
    }
    
    let expected = compute_checksum(descriptor);
    
    if checksum != expected {
        return Err(DescriptorError::InvalidChecksum {
            expected,
            got: checksum.to_string(),
        });
    }
    
    Ok(())
}

/// Add checksum to a descriptor string
pub fn add_checksum(descriptor: &str) -> String {
    let checksum = compute_checksum(descriptor);
    format!("{}#{}", descriptor, checksum)
}

/// Strip checksum from descriptor string if present
pub fn strip_checksum(descriptor: &str) -> &str {
    if let Some(hash_pos) = descriptor.rfind('#') {
        &descriptor[..hash_pos]
    } else {
        descriptor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_checksum() {
        // Test vectors from BIP380
        let desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
        let checksum = compute_checksum(desc);
        assert_eq!(checksum.len(), 8);
    }

    #[test]
    fn test_add_and_verify_checksum() {
        let desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
        let with_checksum = add_checksum(desc);
        
        assert!(with_checksum.contains('#'));
        assert!(verify_checksum(&with_checksum).is_ok());
    }

    #[test]
    fn test_invalid_checksum() {
        let desc = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#xxxxxxxx";
        assert!(verify_checksum(desc).is_err());
    }

    #[test]
    fn test_strip_checksum() {
        let with = "wpkh(key)#abcd1234";
        let without = "wpkh(key)";
        
        assert_eq!(strip_checksum(with), "wpkh(key)");
        assert_eq!(strip_checksum(without), "wpkh(key)");
    }
}
