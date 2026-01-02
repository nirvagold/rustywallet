//! Incremental key scanning using EC point addition.
//!
//! This module provides [`KeyScanner`] for scanning key ranges efficiently
//! using elliptic curve point addition.

use crate::error::BatchError;
use crate::stream::KeyStream;
use rustywallet_keys::private_key::PrivateKey;

/// Direction for key scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanDirection {
    /// Scan forward (increment keys).
    #[default]
    Forward,
    /// Scan backward (decrement keys).
    Backward,
}

/// Incremental key scanner using EC point addition.
///
/// `KeyScanner` efficiently generates sequential keys by adding or subtracting
/// a constant value from a base key, which is faster than generating random keys.
///
/// # Example
///
/// ```rust
/// use rustywallet_batch::prelude::*;
/// use rustywallet_keys::prelude::PrivateKey;
///
/// let base = PrivateKey::from_hex(
///     "0000000000000000000000000000000000000000000000000000000000000001"
/// ).unwrap();
///
/// // Scan forward from base key
/// let scanner = KeyScanner::new(base.clone())
///     .direction(ScanDirection::Forward);
///
/// for key in scanner.scan_range(10) {
///     println!("{}", key.unwrap().to_hex());
/// }
///
/// // Scan backward
/// let scanner = KeyScanner::new(base)
///     .direction(ScanDirection::Backward);
/// ```
#[derive(Debug, Clone)]
pub struct KeyScanner {
    /// The base private key to start scanning from.
    base_key: PrivateKey,

    /// The scanning direction.
    direction: ScanDirection,

    /// Step size for each increment/decrement.
    step: u64,
}

impl KeyScanner {
    /// Create a new key scanner starting from the given base key.
    pub fn new(base_key: PrivateKey) -> Self {
        Self {
            base_key,
            direction: ScanDirection::Forward,
            step: 1,
        }
    }

    /// Set the scanning direction.
    pub fn direction(mut self, direction: ScanDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Set the step size for each increment/decrement.
    pub fn step(mut self, step: u64) -> Self {
        self.step = step;
        self
    }

    /// Scan a range of keys starting from the base key.
    ///
    /// Returns a `KeyStream` that yields keys incrementally.
    pub fn scan_range(self, count: usize) -> KeyStream {
        let iter = ScanIterator::new(
            self.base_key,
            self.direction,
            self.step,
            count,
        );
        KeyStream::new(iter, Some(count))
    }

    /// Scan keys until a predicate returns true.
    ///
    /// Returns a `KeyStream` that yields keys until the predicate matches.
    pub fn scan_until<F>(self, predicate: F) -> KeyStream
    where
        F: Fn(&PrivateKey) -> bool + Send + 'static,
    {
        let iter = ScanUntilIterator::new(
            self.base_key,
            self.direction,
            self.step,
            predicate,
        );
        KeyStream::new(iter, None)
    }
}

/// Iterator for scanning a fixed range of keys.
struct ScanIterator {
    current_bytes: [u8; 32],
    direction: ScanDirection,
    step: u64,
    remaining: usize,
}

impl ScanIterator {
    fn new(base_key: PrivateKey, direction: ScanDirection, step: u64, count: usize) -> Self {
        Self {
            current_bytes: base_key.to_bytes(),
            direction,
            step,
            remaining: count,
        }
    }

    /// Add step to current key bytes (handles overflow/wraparound).
    fn add_step(&mut self) {
        let step_bytes = self.step.to_be_bytes();
        let mut carry: u64 = 0;
        
        // Add step to the last 8 bytes
        for i in (24..32).rev() {
            let step_idx = 31 - i;
            let step_byte = if step_idx < 8 { step_bytes[7 - step_idx] } else { 0 };
            let sum = self.current_bytes[i] as u64 + step_byte as u64 + carry;
            self.current_bytes[i] = sum as u8;
            carry = sum >> 8;
        }

        // Propagate carry to remaining bytes
        for i in (0..24).rev() {
            if carry == 0 {
                break;
            }
            let sum = self.current_bytes[i] as u64 + carry;
            self.current_bytes[i] = sum as u8;
            carry = sum >> 8;
        }

        // Handle wraparound at curve order (simplified - just wrap to 1)
        if carry > 0 || !PrivateKey::is_valid(&self.current_bytes) {
            self.current_bytes = [0u8; 32];
            self.current_bytes[31] = 1;
        }
    }

    /// Subtract step from current key bytes (handles underflow/wraparound).
    fn sub_step(&mut self) {
        let step_bytes = self.step.to_be_bytes();
        let mut borrow: i64 = 0;
        
        // Subtract step from the last 8 bytes
        for i in (24..32).rev() {
            let step_idx = 31 - i;
            let step_byte = if step_idx < 8 { step_bytes[7 - step_idx] } else { 0 };
            let diff = self.current_bytes[i] as i64 - step_byte as i64 - borrow;
            if diff < 0 {
                self.current_bytes[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                self.current_bytes[i] = diff as u8;
                borrow = 0;
            }
        }

        // Propagate borrow to remaining bytes
        for i in (0..24).rev() {
            if borrow == 0 {
                break;
            }
            let diff = self.current_bytes[i] as i64 - borrow;
            if diff < 0 {
                self.current_bytes[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                self.current_bytes[i] = diff as u8;
                borrow = 0;
            }
        }

        // Handle underflow (wrap to max valid key)
        if borrow > 0 || !PrivateKey::is_valid(&self.current_bytes) {
            // Set to curve order - 1 (max valid key)
            self.current_bytes = [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
            ];
        }
    }
}

impl Iterator for ScanIterator {
    type Item = Result<PrivateKey, BatchError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        self.remaining -= 1;

        // Create key from current bytes
        let key = match PrivateKey::from_bytes(self.current_bytes) {
            Ok(k) => k,
            Err(e) => return Some(Err(BatchError::scanner_error(format!("Invalid key: {}", e)))),
        };

        // Advance to next key
        match self.direction {
            ScanDirection::Forward => self.add_step(),
            ScanDirection::Backward => self.sub_step(),
        }

        Some(Ok(key))
    }
}

/// Iterator for scanning until a predicate matches.
struct ScanUntilIterator<F>
where
    F: Fn(&PrivateKey) -> bool,
{
    current_bytes: [u8; 32],
    direction: ScanDirection,
    step: u64,
    predicate: F,
    found: bool,
}

impl<F> ScanUntilIterator<F>
where
    F: Fn(&PrivateKey) -> bool,
{
    fn new(base_key: PrivateKey, direction: ScanDirection, step: u64, predicate: F) -> Self {
        Self {
            current_bytes: base_key.to_bytes(),
            direction,
            step,
            predicate,
            found: false,
        }
    }

    fn add_step(&mut self) {
        let step_bytes = self.step.to_be_bytes();
        let mut carry: u64 = 0;
        
        for i in (24..32).rev() {
            let step_idx = 31 - i;
            let step_byte = if step_idx < 8 { step_bytes[7 - step_idx] } else { 0 };
            let sum = self.current_bytes[i] as u64 + step_byte as u64 + carry;
            self.current_bytes[i] = sum as u8;
            carry = sum >> 8;
        }

        for i in (0..24).rev() {
            if carry == 0 {
                break;
            }
            let sum = self.current_bytes[i] as u64 + carry;
            self.current_bytes[i] = sum as u8;
            carry = sum >> 8;
        }

        if carry > 0 || !PrivateKey::is_valid(&self.current_bytes) {
            self.current_bytes = [0u8; 32];
            self.current_bytes[31] = 1;
        }
    }

    fn sub_step(&mut self) {
        let step_bytes = self.step.to_be_bytes();
        let mut borrow: i64 = 0;
        
        for i in (24..32).rev() {
            let step_idx = 31 - i;
            let step_byte = if step_idx < 8 { step_bytes[7 - step_idx] } else { 0 };
            let diff = self.current_bytes[i] as i64 - step_byte as i64 - borrow;
            if diff < 0 {
                self.current_bytes[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                self.current_bytes[i] = diff as u8;
                borrow = 0;
            }
        }

        for i in (0..24).rev() {
            if borrow == 0 {
                break;
            }
            let diff = self.current_bytes[i] as i64 - borrow;
            if diff < 0 {
                self.current_bytes[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                self.current_bytes[i] = diff as u8;
                borrow = 0;
            }
        }

        if borrow > 0 || !PrivateKey::is_valid(&self.current_bytes) {
            self.current_bytes = [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
            ];
        }
    }
}

impl<F> Iterator for ScanUntilIterator<F>
where
    F: Fn(&PrivateKey) -> bool,
{
    type Item = Result<PrivateKey, BatchError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.found {
            return None;
        }

        let key = match PrivateKey::from_bytes(self.current_bytes) {
            Ok(k) => k,
            Err(e) => return Some(Err(BatchError::scanner_error(format!("Invalid key: {}", e)))),
        };

        if (self.predicate)(&key) {
            self.found = true;
        }

        match self.direction {
            ScanDirection::Forward => self.add_step(),
            ScanDirection::Backward => self.sub_step(),
        }

        Some(Ok(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_forward() {
        let base = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();

        let scanner = KeyScanner::new(base);
        let keys: Vec<_> = scanner.scan_range(5).collect();

        assert_eq!(keys.len(), 5);
        
        // Verify sequential keys
        let hex_keys: Vec<_> = keys.iter()
            .map(|r| r.as_ref().unwrap().to_hex())
            .collect();

        assert_eq!(hex_keys[0], "0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(hex_keys[1], "0000000000000000000000000000000000000000000000000000000000000002");
        assert_eq!(hex_keys[2], "0000000000000000000000000000000000000000000000000000000000000003");
    }

    #[test]
    fn test_scan_backward() {
        let base = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000005"
        ).unwrap();

        let scanner = KeyScanner::new(base)
            .direction(ScanDirection::Backward);
        
        let keys: Vec<_> = scanner.scan_range(5).collect();

        assert_eq!(keys.len(), 5);
        
        let hex_keys: Vec<_> = keys.iter()
            .map(|r| r.as_ref().unwrap().to_hex())
            .collect();

        assert_eq!(hex_keys[0], "0000000000000000000000000000000000000000000000000000000000000005");
        assert_eq!(hex_keys[1], "0000000000000000000000000000000000000000000000000000000000000004");
        assert_eq!(hex_keys[2], "0000000000000000000000000000000000000000000000000000000000000003");
    }

    #[test]
    fn test_scan_with_step() {
        let base = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();

        let scanner = KeyScanner::new(base)
            .step(10);
        
        let keys: Vec<_> = scanner.scan_range(3).collect();

        let hex_keys: Vec<_> = keys.iter()
            .map(|r| r.as_ref().unwrap().to_hex())
            .collect();

        assert_eq!(hex_keys[0], "0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(hex_keys[1], "000000000000000000000000000000000000000000000000000000000000000b"); // 11
        assert_eq!(hex_keys[2], "0000000000000000000000000000000000000000000000000000000000000015"); // 21
    }

    #[test]
    fn test_scan_until() {
        let base = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();

        let scanner = KeyScanner::new(base);
        
        // Scan until we find key ending with "05"
        let keys: Vec<_> = scanner.scan_until(|k| {
            k.to_hex().ends_with("05")
        }).collect();

        assert_eq!(keys.len(), 5); // 1, 2, 3, 4, 5
        
        let last_key = keys.last().unwrap().as_ref().unwrap();
        assert!(last_key.to_hex().ends_with("05"));
    }

    #[test]
    fn test_bidirectional_consistency() {
        // Property 7: Bidirectional Scanning Consistency
        // Forward N steps then backward N steps should return to original
        let base = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000064" // 100
        ).unwrap();

        // Scan forward 10 steps
        let forward_scanner = KeyScanner::new(base.clone())
            .direction(ScanDirection::Forward);
        let forward_keys: Vec<_> = forward_scanner.scan_range(11).collect();
        let last_forward = forward_keys.last().unwrap().as_ref().unwrap().clone();

        // Scan backward 10 steps from the last forward key
        let backward_scanner = KeyScanner::new(last_forward)
            .direction(ScanDirection::Backward);
        let backward_keys: Vec<_> = backward_scanner.scan_range(11).collect();
        let last_backward = backward_keys.last().unwrap().as_ref().unwrap();

        // Should return to original base key
        assert_eq!(base.to_hex(), last_backward.to_hex());
    }
}
