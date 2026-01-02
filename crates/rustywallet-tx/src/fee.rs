//! Fee calculation utilities.

/// Dust threshold in satoshis (546 for P2PKH, 294 for P2WPKH).
pub const DUST_THRESHOLD_P2PKH: u64 = 546;
pub const DUST_THRESHOLD_P2WPKH: u64 = 294;

/// Estimated input sizes in virtual bytes.
pub mod input_vsize {
    /// P2PKH input: ~148 vbytes
    pub const P2PKH: usize = 148;
    /// P2WPKH input: ~68 vbytes
    pub const P2WPKH: usize = 68;
    /// P2TR input: ~58 vbytes
    pub const P2TR: usize = 58;
}

/// Estimated output sizes in bytes.
pub mod output_size {
    /// P2PKH output: 34 bytes
    pub const P2PKH: usize = 34;
    /// P2WPKH output: 31 bytes
    pub const P2WPKH: usize = 31;
    /// P2TR output: 43 bytes
    pub const P2TR: usize = 43;
}

/// Transaction overhead in bytes.
pub const TX_OVERHEAD: usize = 10;
/// SegWit marker and flag overhead.
pub const SEGWIT_OVERHEAD: usize = 2;

/// Estimate transaction virtual size.
///
/// # Arguments
/// * `num_p2pkh_inputs` - Number of P2PKH inputs
/// * `num_p2wpkh_inputs` - Number of P2WPKH inputs
/// * `num_outputs` - Number of outputs
pub fn estimate_vsize(
    num_p2pkh_inputs: usize,
    num_p2wpkh_inputs: usize,
    num_outputs: usize,
) -> usize {
    let input_size = num_p2pkh_inputs * input_vsize::P2PKH
        + num_p2wpkh_inputs * input_vsize::P2WPKH;
    let output_size = num_outputs * output_size::P2PKH; // Assume P2PKH outputs
    
    let has_segwit = num_p2wpkh_inputs > 0;
    let overhead = TX_OVERHEAD + if has_segwit { SEGWIT_OVERHEAD } else { 0 };
    
    overhead + input_size + output_size
}

/// Calculate fee for a given virtual size and fee rate.
///
/// # Arguments
/// * `vsize` - Virtual size in vbytes
/// * `sat_per_vb` - Fee rate in satoshis per virtual byte
pub fn calculate_fee(vsize: usize, sat_per_vb: u64) -> u64 {
    (vsize as u64) * sat_per_vb
}

/// Estimate fee for a transaction.
///
/// # Arguments
/// * `num_inputs` - Number of inputs (assumes P2WPKH)
/// * `num_outputs` - Number of outputs
/// * `sat_per_vb` - Fee rate in satoshis per virtual byte
pub fn estimate_fee(num_inputs: usize, num_outputs: usize, sat_per_vb: u64) -> u64 {
    let vsize = estimate_vsize(0, num_inputs, num_outputs);
    calculate_fee(vsize, sat_per_vb)
}

/// Check if an output value is dust.
pub fn is_dust(value: u64, is_segwit: bool) -> bool {
    let threshold = if is_segwit {
        DUST_THRESHOLD_P2WPKH
    } else {
        DUST_THRESHOLD_P2PKH
    };
    value < threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_vsize() {
        // 1 P2WPKH input, 2 outputs
        let vsize = estimate_vsize(0, 1, 2);
        assert!(vsize > 0);
        assert!(vsize < 200);
    }

    #[test]
    fn test_calculate_fee() {
        let fee = calculate_fee(100, 10);
        assert_eq!(fee, 1000);
    }

    #[test]
    fn test_is_dust() {
        assert!(is_dust(100, false));
        assert!(!is_dust(1000, false));
        assert!(is_dust(100, true));
        assert!(!is_dust(500, true));
    }
}
