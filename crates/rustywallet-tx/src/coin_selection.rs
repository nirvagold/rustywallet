//! Coin selection algorithms.

use crate::error::{TxError, Result};
use crate::types::Utxo;
use crate::fee::estimate_fee;

/// Select coins using largest-first algorithm.
///
/// Selects UTXOs starting from the largest until the target amount
/// plus estimated fees is covered.
///
/// # Arguments
/// * `utxos` - Available UTXOs
/// * `target` - Target amount in satoshis (excluding fees)
/// * `sat_per_vb` - Fee rate in satoshis per virtual byte
///
/// # Returns
/// Selected UTXOs and the total value
pub fn select_coins(
    utxos: &[Utxo],
    target: u64,
    sat_per_vb: u64,
) -> Result<(Vec<Utxo>, u64)> {
    if utxos.is_empty() {
        return Err(TxError::InsufficientFunds {
            needed: target,
            available: 0,
        });
    }

    // Sort by value descending (largest first)
    let mut sorted: Vec<_> = utxos.to_vec();
    sorted.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total = 0u64;

    for utxo in sorted {
        selected.push(utxo);
        total += selected.last().unwrap().value;

        // Estimate fee with current number of inputs
        // Assume 2 outputs (recipient + change)
        let fee = estimate_fee(selected.len(), 2, sat_per_vb);
        let needed = target.saturating_add(fee);

        if total >= needed {
            return Ok((selected, total));
        }
    }

    // Not enough funds
    let fee = estimate_fee(selected.len(), 2, sat_per_vb);
    Err(TxError::InsufficientFunds {
        needed: target + fee,
        available: total,
    })
}

/// Calculate total value of UTXOs.
pub fn total_value(utxos: &[Utxo]) -> u64 {
    utxos.iter().map(|u| u.value).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo(value: u64) -> Utxo {
        Utxo {
            txid: [0u8; 32],
            vout: 0,
            value,
            script_pubkey: vec![],
            address: String::new(),
        }
    }

    #[test]
    fn test_select_coins_single() {
        let utxos = vec![make_utxo(100_000)];
        let (selected, total) = select_coins(&utxos, 50_000, 10).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 100_000);
    }

    #[test]
    fn test_select_coins_multiple() {
        let utxos = vec![
            make_utxo(10_000),
            make_utxo(50_000),
            make_utxo(30_000),
        ];
        let (selected, _) = select_coins(&utxos, 70_000, 1).unwrap();
        // Should select largest first: 50k, then 30k
        assert!(selected.len() >= 2);
    }

    #[test]
    fn test_select_coins_insufficient() {
        let utxos = vec![make_utxo(1_000)];
        let result = select_coins(&utxos, 100_000, 10);
        assert!(matches!(result, Err(TxError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_select_coins_empty() {
        let utxos: Vec<Utxo> = vec![];
        let result = select_coins(&utxos, 1_000, 10);
        assert!(matches!(result, Err(TxError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_total_value() {
        let utxos = vec![
            make_utxo(10_000),
            make_utxo(20_000),
            make_utxo(30_000),
        ];
        assert_eq!(total_value(&utxos), 60_000);
    }
}
