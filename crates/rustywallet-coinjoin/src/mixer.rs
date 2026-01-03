//! Output mixing utilities.

use crate::error::{CoinJoinError, Result};
use crate::types::OutputDef;
use sha2::{Digest, Sha256};

/// Standard CoinJoin denominations (in satoshis).
pub const DENOMINATIONS: &[u64] = &[
    10_000,      // 0.0001 BTC
    50_000,      // 0.0005 BTC
    100_000,     // 0.001 BTC
    500_000,     // 0.005 BTC
    1_000_000,   // 0.01 BTC
    5_000_000,   // 0.05 BTC
    10_000_000,  // 0.1 BTC
    50_000_000,  // 0.5 BTC
    100_000_000, // 1 BTC
];

/// Find the best denomination for a given amount.
pub fn find_best_denomination(amount: u64, min_change: u64) -> Option<u64> {
    DENOMINATIONS
        .iter()
        .rev()
        .find(|&&d| d <= amount && (amount - d) >= min_change || amount == d)
        .copied()
}

/// Calculate how to split an amount into denominations.
pub fn split_into_denominations(amount: u64, min_change: u64) -> Vec<u64> {
    let mut remaining = amount;
    let mut result = Vec::new();

    for &denom in DENOMINATIONS.iter().rev() {
        while remaining >= denom + min_change || remaining == denom {
            result.push(denom);
            remaining -= denom;
        }
    }

    result
}

/// Output mixer for shuffling outputs.
pub struct OutputMixer {
    /// Outputs to mix
    outputs: Vec<OutputDef>,
    /// Shuffle seed
    seed: Option<[u8; 32]>,
}

impl OutputMixer {
    /// Create a new output mixer.
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
            seed: None,
        }
    }

    /// Add an output.
    pub fn add_output(&mut self, output: OutputDef) {
        self.outputs.push(output);
    }

    /// Add multiple outputs.
    pub fn add_outputs(&mut self, outputs: impl IntoIterator<Item = OutputDef>) {
        self.outputs.extend(outputs);
    }

    /// Set shuffle seed for deterministic shuffling.
    pub fn set_seed(&mut self, seed: [u8; 32]) {
        self.seed = Some(seed);
    }

    /// Shuffle outputs.
    pub fn shuffle(&mut self) -> &[OutputDef] {
        let seed = self.seed.unwrap_or_else(|| {
            // Generate random seed
            let mut hasher = Sha256::new();
            hasher.update(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .to_le_bytes(),
            );
            let result = hasher.finalize();
            let mut s = [0u8; 32];
            s.copy_from_slice(&result);
            s
        });

        // Fisher-Yates shuffle with deterministic randomness
        let n = self.outputs.len();
        for i in 0..n {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(i.to_le_bytes());
            let hash = hasher.finalize();
            let j = i + (u64::from_le_bytes(hash[0..8].try_into().unwrap()) as usize % (n - i));
            self.outputs.swap(i, j);
        }

        &self.outputs
    }

    /// Get outputs.
    pub fn outputs(&self) -> &[OutputDef] {
        &self.outputs
    }

    /// Verify all outputs have equal amounts.
    pub fn verify_equal(&self) -> Result<u64> {
        if self.outputs.is_empty() {
            return Err(CoinJoinError::InvalidOutput("No outputs".into()));
        }

        let amount = self.outputs[0].amount;
        for output in &self.outputs[1..] {
            if output.amount != amount {
                return Err(CoinJoinError::UnequalOutputs {
                    expected: amount,
                    actual: output.amount,
                });
            }
        }

        Ok(amount)
    }
}

impl Default for OutputMixer {
    fn default() -> Self {
        Self::new()
    }
}

/// Analyze outputs for privacy.
#[derive(Debug, Clone)]
pub struct PrivacyAnalysis {
    /// Number of equal outputs
    pub equal_outputs: usize,
    /// Unique amounts
    pub unique_amounts: usize,
    /// Anonymity set size (equal outputs)
    pub anonymity_set: usize,
    /// Has change outputs (reduces privacy)
    pub has_change: bool,
    /// Privacy score (0-100)
    pub score: u8,
}

/// Analyze a set of outputs for privacy.
pub fn analyze_privacy(outputs: &[OutputDef]) -> PrivacyAnalysis {
    if outputs.is_empty() {
        return PrivacyAnalysis {
            equal_outputs: 0,
            unique_amounts: 0,
            anonymity_set: 0,
            has_change: false,
            score: 0,
        };
    }

    // Count amounts
    let mut amounts: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for output in outputs {
        *amounts.entry(output.amount).or_insert(0) += 1;
    }

    // Find largest group of equal outputs
    let max_equal = amounts.values().max().copied().unwrap_or(0);
    let unique_amounts = amounts.len();

    // Check for likely change outputs (unique amounts)
    let has_change = amounts.values().any(|&count| count == 1);

    // Calculate privacy score
    let score = if outputs.len() <= 1 {
        0
    } else {
        let equal_ratio = max_equal as f64 / outputs.len() as f64;
        let base_score = (equal_ratio * 80.0) as u8;
        let bonus = if max_equal >= 2 { 20 } else { 0 };
        let penalty = if has_change { 10 } else { 0 };
        (base_score + bonus).saturating_sub(penalty).min(100)
    };

    PrivacyAnalysis {
        equal_outputs: max_equal,
        unique_amounts,
        anonymity_set: max_equal,
        has_change,
        score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_denomination() {
        assert_eq!(find_best_denomination(150_000, 1000), Some(100_000));
        assert_eq!(find_best_denomination(100_000, 0), Some(100_000));
        assert_eq!(find_best_denomination(5_000, 1000), None);
    }

    #[test]
    fn test_split_denominations() {
        let splits = split_into_denominations(250_000, 1000);
        assert!(splits.contains(&100_000));
        assert!(splits.contains(&100_000));
        assert!(splits.contains(&50_000));
    }

    #[test]
    fn test_output_mixer() {
        let mut mixer = OutputMixer::new();
        mixer.add_output(OutputDef::new(50_000, vec![0x01]));
        mixer.add_output(OutputDef::new(50_000, vec![0x02]));
        mixer.add_output(OutputDef::new(50_000, vec![0x03]));

        assert_eq!(mixer.outputs().len(), 3);
        assert!(mixer.verify_equal().is_ok());
    }

    #[test]
    fn test_mixer_shuffle_deterministic() {
        let mut mixer1 = OutputMixer::new();
        let mut mixer2 = OutputMixer::new();

        for i in 0..5 {
            mixer1.add_output(OutputDef::new(50_000, vec![i]));
            mixer2.add_output(OutputDef::new(50_000, vec![i]));
        }

        let seed = [42u8; 32];
        mixer1.set_seed(seed);
        mixer2.set_seed(seed);

        let shuffled1: Vec<_> = mixer1.shuffle().iter().map(|o| o.script_pubkey.clone()).collect();
        let shuffled2: Vec<_> = mixer2.shuffle().iter().map(|o| o.script_pubkey.clone()).collect();

        assert_eq!(shuffled1, shuffled2);
    }

    #[test]
    fn test_verify_unequal() {
        let mut mixer = OutputMixer::new();
        mixer.add_output(OutputDef::new(50_000, vec![0x01]));
        mixer.add_output(OutputDef::new(60_000, vec![0x02]));

        assert!(mixer.verify_equal().is_err());
    }

    #[test]
    fn test_privacy_analysis() {
        // Good privacy: all equal
        let outputs = vec![
            OutputDef::new(50_000, vec![0x01]),
            OutputDef::new(50_000, vec![0x02]),
            OutputDef::new(50_000, vec![0x03]),
        ];
        let analysis = analyze_privacy(&outputs);
        assert_eq!(analysis.equal_outputs, 3);
        assert_eq!(analysis.anonymity_set, 3);
        assert!(!analysis.has_change);
        assert!(analysis.score >= 80);

        // Poor privacy: unique amounts
        let outputs = vec![
            OutputDef::new(50_000, vec![0x01]),
            OutputDef::new(60_000, vec![0x02]),
            OutputDef::new(70_000, vec![0x03]),
        ];
        let analysis = analyze_privacy(&outputs);
        assert_eq!(analysis.equal_outputs, 1);
        assert!(analysis.has_change);
        assert!(analysis.score < 50);
    }
}
