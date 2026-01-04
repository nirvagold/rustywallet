//! BIP39 Mnemonic implementation.

use crate::error::MnemonicError;
use crate::seed::Seed;
use crate::wordlist::Language;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Number of words in a mnemonic phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    /// 12 words (128 bits entropy)
    Words12 = 12,
    /// 15 words (160 bits entropy)
    Words15 = 15,
    /// 18 words (192 bits entropy)
    Words18 = 18,
    /// 21 words (224 bits entropy)
    Words21 = 21,
    /// 24 words (256 bits entropy)
    Words24 = 24,
}

impl WordCount {
    /// Get entropy bits for this word count.
    pub fn entropy_bits(&self) -> usize {
        match self {
            WordCount::Words12 => 128,
            WordCount::Words15 => 160,
            WordCount::Words18 => 192,
            WordCount::Words21 => 224,
            WordCount::Words24 => 256,
        }
    }

    /// Get entropy bytes for this word count.
    pub fn entropy_bytes(&self) -> usize {
        self.entropy_bits() / 8
    }

    /// Get checksum bits for this word count.
    pub fn checksum_bits(&self) -> usize {
        self.entropy_bits() / 32
    }

    /// Try to create WordCount from number of words.
    pub fn from_word_count(count: usize) -> Result<Self, MnemonicError> {
        match count {
            12 => Ok(WordCount::Words12),
            15 => Ok(WordCount::Words15),
            18 => Ok(WordCount::Words18),
            21 => Ok(WordCount::Words21),
            24 => Ok(WordCount::Words24),
            _ => Err(MnemonicError::InvalidWordCount(count)),
        }
    }
}

/// BIP39 Mnemonic phrase.
///
/// A mnemonic is a sequence of words that encodes entropy for key generation.
/// The entropy is protected with zeroize on drop.
///
/// # Example
///
/// ```
/// use rustywallet_mnemonic::{Mnemonic, WordCount};
///
/// // Generate a new 12-word mnemonic
/// let mnemonic = Mnemonic::generate(WordCount::Words12);
/// println!("Mnemonic: {}", mnemonic.to_phrase());
///
/// // Parse an existing mnemonic
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
/// assert_eq!(mnemonic.word_count(), WordCount::Words12);
/// ```
pub struct Mnemonic {
    words: Vec<String>,
    entropy: Zeroizing<Vec<u8>>,
    language: Language,
}

impl Mnemonic {
    /// Generate a new random mnemonic with the specified word count.
    ///
    /// Uses cryptographically secure random number generation.
    pub fn generate(word_count: WordCount) -> Self {
        Self::generate_in(word_count, Language::default())
    }

    /// Generate a new random mnemonic with the specified word count and language.
    ///
    /// This is an alias for `generate_with_language` for backwards compatibility.
    pub fn generate_in(word_count: WordCount, language: Language) -> Self {
        Self::generate_with_language(word_count, language)
    }

    /// Generate a new random mnemonic with the specified word count and language.
    ///
    /// Uses cryptographically secure random number generation.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_mnemonic::{Mnemonic, WordCount, Language};
    ///
    /// // Generate a Japanese mnemonic
    /// let mnemonic = Mnemonic::generate_with_language(WordCount::Words12, Language::Japanese);
    /// assert_eq!(mnemonic.language(), Language::Japanese);
    /// assert_eq!(mnemonic.words().len(), 12);
    ///
    /// // Generate a Spanish mnemonic
    /// let mnemonic = Mnemonic::generate_with_language(WordCount::Words24, Language::Spanish);
    /// assert_eq!(mnemonic.language(), Language::Spanish);
    /// ```
    pub fn generate_with_language(word_count: WordCount, language: Language) -> Self {
        let entropy_bytes = word_count.entropy_bytes();
        let mut entropy = vec![0u8; entropy_bytes];
        rand::rngs::OsRng.fill_bytes(&mut entropy);

        Self::from_entropy_internal(&entropy, language)
            .expect("Generated entropy should always be valid")
    }

    /// Create mnemonic from entropy bytes.
    fn from_entropy_internal(entropy: &[u8], language: Language) -> Result<Self, MnemonicError> {
        let entropy_bits = entropy.len() * 8;
        let word_count = match entropy_bits {
            128 => WordCount::Words12,
            160 => WordCount::Words15,
            192 => WordCount::Words18,
            224 => WordCount::Words21,
            256 => WordCount::Words24,
            _ => {
                return Err(MnemonicError::InvalidEntropyLength {
                    expected: 16, // or 20, 24, 28, 32
                    actual: entropy.len(),
                })
            }
        };

        // Calculate checksum
        let hash = Sha256::digest(entropy);
        let checksum_bits = word_count.checksum_bits();

        // Combine entropy + checksum into bits
        let mut bits = Vec::with_capacity(entropy_bits + checksum_bits);
        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
            }
        }
        for i in (0..checksum_bits).rev() {
            let byte_idx = (checksum_bits - 1 - i) / 8;
            let bit_idx = 7 - ((checksum_bits - 1 - i) % 8);
            bits.push((hash[byte_idx] >> bit_idx) & 1 == 1);
        }

        // Convert to words (11 bits per word)
        let wordlist = language.wordlist();
        let mut words = Vec::with_capacity(word_count as usize);
        for chunk in bits.chunks(11) {
            let mut index = 0usize;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    index |= 1 << (10 - i);
                }
            }
            words.push(wordlist[index].to_string());
        }

        Ok(Self {
            words,
            entropy: Zeroizing::new(entropy.to_vec()),
            language,
        })
    }

    /// Parse a mnemonic from a space-separated phrase.
    ///
    /// The phrase is validated for correct word count, valid words, and checksum.
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        Self::from_phrase_in(phrase, Language::default())
    }

    /// Parse a mnemonic from a phrase with a specific language.
    pub fn from_phrase_in(phrase: &str, language: Language) -> Result<Self, MnemonicError> {
        let phrase = phrase.trim();
        if phrase.is_empty() {
            return Err(MnemonicError::EmptyPhrase);
        }

        let words: Vec<String> = phrase
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect();

        let word_count = WordCount::from_word_count(words.len())?;

        // Validate all words exist in wordlist and get indices
        let mut indices = Vec::with_capacity(words.len());
        for word in &words {
            match language.get_index(word) {
                Some(idx) => indices.push(idx),
                None => return Err(MnemonicError::InvalidWord(word.clone())),
            }
        }

        // Convert indices to bits
        let total_bits = words.len() * 11;
        let mut bits = Vec::with_capacity(total_bits);
        for idx in &indices {
            for i in (0..11).rev() {
                bits.push((idx >> i) & 1 == 1);
            }
        }

        // Split into entropy and checksum
        let entropy_bits = word_count.entropy_bits();
        let checksum_bits = word_count.checksum_bits();

        // Extract entropy bytes
        let mut entropy = vec![0u8; entropy_bits / 8];
        for (i, bit) in bits[..entropy_bits].iter().enumerate() {
            if *bit {
                entropy[i / 8] |= 1 << (7 - (i % 8));
            }
        }

        // Verify checksum
        let hash = Sha256::digest(&entropy);
        for i in 0..checksum_bits {
            let expected_bit = (hash[i / 8] >> (7 - (i % 8))) & 1 == 1;
            let actual_bit = bits[entropy_bits + i];
            if expected_bit != actual_bit {
                return Err(MnemonicError::InvalidChecksum);
            }
        }

        Ok(Self {
            words,
            entropy: Zeroizing::new(entropy),
            language,
        })
    }

    /// Parse a mnemonic from a phrase with automatic language detection.
    ///
    /// This method tries to detect the language by checking which wordlist
    /// contains all the words in the phrase. If no single language contains
    /// all words, it returns an error.
    ///
    /// # Example
    ///
    /// ```
    /// use rustywallet_mnemonic::{Mnemonic, Language};
    ///
    /// // Auto-detect English mnemonic
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let mnemonic = Mnemonic::parse_auto_detect(phrase).unwrap();
    /// assert_eq!(mnemonic.language(), Language::English);
    ///
    /// // Auto-detect Japanese mnemonic
    /// let mnemonic = Mnemonic::generate_with_language(
    ///     rustywallet_mnemonic::WordCount::Words12,
    ///     Language::Japanese
    /// );
    /// let phrase = mnemonic.to_phrase();
    /// let parsed = Mnemonic::parse_auto_detect(&phrase).unwrap();
    /// assert_eq!(parsed.language(), Language::Japanese);
    /// ```
    pub fn parse_auto_detect(phrase: &str) -> Result<Self, MnemonicError> {
        let phrase = phrase.trim();
        if phrase.is_empty() {
            return Err(MnemonicError::EmptyPhrase);
        }

        // Try to detect language from the phrase
        match Language::detect_from_phrase(phrase) {
            Some(language) => Self::from_phrase_in(phrase, language),
            None => {
                // If no language matches all words, try to find the first invalid word
                let words: Vec<&str> = phrase.split_whitespace().collect();
                for word in &words {
                    let word_lower = word.to_lowercase();
                    if Language::detect_from_word(&word_lower).is_none() {
                        return Err(MnemonicError::InvalidWord(word_lower));
                    }
                }
                // If all words exist in some language but not all in the same language
                Err(MnemonicError::LanguageDetectionFailed)
            }
        }
    }

    /// Validate the mnemonic (checksum and wordlist).
    ///
    /// This is automatically called during `from_phrase`, but can be used
    /// to re-validate if needed.
    pub fn validate(&self) -> Result<(), MnemonicError> {
        // Re-parse to validate
        Self::from_phrase_in(&self.to_phrase(), self.language)?;
        Ok(())
    }

    /// Convert mnemonic to seed with optional passphrase.
    ///
    /// Uses PBKDF2-HMAC-SHA512 with 2048 iterations.
    pub fn to_seed(&self, passphrase: &str) -> Seed {
        Seed::new(self, passphrase)
    }

    /// Convert mnemonic to seed without passphrase.
    pub fn to_seed_normalized(&self) -> Seed {
        self.to_seed("")
    }

    /// Derive private key from mnemonic with passphrase.
    ///
    /// This is a convenience method that derives the seed and then
    /// extracts the first 32 bytes as a private key.
    pub fn to_private_key(
        &self,
        passphrase: &str,
    ) -> Result<rustywallet_keys::private_key::PrivateKey, MnemonicError> {
        self.to_seed(passphrase).to_private_key()
    }

    /// Get the words as a slice.
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Get the word count.
    pub fn word_count(&self) -> WordCount {
        WordCount::from_word_count(self.words.len()).expect("Mnemonic always has valid word count")
    }

    /// Get the language.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Export as space-separated phrase.
    pub fn to_phrase(&self) -> String {
        self.words.join(" ")
    }

    /// Get entropy bytes (for advanced use).
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_phrase())
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mnemonic(****)")
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        // Zeroize words
        for word in &mut self.words {
            word.zeroize();
        }
        // entropy is already Zeroizing<Vec<u8>>
    }
}

impl Clone for Mnemonic {
    fn clone(&self) -> Self {
        Self {
            words: self.words.clone(),
            entropy: Zeroizing::new(self.entropy.to_vec()),
            language: self.language,
        }
    }
}

impl std::str::FromStr for Mnemonic {
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_phrase(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_12_words() {
        let mnemonic = Mnemonic::generate(WordCount::Words12);
        assert_eq!(mnemonic.words().len(), 12);
        assert!(mnemonic.validate().is_ok());
    }

    #[test]
    fn test_generate_24_words() {
        let mnemonic = Mnemonic::generate(WordCount::Words24);
        assert_eq!(mnemonic.words().len(), 24);
        assert!(mnemonic.validate().is_ok());
    }

    #[test]
    fn test_parse_valid_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.words().len(), 12);
        assert_eq!(mnemonic.to_phrase(), phrase);
    }

    #[test]
    fn test_parse_invalid_word() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid";
        let result = Mnemonic::from_phrase(phrase);
        assert!(matches!(result, Err(MnemonicError::InvalidWord(_))));
    }

    #[test]
    fn test_parse_invalid_checksum() {
        // Valid words but wrong checksum
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = Mnemonic::from_phrase(phrase);
        assert!(matches!(result, Err(MnemonicError::InvalidChecksum)));
    }

    #[test]
    fn test_parse_invalid_word_count() {
        let phrase = "abandon abandon abandon";
        let result = Mnemonic::from_phrase(phrase);
        assert!(matches!(result, Err(MnemonicError::InvalidWordCount(_))));
    }

    #[test]
    fn test_case_insensitive() {
        let phrase = "ABANDON Abandon ABANDON abandon ABANDON abandon ABANDON abandon ABANDON abandon ABANDON About";
        let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(mnemonic.words().len(), 12);
    }

    #[test]
    fn test_word_count_entropy() {
        assert_eq!(WordCount::Words12.entropy_bits(), 128);
        assert_eq!(WordCount::Words15.entropy_bits(), 160);
        assert_eq!(WordCount::Words18.entropy_bits(), 192);
        assert_eq!(WordCount::Words21.entropy_bits(), 224);
        assert_eq!(WordCount::Words24.entropy_bits(), 256);
    }

    #[test]
    fn test_debug_masked() {
        let mnemonic = Mnemonic::generate(WordCount::Words12);
        let debug = format!("{:?}", mnemonic);
        assert_eq!(debug, "Mnemonic(****)");
        assert!(!debug.contains("abandon"));
    }

    #[test]
    fn test_generate_with_language_japanese() {
        let mnemonic = Mnemonic::generate_with_language(WordCount::Words12, Language::Japanese);
        assert_eq!(mnemonic.words().len(), 12);
        assert_eq!(mnemonic.language(), Language::Japanese);
        assert!(mnemonic.validate().is_ok());
        // Verify all words are in Japanese wordlist
        for word in mnemonic.words() {
            assert!(Language::Japanese.contains(word));
        }
    }

    #[test]
    fn test_generate_with_language_spanish() {
        let mnemonic = Mnemonic::generate_with_language(WordCount::Words12, Language::Spanish);
        assert_eq!(mnemonic.words().len(), 12);
        assert_eq!(mnemonic.language(), Language::Spanish);
        assert!(mnemonic.validate().is_ok());
    }

    #[test]
    fn test_generate_with_language_chinese() {
        let mnemonic = Mnemonic::generate_with_language(WordCount::Words12, Language::ChineseSimplified);
        assert_eq!(mnemonic.words().len(), 12);
        assert_eq!(mnemonic.language(), Language::ChineseSimplified);
        assert!(mnemonic.validate().is_ok());
    }

    #[test]
    fn test_generate_with_language_korean() {
        let mnemonic = Mnemonic::generate_with_language(WordCount::Words12, Language::Korean);
        assert_eq!(mnemonic.words().len(), 12);
        assert_eq!(mnemonic.language(), Language::Korean);
        assert!(mnemonic.validate().is_ok());
    }

    #[test]
    fn test_parse_auto_detect_english() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse_auto_detect(phrase).unwrap();
        assert_eq!(mnemonic.language(), Language::English);
        assert_eq!(mnemonic.words().len(), 12);
    }

    #[test]
    fn test_parse_auto_detect_japanese() {
        // Generate a Japanese mnemonic and then parse it with auto-detect
        let original = Mnemonic::generate_with_language(WordCount::Words12, Language::Japanese);
        let phrase = original.to_phrase();
        let parsed = Mnemonic::parse_auto_detect(&phrase).unwrap();
        assert_eq!(parsed.language(), Language::Japanese);
        assert_eq!(parsed.to_phrase(), phrase);
    }

    #[test]
    fn test_parse_auto_detect_spanish() {
        let original = Mnemonic::generate_with_language(WordCount::Words12, Language::Spanish);
        let phrase = original.to_phrase();
        let parsed = Mnemonic::parse_auto_detect(&phrase).unwrap();
        assert_eq!(parsed.language(), Language::Spanish);
    }

    #[test]
    fn test_parse_auto_detect_chinese() {
        let original = Mnemonic::generate_with_language(WordCount::Words12, Language::ChineseSimplified);
        let phrase = original.to_phrase();
        let parsed = Mnemonic::parse_auto_detect(&phrase).unwrap();
        assert_eq!(parsed.language(), Language::ChineseSimplified);
    }

    #[test]
    fn test_parse_auto_detect_korean() {
        let original = Mnemonic::generate_with_language(WordCount::Words12, Language::Korean);
        let phrase = original.to_phrase();
        let parsed = Mnemonic::parse_auto_detect(&phrase).unwrap();
        assert_eq!(parsed.language(), Language::Korean);
    }

    #[test]
    fn test_parse_auto_detect_invalid_word() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        let result = Mnemonic::parse_auto_detect(phrase);
        assert!(matches!(result, Err(MnemonicError::InvalidWord(_))));
    }

    #[test]
    fn test_parse_auto_detect_empty() {
        let result = Mnemonic::parse_auto_detect("");
        assert!(matches!(result, Err(MnemonicError::EmptyPhrase)));
    }
}


#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // **Feature: rustywallet-mnemonic, Property 1: Mnemonic Generation Validity**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_generated_mnemonic_is_valid(word_count in prop_oneof![
            Just(WordCount::Words12),
            Just(WordCount::Words15),
            Just(WordCount::Words18),
            Just(WordCount::Words21),
            Just(WordCount::Words24),
        ]) {
            let mnemonic = Mnemonic::generate(word_count);
            prop_assert!(mnemonic.validate().is_ok());
            prop_assert_eq!(mnemonic.words().len(), word_count as usize);
        }
    }

    // **Feature: rustywallet-mnemonic, Property 2: Mnemonic Round-Trip**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_mnemonic_roundtrip(word_count in prop_oneof![
            Just(WordCount::Words12),
            Just(WordCount::Words15),
            Just(WordCount::Words18),
            Just(WordCount::Words21),
            Just(WordCount::Words24),
        ]) {
            let original = Mnemonic::generate(word_count);
            let phrase = original.to_phrase();
            let parsed = Mnemonic::from_phrase(&phrase).unwrap();
            prop_assert_eq!(original.to_phrase(), parsed.to_phrase());
        }
    }

    // **Feature: rustywallet-mnemonic, Property 3: Seed Derivation Determinism**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_seed_derivation_deterministic(passphrase in "[a-zA-Z0-9]{0,20}") {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
            
            let seed1 = mnemonic.to_seed(&passphrase);
            let seed2 = mnemonic.to_seed(&passphrase);
            
            prop_assert_eq!(seed1.as_bytes(), seed2.as_bytes());
        }
    }

    // **Feature: rustywallet-mnemonic, Property 4: Passphrase Sensitivity**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_different_passphrase_different_seed(
            pass1 in "[a-zA-Z]{1,10}",
            pass2 in "[a-zA-Z]{1,10}"
        ) {
            prop_assume!(pass1 != pass2);
            
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
            
            let seed1 = mnemonic.to_seed(&pass1);
            let seed2 = mnemonic.to_seed(&pass2);
            
            prop_assert_ne!(seed1.as_bytes(), seed2.as_bytes());
        }
    }

    // **Feature: rustywallet-mnemonic, Property 6: Word Count Consistency**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_word_count_consistency(word_count in prop_oneof![
            Just(WordCount::Words12),
            Just(WordCount::Words15),
            Just(WordCount::Words18),
            Just(WordCount::Words21),
            Just(WordCount::Words24),
        ]) {
            let mnemonic = Mnemonic::generate(word_count);
            let phrase = mnemonic.to_phrase();
            let words: Vec<&str> = phrase.split_whitespace().collect();
            prop_assert_eq!(words.len(), word_count as usize);
        }
    }

    // **Feature: rustywallet-mnemonic, Property 8: Private Key Derivation Validity**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]
        #[test]
        fn prop_private_key_derivation_valid(word_count in prop_oneof![
            Just(WordCount::Words12),
            Just(WordCount::Words24),
        ]) {
            let mnemonic = Mnemonic::generate(word_count);
            let result = mnemonic.to_private_key("");
            prop_assert!(result.is_ok());
        }
    }
}
