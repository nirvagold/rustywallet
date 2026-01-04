//! BIP39 wordlist implementations.
//!
//! This module provides wordlists for multiple languages as defined in BIP39.
//! Each wordlist contains exactly 2048 words.

mod chinese_simplified;
mod english;
mod japanese;
mod korean;
mod spanish;

pub use chinese_simplified::CHINESE_SIMPLIFIED_WORDLIST;
pub use english::ENGLISH_WORDLIST;
pub use japanese::JAPANESE_WORDLIST;
pub use korean::KOREAN_WORDLIST;
pub use spanish::SPANISH_WORDLIST;

/// Supported languages for mnemonic generation.
///
/// BIP39 defines wordlists for multiple languages. Each wordlist contains
/// exactly 2048 words that are used to encode entropy into a mnemonic phrase.
///
/// # Example
///
/// ```
/// use rustywallet_mnemonic::Language;
///
/// let lang = Language::English;
/// assert!(lang.contains("abandon"));
///
/// let lang = Language::Japanese;
/// assert!(lang.contains("あいこくしん"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum Language {
    /// English wordlist (BIP39 standard)
    #[default]
    English,
    /// Japanese wordlist (BIP39)
    Japanese,
    /// Spanish wordlist (BIP39)
    Spanish,
    /// Chinese Simplified wordlist (BIP39)
    ChineseSimplified,
    /// Korean wordlist (BIP39)
    Korean,
}

impl Language {
    /// Get all supported languages.
    pub fn all() -> &'static [Language] {
        &[
            Language::English,
            Language::Japanese,
            Language::Spanish,
            Language::ChineseSimplified,
            Language::Korean,
        ]
    }

    /// Get the wordlist for this language.
    pub fn wordlist(&self) -> &'static [&'static str; 2048] {
        match self {
            Language::English => &ENGLISH_WORDLIST,
            Language::Japanese => &JAPANESE_WORDLIST,
            Language::Spanish => &SPANISH_WORDLIST,
            Language::ChineseSimplified => &CHINESE_SIMPLIFIED_WORDLIST,
            Language::Korean => &KOREAN_WORDLIST,
        }
    }

    /// Get word at index (0-2047).
    pub fn get_word(&self, index: usize) -> Option<&'static str> {
        if index < 2048 {
            Some(self.wordlist()[index])
        } else {
            None
        }
    }

    /// Get index of word in wordlist.
    pub fn get_index(&self, word: &str) -> Option<usize> {
        let word_lower = word.to_lowercase();
        self.wordlist().iter().position(|&w| w == word_lower)
    }

    /// Check if word exists in wordlist.
    pub fn contains(&self, word: &str) -> bool {
        self.get_index(word).is_some()
    }

    /// Get the language name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Japanese => "Japanese",
            Language::Spanish => "Spanish",
            Language::ChineseSimplified => "Chinese (Simplified)",
            Language::Korean => "Korean",
        }
    }

    /// Detect language from a single word.
    ///
    /// Returns the first language that contains the word.
    /// Note: Some words may exist in multiple wordlists.
    pub fn detect_from_word(word: &str) -> Option<Language> {
        for lang in Self::all() {
            if lang.contains(word) {
                return Some(*lang);
            }
        }
        None
    }

    /// Detect language from a phrase by checking all words.
    ///
    /// Returns the language where all words are found in the wordlist.
    /// Returns None if no single language contains all words.
    pub fn detect_from_phrase(phrase: &str) -> Option<Language> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        if words.is_empty() {
            return None;
        }

        for lang in Self::all() {
            let all_match = words.iter().all(|word| lang.contains(word));
            if all_match {
                return Some(*lang);
            }
        }
        None
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_english_wordlist() {
        let lang = Language::English;
        assert_eq!(lang.wordlist().len(), 2048);
        assert_eq!(lang.get_word(0), Some("abandon"));
        assert_eq!(lang.get_word(2047), Some("zoo"));
        assert!(lang.contains("abandon"));
        assert!(!lang.contains("notaword"));
    }

    #[test]
    fn test_japanese_wordlist() {
        let lang = Language::Japanese;
        assert_eq!(lang.wordlist().len(), 2048);
        assert_eq!(lang.get_word(0), Some("あいこくしん"));
        assert!(lang.contains("あいこくしん"));
    }

    #[test]
    fn test_spanish_wordlist() {
        let lang = Language::Spanish;
        assert_eq!(lang.wordlist().len(), 2048);
        assert_eq!(lang.get_word(0), Some("ábaco"));
        assert!(lang.contains("ábaco"));
    }

    #[test]
    fn test_chinese_simplified_wordlist() {
        let lang = Language::ChineseSimplified;
        assert_eq!(lang.wordlist().len(), 2048);
        assert_eq!(lang.get_word(0), Some("的"));
        assert!(lang.contains("的"));
    }

    #[test]
    fn test_korean_wordlist() {
        let lang = Language::Korean;
        assert_eq!(lang.wordlist().len(), 2048);
        assert_eq!(lang.get_word(0), Some("가격"));
        assert!(lang.contains("가격"));
    }

    #[test]
    fn test_detect_from_word() {
        assert_eq!(Language::detect_from_word("abandon"), Some(Language::English));
        assert_eq!(Language::detect_from_word("あいこくしん"), Some(Language::Japanese));
        assert_eq!(Language::detect_from_word("ábaco"), Some(Language::Spanish));
        assert_eq!(Language::detect_from_word("的"), Some(Language::ChineseSimplified));
        assert_eq!(Language::detect_from_word("가격"), Some(Language::Korean));
        assert_eq!(Language::detect_from_word("notaword"), None);
    }

    #[test]
    fn test_detect_from_phrase() {
        let english_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(Language::detect_from_phrase(english_phrase), Some(Language::English));
    }

    #[test]
    fn test_all_languages() {
        let all = Language::all();
        assert_eq!(all.len(), 5);
        assert!(all.contains(&Language::English));
        assert!(all.contains(&Language::Japanese));
        assert!(all.contains(&Language::Spanish));
        assert!(all.contains(&Language::ChineseSimplified));
        assert!(all.contains(&Language::Korean));
    }
}
