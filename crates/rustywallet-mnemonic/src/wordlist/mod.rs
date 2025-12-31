//! BIP39 wordlist implementations.

mod english;

pub use english::ENGLISH_WORDLIST;

/// Supported languages for mnemonic generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    /// English wordlist (BIP39 standard)
    #[default]
    English,
}

impl Language {
    /// Get the wordlist for this language.
    pub fn wordlist(&self) -> &'static [&'static str; 2048] {
        match self {
            Language::English => &ENGLISH_WORDLIST,
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
        self.wordlist()
            .iter()
            .position(|&w| w == word_lower)
    }

    /// Check if word exists in wordlist.
    pub fn contains(&self, word: &str) -> bool {
        self.get_index(word).is_some()
    }
}
