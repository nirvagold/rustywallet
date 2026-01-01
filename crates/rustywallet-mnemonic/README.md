# rustywallet-mnemonic

[![Crates.io](https://img.shields.io/crates/v/rustywallet-mnemonic.svg)](https://crates.io/crates/rustywallet-mnemonic)
[![Documentation](https://docs.rs/rustywallet-mnemonic/badge.svg)](https://docs.rs/rustywallet-mnemonic)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/rustywallet/rustywallet-mnemonic/workflows/CI/badge.svg)](https://github.com/rustywallet/rustywallet-mnemonic/actions)

BIP39 mnemonic (seed phrase) generation and management for cryptocurrency wallets with secure memory handling and comprehensive validation.

## Features

- **Mnemonic Generation**: Generate cryptographically secure 12, 15, 18, 21, or 24-word mnemonics
- **Validation**: Complete mnemonic validation including checksum verification and wordlist compliance
- **Seed Derivation**: PBKDF2-HMAC-SHA512 seed derivation with optional passphrase support
- **Passphrase Support**: BIP39 "25th word" passphrase functionality for enhanced security
- **Memory Security**: Automatic zeroization of sensitive data on drop
- **Standard Compliance**: Full BIP39 specification compliance with English wordlist
- **Integration Ready**: Seamless integration with rustywallet-keys for key derivation

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rustywallet-mnemonic = "0.1.0"
```

## Quick Start

```rust
use rustywallet_mnemonic::prelude::*;

// Generate a new 12-word mnemonic
let mnemonic = Mnemonic::generate(WordCount::Words12);
println!("Mnemonic: {}", mnemonic.to_phrase());

// Derive seed with passphrase
let seed = mnemonic.to_seed("my-passphrase");
println!("Seed: {}", seed.to_hex());
```

## Mnemonic Generation

### Generate Different Word Counts

```rust
use rustywallet_mnemonic::prelude::*;

// 12-word mnemonic (128-bit entropy)
let mnemonic_12 = Mnemonic::generate(WordCount::Words12);

// 24-word mnemonic (256-bit entropy) - recommended for maximum security
let mnemonic_24 = Mnemonic::generate(WordCount::Words24);

// Other supported lengths
let mnemonic_15 = Mnemonic::generate(WordCount::Words15);
let mnemonic_18 = Mnemonic::generate(WordCount::Words18);
let mnemonic_21 = Mnemonic::generate(WordCount::Words21);
```

### Parse Existing Mnemonic

```rust
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase)?;
```

## Seed Derivation

### With Passphrase (BIP39 "25th word")

```rust
let mnemonic = Mnemonic::generate(WordCount::Words12);

// Derive seed with passphrase for enhanced security
let seed_with_passphrase = mnemonic.to_seed("my-secret-passphrase");

// Different passphrases produce different seeds
let seed_different = mnemonic.to_seed("different-passphrase");
```

### Without Passphrase

```rust
// Standard seed derivation without passphrase
let seed = mnemonic.to_seed("");
// or use the convenience method
let seed_normalized = mnemonic.to_seed_normalized();
```

## Passphrase Support

Passphrases provide an additional layer of security by acting as a "25th word":

```rust
let mnemonic = Mnemonic::from_phrase("your twelve word mnemonic phrase here")?;

// Each passphrase creates a different wallet
let wallet_1 = mnemonic.to_seed("passphrase1");
let wallet_2 = mnemonic.to_seed("passphrase2");
let wallet_3 = mnemonic.to_seed(""); // No passphrase

// All three seeds will be completely different
assert_ne!(wallet_1.as_bytes(), wallet_2.as_bytes());
assert_ne!(wallet_1.as_bytes(), wallet_3.as_bytes());
```

## Validation

### Mnemonic Validation

```rust
// Validate mnemonic phrase
let valid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
assert!(Mnemonic::from_phrase(valid_phrase).is_ok());

// Invalid checksum
let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
assert!(Mnemonic::from_phrase(invalid_phrase).is_err());

// Invalid word
let invalid_word = "invalid abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
assert!(Mnemonic::from_phrase(invalid_word).is_err());
```

### Word Count Validation

```rust
// Check if phrase has correct word count
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let word_count = phrase.split_whitespace().count();
assert_eq!(word_count, 12);
```

## API Reference

### Core Types

#### `Mnemonic`

The main mnemonic type with secure memory handling.

```rust
impl Mnemonic {
    // Generate new mnemonic
    pub fn generate(word_count: WordCount) -> Self;
    
    // Parse from phrase
    pub fn from_phrase(phrase: &str) -> Result<Self, MnemonicError>;
    
    // Convert to phrase string
    pub fn to_phrase(&self) -> String;
    
    // Derive seed with passphrase
    pub fn to_seed(&self, passphrase: &str) -> Seed;
    
    // Derive seed without passphrase
    pub fn to_seed_normalized(&self) -> Seed;
    
    // Derive private key directly
    pub fn to_private_key(&self, passphrase: &str) -> Result<PrivateKey, KeyError>;
}
```

#### `WordCount`

Supported mnemonic lengths.

```rust
pub enum WordCount {
    Words12,  // 128-bit entropy
    Words15,  // 160-bit entropy
    Words18,  // 192-bit entropy
    Words21,  // 224-bit entropy
    Words24,  // 256-bit entropy
}
```

#### `Seed`

Derived seed with secure memory handling.

```rust
impl Seed {
    pub fn as_bytes(&self) -> &[u8];
    pub fn to_hex(&self) -> String;
}
```

### BIP39 Specification Compliance

| Word Count | Entropy Bits | Checksum Bits | Total Bits | Security Level |
|------------|--------------|---------------|------------|----------------|
| 12         | 128          | 4             | 132        | Standard       |
| 15         | 160          | 5             | 165        | Enhanced       |
| 18         | 192          | 6             | 198        | High           |
| 21         | 224          | 7             | 231        | Very High      |
| 24         | 256          | 8             | 264        | Maximum        |

### Error Handling

```rust
use rustywallet_mnemonic::MnemonicError;

match Mnemonic::from_phrase("invalid phrase") {
    Ok(mnemonic) => println!("Valid mnemonic"),
    Err(MnemonicError::InvalidChecksum) => println!("Checksum validation failed"),
    Err(MnemonicError::InvalidWordCount) => println!("Invalid number of words"),
    Err(MnemonicError::InvalidWord(word)) => println!("Invalid word: {}", word),
}
```

## Security Considerations

- **Entropy Source**: Uses `OsRng` for cryptographically secure random number generation
- **Memory Safety**: All sensitive data (entropy, seeds) is automatically zeroized on drop
- **Debug Protection**: Debug output is masked to prevent accidental exposure in logs
- **PBKDF2 Parameters**: Uses 2048 iterations with HMAC-SHA512 as per BIP39 specification
- **Constant-Time Operations**: Checksum validation uses constant-time comparison

## Integration with rustywallet-keys

```rust
use rustywallet_mnemonic::prelude::*;
use rustywallet_keys::prelude::*;

// Generate mnemonic and derive keys
let mnemonic = Mnemonic::generate(WordCount::Words12);
let private_key = mnemonic.to_private_key("my-passphrase")?;

// Derive public key and address
let public_key = private_key.public_key();
let address = public_key.to_address();

println!("Address: {}", address);
```

## Examples

See the `examples/` directory for complete usage examples:

- `generate.rs` - Basic mnemonic generation
- `validation.rs` - Mnemonic validation examples
- `passphrase.rs` - Passphrase usage patterns
- `integration.rs` - Integration with other rustywallet crates

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.