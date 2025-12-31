# rustywallet-mnemonic

BIP39 mnemonic (seed phrase) generation and management for cryptocurrency wallets.

## Features

- Generate random mnemonic phrases (12, 15, 18, 21, or 24 words)
- Validate mnemonic phrases (checksum and wordlist)
- Derive seeds from mnemonics with optional passphrase
- Derive private keys from seeds
- Secure memory handling (zeroize on drop)
- English wordlist (BIP39 standard)

## Installation

```toml
[dependencies]
rustywallet-mnemonic = "0.1"
```

## Usage

```rust
use rustywallet_mnemonic::prelude::*;

// Generate a new 12-word mnemonic
let mnemonic = Mnemonic::generate(WordCount::Words12);
println!("Mnemonic: {}", mnemonic.to_phrase());

// Generate a 24-word mnemonic for higher security
let mnemonic_24 = Mnemonic::generate(WordCount::Words24);

// Parse an existing mnemonic
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase).unwrap();

// Derive seed with passphrase (BIP39 "25th word")
let seed = mnemonic.to_seed("my-secret-passphrase");
println!("Seed: {}", seed.to_hex());

// Derive seed without passphrase
let seed_no_pass = mnemonic.to_seed_normalized();

// Derive private key directly
let private_key = mnemonic.to_private_key("passphrase").unwrap();
```

## BIP39 Specification

| Word Count | Entropy Bits | Checksum Bits | Security Level |
|------------|--------------|---------------|----------------|
| 12         | 128          | 4             | Standard       |
| 15         | 160          | 5             | Enhanced       |
| 18         | 192          | 6             | High           |
| 21         | 224          | 7             | Very High      |
| 24         | 256          | 8             | Maximum        |

## Security

- Entropy and seed bytes are zeroized on drop
- Debug output is masked to prevent accidental exposure
- Uses cryptographically secure random number generation (OsRng)
- PBKDF2-HMAC-SHA512 with 2048 iterations for seed derivation

## Integration with rustywallet-keys

```rust
use rustywallet_mnemonic::prelude::*;
use rustywallet_keys::prelude::*;

// Generate mnemonic and derive key
let mnemonic = Mnemonic::generate(WordCount::Words12);
let private_key = mnemonic.to_private_key("").unwrap();

// Derive public key
let public_key = private_key.public_key();
println!("Public Key: {}", public_key.to_hex_compressed());
```

## License

MIT
