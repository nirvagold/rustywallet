# rustywallet-keys

[![Crates.io](https://img.shields.io/crates/v/rustywallet-keys.svg)](https://crates.io/crates/rustywallet-keys)
[![Documentation](https://docs.rs/rustywallet-keys/badge.svg)](https://docs.rs/rustywallet-keys)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Secure secp256k1 private and public key management for cryptocurrency applications.

## Features

- 🔐 **Secure Key Generation** - CSPRNG-based random key generation
- 📥 **Multiple Import Formats** - Hex, WIF, raw bytes
- 📤 **Multiple Export Formats** - Hex, WIF, decimal, raw bytes
- 🔑 **Public Key Derivation** - Compressed and uncompressed formats
- 🛡️ **Secure Memory** - Automatic zeroization on drop
- ✅ **Validation** - Comprehensive key validation

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rustywallet-keys = "0.1"
```

## Quick Start

```rust
use rustywallet_keys::prelude::*;

// Generate a random private key
let private_key = PrivateKey::random();

// Export to various formats
println!("Hex: {}", private_key.to_hex());
println!("WIF (mainnet): {}", private_key.to_wif(Network::Mainnet));
println!("Decimal: {}", private_key.to_decimal());

// Derive public key
let public_key = private_key.public_key();
println!("Public Key: {}", public_key.to_hex(PublicKeyFormat::Compressed));
```

## Import Private Key

```rust
use rustywallet_keys::prelude::*;

// From hex string
let key = PrivateKey::from_hex(
    "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
)?;

// From WIF
let key = PrivateKey::from_wif(
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
)?;

// From bytes
let bytes = [1u8; 32];
let key = PrivateKey::from_bytes(bytes)?;
```

## Export Formats

```rust
use rustywallet_keys::prelude::*;

let key = PrivateKey::random();

// Hex (64 characters)
let hex = key.to_hex();

// WIF (Wallet Import Format)
let wif_mainnet = key.to_wif(Network::Mainnet);  // Starts with 'K' or 'L'
let wif_testnet = key.to_wif(Network::Testnet);  // Starts with 'c'

// Decimal
let decimal = key.to_decimal();

// Raw bytes
let bytes: [u8; 32] = key.to_bytes();
```

## Public Key

```rust
use rustywallet_keys::prelude::*;

let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Compressed format (33 bytes, starts with 02 or 03)
let compressed = public_key.to_compressed();
let compressed_hex = public_key.to_hex(PublicKeyFormat::Compressed);

// Uncompressed format (65 bytes, starts with 04)
let uncompressed = public_key.to_uncompressed();
let uncompressed_hex = public_key.to_hex(PublicKeyFormat::Uncompressed);
```

## Security

- Private keys are automatically zeroized when dropped
- Uses `secp256k1` crate for cryptographic operations
- Uses OS-level CSPRNG (`OsRng`) for key generation

## License

MIT License - see [LICENSE](LICENSE) for details.

## Part of rustywallet

This crate is part of the [rustywallet](https://github.com/nirvagold/rustywallet) ecosystem.
