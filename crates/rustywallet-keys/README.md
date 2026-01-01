# rustywallet-keys

[![Crates.io](https://img.shields.io/crates/v/rustywallet-keys.svg)](https://crates.io/crates/rustywallet-keys)
[![Documentation](https://docs.rs/rustywallet-keys/badge.svg)](https://docs.rs/rustywallet-keys)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/nirvagold/rustywallet/ci.yml?branch=main)](https://github.com/nirvagold/rustywallet/actions)
[![codecov](https://codecov.io/gh/nirvagold/rustywallet/branch/main/graph/badge.svg)](https://codecov.io/gh/nirvagold/rustywallet)

Secure secp256k1 private and public key management for cryptocurrency applications with batch generation capabilities.

## Features

- 🔐 **Secure Key Generation** - CSPRNG-based random key generation
- 📥 **Multiple Import Formats** - Hex, WIF, raw bytes
- 📤 **Multiple Export Formats** - Hex, WIF, decimal, raw bytes
- 🔑 **Public Key Derivation** - Compressed and uncompressed formats
- 🛡️ **Secure Memory** - Automatic zeroization on drop
- ✅ **Validation** - Comprehensive key validation
- 🔄 **Batch Generation** - Efficient iterator-based batch key generation
- 🚀 **High Performance** - Optimized for speed and memory efficiency
- 🌐 **Network Support** - Bitcoin mainnet and testnet

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rustywallet-keys = "0.1.1"
```

## Quick Start

### Basic Usage

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

### Batch Generation Example

```rust
use rustywallet_keys::prelude::*;

// Generate 1000 keys efficiently
let keys: Vec<PrivateKey> = PrivateKey::batch_generate(1000).collect();

// Process keys in batches
for (i, key) in PrivateKey::batch_generate(100).enumerate() {
    let public_key = key.public_key();
    println!("Key {}: {}", i, public_key.to_hex(PublicKeyFormat::Compressed));
}
```

## Import/Export Formats

### Import Private Key

```rust
use rustywallet_keys::prelude::*;

// From hex string (64 characters)
let key = PrivateKey::from_hex(
    "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
)?;

// From WIF (Wallet Import Format)
let key = PrivateKey::from_wif(
    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
)?;

// From raw bytes
let bytes = [1u8; 32];
let key = PrivateKey::from_bytes(bytes)?;

// From decimal string
let key = PrivateKey::from_decimal(
    "5208840098459174055877047153126831306395896654089761670644442129"
)?;
```

### Export Formats

```rust
use rustywallet_keys::prelude::*;

let key = PrivateKey::random();

// Hex format (64 characters, lowercase)
let hex = key.to_hex();

// WIF (Wallet Import Format)
let wif_mainnet = key.to_wif(Network::Mainnet);  // Starts with 'K' or 'L'
let wif_testnet = key.to_wif(Network::Testnet);  // Starts with 'c'

// Decimal string representation
let decimal = key.to_decimal();

// Raw bytes (32 bytes)
let bytes: [u8; 32] = key.to_bytes();
```

## Public Key Operations

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

// Verify key pair
assert!(public_key.verify_private_key(&private_key));
```

## Batch Generation

The batch generation feature provides an efficient iterator for generating multiple keys:

```rust
use rustywallet_keys::prelude::*;

// Generate keys lazily with iterator
let mut key_iter = PrivateKey::batch_generate(10000);

// Take first 100 keys
let first_batch: Vec<PrivateKey> = key_iter.take(100).collect();

// Generate keys with custom processing
for key in PrivateKey::batch_generate(1000) {
    let public_key = key.public_key();
    let address = public_key.to_address(Network::Mainnet);
    
    // Process key/address pair
    if address.starts_with("1A") {
        println!("Found vanity address: {}", address);
        break;
    }
}

// Memory-efficient batch processing
const BATCH_SIZE: usize = 1000;
let total_keys = 100_000;

for batch_start in (0..total_keys).step_by(BATCH_SIZE) {
    let batch: Vec<PrivateKey> = PrivateKey::batch_generate(BATCH_SIZE).collect();
    
    // Process batch
    for (i, key) in batch.iter().enumerate() {
        println!("Key {}: {}", batch_start + i, key.to_hex());
    }
}
```

## API Reference

### PrivateKey

#### Creation Methods
- `PrivateKey::random()` - Generate random key using CSPRNG
- `PrivateKey::from_hex(hex: &str)` - Import from hex string
- `PrivateKey::from_wif(wif: &str)` - Import from WIF format
- `PrivateKey::from_bytes(bytes: [u8; 32])` - Import from raw bytes
- `PrivateKey::from_decimal(decimal: &str)` - Import from decimal string
- `PrivateKey::batch_generate(count: usize)` - Create batch iterator

#### Export Methods
- `to_hex(&self) -> String` - Export as hex string
- `to_wif(&self, network: Network) -> String` - Export as WIF
- `to_decimal(&self) -> String` - Export as decimal string
- `to_bytes(&self) -> [u8; 32]` - Export as raw bytes

#### Key Operations
- `public_key(&self) -> PublicKey` - Derive public key
- `is_valid(&self) -> bool` - Validate private key

### PublicKey

#### Export Methods
- `to_hex(&self, format: PublicKeyFormat) -> String` - Export as hex
- `to_compressed(&self) -> [u8; 33]` - Export compressed format
- `to_uncompressed(&self) -> [u8; 65]` - Export uncompressed format
- `to_address(&self, network: Network) -> String` - Generate address

#### Verification
- `verify_private_key(&self, private_key: &PrivateKey) -> bool` - Verify key pair

### Enums

#### Network
- `Network::Mainnet` - Bitcoin mainnet
- `Network::Testnet` - Bitcoin testnet

#### PublicKeyFormat
- `PublicKeyFormat::Compressed` - 33-byte compressed format
- `PublicKeyFormat::Uncompressed` - 65-byte uncompressed format

## Security Notes

### Memory Security
- Private keys are automatically zeroized when dropped using the `zeroize` crate
- Sensitive data is cleared from memory to prevent recovery
- No private key data is left in memory after use

### Cryptographic Security
- Uses the battle-tested `secp256k1` crate for all cryptographic operations
- Random number generation uses OS-level CSPRNG (`OsRng`)
- All keys are validated according to secp256k1 curve parameters

### Best Practices
- Always validate imported keys before use
- Use secure channels when transmitting keys
- Store private keys encrypted when persisting to disk
- Never log or print private keys in production
- Use testnet for development and testing

### Threat Model
This library protects against:
- Memory dumps revealing private keys after use
- Invalid key generation or import
- Weak random number generation

This library does NOT protect against:
- Side-channel attacks during key operations
- Physical access to running memory
- Malware with memory access privileges
- Social engineering attacks

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Part of rustywallet

This crate is part of the [rustywallet](https://github.com/nirvagold/rustywallet) ecosystem, providing secure and efficient cryptocurrency key management tools.