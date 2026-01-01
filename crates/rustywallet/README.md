# rustywallet

[![Crates.io](https://img.shields.io/crates/v/rustywallet.svg)](https://crates.io/crates/rustywallet)
[![Documentation](https://docs.rs/rustywallet/badge.svg)](https://docs.rs/rustywallet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/username/rustywallet/workflows/CI/badge.svg)](https://github.com/username/rustywallet/actions)

A comprehensive Rust library ecosystem for cryptocurrency wallet utilities. This umbrella crate provides a unified API for all wallet-related operations including key management, address generation, mnemonic handling, hierarchical deterministic wallets, message signing, and blockchain utilities.

## Overview

The rustywallet ecosystem consists of modular crates that work together to provide complete cryptocurrency wallet functionality:

- **Cryptographic primitives** - Secure key generation and management
- **Address generation** - Support for Bitcoin, Ethereum, and other cryptocurrencies  
- **Mnemonic phrases** - BIP39 compliant seed phrase generation and validation
- **HD wallets** - BIP32/BIP44 hierarchical deterministic wallet derivation
- **Message signing** - ECDSA signature creation and verification
- **Blockchain utilities** - Address validation, bloom filters, and more

## Crates

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet-keys](https://crates.io/crates/rustywallet-keys) | [![Crates.io](https://img.shields.io/crates/v/rustywallet-keys.svg)](https://crates.io/crates/rustywallet-keys) | Private and public key management (secp256k1) |
| [rustywallet-address](https://crates.io/crates/rustywallet-address) | [![Crates.io](https://img.shields.io/crates/v/rustywallet-address.svg)](https://crates.io/crates/rustywallet-address) | Bitcoin and Ethereum address generation |
| [rustywallet-mnemonic](https://crates.io/crates/rustywallet-mnemonic) | [![Crates.io](https://img.shields.io/crates/rustywallet-mnemonic.svg)](https://crates.io/crates/rustywallet-mnemonic) | BIP39 mnemonic phrase support |
| [rustywallet-hd](https://crates.io/crates/rustywallet-hd) | [![Crates.io](https://img.shields.io/crates/v/rustywallet-hd.svg)](https://crates.io/crates/rustywallet-hd) | BIP32/BIP44 hierarchical deterministic wallets |
| [rustywallet-signer](https://crates.io/crates/rustywallet-signer) | [![Crates.io](https://img.shields.io/crates/v/rustywallet-signer.svg)](https://crates.io/crates/rustywallet-signer) | ECDSA message signing and verification |
| [rustywallet-checker](https://crates.io/crates/rustywallet-checker) | [![Crates.io](https://img.shields.io/crates/v/rustywallet-checker.svg)](https://crates.io/crates/rustywallet-checker) | Address validation and format checking |
| [rustywallet-bloom](https://crates.io/crates/rustywallet-bloom) | [![Crates.io](https://img.shields.io/crates/v/rustywallet-bloom.svg)](https://crates.io/crates/rustywallet-bloom) | Bloom filter implementation for efficient lookups |

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rustywallet = "0.1.0"
```

## Quick Start

The unified API provides easy access to all wallet functionality:

```rust
use rustywallet::prelude::*;

// Generate a random private key
let key = PrivateKey::random();
let pubkey = key.public_key();

// Generate Bitcoin address
let address = Address::from_public_key(&pubkey, AddressType::P2PKH, Network::Bitcoin);

println!("Private key: {}", key.to_hex());
println!("Address: {}", address);
```

### Complete Wallet Workflow

```rust
use rustywallet::prelude::*;

// 1. Generate mnemonic phrase
let mnemonic = Mnemonic::generate(WordCount::Words12);
println!("Mnemonic: {}", mnemonic.phrase());

// 2. Create HD wallet from mnemonic
let seed = mnemonic.to_seed("");
let master = ExtendedPrivateKey::from_seed(&seed, Network::Bitcoin)?;

// 3. Derive account key (BIP44: m/44'/0'/0'/0/0)
let path = DerivationPath::parse("m/44'/0'/0'/0/0")?;
let account_key = master.derive_path(&path)?;

// 4. Generate address
let private_key = account_key.private_key();
let public_key = private_key.public_key();
let address = Address::from_public_key(&public_key, AddressType::P2PKH, Network::Bitcoin);

// 5. Sign a message
let message = "Hello, Bitcoin!";
let signature = Signer::sign_message(&private_key, message)?;

println!("Address: {}", address);
println!("Signature: {}", signature.to_hex());
```

## Feature Flags

All features are enabled by default. You can selectively enable only the functionality you need:

```toml
[dependencies]
rustywallet = { version = "0.1.0", default-features = false, features = ["keys", "address"] }
```

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `keys` | Private/public key management | - |
| `address` | Address generation and validation | `keys` |
| `mnemonic` | BIP39 mnemonic phrase support | - |
| `hd` | HD wallet derivation (BIP32/BIP44) | `keys`, `mnemonic` |
| `signer` | Message signing and verification | `keys` |
| `checker` | Address validation utilities | `address` |
| `bloom` | Bloom filter implementation | - |
| `full` | All features (default) | all above |

### Individual Crate Usage

You can also use individual crates directly:

```toml
[dependencies]
rustywallet-keys = "0.1.0"
rustywallet-address = "0.1.0"
```

## Examples

### Key Generation
```rust
use rustywallet::keys::*;

let private_key = PrivateKey::random();
let public_key = private_key.public_key();
let compressed = public_key.serialize_compressed();
```

### Mnemonic Handling
```rust
use rustywallet::mnemonic::*;

let mnemonic = Mnemonic::generate(WordCount::Words24);
let seed = mnemonic.to_seed("optional_passphrase");
```

### Address Validation
```rust
use rustywallet::checker::*;

let is_valid = AddressChecker::validate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
let format = AddressChecker::detect_format("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.