# rustywallet

A comprehensive Rust library for cryptocurrency wallet utilities.

## Features

- **keys** - Private and public key management (secp256k1)
- **address** - Bitcoin and Ethereum address generation
- **mnemonic** - BIP39 mnemonic phrase support
- **hd** - BIP32/BIP44 hierarchical deterministic wallets
- **signer** - ECDSA message signing and verification

## Installation

```toml
[dependencies]
rustywallet = "0.1"
```

### Feature Flags

All features are enabled by default. You can disable default features and enable only what you need:

```toml
[dependencies]
rustywallet = { version = "0.1", default-features = false, features = ["keys", "address"] }
```

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `keys` | Private/public key management | - |
| `address` | Address generation | `keys` |
| `mnemonic` | BIP39 mnemonic phrases | - |
| `hd` | HD wallets (BIP32/BIP44) | `keys` |
| `signer` | Message signing | `keys` |
| `full` | All features (default) | all |

## Quick Start

```rust
use rustywallet::prelude::*;

// Generate a random private key
let key = PrivateKey::random();
let pubkey = key.public_key();

println!("Private key: {}", key.to_hex());
println!("Public key: {}", pubkey.to_hex(PublicKeyFormat::Compressed));
```

## Full Wallet Workflow

```rust
use rustywallet::prelude::*;

// 1. Generate mnemonic
let mnemonic = Mnemonic::generate(WordCount::Words12);
println!("Mnemonic: {}", mnemonic.phrase());

// 2. Derive seed
let seed = mnemonic.to_seed("");

// 3. Create HD wallet
let master = ExtendedPrivateKey::from_seed(seed.as_bytes(), HdNetwork::Mainnet).unwrap();

// 4. Derive child key (BIP44: m/44'/0'/0'/0/0)
let path = DerivationPath::parse("m/44'/0'/0'/0/0").unwrap();
let child = master.derive_path(&path).unwrap();
let privkey = child.private_key().unwrap();

println!("Private key: {}", privkey.to_hex());
```

## Sub-crates

This umbrella crate re-exports the following crates:

| Crate | Description |
|-------|-------------|
| [rustywallet-keys](https://crates.io/crates/rustywallet-keys) | Key management |
| [rustywallet-address](https://crates.io/crates/rustywallet-address) | Address generation |
| [rustywallet-mnemonic](https://crates.io/crates/rustywallet-mnemonic) | BIP39 mnemonics |
| [rustywallet-hd](https://crates.io/crates/rustywallet-hd) | HD wallets |
| [rustywallet-signer](https://crates.io/crates/rustywallet-signer) | Message signing |

## License

MIT
