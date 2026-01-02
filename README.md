# rustywallet 🦀💰

A collection of Rust crates for cryptocurrency wallet utilities with focus on clean Developer Experience (DX) and type-safety.

[![Crates.io](https://img.shields.io/crates/v/rustywallet.svg)](https://crates.io/crates/rustywallet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Crates

### Core (Phase 1) ✔️ Complete

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet](https://crates.io/crates/rustywallet) | 0.1.0 | Umbrella crate - all features in one |
| [rustywallet-keys](https://crates.io/crates/rustywallet-keys) | 0.1.2 | Private & Public key management |
| [rustywallet-address](https://crates.io/crates/rustywallet-address) | 0.1.1 | Address generation (P2PKH, P2SH, P2WPKH, P2TR, ETH) |
| [rustywallet-mnemonic](https://crates.io/crates/rustywallet-mnemonic) | 0.1.0 | BIP39 mnemonic/seed phrase |
| [rustywallet-hd](https://crates.io/crates/rustywallet-hd) | 0.1.0 | HD Wallet (BIP32/BIP44/BIP84) |
| [rustywallet-signer](https://crates.io/crates/rustywallet-signer) | 0.1.0 | Message & transaction signing |
| [rustywallet-checker](https://crates.io/crates/rustywallet-checker) | 0.1.0 | Address balance checking via APIs |
| [rustywallet-bloom](https://crates.io/crates/rustywallet-bloom) | 0.1.0 | Bloom filter for address matching |
| [rustywallet-cli](https://crates.io/crates/rustywallet-cli) | 0.1.0 | Command-line interface |

### Performance (Phase 2) ✅ In Progress

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet-batch](https://crates.io/crates/rustywallet-batch) | 0.1.3 | High-performance batch key generation (7M+ keys/sec) |
| [rustywallet-vanity](https://crates.io/crates/rustywallet-vanity) | 0.1.3 | Vanity address generator |
| [rustywallet-electrum](https://crates.io/crates/rustywallet-electrum) | 0.1.0 | Electrum protocol client (no rate limits!) |
| rustywallet-gpu | ⏸️ | GPU-accelerated generation (paused) |

### Network (Phase 4) 📋 Planned

| Crate | Status | Description |
|-------|--------|-------------|
| rustywallet-mempool | 🔜 Next | Mempool.space API integration |
| rustywallet-import | 📋 | Import from wallet formats |
| rustywallet-export | 📋 | Export to various formats |

## Quick Start

### Using the umbrella crate

```toml
[dependencies]
rustywallet = "0.1"
```

```rust
use rustywallet::prelude::*;

// Generate a random private key
let private_key = PrivateKey::random();
println!("WIF: {}", private_key.to_wif(Network::Mainnet));

// Generate Bitcoin address
let address = Address::p2wpkh(&private_key.public_key(), Network::Mainnet)?;
println!("Address: {}", address);

// Generate from mnemonic
let mnemonic = Mnemonic::generate(12)?;
println!("Mnemonic: {}", mnemonic.phrase());
```

### High-Performance Batch Generation

```rust
use rustywallet_batch::prelude::*;

// Generate 1 million keys with FastKeyGenerator (7M+ keys/sec)
let generator = FastKeyGenerator::new();
for key in generator.take(1_000_000) {
    // Process key...
}
```

### Vanity Address Generation

```rust
use rustywallet_vanity::prelude::*;

// Find address starting with "1Love"
let result = VanityGenerator::new()
    .pattern(Pattern::prefix("1Love"))
    .generate()?;

println!("Found: {}", result.address);
println!("Private Key: {}", result.private_key.to_wif(Network::Mainnet));
```

### Electrum Balance Checking (No Rate Limits!)

```rust
use rustywallet_electrum::{ElectrumClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ElectrumClient::new("electrum.blockstream.info").await?;
    
    // Check balance
    let balance = client.get_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await?;
    println!("Balance: {} sats", balance.confirmed);
    
    // Batch check multiple addresses
    let addresses = vec!["addr1...", "addr2...", "addr3..."];
    let balances = client.get_balances(&addresses).await?;
    
    Ok(())
}
```

## Features

### rustywallet-keys
- 🔐 Secure random key generation (CSPRNG)
- 📥 Import from hex, WIF, bytes
- 📤 Export to hex, WIF, decimal, bytes
- 🔑 Public key derivation (compressed/uncompressed)
- 🛡️ Secure memory handling (zeroize on drop)

### rustywallet-address
- 🏠 P2PKH (1...), P2SH (3...), P2WPKH (bc1q...), P2TR (bc1p...)
- 🔷 Ethereum addresses (0x...)
- ✅ Address validation

### rustywallet-batch
- ⚡ 7M+ keys/sec with FastKeyGenerator
- 🔄 Incremental EC point addition scanning
- 📊 Memory-efficient streaming
- 🎯 Configurable presets (fast, balanced, memory_efficient)

### rustywallet-vanity
- 🎨 Prefix, suffix, contains patterns
- 📊 Difficulty estimation
- 🔄 Progress callbacks
- ⚡ Multi-threaded search

### rustywallet-electrum
- 🌐 TCP and TLS/SSL connections
- 📦 Batch balance checking
- 💰 UTXO listing
- 📡 Transaction broadcast
- 🚫 No rate limits!

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
