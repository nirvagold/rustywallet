# rustywallet 🦀💰

A comprehensive collection of Rust crates for Bitcoin wallet development with focus on clean Developer Experience (DX), type-safety, and performance.

[![Crates.io](https://img.shields.io/crates/v/rustywallet.svg)](https://crates.io/crates/rustywallet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## 🎯 Features

- **17 Published Crates** - Modular architecture, use only what you need
- **High Performance** - 7M+ keys/sec batch generation
- **Type-Safe** - Leverage Rust's type system for correctness
- **Secure** - Zeroize sensitive data, constant-time operations
- **Well Documented** - Comprehensive docs and examples
- **No Rate Limits** - Electrum protocol for unlimited balance checks

## 📦 Crates

### Core (v1) ✔️ Complete

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet](https://crates.io/crates/rustywallet) | 0.1.0 | Umbrella crate - all features in one |
| [rustywallet-keys](https://crates.io/crates/rustywallet-keys) | 0.1.3 | Private & Public key management |
| [rustywallet-address](https://crates.io/crates/rustywallet-address) | 0.1.3 | Address generation (P2PKH, P2SH, P2WPKH, P2TR, ETH) |
| [rustywallet-mnemonic](https://crates.io/crates/rustywallet-mnemonic) | 0.1.0 | BIP39 mnemonic/seed phrase |
| [rustywallet-hd](https://crates.io/crates/rustywallet-hd) | 0.1.0 | HD Wallet (BIP32/BIP44/BIP84) |
| [rustywallet-signer](https://crates.io/crates/rustywallet-signer) | 0.1.0 | Message & transaction signing |
| [rustywallet-checker](https://crates.io/crates/rustywallet-checker) | 0.1.0 | Address balance checking via APIs |
| [rustywallet-bloom](https://crates.io/crates/rustywallet-bloom) | 0.1.0 | Bloom filter for address matching |
| [rustywallet-cli](https://crates.io/crates/rustywallet-cli) | 0.1.0 | Command-line interface |

### Performance & Network ✔️ Complete

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet-batch](https://crates.io/crates/rustywallet-batch) | 0.1.3 | High-performance batch generation (7M+ keys/sec) |
| [rustywallet-vanity](https://crates.io/crates/rustywallet-vanity) | 0.1.3 | Vanity address generator |
| [rustywallet-electrum](https://crates.io/crates/rustywallet-electrum) | 0.1.0 | Electrum protocol client (no rate limits!) |
| [rustywallet-mempool](https://crates.io/crates/rustywallet-mempool) | 0.1.0 | Mempool.space API integration |

### Utility & Transaction ✔️ Complete

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet-import](https://crates.io/crates/rustywallet-import) | 0.1.0 | Import from WIF, hex, mnemonic, BIP38 |
| [rustywallet-export](https://crates.io/crates/rustywallet-export) | 0.1.0 | Export to JSON, CSV, paper wallet, BIP38 |
| [rustywallet-tx](https://crates.io/crates/rustywallet-tx) | 0.1.0 | Transaction building & signing |
| [rustywallet-multisig](https://crates.io/crates/rustywallet-multisig) | 0.1.0 | Multi-signature wallets + Shamir Secret Sharing |

### Coming Soon (v2)

| Crate | Status | Description |
|-------|--------|-------------|
| rustywallet-psbt | 🔜 Next | PSBT (BIP174) for hardware wallets |
| rustywallet-taproot | 📋 Planned | Full Taproot support (BIP340/341/342) |
| rustywallet-descriptor | 📋 Planned | Output descriptors (BIP380-386) |
| rustywallet-recovery | 📋 Planned | Wallet recovery tools |

### Future (v3)

| Crate | Status | Description |
|-------|--------|-------------|
| rustywallet-lightning | 📋 Planned | Lightning Network (BOLT11) |
| rustywallet-musig | 📋 Planned | MuSig2 Schnorr multisig |
| rustywallet-frost | 📋 Planned | FROST threshold signatures |
| rustywallet-silent | 📋 Planned | Silent Payments (BIP352) |

## 🚀 Quick Start

### Installation

```toml
[dependencies]
rustywallet = "0.1"
```

Or pick individual crates:

```toml
[dependencies]
rustywallet-keys = "0.1"
rustywallet-address = "0.1"
rustywallet-tx = "0.1"
```

### Basic Usage

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

// Generate keys at 7M+ keys/sec
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
```

### Electrum Balance Checking (No Rate Limits!)

```rust
use rustywallet_electrum::{ElectrumClient, Network};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ElectrumClient::connect("electrum.blockstream.info:50002", Network::Mainnet).await?;
    
    // Check balance - no rate limits!
    let balance = client.get_balance("bc1q...").await?;
    println!("Balance: {} sats", balance.confirmed);
    
    // Batch check thousands of addresses
    let addresses = vec!["bc1q...", "bc1q...", "bc1q..."];
    let balances = client.get_balances(&addresses).await?;
    
    Ok(())
}
```

### Transaction Building

```rust
use rustywallet_tx::prelude::*;

// Build a transaction
let unsigned = TxBuilder::new()
    .add_input(utxo)
    .add_output(50_000, recipient_script)
    .set_fee_rate(10) // sat/vB
    .set_change_address("bc1q...")
    .build()?;

// Sign
sign_p2wpkh(&mut unsigned.tx, 0, utxo.value, &private_key)?;

// Broadcast
let hex = unsigned.tx.to_hex();
```

### Multi-Signature Wallet

```rust
use rustywallet_multisig::prelude::*;

// Create 2-of-3 multisig
let wallet = MultisigWallet::from_pubkeys(2, pubkeys, Network::Mainnet)?;

println!("P2SH: {}", wallet.address_p2sh);      // 3...
println!("P2WSH: {}", wallet.address_p2wsh);    // bc1q...

// Sign with multiple keys
let sig1 = sign_p2sh_multisig(&sighash, &key1, &wallet)?;
let sig2 = sign_p2sh_multisig(&sighash, &key2, &wallet)?;
let combined = combine_signatures(&[sig1, sig2], &wallet)?;
```

### Shamir Secret Sharing

```rust
use rustywallet_multisig::{split_secret, combine_shares};

// Split private key into 5 shares, need 3 to recover
let shares = split_secret(&private_key_bytes, 3, 5)?;

// Recover with any 3 shares
let recovered = combine_shares(&shares[0..3])?;
```

### Import/Export

```rust
use rustywallet_import::{import_any, detect_format};
use rustywallet_export::{export_json, export_csv, export_paper_wallet};

// Auto-detect and import
let key = import_any("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?;

// Export to various formats
let json = export_json(&key, Network::Mainnet)?;
let csv = export_csv(&keys, &["wif", "address", "pubkey"])?;
let paper = export_paper_wallet(&key, Network::Mainnet)?;
```

## 📚 Documentation

- [API Documentation](https://docs.rs/rustywallet)
- [ROADMAP](./ROADMAP.md) - Development roadmap and planned features
- Each crate has its own README with detailed examples

## 🔒 Security

- Private keys are zeroized on drop
- Constant-time operations for cryptographic comparisons
- No logging of sensitive data
- Secure random number generation (CSPRNG)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - see [LICENSE](./LICENSE) for details.

## ⭐ Star History

If you find this project useful, please consider giving it a star!
