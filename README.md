# rustywallet 🦀💰

A comprehensive collection of Rust crates for Bitcoin wallet development with focus on clean Developer Experience (DX), type-safety, and performance.

[![Crates.io](https://img.shields.io/crates/v/rustywallet.svg)](https://crates.io/crates/rustywallet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## 🎯 Features

- **26 Published Crates** - Modular architecture, use only what you need
- **High Performance** - 7M+ keys/sec batch generation
- **Type-Safe** - Leverage Rust's type system for correctness
- **Secure** - Zeroize sensitive data, constant-time operations
- **Well Documented** - Comprehensive docs and examples
- **No Rate Limits** - Electrum protocol for unlimited balance checks
- **Advanced Crypto** - MuSig2, FROST, Silent Payments, Taproot

## 📦 Crates

### Core

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet](https://crates.io/crates/rustywallet) | 0.1.0 | Umbrella crate - all features in one |
| [rustywallet-keys](https://crates.io/crates/rustywallet-keys) | 0.1.3 | Private & Public key management |
| [rustywallet-address](https://crates.io/crates/rustywallet-address) | 0.3.0 | Address generation + descriptor derivation |
| [rustywallet-mnemonic](https://crates.io/crates/rustywallet-mnemonic) | 0.2.0 | BIP39 mnemonic (5 languages) |
| [rustywallet-hd](https://crates.io/crates/rustywallet-hd) | 0.3.0 | HD Wallet + SLIP39 Shamir |
| [rustywallet-signer](https://crates.io/crates/rustywallet-signer) | 0.2.0 | ECDSA + Schnorr signing |
| [rustywallet-descriptor](https://crates.io/crates/rustywallet-descriptor) | 0.2.0 | Output descriptors (BIP380-386) |

### Performance & Network

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet-batch](https://crates.io/crates/rustywallet-batch) | 0.3.0 | Batch key + address generation |
| [rustywallet-vanity](https://crates.io/crates/rustywallet-vanity) | 0.3.0 | Vanity addresses (P2PKH, P2WPKH, P2TR) |
| [rustywallet-electrum](https://crates.io/crates/rustywallet-electrum) | 0.3.0 | Electrum + Silent Payment scanning |
| [rustywallet-mempool](https://crates.io/crates/rustywallet-mempool) | 0.1.0 | Mempool.space API |
| [rustywallet-checker](https://crates.io/crates/rustywallet-checker) | 0.2.0 | Balance checking (API + Electrum) |
| [rustywallet-bloom](https://crates.io/crates/rustywallet-bloom) | 0.2.0 | Bloom + Counting Bloom filters |

### Transaction & PSBT

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet-tx](https://crates.io/crates/rustywallet-tx) | 0.3.0 | TX building + MuSig2/FROST/Silent |
| [rustywallet-psbt](https://crates.io/crates/rustywallet-psbt) | 0.2.0 | PSBT + MuSig2/FROST partial sigs |
| [rustywallet-multisig](https://crates.io/crates/rustywallet-multisig) | 0.3.0 | Multisig + FROST threshold |
| [rustywallet-coinjoin](https://crates.io/crates/rustywallet-coinjoin) | 0.2.0 | CoinJoin + PayJoin (BIP78) |

### Advanced Cryptography

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet-taproot](https://crates.io/crates/rustywallet-taproot) | 0.1.0 | Taproot (BIP340/341/342) |
| [rustywallet-musig](https://crates.io/crates/rustywallet-musig) | 0.1.0 | MuSig2 Schnorr multisig |
| [rustywallet-frost](https://crates.io/crates/rustywallet-frost) | 0.1.0 | FROST threshold signatures |
| [rustywallet-silent](https://crates.io/crates/rustywallet-silent) | 0.1.0 | Silent Payments (BIP352) |

### Utility

| Crate | Version | Description |
|-------|---------|-------------|
| [rustywallet-import](https://crates.io/crates/rustywallet-import) | 0.2.0 | Import WIF, hex, mnemonic, descriptors |
| [rustywallet-export](https://crates.io/crates/rustywallet-export) | 0.2.0 | Export JSON, CSV, descriptors, PSBT |
| [rustywallet-recovery](https://crates.io/crates/rustywallet-recovery) | 0.2.0 | Parallel wallet recovery |
| [rustywallet-lightning](https://crates.io/crates/rustywallet-lightning) | 0.2.0 | BOLT11 + BOLT12 offers |
| [rustywallet-cli](https://crates.io/crates/rustywallet-cli) | 0.1.0 | Command-line interface |

## 🔧 Feature Matrix

| Feature | Crate(s) | Status |
|---------|----------|--------|
| Key Generation | keys, batch | ✅ |
| Address Types (P2PKH, P2WPKH, P2TR) | address | ✅ |
| HD Wallets (BIP32/44/84/86) | hd | ✅ |
| Mnemonics (5 languages) | mnemonic | ✅ |
| SLIP39 Shamir | hd | ✅ |
| Output Descriptors | descriptor, address | ✅ |
| Taproot | taproot, address | ✅ |
| Schnorr Signatures | signer, taproot | ✅ |
| MuSig2 | musig, tx, psbt | ✅ |
| FROST Threshold | frost, tx, psbt, multisig | ✅ |
| Silent Payments | silent, tx, electrum | ✅ |
| PSBT (BIP174) | psbt | ✅ |
| CoinJoin / PayJoin | coinjoin | ✅ |
| BOLT11 Invoices | lightning | ✅ |
| BOLT12 Offers | lightning | ✅ |
| Electrum Protocol | electrum, checker | ✅ |
| Vanity Addresses | vanity | ✅ |
| Bloom Filters | bloom | ✅ |

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
rustywallet-address = "0.3"
rustywallet-tx = "0.3"
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

### Descriptor-Based Address Derivation

```rust
use rustywallet_address::prelude::*;

// Derive from wpkh descriptor
let addr = Address::from_descriptor(
    "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
    0,
    Network::BitcoinMainnet,
)?;

// Derive from Taproot descriptor
let addr = Address::from_descriptor(
    "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
    0,
    Network::BitcoinMainnet,
)?;
```

### BOLT12 Offers

```rust
use rustywallet_lightning::bolt12::{Bolt12Offer, OfferBuilder};

// Create an offer
let offer = OfferBuilder::new()
    .description("Coffee")
    .amount_msats(10_000)
    .issuer("Bob's Coffee Shop")
    .build()?;

println!("Offer: {}", offer.encode());  // lno1...

// Parse an offer
let parsed = Bolt12Offer::parse(&offer.encode())?;
```

### High-Performance Batch Generation

```rust
use rustywallet_batch::prelude::*;

// Generate keys at 7M+ keys/sec
let generator = FastKeyGenerator::new();
for key in generator.take(1_000_000) {
    // Process key...
}

// Generate addresses in parallel
let addr_gen = BatchAddressGenerator::new(BatchAddressType::P2TR, Network::Mainnet);
for (key, address) in addr_gen.generate_stream(10_000) {
    // Process...
}
```

### Vanity Address Generation (Including Taproot)

```rust
use rustywallet_vanity::prelude::*;

// Find Taproot address with pattern
let result = VanityGenerator::new()
    .address_type(AddressType::P2TR)
    .pattern(Pattern::prefix("abc"))
    .generate()?;

println!("Found: {}", result.address);  // bc1pabc...
```

### Electrum Balance Checking

```rust
use rustywallet_electrum::{ElectrumClient, Network};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ElectrumClient::connect("electrum.blockstream.info:50002", Network::Mainnet).await?;
    
    // Check balance - no rate limits!
    let balance = client.get_balance("bc1q...").await?;
    println!("Balance: {} sats", balance.confirmed);
    
    Ok(())
}
```

### Counting Bloom Filter

```rust
use rustywallet_bloom::CountingBloomFilter;

let mut filter = CountingBloomFilter::new(100_000, 0.01);

// Insert and remove items
filter.insert("address1");
filter.insert("address2");
assert!(filter.contains("address1"));

filter.remove("address1")?;
assert!(!filter.contains("address1"));
```

### Multi-Language Mnemonics

```rust
use rustywallet_mnemonic::{Mnemonic, Language};

// Generate in Japanese
let mnemonic = Mnemonic::generate_with_language(12, Language::Japanese)?;

// Auto-detect language when parsing
let parsed = Mnemonic::parse_auto_detect("あいこくしん あいさつ...")?;
assert_eq!(parsed.language(), Language::Japanese);
```

### SLIP39 Shamir Secret Sharing

```rust
use rustywallet_hd::Slip39;

// Split seed into 5 shares, need 3 to recover
let slip39 = Slip39::new(3, 5);
let shares = slip39.split(&seed)?;

// Recover with any 3 shares
let recovered = Slip39::combine(&shares[0..3])?;
```

## 📚 Documentation

- [API Documentation](https://docs.rs/rustywallet)
- [ROADMAP](./ROADMAP.md) - Development roadmap and planned features
- [Getting Started Guide](./docs/getting-started/)
- [Feature Guides](./docs/guides/)
- [Advanced Topics](./docs/advanced/)

## 🔒 Security

- Private keys are zeroized on drop
- Constant-time operations for cryptographic comparisons
- No logging of sensitive data
- Secure random number generation (CSPRNG)
- BIP340 Schnorr signatures
- FROST threshold signatures for distributed key management

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - see [LICENSE](./LICENSE) for details.

## ⭐ Star History

If you find this project useful, please consider giving it a star!
