# rustywallet Documentation

Welcome to the rustywallet documentation! This guide will help you get started with Bitcoin wallet development in Rust.

## 📚 Table of Contents

### Getting Started
- [Installation](./getting-started/installation.md)
- [Quick Start](./getting-started/quick-start.md)
- [Choosing the Right Crate](./getting-started/choosing-crates.md)

### Guides
- [Key Management](./guides/key-management.md)
- [Address Generation](./guides/address-generation.md)
- [HD Wallets](./guides/hd-wallets.md)
- [Transaction Building](./guides/transactions.md)
- [Multi-Signature Wallets](./guides/multisig.md)
- [Balance Checking](./guides/balance-checking.md)
- [Import & Export](./guides/import-export.md)
- [Privacy](./guides/privacy.md) - Silent Payments, CoinJoin, PayJoin

### Advanced Topics
- [High-Performance Generation](./advanced/batch-generation.md)
- [Vanity Addresses](./advanced/vanity-addresses.md)
- [Output Descriptors](./advanced/descriptors.md) - BIP380-386
- [Shamir Secret Sharing](./advanced/shamir.md)
- [Security Best Practices](./advanced/security.md)

### API Reference
- [docs.rs/rustywallet](https://docs.rs/rustywallet)

## 🎯 What is rustywallet?

rustywallet is a collection of 26+ Rust crates for Bitcoin wallet development. It's designed with:

- **Modularity** - Use only what you need
- **Performance** - 7M+ keys/sec batch generation
- **Type Safety** - Leverage Rust's type system
- **Security** - Zeroize sensitive data, constant-time operations
- **Developer Experience** - Clean APIs, comprehensive docs
- **Advanced Crypto** - MuSig2, FROST, Silent Payments, Taproot

## 🚀 Quick Example

```rust
use rustywallet::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new wallet
    let mnemonic = Mnemonic::generate(12)?;
    println!("Mnemonic: {}", mnemonic.phrase());
    
    // Derive HD wallet
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_seed(&seed)?;
    
    // Get first Bitcoin address (BIP84 - Native SegWit)
    let path = "m/84'/0'/0'/0/0";
    let child = master.derive_path(path)?;
    let address = Address::p2wpkh(&child.public_key(), Network::Mainnet)?;
    
    println!("Address: {}", address);
    
    Ok(())
}
```

## 📦 Crate Overview

| Category | Crates | Description |
|----------|--------|-------------|
| Core | keys, address, mnemonic, hd, descriptor | Basic wallet functionality |
| Network | electrum, mempool, checker | Blockchain interaction |
| Transaction | tx, psbt, multisig, signer, coinjoin | Transaction building & signing |
| Cryptography | taproot, musig, frost, silent | Advanced protocols |
| Utility | import, export, bloom, recovery | Data handling |
| Performance | batch, vanity | High-speed operations |
| Lightning | lightning | BOLT11/BOLT12 support |

## 🔧 Feature Highlights

### v2 Features

- **Output Descriptors** - Full BIP380-386 support including Taproot
- **Silent Payments** - BIP352 for enhanced privacy
- **MuSig2** - Schnorr-based multisig
- **FROST** - Threshold signatures
- **BOLT12 Offers** - Reusable Lightning payment requests
- **CoinJoin/PayJoin** - Privacy-enhancing transactions
- **Multi-language Mnemonics** - 5 languages supported
- **SLIP39** - Shamir secret sharing for seeds
- **Counting Bloom Filters** - With removal support

## 🔗 Links

- [GitHub Repository](https://github.com/nirvagold/rustywallet)
- [crates.io](https://crates.io/crates/rustywallet)
- [Roadmap](../ROADMAP.md)
