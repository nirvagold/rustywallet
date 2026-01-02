# Installation

## Requirements

- Rust 1.70 or later
- Cargo (comes with Rust)

## Option 1: Umbrella Crate (Recommended for beginners)

The easiest way to get started is using the umbrella crate which includes all features:

```toml
[dependencies]
rustywallet = "0.1"
```

This gives you access to:
- Key management
- Address generation
- Mnemonic/HD wallets
- Message signing
- Balance checking

## Option 2: Individual Crates (Recommended for production)

For better control over dependencies and compile times, pick only what you need:

```toml
[dependencies]
# Core functionality
rustywallet-keys = "0.1"      # Private/public keys
rustywallet-address = "0.1"   # Address generation
rustywallet-mnemonic = "0.1"  # BIP39 mnemonics
rustywallet-hd = "0.1"        # HD wallets (BIP32/44/84)

# Transaction building
rustywallet-tx = "0.1"        # Build & sign transactions
rustywallet-multisig = "0.1"  # Multi-signature wallets

# Network
rustywallet-electrum = "0.1"  # Electrum protocol (async)
rustywallet-mempool = "0.1"   # Mempool.space API (async)

# Utility
rustywallet-import = "0.1"    # Import from various formats
rustywallet-export = "0.1"    # Export to various formats

# Performance
rustywallet-batch = "0.1"     # High-speed key generation
rustywallet-vanity = "0.1"    # Vanity address generator
```

## Async Runtime

For network crates (`electrum`, `mempool`, `checker`), you need an async runtime:

```toml
[dependencies]
rustywallet-electrum = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Feature Flags

Some crates have optional features:

```toml
[dependencies]
# Enable all address types including Ethereum
rustywallet-address = { version = "0.1", features = ["ethereum"] }
```

## Verify Installation

Create a simple test:

```rust
use rustywallet_keys::prelude::PrivateKey;

fn main() {
    let key = PrivateKey::random();
    println!("Installation successful!");
    println!("Random key: {}", key.to_hex());
}
```

Run with:
```bash
cargo run
```

## Next Steps

- [Quick Start Guide](./quick-start.md)
- [Choosing the Right Crate](./choosing-crates.md)
