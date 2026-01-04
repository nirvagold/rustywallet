# rustywallet-hd

[![Crates.io](https://img.shields.io/crates/v/rustywallet-hd.svg)](https://crates.io/crates/rustywallet-hd)
[![Documentation](https://docs.rs/rustywallet-hd/badge.svg)](https://docs.rs/rustywallet-hd)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

BIP32/BIP44/BIP85/SLIP39 Hierarchical Deterministic wallet implementation for cryptocurrency key derivation in Rust.

## Features

- **BIP32 Compliance**: Full implementation of BIP32 hierarchical deterministic key derivation
- **BIP44/49/84/86 Support**: Standard derivation paths for multiple cryptocurrencies
- **BIP85 Entropy**: Deterministic entropy derivation for child wallets
- **SLIP39 Shamir Sharing**: Split seeds into shares with threshold recovery
- **Fluent Path Builder**: Build custom derivation paths with method chaining
- **Extended Keys**: Export/import extended keys (xprv/xpub, tprv/tpub)
- **Multi-Group SLIP39**: Advanced secret sharing with multiple groups
- **Security**: Secure memory handling with automatic zeroization on drop

## Installation

```toml
[dependencies]
rustywallet-hd = "0.3"
```

## Quick Start

```rust
use rustywallet_hd::prelude::*;

// Create master key from seed
let seed = [0u8; 64];
let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet)?;

// Derive BIP44 Bitcoin path: m/44'/0'/0'/0/0
let path = DerivationPath::bip44_bitcoin(0, 0, 0);
let child = master.derive_path(&path)?;

// Get keys
let private_key = child.private_key()?;
let public_key = child.public_key();
```

## Derivation Path Builder

Build custom derivation paths fluently:

```rust
use rustywallet_hd::path::DerivationPathBuilder;

// Build custom paths
let path = DerivationPathBuilder::new()
    .hardened(44)
    .hardened(0)
    .hardened(0)
    .normal(0)
    .normal(0)
    .build()
    .unwrap();

assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");

// Use BIP presets
let bip84 = DerivationPathBuilder::bip84(0, 0)  // m/84'/0'/0'
    .normal(0)  // change
    .normal(0)  // index
    .build()
    .unwrap();

let bip86 = DerivationPathBuilder::bip86(0, 0)  // m/86'/0'/0' (Taproot)
    .normal(0)
    .normal(0)
    .build()
    .unwrap();
```

### BIP Presets

| Method | Purpose | Path Prefix |
|--------|---------|-------------|
| `bip44(coin, account)` | Legacy P2PKH | m/44'/coin'/account' |
| `bip49(coin, account)` | Nested SegWit P2SH-P2WPKH | m/49'/coin'/account' |
| `bip84(coin, account)` | Native SegWit P2WPKH | m/84'/coin'/account' |
| `bip86(coin, account)` | Taproot P2TR | m/86'/coin'/account' |

## BIP85 - Deterministic Entropy

Derive child wallet entropy from a master key:

```rust
use rustywallet_hd::{ExtendedPrivateKey, Network, Bip85, derive_bip85_mnemonic};

let seed = [0u8; 64];
let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet)?;

// Derive child mnemonic entropy (12 words, index 0)
let entropy = derive_bip85_mnemonic(&master, 12, 0)?;
assert_eq!(entropy.len(), 16); // 128 bits for 12 words

// Or use Bip85 struct for more options
let bip85 = Bip85::new(master.clone());
let child_master = bip85.derive_child_master(0, Network::Mainnet)?;
```

## SLIP39 - Shamir Secret Sharing

Split seeds into shares with threshold recovery:

```rust
use rustywallet_hd::slip39::Slip39;

// Create a 2-of-3 sharing scheme
let slip39 = Slip39::new(2, 3)?;

// Split a 32-byte secret
let secret = [0x42u8; 32];
let shares = slip39.split(&secret)?;

// Recover using any 2 shares
let recovered = Slip39::combine(&shares[0..2])?;
assert_eq!(secret.to_vec(), recovered);
```

### Multi-Group SLIP39

For advanced backup schemes with multiple groups:

```rust
use rustywallet_hd::slip39::{Slip39MultiGroup, GroupConfig};

// Create a 2-of-3 group scheme:
// - Group 0: 2-of-3 shares (e.g., family members)
// - Group 1: 2-of-3 shares (e.g., trusted friends)
// - Group 2: 3-of-5 shares (e.g., safety deposit boxes)
// Need shares from any 2 groups to recover
let groups = vec![
    GroupConfig::new(2, 3)?,
    GroupConfig::new(2, 3)?,
    GroupConfig::new(3, 5)?,
];
let multi = Slip39MultiGroup::new(2, groups)?;

let secret = [0x42u8; 32];
let all_shares = multi.split(&secret)?;

// Recover using shares from groups 0 and 1
let mut combined = Vec::new();
combined.extend(all_shares[0][0..2].iter().cloned()); // 2 from group 0
combined.extend(all_shares[1][0..2].iter().cloned()); // 2 from group 1
let recovered = Slip39MultiGroup::combine(&combined)?;
```

## Extended Keys

### Export/Import xprv/xpub

```rust
use rustywallet_hd::prelude::*;

let master = ExtendedPrivateKey::from_seed(&seed, Network::Mainnet)?;

// Export
let xprv = master.to_xprv();
let xpub = master.extended_public_key().to_xpub();

// Import
let imported = ExtendedPrivateKey::from_xprv(&xprv)?;
let imported_pub = ExtendedPublicKey::from_xpub(&xpub)?;
```

## API Reference

### DerivationPathBuilder

```rust
impl DerivationPathBuilder {
    pub fn new() -> Self;
    pub fn hardened(self, index: u32) -> Self;
    pub fn normal(self, index: u32) -> Self;
    pub fn build(self) -> Result<DerivationPath, HdError>;
    
    // BIP presets
    pub fn bip44(coin_type: u32, account: u32) -> Self;
    pub fn bip49(coin_type: u32, account: u32) -> Self;
    pub fn bip84(coin_type: u32, account: u32) -> Self;
    pub fn bip86(coin_type: u32, account: u32) -> Self;
}
```

### Slip39

```rust
impl Slip39 {
    pub fn new(threshold: u8, share_count: u8) -> Result<Self, HdError>;
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Slip39Share>, HdError>;
    pub fn combine(shares: &[Slip39Share]) -> Result<Vec<u8>, HdError>;
}
```

### Slip39MultiGroup

```rust
impl Slip39MultiGroup {
    pub fn new(group_threshold: u8, groups: Vec<GroupConfig>) -> Result<Self, HdError>;
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Vec<Slip39Share>>, HdError>;
    pub fn combine(shares: &[Slip39Share]) -> Result<Vec<u8>, HdError>;
}
```

## Security Considerations

- Private keys and chain codes are automatically zeroized when dropped
- Debug output masks sensitive data
- Use hardened derivation for account-level keys
- SLIP39 shares should be stored separately in secure locations

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
