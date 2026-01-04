# Output Descriptors Guide

Output descriptors (BIP380-386) provide a standardized way to describe how to derive addresses and scripts.

## Supported Descriptor Types

| Type | Description | Example |
|------|-------------|---------|
| `pk()` | Pay to pubkey | `pk(KEY)` |
| `pkh()` | Pay to pubkey hash (P2PKH) | `pkh(KEY)` |
| `wpkh()` | Pay to witness pubkey hash (P2WPKH) | `wpkh(KEY)` |
| `sh()` | Pay to script hash (P2SH) | `sh(wpkh(KEY))` |
| `wsh()` | Pay to witness script hash (P2WSH) | `wsh(multi(2,KEY,KEY))` |
| `tr()` | Pay to Taproot (P2TR) | `tr(KEY)` |
| `multi()` | k-of-n multisig | `multi(2,KEY,KEY,KEY)` |
| `sortedmulti()` | Sorted k-of-n multisig | `sortedmulti(2,KEY,KEY,KEY)` |

## Basic Usage

### Parsing Descriptors

```rust
use rustywallet_descriptor::{Descriptor, derive_address};
use rustywallet_address::Network;

// Parse a descriptor
let desc = Descriptor::parse("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)")?;

// Derive an address
let address = derive_address(&desc, Network::BitcoinMainnet, 0)?;
println!("Address: {}", address);  // bc1q...
```

### Address Derivation from Descriptors

```rust
use rustywallet_address::prelude::*;

// Using the Address trait
let addr = Address::from_descriptor(
    "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
    0,
    Network::BitcoinMainnet,
)?;

// Derive multiple addresses
let addrs = Address::from_descriptor_range(
    "wpkh(xpub.../0/*)",
    0,    // start index
    100,  // count
    Network::BitcoinMainnet,
)?;
```

## Taproot Descriptors (BIP386)

### Key-Path Only

```rust
use rustywallet_descriptor::taproot::TaprootDescriptor;

// Simple key-path spending
let desc = TaprootDescriptor::parse(
    "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
)?;

let address = desc.derive_address(0, Network::BitcoinMainnet)?;
println!("Taproot: {}", address);  // bc1p...
```

### Script-Path with Tree

```rust
// Key-path with script tree
let desc = TaprootDescriptor::parse(
    "tr(KEY,{pk(KEY2),pk(KEY3)})"
)?;

// Access script tree
if let Some(tree) = desc.script_tree() {
    println!("Leaves: {}", tree.leaves().len());
}
```

### Building Taproot Descriptors

```rust
use rustywallet_descriptor::taproot::{TaprootDescriptor, TapDescriptorTree, TapScript};
use rustywallet_descriptor::key::parse_key;

let internal_key = parse_key("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")?;
let script_key = parse_key("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")?;

// Build script tree
let leaf = TapDescriptorTree::leaf(TapScript::Pk(script_key));

// Create descriptor
let desc = TaprootDescriptor::script_path(internal_key, leaf);
```

## Ranged Descriptors

Ranged descriptors use wildcards (`*`) for deriving multiple addresses.

```rust
// xpub with derivation path and wildcard
let desc = Descriptor::parse(
    "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)"
)?;

// Check if descriptor has wildcard
assert!(desc.has_wildcard());

// Derive addresses at different indices
for i in 0..10 {
    let addr = derive_address(&desc, Network::BitcoinMainnet, i)?;
    println!("Address {}: {}", i, addr);
}
```

## Checksums

Descriptors can include a checksum for error detection.

```rust
use rustywallet_descriptor::{add_checksum, verify_checksum};

let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";

// Add checksum
let with_checksum = add_checksum(desc);
println!("{}", with_checksum);  // wpkh(...)#xxxxxx

// Verify checksum
verify_checksum(&with_checksum)?;

// Parsing validates checksum automatically
let parsed = Descriptor::parse(&with_checksum)?;
```

## Import/Export

### Importing Descriptors

```rust
use rustywallet_import::descriptor::import_descriptor;

let desc_str = "wpkh(xpub.../0/*)#checksum";
let imported = import_descriptor(desc_str)?;

// Extract keys
for key in imported.keys() {
    println!("Key: {}", key);
}
```

### Exporting Descriptors

```rust
use rustywallet_export::descriptor::export_descriptor;

// Export with checksum
let exported = export_descriptor(&desc, true)?;

// Export for specific wallet format
let electrum = export_descriptor_electrum(&desc)?;
let sparrow = export_descriptor_sparrow(&desc)?;
```

## Wallet Format Support

### Electrum

```rust
use rustywallet_import::wallet_format::ElectrumWallet;

let wallet = ElectrumWallet::import("wallet.json")?;
let descriptors = wallet.descriptors();
```

### Sparrow

```rust
use rustywallet_import::wallet_format::SparrowWallet;

let wallet = SparrowWallet::import("wallet.json")?;
let descriptors = wallet.descriptors();
```

### Bitcoin Core

```rust
use rustywallet_import::wallet_format::BitcoinCoreWallet;

let wallet = BitcoinCoreWallet::import("wallet.dat")?;
let descriptors = wallet.descriptors();
```

## Best Practices

1. **Always use checksums** when storing or transmitting descriptors
2. **Use ranged descriptors** for HD wallets
3. **Prefer `sortedmulti`** over `multi` for deterministic key ordering
4. **Use Taproot descriptors** for new wallets
5. **Store descriptors securely** - they reveal your address derivation scheme

## Descriptor Type Detection

```rust
use rustywallet_address::descriptor::{get_descriptor_type, DescriptorType};

let desc_type = get_descriptor_type("wpkh(KEY)")?;

match desc_type {
    DescriptorType::Wpkh => println!("SegWit v0"),
    DescriptorType::Tr => println!("Taproot"),
    _ => println!("Other"),
}

// Check properties
assert!(desc_type.is_segwit());
assert!(!desc_type.is_taproot());
```
