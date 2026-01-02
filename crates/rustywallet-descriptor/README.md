# rustywallet-descriptor

Output descriptors (BIP380-386) for Bitcoin wallet development.

## Features

- **Descriptor Parsing**: Parse pk, pkh, wpkh, sh, wsh, tr, multi, sortedmulti descriptors
- **BIP380 Checksum**: Compute and verify descriptor checksums
- **Key Expressions**: Support for raw pubkeys, xpub/xprv with derivation paths, key origins
- **Script Generation**: Generate scriptPubKey for all descriptor types
- **Address Derivation**: Derive addresses from descriptors with network support
- **Wildcard Support**: Range derivation for HD wallet descriptors

## Installation

```toml
[dependencies]
rustywallet-descriptor = "0.1"
```

## Usage

### Parse and Derive Address

```rust
use rustywallet_descriptor::{Descriptor, derive_address};
use rustywallet_address::Network;

// Parse a wpkh descriptor
let desc = Descriptor::parse("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)").unwrap();

// Derive address
let address = derive_address(&desc, Network::BitcoinMainnet, 0).unwrap();
println!("Address: {}", address); // bc1q...
```

### Checksum Operations

```rust
use rustywallet_descriptor::{add_checksum, verify_checksum};

// Add checksum to descriptor
let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)";
let with_checksum = add_checksum(desc);
println!("{}", with_checksum); // wpkh(...)#xxxxxxxx

// Verify checksum
verify_checksum(&with_checksum).unwrap();
```

### HD Wallet Descriptors

```rust
use rustywallet_descriptor::{Descriptor, derive_addresses};
use rustywallet_address::Network;

// Parse xpub descriptor with wildcard
let desc = Descriptor::parse(
    "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)"
).unwrap();

// Derive multiple addresses
let addresses = derive_addresses(&desc, Network::BitcoinMainnet, 0, 10).unwrap();
for (i, addr) in addresses.iter().enumerate() {
    println!("Address {}: {}", i, addr);
}
```

### Nested Descriptors

```rust
use rustywallet_descriptor::Descriptor;

// P2SH-wrapped P2WPKH
let desc = Descriptor::parse(
    "sh(wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))"
).unwrap();
```

### Multisig Descriptors

```rust
use rustywallet_descriptor::Descriptor;

// 2-of-3 multisig
let desc = Descriptor::parse(
    "multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a)"
).unwrap();
```

## Supported Descriptor Types

| Type | Description | Example |
|------|-------------|---------|
| `pk(KEY)` | Pay-to-PubKey | `pk(02...)` |
| `pkh(KEY)` | Pay-to-PubKey-Hash | `pkh(02...)` |
| `wpkh(KEY)` | Pay-to-Witness-PubKey-Hash | `wpkh(02...)` |
| `sh(SCRIPT)` | Pay-to-Script-Hash | `sh(wpkh(...))` |
| `wsh(SCRIPT)` | Pay-to-Witness-Script-Hash | `wsh(multi(...))` |
| `tr(KEY)` | Pay-to-Taproot | `tr(02...)` |
| `multi(k,KEY,...)` | k-of-n Multisig | `multi(2,02...,03...)` |
| `sortedmulti(k,KEY,...)` | Sorted k-of-n Multisig | `sortedmulti(2,02...,03...)` |

## Key Expression Formats

- Raw hex pubkey: `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5`
- Extended public key: `xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8`
- With derivation path: `xpub.../0/1`
- With wildcard: `xpub.../0/*` or `xpub.../0/*'`
- With key origin: `[fingerprint/path]xpub...`

## License

MIT
