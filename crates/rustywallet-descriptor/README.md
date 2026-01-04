# rustywallet-descriptor

Output descriptors (BIP380-386) for Bitcoin wallet development with full Taproot support.

## Features

- **Descriptor Parsing**: Parse pk, pkh, wpkh, sh, wsh, tr, multi, sortedmulti descriptors
- **BIP380 Checksum**: Compute and verify descriptor checksums
- **Key Expressions**: Support for raw pubkeys, xpub/xprv with derivation paths, key origins
- **Script Generation**: Generate scriptPubKey for all descriptor types
- **Address Derivation**: Derive addresses from descriptors with network support
- **Wildcard Support**: Range derivation for HD wallet descriptors
- **Full Taproot Support (BIP386)**: Key-path and script-path spending with nested script trees

## Installation

```toml
[dependencies]
rustywallet-descriptor = "0.2"
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

### Taproot Descriptors (BIP386)

Full support for Taproot descriptors with key-path and script-path spending.

#### Key-Path Only

```rust
use rustywallet_descriptor::taproot::TaprootDescriptor;
use rustywallet_address::Network;

// Key-path only: tr(KEY)
let desc = TaprootDescriptor::parse(
    "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
).unwrap();

assert!(desc.is_key_path_only());
let address = desc.derive_address(0, Network::BitcoinMainnet).unwrap();
println!("Taproot address: {}", address); // bc1p...
```

#### Script-Path with Single Leaf

```rust
use rustywallet_descriptor::taproot::TaprootDescriptor;
use rustywallet_address::Network;

// Script-path with single leaf: tr(KEY,{SCRIPT})
let desc = TaprootDescriptor::parse(
    "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)})"
).unwrap();

assert!(!desc.is_key_path_only());
let address = desc.derive_address(0, Network::BitcoinMainnet).unwrap();
```

#### Script-Path with Multiple Leaves

```rust
use rustywallet_descriptor::taproot::TaprootDescriptor;

// Script-path with two leaves: tr(KEY,{SCRIPT,SCRIPT})
let desc = TaprootDescriptor::parse(
    "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)})"
).unwrap();

let tree = desc.script_tree().unwrap();
assert_eq!(tree.leaves().len(), 2);
```

#### Nested Script Trees

```rust
use rustywallet_descriptor::taproot::TaprootDescriptor;

// Nested script tree: tr(KEY,{{SCRIPT,SCRIPT},{SCRIPT,SCRIPT}})
let desc = TaprootDescriptor::parse(
    "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{{pk(KEY1),pk(KEY2)},{pk(KEY3),pk(KEY4)}})"
).unwrap();

// Deeply nested: tr(KEY,{A,{B,{C,D}}})
let desc = TaprootDescriptor::parse(
    "tr(KEY,{pk(A),{pk(B),{pk(C),pk(D)}}})"
).unwrap();
```

#### Tapscript Multisig

```rust
use rustywallet_descriptor::taproot::TaprootDescriptor;

// Tapscript multisig with multi_a (uses OP_CHECKSIGADD)
let desc = TaprootDescriptor::parse(
    "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{multi_a(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)})"
).unwrap();

// Sorted multisig
let desc = TaprootDescriptor::parse(
    "tr(KEY,{sortedmulti_a(2,KEY1,KEY2,KEY3)})"
).unwrap();
```

#### Building Trees Programmatically

```rust
use rustywallet_descriptor::taproot::{TaprootDescriptor, TapDescriptorTree, TapScript};
use rustywallet_descriptor::parse_key;

// Build a script tree programmatically
let key1 = parse_key("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
let key2 = parse_key("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").unwrap();

let leaf1 = TapDescriptorTree::leaf(TapScript::Pk(key1.clone()));
let leaf2 = TapDescriptorTree::leaf(TapScript::Pk(key2.clone()));
let tree = TapDescriptorTree::branch(leaf1, leaf2);

// Create descriptor with the tree
let internal_key = parse_key("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").unwrap();
let desc = TaprootDescriptor::script_path(internal_key, tree);

// Serialize to string
println!("{}", desc); // tr(KEY,{pk(KEY1),pk(KEY2)})
```

#### Round-Trip Parsing

```rust
use rustywallet_descriptor::taproot::TaprootDescriptor;

// Parse → Display → Parse produces equivalent descriptors
let original = "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)})";
let desc = TaprootDescriptor::parse(original).unwrap();
let displayed = desc.to_string();
let reparsed = TaprootDescriptor::parse(&displayed).unwrap();

assert_eq!(desc.to_string(), reparsed.to_string());
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

## Supported Tapscript Types

| Type | Description | Example |
|------|-------------|---------|
| `pk(KEY)` | Pay to pubkey | `pk(02abc...)` |
| `pkh(KEY)` | Pay to pubkey hash | `pkh(02abc...)` |
| `multi_a(k,...)` | Tapscript multisig | `multi_a(2,KEY1,KEY2)` |
| `sortedmulti_a(k,...)` | Sorted Tapscript multisig | `sortedmulti_a(2,KEY1,KEY2)` |
| `raw(HEX)` | Raw script bytes | `raw(51)` |

## API Reference

### TaprootDescriptor

- `parse(s: &str)` - Parse a Taproot descriptor string
- `key_path(key)` - Create a key-path only descriptor
- `script_path(key, tree)` - Create a script-path descriptor
- `is_key_path_only()` - Check if key-path only
- `has_wildcard()` - Check for wildcard in keys
- `internal_key()` - Get the internal key
- `script_tree()` - Get the script tree (if any)
- `derive_address(index, network)` - Derive P2TR address
- `derive_addresses(network, start, count)` - Derive multiple addresses
- `derive_output(index)` - Get TaprootOutput
- `script_pubkey(index)` - Get script pubkey bytes

### TapDescriptorTree

- `leaf(script)` - Create a single leaf
- `branch(left, right)` - Create a branch with two children
- `leaves()` - Get all leaves in the tree
- `has_wildcard()` - Check for wildcards
- `to_tap_tree(index)` - Convert to rustywallet-taproot TapTree

## License

MIT
