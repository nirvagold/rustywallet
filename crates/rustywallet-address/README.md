# rustywallet-address

[![Crates.io](https://img.shields.io/crates/v/rustywallet-address.svg)](https://crates.io/crates/rustywallet-address)
[![Documentation](https://docs.rs/rustywallet-address/badge.svg)](https://docs.rs/rustywallet-address)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/rustywallet/rustywallet/workflows/CI/badge.svg)](https://github.com/rustywallet/rustywallet/actions)

Comprehensive cryptocurrency address generation and validation library for Bitcoin and Ethereum networks.

## Features

- **Bitcoin Legacy (P2PKH)** - Pay-to-Public-Key-Hash addresses (`1...` mainnet, `m`/`n` testnet)
- **Bitcoin SegWit (P2WPKH)** - Pay-to-Witness-Public-Key-Hash addresses (`bc1q...` mainnet, `tb1q...` testnet)
- **Bitcoin Taproot (P2TR)** - Pay-to-Taproot addresses (`bc1p...` mainnet, `tb1p...` testnet)
- **Silent Payments (BIP352)** - Privacy-preserving addresses (`sp1...` mainnet, `tsp1...` testnet)
- **Ethereum** - Ethereum addresses with EIP-55 checksum validation (`0x...`)
- **Multi-network support** - Bitcoin mainnet, testnet, regtest, signet
- **Address validation** - Comprehensive validation with detailed error reporting
- **Type-safe API** - Rust's type system prevents address format errors
- **Zero-copy parsing** - Efficient address parsing and validation
- **Serde support** - Serialization and deserialization support

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rustywallet-address = "0.2"
rustywallet-keys = "0.1"
```

## Quick Start

```rust
use rustywallet_keys::prelude::PrivateKey;
use rustywallet_address::prelude::*;

// Generate a random private key
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Bitcoin Legacy (P2PKH)
let p2pkh = P2PKHAddress::from_public_key(&public_key, Network::BitcoinMainnet)?;
println!("P2PKH: {}", p2pkh); // 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

// Bitcoin SegWit (P2WPKH)
let p2wpkh = P2WPKHAddress::from_public_key(&public_key, Network::BitcoinMainnet)?;
println!("P2WPKH: {}", p2wpkh); // bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

// Bitcoin Taproot (P2TR)
let p2tr = P2TRAddress::from_public_key(&public_key, Network::BitcoinMainnet)?;
println!("P2TR: {}", p2tr); // bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297

// Ethereum
let eth = EthereumAddress::from_public_key(&public_key)?;
println!("Ethereum: {}", eth); // 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
```

## Address Types

### P2PKH (Pay-to-Public-Key-Hash)

Legacy Bitcoin addresses using Base58Check encoding:

```rust
use rustywallet_address::prelude::*;

// From public key
let address = P2PKHAddress::from_public_key(&public_key, Network::BitcoinMainnet)?;

// From string
let address = P2PKHAddress::from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")?;

// Validate
P2PKHAddress::validate("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")?;
```

### P2WPKH (Pay-to-Witness-Public-Key-Hash)

SegWit v0 addresses using Bech32 encoding:

```rust
use rustywallet_address::prelude::*;

// From public key
let address = P2WPKHAddress::from_public_key(&public_key, Network::BitcoinMainnet)?;

// From string
let address = P2WPKHAddress::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?;

// Validate
P2WPKHAddress::validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?;
```

### P2TR (Pay-to-Taproot)

Taproot addresses using Bech32m encoding:

```rust
use rustywallet_address::prelude::*;

// From public key
let address = P2TRAddress::from_public_key(&public_key, Network::BitcoinMainnet)?;

// From string
let address = P2TRAddress::from_str("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297")?;

// Validate
P2TRAddress::validate("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297")?;
```

### Silent Payments (BIP352)

Privacy-preserving addresses using Bech32m encoding:

```rust
use rustywallet_address::prelude::*;
use rustywallet_address::silent_payments::{SilentPaymentAddress, SilentPaymentLabel};

// Create from scan and spend keys
let scan_key = PrivateKey::random();
let spend_key = PrivateKey::random();
let address = SilentPaymentAddress::new(
    &scan_key.public_key(),
    &spend_key.public_key(),
    Network::BitcoinMainnet,
)?;
println!("SP Address: {}", address); // sp1q...

// Single-key mode (scan = spend)
let key = PrivateKey::random();
let address = SilentPaymentAddress::from_single_key(&key.public_key(), Network::BitcoinMainnet)?;

// Parse from string
let address = SilentPaymentAddress::parse("sp1q...")?;

// Labels for multiple addresses
let label = SilentPaymentLabel::new(1);
```

### Ethereum

Ethereum addresses with EIP-55 checksum support:

```rust
use rustywallet_address::prelude::*;

// From public key
let address = EthereumAddress::from_public_key(&public_key)?;

// From string
let address = EthereumAddress::from_str("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")?;

// Validate with checksum
EthereumAddress::validate_checksum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")?;

// Convert to checksummed format
let checksummed = address.to_checksum();
```

## Validation Examples

```rust
use rustywallet_address::prelude::*;

// Generic address validation with auto-detection
let result = Address::validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
assert!(result.is_ok());

// Specific type validation
assert!(P2PKHAddress::validate("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_ok());
assert!(P2WPKHAddress::validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_ok());
assert!(P2TRAddress::validate("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297").is_ok());
assert!(EthereumAddress::validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").is_ok());

// Network-specific validation
let mainnet_addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
let testnet_addr = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";

assert!(P2PKHAddress::validate_network(mainnet_addr, Network::BitcoinMainnet).is_ok());
assert!(P2PKHAddress::validate_network(testnet_addr, Network::BitcoinTestnet).is_ok());

// Invalid addresses return detailed errors
match Address::validate("invalid_address") {
    Err(AddressError::InvalidFormat) => println!("Invalid format"),
    Err(AddressError::InvalidChecksum) => println!("Invalid checksum"),
    Err(AddressError::UnsupportedNetwork) => println!("Unsupported network"),
    _ => {}
}
```

## Network Support

| Network | P2PKH Prefix | P2WPKH Prefix | P2TR Prefix | Description |
|---------|--------------|---------------|-------------|-------------|
| Bitcoin Mainnet | `1` | `bc1q` | `bc1p` | Production Bitcoin network |
| Bitcoin Testnet | `m`, `n` | `tb1q` | `tb1p` | Bitcoin test network |
| Bitcoin Regtest | `m`, `n` | `bcrt1q` | `bcrt1p` | Local regression test network |
| Bitcoin Signet | `m`, `n` | `tb1q` | `tb1p` | Bitcoin signet test network |
| Ethereum | N/A | N/A | N/A | All Ethereum networks use `0x` |

## API Reference

### Core Types

- `Address` - Generic address enum supporting all types
- `P2PKHAddress` - Bitcoin Legacy addresses
- `P2WPKHAddress` - Bitcoin SegWit v0 addresses  
- `P2TRAddress` - Bitcoin Taproot addresses
- `EthereumAddress` - Ethereum addresses
- `Network` - Supported network types
- `AddressError` - Comprehensive error types

### Key Methods

```rust
// Address creation
Address::from_str(s: &str) -> Result<Address, AddressError>
Address::from_public_key(pk: &PublicKey, network: Network) -> Result<Address, AddressError>

// Validation
Address::validate(s: &str) -> Result<(), AddressError>
Address::validate_network(s: &str, network: Network) -> Result<(), AddressError>

// Type checking
address.is_bitcoin() -> bool
address.is_ethereum() -> bool
address.address_type() -> AddressType
address.network() -> Option<Network>

// Conversion
address.to_string() -> String
address.as_bytes() -> &[u8]
```

### Error Handling

```rust
use rustywallet_address::AddressError;

match Address::validate("invalid") {
    Err(AddressError::InvalidFormat) => "Invalid address format",
    Err(AddressError::InvalidChecksum) => "Checksum validation failed", 
    Err(AddressError::InvalidLength) => "Invalid address length",
    Err(AddressError::UnsupportedNetwork) => "Network not supported",
    Err(AddressError::InvalidEncoding) => "Encoding error",
    Ok(_) => "Valid address",
};
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.