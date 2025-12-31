# rustywallet-address

Cryptocurrency address generation and validation for Bitcoin and Ethereum.

## Features

- **Bitcoin Legacy (P2PKH)** - Addresses starting with `1` (mainnet) or `m`/`n` (testnet)
- **Bitcoin SegWit (P2WPKH)** - Addresses starting with `bc1q` (mainnet) or `tb1q` (testnet)
- **Bitcoin Taproot (P2TR)** - Addresses starting with `bc1p` (mainnet) or `tb1p` (testnet)
- **Ethereum** - Addresses starting with `0x` with EIP-55 checksum support

## Installation

```toml
[dependencies]
rustywallet-address = "0.1"
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
println!("P2PKH: {}", p2pkh); // 1...

// Bitcoin SegWit (P2WPKH)
let p2wpkh = P2WPKHAddress::from_public_key(&public_key, Network::BitcoinMainnet)?;
println!("P2WPKH: {}", p2wpkh); // bc1q...

// Bitcoin Taproot (P2TR)
let p2tr = P2TRAddress::from_public_key(&public_key, Network::BitcoinMainnet)?;
println!("P2TR: {}", p2tr); // bc1p...

// Ethereum
let eth = EthereumAddress::from_public_key(&public_key)?;
println!("Ethereum: {}", eth); // 0x...
```

## Address Validation

```rust
use rustywallet_address::prelude::*;

// Validate any address with auto-detection
Address::validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?;

// Validate specific types
P2WPKHAddress::validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?;

// Validate Ethereum checksum (EIP-55)
EthereumAddress::validate_checksum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")?;
```

## Address Type Detection

```rust
use rustywallet_address::prelude::*;

let addr = Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?;
assert!(addr.is_bitcoin());

let addr = Address::from_str("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")?;
assert!(addr.is_ethereum());
```

## Supported Networks

| Address Type | Mainnet Prefix | Testnet Prefix | Encoding |
|--------------|----------------|----------------|----------|
| P2PKH | `1` | `m`, `n` | Base58Check |
| P2WPKH | `bc1q` | `tb1q` | Bech32 |
| P2TR | `bc1p` | `tb1p` | Bech32m |
| Ethereum | `0x` | `0x` | Hex + EIP-55 |

## License

MIT
